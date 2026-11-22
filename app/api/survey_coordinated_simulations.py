# ruff: noqa: E501 — field descriptions are kept one per line
"""ASG-2B — coordinated SIMULATION of the surveys of one composite plan. Three operations.

Registered ONLY when ``survey_coordinated_simulation_enabled`` (with requirement groups and everything they need) is
on; off by default. Every operation needs ``survey.assignment.read``; starting one and giving an input also need
``survey.simulate``. Market-scoped; the two state-changing operations are CSRF-protected, rate-limited and audited.
Every response carries ``record_class: SIMULATION``. Nothing here is, starts, schedules or authorises a call, and no
operational record is read or written. The single-survey simulation operations are unchanged.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import ErrorResponse
from app.api.survey_assignments import READ, _write
from app.api.survey_simulations import SurveySimulationInputIn
from app.core.errors import AppError
from app.domain.survey import coordination
from app.domain.survey.store import SurveyError
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-assignment", tags=["survey-assignment"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}


class SurveyCoordinatedSimulationIn(BaseModel):
    label: str = Field(default="", max_length=160)


class SurveyCoordinatedSimulationOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    contract: str
    current_contract: str
    market_code: str
    label: str
    created_at: datetime
    composite_plan_id: uuid.UUID
    composite_fingerprint: str
    composite_intact: bool
    application_sha256: str
    application: dict[str, Any]
    input_consistency: dict[str, Any]
    governed_order: list[str]
    status: Literal[
        "RUNNING", "POLICY_UNRESOLVED", "CROSS_SURVEY_POLICY_UNRESOLVED", "ALL_SURVEYS_COMPLETED", "REPLAY_DRIFT"
    ] = Field(
        description="RUNNING: the current survey waits for an answer. POLICY_UNRESOLVED: a non-answer in the current survey. "
        "CROSS_SURVEY_POLICY_UNRESOLVED: a survey ended without COMPLETED and what follows is undecided. ALL_SURVEYS_COMPLETED: "
        "progress only — not a business outcome. REPLAY_DRIFT: an individual simulation no longer recomputes to its record."
    )
    stop: dict[str, Any] | None = Field(description="Why the coordinated run is not continuing, with a stable code.")
    decisions: list[dict[str, Any]] = Field(
        description="Each boundary between surveys: the ending, PROCEED or STOP, and the rule applied."
    )
    surveys: list[dict[str, Any]] = Field(
        description="Every survey in the governed order: its pinned version, state, individual simulation (in full), run fingerprint and execution contract."
    )
    current: dict[str, Any] | None
    progress: dict[str, int]
    execution_contracts: list[str]
    replay_sha256: str = Field(
        description="Fingerprint of the coordinated result: the same composite and the same inputs always give the same one."
    )
    operational_call_eligibility: dict[str, Any]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


@router.post(
    "/composite-plans/{composite_id}/coordinated-simulations", response_model=SurveyCoordinatedSimulationOut, status_code=201,
    operation_id="survey_coordinated_simulation_create", responses=_ERR,
)  # fmt: skip
@csrf_protected
def survey_coordinated_simulation_create(
    composite_id: uuid.UUID,
    body: SurveyCoordinatedSimulationIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.simulate")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyCoordinatedSimulationOut:
    """Start a coordinated simulation of a recorded composite plan, in its governed order. Refused — with the stable
    code of what is unresolved — unless the selection and the order are settled, every individual plan can be
    computed and no survey version is required twice."""
    _write(request, auth)
    try:
        cid = coordination.create(db, composite_id, _markets(auth), body.label, auth.actor, request_meta(request))
        db.commit()
        return SurveyCoordinatedSimulationOut(**coordination.state(db, cid, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.post(
    "/coordinated-simulations/{coordinated_id}/inputs", response_model=SurveyCoordinatedSimulationOut,
    operation_id="survey_coordinated_simulation_input", responses=_ERR,
)  # fmt: skip
@csrf_protected
def survey_coordinated_simulation_input(
    coordinated_id: uuid.UUID,
    body: SurveySimulationInputIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.simulate")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyCoordinatedSimulationOut:
    """Give one typed input to the current question of the current survey. That survey's own simulation decides
    whether it is accepted. The next survey starts only if this one thereby reaches COMPLETED."""
    _write(request, auth)
    try:
        out = coordination.advance(
            db,
            coordinated_id,
            _markets(auth),
            body.expected_inputs,
            body.key,
            body.answer,
            auth.actor,
            request_meta(request),
        )
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return SurveyCoordinatedSimulationOut(**out)


@router.get(
    "/coordinated-simulations/{coordinated_id}",
    response_model=SurveyCoordinatedSimulationOut,
    operation_id="survey_coordinated_simulation_get",
    responses=_ERR,
)
def survey_coordinated_simulation_get(
    coordinated_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyCoordinatedSimulationOut:
    """The coordinated simulation as it stands, computed now from its steps and the replay of each survey's own run."""
    try:
        return SurveyCoordinatedSimulationOut(**coordination.state(db, coordinated_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc
