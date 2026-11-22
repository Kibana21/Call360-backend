# ruff: noqa: E501 — field descriptions are kept one per line
"""SS-03B — SIMULATION of published survey versions and call-plan assembly. Five operations under ``/api/v1``.

Registered ONLY when ``survey_simulation_enabled`` (and ``survey_definitions_enabled``) is on; off by default. Every
response carries ``record_class: SIMULATION``. Nothing here starts, schedules, authorises or makes anything eligible
for a customer call, and nothing here touches an operational record: no case, attempt, session, operational survey
run, recording, transcript or finding.

Permissions: creating a simulation, giving it an input and generating a call plan change state and need
``survey.simulate`` — a permission of its own, granted to no role by its migration. Reading a simulation or a plan
needs ``survey.read``. Everything is market-scoped: a version, a simulation or a plan outside the caller's markets
does not exist for them. The three state-changing operations are CSRF-protected, rate-limited and audited.
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
from app.core.errors import AppError
from app.domain.survey import simulation
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["survey-simulation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ = "survey.read"
SIMULATE = "survey.simulate"


class SurveySimulationCreateIn(BaseModel):
    facts: dict[str, Any] = Field(
        default_factory=dict, description="A synthetic fact snapshot: governed catalog fields only."
    )
    label: str = Field(default="", max_length=160)


class SurveySimulationInputIn(BaseModel):
    expected_inputs: int = Field(ge=0, description="How many inputs the simulation holds as the caller last saw it.")
    key: str = Field(
        min_length=1, max_length=200, description="The question instance being answered: <instance>/<node>."
    )
    answer: dict[str, Any]


class SurveySimulationInput(BaseModel):
    seq: int
    key: str
    answer: dict[str, Any]
    accepted: bool
    rejection_code: str | None
    run_status: str
    run_sha256: str


class SurveySimulationOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    survey_id: uuid.UUID
    survey_code: str
    survey_name: str
    version_id: uuid.UUID
    version_label: str
    content_sha256: str
    manifest_sha256: str
    facts: dict[str, Any]
    facts_sha256: str
    label: str
    created_at: datetime
    inputs: list[SurveySimulationInput]
    engine_contract: str = Field(description="The execution contract the simulation was recorded under.")
    current_engine_contract: str
    initial_run_sha256: str
    status: Literal["PENDING", "POLICY_UNRESOLVED", "TERMINAL", "REPLAY_DRIFT"] = Field(
        description="PENDING: a question needs an answer. POLICY_UNRESOLVED: the last input was a non-answer whose "
        "handling is an open business decision — a simulation status, never a business outcome. TERMINAL: the run ended. "
        "REPLAY_DRIFT: the run recomputed now is not the one recorded; the simulation takes no further input."
    )
    run_status: Literal["PENDING", "POLICY_UNRESOLVED", "TERMINAL"]
    drift: dict[str, Any] | None = Field(
        default=None, description="What differs when the recomputed run is not the recorded one."
    )
    run: dict[str, Any] = Field(
        description="The complete deterministic run: delivered items, decisions, routes, modules."
    )
    run_sha256: str
    replay_consistent: bool


class SurveyCallPlanCreateIn(BaseModel):
    facts: dict[str, Any] = Field(default_factory=dict)


class SurveyCallPlanOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    survey_id: uuid.UUID
    survey_code: str
    survey_name: str
    version_id: uuid.UUID
    version_label: str
    content_sha256: str
    manifest_sha256: str
    facts: dict[str, Any]
    facts_sha256: str
    created_at: datetime
    status: Literal["READY", "BLOCKED"] = Field(
        description="Whether a technical plan can be computed from these facts. It says nothing about whether a call may be made."
    )
    fingerprint: str
    fingerprint_verified: bool
    plan_contract: str
    current_plan_contract: str
    recomputed_fingerprint: str
    recompute_consistent: bool = Field(
        description="False when assembling the plan again now does not give the recorded plan."
    )
    plan: dict[str, Any]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(
        f"survey-sim:{auth.principal_id}", settings.survey_simulation_inputs_per_minute
    ):
        raise AppError(429, "RATE_LIMITED", "Too many simulation requests; try again shortly", retryable=True)


@router.post(
    "/survey-versions/{version_id}/simulations",
    response_model=SurveySimulationOut,
    status_code=201,
    operation_id="survey_simulation_create",
    responses=_ERR,
)
@csrf_protected
def survey_simulation_create(
    version_id: uuid.UUID,
    body: SurveySimulationCreateIn,
    request: Request,
    auth: AuthContext = Depends(require(SIMULATE)),
    db: Session = Depends(get_db),
) -> SurveySimulationOut:
    """Start an isolated simulation of a PUBLISHED version for one synthetic fact snapshot. The version's manifest is
    verified first. The simulation runs as far as the first question that needs an answer."""
    _write(request, auth)
    try:
        sim = simulation.create(
            db, version_id, _markets(auth), body.facts, body.label, auth.actor, request_meta(request)
        )
        db.commit()
        return SurveySimulationOut(**simulation.state(db, sim, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.post(
    "/survey-simulations/{simulation_id}/inputs",
    response_model=SurveySimulationOut,
    operation_id="survey_simulation_input",
    responses=_ERR,
)
@csrf_protected
def survey_simulation_input(
    simulation_id: uuid.UUID,
    body: SurveySimulationInputIn,
    request: Request,
    auth: AuthContext = Depends(require(SIMULATE)),
    db: Session = Depends(get_db),
) -> SurveySimulationOut:
    """Give one typed input to the question that is current. A rejected answer is recorded as refused with its stable
    code and the same question stays current. An input for another question, to an ended run or against a stale count
    is refused and nothing is recorded."""
    _write(request, auth)
    try:
        out = simulation.advance(
            db, simulation_id, _markets(auth), body.expected_inputs, body.key, body.answer, auth.actor,
            request_meta(request),
        )  # fmt: skip
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return SurveySimulationOut(**out)


@router.get(
    "/survey-simulations/{simulation_id}", response_model=SurveySimulationOut, operation_id="survey_simulation_get", responses=_ERR
)  # fmt: skip
def survey_simulation_get(
    simulation_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveySimulationOut:
    """The simulation's state and complete execution trace, replayed now from its recorded inputs."""
    try:
        return SurveySimulationOut(**simulation.state(db, simulation_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc


@router.post(
    "/survey-versions/{version_id}/call-plans",
    response_model=SurveyCallPlanOut,
    status_code=201,
    operation_id="survey_call_plan_create",
    responses=_ERR,
)
@csrf_protected
def survey_call_plan_create(
    version_id: uuid.UUID,
    body: SurveyCallPlanCreateIn,
    request: Request,
    auth: AuthContext = Depends(require(SIMULATE)),
    db: Session = Depends(get_db),
) -> SurveyCallPlanOut:
    """Assemble and record the deterministic call plan of a PUBLISHED version for one synthetic fact snapshot. A plan
    that can be computed is not an authorisation or eligibility for any call."""
    _write(request, auth)
    try:
        pid = simulation.create_plan(db, version_id, _markets(auth), body.facts, auth.actor, request_meta(request))
        db.commit()
        return SurveyCallPlanOut(**simulation.plan(db, pid, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.get(
    "/survey-call-plans/{plan_id}",
    response_model=SurveyCallPlanOut,
    operation_id="survey_call_plan_get",
    responses=_ERR,
)
def survey_call_plan_get(
    plan_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyCallPlanOut:
    try:
        return SurveyCallPlanOut(**simulation.plan(db, plan_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc
