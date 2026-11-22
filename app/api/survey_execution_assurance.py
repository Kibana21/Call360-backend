# ruff: noqa: E501 — field descriptions are kept one per line
"""EVAL-2B — execution assurance of SYNTHETIC journeys. Three operations.

Registered ONLY when ``survey_execution_assurance_enabled`` (with evaluation and everything it needs) is on; off by
default. Reading needs ``survey.evaluation.read``; verifying a journey needs ``survey.evaluate`` as well — the two
permissions of EVAL-1, held by no role unless given. Market-scoped; the one state-changing operation is
CSRF-protected, rate-limited and audited.

An assurance result says whether the RECORDED execution of a simulated journey followed the survey versions it
pinned. It is not a control outcome, not coverage, not a compliance outcome, and it never establishes operational
call eligibility. A simulation does not show that a person heard any wording.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import ErrorResponse
from app.api.survey_evaluations import EVALUATE, READ, _err, _markets, _write
from app.domain.survey import assurance
from app.domain.survey.store import SurveyError
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-evaluation", tags=["survey-evaluation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
Status = Literal["VERIFIED", "INCOMPLETE", "DEVIATION_DETECTED", "INTEGRITY_FAILED", "NOT_ASSESSABLE"]


class SurveyExecutionAssuranceIn(BaseModel):
    simulation_id: uuid.UUID | None = None
    coordinated_simulation_id: uuid.UUID | None = None
    evaluation_id: uuid.UUID | None = Field(
        default=None,
        description="A control evaluation of the SAME journey to show beside the result. Its outcomes are copied as recorded, never computed again.",
    )


class SurveyExecutionAssuranceOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    contract: str
    execution_contract: str
    market_code: str
    created_at: datetime
    created_by: str
    journey_kind: Literal["SINGLE_SURVEY", "COORDINATED"]
    simulation_id: uuid.UUID | None
    coordinated_id: uuid.UUID | None
    evaluation_id: uuid.UUID | None
    journey: dict[str, Any]
    status: Status = Field(
        description="VERIFIED: the supported checks passed for the recording. INCOMPLETE: the evidence does not let every check finish. DEVIATION_DETECTED: the recording differs from what it pinned. INTEGRITY_FAILED: replay or fingerprints failed. NOT_ASSESSABLE: a contract is not supported. Technical statuses, not compliance outcomes."
    )
    current_status: Literal[
        "VERIFIED", "INCOMPLETE", "DEVIATION_DETECTED", "INTEGRITY_FAILED", "NOT_ASSESSABLE", "ASSURANCE_DRIFT"
    ] = Field(
        description="The recorded status, or ASSURANCE_DRIFT when the result no longer recomputes from the evidence as it stands."
    )
    summary: dict[str, Any]
    surveys: list[dict[str, Any]] = Field(
        description="Each survey execution: status, every check with its question and findings, every delivery with its pinned wording, every placement that was not delivered and why, branches, refusals, the ending."
    )
    journey_checks: list[dict[str, Any]] = Field(
        description="Coordinated journeys: selection, governed order, no bypass, own evidence, no de-duplication."
    )
    findings: list[dict[str, Any]]
    control_evaluation: dict[str, Any] | None = None
    control_evidence: list[dict[str, Any]] = Field(
        description="The named control evaluation's results, as recorded, each beside what was verified about the execution evidence it rests on."
    )
    pins: dict[str, Any]
    input_sha256: str
    result_sha256: str
    replay: dict[str, Any]
    operational_call_eligibility: dict[str, Any] = Field(description="Always NOT_ESTABLISHED.")


class SurveyExecutionAssuranceRef(BaseModel):
    id: uuid.UUID
    journey_kind: str
    status: str
    evaluation_id: uuid.UUID | None
    input_sha256: str
    result_sha256: str
    created_at: datetime
    created_by: str
    summary: dict[str, Any]


class SurveyExecutionAssuranceList(BaseModel):
    items: list[SurveyExecutionAssuranceRef]


@router.post(
    "/assurance",
    response_model=SurveyExecutionAssuranceOut,
    status_code=201,
    operation_id="survey_execution_assurance_create",
    responses={**_ERR, 200: {"model": SurveyExecutionAssuranceOut}},
)
@csrf_protected
def survey_execution_assurance_create(
    body: SurveyExecutionAssuranceIn,
    request: Request,
    response: Response,
    auth: AuthContext = Depends(require(EVALUATE)),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyExecutionAssuranceOut:
    """Verify the recorded execution of one synthetic journey against the survey versions it pinned. 201 for a new
    result; 200 with the existing one when nothing it would be computed from has changed."""
    _write(request, auth)
    try:
        aid, created = assurance.create(
            db,
            _markets(auth),
            body.simulation_id,
            body.coordinated_simulation_id,
            body.evaluation_id,
            auth.actor,
            request_meta(request),
        )
        db.commit()
        out = assurance.get(db, aid, _markets(auth))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    if not created:
        response.status_code = 200
    return SurveyExecutionAssuranceOut(**out)


@router.get(
    "/assurance",
    response_model=SurveyExecutionAssuranceList,
    operation_id="survey_execution_assurance_list",
    responses=_ERR,
)
def survey_execution_assurance_list(
    simulation_id: uuid.UUID | None = Query(default=None),
    coordinated_simulation_id: uuid.UUID | None = Query(default=None),
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyExecutionAssuranceList:
    """Every assurance result of one journey, oldest first. New evidence adds one; none is rewritten."""
    try:
        return SurveyExecutionAssuranceList(
            items=[
                SurveyExecutionAssuranceRef(**r)
                for r in assurance.for_journey(db, _markets(auth), simulation_id, coordinated_simulation_id)
            ]
        )
    except SurveyError as exc:
        raise _err(exc) from exc


@router.get(
    "/assurance/{assurance_id}",
    response_model=SurveyExecutionAssuranceOut,
    operation_id="survey_execution_assurance_get",
    responses=_ERR,
)
def survey_execution_assurance_get(
    assurance_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyExecutionAssuranceOut:
    """The result as recorded, computed again now from the evidence as it stands (drift is reported, never hidden)."""
    try:
        return SurveyExecutionAssuranceOut(**assurance.get(db, assurance_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc
