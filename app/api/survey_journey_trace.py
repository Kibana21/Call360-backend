# ruff: noqa: E501 — field descriptions are kept one per line
"""E2E-1 — the provenance of one SYNTHETIC journey, from the application to its execution assurance. One operation.

READ ONLY: no table, no write, no audit event of its own beyond access control. Registered with execution assurance
(so only when simulation, evaluation and assurance are on); off by default. Needs ``survey.evaluation.read``. The
links that show how surveys were ASSIGNED are withheld from a reader without ``survey.assignment.read``.
Market-scoped by the services it reads through.

It lays out records other services keep. It computes no control outcome, no coverage, no finding and no assurance
result, and it never establishes operational call eligibility.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.schemas import ErrorResponse
from app.api.survey_evaluations import READ, _err, _markets
from app.domain.survey import journey_trace
from app.domain.survey.store import SurveyError
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1/survey-evaluation", tags=["survey-evaluation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422)}
ASSIGNMENT_READ = "survey.assignment.read"


class SurveyJourneyTraceLink(BaseModel):
    step: int
    key: str
    title: str
    status: Literal[
        "RECORDED", "NOT_RECORDED_YET", "NOT_PART_OF_THIS_JOURNEY", "NONE", "NONE_SELECTED", "WITHHELD", "NOT_AVAILABLE"
    ]
    records: list[dict[str, Any]] = Field(
        description="Each: kind, id, label, version, sha256, sha256_of, source, facts."
    )
    notes: list[str]


class SurveyJourneyTraceOut(BaseModel):
    record_class: Literal["SIMULATION"]
    note: str
    contract: str
    market_code: str
    journey: dict[str, Any] = Field(
        description="kind: SINGLE_SURVEY, COORDINATED, or APPLICATION_ONLY (a composite plan whose journey never started)."
    )
    evaluation_id: uuid.UUID | None
    assurance_id: uuid.UUID | None
    evaluations: list[dict[str, Any]]
    assurances: list[dict[str, Any]]
    dimensions: dict[str, Any] = Field(
        description="Five separate statements: completion, satisfaction, coverage, assurance, eligibility. None is derived from another; eligibility is always NOT_ESTABLISHED."
    )
    questions: list[dict[str, Any]]
    chain: list[SurveyJourneyTraceLink]
    evidence_gaps: list[dict[str, Any]] = Field(
        description="The shown evaluation's own control results whose evidence is missing, contradictory or undecided. Recorded results, filtered; nothing is computed here."
    )
    integrity: dict[str, Any]
    open_points: list[dict[str, str]] = Field(
        description="What is unverified or undecided for this journey, stated once."
    )
    trace_sha256: str = Field(
        description="SHA-256 over the kind, id and fingerprint of every record in the chain, in order."
    )
    operational_call_eligibility: dict[str, Any] = Field(description="Always NOT_ESTABLISHED.")


@router.get(
    "/journey-trace", response_model=SurveyJourneyTraceOut, operation_id="survey_journey_trace_get", responses=_ERR
)
def survey_journey_trace_get(
    simulation_id: uuid.UUID | None = Query(default=None),
    coordinated_simulation_id: uuid.UUID | None = Query(default=None),
    composite_plan_id: uuid.UUID | None = Query(
        default=None, description="An application whose journey never started. Needs survey.assignment.read."
    ),
    evaluation_id: uuid.UUID | None = Query(default=None, description="Default: the latest evaluation of the journey."),
    assurance_id: uuid.UUID | None = Query(
        default=None, description="Default: the latest assurance result beside that evaluation."
    ),
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyJourneyTraceOut:
    """One journey's records as one chain, each with its version, fingerprint and source. Read-only."""
    may_read_assignment = ASSIGNMENT_READ in auth.permissions
    try:
        if composite_plan_id is not None and not may_read_assignment:
            raise SurveyError(403, "FORBIDDEN", "Reading a composite plan needs the survey assignment read permission")
        return SurveyJourneyTraceOut(
            **journey_trace.trace(
                db, _markets(auth),
                simulation_id=simulation_id, coordinated_id=coordinated_simulation_id, composite_plan_id=composite_plan_id,
                evaluation_id=evaluation_id, assurance_id=assurance_id, with_assignment=may_read_assignment,
            )
        )  # fmt: skip
    except SurveyError as exc:
        raise _err(exc) from exc
