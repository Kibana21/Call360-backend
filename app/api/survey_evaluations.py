# ruff: noqa: E501 — field descriptions are kept one per line
"""EVAL-1 — governed control mappings and journey-level control evaluation of SYNTHETIC simulations. Ten operations.

Registered ONLY when ``survey_evaluation_enabled`` (with survey definitions and simulation) is on; off by default.

Permissions (migration 0033, granted to no role). Reading the control register as it relates to surveys, a mapping
or an evaluation needs **``survey.evaluation.read``**. Evaluating a journey needs **``survey.evaluate``** as well.
Proposing a mapping needs ``survey.edit``; deciding it ``survey.approve``; publishing it ``survey.publish`` — and
proposer, approver and publisher must be three different people whatever they hold. Everything is market-scoped; the
state-changing operations are CSRF-protected, rate-limited and audited.

Every evaluation carries ``record_class: SIMULATION``. Nothing here evaluates a real call, writes an operational
finding, routes a review or gives a case a disposition, and no model is asked for a judgement: answers are judged by
the existing deterministic evaluator and findings come from the published finding rule set.
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
from app.core.errors import AppError
from app.domain.survey import control_evaluation as ce
from app.domain.survey import control_mapping as cm
from app.domain.survey import journey_evaluation as je
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-evaluation", tags=["survey-evaluation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ = "survey.evaluation.read"
EVALUATE = "survey.evaluate"


class SurveyControlMappingRef(BaseModel):
    id: uuid.UUID
    market_code: str
    revision: int
    status: str | None = None


class SurveyControl(BaseModel):
    id: uuid.UUID
    control_code: str
    name: str
    owner_role: str
    content_approval_status: str
    control_sha256: str = Field(
        description="The register has no revisions: the fingerprint of the control as it is now."
    )
    published: list[SurveyControlMappingRef]
    open: list[SurveyControlMappingRef]


class SurveyControlRegister(BaseModel):
    items: list[SurveyControl]
    combinations: list[str] = Field(
        description="The evidence combinations a mapping may declare. Nothing else has an approved meaning."
    )
    evidence_types: list[str]
    note: str


class SurveyControlMappingEvent(BaseModel):
    seq: int
    event: str
    actor_ref: str
    display_name: str | None = None
    comment: str
    occurred_at: datetime


class SurveyControlMapping(BaseModel):
    id: uuid.UUID
    market_code: str
    control_id: uuid.UUID
    control_code: str
    control_name: str
    control_sha256: str
    revision: int
    combination: str
    applicability: dict[str, Any] | None = Field(
        description="None: declared for every journey of the market. Otherwise a published condition, its parameters and its fingerprint."
    )
    entries: list[dict[str, Any]] = Field(
        description="Each: the exact item (code, version, fingerprint), ANSWER or DELIVERY evidence, whether it is required, an optional survey context, and the rule in the existing rule language."
    )
    source: str
    mapping_sha256: str
    status: Literal["PROPOSED", "APPROVED", "REJECTED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED"]
    proposed_by: str
    proposed_at: datetime
    approved_by: str | None = None
    published_by: str | None = None
    is_proposer: bool
    is_approver: bool
    history: list[SurveyControlMappingEvent] = []


class SurveyControlMappingList(BaseModel):
    items: list[SurveyControlMapping]


class SurveyControlMappingIn(BaseModel):
    market_code: str = Field(min_length=2, max_length=40)
    control_code: str = Field(min_length=1, max_length=40)
    combination: str = Field(max_length=24)
    applicability: dict[str, Any] | None = None
    entries: list[dict[str, Any]] = Field(max_length=50)
    source: str = Field(max_length=2000)


class SurveyControlMappingDecisionIn(BaseModel):
    verdict: Literal["APPROVE", "REJECT"]
    comment: str = Field(default="", max_length=2000)


class SurveyControlMappingWithdrawIn(BaseModel):
    reason: str = Field(max_length=2000)


class SurveyJourneyEvaluationIn(BaseModel):
    simulation_id: uuid.UUID | None = None
    coordinated_simulation_id: uuid.UUID | None = None
    control_policy_id: uuid.UUID | None = Field(
        default=None,
        description="EVAL-2A: a PUBLISHED control policy revision to evaluate under. Without one the evaluation is the EVAL-1 one and coverage is not asserted.",
    )


class SurveyJourneyEvaluationOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    contract: str
    market_code: str
    created_at: datetime
    created_by: str
    journey_kind: Literal["SINGLE_SURVEY", "COORDINATED"]
    simulation_id: uuid.UUID | None
    coordinated_id: uuid.UUID | None
    journey: dict[str, Any] = Field(
        description="The journey as evaluated: its status, whether every survey completed, whether its evidence was trusted, and each survey execution."
    )
    processing_status: Literal["COMPLETED", "INCOMPLETE", "REQUIRES_REVIEW", "FAILED_TECHNICALLY"] = Field(
        description="How the EVALUATION ended — not whether surveys completed and not whether controls are satisfied. COMPLETED does not mean compliant."
    )
    status: Literal["COMPLETED", "INCOMPLETE", "REQUIRES_REVIEW", "FAILED_TECHNICALLY", "EVALUATION_DRIFT"] = Field(
        description="The processing status, or EVALUATION_DRIFT when the evaluation no longer recomputes from what it pinned."
    )
    summary: dict[str, Any]
    coverage: dict[str, Any] = Field(
        description="Always NOT_ASSERTED: controls without a mapping, with unknown applicability, and items no mapping names."
    )
    finding_rules: dict[str, Any] | None
    findings_status: Literal["GENERATED", "FINDING_RULES_MISSING", "NOT_GENERATED_EVIDENCE_NOT_TRUSTED"]
    engines: dict[str, str]
    controls: list[dict[str, Any]] = Field(
        description="One control instance per control of the register: outcome, applicability, reasons, pinned mapping revision and every evidence observation."
    )
    findings: list[dict[str, Any]]
    not_converted: list[dict[str, Any]]
    human_assessment: list[dict[str, Any]]
    pins: dict[str, Any]
    input_sha256: str
    result_sha256: str
    replay: dict[str, Any]
    superseded_by_current_governance: list[dict[str, Any]] = Field(
        description="What is published now that this evaluation did not use. Evaluating again gives a NEW evaluation; this one is not rewritten."
    )
    control_policy_id: uuid.UUID | None = None
    policy: dict[str, Any] | None = Field(
        default=None, description="The control policy revision this evaluation was made under, if any."
    )
    applicability: dict[str, Any] | None = Field(
        default=None, description="Policy scope, missing inputs, lineage and the applicability fingerprint."
    )
    operational_compliance_eligibility: dict[str, Any] = Field(description="Always NOT_ESTABLISHED.")


class SurveyJourneyEvaluationRef(BaseModel):
    id: uuid.UUID
    journey_kind: str
    processing_status: str
    input_sha256: str
    result_sha256: str
    created_at: datetime
    created_by: str
    summary: dict[str, Any]
    policy: dict[str, Any] | None = None
    coverage_status: str | None = None


class SurveyJourneyEvaluationList(BaseModel):
    items: list[SurveyJourneyEvaluationRef]


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
        f"survey-eval:{auth.principal_id}", settings.survey_simulation_inputs_per_minute
    ):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _mapping_out(m: dict[str, Any], auth: AuthContext) -> SurveyControlMapping:
    me = str(auth.principal_id)
    return SurveyControlMapping(
        **{**m, "is_proposer": m["proposed_by"] == me, "is_approver": m.get("approved_by") == me}
    )


@router.get(
    "/controls", response_model=SurveyControlRegister, operation_id="survey_evaluation_controls", responses=_ERR
)
def survey_evaluation_controls(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyControlRegister:
    """The existing control register with, per control, the mapping revisions of the caller's markets."""
    return SurveyControlRegister(
        items=[SurveyControl(**c) for c in cm.register(db, _markets(auth))], combinations=list(ce.COMBINATIONS),
        evidence_types=list(ce.EVIDENCE_TYPES), note=ce.COVERAGE_NOTE,
    )  # fmt: skip


@router.get(
    "/mappings", response_model=SurveyControlMappingList, operation_id="survey_control_mapping_list", responses=_ERR
)
def survey_control_mapping_list(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyControlMappingList:
    """Every mapping revision of the caller's markets, whatever its status."""
    return SurveyControlMappingList(items=[_mapping_out(m, auth) for m in cm.mappings(db, _markets(auth))])


@router.get(
    "/mappings/{mapping_id}",
    response_model=SurveyControlMapping,
    operation_id="survey_control_mapping_get",
    responses=_ERR,
)
def survey_control_mapping_get(
    mapping_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyControlMapping:
    try:
        return _mapping_out(cm.mapping(db, mapping_id, _markets(auth)), auth)
    except SurveyError as exc:
        raise _err(exc) from exc


def _act(db: Session, auth: AuthContext, mapping_id: uuid.UUID, work: Any) -> SurveyControlMapping:
    try:
        work()
        db.commit()
    except SurveyError as exc:
        # a refusal by an identity rule is itself audited: keep that record
        if exc.status == 403:
            db.commit()
        else:
            db.rollback()
        raise _err(exc) from exc
    return _mapping_out(cm.mapping(db, mapping_id, _markets(auth)), auth)


@router.post(
    "/mappings",
    response_model=SurveyControlMapping,
    status_code=201,
    operation_id="survey_control_mapping_propose",
    responses=_ERR,
)
@csrf_protected
def survey_control_mapping_propose(
    body: SurveyControlMappingIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.edit")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlMapping:
    """Propose a new revision of the mapping of one control: exact published items, the evidence each gives, the rule
    of the existing rule language for an answer, how the evidence combines, and when the control applies."""
    _write(request, auth)
    try:
        mid = cm.propose(
            db, _markets(auth), body.market_code, body.control_code, body.combination, body.applicability, body.entries,
            body.source, auth.actor, request_meta(request),
        )  # fmt: skip
        db.commit()
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    return _mapping_out(cm.mapping(db, mid, _markets(auth)), auth)


@router.post(
    "/mappings/{mapping_id}/decision",
    response_model=SurveyControlMapping,
    operation_id="survey_control_mapping_decide",
    responses=_ERR,
)
@csrf_protected
def survey_control_mapping_decide(
    mapping_id: uuid.UUID,
    body: SurveyControlMappingDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.approve")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlMapping:
    """Approve or reject a proposed mapping. Never by its proposer."""
    _write(request, auth)
    return _act(
        db,
        auth,
        mapping_id,
        lambda: cm.decide(
            db, mapping_id, _markets(auth), body.verdict, body.comment, auth.actor, request_meta(request)
        ),
    )


@router.post(
    "/mappings/{mapping_id}/publish",
    response_model=SurveyControlMapping,
    operation_id="survey_control_mapping_publish",
    responses=_ERR,
)
@csrf_protected
def survey_control_mapping_publish(
    mapping_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("survey.publish")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlMapping:
    """Publish an approved mapping: a third person. The previous published revision of the control is superseded."""
    _write(request, auth)
    return _act(
        db, auth, mapping_id, lambda: cm.publish(db, mapping_id, _markets(auth), auth.actor, request_meta(request))
    )


@router.post(
    "/mappings/{mapping_id}/withdraw",
    response_model=SurveyControlMapping,
    operation_id="survey_control_mapping_withdraw",
    responses=_ERR,
)
@csrf_protected
def survey_control_mapping_withdraw(
    mapping_id: uuid.UUID,
    body: SurveyControlMappingWithdrawIn,
    request: Request,
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlMapping:
    """Withdraw an open proposal (its proposer) or a published mapping (a person who may publish)."""
    _write(request, auth)
    return _act(
        db, auth, mapping_id,
        lambda: cm.withdraw(db, mapping_id, _markets(auth), body.reason, auth.actor, "survey.publish" in auth.permissions, request_meta(request)),
    )  # fmt: skip


@router.post(
    "/evaluations",
    response_model=SurveyJourneyEvaluationOut,
    status_code=201,
    operation_id="survey_journey_evaluation_create",
    responses={**_ERR, 200: {"model": SurveyJourneyEvaluationOut}},
)
@csrf_protected
def survey_journey_evaluation_create(
    body: SurveyJourneyEvaluationIn,
    request: Request,
    response: Response,
    auth: AuthContext = Depends(require(EVALUATE)),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyJourneyEvaluationOut:
    """Evaluate one synthetic journey — a simulation or a coordinated simulation — as it stands, against the mappings
    and the finding rule set published now. 201 for a new evaluation; 200 with the existing one when nothing it would
    be computed from has changed."""
    _write(request, auth)
    try:
        eid, created = je.create(
            db,
            _markets(auth),
            body.simulation_id,
            body.coordinated_simulation_id,
            auth.actor,
            request_meta(request),
            policy_id=body.control_policy_id,
            policy_schema=bool(request.app.state.settings.survey_control_policy_enabled),
        )
        db.commit()
        out = je.get(db, eid, _markets(auth))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    if not created:
        response.status_code = 200
    return SurveyJourneyEvaluationOut(**out)


@router.get(
    "/evaluations",
    response_model=SurveyJourneyEvaluationList,
    operation_id="survey_journey_evaluation_list",
    responses=_ERR,
)
def survey_journey_evaluation_list(
    simulation_id: uuid.UUID | None = Query(default=None),
    coordinated_simulation_id: uuid.UUID | None = Query(default=None),
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyJourneyEvaluationList:
    """Every evaluation of one journey, oldest first. A revised rule or mapping adds one; none is rewritten."""
    try:
        return SurveyJourneyEvaluationList(
            items=[
                SurveyJourneyEvaluationRef(**r)
                for r in je.for_journey(db, _markets(auth), simulation_id, coordinated_simulation_id)
            ]
        )
    except SurveyError as exc:
        raise _err(exc) from exc


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=SurveyJourneyEvaluationOut,
    operation_id="survey_journey_evaluation_get",
    responses=_ERR,
)
def survey_journey_evaluation_get(
    evaluation_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyJourneyEvaluationOut:
    """The evaluation as recorded, computed again now from what it pinned (drift is reported, never hidden)."""
    try:
        return SurveyJourneyEvaluationOut(**je.get(db, evaluation_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc
