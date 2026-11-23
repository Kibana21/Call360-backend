# ruff: noqa: E501 — field descriptions are kept one per line
"""ASG-1 — survey selection by the existing governed assignment rules, for SYNTHETIC applications. Nine operations.

Registered ONLY when ``survey_assignment_enabled`` (with survey definitions and simulation) is on; off by default.
Nothing here assigns a survey to a customer case, and nothing touches the Script Studio assignment of scripts.

Permissions. Reading the policy, the governed inputs, a binding or a selection needs **``survey.assignment.read``** —
a permission of its own (migration 0030, granted to no role), because the policy shows the conditions and precedence
of published assignment rules: ``survey.read`` alone must not open Script Studio's rule data. Proposing a binding
needs ``survey.edit``; deciding it ``survey.approve``; publishing it ``survey.publish``; making a selection and
starting a simulation from it ``survey.simulate``. Proposer, approver and publisher must be three different people
whatever they hold. Everything is market-scoped, and only what the survey assignment experience needs is returned:
no script target, no rule author or checker, no draft, no rule history. The Assignment Rules API and its
``script.*`` permissions are unchanged.
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
from app.api.survey_simulations import SurveyCallPlanOut, SurveySimulationOut
from app.core.errors import AppError
from app.domain.survey import assignment, simulation
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-assignment", tags=["survey-assignment"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ = "survey.assignment.read"


class SurveyAssignmentRule(BaseModel):
    ref: str
    rule_code: str
    rule_version: int | None
    rule_version_id: uuid.UUID | None
    name: str
    market_code: str | None
    priority: int
    specificity: int
    is_fallback: bool
    effective_now: bool
    effective_from: datetime | None
    effective_to: datetime | None
    when: list[str]
    target_kind: Literal["SCRIPT_VERSION", "SURVEY_BINDING"] = Field(
        default="SCRIPT_VERSION",
        description="SHARED-1: SURVEY_BINDING = the rule names no script; it selects a survey only through a binding.",
    )
    published_binding: uuid.UUID | None
    open_binding: uuid.UUID | None


class SurveyAssignmentBindingEvent(BaseModel):
    seq: int
    event: str
    actor_ref: str
    display_name: str | None = None
    comment: str
    occurred_at: datetime


class SurveyAssignmentBinding(BaseModel):
    id: uuid.UUID
    rule_version_id: uuid.UUID
    rule_code: str
    rule_version: int
    market_code: str
    survey_version_id: uuid.UUID
    survey_definition_id: uuid.UUID
    survey_code: str
    survey_name: str
    version_label: str
    survey_version_status: str | None
    content_sha256: str
    manifest_sha256: str
    note: str
    status: Literal["PROPOSED", "APPROVED", "REJECTED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED"]
    proposed_by: str
    proposed_at: datetime
    approved_by: str | None = None
    published_by: str | None = None
    history: list[SurveyAssignmentBindingEvent] = Field(default_factory=list)
    is_proposer: bool = False
    is_approver: bool = False


class SurveyAssignmentPolicy(BaseModel):
    rules: list[SurveyAssignmentRule]
    bindings: list[SurveyAssignmentBinding]
    engine: str
    note: str


class SurveyAssignmentOptions(BaseModel):
    fields: list[dict[str, Any]]


class SurveyAssignmentBindingIn(BaseModel):
    rule_code: str = Field(min_length=1, max_length=40)
    rule_version: int = Field(ge=1)
    survey_version_id: uuid.UUID
    note: str = Field(default="", max_length=2000)


class SurveyAssignmentDecisionIn(BaseModel):
    verdict: Literal["APPROVE", "REJECT"]
    comment: str = Field(default="", max_length=2000)


class SurveyAssignmentWithdrawIn(BaseModel):
    reason: str = Field(max_length=2000)


class SurveyAssignmentEvaluationIn(BaseModel):
    assignment_inputs: dict[str, Any] = Field(
        description="The fields of the existing assignment rules, with governed values. Absent or null = unknown."
    )
    facts: dict[str, Any] = Field(
        default_factory=dict,
        description="The synthetic application's facts for the call plan: governed catalog fields.",
    )


class SurveyAssignmentEvaluationOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    market_code: str
    assignment_inputs: dict[str, Any]
    facts: dict[str, Any]
    inputs_sha256: str
    evaluated_at: datetime
    created_at: datetime
    engine: str
    outcome: str = Field(
        description="The existing engine's outcome, or SURVEY_NOT_BOUND when the winning rule has no published survey binding."
    )
    selection: Literal["MATCHED", "NO_MATCH", "AMBIGUOUS", "UNKNOWN_INPUT", "TARGET_UNAVAILABLE"]
    decision: dict[str, Any] = Field(
        description="Reason, winning rules, missing inputs, the selected version and the complete trace of every rule."
    )
    decision_sha256: str
    recomputed_decision_sha256: str
    recompute_consistent: bool
    survey_version_id: uuid.UUID | None
    binding_id: uuid.UUID | None
    call_plan_id: uuid.UUID | None
    plan_fingerprint: str | None
    call_plan: SurveyCallPlanOut | None = Field(
        description="The SS-03B plan of the selected version. Whether a plan can be computed is not whether a call may be made."
    )
    simulations: list[uuid.UUID]


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
        f"survey-asg:{auth.principal_id}", settings.survey_simulation_inputs_per_minute
    ):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _binding_out(b: dict[str, Any], auth: AuthContext) -> SurveyAssignmentBinding:
    me = str(auth.principal_id)
    return SurveyAssignmentBinding(
        **{**b, "is_proposer": b["proposed_by"] == me, "is_approver": b.get("approved_by") == me}
    )


@router.get(
    "/options", response_model=SurveyAssignmentOptions, operation_id="survey_assignment_options", responses=_ERR
)
def survey_assignment_options(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyAssignmentOptions:
    """The governed assignment inputs and their values: the fields of the existing assignment rules."""
    return SurveyAssignmentOptions(fields=assignment.options(db, _markets(auth))["fields"])


@router.get("/policy", response_model=SurveyAssignmentPolicy, operation_id="survey_assignment_policy", responses=_ERR)
def survey_assignment_policy(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyAssignmentPolicy:
    """The published assignment rules in precedence order, each with the survey version bound to it, and every binding."""
    p = assignment.policy(db, _markets(auth))
    return SurveyAssignmentPolicy(
        rules=p["rules"], bindings=[_binding_out(b, auth) for b in p["bindings"]], engine=p["engine"], note=p["note"]
    )


@router.get(
    "/bindings/{binding_id}",
    response_model=SurveyAssignmentBinding,
    operation_id="survey_assignment_binding_get",
    responses=_ERR,
)
def survey_assignment_binding_get(
    binding_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyAssignmentBinding:
    try:
        return _binding_out(assignment.binding(db, binding_id, _markets(auth)), auth)
    except SurveyError as exc:
        raise _err(exc) from exc


@router.post(
    "/bindings",
    response_model=SurveyAssignmentBinding,
    status_code=201,
    operation_id="survey_assignment_binding_propose",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_binding_propose(
    body: SurveyAssignmentBindingIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.edit")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentBinding:
    """Propose that an exact published rule version stands for an exact published survey version of the same market."""
    _write(request, auth)
    try:
        bid = assignment.propose(
            db,
            _markets(auth),
            body.rule_code,
            body.rule_version,
            body.survey_version_id,
            body.note,
            auth.actor,
            request_meta(request),
        )
        db.commit()
        return _binding_out(assignment.binding(db, bid, _markets(auth)), auth)
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


def _act(db: Session, auth: AuthContext, binding_id: uuid.UUID, work: Any) -> SurveyAssignmentBinding:
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
    return _binding_out(assignment.binding(db, binding_id, _markets(auth)), auth)


@router.post(
    "/bindings/{binding_id}/decision",
    response_model=SurveyAssignmentBinding,
    operation_id="survey_assignment_binding_decide",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_binding_decide(
    binding_id: uuid.UUID,
    body: SurveyAssignmentDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.approve")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentBinding:
    """Approve or reject a proposed binding. Never by its proposer."""
    _write(request, auth)
    return _act(
        db,
        auth,
        binding_id,
        lambda: assignment.decide(
            db, binding_id, _markets(auth), body.verdict, body.comment, auth.actor, request_meta(request)
        ),
    )


@router.post(
    "/bindings/{binding_id}/publish",
    response_model=SurveyAssignmentBinding,
    operation_id="survey_assignment_binding_publish",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_binding_publish(
    binding_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("survey.publish")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentBinding:
    """Publish an approved binding. Never by its proposer or its approver. An earlier published binding of the same rule version is superseded."""
    _write(request, auth)
    return _act(
        db,
        auth,
        binding_id,
        lambda: assignment.publish(db, binding_id, _markets(auth), auth.actor, request_meta(request)),
    )


@router.post(
    "/bindings/{binding_id}/withdraw",
    response_model=SurveyAssignmentBinding,
    operation_id="survey_assignment_binding_withdraw",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_binding_withdraw(
    binding_id: uuid.UUID,
    body: SurveyAssignmentWithdrawIn,
    request: Request,
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentBinding:
    """Withdraw an open proposal (its proposer) or a published binding (a person who may publish)."""
    _write(request, auth)
    return _act(
        db, auth, binding_id,
        lambda: assignment.withdraw(db, binding_id, _markets(auth), body.reason, auth.actor, "survey.publish" in auth.permissions, request_meta(request)),
    )  # fmt: skip


@router.post(
    "/evaluations",
    response_model=SurveyAssignmentEvaluationOut,
    status_code=201,
    operation_id="survey_assignment_evaluate",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_evaluate(
    body: SurveyAssignmentEvaluationIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.simulate")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentEvaluationOut:
    """For one synthetic application: decide with the existing assignment rules which published survey version is
    selected, verify its manifest, assemble its call plan, and record all of it as a simulation record. A selection
    assigns nothing to any customer case."""
    _write(request, auth)
    try:
        eid = assignment.evaluate(
            db, _markets(auth), body.assignment_inputs, body.facts, auth.actor, request_meta(request)
        )
        db.commit()
        return SurveyAssignmentEvaluationOut(**assignment.evaluation(db, eid, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=SurveyAssignmentEvaluationOut,
    operation_id="survey_assignment_evaluation_get",
    responses=_ERR,
)
def survey_assignment_evaluation_get(
    evaluation_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyAssignmentEvaluationOut:
    """A recorded selection with its decision trace, its plan and the simulations started from it."""
    try:
        return SurveyAssignmentEvaluationOut(**assignment.evaluation(db, evaluation_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc


@router.post(
    "/evaluations/{evaluation_id}/simulations",
    response_model=SurveySimulationOut,
    status_code=201,
    operation_id="survey_assignment_simulate",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_simulate(
    evaluation_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("survey.simulate")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveySimulationOut:
    """Start a server simulation of the selected version with the same facts, linked to the selection."""
    _write(request, auth)
    try:
        sim = assignment.start_simulation(db, evaluation_id, _markets(auth), auth.actor, request_meta(request))
        db.commit()
        return SurveySimulationOut(**simulation.state(db, sim, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
