# ruff: noqa: E501 — field descriptions are kept one per line
"""ASG-2A — requirement groups and composite plans: one SYNTHETIC application, several surveys. Seven operations.

Registered ONLY when ``survey_assignment_groups_enabled`` (with assignment, simulation and survey definitions) is on;
off by default. Permissions are those of ASG-1: every operation needs ``survey.assignment.read``; proposing a group
also ``survey.edit``, deciding ``survey.approve``, publishing ``survey.publish``, generating a composite plan
``survey.simulate``. Proposer, approver and publisher are three different people. Everything is market-scoped.
Nothing here assigns a survey to a customer case; the ASG-1 operations are unchanged.
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
from app.api.survey_assignments import (
    READ,
    SurveyAssignmentBindingEvent,
    SurveyAssignmentDecisionIn,
    SurveyAssignmentWithdrawIn,
    _write,
)
from app.core.errors import AppError
from app.domain.survey import assignment_groups as ag
from app.domain.survey.store import SurveyError
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-assignment", tags=["survey-assignment"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
Kind = Literal["PRIMARY", "ADD_REQUIRED", "ALTERNATIVE"]


class SurveyAssignmentGroupMember(BaseModel):
    rule_version_id: uuid.UUID
    rule_code: str
    rule_version: int
    rule_status: str


class SurveyAssignmentGroup(BaseModel):
    id: uuid.UUID
    code: str
    version: int
    market_code: str
    kind: Kind
    name: str
    purpose: str
    sequence: int | None = Field(
        description="The group's position in a governed ordering; null when none was governed."
    )
    note: str
    status: Literal["PROPOSED", "APPROVED", "REJECTED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED"]
    proposed_by: str
    proposed_at: datetime
    approved_by: str | None = None
    members: list[SurveyAssignmentGroupMember]
    history: list[SurveyAssignmentBindingEvent] = Field(default_factory=list)
    is_proposer: bool = False
    is_approver: bool = False


class SurveyAssignmentGroups(BaseModel):
    groups: list[SurveyAssignmentGroup]
    note: str


class SurveyAssignmentGroupMemberIn(BaseModel):
    rule_code: str = Field(min_length=1, max_length=40)
    rule_version: int = Field(ge=1)


class SurveyAssignmentGroupIn(BaseModel):
    code: str = Field(min_length=3, max_length=40)
    kind: Kind
    name: str = Field(min_length=3, max_length=160)
    purpose: str = Field(
        min_length=10, max_length=2000, description="Which survey requirement this group stands for, in words."
    )
    sequence: int | None = Field(default=None, ge=1)
    members: list[SurveyAssignmentGroupMemberIn] = Field(min_length=1, max_length=50)
    note: str = Field(default="", max_length=2000)


class SurveyCompositePlanIn(BaseModel):
    assignment_inputs: dict[str, Any]
    facts: dict[str, Any] = Field(default_factory=dict)


class SurveyCompositePlanMember(BaseModel):
    position: int
    group_id: uuid.UUID
    kind: str
    state: Literal["SELECTED", "NOT_APPLICABLE", "UNRESOLVED"]
    outcome: str
    rule_version_id: uuid.UUID | None
    binding_id: uuid.UUID | None
    survey_version_id: uuid.UUID | None
    call_plan_id: uuid.UUID | None
    plan_fingerprint: str | None
    plan_intact: bool


class SurveyCompositePlanOut(BaseModel):
    id: uuid.UUID
    record_class: Literal["SIMULATION"]
    note: str
    market_code: str
    contract: str
    evaluated_at: datetime
    created_at: datetime
    application_sha256: str
    selection_status: Literal["RESOLVED", "UNRESOLVED_REQUIREMENT", "UNRESOLVED_CONFIGURATION"]
    ordering_status: Literal["NOT_APPLICABLE", "GOVERNED", "UNRESOLVED"]
    plan_status: Literal["READY", "BLOCKED", "UNRESOLVED"] = Field(
        description="READY: the set of surveys is settled, their order is governed and each plan can be computed. It says nothing about whether a call may be made, and nothing about what happens between surveys."
    )
    fingerprint: str
    fingerprint_verified: bool
    recomputed_fingerprint: str | None
    recompute_consistent: bool
    states: dict[str, Any] = Field(
        description="Three separate answers: call_plan (COMPUTABLE, NOT_COMPUTABLE, UNRESOLVED); coordinated_simulation (PERMITTED or BLOCKED, with stable blocker codes); operational_call_eligibility (always NOT_ESTABLISHED). None implies another."
    )
    composite: dict[str, Any] = Field(
        description="Schema call360.survey.composite-plan/1: application, policy, requirements with their traces, selected surveys with individual plans, ordering, cross-survey policy."
    )
    members: list[SurveyCompositePlanMember]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _out(g: dict[str, Any], auth: AuthContext) -> SurveyAssignmentGroup:
    me = str(auth.principal_id)
    return SurveyAssignmentGroup(
        **{**g, "is_proposer": g["proposed_by"] == me, "is_approver": g.get("approved_by") == me}
    )


def _composite_out(request: Request, c: dict[str, Any]) -> SurveyCompositePlanOut:
    """Whether a coordinated simulation is PERMITTED is a property of the composite; whether the feature is switched
    on is a property of this server. Both are told, so a screen never offers a control that can only fail."""
    c["states"]["coordinated_simulation"]["available"] = bool(
        request.app.state.settings.survey_coordinated_simulation_enabled
    )
    return SurveyCompositePlanOut(**c)


def _act(db: Session, auth: AuthContext, group_id: uuid.UUID, work: Any) -> SurveyAssignmentGroup:
    try:
        work()
        db.commit()
    except SurveyError as exc:
        if exc.status == 403:
            db.commit()  # a refusal by an identity rule is itself audited
        else:
            db.rollback()
        raise _err(exc) from exc
    return _out(ag.group(db, group_id, _markets(auth)), auth)


@router.get("/groups", response_model=SurveyAssignmentGroups, operation_id="survey_assignment_groups", responses=_ERR)
def survey_assignment_groups(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyAssignmentGroups:
    """Every version of every requirement group in the caller's markets, with its members and state."""
    return SurveyAssignmentGroups(groups=[_out(g, auth) for g in ag.groups(db, _markets(auth))], note=ag.NOTE)


@router.post(
    "/groups",
    response_model=SurveyAssignmentGroup,
    status_code=201,
    operation_id="survey_assignment_group_propose",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_group_propose(
    body: SurveyAssignmentGroupIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.edit")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentGroup:
    """Propose a new version of a requirement group: PRIMARY, ADD_REQUIRED or ALTERNATIVE, with its stated purpose,
    its optional governed position, and the exact published rule versions that compete to satisfy it."""
    _write(request, auth)
    try:
        gid = ag.propose(
            db,
            _markets(auth),
            body.code,
            body.kind,
            body.name,
            body.purpose,
            body.sequence,
            [m.model_dump() for m in body.members],
            body.note,
            auth.actor,
            request_meta(request),
        )
        db.commit()
        return _out(ag.group(db, gid, _markets(auth)), auth)
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.post(
    "/groups/{group_id}/decision",
    response_model=SurveyAssignmentGroup,
    operation_id="survey_assignment_group_decide",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_group_decide(
    group_id: uuid.UUID,
    body: SurveyAssignmentDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.approve")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentGroup:
    """Approve or reject a proposed group version. Never by its proposer."""
    _write(request, auth)
    return _act(
        db,
        auth,
        group_id,
        lambda: ag.decide(db, group_id, _markets(auth), body.verdict, body.comment, auth.actor, request_meta(request)),
    )


@router.post(
    "/groups/{group_id}/publish",
    response_model=SurveyAssignmentGroup,
    operation_id="survey_assignment_group_publish",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_group_publish(
    group_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("survey.publish")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentGroup:
    """Publish an approved group version. Never by its proposer or approver. Refused when it would give the market a
    second primary group or put a rule in two groups."""
    _write(request, auth)
    return _act(db, auth, group_id, lambda: ag.publish(db, group_id, _markets(auth), auth.actor, request_meta(request)))


@router.post(
    "/groups/{group_id}/withdraw",
    response_model=SurveyAssignmentGroup,
    operation_id="survey_assignment_group_withdraw",
    responses=_ERR,
)
@csrf_protected
def survey_assignment_group_withdraw(
    group_id: uuid.UUID,
    body: SurveyAssignmentWithdrawIn,
    request: Request,
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyAssignmentGroup:
    """Withdraw an open proposal (its proposer) or a published group (a person who may publish)."""
    _write(request, auth)
    return _act(
        db,
        auth,
        group_id,
        lambda: ag.withdraw(
            db,
            group_id,
            _markets(auth),
            body.reason,
            auth.actor,
            "survey.publish" in auth.permissions,
            request_meta(request),
        ),
    )


@router.post(
    "/composite-plans",
    response_model=SurveyCompositePlanOut,
    status_code=201,
    operation_id="survey_composite_plan_create",
    responses=_ERR,
)
@csrf_protected
def survey_composite_plan_create(
    body: SurveyCompositePlanIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.simulate")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyCompositePlanOut:
    """For one synthetic application: decide every requirement group with the existing rules, verify each selected
    version's manifest, compute each survey's own SS-03B plan, and record the composite. Nothing is assigned."""
    _write(request, auth)
    try:
        cid = ag.compose(db, _markets(auth), body.assignment_inputs, body.facts, auth.actor, request_meta(request))
        db.commit()
        return _composite_out(request, ag.composite(db, cid, _markets(auth)))
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.get(
    "/composite-plans/{composite_id}",
    response_model=SurveyCompositePlanOut,
    operation_id="survey_composite_plan_get",
    responses=_ERR,
)
def survey_composite_plan_get(
    composite_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyCompositePlanOut:
    """A recorded composite plan, as recorded; with whether computing it again now would give the same."""
    try:
        return _composite_out(request, ag.composite(db, composite_id, _markets(auth)))
    except SurveyError as exc:
        raise _err(exc) from exc
