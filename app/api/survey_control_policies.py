# ruff: noqa: E501 — field descriptions are kept one per line
"""EVAL-2A — governed control policies, applicability and coverage of SYNTHETIC journeys. Ten operations.

Registered ONLY when ``survey_control_policy_enabled`` (with evaluation and everything it needs) is on; off by default.
Same permissions as EVAL-1: reading needs ``survey.evaluation.read``; proposing a policy ``survey.edit``; deciding it
``survey.approve``; publishing it ``survey.publish`` — three different people whatever they hold; trying a policy or a
mapping out against a simulated journey needs ``survey.evaluate``. Market-scoped; state changes are CSRF-protected,
rate-limited and audited.

A policy creates no control and no insurance obligation: it refers to controls of the existing register. Nothing here
evaluates a real application, and operational compliance eligibility is never established.
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
from app.api.survey_evaluations import EVALUATE, READ, _err, _markets, _write
from app.domain import answer_evaluation as ae
from app.domain.survey import control_evaluation as ce
from app.domain.survey import control_policy as cp
from app.domain.survey import journey_evaluation as je
from app.domain.survey import policy_evaluation as pe
from app.domain.survey import store
from app.domain.survey.conditions import fields_of, inputs_of, params_of
from app.domain.survey.store import SurveyError
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/survey-evaluation", tags=["survey-evaluation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}


class SurveyControlPolicyEvent(BaseModel):
    seq: int
    event: str
    actor_ref: str
    display_name: str | None = None
    comment: str
    occurred_at: datetime


class SurveyControlPolicy(BaseModel):
    id: uuid.UUID
    market_code: str
    code: str
    revision: int
    name: str
    scope_statement: str
    scope: dict[str, Any] | None = Field(
        description="None: every application of the market. Otherwise a published condition on application facts."
    )
    completeness: Literal["DECLARED_COMPLETE", "PARTIAL"] = Field(
        description="DECLARED_COMPLETE: its governors state that, within its scope, its controls are the complete list to assess. Coverage can be asserted only then."
    )
    empty_set_is_complete: bool
    controls: list[dict[str, Any]] = Field(
        description="Each: the register control (code, id, fingerprint), purpose, description and obligations — key, title, applicability, combination, evidence requirements."
    )
    owner: str
    source: str
    policy_sha256: str
    status: Literal["PROPOSED", "APPROVED", "REJECTED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED"]
    proposed_by: str
    proposed_at: datetime
    approved_by: str | None = None
    published_by: str | None = None
    is_proposer: bool
    is_approver: bool
    history: list[SurveyControlPolicyEvent] = []


class SurveyControlPolicyList(BaseModel):
    items: list[SurveyControlPolicy]


class SurveyControlPolicyIn(BaseModel):
    market_code: str = Field(min_length=2, max_length=40)
    code: str = Field(max_length=40)
    name: str = Field(max_length=160)
    scope_statement: str = Field(max_length=2000)
    scope: dict[str, Any] | None = None
    completeness: str = Field(max_length=24)
    empty_set_is_complete: bool = False
    controls: list[dict[str, Any]] = Field(max_length=100)
    owner: str = Field(max_length=160)
    source: str = Field(max_length=2000)


class SurveyControlPolicyDecisionIn(BaseModel):
    verdict: Literal["APPROVE", "REJECT"]
    comment: str = Field(default="", max_length=2000)


class SurveyControlPolicyWithdrawIn(BaseModel):
    reason: str = Field(max_length=2000)


class SurveyControlApplicabilityIn(BaseModel):
    control_policy_id: uuid.UUID | None = None
    policy: SurveyControlPolicyIn | None = Field(
        default=None, description="A policy that is not proposed yet, to try out."
    )
    facts: dict[str, Any] = Field(
        default_factory=dict, description="A synthetic application snapshot: catalog fields and their values."
    )


class SurveyControlApplicabilityOut(BaseModel):
    record_class: Literal["SIMULATION"]
    recorded: Literal[False]
    policy: dict[str, Any]
    scope: dict[str, Any]
    obligations: list[dict[str, Any]] = Field(
        description="Every obligation of the policy: APPLICABLE (required), NOT_APPLICABLE or UNKNOWN, with the facts read and the facts missing."
    )
    missing_inputs: list[str]
    counts: dict[str, int]
    input_lineage: dict[str, Any]
    fingerprint: str = Field(
        description="The same policy revision and the same facts always give the same fingerprint."
    )
    operational_compliance_eligibility: dict[str, Any]


class SurveyEvaluationPreviewIn(BaseModel):
    simulation_id: uuid.UUID | None = None
    coordinated_simulation_id: uuid.UUID | None = None
    control_policy_id: uuid.UUID | None = None
    policy: SurveyControlPolicyIn | None = None
    mappings: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=20,
        description="Mappings that are not proposed yet: control_code, combination, applicability, entries.",
    )


class SurveyEvaluationPreviewOut(BaseModel):
    record_class: Literal["SIMULATION"]
    recorded: Literal[False]
    preview: dict[str, Any]
    market_code: str
    contract: str
    journey: dict[str, Any]
    processing_status: str
    summary: dict[str, Any]
    coverage: dict[str, Any]
    policy: dict[str, Any] | None = None
    applicability: dict[str, Any] | None = None
    controls: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    not_converted: list[dict[str, Any]]
    findings_status: str
    finding_rules: dict[str, Any] | None
    operational_compliance_eligibility: dict[str, Any]
    result_sha256: str


class SurveyEvaluationJourney(BaseModel):
    id: uuid.UUID
    kind: Literal["SINGLE_SURVEY", "COORDINATED"]
    label: str
    title: str
    surveys: int
    created_at: datetime


class SurveyEvaluationJourneyList(BaseModel):
    items: list[SurveyEvaluationJourney]


class SurveyBuilderCondition(BaseModel):
    code: str
    version: int
    name: str
    description: str
    params: list[str]
    fields: list[str]
    usable: bool = Field(description="False when it reads answers: applicability reads application facts only.")


class SurveyBuilderItem(BaseModel):
    code: str
    version: int
    name: str
    answer_type: str
    options: list[dict[str, Any]]
    surveys: list[dict[str, Any]] = Field(
        description="The published survey versions that pin this exact item revision."
    )
    evidence: list[str] = Field(
        description="What it can be evidence of: ANSWER, DELIVERY, or DELIVERY only for a statement."
    )
    methods: list[str] = Field(
        description="The evaluation methods of the existing rule language that suit its answer; empty when none exists."
    )


class SurveyBuilderOptions(BaseModel):
    market_code: str
    combinations: list[str]
    evidence_types: list[str]
    completeness: list[str]
    conditions: list[SurveyBuilderCondition]
    items: list[SurveyBuilderItem]
    fields: dict[str, dict[str, Any]] = Field(
        description="The governed fact catalog: what a synthetic application can state."
    )
    operators: dict[str, str]
    set_modes: dict[str, str] = Field(
        description="SET_MATCH: how a multiple-choice selection is compared with the expected options."
    )
    units: dict[str, str]
    instance_coverage: list[str]
    journey_coverage: list[str]
    note: str


def _policy_out(p: dict[str, Any], auth: AuthContext) -> SurveyControlPolicy:
    me = str(auth.principal_id)
    return SurveyControlPolicy(
        **{**p, "is_proposer": p["proposed_by"] == me, "is_approver": p.get("approved_by") == me}
    )


def _market(auth: AuthContext, wanted: str | None = None) -> str:
    markets = _markets(auth)
    if wanted and wanted in markets:
        return wanted
    if len(markets) != 1 and not wanted:
        raise _err(SurveyError(422, "MARKET_REQUIRED", "Name the market"))
    if wanted and wanted not in markets:
        raise _err(SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with control policies of this market"))
    return markets[0]


@router.get(
    "/builder-options",
    response_model=SurveyBuilderOptions,
    operation_id="survey_evaluation_builder_options",
    responses=_ERR,
)
def survey_evaluation_builder_options(
    market_code: str | None = None, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyBuilderOptions:
    """What a policy and a mapping can be built from: published conditions and published questions and statements of the
    market, the supported combination, and the fact catalog. Nothing here is a draft or an unpublished component."""
    market = _market(auth, market_code)
    index = store.published_index(db, [market])
    fields, _, _ = store.catalogs(db)
    conditions, items = [], []
    for (kind, code, version), versions in sorted(index.items()):
        doc = store._doc(db, kind, code, version)
        if doc is None:
            continue
        content = doc["content"]
        if kind == "CONDITION":
            ast = content.get("ast") or {}
            conditions.append(
                SurveyBuilderCondition(
                    code=code, version=version, name=str(content.get("name") or code), description=str(content.get("description") or ""),
                    params=sorted(params_of(ast)), fields=sorted(fields_of(ast)), usable=not inputs_of(ast),
                )
            )  # fmt: skip
        elif kind == "ITEM":
            options: list[dict[str, Any]] = []
            ref = content.get("option_set")
            if ref:
                os_doc = store._doc(db, "OPTION_SET", ref["code"], int(ref["version"]))
                options = [
                    {"code": o["code"], "label": o.get("label") or o["code"]}
                    for o in (os_doc or {}).get("content", {}).get("options", [])
                ]
            kind_of = content["answer_type"]
            mapped = ce.ANSWER_TYPE.get(kind_of)
            items.append(
                SurveyBuilderItem(
                    code=code, version=version, name=str(content.get("intent") or content.get("name") or code), answer_type=kind_of, options=options,
                    surveys=[{"survey_code": v["survey_code"], "survey_name": v["survey_name"], "version_label": v["label"]} for v in versions],
                    evidence=["DELIVERY"] if kind_of == "STATEMENT" or mapped is None else ["ANSWER", "DELIVERY"],
                    methods=[m for m in ae.ALL_METHODS if mapped and mapped in ae.METHOD_ANSWER_TYPES[m] and m not in ae.FACT_METHODS and m != "COLLECT_ONLY"],
                )
            )  # fmt: skip
    return SurveyBuilderOptions(
        market_code=market, combinations=list(ce.COMBINATIONS), evidence_types=list(ce.EVIDENCE_TYPES), completeness=list(cp.COMPLETENESS),
        conditions=conditions, items=items, fields={k: dict(v) for k, v in fields.items()}, operators=dict(ae.OPERATORS), set_modes=dict(ae.SET_MODES), units=dict(ae.UNITS),
        instance_coverage=list(pe.INSTANCE_COVERAGE), journey_coverage=list(pe.JOURNEY_COVERAGE), note=pe.COVERAGE_NOTE,
    )  # fmt: skip


@router.get(
    "/journeys", response_model=SurveyEvaluationJourneyList, operation_id="survey_evaluation_journeys", responses=_ERR
)
def survey_evaluation_journeys(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyEvaluationJourneyList:
    """Recent simulated journeys of the caller's markets, to try a policy or a mapping out against."""
    return SurveyEvaluationJourneyList(items=[SurveyEvaluationJourney(**j) for j in je.journeys(db, _markets(auth))])


@router.get(
    "/control-policies",
    response_model=SurveyControlPolicyList,
    operation_id="survey_control_policy_list",
    responses=_ERR,
)
def survey_control_policy_list(
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyControlPolicyList:
    """Every control policy revision of the caller's markets, whatever its status."""
    return SurveyControlPolicyList(items=[_policy_out(p, auth) for p in cp.policies(db, _markets(auth))])


@router.get(
    "/control-policies/{policy_id}",
    response_model=SurveyControlPolicy,
    operation_id="survey_control_policy_get",
    responses=_ERR,
)
def survey_control_policy_get(
    policy_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyControlPolicy:
    try:
        return _policy_out(cp.policy(db, policy_id, _markets(auth)), auth)
    except SurveyError as exc:
        raise _err(exc) from exc


def _act(db: Session, auth: AuthContext, policy_id: uuid.UUID, work: Any) -> SurveyControlPolicy:
    try:
        work()
        db.commit()
    except SurveyError as exc:
        if exc.status == 403:  # a refusal by an identity rule is itself audited: keep that record
            db.commit()
        else:
            db.rollback()
        raise _err(exc) from exc
    return _policy_out(cp.policy(db, policy_id, _markets(auth)), auth)


@router.post(
    "/control-policies",
    response_model=SurveyControlPolicy,
    status_code=201,
    operation_id="survey_control_policy_propose",
    responses=_ERR,
)
@csrf_protected
def survey_control_policy_propose(
    body: SurveyControlPolicyIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.edit")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlPolicy:
    """Propose a new revision of a control policy. Refused, saying what is wrong and where, unless every control is in
    the register, every condition is published and reads application facts only, and every obligation names required evidence."""
    _write(request, auth)
    try:
        pid = cp.propose(db, _markets(auth), body.model_dump(), auth.actor, request_meta(request))
        db.commit()
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    return _policy_out(cp.policy(db, pid, _markets(auth)), auth)


@router.post(
    "/control-policies/{policy_id}/decision",
    response_model=SurveyControlPolicy,
    operation_id="survey_control_policy_decide",
    responses=_ERR,
)
@csrf_protected
def survey_control_policy_decide(
    policy_id: uuid.UUID,
    body: SurveyControlPolicyDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("survey.approve")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlPolicy:
    """Approve or reject a proposed policy revision. Never by its proposer."""
    _write(request, auth)
    return _act(
        db,
        auth,
        policy_id,
        lambda: cp.decide(db, policy_id, _markets(auth), body.verdict, body.comment, auth.actor, request_meta(request)),
    )


@router.post(
    "/control-policies/{policy_id}/publish",
    response_model=SurveyControlPolicy,
    operation_id="survey_control_policy_publish",
    responses=_ERR,
)
@csrf_protected
def survey_control_policy_publish(
    policy_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("survey.publish")),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlPolicy:
    """Publish an approved revision: a third person. The published revision of the same policy is superseded; evaluations made under it keep it."""
    _write(request, auth)
    return _act(
        db, auth, policy_id, lambda: cp.publish(db, policy_id, _markets(auth), auth.actor, request_meta(request))
    )


@router.post(
    "/control-policies/{policy_id}/withdraw",
    response_model=SurveyControlPolicy,
    operation_id="survey_control_policy_withdraw",
    responses=_ERR,
)
@csrf_protected
def survey_control_policy_withdraw(
    policy_id: uuid.UUID,
    body: SurveyControlPolicyWithdrawIn,
    request: Request,
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlPolicy:
    """Withdraw an open proposal (its proposer) or a published revision (a person who may publish)."""
    _write(request, auth)
    return _act(
        db, auth, policy_id,
        lambda: cp.withdraw(db, policy_id, _markets(auth), body.reason, auth.actor, "survey.publish" in auth.permissions, request_meta(request)),
    )  # fmt: skip


@router.post(
    "/applicability",
    response_model=SurveyControlApplicabilityOut,
    operation_id="survey_control_applicability",
    responses=_ERR,
)
@csrf_protected
def survey_control_applicability(
    body: SurveyControlApplicabilityIn,
    request: Request,
    auth: AuthContext = Depends(require(EVALUATE)),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyControlApplicabilityOut:
    """Which obligations of a policy a synthetic application requires — for a recorded revision, or for a policy that
    is not proposed yet. Nothing is recorded. Unknown stays unknown."""
    _write(request, auth)
    try:
        if (body.control_policy_id is None) == (body.policy is None):
            raise SurveyError(
                422, "POLICY_REQUIRED", "Name a policy revision, or give a policy to try out — one of the two"
            )
        if body.policy is not None:
            market = _market(auth, body.policy.market_code)
            policy = cp.as_policy(cp.document(db, market, body.policy.model_dump()))
        else:
            assert body.control_policy_id is not None
            policy = cp.policy(db, body.control_policy_id, _markets(auth))
        if not isinstance(body.facts, dict) or any(k not in store.catalogs(db)[0] for k in body.facts):
            raise SurveyError(422, "FACT_UNKNOWN", "A fact names a field the governed catalog does not have")
        out = pe.determine(policy, body.facts)
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    return SurveyControlApplicabilityOut(
        **out, record_class="SIMULATION", recorded=False, operational_compliance_eligibility=pe.ELIGIBILITY
    )


@router.post(
    "/evaluations/preview",
    response_model=SurveyEvaluationPreviewOut,
    operation_id="survey_journey_evaluation_preview",
    responses=_ERR,
)
@csrf_protected
def survey_journey_evaluation_preview(
    body: SurveyEvaluationPreviewIn,
    request: Request,
    auth: AuthContext = Depends(require(EVALUATE)),
    _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyEvaluationPreviewOut:
    """What an evaluation of a simulated journey WOULD say under a policy and mappings that are not published yet.
    Validated exactly as proposals are; nothing is recorded or proposed."""
    _write(request, auth)
    try:
        out = je.preview(
            db, _markets(auth), body.simulation_id, body.coordinated_simulation_id, policy_id=body.control_policy_id,
            policy_draft=body.policy.model_dump() if body.policy else None, mapping_drafts=body.mappings,
        )  # fmt: skip
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.rollback()  # nothing of a trial is kept
    return SurveyEvaluationPreviewOut(**out)
