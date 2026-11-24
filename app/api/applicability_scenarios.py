# ruff: noqa: E501 — field descriptions are kept one per line
"""APPL-X4a — saved synthetic scenarios, regression suites and recorded evaluation runs. Twenty-two operations under
``/api/v1/applicability`` (``/scenarios``, ``/suites``, ``/runs``).

A scenario is one saved SYNTHETIC application with the exact library definitions it was saved against. A suite is an
ordered regression dataset for one policy, with the outcome a person EXPECTS for each scenario. A run is immutable
evidence of what the Python evaluator returned for exactly that policy revision and exactly those scenarios.

Registered ONLY when ``applicability_scenarios_enabled`` (with policies and the library) is on; off by default; needs
migration 0040. Permissions — no new one: ``applicability.read`` to read, evaluate and compare; ``applicability.edit``
to create, save, archive and to record a run; and ``survey.read`` on every operation. Market-scoped: another market's
scenario, suite or run answers 404. Writes are CSRF-protected, rate-limited and audited.

There is NO publication of policies here (APPL-X4b). Everything is synthetic: nothing reads or writes a customer, an
operational policy, a case or a session, and no assignment rule, survey binding or requirement group is touched.
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
from app.domain.survey.applicability import scenarios as sc
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/applicability", tags=["applicability-scenarios"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 413, 422, 429)}
READ, EDIT, SURVEYS = "applicability.read", "applicability.edit", "survey.read"
NOTE = "Synthetic data and synthetic results only. A selection plan assigns nothing and gives no permission to call anyone."
Purpose = Literal["REGRESSION", "EXPLORATORY"]
SuitePurpose = Literal["PUBLICATION_GATING", "EXPLORATORY"]
Outcome = Literal["PASSED", "FAILED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION", "NO_EXPECTATION"]
RunStatus = Literal["PASSED", "FAILED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION"]


class ApplicabilityScenarioEvent(BaseModel):
    seq: int
    event: str
    actor: str
    draft_revision: int
    comment: str
    detail: dict[str, Any]
    occurred_at: datetime


class ApplicabilityScenarioSummary(BaseModel):
    id: str
    market_code: str
    code: str
    name: str
    description: str
    record_class: Literal["SYNTHETIC"]
    purpose: Purpose = Field(
        description="REGRESSION: may belong to a publication-gating suite. EXPLORATORY: never counts towards publication."
    )
    state: Literal["DRAFT", "ARCHIVED"]
    policy_id: str | None
    baseline_id: str | None = Field(description="The scenario this one is a variant of.")
    draft_revision: int
    updated_at: datetime
    updated_by: str | None
    created_at: datetime
    profiles: list[str]
    facts: int
    unknown_facts: int
    unpublished: int
    suites: int
    variants: int
    document_sha256: str
    snapshot_sha256: str
    scenario_fingerprint: str = Field(
        description="One fingerprint over the canonical document and its dependency snapshot."
    )


class ApplicabilityScenarioPage(BaseModel):
    items: list[ApplicabilityScenarioSummary]
    total: int
    limit: int
    offset: int


class ApplicabilityScenarioInspection(BaseModel):
    pins: list[dict[str, Any]]
    dependencies: list[dict[str, Any]] = Field(
        description="Each variable and profile with identity, version, fingerprints and state."
    )
    diagnostics: list[dict[str, Any]]
    snapshot_sha256: str
    scenario_fingerprint: str
    stale: int
    unpublished: int
    invalid: int
    reproducible: bool = Field(
        description="True only when every dependency is an exact published version and none has moved."
    )
    definitions: dict[str, list[dict[str, Any]]] = Field(
        description="The pinned definitions themselves, for the fact editor."
    )


class ApplicabilityScenarioLink(BaseModel):
    id: str
    code: str
    name: str
    purpose: str | None = None


class ApplicabilityScenarioBaseline(BaseModel):
    id: str
    code: str
    name: str
    facts: dict[str, Any]
    profiles: list[str]


class ApplicabilityScenario(ApplicabilityScenarioSummary):
    document: dict[str, Any]
    snapshot: dict[str, Any]
    inspection: ApplicabilityScenarioInspection
    baseline: ApplicabilityScenarioBaseline | None
    variant_list: list[ApplicabilityScenarioLink]
    suite_list: list[ApplicabilityScenarioLink]
    events: list[ApplicabilityScenarioEvent]


class ApplicabilityScenarioCreateIn(BaseModel):
    market_code: str = Field(max_length=40)
    code: str = Field(max_length=60, description="Chosen after naming the scenario; it never changes.")
    document: dict[str, Any] = Field(
        description="name, description, profiles, facts (a value, null for 'not known', absent for 'not provided'), pins."
    )
    purpose: Purpose = "REGRESSION"
    policy_id: uuid.UUID | None = None
    baseline_id: uuid.UUID | None = Field(default=None, description="Makes this scenario a saved variant of another.")
    origin: str = Field(default="", max_length=60)


class ApplicabilityScenarioSaveIn(BaseModel):
    expected_revision: int
    document: dict[str, Any]
    purpose: Purpose | None = None
    note: str = Field(default="", max_length=500)


class ApplicabilityArchiveIn(BaseModel):
    expected_revision: int
    reason: str = Field(default="", max_length=500)


class ApplicabilityScenarioInspectIn(BaseModel):
    market_code: str = Field(max_length=40)
    document: dict[str, Any]
    snapshot: dict[str, Any] | None = Field(
        default=None, description="The stored snapshot of the scenario being edited, if it is a saved one."
    )


class ApplicabilityScenarioItemIn(BaseModel):
    ref: str = Field(default="", max_length=80)
    scenario_id: uuid.UUID | None = Field(default=None, description="A SAVED scenario, evaluated exactly as saved.")
    document: dict[str, Any] | None = Field(default=None, description="An UNSAVED scenario: exploratory.")
    snapshot: dict[str, Any] | None = None


class ApplicabilityScenarioEvaluateIn(BaseModel):
    policy_id: uuid.UUID
    policy_document: dict[str, Any] | None = Field(
        default=None, description="An unsaved edit of that policy: a preview."
    )
    scenarios: list[ApplicabilityScenarioItemIn] = Field(max_length=sc.MAX_EVALUATE)


class ApplicabilityScenarioResult(BaseModel):
    ref: str
    scenario_id: str | None
    scenario_code: str | None
    scenario_revision: int | None
    mode: Literal["SAVED_SCENARIO", "EXPLORATORY"]
    state: Literal["EVALUATED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION"]
    reason: str | None
    plan: dict[str, Any] | None
    diagnostics: list[dict[str, Any]]
    resolved: list[dict[str, Any]] = Field(
        description="Exactly which library definitions were read for this scenario, with fingerprints."
    )
    scenario_fingerprint: str
    scenario_snapshot_sha256: str
    reproducible: bool = Field(
        description="A saved scenario on published definitions against the saved policy revision."
    )


class ApplicabilityScenarioEvaluation(BaseModel):
    policy_source: Literal["SAVED", "PREVIEW"]
    status: Literal["OK", "DEPENDENCY_STALE", "INVALID_DEPENDENCY"]
    contract: str
    note: str
    policy_id: str
    policy_revision: int
    policy_document_sha256: str | None
    policy_snapshot_sha256: str
    policy_fingerprint: str | None
    reasons: list[dict[str, Any]]
    results: list[ApplicabilityScenarioResult]


class ApplicabilityScenarioCompareIn(BaseModel):
    policy_id: uuid.UUID
    before_id: uuid.UUID
    after_id: uuid.UUID


class ApplicabilityScenarioComparison(BaseModel):
    policy_id: str
    policy_revision: int
    status: str
    before: ApplicabilityScenarioResult
    after: ApplicabilityScenarioResult
    facts_changed: list[dict[str, Any]]
    comparison: dict[str, Any] | None


class ApplicabilitySuiteMemberIn(BaseModel):
    scenario_id: uuid.UUID
    expectation: dict[str, Any] | None = Field(
        default=None,
        description="What the person expects: status, selected [{code, version}], pending [codes], optionally replaced [requirement ids] and needs [variables]; 'confirmed' must be true. Never filled in by the server.",
    )


class ApplicabilitySuiteLastRun(BaseModel):
    id: str
    status: RunStatus
    passed: int
    failed: int
    scenarios: int
    created_at: datetime
    policy_revision: int
    suite_revision: int


class ApplicabilitySuiteSummary(BaseModel):
    id: str
    market_code: str
    code: str
    name: str
    description: str
    purpose: SuitePurpose
    policy_id: str
    state: Literal["DRAFT", "ARCHIVED"]
    draft_revision: int
    updated_at: datetime
    updated_by: str | None
    created_at: datetime
    suite_sha256: str
    members: int
    with_expectation: int
    last_run: ApplicabilitySuiteLastRun | None


class ApplicabilitySuitePage(BaseModel):
    items: list[ApplicabilitySuiteSummary]
    total: int
    limit: int
    offset: int


class ApplicabilitySuiteMember(BaseModel):
    position: int
    scenario_id: str
    code: str
    name: str
    purpose: Purpose
    draft_revision: int
    facts: dict[str, Any]
    profiles: list[str]
    baseline_id: str | None
    expectation: dict[str, Any] | None
    expectation_stated_by: str | None = Field(
        default=None, description="Who stated this expected outcome (stamped by the server when its content changes)."
    )
    expectation_stated_at: str | None = None
    scenario_changed: bool = Field(description="The scenario was saved again after its expectation was last reviewed.")


class ApplicabilitySuitePolicy(BaseModel):
    id: str
    code: str
    name: str
    draft_revision: int
    archived: bool


class ApplicabilitySuite(ApplicabilitySuiteSummary):
    policy: ApplicabilitySuitePolicy
    member_list: list[ApplicabilitySuiteMember]
    diagnostics: list[dict[str, Any]]
    events: list[ApplicabilityScenarioEvent]


class ApplicabilitySuiteCreateIn(BaseModel):
    market_code: str = Field(max_length=40)
    code: str = Field(max_length=60)
    policy_id: uuid.UUID
    document: dict[str, Any] = Field(description="name and description.")
    purpose: SuitePurpose = "PUBLICATION_GATING"
    members: list[ApplicabilitySuiteMemberIn] = Field(default_factory=list, max_length=sc.MAX_MEMBERS)
    origin: str = Field(default="", max_length=60)


class ApplicabilitySuiteSaveIn(BaseModel):
    expected_revision: int
    document: dict[str, Any]
    purpose: SuitePurpose
    members: list[ApplicabilitySuiteMemberIn] = Field(max_length=sc.MAX_MEMBERS)
    note: str = Field(default="", max_length=500)


class ApplicabilityRunIn(BaseModel):
    idempotency_key: str = Field(
        min_length=8,
        max_length=80,
        description="Chosen by the client; the same key for the same suite returns the run already recorded.",
    )
    target: dict[str, Any] | None = Field(
        default=None,
        description="APPL-X4b: exactly what to evaluate — {kind: DRAFT, revision} | {kind: CANDIDATE, id} | {kind: VERSION, id}. REQUIRED once the policy has a candidate or a published version; nothing is assumed then.",
    )


class ApplicabilityRunSummary(BaseModel):
    id: str
    market_code: str
    record_class: Literal["SYNTHETIC"]
    target: dict[str, Any] = Field(
        description="Exactly what was evaluated: the saved draft at a revision, a candidate, or a published version — with its fingerprints."
    )
    suite_id: str
    suite_code: str
    suite_name: str
    suite_revision: int
    suite_purpose: str
    policy_id: str
    policy_code: str
    policy_name: str
    policy_revision: int
    policy_document_sha256: str
    policy_snapshot_sha256: str
    policy_fingerprint: str | None
    evaluator_contract: str
    status: RunStatus
    scenarios: int
    passed: int
    failed: int
    not_evaluated: int
    invalid: int
    no_expectation: int
    record_sha256: str
    run_sha256: str
    duration_ms: int
    created_at: datetime
    created_by: str


class ApplicabilityRunPage(BaseModel):
    items: list[ApplicabilityRunSummary]
    total: int
    limit: int
    offset: int


class ApplicabilityRunResultSummary(BaseModel):
    position: int
    scenario_id: str
    scenario_code: str
    scenario_name: str
    scenario_revision: int
    scenario_document_sha256: str
    scenario_snapshot_sha256: str
    expectation: dict[str, Any] | None
    outcome: Outcome
    plan_fingerprint: str | None
    differences: list[dict[str, Any]] = Field(
        description="Every way the actual plan differs from the expectation; empty when the test passed."
    )
    reason: str | None
    actual: dict[str, Any] = Field(description="The actual status, selected surveys and pending surveys, in brief.")


class ApplicabilityRun(ApplicabilityRunSummary):
    replayed: bool = Field(
        default=False, description="True when this answer is a run recorded earlier under the same idempotency key."
    )
    note: str = NOTE
    coverage: dict[str, Any] = Field(
        description="Requirement- and condition-level coverage of the scenarios run. Never a claim of exhaustiveness."
    )
    suite: dict[str, Any] = Field(description="The suite exactly as it was run: members, revisions and expectations.")
    policy_status: str
    policy_reasons: list[dict[str, Any]]
    results_total: int
    results: list[ApplicabilityRunResultSummary]
    limit: int
    offset: int


class ApplicabilityRunResult(ApplicabilityRunResultSummary):
    plan: dict[str, Any] | None
    scenario_document: dict[str, Any]
    scenario_snapshot: dict[str, Any]
    diagnostics: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    reproducible: bool
    scenario_fingerprint: str | None


class ApplicabilityRunVerification(BaseModel):
    run_id: str
    record_intact: bool
    run_fingerprint_intact: bool
    results_checked: int
    results_reproduced: int
    mismatched_positions: list[int]
    reproduced: bool
    note: str


class ApplicabilityRunCompareIn(BaseModel):
    before_run_id: uuid.UUID
    after_run_id: uuid.UUID


class ApplicabilityRunComparison(BaseModel):
    kind: Literal["RUN_TO_RUN", "RUN_TO_CURRENT_DRAFT"]
    before: ApplicabilityRunSummary
    after: dict[str, Any]
    same_policy: bool
    policy_changed: bool
    dependency_changes: list[dict[str, Any]]
    scenarios: list[dict[str, Any]]
    changed: int
    unchanged: int
    note: str


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext, *, computing: bool = False) -> None:
    """CSRF and the request limit. Working something out is counted separately from saving, as for policies."""
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    key, limit = (
        (f"applicability-scenario-run:{auth.principal_id}", settings.survey_simulation_inputs_per_minute)
        if computing
        else (f"applicability-scenario:{auth.principal_id}", settings.survey_writes_per_minute)
    )
    if not request.app.state.limiter.allow(key, limit):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _act(db: Session, work: Any) -> Any:
    try:
        out = work()
        db.commit()
        return out
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


def _try(work: Any) -> Any:
    try:
        return work()
    except SurveyError as exc:
        raise _err(exc) from exc


R = Depends(require(READ))
S = Depends(require(SURVEYS))
E = Depends(require(EDIT))
DB = Depends(get_db)


# ------------------------------------------------------------------------------------------------------ scenarios
@router.get(
    "/scenarios", response_model=ApplicabilityScenarioPage, operation_id="applicability_scenario_list", responses=_ERR
)
def applicability_scenario_list(
    policy_id: uuid.UUID | None = None, q: str = "", purpose: Purpose | None = None, baseline_id: uuid.UUID | None = None, suite_id: uuid.UUID | None = None,
    archived: bool = False, limit: int = 50, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB,
) -> ApplicabilityScenarioPage:  # fmt: skip
    """A page of saved scenarios of the caller's markets, most recently saved first. Nothing is evaluated to list them."""
    return ApplicabilityScenarioPage(**sc.listing(db, _markets(auth), policy_id=policy_id, q=q, purpose=purpose, baseline_id=baseline_id, suite_id=suite_id, archived=archived, limit=limit, offset=offset))  # fmt: skip


def _scenario(db: Session, auth: AuthContext, sid: uuid.UUID) -> ApplicabilityScenario:
    return ApplicabilityScenario(**_try(lambda: sc.detail(db, _markets(auth), sid)))


@router.post(
    "/scenarios",
    response_model=ApplicabilityScenario,
    status_code=201,
    operation_id="applicability_scenario_create",
    responses=_ERR,
)
@csrf_protected
def applicability_scenario_create(body: ApplicabilityScenarioCreateIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenario:  # fmt: skip
    """Save a new synthetic scenario — blank, from a profile, a copy, or a VARIANT of another (``baseline_id``). Every
    fact's variable and every profile is pinned at an exact version. Anything that looks like a real identifier is refused."""
    _write(request, auth)
    sid = _act(db, lambda: sc.create(db, _markets(auth), body.market_code, body.code, body.document, auth.actor, request_meta(request), purpose=body.purpose, policy_id=body.policy_id, baseline_id=body.baseline_id, origin=body.origin))  # fmt: skip
    return _scenario(db, auth, sid)


@router.post(
    "/scenarios/inspect",
    response_model=ApplicabilityScenarioInspection,
    operation_id="applicability_scenario_inspect",
    responses=_ERR,
)
@csrf_protected
def applicability_scenario_inspect(body: ApplicabilityScenarioInspectIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenarioInspection:  # fmt: skip
    """What the server says about a scenario document, saved or not: the exact definitions it resolves to, their state,
    and every diagnostic. Writes nothing."""
    _write(request, auth, computing=True)
    if body.market_code not in _markets(auth):
        raise AppError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with scenarios of this market")
    return ApplicabilityScenarioInspection(
        **_try(lambda: sc.inspect(db, body.market_code, sc.normalise(body.document), body.snapshot))
    )


@router.post(
    "/scenarios/evaluate",
    response_model=ApplicabilityScenarioEvaluation,
    operation_id="applicability_scenario_evaluate",
    responses=_ERR,
)
@csrf_protected
def applicability_scenario_evaluate(body: ApplicabilityScenarioEvaluateIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenarioEvaluation:  # fmt: skip
    """Scenarios against a policy, by the Python evaluator. A saved scenario is evaluated exactly as saved; an unsaved one
    is EXPLORATORY and says which definitions were resolved for it. Records nothing."""
    _write(request, auth, computing=True)
    out = _try(
        lambda: sc.evaluate(
            db,
            _markets(auth),
            body.policy_id,
            [s.model_dump(mode="json") for s in body.scenarios],
            body.policy_document,
        )
    )
    return ApplicabilityScenarioEvaluation(**out, note=NOTE)


@router.post(
    "/scenarios/compare",
    response_model=ApplicabilityScenarioComparison,
    operation_id="applicability_scenario_compare",
    responses=_ERR,
)
@csrf_protected
def applicability_scenario_compare(body: ApplicabilityScenarioCompareIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenarioComparison:  # fmt: skip
    """Two saved scenarios against one saved policy: the facts that differ and what that changes in the selection."""
    _write(request, auth, computing=True)
    return ApplicabilityScenarioComparison(
        **_try(lambda: sc.compare_scenarios(db, _markets(auth), body.policy_id, body.before_id, body.after_id))
    )


@router.get(
    "/scenarios/{scenario_id}",
    response_model=ApplicabilityScenario,
    operation_id="applicability_scenario_get",
    responses=_ERR,
)
def applicability_scenario_get(
    scenario_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilityScenario:
    """One scenario: its document, its dependency snapshot, its baseline and variants, the suites it is in, its history."""
    return _scenario(db, auth, scenario_id)


@router.put(
    "/scenarios/{scenario_id}/draft",
    response_model=ApplicabilityScenario,
    operation_id="applicability_scenario_save",
    responses=_ERR,
)
@csrf_protected
def applicability_scenario_save(scenario_id: uuid.UUID, body: ApplicabilityScenarioSaveIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenario:  # fmt: skip
    """Save the scenario. 409 STALE_REVISION when someone else saved first. Document, snapshot, dependency rows, history: one transaction."""
    _write(request, auth)
    _act(
        db,
        lambda: sc.save(
            db,
            _markets(auth),
            scenario_id,
            body.expected_revision,
            body.document,
            auth.actor,
            request_meta(request),
            purpose=body.purpose,
            note=body.note,
        ),
    )
    return _scenario(db, auth, scenario_id)


def _archive(kind: str, restore: bool) -> Any:
    def scenario(scenario_id: uuid.UUID, body: ApplicabilityArchiveIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityScenario:  # fmt: skip
        _write(request, auth)
        _act(
            db,
            lambda: sc.archive(
                db,
                _markets(auth),
                kind,
                scenario_id,
                body.expected_revision,
                body.reason,
                auth.actor,
                request_meta(request),
                restore=restore,
            ),
        )
        return _scenario(db, auth, scenario_id)

    def suite(suite_id: uuid.UUID, body: ApplicabilityArchiveIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilitySuite:  # fmt: skip
        _write(request, auth)
        _act(
            db,
            lambda: sc.archive(
                db,
                _markets(auth),
                kind,
                suite_id,
                body.expected_revision,
                body.reason,
                auth.actor,
                request_meta(request),
                restore=restore,
            ),
        )
        return _suite(db, auth, suite_id)

    return scenario if kind == sc.SCENARIO else suite


applicability_scenario_archive = router.post("/scenarios/{scenario_id}/archive", response_model=ApplicabilityScenario, operation_id="applicability_scenario_archive", responses=_ERR, summary="Archive a scenario: out of the listings, never deleted")(csrf_protected(_archive(sc.SCENARIO, False)))  # fmt: skip
applicability_scenario_restore = router.post("/scenarios/{scenario_id}/restore", response_model=ApplicabilityScenario, operation_id="applicability_scenario_restore", responses=_ERR, summary="Bring an archived scenario back")(csrf_protected(_archive(sc.SCENARIO, True)))  # fmt: skip


# ---------------------------------------------------------------------------------------------------------- suites
def _suite(db: Session, auth: AuthContext, uid: uuid.UUID) -> ApplicabilitySuite:
    return ApplicabilitySuite(**_try(lambda: sc.suite_detail(db, _markets(auth), uid)))


@router.get("/suites", response_model=ApplicabilitySuitePage, operation_id="applicability_suite_list", responses=_ERR)
def applicability_suite_list(policy_id: uuid.UUID | None = None, archived: bool = False, limit: int = 50, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilitySuitePage:  # fmt: skip
    """A page of regression suites, with each one's last recorded run in brief."""
    return ApplicabilitySuitePage(
        **sc.suites(db, _markets(auth), policy_id=policy_id, archived=archived, limit=limit, offset=offset)
    )


@router.post(
    "/suites",
    response_model=ApplicabilitySuite,
    status_code=201,
    operation_id="applicability_suite_create",
    responses=_ERR,
)
@csrf_protected
def applicability_suite_create(body: ApplicabilitySuiteCreateIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilitySuite:  # fmt: skip
    """Create a suite for one policy — empty, or with members (a clone carries its members and expectations)."""
    _write(request, auth)
    uid = _act(db, lambda: sc.create_suite(db, _markets(auth), body.market_code, body.code, body.policy_id, body.document, body.purpose, [m.model_dump() for m in body.members], auth.actor, request_meta(request), body.origin))  # fmt: skip
    return _suite(db, auth, uid)


@router.get(
    "/suites/{suite_id}", response_model=ApplicabilitySuite, operation_id="applicability_suite_get", responses=_ERR
)
def applicability_suite_get(
    suite_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilitySuite:
    """One suite: its ordered members, each one's expected outcome, what is missing, and its history."""
    return _suite(db, auth, suite_id)


@router.put(
    "/suites/{suite_id}/draft",
    response_model=ApplicabilitySuite,
    operation_id="applicability_suite_save",
    responses=_ERR,
)
@csrf_protected
def applicability_suite_save(suite_id: uuid.UUID, body: ApplicabilitySuiteSaveIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilitySuite:  # fmt: skip
    """Save the suite: name, purpose, ordered members and their expected outcomes. Expectations are stored as stated and
    must be confirmed; the server never fills one in from a result."""
    _write(request, auth)
    _act(db, lambda: sc.save_suite(db, _markets(auth), suite_id, body.expected_revision, body.document, body.purpose, [m.model_dump() for m in body.members], auth.actor, request_meta(request), body.note))  # fmt: skip
    return _suite(db, auth, suite_id)


applicability_suite_archive = router.post("/suites/{suite_id}/archive", response_model=ApplicabilitySuite, operation_id="applicability_suite_archive", responses=_ERR, summary="Archive a suite: its recorded runs are kept")(csrf_protected(_archive(sc.SUITE, False)))  # fmt: skip
applicability_suite_restore = router.post("/suites/{suite_id}/restore", response_model=ApplicabilitySuite, operation_id="applicability_suite_restore", responses=_ERR, summary="Bring an archived suite back")(csrf_protected(_archive(sc.SUITE, True)))  # fmt: skip


# ------------------------------------------------------------------------------------------------------------ runs
def _run(db: Session, auth: AuthContext, rid: uuid.UUID, outcome: str | None = None, limit: int = 50, offset: int = 0, replayed: bool = False) -> ApplicabilityRun:  # fmt: skip
    return ApplicabilityRun(
        **_try(lambda: sc.run_detail(db, _markets(auth), rid, outcome=outcome, limit=limit, offset=offset)),
        replayed=replayed,
    )


@router.post(
    "/suites/{suite_id}/runs",
    response_model=ApplicabilityRun,
    status_code=201,
    operation_id="applicability_suite_run",
    responses=_ERR,
)
@csrf_protected
def applicability_suite_run(suite_id: uuid.UUID, body: ApplicabilityRunIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRun:  # fmt: skip
    """Run the whole suite against the policy's SAVED revision and RECORD it: the exact policy document and manifest, the
    definitions read, every scenario as it was, every expectation, every actual plan and verdict. Immutable. A test that
    could not be evaluated, or has no expectation, never passes."""
    _write(request, auth)
    _write(request, auth, computing=True)
    subject = None
    if request.app.state.settings.applicability_publication_enabled:
        from app.domain.survey.applicability import publication as pub  # the tables of 0041 exist only then

        subject = _try(lambda: pub.run_subject(db, _markets(auth), suite_id, body.target))
    elif body.target is not None and body.target.get("kind") != "DRAFT":
        raise AppError(422, "INVALID_TARGET", "Only the saved working draft can be evaluated here")
    rid, new = _act(
        db,
        lambda: sc.run_suite(
            db, _markets(auth), suite_id, body.idempotency_key, auth.actor, request_meta(request), subject
        ),
    )
    return _run(db, auth, rid, replayed=not new)


@router.get("/runs", response_model=ApplicabilityRunPage, operation_id="applicability_run_list", responses=_ERR)
def applicability_run_list(suite_id: uuid.UUID | None = None, policy_id: uuid.UUID | None = None, limit: int = 25, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRunPage:  # fmt: skip
    """Recorded runs, newest first."""
    return ApplicabilityRunPage(
        **sc.runs(db, _markets(auth), suite_id=suite_id, policy_id=policy_id, limit=limit, offset=offset)
    )


@router.post(
    "/runs/compare", response_model=ApplicabilityRunComparison, operation_id="applicability_run_compare", responses=_ERR
)
@csrf_protected
def applicability_run_compare(body: ApplicabilityRunCompareIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRunComparison:  # fmt: skip
    """Two recorded runs: what changed in the policy and its dependencies, and for each scenario in facts, expectation,
    verdict and selection."""
    _write(request, auth, computing=True)
    return ApplicabilityRunComparison(
        **_try(lambda: sc.compare_runs(db, _markets(auth), body.before_run_id, body.after_run_id))
    )


@router.get("/runs/{run_id}", response_model=ApplicabilityRun, operation_id="applicability_run_get", responses=_ERR)
def applicability_run_get(run_id: uuid.UUID, outcome: Outcome | None = None, limit: int = 50, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRun:  # fmt: skip
    """A recorded run and a page of its results. It reads the same whatever happened to the policy, the scenarios or the
    library since."""
    return _run(db, auth, run_id, outcome, limit, offset)


@router.get(
    "/runs/{run_id}/results/{position}",
    response_model=ApplicabilityRunResult,
    operation_id="applicability_run_result",
    responses=_ERR,
)
def applicability_run_result(run_id: uuid.UUID, position: int, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRunResult:  # fmt: skip
    """One recorded result in full: the scenario exactly as it was, the expectation, the complete plan and explanation."""
    return ApplicabilityRunResult(**_try(lambda: sc.run_result(db, _markets(auth), run_id, position)))


@router.post(
    "/runs/{run_id}/verify",
    response_model=ApplicabilityRunVerification,
    operation_id="applicability_run_verify",
    responses=_ERR,
)
@csrf_protected
def applicability_run_verify(run_id: uuid.UUID, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRunVerification:  # fmt: skip
    """Re-evaluate a recorded run from its own record — not from the library — and compare every fingerprint. Writes nothing."""
    _write(request, auth, computing=True)
    return ApplicabilityRunVerification(**_try(lambda: sc.verify(db, _markets(auth), run_id)))


@router.post(
    "/runs/{run_id}/against-current",
    response_model=ApplicabilityRunComparison,
    operation_id="applicability_run_against_current",
    responses=_ERR,
)
@csrf_protected
def applicability_run_against_current(run_id: uuid.UUID, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityRunComparison:  # fmt: skip
    """A recorded run's scenarios and expectations against the policy's CURRENT saved draft — a what-if, not recorded."""
    _write(request, auth, computing=True)
    return ApplicabilityRunComparison(**_try(lambda: sc.against_current(db, _markets(auth), run_id)))
