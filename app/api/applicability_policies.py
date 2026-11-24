# ruff: noqa: E501 — field descriptions are kept one per line
"""APPL-X3 — persistent Applicability Policies (working drafts). Ten operations under ``/api/v1/applicability/policies``.

A policy is one document. It is saved with an expected revision, together with the exact dependencies it was saved
against (library versions or draft revisions, and published Survey Studio versions), which never move by themselves.
``evaluate`` runs the SAVED revision; ``preview`` runs an unsaved document and says so. Both resolve the workspace from
exactly what the document pins and use the one Python evaluator.

Registered ONLY when ``applicability_policies_enabled`` (with the library) is on; off by default; needs migration 0039.
Permissions — no new one: ``applicability.read`` to read and evaluate, ``applicability.edit`` to create, save and
archive, and ``survey.read`` on every operation, because a policy names published surveys (an explicit, read-only
dependency). Market-scoped: another market's policy answers 404. Writes are CSRF-protected, rate-limited and audited.

There is NO publication here (APPL-X4): no candidate, no approval, no published policy. A selection plan is a synthetic
result: it assigns nothing and permits no call. Assignment rules, survey bindings and requirement groups are neither
read nor written.
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
from app.domain.survey.applicability import policies as pol
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/applicability/policies", tags=["applicability-policies"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ, EDIT, SURVEYS = "applicability.read", "applicability.edit", "survey.read"
NOTE = "Synthetic result. A selection plan assigns nothing and gives no permission to call anyone. Policies are drafts: publication is not available yet."
MAX_SCENARIOS = 300


class ApplicabilityPolicySummary(BaseModel):
    id: str
    market_code: str
    code: str
    name: str
    description: str
    state: Literal["DRAFT", "ARCHIVED"]
    draft_revision: int
    updated_at: datetime
    updated_by: str | None
    created_at: datetime
    requirements: int
    surveys: list[str]
    conditions: list[str]
    unpublished: int
    document_sha256: str
    snapshot_sha256: str


class ApplicabilityPolicyList(BaseModel):
    items: list[ApplicabilityPolicySummary]


class ApplicabilityPolicyInspection(BaseModel):
    pins: list[dict[str, Any]] = Field(
        description="Every variable and profile the document reads, and every draft condition, at the exact version or draft revision resolved."
    )
    dependencies: list[dict[str, Any]] = Field(
        description="Each dependency with its identity, fingerprints and state: published or draft, changed since saved, newer version available."
    )
    requirements: dict[str, dict[str, list[str]]] = Field(description="What each requirement depends on.")
    diagnostics: list[dict[str, Any]]
    workspace: dict[str, list[dict[str, Any]]] = Field(
        description="The definitions exactly as pinned: what the evaluator reads for this document."
    )
    policy_fingerprint: str | None
    snapshot_sha256: str
    unpublished: int
    stale: int
    blockers: int
    ready_for_publication: bool
    readiness: str
    can_evaluate: bool


class ApplicabilityPolicyEvent(BaseModel):
    seq: int
    event: str
    actor: str
    draft_revision: int
    comment: str
    detail: dict[str, Any]
    occurred_at: datetime


class ApplicabilityPolicy(ApplicabilityPolicySummary):
    document: dict[str, Any]
    snapshot: dict[str, Any] = Field(description="The stored dependency manifest of the saved draft.")
    inspection: ApplicabilityPolicyInspection | None = Field(
        description="What the server says about the saved draft. Omitted when the read asked for the document only."
    )
    events: list[ApplicabilityPolicyEvent]


class ApplicabilityPolicyCreateIn(BaseModel):
    market_code: str = Field(max_length=40)
    code: str = Field(max_length=60, description="Chosen by the person after naming the policy; it never changes.")
    document: dict[str, Any]
    origin: str = Field(
        default="", max_length=40, description="BLANK, TEMPLATE:<id> or COPY:<code>; recorded in the history."
    )


class ApplicabilityPolicySaveIn(BaseModel):
    expected_revision: int
    document: dict[str, Any]
    note: str = Field(default="", max_length=500)


class ApplicabilityPolicyArchiveIn(BaseModel):
    expected_revision: int
    reason: str = Field(default="", max_length=500)


class ApplicabilityPolicyInspectIn(BaseModel):
    document: dict[str, Any] | None = Field(
        default=None, description="An unsaved document to inspect; the saved draft when omitted."
    )


class ApplicabilityPolicyScenarioIn(BaseModel):
    id: str = Field(max_length=80)
    facts: dict[str, Any] = Field(default_factory=dict)
    profiles: list[str] | None = None


class ApplicabilityPolicyEvaluateIn(BaseModel):
    scenarios: list[ApplicabilityPolicyScenarioIn] = Field(max_length=MAX_SCENARIOS)


class ApplicabilityPolicyPreviewIn(BaseModel):
    document: dict[str, Any]
    scenarios: list[ApplicabilityPolicyScenarioIn] = Field(max_length=MAX_SCENARIOS)
    compare_with_saved: bool = Field(
        default=False, description="Also evaluate the saved draft and say what changes for each scenario."
    )


class ApplicabilityPolicyRun(BaseModel):
    source: Literal["SAVED", "PREVIEW"] = Field(
        description="SAVED: the stored revision. PREVIEW: an unsaved document — a what-if, not a result of the saved policy."
    )
    status: Literal["OK", "DEPENDENCY_STALE", "INVALID_DEPENDENCY"]
    contract: str
    note: str
    draft_revision: int = Field(
        description="The saved revision this run belongs to (for a preview: the revision it was edited from)."
    )
    document_sha256: str | None
    snapshot_sha256: str
    policy_fingerprint: str | None
    results: list[dict[str, Any]]
    reasons: list[dict[str, Any]] = Field(default_factory=list)


class ApplicabilityPolicyUse(BaseModel):
    policy_id: str
    policy_code: str
    policy_name: str
    market_code: str
    draft_revision: int
    kind: str
    code: str
    version_no: int | None
    pinned_draft_revision: int | None
    content_sha256: str


class ApplicabilityPolicyUsage(BaseModel):
    items: list[ApplicabilityPolicyUse]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext, *, computing: bool = False) -> None:
    """CSRF and the request limit. Saving a policy and working one out are counted SEPARATELY: the designer inspects
    and previews on every edit, and that must never use up the allowance that lets the person save."""
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    key, limit = (
        (f"applicability-policy-run:{auth.principal_id}", settings.survey_simulation_inputs_per_minute)
        if computing
        else (f"applicability-policy:{auth.principal_id}", settings.survey_writes_per_minute)
    )
    if not request.app.state.limiter.allow(key, limit):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _detail(db: Session, auth: AuthContext, policy_id: uuid.UUID, inspection: bool = True) -> ApplicabilityPolicy:
    try:
        return ApplicabilityPolicy(**pol.detail(db, _markets(auth), policy_id, inspection=inspection))
    except SurveyError as exc:
        raise _err(exc) from exc


def _act(db: Session, work: Any) -> Any:
    try:
        out = work()
        db.commit()
        return out
    except SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc


@router.get("", response_model=ApplicabilityPolicyList, operation_id="applicability_policy_list", responses=_ERR)
def applicability_policy_list(
    archived: bool = False, auth: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)),
    db: Session = Depends(get_db),
) -> ApplicabilityPolicyList:  # fmt: skip
    """Every saved policy of the caller's markets, most recently saved first."""
    return ApplicabilityPolicyList(
        items=[ApplicabilityPolicySummary(**p) for p in pol.listing(db, _markets(auth), archived=archived)]
    )


@router.post(
    "", response_model=ApplicabilityPolicy, status_code=201, operation_id="applicability_policy_create", responses=_ERR
)
@csrf_protected
def applicability_policy_create(
    body: ApplicabilityPolicyCreateIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _r: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicy:  # fmt: skip
    """Create a saved policy draft — blank, from a pattern or as a copy. The code is unique in its market and never changes."""
    _write(request, auth)
    pid = _act(
        db,
        lambda: pol.create(
            db,
            _markets(auth),
            body.market_code,
            body.code,
            body.document,
            auth.actor,
            request_meta(request),
            body.origin,
        ),
    )
    return _detail(db, auth, pid)


@router.get(
    "/usage", response_model=ApplicabilityPolicyUsage, operation_id="applicability_policy_usage", responses=_ERR
)
def applicability_policy_usage(
    kind: Literal["VARIABLE", "PROFILE", "CONDITION", "SURVEY"] | None = None, code: str | None = None,
    auth: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicyUsage:  # fmt: skip
    """Which saved policies depend on a library item or a published survey, and at which exact version."""
    return ApplicabilityPolicyUsage(
        items=[ApplicabilityPolicyUse(**u) for u in pol.usage(db, _markets(auth), kind=kind, code=code)]
    )


@router.get("/{policy_id}", response_model=ApplicabilityPolicy, operation_id="applicability_policy_get", responses=_ERR)
def applicability_policy_get(
    policy_id: uuid.UUID, inspection: bool = True, auth: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)),
    db: Session = Depends(get_db),
) -> ApplicabilityPolicy:  # fmt: skip
    """One policy: its saved document, its dependency manifest, its history, and — unless ``inspection=false`` — what the
    server says about it (which runs the evaluator's whole analysis)."""
    return _detail(db, auth, policy_id, inspection)


@router.put(
    "/{policy_id}/draft", response_model=ApplicabilityPolicy, operation_id="applicability_policy_save", responses=_ERR
)
@csrf_protected
def applicability_policy_save(
    policy_id: uuid.UUID, body: ApplicabilityPolicySaveIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _r: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicy:  # fmt: skip
    """Save the draft. 409 STALE_REVISION when someone else saved first; 422 when a survey reference or a dependency pin
    does not name something that exists exactly as stated. Document, manifest, dependency rows and history: one transaction."""
    _write(request, auth)
    _act(
        db,
        lambda: pol.save(
            db,
            _markets(auth),
            policy_id,
            body.expected_revision,
            body.document,
            auth.actor,
            request_meta(request),
            body.note,
        ),
    )
    return _detail(db, auth, policy_id)


def _archive(restore: bool) -> Any:
    def run(
        policy_id: uuid.UUID, body: ApplicabilityPolicyArchiveIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
        _r: AuthContext = Depends(require(READ)), _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
    ) -> ApplicabilityPolicy:  # fmt: skip
        _write(request, auth)
        _act(
            db,
            lambda: pol.archive(
                db,
                _markets(auth),
                policy_id,
                body.expected_revision,
                body.reason,
                auth.actor,
                request_meta(request),
                restore=restore,
            ),
        )
        return _detail(db, auth, policy_id)

    return run


applicability_policy_archive = router.post(
    "/{policy_id}/archive",
    response_model=ApplicabilityPolicy,
    operation_id="applicability_policy_archive",
    responses=_ERR,
    summary="Archive a policy: out of the gallery, never deleted",
)(csrf_protected(_archive(False)))
applicability_policy_restore = router.post(
    "/{policy_id}/restore",
    response_model=ApplicabilityPolicy,
    operation_id="applicability_policy_restore",
    responses=_ERR,
    summary="Bring an archived policy back",
)(csrf_protected(_archive(True)))


@router.post(
    "/{policy_id}/inspect",
    response_model=ApplicabilityPolicyInspection,
    operation_id="applicability_policy_inspect",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_inspect(
    policy_id: uuid.UUID, body: ApplicabilityPolicyInspectIn, request: Request, auth: AuthContext = Depends(require(READ)),
    _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicyInspection:  # fmt: skip
    """What the server says about a document, saved or not: its pins, every dependency and its state, diagnostics per
    requirement, and whether it could be published. Writes nothing."""
    _write(request, auth, computing=True)
    try:
        p = pol.policy_row(db, policy_id, _markets(auth))
        doc = pol.normalise(body.document) if body.document is not None else p["document"]
        return ApplicabilityPolicyInspection(**pol.inspect(db, p, doc, p["snapshot"]))
    except SurveyError as exc:
        raise _err(exc) from exc


def _run(
    db: Session,
    auth: AuthContext,
    policy_id: uuid.UUID,
    scenarios: list[ApplicabilityPolicyScenarioIn],
    document: dict[str, Any] | None,
    compare: bool,
) -> ApplicabilityPolicyRun:
    try:
        p = pol.policy_row(db, policy_id, _markets(auth))
        doc = p["document"] if document is None else pol.normalise(document)
        out = pol.run(
            db, p, doc, [s.model_dump() for s in scenarios], source="SAVED" if document is None else "PREVIEW",
            previous=p["snapshot"], compare=p["document"] if compare and document is not None else None,
        )  # fmt: skip
    except SurveyError as exc:
        raise _err(exc) from exc
    return ApplicabilityPolicyRun(
        **out,
        note=NOTE,
        draft_revision=p["draft_revision"],
        document_sha256=p["document_sha256"] if document is None else None,
    )


@router.post(
    "/{policy_id}/evaluate",
    response_model=ApplicabilityPolicyRun,
    operation_id="applicability_policy_evaluate",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_evaluate(
    policy_id: uuid.UUID, body: ApplicabilityPolicyEvaluateIn, request: Request, auth: AuthContext = Depends(require(READ)),
    _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicyRun:  # fmt: skip
    """The SAVED revision applied to each synthetic scenario, from exactly the dependencies it was saved against. The same
    revision and the same facts give the same plan and the same fingerprints. Refused (status DEPENDENCY_STALE) while a
    pinned draft has changed. Stores nothing."""
    _write(request, auth, computing=True)
    return _run(db, auth, policy_id, body.scenarios, None, False)


@router.post(
    "/{policy_id}/preview",
    response_model=ApplicabilityPolicyRun,
    operation_id="applicability_policy_preview",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_preview(
    policy_id: uuid.UUID, body: ApplicabilityPolicyPreviewIn, request: Request, auth: AuthContext = Depends(require(READ)),
    _s: AuthContext = Depends(require(SURVEYS)), db: Session = Depends(get_db),
) -> ApplicabilityPolicyRun:  # fmt: skip
    """An UNSAVED document applied to each synthetic scenario — a what-if, marked PREVIEW, never a result of the saved
    policy. Same resolution, same evaluator. Stores nothing."""
    _write(request, auth, computing=True)
    return _run(db, auth, policy_id, body.scenarios, body.document, body.compare_with_saved)
