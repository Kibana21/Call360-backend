# ruff: noqa: E501 — field descriptions are kept one per line
"""APPL-X4b — governed publication of Applicability Policies. Thirteen operations under ``/api/v1/applicability``.

The readiness gate, the immutable candidate, three-person approval and publication, published versions, and the
comparison of exact targets over one fixed dataset. Every decision is the server's: the browser shows it.

Registered ONLY when ``applicability_publication_enabled`` (with scenarios, policies and the library) is on; off by
default; needs migration 0041. Permissions — no new one: ``applicability.read`` to read, ``applicability.edit`` to
submit and withdraw, ``applicability.approve`` to approve or return, ``applicability.publish`` to publish; and
``survey.read`` on every operation. Holding a permission is not enough: submitting, approving and publishing one
candidate are done by three DIFFERENT people, checked from the signed-in identity. Market-scoped. Writes are
CSRF-protected, rate-limited and audited; a refused decision or publication is recorded too.

A published version is a governed configuration artefact. Nothing here selects a survey for a real case, plans a
callback or starts a session.
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
from app.domain.survey.applicability import publication as pub
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/applicability", tags=["applicability-publication"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ, EDIT, APPROVE, PUBLISH, SURVEYS = "applicability.read", "applicability.edit", "applicability.approve", "applicability.publish", "survey.read"  # fmt: skip
CandidateStatus = Literal["SUBMITTED", "APPROVED", "RETURNED", "WITHDRAWN", "PUBLISHED"]


class ApplicabilityBlocker(BaseModel):
    code: str
    message: str
    action: str = Field(description="What to do to clear it.")
    prevents: list[Literal["SUBMISSION", "APPROVAL", "PUBLICATION"]]
    at: dict[str, Any] = Field(
        description="What it concerns: the requirement, the dependency, the exact versions in conflict."
    )


class ApplicabilityReadiness(BaseModel):
    policy_id: str
    policy_code: str
    policy_name: str
    market_code: str
    draft_revision: int
    document_sha256: str
    manifest_sha256: str
    policy_fingerprint: str | None
    saved_by: str | None
    saved_at: str
    ready: bool = Field(description="True only when no blocker prevents submission.")
    blockers: list[ApplicabilityBlocker]
    notices: list[dict[str, Any]] = Field(
        description="Worth knowing, not blocking — a newer published version of a pinned item, say."
    )
    dependencies: list[dict[str, Any]]
    evidence: dict[str, Any] | None = Field(
        description="The run the author chose, examined: fingerprints, coverage, independence, provenance."
    )
    runs: list[dict[str, Any]] = Field(
        description="The recorded runs of this policy to choose from. None is chosen for the author."
    )
    open_candidate: dict[str, Any] | None
    published: dict[str, Any] | None
    you: str | None


class ApplicabilitySubmitPolicyIn(BaseModel):
    expected_revision: int
    run_id: uuid.UUID = Field(description="The qualifying recorded run the author chose.")
    document_sha256: str = Field(description="The policy document fingerprint the author was shown and confirms.")
    manifest_sha256: str = Field(description="The dependency manifest fingerprint the author was shown and confirms.")
    run_sha256: str = Field(description="The evidence run fingerprint the author was shown and confirms.")
    note: str = Field(default="", max_length=1000)


class ApplicabilityCandidateSummary(BaseModel):
    id: str
    policy_id: str
    policy_code: str
    policy_name: str
    market_code: str
    candidate_no: int
    status: CandidateStatus
    draft_revision: int
    document_sha256: str
    manifest_sha256: str
    candidate_sha256: str
    evidence_run_id: str
    evidence_run_sha256: str
    evidence_suite: str
    evidence_recorded_at: str
    requirements: int
    submitted_by: str
    submitted_by_ref: str
    submitted_at: datetime
    submission_note: str
    decided_by: str | None
    decided_by_ref: str | None
    decided_at: datetime | None
    decision_comment: str
    published_by: str | None
    published_at: datetime | None


class ApplicabilityCandidatePage(BaseModel):
    items: list[ApplicabilityCandidateSummary]
    total: int
    limit: int
    offset: int


class ApplicabilityCandidateEvent(BaseModel):
    seq: int
    event: str
    actor: str
    comment: str
    detail: dict[str, Any]
    occurred_at: datetime


class ApplicabilityCandidate(ApplicabilityCandidateSummary):
    document: dict[str, Any] = Field(description="The policy exactly as submitted. It never changes.")
    selection: list[dict[str, Any]] = Field(
        description="Requirement by requirement: which surveys, at which exact versions."
    )
    dependencies: list[dict[str, Any]]
    evidence: dict[str, Any]
    revalidation: list[ApplicabilityBlocker] = Field(
        description="The frozen candidate checked against what exists now. Empty: nothing prevents the next step."
    )
    events: list[ApplicabilityCandidateEvent]
    version: dict[str, Any] | None
    next_version_no: int
    published_now: dict[str, Any] | None
    you_submitted: bool
    you_decided: bool


class ApplicabilityDecisionPolicyIn(BaseModel):
    verdict: Literal["APPROVE", "RETURN"]
    candidate_sha256: str = Field(description="The fingerprint of the candidate the checker reviewed.")
    comment: str = Field(default="", max_length=1000)


class ApplicabilityPolicyWithdrawIn(BaseModel):
    reason: str = Field(max_length=1000)


class ApplicabilityPublishPolicyIn(BaseModel):
    candidate_sha256: str = Field(description="The fingerprint of the approved candidate, confirmed by the publisher.")
    version_no: int = Field(description="The version number this publication creates, confirmed by the publisher.")


class ApplicabilityPolicyVersionSummary(BaseModel):
    id: str
    policy_id: str
    policy_code: str
    policy_name: str
    market_code: str
    version_no: int
    status: Literal["PUBLISHED", "SUPERSEDED"]
    candidate_id: str
    document_sha256: str
    manifest_sha256: str
    candidate_sha256: str
    version_sha256: str
    evidence_run_id: str
    evidence_run_sha256: str
    requirements: int
    published_by: str
    published_at: datetime
    superseded_at: datetime | None


class ApplicabilityPolicyVersionList(BaseModel):
    items: list[ApplicabilityPolicyVersionSummary]


class ApplicabilityPolicyVersion(ApplicabilityPolicyVersionSummary):
    document: dict[str, Any]
    selection: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]
    evidence: dict[str, Any]
    submitted_by: str
    submitted_at: datetime
    approved_by: str
    approved_at: datetime | None
    draft_revision: int
    events: list[ApplicabilityCandidateEvent]


class ApplicabilityVersionVerification(BaseModel):
    version_id: str
    version_no: int
    status: str
    fingerprints_intact: bool
    identical_to_candidate: bool
    evidence_reproduced: bool
    results_checked: int
    results_reproduced: int
    verified: bool
    note: str


class ApplicabilityRunTargets(BaseModel):
    policy_id: str
    items: list[dict[str, Any]] = Field(
        description="The saved working draft, open candidates and published versions, each with status and fingerprints."
    )
    must_choose: bool = Field(
        description="True once there is more than the working draft: a run must then name its target."
    )


class ApplicabilityImpactIn(BaseModel):
    dataset_run_id: uuid.UUID = Field(
        description="A recorded run of this policy: its scenarios, as recorded, are the fixed dataset for BOTH sides."
    )
    before: dict[str, Any] = Field(description="{kind: DRAFT | CANDIDATE | VERSION, id?}")
    after: dict[str, Any]


class ApplicabilityImpact(BaseModel):
    policy_id: str
    before: dict[str, Any]
    after: dict[str, Any]
    dataset: dict[str, Any]
    reproducible: bool
    why_not_reproducible: str | None
    document_changed: bool
    dependency_changes: list[dict[str, Any]]
    requirements_added: list[str]
    requirements_removed: list[str]
    requirements_changed: list[str]
    scope_changed: bool
    scenarios: list[dict[str, Any]]
    changed: int
    unchanged: int
    note: str


class ApplicabilityVersionUse(BaseModel):
    version_id: str
    policy_code: str
    policy_name: str
    version_no: int
    status: str
    kind: str
    code: str
    pinned_version_no: int
    content_sha256: str


class ApplicabilityVersionUsage(BaseModel):
    items: list[ApplicabilityVersionUse]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext, *, computing: bool = False) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    key, limit = (
        (f"applicability-publication-run:{auth.principal_id}", settings.survey_simulation_inputs_per_minute)
        if computing
        else (f"applicability-publication:{auth.principal_id}", settings.survey_writes_per_minute)
    )
    if not request.app.state.limiter.allow(key, limit):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _try(work: Any) -> Any:
    try:
        return work()
    except SurveyError as exc:
        raise _err(exc) from exc


def _act(db: Session, work: Any, *, refused: Any = None) -> Any:
    """One transaction, or nothing. A refused transition is then recorded in a transaction of its own."""
    try:
        out = work()
        db.commit()
        return out
    except SurveyError as exc:
        db.rollback()
        if refused is not None and exc.status == 409:
            refused(exc)
            db.commit()
        raise _err(exc) from exc


R = Depends(require(READ))
S = Depends(require(SURVEYS))
E = Depends(require(EDIT))
A = Depends(require(APPROVE))
P = Depends(require(PUBLISH))
DB = Depends(get_db)


@router.get(
    "/policies/{policy_id}/readiness",
    response_model=ApplicabilityReadiness,
    operation_id="applicability_policy_readiness",
    responses=_ERR,
)
def applicability_policy_readiness(policy_id: uuid.UUID, run_id: uuid.UUID | None = None, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityReadiness:  # fmt: skip
    """Whether the SAVED revision can be submitted, and every reason why not: each blocker with what it concerns, the
    versions in conflict, how to clear it and which steps it prevents. ``run_id`` is the recorded run the author chose
    as evidence; none is chosen for them. Writes nothing."""
    return ApplicabilityReadiness(**_try(lambda: pub.readiness(db, _markets(auth), policy_id, run_id, auth.actor)))


@router.get(
    "/policies/{policy_id}/run-targets",
    response_model=ApplicabilityRunTargets,
    operation_id="applicability_policy_run_targets",
    responses=_ERR,
)
def applicability_policy_run_targets(
    policy_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilityRunTargets:
    """What a suite run of this policy can evaluate: the working draft at its revision, an open candidate, a published
    version — each with its status and fingerprints."""
    return ApplicabilityRunTargets(**_try(lambda: pub.targets(db, _markets(auth), policy_id)))


def _candidate(db: Session, auth: AuthContext, cid: uuid.UUID) -> ApplicabilityCandidate:
    return ApplicabilityCandidate(**_try(lambda: pub.candidate_detail(db, _markets(auth), cid, auth.actor)))


@router.post(
    "/policies/{policy_id}/submit",
    response_model=ApplicabilityCandidate,
    status_code=201,
    operation_id="applicability_policy_submit",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_submit(policy_id: uuid.UUID, body: ApplicabilitySubmitPolicyIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityCandidate:  # fmt: skip
    """Freeze an immutable candidate from the saved revision and the chosen run. Refused (409 PUBLICATION_BLOCKED, with
    every blocker) unless the gate is clear, and unless the fingerprints the author confirms are the current ones."""
    _write(request, auth)
    cid = _act(db, lambda: pub.submit(db, _markets(auth), policy_id, body.expected_revision, body.run_id,
                                      {"document_sha256": body.document_sha256, "manifest_sha256": body.manifest_sha256, "run_sha256": body.run_sha256}, body.note, auth.actor, request_meta(request)))  # fmt: skip
    return _candidate(db, auth, cid)


@router.get(
    "/policy-candidates",
    response_model=ApplicabilityCandidatePage,
    operation_id="applicability_policy_candidate_list",
    responses=_ERR,
)
def applicability_policy_candidate_list(policy_id: uuid.UUID | None = None, status: CandidateStatus | None = None, limit: int = 50, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityCandidatePage:  # fmt: skip
    """Candidates of the caller's markets, newest first — including returned and withdrawn ones, which stay readable."""
    return ApplicabilityCandidatePage(
        **pub.candidates(db, _markets(auth), policy_id=policy_id, status=status, limit=limit, offset=offset)
    )


@router.get(
    "/policy-candidates/{candidate_id}",
    response_model=ApplicabilityCandidate,
    operation_id="applicability_policy_candidate_get",
    responses=_ERR,
)
def applicability_policy_candidate_get(
    candidate_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilityCandidate:
    """Exactly what was submitted: the document, the manifest, the evidence with its provenance, the history — and the
    candidate revalidated against what exists now."""
    return _candidate(db, auth, candidate_id)


@router.post(
    "/policy-candidates/{candidate_id}/decision",
    response_model=ApplicabilityCandidate,
    operation_id="applicability_policy_candidate_decide",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_candidate_decide(candidate_id: uuid.UUID, body: ApplicabilityDecisionPolicyIn, request: Request, auth: AuthContext = A, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityCandidate:  # fmt: skip
    """Approve or return a submitted candidate. Not by the person who submitted it (409 SAME_PERSON). The checker names
    the fingerprint they reviewed; approval revalidates the frozen candidate first. A return needs a reason."""
    _write(request, auth)
    meta = request_meta(request)
    _act(db, lambda: pub.decide(db, _markets(auth), candidate_id, body.verdict, body.comment, body.candidate_sha256, auth.actor, meta),
         refused=lambda exc: pub.refused(db, _markets(auth), candidate_id, "DECISION", exc, auth.actor, meta))  # fmt: skip
    return _candidate(db, auth, candidate_id)


@router.post(
    "/policy-candidates/{candidate_id}/withdraw",
    response_model=ApplicabilityCandidate,
    operation_id="applicability_policy_candidate_withdraw",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_candidate_withdraw(candidate_id: uuid.UUID, body: ApplicabilityPolicyWithdrawIn, request: Request, auth: AuthContext = E, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityCandidate:  # fmt: skip
    """Withdraw a candidate that is submitted or approved. Only by the person who submitted it. It stays readable."""
    _write(request, auth)
    _act(db, lambda: pub.withdraw(db, _markets(auth), candidate_id, body.reason, auth.actor, request_meta(request)))
    return _candidate(db, auth, candidate_id)


@router.post(
    "/policy-candidates/{candidate_id}/publish",
    response_model=ApplicabilityCandidate,
    operation_id="applicability_policy_candidate_publish",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_candidate_publish(candidate_id: uuid.UUID, body: ApplicabilityPublishPolicyIn, request: Request, auth: AuthContext = P, _r: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityCandidate:  # fmt: skip
    """Publish an APPROVED candidate as the next version. Not by its submitter or its checker (409 SAME_PERSON). The
    exact candidate is revalidated first — pinned versions, the evidence suite and scenarios, the reproduction of the
    run — and nothing is refreshed or substituted. The version is written from the candidate, never from the draft."""
    _write(request, auth)
    meta = request_meta(request)
    _act(db, lambda: pub.publish(db, _markets(auth), candidate_id, body.candidate_sha256, body.version_no, auth.actor, meta),
         refused=lambda exc: pub.refused(db, _markets(auth), candidate_id, "PUBLICATION", exc, auth.actor, meta))  # fmt: skip
    return _candidate(db, auth, candidate_id)


@router.get(
    "/policies/{policy_id}/versions",
    response_model=ApplicabilityPolicyVersionList,
    operation_id="applicability_policy_versions",
    responses=_ERR,
)
def applicability_policy_versions(
    policy_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilityPolicyVersionList:
    """Every published version of a policy, newest first: the current one and the superseded ones."""
    return ApplicabilityPolicyVersionList(**_try(lambda: pub.versions(db, _markets(auth), policy_id)))


@router.get(
    "/policy-versions/usage",
    response_model=ApplicabilityVersionUsage,
    operation_id="applicability_policy_version_usage",
    responses=_ERR,
)
def applicability_policy_version_usage(kind: Literal["VARIABLE", "PROFILE", "CONDITION", "SURVEY"] | None = None, code: str | None = None, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityVersionUsage:  # fmt: skip
    """Which published policy versions pin a library item or a survey, and at which exact version."""
    return ApplicabilityVersionUsage(
        items=[ApplicabilityVersionUse(**u) for u in pub.usage(db, _markets(auth), kind=kind, code=code)]
    )


@router.get(
    "/policy-versions/{version_id}",
    response_model=ApplicabilityPolicyVersion,
    operation_id="applicability_policy_version_get",
    responses=_ERR,
)
def applicability_policy_version_get(
    version_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> ApplicabilityPolicyVersion:
    """One published version, current or superseded: its document, manifest, evidence, the three people and its history."""
    return ApplicabilityPolicyVersion(**_try(lambda: pub.version_detail(db, _markets(auth), version_id)))


@router.post(
    "/policy-versions/{version_id}/verify",
    response_model=ApplicabilityVersionVerification,
    operation_id="applicability_policy_version_verify",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_version_verify(version_id: uuid.UUID, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityVersionVerification:  # fmt: skip
    """Check a published version against itself and re-evaluate its evidence run from the run's own record."""
    _write(request, auth, computing=True)
    return ApplicabilityVersionVerification(**_try(lambda: pub.verify_version(db, _markets(auth), version_id)))


@router.post(
    "/policies/{policy_id}/impact",
    response_model=ApplicabilityImpact,
    operation_id="applicability_policy_impact",
    responses=_ERR,
)
@csrf_protected
def applicability_policy_impact(policy_id: uuid.UUID, body: ApplicabilityImpactIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB) -> ApplicabilityImpact:  # fmt: skip
    """What changes between two exact targets — draft, candidate or published version — over ONE fixed dataset: the
    scenarios of a recorded run, as recorded, on both sides. Records nothing."""
    _write(request, auth, computing=True)
    return ApplicabilityImpact(
        **_try(lambda: pub.impact(db, _markets(auth), policy_id, body.dataset_run_id, body.before, body.after))
    )
