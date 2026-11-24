# ruff: noqa: E501 — field descriptions are kept one per line
"""APPL-X2 — the governed Applicability library. Fourteen operations under ``/api/v1/applicability``.

Variables, application profiles and reusable conditions, PERSISTED: one working draft per item saved with an expected
revision, immutable candidates, published versions that pin the exact versions they read, and a complete history.

Registered ONLY when ``applicability_library_enabled`` is on (off by default; needs migration 0038). Permissions of its
own, independent of ``survey.*`` and ``script.*`` and granted to no role by the migration: ``applicability.read`` to
read; ``applicability.edit`` to draft and submit; ``applicability.approve`` to approve or return; and
``applicability.publish`` to publish — three different people, whatever permissions each one holds. Market-scoped: an
item of another market does not exist for the caller. State changes are CSRF-protected, rate-limited and audited.

Nothing here selects a survey, assigns anything to a case or permits a call. Applicability POLICIES are not stored
(APPL-X3). Assignment rules, survey bindings and requirement groups are neither read nor written.
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
from app.domain.survey.applicability import ApplicabilityError
from app.domain.survey.applicability import library as lib
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/applicability", tags=["applicability-library"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ, EDIT, APPROVE, PUBLISH = (
    "applicability.read",
    "applicability.edit",
    "applicability.approve",
    "applicability.publish",
)
Kind = Literal["VARIABLE", "PROFILE", "CONDITION"]


class ApplicabilityPin(BaseModel):
    kind: str
    code: str
    version_no: int
    version_id: str
    content_sha256: str


class ApplicabilityVersion(BaseModel):
    id: str
    candidate_no: int
    version_no: int | None = Field(description="Set when the candidate was published.")
    status: Literal["SUBMITTED", "APPROVED", "RETURNED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED"]
    document: dict[str, Any]
    pins: list[ApplicabilityPin] = Field(description="The exact published versions this candidate reads.")
    content_sha256: str
    manifest_sha256: str
    note: str
    draft_revision: int
    submitted_by: str
    submitted_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_comment: str | None
    published_by: str | None
    published_at: datetime | None
    is_submitter: bool
    is_approver: bool


class ApplicabilityDraft(BaseModel):
    document: dict[str, Any]
    revision: int
    base_version_no: int | None
    updated_at: datetime | None
    updated_by: str | None
    locked: bool = Field(description="True while a candidate is in review: the draft cannot change.")


class ApplicabilityAsset(BaseModel):
    id: str
    market_code: str
    kind: Kind
    code: str
    name: str
    state: Literal["DRAFT", "IN_REVIEW", "APPROVED", "RETURNED", "PUBLISHED", "EMPTY"]
    draft: ApplicabilityDraft | None
    draft_revision: int
    candidate: ApplicabilityVersion | None
    published: ApplicabilityVersion | None
    returned: ApplicabilityVersion | None
    published_versions: int


class ApplicabilityEvent(BaseModel):
    seq: int
    event: str
    actor: str
    comment: str
    detail: dict[str, Any]
    occurred_at: datetime
    version_id: str | None


class ApplicabilityUse(BaseModel):
    kind: str
    code: str
    name: str
    state: Literal["PUBLISHED", "EARLIER_VERSION", "IN_REVIEW", "DRAFT"]
    version_no: int | None
    pinned_version: int | None


class ApplicabilityDiagnostic(BaseModel):
    severity: str
    code: str
    message: str
    at: dict[str, Any] = Field(default_factory=dict)


class ApplicabilityAssetDetail(ApplicabilityAsset):
    versions: list[ApplicabilityVersion]
    events: list[ApplicabilityEvent]
    used_by: list[ApplicabilityUse]
    diagnostics: list[ApplicabilityDiagnostic]
    newer_pins: list[dict[str, Any]]


class ApplicabilityAssetList(BaseModel):
    items: list[ApplicabilityAsset]


class ApplicabilityAssetCreateIn(BaseModel):
    market_code: str = Field(max_length=40)
    kind: Kind
    code: str = Field(max_length=60)
    document: dict[str, Any]


class ApplicabilityDraftIn(BaseModel):
    expected_revision: int = Field(description="The draft revision this edit was made on.")
    document: dict[str, Any]


class ApplicabilityRevisionIn(BaseModel):
    expected_revision: int


class ApplicabilityStartDraftIn(BaseModel):
    version_no: int | None = Field(
        default=None, description="The published version to start from; the latest when omitted."
    )


class ApplicabilityPinAck(BaseModel):
    kind: Kind
    code: str = Field(max_length=60)
    version_no: int


class ApplicabilitySubmitIn(BaseModel):
    expected_revision: int
    note: str = Field(default="", max_length=2000)
    pins: list[ApplicabilityPinAck] | None = Field(
        default=None,
        max_length=400,
        description="The exact versions the submitter reviewed (from `validate`). When given, the submission is refused with 409 PINS_CHANGED unless they are exactly what would be frozen now.",
    )


class ApplicabilityDecisionIn(BaseModel):
    verdict: Literal["APPROVE", "RETURN"]
    comment: str = Field(default="", max_length=2000)


class ApplicabilityWithdrawIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ApplicabilityValidateIn(BaseModel):
    document: dict[str, Any] | None = Field(
        default=None, description="An unsaved edit to check; the saved draft when omitted."
    )


class ApplicabilityValidateOut(BaseModel):
    diagnostics: list[ApplicabilityDiagnostic]
    pins: list[ApplicabilityPin]
    can_submit: bool


class ApplicabilityWorkspace(BaseModel):
    market_code: str
    view: Literal["authoring", "published"]
    variables: list[dict[str, Any]]
    profiles: list[dict[str, Any]]
    conditions: list[dict[str, Any]]


class ApplicabilityTestIn(BaseModel):
    market_code: str = Field(max_length=40)
    expr: dict[str, Any]
    facts: dict[str, Any] = Field(default_factory=dict)
    profiles: list[str] | None = None
    view: Literal["authoring", "published"] = "authoring"


class ApplicabilityTestOut(BaseModel):
    result: Literal["TRUE", "FALSE", "UNKNOWN"] | None
    trace: dict[str, Any] | None
    facts: dict[str, Any]
    diagnostics: list[ApplicabilityDiagnostic]
    error: dict[str, Any] | None = None


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"applicability:{auth.principal_id}", settings.survey_writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _detail(db: Session, auth: AuthContext, asset_id: uuid.UUID) -> ApplicabilityAssetDetail:
    return ApplicabilityAssetDetail(**lib.detail(db, _markets(auth), asset_id, str(auth.principal_id)))


def _act(db: Session, auth: AuthContext, work: Any) -> uuid.UUID:
    """Run one state change. A refusal by an identity rule is itself recorded, so that record is kept."""
    try:
        asset_id: uuid.UUID = work()
        db.commit()
    except SurveyError as exc:
        if exc.status == 403 and exc.code.endswith("_DENIED"):
            db.commit()
        else:
            db.rollback()
        raise _err(exc) from exc
    return asset_id


@router.get("/assets", response_model=ApplicabilityAssetList, operation_id="applicability_asset_list", responses=_ERR)
def applicability_asset_list(
    kind: Kind | None = None, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> ApplicabilityAssetList:
    """Every variable, profile and condition of the caller's markets, with its draft, open candidate and published version."""
    return ApplicabilityAssetList(
        items=[ApplicabilityAsset(**a) for a in lib.listing(db, _markets(auth), str(auth.principal_id), kind)]
    )


@router.post(
    "/assets",
    response_model=ApplicabilityAssetDetail,
    status_code=201,
    operation_id="applicability_asset_create",
    responses=_ERR,
)
@csrf_protected
def applicability_asset_create(
    body: ApplicabilityAssetCreateIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Create a library item with its first draft. The code is unique per market and kind, and never changes."""
    _write(request, auth)
    aid = _act(
        db,
        auth,
        lambda: lib.create(
            db, _markets(auth), body.market_code, body.kind, body.code, body.document, auth.actor, request_meta(request)
        ),
    )
    return _detail(db, auth, aid)


@router.get(
    "/assets/{asset_id}",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_asset_get",
    responses=_ERR,
)
def applicability_asset_get(
    asset_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> ApplicabilityAssetDetail:
    """One item: draft, candidates, every published version with what it pins, where it is used, and its history."""
    try:
        return _detail(db, auth, asset_id)
    except SurveyError as exc:
        raise _err(exc) from exc


def _on_asset(db: Session, auth: AuthContext, asset_id: uuid.UUID, work: Any) -> ApplicabilityAssetDetail:
    def run() -> uuid.UUID:
        work()
        return asset_id

    _act(db, auth, run)
    return _detail(db, auth, asset_id)


@router.put(
    "/assets/{asset_id}/draft",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_draft_save",
    responses=_ERR,
)
@csrf_protected
def applicability_draft_save(
    asset_id: uuid.UUID, body: ApplicabilityDraftIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Save the draft. Refused with 409 STALE_REVISION when someone else saved it first: nothing is overwritten."""
    _write(request, auth)
    return _on_asset(
        db,
        auth,
        asset_id,
        lambda: lib.save(
            db, _markets(auth), asset_id, body.expected_revision, body.document, auth.actor, request_meta(request)
        ),
    )


@router.post(
    "/assets/{asset_id}/draft",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_draft_start",
    responses=_ERR,
)
@csrf_protected
def applicability_draft_start(
    asset_id: uuid.UUID, body: ApplicabilityStartDraftIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Start a new draft from a published version. The published version itself never changes."""
    _write(request, auth)
    return _on_asset(
        db,
        auth,
        asset_id,
        lambda: lib.start_draft(db, _markets(auth), asset_id, body.version_no, auth.actor, request_meta(request)),
    )


@router.post(
    "/assets/{asset_id}/draft/discard",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_draft_discard",
    responses=_ERR,
)
@csrf_protected
def applicability_draft_discard(
    asset_id: uuid.UUID, body: ApplicabilityRevisionIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Discard the working draft. Published versions and history are kept."""
    _write(request, auth)
    return _on_asset(
        db,
        auth,
        asset_id,
        lambda: lib.discard_draft(
            db, _markets(auth), asset_id, body.expected_revision, auth.actor, request_meta(request)
        ),
    )


@router.post(
    "/assets/{asset_id}/validate",
    response_model=ApplicabilityValidateOut,
    operation_id="applicability_asset_validate",
    responses=_ERR,
)
@csrf_protected
def applicability_asset_validate(
    asset_id: uuid.UUID, body: ApplicabilityValidateIn, request: Request, auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> ApplicabilityValidateOut:  # fmt: skip
    """Check the saved draft, or an unsaved edit, without changing anything: diagnostics and what it would pin."""
    _write(request, auth)
    try:
        a = lib.asset_row(db, asset_id, _markets(auth))
        market = lib.Market(db, a["market_code"])
        doc = lib.normalise(a["kind"], body.document) if body.document is not None else a["draft"]
        if doc is None:
            raise SurveyError(409, "NO_DRAFT", "There is no draft to check")
        found = lib.validate(market, a, doc)
        pinned, _ = lib.pins(market, a, doc)
    except SurveyError as exc:
        raise _err(exc) from exc
    return ApplicabilityValidateOut(
        diagnostics=[ApplicabilityDiagnostic(**d) for d in found], pins=[ApplicabilityPin(**p) for p in pinned],
        can_submit=not lib.blockers(found),
    )  # fmt: skip


@router.post(
    "/assets/{asset_id}/submit",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_asset_submit",
    responses=_ERR,
)
@csrf_protected
def applicability_asset_submit(
    asset_id: uuid.UUID, body: ApplicabilitySubmitIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Freeze the saved draft as an immutable candidate. Refused while it has a blocker or reads anything unpublished."""
    _write(request, auth)
    return _on_asset(
        db,
        auth,
        asset_id,
        lambda: lib.submit(
            db,
            _markets(auth),
            asset_id,
            body.expected_revision,
            body.note,
            auth.actor,
            request_meta(request),
            None if body.pins is None else [p.model_dump() for p in body.pins],
        ),  # fmt: skip
    )


def _on_candidate(db: Session, auth: AuthContext, candidate_id: uuid.UUID, work: Any) -> ApplicabilityAssetDetail:
    def run() -> uuid.UUID:
        v = lib.version_row(db, candidate_id, _markets(auth))
        work()
        return uuid.UUID(str(v["asset_id"]))

    return _detail(db, auth, _act(db, auth, run))


@router.post(
    "/candidates/{candidate_id}/decision",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_candidate_decide",
    responses=_ERR,
)
@csrf_protected
def applicability_candidate_decide(
    candidate_id: uuid.UUID, body: ApplicabilityDecisionIn, request: Request,
    auth: AuthContext = Depends(require(APPROVE)), _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Approve a candidate or return it to its author. Never by the person who submitted it."""
    _write(request, auth)
    return _on_candidate(
        db,
        auth,
        candidate_id,
        lambda: lib.decide(
            db, _markets(auth), candidate_id, body.verdict, body.comment, auth.actor, request_meta(request)
        ),
    )


@router.post(
    "/candidates/{candidate_id}/publish",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_candidate_publish",
    responses=_ERR,
)
@csrf_protected
def applicability_candidate_publish(
    candidate_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require(PUBLISH)),
    _read: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """Publish an approved candidate as the next immutable version: a third person. The earlier version is kept."""
    _write(request, auth)
    return _on_candidate(
        db, auth, candidate_id, lambda: lib.publish(db, _markets(auth), candidate_id, auth.actor, request_meta(request))
    )


@router.post(
    "/candidates/{candidate_id}/withdraw",
    response_model=ApplicabilityAssetDetail,
    operation_id="applicability_candidate_withdraw",
    responses=_ERR,
)
@csrf_protected
def applicability_candidate_withdraw(
    candidate_id: uuid.UUID, body: ApplicabilityWithdrawIn, request: Request,
    auth: AuthContext = Depends(require(EDIT)), _read: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> ApplicabilityAssetDetail:  # fmt: skip
    """The submitter takes an open candidate back; the draft can be edited again."""
    _write(request, auth)
    return _on_candidate(
        db,
        auth,
        candidate_id,
        lambda: lib.withdraw(db, _markets(auth), candidate_id, body.reason, auth.actor, request_meta(request)),
    )


@router.get(
    "/versions/{version_id}",
    response_model=ApplicabilityVersion,
    operation_id="applicability_version_get",
    responses=_ERR,
)
def applicability_version_get(
    version_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> ApplicabilityVersion:
    """One candidate or published version, exactly as it was frozen."""
    try:
        v = lib.version_row(db, version_id, _markets(auth))
    except SurveyError as exc:
        raise _err(exc) from exc
    names = lib._names(db, [v["submitted_by"], v["decided_by"], v["published_by"]])  # noqa: SLF001
    return ApplicabilityVersion(**lib._version_out(v, names, str(auth.principal_id)))  # noqa: SLF001


def _market(auth: AuthContext, wanted: str | None) -> str:
    markets = _markets(auth)
    if wanted:
        if wanted not in markets:
            raise AppError(403, "MARKET_NOT_IN_SCOPE", "You cannot read the applicability library of this market")
        return wanted
    if len(markets) != 1:
        raise AppError(422, "MARKET_REQUIRED", "Name the market")
    return markets[0]


@router.get("/workspace", response_model=ApplicabilityWorkspace, operation_id="applicability_workspace", responses=_ERR)
def applicability_workspace(
    market_code: str | None = None, view: Literal["authoring", "published"] = "authoring",
    auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db),
) -> ApplicabilityWorkspace:  # fmt: skip
    """The library of one market as the evaluator reads it. ``published``: published versions only. ``authoring``: a
    working draft stands in for its item where one exists, marked ``DRAFT``."""
    code = _market(auth, market_code)
    return ApplicabilityWorkspace(
        market_code=code, view=view, **lib.Market(db, code).workspace(drafts=view == "authoring")
    )


@router.post("/test", response_model=ApplicabilityTestOut, operation_id="applicability_expression_test", responses=_ERR)
@csrf_protected
def applicability_expression_test(
    body: ApplicabilityTestIn, request: Request, auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> ApplicabilityTestOut:  # fmt: skip
    """TRUE, FALSE or UNKNOWN for one expression and one set of synthetic facts, against the PERSISTED library, with
    the full trace. Run by the Python evaluator; nothing is stored."""
    _write(request, auth)
    code = _market(auth, body.market_code)
    try:
        out = lib.test_expression(db, code, body.expr, body.facts, body.profiles, drafts=body.view == "authoring")
    except ApplicabilityError as exc:
        return ApplicabilityTestOut(
            result=None,
            trace=None,
            facts={},
            diagnostics=[],
            error={"code": exc.code, "message": exc.message, "at": exc.at},
        )
    return ApplicabilityTestOut(**out)
