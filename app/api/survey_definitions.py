"""SS-03A.3 — survey definition API: drafts, immutable candidates, published versions, the library and condition
evaluation. Fifteen operations under ``/api/v1``, with "survey" vocabulary (owner decision D-166).

Registered ONLY when the server setting ``survey_definitions_enabled`` is on; it is off by default, and no screen calls
these operations. The path is ``/survey-definitions``: the bare plural of "survey" is a legacy route name retired by
ADR-0007 and is deliberately not reactivated.

Permissions: ``survey.read``, ``survey.edit``, ``survey.approve``, ``survey.publish``: four separate permissions,
none implying another, granted to no role by the migration. Identity rules are enforced by the service and by the
database independently of them. Every survey is market-scoped: one outside the caller's markets does not exist for
them.

Nothing here executes a survey, assembles a call plan, speaks, dials, or implements any non-answer, refusal, repeat,
consent or timeout behaviour.
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
from app.domain.survey import store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import ConditionError, Explanation, check_condition, evaluate
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["survey-definitions"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
MARKET = "SG"  # Singapore-only synthetic development (D-39)
NOTE = "Synthetic content, unapproved for operational use. No survey here is eligible for a live call."

READ, EDIT, APPROVE, PUBLISH = "survey.read", "survey.edit", "survey.approve", "survey.publish"


# ---------------------------------------------------------------------------------------------------------------- DTOs
class SurveyCreateIn(BaseModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{2,59}$")
    name: str = Field(min_length=3, max_length=160)
    purpose: str = Field(default="", max_length=2000)


class SurveyOut(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    purpose: str
    market_code: str
    draft_revision: int
    open_candidate_id: uuid.UUID | None
    open_candidate_status: str | None
    latest_version_id: uuid.UUID | None
    latest_version_label: str | None
    note: str = NOTE


class SurveyList(BaseModel):
    items: list[SurveyOut]


class SurveyDraftAsset(BaseModel):
    kind: str
    code: str
    version: int
    state: Literal["DRAFT", "FROZEN"]
    sha256: str


class SurveyDraftOut(BaseModel):
    survey_id: uuid.UUID
    revision: int
    content: dict[str, Any]
    content_sha256: str
    assets: list[SurveyDraftAsset]
    updated_at: datetime


class SurveyOperationIn(BaseModel):
    expected_revision: int = Field(ge=0)
    operation: dict[str, Any]


class SurveyFindingOut(BaseModel):
    code: str
    at: str
    severity: Literal["BLOCKER", "WARNING", "INFO"]
    message: str


class SurveyValidationOut(BaseModel):
    revision: int
    blockers: int
    findings: list[SurveyFindingOut]


class SurveySubmitIn(BaseModel):
    note: str = Field(default="", max_length=2000)
    acknowledgements: list[dict[str, Any]] = Field(default_factory=list, max_length=200)


class SurveyLifecycleEvent(BaseModel):
    event: str
    actor_ref: str
    actor_name: str | None
    reason: str | None
    occurred_at: datetime


class SurveyManifestEntry(BaseModel):
    kind: str
    code: str
    version: int
    sha256: str


class SurveyCandidateOut(BaseModel):
    id: uuid.UUID
    survey_id: uuid.UUID
    n: int
    status: str
    draft_revision: int
    content: dict[str, Any]
    content_sha256: str
    manifest: list[SurveyManifestEntry]
    manifest_sha256: str
    manifest_intact: bool
    note: str
    submitted_by: str
    submitted_at: datetime
    history: list[SurveyLifecycleEvent]


class SurveyDecisionIn(BaseModel):
    verdict: Literal["APPROVE", "REJECT"]
    comment: str = Field(default="", max_length=2000)


class SurveyWithdrawIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class SurveyPublishIn(BaseModel):
    effective_from: datetime | None = Field(
        default=None,
        description="Recorded only. Nothing takes effect on a date: scheduled publication has no behaviour.",
    )


class SurveyVersionOut(BaseModel):
    id: uuid.UUID
    survey_id: uuid.UUID
    version_no: int
    label: str
    status: str
    candidate_id: uuid.UUID
    content_sha256: str
    manifest_sha256: str
    effective_from: datetime | None
    created_at: datetime
    history: list[SurveyLifecycleEvent]
    note: str = NOTE


class SurveyVersionContent(BaseModel):
    version_id: uuid.UUID
    content: dict[str, Any]
    content_sha256: str
    manifest: list[SurveyManifestEntry]
    manifest_sha256: str


class SurveyLibraryItem(BaseModel):
    kind: str
    code: str
    version: int
    sha256: str
    frozen_at: datetime
    candidates: int
    versions: int


class SurveyLibraryOut(BaseModel):
    kind: str
    items: list[SurveyLibraryItem]


class SurveyConditionEvaluateIn(BaseModel):
    condition: dict[str, Any] = Field(description="A condition version document, or at least {ast, params, inputs}.")
    params: dict[str, Any] = Field(default_factory=dict)
    facts: dict[str, Any] = Field(default_factory=dict)
    answers: dict[str, Any] = Field(default_factory=dict)


class SurveyConditionExplanation(BaseModel):
    op: str
    result: Literal["TRUE", "FALSE", "UNKNOWN"]
    reads: list[dict[str, Any]]
    children: list[SurveyConditionExplanation]


class SurveyConditionEvaluateOut(BaseModel):
    result: Literal["TRUE", "FALSE", "UNKNOWN"]
    explanation: SurveyConditionExplanation
    note: str = "UNKNOWN is reported, never resolved here: the binding's stated policy says what happens next."


# ------------------------------------------------------------------------------------------------------------- helpers
def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: store.SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext) -> None:
    """Every state-changing request: session-bound CSRF token, then the per-person rate limit."""
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"survey-writes:{auth.principal_id}", settings.survey_writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many survey changes; try again shortly", retryable=True)


def _events(db: Session, subject: uuid.UUID) -> list[SurveyLifecycleEvent]:
    return [
        SurveyLifecycleEvent(
            event=h["event"], actor_ref=h["actor_ref"], actor_name=h["display_name"], reason=h["reason"],
            occurred_at=h["occurred_at"],
        )
        for h in store.history(db, subject)
    ]  # fmt: skip


def _survey_out(db: Session, row: dict[str, Any]) -> SurveyOut:
    sid = row["id"]
    open_c: tuple[uuid.UUID | None, str | None] = (None, None)
    for c in reversed(store.candidates_of(db, sid)):
        status = store.status_of(db, c["id"])
        if status in store.OPEN_CANDIDATE:
            open_c = (c["id"], status)
            break
    versions = store.versions_of(db, sid)
    return SurveyOut(
        id=sid, code=row["code"], name=row["name"], purpose=row["purpose"], market_code=row["market_code"],
        draft_revision=store.draft(db, sid)["revision"], open_candidate_id=open_c[0], open_candidate_status=open_c[1],
        latest_version_id=versions[-1]["id"] if versions else None,
        latest_version_label=versions[-1]["label"] if versions else None,
    )  # fmt: skip


def _draft_out(db: Session, sid: uuid.UUID) -> SurveyDraftOut:
    d = store.draft(db, sid)
    assets = store._all(  # noqa: SLF001 — one read of the survey's own draft and frozen assets
        db,
        "SELECT kind, code, version, state, sha256 FROM survey_asset_version WHERE owner_definition_id = :s "
        "ORDER BY kind, code, version",
        s=sid,
    )
    return SurveyDraftOut(
        survey_id=sid, revision=d["revision"], content=d["content"], content_sha256=sha256_hex(d["content"]),
        assets=[SurveyDraftAsset(**a) for a in assets], updated_at=d["updated_at"],
    )  # fmt: skip


def _candidate_out(db: Session, c: dict[str, Any]) -> SurveyCandidateOut:
    return SurveyCandidateOut(
        id=c["id"], survey_id=c["survey_definition_id"], n=c["n"], status=store.status_of(db, c["id"]) or "UNKNOWN",
        draft_revision=c["draft_revision"], content=c["content"], content_sha256=c["content_sha256"],
        manifest=[SurveyManifestEntry(**e) for e in c["manifest"]], manifest_sha256=c["manifest_sha256"],
        manifest_intact=not store.manifest_problems(db, c), note=c["note"], submitted_by=c["submitted_by"],
        submitted_at=c["submitted_at"], history=_events(db, c["id"]),
    )  # fmt: skip


def _version_out(db: Session, v: dict[str, Any]) -> SurveyVersionOut:
    return SurveyVersionOut(
        id=v["id"], survey_id=v["survey_definition_id"], version_no=v["version_no"], label=v["label"],
        status=store.status_of(db, v["id"]) or "UNKNOWN", candidate_id=v["candidate_id"],
        content_sha256=v["content_sha256"], manifest_sha256=v["manifest_sha256"], effective_from=v["effective_from"],
        created_at=v["created_at"], history=_events(db, v["id"]),
    )  # fmt: skip


def _explain(e: Explanation) -> SurveyConditionExplanation:
    return SurveyConditionExplanation(
        op=e.op, result=e.result, reads=[{"kind": k, "name": n, "value": v} for k, n, v in e.reads],
        children=[_explain(c) for c in e.children],
    )  # fmt: skip


# ------------------------------------------------------------------------------------------------------------ surveys
@router.post(
    "/survey-definitions",
    response_model=SurveyOut,
    status_code=201,
    operation_id="survey_definition_create",
    responses=_ERR,
)
@csrf_protected
def survey_definition_create(
    body: SurveyCreateIn, request: Request, auth: AuthContext = Depends(require(EDIT)), db: Session = Depends(get_db)
) -> SurveyOut:
    """Create a survey and its empty draft."""
    _write(request, auth)
    if MARKET not in auth.markets:
        raise AppError(403, "MARKET_NOT_IN_SCOPE", "Not available in your markets")
    try:
        sid = store.create_survey(
            db, code=body.code, name=body.name, purpose=body.purpose, market=MARKET, actor=auth.actor,
            meta=request_meta(request),
        )  # fmt: skip
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return _survey_out(db, store.survey(db, sid, _markets(auth)))


@router.get("/survey-definitions", response_model=SurveyList, operation_id="survey_definition_list", responses=_ERR)
def survey_definition_list(auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)) -> SurveyList:
    """Surveys in the caller's markets, with the status derived from their history."""
    return SurveyList(items=[_survey_out(db, r) for r in store.surveys(db, _markets(auth))])


@router.get(
    "/survey-definitions/{survey_id}", response_model=SurveyOut, operation_id="survey_definition_get", responses=_ERR
)
def survey_definition_get(
    survey_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyOut:
    try:
        return _survey_out(db, store.survey(db, survey_id, _markets(auth)))
    except store.SurveyError as exc:
        raise _err(exc) from exc


# -------------------------------------------------------------------------------------------------------------- drafts
@router.get(
    "/survey-definitions/{survey_id}/draft",
    response_model=SurveyDraftOut,
    operation_id="survey_draft_get",
    responses=_ERR,
)
def survey_draft_get(
    survey_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyDraftOut:
    """The draft content document, its revision and the asset versions this survey owns."""
    try:
        store.survey(db, survey_id, _markets(auth))
    except store.SurveyError as exc:
        raise _err(exc) from exc
    return _draft_out(db, survey_id)


@router.post(
    "/survey-definitions/{survey_id}/draft/operations",
    response_model=SurveyDraftOut,
    operation_id="survey_draft_operation",
    responses=_ERR,
)
@csrf_protected
def survey_draft_operation(
    survey_id: uuid.UUID,
    body: SurveyOperationIn,
    request: Request,
    auth: AuthContext = Depends(require(EDIT)),
    db: Session = Depends(get_db),
) -> SurveyDraftOut:
    """Apply ONE operation to the draft: ``PUT_ASSET``, ``REMOVE_ASSET`` or ``SET_CONTENT``. ``expected_revision``
    must be the draft's current revision; a stale one is refused with ``STALE_DRAFT`` and nothing is changed."""
    _write(request, auth)
    try:
        store.apply_operation(
            db, survey_id, _markets(auth), body.expected_revision, body.operation, auth.actor, request_meta(request)
        )
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return _draft_out(db, survey_id)


@router.post(
    "/survey-definitions/{survey_id}/draft/validate",
    response_model=SurveyValidationOut,
    operation_id="survey_draft_validate",
    responses=_ERR,
)
@csrf_protected
def survey_draft_validate(
    survey_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require(EDIT)), db: Session = Depends(get_db)
) -> SurveyValidationOut:
    """Server validation of the draft: stable codes, never matched by message. Nothing is stored."""
    _write(request, auth)
    try:
        store.survey(db, survey_id, _markets(auth))
    except store.SurveyError as exc:
        raise _err(exc) from exc
    d = store.draft(db, survey_id)
    findings = [
        SurveyFindingOut(**{k: f[k] for k in ("code", "at", "severity", "message")})
        for f in store.findings_of(db, d["content"])
    ]
    db.rollback()
    return SurveyValidationOut(
        revision=d["revision"], blockers=sum(f.severity == "BLOCKER" for f in findings), findings=findings
    )


# ---------------------------------------------------------------------------------------------------------- candidates
@router.post(
    "/survey-definitions/{survey_id}/candidates",
    response_model=SurveyCandidateOut,
    status_code=201,
    operation_id="survey_candidate_submit",
    responses=_ERR,
)
@csrf_protected
def survey_candidate_submit(
    survey_id: uuid.UUID,
    body: SurveySubmitIn,
    request: Request,
    auth: AuthContext = Depends(require(EDIT)),
    db: Session = Depends(get_db),
) -> SurveyCandidateOut:
    """Submit the draft: freeze what it pins, build the manifest, insert an immutable candidate. The draft stays
    editable. A draft with any blocker is refused with ``VALIDATION_BLOCKED``."""
    _write(request, auth)
    try:
        cid = store.submit(
            db, survey_id, _markets(auth), body.note, body.acknowledgements, auth.actor, request_meta(request)
        )
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return _candidate_out(db, store.candidate(db, cid, _markets(auth)))


@router.get(
    "/survey-candidates/{candidate_id}",
    response_model=SurveyCandidateOut,
    operation_id="survey_candidate_get",
    responses=_ERR,
)
def survey_candidate_get(
    candidate_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyCandidateOut:
    try:
        return _candidate_out(db, store.candidate(db, candidate_id, _markets(auth)))
    except store.SurveyError as exc:
        raise _err(exc) from exc


def _decided(db: Session, candidate_id: uuid.UUID, auth: AuthContext) -> SurveyCandidateOut:
    db.commit()
    return _candidate_out(db, store.candidate(db, candidate_id, _markets(auth)))


@router.post(
    "/survey-candidates/{candidate_id}/decision",
    response_model=SurveyCandidateOut,
    operation_id="survey_candidate_decide",
    responses=_ERR,
)
@csrf_protected
def survey_candidate_decide(
    candidate_id: uuid.UUID,
    body: SurveyDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require(APPROVE)),
    db: Session = Depends(get_db),
) -> SurveyCandidateOut:
    """Approve or reject. Never by a maker of the candidate, whatever they are permitted (``SELF_REVIEW_DENIED``). The
    manifest is re-verified first (``MANIFEST_MISMATCH``)."""
    _write(request, auth)
    try:
        store.decide(db, candidate_id, _markets(auth), body.verdict, body.comment, auth.actor, request_meta(request))
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    return _decided(db, candidate_id, auth)


@router.post(
    "/survey-candidates/{candidate_id}/withdraw",
    response_model=SurveyCandidateOut,
    operation_id="survey_candidate_withdraw",
    responses=_ERR,
)
@csrf_protected
def survey_candidate_withdraw(
    candidate_id: uuid.UUID,
    body: SurveyWithdrawIn,
    request: Request,
    auth: AuthContext = Depends(require(EDIT)),
    db: Session = Depends(get_db),
) -> SurveyCandidateOut:
    """Withdraw an open candidate. Only its submitter."""
    _write(request, auth)
    try:
        store.withdraw(db, candidate_id, _markets(auth), body.reason, auth.actor, request_meta(request))
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    return _decided(db, candidate_id, auth)


@router.post(
    "/survey-candidates/{candidate_id}/publish",
    response_model=SurveyVersionOut,
    status_code=201,
    operation_id="survey_candidate_publish",
    responses=_ERR,
)
@csrf_protected
def survey_candidate_publish(
    candidate_id: uuid.UUID,
    body: SurveyPublishIn,
    request: Request,
    auth: AuthContext = Depends(require(PUBLISH)),
    db: Session = Depends(get_db),
) -> SurveyVersionOut:
    """Publish an approved candidate as an immutable version. Never by a maker (``SELF_PUBLISH_DENIED``) nor, until
    governance rules otherwise, by its approver (``APPROVER_PUBLISH_DENIED``). Publishing makes nothing eligible for a
    live call."""
    _write(request, auth)
    try:
        vid = store.publish(db, candidate_id, _markets(auth), body.effective_from, auth.actor, request_meta(request))
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return _version_out(db, store.version(db, vid, _markets(auth)))


# ------------------------------------------------------------------------------------------------------------ versions
@router.get(
    "/survey-versions/{version_id}", response_model=SurveyVersionOut, operation_id="survey_version_get", responses=_ERR
)
def survey_version_get(
    version_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyVersionOut:
    try:
        return _version_out(db, store.version(db, version_id, _markets(auth)))
    except store.SurveyError as exc:
        raise _err(exc) from exc


@router.get(
    "/survey-versions/{version_id}/content",
    response_model=SurveyVersionContent,
    operation_id="survey_version_content",
    responses=_ERR,
)
def survey_version_content(
    version_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyVersionContent:
    """The published content document and the manifest that pins every version it uses."""
    try:
        v = store.version(db, version_id, _markets(auth))
    except store.SurveyError as exc:
        raise _err(exc) from exc
    return SurveyVersionContent(
        version_id=v["id"], content=v["content"], content_sha256=v["content_sha256"],
        manifest=[SurveyManifestEntry(**e) for e in v["manifest"]], manifest_sha256=v["manifest_sha256"],
    )  # fmt: skip


# ----------------------------------------------------------------------------------------------- library and conditions
@router.get(
    "/survey-library/{kind}", response_model=SurveyLibraryOut, operation_id="survey_library_list", responses=_ERR
)
def survey_library_list(
    kind: Literal["OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE"],
    _auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyLibraryOut:
    """Frozen asset versions of one kind, with how many candidates and versions pin each."""
    return SurveyLibraryOut(kind=kind, items=[SurveyLibraryItem(**r) for r in store.library(db, kind)])


@router.post(
    "/survey-conditions/evaluate",
    response_model=SurveyConditionEvaluateOut,
    operation_id="survey_condition_evaluate",
    responses=_ERR,
)
@csrf_protected
def survey_condition_evaluate(
    body: SurveyConditionEvaluateIn,
    request: Request,
    auth: AuthContext = Depends(require(READ)),
    db: Session = Depends(get_db),
) -> SurveyConditionEvaluateOut:
    """Evaluate one condition against supplied facts and answers: TRUE, FALSE or UNKNOWN with the explanation.
    Read-only: nothing is stored, and missing information is UNKNOWN, never FALSE."""
    _write(request, auth)
    fields, _, _ = store.catalogs(db)
    problems = check_condition(body.condition, fields)
    if problems:
        raise AppError(
            422,
            "CONDITION_INVALID",
            "The condition is not well formed",
            details=[{"code": c, "message": d} for c, d in problems],
        )
    try:
        ex = evaluate(body.condition.get("ast") or {}, body.params, body.facts, body.answers)
    except ConditionError as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return SurveyConditionEvaluateOut(result=ex.result, explanation=_explain(ex))
