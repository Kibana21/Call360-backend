"""S2-A Script Studio authoring API (SUR-002/003/005/006/007, SCR-007/008/012/013/014/015; ADR-0007).

Every change is server-validated, market-scoped, CSRF-protected, rate-limited, audited and recorded in the version's
change history. Drafts are changed with an optimistic-concurrency token (``expected_row_version``). Approve and
publish need ``script.approve`` / ``script.publish`` (S&C checker role) and a principal who did not author or edit the
version; ADMIN holds neither (ADR-0004, D-54).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    AbandonIn,
    AuthoringOptions,
    ControlLinksIn,
    DiffVersionRef,
    DraftChanged,
    DraftCreated,
    ErrorResponse,
    LifecycleOut,
    ModuleOption,
    OrderIn,
    PickOption,
    PublishIn,
    QuestionAdd,
    QuestionBankItemOut,
    QuestionBankList,
    QuestionUpdate,
    ReviewIn,
    ScriptChangeEventOut,
    ScriptDiff,
    ScriptDraftCreate,
    ScriptFamilyCreate,
    ScriptHistory,
    SectionCreate,
    SectionUpdate,
    SubmitIn,
    ValidationResult,
)
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import answer_evaluation as ae
from app.domain import lifecycle as lc
from app.domain import script_authoring as sa
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["script-studio"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}


def _guard(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"script-writes:{auth.principal_id}", settings.script_writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many script changes; try again shortly", retryable=True)


def _err(exc: sa.AuthoringError) -> AppError:
    details = exc.details.get("issues") or ([exc.details] if exc.details else None)
    return AppError(exc.status, exc.code, exc.message, details=details)


def _who(auth: AuthContext) -> tuple[str, str]:
    return str(auth.principal_id), auth.display_name


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    entity_type: str,
    entity_id: Any,
    after: dict[str, Any],
    outcome: str = "SUCCEEDED",
    reason: str | None = None,
) -> None:
    write_audit(
        db,
        action=action,
        outcome=outcome,
        actor=auth.actor,
        meta=request_meta(request),
        entity_type=entity_type,
        entity_id=str(entity_id),
        reason=reason,
        after=after,
    )


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _change(
    request: Request, auth: AuthContext, db: Session, vid: uuid.UUID, action: str, fn: Any, *args: Any, **kw: Any
) -> DraftChanged:
    _guard(request, auth)
    try:
        rv = fn(db, vid, _markets(auth), *args, *_who(auth), **kw)
    except sa.AuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, f"SCRIPT.{action}", "script_version", vid, {"row_version": rv})
    db.commit()
    return DraftChanged(script_version_id=vid, row_version=rv)


# ---- families and drafts ----------------------------------------------------------------------------------------
@router.post(
    "/scripts", response_model=DraftCreated, status_code=201, operation_id="script_family_create", responses=_ERR
)
@csrf_protected
def create_family(
    body: ScriptFamilyCreate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftCreated:
    """Create a script family and its first draft version (v1.0)."""
    _guard(request, auth)
    if body.market not in auth.markets:
        raise AppError(403, "MARKET_NOT_IN_SCOPE", "You can only create scripts in your markets")
    try:
        fid, vid = sa.create_family(
            db,
            code=body.code,
            name=body.name,
            purpose=body.purpose,
            description=body.description,
            market=body.market,
            actor_ref=str(auth.principal_id),
            actor_name=auth.display_name,
        )
    except sa.AuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db, request, auth, "SCRIPT.FAMILY_CREATED", "script_family", fid, {"code": body.code.upper(), "draft": str(vid)}
    )
    db.commit()
    return DraftCreated(script_family_id=fid, script_version_id=vid, version_label="1.0")


@router.post(
    "/scripts/{script_family_id}/drafts",
    response_model=DraftCreated,
    status_code=201,
    operation_id="script_draft_create",
    responses=_ERR,
)
@csrf_protected
def create_draft(
    script_family_id: uuid.UUID,
    body: ScriptDraftCreate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftCreated:
    """New draft version of a family, starting from a base version (default: the published one). One open version
    (draft, submitted or approved) per family."""
    _guard(request, auth)
    try:
        vid = sa.create_draft(db, script_family_id, _markets(auth), body.base_version_id, *_who(auth))
    except sa.AuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    label = db.execute(text("SELECT version_label FROM script_version WHERE id = :v"), {"v": vid}).scalar_one()
    _audit(
        db,
        request,
        auth,
        "SCRIPT.DRAFT_CREATED",
        "script_version",
        vid,
        {"family": str(script_family_id), "label": label},
    )
    db.commit()
    return DraftCreated(script_family_id=script_family_id, script_version_id=vid, version_label=label)


# ---- sections ---------------------------------------------------------------------------------------------------
@router.post(
    "/script-versions/{script_version_id}/sections",
    response_model=DraftChanged,
    operation_id="script_section_add",
    responses=_ERR,
)
@csrf_protected
def add_section(
    script_version_id: uuid.UUID,
    body: SectionCreate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "SECTION_ADDED",
        sa.add_section,
        body.expected_row_version,
        module_id=body.module_id,
        code=body.module_code,
        name=body.module_name,
        kind=body.module_kind,
        condition=body.inclusion_condition,
    )


@router.patch(
    "/script-versions/{script_version_id}/sections/{section_id}",
    response_model=DraftChanged,
    operation_id="script_section_update",
    responses=_ERR,
)
@csrf_protected
def update_section(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    body: SectionUpdate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "SECTION_CHANGED",
        _update_section,
        body.expected_row_version,
        section_id=section_id,
        condition=body.inclusion_condition,
        name=body.module_name,
    )


def _update_section(db: Session, vid: uuid.UUID, m: list[str], rv: int, a: str, n: str, **kw: Any) -> int:
    return sa.update_section(db, vid, m, rv, a, n, kw.pop("section_id"), **kw)


@router.delete(
    "/script-versions/{script_version_id}/sections/{section_id}",
    response_model=DraftChanged,
    operation_id="script_section_remove",
    responses=_ERR,
)
@csrf_protected
def remove_section(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    request: Request,
    expected_row_version: int = Query(),
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "SECTION_REMOVED",
        lambda d, v, m, rv, a, n: sa.remove_section(d, v, m, rv, a, n, section_id),
        expected_row_version,
    )


@router.post(
    "/script-versions/{script_version_id}/sections/reorder",
    response_model=DraftChanged,
    operation_id="script_sections_reorder",
    responses=_ERR,
)
@csrf_protected
def reorder_sections(
    script_version_id: uuid.UUID,
    body: OrderIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "SECTIONS_REORDERED",
        lambda d, v, m, rv, a, n: sa.reorder_sections(d, v, m, rv, a, n, body.order),
        body.expected_row_version,
    )


# ---- questions --------------------------------------------------------------------------------------------------
@router.post(
    "/script-versions/{script_version_id}/sections/{section_id}/questions",
    response_model=DraftChanged,
    operation_id="script_question_add",
    responses=_ERR,
)
@csrf_protected
def add_question(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    body: QuestionAdd,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    """Add a new question (with content) or reuse a question-bank question (by code; content optional)."""
    content = body.content.model_dump() if body.content else None
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "QUESTION_ADDED",
        lambda d, v, m, rv, a, n: sa.add_question(
            d,
            v,
            m,
            rv,
            a,
            n,
            section_id,
            question_code=body.question_code,
            content=content,
            branch=body.branch_condition,
            reason=body.change_reason,
        ),
        body.expected_row_version,
    )


@router.put(
    "/script-versions/{script_version_id}/sections/{section_id}/questions/{module_question_id}",
    response_model=DraftChanged,
    operation_id="script_question_update",
    responses=_ERR,
)
@csrf_protected
def update_question(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    module_question_id: uuid.UUID,
    body: QuestionUpdate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    """Change a question. Changed content becomes a new question revision; earlier revisions never change."""
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "QUESTION_CHANGED",
        lambda d, v, m, rv, a, n: sa.update_question(
            d,
            v,
            m,
            rv,
            a,
            n,
            section_id,
            module_question_id,
            content=body.content.model_dump(),
            branch=body.branch_condition,
            reason=body.change_reason,
        ),
        body.expected_row_version,
    )


@router.delete(
    "/script-versions/{script_version_id}/sections/{section_id}/questions/{module_question_id}",
    response_model=DraftChanged,
    operation_id="script_question_remove",
    responses=_ERR,
)
@csrf_protected
def remove_question(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    module_question_id: uuid.UUID,
    request: Request,
    expected_row_version: int = Query(),
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "QUESTION_REMOVED",
        lambda d, v, m, rv, a, n: sa.remove_question(d, v, m, rv, a, n, section_id, module_question_id),
        expected_row_version,
    )


@router.post(
    "/script-versions/{script_version_id}/sections/{section_id}/questions/reorder",
    response_model=DraftChanged,
    operation_id="script_questions_reorder",
    responses=_ERR,
)
@csrf_protected
def reorder_questions(
    script_version_id: uuid.UUID,
    section_id: uuid.UUID,
    body: OrderIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "QUESTIONS_REORDERED",
        lambda d, v, m, rv, a, n: sa.reorder_questions(d, v, m, rv, a, n, section_id, body.order),
        body.expected_row_version,
    )


@router.put(
    "/script-versions/{script_version_id}/questions/{question_code}/controls",
    response_model=DraftChanged,
    operation_id="script_question_controls",
    responses=_ERR,
)
@csrf_protected
def set_controls(
    script_version_id: uuid.UUID,
    question_code: str,
    body: ControlLinksIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> DraftChanged:
    """Link a question to existing controls and, optionally, a regulatory reference (proposed links; removed links
    are retired, never deleted)."""
    links = [x.model_dump() for x in body.links]
    return _change(
        request,
        auth,
        db,
        script_version_id,
        "CONTROLS_CHANGED",
        lambda d, v, m, rv, a, n: sa.set_controls(d, v, m, rv, a, n, question_code, links),
        body.expected_row_version,
    )


# ---- validation and lifecycle -----------------------------------------------------------------------------------
@router.post(
    "/script-versions/{script_version_id}/validate",
    response_model=ValidationResult,
    operation_id="script_version_validate",
    responses=_ERR,
)
@csrf_protected
def validate(
    script_version_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> ValidationResult:
    _guard(request, auth)
    try:
        v = sa.version_row(db, script_version_id, _markets(auth), lock=True)
        if v["status"] != "DRAFT":
            raise sa.AuthoringError(409, "VERSION_NOT_EDITABLE", "Only drafts are validated")
        issues = sa.validate(db, v)
        status = sa.record_validation(db, v, issues, *_who(auth))
    except sa.AuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return ValidationResult(script_version_id=script_version_id, validation_status=status, issues=issues)


@router.post(
    "/script-versions/{script_version_id}/submit",
    response_model=LifecycleOut,
    operation_id="script_version_submit",
    responses=_ERR,
)
@csrf_protected
def submit(
    script_version_id: uuid.UUID,
    body: SubmitIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> LifecycleOut:
    """Validate, freeze the manifest (SHA-256) and lock the draft for review."""
    _guard(request, auth)
    try:
        out = sa.submit(
            db, script_version_id, _markets(auth), body.expected_row_version, *_who(auth), body.change_summary
        )
    except sa.AuthoringError as exc:
        if exc.code == "VALIDATION_FAILED":
            db.commit()  # keep the recorded INVALID validation result
        else:
            db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "SCRIPT.SUBMITTED",
        "script_version",
        script_version_id,
        {"manifest_sha256": out["manifest_sha256"]},
        reason=body.change_summary,
    )
    db.commit()
    return LifecycleOut(
        script_version_id=script_version_id,
        status="SUBMITTED_FOR_REVIEW",
        manifest_sha256=out["manifest_sha256"],
        issues=out["issues"],
    )


@router.post(
    "/script-versions/{script_version_id}/review",
    response_model=LifecycleOut,
    operation_id="script_version_review",
    responses=_ERR,
)
@csrf_protected
def review(
    script_version_id: uuid.UUID,
    body: ReviewIn,
    request: Request,
    auth: AuthContext = Depends(require("script.approve")),
    db: Session = Depends(get_db),
) -> LifecycleOut:
    """Checker decision: approve, or return the version to its author with the requested changes."""
    _guard(request, auth)
    try:
        status = sa.review(
            db,
            script_version_id,
            _markets(auth),
            *_who(auth),
            body.decision,
            body.reason,
            body.acknowledged_unmapped_mandatory,
        )
    except sa.AuthoringError as exc:
        db.rollback()
        if exc.code == "SELF_REVIEW_DENIED":
            _audit(
                db,
                request,
                auth,
                "SCRIPT.REVIEW_DENIED",
                "script_version",
                script_version_id,
                {"reason": exc.code},
                outcome="DENIED",
            )
            db.commit()
        raise _err(exc) from exc
    action = "SCRIPT.APPROVED" if status == "APPROVED" else "SCRIPT.CHANGES_REQUESTED"
    _audit(db, request, auth, action, "script_version", script_version_id, {"status": status}, reason=body.reason)
    db.commit()
    sha = db.execute(
        text("SELECT manifest_sha256 FROM script_version WHERE id = :v"), {"v": script_version_id}
    ).scalar()
    return LifecycleOut(script_version_id=script_version_id, status=status, manifest_sha256=sha)


@router.post(
    "/script-versions/{script_version_id}/publish",
    response_model=LifecycleOut,
    operation_id="script_version_publish",
    responses=_ERR,
)
@csrf_protected
def publish(
    script_version_id: uuid.UUID,
    body: PublishIn,
    request: Request,
    auth: AuthContext = Depends(require("script.publish")),
    db: Session = Depends(get_db),
) -> LifecycleOut:
    """Publish an approved version now (immutable from here); optionally supersede the family's published version."""
    _guard(request, auth)
    try:
        out = sa.publish(db, script_version_id, _markets(auth), *_who(auth), body.supersede_version_id, body.reason)
    except sa.AuthoringError as exc:
        db.rollback()
        if exc.code == "SELF_PUBLISH_DENIED":
            _audit(
                db,
                request,
                auth,
                "SCRIPT.PUBLISH_DENIED",
                "script_version",
                script_version_id,
                {"reason": exc.code},
                outcome="DENIED",
            )
            db.commit()
        raise _err(exc) from exc
    sha = db.execute(
        text("SELECT manifest_sha256 FROM script_version WHERE id = :v"), {"v": script_version_id}
    ).scalar()
    _audit(
        db,
        request,
        auth,
        "SCRIPT.PUBLISHED",
        "script_version",
        script_version_id,
        {"manifest_sha256": sha, "superseded": out["superseded"]},
        reason=body.reason,
    )
    db.commit()
    return LifecycleOut(
        script_version_id=script_version_id, status="PUBLISHED", manifest_sha256=sha, superseded=out["superseded"]
    )


@router.post(
    "/script-versions/{script_version_id}/abandon",
    response_model=LifecycleOut,
    operation_id="script_version_abandon",
    responses=_ERR,
)
@csrf_protected
def abandon(
    script_version_id: uuid.UUID,
    body: AbandonIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> LifecycleOut:
    """Abandon a draft (S2-A.1): its author or an editor, with a reason. Nothing is deleted; the abandoned content and
    its history stay readable and frozen, and the family may start a new draft."""
    _guard(request, auth)
    try:
        sa.abandon(db, script_version_id, _markets(auth), body.expected_row_version, *_who(auth), body.reason)
    except sa.AuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "SCRIPT.DRAFT_ABANDONED",
        "script_version",
        script_version_id,
        {"status": "ABANDONED"},
        reason=body.reason,
    )
    db.commit()
    return LifecycleOut(script_version_id=script_version_id, status="ABANDONED", manifest_sha256=None)


# ---- reading: history, diff, question bank, options ---------------------------------------------------------------
@router.get(
    "/script-versions/{script_version_id}/history",
    response_model=ScriptHistory,
    operation_id="script_version_history",
    responses=_ERR,
)
def history(
    script_version_id: uuid.UUID,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScriptHistory:
    try:
        v = sa.version_row(db, script_version_id, _markets(auth))
    except sa.AuthoringError as exc:
        raise _err(exc) from exc
    events = db.execute(
        text("SELECT * FROM script_change_event WHERE script_version_id = :v ORDER BY seq"), {"v": script_version_id}
    ).mappings()
    return ScriptHistory(
        script_version_id=script_version_id,
        version_label=v["version_label"],
        status=v["status"],
        makers=sorted(sa.makers(db, script_version_id, v["author_ref"])),
        events=[ScriptChangeEventOut(**{k: e[k] for k in ScriptChangeEventOut.model_fields}) for e in events],
    )


@router.get(
    "/script-versions/{script_version_id}/diff",
    response_model=ScriptDiff,
    operation_id="script_version_diff",
    responses=_ERR,
)
def version_diff(
    script_version_id: uuid.UUID,
    against: uuid.UUID | None = Query(default=None),
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScriptDiff:
    """Semantic comparison with another version of the same family (default: the version this one was based on)."""
    try:
        v = sa.version_row(db, script_version_id, _markets(auth))
        base_id = against or v["supersedes_id"]
        base = sa.version_row(db, base_id, _markets(auth)) if base_id else None
    except sa.AuthoringError as exc:
        raise _err(exc) from exc
    if base is not None and base["script_family_id"] != v["script_family_id"]:
        raise AppError(422, "DIFFERENT_FAMILY", "Compare versions of the same script family")
    d = sa.diff(sa.content_of(db, base) if base else None, sa.content_of(db, v))

    def ref(x: dict[str, Any]) -> DiffVersionRef:
        return DiffVersionRef(
            id=x["id"], version_label=x["version_label"], status=x["status"], manifest_sha256=x["manifest_sha256"]
        )

    return ScriptDiff(base=ref(base) if base else None, target=ref(v), **d)


@router.get("/question-bank", response_model=QuestionBankList, operation_id="question_bank", responses=_ERR)
def question_bank(
    q: str | None = Query(default=None, max_length=80),
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> QuestionBankList:
    """Reusable questions with their latest *published* English revision (S2-A.1: content that exists only in some
    draft is never offered to another draft; such questions are listed with ``reusable = false``)."""
    rows = (
        db.execute(
            text(
                "SELECT i.id, i.question_code, coalesce(d.intent, i.intent) AS intent, "
                "coalesce(d.category, i.category) AS category, r.revision AS latest_revision, r.customer_wording, "
                "r.answer_type, r.delivery_mode, r.mandatory, r.expected_answer_policy, r.content_approval_status, "
                "r.published AS reusable, "
                "(SELECT count(DISTINCT s.script_version_id) FROM question_revision x JOIN module_question mq "
                " ON mq.question_revision_id = x.id JOIN script_section s ON s.script_module_id = mq.script_module_id "
                " JOIN script_version sv ON sv.id = s.script_version_id "
                " WHERE x.question_bank_item_id = i.id AND sv.status <> 'ABANDONED') AS used_in_versions "
                "FROM question_bank_item i JOIN LATERAL (SELECT qr.*, EXISTS (SELECT 1 FROM module_question pmq "
                "JOIN script_module pm ON pm.id = pmq.script_module_id WHERE pmq.question_revision_id = qr.id "
                "AND pm.status IN ('PUBLISHED', 'SUPERSEDED')) AS published FROM question_revision qr "
                "WHERE qr.question_bank_item_id = i.id AND qr.language = 'en' ORDER BY published DESC, "
                "qr.revision DESC LIMIT 1) r ON true LEFT JOIN question_revision_detail d "
                "ON d.question_revision_id = r.id WHERE (CAST(:q AS text) IS NULL OR i.question_code ILIKE :like "
                "OR i.intent ILIKE :like OR r.customer_wording ILIKE :like) ORDER BY i.question_code"
            ),
            {"q": q, "like": f"%{q}%" if q else None},
        )
        .mappings()
        .all()
    )
    items = [QuestionBankItemOut(**dict(r)) for r in rows]
    return QuestionBankList(items=items, total=len(items))


@router.get(
    "/script-authoring/options",
    response_model=AuthoringOptions,
    operation_id="script_authoring_options",
    responses=_ERR,
)
def options(auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)) -> AuthoringOptions:
    modules = (
        db.execute(
            text(
                "SELECT m.id, m.code, m.revision, m.name, m.kind, count(mq.id) AS questions FROM script_module m "
                "LEFT JOIN module_question mq ON mq.script_module_id = m.id WHERE m.status = 'PUBLISHED' "
                "GROUP BY m.id ORDER BY m.code, m.revision"
            )
        )
        .mappings()
        .all()
    )
    controls = db.execute(text("SELECT id, control_code AS code, name AS label FROM control ORDER BY control_code"))
    refs = db.execute(
        text(
            "SELECT id, document_version AS code, title AS label FROM regulatory_reference WHERE market_code = ANY(:m) "
            "ORDER BY title"
        ),
        {"m": sorted(auth.markets)},
    )
    return AuthoringOptions(
        controls=[PickOption(**dict(r._mapping)) for r in controls],
        regulatory_references=[PickOption(**dict(r._mapping)) for r in refs],
        condition_facts={k: list(v) for k, v in sa.CONDITION_FACTS.items()},
        risk_bands=list(sa.RISK_BANDS),
        fact_keys=sa.FACT_KEYS,
        categories=list(sa.CATEGORIES),
        delivery_modes=list(sa.DELIVERY_MODES),
        answer_types=list(sa.ANSWER_TYPES),
        expected_answer_policies=list(sa.POLICIES),
        module_kinds=list(sa.MODULE_KINDS),
        published_modules=[ModuleOption(**dict(m)) for m in modules],
        evaluation={
            "engine": ae.ENGINE,
            "method_answer_types": {m: list(t) for m, t in ae.METHOD_ANSWER_TYPES.items()},
            "operators": ae.OPERATORS,
            "units": ae.UNITS,
            "facts": {
                k: {kk: (list(vv) if isinstance(vv, tuple) else vv) for kk, vv in f.items()}
                for k, f in ae.EVALUATION_FACTS.items()
            },
            "results": list(ae.RESULTS),
            "note": "No tolerance or threshold is assumed: comparisons are exact unless an approved tolerance and its "
            "approval reference are configured and pass maker-checker review. A mismatch is a discrepancy for "
            "review, not a compliance finding.",
        },
        lifecycle={
            "stages": list(lc.STAGES),
            "kind_stage": lc.KIND_STAGE,
            "roles": [
                {
                    "role": r,
                    "stage": lc.ROLE_STAGE[r],
                    "answer_types": list(lc.ROLE_ANSWER_TYPES.get(r, sa.ANSWER_TYPES)),
                    "on_failure": list(lc.ALLOWED_ON_FAILURE[r]),
                    "default_on_failure": lc.DEFAULT_ON_FAILURE[r],
                    "statement": r in lc.STATEMENT_ROLES,
                }
                for r in lc.ROLES
            ],
            "events": lc.EVENTS,
            "assumptions": list(lc.ASSUMPTIONS),
        },
    )
