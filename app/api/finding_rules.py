"""S3-B governed finding rules API (COMP-008, REG-007): versioned rule sets with maker-checker publication.

Read ``script.read``; author (create, edit, submit, abandon) ``script.edit``; review ``script.approve``; publish
``script.publish`` — the same separation of duties as Script Studio (expected-answer and escalation rule changes need
independent approval). The maker of a version can neither review nor publish it. Published versions are immutable.
Writes are CSRF-protected, rate-limited and audited (``FINDING_RULES.*``). Rules are synthetic configuration.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    ErrorResponse,
    FindingRuleOptions,
    FindingRuleOut,
    FindingRuleSetAbandonIn,
    FindingRuleSetCreateIn,
    FindingRuleSetEvent,
    FindingRuleSetList,
    FindingRuleSetOut,
    FindingRuleSetReviewIn,
    FindingRuleSetSubmitIn,
    FindingRuleSetSummary,
    FindingRuleSetUpdateIn,
    PickCode,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import finding_engine as fe
from app.domain import finding_rules as fr
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["finding-rules"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
MARKET = "SG"  # Singapore-only synthetic development (D-39)


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _who(auth: AuthContext) -> str:
    return str(auth.principal_id)


def _err(exc: fr.RuleSetError) -> AppError:
    return AppError(
        exc.status, exc.code, exc.message, details=[{"message": d} for d in exc.details] if exc.details else None
    )


def _market(auth: AuthContext) -> str:
    if MARKET not in auth.markets:
        raise AppError(403, "FORBIDDEN", "Finding rules are maintained for Singapore only")
    return MARKET


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    vid: uuid.UUID,
    after: dict[str, Any],
    reason: str | None = None,
) -> None:
    write_audit(
        db,
        action=action,
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="finding_rule_set_version",
        entity_id=str(vid),
        after=after,
        reason=reason,
    )


def _summary(v: dict[str, Any]) -> FindingRuleSetSummary:
    return FindingRuleSetSummary(
        id=v["id"],
        market_code=v["market_code"],
        version_no=v["version_no"],
        label=fr.label(v),
        status=v["status"],
        rules_count=v.get("rules_count", len(v.get("rules") or [])),
        rules_sha256=v["rules_sha256"],
        change_summary=v["change_summary"],
        created_at=v["created_at"],
        published_at=v["published_at"],
        created_by_name=v.get("created_by_name"),
    )


def _out(db: Session, v: dict[str, Any], auth: AuthContext) -> FindingRuleSetOut:
    from sqlalchemy import text

    name = db.execute(
        text("SELECT display_name FROM principal WHERE CAST(id AS text) = :p"), {"p": v["created_by"]}
    ).scalar()
    reviewer = (
        db.execute(
            text("SELECT display_name FROM principal WHERE CAST(id AS text) = :p"), {"p": v["reviewed_by"]}
        ).scalar()
        if v["reviewed_by"]
        else None
    )
    pub = fr.published(db, v["market_code"])
    rules = v["rules"] or []
    return FindingRuleSetOut(
        **_summary(v | {"created_by_name": name}).model_dump(),
        row_version=v["row_version"],
        rules=[FindingRuleOut(**r, text=fe.describe_rule(r)) for r in rules],
        content_approval_status=v["content_approval_status"],
        reviewed_by_name=reviewer,
        review_reason=v["review_reason"],
        i_am_maker=_who(auth) in fr.makers(db, v["id"]),
        diff_vs_published=fr.diff(pub["rules"], rules) if pub and pub["id"] != v["id"] else None,
        warnings=fr.warnings(db, rules),
        history=[
            FindingRuleSetEvent(
                action=h["action"],
                reason=h["reason"],
                details=h["details"] or {},
                occurred_at=h["occurred_at"],
                actor_name=h["display_name"],
            )
            for h in fr.history(db, v["id"])
        ],
        note=fe.NOTE + " Rules and severities here are synthetic development configuration, not approved policy.",
    )


@router.get(
    "/finding-rule-sets/options", response_model=FindingRuleOptions, operation_id="finding_rule_options", responses=_ERR
)
def finding_rule_options(
    auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> FindingRuleOptions:
    from sqlalchemy import text

    qs = db.execute(
        text("SELECT question_code AS code, intent AS label FROM question_bank_item ORDER BY question_code")
    ).mappings()
    return FindingRuleOptions(
        engine=fe.ENGINE,
        triggers=list(fe.TRIGGERS),
        trigger_class=fe.TRIGGER_CLASS,
        class_labels=fe.CLASS_LABEL,
        categories=list(fe.CATEGORIES),
        trigger_categories={k: list(v) for k, v in fe.TRIGGER_CATEGORIES.items()},
        severities=list(fe.SEVERITIES),
        scopes=list(fe.SCOPES),
        controls=[PickCode(**c) for c in fr.controls(db)],
        questions=[PickCode(code=r["code"], label=r["label"] or "") for r in qs],
        note="Severity is never assumed: every rule states its severity and justification, and passes maker-checker "
        "review. A finding is a flagged potential concern for human review, not a breach determination.",
    )


@router.get("/finding-rule-sets", response_model=FindingRuleSetList, operation_id="finding_rule_sets", responses=_ERR)
def finding_rule_sets(
    auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> FindingRuleSetList:
    items = fr.versions(db, _markets(auth))
    pub = next((i for i in items if i["status"] == "PUBLISHED"), None)
    return FindingRuleSetList(items=[_summary(i) for i in items], published_id=pub["id"] if pub else None, note=fe.NOTE)


@router.post(
    "/finding-rule-sets",
    response_model=FindingRuleSetOut,
    status_code=201,
    operation_id="finding_rule_set_create",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_create(
    body: FindingRuleSetCreateIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    """Open a new draft (a copy of the published rules, or empty)."""
    _guard(request, auth)
    try:
        vid = fr.create_draft(db, _market(auth), _who(auth), empty=body.empty)
    except fr.RuleSetError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "FINDING_RULES.CREATED", vid, {"empty": body.empty})
    db.commit()
    return _out(db, fr.version(db, vid, _markets(auth)), auth)


@router.get(
    "/finding-rule-sets/{version_id}",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_get",
    responses=_ERR,
)
def finding_rule_set_get(
    version_id: uuid.UUID, auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> FindingRuleSetOut:
    try:
        return _out(db, fr.version(db, version_id, _markets(auth)), auth)
    except fr.RuleSetError as exc:
        raise _err(exc) from exc


@router.put(
    "/finding-rule-sets/{version_id}",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_update",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_update(
    version_id: uuid.UUID,
    body: FindingRuleSetUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    """Replace the draft's rules (validated against the governed vocabularies; optimistic concurrency)."""
    _guard(request, auth)
    try:
        fr.update(
            db,
            version_id,
            _markets(auth),
            _who(auth),
            body.expected_row_version,
            [r.model_dump() for r in body.rules],
            body.change_summary,
        )
    except fr.RuleSetError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "FINDING_RULES.EDITED", version_id, {"rules": len(body.rules)}, body.change_summary)
    db.commit()
    return _out(db, fr.version(db, version_id, _markets(auth)), auth)


def _step(
    request: Request,
    auth: AuthContext,
    db: Session,
    version_id: uuid.UUID,
    action: str,
    fn: Any,
    after: dict[str, Any],
    reason: str | None = None,
) -> FindingRuleSetOut:
    _guard(request, auth)
    try:
        fn()
    except fr.RuleSetError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, action, version_id, after, reason)
    db.commit()
    return _out(db, fr.version(db, version_id, _markets(auth)), auth)


@router.post(
    "/finding-rule-sets/{version_id}/submit",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_submit",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_submit(
    version_id: uuid.UUID,
    body: FindingRuleSetSubmitIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    return _step(
        request,
        auth,
        db,
        version_id,
        "FINDING_RULES.SUBMITTED",
        lambda: fr.submit(db, version_id, _markets(auth), _who(auth), body.expected_row_version, body.change_summary),
        {},
        body.change_summary,
    )


@router.post(
    "/finding-rule-sets/{version_id}/review",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_review",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_review(
    version_id: uuid.UUID,
    body: FindingRuleSetReviewIn,
    request: Request,
    auth: AuthContext = Depends(require("script.approve")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    """A different S&C checker approves the version or returns it to draft (the maker cannot review)."""
    return _step(
        request,
        auth,
        db,
        version_id,
        "FINDING_RULES.REVIEWED",
        lambda: fr.review(db, version_id, _markets(auth), _who(auth), body.decision, body.reason),
        {"decision": body.decision},
        body.reason,
    )


@router.post(
    "/finding-rule-sets/{version_id}/publish",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_publish",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_publish(
    version_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.publish")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    """Publish an approved version (immutable from now on); the previous published version is superseded."""
    return _step(
        request,
        auth,
        db,
        version_id,
        "FINDING_RULES.PUBLISHED",
        lambda: fr.publish(db, version_id, _markets(auth), _who(auth)),
        {},
    )


@router.post(
    "/finding-rule-sets/{version_id}/abandon",
    response_model=FindingRuleSetOut,
    operation_id="finding_rule_set_abandon",
    responses=_ERR,
)
@csrf_protected
def finding_rule_set_abandon(
    version_id: uuid.UUID,
    body: FindingRuleSetAbandonIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> FindingRuleSetOut:
    return _step(
        request,
        auth,
        db,
        version_id,
        "FINDING_RULES.ABANDONED",
        lambda: fr.abandon(db, version_id, _markets(auth), _who(auth), body.reason),
        {},
        body.reason,
    )
