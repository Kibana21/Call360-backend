"""ADMIN Users and Audit APIs: API-010, API-012, API-021 (CP0.1A)."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    AdminUser,
    AdminUserList,
    AdminUserPatch,
    AuditEventList,
    AuditEventOut,
    ErrorResponse,
    PageInfo,
)
from app.audit import scope
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require, resolve_grants
from app.security.identity import active_admin_count
from app.security.models import AppGroup, AuditEvent, AuthSession, GroupMembership, IdentityBinding, Principal
from app.security.service import revoke_all_sessions

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
_ERR: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    428: {"model": ErrorResponse},
}


def _snapshot_str(snapshot: dict[str, object] | None, key: str) -> str | None:
    value = (snapshot or {}).get(key)
    return value if isinstance(value, str) else None


def _encode_cursor(values: list[str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(values).encode()).decode()


def _decode_cursor(cursor: str) -> list[str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        if not isinstance(data, list) or not all(isinstance(v, str) for v in data):
            raise ValueError
        return data
    except ValueError as exc:
        raise AppError(422, "INVALID_CURSOR", "Cursor is not valid") from exc


def _user_view(db: Session, p: Principal, now: datetime) -> AdminUser:
    username = db.execute(select(IdentityBinding.username).where(IdentityBinding.principal_id == p.id)).scalar()
    groups = (
        db.execute(
            select(AppGroup.code)
            .join(GroupMembership, GroupMembership.group_id == AppGroup.id)
            .where(
                GroupMembership.principal_id == p.id,
                GroupMembership.valid_from <= now,
                or_(GroupMembership.valid_to.is_(None), GroupMembership.valid_to > now),
            )
        )
        .scalars()
        .all()
    )
    roles, _ = resolve_grants(db, p.id, now)
    last_login = db.execute(select(func.max(AuthSession.created_at)).where(AuthSession.principal_id == p.id)).scalar()
    active_sessions = db.execute(
        select(func.count())
        .select_from(AuthSession)
        .where(
            AuthSession.principal_id == p.id,
            AuthSession.revoked_at.is_(None),
            AuthSession.idle_expires_at > now,
            AuthSession.absolute_expires_at > now,
        )
    ).scalar_one()
    return AdminUser(
        principal_id=p.id,
        username=username,
        display_name=p.display_name,
        status=p.status,
        groups=sorted(groups),
        roles=sorted(roles),
        created_at=p.created_at,
        disabled_at=p.disabled_at,
        last_login_at=last_login,
        active_sessions=active_sessions,
        row_version=p.row_version,
    )


@router.get("/users", response_model=AdminUserList, operation_id="admin_users_list", responses=_ERR)
def list_users(
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require("admin.users.read")),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=200),
) -> AdminUserList:
    now = datetime.now(UTC)
    stmt = select(Principal).order_by(Principal.created_at, Principal.id).limit(limit + 1)
    if cursor:
        created, pid = _decode_cursor(cursor)
        try:
            created_at, principal_id = datetime.fromisoformat(created), uuid.UUID(pid)
        except ValueError as exc:
            raise AppError(422, "INVALID_CURSOR", "Cursor is not valid") from exc
        stmt = stmt.where(
            or_(
                Principal.created_at > created_at, and_(Principal.created_at == created_at, Principal.id > principal_id)
            )
        )
    rows = db.execute(stmt).scalars().all()
    page, more = rows[:limit], len(rows) > limit
    next_cursor = _encode_cursor([page[-1].created_at.isoformat(), str(page[-1].id)]) if more and page else None
    return AdminUserList(
        items=[_user_view(db, p, now) for p in page],
        page=PageInfo(next_cursor=next_cursor, limit=limit, sort="created_at:asc"),
    )


@router.patch("/users/{principal_id}", response_model=AdminUser, operation_id="admin_users_update", responses=_ERR)
@csrf_protected
def update_user(
    principal_id: uuid.UUID,
    body: AdminUserPatch,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.users.manage")),
    if_match: str | None = Header(None, alias="If-Match", max_length=20),
) -> AdminUser:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"writes:{auth.principal_id}", settings.writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many changes; try again shortly", retryable=True)
    if if_match is None:
        raise AppError(428, "IF_MATCH_REQUIRED", "If-Match header with the row version is required")
    principal = db.execute(select(Principal).where(Principal.id == principal_id).with_for_update()).scalar()
    if principal is None:
        raise AppError(404, "NOT_FOUND", "Not found or not available to you")
    if if_match.strip('"') != str(principal.row_version):
        raise AppError(409, "CONFLICT_ROW_VERSION", "This user was changed by someone else; reload and retry")
    if body.status is None and body.display_name is None:
        raise AppError(422, "VALIDATION_FAILED", "Nothing to change")

    now = datetime.now(UTC)
    before = {"status": principal.status, "display_name": principal.display_name}
    action = "ADMIN.USER_UPDATED"
    if body.status == "DISABLED" and principal.status != "DISABLED":
        if principal.id == auth.principal_id:
            raise AppError(409, "LAST_ADMIN_GUARD", "You cannot disable your own account")
        roles, _ = resolve_grants(db, principal.id, now)
        if "ADMIN" in roles and active_admin_count(db, now) <= 1:
            raise AppError(409, "LAST_ADMIN_GUARD", "The last active administrator cannot be disabled")
        principal.status, principal.disabled_at, principal.disabled_by = "DISABLED", now, str(auth.principal_id)
        revoke_all_sessions(db, principal.id, "PRINCIPAL_DISABLED")
        action = "ADMIN.USER_DISABLED"
    elif body.status == "ACTIVE" and principal.status != "ACTIVE":
        principal.status, principal.disabled_at, principal.disabled_by = "ACTIVE", None, None
        action = "ADMIN.USER_ENABLED"
    if body.display_name is not None:
        principal.display_name = body.display_name.strip()
    principal.row_version += 1
    principal.updated_at, principal.updated_by = now, str(auth.principal_id)
    write_audit(
        db,
        action=action,
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="principal",
        entity_id=str(principal.id),
        entity_version=principal.row_version,
        reason=body.reason,
        before=before,
        after={"status": principal.status, "display_name": principal.display_name},
    )
    db.commit()
    return _user_view(db, principal, now)


def _seed_view(e: AuditEvent) -> dict[str, Any] | None:
    """The seed manifest without its dataset-wide (all-market) totals; the digest identifies the seed."""
    return {k: v for k, v in (e.after or {}).items() if k not in scope.SEED_TOTALS}


@router.get("/audit-events", response_model=AuditEventList, operation_id="admin_audit_events_list", responses=_ERR)
def list_audit_events(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("audit.read")),
    action: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, pattern="^(SUCCEEDED|DENIED|FAILED)$"),
    actor_principal_id: uuid.UUID | None = None,
    entity_type: str | None = Query(None, max_length=64),
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=200),
) -> AuditEventList:
    markets = sorted(auth.markets)
    # CP0.6-F1: the operational view follows the market scope; the ledger itself is unchanged (app.audit.scope).
    stmt = select(AuditEvent).where(scope.visible(markets)).order_by(AuditEvent.seq.desc()).limit(limit + 1)
    if action:
        stmt = stmt.where(AuditEvent.action.startswith(action, autoescape=True))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if actor_principal_id:
        stmt = stmt.where(AuditEvent.actor_principal_id == actor_principal_id)
    if entity_type:
        stmt = stmt.where(AuditEvent.entity_type == entity_type)
    if occurred_from:
        stmt = stmt.where(AuditEvent.occurred_at >= occurred_from)
    if occurred_to:
        stmt = stmt.where(AuditEvent.occurred_at < occurred_to)
    if cursor:
        (seq,) = _decode_cursor(cursor)
        if not seq.isdigit():
            raise AppError(422, "INVALID_CURSOR", "Cursor is not valid")
        stmt = stmt.where(AuditEvent.seq < int(seq))
    rows = db.execute(stmt).scalars().all()
    page, more = rows[:limit], len(rows) > limit
    hidden_ids = scope.redacted_ids(db, [e.id for e in page], markets)
    items = [
        AuditEventOut(
            event_id=e.id,
            seq=e.seq,
            occurred_at=e.occurred_at,
            action=e.action,
            outcome=e.outcome,
            actor_principal_id=e.actor_principal_id,
            actor_display_name=_snapshot_str(e.actor_snapshot, "display_name"),
            actor_username=_snapshot_str(e.actor_snapshot, "username"),
            actor_service=_snapshot_str(e.actor_snapshot, "service"),
            session_id=e.session_id,
            correlation_id=e.correlation_id,
            source_ip=e.source_ip,
            entity_type=e.entity_type,
            entity_id=None if e.id in hidden_ids else e.entity_id,
            entity_version=e.entity_version,
            reason=e.reason,
            before=e.before,
            after=_seed_view(e) if e.action == "SEED.MANIFEST" else e.after,
            scope_redacted=e.id in hidden_ids or e.action == "SEED.MANIFEST",
        )
        for e in page
    ]
    return AuditEventList(
        items=items,
        page=PageInfo(
            next_cursor=_encode_cursor([str(page[-1].seq)]) if more and page else None, limit=limit, sort="seq:desc"
        ),
    )
