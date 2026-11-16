"""Administration completion (CP0.1B-3): API-007, 009, 011, 013, 014…020, 026.

- Own account: ``GET /auth/session`` (API-007), ``POST /me/password`` (API-009; also clears a one-time password).
- Users: create a LOCAL user with a server-generated one-time password (API-011, ``Idempotency-Key``), reset a
  password to a new one-time password and revoke the user's sessions (API-013). The password is returned once to the
  administrator and is never stored in plain text, logged or audited.
- Groups: list with members, role and scope mappings and their history (API-014); add or end a membership
  (API-015/016); replace mappings as new effective-dated rows (API-018, ``If-Match``); roles and permissions
  (API-017). Reserved (later-stage) permissions cannot be granted; only enabled markets ({SG}, D-39) can be mapped;
  no change may leave the system without an active administrator or remove the caller's own administrator access.
- Sessions: active sessions without token material (API-019) and revoke with reason (API-020).
- System health (API-026): checks, counts, migration head, audit chain head and the OpenAPI digest.

Every change needs the session CSRF token, a reason, and writes a before/after audit event in the same transaction.
Group, membership and mapping changes take effect on the next request (permissions are resolved per request).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.api.admin import _user_view
from app.api.admin_config import _write_guard
from app.api.deps import csrf_protected
from app.api.health import NON_SYNTHETIC_SQL  # the same check as /health/ready
from app.api.schemas import (
    AdminGroup,
    AdminGroupList,
    AdminRole,
    AdminRoleList,
    AdminSessionList,
    AdminSessionOut,
    AdminUserCreate,
    ErrorResponse,
    GroupMappingsUpdate,
    GroupMember,
    GroupRoleOut,
    GroupScopeOut,
    HealthCheck,
    OneTimePassword,
    PasswordChange,
    Reason,
    RolePermissionOut,
    SessionStatus,
    SystemHealth,
)
from app.audit import scope as audit_scope
from app.audit.chain import verify_chain, write_audit
from app.config.service import CURRENT_STAGE
from app.core.errors import AppError
from app.domain.protection import protection_for
from app.security.authz import AuthContext, authenticate, get_db, request_meta, require, resolve_grants
from app.security.identity import AccountError, active_admin_count, create_local_account
from app.security.models import (
    AppGroup,
    AuditEvent,
    AuthSession,
    GroupMembership,
    GroupRoleMapping,
    GroupScopeMapping,
    IdentityBinding,
    IdentityProvider,
    LocalCredential,
    Permission,
    Principal,
    Role,
    RolePermission,
)
from app.security.passwords import HASH_PARAMS, PasswordPolicyError, check_policy, hash_password, verify_password
from app.security.scope import ENABLED_MARKETS
from app.security.service import _revoke_session, revoke_all_sessions

router = APIRouter(prefix="/api/v1", tags=["admin"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 428, 429)}
_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
OTP_NOTE = "Shown once. Give it to the user through a separate channel; they must change it at first sign-in."
OPENAPI_SHA = Path(__file__).resolve().parents[2] / "contracts" / "generated" / "openapi.sha256"


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _one_time_password(username: str, display_name: str) -> str:
    while True:
        candidate = secrets.token_urlsafe(15)  # 20 characters, ~120 bits
        try:
            check_policy(candidate, username=username, display_name=display_name)
            return candidate
        except PasswordPolicyError:
            continue


def _active(now: datetime) -> Any:
    return or_(GroupMembership.valid_to.is_(None), GroupMembership.valid_to > now)


def _guard_admins(db: Session, auth: AuthContext, now: datetime) -> None:
    """After a pending change: keep at least one active administrator and the caller's own ADMIN role."""
    db.flush()
    if active_admin_count(db, now) < 1:
        raise AppError(409, "LAST_ADMIN_GUARD", "This change would leave no active administrator")
    if "ADMIN" in auth.roles and "ADMIN" not in resolve_grants(db, auth.principal_id, now)[0]:
        raise AppError(409, "LAST_ADMIN_GUARD", "You cannot remove your own administrator access")


# ---- API-007 / API-009: own session and password ----------------------------------------------------------------
@router.get("/auth/session", response_model=SessionStatus, operation_id="auth_session", responses=_ERR)
def own_session(auth: AuthContext = Depends(authenticate)) -> SessionStatus:
    s = auth.session
    return SessionStatus(
        session_id=s.id,
        created_at=s.created_at,
        last_seen_at=s.last_seen_at,
        idle_expires_at=s.idle_expires_at,
        absolute_expires_at=s.absolute_expires_at,
    )


@router.post("/me/password", status_code=204, operation_id="me_password_change", responses=_ERR)
@csrf_protected
def change_own_password(
    body: PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(authenticate),
) -> Response:
    _write_guard(request, auth)
    cred = db.execute(
        select(LocalCredential).where(LocalCredential.principal_id == auth.principal_id).with_for_update()
    ).scalar()
    if cred is None:
        raise AppError(422, "NOT_A_LOCAL_ACCOUNT", "This account has no local password")
    if not verify_password(cred.password_hash, body.current_password):
        write_audit(
            db,
            action="AUTH.PASSWORD_CHANGE_FAILED",
            outcome="DENIED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="principal",
            entity_id=str(auth.principal_id),
            reason="current password did not verify",
        )
        db.commit()
        raise AppError(422, "CURRENT_PASSWORD_INVALID", "The current password is not correct")
    if body.new_password == body.current_password:
        raise AppError(422, "PASSWORD_POLICY", "The new password must differ from the current one")
    try:
        check_policy(body.new_password, username=auth.username or "", display_name=auth.display_name)
    except PasswordPolicyError as exc:
        raise AppError(422, "PASSWORD_POLICY", str(exc).capitalize()) from exc
    now = datetime.now(UTC)
    was_one_time = cred.must_change_password
    cred.password_hash, cred.hash_params = hash_password(body.new_password), HASH_PARAMS
    cred.password_changed_at = cred.updated_at = now
    cred.must_change_password, cred.failed_count, cred.locked_until = False, 0, None
    others = db.execute(
        select(AuthSession).where(
            AuthSession.principal_id == auth.principal_id,
            AuthSession.id != auth.session_id,
            AuthSession.revoked_at.is_(None),
        )
    ).scalars()
    revoked = 0
    for s in others:
        _revoke_session(db, s, now, "PASSWORD_CHANGED")
        revoked += 1
    write_audit(
        db,
        action="AUTH.PASSWORD_CHANGED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="principal",
        entity_id=str(auth.principal_id),
        after={"one_time_password_replaced": was_one_time, "other_sessions_revoked": revoked},
    )
    db.commit()
    return Response(status_code=204)


# ---- API-011 / API-013: create user, reset password -------------------------------------------------------------
@router.post(
    "/admin/users", response_model=OneTimePassword, status_code=201, operation_id="admin_users_create", responses=_ERR
)
@csrf_protected
def create_user(
    body: AdminUserCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.users.manage")),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=128),
) -> OneTimePassword:
    _write_guard(request, auth)
    _no_store(response)
    if idempotency_key is None or not 8 <= len(idempotency_key) <= 128 or set(idempotency_key) - _KEY_CHARS:
        raise AppError(428, "IDEMPOTENCY_KEY_REQUIRED", "Send an Idempotency-Key header (8–128 characters)")
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    db.execute(text("SELECT pg_advisory_xact_lock(3600011)"))
    prior = db.execute(
        select(AuditEvent).where(
            AuditEvent.action == "ADMIN.USER_CREATED", AuditEvent.after["idempotency_key_sha256"].astext == key_hash
        )
    ).scalar()
    now = datetime.now(UTC)
    if prior is not None:
        if (prior.after or {}).get("username") != body.username.strip().lower():
            raise AppError(409, "IDEMPOTENCY_KEY_REUSED", "This Idempotency-Key was used for a different user")
        principal = db.get(Principal, uuid.UUID(str(prior.entity_id)))
        assert principal is not None
        response.status_code = 200
        return OneTimePassword(
            user=_user_view(db, principal, now),
            one_time_password=None,
            replayed=True,
            note="Already created with this key. The one-time password is not shown again; reset it if it was lost.",
        )
    group = db.execute(select(AppGroup).where(AppGroup.code == body.group_code)).scalar()
    if group is None or group.status != "ACTIVE":
        raise AppError(422, "UNKNOWN_GROUP", "Choose an active group")
    password = _one_time_password(body.username, body.display_name)
    try:
        principal = create_local_account(
            db,
            username=body.username,
            display_name=body.display_name,
            password=password,
            group_code=body.group_code,
            created_by=str(auth.principal_id),
            actor=auth.actor,
            meta=request_meta(request),
            audit_reason=body.reason,
            audit_extra={"one_time_password": True, "idempotency_key_sha256": key_hash},
        )
    except AccountError as exc:
        if "taken" in str(exc):
            raise AppError(409, "USERNAME_TAKEN", "This username is already taken") from exc
        raise AppError(422, "VALIDATION_FAILED", str(exc).capitalize()) from exc
    cred = db.execute(select(LocalCredential).where(LocalCredential.principal_id == principal.id)).scalar_one()
    cred.must_change_password = True
    db.commit()
    return OneTimePassword(user=_user_view(db, principal, now), one_time_password=password, note=OTP_NOTE)


@router.post(
    "/admin/users/{principal_id}/password-reset",
    response_model=OneTimePassword,
    operation_id="admin_users_password_reset",
    responses=_ERR,
)
@csrf_protected
def reset_password(
    principal_id: uuid.UUID,
    body: Reason,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.users.manage")),
) -> OneTimePassword:
    _write_guard(request, auth)
    _no_store(response)
    if principal_id == auth.principal_id:
        raise AppError(409, "OWN_ACCOUNT", "Change your own password from your account menu instead")
    principal = db.get(Principal, principal_id)
    cred = db.execute(
        select(LocalCredential).where(LocalCredential.principal_id == principal_id).with_for_update()
    ).scalar()
    if principal is None or cred is None:
        raise AppError(404, "NOT_FOUND", "Not found or not available to you")
    username = db.execute(select(IdentityBinding.username).where(IdentityBinding.principal_id == principal_id)).scalar()
    password = _one_time_password(username or "", principal.display_name)
    now = datetime.now(UTC)
    cred.password_hash, cred.hash_params = hash_password(password), HASH_PARAMS
    cred.password_changed_at = cred.updated_at = now
    cred.must_change_password, cred.failed_count, cred.locked_until = True, 0, None
    revoked = revoke_all_sessions(db, principal_id, "PASSWORD_RESET")
    write_audit(
        db,
        action="ADMIN.PASSWORD_RESET",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="principal",
        entity_id=str(principal_id),
        reason=body.reason,
        after={"one_time_password": True, "sessions_revoked": revoked},
    )
    db.commit()
    return OneTimePassword(user=_user_view(db, principal, now), one_time_password=password, note=OTP_NOTE)


# ---- API-014…018: groups, memberships, roles, mappings ---------------------------------------------------------
def _member(db: Session, m: GroupMembership) -> GroupMember:
    p = db.get(Principal, m.principal_id)
    assert p is not None
    username = db.execute(select(IdentityBinding.username).where(IdentityBinding.principal_id == p.id)).scalar()
    return GroupMember(
        principal_id=p.id,
        username=username,
        display_name=p.display_name,
        status=p.status,
        valid_from=m.valid_from,
        valid_to=m.valid_to,
        provenance=m.provenance,
        created_by=m.created_by,
    )


def _current_mappings(
    db: Session, group_id: uuid.UUID, now: datetime
) -> tuple[list[GroupRoleMapping], list[GroupScopeMapping]]:
    roles = (
        db.execute(
            select(GroupRoleMapping).where(
                GroupRoleMapping.group_id == group_id,
                GroupRoleMapping.effective_from <= now,
                or_(GroupRoleMapping.effective_to.is_(None), GroupRoleMapping.effective_to > now),
            )
        )
        .scalars()
        .all()
    )
    scopes = (
        db.execute(
            select(GroupScopeMapping).where(
                GroupScopeMapping.group_id == group_id,
                GroupScopeMapping.effective_from <= now,
                or_(GroupScopeMapping.effective_to.is_(None), GroupScopeMapping.effective_to > now),
            )
        )
        .scalars()
        .all()
    )
    return list(roles), list(scopes)


def _mappings_version(roles: list[GroupRoleMapping], scopes: list[GroupScopeMapping]) -> str:
    ids = sorted(str(r.id) for r in roles) + sorted(str(s.id) for s in scopes)
    return hashlib.sha256("|".join(ids).encode()).hexdigest()[:16]


def _group_view(db: Session, g: AppGroup, now: datetime) -> AdminGroup:
    role_codes = {r.id: r.code for r in db.execute(select(Role)).scalars()}
    roles, scopes = _current_mappings(db, g.id, now)
    memberships = (
        db.execute(select(GroupMembership).where(GroupMembership.group_id == g.id).order_by(GroupMembership.valid_from))
        .scalars()
        .all()
    )
    current = [m for m in memberships if m.valid_from <= now and (m.valid_to is None or m.valid_to > now)]
    former = [m for m in memberships if m.valid_to is not None and m.valid_to <= now]
    provider = db.get(IdentityProvider, g.identity_provider_id)
    role_rows = db.execute(
        select(GroupRoleMapping).where(GroupRoleMapping.group_id == g.id).order_by(GroupRoleMapping.effective_from)
    ).scalars()
    scope_rows = db.execute(
        select(GroupScopeMapping).where(GroupScopeMapping.group_id == g.id).order_by(GroupScopeMapping.effective_from)
    ).scalars()
    return AdminGroup(
        group_id=g.id,
        code=g.code,
        name=g.name,
        status=g.status,
        provider=getattr(provider, "kind", None) or "LOCAL",
        member_count=len(current),
        roles=sorted(role_codes[r.role_id] for r in roles),
        markets=sorted(s.market_code for s in scopes),
        mappings_version=_mappings_version(roles, scopes),
        members=[_member(db, m) for m in current],
        former_members=[_member(db, m) for m in former],
        role_history=[
            GroupRoleOut(
                role=role_codes[r.role_id],
                effective_from=r.effective_from,
                effective_to=r.effective_to,
                approved_by=r.approved_by,
            )
            for r in role_rows
        ],
        scope_history=[
            GroupScopeOut(
                market=s.market_code,
                effective_from=s.effective_from,
                effective_to=s.effective_to,
                created_by=s.created_by,
                change_reason=s.change_reason,
            )
            for s in scope_rows
        ],
    )


@router.get("/admin/groups", response_model=AdminGroupList, operation_id="admin_groups_list", responses=_ERR)
def list_groups(
    db: Session = Depends(get_db), _auth: AuthContext = Depends(require("admin.users.read"))
) -> AdminGroupList:
    now = datetime.now(UTC)
    groups = db.execute(select(AppGroup).order_by(AppGroup.code)).scalars().all()
    return AdminGroupList(items=[_group_view(db, g, now) for g in groups], enabled_markets=sorted(ENABLED_MARKETS))


def _group_and_principal(db: Session, group_id: uuid.UUID, principal_id: uuid.UUID) -> tuple[AppGroup, Principal]:
    g, p = db.get(AppGroup, group_id), db.get(Principal, principal_id)
    if g is None or p is None:
        raise AppError(404, "NOT_FOUND", "Not found or not available to you")
    return g, p


@router.put(
    "/admin/groups/{group_id}/members/{principal_id}",
    response_model=AdminGroup,
    operation_id="admin_group_member_add",
    responses=_ERR,
)
@csrf_protected
def add_member(
    group_id: uuid.UUID,
    principal_id: uuid.UUID,
    body: Reason,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.groups.manage")),
) -> AdminGroup:
    _write_guard(request, auth)
    g, p = _group_and_principal(db, group_id, principal_id)
    if g.status != "ACTIVE":
        raise AppError(422, "GROUP_INACTIVE", "This group is not active")
    now = datetime.now(UTC)
    existing = db.execute(
        select(GroupMembership).where(
            GroupMembership.group_id == g.id, GroupMembership.principal_id == p.id, _active(now)
        )
    ).scalar()
    if existing is None:  # PUT is idempotent: an existing membership is left as it is
        db.add(
            GroupMembership(
                principal_id=p.id,
                group_id=g.id,
                valid_from=now,
                provenance="LOCAL_ADMIN_ACTION",
                created_by=str(auth.principal_id),
            )
        )
        write_audit(
            db,
            action="ADMIN.MEMBERSHIP_ADDED",
            outcome="SUCCEEDED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="group_membership",
            entity_id=f"{g.code}:{p.id}"[:64],
            reason=body.reason,
            before={"member": False},
            after={"member": True, "group": g.code, "principal_id": str(p.id)},
        )
        db.commit()
    return _group_view(db, g, now)


@router.delete(
    "/admin/groups/{group_id}/members/{principal_id}",
    response_model=AdminGroup,
    operation_id="admin_group_member_remove",
    responses=_ERR,
)
@csrf_protected
def remove_member(
    group_id: uuid.UUID,
    principal_id: uuid.UUID,
    body: Reason,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.groups.manage")),
) -> AdminGroup:
    _write_guard(request, auth)
    g, p = _group_and_principal(db, group_id, principal_id)
    now = datetime.now(UTC)
    m = db.execute(
        select(GroupMembership)
        .where(GroupMembership.group_id == g.id, GroupMembership.principal_id == p.id, _active(now))
        .with_for_update()
    ).scalar()
    if m is None:
        raise AppError(404, "NOT_FOUND", "This user is not a current member of the group")
    m.valid_to = now  # history kept: the row is ended, not deleted
    _guard_admins(db, auth, now)
    write_audit(
        db,
        action="ADMIN.MEMBERSHIP_ENDED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="group_membership",
        entity_id=f"{g.code}:{p.id}"[:64],
        reason=body.reason,
        before={"member": True},
        after={"member": False, "group": g.code, "principal_id": str(p.id), "valid_to": now.isoformat()},
    )
    db.commit()
    return _group_view(db, g, now)


@router.get("/admin/roles", response_model=AdminRoleList, operation_id="admin_roles_list", responses=_ERR)
def list_roles(
    db: Session = Depends(get_db), _auth: AuthContext = Depends(require("admin.users.read"))
) -> AdminRoleList:
    def out(p: Permission) -> RolePermissionOut:
        return RolePermissionOut(code=p.code, alias=p.alias, reserved=p.reserved, description=p.description)

    items = []
    for r in db.execute(select(Role).order_by(Role.code)).scalars():
        perms = db.execute(
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == r.id)
            .order_by(Permission.code)
        ).scalars()
        items.append(AdminRole(code=r.code, name=r.name, permissions=[out(p) for p in perms]))
    reserved = db.execute(select(Permission).where(Permission.reserved).order_by(Permission.code)).scalars()
    return AdminRoleList(items=items, reserved_permissions=[out(p) for p in reserved])


@router.put(
    "/admin/groups/{group_id}/mappings",
    response_model=AdminGroup,
    operation_id="admin_group_mappings_replace",
    responses=_ERR,
)
@csrf_protected
def replace_mappings(
    group_id: uuid.UUID,
    body: GroupMappingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.groups.manage")),
    if_match: str | None = Header(None, alias="If-Match", max_length=40),
) -> AdminGroup:
    _write_guard(request, auth)
    if if_match is None:
        raise AppError(428, "IF_MATCH_REQUIRED", "If-Match with the group's mappings version is required")
    db.execute(text("SELECT pg_advisory_xact_lock(3600018)"))
    g = db.get(AppGroup, group_id)
    if g is None:
        raise AppError(404, "NOT_FOUND", "Not found or not available to you")
    now = datetime.now(UTC)
    roles, scopes = _current_mappings(db, g.id, now)
    if if_match.strip('"') != _mappings_version(roles, scopes):
        raise AppError(409, "CONFLICT_ROW_VERSION", "These mappings were changed by someone else; reload and retry")
    by_code = {r.code: r for r in db.execute(select(Role)).scalars()}
    unknown = sorted(set(body.roles) - by_code.keys())
    if unknown:
        raise AppError(422, "UNKNOWN_ROLE", f"Unknown role: {', '.join(unknown)}")
    for code in set(body.roles):
        reserved = db.execute(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == by_code[code].id, Permission.reserved)
        ).first()
        if reserved:
            raise AppError(422, "RESERVED_PERMISSION", f"Role {code} carries a reserved later-stage permission")
    markets = sorted(set(body.markets))
    if set(markets) - ENABLED_MARKETS:
        raise AppError(
            422, "MARKET_NOT_ENABLED", f"Only enabled markets can be mapped ({', '.join(sorted(ENABLED_MARKETS))})"
        )
    code_of = {r.id: r.code for r in by_code.values()}
    before = {"roles": sorted(code_of[r.role_id] for r in roles), "markets": sorted(s.market_code for s in scopes)}
    after = {"roles": sorted(set(body.roles)), "markets": markets}
    if before == after:
        raise AppError(422, "NO_CHANGE", "The mappings are unchanged")
    keep_roles = set(after["roles"])
    for r in roles:  # end only what changes; unchanged rows stay as they are
        if code_of[r.role_id] not in keep_roles:
            r.effective_to = now
    for code in keep_roles - set(before["roles"]):
        db.add(
            GroupRoleMapping(
                group_id=g.id, role_id=by_code[code].id, effective_from=now, approved_by=str(auth.principal_id)
            )
        )
    for s in scopes:
        if s.market_code not in markets:
            s.effective_to = now
    for m in set(markets) - set(before["markets"]):
        db.add(
            GroupScopeMapping(
                group_id=g.id,
                market_code=m,
                effective_from=now,
                created_by=str(auth.principal_id),
                change_reason=body.reason,
            )
        )
    _guard_admins(db, auth, now)
    write_audit(
        db,
        action="ADMIN.GROUP_MAPPINGS_REPLACED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="app_group",
        entity_id=str(g.id),
        reason=body.reason,
        before=before,
        after=after,
    )
    db.commit()
    return _group_view(db, g, datetime.now(UTC))


# ---- API-019 / API-020: sessions -------------------------------------------------------------------------------
@router.get("/admin/sessions", response_model=AdminSessionList, operation_id="admin_sessions_list", responses=_ERR)
def list_sessions(
    db: Session = Depends(get_db), auth: AuthContext = Depends(require("admin.sessions.manage"))
) -> AdminSessionList:
    now = datetime.now(UTC)
    rows = db.execute(
        select(AuthSession, Principal, IdentityBinding.username)
        .join(Principal, Principal.id == AuthSession.principal_id)
        .outerjoin(IdentityBinding, IdentityBinding.principal_id == Principal.id)
        .where(
            AuthSession.revoked_at.is_(None),
            AuthSession.idle_expires_at > now,
            AuthSession.absolute_expires_at > now,
            Principal.status == "ACTIVE",
        )
        .order_by(AuthSession.last_seen_at.desc())
    ).all()
    return AdminSessionList(
        items=[
            AdminSessionOut(
                session_id=s.id,
                principal_id=p.id,
                username=u,
                display_name=p.display_name,
                created_at=s.created_at,
                last_seen_at=s.last_seen_at,
                idle_expires_at=s.idle_expires_at,
                absolute_expires_at=s.absolute_expires_at,
                ip=s.ip,
                current=s.id == auth.session_id,
            )
            for s, p, u in rows
        ]
    )


@router.post(
    "/admin/sessions/{session_id}/revoke", status_code=204, operation_id="admin_sessions_revoke", responses=_ERR
)
@csrf_protected
def revoke_session(
    session_id: uuid.UUID,
    body: Reason,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("admin.sessions.manage")),
) -> Response:
    _write_guard(request, auth)
    if session_id == auth.session_id:
        raise AppError(409, "OWN_SESSION", "Use Sign out to end your own session")
    s = db.execute(select(AuthSession).where(AuthSession.id == session_id).with_for_update()).scalar()
    now = datetime.now(UTC)
    if s is None or s.revoked_at is not None or s.idle_expires_at <= now or s.absolute_expires_at <= now:
        raise AppError(404, "NOT_FOUND", "No active session with this ID")
    _revoke_session(db, s, now, "ADMIN_REVOKED")
    write_audit(
        db,
        action="ADMIN.SESSION_REVOKED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="auth_session",
        entity_id=str(session_id),
        reason=body.reason,
        before={"active": True},
        after={"active": False, "principal_id": str(s.principal_id)},
    )
    db.commit()
    return Response(status_code=204)


# ---- API-026: system health ------------------------------------------------------------------------------------
@router.get("/admin/system-health", response_model=SystemHealth, operation_id="admin_system_health", responses=_ERR)
def system_health(
    request: Request, db: Session = Depends(get_db), _auth: AuthContext = Depends(require("system.health.read"))
) -> SystemHealth:
    settings = request.app.state.settings
    now = datetime.now(UTC)
    expected = request.app.state.expected_migration_head
    head = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    non_synthetic = db.execute(text(NON_SYNTHETIC_SQL)).scalar()
    chain = verify_chain(db)
    try:
        protection_for(db.connection(), settings)
        keys = HealthCheck(
            code="PII_KEYS", label="Field-protection keys", status="OK", detail="Present for the business domain"
        )
    except Exception:  # noqa: BLE001 — reported, not raised
        keys = HealthCheck(code="PII_KEYS", label="Field-protection keys", status="FAIL", detail="Missing or invalid")
    digest = OPENAPI_SHA.read_text().strip() if OPENAPI_SHA.exists() else ""
    checks = [
        HealthCheck(code="DATABASE", label="Database", status="OK", detail="Connected to the configured schema"),
        HealthCheck(
            code="MIGRATIONS",
            label="Migrations",
            status="OK" if head == expected else "FAIL",
            detail=f"At {head}" if head == expected else f"At {head}; expected {expected}",
        ),
        HealthCheck(
            code="DATA_POLICY",
            label="Synthetic-only data",
            status="OK" if settings.data_policy == "SYNTHETIC_ONLY" and not non_synthetic else "FAIL",
            detail="Policy SYNTHETIC_ONLY; no non-synthetic business rows"
            if not non_synthetic
            else "Non-synthetic business rows present",
        ),
        HealthCheck(
            code="AUDIT_CHAIN",
            label="Audit hash chain",
            status="OK" if chain.ok else "FAIL",
            detail=f"{chain.events} events verified" if chain.ok else f"Broken at sequence {chain.first_break_seq}",
        ),
        keys,
        HealthCheck(
            code="MOCK_UPSTREAM",
            label="Mock upstream intake API",
            status="NOT_AVAILABLE",
            detail="Deferred (remainder of CP0.4b)",
        ),
        HealthCheck(code="VOICE", label="Browser voice", status="NOT_AVAILABLE", detail="Introduced in Stage S1"),
    ]
    active_sessions = db.execute(
        select(func.count())
        .select_from(AuthSession)
        .where(
            AuthSession.revoked_at.is_(None), AuthSession.idle_expires_at > now, AuthSession.absolute_expires_at > now
        )
    ).scalar_one()
    counts = {
        "users_active": db.execute(select(func.count()).where(Principal.status == "ACTIVE")).scalar_one(),
        "users_disabled": db.execute(select(func.count()).where(Principal.status == "DISABLED")).scalar_one(),
        "groups": db.execute(select(func.count()).select_from(AppGroup)).scalar_one(),
        "active_admins": active_admin_count(db, now),
        "active_sessions": active_sessions,
        "audit_events_24h": db.execute(  # operational (market-scoped) view, as in API-021
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.occurred_at > now - timedelta(hours=24), audit_scope.visible(sorted(_auth.markets)))
        ).scalar_one(),
    }
    return SystemHealth(
        checked_at=now,
        app_env=settings.app_env,
        data_policy=settings.data_policy,
        current_stage=CURRENT_STAGE,
        migration_head=head,
        expected_migration_head=expected,
        enabled_markets=sorted(ENABLED_MARKETS),
        openapi_sha256=digest,
        audit_chain_head=chain.head,
        audit_events=chain.events,
        checks=checks,
        counts=counts,
    )
