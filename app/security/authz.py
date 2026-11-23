"""Per-request authentication and authorization (ADR-0004; S0_IDENTITY_ACCESS_DESIGN §7).

Every request re-validates the JWT *and* the server-side session, and re-resolves permissions from
the database (memberships → group-role mappings → roles → permissions), so disablement and
membership changes take effect on the next request.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Request
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.errors import AppError
from app.security.models import (
    AppGroup,
    AuthSession,
    GroupMembership,
    GroupRoleMapping,
    IdentityBinding,
    LocalCredential,
    Permission,
    Principal,
    Role,
    RolePermission,
)
from app.security.scope import resolve_markets
from app.security.tokens import TokenExpired, TokenInvalid, TokenService


@dataclass(frozen=True)
class AuthContext:
    principal_id: uuid.UUID
    display_name: str
    username: str | None
    session_id: uuid.UUID
    roles: frozenset[str]
    permissions: frozenset[str]
    access_expires_at: datetime
    session: AuthSession
    # Effective market scope (CP0.1B-2, D-39): mapped markets ∩ enabled markets ({SG}). Empty = no business data.
    markets: frozenset[str] = field(default_factory=frozenset)
    # CP0.1B-3: a one-time password set by an administrator must be changed before any permissioned action.
    password_change_required: bool = False

    @property
    def actor(self) -> Actor:
        return Actor(self.principal_id, self.display_name, self.username, self.session_id)


def request_meta(request: Request) -> RequestMeta:
    return RequestMeta(getattr(request.state, "correlation_id", None), request.client.host if request.client else None)


def get_db(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    with factory() as db:
        yield db


def resolve_grants(db: Session, principal_id: uuid.UUID, now: datetime) -> tuple[frozenset[str], frozenset[str]]:
    rows = db.execute(
        select(Role.code, Permission.code)
        .select_from(GroupMembership)
        .join(AppGroup, and_(AppGroup.id == GroupMembership.group_id, AppGroup.status == "ACTIVE"))
        .join(GroupRoleMapping, GroupRoleMapping.group_id == AppGroup.id)
        .join(Role, Role.id == GroupRoleMapping.role_id)
        .outerjoin(RolePermission, RolePermission.role_id == Role.id)
        .outerjoin(Permission, and_(Permission.id == RolePermission.permission_id, Permission.reserved.is_(False)))
        .where(
            GroupMembership.principal_id == principal_id,
            GroupMembership.valid_from <= now,
            or_(GroupMembership.valid_to.is_(None), GroupMembership.valid_to > now),
            GroupRoleMapping.effective_from <= now,
            or_(GroupRoleMapping.effective_to.is_(None), GroupRoleMapping.effective_to > now),
        )
    ).all()
    roles = frozenset(r for r, _ in rows)
    perms = frozenset(p for _, p in rows if p is not None)
    return roles, perms


def session_is_active(s: AuthSession | None, now: datetime) -> bool:
    return bool(s and s.revoked_at is None and s.idle_expires_at > now and s.absolute_expires_at > now)


def authenticate(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    return resolve_auth(request.app, request.cookies, db)


def resolve_auth(app: Any, cookies: Mapping[str, str], db: Session) -> AuthContext:
    """The shared per-request check (HTTP and the S1-A voice WebSocket): token, server session, grants, markets."""
    tokens: TokenService = app.state.tokens
    token = cookies.get(app.state.cookies.access)
    if not token:
        raise AppError(401, "AUTH_REQUIRED", "Authentication required")
    try:
        claims = tokens.decode_access(token)
    except TokenExpired as exc:
        raise AppError(401, "AUTH_TOKEN_EXPIRED", "Access token expired", retryable=True) from exc
    except TokenInvalid as exc:
        raise AppError(401, "AUTH_REQUIRED", "Authentication required") from exc
    now = datetime.now(UTC)
    session = db.get(AuthSession, claims.session_id)
    if not session_is_active(session, now) or session is None or session.principal_id != claims.principal_id:
        raise AppError(401, "AUTH_SESSION_INVALID", "Session is no longer valid")
    principal = db.get(Principal, claims.principal_id)
    if principal is None or principal.status != "ACTIVE":
        raise AppError(401, "AUTH_SESSION_INVALID", "Session is no longer valid")
    username = db.execute(select(IdentityBinding.username).where(IdentityBinding.principal_id == principal.id)).scalar()
    roles, perms = resolve_grants(db, principal.id, now)
    markets = resolve_markets(db, principal.id, now)
    must_change = bool(
        db.execute(
            select(LocalCredential.must_change_password).where(LocalCredential.principal_id == principal.id)
        ).scalar()
    )
    return AuthContext(
        principal.id,
        principal.display_name,
        username,
        session.id,
        roles,
        perms,
        claims.expires_at,
        session,
        markets,
        must_change,
    )


def require(permission: str) -> Callable[..., AuthContext]:
    """Route dependency: authenticated principal holding ``permission`` (403 + audit otherwise)."""

    def dependency(request: Request, auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if auth.password_change_required:
            raise AppError(403, "PASSWORD_CHANGE_REQUIRED", "Set your own password before continuing")
        if permission not in auth.permissions:
            with request.app.state.session_factory() as db, db.begin():
                write_audit(
                    db,
                    action="ACCESS.DENIED_FUNCTION",
                    outcome="DENIED",
                    actor=auth.actor,
                    meta=request_meta(request),
                    entity_type="route",
                    entity_id=request.url.path[:64],
                    reason=f"missing permission {permission}",
                )
            raise AppError(403, "FORBIDDEN", "You do not have permission for this action")
        return auth

    dependency.required_permission = permission  # type: ignore[attr-defined]
    return dependency


def require_any(*permissions: str) -> Callable[..., AuthContext]:
    """Route dependency: authenticated principal holding AT LEAST ONE of ``permissions`` (403 + audit otherwise).

    SHARED-1: a shared capability accepts its own dedicated permission or the legacy one that governed it until now, so
    that nobody who is authorised today loses access and a person given only the dedicated permission needs no other.
    The first permission named is the one the route inventory has always reported; all of them are accepted."""
    wanted = frozenset(permissions)

    def dependency(request: Request, auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if auth.password_change_required:
            raise AppError(403, "PASSWORD_CHANGE_REQUIRED", "Set your own password before continuing")
        if not wanted & auth.permissions:
            with request.app.state.session_factory() as db, db.begin():
                write_audit(
                    db,
                    action="ACCESS.DENIED_FUNCTION",
                    outcome="DENIED",
                    actor=auth.actor,
                    meta=request_meta(request),
                    entity_type="route",
                    entity_id=request.url.path[:64],
                    reason="missing permission " + " or ".join(permissions),
                )
            raise AppError(403, "FORBIDDEN", "You do not have permission for this action")
        return auth

    dependency.required_permission = permissions[0]  # type: ignore[attr-defined]
    dependency.accepted_permissions = permissions  # type: ignore[attr-defined]
    return dependency
