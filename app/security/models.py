"""CP0.1A identity, session and access tables (S0_DATA_MODEL §4.1, Build = CP0.1A)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

TS = DateTime(timezone=True)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class IdentityProvider(Base):
    __tablename__ = "identity_provider"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32))
    issuer: Mapped[str] = mapped_column(String(200), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class Principal(Base):
    __tablename__ = "principal"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    display_name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    disabled_at: Mapped[datetime | None] = mapped_column(TS)
    disabled_by: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    created_by: Mapped[str] = mapped_column(String(80))
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    updated_by: Mapped[str] = mapped_column(String(80))
    row_version: Mapped[int] = mapped_column(Integer, default=1)


class IdentityBinding(Base):
    __tablename__ = "identity_binding"
    __table_args__ = (UniqueConstraint("identity_provider_id", "subject"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principal.id"))
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_provider.id"))
    subject: Mapped[str] = mapped_column(String(200))
    username: Mapped[str | None] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class LocalCredential(Base):
    __tablename__ = "local_credential"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principal.id"), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    hash_params: Mapped[str] = mapped_column(String(64))
    password_changed_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class AppGroup(Base):
    __tablename__ = "app_group"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identity_provider.id"))
    external_group_id: Mapped[str | None] = mapped_column(String(200))
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")


class GroupMembership(Base):
    __tablename__ = "group_membership"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principal.id"))
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_group.id"))
    valid_from: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    valid_to: Mapped[datetime | None] = mapped_column(TS)
    provenance: Mapped[str] = mapped_column(String(40))
    created_by: Mapped[str] = mapped_column(String(80))


class Role(Base):
    __tablename__ = "role"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(80))


class Permission(Base):
    __tablename__ = "permission"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    alias: Mapped[str | None] = mapped_column(String(64))
    reserved: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(String(200))


class RolePermission(Base):
    __tablename__ = "role_permission"
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("role.id"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permission.id"), primary_key=True)


class GroupRoleMapping(Base):
    __tablename__ = "group_role_mapping"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_group.id"))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("role.id"))
    effective_from: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    effective_to: Mapped[datetime | None] = mapped_column(TS)
    approved_by: Mapped[str] = mapped_column(String(80))


class GroupScopeMapping(Base):
    """Group → market scope (CP0.1B-2; seeded, not administered, in Stage 0 — D-39)."""

    __tablename__ = "group_scope_mapping"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_group.id"))
    market_code: Mapped[str] = mapped_column(String(40))
    effective_from: Mapped[datetime] = mapped_column(TS)
    effective_to: Mapped[datetime | None] = mapped_column(TS)
    created_by: Mapped[str] = mapped_column(String(80))
    change_reason: Mapped[str] = mapped_column(Text)


class AuthSession(Base):
    __tablename__ = "auth_session"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principal.id"))
    created_at: Mapped[datetime] = mapped_column(TS)
    last_seen_at: Mapped[datetime] = mapped_column(TS)
    idle_expires_at: Mapped[datetime] = mapped_column(TS)
    absolute_expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))


class RefreshTokenFamily(Base):
    __tablename__ = "refresh_token_family"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("auth_session.id"))
    created_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    revoked_reason: Mapped[str | None] = mapped_column(String(64))


class RefreshToken(Base):
    __tablename__ = "refresh_token"
    __table_args__ = (UniqueConstraint("family_id", "generation"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    family_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("refresh_token_family.id"))
    generation: Mapped[int] = mapped_column(Integer)
    token_hmac: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime] = mapped_column(TS)
    expires_at: Mapped[datetime] = mapped_column(TS)
    used_at: Mapped[datetime | None] = mapped_column(TS)
    reuse_detected_at: Mapped[datetime | None] = mapped_column(TS)


class LoginAttempt(Base):
    __tablename__ = "login_attempt"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    username_hash: Mapped[str] = mapped_column(String(64), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(TS)
    outcome: Mapped[str] = mapped_column(String(16))


class AuditEvent(Base):
    __tablename__ = "audit_event"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    seq: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True)
    occurred_at: Mapped[datetime] = mapped_column(TS)
    actor_principal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    request_id: Mapped[str | None] = mapped_column(String(64))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    entity_version: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(500))
    before: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    after: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))
