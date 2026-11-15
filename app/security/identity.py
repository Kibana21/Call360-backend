"""Identity-provider abstraction and local accounts (ADR-0004 §1; S0_IDENTITY_ACCESS_DESIGN §2–§3).

Person (``principal``) ≠ login identity (``identity_binding``) ≠ credential (``local_credential``).
S5 adds an OIDC provider (Okta / Entra ID) behind the same protocol.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.security.models import (
    AppGroup,
    GroupMembership,
    GroupRoleMapping,
    IdentityBinding,
    IdentityProvider,
    LocalCredential,
    Principal,
    Role,
)
from app.security.passwords import HASH_PARAMS, check_policy, hash_password

LOCAL_ISSUER = "call360-local"


@dataclass(frozen=True)
class ExternalIdentity:
    issuer: str
    subject: str
    display_name: str


class IdentityProviderAdapter(Protocol):
    kind: str

    def issuer(self) -> str: ...


class LocalIdentityProvider:
    """Username + Argon2id password against ``local_credential``. Verification lives in the
    authentication service so failed attempts share one throttling and audit path."""

    kind = "LOCAL"

    def issuer(self) -> str:
        return LOCAL_ISSUER


class AccountError(ValueError):
    pass


def local_provider(db: Session) -> IdentityProvider:
    provider = db.execute(select(IdentityProvider).where(IdentityProvider.issuer == LOCAL_ISSUER)).scalar_one()
    return provider


def normalise_username(username: str) -> str:
    return username.strip().lower()


def active_admin_count(db: Session, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    return db.execute(
        select(func.count(func.distinct(Principal.id)))
        .join(GroupMembership, GroupMembership.principal_id == Principal.id)
        .join(GroupRoleMapping, GroupRoleMapping.group_id == GroupMembership.group_id)
        .join(Role, Role.id == GroupRoleMapping.role_id)
        .where(
            Principal.status == "ACTIVE",
            Role.code == "ADMIN",
            GroupMembership.valid_from <= now,
            (GroupMembership.valid_to.is_(None)) | (GroupMembership.valid_to > now),
            (GroupRoleMapping.effective_to.is_(None)) | (GroupRoleMapping.effective_to > now),
        )
    ).scalar_one()


def create_local_account(
    db: Session,
    *,
    username: str,
    display_name: str,
    password: str,
    group_code: str,
    created_by: str,
    actor: Actor,
    meta: RequestMeta,
    audit_action: str = "ADMIN.USER_CREATED",
) -> Principal:
    username = normalise_username(username)
    if not 3 <= len(username) <= 64 or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
        raise AccountError("username must be 3–64 characters: letters, digits, '.', '_' or '-'")
    check_policy(password, username=username, display_name=display_name)
    if db.execute(select(IdentityBinding.id).where(IdentityBinding.username == username)).first():
        raise AccountError("username is already taken")
    group = db.execute(select(AppGroup).where(AppGroup.code == group_code, AppGroup.status == "ACTIVE")).scalar()
    if group is None:
        raise AccountError(f"unknown group {group_code!r}")
    provider = local_provider(db)
    principal = Principal(
        id=uuid.uuid4(),
        display_name=display_name.strip()[:120],
        status="ACTIVE",
        created_by=created_by,
        updated_by=created_by,
        row_version=1,
    )
    db.add(principal)
    db.flush()
    db.add(
        IdentityBinding(
            principal_id=principal.id, identity_provider_id=provider.id, subject=str(uuid.uuid4()), username=username
        )
    )
    db.add(
        LocalCredential(
            principal_id=principal.id, password_hash=hash_password(password), hash_params=HASH_PARAMS, failed_count=0
        )
    )
    db.add(
        GroupMembership(
            principal_id=principal.id, group_id=group.id, provenance="LOCAL_ADMIN_ACTION", created_by=created_by
        )
    )
    db.flush()
    write_audit(
        db,
        action=audit_action,
        outcome="SUCCEEDED",
        actor=actor,
        meta=meta,
        entity_type="principal",
        entity_id=str(principal.id),
        entity_version=1,
        after={"username": username, "display_name": principal.display_name, "group": group_code, "status": "ACTIVE"},
    )
    return principal
