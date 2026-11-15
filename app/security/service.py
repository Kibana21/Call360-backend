"""Login, refresh rotation (with benign-concurrency classification), logout and revocation.

Normative: S0_IDENTITY_ACCESS_DESIGN §3–§4 (D-23 as refined at CP0.1A).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.errors import AppError
from app.core.settings import Settings
from app.security.identity import LOCAL_ISSUER, normalise_username
from app.security.models import (
    AuthSession,
    IdentityBinding,
    IdentityProvider,
    LocalCredential,
    LoginAttempt,
    Principal,
    RefreshToken,
    RefreshTokenFamily,
)
from app.security.passwords import hash_password, needs_rehash, verify_password
from app.security.tokens import TokenService


def invalid_credentials() -> AppError:
    return AppError(401, "AUTH_INVALID_CREDENTIALS", "Sign-in failed")


@dataclass(frozen=True)
class IssuedSession:
    principal: Principal
    username: str | None
    session: AuthSession
    access_token: str
    access_expires_at: datetime
    refresh_token: str


class RefreshSuperseded(Exception):
    """Benign concurrent refresh: the caller should retry with the cookies it already holds."""


def username_hash(settings: Settings, username: str) -> str:
    pepper = settings.refresh_token_pepper.get_secret_value()
    return hashlib.sha256(f"{pepper}:login:{username}".encode()).hexdigest()


def _new_refresh(
    db: Session, tokens: TokenService, family: RefreshTokenFamily, generation: int, session: AuthSession, now: datetime
) -> str:
    raw = tokens.new_refresh_token()
    db.add(
        RefreshToken(
            family_id=family.id,
            generation=generation,
            token_hmac=tokens.refresh_hmac(raw),
            issued_at=now,
            expires_at=session.absolute_expires_at,
        )
    )
    return raw


def login(
    db: Session,
    settings: Settings,
    tokens: TokenService,
    *,
    username: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
    meta: RequestMeta,
) -> IssuedSession:
    now = datetime.now(UTC)
    uname = normalise_username(username)
    uhash = username_hash(settings, uname)
    row = db.execute(
        select(IdentityBinding, LocalCredential, Principal)
        .join(IdentityProvider, IdentityProvider.id == IdentityBinding.identity_provider_id)
        .join(LocalCredential, LocalCredential.principal_id == IdentityBinding.principal_id)
        .join(Principal, Principal.id == IdentityBinding.principal_id)
        .where(IdentityBinding.username == uname, IdentityProvider.issuer == LOCAL_ISSUER)
        .with_for_update(of=LocalCredential)
    ).first()
    binding, cred, principal = row if row else (None, None, None)
    password_ok = verify_password(cred.password_hash if cred else None, password)
    locked = bool(cred and cred.locked_until and cred.locked_until > now)
    active = bool(principal and principal.status == "ACTIVE")

    if not (password_ok and not locked and active and cred and principal):
        _record_failure(db, settings, cred, uhash, ip, now, meta, principal, locked=locked)
        db.commit()
        raise invalid_credentials()

    db.add(LoginAttempt(username_hash=uhash, ip=ip, occurred_at=now, outcome="SUCCEEDED"))
    cred.failed_count = 0
    cred.locked_until = None
    if needs_rehash(cred.password_hash):
        cred.password_hash = hash_password(password)
    session = AuthSession(
        id=uuid.uuid4(),
        principal_id=principal.id,
        created_at=now,
        last_seen_at=now,
        idle_expires_at=now + timedelta(seconds=settings.refresh_idle_seconds),
        absolute_expires_at=now + timedelta(seconds=settings.refresh_absolute_seconds),
        user_agent_hash=hashlib.sha256((user_agent or "").encode()).hexdigest(),
        ip=ip,
    )
    db.add(session)
    family = RefreshTokenFamily(id=uuid.uuid4(), session_id=session.id, created_at=now)
    db.add(family)
    db.flush()
    refresh = _new_refresh(db, tokens, family, 1, session, now)
    access, access_exp = tokens.issue_access(principal.id, session.id, now)
    write_audit(
        db,
        action="AUTH.LOGIN_SUCCEEDED",
        outcome="SUCCEEDED",
        actor=Actor(principal.id, principal.display_name, uname, session.id),
        meta=meta,
        entity_type="auth_session",
        entity_id=str(session.id),
    )
    db.commit()
    return IssuedSession(principal, binding.username if binding else None, session, access, access_exp, refresh)


def _record_failure(
    db: Session,
    settings: Settings,
    cred: LocalCredential | None,
    uhash: str,
    ip: str | None,
    now: datetime,
    meta: RequestMeta,
    principal: Principal | None,
    *,
    locked: bool,
) -> None:
    db.add(LoginAttempt(username_hash=uhash, ip=ip, occurred_at=now, outcome="FAILED"))
    db.flush()
    window_start = now - timedelta(seconds=settings.login_failure_window_seconds)
    failures = db.execute(
        select(func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.username_hash == uhash,
            LoginAttempt.outcome == "FAILED",
            LoginAttempt.occurred_at >= window_start,
        )
    ).scalar_one()
    actor = Actor(principal.id, principal.display_name) if principal else Actor()
    write_audit(
        db,
        action="AUTH.LOGIN_FAILED",
        outcome="FAILED",
        actor=actor,
        meta=meta,
        entity_type="login",
        entity_id=uhash[:16],
        reason="account locked" if locked else None,
    )
    if cred is not None and not locked and failures >= settings.login_max_failures:
        exponent = failures - settings.login_max_failures
        backoff = min(60 * (2**exponent), settings.login_backoff_cap_seconds)
        cred.failed_count = failures
        cred.locked_until = now + timedelta(seconds=backoff)
        write_audit(
            db,
            action="AUTH.LOCKOUT_APPLIED",
            outcome="SUCCEEDED",
            actor=actor,
            meta=meta,
            entity_type="principal",
            entity_id=str(cred.principal_id),
            reason=f"backoff {backoff}s",
        )


def refresh(
    db: Session, settings: Settings, tokens: TokenService, *, raw_token: str, meta: RequestMeta
) -> IssuedSession:
    """Rotate a refresh token. Raises RefreshSuperseded for a benign concurrent duplicate and
    AppError(401) for invalid tokens or reuse (which revokes the family and session)."""
    now = datetime.now(UTC)
    token = db.execute(select(RefreshToken).where(RefreshToken.token_hmac == tokens.refresh_hmac(raw_token))).scalar()
    if token is None:
        raise AppError(401, "AUTH_REFRESH_INVALID", "Refresh token is not valid")
    # Row-lock the family: serialises concurrent redemptions so exactly one rotation happens.
    family = db.execute(
        select(RefreshTokenFamily).where(RefreshTokenFamily.id == token.family_id).with_for_update()
    ).scalar_one()
    db.refresh(token)
    session = db.get(AuthSession, family.session_id)
    principal = db.get(Principal, session.principal_id) if session else None
    usable = (
        family.revoked_at is None
        and session is not None
        and principal is not None
        and principal.status == "ACTIVE"
        and _session_active(session, now)
    )

    if token.used_at is None and usable and token.expires_at > now:
        assert session is not None and principal is not None
        token.used_at = now
        newest_generation = token.generation + 1
        new_raw = _new_refresh(db, tokens, family, newest_generation, session, now)
        session.last_seen_at = now
        session.idle_expires_at = min(
            now + timedelta(seconds=settings.refresh_idle_seconds), session.absolute_expires_at
        )
        access, access_exp = tokens.issue_access(principal.id, session.id, now)
        db.commit()
        return IssuedSession(principal, None, session, access, access_exp, new_raw)

    if token.used_at is not None and usable:
        newest = db.execute(
            select(RefreshToken)
            .where(RefreshToken.family_id == family.id)
            .order_by(RefreshToken.generation.desc())
            .limit(1)
        ).scalar_one()
        grace = timedelta(seconds=settings.refresh_reuse_grace_seconds)
        if newest.generation == token.generation + 1 and now - newest.issued_at <= grace:
            db.rollback()
            raise RefreshSuperseded()

    # Reuse, or a token whose family/session/principal is no longer valid.
    if session is not None and family.revoked_at is None:
        actor = Actor(principal.id, principal.display_name, session_id=session.id) if principal else Actor()
        if token.used_at is not None:
            token.reuse_detected_at = now
            _revoke_session(db, session, now, "REFRESH_REUSE")
            write_audit(
                db,
                action="SECURITY.REFRESH_REUSE_DETECTED",
                outcome="DENIED",
                actor=actor,
                meta=meta,
                entity_type="refresh_token_family",
                entity_id=str(family.id),
                reason=f"generation {token.generation} presented after rotation",
            )
        db.commit()
    else:
        db.rollback()
    raise AppError(401, "AUTH_REFRESH_INVALID", "Refresh token is not valid")


def _session_active(s: AuthSession, now: datetime) -> bool:
    return s.revoked_at is None and s.idle_expires_at > now and s.absolute_expires_at > now


def _revoke_session(db: Session, session: AuthSession, now: datetime, reason: str) -> None:
    if session.revoked_at is None:
        session.revoked_at = now
        session.revoked_reason = reason
    db.execute(
        update(RefreshTokenFamily)
        .where(RefreshTokenFamily.session_id == session.id, RefreshTokenFamily.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )


def logout(db: Session, *, session_id: uuid.UUID, actor: Actor, meta: RequestMeta) -> None:
    now = datetime.now(UTC)
    session = db.get(AuthSession, session_id)
    if session is None:
        return
    _revoke_session(db, session, now, "LOGOUT")
    write_audit(
        db,
        action="AUTH.LOGOUT",
        outcome="SUCCEEDED",
        actor=actor,
        meta=meta,
        entity_type="auth_session",
        entity_id=str(session_id),
    )


def revoke_all_sessions(db: Session, principal_id: uuid.UUID, reason: str) -> int:
    now = datetime.now(UTC)
    sessions = (
        db.execute(
            select(AuthSession).where(AuthSession.principal_id == principal_id, AuthSession.revoked_at.is_(None))
        )
        .scalars()
        .all()
    )
    for s in sessions:
        _revoke_session(db, s, now, reason)
    return len(sessions)
