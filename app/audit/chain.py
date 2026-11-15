"""Append-only audit trail with a SHA-256 hash chain (ADR-0005 §1).

The chain proves internal consistency, not authenticity (ADR-0005 §2, RR-01/RR-11).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.security.models import AuditEvent

_CHAIN_LOCK_KEY = 360_0001  # pg_advisory_xact_lock key serialising chain appends

_HASHED_FIELDS = (
    "id",
    "occurred_at",
    "actor_principal_id",
    "actor_snapshot",
    "session_id",
    "request_id",
    "correlation_id",
    "source_ip",
    "action",
    "entity_type",
    "entity_id",
    "entity_version",
    "outcome",
    "reason",
    "before",
    "after",
    "prev_hash",
)


def _canonical(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return value


def compute_row_hash(event: AuditEvent) -> str:
    payload = {f: _canonical(getattr(event, f)) for f in _HASHED_FIELDS}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class Actor:
    principal_id: uuid.UUID | None = None
    display_name: str | None = None
    username: str | None = None
    session_id: uuid.UUID | None = None
    service: str | None = None


@dataclass(frozen=True)
class RequestMeta:
    correlation_id: str | None = None
    source_ip: str | None = None


def write_audit(
    db: Session,
    *,
    action: str,
    outcome: str,
    actor: Actor | None = None,
    meta: RequestMeta | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    entity_version: int | None = None,
    reason: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one audit event in the caller's transaction (it commits or rolls back with it)."""
    actor = actor or Actor()
    meta = meta or RequestMeta()
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY})
    prev = db.execute(select(AuditEvent.row_hash).order_by(AuditEvent.seq.desc()).limit(1)).scalar()
    snapshot = None
    if actor.principal_id or actor.service:
        snapshot = {
            "provider": "LOCAL" if actor.principal_id else None,
            "display_name": actor.display_name,
            "username": actor.username,
            "service": actor.service,
        }
    event = AuditEvent(
        id=uuid.uuid4(),
        occurred_at=datetime.now(UTC),
        actor_principal_id=actor.principal_id,
        actor_snapshot=snapshot,
        session_id=actor.session_id,
        request_id=meta.correlation_id,
        correlation_id=meta.correlation_id,
        source_ip=meta.source_ip,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_version=entity_version,
        outcome=outcome,
        reason=reason,
        before=before,
        after=after,
        prev_hash=prev,
    )
    event.row_hash = compute_row_hash(event)
    db.add(event)
    db.flush()
    return event


@dataclass(frozen=True)
class ChainReport:
    events: int
    head: str | None
    first_break_seq: int | None

    @property
    def ok(self) -> bool:
        return self.first_break_seq is None


def verify_chain(db: Session) -> ChainReport:
    prev: str | None = None
    count = 0
    for event in db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars():
        count += 1
        if event.prev_hash != prev or compute_row_hash(event) != event.row_hash:
            return ChainReport(count, prev, event.seq)
        prev = event.row_hash
    return ChainReport(count, prev, None)
