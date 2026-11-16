"""S1-B voice-session persistence on the existing model.

Lifecycle (one browser test session = one ``contact_attempt``, transport BROWSER, record origin CALL360_RUNTIME):

    attempt INITIATED ──connect──► attempt IN_SESSION + conversation_session CREATED (live)
        │                              │ network loss / tab closed / refresh ──► INTERRUPTED ──resume (30 s)──► CREATED
        │                              │ stop / limit ──► FINALIZING ──► FINALIZED  (attempt ENDED)
        │                              └ failure / abandonment / backend restart ──► ABORTED (attempt ENDED)
        └ never connected (credential lost or expired, restart) ──► attempt FAILED

Every step appends to ``session_event`` (server ``seq`` per attempt; client events de-duplicated by their event ID and
flagged when they arrive out of order) and the case timeline gets ``VOICE_SESSION_STARTED`` / ``VOICE_SESSION_ENDED``.
Session pins (script version + manifest, decided risk assessment + hash, fact snapshot + hash, contacted party and
masked contact) are fixed at connection by the existing guard. Nothing here stores audio, transcript text or
microphone content, and nothing changes the case state or verifies anyone.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

LIVE = "CREATED"
FINAL_STATES = ("FINALIZED", "ABORTED")
SOURCE_SYSTEM = "CALL360-VOICE"
MAPPING_VERSION = "S1-B-1"
RESUME_GRACE = timedelta(seconds=30)
CONNECT_GRACE = timedelta(seconds=90)  # the 60 s credential plus margin
ABORT_REASONS = {"ABANDONED", "BACKEND_RESTART", "ORPHANED", "IDLE_TIMEOUT", "MIC_DEVICE_LOST", "PROVIDER_ERROR"}


class TransitionError(Exception):
    pass


@dataclass(frozen=True)
class Pins:
    script_version_id: uuid.UUID
    script_manifest_sha256: str
    risk_assessment_id: uuid.UUID
    risk_snapshot_sha256: str
    policy_fact_snapshot_id: uuid.UUID
    policy_fact_snapshot_sha256: str


def pins_for(db: Session, case_id: uuid.UUID) -> Pins | None:
    """The current published script, the decided (FINAL) risk assessment and the latest fact snapshot of the sale."""
    r = db.execute(
        text(
            "SELECT a.script_version_id, v.manifest_sha256, ra.id AS ra_id, ra.input_snapshot_sha256, "
            "f.id AS f_id, f.sha256 AS f_sha FROM callback_case c "
            "JOIN LATERAL (SELECT script_version_id FROM script_assignment WHERE callback_case_id = c.id "
            "  ORDER BY assigned_at DESC LIMIT 1) a ON true "
            "JOIN script_version v ON v.id = a.script_version_id AND v.status = 'PUBLISHED' "
            "JOIN LATERAL (SELECT id, input_snapshot_sha256 FROM risk_assessment WHERE sale_event_id = c.sale_event_id "
            "  AND status = 'FINAL' ORDER BY assessed_at DESC LIMIT 1) ra ON true "
            "JOIN LATERAL (SELECT id, sha256 FROM policy_fact_snapshot WHERE sale_event_id = c.sale_event_id "
            "  ORDER BY captured_at DESC LIMIT 1) f ON true WHERE c.id = :c"
        ),
        {"c": case_id},
    ).first()
    if r is None:
        return None
    return Pins(r.script_version_id, r.manifest_sha256, r.ra_id, r.input_snapshot_sha256, r.f_id, r.f_sha)


def _common(actor: str, ref: str, now: datetime) -> dict[str, Any]:
    return {
        "created_by": actor,
        "updated_by": actor,
        "updated_at": now,
        "row_version": 1,
        "source_type": "MANUAL",
        "source_system": SOURCE_SYSTEM,
        "source_reference": ref,
        "source_observed_at": now,
        "recorded_at": now,
        "mapping_version": MAPPING_VERSION,
        "is_synthetic": True,
        "record_origin": "CALL360_RUNTIME",
    }


def append_event(
    db: Session,
    attempt_id: uuid.UUID,
    event_type: str,
    *,
    source: str = "SERVER",
    actor: str,
    details: dict[str, Any] | None = None,
    client_event_id: str | None = None,
    client_seq: int | None = None,
    client_occurred_at: datetime | None = None,
) -> dict[str, Any] | None:
    """Append one ordered event. A repeated client event ID is a no-op (returns ``None``)."""
    a = db.execute(  # serialises writers per attempt
        text("SELECT id FROM contact_attempt WHERE id = :a FOR UPDATE"), {"a": attempt_id}
    ).first()
    if a is None:
        raise TransitionError("unknown attempt")
    if (
        client_event_id is not None
        and db.execute(
            text("SELECT 1 FROM session_event WHERE contact_attempt_id = :a AND client_event_id = :e"),
            {"a": attempt_id, "e": client_event_id},
        ).first()
    ):
        return None
    last = db.execute(
        text(
            "SELECT coalesce(max(seq), 0) AS seq, max(client_seq) AS client_seq FROM session_event "
            "WHERE contact_attempt_id = :a"
        ),
        {"a": attempt_id},
    ).one()
    session_id = db.execute(
        text("SELECT id FROM conversation_session WHERE contact_attempt_id = :a"), {"a": attempt_id}
    ).scalar()
    row = {
        "id": uuid.uuid4(),
        "a": attempt_id,
        "s": session_id,
        "seq": last.seq + 1,
        "t": event_type,
        "src": source,
        "ce": client_event_id,
        "cs": client_seq,
        "co": client_occurred_at,
        "ooo": client_seq is not None and last.client_seq is not None and client_seq < last.client_seq,
        "d": _json(details or {}),
        "by": actor,
    }
    db.execute(
        text(
            "INSERT INTO session_event (id, contact_attempt_id, conversation_session_id, seq, event_type, source, "
            "client_event_id, client_seq, client_occurred_at, out_of_order, details, created_by) VALUES "
            "(:id, :a, :s, :seq, :t, :src, :ce, :cs, :co, :ooo, CAST(:d AS jsonb), :by)"
        ),
        row,
    )
    return {"seq": row["seq"], "out_of_order": row["ooo"]}


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, default=str)


def _case_event(db: Session, case_id: uuid.UUID, kind: str, actor: str, attempt_id: uuid.UUID, summary: str) -> None:
    db.execute(
        text(
            "INSERT INTO case_event (id, callback_case_id, event_type, occurred_at, actor_ref, related_entity_type, "
            "related_entity_id, summary, created_by) VALUES (:id, :c, :k, now(), :a, 'contact_attempt', :r, :s, :a)"
        ),
        {"id": uuid.uuid4(), "c": case_id, "k": kind, "a": actor, "r": attempt_id, "s": summary},
    )


def create_attempt(
    db: Session,
    *,
    case_id: uuid.UUID,
    case_ref: str,
    party_id: uuid.UUID,
    contact_method_id: uuid.UUID | None,
    contact_snapshot: dict[str, Any],
    actor: str,
    provider: str,
) -> tuple[uuid.UUID, str]:
    now = datetime.now(UTC)
    db.execute(text("SELECT id FROM callback_case WHERE id = :c FOR UPDATE"), {"c": case_id})
    seq = db.execute(
        text("SELECT coalesce(max(sequence), 0) + 1 FROM contact_attempt WHERE callback_case_id = :c"), {"c": case_id}
    ).scalar_one()
    attempt_id, ref = uuid.uuid4(), f"AT-{case_ref.removeprefix('CB-')}-{seq}"
    db.execute(
        text(
            "INSERT INTO contact_attempt (id, attempt_ref, callback_case_id, sequence, transport, direction, status, "
            "contacted_party_id, contact_method_id, contact_snapshot, scheduled_at, created_by, updated_by, "
            "updated_at, row_version, source_type, source_system, source_reference, source_observed_at, recorded_at, "
            "mapping_version, is_synthetic, record_origin) VALUES (:id, :ref, :c, :seq, 'BROWSER', 'OUTBOUND', "
            "'INITIATED', :p, :m, CAST(:snap AS jsonb), :now, :created_by, :updated_by, :updated_at, :row_version, "
            ":source_type, :source_system, :source_reference, :source_observed_at, :recorded_at, :mapping_version, "
            ":is_synthetic, :record_origin)"
        ),
        {
            "id": attempt_id,
            "ref": ref,
            "c": case_id,
            "seq": seq,
            "p": party_id,
            "m": contact_method_id,
            "snap": _json(contact_snapshot),
            "now": now,
            **_common(actor, ref, now),
        },
    )
    append_event(
        db, attempt_id, "SESSION_REQUESTED", actor=actor, details={"provider": provider, "transport": "BROWSER"}
    )
    return attempt_id, ref


def state_of(db: Session, attempt_id: uuid.UUID) -> dict[str, Any] | None:
    r = (
        db.execute(
            text(
                "SELECT a.id, a.attempt_ref, a.callback_case_id, a.status, a.started_at, a.ended_at, a.failure_reason, "
                "a.created_by, c.case_ref, c.market_code, s.id AS session_id, s.session_ref, s.state AS session_state "
                "FROM contact_attempt a JOIN callback_case c ON c.id = a.callback_case_id "
                "LEFT JOIN conversation_session s ON s.contact_attempt_id = a.id WHERE a.id = :a"
            ),
            {"a": attempt_id},
        )
        .mappings()
        .first()
    )
    return dict(r) if r else None


def connect(db: Session, attempt_id: uuid.UUID, *, actor: str, provider: str) -> str:
    """First connection creates the conversation session (pins fixed); a later one resumes an interrupted session."""
    st = state_of(db, attempt_id)
    if st is None:
        raise TransitionError("unknown attempt")
    now = datetime.now(UTC)
    if st["session_id"] is None:
        if st["status"] != "INITIATED":
            raise TransitionError(f"attempt is {st['status']}")
        pins = pins_for(db, st["callback_case_id"])
        if pins is None:
            raise TransitionError("case has no publishable pins")
        a = db.execute(
            text("SELECT contacted_party_id, contact_snapshot FROM contact_attempt WHERE id = :a"), {"a": attempt_id}
        ).one()
        db.execute(
            text(
                "UPDATE contact_attempt SET status = 'IN_SESSION', started_at = :now, updated_at = :now, "
                "updated_by = :by, row_version = row_version + 1 WHERE id = :a"
            ),
            {"now": now, "by": actor, "a": attempt_id},
        )
        session_ref = f"SS-{st['attempt_ref'].removeprefix('AT-')}"
        db.execute(
            text(
                "INSERT INTO conversation_session (id, session_ref, contact_attempt_id, state, transport, "
                "external_session_ref, started_at, script_version_id, script_manifest_sha256, risk_assessment_id, "
                "risk_snapshot_sha256, policy_fact_snapshot_id, policy_fact_snapshot_sha256, contacted_party_id, "
                "contact_method_snapshot, media_status, transcript_status, created_by, updated_by, updated_at, "
                "row_version, source_type, source_system, source_reference, source_observed_at, recorded_at, "
                "mapping_version, is_synthetic, record_origin) VALUES (:id, :ref, :a, 'CREATED', 'BROWSER', :ext, "
                ":now, :sv, :svh, :ra, :rah, :f, :fh, :p, CAST(:snap AS jsonb), 'NOT_REQUIRED', 'UNAVAILABLE', "
                ":created_by, :updated_by, :updated_at, :row_version, :source_type, :source_system, "
                ":source_reference, :source_observed_at, :recorded_at, :mapping_version, :is_synthetic, "
                ":record_origin)"
            ),
            {
                "id": uuid.uuid4(),
                "ref": session_ref,
                "a": attempt_id,
                "ext": f"{provider}:{attempt_id}",
                "now": now,
                "sv": pins.script_version_id,
                "svh": pins.script_manifest_sha256,
                "ra": pins.risk_assessment_id,
                "rah": pins.risk_snapshot_sha256,
                "f": pins.policy_fact_snapshot_id,
                "fh": pins.policy_fact_snapshot_sha256,
                "p": a.contacted_party_id,
                "snap": _json(dict(a.contact_snapshot)),
                **_common(actor, session_ref, now),
            },
        )
        append_event(
            db,
            attempt_id,
            "CONNECTED",
            actor=actor,
            details={
                "provider": provider,
                "model": f"{provider.lower()}-fixed-message-v1",
                "identity_verification": "NOT_PERFORMED",
                "compliance_outcome": "NOT_EVALUATED",
                "recording": "DISABLED",
            },
        )
        _case_event(
            db,
            st["callback_case_id"],
            "VOICE_SESSION_STARTED",
            actor,
            attempt_id,
            f"Browser voice test session {session_ref} started (synthetic, mock provider; nothing verified)",
        )
        return "CREATED"
    if st["session_state"] != "INTERRUPTED":
        raise TransitionError(f"session is {st['session_state']}")
    _set_session(db, attempt_id, LIVE, actor, now)
    append_event(db, attempt_id, "RESUMED", actor=actor)
    return "RESUMED"


def _set_session(
    db: Session, attempt_id: uuid.UUID, state: str, actor: str, now: datetime, ended: bool = False
) -> None:
    db.execute(
        text(
            "UPDATE conversation_session SET state = :s, updated_at = :now, updated_by = :by, "
            "row_version = row_version + 1, ended_at = CASE WHEN :ended THEN :now ELSE ended_at END "
            "WHERE contact_attempt_id = :a"
        ),
        {"s": state, "now": now, "by": actor, "a": attempt_id, "ended": ended},
    )


def interrupt(db: Session, attempt_id: uuid.UUID, *, actor: str, reason: str) -> bool:
    """Connection lost without a stop: the session can be resumed for ``RESUME_GRACE``."""
    st = state_of(db, attempt_id)
    if st is None or st["session_state"] != LIVE:
        return False
    _set_session(db, attempt_id, "INTERRUPTED", actor, datetime.now(UTC))
    append_event(db, attempt_id, "DISCONNECTED", actor=actor, details={"reason": reason})
    return True


def finalize(
    db: Session,
    attempt_id: uuid.UUID,
    *,
    actor: str,
    reason: str,
    stats: dict[str, Any] | None = None,
    source: str = "SERVER",
) -> dict[str, Any]:
    """End the session once. Repeated calls return the existing final state (idempotent Stop)."""
    st = state_of(db, attempt_id)
    if st is None:
        raise TransitionError("unknown attempt")
    now = datetime.now(UTC)
    if st["session_state"] in FINAL_STATES or st["status"] in ("ENDED", "FAILED"):
        return {"state": st["session_state"] or st["status"], "already_final": True}
    aborted = reason in ABORT_REASONS
    if st["session_id"] is None:  # never connected
        db.execute(
            text(
                "UPDATE contact_attempt SET status = 'FAILED', failure_reason = :r, ended_at = :now, "
                "updated_at = :now, updated_by = :by, row_version = row_version + 1 WHERE id = :a"
            ),
            {"r": reason[:64], "now": now, "by": actor, "a": attempt_id},
        )
        append_event(
            db,
            attempt_id,
            "FAILED" if reason != "ABANDONED" else "ABANDONED",
            source=source,
            actor=actor,
            details={"reason": reason},
        )
        return {"state": "FAILED", "already_final": False}
    _set_session(db, attempt_id, "FINALIZING", actor, now)
    final = "ABORTED" if aborted else "FINALIZED"
    _set_session(db, attempt_id, final, actor, now, ended=True)
    db.execute(
        text(
            "UPDATE contact_attempt SET status = 'ENDED', ended_at = :now, failure_reason = :fr, updated_at = :now, "
            "updated_by = :by, row_version = row_version + 1 WHERE id = :a"
        ),
        {"now": now, "fr": reason[:64] if aborted else None, "by": actor, "a": attempt_id},
    )
    if reason == "ABANDONED":
        append_event(db, attempt_id, "ABANDONED", source="SYSTEM", actor=actor, details={"reason": reason})
    append_event(
        db,
        attempt_id,
        "ENDED",
        source="SYSTEM" if source == "SYSTEM" else "SERVER",
        actor=actor,
        details={
            "reason": reason,
            "final_state": final,
            **(stats or {}),
            "identity_verification": "NOT_PERFORMED",
            "compliance_outcome": "NOT_EVALUATED",
        },
    )
    _case_event(
        db,
        st["callback_case_id"],
        "VOICE_SESSION_ENDED",
        actor,
        attempt_id,
        f"Browser voice test session {st['session_ref']} {final.lower()} ({reason}); nothing recorded or verified",
    )
    return {"state": final, "already_final": False}


def sweep(db: Session, *, live: set[uuid.UUID], now: datetime | None = None, startup: bool = False) -> list[str]:
    """Finalise sessions that can no longer continue: never connected in time, interrupted beyond the resume grace,
    or marked live with no live connection in this process (``startup``: after a backend restart, all of them)."""
    now = now or datetime.now(UTC)
    done: list[str] = []
    rows = (
        db.execute(
            text(
                "SELECT a.id, a.status, a.scheduled_at, s.state, (SELECT max(e.occurred_at) FROM session_event e "
                "WHERE e.contact_attempt_id = a.id) AS last_event FROM contact_attempt a "
                "LEFT JOIN conversation_session s ON s.contact_attempt_id = a.id "
                "WHERE a.transport = 'BROWSER' AND a.record_origin = 'CALL360_RUNTIME' "
                "AND (a.status = 'INITIATED' OR s.state IN ('CREATED', 'INTERRUPTED', 'FINALIZING'))"
            )
        )
        .mappings()
        .all()
    )
    for r in rows:
        if r["id"] in live and not startup:
            continue
        last = r["last_event"] or r["scheduled_at"]
        if startup:
            reason = "BACKEND_RESTART"
        elif r["status"] == "INITIATED" and now - r["scheduled_at"] > CONNECT_GRACE:
            reason = "ABANDONED"
        elif r["state"] == "INTERRUPTED" and now - last > RESUME_GRACE:
            reason = "ABANDONED"
        elif r["state"] in ("CREATED", "FINALIZING") and now - last > RESUME_GRACE:
            reason = "ORPHANED"
        else:
            continue
        finalize(db, r["id"], actor="SYSTEM:voice-sweeper", reason=reason, source="SYSTEM")
        done.append(f"{r['id']}:{reason}")
    return done
