"""Voice APIs: API-078 preflight and browser voice test sessions (S1-A mock provider; S1-B persistence).

- ``GET /voice/preflight`` (API-078, ``voice.preflight.read``): the genuine capability state.
- ``POST /voice/sessions`` (``voice.session.start``, CSRF): for a **callable** Singapore case (Call Detail pre-check;
  holds never bypassed) with a published script, a decided risk assessment and a fact snapshot, persists a BROWSER
  ``contact_attempt`` (INITIATED) and returns a single-use, 60 s, case- and user-bound credential.
- ``WS /voice/sessions/{id}/stream``: Origin, signed-in session, permission and owner checks; credential as the first
  message. The first connection creates the ``conversation_session`` with its fixed pins; a reconnect resumes an
  INTERRUPTED session. Audio is 16 kHz PCM16 in 20 ms frames both ways and is never stored.
- ``POST /voice/sessions/{id}/resume`` (owner): a new credential for an interrupted session within 30 s (or a session
  that never connected, within its connect window), e.g. after a refresh or a network drop.
- ``POST /voice/sessions/{id}/stop`` (owner): idempotent finalisation, also ending a live connection elsewhere.
- ``GET /voice/sessions/{id}`` and ``GET /voice/sessions?case_id=`` (``case.read``, market-scoped): status, counts
  and the persisted event timeline.

Lifecycle and the event ledger are in ``app.voice.store``. No session records audio or transcript, verifies anyone or
changes the case state: identity ``NOT_PERFORMED``, compliance ``NOT_EVALUATED``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import secrets
import struct
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.admin_config import _write_guard
from app.api.case_detail import _case, _holds, _pin, call_blockers
from app.api.deps import csrf_protected
from app.api.schemas import (
    ErrorResponse,
    VoiceCapability,
    VoiceCaseOption,
    VoiceContact,
    VoicePreflight,
    VoiceSessionCreate,
    VoiceSessionEvent,
    VoiceSessionList,
    VoiceSessionOut,
    VoiceSessionStatus,
)
from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.errors import AppError
from app.security.authz import AuthContext, get_db, request_meta, require, resolve_auth
from app.security.scope import not_found
from app.voice import store
from app.voice.mock import FIXED_MESSAGE, MockVoiceProvider
from app.voice.provider import FRAME_MS, SAMPLE_RATE, Inbound, SessionStats, VoiceProvider

router = APIRouter(prefix="/api/v1", tags=["voice"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
log = logging.getLogger("call360.voice")
CREDENTIAL_TTL = timedelta(seconds=60)
MAX_DURATION_S = 300
IDLE_TIMEOUT_S = 20
MAX_FRAME_BYTES = 4096
AUTH_TIMEOUT_S = 5
CLIENT_STOP_REASONS = {"STOPPED_BY_USER", "MIC_DEVICE_LOST", "PAGE_CLOSED"}
PERSISTED_PROVIDER_EVENTS = {
    "response.started": "PROVIDER_RESPONSE_STARTED",
    "playback.clear": "BARGE_IN",
}


@dataclass
class VoiceSession:
    attempt_id: uuid.UUID
    case_id: uuid.UUID
    case_ref: str
    principal_id: uuid.UUID
    credential_hash: str
    credential_expires_at: datetime
    connected: bool = False
    stop: asyncio.Event | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class SessionRegistry:
    """Pending credentials (SHA-256 digests, single use) and live connections of this process."""

    def __init__(self) -> None:
        self._pending: dict[uuid.UUID, VoiceSession] = {}
        self.live: dict[uuid.UUID, VoiceSession] = {}

    def add(self, s: VoiceSession) -> None:
        now = datetime.now(UTC)
        for k in [k for k, v in self._pending.items() if v.credential_expires_at < now]:
            del self._pending[k]
        self._pending[s.attempt_id] = s

    def claim(self, attempt_id: uuid.UUID, principal_id: uuid.UUID, credential: str) -> VoiceSession | None:
        s = self._pending.get(attempt_id)
        if s is None or s.principal_id != principal_id or s.credential_expires_at < datetime.now(UTC):
            return None
        if attempt_id in self.live:
            return None
        if not hmac.compare_digest(hashlib.sha256(credential.encode()).hexdigest(), s.credential_hash):
            return None
        del self._pending[attempt_id]  # single use
        s.connected, s.stop = True, asyncio.Event()
        self.live[attempt_id] = s
        return s

    def release(self, attempt_id: uuid.UUID) -> None:
        self.live.pop(attempt_id, None)

    def signal_stop(self, attempt_id: uuid.UUID) -> bool:
        s = self.live.get(attempt_id)
        if s is not None and s.stop is not None:
            s.stop.set()
            return True
        return False


def registry(app: Any) -> SessionRegistry:
    if not hasattr(app.state, "voice_sessions"):
        app.state.voice_sessions = SessionRegistry()
    reg: SessionRegistry = app.state.voice_sessions
    return reg


def provider_for(app: Any) -> VoiceProvider:
    if not hasattr(app.state, "voice_provider"):
        app.state.voice_provider = MockVoiceProvider()
    p: VoiceProvider = app.state.voice_provider
    return p


def run_sweep(app: Any, *, startup: bool = False) -> list[str]:
    """Finalise stale or orphaned sessions (also called at startup: nothing is live after a restart)."""
    with app.state.session_factory() as db, db.begin():
        if db.execute(text("SELECT to_regclass('session_event')")).scalar() is None:
            return []  # an earlier schema (before migration 0012) has no voice sessions to recover
        return store.sweep(db, live=set(registry(app).live), startup=startup)


def _callable_cases(db: Session, markets: list[str], limit: int = 6) -> list[VoiceCaseOption]:
    rows = db.execute(
        text(
            "SELECT c.id, c.case_ref, c.state FROM callback_case c WHERE c.market_code = ANY(:m) "
            "AND c.state IN ('READY', 'AWAITING_CALLBACK') "
            "AND NOT EXISTS (SELECT 1 FROM case_hold h WHERE h.callback_case_id = c.id AND h.is_blocking "
            "AND h.released_at IS NULL) "
            "AND EXISTS (SELECT 1 FROM case_contact_selection s WHERE s.callback_case_id = c.id AND s.eligible "
            "AND NOT EXISTS (SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = s.id)) "
            "AND EXISTS (SELECT 1 FROM script_assignment a JOIN script_version v ON v.id = a.script_version_id "
            "WHERE a.callback_case_id = c.id AND v.status = 'PUBLISHED') ORDER BY c.case_ref LIMIT :l"
        ),
        {"m": markets, "l": limit},
    ).mappings()
    return [VoiceCaseOption(case_id=r["id"], case_ref=r["case_ref"], state=r["state"]) for r in rows]


# ---- API-078 ---------------------------------------------------------------------------------------------------
@router.get("/voice/preflight", response_model=VoicePreflight, operation_id="voice_preflight", responses=_ERR)
def voice_preflight(
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("voice.preflight.read")),
) -> VoicePreflight:
    can_start = "voice.session.start" in auth.permissions
    caps = [
        VoiceCapability(
            code="VOICE_SESSION",
            label="Browser voice session (local test)",
            status="AVAILABLE" if can_start else "NOT_AVAILABLE",
            reason="Full-duplex browser audio with a mock provider on a callable synthetic Singapore case; "
            "sessions and their events are persisted (S1-B)"
            if can_start
            else "Your role cannot start voice sessions",
            stage="S1-A",
        ),
        VoiceCapability(
            code="MICROPHONE",
            label="Microphone",
            status="AVAILABLE",
            reason="Requested by the browser when you start a session; denial or device loss ends the session safely",
            stage="S1-A",
        ),
        VoiceCapability(
            code="VOICE_PROVIDER",
            label="Voice provider",
            status="AVAILABLE",
            reason="Mock provider: keyless, server-side, speaks only the fixed synthetic test message. "
            "A real provider (GPT-Live) is deferred to S1-E",
            stage="S1-A",
        ),
        VoiceCapability(
            code="RECORDING",
            label="Recording",
            status="DISABLED",
            reason="Not captured in S1-A; consent-gated recording arrives in S1-C",
            stage="S1-C",
        ),
        VoiceCapability(
            code="TRANSCRIPT", label="Transcript", status="NOT_AVAILABLE", reason="Arrives in S1-D", stage="S1-D"
        ),
        VoiceCapability(
            code="SCRIPT_CONTROLLER",
            label="Script-controlled questions",
            status="NOT_AVAILABLE",
            reason="No insurance or verification questions are asked; script control arrives in S2",
            stage="S2",
        ),
        VoiceCapability(
            code="IDENTITY",
            label="Identity verification",
            status="NOT_PERFORMED",
            reason="No session can verify a customer or a case",
            stage="S1",
        ),
        VoiceCapability(
            code="COMPLIANCE",
            label="Compliance outcome",
            status="NOT_EVALUATED",
            reason="Compliance evaluation arrives in S3",
            stage="S3",
        ),
    ]
    return VoicePreflight(
        status="AVAILABLE" if can_start else "NOT_AVAILABLE",
        reason="Local synthetic audio test with a mock provider (S1-A)"
        if can_start
        else "Voice sessions are not available to your role",
        stage="S1-A",
        provider=provider_for(request.app).name,
        capabilities=caps,
        data_policy=request.app.state.settings.data_policy,
        test_message=list(FIXED_MESSAGE),
        callable_cases=_callable_cases(db, sorted(auth.markets)) if can_start else [],
    )


def _issue(
    request: Request,
    db: Session,
    auth: AuthContext,
    attempt_id: uuid.UUID,
    case_id: uuid.UUID,
    case_ref: str,
    attempt_ref: str,
    *,
    resumed: bool,
) -> VoiceSessionOut:
    contact = (
        db.execute(
            text(
                "SELECT pa.party_ref, pa.masked_name, ppr.role, a.contact_snapshot FROM contact_attempt a "
                "JOIN party pa ON pa.id = a.contacted_party_id JOIN case_contact_selection s ON s.callback_case_id = "
                "a.callback_case_id AND s.party_id = a.contacted_party_id AND s.eligible "
                "JOIN policy_party_role ppr ON ppr.id = s.policy_party_role_id WHERE a.id = :a LIMIT 1"
            ),
            {"a": attempt_id},
        )
        .mappings()
        .one()
    )
    pins = store.pins_for(db, case_id)
    assert pins is not None
    credential = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    registry(request.app).add(
        VoiceSession(
            attempt_id=attempt_id,
            case_id=case_id,
            case_ref=case_ref,
            principal_id=auth.principal_id,
            credential_hash=hashlib.sha256(credential.encode()).hexdigest(),
            credential_expires_at=now + CREDENTIAL_TTL,
        )
    )
    snap = dict(contact["contact_snapshot"])
    return VoiceSessionOut(
        session_id=attempt_id,
        attempt_ref=attempt_ref,
        resumed=resumed,
        credential=credential,
        credential_expires_at=now + CREDENTIAL_TTL,
        stream_path=f"/api/v1/voice/sessions/{attempt_id}/stream",
        case_id=case_id,
        case_ref=case_ref,
        provider=provider_for(request.app).name,
        script=_pin(db, pins.script_version_id),
        contact=VoiceContact(
            party_ref=contact["party_ref"],
            masked_name=contact["masked_name"],
            role=contact["role"],
            channel=snap.get("channel"),
            masked_contact=snap.get("masked_value"),
        ),
        test_message=list(FIXED_MESSAGE),
        sample_rate=SAMPLE_RATE,
        frame_ms=FRAME_MS,
        max_duration_s=MAX_DURATION_S,
    )


@router.post(
    "/voice/sessions",
    response_model=VoiceSessionOut,
    status_code=201,
    operation_id="voice_session_create",
    responses=_ERR,
)
@csrf_protected
def create_session(
    body: VoiceSessionCreate,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("voice.session.start")),
) -> VoiceSessionOut:
    _write_guard(request, auth)
    c = _case(db, request, auth, body.case_id)  # audited 404 when missing or out of scope
    eligible = (
        db.execute(
            text(
                "SELECT s.party_id, s.contact_method_id, cm.channel, cm.masked_value, cm.valid_from "
                "FROM case_contact_selection s LEFT JOIN contact_method cm ON cm.id = s.contact_method_id "
                "JOIN party pa ON pa.id = s.party_id JOIN policy_party_role ppr ON ppr.id = s.policy_party_role_id "
                "WHERE s.callback_case_id = :c AND s.eligible "
                "AND NOT EXISTS (SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = s.id) "
                "ORDER BY pa.party_ref, ppr.role LIMIT 1"
            ),
            {"c": body.case_id},
        )
        .mappings()
        .first()
    )
    blockers = call_blockers(_holds(db, body.case_id), eligible is not None, c["state"])
    if blockers:
        raise AppError(
            409,
            "CASE_NOT_CALLABLE",
            "This case cannot be called: " + ", ".join(blockers),
            details=[{"loc": ["body", "case_id"], "code": b, "message": b} for b in blockers],
        )
    if store.pins_for(db, body.case_id) is None:
        raise AppError(
            409,
            "NO_SCRIPT_ASSIGNED",
            "This case has no published script, decided risk assessment and fact snapshot to pin",
        )
    assert eligible is not None
    store.sweep(db, live=set(registry(request.app).live))  # finalise anything abandoned before adding more
    attempt_id, attempt_ref = store.create_attempt(
        db,
        case_id=body.case_id,
        case_ref=c["case_ref"],
        party_id=eligible["party_id"],
        contact_method_id=eligible["contact_method_id"],
        contact_snapshot={
            "channel": eligible["channel"],
            "masked_value": eligible["masked_value"],
            "contact_method_id": str(eligible["contact_method_id"]) if eligible["contact_method_id"] else None,
        },
        actor=str(auth.principal_id),
        provider=provider_for(request.app).name,
    )
    write_audit(
        db,
        action="VOICE.SESSION_CREATED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="callback_case",
        entity_id=str(body.case_id),
        after={
            "voice_session_id": str(attempt_id),
            "attempt_ref": attempt_ref,
            "case_ref": c["case_ref"],
            "provider": provider_for(request.app).name,
            "identity_verification": "NOT_PERFORMED",
            "compliance_outcome": "NOT_EVALUATED",
            "recording": "DISABLED",
        },
    )
    out = _issue(request, db, auth, attempt_id, body.case_id, c["case_ref"], attempt_ref, resumed=False)
    db.commit()
    return out


def _owned(db: Session, request: Request, auth: AuthContext, attempt_id: uuid.UUID) -> dict[str, Any]:
    st = store.state_of(db, attempt_id)
    if st is None or st["market_code"] not in auth.markets or st["created_by"] != str(auth.principal_id):
        raise not_found(
            db,
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="voice_session",
            entity_id=str(attempt_id),
            reason="missing, out of scope or not yours",
        )
    return st


@router.post(
    "/voice/sessions/{session_id}/resume",
    response_model=VoiceSessionOut,
    operation_id="voice_session_resume",
    responses=_ERR,
)
@csrf_protected
def resume_session(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("voice.session.start")),
) -> VoiceSessionOut:
    _write_guard(request, auth)
    store.sweep(db, live=set(registry(request.app).live))
    st = _owned(db, request, auth, session_id)
    resumable = st["session_state"] == "INTERRUPTED" or (st["session_id"] is None and st["status"] == "INITIATED")
    if not resumable or session_id in registry(request.app).live:
        raise AppError(
            409, "SESSION_NOT_RESUMABLE", f"This session cannot be resumed ({st['session_state'] or st['status']})"
        )
    out = _issue(request, db, auth, session_id, st["callback_case_id"], st["case_ref"], st["attempt_ref"], resumed=True)
    db.commit()
    return out


@router.post(
    "/voice/sessions/{session_id}/stop",
    response_model=VoiceSessionStatus,
    operation_id="voice_session_stop",
    responses=_ERR,
)
@csrf_protected
def stop_session(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("voice.session.start")),
) -> VoiceSessionStatus:
    _write_guard(request, auth)
    st = _owned(db, request, auth, session_id)
    already_final = st["session_state"] in store.FINAL_STATES or st["status"] in ("ENDED", "FAILED")
    if already_final:  # repeated Stop: nothing to do, nothing appended
        return _status(db, auth, session_id, events=True)
    if not registry(request.app).signal_stop(session_id):  # a live connection finalises itself on its way out
        store.append_event(
            db, session_id, "STOP_REQUESTED", source="SERVER", actor=str(auth.principal_id), details={"via": "rest"}
        )
        store.finalize(db, session_id, actor=str(auth.principal_id), reason="STOPPED_BY_USER")
        db.commit()
    return _status(db, auth, session_id, events=True)


def _status(db: Session, auth: AuthContext, attempt_id: uuid.UUID, *, events: bool) -> VoiceSessionStatus:
    st = store.state_of(db, attempt_id)
    assert st is not None
    rows = (
        db.execute(
            text(
                "SELECT seq, event_type, source, occurred_at, client_seq, out_of_order, details FROM session_event "
                "WHERE contact_attempt_id = :a ORDER BY seq"
            ),
            {"a": attempt_id},
        )
        .mappings()
        .all()
    )
    reason = next(
        (
            dict(r["details"]).get("reason")
            for r in reversed(rows)
            if r["event_type"] in ("ENDED", "FAILED", "ABANDONED")
        ),
        None,
    )
    status = st["session_state"] or ("PENDING_CONNECTION" if st["status"] == "INITIATED" else "NOT_CONNECTED")
    mine = st["created_by"] == str(auth.principal_id)
    names = {
        p.id: p.display_name
        for p in db.execute(
            text("SELECT id, display_name FROM principal WHERE CAST(id AS text) = :i"), {"i": st["created_by"]}
        )
    }
    return VoiceSessionStatus(
        session_id=attempt_id,
        attempt_ref=st["attempt_ref"],
        session_ref=st["session_ref"],
        case_id=st["callback_case_id"],
        case_ref=st["case_ref"],
        status=status,
        started_at=st["started_at"],
        ended_at=st["ended_at"],
        end_reason=reason,
        responses=sum(r["event_type"] == "PROVIDER_RESPONSE_STARTED" for r in rows),
        interruptions=sum(r["event_type"] == "BARGE_IN" for r in rows),
        events_total=len(rows),
        started_by=next(iter(names.values()), st["created_by"]),
        yours=mine,
        can_resume=mine and (status == "INTERRUPTED" or status == "PENDING_CONNECTION"),
        events=[VoiceSessionEvent(**{**dict(r), "details": dict(r["details"])}) for r in rows] if events else [],
    )


@router.get(
    "/voice/sessions/{session_id}", response_model=VoiceSessionStatus, operation_id="voice_session_get", responses=_ERR
)
def get_session(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("case.read")),
) -> VoiceSessionStatus:
    st = store.state_of(db, session_id)
    if st is None or st["market_code"] not in auth.markets:
        raise not_found(
            db,
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="voice_session",
            entity_id=str(session_id),
            reason="missing or out of scope",
        )
    return _status(db, auth, session_id, events=True)


@router.get("/voice/sessions", response_model=VoiceSessionList, operation_id="voice_sessions_list", responses=_ERR)
def list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("case.read")),
    case_id: uuid.UUID = Query(...),
) -> VoiceSessionList:
    _case(db, request, auth, case_id)  # audited 404 when missing or out of scope
    ids = (
        db.execute(
            text(
                "SELECT id FROM contact_attempt WHERE callback_case_id = :c AND transport = 'BROWSER' "
                "AND record_origin = 'CALL360_RUNTIME' ORDER BY sequence DESC LIMIT 50"
            ),
            {"c": case_id},
        )
        .scalars()
        .all()
    )
    return VoiceSessionList(items=[_status(db, auth, i, events=False) for i in ids])


# ---- WebSocket stream ------------------------------------------------------------------------------------------
class _WsChannel:
    def __init__(self, ws: WebSocket, app: Any, attempt_id: uuid.UUID, actor: str, stop: asyncio.Event) -> None:
        self.ws, self.app, self.attempt_id, self.actor, self.stop = ws, app, attempt_id, actor, stop
        self.lock = asyncio.Lock()
        self.muted = False

    def _persist(self, event_type: str, **kw: Any) -> dict[str, Any] | None:
        with self.app.state.session_factory() as db, db.begin():
            return store.append_event(db, self.attempt_id, event_type, actor=self.actor, **kw)

    async def receive(self) -> Inbound | None:
        recv = asyncio.ensure_future(self.ws.receive())
        stopper = asyncio.ensure_future(self.stop.wait())
        done, _ = await asyncio.wait({recv, stopper}, timeout=IDLE_TIMEOUT_S, return_when=asyncio.FIRST_COMPLETED)
        if recv not in done:
            recv.cancel()
            stopper.cancel()
            if stopper in done:
                return Inbound(event={"type": "session.stop", "reason": "STOPPED_BY_USER"})
            return None  # idle
        stopper.cancel()
        msg = recv.result()
        if msg.get("type") == "websocket.disconnect":
            return None
        if msg.get("bytes") is not None:
            data: bytes = msg["bytes"]
            if len(data) > MAX_FRAME_BYTES or len(data) % 2:
                return Inbound(event={"type": "ignored"})
            return Inbound(audio=data)
        try:
            event = json.loads(msg.get("text") or "{}")
        except ValueError:
            return Inbound(event={"type": "ignored"})
        if not isinstance(event, dict):
            return Inbound(event={"type": "ignored"})
        return await self._client_event(event)

    async def _client_event(self, event: dict[str, Any]) -> Inbound:
        kind = event.get("type")
        mapped = {
            "input.mute": "MIC_MUTED" if event.get("muted") else "MIC_UNMUTED",
            "session.stop": "STOP_REQUESTED",
            "client.notice": "CLIENT_NOTICE",
        }.get(str(kind))
        if mapped is None:
            return Inbound(event={"type": "ignored"})
        event_id = event.get("event_id")
        event_id = str(event_id)[:64] if isinstance(event_id, str) and event_id else None
        client_seq = event.get("seq") if isinstance(event.get("seq"), int) else None
        try:
            at = datetime.fromisoformat(str(event.get("at"))) if event.get("at") else None
        except ValueError:
            at = None
        details: dict[str, Any] = {}
        if kind == "session.stop":
            reason = event.get("reason")
            details["reason"] = reason if reason in CLIENT_STOP_REASONS else "STOPPED_BY_USER"
        if kind == "client.notice":
            details["notice"] = str(event.get("notice", ""))[:40]
        saved = await asyncio.to_thread(
            self._persist,
            mapped,
            source="CLIENT",
            details=details,
            client_event_id=event_id,
            client_seq=client_seq,
            client_occurred_at=at,
        )
        if saved is None:
            return Inbound(event={"type": "ignored", "duplicate": True})  # a retried event never acts twice
        if kind == "input.mute" and saved["out_of_order"]:
            return Inbound(event={"type": "ignored", "stale": True})  # a late mute never overrides a newer one
        if kind == "session.stop":
            return Inbound(event={"type": "session.stop", "reason": details["reason"]})
        if kind == "input.mute":
            self.muted = bool(event.get("muted"))
        return Inbound(event=event if kind != "client.notice" else {"type": "ignored"})

    async def send_audio(self, response: int, pcm: bytes) -> None:
        async with self.lock:
            await self.ws.send_bytes(struct.pack("<I", response) + pcm)

    async def send_event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        persisted = PERSISTED_PROVIDER_EVENTS.get(str(kind))
        if kind == "response.done" and event.get("completed"):
            persisted = "PROVIDER_RESPONSE_COMPLETED"
        if kind == "input.speech_stopped" and not event.get("muted"):
            persisted = "USER_TURN_ENDED"
        if persisted:
            await asyncio.to_thread(
                self._persist, persisted, details={"response": event.get("response")} if "response" in event else {}
            )
        async with self.lock:
            await self.ws.send_text(json.dumps(event))


def _audit_ws(
    app: Any,
    action: str,
    outcome: str,
    case_id: uuid.UUID | None,
    actor: Actor | None,
    origin: str | None,
    attempt_id: uuid.UUID | None,
    **after: Any,
) -> None:
    with app.state.session_factory() as db, db.begin():
        write_audit(
            db,
            action=action,
            outcome=outcome,
            actor=actor,
            meta=RequestMeta(),
            entity_type="callback_case" if case_id else "voice_session",
            entity_id=str(case_id) if case_id else None,
            after={"voice_session_id": str(attempt_id) if attempt_id else None, "origin": origin, **after},
        )


@router.websocket("/voice/sessions/{session_id}/stream")
async def voice_stream(websocket: WebSocket, session_id: uuid.UUID) -> None:
    app = websocket.app
    origin = websocket.headers.get("origin")
    if origin not in set(app.state.settings.allowed_origins):
        await websocket.close(code=4403)  # cross-site WebSocket hijacking defence
        return
    try:
        with app.state.session_factory() as db:
            auth = resolve_auth(app, websocket.cookies, db)
    except AppError:
        await websocket.close(code=4401)
        return
    if "voice.session.start" not in auth.permissions or auth.password_change_required:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    try:
        first = await asyncio.wait_for(websocket.receive_json(), timeout=AUTH_TIMEOUT_S)
    except (TimeoutError, ValueError, WebSocketDisconnect, RuntimeError):
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=4401)
        return
    credential = first.get("credential") if isinstance(first, dict) and first.get("type") == "session.auth" else None
    reg = registry(app)
    session = reg.claim(session_id, auth.principal_id, str(credential or ""))
    if session is None:
        _audit_ws(app, "VOICE.SESSION_REJECTED", "DENIED", None, auth.actor, origin, None, reason="credential")
        await websocket.send_text(json.dumps({"type": "error", "code": "SESSION_CREDENTIAL_INVALID"}))
        await websocket.close(code=4401)
        return
    provider = provider_for(app)
    actor = str(auth.principal_id)

    def _connect() -> str:
        with app.state.session_factory() as db, db.begin():
            return store.connect(db, session.attempt_id, actor=actor, provider=provider.name)

    try:
        mode = await asyncio.to_thread(_connect)
    except store.TransitionError as exc:
        reg.release(session.attempt_id)
        await websocket.send_text(json.dumps({"type": "error", "code": "SESSION_NOT_CONNECTABLE", "detail": str(exc)}))
        await websocket.close(code=4409)
        return
    _audit_ws(
        app, "VOICE.SESSION_CONNECTED", "SUCCEEDED", session.case_id, auth.actor, origin, session.attempt_id, mode=mode
    )
    assert session.stop is not None
    stats = SessionStats()
    channel = _WsChannel(websocket, app, session.attempt_id, actor, session.stop)
    started = datetime.now(UTC)
    try:
        await channel.send_event(
            {
                "type": "session.ready",
                "session_id": str(session.attempt_id),
                "case_ref": session.case_ref,
                "provider": provider.name,
                "sample_rate": SAMPLE_RATE,
                "frame_ms": FRAME_MS,
                "resumed": mode == "RESUMED",
                "max_duration_s": MAX_DURATION_S,
                "identity_verification": "NOT_PERFORMED",
                "compliance_outcome": "NOT_EVALUATED",
                "recording": "DISABLED",
            }
        )
        try:
            await asyncio.wait_for(provider.run(channel, stats), timeout=MAX_DURATION_S)
        except TimeoutError:
            stats.end_reason = "MAX_DURATION"
        if stats.end_reason == "DISCONNECTED" and websocket.client_state.name == "CONNECTED":
            stats.end_reason = "IDLE_TIMEOUT"
    except (WebSocketDisconnect, RuntimeError):
        stats.end_reason = "DISCONNECTED"
    finally:
        reg.release(session.attempt_id)
        summary = {
            "responses": stats.responses,
            "completed_responses": stats.completed_responses,
            "barge_ins": stats.barge_ins,
            "user_turns": stats.user_turns,
            "frames_in": stats.frames_in,
            "duration_s": round((datetime.now(UTC) - started).total_seconds(), 1),
        }

        def _close() -> str:
            with app.state.session_factory() as db, db.begin():
                if stats.end_reason == "DISCONNECTED":  # network loss, refresh or tab closed: resumable for 30 s
                    store.interrupt(db, session.attempt_id, actor=actor, reason="CONNECTION_LOST")
                    return "INTERRUPTED"
                return str(
                    store.finalize(db, session.attempt_id, actor=actor, reason=stats.end_reason, stats=summary)["state"]
                )

        final = await asyncio.to_thread(_close)
        with contextlib.suppress(Exception):
            await websocket.send_text(json.dumps({"type": "session.ended", "reason": stats.end_reason, "state": final}))
            await websocket.close(code=1000)
        _audit_ws(
            app,
            "VOICE.SESSION_ENDED" if final != "INTERRUPTED" else "VOICE.SESSION_INTERRUPTED",
            "SUCCEEDED",
            session.case_id,
            auth.actor,
            origin,
            session.attempt_id,
            reason=stats.end_reason,
            state=final,
            **summary,
            identity_verification="NOT_PERFORMED",
            compliance_outcome="NOT_EVALUATED",
        )
        log.info("voice session %s: %s (%s)", session.attempt_id, final, stats.end_reason)
