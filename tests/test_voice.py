"""S1-A — local browser voice POC with the mock provider: barge-in stops speech within a frame and clears queued
audio (no stale frames afterwards), repeated interruptions, user stop; session creation only for callable Singapore
cases (holds never bypassed, Malaysian cases are audited 404s), single-use case-bound credentials, WebSocket Origin
and identity checks, safe termination, audit without content, and no identity or compliance outcome."""

from __future__ import annotations

import asyncio
import json
import math
import struct
import uuid
from array import array
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.voice.mock import FIXED_MESSAGE, MockVoiceProvider, Vad, rms_dbfs
from app.voice.provider import FRAME_BYTES, FRAME_SAMPLES, Inbound, SessionStats
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")
ORIGIN = {"origin": "http://testserver"}  # in the test ALLOWED_ORIGINS


def tone(amplitude: int = 9000) -> bytes:
    a = array("h", (int(amplitude * math.sin(2 * math.pi * 440 * i / 16000)) for i in range(FRAME_SAMPLES)))
    return a.tobytes()


SILENCE = b"\x00" * FRAME_BYTES


class FakeChannel:
    def __init__(self, script: list[Inbound | float]) -> None:
        self.script = script
        self.audio: list[int] = []
        self.events: list[dict[str, Any]] = []
        self.timeline: list[tuple[str, Any]] = []

    async def receive(self) -> Inbound | None:
        while self.script:
            item = self.script.pop(0)
            if isinstance(item, float):
                await asyncio.sleep(item)
                continue
            await asyncio.sleep(0.02)  # real-time input pacing
            return item
        return None

    async def send_audio(self, response: int, pcm: bytes) -> None:
        self.audio.append(response)
        self.timeline.append(("audio", response))

    async def send_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self.timeline.append(("event", event))


def test_vad_and_levels() -> None:
    assert rms_dbfs(SILENCE) == -120.0 and -20 < rms_dbfs(tone()) < -10
    vad = Vad()
    assert [vad.update(SILENCE, agent_speaking=False) for _ in range(10)] == [None] * 10
    changes = [vad.update(tone(), agent_speaking=False) for _ in range(3)]
    assert changes[-1] == "speech_started"
    assert "speech_stopped" in [vad.update(SILENCE, agent_speaking=False) for _ in range(31)]
    quiet_echo = Vad()
    assert all(quiet_echo.update(tone(300), agent_speaking=True) is None for _ in range(20))  # weak echo ignored


def test_mock_barge_in_clears_playback_and_responds_again() -> None:
    speech = [Inbound(audio=tone()) for _ in range(10)]
    pause = [Inbound(audio=SILENCE) for _ in range(35)]
    script: list[Inbound | float] = [
        *[Inbound(audio=SILENCE)] * 15,
        *speech,
        *pause,
        *speech,
        *pause[:5],
        Inbound(event={"type": "session.stop"}),
    ]
    ch, stats = FakeChannel(script), SessionStats()
    asyncio.run(MockVoiceProvider().run(ch, stats))
    kinds = [e["type"] for e in ch.events]
    assert kinds[0] == "response.started" and stats.end_reason == "STOPPED_BY_USER"
    clears = [e for e in ch.events if e["type"] == "playback.clear"]
    assert len(clears) == 2 and stats.barge_ins == 2  # each interruption stops the mock
    assert [e["response"] for e in ch.events if e["type"] == "response.started"] == [1, 2]
    assert [e["completed"] for e in ch.events if e["type"] == "response.done"] == [False, False]
    for i, (kind, item) in enumerate(ch.timeline):  # nothing of an interrupted response is sent after its clear
        if kind == "event" and item["type"] == "playback.clear":
            assert ("audio", item["response"]) not in ch.timeline[i:]
    assert stats.user_turns == 1


def test_mock_speaks_only_the_fixed_message() -> None:
    provider = MockVoiceProvider()
    seconds = len(provider.message) / 2 / 16000
    assert 10 < seconds < 14 and len(FIXED_MESSAGE) == 4
    assert FIXED_MESSAGE[0].startswith("Hello. This is a Call360 synthetic audio test.")
    assert FIXED_MESSAGE[-1] == "This test does not verify an insurance transaction."


def _callable_case(conn: Connection) -> tuple[uuid.UUID, str]:
    r = conn.execute(
        text(
            f"SELECT c.id, c.case_ref FROM {SCHEMA}.callback_case c WHERE c.market_code = 'SG' "
            "AND c.state IN ('READY', 'AWAITING_CALLBACK') AND NOT EXISTS (SELECT 1 FROM "
            f"{SCHEMA}.case_hold h WHERE h.callback_case_id = c.id AND h.is_blocking AND h.released_at IS NULL) "
            f"AND EXISTS (SELECT 1 FROM {SCHEMA}.case_contact_selection s WHERE s.callback_case_id = c.id "
            f"AND s.eligible AND NOT EXISTS (SELECT 1 FROM {SCHEMA}.case_contact_selection x "
            "WHERE x.supersedes_id = s.id)) "
            f"AND EXISTS (SELECT 1 FROM {SCHEMA}.script_assignment a JOIN {SCHEMA}.script_version v "
            "ON v.id = a.script_version_id WHERE a.callback_case_id = c.id AND v.status = 'PUBLISHED') "
            "ORDER BY c.case_ref LIMIT 1"
        )
    ).one()
    return r.id, r.case_ref


def _start(client: TestClient, case_id: uuid.UUID) -> dict[str, Any]:
    r = client.post("/api/v1/voice/sessions", json={"case_id": str(case_id)}, headers=csrf_header(client))
    assert r.status_code == 201, r.text
    return r.json()


def test_session_creation_rules(client: TestClient, user: Account, db: Session, conn: Connection) -> None:
    login(client, user)
    case_id, case_ref = _callable_case(conn)
    s = _start(client, case_id)
    assert (s["case_ref"], s["provider"], s["identity_verification"], s["compliance_outcome"]) == (
        case_ref,
        "MOCK",
        "NOT_PERFORMED",
        "NOT_EVALUATED",
    )
    assert s["recording"] == "DISABLED" and s["transcript"] == "NOT_AVAILABLE" and s["script"]["status"] == "PUBLISHED"
    assert len(s["credential"]) >= 40 and s["stream_path"].endswith(f"{s['session_id']}/stream")
    assert "•" in (s["contact"]["masked_contact"] or "")  # masked contact only; no raw value
    held = conn.execute(
        text(
            f"SELECT callback_case_id FROM {SCHEMA}.case_hold h JOIN {SCHEMA}.callback_case c ON c.id = "
            "h.callback_case_id WHERE h.is_blocking AND h.released_at IS NULL AND c.market_code = 'SG' LIMIT 1"
        )
    ).scalar_one()
    r = client.post("/api/v1/voice/sessions", json={"case_id": str(held)}, headers=csrf_header(client))
    assert r.status_code == 409 and r.json()["code"] == "CASE_NOT_CALLABLE"  # holds are never bypassed
    my = conn.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE market_code = 'MY' LIMIT 1")).scalar_one()
    assert (
        client.post("/api/v1/voice/sessions", json={"case_id": str(my)}, headers=csrf_header(client)).status_code == 404
    )
    assert client.post("/api/v1/voice/sessions", json={"case_id": str(case_id)}).status_code == 403  # CSRF
    pre = client.get("/api/v1/voice/preflight").json()
    assert pre["status"] == "AVAILABLE" and pre["provider"] == "MOCK" and pre["callable_cases"]
    assert {c["code"]: c["status"] for c in pre["capabilities"]}["RECORDING"] == "DISABLED"
    client.cookies.clear()
    norole = make_account(db, "LOCAL_USER_SG", prefix="novoice")
    db.execute(text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": norole.principal_id})
    db.commit()
    login(client, norole)
    assert (
        client.post("/api/v1/voice/sessions", json={"case_id": str(case_id)}, headers=csrf_header(client)).status_code
        == 403
    )


def _frames(ws: Any, until: str, limit: int = 2000) -> tuple[list[dict[str, Any]], list[int]]:
    events, audio = [], []
    for _ in range(limit):
        msg = ws.receive()
        if msg.get("bytes"):
            audio.append(struct.unpack("<I", msg["bytes"][:4])[0])
            continue
        if msg.get("text"):
            events.append(json.loads(msg["text"]))
            if events[-1]["type"] == until:
                return events, audio
        if msg.get("type") == "websocket.close":
            break
    return events, audio


def test_websocket_full_duplex_barge_in_and_safe_stop(client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = _start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        events, _ = _frames(ws, "response.started")
        assert events[0]["type"] == "session.ready" and events[0]["identity_verification"] == "NOT_PERFORMED"
        _, audio = _frames(ws, "never", limit=30)
        assert audio and set(audio) == {1}  # the mock is speaking response 1
        for _ in range(8):
            ws.send_bytes(tone())
        events, _ = _frames(ws, "input.speech_started")
        assert {"type": "playback.clear", "response": 1, "reason": "barge_in"} in events
        for _ in range(35):
            ws.send_bytes(SILENCE)
        events, audio = _frames(ws, "response.started")
        assert events[-1]["response"] == 2
        ws.send_json({"type": "session.stop"})
        events, audio = _frames(ws, "session.ended")
        assert events[-1]["reason"] == "STOPPED_BY_USER" and 1 not in audio  # no stale playback afterwards
    ended = conn.execute(
        text(f"SELECT after FROM {SCHEMA}.audit_event WHERE action = 'VOICE.SESSION_ENDED' ORDER BY seq DESC LIMIT 1")
    ).scalar_one()
    assert ended["reason"] == "STOPPED_BY_USER" and ended["barge_ins"] >= 1
    assert ended["identity_verification"] == "NOT_PERFORMED" and ended["compliance_outcome"] == "NOT_EVALUATED"
    state = conn.execute(
        text(f"SELECT state, verified_at FROM {SCHEMA}.callback_case WHERE id = :i"), {"i": case_id}
    ).one()
    assert state.verified_at is None and state.state in ("READY", "AWAITING_CALLBACK")  # nothing verified


def test_websocket_guards(
    client: TestClient, other_client: TestClient, user: Account, db: Session, conn: Connection
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = _start(client, case_id)
    with pytest.raises(WebSocketDisconnect) as bad_origin:
        with client.websocket_connect(s["stream_path"], headers={"origin": "https://evil.example"}) as ws:
            ws.receive()
    assert bad_origin.value.code == 4403
    with pytest.raises(WebSocketDisconnect) as anon:
        with other_client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
            ws.receive()
    assert anon.value.code == 4401
    login(other_client, make_account(db, "LOCAL_USER_SG", prefix="other"))  # a different signed-in user
    with other_client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert json.loads(ws.receive()["text"])["code"] == "SESSION_CREDENTIAL_INVALID"
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:  # owner, wrong credential
        ws.send_json({"type": "session.auth", "credential": "x" * 43})
        assert json.loads(ws.receive()["text"])["code"] == "SESSION_CREDENTIAL_INVALID"
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:  # correct: used once
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert json.loads(ws.receive()["text"])["type"] == "session.ready"
        ws.send_json({"type": "session.stop"})
        _frames(ws, "session.ended")
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:  # reuse refused
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert json.loads(ws.receive()["text"])["code"] == "SESSION_CREDENTIAL_INVALID"
    rejected = conn.execute(
        text(f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'VOICE.SESSION_REJECTED'")
    ).scalar_one()
    assert rejected >= 3
    blob = json.dumps(
        conn.execute(text(f"SELECT json_agg(after) FROM {SCHEMA}.audit_event WHERE action LIKE 'VOICE.%'")).scalar_one()
    )
    assert s["credential"] not in blob
