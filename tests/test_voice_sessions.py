"""S1-B — voice-session persistence: lifecycle on the existing contact_attempt / conversation_session rows with fixed
pins, the ordered and idempotent session_event ledger, case-timeline entries, Start → Stop, repeated Stop, network
loss with resume, abandonment, never-connected credentials, backend restart recovery, duplicate and out-of-order
client events, idle timeout, live REST stop, ownership and scope, and no content in the ledger."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.api import voice as voice_api
from app.voice import store
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_voice import ORIGIN, SILENCE, _callable_case, tone

pytestmark = pytest.mark.usefixtures("seeded")


def start(client: TestClient, case_id: uuid.UUID) -> dict[str, Any]:
    r = client.post("/api/v1/voice/sessions", json={"case_id": str(case_id)}, headers=csrf_header(client))
    assert r.status_code == 201, r.text
    return r.json()


def until(ws: Any, kind: str, limit: int = 3000) -> list[dict[str, Any]]:
    seen = []
    for _ in range(limit):
        msg = ws.receive()
        if msg.get("text"):
            seen.append(json.loads(msg["text"]))
            if seen[-1]["type"] == kind:
                return seen
        if msg.get("type") == "websocket.close":
            break
    raise AssertionError(f"{kind} not received: {[e['type'] for e in seen]}")


def status(client: TestClient, sid: str) -> dict[str, Any]:
    r = client.get(f"/api/v1/voice/sessions/{sid}")
    assert r.status_code == 200, r.text
    return r.json()


def test_start_stop_is_persisted_with_pins_ordered_events_and_case_timeline(
    client: TestClient, user: Account, conn: Connection
) -> None:
    login(client, user)
    case_id, case_ref = _callable_case(conn)
    s = start(client, case_id)
    assert status(client, s["session_id"])["status"] == "PENDING_CONNECTION"
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        for _ in range(8):
            ws.send_bytes(tone())
        until(ws, "playback.clear")
        for _ in range(35):
            ws.send_bytes(SILENCE)
        until(ws, "response.started")
        assert status(client, s["session_id"])["status"] == "CREATED"  # live, persisted
        ws.send_json({"type": "session.stop", "event_id": "stop-1", "seq": 1})
        assert until(ws, "session.ended")[-1]["state"] == "FINALIZED"
    st = status(client, s["session_id"])
    assert (st["status"], st["end_reason"], st["interruptions"], st["identity_verification"]) == (
        "FINALIZED",
        "STOPPED_BY_USER",
        1,
        "NOT_PERFORMED",
    )
    assert st["responses"] >= 2 and st["session_ref"] == f"SS-{st['attempt_ref'].removeprefix('AT-')}"
    kinds = [e["event_type"] for e in st["events"]]
    assert kinds[:2] == ["SESSION_REQUESTED", "CONNECTED"] and kinds[-2:] == ["STOP_REQUESTED", "ENDED"]
    assert "BARGE_IN" in kinds and "USER_TURN_ENDED" in kinds
    assert [e["seq"] for e in st["events"]] == list(range(1, len(kinds) + 1))  # gap-free server order
    allowed = {
        "provider",
        "transport",
        "model",
        "identity_verification",
        "compliance_outcome",
        "recording",
        "response",
        "reason",
        "final_state",
        "responses",
        "completed_responses",
        "barge_ins",
        "user_turns",
        "frames_in",
        "duration_s",
        "via",
        "notice",
    }
    assert all(set(e["details"]) <= allowed for e in st["events"])  # metadata only: no audio or speech
    row = conn.execute(
        text(
            f"SELECT a.status, a.transport, a.record_origin, s.state, s.ended_at, s.media_status, s.transcript_status, "
            f"s.script_manifest_sha256 = v.manifest_sha256 AS pinned FROM {SCHEMA}.contact_attempt a "
            f"JOIN {SCHEMA}.conversation_session s ON s.contact_attempt_id = a.id "
            f"JOIN {SCHEMA}.script_version v ON v.id = s.script_version_id WHERE a.id = :a"
        ),
        {"a": s["session_id"]},
    ).one()
    assert (row.status, row.transport, row.record_origin, row.state, row.media_status, row.transcript_status) == (
        "ENDED",
        "BROWSER",
        "CALL360_RUNTIME",
        "FINALIZED",
        "NOT_REQUIRED",
        "UNAVAILABLE",
    )
    assert row.ended_at is not None and row.pinned
    timeline = (
        conn.execute(
            text(f"SELECT event_type FROM {SCHEMA}.case_event WHERE related_entity_id = :a ORDER BY occurred_at"),
            {"a": s["session_id"]},
        )
        .scalars()
        .all()
    )
    assert timeline == ["VOICE_SESSION_STARTED", "VOICE_SESSION_ENDED"]
    case = client.get(f"/api/v1/cases/{case_id}").json()
    assert case["verified_at"] is None and case["case_ref"] == case_ref  # nothing verified
    attempts = client.get(f"/api/v1/cases/{case_id}/attempts").json()["items"]
    browser = next(a for a in attempts if a["id"] == s["session_id"])
    assert browser["transport"] == "BROWSER" and browser["session"] is not None
    listed = client.get("/api/v1/voice/sessions", params={"case_id": str(case_id)}).json()["items"]
    assert listed[0]["session_id"] == s["session_id"] and listed[0]["events"] == []

    # Repeated Stop: idempotent, no second ENDED.
    again = client.post(f"/api/v1/voice/sessions/{s['session_id']}/stop", headers=csrf_header(client))
    assert again.status_code == 200 and again.json()["status"] == "FINALIZED"
    assert [e["event_type"] for e in again.json()["events"]].count("ENDED") == 1


def test_network_loss_resume_then_abandonment(client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:  # dropped without a stop
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
    st = status(client, s["session_id"])
    assert st["status"] == "INTERRUPTED" and st["can_resume"]
    r = client.post(f"/api/v1/voice/sessions/{s['session_id']}/resume", headers=csrf_header(client))
    assert r.status_code == 200 and r.json()["resumed"] and r.json()["credential"] != s["credential"]
    with client.websocket_connect(r.json()["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": r.json()["credential"]})
        assert until(ws, "session.ready")[-1]["resumed"] is True
        until(ws, "response.started")
    kinds = [e["event_type"] for e in status(client, s["session_id"])["events"]]
    assert kinds.count("CONNECTED") == 1 and "RESUMED" in kinds and kinds.count("DISCONNECTED") == 2
    with Session(conn.engine) as db, db.begin():  # 31 s later nobody came back
        done = store.sweep(db, live=set(), now=datetime.now(UTC) + timedelta(seconds=31))
    assert any(d.startswith(s["session_id"]) and d.endswith("ABANDONED") for d in done)
    st = status(client, s["session_id"])
    assert (st["status"], st["end_reason"], st["can_resume"]) == ("ABORTED", "ABANDONED", False)
    late = client.post(f"/api/v1/voice/sessions/{s['session_id']}/resume", headers=csrf_header(client))
    assert late.status_code == 409 and late.json()["code"] == "SESSION_NOT_RESUMABLE"


def test_never_connected_and_backend_restart_are_finalised(client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    pending = start(client, case_id)  # credential issued, never used
    live = start(client, case_id)
    with Session(conn.engine) as db, db.begin():  # connected, then the process "dies" (nothing live in the registry)
        store.connect(db, uuid.UUID(live["session_id"]), actor="test", provider="MOCK")
    with Session(conn.engine) as db, db.begin():
        assert store.sweep(db, live=set(), now=datetime.now(UTC) + timedelta(seconds=91))
    assert status(client, pending["session_id"])["status"] == "NOT_CONNECTED"
    orphan = status(client, live["session_id"])
    assert orphan["status"] == "ABORTED" and orphan["end_reason"] in ("ORPHANED", "ABANDONED")
    again = start(client, case_id)
    with Session(conn.engine) as db, db.begin():
        store.connect(db, uuid.UUID(again["session_id"]), actor="test", provider="MOCK")
    voice_api.run_sweep(client.app, startup=True)  # what the lifespan does after a restart
    st = status(client, again["session_id"])
    assert (st["status"], st["end_reason"]) == ("ABORTED", "BACKEND_RESTART")
    orphans = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.contact_attempt a LEFT JOIN {SCHEMA}.conversation_session s "
            "ON s.contact_attempt_id = a.id WHERE a.transport = 'BROWSER' AND (a.status = 'INITIATED' "
            "OR s.state IN ('CREATED', 'INTERRUPTED', 'FINALIZING'))"
        )
    ).scalar_one()
    assert orphans == 0  # no orphaned active session remains


def test_duplicate_and_out_of_order_client_events(client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        mute = {
            "type": "input.mute",
            "muted": True,
            "event_id": "evt-mute-1",
            "seq": 5,
            "at": datetime.now(UTC).isoformat(),
        }
        ws.send_json(mute)
        ws.send_json(mute)  # retried on reconnect: must not act or be stored twice
        ws.send_json({"type": "input.mute", "muted": False, "event_id": "evt-unmute-0", "seq": 3})  # arrives late
        ws.send_json({"type": "client.notice", "notice": "visibility_hidden", "event_id": "evt-n-1", "seq": 6})
        ws.send_json({"type": "session.stop", "event_id": "evt-stop", "seq": 7})
        until(ws, "session.ended")
    events = status(client, s["session_id"])["events"]
    client_events = [e for e in events if e["source"] == "CLIENT"]
    assert [e["event_type"] for e in client_events] == ["MIC_MUTED", "MIC_UNMUTED", "CLIENT_NOTICE", "STOP_REQUESTED"]
    assert [e["out_of_order"] for e in client_events] == [False, True, False, False]
    assert client_events[0]["client_seq"] == 5


def test_idle_timeout_and_live_rest_stop(
    client: TestClient, user: Account, conn: Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    monkeypatch.setattr(voice_api, "IDLE_TIMEOUT_S", 0.6)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert until(ws, "session.ended")[-1]["reason"] == "IDLE_TIMEOUT"
    st = status(client, s["session_id"])
    assert (st["status"], st["end_reason"]) == ("ABORTED", "IDLE_TIMEOUT")
    monkeypatch.setattr(voice_api, "IDLE_TIMEOUT_S", 20)
    s2 = start(client, case_id)
    with client.websocket_connect(s2["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s2["credential"]})
        until(ws, "response.started")
        r = client.post(f"/api/v1/voice/sessions/{s2['session_id']}/stop", headers=csrf_header(client))
        assert r.status_code == 200
        assert until(ws, "session.ended")[-1]["state"] == "FINALIZED"  # the live connection was ended too
    assert status(client, s2["session_id"])["status"] == "FINALIZED"


def test_ownership_scope_and_permissions(
    client: TestClient, other_client: TestClient, user: Account, db: Session, conn: Connection
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    login(other_client, make_account(db, "LOCAL_USER_SG", prefix="peer"))
    peer = other_client.get(f"/api/v1/voice/sessions/{s['session_id']}")
    assert peer.status_code == 200 and peer.json()["yours"] is False and peer.json()["can_resume"] is False
    for path in (f"/api/v1/voice/sessions/{s['session_id']}/stop", f"/api/v1/voice/sessions/{s['session_id']}/resume"):
        assert other_client.post(path, headers=csrf_header(other_client)).status_code == 404  # not theirs
    other_client.cookies.clear()
    login(other_client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))
    assert other_client.get(f"/api/v1/voice/sessions/{s['session_id']}").status_code == 404
    assert other_client.get("/api/v1/voice/sessions", params={"case_id": str(case_id)}).status_code == 404
    my = conn.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE market_code = 'MY' LIMIT 1")).scalar_one()
    assert client.get("/api/v1/voice/sessions", params={"case_id": str(my)}).status_code == 404
    assert client.post(f"/api/v1/voice/sessions/{s['session_id']}/stop").status_code == 403  # CSRF
    blob = json.dumps(status(client, s["session_id"]))
    assert s["credential"] not in blob and "MY-" not in blob
