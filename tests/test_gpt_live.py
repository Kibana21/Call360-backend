"""S1-E.2 GPT-Live adapter, offline: every test talks to a mocked GPT-Live protocol server on 127.0.0.1
(``app.voice.gpt_live_mock``) — never to the provider. No real API key is needed (a placeholder is used to prove the
key travels only to the configured endpoint) and no paid call can be made: the connector refuses any host other than
the official endpoint and, in tests, loopback; the default connector is replaced by one that fails the test if used.

Covers: session lifecycle (session.start → started → close → closed), full-duplex audio relay at 16 kHz, client
delegation answered deterministically, per-turn and Playground instructions, barge-in, provider errors and invalid
events, provider disconnect, provider expiry, browser disconnect, server-enforced maximum duration, emergency stop
during an active session, connect failure, usage reconciliation only from session.closed, retained reservations for
unconfirmed termination (concurrency then blocked), sideband close and manual resolution, crash recovery, the paid
gates (switch, single-use smoke-test authorisation by another user, mismatch, duplicate use, revocation, PAID budget),
retention purge, human speech assessment and operational isolation."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.db.session import make_session_factory
from app.domain.protection import DataProtection
from app.domain.seed import seed
from app.voice import gpt_live, lab, lab_eval
from app.voice.gpt_live_mock import MockGptLiveServer
from tests.domain_support import SCHEMA
from tests.support import ORIGIN, Account, csrf_header, login, make_account, reset_test_schema
from tests.test_voice_lab import LOUD, OPERATIONAL, QUIET, counts, ok, post, refused, until

pytestmark = pytest.mark.usefixtures("seeded")
WS = {"origin": ORIGIN}
FAKE_KEY = "test-placeholder-not-a-key-0000"


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture(scope="module")
def mock_server() -> Iterator[MockGptLiveServer]:
    loop = asyncio.new_event_loop()
    srv = MockGptLiveServer()
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(srv.start())
        ready.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(10)
    yield srv
    asyncio.run_coroutine_threadsafe(srv.stop(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)


def _forbidden_connect(*_: Any, **__: Any) -> Any:
    raise AssertionError("the default network connector must never be used in tests")


@pytest.fixture
def app(settings: Settings, engine: Engine, mock_server: MockGptLiveServer, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    from app.main import create_app

    monkeypatch.setattr(gpt_live, "default_connect", _forbidden_connect)
    st = settings.model_copy(
        update={
            "transcription_worker": False,
            "voice_lab_gpt_live_mock_url": mock_server.url,
            "voice_lab_gpt_live_mode": "LIVE",
            "voice_lab_openai_api_key": __import__("pydantic").SecretStr(FAKE_KEY),
            "voice_lab_gpt_live_url": mock_server.url,  # loopback: accepted only because APP_ENV=test
            "voice_lab_close_timeout_s": 2.0,
        }
    )
    a = create_app(st)
    a.state.voicelab_inline = True

    import websockets

    async def loopback_only(url: str, headers: dict[str, str]) -> Any:
        assert url.startswith("ws://127.0.0.1:"), url
        return await websockets.connect(url, additional_headers=headers, open_timeout=5)

    a.state.gpt_live_connect = loopback_only
    return a


@pytest.fixture
def admin_c(app: Any, db: Session) -> Iterator[TestClient]:
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        assert login(c, make_account(db, "LOCAL_ADMIN", prefix="gladm")).status_code == 200
        yield c


@pytest.fixture
def user_c(client: TestClient, user: Account) -> TestClient:
    assert login(client, user).status_code == 200
    return client


def gpt_prompt(
    c: TestClient,
    provider: str = "GPT_LIVE_MOCK",
    instructions: str = "",
    voice: str = "marin",
    turns: list[str] | None = None,
) -> str:
    body = {
        "name": f"GPT {uuid.uuid4().hex[:6]}",
        "system_prompt": f"You are a synthetic test voice. {instructions}",
        "turn_instructions": turns if turns is not None else ["Ask the caller to confirm they can hear you"],
        "provider": provider,
        "model": "gpt-live-1",
        "voice": voice,
    }
    return str(post(c, "/prompts", body, 201)["versions"][0]["id"])


def budgets(admin: TestClient, cls: str = "SIMULATED", **values: Any) -> None:
    cur = next(b for b in ok(admin.get("/api/v1/voice-lab/settings"))["budgets"] if b["spend_class"] == cls)
    keys = (
        "overall_usd",
        "daily_usd",
        "per_experiment_usd",
        "max_concurrent_sessions",
        "interactive_max_s",
        "idle_timeout_s",
    )
    r = admin.put(
        f"/api/v1/voice-lab/budgets/{cls}",
        headers=csrf_header(admin),
        json={
            **{k: values.get(k, cur[k]) for k in keys},
            "expected_row_version": cur["row_version"],
            "reason": "GPT-Live test budget",
        },
    )
    assert r.status_code == 200, r.text


def session(c: TestClient, sid: str) -> dict[str, Any]:
    return dict(ok(c.get(f"/api/v1/voice-lab/sessions/{sid}")))


def wait_ended(c: TestClient, sid: str, timeout: float = 20) -> dict[str, Any]:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        s = session(c, sid)
        if s["status"] in ("ENDED", "FAILED"):
            return s
        time.sleep(0.2)
    raise AssertionError("session did not end")


def kinds(s: dict[str, Any]) -> list[str]:
    return [e["event_type"] for e in s["events"]]


def talk(ws: Any, loud: int = 12, quiet: int = 40) -> None:
    for _ in range(loud):
        ws.send_bytes(LOUD)
    for _ in range(quiet):
        ws.send_bytes(QUIET)


def test_lifecycle_audio_delegation_instructions_and_barge_in(
    app: Any, user_c: TestClient, admin_c: TestClient, mock_server: MockGptLiveServer, db: Session
) -> None:
    budgets(
        admin_c,
        overall_usd=10,
        daily_usd=10,
        per_experiment_usd=1,
        max_concurrent_sessions=1,
        interactive_max_s=60,
        idle_timeout_s=15,
    )
    before = counts(db)
    pv = gpt_prompt(user_c)
    s = post(user_c, "/sessions", {"prompt_version_id": pv, "record": True}, 201)
    assert s["provider"] == "GPT_LIVE_MOCK" and s["spend_class"] == "SIMULATED"
    assert s["estimated_max_usd"] == "0.0500" and s["reservation_status"] == "HELD"  # 60 s × USD 0.05 / min
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert until(ws, "session.ready")[-1]["provider"] == "GPT_LIVE_MOCK"
        until(ws, "response.started")  # the provider's greeting audio is relayed
        audio = 0
        for _ in range(10):
            if ws.receive().get("bytes"):
                audio += 1
        assert audio >= 5
        for _ in range(12):  # the caller talks over the greeting: local barge-in clears browser playback
            ws.send_bytes(LOUD)
        until(ws, "playback.clear")
        for _ in range(40):
            ws.send_bytes(QUIET)
        until(ws, "input.speech_stopped")  # turn 1 → per-turn instruction, mock replies
        ws.send_json({"type": "lab.instruction", "text": "Keep the reply under ten words"})
        time.sleep(0.5)
        talk(ws)  # turn 2 → the mock delegates; the backend answers deterministically and the answer is spoken
        sess = max(mock_server.sessions.values(), key=lambda x: x.started)
        t0 = time.monotonic()
        while "session.commentary.append" not in sess.seen and time.monotonic() - t0 < 10:
            ws.receive()  # provider audio keeps flowing while the delegation completes
        assert "session.commentary.append" in sess.seen
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    out = wait_ended(user_c, s["id"])
    k = kinds(out)
    for e in (
        "PROVIDER_SESSION_STARTED",
        "FIRST_AUDIO",
        "BARGE_IN",
        "INSTRUCTION_APPENDED",
        "PLAYGROUND_INSTRUCTION",
        "DELEGATION_CREATED",
        "DELEGATION_ANSWERED",
        "TRANSCRIPT_DELTA",
        "CLOSE_SENT",
        "PROVIDER_SESSION_CLOSED",
        "PROVIDER_TERMINATION",
        "BUDGET_RECONCILED",
        "SESSION_ENDED",
    ):
        assert e in k, (e, " ".join(k))
    sources = {e["details"].get("origin") for e in out["events"] if e["event_type"] == "INSTRUCTION_APPENDED"}
    assert {"TURN_1", "PLAYGROUND"} <= sources
    answered = next(e for e in out["events"] if e["event_type"] == "DELEGATION_ANSWERED")
    assert answered["details"]["responder"] == "DETERMINISTIC_PYTHON/1"
    assert out["termination_status"] == "CONFIRMED" and out["usage_source"] == "PROVIDER_SESSION_CLOSED"
    used = float(out["provider_usage_seconds"])
    assert used > 0 and out["reservation_status"] == "RECONCILED"
    assert float(out["reconciled_usd"]) == pytest.approx(round(used * 0.05 / 60 + 0.00005, 4), abs=0.0001)
    assert out["provider_session_id"].startswith("live_mock_")
    assert {m["track"] for m in out["media"]} == {"MIC", "PROVIDER_PLAYBACK"}  # server-side recording
    provider_tx = [t for t in out["transcripts"] if t["source"] == "PROVIDER_TRANSCRIPT"]
    assert provider_tx and all("not independent" in t["engine"] for t in provider_tx)
    trace_text = json.dumps([e["details"] for e in out["events"]])
    assert "mock transcript of the caller" not in trace_text  # transcript text is kept out of the trace
    sess = mock_server.sessions[out["provider_session_id"]]
    for kind in (
        "session.input_audio.append",
        "session.instructions.append",
        "session.commentary.append",
        "session.close",
    ):
        assert kind in sess.seen, kind
    assert set(app.state.gpt_live_connect_log) == {"127.0.0.1"}  # nothing but the loopback mock was contacted
    assert counts(db) == before  # no operational row


def test_provider_errors_invalid_events_expiry_and_connect_failure(
    app: Any, user_c: TestClient, admin_c: TestClient
) -> None:
    budgets(admin_c, max_concurrent_sessions=1, interactive_max_s=60)
    s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c, instructions="[mock:error]")}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        time.sleep(1.0)
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    out = wait_ended(user_c, s["id"])
    k = kinds(out)
    assert "PROVIDER_ERROR" in k and "INVALID_PROVIDER_EVENT" in k and "UNHANDLED_PROVIDER_EVENT" in k
    assert out["termination_status"] == "CONFIRMED" and out["metrics"]["invalid_provider_events"] >= 2
    # The provider ends the session itself (duration limit): confirmed, reconciled.
    s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c, instructions="[mock:expire=2]")}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ended")
    out = wait_ended(user_c, s["id"])
    assert out["end_reason"] == "PROVIDER_CLOSED_EXPIRED" and out["termination_status"] == "CONFIRMED"
    assert "CLOSE_SENT" not in kinds(out) and out["reservation_status"] == "RECONCILED"
    # Connect failure: nothing can have been created or billed.
    saved = app.state.settings.voice_lab_gpt_live_mock_url
    app.state.settings.voice_lab_gpt_live_mock_url = "ws://127.0.0.1:9/v1/live/sessions"
    try:
        s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c)}, 201)
        with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            until(ws, "session.ended")
    finally:
        app.state.settings.voice_lab_gpt_live_mock_url = saved
    out = wait_ended(user_c, s["id"])
    assert out["end_reason"] == "PROVIDER_CONNECT_FAILED" and out["termination_status"] == "NOT_STARTED"
    assert out["reconciled_usd"] == "0.0000" and out["usage_source"] == "NO_PROVIDER_CONNECTION"


def test_timeout_kill_switch_and_browser_disconnect_close_the_provider_session(
    user_c: TestClient, admin_c: TestClient, mock_server: MockGptLiveServer
) -> None:
    budgets(admin_c, max_concurrent_sessions=1, interactive_max_s=5)
    pv = gpt_prompt(user_c)
    s = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
    assert s["max_duration_s"] == 5
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert until(ws, "session.ended", limit=20000)[-1]["reason"] == "MAX_DURATION"  # server timer, not browser
    out = wait_ended(user_c, s["id"])
    assert "CLOSE_SENT" in kinds(out) and out["termination_status"] == "CONFIRMED"
    assert mock_server.sessions[out["provider_session_id"]].closed
    budgets(admin_c, interactive_max_s=60)
    s = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        post(admin_c, "/kill-switch", {"engaged": True, "reason": "Emergency stop during a GPT-Live session"})
        assert until(ws, "session.ended", limit=20000)[-1]["reason"] == "KILL_SWITCH"
    out = wait_ended(user_c, s["id"])
    assert "CLOSE_SENT" in kinds(out) and out["termination_status"] == "CONFIRMED"
    assert refused(user_c, "/sessions", {"prompt_version_id": pv})["code"] == "KILL_SWITCH"
    post(admin_c, "/kill-switch", {"engaged": False, "reason": "Drill complete"})
    s = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
    # The browser went away without a stop: the server still closes the provider session.
    out = wait_ended(user_c, s["id"])
    assert out["end_reason"] == "DISCONNECTED" and "CLOSE_SENT" in kinds(out)
    assert out["termination_status"] == "CONFIRMED"


def test_unconfirmed_termination_retains_the_reservation_until_resolved(
    user_c: TestClient, admin_c: TestClient
) -> None:
    budgets(admin_c, max_concurrent_sessions=1, interactive_max_s=60)
    s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c, instructions="[mock:noclose]")}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended", limit=20000)
    out = wait_ended(user_c, s["id"])
    assert out["termination_status"] == "UNCONFIRMED" and out["reservation_status"] == "HELD"
    assert out["reconciled_usd"] is None and "USAGE_UNCONFIRMED" in kinds(out)  # never treated as zero
    blocked = refused(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c)})
    assert blocked["code"] == "CONCURRENCY_LIMIT"  # the retained reservation still counts
    assert (
        user_c.post(f"/api/v1/voice-lab/sessions/{s['id']}/provider-close", headers=csrf_header(user_c)).status_code
        == 403
    )
    closed = post(admin_c, f"/sessions/{s['id']}/provider-close", {})  # documented sideband: attach → close
    assert closed["termination_status"] == "RESOLVED" and closed["usage_source"] == "SIDEBAND_SESSION_CLOSED"
    assert closed["reservation_status"] == "RECONCILED"
    # A dropped provider connection: no session.closed → unconfirmed → a manager enters the provider-reported usage.
    s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c, instructions="[mock:drop]")}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ended", limit=40000)
    out = wait_ended(user_c, s["id"])
    assert out["termination_status"] == "UNCONFIRMED" and out["reservation_status"] == "HELD"
    assert "PROVIDER_CONNECTION_LOST" in kinds(out)
    r = post(
        admin_c,
        f"/sessions/{s['id']}/resolve-usage",
        {"usage_seconds": 2.4, "source": "PROVIDER_USAGE_DASHBOARD", "reason": "Usage page shows 2.4 s"},
    )
    assert r["termination_status"] == "RESOLVED" and r["reconciled_usd"] == "0.0020"
    assert (
        refused(
            admin_c,
            f"/sessions/{s['id']}/resolve-usage",
            {"usage_seconds": 1, "source": "PROVIDER_USAGE_DASHBOARD", "reason": "again"},
        )["code"]
        == "NOT_UNCONFIRMED"
    )


def test_paid_gates_single_use_authorisation_and_crash_recovery(
    app: Any, user_c: TestClient, admin_c: TestClient, mock_server: MockGptLiveServer, engine: Engine, user: Account
) -> None:
    """The real GPT_LIVE provider path (PAID class), pointed at the loopback mock with a placeholder key."""
    budgets(
        admin_c,
        "PAID",
        overall_usd=10,
        daily_usd=2,
        per_experiment_usd=1,
        max_concurrent_sessions=1,
        interactive_max_s=300,
        idle_timeout_s=15,
    )
    pv = gpt_prompt(user_c, "OPENAI_GPT_LIVE")
    e = refused(user_c, "/sessions", {"prompt_version_id": pv})
    msgs = " ".join(d["message"] for d in e["details"])
    assert e["code"] == "PAID_DISABLED" and "SMOKE_TEST_NOT_AUTHORISED" in msgs
    post(admin_c, "/paid-switch", {"enabled": True, "reason": "Offline paid-path test"})
    assert refused(user_c, "/sessions", {"prompt_version_id": pv})["code"] == "SMOKE_TEST_NOT_AUTHORISED"
    a = post(
        admin_c,
        "/paid-authorisations",
        {
            "provider": "OPENAI_GPT_LIVE",
            "model": "gpt-live-1",
            "reason": "First smoke test (offline mock)",
            "max_duration_s": 120,
        },
        201,
    )
    assert a["status"] == "ISSUED" and a["max_usd"] == "0.1000" and a["max_sessions"] == 1
    assert (
        refused(
            admin_c,
            "/paid-authorisations",
            {"provider": "OPENAI_GPT_LIVE", "model": "gpt-live-1", "reason": "Second one"},
        )["code"]
        == "AUTHORISATION_EXISTS"
    )
    assert (
        admin_c.post(
            "/api/v1/voice-lab/sessions", json={"prompt_version_id": pv}, headers=csrf_header(admin_c)
        ).status_code
        == 403
    )  # the authoriser cannot execute
    other = gpt_prompt(user_c, "OPENAI_GPT_LIVE", voice="quartz")
    assert refused(user_c, "/sessions", {"prompt_version_id": other})["code"] == "AUTHORISATION_MISMATCH"
    with make_session_factory(engine)() as db:  # self-execution is refused even for a user holding both roles
        with pytest.raises(lab.LabError) as exc:
            lab.create_session(
                db,
                a["authorised_by"],
                uuid.UUID(pv),
                record=False,
                recording_available=True,
                settings=app.state.settings,
            )
        assert exc.value.code == "SELF_AUTHORISATION"
        db.rollback()
    s = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
    assert s["spend_class"] == "PAID" and s["max_duration_s"] == 120 and s["estimated_max_usd"] == "0.1000"
    assert s["authorisation_ref"] == a["authorisation_ref"] and s["reservation_status"] == "HELD"
    assert refused(user_c, "/sessions", {"prompt_version_id": pv})["code"] == "SMOKE_TEST_NOT_AUTHORISED"  # used
    before = len(mock_server.auth_headers)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    assert mock_server.auth_headers[before:] == [True]  # the backend sent the key to the endpoint only
    out = wait_ended(user_c, s["id"])
    assert out["termination_status"] == "CONFIRMED" and out["reservation_status"] == "RECONCILED"
    for body in (ok(user_c.get("/api/v1/voice-lab/settings")), out, ok(user_c.get("/api/v1/voice-lab/sessions"))):
        assert FAKE_KEY not in json.dumps(body)  # never returned
    # Crash recovery: a paid session that had connected keeps its reservation until a manager confirms usage.
    a2 = post(
        admin_c,
        "/paid-authorisations",
        {"provider": "OPENAI_GPT_LIVE", "model": "gpt-live-1", "reason": "Crash recovery test", "max_duration_s": 60},
        201,
    )
    s2 = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
    with make_session_factory(engine)() as db, db.begin():
        lab.mark_live(db, uuid.UUID(s2["id"]))
    with make_session_factory(engine)() as db, db.begin():
        lab.recover(db)
    r = session(user_c, s2["id"])
    assert r["end_reason"] == "SERVER_RESTART" and r["termination_status"] == "UNCONFIRMED"
    assert r["reservation_status"] == "HELD"
    a3 = post(
        admin_c,
        "/paid-authorisations",
        {
            "provider": "OPENAI_GPT_LIVE",
            "model": "gpt-live-1",
            "reason": "Blocked by the held reservation",
            "max_duration_s": 60,
        },
        201,
    )
    assert refused(user_c, "/sessions", {"prompt_version_id": pv})["code"] == "CONCURRENCY_LIMIT"
    revoked = post(admin_c, f"/paid-authorisations/{a3['id']}/revoke", {"reason": "Not needed"})
    assert revoked["status"] == "REVOKED" and a2["authorisation_ref"] != a3["authorisation_ref"]
    assert (
        post(
            admin_c,
            f"/sessions/{s2['id']}/resolve-usage",
            {"usage_seconds": 0, "source": "PROVIDER_USAGE_DASHBOARD", "reason": "Never started at the provider"},
        )["reconciled_usd"]
        == "0.0000"
    )
    post(admin_c, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    with make_session_factory(engine)() as db:  # authorisations are immutable and never deleted
        with pytest.raises(DBAPIError):
            db.execute(text(f"UPDATE {SCHEMA}.lab_paid_authorisation SET max_usd = 1 WHERE status <> 'ISSUED'"))
        db.rollback()


def test_disabled_configuration_never_connects(
    settings: Settings, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.main import create_app

    calls: list[str] = []
    monkeypatch.setattr(gpt_live, "default_connect", lambda u, h: calls.append(u))  # type: ignore[arg-type]
    a = create_app(settings.model_copy(update={"transcription_worker": False}))  # defaults: DISABLED, no mock URL
    with TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        assert login(c, make_account(db, "LOCAL_USER_SG", prefix="glusr")).status_code == 200
        st = ok(c.get("/api/v1/voice-lab/settings"))
        prov = {p["code"]: p for p in st["providers"]}
        assert not prov["OPENAI_GPT_LIVE"]["available"] and not prov["GPT_LIVE_MOCK"]["available"]
        assert st["gpt_live"] == {
            **st["gpt_live"],
            "mode": "DISABLED",
            "api_key_configured": False,
            "endpoint_host": "api.openai.com",
        }
        for provider in ("OPENAI_GPT_LIVE", "GPT_LIVE_MOCK"):
            e = refused(c, "/sessions", {"prompt_version_id": gpt_prompt(c, provider)})
            assert e["code"] in ("PAID_DISABLED", "PROVIDER_NOT_AVAILABLE")
    assert calls == [] and getattr(a.state, "gpt_live_connect_log", []) == []
    assert not gpt_live.allowed_url("wss://example.com/v1/live/sessions", app_env="test", mock=False)
    assert not gpt_live.allowed_url("ws://127.0.0.1:1/v1/live/sessions", app_env="local", mock=False)
    assert gpt_live.allowed_url("wss://api.openai.com/v1/live/sessions", app_env="local", mock=False)
    assert not gpt_live.allowed_url("wss://api.openai.com/v1/live/sessions", app_env="local", mock=True)
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                **settings.model_dump(),
                "app_env": "local",
                "voice_lab_gpt_live_url": "wss://evil.example/v1/live/sessions",
            }
        )


def test_retention_purges_lab_audio_and_session_transcripts(app: Any, user_c: TestClient, db: Session) -> None:
    pv = gpt_prompt(user_c, "GPT_LIVE_MOCK")
    s = post(user_c, "/sessions", {"prompt_version_id": pv, "record": True}, 201)
    with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        talk(ws)
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    out = wait_ended(user_c, s["id"])
    assert out["media"] and out["transcripts"]
    rs = lab.store_for(app)
    keys = [
        r[0]
        for r in db.execute(text(f"SELECT object_key FROM {SCHEMA}.lab_media WHERE session_id = :s"), {"s": s["id"]})
    ]
    assert all(rs.get(k) is not None for k in keys)
    with make_session_factory(db.get_bind())() as d2, d2.begin():  # type: ignore[arg-type]
        assert lab.purge_expired(d2, rs, 168) == {"media": 0, "transcripts": 0}  # nothing is old yet
        done = lab.purge_expired(d2, rs, 168, now=datetime.now(UTC) + timedelta(hours=169))
    assert done["media"] >= 2 and done["transcripts"] >= 1
    assert all(rs.get(k) is None for k in keys)  # audio objects deleted
    out = session(user_c, s["id"])
    assert all(m["purged_at"] for m in out["media"]) and all(
        t["purged_at"] and t["text"] == "" for t in out["transcripts"]
    )
    assert out["metrics"] and out["events"] and out["reconciled_usd"] is not None  # evaluation history kept
    for sql in (
        f"UPDATE {SCHEMA}.lab_media SET sha256 = repeat('0', 64)",
        f"DELETE FROM {SCHEMA}.lab_transcript",
        f"UPDATE {SCHEMA}.lab_media SET purged_at = now()",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()


def test_speech_results_and_human_assessment(user_c: TestClient, db: Session) -> None:
    m = {"heard": None}
    assert lab_eval.speech_result(m) == "INSUFFICIENT_AUDIO_EVIDENCE"
    assert lab_eval.speech_result({"heard": {"exact_match": True}}) == "AUTOMATED_TRANSCRIPT_MATCH"
    assert (
        lab_eval.speech_result(
            {"heard": {"exact_match": False}, "attributions": [{"attribution": "SUSPECTED_TRANSCRIPTION_ERROR"}]}
        )
        == "SUSPECTED_TRANSCRIPTION_ERROR"
    )
    assert (
        lab_eval.speech_result(
            {"heard": {"exact_match": False}, "attributions": [{"attribution": "SUSPECTED_SPEECH_DEVIATION"}]}
        )
        == "SUSPECTED_SPEECH_DEVIATION"
    )
    assert "not proof" in lab_eval.SPEECH_RESULTS["AUTOMATED_TRANSCRIPT_MATCH"]
    # A no-audio trial cannot be human-confirmed; assessments are insert-only.
    d = post(user_c, "/datasets", {"name": "Assessment set"}, 201)
    post(user_c, f"/datasets/{d['id']}/cases", {"name": "No audio", "expected_statement": "Hello there"}, 201)
    pv = str(
        post(
            user_c,
            "/prompts",
            {
                "name": "Mock for assessment",
                "system_prompt": "x",
                "provider": "MOCK",
                "model": "mock-fixed-message-1",
                "voice": "synthetic-fixed",
            },
            201,
        )["versions"][0]["id"]
    )
    e = post(
        user_c,
        "/experiments",
        {
            "name": "Assessment run",
            "dataset_id": d["id"],
            "prompt_version_id": pv,
            "max_spend_usd": 0,
            "repetitions": 1,
            "max_duration_s": 10,
        },
        201,
    )
    e = post(user_c, f"/experiments/{e['id']}/run", {})
    t = e["trials"][0]
    assert t["speech_result"] == "INSUFFICIENT_AUDIO_EVIDENCE"
    r = refused(
        user_c,
        f"/trials/{t['id']}/assessments",
        {"result": "CONFIRMED_AS_EXPECTED", "notes": "Sounds fine", "listened": True},
    )
    assert r["code"] == "NO_AUDIO"
    r = refused(
        user_c,
        f"/trials/{t['id']}/assessments",
        {"result": "INCONCLUSIVE", "notes": "Not listened", "listened": False},
        422,
    )
    assert r["code"] == "LISTENING_REQUIRED"
    assert (
        refused(
            user_c,
            "/experiments",
            {
                "name": "GPT experiment",
                "dataset_id": d["id"],
                "max_spend_usd": 1,
                "prompt_version_id": gpt_prompt(user_c),
            },
            422,
        )["code"]
        == "EXPERIMENT_PROVIDER_UNSUPPORTED"
    )
    assert OPERATIONAL  # isolation is asserted in the lifecycle test
