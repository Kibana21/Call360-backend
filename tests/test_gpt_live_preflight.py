"""S1-E.2 live smoke-test preflight (offline; loopback mocked protocol server only — no paid call is possible: in
APP_ENV=test the connector refuses every non-loopback host, including the official endpoint).

1. The API key stays on the backend and is never logged — with the production connector and DEBUG logging on.
2. Nothing connects on application startup or when the Voice Lab pages load.
3. Startup and termination are bounded; an unconfirmed termination keeps the reservation and blocks further sessions.
4. After an interruption the browser is told to clear its queue, no further audio of the interrupted response is sent,
   and no provider audio is sent until the caller's turn ends (stale audio cannot be played).
5. Server-recorded outgoing audio is labelled as sent, not as played."""

# ruff: noqa: F811 — pytest fixtures imported from test_gpt_live
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.voice import gpt_live, lab
from app.voice.gpt_live_mock import MockGptLiveServer
from app.voice.provider import Inbound, SessionStats
from tests.support import ORIGIN, login, make_account
from tests.test_gpt_live import (  # noqa: F401 — fixtures
    FAKE_KEY,
    budgets,
    gpt_prompt,
    mock_server,
    restore,
    session,
    talk,
    wait_ended,
)
from tests.test_voice_lab import LOUD, QUIET, ok, post, refused, until

pytestmark = pytest.mark.usefixtures("seeded")
WS = {"origin": ORIGIN}


def make_app(settings: Settings, mock_server: MockGptLiveServer, **over: Any) -> Any:
    from app.main import create_app

    st = settings.model_copy(
        update={
            "transcription_worker": False,
            "voice_lab_gpt_live_mode": "LIVE",
            "voice_lab_openai_api_key": SecretStr(FAKE_KEY),
            "voice_lab_gpt_live_url": mock_server.url,
            "voice_lab_gpt_live_mock_url": mock_server.url,
            "voice_lab_close_timeout_s": 2.0,
            **over,
        }
    )
    a = create_app(st)
    a.state.voicelab_inline = True
    return a  # the PRODUCTION connector (gpt_live.default_connect) is used: no test override


def test_key_never_logged_and_nothing_connects_on_startup_or_page_load(
    settings: Settings, mock_server: MockGptLiveServer, db: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    names = ("websockets", "websockets.client", "call360.gpt_live.transport")
    levels = {n: logging.getLogger(n).level for n in names}
    for name in names:
        logging.getLogger(name).setLevel(logging.DEBUG)  # try to make the transport chatty: it must still not leak
    try:
        _key_run(settings, mock_server, db, caplog)
    finally:
        for n, lvl in levels.items():
            logging.getLogger(n).setLevel(lvl)


def _key_run(settings: Settings, mock_server: MockGptLiveServer, db: Session, caplog: pytest.LogCaptureFixture) -> None:
    before = mock_server.connections
    a = make_app(settings, mock_server)
    with (
        TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN}) as user_c,
        TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN}) as admin_c,
    ):
        assert login(user_c, make_account(db, "LOCAL_USER_SG", prefix="pfusr")).status_code == 200
        assert login(admin_c, make_account(db, "LOCAL_ADMIN", prefix="pfadm")).status_code == 200
        # Startup (lifespan, recovery, sweeps) and every request the Voice Lab pages make on load: no connection.
        for path in ("settings", "prompts", "sessions", "datasets", "experiments", "script-sources"):
            ok(user_c.get(f"/api/v1/voice-lab/{path}"))
        ok(admin_c.get("/api/v1/voice-lab/settings"))
        assert mock_server.connections == before and getattr(a.state, "gpt_live_connect_log", []) == []
        # One paid-path session through the production connector to the loopback mock.
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
        post(admin_c, "/paid-switch", {"enabled": True, "reason": "Preflight key-handling check"})
        auth = post(
            admin_c,
            "/paid-authorisations",
            {
                "provider": "OPENAI_GPT_LIVE",
                "model": "gpt-live-1",
                "reason": "Preflight (loopback mock only)",
                "max_duration_s": 60,
            },
            201,
        )
        s = post(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c, "OPENAI_GPT_LIVE")}, 201)
        assert mock_server.connections == before  # creating the session does not connect either
        with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            until(ws, "response.started")
            ws.send_json({"type": "session.stop"})
            until(ws, "session.ended")
        out = wait_ended(user_c, s["id"])
        assert out["termination_status"] == "CONFIRMED" and out["authorisation_ref"] == auth["authorisation_ref"]
        assert mock_server.connections == before + 1 and mock_server.auth_headers[-1] is True
        assert a.state.gpt_live_connect_log == ["127.0.0.1"]
        bodies = [ok(user_c.get(f"/api/v1/voice-lab/{p}")) for p in ("settings", "sessions")] + [out]
        post(admin_c, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    # Every record except the mocked server's own (a test double that receives the header by design).
    ours = [r for r in caplog.records if not r.name.startswith(("websockets.server", "call360.gpt_live_mock"))]
    assert any(r.name.startswith(("websockets", "call360.gpt_live")) for r in caplog.records)  # logging was active
    assert all(FAKE_KEY not in r.getMessage() for r in ours)
    assert all(FAKE_KEY not in json.dumps(b, default=str) for b in bodies)
    assert all(FAKE_KEY not in json.dumps(e["details"]) for e in out["events"])


def test_startup_timeout_is_bounded_and_unconfirmed_blocks_further_sessions(
    settings: Settings, mock_server: MockGptLiveServer, db: Session
) -> None:
    a = make_app(settings, mock_server, voice_lab_start_timeout_s=2.0)
    with (
        TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN}) as user_c,
        TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN}) as admin_c,
    ):
        assert login(user_c, make_account(db, "LOCAL_USER_SG", prefix="pfu2")).status_code == 200
        assert login(admin_c, make_account(db, "LOCAL_ADMIN", prefix="pfa2")).status_code == 200
        budgets(admin_c, max_concurrent_sessions=1, interactive_max_s=60)
        pv = gpt_prompt(user_c, instructions="[mock:nostart]")
        s = post(user_c, "/sessions", {"prompt_version_id": pv}, 201)
        t0 = time.monotonic()
        with user_c.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            assert until(ws, "session.ended", limit=20000)[-1]["reason"] == "PROVIDER_START_FAILED"
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0 + 2.0 + 3.0  # start timeout + close timeout + slack: bounded, never hanging
        out = wait_ended(user_c, s["id"])
        # The connection was open, so a provider session may exist: unconfirmed, the reservation is kept.
        assert out["termination_status"] == "UNCONFIRMED" and out["reservation_status"] == "HELD"
        blocked = refused(user_c, "/sessions", {"prompt_version_id": gpt_prompt(user_c)})
        assert blocked["code"] == "CONCURRENCY_LIMIT"
        post(
            admin_c,
            f"/sessions/{s['id']}/resolve-usage",
            {"usage_seconds": 0, "source": "PROVIDER_USAGE_DASHBOARD", "reason": "No session on the provider side"},
        )
        post(
            user_c,
            f"/sessions/{post(user_c, '/sessions', {'prompt_version_id': gpt_prompt(user_c)}, 201)['id']}/stop",
            {},
        )


class _Recorder:
    """A fake browser channel recording what the adapter sends, in order."""

    def __init__(self) -> None:
        self.q: asyncio.Queue[Inbound | None] = asyncio.Queue()
        self.log: list[tuple[str, int | None]] = []

    async def receive(self) -> Inbound | None:
        return await self.q.get()

    async def send_audio(self, response: int, pcm: bytes) -> None:
        self.log.append(("audio", response))

    async def send_event(self, event: dict[str, Any]) -> None:
        self.log.append((str(event["type"]), event.get("response")))


def test_no_stale_audio_after_interruption(mock_server: MockGptLiveServer) -> None:
    async def scenario() -> list[tuple[str, int | None]]:
        cfg = gpt_live.LiveConfig(
            url=mock_server.url,
            headers={},
            model="gpt-live-1",
            voice="marin",
            instructions="",
            turn_instructions=[],
            max_duration_s=20,
            close_timeout_s=2,
        )
        p = gpt_live.GptLiveProvider(cfg)
        ch = _Recorder()
        task = asyncio.ensure_future(p.run(ch, SessionStats()))
        for _ in range(100):
            await asyncio.sleep(0.05)
            if ("response.started", 1) in ch.log:
                break
        await asyncio.sleep(0.3)
        for frame in [LOUD] * 12:  # the caller talks over the provider
            await ch.q.put(Inbound(audio=frame))
        await asyncio.sleep(0.6)  # the mock "keeps speaking briefly" — that audio must not reach the browser
        for frame in [QUIET] * 40:
            await ch.q.put(Inbound(audio=frame))
        await asyncio.sleep(1.5)
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        await task
        assert p.outcome.termination == "CONFIRMED"
        return ch.log

    log = asyncio.run(scenario())
    clear = log.index(("playback.clear", 1))
    after = log[clear + 1 :]
    assert ("audio", 1) not in after  # nothing more of the interrupted response
    stopped = after.index(("input.speech_stopped", None))
    assert not any(k == "audio" for k, _ in after[:stopped])  # no provider audio until the caller's turn ends
    later = [r for k, r in after[stopped:] if k == "audio"]
    assert later and all(r is not None and r >= 2 for r in later)  # new audio belongs to a new response


def test_automated_tests_can_only_reach_loopback() -> None:
    assert not gpt_live.allowed_url("wss://api.openai.com/v1/live/sessions", app_env="test", mock=False)
    assert gpt_live.allowed_url("ws://127.0.0.1:9/v1/live/sessions", app_env="test", mock=False)
    assert gpt_live.allowed_url("wss://api.openai.com/v1/live/sessions", app_env="local", mock=False)
    assert not gpt_live.allowed_url("ws://127.0.0.1:9/v1/live/sessions", app_env="local", mock=False)
    assert "not a record of what the browser played" in lab.BASIS["PROVIDER_PLAYBACK"]
    assert uuid  # noqa: S101
