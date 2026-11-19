"""S1-E.2A Azure OpenAI GPT-Live, offline: the shared GPT-Live adapter against the mocked protocol server on 127.0.0.1
with the Azure URL path (``/openai/v1/live/sessions``), 24 kHz PCM16 on the wire and Azure authentication. No Azure
connection, no paid call: in APP_ENV=test only loopback hosts are reachable; credentials are placeholders; the Azure
price used here is a SYNTHETIC test value (Azure's real price is unknown to Call360; the owner configures it).

Covers: API-key authentication (``api-key`` header, never ``Authorization``), Entra ID bearer tokens from an injected
credential (and fail-closed when azure-identity is missing), deployment name sent as ``session.model`` and enforced,
24 kHz wire audio resampled to the browser's 16 kHz, delegation, interruption, termination and sideband close on the
Azure paths, usage reconciliation at the configured Azure rate, fail-closed without a verified price, URL and
configuration guards, credentials never returned or logged, operational isolation."""

# ruff: noqa: F811 — pytest fixtures imported from test_gpt_live
from __future__ import annotations

import json
import logging
import time
from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.voice import live_providers as lp
from app.voice.gpt_live_mock import MockGptLiveServer
from tests.support import ORIGIN, login, make_account
from tests.test_gpt_live import budgets, gpt_prompt, mock_server, restore, talk, wait_ended  # noqa: F401
from tests.test_voice_lab import counts, ok, post, refused, until

pytestmark = pytest.mark.usefixtures("seeded")
WS = {"origin": ORIGIN}
AZ_KEY = "azure-placeholder-not-a-key-1111"
DEPLOYMENT = "gpt-live-1-sg-lab"
TEST_PRICE = Decimal("0.07")  # SYNTHETIC test value — not an Azure price


def azure_app(settings: Settings, srv: MockGptLiveServer, **over: Any) -> Any:
    from app.main import create_app

    st = settings.model_copy(
        update={
            "transcription_worker": False,
            "voice_lab_azure_gpt_live_mode": "LIVE",
            "voice_lab_azure_openai_endpoint": f"http://127.0.0.1:{srv.port}",  # loopback: APP_ENV=test only
            "voice_lab_azure_openai_deployment": DEPLOYMENT,
            "voice_lab_azure_auth": "API_KEY",
            "voice_lab_azure_openai_api_key": SecretStr(AZ_KEY),
            "voice_lab_azure_audio_rate": 24000,
            "voice_lab_azure_deployment_type": "DATA_ZONE",
            "voice_lab_azure_region": "test-region",
            "voice_lab_azure_price_usd_per_min": TEST_PRICE,
            "voice_lab_azure_price_source": "SYNTHETIC TEST VALUE (not an Azure price)",
            "voice_lab_azure_price_verified_on": "2026-11-18",
            "voice_lab_close_timeout_s": 2.0,
            **over,
        }
    )
    a = create_app(st)
    a.state.voicelab_inline = True
    return a  # production connector (loopback only in tests)


def clients(a: Any, db: Session) -> tuple[TestClient, TestClient]:
    u = TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN})
    m = TestClient(a, base_url=ORIGIN, headers={"Origin": ORIGIN})
    u.__enter__()
    m.__enter__()
    assert login(u, make_account(db, "LOCAL_USER_SG", prefix="azu")).status_code == 200
    assert login(m, make_account(db, "LOCAL_ADMIN", prefix="aza")).status_code == 200
    budgets(
        m,
        "PAID",
        overall_usd=10,
        daily_usd=2,
        per_experiment_usd=1,
        max_concurrent_sessions=1,
        interactive_max_s=300,
        idle_timeout_s=15,
    )
    return u, m


def close(*cs: TestClient) -> None:
    for c in cs:
        c.__exit__(None, None, None)


def authorise(m: TestClient, seconds: int = 120) -> dict[str, Any]:
    post(m, "/paid-switch", {"enabled": True, "reason": "Azure offline test"})
    return dict(
        post(
            m,
            "/paid-authorisations",
            {
                "provider": "AZURE_OPENAI_GPT_LIVE",
                "model": DEPLOYMENT,
                "voice": "marin",
                "max_duration_s": seconds,
                "reason": "Azure smoke test (loopback mock only)",
            },
            201,
        )
    )


def az_prompt(c: TestClient, instructions: str = "", model: str = DEPLOYMENT) -> str:
    body = {
        "name": "Azure GPT-Live prompt",
        "system_prompt": f"Synthetic Azure test voice. [mock:greet] {instructions}",  # S1-E.2B: mock waits otherwise
        "turn_instructions": ["Ask the caller to confirm"],
        "provider": "AZURE_OPENAI_GPT_LIVE",
        "model": model,
        "voice": "marin",
    }
    return str(post(c, "/prompts", body, 201)["versions"][0]["id"])


def test_azure_session_end_to_end_on_the_mocked_protocol(
    settings: Settings, mock_server: MockGptLiveServer, db: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    a = azure_app(settings, mock_server)
    u, m = clients(a, db)
    try:
        before = counts(db)
        st = ok(u.get("/api/v1/voice-lab/settings"))
        prov = {p["code"]: p for p in st["providers"]}
        az = prov["AZURE_OPENAI_GPT_LIVE"]
        assert az["available"] and az["preferred"] and az["models"] == [DEPLOYMENT] and az["vendor"] == "AZURE"
        assert az["rate_card"]["session_usd_per_min"] == "0.07" and "SYNTHETIC" in az["rate_card"]["source"]
        assert st["azure"]["deployment"] == DEPLOYMENT and st["azure"]["auth"] == "API_KEY"
        assert st["azure"]["credential_configured"] and st["azure"]["audio_rate"] == 24000
        assert prov["GPT_LIVE"]["hidden"]  # legacy code is not offered
        n0 = mock_server.connections
        auth = authorise(m)
        assert auth["max_usd"] == "0.1400"  # 120 s × the configured Azure rate — never the direct OpenAI price
        assert mock_server.connections == n0  # issuing and opening pages never connect
        s = post(u, "/sessions", {"prompt_version_id": az_prompt(u), "record": True}, 201)
        assert s["provider"] == "AZURE_OPENAI_GPT_LIVE" and s["spend_class"] == "PAID"
        assert s["estimated_max_usd"] == "0.1400" and s["model"] == DEPLOYMENT
        with u.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            until(ws, "response.started")
            frames = []
            for _ in range(20):
                msg = ws.receive()
                if msg.get("bytes"):
                    frames.append(len(msg["bytes"]) - 4)
            assert frames and set(frames) == {640}  # 24 kHz wire audio arrives as 16 kHz 20 ms browser frames
            for _ in range(12):
                ws.send_bytes(b"\x28\x23" * 320)  # loud: barge-in
            until(ws, "playback.clear")
            for _ in range(40):
                ws.send_bytes(b"\x00" * 640)
            until(ws, "input.speech_stopped")
            time.sleep(0.5)
            talk(ws)  # second turn: the mock delegates
            sess = max(mock_server.sessions.values(), key=lambda x: x.started)
            t0 = time.monotonic()
            while "session.commentary.append" not in sess.seen and time.monotonic() - t0 < 10:
                ws.receive()
            ws.send_json({"type": "session.stop"})
            until(ws, "session.ended")
        out = wait_ended(u, s["id"])
        assert out["termination_status"] == "CONFIRMED" and out["usage_source"] == "PROVIDER_SESSION_CLOSED"
        secs = float(out["provider_usage_seconds"])
        expected = (Decimal(str(secs)) * TEST_PRICE / 60).quantize(Decimal("0.0001"), rounding="ROUND_UP")
        assert Decimal(out["reconciled_usd"]) == expected
        assert mock_server.auth_kinds[-1] == "api-key"  # Azure API-key header, not Authorization
        assert mock_server.models[-1] == DEPLOYMENT and mock_server.rates[-1] == 24000
        assert mock_server.session_keys[-1] == ["audio", "delegation", "instructions", "model"]  # documented fields
        kinds = [e["event_type"] for e in out["events"]]
        for k in (
            "PROVIDER_SESSION_STARTED",
            "BARGE_IN",
            "DELEGATION_ANSWERED",
            "CLOSE_SENT",
            "PROVIDER_SESSION_CLOSED",
        ):
            assert k in kinds, k
        assert {"MIC", "PROVIDER_PLAYBACK"} == {x["track"] for x in out["media"]}
        ep = next(e["details"] for e in out["events"] if e["event_type"] == "PROVIDER_ENDPOINT")
        assert ep == {
            **ep,
            "vendor": "AZURE",
            "host": "127.0.0.1",
            "wire_rate": 24000,
            "model": DEPLOYMENT,
            "auth": ["api-key"],
            "mock": False,
        }
        for body in (out, ok(u.get("/api/v1/voice-lab/settings")), ok(m.get("/api/v1/voice-lab/settings"))):
            assert AZ_KEY not in json.dumps(body, default=str)
        assert all(
            AZ_KEY not in r.getMessage()
            for r in caplog.records
            if not r.name.startswith(("websockets.server", "call360.gpt_live_mock"))
        )
        assert set(a.state.gpt_live_connect_log) == {"127.0.0.1"} and counts(db) == before
        post(m, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    finally:
        close(u, m)


def test_azure_fails_closed_without_a_verified_price(
    settings: Settings, mock_server: MockGptLiveServer, db: Session
) -> None:
    a = azure_app(
        settings,
        mock_server,
        voice_lab_azure_price_usd_per_min=None,
        voice_lab_azure_price_source=None,
        voice_lab_azure_price_verified_on=None,
    )
    u, m = clients(a, db)
    try:
        st = ok(u.get("/api/v1/voice-lab/settings"))
        az = next(p for p in st["providers"] if p["code"] == "AZURE_OPENAI_GPT_LIVE")
        assert not az["available"] and az["rate_card"]["session_usd_per_min"] == "0"
        assert az["rate_card"]["input_usd_per_audio_min"] is None and "no verified Azure price" in az["reason"]
        assert "no verified Azure price" in st["azure"]["missing"]
        post(m, "/paid-switch", {"enabled": True, "reason": "Fail-closed check"})
        e = refused(
            m,
            "/paid-authorisations",
            {
                "provider": "AZURE_OPENAI_GPT_LIVE",
                "model": DEPLOYMENT,
                "reason": "Should be refused",
                "max_duration_s": 120,
            },
            422,
        )
        assert e["code"] == "COST_UNKNOWN"
        e = refused(u, "/sessions", {"prompt_version_id": az_prompt(u)})
        msgs = " ".join(d["message"] for d in e["details"])
        assert "COST_UNKNOWN" in msgs and "PROVIDER_NOT_AVAILABLE" in msgs
        post(m, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    finally:
        close(u, m)


class _FakeCredential:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    def get_token(self, scope: str) -> Any:
        self.scopes.append(scope)
        return type("Tok", (), {"token": "fake-entra-token-not-real", "expires_on": int(time.time()) + 3600})()


def test_azure_entra_id_bearer_token_and_fail_closed_without_library(
    settings: Settings, mock_server: MockGptLiveServer, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = azure_app(settings, mock_server, voice_lab_azure_auth="ENTRA", voice_lab_azure_openai_api_key=None)
    u, m = clients(a, db)
    try:
        # azure-identity is not installed locally: Entra mode is unavailable (fail closed), with the reason shown.
        st = ok(u.get("/api/v1/voice-lab/settings"))
        az = next(p for p in st["providers"] if p["code"] == "AZURE_OPENAI_GPT_LIVE")
        assert not az["available"] and "azure-identity" in az["reason"]
        # With a credential (as Managed Identity / DefaultAzureCredential would supply) the token is a bearer header.
        monkeypatch.setattr(lp, "entra_available", lambda: True)
        cred = _FakeCredential()
        a.state.azure_credential = cred
        authorise(m, 60)
        s = post(u, "/sessions", {"prompt_version_id": az_prompt(u)}, 201)
        with u.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            until(ws, "response.started")
            ws.send_json({"type": "session.stop"})
            until(ws, "session.ended")
        assert wait_ended(u, s["id"])["termination_status"] == "CONFIRMED"
        assert mock_server.auth_kinds[-1] == "bearer" and cred.scopes == ["https://ai.azure.com/.default"]
        post(m, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    finally:
        close(u, m)


def test_azure_deployment_enforced_and_sideband_close(
    settings: Settings, mock_server: MockGptLiveServer, db: Session
) -> None:
    a = azure_app(settings, mock_server)
    u, m = clients(a, db)
    try:
        authorise(m, 60)
        e = refused(u, "/sessions", {"prompt_version_id": az_prompt(u, model="another-deployment")})
        assert any("DEPLOYMENT_MISMATCH" in d["message"] for d in e["details"])
        s = post(u, "/sessions", {"prompt_version_id": az_prompt(u, instructions="[mock:noclose]")}, 201)
        with u.websocket_connect(s["stream_path"], headers=WS) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            until(ws, "response.started")
            ws.send_json({"type": "session.stop"})
            until(ws, "session.ended", limit=20000)
        out = wait_ended(u, s["id"])
        assert out["termination_status"] == "UNCONFIRMED" and out["reservation_status"] == "HELD"
        n = mock_server.connections
        closed = post(
            m, f"/sessions/{s['id']}/provider-close", {}
        )  # Azure sideband …/openai/v1/live/sessions/{id}/attach
        assert closed["termination_status"] == "RESOLVED" and closed["usage_source"] == "SIDEBAND_SESSION_CLOSED"
        assert mock_server.connections == n + 1 and mock_server.auth_kinds[-1] == "api-key"
        post(m, "/paid-switch", {"enabled": False, "reason": "Back to the default"})
    finally:
        close(u, m)


def test_azure_url_configuration_and_resampling_guards(settings: Settings) -> None:
    ok_url = "wss://my-resource.openai.azure.com/openai/v1/live/sessions"
    assert lp.azure_url("https://my-resource.openai.azure.com/") == ok_url
    assert lp.allowed(ok_url, vendor="AZURE", app_env="local", mock=False)
    for bad in (
        "wss://my-resource.openai.azure.com.evil.example/openai/v1/live/sessions",
        "ws://my-resource.openai.azure.com/openai/v1/live/sessions",
        "wss://api.openai.com/v1/live/sessions",
        "wss://openai.azure.com/openai/v1/live/sessions",
    ):
        assert not lp.allowed(bad, vendor="AZURE", app_env="local", mock=False), bad
    assert not lp.allowed(ok_url, vendor="AZURE", app_env="test", mock=False)  # tests: loopback only
    assert not lp.allowed(ok_url, vendor="OPENAI", app_env="local", mock=False)  # vendor-specific hosts
    base = {**settings.model_dump(), "app_env": "local"}
    for bad in (
        {"voice_lab_azure_openai_endpoint": "https://evil.example"},
        {"voice_lab_azure_openai_deployment": "bad deployment!"},
        {"voice_lab_azure_price_usd_per_min": Decimal("0.05")},
    ):  # a price without its source and date
        with pytest.raises(ValueError):
            Settings.model_validate({**base, **bad})
    pcm = (b"\x10\x27" + b"\xf0\xd8") * 1600  # 3200 samples at 16 kHz
    up = lp.resample(pcm, 16000, 24000)
    assert len(up) == len(pcm) * 3 // 2 and len(lp.resample(up, 24000, 16000)) == len(pcm)
