"""S1-E.2B — opening instruction (D-109), bounded post-barge-in suppression (D-110) and a mock that waits for the
caller like the live model (D-111). Loopback mock and fake clocks only: no network, no key, no money.

Background: in the first live Azure session (LAB-S-00023) the model waited for the caller before speaking, and
background voices kept the local VAD "speaking", so after one barge-in every later reply was dropped.
"""

# ruff: noqa: F811 — pytest fixtures imported from test_gpt_live
from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.voice import gpt_live, lab
from app.voice.gpt_live_mock import MockGptLiveServer
from app.voice.provider import Inbound, SessionStats
from tests.test_gpt_live import (  # noqa: F401 — fixtures
    admin_c,
    app,
    mock_server,
    restore,
    user_c,
)
from tests.test_voice_lab import LOUD, QUIET, post, refused

pytestmark = pytest.mark.usefixtures("seeded")
OPENING = "Greet the caller now, say this is a synthetic Call360 test, and ask them to say hello."


class _Recorder:
    """A fake browser channel recording audio, events and the adapter's trace, in order."""

    def __init__(self) -> None:
        self.q: asyncio.Queue[Inbound | None] = asyncio.Queue()
        self.log: list[tuple[str, int | None]] = []
        self.traces: list[tuple[str, dict[str, Any]]] = []

    async def receive(self) -> Inbound | None:
        return await self.q.get()

    async def send_audio(self, response: int, pcm: bytes) -> None:
        self.log.append(("audio", response))

    async def send_event(self, event: dict[str, Any]) -> None:
        self.log.append((str(event["type"]), event.get("response")))

    async def trace(self, kind: str, source: str, **details: Any) -> None:
        self.traces.append((kind, details))
        self.log.append((f"trace:{kind}", None))


def _cfg(url: str, instructions: str = "", opening: str = "", suppress_max_s: float = 1.5) -> gpt_live.LiveConfig:
    return gpt_live.LiveConfig(
        url=url,
        headers={},
        model="gpt-live-1",
        voice="marin",
        instructions=instructions,
        turn_instructions=[],
        max_duration_s=20,
        close_timeout_s=2,
        opening_instruction=opening,
        suppress_max_s=suppress_max_s,
    )


async def _wait_for(ch: _Recorder, item: tuple[str, int | None], seconds: float) -> bool:
    for _ in range(int(seconds / 0.05)):
        if item in ch.log:
            return True
        await asyncio.sleep(0.05)
    return item in ch.log


def _latest(server: MockGptLiveServer) -> Any:
    return max(server.sessions.values(), key=lambda s: s.started)


# ---- 1. the mock waits for the caller (reproduces LAB-S-00023's silent start) ----------------------------------------
def test_without_an_opening_instruction_the_mock_waits_for_the_caller(mock_server: MockGptLiveServer) -> None:
    async def scenario() -> _Recorder:
        p = gpt_live.GptLiveProvider(_cfg(mock_server.url))
        ch = _Recorder()
        task = asyncio.ensure_future(p.run(ch, SessionStats()))
        for _ in range(40):  # 0.8 s of caller silence
            await ch.q.put(Inbound(audio=QUIET))
            await asyncio.sleep(0.02)
        await asyncio.sleep(1.2)
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        await task
        assert p.outcome.termination == "CONFIRMED"
        return ch

    ch = asyncio.run(scenario())
    assert not any(k == "audio" for k, _ in ch.log)  # no greeting without the caller or an opening instruction
    assert not any(k.startswith("trace:OPENING") for k, _ in ch.log)


# ---- 2. the opening instruction: once, before any caller audio, and the greeting is heard ---------------------------
def test_opening_instruction_is_sent_once_before_caller_audio_and_the_greeting_reaches_the_browser(
    mock_server: MockGptLiveServer,
) -> None:
    async def scenario() -> tuple[_Recorder, list[str], gpt_live.Outcome]:
        p = gpt_live.GptLiveProvider(_cfg(mock_server.url, opening=OPENING))
        ch = _Recorder()
        task = asyncio.ensure_future(p.run(ch, SessionStats()))
        assert await _wait_for(ch, ("response.started", 1), 5)
        for _ in range(10):
            await ch.q.put(Inbound(audio=QUIET))
        await asyncio.sleep(0.5)
        seen = list(_latest(mock_server).seen)
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        await task
        return ch, seen, p.outcome

    ch, seen, outcome = asyncio.run(scenario())
    assert seen.count("session.instructions.append") == 1
    assert seen.index("session.instructions.append") < seen.index("session.input_audio.append")
    assert ("audio", 1) in ch.log  # the greeting reached the browser without the caller speaking first
    kind, details = next(t for t in ch.traces if t[0].startswith("OPENING"))
    assert kind == "OPENING_INSTRUCTION_APPENDED" and details["chars"] == len(OPENING)
    assert "content" not in details and outcome.instructions_sent == 1  # the trace carries no text


def test_a_failed_opening_send_is_traced_and_the_session_continues_without_retry(
    mock_server: MockGptLiveServer,
) -> None:
    async def scenario() -> tuple[_Recorder, gpt_live.GptLiveProvider]:
        p = gpt_live.GptLiveProvider(_cfg(mock_server.url, opening=OPENING))
        real = p._send
        attempts: list[str] = []

        async def failing_opening(event: dict[str, Any]) -> bool:
            if event["type"] == "session.instructions.append":
                attempts.append(event["type"])
                return False
            return await real(event)

        p._send = failing_opening  # type: ignore[method-assign]
        ch = _Recorder()
        task = asyncio.ensure_future(p.run(ch, SessionStats()))
        await asyncio.sleep(1.0)
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        await task
        assert attempts == ["session.instructions.append"]  # exactly one attempt: no retry
        return ch, p

    ch, p = asyncio.run(scenario())
    assert ("trace:OPENING_INSTRUCTION_NOT_SENT", None) in ch.log
    assert p.outcome.instructions_sent == 0 and p.outcome.termination == "CONFIRMED"


# ---- 3. bounded suppression: the live failure mode (VAD never reports a turn end) ------------------------------------
def test_suppression_is_released_by_timeout_when_background_speech_never_stops(mock_server: MockGptLiveServer) -> None:
    async def scenario() -> _Recorder:
        p = gpt_live.GptLiveProvider(_cfg(mock_server.url, instructions="[mock:talk-over]", opening=OPENING))
        ch = _Recorder()
        task = asyncio.ensure_future(p.run(ch, SessionStats()))
        assert await _wait_for(ch, ("response.started", 1), 5)
        await asyncio.sleep(0.3)

        async def background() -> None:  # continuous loud "background voices" in real time: no turn end
            for _ in range(200):
                await ch.q.put(Inbound(audio=LOUD))
                await asyncio.sleep(0.02)

        await background()
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        await task
        return ch

    ch = asyncio.run(scenario())
    clear = ch.log.index(("playback.clear", 1))
    after = ch.log[clear + 1 :]
    assert ("input.speech_stopped", None) not in after  # the local VAD never reported a turn end
    released = [d for k, d in ch.traces if k == "SUPPRESSION_RELEASED"]
    assert released and released[0]["reason"] == "TIMEOUT"
    assert 1400 <= released[0]["held_ms"] <= 1800  # 1.5 s bound (± one provider chunk and scheduling)
    resumed = [r for k, r in after if k == "audio"]
    assert resumed and all(r is not None and r >= 2 for r in resumed)  # heard again, as a new response
    rel = after.index(("trace:SUPPRESSION_RELEASED", None))
    assert not any(k == "audio" for k, _ in after[:rel])  # nothing reached the browser while suppressed


# ---- 4. release rules with a fake clock (deterministic) -----------------------------------------------------------
class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t


def _unit(monkeypatch: pytest.MonkeyPatch, suppress_max_s: float = 1.5) -> tuple[Any, _Recorder, _Clock]:
    clock = _Clock()
    monkeypatch.setattr(gpt_live, "time", clock)
    p = gpt_live.GptLiveProvider(_cfg("ws://127.0.0.1:1", suppress_max_s=suppress_max_s))
    ch = _Recorder()
    p._channel, p._stats = ch, SessionStats()
    return p, ch, clock


CHUNK = b"\x01\x00" * 1600  # 100 ms of 16 kHz PCM16


def test_new_reply_after_a_gap_releases_suppression_but_the_tail_is_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    p, ch, clock = _unit(monkeypatch, suppress_max_s=5.0)

    async def scenario() -> None:
        await p._audio_out(CHUNK)  # response 1 playing
        await p._barge_in()
        for _ in range(3):  # the interrupted reply's tail, 100 ms apart: dropped
            clock.t += 0.1
            await p._audio_out(CHUNK)
        clock.t += 0.7  # gap ≥ RESPONSE_GAP_S, then audio resumes: a new reply
        await p._audio_out(CHUNK)

    asyncio.run(scenario())
    assert [r for k, r in ch.log if k == "audio"][-1] == 2
    tail = ch.log[ch.log.index(("playback.clear", 1)) + 1 : ch.log.index(("trace:SUPPRESSION_RELEASED", None))]
    assert not any(k == "audio" for k, _ in tail)
    assert [d["reason"] for k, d in ch.traces if k == "SUPPRESSION_RELEASED"] == ["NEW_RESPONSE"]


def test_a_gap_before_any_dropped_tail_does_not_release_early(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider audio arrives faster than real time: a gap before the barge-in proves nothing about a new reply."""
    p, ch, clock = _unit(monkeypatch, suppress_max_s=1.5)

    async def scenario() -> None:
        await p._audio_out(CHUNK)
        clock.t += 1.0
        await p._barge_in()
        clock.t += 0.1
        await p._audio_out(CHUNK)  # first audio after the barge-in: the tail — dropped
        clock.t += 0.1
        await p._audio_out(CHUNK)  # still the tail
        clock.t += 1.4  # 1.6 s since the barge-in
        await p._audio_out(CHUNK)  # released by the bound

    asyncio.run(scenario())
    assert [d["reason"] for k, d in ch.traces if k == "SUPPRESSION_RELEASED"] == ["TIMEOUT"]
    responses = [r for k, r in ch.log if k == "audio"]
    assert sorted(set(responses)) == [1, 2] and responses == sorted(responses)  # tail dropped, then a new reply


def test_turn_end_still_releases_and_the_bound_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from app.voice import mock as voice_mock

    p, ch, clock = _unit(monkeypatch)

    class _Vad:
        def __init__(self) -> None:
            self.calls = 0

        def update(self, frame: bytes, *, agent_speaking: bool) -> str | None:
            self.calls += 1
            return {1: "speech_started", 2: "speech_stopped"}.get(self.calls)

    monkeypatch.setattr(gpt_live, "Vad", _Vad)
    sent: list[dict[str, Any]] = []

    async def fake_send(event: dict[str, Any]) -> bool:
        sent.append(event)
        return True

    p._send = fake_send  # type: ignore[method-assign]

    async def scenario() -> None:
        await p._audio_out(CHUNK)
        p._play_until = clock.t + 5  # the browser is still playing response 1
        for frame in (LOUD, QUIET):
            await ch.q.put(Inbound(audio=frame))
        await ch.q.put(Inbound(event={"type": "session.stop"}))
        assert await p._uplink() == "STOPPED_BY_USER"

    asyncio.run(scenario())
    assert ("playback.clear", 1) in ch.log
    assert [d["reason"] for k, d in ch.traces if k == "SUPPRESSION_RELEASED"] == ["TURN_END"]
    assert voice_mock.Vad is not _Vad  # the real VAD is untouched outside this test
    for bad in (0.4, 5.5):
        with pytest.raises(ValueError, match="VOICE_LAB_SUPPRESS_MAX_S"):
            gpt_live.check_urls(
                SimpleNamespace(
                    voice_lab_gpt_live_url=gpt_live.OFFICIAL_URL,
                    voice_lab_gpt_live_mock_url=None,
                    voice_lab_close_timeout_s=5.0,
                    voice_lab_start_timeout_s=10.0,
                    voice_lab_suppress_max_s=bad,
                    voice_lab_azure_openai_endpoint=None,
                    voice_lab_azure_openai_deployment=None,
                    voice_lab_azure_price_usd_per_min=None,
                    app_env="test",
                )
            )


# ---- 5. the opening instruction is part of the versioned prompt ------------------------------------------------------
def _body(**over: Any) -> dict[str, Any]:
    return {
        "name": "Opening prompt",
        "system_prompt": "You are a synthetic test voice.",
        "turn_instructions": [],
        "provider": "GPT_LIVE_MOCK",
        "model": "gpt-live-1",
        "voice": "marin",
        **over,
    }


def test_opening_instruction_is_versioned_in_the_prompt_sha_and_validated(user_c: TestClient) -> None:
    p1 = post(user_c, "/prompts", _body(), 201)
    v1 = p1["versions"][0]
    assert v1["opening_instruction"] is None and "opening_instruction" not in v1["parameters"]
    p2 = post(user_c, f"/prompts/{p1['id']}/versions", _body(opening_instruction=f"  {OPENING}  "))
    v2 = p2["versions"][0]
    assert v2["version_no"] == 2 and v2["opening_instruction"] == OPENING
    assert v2["parameters"]["opening_instruction"] == OPENING and v2["sha256"] != v1["sha256"]
    assert p2["versions"][1]["sha256"] == v1["sha256"] and p2["versions"][1]["opening_instruction"] is None
    same = refused(user_c, f"/prompts/{p1['id']}/versions", _body(opening_instruction=OPENING))
    assert same["code"] == "NO_CHANGE"
    # the same text given through parameters is the same configuration
    alias = refused(user_c, f"/prompts/{p1['id']}/versions", _body(parameters={"opening_instruction": OPENING}))
    assert alias["code"] == "NO_CHANGE"
    assert refused(user_c, "/prompts", _body(opening_instruction="x" * 501), 422)
    long_param = refused(user_c, "/prompts", _body(parameters={"opening_instruction": "x" * 501}), 422)
    assert long_param["code"] == "OPENING_TOO_LONG"
    mock_only = refused(
        user_c,
        "/prompts",
        _body(provider="MOCK", model="mock-fixed-message-1", voice="synthetic-fixed", opening_instruction=OPENING),
        422,
    )
    assert mock_only["code"] == "OPENING_NOT_SUPPORTED"
    assert lab.opening_instruction({"parameters": {"opening_instruction": 5}}) == ""
