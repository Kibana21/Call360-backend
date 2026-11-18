"""GPT-Live provider adapter (S1-E.2) behind the S1-A ``VoiceProvider`` protocol — Voice Lab only.

Protocol (official documentation read 2026-11-18; ``Call360-specs/docs/integrations/GPT_LIVE_PROTOCOL_NOTES.md``):
primary WebSocket ``wss://api.openai.com/v1/live/sessions`` with ``Authorization: Bearer`` (backend only);
``session.start`` → ``session.started``; ``session.input_audio.append`` / ``session.output_audio.delta`` (raw PCM16,
16 kHz — the browser format, so nothing is resampled); ``session.input_audio.mute|unmute``;
``session.instructions.append``; client delegation (``session.delegation.created`` → ``session.commentary.append``);
``session.usage.updated`` and ``session.closed`` (usage seconds); ``session.close``; ``error``.

Where the protocol is silent (no speech-started, cancel, truncate or output-done events), the adapter applies the
client-side policy the documentation describes: the S1-A local VAD detects the caller's speech, clears browser playback
and drops provider audio until the caller's turn ends. Response boundaries are inferred from audio gaps.

Cost safety: the adapter never decides whether it may connect — ``app.voice.lab`` does (paid switch, single-use
smoke-test authorisation, budget reservation). The adapter only connects to an allowed URL, enforces the duration it
is given on the server, always sends ``session.close`` (timeout, stop, emergency stop, browser disconnect, error) and
reports termination as CONFIRMED only when ``session.closed`` arrives; otherwise UNCONFIRMED, and the reservation is
retained. Delegation answers are deterministic Python text — no LLM, tool, backend model or network call.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from app.voice.live_providers import resample
from app.voice.mock import Vad
from app.voice.provider import FRAME_BYTES, FRAME_MS, SAMPLE_RATE, SessionStats, VoiceChannel

log = logging.getLogger("call360.gpt_live")
OFFICIAL_HOST = "api.openai.com"
OFFICIAL_URL = "wss://api.openai.com/v1/live/sessions"
MODEL = "gpt-live-1"
AUDIO_FORMAT = {"type": "audio/pcm", "rate": SAMPLE_RATE}
# Built-in voices listed by the live guide's table (the API reference enumerates a superset). Default "marin".
VOICES = (
    "marin", "quartz", "ripple", "vesper", "willow", "stone", "gleam", "meridian", "bossa", "tempo", "beacon", "delta",
    "cinder", "nuri", "juni", "flitz", "brise", "sillage", "nira", "harema", "shida", "noeul",
)  # fmt: skip
APPEND_FRAMES = 5  # 100 ms of caller audio per session.input_audio.append
RESPONSE_GAP_S = 0.6  # provider audio resuming after this silence starts a new response
RESPONSE_DONE_S = 0.8
START_TIMEOUT_S = 10.0
MAX_INVALID_EVENTS = 100
INSTRUCTION_MAX_CHARS = 1500  # well inside the documented 500-token limit for plain English
SGT = ZoneInfo("Asia/Singapore")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class GptLiveError(Exception):
    pass


def _loopback(url: str) -> bool:
    u = urlparse(url)
    return u.scheme in ("ws", "wss") and (u.hostname or "") in LOOPBACK


def allowed_url(url: str, *, app_env: str, mock: bool, vendor: str = "OPENAI") -> bool:
    """Connection-time guard (see ``app.voice.live_providers.allowed``)."""
    from app.voice import live_providers as lp

    return lp.allowed(url, vendor=vendor, app_env=app_env, mock=mock)


def _allowed_openai(url: str, *, app_env: str, mock: bool) -> bool:
    """The official endpoint, or a loopback mocked protocol server. In APP_ENV=test only loopback is allowed — the
    official endpoint is refused even if a key were configured, so no automated test can make a paid call."""
    if mock or app_env == "test":
        return _loopback(url)
    u = urlparse(url)
    if u.scheme == "wss" and u.hostname == OFFICIAL_HOST and u.path.startswith("/v1/live/sessions"):
        return True
    return False


def check_urls(settings: Any) -> None:
    url = settings.voice_lab_gpt_live_url
    official = _allowed_openai(url, app_env="local", mock=False)
    if not (official or (settings.app_env == "test" and _loopback(url))):
        raise ValueError("VOICE_LAB_GPT_LIVE_URL must be the official GPT-Live endpoint (loopback only in tests)")
    from app.voice import live_providers as lp

    lp.check(settings)
    if settings.voice_lab_gpt_live_mock_url and not allowed_url(
        settings.voice_lab_gpt_live_mock_url, app_env=settings.app_env, mock=True
    ):
        raise ValueError("VOICE_LAB_GPT_LIVE_MOCK_URL must be a loopback ws:// URL")
    if not 1.0 <= settings.voice_lab_close_timeout_s <= 30.0:
        raise ValueError("VOICE_LAB_CLOSE_TIMEOUT_S must be between 1 and 30")
    if not 2.0 <= settings.voice_lab_start_timeout_s <= 30.0:
        raise ValueError("VOICE_LAB_START_TIMEOUT_S must be between 2 and 30")


# ---- deterministic delegation (no LLM, no tool, no network) --------------------------------------------------------
def delegate_reply(last_caller_text: str, n: int, now: datetime | None = None) -> str:
    """The backend's answer to a client delegation. GPT-Live sends no task text, so the request is reconstructed from
    the latest caller transcript; replies are fixed synthetic sentences."""
    t = last_caller_text.lower()
    if "time" in t:
        at = (now or datetime.now(SGT)).astimezone(SGT).strftime("%H:%M")
        return f"Synthetic backend result {n}: the time in Singapore is {at}."
    if any(w in t for w in ("policy", "premium", "account", "payment")):
        return f"Synthetic backend result {n}: Voice Lab has no policy data; this is a synthetic test."
    return f"Synthetic backend result {n}: request received; Voice Lab performs no lookup."


@dataclass
class LiveConfig:
    url: str
    headers: dict[str, str]  # secret authentication headers: never logged, returned or persisted
    model: str
    voice: str
    instructions: str
    turn_instructions: list[str]
    max_duration_s: float
    close_timeout_s: float = 5.0
    start_timeout_s: float = START_TIMEOUT_S
    wire_rate: int = SAMPLE_RATE  # GPT-Live audio rate on the wire; browser audio is always 16 kHz
    store: bool | None = False  # None: omit (Azure's strict session object does not list ``store``)


@dataclass
class Outcome:
    connected: bool = False
    started: bool = False
    provider_session_id: str | None = None
    expires_at: int | None = None
    termination: str = "NOT_STARTED"  # NOT_STARTED | CONFIRMED | UNCONFIRMED
    close_reason: str | None = None
    usage_seconds: float | None = None  # last cumulative value seen
    usage_confirmed: bool = False  # from session.closed
    input_transcript: list[str] = field(default_factory=list)
    output_transcript: list[str] = field(default_factory=list)
    delegations: int = 0
    instructions_sent: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    invalid_events: int = 0
    unknown_events: set[str] = field(default_factory=set)
    close_sent: bool = False
    send_failures: int = 0


class Connection(Protocol):
    async def send(self, message: str) -> None: ...
    async def recv(self) -> str | bytes: ...
    async def close(self) -> None: ...


Connector = Callable[[str, dict[str, str]], Awaitable[Connection]]


class _RedactAuthorization(logging.Filter):
    """Defence in depth: no log record may carry a bearer credential."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        low = msg.lower()
        if "bearer " in low or "authorization" in low or "api-key" in low:
            record.msg, record.args = "[redacted: authorization header]", ()
        return True


_WS_LOG = logging.getLogger("call360.gpt_live.transport")
_WS_LOG.setLevel(logging.INFO)  # never DEBUG: the websockets client logs request headers at DEBUG level
_WS_LOG.addFilter(_RedactAuthorization())


async def default_connect(url: str, headers: dict[str, str]) -> Connection:
    import websockets

    ws = await websockets.connect(
        url, additional_headers=headers, max_size=4 * 1024 * 1024, open_timeout=START_TIMEOUT_S, logger=_WS_LOG
    )
    return ws


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _event_id() -> str:
    return f"c360_{uuid.uuid4().hex[:20]}"


class GptLiveProvider:
    """One GPT-Live session relayed to one browser channel."""

    name = "GPT_LIVE"

    def __init__(self, cfg: LiveConfig, *, connect: Connector = default_connect, label: str = "GPT_LIVE") -> None:
        self.cfg, self.connect, self.name = cfg, connect, label
        self.outcome = Outcome()
        self._ws: Connection | None = None
        self._closed_evt = asyncio.Event()
        self._started_evt = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._response = 0
        self._play_until = 0.0
        self._last_audio = 0.0
        self._in_response = False
        self._suppress = False
        self._partial = b""
        self._user_turns = 0
        self._channel: VoiceChannel | None = None
        self._stats: SessionStats | None = None
        self._browser_gone = False
        self._term_task: asyncio.Future[None] | None = None
        self.endpoint_info: dict[str, Any] = {}

    # ---- helpers ----------------------------------------------------------------------------------------------------
    async def _trace(self, kind: str, **details: Any) -> None:
        tr = getattr(self._channel, "trace", None)
        if tr is not None:
            with contextlib.suppress(Exception):
                await tr(kind, "PROVIDER", **details)

    async def _send(self, event: dict[str, Any]) -> bool:
        """Send to the provider; a failure (e.g. the provider already closed) is recorded, never mistaken for the
        browser leaving — the reader keeps reading, because ``session.closed`` may still be on its way."""
        if self._ws is None:
            return False
        try:
            async with self._send_lock:
                await self._ws.send(json.dumps(event))
            return True
        except Exception:  # noqa: BLE001
            self.outcome.send_failures += 1
            return False

    def _speaking(self) -> bool:
        return time.monotonic() < self._play_until

    # ---- lifecycle --------------------------------------------------------------------------------------------------
    async def run(self, channel: VoiceChannel, stats: SessionStats) -> None:
        self._channel, self._stats = channel, stats
        headers = dict(self.cfg.headers)
        try:
            self._ws = await asyncio.wait_for(self.connect(self.cfg.url, headers), timeout=self.cfg.start_timeout_s)
        except Exception as exc:  # noqa: BLE001 — no connection: nothing can have been billed
            stats.end_reason = "PROVIDER_CONNECT_FAILED"
            await self._trace("PROVIDER_CONNECT_FAILED", error=type(exc).__name__)
            return
        self.outcome.connected = True
        down = asyncio.ensure_future(self._downlink())
        up: asyncio.Future[str] | None = None
        timer: asyncio.Future[None] | None = None
        try:
            await self._send(
                {
                    "type": "session.start",
                    "event_id": _event_id(),
                    "session": {
                        "model": self.cfg.model,
                        "instructions": self.cfg.instructions,
                        "audio": {
                            "format": {"type": "audio/pcm", "rate": self.cfg.wire_rate},
                            "output": {"voice": self.cfg.voice},
                        },
                        "delegation": {"type": "client"},
                        **({"store": self.cfg.store} if self.cfg.store is not None else {}),
                    },
                }
            )
            started = asyncio.ensure_future(self._started_evt.wait())
            first: set[asyncio.Future[Any]] = {started, down}
            done, _ = await asyncio.wait(first, timeout=self.cfg.start_timeout_s, return_when=asyncio.FIRST_COMPLETED)
            if started not in done:
                started.cancel()
                stats.end_reason = "PROVIDER_START_FAILED"
                return
            up = asyncio.ensure_future(self._uplink())
            timer = asyncio.ensure_future(asyncio.sleep(self.cfg.max_duration_s))
            watchdog = asyncio.ensure_future(self._response_watchdog())
            try:
                waits: set[asyncio.Future[Any]] = {up, down, timer}
                done, _ = await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
            finally:
                watchdog.cancel()
            if timer in done:
                stats.end_reason = "MAX_DURATION"
            elif up in done:
                stats.end_reason = up.result()
            elif down in done and stats.end_reason == "UNKNOWN":
                if self._browser_gone:
                    stats.end_reason = "DISCONNECTED"
                else:
                    stats.end_reason = "PROVIDER_PROTOCOL_ERROR" if down.exception() else "PROVIDER_ENDED"
        finally:
            for t in (up, timer):
                if t is not None and not t.done():
                    t.cancel()
            self._term_task = asyncio.ensure_future(self._terminate(down))
            await asyncio.shield(self._term_task)

    async def _terminate(self, down: asyncio.Future[None]) -> None:
        """Always ask the provider to close and wait for its confirmation (bounded)."""
        reader = down
        try:
            if not self._closed_evt.is_set() and self.outcome.connected:
                if down.done():  # e.g. a protocol error ended the reader: read again while the session closes
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        down.result()
                    reader = asyncio.ensure_future(self._downlink())
                if await self._send({"type": "session.close", "event_id": _event_id()}):
                    self.outcome.close_sent = True
                    await self._trace("CLOSE_SENT")
                else:
                    await self._trace("CLOSE_NOT_SENT", reason="the provider connection no longer accepts messages")
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._closed_evt.wait(), timeout=self.cfg.close_timeout_s)
        finally:
            for t in {down, reader}:
                if not t.done():
                    t.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
            if self._ws is not None:
                with contextlib.suppress(Exception):
                    await self._ws.close()
            if self._closed_evt.is_set():
                self.outcome.termination = "CONFIRMED"
            elif self.outcome.connected:
                # The session may exist (or have been billed) even without session.started: never assume zero.
                self.outcome.termination = "UNCONFIRMED"
            await self._trace(
                "PROVIDER_TERMINATION",
                termination=self.outcome.termination,
                close_reason=self.outcome.close_reason,
                usage_seconds=self.outcome.usage_seconds,
                usage_confirmed=self.outcome.usage_confirmed,
            )

    async def finished(self) -> None:
        """Wait for the termination step (also when the caller's task was cancelled mid-close)."""
        if self._term_task is not None:
            await asyncio.shield(self._term_task)

    # ---- browser → provider ------------------------------------------------------------------------------------------
    async def _uplink(self) -> str:
        assert self._channel is not None and self._stats is not None
        vad = Vad()
        batch = b""
        while True:
            msg = await self._channel.receive()
            if msg is None:
                return "DISCONNECTED"
            if msg.event is not None:
                kind = msg.event.get("type")
                if kind == "session.stop":
                    return str(msg.event.get("reason") or "STOPPED_BY_USER")
                if kind == "input.mute":
                    muted = bool(msg.event.get("muted"))
                    await self._send(
                        {"type": f"session.input_audio.{'mute' if muted else 'unmute'}", "event_id": _event_id()}
                    )
                    continue
                if kind == "lab.instruction":
                    await self.append_instruction(str(msg.event.get("text") or ""), source="PLAYGROUND")
                continue
            if msg.audio is None:
                continue
            self._stats.frames_in += 1
            change = vad.update(msg.audio, agent_speaking=self._speaking())
            if change == "speech_started":
                if self._speaking() or self._in_response:
                    await self._barge_in()
                await self._channel.send_event({"type": "input.speech_started"})
            elif change == "speech_stopped":
                self._user_turns += 1
                self._stats.user_turns += 1
                self._suppress = False
                await self._channel.send_event({"type": "input.speech_stopped"})
                k = self._user_turns
                if k <= len(self.cfg.turn_instructions) and self.cfg.turn_instructions[k - 1].strip():
                    await self.append_instruction(self.cfg.turn_instructions[k - 1], source=f"TURN_{k}")
            batch += msg.audio
            if len(batch) >= APPEND_FRAMES * FRAME_BYTES:
                wire = resample(batch, SAMPLE_RATE, self.cfg.wire_rate)
                await self._send({"type": "session.input_audio.append", "audio": base64.b64encode(wire).decode()})
                batch = b""

    async def append_instruction(self, text: str, *, source: str) -> None:
        text = text.strip()[:INSTRUCTION_MAX_CHARS]
        if not text:
            return
        eid = _event_id()
        await self._send(
            {"type": "session.instructions.append", "event_id": eid, "delegation_id": None, "content": text}
        )
        self.outcome.instructions_sent += 1
        await self._trace("INSTRUCTION_APPENDED", origin=source, client_event_id=eid, chars=len(text))

    async def _barge_in(self) -> None:
        assert self._channel is not None and self._stats is not None
        self._stats.barge_ins += 1
        self._suppress = True  # drop provider audio until the caller's turn ends (it "may keep speaking briefly")
        self._play_until = 0.0
        await self._channel.send_event({"type": "playback.clear", "response": self._response, "reason": "barge_in"})
        if self._in_response:
            self._in_response = False
            await self._channel.send_event({"type": "response.done", "response": self._response, "completed": False})

    # ---- provider → browser ------------------------------------------------------------------------------------------
    async def _downlink(self) -> None:
        assert self._ws is not None
        while True:
            try:
                raw = await self._ws.recv()
            except Exception:  # noqa: BLE001 — connection closed or dropped
                if not self._closed_evt.is_set():
                    await self._trace("PROVIDER_CONNECTION_LOST")
                return
            try:
                ev = json.loads(raw)
                kind = ev["type"] if isinstance(ev, dict) else None
                if not isinstance(kind, str):
                    raise ValueError("no type")
            except (ValueError, KeyError, TypeError):
                await self._invalid("not a JSON event with a type")
                continue
            try:
                await self._handle(kind, ev)
            except GptLiveError as exc:
                await self._invalid(str(exc))
            except Exception:  # noqa: BLE001 — sending to the browser failed: the caller has gone
                # Keep reading the provider (session.closed and usage may still arrive); stop forwarding.
                self._browser_gone = True
            if self._closed_evt.is_set():
                return

    async def _invalid(self, why: str) -> None:
        self.outcome.invalid_events += 1
        if self.outcome.invalid_events <= 5:
            await self._trace("INVALID_PROVIDER_EVENT", reason=why[:120])
        if self.outcome.invalid_events > MAX_INVALID_EVENTS:
            raise GptLiveError("too many invalid provider events")

    async def _handle(self, kind: str, ev: dict[str, Any]) -> None:
        assert self._channel is not None and self._stats is not None
        if kind == "session.output_audio.delta":
            try:
                pcm = base64.b64decode(str(ev.get("delta") or ""), validate=True)
            except ValueError as exc:
                raise GptLiveError("output audio is not base64") from exc
            await self._audio_out(resample(pcm, self.cfg.wire_rate, SAMPLE_RATE))
        elif kind == "session.started":
            s = _obj(ev.get("session"))
            self.outcome.started = True
            self.outcome.provider_session_id = str(s.get("id") or "") or None
            self.outcome.expires_at = s.get("expires_at") if isinstance(s.get("expires_at"), int) else None
            await self._trace(
                "PROVIDER_SESSION_STARTED",
                provider_session_id=self.outcome.provider_session_id,
                expires_at=self.outcome.expires_at,
                model=s.get("model"),
            )
            self._started_evt.set()
        elif kind == "session.usage.updated":
            sec = _obj(ev.get("usage")).get("seconds")
            if isinstance(sec, int | float) and sec >= 0:
                self.outcome.usage_seconds = float(sec)  # cumulative: replace, never sum
                await self._trace("USAGE_UPDATED", usage_seconds=float(sec))
            else:
                raise GptLiveError("usage without seconds")
        elif kind == "session.closed":
            sec = _obj(ev.get("usage")).get("seconds")
            self.outcome.close_reason = str(ev.get("reason") or "unknown")
            if isinstance(sec, int | float) and sec >= 0:
                self.outcome.usage_seconds = float(sec)
                self.outcome.usage_confirmed = True
            await self._trace(
                "PROVIDER_SESSION_CLOSED", reason=self.outcome.close_reason, usage_seconds=self.outcome.usage_seconds
            )
            if not self.outcome.close_sent and self._stats.end_reason == "UNKNOWN":
                self._stats.end_reason = f"PROVIDER_CLOSED_{self.outcome.close_reason.upper()}"[:40]
            self._closed_evt.set()
        elif kind in ("session.input_transcript.delta", "session.output_transcript.delta"):
            text = str(ev.get("delta") or "")
            side = "input" if kind.startswith("session.input") else "output"
            (self.outcome.input_transcript if side == "input" else self.outcome.output_transcript).append(text)
            await self._trace(
                "TRANSCRIPT_DELTA", side=side, chars=len(text), start_ms=ev.get("start_ms"), end_ms=ev.get("end_ms")
            )  # text is kept in the purgeable transcript, not the trace
        elif kind == "session.delegation.created":
            d = _obj(ev.get("delegation"))
            did = str(d.get("id") or "")
            if not did:
                raise GptLiveError("delegation without id")
            self.outcome.delegations += 1
            caller = " ".join(self.outcome.input_transcript[-20:])
            reply = delegate_reply(caller, self.outcome.delegations)
            await self._trace(
                "DELEGATION_CREATED", delegation_id=did, target=d.get("target"), offset_ms=ev.get("offset_ms")
            )
            eid = _event_id()
            sent = await self._send(
                {"type": "session.commentary.append", "event_id": eid, "delegation_id": did, "content": reply}
            )
            await self._trace(
                "DELEGATION_ANSWERED" if sent else "DELEGATION_ANSWER_NOT_SENT",
                delegation_id=did,
                client_event_id=eid,
                responder="DETERMINISTIC_PYTHON/1",
                chars=len(reply),
            )
        elif kind == "error":
            err = _obj(ev.get("error"))
            info = {
                k: str(err.get(k))[:200]
                for k in ("type", "code", "message", "param", "client_event_id")
                if err.get(k) is not None
            }
            self.outcome.errors.append(info)
            await self._trace("PROVIDER_ERROR", **info)
        elif kind in (
            "session.instructions.appended",
            "session.commentary.appended",
            "session.thinking.appended",
            "session.input_audio.muted",
            "session.input_audio.unmuted",
            "session.updated",
            "info",
        ):
            await self._trace(
                "PROVIDER_ACK",
                event=kind,
                client_event_id=ev.get("client_event_id"),
                start_ms=ev.get("start_ms"),
                end_ms=ev.get("end_ms"),
            )
        elif kind not in self.outcome.unknown_events:
            self.outcome.unknown_events.add(kind)
            await self._trace("UNHANDLED_PROVIDER_EVENT", event=kind[:64])

    async def _audio_out(self, pcm: bytes) -> None:
        assert self._channel is not None and self._stats is not None
        if self._suppress or self._browser_gone:
            return  # after a barge-in, until the caller's turn ends
        now = time.monotonic()
        if not self._in_response or now - self._last_audio > RESPONSE_GAP_S and not self._speaking():
            self._response += 1
            self._in_response = True
            self._stats.responses += 1
            await self._channel.send_event({"type": "response.started", "response": self._response})
        self._last_audio = now
        data = self._partial + pcm
        whole = len(data) - len(data) % FRAME_BYTES
        self._partial = data[whole:]
        for i in range(0, whole, FRAME_BYTES):
            self._play_until = max(self._play_until, time.monotonic()) + FRAME_MS / 1000
            await self._channel.send_audio(self._response, data[i : i + FRAME_BYTES])

    async def _response_watchdog(self) -> None:
        assert self._channel is not None and self._stats is not None
        while True:
            await asyncio.sleep(0.1)
            if self._in_response and not self._speaking() and time.monotonic() - self._last_audio > RESPONSE_DONE_S:
                self._in_response = False
                self._stats.completed_responses += 1
                await self._channel.send_event({"type": "response.done", "response": self._response, "completed": True})


async def close_orphan(
    base_url: str,
    headers: dict[str, str],
    provider_session_id: str,
    *,
    timeout_s: float,
    connect: Connector = default_connect,
) -> tuple[bool, float | None, str | None]:
    """A manager's explicit close of a session whose termination was not confirmed: attach on the sideband URL, send
    ``session.close`` and wait for ``session.closed``. Returns (confirmed, usage seconds, reason)."""
    url = f"{base_url.rstrip('/')}/{provider_session_id}/attach"
    ws = await asyncio.wait_for(connect(url, headers), timeout=START_TIMEOUT_S)
    try:
        await ws.send(json.dumps({"type": "session.close", "event_id": _event_id()}))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - time.monotonic()))
            with contextlib.suppress(ValueError, TypeError):
                ev = json.loads(raw)
                if isinstance(ev, dict) and ev.get("type") == "session.closed":
                    sec = _obj(ev.get("usage")).get("seconds")
                    return True, float(sec) if isinstance(sec, int | float) else None, str(ev.get("reason") or "")
        return False, None, None
    except (TimeoutError, Exception):  # noqa: BLE001
        return False, None, None
    finally:
        with contextlib.suppress(Exception):
            await ws.close()
