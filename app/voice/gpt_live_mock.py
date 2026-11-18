"""A mocked GPT-Live protocol server (S1-E.2) — loopback only, no model, no key check, no money.

It speaks the documented primary-WebSocket protocol (``GPT_LIVE_PROTOCOL_NOTES.md``) closely enough to exercise the
adapter: ``session.start`` → ``session.started``; paced ``session.output_audio.delta`` (the S1-A synthetic message
assets, 16 kHz) with ``session.output_transcript.delta``; an energy detector on ``session.input_audio.append`` that
stops the current utterance shortly after the caller starts speaking (the model "may keep speaking briefly") and emits
``session.input_transcript.delta`` when the caller's turn ends; ``session.delegation.created`` on the second caller
turn (client delegation), answered by ``session.commentary.append`` → ``…appended`` and spoken; acknowledgements for
instructions and mute; cumulative ``session.usage.updated`` every 2 s; ``session.close`` → ``session.closed`` with
usage seconds; the sideband ``…/{id}/attach`` close. Fault injection with markers in the session instructions:
``[mock:noclose]`` (ignore session.close), ``[mock:drop]`` (drop the connection after 2 s), ``[mock:error]`` (error and
invalid events), ``[mock:expire=N]`` (close with reason ``expired`` after N s), ``[mock:silent]`` (no greeting),
``[mock:delegate]`` (delegate on the first caller turn). It is a test double, not a description of model behaviour.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import math
import re
import time
import uuid
import wave
from array import array
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ASSETS = Path(__file__).parent / "assets"
RATE = 16000
CHUNK = RATE // 10 * 2  # 100 ms PCM16


def _wav(name: str) -> bytes:
    with wave.open(str(ASSETS / name)) as w:
        data: bytes = w.readframes(w.getnframes())
        return data


GREETING = (_wav("test_1.wav") + _wav("test_2.wav"), "Hello. This is a Call360 synthetic audio test. Please say hello.")
REPLY = (_wav("test_3.wav"), "You can interrupt me while I am speaking.")
COMMENTARY = _wav("test_4.wav")


def _rms(pcm: bytes) -> float:
    a = array("h")
    a.frombytes(pcm[: len(pcm) - len(pcm) % 2])
    if not a:
        return -120.0
    m = sum(x * x for x in a) / len(a)
    return 20 * math.log10(math.sqrt(m) / 32768) if m > 0 else -120.0


@dataclass
class MockSession:
    id: str
    started: float
    instructions: str
    closed: bool = False
    seen: list[str] = field(default_factory=list)

    def usage(self) -> float:
        return round(time.monotonic() - self.started, 1)


class MockGptLiveServer:
    """Run with ``await server.start()``; ``server.url`` is the primary endpoint. Records what it received."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host, self.port = host, port
        self.sessions: dict[str, MockSession] = {}
        self.connections = 0
        self.auth_headers: list[bool] = []
        self._server: Any = None

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}/v1/live/sessions"

    async def start(self) -> None:
        import websockets

        self._server = await websockets.serve(self._handler, self.host, self.port, max_size=4 * 1024 * 1024)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handler(self, ws: Any) -> None:
        self.connections += 1
        path = ws.request.path
        self.auth_headers.append(bool(ws.request.headers.get("Authorization")))
        m = re.fullmatch(r"/v1/live/sessions/([\w-]+)/attach", path)
        if m:
            await self._attach(ws, m.group(1))
        elif path == "/v1/live/sessions":
            await self._primary(ws)
        else:
            await ws.close(code=4404)

    async def _attach(self, ws: Any, sid: str) -> None:
        s = self.sessions.get(sid)
        async for raw in ws:
            ev = json.loads(raw)
            if ev.get("type") == "session.close" and s is not None and not s.closed:
                s.closed = True
                await ws.send(json.dumps(self._closed(s, "close_requested", ev.get("event_id"))))
                return

    def _closed(self, s: MockSession, reason: str, cid: str | None = None) -> dict[str, Any]:
        return {
            "type": "session.closed",
            "event_id": f"evt_{uuid.uuid4().hex[:10]}",
            "client_event_id": cid,
            "reason": reason,
            "session": {"id": s.id, "status": "active", "model": "gpt-live-1"},
            "usage": {"seconds": s.usage()},
        }

    async def _primary(self, ws: Any) -> None:
        first = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        cfg = first.get("session") or {}
        fmt = (cfg.get("audio") or {}).get("format") or {}
        if first.get("type") != "session.start" or cfg.get("model") != "gpt-live-1" or fmt.get("rate") != RATE:
            await ws.send(
                json.dumps(
                    {
                        "type": "error",
                        "event_id": "evt_err",
                        "error": {
                            "type": "invalid_request_error",
                            "code": "unknown_parameter",
                            "message": "mock: bad session.start",
                            "param": "session",
                            "client_event_id": first.get("event_id"),
                        },
                    }
                )
            )
            await ws.close()
            return
        s = MockSession(f"live_mock_{uuid.uuid4().hex[:12]}", time.monotonic(), str(cfg.get("instructions") or ""))
        self.sessions[s.id] = s
        marks = s.instructions
        await ws.send(
            json.dumps(
                {
                    "type": "session.started",
                    "event_id": "evt_started",
                    "client_event_id": first.get("event_id"),
                    "session": {
                        "id": s.id,
                        "expires_at": int(time.time()) + 3600,
                        "status": "active",
                        "model": "gpt-live-1",
                    },
                }
            )
        )
        speaking: dict[str, Any] = {"task": None, "cut": False}
        lock = asyncio.Lock()

        async def send(ev: dict[str, Any]) -> None:
            async with lock:
                await ws.send(json.dumps(ev))

        async def speak(pcm: bytes, text: str) -> None:
            speaking["cut"] = False
            await send(
                {
                    "type": "session.output_transcript.delta",
                    "event_id": "evt_ot",
                    "delta": text,
                    "start_ms": 0,
                    "end_ms": 0,
                }
            )
            t0 = time.monotonic()
            for i in range(0, len(pcm), CHUNK):
                if speaking["cut"]:
                    return
                await send(
                    {"type": "session.output_audio.delta", "delta": base64.b64encode(pcm[i : i + CHUNK]).decode()}
                )
                await asyncio.sleep(max(0.0, t0 + (i // CHUNK + 1) * 0.1 - 0.2 - time.monotonic()))

        def say(pcm: bytes, text: str) -> None:
            if speaking["task"] is not None and not speaking["task"].done():
                speaking["task"].cancel()
            speaking["task"] = asyncio.ensure_future(speak(pcm, text))

        async def usage_loop() -> None:
            while not s.closed:
                await asyncio.sleep(2)
                await send(
                    {
                        "type": "session.usage.updated",
                        "event_id": "evt_usage",
                        "usage": {"seconds": s.usage()},
                        "context_window": {"usage_ratio": 0.01},
                    }
                )

        async def faults() -> None:
            if "[mock:error]" in marks:
                await asyncio.sleep(0.3)
                await send(
                    {
                        "type": "error",
                        "event_id": "evt_e1",
                        "error": {"type": "server_error", "code": None, "message": "mock transient error"},
                    }
                )
                async with lock:
                    await ws.send("not json")
                    await ws.send(json.dumps({"no": "type"}))
                    await ws.send(json.dumps({"type": "session.mock_unknown"}))
            if m := re.search(r"\[mock:expire=(\d+)\]", marks):
                await asyncio.sleep(int(m.group(1)))
                s.closed = True
                await send(self._closed(s, "expired"))
                await ws.close()
            if "[mock:drop]" in marks:
                await asyncio.sleep(2)
                ws.transport.abort() if hasattr(ws, "transport") else await ws.close()

        bg = [asyncio.ensure_future(usage_loop()), asyncio.ensure_future(faults())]
        if "[mock:silent]" not in marks:
            say(*GREETING)
        loud = quiet = turns = 0
        in_speech = False
        pending_delegation: str | None = None
        try:
            async for raw in ws:
                ev = json.loads(raw)
                kind = ev.get("type")
                s.seen.append(kind)
                cid = ev.get("event_id")
                if kind == "session.input_audio.append":
                    pcm = base64.b64decode(ev["audio"])
                    level = _rms(pcm)
                    if not in_speech:
                        loud = loud + 1 if level > -40 else 0
                        if loud >= 2:
                            in_speech, quiet = True, 0
                            await asyncio.sleep(0.2)  # "may keep speaking briefly after an interruption"
                            speaking["cut"] = True
                    else:
                        quiet = quiet + 1 if level < -50 else 0
                        if quiet >= 6:
                            in_speech, turns = False, turns + 1
                            await send(
                                {
                                    "type": "session.input_transcript.delta",
                                    "event_id": "evt_it",
                                    "delta": "(mock transcript of the caller's turn)",
                                    "start_ms": 0,
                                    "end_ms": 0,
                                }
                            )
                            if turns == 2 or ("[mock:delegate]" in marks and turns == 1):
                                pending_delegation = f"del_{uuid.uuid4().hex[:10]}"
                                await send(
                                    {
                                        "type": "session.delegation.created",
                                        "event_id": "evt_del",
                                        "offset_ms": int((time.monotonic() - s.started) * 1000),
                                        "delegation": {
                                            "id": pending_delegation,
                                            "type": "delegation",
                                            "target": "client",
                                        },
                                    }
                                )
                            else:
                                say(*REPLY)
                elif kind == "session.instructions.append":
                    await send(
                        {
                            "type": "session.instructions.appended",
                            "event_id": "evt_ia",
                            "client_event_id": cid,
                            "start_ms": 0,
                            "end_ms": 0,
                        }
                    )
                elif kind == "session.commentary.append":
                    await send(
                        {
                            "type": "session.commentary.appended",
                            "event_id": "evt_ca",
                            "client_event_id": cid,
                            "start_ms": 0,
                            "end_ms": 0,
                        }
                    )
                    if ev.get("delegation_id") == pending_delegation:
                        say(COMMENTARY, str(ev.get("content") or ""))
                elif kind in ("session.input_audio.mute", "session.input_audio.unmute"):
                    await send({"type": f"{kind}d", "event_id": "evt_m", "client_event_id": cid})
                elif kind == "session.close":
                    if "[mock:noclose]" in marks:
                        continue
                    s.closed = True
                    await send(self._closed(s, "close_requested", cid))
                    await ws.close()
                    return
                else:
                    await send(
                        {
                            "type": "error",
                            "event_id": "evt_unknown",
                            "error": {
                                "type": "invalid_request_error",
                                "code": "unknown_parameter",
                                "message": f"mock: unsupported client event {kind}",
                                "client_event_id": cid,
                            },
                        }
                    )
        except Exception:  # noqa: BLE001 — the connection ended
            import logging

            logging.getLogger("call360.gpt_live_mock").debug("mock connection ended", exc_info=True)
        finally:
            for t in [*bg, speaking["task"]]:
                if t is not None:
                    t.cancel()


async def serve_forever(host: str, port: int) -> None:
    srv = MockGptLiveServer(host, port)
    await srv.start()
    print(f"Mocked GPT-Live protocol server on {srv.url} (loopback, no model, no money)", flush=True)  # noqa: T201
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.Future()
