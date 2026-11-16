"""Keyless mock voice provider (S1-A).

It speaks only the owner-approved fixed synthetic test message (pre-generated audio in ``assets/``), listens with a
simple energy-based voice-activity detector, and supports barge-in: when the caller starts speaking while the mock is
speaking, playback stops at the next 20 ms frame and the browser is told to clear anything already queued. After the
caller finishes a turn, the mock replays the same fixed message. It asks no question, interprets nothing the caller
says, and makes no promise, verification or compliance statement.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import wave
from array import array
from pathlib import Path
from typing import Any

from app.voice.provider import FRAME_BYTES, FRAME_MS, SAMPLE_RATE, SessionStats, VoiceChannel

ASSETS = Path(__file__).parent / "assets"
FIXED_MESSAGE = (
    "Hello. This is a Call360 synthetic audio test.",
    "Please say hello to check your microphone.",
    "You can interrupt me while I am speaking.",
    "This test does not verify an insurance transaction.",
)
PREBUFFER_FRAMES = 5  # ~100 ms sent ahead of real time, so an interruption leaves at most this much queued
GAP_MS = 250


def load_message() -> bytes:
    """The fixed message as one PCM16 16 kHz mono buffer (sentences separated by short silences)."""
    pcm = b""
    for i in range(1, len(FIXED_MESSAGE) + 1):
        with wave.open(str(ASSETS / f"test_{i}.wav")) as w:
            assert (w.getframerate(), w.getnchannels(), w.getsampwidth()) == (SAMPLE_RATE, 1, 2)
            pcm += w.readframes(w.getnframes()) + b"\x00\x00" * (SAMPLE_RATE * GAP_MS // 1000)
    pad = (-len(pcm)) % FRAME_BYTES
    return pcm + b"\x00" * pad


def rms_dbfs(frame: bytes) -> float:
    samples = array("h")
    samples.frombytes(frame[: len(frame) - len(frame) % 2])
    if not samples:
        return -120.0
    mean = sum(s * s for s in samples) / len(samples)
    return 20 * math.log10(math.sqrt(mean) / 32768) if mean > 0 else -120.0


class Vad:
    """Energy VAD with an adaptive noise floor. While the mock is speaking it needs a louder, longer onset, so echo
    leaking past the browser's echo cancellation is less likely to be taken for an interruption."""

    def __init__(self) -> None:
        self.noise = -60.0
        self.active = False
        self.loud = 0
        self.quiet = 0

    def update(self, frame: bytes, *, agent_speaking: bool) -> str | None:
        level = rms_dbfs(frame)
        start_db, start_frames = (
            (max(-38.0, self.noise + 22), 5) if agent_speaking else (max(-48.0, self.noise + 14), 3)
        )
        if not self.active:
            if level > start_db:
                self.loud += 1
                if self.loud >= start_frames:
                    self.active, self.loud, self.quiet = True, 0, 0
                    return "speech_started"
            else:
                self.loud = 0
                self.noise = 0.95 * self.noise + 0.05 * max(level, -90.0)
            return None
        if level < max(-52.0, self.noise + 8):
            self.quiet += 1
            if self.quiet * FRAME_MS >= 600:
                self.active, self.quiet = False, 0
                return "speech_stopped"
        else:
            self.quiet = 0
        return None


class MockVoiceProvider:
    name = "MOCK"

    def __init__(self, message: bytes | None = None) -> None:
        self.message = message if message is not None else load_message()

    async def run(self, channel: VoiceChannel, stats: SessionStats) -> None:
        vad = Vad()
        playback: asyncio.Task[None] | None = None
        response = 0
        muted = False

        async def speak(n: int) -> None:
            loop = asyncio.get_running_loop()
            start = loop.time()
            frames = len(self.message) // FRAME_BYTES
            for i in range(frames):
                await channel.send_audio(n, self.message[i * FRAME_BYTES : (i + 1) * FRAME_BYTES])
                delay = start + (i + 1 - PREBUFFER_FRAMES) * FRAME_MS / 1000 - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
            stats.completed_responses += 1
            await channel.send_event({"type": "response.done", "response": n, "completed": True})

        async def start_response() -> None:
            nonlocal playback, response
            response += 1
            stats.responses += 1
            await channel.send_event({"type": "response.started", "response": response})
            playback = asyncio.create_task(speak(response))

        async def interrupt() -> None:
            nonlocal playback
            if playback is not None and not playback.done():
                playback.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await playback
                stats.barge_ins += 1
                await channel.send_event({"type": "playback.clear", "response": response, "reason": "barge_in"})
                await channel.send_event({"type": "response.done", "response": response, "completed": False})
            playback = None

        try:
            await start_response()
            while True:
                msg = await channel.receive()
                if msg is None:
                    stats.end_reason = stats.end_reason if stats.end_reason != "UNKNOWN" else "DISCONNECTED"
                    return
                if msg.event is not None:
                    kind = msg.event.get("type")
                    if kind == "session.stop":
                        stats.end_reason = str(msg.event.get("reason") or "STOPPED_BY_USER")
                        return
                    if kind == "input.mute":
                        muted = bool(msg.event.get("muted"))
                        if muted and vad.active:
                            vad.active = False
                            await channel.send_event({"type": "input.speech_stopped", "muted": True})
                    continue
                if msg.audio is None or muted:
                    continue
                stats.frames_in += 1
                speaking = playback is not None and not playback.done()
                change = vad.update(msg.audio, agent_speaking=speaking)
                if change == "speech_started":
                    await interrupt()
                    await channel.send_event({"type": "input.speech_started"})
                elif change == "speech_stopped":
                    stats.user_turns += 1
                    await channel.send_event({"type": "input.speech_stopped"})
                    await start_response()
        finally:
            if playback is not None and not playback.done():
                playback.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await playback


def describe() -> dict[str, Any]:
    return {"provider": MockVoiceProvider.name, "message": list(FIXED_MESSAGE), "sample_rate": SAMPLE_RATE}
