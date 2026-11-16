"""Voice provider abstraction (ADR-0003 §4; S1-A).

A provider runs one live conversation over a ``VoiceChannel`` that carries 16 kHz mono PCM16 audio both ways plus
JSON control events. S1-A ships ``MockVoiceProvider`` (keyless, server-side, fixed synthetic test speech); S1-E adds a
real provider behind the same protocol. A provider never decides questions, identity or compliance: the session
always reports ``identity_verification = NOT_PERFORMED`` and ``compliance_outcome = NOT_EVALUATED`` in S1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

SAMPLE_RATE = 16_000
FRAME_MS = 20
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000  # 320
FRAME_BYTES = FRAME_SAMPLES * 2  # PCM16


@dataclass(frozen=True)
class Inbound:
    """One message from the browser: ``audio`` (PCM16 bytes) or a control ``event``."""

    audio: bytes | None = None
    event: dict[str, Any] | None = None


class VoiceChannel(Protocol):
    async def receive(self) -> Inbound | None:
        """Next browser message, or ``None`` when the browser has gone (closed, dropped or timed out)."""

    async def send_audio(self, response: int, pcm: bytes) -> None:
        """One frame of provider speech, tagged with its response number so stale frames can be discarded."""

    async def send_event(self, event: dict[str, Any]) -> None: ...


@dataclass
class SessionStats:
    responses: int = 0
    completed_responses: int = 0
    barge_ins: int = 0
    user_turns: int = 0
    frames_in: int = 0
    end_reason: str = "UNKNOWN"


class VoiceProvider(Protocol):
    name: str

    async def run(self, channel: VoiceChannel, stats: SessionStats) -> None:
        """Run the conversation until the browser stops, disconnects or a limit is reached."""
