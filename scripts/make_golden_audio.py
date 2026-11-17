"""Generate the S1-D golden audio dataset (synthetic English speech with known text and timing).

macOS only: speech comes from the system ``say`` voices (synthetic, no real person), converted to 16 kHz mono PCM16.
Each clip is assembled from utterances placed after known silences, so the expected utterance times are measured
from the generated audio itself (energy onset/offset), not from any recogniser. Non-speech clips (silence, a tone,
noise) and degraded-speech clips (noise, very low level) test that nothing is invented and uncertainty is shown.

    uv run python scripts/make_golden_audio.py      # writes tests/fixtures/golden_audio/*.wav + golden.json

Re-running regenerates the files; ``golden.json`` records each file's SHA-256 so tests detect any change.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import wave
from pathlib import Path

import numpy as np

RATE = 16_000
OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "golden_audio"

# (clip id, expectation, voice, [(lead silence s, text)], post-processing)
CLIPS: list[tuple[str, str, str, list[tuple[float, str]], dict[str, float]]] = [
    ("g01_us_greeting", "SPEECH", "Samantha", [(0.5, "Good morning. I am calling about my policy renewal.")], {}),
    (
        "g02_gb_two_turns",
        "SPEECH",
        "Daniel",
        [(0.4, "Yes, I understand the policy."), (2.0, "Please call me back tomorrow afternoon.")],
        {},
    ),
    ("g03_au_question", "SPEECH", "Karen", [(0.6, "Can you tell me when my next payment is due?")], {}),
    (
        "g04_ie_statement",
        "SPEECH",
        "Moira",
        [(0.5, "I did not receive the product summary, and I would like it sent by email.")],
        {},
    ),
    (
        "g05_in_statement",
        "SPEECH",
        "Rishi",
        [(0.5, "I bought the savings plan last month through my financial adviser.")],
        {},
    ),
    (
        "g06_za_numbers",
        "SPEECH",
        "Tessa",
        [(0.5, "My policy number ends in four seven two nine and the premium is three hundred dollars.")],
        {},
    ),
    ("g07_us_noisy", "DEGRADED", "Samantha", [(0.5, "I am not sure which plan I bought.")], {"noise_snr_db": -6.0}),
    (
        "g08_gb_very_low",
        "DEGRADED",
        "Daniel",
        [(0.5, "Please send the documents to my home address.")],
        {"gain_db": -42.0, "noise_snr_db": 0.0},
    ),
    ("g09_silence", "NO_SPEECH", "", [], {"seconds": 4.0}),
    (
        "g12_us_buried",
        "DEGRADED",
        "Samantha",
        [(0.5, "Good morning. I am calling about my policy renewal.")],
        {"noise_snr_db": -10.0},
    ),
    ("g10_tone_bursts", "NO_SPEECH", "", [], {"seconds": 5.0, "tone_hz": 220.0}),
    ("g11_noise", "NO_SPEECH", "", [], {"seconds": 4.0, "noise_rms": 0.05}),
]


WRITTEN = {"g06_za_numbers": "My policy number ends in 4729 and the premium is 300 dollars."}


def tts(voice: str, words: str, tmp: Path) -> np.ndarray:
    aiff, wav = tmp / "u.aiff", tmp / "u.wav"
    subprocess.run(["say", "-v", voice, "-o", str(aiff), words], check=True)  # noqa: S603, S607 — fixed macOS tools
    subprocess.run(  # noqa: S603
        ["afconvert", "-f", "WAVE", "-d", f"LEI16@{RATE}", "-c", "1", str(aiff), str(wav)],  # noqa: S607
        check=True,
    )
    with wave.open(str(wav)) as w:
        assert (w.getframerate(), w.getnchannels(), w.getsampwidth()) == (RATE, 1, 2)
        return np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float32) / 32768.0


def bounds(x: np.ndarray) -> tuple[int, int]:
    """First and last 10 ms frame whose RMS exceeds 5 % of the utterance's peak frame RMS."""
    frames = x[: len(x) // 160 * 160].reshape(-1, 160)
    rms = np.sqrt((frames**2).mean(axis=1))
    on = np.nonzero(rms > 0.05 * rms.max())[0]
    return int(on[0]) * 160, int(on[-1] + 1) * 160


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(20261117)
    manifest = []
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for cid, expect, voice, utterances, post in CLIPS:
            audio = np.zeros(0, dtype=np.float32)
            expected = []
            for lead, words in utterances:
                u = tts(voice, words, tmp)
                lo, hi = bounds(u)
                u = u[lo:hi]
                audio = np.concatenate([audio, np.zeros(int(lead * RATE), dtype=np.float32)])
                start = len(audio)
                audio = np.concatenate([audio, u])
                expected.append(
                    {"text": words, "start_s": round(start / RATE, 2), "end_s": round(len(audio) / RATE, 2)}
                )
            if utterances:
                audio = np.concatenate([audio, np.zeros(int(0.6 * RATE), dtype=np.float32)])
            else:
                n = int(post["seconds"] * RATE)
                audio = np.zeros(n, dtype=np.float32)
                if "tone_hz" in post:  # 0.8 s bursts every 2 s
                    tt = np.arange(n) / RATE
                    gate = (tt % 2.0) < 0.8
                    audio = (0.3 * np.sin(2 * np.pi * post["tone_hz"] * tt) * gate).astype(np.float32)
                if "noise_rms" in post:
                    audio = rng.normal(0, post["noise_rms"], n).astype(np.float32)
            if "gain_db" in post:
                audio = audio * 10 ** (post["gain_db"] / 20)
            if "noise_snr_db" in post and utterances:
                speech = np.concatenate([audio[int(e["start_s"] * RATE) : int(e["end_s"] * RATE)] for e in expected])
                p_sig = float((speech**2).mean())
                noise = rng.normal(0, np.sqrt(p_sig / 10 ** (post["noise_snr_db"] / 10)), len(audio))
                audio = audio + noise.astype(np.float32)
            pcm = (np.clip(audio, -1, 1) * 32767).astype("<i2").tobytes()
            path = OUT / f"{cid}.wav"
            with wave.open(str(path), "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(RATE)
                w.writeframes(pcm)
            manifest.append(
                {
                    **({"written_form": WRITTEN[cid]} if cid in WRITTEN else {}),
                    "id": cid,
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "expect": expect,
                    "voice": voice or None,
                    "duration_s": round(len(audio) / RATE, 2),
                    "post": post,
                    "utterances": expected,
                }
            )
    (OUT / "golden.json").write_text(
        json.dumps(
            {
                "description": "S1-D golden audio: synthetic macOS TTS English speech with known text; expected times "
                "measured from the generated audio (energy onset/offset). Not real customer audio.",
                "sample_rate": RATE,
                "clips": manifest,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {len(manifest)} clips to {OUT}")


if __name__ == "__main__":
    main()
