"""S1-D golden audio: the pinned local engine against synthetic English speech with known text and timing.

Accuracy is measured, not assumed (scripts/evaluate_golden.py prints the full report). These assertions are the
acceptance floor for the development configuration: clean speech is recognised with low word error and utterance
times within 0.6 s; silence, a tone and noise produce no text; degraded speech that is recognised wrongly is always
marked (low-confidence segment or uncertain words) or not shown at all.
"""

from __future__ import annotations

import hashlib
import json
import wave
from pathlib import Path
from typing import Any

import pytest

from app.voice.transcript import FasterWhisperEngine, Thresholds, pieces, word_error_rate
from scripts.evaluate_golden import evaluate

GOLDEN = Path(__file__).parent / "fixtures" / "golden_audio"
MODEL = Path.home() / ".call360" / "models" / "faster-whisper-small.en"


@pytest.fixture(scope="module")
def report(asr: FasterWhisperEngine) -> dict[str, Any]:
    return evaluate(asr, Thresholds())


def test_golden_files_are_the_recorded_dataset() -> None:
    spec = json.loads((GOLDEN / "golden.json").read_text())
    assert len(spec["clips"]) == 12 and spec["sample_rate"] == 16000
    for c in spec["clips"]:
        path = GOLDEN / c["file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == c["sha256"], c["id"]
        with wave.open(str(path)) as w:
            assert (w.getframerate(), w.getnchannels(), w.getsampwidth()) == (16000, 1, 2)


def test_clean_english_speech_text_and_timing(report: dict[str, Any]) -> None:
    clean = [c for c in report["clips"] if c["expect"] == "SPEECH"]
    assert len(clean) == 6
    for c in clean:
        assert c["wer"] <= 0.10, (c["id"], c["recognised"])
        assert all(s["kind"] == "SPEECH" and s["confidence"] == "NORMAL" for s in c["segments"]), c["id"]
        assert c["timing_error_s"] is not None, c["id"]  # one recognised segment per expected utterance
        for t in c["timing_error_s"]:
            assert abs(t["start"]) <= 0.6 and abs(t["end"]) <= 0.6, (c["id"], t)
    assert report["summary"]["clean_speech_wer"] <= 0.05


def test_two_turns_after_a_pause_are_separate_segments(report: dict[str, Any]) -> None:
    c = next(c for c in report["clips"] if c["id"] == "g02_gb_two_turns")
    assert [s["text"] for s in c["segments"]] == [
        "Yes, I understand the policy.",
        "Please call me back tomorrow afternoon.",
    ]
    assert c["segments"][1]["start_s"] == pytest.approx(4.65, abs=0.3)


def test_silence_tone_and_noise_produce_no_text(report: dict[str, Any]) -> None:
    for c in report["clips"]:
        if c["expect"] == "NO_SPEECH":
            assert c["recognised"] == "" and not [s for s in c["segments"] if s["kind"] == "SPEECH"], c["id"]
    assert report["summary"]["no_speech_clips_with_text"] == []


def test_wrong_or_degraded_recognition_is_always_marked(report: dict[str, Any]) -> None:
    """Never a confident-looking wrong transcript: any recognition error in degraded audio carries a marker."""
    degraded = [c for c in report["clips"] if c["expect"] == "DEGRADED"]
    assert len(degraded) == 3
    for c in degraded:
        shown = [s for s in c["segments"] if s["kind"] == "SPEECH"]
        if c["wer"] > 0 and shown:
            assert any(s["confidence"] == "LOW" or s["uncertain_words"] > 0 for s in shown), c["id"]
    noisy = next(c for c in degraded if c["id"] == "g07_us_noisy")
    assert noisy["wer"] > 0 and sum(s["uncertain_words"] for s in noisy["segments"]) >= 1  # a real wrong-word case


def test_rejected_output_is_never_text(asr: FasterWhisperEngine) -> None:
    """The engine's hallucination-prone output on buried speech is rejected (no text) or flagged, never NORMAL."""
    with wave.open(str(GOLDEN / "g12_us_buried.wav")) as w:
        out = pieces(asr.transcribe(w.readframes(w.getnframes())), Thresholds())
    assert all(p["kind"] == "UNRECOGNIZED" or p["confidence"] == "LOW" or p["uncertain"] for p in out)
    assert all(p["words"] == [] for p in out if p["kind"] == "UNRECOGNIZED")


def test_word_error_rate_and_precision_helpers() -> None:
    from app.voice.transcript import normalise, reference_precision

    assert word_error_rate("I bought it.", "i bought it") == 0
    assert word_error_rate("a b c d", "a x c") == 0.5
    assert normalise("Hello, this is a Call 360 test.") == ["hello", "this", "is", "a", "call360", "test"]
    assert reference_precision("one two three four", "one two") == 1.0  # truncation is not an error
    assert reference_precision("one two three four", "one five") == 0.5


def test_repetition_with_good_log_probability_is_shown_but_flagged() -> None:
    """Real repetition (the mock voice repeating its message) is kept and flagged; a low-probability loop is not."""
    from app.voice.transcript import Recognised, Word, classify

    words = (Word(" Hello.", 0.0, 0.4, 0.95),)
    real = Recognised(0.0, 12.0, " Hello. Hello. Hello.", -0.25, 0.01, 3.1, words)
    loop = Recognised(0.0, 12.0, " I'm fine, I'm fine, I'm fine.", -0.6, 0.3, 3.1, words)
    assert classify(real, Thresholds()) == ("SPEECH", "LOW", 0, ["REPETITIVE_TEXT"])
    assert classify(loop, Thresholds())[0] == "UNRECOGNIZED"
