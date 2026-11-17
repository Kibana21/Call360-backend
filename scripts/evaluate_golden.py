"""Measure the pinned transcription engine on the S1-D golden audio dataset (accuracy is measured, never assumed).

    uv run python scripts/evaluate_golden.py [--model-dir DIR] [--json OUT]

For each clip it reports the recognised text, word error rate (after lower-casing and removing punctuation; numbers
are not normalised, so "4729" against "four seven two nine" counts as errors), the segment kinds and confidence
indicators produced with the configured thresholds, and the start/end time error of each expected utterance.
"""

from __future__ import annotations

import argparse
import json
import sys
import wave
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.voice.transcript import FasterWhisperEngine, Thresholds, pieces, word_error_rate  # noqa: E402

GOLDEN = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "golden_audio"
DEFAULT_MODEL = Path.home() / ".call360" / "models" / "faster-whisper-small.en"
DEFAULT_TH = Thresholds()  # the configured defaults (app.core.settings)


def evaluate(engine: Any, th: Thresholds = DEFAULT_TH) -> dict[str, Any]:
    spec = json.loads((GOLDEN / "golden.json").read_text())
    clips = []
    ref_words = err_words = 0.0
    for c in spec["clips"]:
        with wave.open(str(GOLDEN / c["file"])) as w:
            pcm = w.readframes(w.getnframes())
        rec = engine.transcribe(pcm)
        segs = [
            {
                "start_s": round(p["start"], 2),
                "end_s": round(p["end"], 2),
                "kind": p["kind"],
                "confidence": p["confidence"],
                "uncertain_words": p["uncertain"],
                "avg_logprob": round(p["r"].avg_logprob, 3),
                "no_speech_prob": round(p["r"].no_speech_prob, 3),
                "compression_ratio": round(p["r"].compression_ratio, 2),
                "text": p["text"] if p["kind"] == "SPEECH" else None,
                "words": [[w.text.strip(), round(w.probability, 2)] for w in p["words"]],
            }
            for p in pieces(rec, th)
        ]
        shown = " ".join(s["text"] for s in segs if s["text"])
        reference = " ".join(u["text"] for u in c["utterances"])
        written = c.get("written_form")  # the same words in written form (digits), equally correct
        out: dict[str, Any] = {
            "id": c["id"],
            "expect": c["expect"],
            "voice": c["voice"],
            "segments": segs,
            "recognised": shown,
            "reference": reference,
        }
        if c["utterances"]:
            wer = word_error_rate(reference, shown)
            out["wer_spoken_form"] = round(wer, 3)
            if written:
                wer = min(wer, word_error_rate(written, shown))
            n = len(reference.split())
            ref_words += n
            err_words += wer * n
            out["wer"] = round(wer, 3)
            speech = [s for s in segs if s["kind"] == "SPEECH"]
            if len(speech) == len(c["utterances"]):  # timing compared utterance by utterance
                out["timing_error_s"] = [
                    {"start": round(s["start_s"] - u["start_s"], 2), "end": round(s["end_s"] - u["end_s"], 2)}
                    for s, u in zip(speech, c["utterances"], strict=True)
                ]
            else:
                out["timing_error_s"] = None
        clips.append(out)
    clean = [c for c in clips if c["expect"] == "SPEECH"]
    return {
        "thresholds": th.__dict__,
        "clips": clips,
        "summary": {
            "clean_speech_wer": round(
                sum(c["wer"] * len(c["reference"].split()) for c in clean)
                / sum(len(c["reference"].split()) for c in clean),
                3,
            ),
            "all_speech_wer": round(err_words / ref_words, 3) if ref_words else None,
            "no_speech_clips_with_text": [c["id"] for c in clips if c["expect"] == "NO_SPEECH" and c["recognised"]],
            "max_abs_timing_error_s": max(
                (abs(v) for c in clean if c.get("timing_error_s") for t in c["timing_error_s"] for v in t.values()),
                default=None,
            ),
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    engine = FasterWhisperEngine(a.model_dir)
    report = evaluate(engine)
    report["engine"] = {
        "version": engine.version,
        "model_id": engine.model_id,
        "model_revision": engine.model_revision,
        "model_sha256": engine.model_sha256,
    }
    text = json.dumps(report, indent=2)
    if a.json:
        a.json.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
