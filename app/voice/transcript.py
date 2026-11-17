"""S1-D machine transcripts of recorded tracks (VOICE-009, EVD-004) and the recording timeline (playback mapping).

Rules that keep recognised text honest:

- Only engine output becomes transcript text. Nothing is generated from the script, the mock provider's fixed message,
  the case or a prompt; silence, tones and noise produce no text; a recording gap is never transcribed.
- Each stored track is transcribed on its own: ``MIC`` → speaker ``CALLER_MIC``, ``PROVIDER_PLAYBACK`` →
  ``MOCK_PROVIDER``. The speaker comes from the track (channel separation) — never from diarisation or identity.
- Engine: local, offline faster-whisper with the pinned ``small.en`` model (D-49), English only (D-51). The model files
  are verified against pinned SHA-256 values before use; engine, versions, model revision and hash, configuration and
  the checksum of the transcribed audio are stored on every run.
- Indicators (D-52) are configurable development values. Model probabilities are **not** calibrated
  compliance-confidence scores and a transcript is never certified: every transcript is ``NOT_REVIEWED``.
- Runs are immutable once finished; a retry is a new revision; segment metadata is insert-only; text lives only in
  one AES-256-GCM object per run in the recording store and is deleted with the audio at retention expiry.

Transcription runs in a background worker (``work``), never inside a request.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.voice import media
from app.voice.provider import SAMPLE_RATE
from app.voice.store import append_event

log = logging.getLogger("call360.transcript")

ENGINE = "faster-whisper"
MODEL_ID = "Systran/faster-whisper-small.en"
MODEL_REVISION = "d1d751a5f8271d482d14ca55d9e2deeebbae577f"  # gitleaks:allow
# SHA-256 of each model file at MODEL_REVISION (model.bin equals the Hugging Face LFS object id; the small files were
# checked against their git blob ids). Verified on load; any difference refuses the engine. They are public file
# checksums, not secrets, hence the inline gitleaks:allow markers.
MODEL_FILES = {
    "config.json": "666a9605530ac1f61fa8177f3702b4dacec9966749e42610839fcc32661d5fae",  # gitleaks:allow
    "model.bin": "62b2a45b05ee59acb4a5341b33ee35e041395d378d418a18acfe4c9e768ee37a",  # gitleaks:allow
    "tokenizer.json": "929c5252409436dce1b38a75d1abbcb5e132d170d8e324e4e04ed915fa2d22df",  # gitleaks:allow
    "vocabulary.txt": "ff77588746d3a2595d32ab5b69ffd7b95ce2441ac57533cb66fc3eb575a115cf",  # gitleaks:allow
}
LANGUAGE = "en"
# Pinned decoding configuration: greedy-free beam search at temperature 0 only (no sampling fallback), no conditioning
# on previous text (limits run-on hallucination), Silero VAD so silence stays silence, word timestamps on.
DECODE = {
    "language": LANGUAGE,
    "task": "transcribe",
    "beam_size": 5,
    "temperature": [0.0],
    "condition_on_previous_text": False,
    "vad_filter": True,
    "vad_parameters": {"min_silence_duration_ms": 500, "speech_pad_ms": 200},
    "word_timestamps": True,
    "no_speech_threshold": 0.6,
    "log_prob_threshold": -1.0,
}
RUNTIME = {"device": "cpu", "compute_type": "int8"}
SPEAKER = {"MIC": "CALLER_MIC", "PROVIDER_PLAYBACK": "MOCK_PROVIDER"}
SPEAKER_LABEL = {"CALLER_MIC": "Caller (browser microphone)", "MOCK_PROVIDER": "Mock voice (Call360 test)"}
MAX_ATTEMPTS = 3
LEASE = timedelta(minutes=5)
SYSTEM = "SYSTEM:transcriber"


class TranscriptError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code, self.message, self.retryable = code, message, retryable


# ---- engine ----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Word:
    text: str
    start: float  # seconds within the transcribed span
    end: float
    probability: float


@dataclass(frozen=True)
class Recognised:
    start: float
    end: float
    text: str
    avg_logprob: float
    no_speech_prob: float
    compression_ratio: float
    words: tuple[Word, ...]


class Engine(Protocol):
    name: str
    version: str
    model_id: str
    model_revision: str
    model_sha256: str

    def transcribe(self, pcm16: bytes) -> list[Recognised]: ...


def verify_model(model_dir: Path) -> None:
    """Refuse a model directory whose files differ from the pinned revision (D-49)."""
    missing = [n for n in MODEL_FILES if not (model_dir / n).is_file()]
    if missing:
        raise TranscriptError("MODEL_NOT_FOUND", f"model file {missing[0]} is missing", retryable=False)
    for name, want in MODEL_FILES.items():
        path = model_dir / name
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        if h.hexdigest() != want:
            raise TranscriptError("MODEL_CHECKSUM_MISMATCH", f"model file {name} does not match", retryable=False)


class FasterWhisperEngine:
    """faster-whisper (CTranslate2) on CPU, int8, one transcription at a time."""

    name = ENGINE
    model_id = MODEL_ID
    model_revision = MODEL_REVISION
    model_sha256 = MODEL_FILES["model.bin"]

    def __init__(self, model_dir: Path, threads: int = 4) -> None:
        import ctranslate2  # type: ignore[import-untyped]
        import faster_whisper  # type: ignore[import-untyped]

        verify_model(model_dir)
        self.version = f"faster-whisper {faster_whisper.__version__}; ctranslate2 {ctranslate2.__version__}"
        self._dir, self._threads = model_dir, threads
        self._model: Any = None
        self._lock = threading.Lock()

    def _load(self) -> Any:
        if self._model is None:
            from faster_whisper import WhisperModel

            self._model = WhisperModel(str(self._dir), cpu_threads=self._threads, local_files_only=True, **RUNTIME)
        return self._model

    def transcribe(self, pcm16: bytes) -> list[Recognised]:
        import numpy as np

        audio = np.frombuffer(pcm16, dtype="<i2").astype(np.float32) / 32768.0
        with self._lock:
            segments, _info = self._load().transcribe(audio, **DECODE)
            out = []
            for s in segments:  # the generator decodes lazily: consume it inside the lock
                words = tuple(Word(w.word, float(w.start), float(w.end), float(w.probability)) for w in s.words or ())
                out.append(
                    Recognised(
                        float(s.start),
                        float(s.end),
                        s.text,
                        float(s.avg_logprob),
                        float(s.no_speech_prob),
                        float(s.compression_ratio),
                        words,
                    )
                )
        return out


def engine_for(app: Any) -> Engine | None:
    """The process's engine, or ``None`` when no model directory is configured (transcripts UNAVAILABLE)."""
    if getattr(app.state, "transcription_engine", None) is not None:
        e: Engine = app.state.transcription_engine
        return e
    settings: Settings = app.state.settings
    if settings.transcription_model_dir is None:
        return None
    app.state.transcription_engine = FasterWhisperEngine(
        settings.transcription_model_dir.expanduser(), settings.transcription_threads
    )
    return app.state.transcription_engine  # type: ignore[no-any-return]


@dataclass(frozen=True)
class Thresholds:
    low_logprob: float = -0.45
    word_prob: float = 0.7
    no_speech_prob: float = 0.6
    max_compression: float = 2.4
    reject_logprob: float = -0.8
    split_pause_s: float = 1.0

    @classmethod
    def of(cls, settings: Settings) -> Thresholds:
        return cls(
            settings.transcript_low_logprob,
            settings.transcript_word_prob,
            settings.transcript_no_speech_prob,
            settings.transcript_max_compression,
            settings.transcript_reject_logprob,
            settings.transcript_split_pause_s,
        )


def run_config(th: Thresholds) -> dict[str, Any]:
    return {
        "decode": DECODE,
        "runtime": RUNTIME,
        "indicators": {
            "low_confidence_below_avg_logprob": th.low_logprob,
            "uncertain_word_below_probability": th.word_prob,
            "reject_below_avg_logprob": th.reject_logprob,
            "reject_if_no_speech_prob_above_and_low_logprob": th.no_speech_prob,
            "reject_if_compression_ratio_above_and_low_logprob": th.max_compression,
            "split_segment_at_word_pause_s": th.split_pause_s,
            "note": "Development indicators only; model probabilities are not calibrated confidence scores.",
        },
        "granularity": "contiguous stored audio spans; nothing is transcribed across a recording gap",
    }


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---- recording timeline (recording time ↔ playback offset) -------------------------------------------------------
def _good_chunks(asset: dict[str, Any], chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The chunks that make up the stored content (and the evidence WAV): unreadable ones were gaps at finalisation."""
    bad = {(g["segment"], g.get("seq")) for g in asset["gaps"] if g["type"] == "OBJECT_UNREADABLE"}
    return [c for c in chunks if (c["segment"], c["seq"]) not in bad]


def timeline(db: Session, attempt_id: uuid.UUID) -> dict[str, Any]:
    """The session's recording laid on one timeline shared by both tracks.

    Recording time is (recording segment, sample offset) on the shared 16 kHz clock; segment *g* starts on the timeline
    after the previous segments' lengths (the disconnected interval between segments is not on the timeline; it is
    marked). Each stored chunk span gets its timeline position and its offset in the evidence WAV, which concatenates
    stored chunks only — so after a gap the WAV offset is earlier than the timeline position. Gaps become spans
    (``estimated`` when their length is not known from neighbouring chunks). Nothing is filled in."""
    assets = media._assets(db, attempt_id)
    segments = media._segments(db, attempt_id)
    per: dict[str, dict[str, Any]] = {}
    lengths: dict[int, int] = {s["segment"]: 0 for s in segments}
    for a in assets:
        chunks = media._chunks(db, a["id"])
        good = _good_chunks(a, chunks)
        manifests = dict(a["close_manifests"])
        per[a["track"]] = {"asset": a, "good": good, "manifests": manifests}
        for s in segments:
            g = s["segment"]
            mine = [c for c in good if c["segment"] == g]
            end = max((c["start_sample"] + c["sample_count"] for c in mine), default=0)
            last = max((c["seq"] for c in mine), default=0)
            declared = manifests.get(str(g), {}).get("chunks", last)
            end += max(0, declared - last) * media.CHUNK_MAX_SAMPLES  # trailing chunks never stored: estimated
            lengths[g] = max(lengths[g], end)
    starts: dict[int, int] = {}
    t = 0
    for s in segments:
        starts[s["segment"]] = t
        t += lengths[s["segment"]]
    tracks: dict[str, Any] = {}
    for track, info in per.items():
        a, good = info["asset"], info["good"]
        spans, gaps, wav = [], [], 0
        for c in good:
            spans.append(
                {
                    "segment": c["segment"],
                    "seq": c["seq"],
                    "start_sample": c["start_sample"],
                    "sample_count": c["sample_count"],
                    "timeline_start": starts.get(c["segment"], 0) + c["start_sample"],
                    "wav_offset": wav,
                }
            )
            wav += c["sample_count"]
        for s in segments:
            g = s["segment"]
            base = starts[g]
            mine = [c for c in good if c["segment"] == g]
            by_seq = {c["seq"]: c for c in mine}
            m = info["manifests"].get(str(g))
            declared = m["chunks"] if m else max(by_seq, default=0)
            if g > 1:
                gaps.append(_gap("SESSION_INTERRUPTED", g, None, base, base, False))
            types = {(x["segment"], x.get("seq")): x["type"] for x in a["gaps"]}
            q = 1
            while q <= declared:
                if q in by_seq:
                    q += 1
                    continue
                first = q
                while q <= declared and q not in by_seq:
                    q += 1
                prev, nxt = by_seq.get(first - 1), by_seq.get(q)
                lo = prev["start_sample"] + prev["sample_count"] if prev else 0
                if first == 1 and prev is None and nxt is None and not mine:
                    lo = 0
                if nxt is not None:
                    hi, est = nxt["start_sample"], False
                else:
                    hi, est = lo + (q - first) * media.CHUNK_MAX_SAMPLES, True
                kind = types.get((g, first), "MISSING")
                gaps.append(_gap(kind, g, list(range(first, q)), base + lo, base + hi, est))
            prev_c = None
            for c in mine:  # a jump in sample position between consecutive stored chunks
                if prev_c is not None and c["seq"] == prev_c["seq"] + 1:
                    expect = prev_c["start_sample"] + prev_c["sample_count"]
                    if c["start_sample"] > expect:
                        gaps.append(
                            _gap("DISCONTINUITY", g, [c["seq"]], base + expect, base + c["start_sample"], False)
                        )
                prev_c = c
            end = base + lengths[g]
            if m is None:
                gaps.append(_gap("END_NOT_CONFIRMED", g, None, end, end, False))
            elif m["reason"] != "STOPPED":
                gaps.append(_gap("CAPTURE_INTERRUPTED", g, None, end, end, False, reason=m["reason"]))
        tracks[track] = {
            "asset_ref": a["asset_ref"],
            "media_status": a["status"],
            "coverage": a["coverage"],
            "content_sha256": a["content_sha256"],
            "stored_samples": wav,
            "spans": spans,
            "gaps": gaps,
        }
    return {
        "sample_rate": SAMPLE_RATE,
        "total_samples": t,
        "segments": [
            {
                "segment": s["segment"],
                "timeline_start": starts[s["segment"]],
                "length": lengths[s["segment"]],
                "started_at": s["started_at"],
            }
            for s in segments
        ],
        "tracks": tracks,
    }


def _gap(
    kind: str, segment: int, seqs: list[int] | None, lo: int, hi: int, estimated: bool, *, reason: str | None = None
) -> dict[str, Any]:
    return {
        "type": kind,
        "segment": segment,
        "seqs": seqs or [],
        "timeline_start": lo,
        "timeline_end": hi,
        "estimated": estimated,
        "reason": reason,
    }


def wav_offset(tl_track: dict[str, Any], segment: int, sample: int) -> int | None:
    """Evidence-WAV sample offset of a recording position, or ``None`` when that position was not stored."""
    for s in tl_track["spans"]:
        if s["segment"] == segment and s["start_sample"] <= sample <= s["start_sample"] + s["sample_count"]:
            return int(s["wav_offset"] + sample - s["start_sample"])
    return None


def contiguous_spans(good: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Runs of stored chunks with no gap between them (same segment, consecutive sequence, continuous samples)."""
    runs: list[list[dict[str, Any]]] = []
    for c in good:
        last = runs[-1][-1] if runs else None
        if (
            last is not None
            and last["segment"] == c["segment"]
            and c["seq"] == last["seq"] + 1
            and c["start_sample"] == last["start_sample"] + last["sample_count"]
        ):
            runs[-1].append(c)
        else:
            runs.append([c])
    return runs


# ---- runs: queue, claim, process -------------------------------------------------------------------------------
def object_key(attempt_id: uuid.UUID, track: str, revision: int) -> str:
    return f"{attempt_id}/{track}/transcript-r{revision:03d}.c360"


def _finalized_seq(db: Session, attempt_id: uuid.UUID, track: str) -> int:
    seq = db.execute(
        text(
            "SELECT max(seq) FROM session_event WHERE contact_attempt_id = :a AND event_type = 'RECORDING_FINALIZED' "
            "AND details ->> 'track' = :t"
        ),
        {"a": attempt_id, "t": track},
    ).scalar()
    return int(seq or 0)


def _insert_run(
    db: Session,
    engine: Engine,
    rs: media.EncryptedObjectStore,
    a: dict[str, Any],
    th: Thresholds,
    *,
    revision: int,
    actor: str,
) -> uuid.UUID | None:
    cfg = run_config(th)
    rid = uuid.uuid4()
    row = db.execute(
        text(
            "INSERT INTO transcript_run (id, run_ref, contact_attempt_id, conversation_session_id, media_asset_id, "
            "track, revision, status, language, engine, engine_version, model_id, model_revision, model_sha256, "
            "config, config_sha256, input_content_sha256, input_manifest_sha256, source_event_seq, requested_by, "
            "storage_backend, key_id, is_synthetic, updated_at) VALUES (:id, :ref, :a, :s, :m, :t, :rev, 'PENDING', "
            ":lang, :eng, :ev, :mid, :mrev, :msha, CAST(:cfg AS jsonb), :csha, :ich, :imh, :seq, :by, :be, :kid, "
            ":syn, now()) ON CONFLICT (media_asset_id, revision) DO NOTHING RETURNING id"
        ),
        {
            "id": rid,
            "ref": f"TR-{a['asset_ref'].removeprefix('MA-')}-r{revision}",
            "a": a["contact_attempt_id"],
            "s": a["conversation_session_id"],
            "m": a["id"],
            "t": a["track"],
            "rev": revision,
            "lang": LANGUAGE,
            "eng": engine.name,
            "ev": engine.version,
            "mid": engine.model_id,
            "mrev": engine.model_revision,
            "msha": engine.model_sha256,
            "cfg": json.dumps(cfg),
            "csha": hashlib.sha256(_canon(cfg)).hexdigest(),
            "ich": a["content_sha256"],
            "imh": a["manifest_sha256"],
            "seq": _finalized_seq(db, a["contact_attempt_id"], a["track"]),
            "by": actor,
            "be": rs.backend,
            "kid": rs.key_id,
            "syn": a["is_synthetic"],
        },
    ).first()
    return row[0] if row else None


def enqueue(
    db: Session, engine: Engine, rs: media.EncryptedObjectStore, th: Thresholds, attempt_id: uuid.UUID | None = None
) -> list[uuid.UUID]:
    """Queue revision 1 for every finalised, available track that has no run yet (idempotent)."""
    rows = db.execute(
        text(
            "SELECT a.* FROM media_asset a WHERE a.status = 'AVAILABLE' AND a.content_sha256 IS NOT NULL "
            "AND (CAST(:a AS uuid) IS NULL OR a.contact_attempt_id = :a) "
            "AND NOT EXISTS (SELECT 1 FROM transcript_run r WHERE r.media_asset_id = a.id) ORDER BY a.finalized_at"
        ),
        {"a": attempt_id},
    ).mappings()
    out = []
    for a in [dict(r) for r in rows]:
        rid = _insert_run(db, engine, rs, a, th, revision=1, actor=SYSTEM)
        if rid:
            out.append(rid)
            _sync_session(db, a["contact_attempt_id"])
    return out


def retry(
    db: Session,
    engine: Engine | None,
    rs: media.EncryptedObjectStore | None,
    settings: Settings,
    attempt_id: uuid.UUID,
    *,
    actor: str,
) -> list[str]:
    """A new revision for each track whose latest run FAILED; anything else is left as is (idempotent)."""
    if engine is None or rs is None:
        raise TranscriptError("TRANSCRIPTION_NOT_AVAILABLE", "Transcription is not configured", retryable=False)
    out = []
    for a in media._assets(db, attempt_id, lock=True):
        latest = _latest_run(db, a["id"])
        if latest is None or latest["status"] != "FAILED" or a["status"] != "AVAILABLE":
            continue
        if _insert_run(db, engine, rs, a, Thresholds.of(settings), revision=latest["revision"] + 1, actor=actor):
            out.append(a["track"])
    if out:
        _sync_session(db, attempt_id)
    return out


def _latest_run(db: Session, asset_id: uuid.UUID) -> dict[str, Any] | None:
    r = (
        db.execute(
            text("SELECT * FROM transcript_run WHERE media_asset_id = :m ORDER BY revision DESC LIMIT 1"),
            {"m": asset_id},
        )
        .mappings()
        .first()
    )
    return dict(r) if r else None


def claim(db: Session, attempt_id: uuid.UUID | None = None) -> dict[str, Any] | None:
    """Take the oldest PENDING run, or a PROCESSING run whose lease expired (the worker died), for this worker."""
    r = (
        db.execute(
            text(
                "SELECT * FROM transcript_run WHERE (status = 'PENDING' "
                "OR (status = 'PROCESSING' AND lease_until < now())) "
                "AND (CAST(:a AS uuid) IS NULL OR contact_attempt_id = :a) "
                "ORDER BY requested_at, revision FOR UPDATE SKIP LOCKED LIMIT 1"
            ),
            {"a": attempt_id},
        )
        .mappings()
        .first()
    )
    if r is None:
        return None
    run = dict(r)
    if run["attempts"] >= MAX_ATTEMPTS:  # an interrupted run that already used its attempts
        _fail(db, run, "PROCESSING_INTERRUPTED")
        return claim(db, attempt_id)
    db.execute(
        text(
            "UPDATE transcript_run SET status = 'PROCESSING', attempts = attempts + 1, lease_until = :lease, "
            "started_at = coalesce(started_at, now()), updated_at = now(), row_version = row_version + 1 "
            "WHERE id = :id"
        ),
        {"id": run["id"], "lease": datetime.now(UTC) + LEASE},
    )
    run["attempts"] += 1
    append_event(
        db,
        run["contact_attempt_id"],
        "TRANSCRIPT_STARTED",
        source="SYSTEM",
        actor=SYSTEM,
        details={
            "track": run["track"],
            "revision": run["revision"],
            "attempt": run["attempts"],
            "engine": run["engine"],
            "model_id": run["model_id"],
        },
    )
    _sync_session(db, run["contact_attempt_id"])
    return run


def _fail(db: Session, run: dict[str, Any], code: str) -> None:
    db.execute(
        text(
            "UPDATE transcript_run SET status = 'FAILED', error_code = :c, lease_until = NULL, finished_at = now(), "
            "updated_at = now(), row_version = row_version + 1 WHERE id = :id"
        ),
        {"c": code, "id": run["id"]},
    )
    append_event(
        db,
        run["contact_attempt_id"],
        "TRANSCRIPT_FAILED",
        source="SYSTEM",
        actor=SYSTEM,
        details={"track": run["track"], "revision": run["revision"], "error_code": code, "attempts": run["attempts"]},
    )
    _sync_session(db, run["contact_attempt_id"])


def recover(app: Any) -> int:
    """At startup nothing is transcribing: expire every PROCESSING lease so those runs are taken again."""
    with app.state.session_factory() as db, db.begin():
        if db.execute(text("SELECT to_regclass('transcript_run')")).scalar() is None:
            return 0
        return int(
            db.execute(
                text(
                    "UPDATE transcript_run SET lease_until = now() - interval '1 second', updated_at = now() "
                    "WHERE status = 'PROCESSING'"
                )
            ).rowcount
        )


def _load_audio(db: Session, rs: media.EncryptedObjectStore, run: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    a = db.execute(text("SELECT * FROM media_asset WHERE id = :m"), {"m": run["media_asset_id"]}).mappings().one()
    asset = dict(a)
    if asset["status"] != "AVAILABLE":
        raise TranscriptError("RECORDING_NOT_AVAILABLE", "The recording is no longer available", retryable=False)
    if asset["content_sha256"] != run["input_content_sha256"]:
        raise TranscriptError("RECORDING_INTEGRITY_FAILED", "Recording checksum changed", retryable=False)
    good = _good_chunks(asset, media._chunks(db, asset["id"]))
    digest = hashlib.sha256()
    spans = []
    for span in contiguous_spans(good):
        parts = []
        for c in span:
            data = rs.get(c["object_key"])
            if data is None or hashlib.sha256(data).hexdigest() != c["sha256"]:
                raise TranscriptError("RECORDING_INTEGRITY_FAILED", "A stored chunk is unreadable", retryable=False)
            digest.update(data)
            parts.append(data)
        spans.append((span[0]["segment"], span[0]["start_sample"], b"".join(parts)))
    if digest.hexdigest() != asset["content_sha256"]:
        raise TranscriptError(
            "RECORDING_INTEGRITY_FAILED", "Stored audio no longer matches its checksum", retryable=False
        )
    return asset, spans


def classify(r: Recognised, th: Thresholds) -> tuple[str, str, int, list[str]]:
    """(kind, confidence, uncertain word count, flags). UNRECOGNIZED output is discarded, never shown as text.

    A high compression ratio means repetitive text. With a low log-probability that is the classic hallucination loop
    and the output is rejected; with a good log-probability it can be real repetition (the mock voice repeats its
    message), so the text is kept but marked LOW confidence and flagged REPETITIVE_TEXT for a human to check."""
    repetitive = r.compression_ratio > th.max_compression
    if (
        r.avg_logprob < th.reject_logprob
        or (repetitive and r.avg_logprob < th.low_logprob)
        or (r.no_speech_prob > th.no_speech_prob and r.avg_logprob < th.low_logprob)
    ):
        return "UNRECOGNIZED", "LOW", 0, []
    uncertain = sum(1 for w in r.words if w.probability < th.word_prob)
    low = r.avg_logprob < th.low_logprob or repetitive
    return "SPEECH", "LOW" if low else "NORMAL", uncertain, ["REPETITIVE_TEXT"] if repetitive else []


def pieces(results: list[Recognised], th: Thresholds) -> list[dict[str, Any]]:
    """Classify each engine segment, then split SPEECH segments at word pauses of at least ``split_pause_s`` using the
    engine's own word timings (so a turn after a pause gets its own timestamp). Text is the engine's words, joined;
    segment-level metrics (log-probability, no-speech probability) are those of the engine segment."""
    out: list[dict[str, Any]] = []
    for r in results:
        if not r.text.strip():
            continue
        kind, conf, _, flags = classify(r, th)
        if kind != "SPEECH" or not r.words:
            out.append(
                {
                    "r": r,
                    "kind": kind,
                    "confidence": conf,
                    "start": r.start,
                    "end": r.end,
                    "words": list(r.words) if kind == "SPEECH" else [],
                    "text": r.text.strip(),
                    "uncertain": sum(w.probability < th.word_prob for w in r.words) if kind == "SPEECH" else 0,
                    "flags": flags,
                }
            )
            continue
        groups: list[list[Word]] = [[r.words[0]]]
        for w in r.words[1:]:
            if w.start - groups[-1][-1].end >= th.split_pause_s:
                groups.append([w])
            else:
                groups[-1].append(w)
        for g in groups:
            out.append(
                {
                    "r": r,
                    "kind": "SPEECH",
                    "confidence": conf,
                    "start": g[0].start if len(groups) > 1 else min(r.start, g[0].start),
                    "end": g[-1].end if len(groups) > 1 else max(r.end, g[-1].end),
                    "words": g,
                    "text": "".join(w.text for w in g).strip(),
                    "uncertain": sum(w.probability < th.word_prob for w in g),
                    "flags": flags,
                }
            )
    return out


def build(
    run: dict[str, Any], spans: list[tuple[int, int, bytes]], engine: Engine, th: Thresholds
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Transcribe each contiguous span and return (segment rows, encrypted payload, metrics)."""
    rows: list[dict[str, Any]] = []
    payload: list[dict[str, Any]] = []
    audio_samples = 0
    t0 = time.monotonic()
    for segment, start, pcm in spans:
        audio_samples += len(pcm) // 2
        for piece in pieces(engine.transcribe(pcm), th):
            r = piece["r"]
            kind = piece["kind"]
            s0 = start + round(piece["start"] * SAMPLE_RATE)
            s1 = max(s0, min(start + len(pcm) // 2, start + round(piece["end"] * SAMPLE_RATE)))
            ordinal = len(rows) + 1
            rows.append(
                {
                    "ordinal": ordinal,
                    "kind": kind,
                    "confidence": piece["confidence"],
                    "rec_segment": segment,
                    "start_sample": s0,
                    "end_sample": s1,
                    "avg_logprob": r.avg_logprob,
                    "no_speech_prob": r.no_speech_prob,
                    "compression_ratio": r.compression_ratio,
                    "word_count": len(piece["words"]) if kind == "SPEECH" else 0,
                    "uncertain_words": piece["uncertain"],
                    "min_word_prob": min((w.probability for w in piece["words"]), default=None)
                    if kind == "SPEECH"
                    else None,
                    "text_sha256": hashlib.sha256(piece["text"].encode()).hexdigest() if kind == "SPEECH" else None,
                    "flags": piece["flags"],
                }
            )
            if kind == "SPEECH":
                payload.append(
                    {
                        "ordinal": ordinal,
                        "text": piece["text"],
                        "words": [
                            [
                                w.text.strip(),
                                start + round(w.start * SAMPLE_RATE),
                                start + round(w.end * SAMPLE_RATE),
                                round(w.probability, 4),
                            ]
                            for w in piece["words"]
                        ],
                    }
                )
    elapsed = time.monotonic() - t0
    speech = [r for r in rows if r["kind"] == "SPEECH"]
    metrics = {
        "spans": len(spans),
        "audio_ms": audio_samples * 1000 // SAMPLE_RATE,
        "processing_ms": round(elapsed * 1000),
        "realtime_factor": round(elapsed / (audio_samples / SAMPLE_RATE), 3) if audio_samples else None,
        "speech_segments": len(speech),
        "unrecognized_segments": len(rows) - len(speech),
        "low_confidence_segments": sum(1 for r in speech if r["confidence"] == "LOW"),
        "words": sum(r["word_count"] for r in speech),
        "uncertain_words": sum(r["uncertain_words"] for r in speech),
    }
    if run["track"] == "PROVIDER_PLAYBACK":
        from app.voice.mock import FIXED_MESSAGE

        hyp = " ".join(p["text"] for p in payload)
        metrics["engine_check"] = {
            "reference": "MOCK_SCHEDULED_MESSAGE",
            "recognised_word_precision": reference_precision(" ".join(FIXED_MESSAGE), hyp),
            "note": "Engine self-check only; the scheduled mock message is not evidence of what was heard.",
        }
    return rows, {"run_ref": run["run_ref"], "segments": payload}, metrics


def run_one(app: Any, engine: Engine, rs: media.EncryptedObjectStore, run: dict[str, Any]) -> str:
    """Transcribe a claimed run outside any open transaction, then commit it atomically (or fail / requeue it)."""
    th = Thresholds.of(app.state.settings)
    sf = app.state.session_factory
    try:
        with sf() as db:
            _asset, spans = _load_audio(db, rs, run)
        rows, payload, metrics = build(run, spans, engine, th)
    except TranscriptError as exc:
        return _finish_error(sf, run, exc.code, retryable=exc.retryable)
    except Exception:  # noqa: BLE001 — an engine fault is recorded and retried, never swallowed silently
        log.exception("transcription failed for %s", run["run_ref"])
        return _finish_error(sf, run, "ENGINE_ERROR", retryable=True)
    blob = _canon(payload)
    key = object_key(run["contact_attempt_id"], run["track"], run["revision"])
    with sf() as db, db.begin():
        cur = db.execute(
            text("SELECT status, attempts FROM transcript_run WHERE id = :i FOR UPDATE"), {"i": run["id"]}
        ).one()
        if cur.status != "PROCESSING" or cur.attempts != run["attempts"]:
            return f"{run['run_ref']}:SUPERSEDED"  # another worker took over after a lease expiry
        if rs.exists(key):  # left by an earlier attempt of this same run that died before committing
            rs.delete(key)
        rs.put(key, blob)
        try:
            for r in rows:
                db.execute(
                    text(
                        "INSERT INTO transcript_segment (id, transcript_run_id, contact_attempt_id, track, speaker, "
                        "ordinal, kind, confidence, rec_segment, start_sample, end_sample, avg_logprob, "
                        "no_speech_prob, compression_ratio, word_count, uncertain_words, min_word_prob, text_sha256, "
                        "flags) "
                        "VALUES (:id, :run, :a, :t, :sp, :ordinal, :kind, :confidence, :rec_segment, :start_sample, "
                        ":end_sample, :avg_logprob, :no_speech_prob, :compression_ratio, :word_count, "
                        ":uncertain_words, :min_word_prob, :text_sha256, :flags)"
                    ),
                    {
                        **r,
                        "id": uuid.uuid4(),
                        "run": run["id"],
                        "a": run["contact_attempt_id"],
                        "t": run["track"],
                        "sp": SPEAKER[run["track"]],
                    },
                )
            db.execute(
                text(
                    "UPDATE transcript_run SET status = 'DONE', object_key = :k, text_sha256 = :h, "
                    "metrics = CAST(:m AS jsonb), lease_until = NULL, finished_at = now(), updated_at = now(), "
                    "row_version = row_version + 1 WHERE id = :i"
                ),
                {"k": key, "h": hashlib.sha256(blob).hexdigest(), "m": json.dumps(metrics), "i": run["id"]},
            )
            append_event(
                db,
                run["contact_attempt_id"],
                "TRANSCRIPT_COMPLETED",
                source="SYSTEM",
                actor=SYSTEM,
                details={
                    "track": run["track"],
                    "revision": run["revision"],
                    "speech_segments": metrics["speech_segments"],
                    "unrecognized_segments": metrics["unrecognized_segments"],
                    "low_confidence_segments": metrics["low_confidence_segments"],
                },
            )
            _sync_session(db, run["contact_attempt_id"])
        except Exception:
            rs.delete(key)  # the transaction rolls back; do not leave an orphan text object
            raise
    return f"{run['run_ref']}:DONE"


def _finish_error(sf: Any, run: dict[str, Any], code: str, *, retryable: bool) -> str:
    with sf() as db, db.begin():
        cur = (
            db.execute(text("SELECT * FROM transcript_run WHERE id = :i FOR UPDATE"), {"i": run["id"]}).mappings().one()
        )
        if cur["status"] != "PROCESSING" or cur["attempts"] != run["attempts"]:
            return f"{run['run_ref']}:SUPERSEDED"
        if retryable and cur["attempts"] < MAX_ATTEMPTS:
            db.execute(
                text(
                    "UPDATE transcript_run SET status = 'PENDING', lease_until = NULL, updated_at = now(), "
                    "row_version = row_version + 1 WHERE id = :i"
                ),
                {"i": run["id"]},
            )
            _sync_session(db, run["contact_attempt_id"])
            return f"{run['run_ref']}:RETRY"
        _fail(db, dict(cur), code)
    return f"{run['run_ref']}:FAILED"


def work(app: Any, *, limit: int = 4, attempt_id: uuid.UUID | None = None) -> list[str]:
    """One worker pass: queue new runs, then process up to ``limit`` runs one by one."""
    rs = media.store_for(app)
    if rs is None:
        return []
    try:
        engine = engine_for(app)
    except TranscriptError as exc:  # misconfigured model: record nothing, report once per pass
        log.error("transcription engine unavailable: %s", exc.code)
        return []
    if engine is None:
        return []
    sf = app.state.session_factory
    with sf() as db, db.begin():
        if db.execute(text("SELECT to_regclass('transcript_run')")).scalar() is None:
            return []
        enqueue(db, engine, rs, Thresholds.of(app.state.settings), attempt_id)
    out = []
    for _ in range(limit):
        with sf() as db, db.begin():
            run = claim(db, attempt_id)
        if run is None:
            break
        out.append(run_one(app, engine, rs, run))
    return out


# ---- retention -------------------------------------------------------------------------------------------------
def purge_asset(db: Session, rs: media.EncryptedObjectStore | None, asset_id: uuid.UUID, *, actor: str) -> int:
    """Delete the transcript text objects of a purged track; run and segment metadata and checksums remain."""
    runs = (
        db.execute(
            text("SELECT * FROM transcript_run WHERE media_asset_id = :m AND purged_at IS NULL FOR UPDATE"),
            {"m": asset_id},
        )
        .mappings()
        .all()
    )
    removed = 0
    for r in runs:
        if r["object_key"] and rs is not None:
            rs.delete(r["object_key"])
            removed += 1
        status = "FAILED" if r["status"] in ("PENDING", "PROCESSING") else r["status"]
        db.execute(
            text(
                "UPDATE transcript_run SET purged_at = now(), status = :st, error_code = :ec, "
                "finished_at = coalesce(finished_at, now()), lease_until = NULL, "
                "updated_at = now(), row_version = row_version + 1 WHERE id = :i"
            ),
            {"st": status, "ec": r["error_code"] or ("RECORDING_PURGED" if status == "FAILED" else None), "i": r["id"]},
        )
    if runs:
        append_event(
            db,
            runs[0]["contact_attempt_id"],
            "TRANSCRIPT_PURGED",
            source="SYSTEM",
            actor=actor,
            details={"track": runs[0]["track"], "runs": len(runs), "objects_removed": removed},
        )
        _sync_session(db, runs[0]["contact_attempt_id"])
    return removed


# ---- status and reading ----------------------------------------------------------------------------------------
SESSION_COLUMN = {  # API status → approved conversation_session.transcript_status vocabulary (BRD §3.3)
    "PENDING": "PENDING",
    "PROCESSING": "PENDING",
    "COMPLETE": "FINALIZED",
    "PARTIAL": "PARTIAL",
    "FAILED": "UNAVAILABLE",
    "UNAVAILABLE": "UNAVAILABLE",
}


def _runs(db: Session, attempt_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.execute(
        text("SELECT * FROM transcript_run WHERE contact_attempt_id = :a ORDER BY track, revision"), {"a": attempt_id}
    ).mappings()
    return [dict(r) for r in rows]


def latest_runs(runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in runs:
        out[r["track"]] = r  # ordered by revision
    return out


def derive(
    recording: dict[str, Any], runs: list[dict[str, Any]], *, engine_configured: bool, flagged: bool
) -> tuple[str, str]:
    """(status, reason) of a session's transcript. COMPLETE means every stored track was processed over complete
    recording coverage — not that the text is correct, reviewed or certified."""
    rec = recording["status"]
    latest = latest_runs(runs)
    if rec == "NOT_RECORDED":
        return "UNAVAILABLE", "CONSENT_DECLINED" if recording["consent"] == "DECLINED" else "NOT_RECORDED"
    if rec == "RECORDING":
        return "PENDING", "RECORDING_IN_PROGRESS"
    if rec == "FAILED":
        return "UNAVAILABLE", "NO_AUDIO_STORED"
    if rec == "PURGED":
        return "UNAVAILABLE", "PURGED"
    available = [t["track"] for t in recording["tracks"] if t["media_status"] == "AVAILABLE"]
    if not latest:
        return ("PENDING", "QUEUED") if engine_configured else ("UNAVAILABLE", "ENGINE_NOT_CONFIGURED")
    sts = [latest[t]["status"] if t in latest else "PENDING" for t in available]
    if "PROCESSING" in sts:
        return "PROCESSING", "TRANSCRIBING"
    if "PENDING" in sts:
        return "PENDING", "QUEUED"
    if all(s == "FAILED" for s in sts):
        return "FAILED", latest[available[0]]["error_code"] or "FAILED"
    if "FAILED" in sts:
        return "PARTIAL", "TRACK_FAILED"
    if rec != "COMPLETE":
        return "PARTIAL", "RECORDING_GAPS"
    return "COMPLETE", "UNCERTAIN_SPEECH" if flagged else "PROCESSED"


def _flagged(db: Session, attempt_id: uuid.UUID, latest: dict[str, dict[str, Any]]) -> bool:
    ids = [r["id"] for r in latest.values() if r["status"] == "DONE"]
    if not ids:
        return False
    n = db.execute(
        text(
            "SELECT count(*) FROM transcript_segment WHERE transcript_run_id = ANY(:ids) AND "
            "(confidence = 'LOW' OR kind = 'UNRECOGNIZED' OR uncertain_words > 0)"
        ),
        {"ids": ids},
    ).scalar()
    return bool(n)


def _sync_session(db: Session, attempt_id: uuid.UUID) -> None:
    rec = media.summary(db, attempt_id)
    runs = _runs(db, attempt_id)
    latest = latest_runs(runs)
    flagged = _flagged(db, attempt_id, latest)
    status, _ = derive(rec, runs, engine_configured=True, flagged=flagged)
    col = SESSION_COLUMN[status]
    if status == "COMPLETE" and flagged:
        col = "QUALITY_FLAGGED"
    db.execute(
        text(
            "UPDATE conversation_session SET transcript_status = :t, updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE contact_attempt_id = :a AND transcript_status IS DISTINCT FROM :t"
        ),
        {"t": col, "by": SYSTEM, "a": attempt_id},
    )


def _run_out(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_ref": r["run_ref"],
        "track": r["track"],
        "revision": r["revision"],
        "status": r["status"],
        "attempts": r["attempts"],
        "error_code": r["error_code"],
        "language": r["language"],
        "engine": r["engine"],
        "engine_version": r["engine_version"],
        "model_id": r["model_id"],
        "model_revision": r["model_revision"],
        "model_sha256": r["model_sha256"],
        "config": r["config"],
        "config_sha256": r["config_sha256"],
        "input_content_sha256": r["input_content_sha256"],
        "text_sha256": r["text_sha256"],
        "source_event_seq": r["source_event_seq"],
        "requested_at": r["requested_at"],
        "started_at": r["started_at"],
        "finished_at": r["finished_at"],
        "metrics": r["metrics"],
        "purged_at": r["purged_at"],
    }


def overview(db: Session, attempt_id: uuid.UUID, *, engine_configured: bool) -> dict[str, Any]:
    """Status, provenance and counts — no text (any reader of the case)."""
    rec = media.summary(db, attempt_id)
    runs = _runs(db, attempt_id)
    latest = latest_runs(runs)
    flagged = _flagged(db, attempt_id, latest)
    status, reason = derive(rec, runs, engine_configured=engine_configured, flagged=flagged)
    counts = db.execute(
        text(
            "SELECT track, count(*) FILTER (WHERE kind = 'SPEECH') AS speech, "
            "count(*) FILTER (WHERE kind = 'UNRECOGNIZED') AS unrecognized, "
            "count(*) FILTER (WHERE confidence = 'LOW' AND kind = 'SPEECH') AS low, "
            "coalesce(sum(uncertain_words), 0) AS uncertain_words FROM transcript_segment "
            "WHERE transcript_run_id = ANY(:ids) GROUP BY track"
        ),
        {"ids": [r["id"] for r in latest.values()]},
    ).mappings()
    by_track = {c["track"]: dict(c) for c in counts}
    return {
        "status": status,
        "reason": reason,
        "review_status": "NOT_REVIEWED",
        "uncertain": flagged,
        "language": LANGUAGE,
        "recording_status": rec["status"],
        "tracks": [
            {
                "track": t,
                "speaker": SPEAKER[t],
                "speaker_label": SPEAKER_LABEL[SPEAKER[t]],
                "run": _run_out(latest[t]) if t in latest else None,
                "revisions": sum(1 for r in runs if r["track"] == t),
                "speech_segments": int(by_track.get(t, {}).get("speech", 0)),
                "unrecognized_segments": int(by_track.get(t, {}).get("unrecognized", 0)),
                "low_confidence_segments": int(by_track.get(t, {}).get("low", 0)),
                "uncertain_words": int(by_track.get(t, {}).get("uncertain_words", 0)),
            }
            for t in media.TRACKS
            if any(x["track"] == t for x in rec["tracks"])
        ],
    }


def segments(db: Session, rs: media.EncryptedObjectStore | None, attempt_id: uuid.UUID) -> dict[str, Any]:
    """Segments of the latest finished run of each track, with decrypted text, in timeline order. Text is verified
    against the run and segment checksums; a mismatch is reported, never shown."""
    tl = timeline(db, attempt_id)
    latest = latest_runs(_runs(db, attempt_id))
    out: list[dict[str, Any]] = []
    problems: list[dict[str, str]] = []
    th_words: dict[str, float] = {}
    starts = {s["segment"]: s["timeline_start"] for s in tl["segments"]}
    for track, run in latest.items():
        if run["status"] != "DONE":
            continue
        th_words[track] = float(run["config"]["indicators"]["uncertain_word_below_probability"])
        texts: dict[int, dict[str, Any]] = {}
        if run["purged_at"] is None:
            blob = rs.get(run["object_key"]) if rs is not None else None
            if blob is None or hashlib.sha256(blob).hexdigest() != run["text_sha256"]:
                problems.append({"track": track, "code": "TRANSCRIPT_INTEGRITY_FAILED"})
            else:
                texts = {p["ordinal"]: p for p in json.loads(blob)["segments"]}
        rows = db.execute(
            text("SELECT * FROM transcript_segment WHERE transcript_run_id = :r ORDER BY ordinal"), {"r": run["id"]}
        ).mappings()
        tl_track = tl["tracks"].get(track, {"spans": []})
        for r in rows:
            p = texts.get(r["ordinal"])
            body = None
            if r["kind"] == "SPEECH" and p is not None:
                if hashlib.sha256(p["text"].encode()).hexdigest() != r["text_sha256"]:
                    problems.append({"track": track, "code": "SEGMENT_INTEGRITY_FAILED"})
                else:
                    body = p
            base = starts.get(r["rec_segment"], 0)
            out.append(
                {
                    "track": track,
                    "speaker": r["speaker"],
                    "speaker_label": SPEAKER_LABEL[r["speaker"]],
                    "run_ref": run["run_ref"],
                    "ordinal": r["ordinal"],
                    "kind": r["kind"],
                    "confidence": r["confidence"],
                    "rec_segment": r["rec_segment"],
                    "start_sample": r["start_sample"],
                    "end_sample": r["end_sample"],
                    "timeline_start_ms": (base + r["start_sample"]) * 1000 // SAMPLE_RATE,
                    "timeline_end_ms": (base + r["end_sample"]) * 1000 // SAMPLE_RATE,
                    "wav_offset_ms": _ms(wav_offset(tl_track, r["rec_segment"], r["start_sample"])),
                    "time_alignment": r["time_alignment"],
                    "avg_logprob": round(r["avg_logprob"], 3),
                    "no_speech_prob": round(r["no_speech_prob"], 3),
                    "word_count": r["word_count"],
                    "uncertain_words": r["uncertain_words"],
                    "text": body["text"] if body else None,
                    "words": [
                        {
                            "text": w[0],
                            "timeline_start_ms": (base + w[1]) * 1000 // SAMPLE_RATE,
                            "timeline_end_ms": (base + w[2]) * 1000 // SAMPLE_RATE,
                            "probability": w[3],
                            "uncertain": w[3] < th_words[track],
                        }
                        for w in (body["words"] if body else [])
                    ],
                    "text_available": body is not None,
                    "flags": list(r["flags"]),
                }
            )
    out.sort(key=lambda s: (s["timeline_start_ms"], s["track"]))
    provider = [s for s in out if s["track"] == "PROVIDER_PLAYBACK" and s["kind"] == "SPEECH"]
    for s in out:  # caller speech overlapping the mock voice: a barge-in or echo; the text is not altered
        if s["track"] == "MIC" and any(
            p["timeline_start_ms"] < s["timeline_end_ms"] and s["timeline_start_ms"] < p["timeline_end_ms"]
            for p in provider
        ):
            s["flags"].append("OVERLAPS_MOCK_VOICE")
    return {"segments": out, "problems": problems, "timeline": tl}


def _ms(samples: int | None) -> int | None:
    return None if samples is None else samples * 1000 // SAMPLE_RATE


# ---- accuracy measurement (golden dataset and engine self-check) ------------------------------------------------
_WORD = re.compile(r"[a-z0-9']+")


def normalise(s: str) -> list[str]:
    """Lower-case words without punctuation; "call 360" and "call360" compare equal."""
    s = s.lower().replace("call 360", "call360").replace("call-360", "call360")
    return _WORD.findall(s)


def word_error_rate(reference: str, hypothesis: str) -> float:
    ref, hyp = normalise(reference), normalise(hypothesis)
    if not ref:
        return 0.0 if not hyp else 1.0
    d = list(range(len(hyp) + 1))
    for i, rw in enumerate(ref, 1):
        prev, d[0] = d[0], i
        for j, hw in enumerate(hyp, 1):
            cur = min(d[j] + 1, d[j - 1] + 1, prev + (rw != hw))
            prev, d[j] = d[j], cur
    return d[len(hyp)] / len(ref)


def reference_precision(reference: str, hypothesis: str) -> float | None:
    """Share of recognised words that match the reference in order (longest common subsequence / recognised words).
    Truncation (barge-in) is not an error here; substitutions and insertions are."""
    ref, hyp = normalise(reference), normalise(hypothesis)
    if not hyp:
        return None
    d = [0] * (len(hyp) + 1)
    for rw in ref:
        prev = 0
        for j, hw in enumerate(hyp, 1):
            cur = prev + 1 if rw == hw else max(d[j], d[j - 1])
            prev, d[j] = d[j], cur
    return round(d[len(hyp)] / len(hyp), 3)
