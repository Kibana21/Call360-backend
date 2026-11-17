"""S1-C consent-gated recording: encrypted local object store, consent, chunk intake, coverage, retention.

Capture is client-side (it keeps working when S1-E moves audio to WebRTC): the browser records two tracks from one
16 kHz AudioContext clock — ``MIC`` (the microphone frames it sends) and ``PROVIDER_PLAYBACK`` (provider audio as
rendered by the browser audio graph after barge-in clearing; not acoustic speaker output) — and uploads PCM16 chunks
numbered by connection **segment** and sequence. This module decides what is accepted and what the evidence says:

- consent (D-45): decided at session creation, default DECLINED, stored in the insert-only session ledger with the
  test notice version and its SHA-256; nothing is accepted for a session without GRANTED consent;
- chunks (SEC-010): server-generated object keys, exclusive writes (no overwrite), size, parity, sample count and
  SHA-256 checked, and no chunk may claim more audio than time has elapsed since its segment started;
- finalisation (VOICE-010, EVD-003): coverage is computed from what is stored — missing sequences, discontinuities,
  interruptions between segments and unconfirmed ends are gaps; nothing is filled or backfilled;
- retention (D-47): a local setting; expiry deletes audio objects and keeps every row, checksum and event.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.voice.provider import SAMPLE_RATE
from app.voice.store import append_event

TRACKS = ("MIC", "PROVIDER_PLAYBACK")
CODEC = "audio/L16"
CHUNK_MAX_SAMPLES = SAMPLE_RATE * 2  # 2 s
MAX_SEQ = 10_000
UPLOAD_GRACE = timedelta(seconds=30)
TIME_TOLERANCE_S = 2.0
NOTICE_VERSION = "S1C-TEST-1"
NOTICE_TEXT = (
    "Synthetic test recording (local development only). If you choose to record, Call360 stores your microphone "
    "audio and the test audio played in this browser for this test session, encrypted on this computer, and deletes "
    "it automatically after the local retention period. Do not say any real personal or customer information. "
    "Recording is optional: the voice test works the same if you do not record. This test-only notice is not "
    "approved AIA or MAS consent wording."
)
NOTICE_SHA256 = hashlib.sha256(NOTICE_TEXT.encode()).hexdigest()
CLOSE_REASONS = {"STOPPED", "MIC_DEVICE_LOST", "CONNECTION_LOST", "PAGE_CLOSED", "UPLOAD_FAILED", "CAPTURE_ERROR"}
# Audio chunks (S1-C) and, from S1-D, one encrypted transcript text object per transcription run.
_KEY_RE = re.compile(r"^[0-9a-f-]{36}/(MIC|PROVIDER_PLAYBACK)/([0-9]{3}-[0-9]{6}|transcript-r[0-9]{3})\.c360$")
_FORMAT = b"\x01"


class RecordingError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# ---- object store ----------------------------------------------------------------------------------------------
class EncryptedObjectStore:
    """Local filesystem object store: AES-256-GCM per object (random nonce; the object key is the associated data, so
    an object copied to another key fails to decrypt), exclusive creation (no overwrite), keys validated and confined
    to the root. Paths never leave this class."""

    backend = "LOCAL_ENCRYPTED"

    def __init__(self, root: Path, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("recording key must be 32 bytes")
        self.root = root
        self._aead = AESGCM(key)
        self.key_id = hmac.new(key, b"call360-recording-key-id", hashlib.sha256).hexdigest()[:12]

    def _path(self, key: str) -> Path:
        if not _KEY_RE.match(key):
            raise RecordingError(422, "OBJECT_KEY_INVALID", "invalid object key")
        root = self.root.resolve()
        path = (root / key).resolve()
        if root not in path.parents:
            raise RecordingError(422, "OBJECT_KEY_INVALID", "invalid object key")
        return path

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        nonce = os.urandom(12)
        blob = _FORMAT + nonce + self._aead.encrypt(nonce, data, key.encode())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never overwrite
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            return None
        if blob[:1] != _FORMAT:
            return None
        try:
            return self._aead.decrypt(blob[1:13], blob[13:], key.encode())
        except InvalidTag:
            return None

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> None:
        path = self._path(key)
        path.unlink(missing_ok=True)


def store_for(app: Any) -> EncryptedObjectStore | None:
    """The process's recording store, or ``None`` when no recording key is configured (recording NOT_AVAILABLE)."""
    if getattr(app.state, "recording_store", None) is not None:
        rs: EncryptedObjectStore = app.state.recording_store
        return rs
    settings: Settings = app.state.settings
    if settings.recording_encryption_key is None:
        return None
    from app.domain.protection import decode_key

    root = settings.recording_storage_dir.expanduser() / settings.target_schema
    app.state.recording_store = EncryptedObjectStore(
        root, decode_key(settings.recording_encryption_key.get_secret_value())
    )
    return app.state.recording_store  # type: ignore[no-any-return]


def object_key(attempt_id: uuid.UUID, track: str, segment: int, seq: int) -> str:
    return f"{attempt_id}/{track}/{segment:03d}-{seq:06d}.c360"


# ---- consent and lifecycle -------------------------------------------------------------------------------------
def record_consent(db: Session, attempt_id: uuid.UUID, *, granted: bool, actor: str, defaulted: bool) -> None:
    append_event(
        db,
        attempt_id,
        "RECORDING_CONSENT_GRANTED" if granted else "RECORDING_CONSENT_DECLINED",
        actor=actor,
        details={
            "notice_version": NOTICE_VERSION,
            "notice_sha256": NOTICE_SHA256,
            "decided_by": actor,
            "defaulted": defaulted,
            "basis": "TEST_NOTICE_NOT_APPROVED_POLICY",
        },
    )


def consent_of(db: Session, attempt_id: uuid.UUID) -> dict[str, Any] | None:
    r = (
        db.execute(
            text(
                "SELECT seq, event_type, occurred_at, details FROM session_event WHERE contact_attempt_id = :a "
                "AND event_type IN ('RECORDING_CONSENT_GRANTED', 'RECORDING_CONSENT_DECLINED') ORDER BY seq LIMIT 1"
            ),
            {"a": attempt_id},
        )
        .mappings()
        .first()
    )
    if r is None:
        return None
    return {
        "seq": r["seq"],
        "decision": "GRANTED" if r["event_type"] == "RECORDING_CONSENT_GRANTED" else "DECLINED",
        "decided_at": r["occurred_at"],
        **dict(r["details"]),
    }


_ASSETS = "SELECT * FROM media_asset WHERE contact_attempt_id = :a ORDER BY track"
_ASSETS_LOCK = _ASSETS + " FOR UPDATE"


def _assets(db: Session, attempt_id: uuid.UUID, *, lock: bool = False) -> list[dict[str, Any]]:
    sql = _ASSETS_LOCK if lock else _ASSETS
    rows = db.execute(text(sql), {"a": attempt_id}).mappings()
    return [dict(r) for r in rows]


def _segments(db: Session, attempt_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            "SELECT occurred_at, details FROM session_event WHERE contact_attempt_id = :a "
            "AND event_type = 'RECORDING_STARTED' ORDER BY seq"
        ),
        {"a": attempt_id},
    ).mappings()
    return [{"segment": int(dict(r["details"])["segment"]), "started_at": r["occurred_at"]} for r in rows]


def on_connect(
    db: Session, rs: EncryptedObjectStore | None, attempt_id: uuid.UUID, *, actor: str, retention_hours: int
) -> dict[str, Any]:
    """Called inside the connect transaction. With GRANTED consent, the first connection creates one ``media_asset``
    per track and every connection opens a new segment. Returns what the browser is told on ``session.ready``."""
    consent = consent_of(db, attempt_id)
    if consent is None or consent["decision"] != "GRANTED":
        return {"state": "NOT_RECORDED", "reason": "CONSENT_DECLINED"}
    if rs is None:  # consent recorded but no store: honest failure, nothing captured
        return {"state": "NOT_RECORDED", "reason": "RECORDING_NOT_CONFIGURED"}
    session = db.execute(
        text("SELECT id, session_ref FROM conversation_session WHERE contact_attempt_id = :a"), {"a": attempt_id}
    ).one()
    assets = _assets(db, attempt_id, lock=True)
    now = datetime.now(UTC)
    if not assets:
        for track in TRACKS:
            db.execute(
                text(
                    "INSERT INTO media_asset (id, asset_ref, contact_attempt_id, conversation_session_id, track, "
                    "source, codec, sample_rate, channels, status, coverage, consent_event_seq, "
                    "consent_notice_version, consent_notice_sha256, storage_backend, key_id, started_at, "
                    "retention_until, is_synthetic, record_origin, created_by, updated_at, updated_by) VALUES "
                    "(:id, :ref, :a, :s, :t, 'BROWSER_CAPTURE', :codec, :sr, 1, 'CAPTURING', 'PENDING', :cs, :nv, "
                    ":nh, :be, :kid, :now, :ret, true, 'CALL360_RUNTIME', :by, :now, :by)"
                ),
                {
                    "id": uuid.uuid4(),
                    "ref": f"MA-{session.session_ref.removeprefix('SS-')}-{'M' if track == 'MIC' else 'P'}",
                    "a": attempt_id,
                    "s": session.id,
                    "t": track,
                    "codec": CODEC,
                    "sr": SAMPLE_RATE,
                    "cs": consent["seq"],
                    "nv": consent["notice_version"],
                    "nh": consent["notice_sha256"],
                    "be": rs.backend,
                    "kid": rs.key_id,
                    "now": now,
                    "ret": now + timedelta(hours=retention_hours),
                    "by": actor,
                },
            )
    elif any(a["status"] != "CAPTURING" for a in assets):
        return {"state": "NOT_RECORDED", "reason": "RECORDING_CLOSED"}
    segment = len(_segments(db, attempt_id)) + 1
    append_event(
        db,
        attempt_id,
        "RECORDING_STARTED",
        actor=actor,
        details={"segment": segment, "tracks": list(TRACKS), "codec": CODEC, "sample_rate": SAMPLE_RATE},
    )
    _set_session_media(db, attempt_id, "CAPTURING", actor)
    return {
        "state": "RECORDING",
        "segment": segment,
        "chunk_max_samples": CHUNK_MAX_SAMPLES,
        "codec": CODEC,
        "sample_rate": SAMPLE_RATE,
        "tracks": list(TRACKS),
    }


def _set_session_media(db: Session, attempt_id: uuid.UUID, status: str, actor: str) -> None:
    db.execute(
        text(
            "UPDATE conversation_session SET media_status = :m, updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE contact_attempt_id = :a AND media_status IS DISTINCT FROM :m"
        ),
        {"m": status, "by": actor, "a": attempt_id},
    )


def on_session_end(db: Session, rs: EncryptedObjectStore | None, attempt_id: uuid.UUID, *, actor: str) -> None:
    """The session is final: capture has ended; late chunks are accepted for ``UPLOAD_GRACE``, then finalised."""
    assets = _assets(db, attempt_id, lock=True)
    if not assets:
        return
    for a in assets:
        if a["status"] == "CAPTURING":
            db.execute(
                text(
                    "UPDATE media_asset SET status = 'UPLOADING', capture_ended_at = now(), updated_at = now(), "
                    "updated_by = :by, row_version = row_version + 1 WHERE id = :id"
                ),
                {"by": actor, "id": a["id"]},
            )
    _set_session_media(db, attempt_id, "UPLOADING", actor)
    maybe_finalize(db, rs, attempt_id, actor=actor)


# ---- chunks ----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Chunk:
    track: str
    segment: int
    seq: int
    start_sample: int
    sample_count: int
    sha256: str
    data_b64: str
    captured_at: datetime | None = None


def accept_chunk(
    db: Session, rs: EncryptedObjectStore | None, attempt_id: uuid.UUID, c: Chunk, *, actor: str
) -> dict[str, Any]:
    if rs is None:
        raise RecordingError(409, "RECORDING_NOT_AVAILABLE", "Recording is not configured on this server")
    consent = consent_of(db, attempt_id)
    if consent is None or consent["decision"] != "GRANTED":
        raise RecordingError(409, "RECORDING_NOT_CONSENTED", "Recording consent was not granted for this session")
    if c.track not in TRACKS:
        raise RecordingError(422, "TRACK_INVALID", "Unknown track")
    asset = next((a for a in _assets(db, attempt_id, lock=True) if a["track"] == c.track), None)
    if asset is None:
        raise RecordingError(409, "RECORDING_NOT_ACTIVE", "No recording is active for this session")
    now = datetime.now(UTC)
    late_ok = (
        asset["status"] == "UPLOADING" and asset["capture_ended_at"] and now - asset["capture_ended_at"] <= UPLOAD_GRACE
    )
    if asset["status"] != "CAPTURING" and not late_ok:
        raise RecordingError(409, "RECORDING_CLOSED", f"The recording track is {asset['status']}")
    segments = {s["segment"]: s["started_at"] for s in _segments(db, attempt_id)}
    if c.segment not in segments:
        raise RecordingError(422, "SEGMENT_INVALID", "Unknown recording segment")
    if not 1 <= c.seq <= MAX_SEQ or c.start_sample < 0 or not 0 < c.sample_count <= CHUNK_MAX_SAMPLES:
        raise RecordingError(422, "CHUNK_INVALID", "Chunk position or size out of range")
    if not re.fullmatch(r"[0-9a-f]{64}", c.sha256):
        raise RecordingError(422, "CHUNK_INVALID", "Checksum must be lowercase hex SHA-256")
    try:
        data = base64.b64decode(c.data_b64, validate=True)
    except ValueError as exc:
        raise RecordingError(422, "CHUNK_INVALID", "Chunk data is not base64") from exc
    if len(data) != c.sample_count * 2:
        raise RecordingError(422, "CHUNK_SIZE_MISMATCH", "Chunk size does not match its sample count (PCM16 mono)")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), c.sha256):
        raise RecordingError(422, "CHUNK_CHECKSUM_MISMATCH", "Chunk checksum does not match its data")
    # No chunk may claim more audio than has elapsed since its segment started: no pre-segment (pre-consent) audio.
    elapsed = (now - segments[c.segment]).total_seconds()
    if (c.start_sample + c.sample_count) / SAMPLE_RATE > elapsed + TIME_TOLERANCE_S:
        raise RecordingError(422, "CHUNK_OUTSIDE_SESSION", "Chunk claims audio beyond the time elapsed in its segment")
    existing = db.execute(
        text("SELECT sha256 FROM media_chunk WHERE media_asset_id = :m AND segment = :g AND seq = :q"),
        {"m": asset["id"], "g": c.segment, "q": c.seq},
    ).first()
    if existing is not None:
        if existing.sha256 == c.sha256:
            return {"stored": False, "duplicate": True}
        raise RecordingError(409, "CHUNK_CONFLICT", "A different chunk is already stored at this position")
    key = object_key(attempt_id, c.track, c.segment, c.seq)
    if rs.exists(key):  # an object without a row (an earlier failed transaction): never overwrite, refuse
        raise RecordingError(409, "CHUNK_CONFLICT", "Chunk object already exists")
    rs.put(key, data)
    try:
        db.execute(
            text(
                "INSERT INTO media_chunk (id, media_asset_id, segment, seq, start_sample, sample_count, byte_size, "
                "sha256, object_key, client_captured_at, created_by) VALUES (:id, :m, :g, :q, :st, :n, :b, :h, :k, "
                ":ca, :by)"
            ),
            {
                "id": uuid.uuid4(),
                "m": asset["id"],
                "g": c.segment,
                "q": c.seq,
                "st": c.start_sample,
                "n": c.sample_count,
                "b": len(data),
                "h": c.sha256,
                "k": key,
                "ca": c.captured_at,
                "by": actor,
            },
        )
        db.execute(
            text(
                "UPDATE media_asset SET chunks_stored = chunks_stored + 1, samples_stored = samples_stored + :n, "
                "bytes_stored = bytes_stored + :b, updated_at = now(), updated_by = :by, row_version = row_version + 1 "
                "WHERE id = :id"
            ),
            {"n": c.sample_count, "b": len(data), "by": actor, "id": asset["id"]},
        )
        db.flush()
    except Exception:
        rs.delete(key)  # the row failed: remove the object so no unreferenced audio remains
        raise
    if asset["status"] == "UPLOADING":  # a late chunk may be the last one a closed manifest was waiting for
        maybe_finalize(db, rs, attempt_id, actor=actor)
    return {"stored": True, "duplicate": False}


def close_track(
    db: Session,
    rs: EncryptedObjectStore | None,
    attempt_id: uuid.UUID,
    *,
    track: str,
    segment: int,
    chunks: int,
    failed: list[int],
    reason: str,
    actor: str,
) -> dict[str, Any]:
    """The browser's manifest for one track and segment: how many chunks it produced, which it could not upload."""
    if track not in TRACKS:
        raise RecordingError(422, "TRACK_INVALID", "Unknown track")
    asset = next((a for a in _assets(db, attempt_id, lock=True) if a["track"] == track), None)
    if asset is None:
        raise RecordingError(409, "RECORDING_NOT_ACTIVE", "No recording exists for this session")
    if segment not in {s["segment"] for s in _segments(db, attempt_id)}:
        raise RecordingError(422, "SEGMENT_INVALID", "Unknown recording segment")
    if not 0 <= chunks <= MAX_SEQ or any(not 1 <= f <= chunks for f in failed):
        raise RecordingError(422, "MANIFEST_INVALID", "Manifest counts out of range")
    manifests = dict(asset["close_manifests"])
    entry: dict[str, Any] = {
        "chunks": chunks,
        "failed": sorted(set(failed)),
        "reason": reason if reason in CLOSE_REASONS else "STOPPED",
    }
    if str(segment) in manifests:
        if manifests[str(segment)] == entry:
            return {"duplicate": True}
        raise RecordingError(409, "MANIFEST_CONFLICT", "This segment was already closed with a different manifest")
    if asset["status"] not in ("CAPTURING", "UPLOADING"):
        raise RecordingError(409, "RECORDING_CLOSED", f"The recording track is {asset['status']}")
    manifests[str(segment)] = entry
    db.execute(
        text(
            "UPDATE media_asset SET close_manifests = CAST(:m AS jsonb), updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE id = :id"
        ),
        {"m": json.dumps(manifests), "by": actor, "id": asset["id"]},
    )
    append_event(
        db,
        attempt_id,
        "RECORDING_TRACK_CLOSED",
        source="CLIENT",
        actor=actor,
        details={
            "track": track,
            "segment": segment,
            "chunks": chunks,
            "failed": len(entry["failed"]),
            "reason": entry["reason"],
        },
    )
    maybe_finalize(db, rs, attempt_id, actor=actor)
    return {"duplicate": False}


# ---- finalisation ----------------------------------------------------------------------------------------------
def _chunks(db: Session, asset_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.execute(
        text(
            "SELECT segment, seq, start_sample, sample_count, byte_size, sha256, object_key FROM media_chunk "
            "WHERE media_asset_id = :m ORDER BY segment, seq"
        ),
        {"m": asset_id},
    ).mappings()
    return [dict(r) for r in rows]


def maybe_finalize(
    db: Session, rs: EncryptedObjectStore | None, attempt_id: uuid.UUID, *, actor: str, force: bool = False
) -> list[str]:
    """Finalise UPLOADING tracks once every segment is closed and every declared chunk is stored, or (``force``, the
    sweeper) once the upload window has passed."""
    done: list[str] = []
    segments = _segments(db, attempt_id)
    for a in _assets(db, attempt_id, lock=True):
        if a["status"] != "UPLOADING":
            continue
        manifests = dict(a["close_manifests"])
        chunks = _chunks(db, a["id"])
        stored = {(c["segment"], c["seq"]) for c in chunks}
        all_closed = all(str(s["segment"]) in manifests for s in segments)
        all_in = all_closed and all(
            (int(g), q) in stored or q in m["failed"] for g, m in manifests.items() for q in range(1, m["chunks"] + 1)
        )
        if all_in or force:
            _finalize_asset(db, rs, attempt_id, a, segments, chunks, actor=actor)
            done.append(a["track"])
    if done:
        _aggregate(db, attempt_id, actor)
    return done


def _finalize_asset(
    db: Session,
    rs: EncryptedObjectStore | None,
    attempt_id: uuid.UUID,
    a: dict[str, Any],
    segments: list[dict[str, Any]],
    chunks: list[dict[str, Any]],
    *,
    actor: str,
) -> None:
    manifests = dict(a["close_manifests"])
    gaps: list[dict[str, Any]] = []
    good: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for s in segments:
        g = s["segment"]
        if g > 1:
            gaps.append({"type": "SESSION_INTERRUPTED", "segment": g})
        mine = [c for c in chunks if c["segment"] == g]
        m = manifests.get(str(g))
        expected = m["chunks"] if m else max((c["seq"] for c in mine), default=0)
        have = {c["seq"] for c in mine}
        for q in range(1, expected + 1):
            if q not in have:
                gaps.append({"type": "UPLOAD_FAILED" if m and q in m["failed"] else "MISSING", "segment": g, "seq": q})
        if m is None:
            gaps.append({"type": "END_NOT_CONFIRMED", "segment": g})
        elif m["reason"] != "STOPPED":  # capture ended by device loss, a dropped connection, a closed page…
            gaps.append({"type": "CAPTURE_INTERRUPTED", "segment": g, "reason": m["reason"]})
        cursor = 0
        prev_seq = 0
        for c in mine:
            if c["seq"] == prev_seq + 1 and c["start_sample"] != cursor:
                gaps.append(
                    {"type": "DISCONTINUITY", "segment": g, "seq": c["seq"], "samples": c["start_sample"] - cursor}
                )
            data = rs.get(c["object_key"]) if rs else None
            if data is None or hashlib.sha256(data).hexdigest() != c["sha256"]:
                gaps.append({"type": "OBJECT_UNREADABLE", "segment": g, "seq": c["seq"]})
            else:
                digest.update(data)
                good.append(c)
            cursor, prev_seq = c["start_sample"] + c["sample_count"], c["seq"]
    status = "AVAILABLE" if good else "FAILED"
    coverage = "NONE" if not good else ("COMPLETE" if not gaps else "PARTIAL")
    manifest = {
        "asset_ref": a["asset_ref"],
        "track": a["track"],
        "codec": a["codec"],
        "sample_rate": a["sample_rate"],
        "consent_event_seq": a["consent_event_seq"],
        "consent_notice_sha256": a["consent_notice_sha256"],
        "chunks": [[c["segment"], c["seq"], c["start_sample"], c["sample_count"], c["sha256"]] for c in good],
        "gaps": gaps,
    }
    db.execute(
        text(
            "UPDATE media_asset SET status = :st, coverage = :cov, gaps = CAST(:gaps AS jsonb), content_sha256 = :ch, "
            "manifest_sha256 = :mh, finalized_at = now(), updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE id = :id"
        ),
        {
            "st": status,
            "cov": coverage,
            "gaps": json.dumps(gaps),
            "ch": digest.hexdigest() if good else None,
            "mh": hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "by": actor,
            "id": a["id"],
        },
    )
    append_event(
        db,
        attempt_id,
        "RECORDING_FINALIZED",
        source="SYSTEM" if actor.startswith("SYSTEM") else "SERVER",
        actor=actor,
        details={"track": a["track"], "status": status, "coverage": coverage, "chunks": len(good), "gaps": len(gaps)},
    )


def _aggregate(db: Session, attempt_id: uuid.UUID, actor: str) -> None:
    sts = {a["status"] for a in _assets(db, attempt_id)}
    if sts & {"CAPTURING", "UPLOADING"}:
        return
    if sts == {"PURGED"}:
        session_status = "PURGED"
    elif "AVAILABLE" in sts:
        session_status = "AVAILABLE"
    else:
        session_status = "FAILED"
    _set_session_media(db, attempt_id, session_status, actor)


# ---- sweep: late finalisation and retention --------------------------------------------------------------------
def sweep(db: Session, rs: EncryptedObjectStore | None, *, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(UTC)
    out: list[str] = []
    stale = db.execute(
        text(
            "SELECT DISTINCT a.contact_attempt_id FROM media_asset a "
            "LEFT JOIN conversation_session s ON s.contact_attempt_id = a.contact_attempt_id "
            "WHERE (a.status = 'UPLOADING' "
            "AND a.capture_ended_at < :cut) OR (a.status = 'CAPTURING' AND s.state IN ('FINALIZED', 'ABORTED'))"
        ),
        {"cut": now - UPLOAD_GRACE},
    ).scalars()
    for attempt_id in list(stale):
        on_session_end(db, rs, attempt_id, actor="SYSTEM:recording-sweeper")
        for t in maybe_finalize(db, rs, attempt_id, actor="SYSTEM:recording-sweeper", force=True):
            out.append(f"{attempt_id}:{t}:FINALIZED")
    expired = db.execute(
        text(
            "SELECT id, contact_attempt_id, track FROM media_asset WHERE status IN ('AVAILABLE', 'FAILED') "
            "AND retention_until < :now"
        ),
        {"now": now},
    ).all()
    for r in expired:
        purge(db, rs, r.id, actor="SYSTEM:recording-retention", reason="LOCAL_RETENTION_EXPIRED")
        out.append(f"{r.contact_attempt_id}:{r.track}:PURGED")
    return out


def purge(db: Session, rs: EncryptedObjectStore | None, asset_id: uuid.UUID, *, actor: str, reason: str) -> None:
    a = db.execute(text("SELECT * FROM media_asset WHERE id = :i FOR UPDATE"), {"i": asset_id}).mappings().one()
    if a["status"] == "PURGED":
        return
    removed = 0
    for c in _chunks(db, asset_id):
        if rs is not None:
            rs.delete(c["object_key"])
            removed += 1
    db.execute(
        text(
            "UPDATE media_asset SET status = 'PURGED', purged_at = now(), purge_reason = :r, updated_at = now(), "
            "updated_by = :by, row_version = row_version + 1 WHERE id = :i"
        ),
        {"r": reason, "by": actor, "i": asset_id},
    )
    append_event(
        db,
        a["contact_attempt_id"],
        "RECORDING_PURGED",
        source="SYSTEM",
        actor=actor,
        details={"track": a["track"], "reason": reason, "objects_removed": removed},
    )
    _aggregate(db, a["contact_attempt_id"], actor)
    if db.execute(text("SELECT to_regclass('transcript_run')")).scalar() is not None:
        from app.voice import transcript  # S1-D: transcript text follows the audio's retention

        transcript.purge_asset(db, rs, asset_id, actor=actor)


# ---- summaries and retrieval -----------------------------------------------------------------------------------
def summary(db: Session, attempt_id: uuid.UUID) -> dict[str, Any]:
    """The recording evidence of one session: derived status, consent and per-track manifest metadata (no keys)."""
    consent = consent_of(db, attempt_id)
    assets = _assets(db, attempt_id)
    tracks = [
        {
            "track": a["track"],
            "asset_ref": a["asset_ref"],
            "media_status": a["status"],
            "coverage": a["coverage"],
            "codec": f"{a['codec']};rate={a['sample_rate']}",
            "started_at": a["started_at"],
            "capture_ended_at": a["capture_ended_at"],
            "finalized_at": a["finalized_at"],
            "chunks_stored": a["chunks_stored"],
            "duration_ms": a["samples_stored"] * 1000 // a["sample_rate"],
            "bytes_stored": a["bytes_stored"],
            "gaps": list(a["gaps"]),
            "content_sha256": a["content_sha256"],
            "manifest_sha256": a["manifest_sha256"],
            "retention_until": a["retention_until"],
            "purged_at": a["purged_at"],
        }
        for a in assets
    ]
    return {
        "status": derive_status(consent, assets),
        "consent": consent["decision"] if consent else "NOT_ASKED",
        "consent_at": consent["decided_at"] if consent else None,
        "notice_version": consent.get("notice_version") if consent else None,
        "tracks": tracks,
    }


def derive_status(consent: dict[str, Any] | None, assets: list[dict[str, Any]]) -> str:
    if not assets:
        return "NOT_RECORDED"
    sts = [a["status"] for a in assets]
    if any(s in ("CAPTURING", "UPLOADING") for s in sts):
        return "RECORDING"
    if all(s == "PURGED" for s in sts):
        return "PURGED"
    if all(s == "FAILED" for s in sts):
        return "FAILED"
    if all(s == "AVAILABLE" and a["coverage"] == "COMPLETE" for s, a in zip(sts, assets, strict=True)):
        return "COMPLETE"
    return "PARTIAL"


def audio_stream(
    db: Session, rs: EncryptedObjectStore, attempt_id: uuid.UUID, track: str
) -> tuple[dict[str, Any], Iterator[bytes]] | None:
    """A WAV of the stored chunks in order (gaps are listed in the manifest, never filled) and the asset row."""
    a = next((x for x in _assets(db, attempt_id) if x["track"] == track), None)
    if a is None or a["status"] != "AVAILABLE":
        return None
    chunks = [c for c in _chunks(db, a["id"])]
    payload: list[bytes] = []
    digest = hashlib.sha256()
    for c in chunks:
        data = rs.get(c["object_key"])
        if data is None or hashlib.sha256(data).hexdigest() != c["sha256"]:
            continue  # unreadable objects were already recorded as gaps at finalisation
        digest.update(data)
        payload.append(data)
    if digest.hexdigest() != a["content_sha256"]:
        raise RecordingError(409, "RECORDING_INTEGRITY_FAILED", "Stored audio no longer matches its checksum")
    size = sum(len(p) for p in payload)
    header = _wav_header(size)

    def gen() -> Iterator[bytes]:
        yield header
        yield from payload

    return a, gen()


def _wav_header(data_len: int, rate: int = SAMPLE_RATE) -> bytes:
    import struct

    return (
        b"RIFF"
        + struct.pack("<I", 36 + data_len)
        + b"WAVEfmt "
        + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
        + b"data"
        + struct.pack("<I", data_len)
    )
