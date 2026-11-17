"""S1-D transcript and playback mapping through the real API, database, encrypted store and the pinned local engine.

Covers: both speaker tracks; barge-in (interrupted mock speech is transcribed as rendered, never completed from the
script); missing chunks and the recording-time ↔ WAV mapping; silence and non-speech; uncertain recognition;
failure, retry and lease recovery; authorisation and audit; encryption, integrity and retention; status vocabulary.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
import wave
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.voice import media, transcript
from app.voice.mock import ASSETS, FIXED_MESSAGE
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_voice import ORIGIN, _callable_case
from tests.test_voice_sessions import until

pytestmark = pytest.mark.usefixtures("seeded")
GOLDEN = Path(__file__).parent / "fixtures" / "golden_audio"
CH = media.CHUNK_MAX_SAMPLES  # 2 s chunks, as the browser sends them


@pytest.fixture(autouse=True)
def stores(app: Any, tmp_path: Path, asr: transcript.FasterWhisperEngine, monkeypatch: pytest.MonkeyPatch) -> Any:
    rs = media.EncryptedObjectStore(tmp_path / "recordings", __import__("os").urandom(32))
    app.state.recording_store = rs
    app.state.transcription_engine = asr
    monkeypatch.setattr(media, "TIME_TOLERANCE_S", 600.0)  # tests upload whole recordings at once
    return rs


def wav_pcm(path: Path) -> bytes:
    with wave.open(str(path)) as w:
        return w.readframes(w.getnframes())


def silence(seconds: float) -> bytes:
    return b"\x00\x00" * int(seconds * 16000)


def tone(seconds: float, hz: float = 220.0) -> bytes:
    t = np.arange(int(seconds * 16000)) / 16000
    return (0.3 * np.sin(2 * np.pi * hz * t) * 32767).astype("<i2").tobytes()


def chunks_of(pcm: bytes) -> list[bytes]:
    return [pcm[i : i + CH * 2] for i in range(0, len(pcm), CH * 2)]


def upload(client: TestClient, sid: str, track: str, pcm: bytes, *, skip: set[int] = frozenset()) -> int:  # type: ignore[assignment]
    parts = chunks_of(pcm)
    pos = 0
    for seq, data in enumerate(parts, 1):
        if seq not in skip:
            r = client.post(
                f"/api/v1/voice/sessions/{sid}/recording/chunks",
                json={
                    "track": track,
                    "segment": 1,
                    "seq": seq,
                    "start_sample": pos,
                    "sample_count": len(data) // 2,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "data_b64": base64.b64encode(data).decode(),
                },
                headers=csrf_header(client),
            )
            assert r.status_code == 200, r.text
        pos += len(data) // 2
    return len(parts)


def recorded_session(
    client: TestClient,
    conn: Connection,
    mic: bytes,
    provider: bytes,
    *,
    mic_skip: set[int] = frozenset(),  # type: ignore[assignment]
) -> tuple[str, uuid.UUID]:
    case_id, _ = _callable_case(conn)
    r = client.post(
        "/api/v1/voice/sessions",
        json={"case_id": str(case_id), "recording_consent": "GRANTED", "consent_notice_version": media.NOTICE_VERSION},
        headers=csrf_header(client),
    )
    assert r.status_code == 201, r.text
    s = r.json()
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        n_mic = upload(client, s["session_id"], "MIC", mic, skip=mic_skip)
        n_pro = upload(client, s["session_id"], "PROVIDER_PLAYBACK", provider)
        tracks = [
            {"track": "MIC", "segment": 1, "chunks": n_mic, "failed": sorted(mic_skip), "reason": "STOPPED"},
            {"track": "PROVIDER_PLAYBACK", "segment": 1, "chunks": n_pro, "failed": [], "reason": "STOPPED"},
        ]
        assert (
            client.post(
                f"/api/v1/voice/sessions/{s['session_id']}/recording/close",
                json={"tracks": tracks},
                headers=csrf_header(client),
            ).status_code
            == 200
        )
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    sess = conn.execute(
        text(f"SELECT id FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
    ).scalar_one()
    return s["session_id"], sess


def overview(client: TestClient, sess: uuid.UUID) -> dict[str, Any]:
    r = client.get(f"/api/v1/sessions/{sess}/transcript")
    assert r.status_code == 200, r.text
    return dict(r.json())


def segs(client: TestClient, sess: uuid.UUID) -> dict[str, Any]:
    r = client.get(f"/api/v1/sessions/{sess}/transcript/segments")
    assert r.status_code == 200, r.text
    return dict(r.json())


def column(conn: Connection, sess: uuid.UUID) -> str:
    return str(
        conn.execute(
            text(f"SELECT transcript_status FROM {SCHEMA}.conversation_session WHERE id = :s"), {"s": sess}
        ).scalar_one()
    )


def transcribe(app: Any, attempt: str) -> list[str]:
    return transcript.work(app, attempt_id=uuid.UUID(attempt))


# ---- both tracks, speakers, times, provenance, encryption, audit --------------------------------------------
def test_both_tracks_transcribed_with_speakers_times_provenance_and_audited_access(
    app: Any, client: TestClient, user: Account, conn: Connection, stores: media.EncryptedObjectStore
) -> None:
    login(client, user)
    mic = wav_pcm(GOLDEN / "g02_gb_two_turns.wav")
    # Mock sentences 2 and 3 ("Call360" in sentence 1 gets an uncertain-word marker from the engine: see below).
    provider = wav_pcm(ASSETS / "test_2.wav") + silence(1.0) + wav_pcm(ASSETS / "test_3.wav")
    attempt, sess = recorded_session(client, conn, mic, provider)
    before = overview(client, sess)
    assert (before["status"], before["reason"]) == ("PENDING", "QUEUED") and before["availability"] == "PENDING"
    done = transcribe(app, attempt)
    assert sorted(d.split(":")[-1] for d in done) == ["DONE", "DONE"]
    o = overview(client, sess)
    assert (o["status"], o["availability"], o["review_status"], o["can_read_text"]) == (
        "COMPLETE",
        "AVAILABLE",
        "NOT_REVIEWED",
        True,
    )
    assert column(conn, sess) == o["session_transcript_status"] == "FINALIZED"
    run = o["tracks"][0]["run"]
    assert (run["engine"], run["model_id"], run["model_revision"], run["language"]) == (
        "faster-whisper",
        transcript.MODEL_ID,
        transcript.MODEL_REVISION,
        "en",
    )
    assert run["model_sha256"] == transcript.MODEL_FILES["model.bin"] and run["config"]["decode"]["beam_size"] == 5
    assert run["metrics"]["realtime_factor"] < 1.0  # faster than real time on this machine
    out = segs(client, sess)
    mine = [s for s in out["segments"] if s["track"] == "MIC"]
    theirs = [s for s in out["segments"] if s["track"] == "PROVIDER_PLAYBACK"]
    assert [s["text"] for s in mine] == ["Yes, I understand the policy.", "Please call me back tomorrow afternoon."]
    assert {s["speaker"] for s in mine} == {"CALLER_MIC"} and {s["speaker"] for s in theirs} == {"MOCK_PROVIDER"}
    assert transcript.word_error_rate(" ".join(FIXED_MESSAGE[1:3]), " ".join(s["text"] for s in theirs)) <= 0.1
    assert abs(mine[1]["timeline_start_ms"] - 4650) <= 400  # measured onset of the second turn in the golden clip
    assert all(s["wav_offset_ms"] == s["timeline_start_ms"] for s in out["segments"])  # no gap: same position
    assert all(w["timeline_start_ms"] >= s["timeline_start_ms"] - 50 for s in mine for w in s["words"])
    pro_run = next(t["run"] for t in o["tracks"] if t["track"] == "PROVIDER_PLAYBACK")
    assert pro_run["metrics"]["engine_check"]["recognised_word_precision"] >= 0.9
    # Encrypted at rest: transcript text objects never contain the plaintext; nothing in the ledger or events.
    objects = sorted(stores.root.rglob("transcript-r*.c360"))
    assert len(objects) == 2 and all(b"understand" not in p.read_bytes() for p in objects)
    st = client.get(f"/api/v1/voice/sessions/{attempt}").json()
    kinds = [e["event_type"] for e in st["events"]]
    assert kinds.count("TRANSCRIPT_STARTED") == 2 and kinds.count("TRANSCRIPT_COMPLETED") == 2
    assert "understand" not in json.dumps(st) and "understand" not in json.dumps(o)
    assert ".c360" not in json.dumps(out) and "object_key" not in json.dumps(out)
    audit = conn.execute(
        text(f"SELECT after FROM {SCHEMA}.audit_event WHERE action = 'TRANSCRIPT.ACCESSED' AND entity_id = :s"),
        {"s": str(sess)},
    ).all()
    assert len(audit) == 1 and "understand" not in json.dumps(audit[0].after)
    # Idempotent worker: another pass changes nothing.
    assert transcribe(app, attempt) == []
    # Immutable provenance and insert-only segments.
    with pytest.raises(Exception, match="immutable|final"):
        conn.execute(
            text(f"UPDATE {SCHEMA}.transcript_run SET model_id = 'x' WHERE contact_attempt_id = :a"), {"a": attempt}
        )
    conn.rollback()
    with pytest.raises(Exception):  # noqa: B017 — the forbid_change trigger refuses any segment change
        conn.execute(text(f"DELETE FROM {SCHEMA}.transcript_segment WHERE contact_attempt_id = :a"), {"a": attempt})
    conn.rollback()


# ---- barge-in: interrupted mock speech is what was rendered, never completed from the script ----------------
def test_interrupted_mock_speech_is_transcribed_as_rendered_and_overlap_flagged(
    app: Any, client: TestClient, user: Account, conn: Connection
) -> None:
    login(client, user)
    full = wav_pcm(ASSETS / "test_1.wav")
    cut = full[: int(1.5 * 16000) * 2]  # barge-in after ~1.5 s: the rest of the sentence was never played
    provider = silence(0.3) + cut + silence(4.0)
    mic = silence(1.0) + wav_pcm(GOLDEN / "g01_us_greeting.wav")  # the caller talks over the mock voice
    attempt, sess = recorded_session(client, conn, mic, provider)
    transcribe(app, attempt)
    out = segs(client, sess)
    theirs = " ".join(s["text"] or "" for s in out["segments"] if s["track"] == "PROVIDER_PLAYBACK")
    assert theirs and "synthetic audio test" not in theirs.lower()  # never completed from FIXED_MESSAGE
    assert transcript.word_error_rate(FIXED_MESSAGE[0], theirs) > 0.3
    mic_segs = [s for s in out["segments"] if s["track"] == "MIC"]
    assert any("OVERLAPS_MOCK_VOICE" in s["flags"] for s in mic_segs)


# ---- missing chunks: gap on the timeline, WAV offset mapping, nothing transcribed in the gap ----------------
def test_missing_chunk_is_a_timeline_gap_and_times_map_to_the_wav(
    app: Any, client: TestClient, user: Account, conn: Connection
) -> None:
    login(client, user)
    speech = wav_pcm(GOLDEN / "g03_au_question.wav")
    lost = wav_pcm(GOLDEN / "g04_ie_statement.wav")[: CH * 2]  # exactly the chunk that never arrives
    mic = silence(2.0) + lost + silence(2.0) + speech  # chunks: 1 silence, 2 lost, 3 silence, 4-5 speech
    attempt, sess = recorded_session(client, conn, mic, silence(len(mic) / 32000), mic_skip={2})
    tl = client.get(f"/api/v1/sessions/{sess}/media/timeline").json()
    gap = next(g for g in tl["tracks"]["MIC"]["gaps"] if g["type"] == "UPLOAD_FAILED")
    assert (gap["timeline_start"], gap["timeline_end"], gap["estimated"], gap["seqs"]) == (CH, 2 * CH, False, [2])
    transcribe(app, attempt)
    o = overview(client, sess)
    assert (o["status"], o["reason"]) == ("PARTIAL", "RECORDING_GAPS") and column(conn, sess) == "PARTIAL"
    out = segs(client, sess)
    mine = [s for s in out["segments"] if s["track"] == "MIC" and s["kind"] == "SPEECH"]
    assert (
        len(mine) == 1
        and transcript.word_error_rate("Can you tell me when my next payment is due?", mine[0]["text"]) <= 0.1
    )
    assert "product summary" not in json.dumps(out)  # the lost chunk's speech is never transcribed or filled in
    s = mine[0]
    assert s["timeline_start_ms"] >= 6000 and s["wav_offset_ms"] == s["timeline_start_ms"] - 2000  # gap removed
    assert out["timeline"]["tracks"]["MIC"]["stored_samples"] == len(mic) // 2 - CH


# ---- silence and non-speech ----------------------------------------------------------------------------------
def test_silence_and_tone_tracks_produce_no_text(app: Any, client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, silence(4.0), tone(4.0))
    transcribe(app, attempt)
    o = overview(client, sess)
    assert o["status"] == "COMPLETE" and o["uncertain"] is False
    assert [(t["track"], t["speech_segments"]) for t in o["tracks"]] == [("MIC", 0), ("PROVIDER_PLAYBACK", 0)]
    assert segs(client, sess)["segments"] == []


# ---- uncertain recognition ------------------------------------------------------------------------------------
def test_uncertain_speech_is_marked_and_flags_the_session(
    app: Any, client: TestClient, user: Account, conn: Connection
) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, wav_pcm(GOLDEN / "g07_us_noisy.wav"), silence(3.0))
    transcribe(app, attempt)
    o = overview(client, sess)
    assert (o["status"], o["reason"], o["uncertain"]) == ("COMPLETE", "UNCERTAIN_SPEECH", True)
    assert column(conn, sess) == "QUALITY_FLAGGED"
    mine = [s for s in segs(client, sess)["segments"] if s["track"] == "MIC"]
    assert mine and any(w["uncertain"] for s in mine for w in s["words"])
    assert all(s["uncertain_words"] == sum(w["uncertain"] for w in s["words"]) for s in mine)


# ---- failure, retry, lease recovery ---------------------------------------------------------------------------
def test_engine_failure_is_recorded_and_retry_creates_a_new_revision(
    app: Any, client: TestClient, user: Account, conn: Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, wav_pcm(GOLDEN / "g01_us_greeting.wav"), silence(4.0))
    real = app.state.transcription_engine

    class Broken:
        name, version, model_id = real.name, real.version, real.model_id
        model_revision, model_sha256 = real.model_revision, real.model_sha256

        def transcribe(self, pcm16: bytes) -> list[Any]:
            raise RuntimeError("engine crashed")

    app.state.transcription_engine = Broken()
    for _ in range(transcript.MAX_ATTEMPTS):
        transcribe(app, attempt)
    o = overview(client, sess)
    assert (o["status"], o["reason"], o["can_retry"]) == ("FAILED", "ENGINE_ERROR", True)
    assert column(conn, sess) == "UNAVAILABLE"
    assert {t["run"]["attempts"] for t in o["tracks"]} == {transcript.MAX_ATTEMPTS}
    app.state.transcription_engine = real
    assert client.post(f"/api/v1/sessions/{sess}/transcript/retry").status_code == 403  # CSRF required
    r = client.post(f"/api/v1/sessions/{sess}/transcript/retry", headers=csrf_header(client))
    assert r.status_code == 200 and sorted(r.json()["queued_tracks"]) == ["MIC", "PROVIDER_PLAYBACK"]
    again = client.post(f"/api/v1/sessions/{sess}/transcript/retry", headers=csrf_header(client)).json()
    assert again["queued_tracks"] == []  # idempotent: revision 2 is already queued
    transcribe(app, attempt)
    o = overview(client, sess)
    assert o["status"] == "COMPLETE" and {t["run"]["revision"] for t in o["tracks"]} == {2}
    runs = conn.execute(
        text(
            f"SELECT revision, status, error_code FROM {SCHEMA}.transcript_run WHERE contact_attempt_id = :a "
            "AND track = 'MIC' ORDER BY revision"
        ),
        {"a": attempt},
    ).all()
    assert [tuple(r) for r in runs] == [(1, "FAILED", "ENGINE_ERROR"), (2, "DONE", None)]  # revision 1 kept
    kinds = [e["event_type"] for e in client.get(f"/api/v1/voice/sessions/{attempt}").json()["events"]]
    assert kinds.count("TRANSCRIPT_FAILED") == 2
    assert (
        conn.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'TRANSCRIPT.RETRY_REQUESTED' "
                "AND entity_id = :s"
            ),
            {"s": str(sess)},
        ).scalar_one()
        == 2
    )


def test_a_run_interrupted_mid_processing_is_resumed_after_restart(
    app: Any, client: TestClient, user: Account, conn: Connection, stores: media.EncryptedObjectStore
) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, wav_pcm(GOLDEN / "g01_us_greeting.wav"), silence(4.0))
    rs, eng = stores, app.state.transcription_engine
    sf = app.state.session_factory
    with sf() as db, db.begin():
        transcript.enqueue(db, eng, rs, transcript.Thresholds(), uuid.UUID(attempt))
        run = transcript.claim(db, uuid.UUID(attempt))  # the worker took it …
    assert run is not None
    rs.put(transcript.object_key(run["contact_attempt_id"], run["track"], run["revision"]), b"partial")  # … and died
    assert overview(client, sess)["status"] == "PROCESSING"
    assert transcript.recover(app) == 1  # restart: the lease is expired
    transcribe(app, attempt)
    o = overview(client, sess)
    assert o["status"] == "COMPLETE" and {t["run"]["attempts"] for t in o["tracks"]} <= {1, 2}
    assert segs(client, sess)["problems"] == []  # the orphan object was replaced by this run's own text


# ---- authorisation, scope, audit -----------------------------------------------------------------------------
def test_transcript_text_needs_permission_and_scope_and_every_read_is_audited(
    app: Any,
    client: TestClient,
    other_client: TestClient,
    user: Account,
    admin: Account,
    db: Session,
    conn: Connection,
) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, wav_pcm(GOLDEN / "g01_us_greeting.wav"), silence(4.0))
    transcribe(app, attempt)
    login(other_client, admin)  # ADMIN: status and provenance only (ADR-0004 segregation, D-50)
    o = other_client.get(f"/api/v1/sessions/{sess}/transcript").json()
    assert (o["availability"], o["can_read_text"], o["status"]) == ("RESTRICTED", False, "COMPLETE")
    assert other_client.get(f"/api/v1/sessions/{sess}/transcript/segments").status_code == 403
    assert (
        other_client.post(f"/api/v1/sessions/{sess}/transcript/retry", headers=csrf_header(other_client)).status_code
        == 403
    )
    other_client.cookies.clear()
    colleague = make_account(db, "LOCAL_USER_SG", prefix="colleague")
    login(other_client, colleague)
    assert other_client.get(f"/api/v1/sessions/{sess}/transcript/segments").status_code == 200
    other_client.cookies.clear()
    outsider = make_account(db, "LOCAL_USER_MY", prefix="outsider")
    login(other_client, outsider)
    for path in ("transcript", "transcript/segments", "media/timeline"):
        assert other_client.get(f"/api/v1/sessions/{sess}/{path}").status_code == 404
    rows = conn.execute(
        text(f"SELECT action, outcome FROM {SCHEMA}.audit_event WHERE entity_id = :s AND action LIKE 'TRANSCRIPT.%'"),
        {"s": str(sess)},
    ).all()
    assert sorted(tuple(r) for r in rows) == [("TRANSCRIPT.ACCESSED", "SUCCEEDED")]
    denied = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE outcome = 'DENIED' AND actor_principal_id = :p "
            "AND occurred_at > now() - interval '5 minutes'"
        ),
        {"p": admin.principal_id},
    ).scalar_one()
    assert denied >= 2  # the permission refusals are audited by require()
    # Playback retrieval is audited with its purpose.
    wav = client.get(f"/api/v1/sessions/{sess}/media/MIC/audio", params={"purpose": "PLAYBACK"})
    assert wav.status_code == 200 and wav.headers["content-disposition"].startswith("inline")
    after = conn.execute(
        text(f"SELECT after FROM {SCHEMA}.audit_event WHERE action = 'RECORDING.ACCESSED' AND entity_id = :s"),
        {"s": str(sess)},
    ).all()
    assert [a.after["purpose"] for a in after] == ["PLAYBACK"]


# ---- encryption integrity and retention ----------------------------------------------------------------------
def test_tampered_text_is_never_shown_and_retention_purges_text_but_keeps_metadata(
    app: Any, client: TestClient, user: Account, conn: Connection, stores: media.EncryptedObjectStore
) -> None:
    login(client, user)
    attempt, sess = recorded_session(client, conn, wav_pcm(GOLDEN / "g01_us_greeting.wav"), silence(4.0))
    transcribe(app, attempt)
    obj = next(stores.root.rglob("*/MIC/transcript-r001.c360"))
    original = obj.read_bytes()
    blob = bytearray(original)
    blob[-1] ^= 1
    obj.write_bytes(bytes(blob))
    out = segs(client, sess)
    assert {"track": "MIC", "code": "TRANSCRIPT_INTEGRITY_FAILED"} in out["problems"]
    assert all(s["text"] is None for s in out["segments"] if s["track"] == "MIC")
    obj.write_bytes(original)
    with app.state.session_factory() as db, db.begin():
        media.sweep(db, stores, now=datetime.now(UTC) + timedelta(hours=169))
    o = overview(client, sess)
    assert (o["status"], o["reason"]) == ("UNAVAILABLE", "PURGED") and column(conn, sess) == "UNAVAILABLE"
    assert not list(stores.root.rglob("transcript-r*.c360"))
    meta = conn.execute(
        text(
            f"SELECT r.purged_at, r.text_sha256, count(s.id) AS n FROM {SCHEMA}.transcript_run r LEFT JOIN "
            f"{SCHEMA}.transcript_segment s ON s.transcript_run_id = r.id WHERE r.contact_attempt_id = :a "
            "GROUP BY r.id"
        ),
        {"a": attempt},
    ).all()
    assert all(m.purged_at is not None and m.text_sha256 and m.n >= 0 for m in meta) and sum(m.n for m in meta) >= 1
    kinds = [e["event_type"] for e in client.get(f"/api/v1/voice/sessions/{attempt}").json()["events"]]
    assert kinds.count("TRANSCRIPT_PURGED") == 2


# ---- unavailable states --------------------------------------------------------------------------------------
def test_declined_and_unconfigured_sessions_have_no_transcript(
    app: Any, client: TestClient, user: Account, conn: Connection
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = client.post("/api/v1/voice/sessions", json={"case_id": str(case_id)}, headers=csrf_header(client)).json()
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    sess = conn.execute(
        text(f"SELECT id FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
    ).scalar_one()
    assert transcribe(app, s["session_id"]) == []
    o = overview(client, sess)
    assert (o["status"], o["reason"], o["tracks"]) == ("UNAVAILABLE", "CONSENT_DECLINED", [])
    # A recorded session on a server without a model: UNAVAILABLE, never a placeholder transcript.
    attempt, sess2 = recorded_session(client, conn, silence(2.0), silence(2.0))
    app.state.transcription_engine = None
    app.state.settings = app.state.settings.model_copy(update={"transcription_model_dir": None})
    assert transcribe(app, attempt) == []
    assert (overview(client, sess2)["status"], overview(client, sess2)["reason"]) == (
        "UNAVAILABLE",
        "ENGINE_NOT_CONFIGURED",
    )


def test_model_files_must_match_the_pinned_checksums(tmp_path: Path) -> None:
    for name in transcript.MODEL_FILES:
        (tmp_path / name).write_bytes(b"not the model")
    with pytest.raises(transcript.TranscriptError) as exc:
        transcript.verify_model(tmp_path)
    assert exc.value.code == "MODEL_CHECKSUM_MISMATCH"
    (tmp_path / "model.bin").unlink()
    with pytest.raises(transcript.TranscriptError) as exc:
        transcript.verify_model(tmp_path)
    assert exc.value.code == "MODEL_NOT_FOUND"
