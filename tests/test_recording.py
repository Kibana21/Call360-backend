"""S1-C — consent-gated recording (VOICE-007, VOICE-008, VOICE-010, EVD-001, EVD-003, SEC-010; D-45…D-48).

Consent granted before capture; refusal stores nothing; no audio before the segment start (pre-consent); a complete
two-track recording with matching checksums and an audited WAV download; a missing chunk, a declared upload failure
and microphone loss reported as PARTIAL; network interruption with resume (two segments) and a refresh that never
closes its segment; backend restart finalisation; chunk validation (checksum, size, conflict, idempotent repeat,
object keys); unauthorised and out-of-market access; encryption at rest; local retention purge that keeps metadata;
test sessions labelled and disclosed in KPIs; no object key or path in any response."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.api import voice as voice_api
from app.voice import media
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_voice import ORIGIN, _callable_case
from tests.test_voice_sessions import settled, until

pytestmark = pytest.mark.usefixtures("seeded")
CHUNK = 1600  # 0.1 s: tests upload right after connecting, so chunks must fit inside the elapsed time


@pytest.fixture(autouse=True)
def rec_store(app: Any, tmp_path: Path) -> media.EncryptedObjectStore:
    rs = media.EncryptedObjectStore(tmp_path / "recordings", os.urandom(32))
    app.state.recording_store = rs
    return rs


def pcm(n: int = CHUNK, value: int = 1200) -> bytes:
    return (value.to_bytes(2, "little", signed=True)) * n


def start(client: TestClient, case_id: uuid.UUID, consent: str | None = "GRANTED") -> dict[str, Any]:
    body: dict[str, Any] = {"case_id": str(case_id)}
    if consent is not None:
        body["recording_consent"] = consent
        body["consent_notice_version"] = media.NOTICE_VERSION
    r = client.post("/api/v1/voice/sessions", json=body, headers=csrf_header(client))
    assert r.status_code == 201, r.text
    return r.json()


def chunk(
    client: TestClient,
    sid: str,
    track: str,
    seq: int,
    *,
    segment: int = 1,
    start_sample: int | None = None,
    data: bytes | None = None,
    sha: str | None = None,
) -> Any:
    data = pcm() if data is None else data
    body = {
        "track": track,
        "segment": segment,
        "seq": seq,
        "start_sample": (seq - 1) * CHUNK if start_sample is None else start_sample,
        "sample_count": len(data) // 2,
        "sha256": sha or hashlib.sha256(data).hexdigest(),
        "data_b64": base64.b64encode(data).decode(),
    }
    return client.post(f"/api/v1/voice/sessions/{sid}/recording/chunks", json=body, headers=csrf_header(client))


def close(client: TestClient, sid: str, tracks: list[dict[str, Any]]) -> Any:
    return client.post(
        f"/api/v1/voice/sessions/{sid}/recording/close", json={"tracks": tracks}, headers=csrf_header(client)
    )


def both(segment: int, chunks: int, reason: str = "STOPPED", failed: list[int] | None = None) -> list[dict[str, Any]]:
    return [
        {"track": t, "segment": segment, "chunks": chunks, "failed": failed or [], "reason": reason}
        for t in ("MIC", "PROVIDER_PLAYBACK")
    ]


def rec(client: TestClient, sid: str) -> dict[str, Any]:
    r = client.get(f"/api/v1/voice/sessions/{sid}")
    assert r.status_code == 200, r.text
    return dict(r.json()["recording"])


def wait_recording(client: TestClient, sid: str, *, not_in: tuple[str, ...] = ("RECORDING",)) -> dict[str, Any]:
    import time

    for _ in range(100):
        r = rec(client, sid)
        if r["status"] not in not_in:
            return r
        time.sleep(0.05)
    return rec(client, sid)


def no_secret_paths(payload: Any) -> None:
    blob = json.dumps(payload)
    assert ".c360" not in blob and "object_key" not in blob and "/recordings" not in blob


# ---- 1, 4: consent granted → complete two-track recording, integrity, audited download --------------------------
def test_consent_granted_complete_recording_with_matching_checksums_and_audited_download(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    assert s["recording_consent"] == "GRANTED" and s["attempt_kind"] == "TEST_SESSION"
    st0 = client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()
    assert st0["recording"]["status"] == "NOT_RECORDED"  # consented, but nothing until the session connects
    assert chunk(client, s["session_id"], "MIC", 1).json()["code"] == "RECORDING_NOT_ACTIVE"
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        ready = until(ws, "session.ready")[-1]
        assert ready["recording"]["state"] == "RECORDING" and ready["recording"]["segment"] == 1
        assert rec(client, s["session_id"])["status"] == "RECORDING"
        for seq in (1, 2, 3):
            for track in ("MIC", "PROVIDER_PLAYBACK"):
                r = chunk(client, s["session_id"], track, seq, data=pcm(value=seq * 100 + (track == "MIC")))
                assert r.status_code == 200 and r.json() == {"stored": True, "duplicate": False}, r.text
        repeat = chunk(client, s["session_id"], "MIC", 1, data=pcm(value=101))
        assert repeat.json() == {"stored": False, "duplicate": True}  # idempotent retry
        conflict = chunk(client, s["session_id"], "MIC", 1, data=pcm(value=999))
        assert conflict.status_code == 409 and conflict.json()["code"] == "CHUNK_CONFLICT"  # never overwritten
        assert close(client, s["session_id"], both(1, 3)).status_code == 200
        ws.send_json({"type": "session.stop", "event_id": "stop-1", "seq": 1})
        until(ws, "session.ended")
    r = wait_recording(client, s["session_id"])
    assert r["status"] == "COMPLETE" and r["consent"] == "GRANTED" and r["notice_version"] == media.NOTICE_VERSION
    assert {t["track"]: (t["media_status"], t["coverage"], t["chunks_stored"], t["gaps"]) for t in r["tracks"]} == {
        "MIC": ("AVAILABLE", "COMPLETE", 3, []),
        "PROVIDER_PLAYBACK": ("AVAILABLE", "COMPLETE", 3, []),
    }
    mic = next(t for t in r["tracks"] if t["track"] == "MIC")
    expected = hashlib.sha256(b"".join(pcm(value=q * 100 + 1) for q in (1, 2, 3))).hexdigest()
    assert mic["content_sha256"] == expected and mic["duration_ms"] == 300 and mic["codec"] == "audio/L16;rate=16000"
    st = client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()
    kinds = [e["event_type"] for e in st["events"]]
    assert kinds.index("RECORDING_CONSENT_GRANTED") < kinds.index("CONNECTED") < kinds.index("RECORDING_STARTED")
    assert kinds.count("RECORDING_FINALIZED") == 2 and kinds.count("RECORDING_TRACK_CLOSED") == 2
    no_secret_paths(st)
    session_id = conn.execute(
        text(f"SELECT id FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
    ).scalar_one()
    m = client.get(f"/api/v1/sessions/{session_id}/media").json()
    assert (m["availability"], m["media_status"], m["can_retrieve_audio"]) == ("AVAILABLE", "AVAILABLE", True)
    no_secret_paths(m)
    wav = client.get(f"/api/v1/sessions/{session_id}/media/MIC/audio")
    assert wav.status_code == 200 and wav.headers["content-type"] == "audio/wav"
    assert wav.content[:4] == b"RIFF" and hashlib.sha256(wav.content[44:]).hexdigest() == expected
    assert wav.headers["x-call360-content-sha256"] == expected and wav.headers["cache-control"] == "no-store"
    audit = conn.execute(
        text(f"SELECT after FROM {SCHEMA}.audit_event WHERE action = 'RECORDING.ACCESSED' AND entity_id = :s"),
        {"s": str(session_id)},
    ).all()
    assert len(audit) == 1 and audit[0].after["content_sha256"] == expected
    # Encryption at rest: the stored object never contains the plaintext; tampering is detected.
    objects = sorted((rec_store.root).rglob("*.c360"))
    assert len(objects) == 6 and all(pcm(value=101) not in p.read_bytes() for p in objects)
    row = conn.execute(
        text(
            f"SELECT a.media_status, c.object_key FROM {SCHEMA}.conversation_session a JOIN {SCHEMA}.media_asset m "
            f"ON m.conversation_session_id = a.id JOIN {SCHEMA}.media_chunk c ON c.media_asset_id = m.id "
            "WHERE a.id = :s AND m.track = 'MIC' AND c.seq = 1"
        ),
        {"s": session_id},
    ).one()
    assert row.media_status == "AVAILABLE"
    target = rec_store.root / row.object_key
    blob = bytearray(target.read_bytes())
    blob[-1] ^= 0x01
    target.write_bytes(bytes(blob))
    tampered = client.get(f"/api/v1/sessions/{session_id}/media/MIC/audio")
    assert tampered.status_code == 409 and tampered.json()["code"] == "RECORDING_INTEGRITY_FAILED"


# ---- 2, 3: refusal stores nothing; nothing before consent or outside the segment --------------------------------
def test_refusal_and_default_store_nothing_and_pre_consent_audio_is_refused(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    for consent in ("DECLINED", None):  # explicit refusal, and the default when nothing is chosen
        s = start(client, case_id, consent)
        assert s["recording_consent"] == "DECLINED"
        with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
            ws.send_json({"type": "session.auth", "credential": s["credential"]})
            ready = until(ws, "session.ready")[-1]
            assert ready["recording"] == {"state": "NOT_RECORDED", "reason": "CONSENT_DECLINED"}
            r = chunk(client, s["session_id"], "MIC", 1)
            assert r.status_code == 409 and r.json()["code"] == "RECORDING_NOT_CONSENTED"
            ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
            until(ws, "session.ended")
        st = client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()
        assert st["recording"] == {
            "status": "NOT_RECORDED",
            "consent": "DECLINED",
            "consent_at": st["recording"]["consent_at"],
            "notice_version": media.NOTICE_VERSION,
            "tracks": [],
        }
        declined = next(e for e in st["events"] if e["event_type"] == "RECORDING_CONSENT_DECLINED")
        assert declined["details"]["defaulted"] is (consent is None)
        assert (
            conn.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.media_asset WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(f"SELECT media_status FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"),
                {"a": s["session_id"]},
            ).scalar_one()
            == "NOT_REQUIRED"
        )
    assert not list(rec_store.root.rglob("*.c360"))  # no audio object at all
    bad = client.post(
        "/api/v1/voice/sessions",
        json={"case_id": str(case_id), "recording_consent": "GRANTED", "consent_notice_version": "OLD"},
        headers=csrf_header(client),
    )
    assert bad.status_code == 422 and bad.json()["code"] == "CONSENT_NOTICE_MISMATCH"
    # Consented session: audio claiming to start before (or beyond) the elapsed segment time is refused.
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        far = chunk(client, s["session_id"], "MIC", 1, start_sample=16000 * 60)
        assert far.status_code == 422 and far.json()["code"] == "CHUNK_OUTSIDE_SESSION"
        assert chunk(client, s["session_id"], "MIC", 1, sha="0" * 64).json()["code"] == "CHUNK_CHECKSUM_MISMATCH"
        odd = chunk(client, s["session_id"], "MIC", 1, data=b"\x01\x02\x03")
        assert odd.status_code == 422
        assert chunk(client, s["session_id"], "MIC", 1, segment=2).json()["code"] == "SEGMENT_INVALID"
        traversal = client.post(
            f"/api/v1/voice/sessions/{s['session_id']}/recording/chunks",
            json={
                "track": "../../etc",
                "segment": 1,
                "seq": 1,
                "start_sample": 0,
                "sample_count": 1,
                "sha256": "0" * 64,
                "data_b64": "AAA=",
            },
            headers=csrf_header(client),
        )
        assert traversal.status_code == 422  # tracks are an enum; keys are generated by the server
        no_csrf = client.post(f"/api/v1/voice/sessions/{s['session_id']}/recording/chunks", json={})
        assert no_csrf.status_code in (403, 422)
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    with pytest.raises(media.RecordingError):
        rec_store.put("../escape.c360", b"x")


# ---- 5, 6: missing chunk, declared upload failure, microphone loss → PARTIAL --------------------------------------
def test_missing_chunk_upload_failure_and_mic_loss_are_partial_never_backfilled(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        for seq in (1, 3):  # MIC chunk 2 never arrives
            assert chunk(client, s["session_id"], "MIC", seq).status_code == 200
        assert chunk(client, s["session_id"], "PROVIDER_PLAYBACK", 1).status_code == 200  # 2 failed to upload
        r = close(
            client,
            s["session_id"],
            [
                {"track": "MIC", "segment": 1, "chunks": 3, "failed": [], "reason": "MIC_DEVICE_LOST"},
                {"track": "PROVIDER_PLAYBACK", "segment": 1, "chunks": 2, "failed": [2], "reason": "MIC_DEVICE_LOST"},
            ],
        )
        assert r.status_code == 200
        ws.send_json({"type": "session.stop", "event_id": "lost", "seq": 1, "reason": "MIC_DEVICE_LOST"})
        until(ws, "session.ended")
    # MIC still waits for chunk 2 during the upload window; the sweeper finalises it after the window.
    with Session(conn.engine) as db, db.begin():
        media.sweep(db, rec_store, now=datetime.now(UTC) + timedelta(seconds=31))
    r = rec(client, s["session_id"])
    tracks = {t["track"]: t for t in r["tracks"]}
    assert r["status"] == "PARTIAL"
    assert tracks["MIC"]["coverage"] == "PARTIAL" and tracks["MIC"]["chunks_stored"] == 2
    assert {"type": "MISSING", "segment": 1, "seq": 2} in [
        {k: g[k] for k in ("type", "segment", "seq")} for g in tracks["MIC"]["gaps"] if g["type"] == "MISSING"
    ]
    assert any(g["type"] == "CAPTURE_INTERRUPTED" and g["reason"] == "MIC_DEVICE_LOST" for g in tracks["MIC"]["gaps"])
    assert any(g["type"] == "UPLOAD_FAILED" and g["seq"] == 2 for g in tracks["PROVIDER_PLAYBACK"]["gaps"])
    # Never backfilled: the content checksum covers exactly the stored chunks.
    assert tracks["MIC"]["content_sha256"] == hashlib.sha256(pcm() + pcm()).hexdigest()
    assert tracks["MIC"]["duration_ms"] == 200


# ---- 7: network interruption + resume (two segments) and a refresh that never closes its segment ----------------
def test_network_interruption_resume_records_a_second_segment_and_reports_the_gap(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:  # dropped (e.g. a refresh) without close
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        for t in ("MIC", "PROVIDER_PLAYBACK"):
            assert chunk(client, s["session_id"], t, 1).status_code == 200
    settled(client, s["session_id"], lambda k: "DISCONNECTED" in k)
    assert rec(client, s["session_id"])["status"] == "RECORDING"  # still capturing: the session is resumable
    r = client.post(f"/api/v1/voice/sessions/{s['session_id']}/resume", headers=csrf_header(client))
    assert r.status_code == 200 and r.json()["recording_consent"] == "GRANTED"  # the decision is kept
    with client.websocket_connect(r.json()["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": r.json()["credential"]})
        ready = until(ws, "session.ready")[-1]
        assert ready["resumed"] and ready["recording"]["segment"] == 2
        for t in ("MIC", "PROVIDER_PLAYBACK"):
            assert chunk(client, s["session_id"], t, 1, segment=2).status_code == 200
        assert close(client, s["session_id"], both(2, 1)).status_code == 200
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    with Session(conn.engine) as db, db.begin():  # segment 1 was never closed: finalised after the upload window
        media.sweep(db, rec_store, now=datetime.now(UTC) + timedelta(seconds=31))
    rr = rec(client, s["session_id"])
    assert rr["status"] == "PARTIAL"
    for t in rr["tracks"]:
        types = {g["type"] for g in t["gaps"]}
        assert {"SESSION_INTERRUPTED", "END_NOT_CONFIRMED"} <= types and t["chunks_stored"] == 2


# ---- 8: backend restart finalises the session and the recording, nothing left open ------------------------------
def test_backend_restart_finalises_session_and_recording(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        assert chunk(client, s["session_id"], "MIC", 1).status_code == 200
    settled(client, s["session_id"], lambda k: "DISCONNECTED" in k)
    voice_api.run_sweep(client.app, startup=True)  # what the lifespan does after a restart
    st = client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()
    assert (st["status"], st["end_reason"]) == ("ABORTED", "BACKEND_RESTART")
    assert st["recording"]["status"] == "RECORDING"  # capture ended; late uploads still accepted briefly
    late = chunk(client, s["session_id"], "PROVIDER_PLAYBACK", 1)
    assert late.status_code == 200
    with Session(conn.engine) as db, db.begin():
        media.sweep(db, rec_store, now=datetime.now(UTC) + timedelta(seconds=31))
    r = rec(client, s["session_id"])
    assert r["status"] == "PARTIAL" and all(t["media_status"] == "AVAILABLE" for t in r["tracks"])
    after = chunk(client, s["session_id"], "MIC", 2)
    assert after.status_code == 409 and after.json()["code"] == "RECORDING_CLOSED"
    open_rows = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.media_asset WHERE contact_attempt_id = :a "
            "AND status IN ('CAPTURING', 'UPLOADING')"
        ),
        {"a": s["session_id"]},
    ).scalar_one()
    assert open_rows == 0


def test_consent_granted_but_nothing_stored_is_failed(client: TestClient, user: Account, conn: Connection) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        assert close(client, s["session_id"], both(1, 0, reason="CAPTURE_ERROR")).status_code == 200
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    r = wait_recording(client, s["session_id"])
    assert r["status"] == "FAILED" and all(t["media_status"] == "FAILED" for t in r["tracks"])
    sess = conn.execute(
        text(f"SELECT id, media_status FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"),
        {"a": s["session_id"]},
    ).one()
    assert sess.media_status == "FAILED"
    m = client.get(f"/api/v1/sessions/{sess.id}/media").json()
    assert (m["availability"], m["reason"]) == ("FAILED", "CAPTURE_FAILED")


# ---- 9, 10: access control and Singapore-only scope -------------------------------------------------------------
def test_recording_access_is_restricted_audited_and_singapore_only(
    client: TestClient, other_client: TestClient, user: Account, admin: Account, db: Session, conn: Connection
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        for t in ("MIC", "PROVIDER_PLAYBACK"):
            chunk(client, s["session_id"], t, 1)
        close(client, s["session_id"], both(1, 1))
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    wait_recording(client, s["session_id"])
    session_id = conn.execute(
        text(f"SELECT id FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
    ).scalar_one()
    # ADMIN: metadata yes, audio no (ADR-0004 segregation, D-46).
    login(other_client, admin)
    m = other_client.get(f"/api/v1/sessions/{session_id}/media").json()
    assert (m["availability"], m["can_retrieve_audio"]) == ("RESTRICTED", False)
    assert other_client.get(f"/api/v1/sessions/{session_id}/media/MIC/audio").status_code == 403
    # Another Singapore USER may read (recording.read + scope) but cannot upload into someone else's session.
    other_client.cookies.clear()
    colleague = make_account(db, "LOCAL_USER_SG", prefix="colleague")
    login(other_client, colleague)
    assert other_client.get(f"/api/v1/sessions/{session_id}/media/PROVIDER_PLAYBACK/audio").status_code == 200
    intrude = chunk(other_client, s["session_id"], "MIC", 2, start_sample=CHUNK)
    assert intrude.status_code == 404
    assert close(other_client, s["session_id"], both(1, 1)).status_code == 404
    # A user without Singapore scope: the same audited 404 as a missing session.
    other_client.cookies.clear()
    outsider = make_account(db, "LOCAL_USER_MY", prefix="outsider")
    login(other_client, outsider)
    assert other_client.get(f"/api/v1/sessions/{session_id}/media").status_code == 404
    assert other_client.get(f"/api/v1/sessions/{session_id}/media/MIC/audio").status_code == 404
    assert other_client.get(f"/api/v1/sessions/{uuid.uuid4()}/media/MIC/audio").status_code == 404
    other_client.cookies.clear()
    assert other_client.get(f"/api/v1/sessions/{session_id}/media/MIC/audio").status_code == 401
    accesses = conn.execute(
        text(f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'RECORDING.ACCESSED' AND entity_id = :s"),
        {"s": str(session_id)},
    ).scalar_one()
    assert accesses == 1  # only the colleague's successful retrieval


# ---- retention, test-session labelling, KPI disclosure ------------------------------------------------------------
def test_local_retention_purges_audio_and_keeps_metadata(
    client: TestClient, user: Account, conn: Connection, rec_store: media.EncryptedObjectStore
) -> None:
    login(client, user)
    case_id, _ = _callable_case(conn)
    s = start(client, case_id)
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        for t in ("MIC", "PROVIDER_PLAYBACK"):
            chunk(client, s["session_id"], t, 1)
        close(client, s["session_id"], both(1, 1))
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    before = wait_recording(client, s["session_id"])
    assert before["status"] == "COMPLETE"
    keys = (
        conn.execute(
            text(
                f"SELECT c.object_key FROM {SCHEMA}.media_chunk c "
                f"JOIN {SCHEMA}.media_asset m ON m.id = c.media_asset_id "
                "WHERE m.contact_attempt_id = :a"
            ),
            {"a": s["session_id"]},
        )
        .scalars()
        .all()
    )
    assert all((rec_store.root / k).exists() for k in keys)
    with Session(conn.engine) as db, db.begin():
        done = media.sweep(db, rec_store, now=datetime.now(UTC) + timedelta(hours=169))
    assert sum(d.startswith(s["session_id"]) for d in done) == 2
    after = rec(client, s["session_id"])
    assert after["status"] == "PURGED" and not any((rec_store.root / k).exists() for k in keys)
    for b, a in zip(before["tracks"], after["tracks"], strict=True):  # manifest metadata and checksums remain
        assert (a["content_sha256"], a["manifest_sha256"], a["chunks_stored"]) == (
            b["content_sha256"],
            b["manifest_sha256"],
            b["chunks_stored"],
        ) and a["purged_at"] is not None
    st = client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()
    assert [e["event_type"] for e in st["events"]].count("RECORDING_PURGED") == 2
    sid = conn.execute(
        text(f"SELECT id FROM {SCHEMA}.conversation_session WHERE contact_attempt_id = :a"), {"a": s["session_id"]}
    ).scalar_one()
    assert client.get(f"/api/v1/sessions/{sid}/media").json()["reason"] == "PURGED"
    assert client.get(f"/api/v1/sessions/{sid}/media/MIC/audio").status_code == 404
    with pytest.raises(Exception, match="immutable|stays purged"):  # the database refuses to rewrite evidence
        conn.execute(
            text(f"UPDATE {SCHEMA}.media_asset SET content_sha256 = repeat('0', 64) WHERE contact_attempt_id = :a"),
            {"a": s["session_id"]},
        )
    conn.rollback()


def test_test_sessions_are_labelled_and_excluded_from_operational_kpis(
    client: TestClient, user: Account, conn: Connection
) -> None:
    """D-48: a marked browser test session is visible in case history but changes no operational KPI."""
    from zoneinfo import ZoneInfo

    login(client, user)
    case_id, _ = _callable_case(conn)
    today = datetime.now(ZoneInfo("Asia/Singapore")).date()  # KPI ranges are Singapore local dates
    window = {"from": (today - timedelta(days=1)).isoformat(), "to": (today + timedelta(days=2)).isoformat()}

    def kpis() -> dict[str, dict[str, Any]]:
        r = client.get("/api/v1/dashboard/kpis", params=window)
        assert r.status_code == 200, r.text
        return {k["definition_id"]: k for k in r.json()["items"]}

    def trend() -> list[dict[str, Any]]:
        r = client.get("/api/v1/dashboard/trend", params={"kpi": "KPI-02", "days": 7})
        assert r.status_code == 200, r.text
        return [(p["numerator"], p["denominator"]) for p in r.json()["points"]]

    before, trend_before = kpis(), trend()
    s = start(client, case_id, "DECLINED")
    with client.websocket_connect(s["stream_path"], headers=ORIGIN) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "session.ready")
        ws.send_json({"type": "session.stop", "event_id": "stop", "seq": 1})
        until(ws, "session.ended")
    attempts = client.get(f"/api/v1/cases/{case_id}/attempts").json()["items"]
    assert next(a for a in attempts if a["id"] == s["session_id"])["attempt_kind"] == "TEST_SESSION"  # still visible
    for a in attempts:  # seeded attempts stay customer contact attempts; only runtime browser sessions are tests
        runtime = a["transport"] == "BROWSER" and a["record_origin"] == "CALL360_RUNTIME"
        assert a["attempt_kind"] == ("TEST_SESSION" if runtime else "CONTACT_ATTEMPT")
    assert client.get(f"/api/v1/voice/sessions/{s['session_id']}").json()["attempt_kind"] == "TEST_SESSION"

    after = kpis()
    for kid in ("KPI-01", "KPI-02", "KPI-12"):  # numerators and denominators unchanged by the test session
        assert (after[kid]["numerator"], after[kid]["denominator"]) == (
            before[kid]["numerator"],
            before[kid]["denominator"],
        ), kid
        assert after[kid]["exclusions"]["test_sessions_excluded"] is True
    assert after["KPI-02"]["exclusions"]["test_sessions_excluded_count"] >= 1
    assert (
        after["KPI-02"]["exclusions"]["test_sessions_excluded_count"]
        > before["KPI-02"]["exclusions"]["test_sessions_excluded_count"]
    )
    assert trend() == trend_before
