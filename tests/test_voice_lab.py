"""S1-E.1 Voice Lab over the API: mock voice sessions (WebSocket) with prompt configuration, provider trace, barge-in,
server recording and independent transcription; prompt and test-case versioning; Script Studio import; mock experiment
execution and deterministic evaluation; backend-enforced cost controls (paid refusal, fail-closed estimates, budget
reservation and reconciliation, per-experiment / daily / overall limits, concurrency under parallel requests, spend
authorisation by a different user, timeouts and the kill switch); and isolation from operational records and KPIs.
No test contacts any network provider: none exists in the code."""

from __future__ import annotations

import base64
import json
import threading
import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.db.session import make_session_factory
from app.domain.protection import DataProtection
from app.domain.seed import seed
from app.voice import lab, lab_eval
from tests.domain_support import SCHEMA
from tests.support import ORIGIN, Account, csrf_header, login, make_account, reset_test_schema

pytestmark = pytest.mark.usefixtures("seeded")
WS = {"origin": ORIGIN}
GOLDEN = Path(__file__).parent / "fixtures" / "golden_audio"
OPERATIONAL = (
    "callback_case",
    "contact_attempt",
    "conversation_session",
    "session_event",
    "media_asset",
    "finding",
    "review_decision",
    "survey_run",
    "question_execution",
)


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # lab rows are insert-only; reset the test schema afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    from app.main import create_app

    a = create_app(settings.model_copy(update={"transcription_worker": False}))
    a.state.voicelab_inline = True  # experiments run inside the request; transcription is driven explicitly
    return a


def ok(r: Any, status: int = 200) -> Any:
    assert r.status_code == status, r.text
    return r.json()


def post(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> Any:
    return ok(c.post(f"/api/v1/voice-lab{path}", json=body, headers=csrf_header(c)), status)


def refused(c: TestClient, path: str, body: dict[str, Any], status: int = 409) -> dict[str, Any]:
    r = c.post(f"/api/v1/voice-lab{path}", json=body, headers=csrf_header(c))
    assert r.status_code == status, r.text
    return dict(r.json())


def prompt(c: TestClient, provider: str = "MOCK", **over: Any) -> dict[str, Any]:
    body = {
        "name": f"Lab prompt {uuid.uuid4().hex[:6]}",
        "system_prompt": "You are a synthetic test voice.",
        "turn_instructions": ["Greet the customer", "Ask them to confirm"],
        "provider": provider,
        "model": "mock-fixed-message-1",
        "voice": "synthetic-fixed",
        **over,
    }
    return dict(post(c, "/prompts", body, 201))


def budget(admin: TestClient, **values: Any) -> dict[str, Any]:
    cur = next(b for b in ok(admin.get("/api/v1/voice-lab/settings"))["budgets"] if b["spend_class"] == "SIMULATED")
    keys = (
        "overall_usd",
        "daily_usd",
        "per_experiment_usd",
        "max_concurrent_sessions",
        "interactive_max_s",
        "idle_timeout_s",
    )
    body = {k: values.get(k, cur[k]) for k in keys}
    r = admin.put(
        "/api/v1/voice-lab/budgets/SIMULATED",
        headers=csrf_header(admin),
        json={**body, "expected_row_version": cur["row_version"], "reason": "Test budget configuration"},
    )
    return dict(ok(r))


def until(ws: Any, kind: str, limit: int = 4000) -> list[dict[str, Any]]:
    seen = []
    for _ in range(limit):
        msg = ws.receive()
        if msg.get("text"):
            seen.append(json.loads(msg["text"]))
            if seen[-1]["type"] == kind:
                return seen
        if msg.get("type") == "websocket.close":
            break
    raise AssertionError(f"{kind} not received: {[e['type'] for e in seen]}")


LOUD = (9000).to_bytes(2, "little", signed=True) * 160 + (-9000).to_bytes(2, "little", signed=True) * 160
QUIET = b"\x00" * 640


def counts(db: Session) -> dict[str, int]:
    return {t: db.execute(text(f"SELECT count(*) FROM {SCHEMA}.{t}")).scalar_one() for t in OPERATIONAL}


@pytest.fixture
def lab_admin(app: Any, db: Session) -> Iterator[TestClient]:
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        assert login(c, make_account(db, "LOCAL_ADMIN", prefix="labadm")).status_code == 200
        yield c


@pytest.fixture
def lab_user(client: TestClient, user: Account) -> TestClient:
    assert login(client, user).status_code == 200
    return client


def test_paid_access_is_disabled_and_fails_closed(lab_user: TestClient, lab_admin: TestClient, db: Session) -> None:
    before = counts(db)
    s = ok(lab_user.get("/api/v1/voice-lab/settings"))  # opening the lab creates and connects nothing
    assert s["control"] == {
        **s["control"],
        "paid_enabled": False,
        "retries_enabled": False,
        "scheduling_enabled": False,
        "kill_switch": False,
    }
    live = {p["code"]: p for p in s["providers"]}
    assert live["GPT_LIVE"]["available"] is False and live["GPT_LIVE"]["rate_card"]["session_usd_per_min"] == "0.05"
    assert s["gpt_live"]["mode"] == "DISABLED" and s["gpt_live"]["api_key_configured"] is False
    assert live["MOCK"]["spend_class"] == "NONE" and live["MOCK_METERED"]["spend_class"] == "SIMULATED"
    assert s["paid_spend"] == {"paid_reservations": 0, "paid_usd": "0", "paid_sessions": 0, "paid_experiments": 0}
    assert db.execute(text(f"SELECT count(*) FROM {SCHEMA}.lab_session")).scalar_one() == 0
    # A paid provider can be configured in a prompt, but a session or experiment with it is refused (and audited).
    p = prompt(lab_user, "GPT_LIVE", model="gpt-live-1", voice="marin")
    e = refused(lab_user, "/sessions", {"prompt_version_id": p["versions"][0]["id"]})
    assert e["code"] == "PAID_DISABLED" and any("PROVIDER_NOT_AVAILABLE" in d["message"] for d in e["details"])
    assert any("SMOKE_TEST_NOT_AUTHORISED" in d["message"] for d in e["details"])
    d = post(lab_user, "/datasets", {"name": "Paid refusal set"}, 201)
    post(lab_user, f"/datasets/{d['id']}/cases", {"name": "Greeting", "expected_statement": "Hello"}, 201)
    ex = refused(
        lab_user,
        "/experiments",
        {"name": "Paid run", "dataset_id": d["id"], "max_spend_usd": 1, "prompt_version_id": p["versions"][0]["id"]},
    )
    assert ex["code"] == "PAID_DISABLED"
    assert (
        db.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action IN ('LAB.SESSION_REFUSED', "
                "'LAB.EXPERIMENT_REFUSED') AND outcome = 'DENIED'"
            )
        ).scalar_one()
        >= 2
    )
    # The database itself refuses retries, schedules and PAID sessions without a consumed authorisation (S1-E.2: the
    # paid switch itself is a manager setting, off by default).
    for sql in (
        "UPDATE {s}.lab_control SET retries_enabled = true",
        "UPDATE {s}.lab_control SET scheduling_enabled = true",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql.format(s=SCHEMA)))
        db.rollback()
    checks = set(
        db.execute(
            text("SELECT conname FROM pg_constraint WHERE connamespace = CAST(:s AS regnamespace)"), {"s": SCHEMA}
        ).scalars()
    )
    assert {
        "ck_lab_session_paid_authorised",
        "ck_lab_experiment_no_paid",
        "ck_lab_reservation_paid_session",
        "ck_lab_paid_auth_four_eyes",
        "ck_lab_paid_auth_single",
        "ck_lab_paid_auth_duration",
    } <= checks
    # Roles: ADMIN manages but cannot run sessions; USER cannot change budgets.
    assert (
        lab_admin.post(
            "/api/v1/voice-lab/sessions",
            json={"prompt_version_id": p["versions"][0]["id"]},
            headers=csrf_header(lab_admin),
        ).status_code
        == 403
    )
    assert (
        lab_user.post(
            "/api/v1/voice-lab/kill-switch", json={"engaged": True, "reason": "not mine"}, headers=csrf_header(lab_user)
        ).status_code
        == 403
    )
    assert counts(db) == before


def test_prompt_versions_are_kept(lab_user: TestClient) -> None:
    p = prompt(lab_user)
    body = {k: p["versions"][0][k] for k in ("system_prompt", "turn_instructions", "provider", "model", "voice")}
    v2 = post(
        lab_user,
        f"/prompts/{p['id']}/versions",
        {**body, "name": p["name"], "system_prompt": "Be brief.", "change_note": "Shorter", "expected_version": 1},
    )
    assert [v["version_no"] for v in v2["versions"]] == [2, 1]
    assert v2["versions"][1]["system_prompt"] == "You are a synthetic test voice."  # history preserved
    same = refused(lab_user, f"/prompts/{p['id']}/versions", {**body, "name": p["name"], "system_prompt": "Be brief."})
    assert same["code"] == "NO_CHANGE"
    stale = refused(lab_user, f"/prompts/{p['id']}/versions", {**body, "name": p["name"], "expected_version": 1})
    assert stale["code"] == "STALE_PROMPT"
    bad = refused(lab_user, "/prompts", {**body, "name": "Bad model", "model": "gpt-x"}, 422)
    assert bad["code"] == "MODEL_UNKNOWN"


def test_mock_session_records_trace_barge_in_recording_and_transcript(
    app: Any, lab_user: TestClient, db: Session, asr: Any
) -> None:
    app.state.transcription_engine = asr
    p = prompt(lab_user)
    s = post(lab_user, "/sessions", {"prompt_version_id": p["versions"][0]["id"], "record": True}, 201)
    assert s["provider"] == "MOCK" and s["estimated_max_usd"] == "0.0000" and s["reservation_status"] is None
    with lab_user.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        ready = until(ws, "session.ready")[-1]
        assert ready["recording"]["state"] == "SERVER_RECORDING" and ready["idle_timeout_s"] == 15
        until(ws, "response.started")
        for _ in range(25):  # ~0.5 s of silence while the mock speaks, then a loud interruption
            ws.send_bytes(QUIET)
        for _ in range(12):
            ws.send_bytes(LOUD)
        until(ws, "playback.clear")
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    out = ok(lab_user.get(f"/api/v1/voice-lab/sessions/{s['id']}"))
    kinds = [e["event_type"] for e in out["events"]]
    for k in (
        "SESSION_CREATED",
        "SESSION_LIVE",
        "PROMPT_APPLIED",
        "FIRST_AUDIO",
        "RESPONSE_STARTED",
        "BARGE_IN",
        "STOP_REQUESTED",
        "RECORDING_SAVED",
        "SESSION_ENDED",
    ):
        assert k in kinds, kinds
    first = next(e for e in out["events"] if e["event_type"] == "RESPONSE_STARTED")
    assert first["details"]["turn_instruction"] == "Greet the customer"
    barge = next(e for e in out["events"] if e["event_type"] == "BARGE_IN")
    assert barge["details"]["interruption_latency_ms"] is not None
    m = out["metrics"]
    assert out["status"] == "ENDED" and out["end_reason"] == "STOPPED_BY_USER" and m["interruptions"] == 1
    assert m["first_audio_ms"] is not None and m["duration_ms"] > 0 and out["reconciled_usd"] == "0.0000"
    assert {x["track"] for x in out["media"]} == {"MIC", "PROVIDER_PLAYBACK"}
    wav = lab_user.get(f"/api/v1/voice-lab/sessions/{s['id']}/audio/PROVIDER_PLAYBACK")
    assert wav.status_code == 200 and wav.content[:4] == b"RIFF" and len(wav.content) > 16000
    assert lab.transcribe_session(app, uuid.UUID(s["id"])) == "COMPLETED"
    out = ok(lab_user.get(f"/api/v1/voice-lab/sessions/{s['id']}"))
    assert out["transcript_status"] == "COMPLETED"
    provider = next(t for t in out["transcripts"] if t["track"] == "PROVIDER_PLAYBACK")
    assert provider["engine"].startswith("faster-whisper") and provider["text"]  # interrupted after ~0.5 s: "Hello" cut
    # The credential is single use; a second connection is refused.
    with lab_user.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert until(ws, "error")[-1]["code"] == "SESSION_CREDENTIAL_INVALID"


def test_metered_reservations_limits_and_parallel_requests(
    app: Any, lab_user: TestClient, lab_admin: TestClient, engine: Engine, user: Account
) -> None:
    p = prompt(lab_user, "MOCK_METERED")
    pv = p["versions"][0]["id"]
    budget(
        lab_admin,
        overall_usd=10,
        daily_usd=2,
        per_experiment_usd=1,
        max_concurrent_sessions=1,
        interactive_max_s=300,
        idle_timeout_s=15,
    )
    a = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    assert a["estimated_max_usd"] == "0.8000" and a["reservation_status"] == "HELD" and a["reserved_usd"] == "0.8000"
    b = refused(lab_user, "/sessions", {"prompt_version_id": pv})
    assert b["code"] == "CONCURRENCY_LIMIT"
    stopped = post(lab_user, f"/sessions/{a['id']}/stop", {})
    assert stopped["reservation_status"] == "RECONCILED" and stopped["reconciled_usd"] == "0.0000"
    # A connected session is reconciled with the audio actually exchanged (never above the reservation).
    c = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    with lab_user.websocket_connect(c["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": c["credential"]})
        until(ws, "response.started")
        for _ in range(50):
            ws.send_bytes(QUIET)
        ws.send_json({"type": "session.stop"})
        until(ws, "session.ended")
    c = ok(lab_user.get(f"/api/v1/voice-lab/sessions/{c['id']}"))
    assert c["reservation_status"] == "RECONCILED" and Decimal("0") < Decimal(c["reconciled_usd"]) < Decimal("0.8")
    assert "BUDGET_RESERVED" in [e["event_type"] for e in c["events"]]
    # Per-experiment, daily and overall limits.
    budget(lab_admin, overall_usd=1, daily_usd=1, per_experiment_usd="0.5", max_concurrent_sessions=2)
    e = refused(lab_user, "/sessions", {"prompt_version_id": pv})
    assert e["code"] == "PER_EXPERIMENT_LIMIT"
    budget(lab_admin, per_experiment_usd=1)
    first = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    e = refused(lab_user, "/sessions", {"prompt_version_id": pv})
    msgs = " ".join(d["message"] for d in e["details"])
    assert e["code"] == "DAILY_LIMIT" and "OVERALL_LIMIT" in msgs
    post(lab_user, f"/sessions/{first['id']}/stop", {})
    # Parallel requests: with one concurrent session allowed, exactly one of eight simultaneous requests wins.
    budget(lab_admin, overall_usd=10, daily_usd=10, per_experiment_usd=1, max_concurrent_sessions=1)
    results: list[str] = []
    barrier = threading.Barrier(8)

    def attempt() -> None:
        with make_session_factory(engine)() as db:
            barrier.wait()
            try:
                lab.create_session(
                    db,
                    str(user.principal_id),
                    uuid.UUID(pv),
                    record=False,
                    recording_available=True,
                    settings=app.state.settings,
                )
                db.commit()
                results.append("CREATED")
            except lab.LabError as exc:
                db.rollback()
                results.append(exc.code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["CONCURRENCY_LIMIT"] * 7 + ["CREATED"], results
    with make_session_factory(engine)() as db, db.begin():
        assert lab.abandon_unconnected(db, older_than_s=0)  # the sweeper ends never-connected sessions
        assert db.execute(text(f"SELECT count(*) FROM {SCHEMA}.lab_reservation WHERE status = 'HELD'")).scalar() == 0
    with make_session_factory(engine)() as db:  # reservation amounts are immutable and never deleted
        with pytest.raises(DBAPIError):
            db.execute(text(f"UPDATE {SCHEMA}.lab_reservation SET reserved_usd = 0"))
        db.rollback()
        with pytest.raises(DBAPIError):
            db.execute(text(f"DELETE FROM {SCHEMA}.lab_reservation"))
        db.rollback()


def test_timeouts_end_sessions(lab_user: TestClient, lab_admin: TestClient) -> None:
    budget(
        lab_admin,
        interactive_max_s=5,
        idle_timeout_s=2,
        max_concurrent_sessions=1,
        overall_usd=10,
        daily_usd=10,
        per_experiment_usd=1,
    )
    pv = prompt(lab_user)["versions"][0]["id"]
    s = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    with lab_user.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        assert until(ws, "session.ended")[-1]["reason"] == "MAX_DURATION"  # the fixed message outlasts 5 s
    budget(lab_admin, interactive_max_s=30)
    s = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    with lab_user.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.done")
        assert until(ws, "session.ended")[-1]["reason"] == "IDLE_TIMEOUT"  # silence after the mock finished
    budget(lab_admin, interactive_max_s=300, idle_timeout_s=15)


def test_kill_switch_stops_and_refuses(app: Any, lab_user: TestClient, lab_admin: TestClient) -> None:
    pv = prompt(lab_user)["versions"][0]["id"]
    s = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    with lab_user.websocket_connect(s["stream_path"], headers=WS) as ws:
        ws.send_json({"type": "session.auth", "credential": s["credential"]})
        until(ws, "response.started")
        post(lab_admin, "/kill-switch", {"engaged": True, "reason": "Emergency stop drill"})
        assert until(ws, "session.ended")[-1]["reason"] == "KILL_SWITCH"
    e = refused(lab_user, "/sessions", {"prompt_version_id": pv})
    assert e["code"] == "KILL_SWITCH"
    st = ok(lab_admin.get("/api/v1/voice-lab/settings"))
    assert st["control"]["kill_switch"] and st["history"][0]["target"] == "KILL_SWITCH"
    post(lab_admin, "/kill-switch", {"engaged": False, "reason": "Drill complete"})
    post(lab_user, f"/sessions/{post(lab_user, '/sessions', {'prompt_version_id': pv}, 201)['id']}/stop", {})


def _wav_b64(name: str) -> str:
    return base64.b64encode((GOLDEN / name).read_bytes()).decode()


def test_dataset_experiment_and_deterministic_evaluation(
    app: Any, lab_user: TestClient, lab_admin: TestClient, db: Session, asr: Any
) -> None:
    app.state.transcription_engine = asr
    budget(lab_admin, overall_usd=10, daily_usd=10, per_experiment_usd=1, max_concurrent_sessions=1)
    d = post(lab_user, "/datasets", {"name": "Golden greetings", "description": "Synthetic"}, 201)
    base = {
        "description": "Synthetic",
        "system_prompt": "Speak clearly",
        "test_instruction": "Read the greeting",
        "customer_response": "Yes, that is correct",
        "expected_answer": {"answer": "YES"},
        "expected_behaviour": "Does not add a sales pitch",
        "criteria": {
            "exact_wording": True,
            "max_wer": 0.1,
            "max_first_audio_ms": 2000,
            "max_interruption_ms": 1000,
            "min_answer_accuracy": 1,
        },
    }
    # The model says "my" instead of "your" and omits "today"; the audio fixture is the matching synthetic speech.
    deviate = post(
        lab_user,
        f"/datasets/{d['id']}/cases",
        {
            **base,
            "name": "Deviating greeting",
            "expected_statement": "Good morning. I am calling about your policy renewal today.",
            "mock_output": "Good morning. I am calling about my policy renewal.",
            "audio_wav_b64": _wav_b64("g01_us_greeting.wav"),
        },
        201,
    )
    faithful = post(
        lab_user,
        f"/datasets/{d['id']}/cases",
        {
            **base,
            "name": "Faithful statement",
            "expected_statement": "I did not receive the product summary, and I would like it sent by email.",
            "audio_wav_b64": _wav_b64("g04_ie_statement.wav"),
        },
        201,
    )
    bad = refused(
        lab_user,
        f"/datasets/{d['id']}/cases",
        {**base, "name": "Bad", "expected_statement": "x", "criteria": {"max_wer": 3}},
        422,
    )
    assert bad["code"] == "CRITERIA_INVALID"
    # Revisions are kept; the fixture audio carries over unless replaced.
    r2 = post(
        lab_user,
        f"/datasets/{d['id']}/cases/{faithful['test_case_id']}/revisions",
        {
            **base,
            "name": "Faithful statement",
            "expected_statement": faithful["expected_statement"],
            "change_note": "Tightened criteria",
            "expected_revision": 1,
        },
    )
    assert r2["revision"] == 2 and r2["audio_sha256"] == faithful["audio_sha256"]
    hist = ok(lab_user.get(f"/api/v1/voice-lab/test-cases/{faithful['test_case_id']}/revisions"))["items"]
    assert [h["revision"] for h in hist] == [2, 1]
    # Script Studio import (read-only on scripts): every imported case records its source question revision.
    src = ok(lab_user.get("/api/v1/voice-lab/script-sources"))["items"]
    imported = post(lab_user, f"/datasets/{d['id']}/import-script", {"script_version_id": src[0]["id"]})["items"]
    assert imported and all(
        c["source"]["kind"] == "SCRIPT_STUDIO" and c["source"]["question_revision_id"] for c in imported
    )
    # Free (mock) experiment over the two golden cases, two repetitions.
    pv = prompt(lab_user)["versions"][0]["id"]
    chosen = [deviate["id"], r2["id"]]
    e = post(
        lab_user,
        "/experiments",
        {
            "name": "Mock wording run",
            "dataset_id": d["id"],
            "prompt_version_id": pv,
            "case_revision_ids": chosen,
            "repetitions": 2,
            "max_duration_s": 30,
            "max_spend_usd": 0,
        },
        201,
    )
    assert e["status"] == "READY" and e["estimated_max_usd"] == "0.0000"
    e = post(lab_user, f"/experiments/{e['id']}/run", {})
    assert e["status"] == "COMPLETED" and len(e["trials"]) == 4 and e["summary"]["completed"] == 4
    dev = next(t for t in e["trials"] if t["case_name"] == "Deviating greeting")
    said = dev["metrics"]["said"]
    assert not said["exact_match"] and "today" in said["omitted"]
    assert {"expected": "your", "actual": "my"} in said["substituted"]
    assert dev["heard_text"] and dev["metrics"]["heard"]["wer"] > 0
    assert any(
        a["attribution"] == "SUSPECTED_SPEECH_DEVIATION" and a["expected"] == "today"
        for a in dev["metrics"]["attributions"]
    )
    assert dev["verdict"] == "FAIL" and dev["metrics"]["answer"]["accuracy"] == 1.0
    assert dev["metrics"]["first_audio_ms"] is not None and dev["metrics"]["interruption_ms"] is not None
    fa = next(t for t in e["trials"] if t["case_name"] == "Faithful statement")
    assert fa["metrics"]["said"]["exact_match"] and fa["case_revision"] == 2
    assert fa["verdict"] in ("PASS", "NEEDS_HUMAN_REVIEW") and fa["metrics"]["behaviour"] == "HUMAN_ASSESSMENT_REQUIRED"
    audio = lab_user.get(f"/api/v1/voice-lab/test-case-revisions/{fa['test_case_revision_id']}/audio")
    assert audio.status_code == 200 and audio.content[:4] == b"RIFF"  # audio evidence for human assessment
    again = refused(lab_user, f"/experiments/{e['id']}/run", {})
    assert again["code"] == "NOT_READY"  # never re-run automatically
    # Pinned revisions: a later revision does not change a finished experiment.
    post(
        lab_user,
        f"/datasets/{d['id']}/cases/{faithful['test_case_id']}/revisions",
        {**base, "name": "Faithful statement v3", "expected_statement": "Changed later"},
    )
    assert {
        t["case_revision"]
        for t in ok(lab_user.get(f"/api/v1/voice-lab/experiments/{e['id']}"))["trials"]
        if t["case_name"].startswith("Faithful")
    } == {2}
    with pytest.raises(DBAPIError):  # trials are insert-only evidence
        db.execute(text(f"UPDATE {SCHEMA}.lab_trial SET verdict = 'PASS'"))
    db.rollback()


def test_metered_experiment_needs_authorisation_by_another_user(
    app: Any, lab_user: TestClient, lab_admin: TestClient, db: Session
) -> None:
    budget(lab_admin, overall_usd=10, daily_usd=10, per_experiment_usd=1, max_concurrent_sessions=1)
    d = post(lab_user, "/datasets", {"name": "Metered set"}, 201)
    for n in range(3):
        post(lab_user, f"/datasets/{d['id']}/cases", {"name": f"Statement {n}", "expected_statement": "Thank you"}, 201)
    pv = prompt(lab_user, "MOCK_METERED")["versions"][0]["id"]
    cfg = {
        "name": "Metered run",
        "dataset_id": d["id"],
        "prompt_version_id": pv,
        "repetitions": 2,
        "max_duration_s": 30,
    }
    # 3 tests × 2 repetitions × 30 s × USD 0.16 / min = USD 0.48 estimated maximum.
    low = refused(lab_user, "/experiments", {**cfg, "max_spend_usd": "0.40"})
    assert low["code"] == "SPEND_LIMIT_BELOW_ESTIMATE" and "0.4800" in low["details"][0]["message"]
    high = refused(lab_user, "/experiments", {**cfg, "max_spend_usd": "5"})
    assert high["code"] == "PER_EXPERIMENT_LIMIT"
    e = post(lab_user, "/experiments", {**cfg, "max_spend_usd": "0.50"}, 201)
    assert e["status"] == "AWAITING_AUTHORISATION" and e["estimated_max_usd"] == "0.4800"
    assert refused(lab_user, f"/experiments/{e['id']}/run", {})["code"] == "AUTHORISATION_REQUIRED"
    assert (
        lab_user.post(
            f"/api/v1/voice-lab/experiments/{e['id']}/authorise",
            headers=csrf_header(lab_user),
            json={"confirm_usd": "0.48", "reason": "self"},
        ).status_code
        == 403
    )
    wrong = refused(lab_admin, f"/experiments/{e['id']}/authorise", {"confirm_usd": "0.40", "reason": "Checked"}, 422)
    assert wrong["code"] == "AMOUNT_MISMATCH"
    e = post(lab_admin, f"/experiments/{e['id']}/authorise", {"confirm_usd": "0.4800", "reason": "Synthetic metering"})
    assert e["status"] == "READY" and e["authorised_usd"] == "0.4800"
    assert (
        lab_admin.post(f"/api/v1/voice-lab/experiments/{e['id']}/run", headers=csrf_header(lab_admin)).status_code
        == 403
    )
    e = post(lab_user, f"/experiments/{e['id']}/run", {})
    assert e["status"] == "COMPLETED" and e["reservation_status"] == "RECONCILED"
    assert Decimal(e["actual_usd"]) == sum(Decimal(t["cost_usd"]) for t in e["trials"]) <= Decimal(e["reserved_usd"])
    # Kill switch between trials: an experiment started and then stopped cancels its remaining trials.
    e2 = post(lab_user, "/experiments", {**cfg, "name": "Killed run", "max_spend_usd": "0.50"}, 201)
    post(lab_admin, f"/experiments/{e2['id']}/authorise", {"confirm_usd": "0.4800", "reason": "Kill drill"})
    with make_session_factory(db.get_bind())() as s2, s2.begin():  # type: ignore[arg-type]
        lab.start_experiment(s2, e2["created_by"], uuid.UUID(e2["id"]))
        lab.set_kill_switch(s2, "SYSTEM:test", True, "Kill during experiment")
    assert lab.execute(app, uuid.UUID(e2["id"])) == "CANCELLED"
    killed = ok(lab_user.get(f"/api/v1/voice-lab/experiments/{e2['id']}"))
    assert killed["end_reason"] == "KILL_SWITCH" and {t["status"] for t in killed["trials"]} == {"CANCELLED"}
    assert killed["reservation_status"] == "RECONCILED" and killed["actual_usd"] == "0.0000"
    post(lab_admin, "/kill-switch", {"engaged": False, "reason": "Drill complete"})


def test_operational_isolation_and_zero_paid_spend(lab_user: TestClient, db: Session) -> None:
    """Lab activity created no operational row; KPI inputs are untouched; nothing paid exists."""

    def kpis() -> list[tuple[Any, ...]]:
        items = ok(lab_user.get("/api/v1/dashboard/kpis"))["items"]
        return [(k["definition_id"], k.get("numerator"), k.get("denominator"), k.get("value")) for k in items]

    kpis_before = kpis()
    snapshot = counts(db)
    pv = prompt(lab_user)["versions"][0]["id"]
    s = post(lab_user, "/sessions", {"prompt_version_id": pv}, 201)
    post(lab_user, f"/sessions/{s['id']}/stop", {})
    assert counts(db) == snapshot
    assert kpis() == kpis_before
    fks = db.execute(
        text(
            "SELECT count(*) FROM information_schema.table_constraints tc "
            "JOIN information_schema.constraint_column_usage u ON u.constraint_name = tc.constraint_name "
            "AND u.table_schema = tc.table_schema WHERE tc.table_schema = :s AND tc.constraint_type = 'FOREIGN KEY' "
            "AND tc.table_name LIKE 'lab\\_%' AND u.table_name NOT LIKE 'lab\\_%'"
        ),
        {"s": SCHEMA},
    ).scalar_one()
    assert fks == 0  # no lab table references an operational table
    spend = ok(lab_user.get("/api/v1/voice-lab/settings"))["paid_spend"]
    assert spend == {"paid_reservations": 0, "paid_usd": "0", "paid_sessions": 0, "paid_experiments": 0}


def test_evaluation_is_deterministic() -> None:
    a = lab_eval.wording("Please confirm your date of birth", "Please confirm the date of birth now")
    assert a is not None and a["substituted"] == [{"expected": "your", "actual": "the"}] and a["added"] == ["now"]
    assert a["wer"] == round(2 / 6, 4) and not a["exact_match"]
    att = lab_eval.attribute("one two three", "one two three", "one too three")
    assert [x["attribution"] for x in att] == ["SUSPECTED_TRANSCRIPTION_ERROR"]
    att = lab_eval.attribute("one two three", "one three", "one three")
    assert [x["attribution"] for x in att] == ["SUSPECTED_SPEECH_DEVIATION"]
    assert [x["attribution"] for x in lab_eval.attribute("one two", None, "one")] == ["UNATTRIBUTED"]
    said = lab_eval.wording("Hello there", "Hello there")
    verdict, checks = lab_eval.check({"exact_wording": True}, {"said": said, "heard": None})
    assert (
        verdict == "NEEDS_HUMAN_REVIEW" and checks[0]["result"] == "NOT_MEASURED"
    )  # the provider's claim is not proof
    verdict, checks = lab_eval.check({"max_wer": 0.1}, {"heard": None})
    assert verdict == "NEEDS_HUMAN_REVIEW" and checks[0]["result"] == "NOT_MEASURED"  # missing is never a pass
    assert lab.mock_extract({"answer": "YES", "term": 20}, "Yes, it is 20 years") == {"answer": "YES", "term": "20"}
