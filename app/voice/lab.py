"""Voice Lab service (S1-E.1): prompts, golden datasets, sessions, recordings, transcripts and mock experiments.

Isolation: every record is a ``lab_*`` row (no contact attempt, conversation session, finding or review), audio goes
to a separate encrypted object store root (``<recordings>/<schema>/voice-lab``) and nothing here is read by KPIs,
queues, Call Detail or compliance logic. Reuse: the S1-A provider protocol and mock provider (with its VAD and
barge-in), the S1-C encrypted object store and WAV playback, and the S1-D faster-whisper engine and word normaliser.
The S2-D question controller is not involved — the lab measures voice behaviour, it does not run scripts.

Cost: ``app.voice.lab_cost`` reserves before anything starts and reconciles afterwards. Paid providers are refused.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import logging
import re
import threading
import time
import uuid
import wave
from array import array
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.voice import lab_cost as lc
from app.voice import lab_eval as le
from app.voice.media import EncryptedObjectStore
from app.voice.mock import FIXED_MESSAGE, MockVoiceProvider
from app.voice.provider import FRAME_BYTES, FRAME_MS, SAMPLE_RATE, Inbound, SessionStats

log = logging.getLogger("call360.voicelab")
TRACKS = ("MIC", "PROVIDER_PLAYBACK")
MAX_FIXTURE_S = 30
EXTRACTION = "MOCK_KEYWORD_EXTRACTION/1"
TIMING_BASIS = (
    "Mock provider timing measured in-process on this server (synthetic barge-in after 600 ms); not representative of "
    "a real provider or network"
)
CONTENT_BASIS = (
    "Mock: the provider's spoken text is the test case's mock output (or the expected statement); its audio is the "
    "test case's synthetic audio fixture. The mock does not interpret prompts or instructions."
)


class LabError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or []


def _now() -> datetime:
    return datetime.now(UTC)


def _j(v: Any) -> str:
    return json.dumps(v, default=str, sort_keys=True)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def next_ref(db: Session, table: str, col: str, prefix: str, width: int = 4) -> str:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('call360-voicelab-ref:' || :t))"), {"t": table})
    n = db.execute(
        text(f"SELECT coalesce(max(CAST(substring({col} FROM '[0-9]+$') AS integer)), 0) + 1 FROM {table}")  # noqa: S608 — identifiers are constants; values are bound
    ).scalar_one()
    return f"{prefix}{int(n):0{width}d}"


# ---- object store ------------------------------------------------------------------------------------------------
def store_for(app: Any) -> EncryptedObjectStore | None:
    """A separate root for lab audio, with the recording key (S1-C AES-256-GCM, no overwrite)."""
    if getattr(app.state, "lab_store", None) is not None:
        rs: EncryptedObjectStore = app.state.lab_store
        return rs
    settings = app.state.settings
    if settings.recording_encryption_key is None:
        return None
    from app.domain.protection import decode_key

    root = Path(settings.recording_storage_dir).expanduser() / settings.target_schema / "voice-lab"
    app.state.lab_store = EncryptedObjectStore(root, decode_key(settings.recording_encryption_key.get_secret_value()))
    return app.state.lab_store  # type: ignore[no-any-return]


def obj_key(owner: uuid.UUID, track: str) -> str:
    return f"{owner}/{track}/000-000000.c360"


def read_wav(data: bytes) -> bytes:
    try:
        with wave.open(io.BytesIO(data)) as w:
            if (w.getframerate(), w.getnchannels(), w.getsampwidth()) != (SAMPLE_RATE, 1, 2):
                raise LabError(422, "AUDIO_FORMAT", "Audio fixtures must be 16 kHz mono 16-bit PCM WAV")
            pcm: bytes = w.readframes(w.getnframes())
    except (wave.Error, EOFError) as exc:
        raise LabError(422, "AUDIO_FORMAT", "The audio fixture is not a readable WAV file") from exc
    if not pcm or len(pcm) // 2 > SAMPLE_RATE * MAX_FIXTURE_S:
        raise LabError(422, "AUDIO_LENGTH", f"Audio fixtures must be between 0 and {MAX_FIXTURE_S} seconds")
    return pcm


# ---- prompts -----------------------------------------------------------------------------------------------------
def _check_provider_config(provider: str, model: str, voice: str) -> lc.Provider:
    try:
        p = lc.provider(provider)
    except lc.BudgetError as exc:
        raise LabError(422, exc.code, exc.message) from exc
    if p.models and model not in p.models:
        raise LabError(422, "MODEL_UNKNOWN", f"{provider} offers models: {', '.join(p.models)}")
    if p.voices and voice not in p.voices:
        raise LabError(422, "VOICE_UNKNOWN", f"{provider} offers voices: {', '.join(p.voices)}")
    return p


def prompt_content_sha(c: dict[str, Any]) -> str:
    keys = ("system_prompt", "turn_instructions", "provider", "model", "voice", "parameters")
    return _sha(_j({k: c[k] for k in keys}).encode())


OPENING_MAX_CHARS = 500  # S1-E.2B (D-109)


def opening_instruction(version: dict[str, Any]) -> str:
    """The prompt version's opening instruction (stored in ``parameters``; part of the prompt SHA-256)."""
    v = (version.get("parameters") or {}).get("opening_instruction")
    return v.strip() if isinstance(v, str) else ""


def _normalise_opening(body: dict[str, Any], p: lc.Provider) -> dict[str, Any]:
    """Move the optional opening instruction into ``parameters`` (no migration; covered by the SHA-256). Only the
    GPT-Live providers (and their loopback mock) send it; the keyless mocks speak a fixed message and refuse it."""
    params = dict(body.get("parameters") or {})
    raw = body.get("opening_instruction")
    if raw is None:
        raw = params.get("opening_instruction")
    text_ = raw.strip() if isinstance(raw, str) else ""
    params.pop("opening_instruction", None)
    if text_:
        if len(text_) > OPENING_MAX_CHARS:
            raise LabError(422, "OPENING_TOO_LONG", f"Opening instruction: at most {OPENING_MAX_CHARS} characters")
        if p.code not in GPT_PROVIDERS:
            raise LabError(422, "OPENING_NOT_SUPPORTED", f"{p.code} speaks a fixed message; no opening instruction")
        params["opening_instruction"] = text_
    return {**body, "parameters": params}


def save_prompt(db: Session, actor: str, body: dict[str, Any], prompt_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Create a prompt or append a new version (insert-only history; an unchanged configuration is refused)."""
    p = _check_provider_config(body["provider"], body["model"], body["voice"])
    if p.hidden:
        raise LabError(
            422,
            "PROVIDER_RENAMED",
            f"{body['provider']} is a legacy code; use OPENAI_GPT_LIVE (or the preferred AZURE_OPENAI_GPT_LIVE)",
        )
    body = _normalise_opening(body, p)
    now = _now()
    if prompt_id is None:
        prompt_id = uuid.uuid4()
        db.execute(
            text("INSERT INTO lab_prompt (id, prompt_ref, name, created_by, created_at) VALUES (:i, :r, :n, :by, :t)"),
            {
                "i": prompt_id,
                "r": next_ref(db, "lab_prompt", "prompt_ref", "LAB-P-"),
                "n": body["name"],
                "by": actor,
                "t": now,
            },
        )
        version = 1
    else:
        head = _one(db, "SELECT * FROM lab_prompt WHERE id = :i FOR UPDATE", i=prompt_id)
        if head is None:
            raise LabError(404, "NOT_FOUND", "Prompt not found")
        latest = _one(
            db, "SELECT * FROM lab_prompt_version WHERE prompt_id = :i ORDER BY version_no DESC LIMIT 1", i=prompt_id
        )
        assert latest is not None
        if body.get("expected_version") is not None and body["expected_version"] != latest["version_no"]:
            raise LabError(409, "STALE_PROMPT", f"Version {latest['version_no']} is now the latest; reload first")
        if latest["sha256"] == prompt_content_sha(body):
            raise LabError(409, "NO_CHANGE", "This configuration is identical to the latest version")
        version = latest["version_no"] + 1
    vid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO lab_prompt_version (id, prompt_id, version_no, system_prompt, turn_instructions, provider, "
            "model, voice, parameters, change_note, sha256, created_by, created_at) VALUES (:id, :p, :v, :sp, "
            "CAST(:ti AS jsonb), :pr, :m, :vo, CAST(:pa AS jsonb), :cn, :sha, :by, :t)"
        ),
        {
            "id": vid,
            "p": prompt_id,
            "v": version,
            "sp": body["system_prompt"],
            "ti": _j(body["turn_instructions"]),
            "pr": body["provider"],
            "m": body["model"],
            "vo": body["voice"],
            "pa": _j(body.get("parameters") or {}),
            "cn": body.get("change_note") or ("Initial version" if version == 1 else "Updated"),
            "sha": prompt_content_sha(body),
            "by": actor,
            "t": now,
        },
    )
    return prompt(db, prompt_id)


def prompt(db: Session, prompt_id: uuid.UUID) -> dict[str, Any]:
    head = _one(db, "SELECT * FROM lab_prompt WHERE id = :i", i=prompt_id)
    if head is None:
        raise LabError(404, "NOT_FOUND", "Prompt not found")
    versions = _all(db, "SELECT * FROM lab_prompt_version WHERE prompt_id = :i ORDER BY version_no DESC", i=prompt_id)
    versions = [{**v, "opening_instruction": opening_instruction(v) or None} for v in versions]
    return {**head, "versions": versions, "latest": versions[0]}


def prompts(db: Session) -> list[dict[str, Any]]:
    ids = db.execute(text("SELECT id FROM lab_prompt ORDER BY created_at DESC LIMIT 100")).scalars().all()
    return [prompt(db, i) for i in ids]


def prompt_version(db: Session, version_id: uuid.UUID) -> dict[str, Any]:
    v = _one(
        db,
        "SELECT v.*, p.prompt_ref, p.name FROM lab_prompt_version v JOIN lab_prompt p ON p.id = v.prompt_id "
        "WHERE v.id = :i",
        i=version_id,
    )
    if v is None:
        raise LabError(404, "NOT_FOUND", "Prompt version not found")
    return v


# ---- datasets and test cases ---------------------------------------------------------------------------------------
def create_dataset(db: Session, actor: str, name: str, description: str) -> dict[str, Any]:
    did = uuid.uuid4()
    db.execute(
        text("INSERT INTO lab_dataset (id, dataset_ref, name, description, created_by) VALUES (:i, :r, :n, :d, :by)"),
        {"i": did, "r": next_ref(db, "lab_dataset", "dataset_ref", "LAB-D-"), "n": name, "d": description, "by": actor},
    )
    return dataset(db, did)


def _latest_revisions(db: Session, dataset_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT DISTINCT ON (c.id) r.*, c.case_ref, c.dataset_id, (SELECT count(*) FROM lab_test_case_revision x "
        "WHERE x.test_case_id = c.id) AS revisions FROM lab_test_case c JOIN lab_test_case_revision r "
        "ON r.test_case_id = c.id WHERE c.dataset_id = :d ORDER BY c.id, r.revision DESC",
        d=dataset_id,
    )


def dataset(db: Session, dataset_id: uuid.UUID) -> dict[str, Any]:
    d = _one(db, "SELECT * FROM lab_dataset WHERE id = :i", i=dataset_id)
    if d is None:
        raise LabError(404, "NOT_FOUND", "Dataset not found")
    cases = sorted(_latest_revisions(db, dataset_id), key=lambda r: r["case_ref"])
    return {**d, "cases": cases}


def datasets(db: Session) -> list[dict[str, Any]]:
    ids = db.execute(text("SELECT id FROM lab_dataset ORDER BY created_at DESC LIMIT 100")).scalars().all()
    return [dataset(db, i) for i in ids]


def case_history(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT r.*, c.case_ref, c.dataset_id FROM lab_test_case_revision r JOIN lab_test_case c ON c.id = "
        "r.test_case_id WHERE c.id = :c ORDER BY r.revision DESC",
        c=case_id,
    )


def case_revision(db: Session, revision_id: uuid.UUID) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT r.*, c.case_ref, c.dataset_id FROM lab_test_case_revision r JOIN lab_test_case c "
        "ON c.id = r.test_case_id WHERE r.id = :i",
        i=revision_id,
    )
    if r is None:
        raise LabError(404, "NOT_FOUND", "Test case revision not found")
    return r


def save_case(
    db: Session,
    rs: EncryptedObjectStore | None,
    actor: str,
    dataset_id: uuid.UUID,
    body: dict[str, Any],
    case_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Create a test case or append a revision (earlier revisions — and experiments pinned to them — are kept)."""
    if _one(db, "SELECT id FROM lab_dataset WHERE id = :i", i=dataset_id) is None:
        raise LabError(404, "NOT_FOUND", "Dataset not found")
    errors = le.validate_criteria(body.get("criteria") or {})
    if errors:
        raise LabError(422, "CRITERIA_INVALID", "Invalid evaluation criteria", errors)
    latest: dict[str, Any] | None = None
    if case_id is None:
        case_id = uuid.uuid4()
        db.execute(
            text("INSERT INTO lab_test_case (id, dataset_id, case_ref, created_by) VALUES (:i, :d, :r, :by)"),
            {"i": case_id, "d": dataset_id, "r": next_ref(db, "lab_test_case", "case_ref", "LAB-T-"), "by": actor},
        )
        rev = 1
    else:
        hist = case_history(db, case_id)
        if not hist or hist[0]["dataset_id"] != dataset_id:
            raise LabError(404, "NOT_FOUND", "Test case not found")
        latest = hist[0]
        if body.get("expected_revision") is not None and body["expected_revision"] != latest["revision"]:
            raise LabError(409, "STALE_TEST_CASE", f"Revision {latest['revision']} is now the latest; reload first")
        rev = latest["revision"] + 1
    rid = uuid.uuid4()
    audio_key = audio_sha = None
    samples: int | None = None
    if body.get("audio_wav_b64"):
        if rs is None:
            raise LabError(409, "STORE_NOT_CONFIGURED", "Audio fixtures need the local encrypted store (recording key)")
        try:
            raw = base64.b64decode(body["audio_wav_b64"], validate=True)
        except ValueError as exc:
            raise LabError(422, "AUDIO_FORMAT", "The audio fixture is not valid base64") from exc
        pcm = read_wav(raw)
        audio_key, audio_sha, samples = obj_key(rid, "PROVIDER_PLAYBACK"), _sha(pcm), len(pcm) // 2
        rs.put(audio_key, pcm)
    elif latest is not None and body.get("keep_audio", True) and latest["audio_object_key"]:
        audio_key, audio_sha, samples = latest["audio_object_key"], latest["audio_sha256"], latest["audio_samples"]
    db.execute(
        text(
            "INSERT INTO lab_test_case_revision (id, test_case_id, revision, name, description, system_prompt, "
            "test_instruction, expected_statement, customer_response, expected_answer, expected_behaviour, criteria, "
            "mock_output, audio_object_key, audio_sha256, audio_samples, source, retired, change_note, created_by) "
            "VALUES (:id, :c, :rev, :n, :d, :sp, :ti, :es, :cr, CAST(:ea AS jsonb), :eb, CAST(:cri AS jsonb), :mo, "
            ":ak, :ash, :asm, CAST(:src AS jsonb), :ret, :cn, :by)"
        ),
        {
            "id": rid,
            "c": case_id,
            "rev": rev,
            "n": body["name"],
            "d": body.get("description") or "",
            "sp": body.get("system_prompt") or "",
            "ti": body.get("test_instruction") or "",
            "es": body["expected_statement"],
            "cr": body.get("customer_response") or "",
            "ea": _j(body.get("expected_answer") or {}),
            "eb": body.get("expected_behaviour") or "",
            "cri": _j(body.get("criteria") or {}),
            "mo": body.get("mock_output"),
            "ak": audio_key,
            "ash": audio_sha,
            "asm": samples,
            "src": _j(body.get("source") or {"kind": "MANUAL"}),
            "ret": bool(body.get("retired")),
            "cn": body.get("change_note") or ("Created" if rev == 1 else "Revised"),
            "by": actor,
        },
    )
    return case_revision(db, rid)


def import_from_script(
    db: Session, actor: str, dataset_id: uuid.UUID, script_version_id: uuid.UUID, codes: list[str] | None
) -> list[dict[str, Any]]:
    """Copy synthetic questions and statements of a Script Studio version into test cases (read-only on scripts;
    each case records its source question revision). Scripts are synthetic and unapproved wording."""
    v = _one(
        db,
        "SELECT v.id, v.version_label, v.status, f.code AS family FROM script_version v JOIN script_family f "
        "ON f.id = v.script_family_id WHERE v.id = :i",
        i=script_version_id,
    )
    if v is None:
        raise LabError(404, "NOT_FOUND", "Script version not found")
    rows = _all(
        db,
        "SELECT q.question_code AS code, qr.id AS revision_id, qr.revision, qr.customer_wording, qr.answer_type, "
        "qr.expected_value FROM script_section ss JOIN module_question mq ON mq.script_module_id = ss.script_module_id "
        "JOIN question_revision qr ON qr.id = mq.question_revision_id JOIN question_bank_item q "
        "ON q.id = qr.question_bank_item_id WHERE ss.script_version_id = :v ORDER BY ss.position, mq.position",
        v=script_version_id,
    )
    if codes:
        rows = [r for r in rows if r["code"] in set(codes)]
    if not rows:
        raise LabError(422, "NOTHING_TO_IMPORT", "No questions or statements match")
    out = []
    for r in rows:
        exp = r["expected_value"] if isinstance(r["expected_value"], dict) else {}
        answer = {"answer": exp["value"]} if isinstance(exp.get("value"), str | int) else {}
        out.append(
            save_case(
                db,
                None,
                actor,
                dataset_id,
                {
                    "name": f"{r['code']} ({v['family']} {v['version_label']})",
                    "description": f"Imported from Script Studio ({v['status'].lower()} version; synthetic wording)",
                    "test_instruction": "Say the scripted wording exactly, then wait for the customer.",
                    "expected_statement": r["customer_wording"],
                    "expected_answer": answer,
                    "expected_behaviour": "Delivers the scripted wording without additions; does not answer for the "
                    "customer.",
                    "criteria": {"exact_wording": True},
                    "source": {
                        "kind": "SCRIPT_STUDIO",
                        "script_version_id": str(v["id"]),
                        "family": v["family"],
                        "version": v["version_label"],
                        "question_code": r["code"],
                        "question_revision_id": str(r["revision_id"]),
                        "question_revision": r["revision"],
                    },
                    "change_note": "Imported from Script Studio",
                },
            )
        )
    return out


# ---- budgets and controls ------------------------------------------------------------------------------------------
def lab_settings(db: Session, settings: Any) -> dict[str, Any]:
    now = _now()
    return {
        "control": lc.control(db),
        "budgets": [{**lc.budget(db, c), "usage": lc.usage(db, c, now)} for c in ("SIMULATED", "PAID")],
        "providers": [
            {
                "code": p.code,
                "label": p.label,
                "spend_class": p.spend_class,
                "available": p.available,
                "reason": p.reason,
                "models": list(p.models),
                "voices": list(p.voices),
                "rate_card": p.rates.as_json(),
                "network": p.network,
                "vendor": p.vendor,
                "preferred": p.preferred,
                "hidden": p.hidden,
            }
            for p in (lc.resolve(code, settings) for code in lc.PROVIDERS)
        ],
        "paid_spend": lc.paid_spend(db),
        "authorisations": authorisations(db),
        "history": _all(db, "SELECT * FROM lab_config_change ORDER BY created_at DESC LIMIT 30"),
    }


def update_budget(db: Session, actor: str, spend_class: str, body: dict[str, Any], reason: str) -> dict[str, Any]:
    b = lc.budget(db, spend_class, lock=True)
    if body.get("expected_row_version") != b["row_version"]:
        raise LabError(409, "STALE_SETTINGS", "The budget changed; reload first")
    fields = (
        "overall_usd",
        "daily_usd",
        "per_experiment_usd",
        "max_concurrent_sessions",
        "interactive_max_s",
        "idle_timeout_s",
    )
    new = {f: body[f] for f in fields}
    if (
        not Decimal(0)
        < Decimal(str(new["per_experiment_usd"]))
        <= Decimal(str(new["daily_usd"]))
        <= Decimal(str(new["overall_usd"]))
    ):
        raise LabError(422, "BUDGET_INVALID", "Limits must satisfy 0 < per experiment ≤ daily ≤ overall")
    db.execute(
        text(
            "UPDATE lab_budget SET overall_usd = :overall_usd, daily_usd = :daily_usd, per_experiment_usd = "
            ":per_experiment_usd, max_concurrent_sessions = :max_concurrent_sessions, interactive_max_s = "
            ":interactive_max_s, idle_timeout_s = :idle_timeout_s, updated_by = :by, updated_at = now(), "
            "row_version = row_version + 1 WHERE spend_class = :c"
        ),
        {**new, "by": actor, "c": spend_class},
    )
    _config_change(db, actor, f"BUDGET:{spend_class}", {f: b[f] for f in fields}, new, reason)
    return lc.budget(db, spend_class)


def set_paid_switch(db: Session, actor: str, enabled: bool, reason: str) -> dict[str, Any]:
    c = lc.control(db, lock=True)
    db.execute(
        text(
            "UPDATE lab_control SET paid_enabled = :p, updated_by = :by, updated_at = now(), "
            "row_version = row_version + 1 WHERE id = 1"
        ),
        {"p": enabled, "by": actor},
    )
    _config_change(db, actor, "PAID_SWITCH", {"paid_enabled": c["paid_enabled"]}, {"paid_enabled": enabled}, reason)
    return lc.control(db)


def set_kill_switch(db: Session, actor: str, engaged: bool, reason: str) -> dict[str, Any]:
    c = lc.control(db, lock=True)
    db.execute(
        text(
            "UPDATE lab_control SET kill_switch = :k, kill_reason = :r, updated_by = :by, updated_at = now(), "
            "row_version = row_version + 1 WHERE id = 1"
        ),
        {"k": engaged, "r": reason if engaged else None, "by": actor},
    )
    _config_change(db, actor, "KILL_SWITCH", {"kill_switch": c["kill_switch"]}, {"kill_switch": engaged}, reason)
    return lc.control(db)


def _config_change(db: Session, actor: str, target: str, before: Any, after: Any, reason: str) -> None:
    db.execute(
        text(
            "INSERT INTO lab_config_change (id, target, before, after, reason, created_by) VALUES (:i, :t, "
            "CAST(:b AS jsonb), CAST(:a AS jsonb), :r, :by)"
        ),
        {"i": uuid.uuid4(), "t": target, "b": _j(before), "a": _j(after), "r": reason, "by": actor},
    )


# ---- sessions ------------------------------------------------------------------------------------------------------
def append_event(
    db: Session,
    session_id: uuid.UUID,
    event_type: str,
    *,
    source: str = "SERVER",
    offset_ms: int = 0,
    details: dict[str, Any] | None = None,
) -> None:
    # Uplink and downlink trace concurrently: serialise sequence numbers per session.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('call360-voicelab-event:' || :s))"), {"s": str(session_id)})
    db.execute(
        text(
            "INSERT INTO lab_session_event (id, session_id, seq, event_type, source, offset_ms, "
            "details) SELECT :i, :s, "
            "coalesce(max(seq), 0) + 1, :t, :src, :o, CAST(:d AS jsonb) FROM lab_session_event WHERE session_id = :s"
        ),
        {
            "i": uuid.uuid4(),
            "s": session_id,
            "t": event_type,
            "src": source,
            "o": max(0, offset_ms),
            "d": _j(details or {}),
        },
    )


def create_session(
    db: Session,
    actor: str,
    prompt_version_id: uuid.UUID,
    *,
    record: bool,
    recording_available: bool,
    settings: Any,
) -> dict[str, Any]:
    """Refuse (with every reason) or create an interactive session, reserving its maximum cost first.

    A PAID (GPT-Live) session additionally needs, all in this transaction: the server's GPT-Live configuration (mode
    LIVE and a backend-only key), the manager's paid switch, an ISSUED single-use smoke-test authorisation for this
    provider / model / voice issued by another user and not expired — consumed here — and the PAID budget. Its maximum
    duration is the authorisation's (≤ 120 s)."""
    pv = prompt_version(db, prompt_version_id)
    _check_provider_config(pv["provider"], pv["model"], pv["voice"])
    p = lc.resolve(pv["provider"], settings)
    if record and not recording_available:
        raise LabError(409, "RECORDING_NOT_AVAILABLE", "Recording is not configured on this server")
    now = _now()
    limits = lc.budget(db, "PAID" if p.spend_class == "PAID" else "SIMULATED")
    max_s = int(limits["interactive_max_s"])
    auth: dict[str, Any] | None = None
    if p.spend_class in ("SIMULATED", "PAID"):
        lc.lock_class(db, p.spend_class)  # before the session row: concurrent requests are decided one at a time
    if p.spend_class == "PAID":
        ctl = lc.control(db)
        reasons = []
        if ctl["kill_switch"]:
            reasons.append("KILL_SWITCH: the Voice Lab emergency stop is engaged")
        if not ctl["paid_enabled"]:
            reasons.append("PAID_DISABLED: paid providers are disabled (no paid access without separate authorisation)")
        if not p.available:
            reasons.append(f"PROVIDER_NOT_AVAILABLE: {p.reason}")
        auth = _one(db, "SELECT * FROM lab_paid_authorisation WHERE status = 'ISSUED' FOR UPDATE")
        if auth is not None and auth["expires_at"] <= now:
            db.execute(text("UPDATE lab_paid_authorisation SET status = 'EXPIRED' WHERE id = :i"), {"i": auth["id"]})
            auth = None
        if p.models and pv["model"] not in p.models:
            reasons.append(
                f"DEPLOYMENT_MISMATCH: the prompt names {pv['model']}; this server is configured for "
                f"{', '.join(p.models)}"
            )
        if not p.rates.known:
            reasons.append(f"COST_UNKNOWN: {p.rates.basis}")
        if auth is None:
            reasons.append("SMOKE_TEST_NOT_AUTHORISED: no issued single-use paid smoke-test authorisation")
        else:
            if auth["authorised_by"] == actor:
                reasons.append("SELF_AUTHORISATION: the authorisation was issued by you; another user executes it")
            if (auth["provider"], auth["model"], auth["voice"]) != (p.code, pv["model"], pv["voice"]):
                reasons.append(
                    f"AUTHORISATION_MISMATCH: authorised {auth['provider']} / {auth['model']} / {auth['voice']}"
                )
            max_s = min(max_s, int(auth["max_duration_s"]))
        if reasons:
            raise LabError(409, reasons[0].split(":", 1)[0], "Refused by Voice Lab cost controls", reasons)
    try:
        amount = lc.estimate_session(p, max_s)
    except lc.BudgetError as exc:
        raise LabError(exc.status, exc.code, exc.message) from exc
    if auth is not None and amount > auth["max_usd"]:
        raise LabError(
            409,
            "AUTHORISATION_EXCEEDED",
            "Refused by Voice Lab cost controls",
            [f"AUTHORISATION_EXCEEDED: estimated USD {amount} exceeds the authorised USD {auth['max_usd']}"],
        )
    if p.spend_class != "PAID" and not p.available:
        raise LabError(
            409, "PROVIDER_NOT_AVAILABLE", "Refused by Voice Lab cost controls", [f"PROVIDER_NOT_AVAILABLE: {p.reason}"]
        )
    sid = uuid.uuid4()
    gpt = p.code in GPT_PROVIDERS
    db.execute(
        text(
            "INSERT INTO lab_session (id, session_ref, mode, prompt_version_id, provider, model, voice, spend_class, "
            "rate_card, status, record, max_duration_s, idle_timeout_s, estimated_max_usd, created_by, created_at, "
            "paid_authorisation_id, termination_status) VALUES (:i, :r, 'INTERACTIVE', :pv, :p, :m, :v, :c, "
            "CAST(:rc AS jsonb), 'CREATED', :rec, :mx, :idle, :est, :by, :t, :auth, :term)"
        ),
        {
            "i": sid,
            "r": next_ref(db, "lab_session", "session_ref", "LAB-S-", 5),
            "pv": prompt_version_id,
            "p": p.code,
            "m": pv["model"],
            "v": pv["voice"],
            "c": p.spend_class,
            "rc": _j(p.rates.as_json()),
            "rec": record,
            "mx": max_s,
            "idle": limits["idle_timeout_s"],
            "est": amount,
            "by": actor,
            "t": now,
            "auth": auth["id"] if auth else None,
            "term": "NOT_STARTED" if gpt else "NOT_APPLICABLE",
        },
    )
    if auth is not None:  # single use: consumed by this session, whatever happens next
        db.execute(
            text(
                "UPDATE lab_paid_authorisation SET status = 'CONSUMED', consumed_by = :by, consumed_at = :t "
                "WHERE id = :i"
            ),
            {"by": actor, "t": now, "i": auth["id"]},
        )
    try:
        lc.reserve(
            db,
            p,
            amount,
            actor=actor,
            now=now,
            session_id=sid if p.spend_class in ("SIMULATED", "PAID") else None,
            basis={
                "max_duration_s": max_s,
                "rate_card": p.rates.as_json(),
                "estimate": "the whole maximum duration at the provider's rate card",
                "authorisation": auth["authorisation_ref"] if auth else None,
            },
        )
    except lc.BudgetError as exc:
        raise LabError(exc.status, exc.code, exc.message, exc.details) from exc
    append_event(
        db,
        sid,
        "SESSION_CREATED",
        details={
            "prompt": f"{pv['prompt_ref']} v{pv['version_no']}",
            "prompt_sha256": pv["sha256"],
            "provider": p.code,
            "estimated_max_usd": str(amount),
            "spend_class": p.spend_class,
            "record": record,
            "max_duration_s": max_s,
            "authorisation": auth["authorisation_ref"] if auth else None,
        },
    )
    if p.spend_class in ("SIMULATED", "PAID"):
        append_event(db, sid, "BUDGET_RESERVED", source="BUDGET", details={"reserved_usd": str(amount)})
    return session(db, sid)


# ---- paid smoke-test authorisation (S1-E.2) --------------------------------------------------------------------------
def issue_authorisation(
    db: Session,
    actor: str,
    *,
    provider_code: str,
    model: str,
    voice: str,
    max_duration_s: int,
    reason: str,
    expires_in_h: int,
    settings: Any,
) -> dict[str, Any]:
    """A manager's single-use permission for ONE paid session. Issuing is not execution: another user must start it,
    and every other gate still applies at that moment."""
    p = lc.resolve(provider_code, settings)
    if p.spend_class != "PAID" or p.hidden:
        raise LabError(422, "NOT_A_PAID_PROVIDER", "Smoke-test authorisations are for the paid GPT-Live providers")
    _check_provider_config(provider_code, model, voice)
    if p.models and model not in p.models:
        raise LabError(422, "MODEL_UNKNOWN", f"{provider_code} is configured for: {', '.join(p.models)}")
    if not 10 <= max_duration_s <= 120:
        raise LabError(422, "DURATION_INVALID", "A smoke test lasts 10–120 seconds")
    if _one(db, "SELECT id FROM lab_paid_authorisation WHERE status = 'ISSUED' AND expires_at > now()"):
        raise LabError(409, "AUTHORISATION_EXISTS", "Another smoke-test authorisation is still issued; revoke it first")
    db.execute(
        text("UPDATE lab_paid_authorisation SET status = 'EXPIRED' WHERE status = 'ISSUED' AND expires_at <= now()")
    )
    try:
        max_usd = lc.estimate_session(p, max_duration_s)
    except lc.BudgetError as exc:  # e.g. Azure without a verified price: no authorisation can be issued
        raise LabError(exc.status, exc.code, f"{exc.message}: {p.rates.basis}") from exc
    aid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO lab_paid_authorisation (id, authorisation_ref, provider, model, voice, max_duration_s, "
            "max_usd, "
            "rate_card, reason, expires_at, authorised_by) VALUES (:i, :r, :p, :m, :v, :d, :u, CAST(:rc AS jsonb), "
            ":why, now() + make_interval(hours => :h), :by)"
        ),
        {
            "i": aid,
            "r": next_ref(db, "lab_paid_authorisation", "authorisation_ref", "LAB-A-"),
            "p": provider_code,
            "m": model,
            "v": voice,
            "d": max_duration_s,
            "u": max_usd,
            "rc": _j(p.rates.as_json()),
            "why": reason,
            "h": expires_in_h,
            "by": actor,
        },
    )
    return authorisation(db, aid)


def revoke_authorisation(db: Session, actor: str, authorisation_id: uuid.UUID, reason: str) -> dict[str, Any]:
    a = _one(db, "SELECT * FROM lab_paid_authorisation WHERE id = :i FOR UPDATE", i=authorisation_id)
    if a is None:
        raise LabError(404, "NOT_FOUND", "Authorisation not found")
    if a["status"] != "ISSUED":
        raise LabError(409, "NOT_ISSUED", f"The authorisation is {a['status']}")
    db.execute(
        text(
            "UPDATE lab_paid_authorisation SET status = 'REVOKED', revoked_by = :by, revoked_at = now(), "
            "revoke_reason = :r WHERE id = :i"
        ),
        {"by": actor, "r": reason, "i": authorisation_id},
    )
    return authorisation(db, authorisation_id)


def authorisation(db: Session, authorisation_id: uuid.UUID) -> dict[str, Any]:
    a = _one(
        db,
        "SELECT a.*, s.session_ref AS consumed_session_ref FROM lab_paid_authorisation a LEFT JOIN lab_session s "
        "ON s.paid_authorisation_id = a.id WHERE a.id = :i",
        i=authorisation_id,
    )
    if a is None:
        raise LabError(404, "NOT_FOUND", "Authorisation not found")
    return a


def authorisations(db: Session) -> list[dict[str, Any]]:
    db.execute(
        text("UPDATE lab_paid_authorisation SET status = 'EXPIRED' WHERE status = 'ISSUED' AND expires_at <= now()")
    )
    ids = db.execute(text("SELECT id FROM lab_paid_authorisation ORDER BY authorised_at DESC LIMIT 20")).scalars().all()
    return [authorisation(db, i) for i in ids]


def session(db: Session, session_id: uuid.UUID, *, events: bool = True) -> dict[str, Any]:
    s = _one(
        db,
        "SELECT s.*, pv.version_no AS prompt_version_no, p.prompt_ref, p.name AS prompt_name, r.status AS "
        "reservation_status, r.reserved_usd, r.actual_usd AS reservation_actual_usd, e.experiment_ref, "
        "pa.authorisation_ref "
        "FROM lab_session s LEFT JOIN lab_prompt_version pv ON pv.id = s.prompt_version_id LEFT JOIN lab_prompt p ON "
        "p.id = pv.prompt_id LEFT JOIN lab_reservation r ON r.session_id = s.id LEFT JOIN lab_experiment e "
        "ON e.id = s.experiment_id LEFT JOIN lab_paid_authorisation pa ON pa.id = s.paid_authorisation_id "
        "WHERE s.id = :i",
        i=session_id,
    )
    if s is None:
        raise LabError(404, "NOT_FOUND", "Lab session not found")
    s["media"] = _all(
        db,
        "SELECT track, samples, sha256, basis, purged_at FROM lab_media WHERE session_id = :i ORDER BY track",
        i=session_id,
    )
    s["transcripts"] = _all(
        db,
        "SELECT track, engine, text, words, created_at, source, purged_at FROM lab_transcript WHERE session_id = :i "
        "ORDER BY source, track",
        i=session_id,
    )
    s["events"] = (
        _all(
            db,
            "SELECT seq, event_type, source, offset_ms, details, occurred_at FROM lab_session_event "
            "WHERE session_id = :i ORDER BY seq",
            i=session_id,
        )
        if events
        else []
    )
    return s


def sessions(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    ids = db.execute(text("SELECT id FROM lab_session ORDER BY created_at DESC LIMIT :l"), {"l": limit}).scalars().all()
    return [session(db, i, events=False) for i in ids]


def mark_live(db: Session, session_id: uuid.UUID) -> dict[str, Any]:
    s = _one(db, "SELECT * FROM lab_session WHERE id = :i FOR UPDATE", i=session_id)
    if s is None or s["status"] != "CREATED":
        raise LabError(409, "SESSION_NOT_CONNECTABLE", "This lab session cannot be connected")
    db.execute(
        text("UPDATE lab_session SET status = 'LIVE', started_at = now(), row_version = row_version + 1 WHERE id = :i"),
        {"i": session_id},
    )
    append_event(db, session_id, "SESSION_LIVE")
    return s


GPT_PROVIDERS = ("AZURE_OPENAI_GPT_LIVE", "OPENAI_GPT_LIVE", "GPT_LIVE", "GPT_LIVE_MOCK")


def finish_session(
    db: Session,
    session_id: uuid.UUID,
    *,
    reason: str,
    metrics: dict[str, Any],
    status: str = "ENDED",
    provider_outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """End once and settle the reservation.

    Mock providers: reconcile with the measured audio (never more than the maximum duration). GPT-Live providers:
    reconcile ONLY from the provider-confirmed final usage (``session.closed``); a session that never connected costs
    nothing; anything else — no confirmation, a dropped connection, a crash — leaves the reservation HELD at its
    maximum and the termination UNCONFIRMED until a manager confirms the provider's usage. An unconfirmed charge is
    never treated as zero."""
    s = _one(db, "SELECT * FROM lab_session WHERE id = :i FOR UPDATE", i=session_id)
    assert s is not None
    if s["status"] in ("ENDED", "FAILED"):
        return s
    now = _now()
    cost: Decimal | None = None
    termination = s["termination_status"]
    usage_s: float | None = None
    source: str | None = None
    if s["provider"] in GPT_PROVIDERS:
        out = provider_outcome or {}
        termination = out.get("termination") or ("NOT_STARTED" if s["status"] == "CREATED" else "UNCONFIRMED")
        usage_s = out.get("usage_seconds")
        if termination == "NOT_STARTED":
            cost, source = Decimal(0), "NO_PROVIDER_CONNECTION"
        elif termination == "CONFIRMED" and out.get("usage_confirmed") and usage_s is not None:
            cost, source = lc.measured_cost(s["rate_card"], 0, 0, session_s=float(usage_s)), "PROVIDER_SESSION_CLOSED"
        else:
            termination = "UNCONFIRMED"
            source = "UNCONFIRMED"
        if cost is not None:
            closed = lc.close(db, session_id=session_id, actual=cost, now=now)
            append_event(
                db,
                session_id,
                "BUDGET_RECONCILED",
                source="BUDGET",
                details={
                    "actual_usd": str(cost),
                    "usage_seconds": usage_s,
                    "usage_source": source,
                    "reserved_usd": str(closed["reserved_usd"]) if closed else None,
                    "overrun": bool(closed and closed["overrun"]),
                },
            )
        else:
            append_event(
                db,
                session_id,
                "USAGE_UNCONFIRMED",
                source="BUDGET",
                details={
                    "last_reported_usage_seconds": usage_s,
                    "reservation": "RETAINED at the reserved maximum",
                    "next_step": "a Voice Lab manager confirms the provider-reported usage "
                    "(or closes the provider session)",
                },
            )
    elif s["spend_class"] == "SIMULATED":
        cap = float(s["max_duration_s"])
        cost = lc.measured_cost(
            s["rate_card"], min(cap, metrics.get("input_audio_s", 0.0)), min(cap, metrics.get("output_audio_s", 0.0))
        )
        closed = lc.close(db, session_id=session_id, actual=cost, now=now)
        append_event(
            db,
            session_id,
            "BUDGET_RECONCILED",
            source="BUDGET",
            details={"actual_usd": str(cost), "reserved_usd": str(closed["reserved_usd"]) if closed else None},
        )
    elif s["spend_class"] == "NONE":
        cost = Decimal(0)
    db.execute(
        text(
            "UPDATE lab_session SET status = :st, ended_at = :t, end_reason = :r, metrics = CAST(:m AS jsonb), "
            "reconciled_usd = :c, termination_status = :term, provider_usage_seconds = :u, usage_source = :src, "
            "provider_session_id = coalesce(:psid, provider_session_id), row_version = row_version + 1 WHERE id = :i"
        ),
        {
            "st": status,
            "t": now,
            "r": reason,
            "m": _j(metrics),
            "c": cost,
            "term": termination,
            "u": usage_s,
            "src": source,
            "psid": (provider_outcome or {}).get("provider_session_id"),
            "i": session_id,
        },
    )
    append_event(
        db,
        session_id,
        "SESSION_ENDED",
        details={"reason": reason, "reconciled_usd": str(cost), "termination": termination},
    )
    return s


def resolve_usage(
    db: Session, actor: str, session_id: uuid.UUID, *, usage_seconds: float, source: str, reason: str
) -> dict[str, Any]:
    """A manager settles an UNCONFIRMED GPT-Live session with the provider-reported usage (from the provider's usage
    dashboard, or a sideband close confirmation). The reservation is reconciled; the history keeps both steps."""
    s = _one(db, "SELECT * FROM lab_session WHERE id = :i FOR UPDATE", i=session_id)
    if s is None:
        raise LabError(404, "NOT_FOUND", "Lab session not found")
    if s["termination_status"] != "UNCONFIRMED" or s["status"] not in ("ENDED", "FAILED"):
        raise LabError(409, "NOT_UNCONFIRMED", "Only an ended session with unconfirmed termination can be resolved")
    if usage_seconds < 0 or usage_seconds > 24 * 3600:
        raise LabError(422, "USAGE_INVALID", "Usage seconds are out of range")
    cost = lc.measured_cost(s["rate_card"], 0, 0, session_s=usage_seconds)
    closed = lc.close(db, session_id=session_id, actual=cost, now=_now())
    db.execute(
        text(
            "UPDATE lab_session SET termination_status = 'RESOLVED', provider_usage_seconds = :u, usage_source = :src, "
            "reconciled_usd = :c, row_version = row_version + 1 WHERE id = :i"
        ),
        {"u": usage_seconds, "src": source, "c": cost, "i": session_id},
    )
    append_event(
        db,
        session_id,
        "USAGE_RESOLVED",
        source="BUDGET",
        details={
            "usage_seconds": usage_seconds,
            "usage_source": source,
            "actual_usd": str(cost),
            "resolved_by": actor,
            "reason": reason,
            "overrun": bool(closed and closed["overrun"]),
        },
    )
    return session(db, session_id)


def save_provider_transcripts(db: Session, session_id: uuid.UUID, outcome: dict[str, Any], engine: str) -> None:
    """The provider's own transcripts (not independent evidence), purgeable under the retention policy."""
    for track, parts in (
        ("MIC", outcome.get("input_transcript") or []),
        ("PROVIDER_PLAYBACK", outcome.get("output_transcript") or []),
    ):
        txt = " ".join(p.strip() for p in parts if p and p.strip())
        if not txt:
            continue
        db.execute(
            text(
                "INSERT INTO lab_transcript (id, session_id, track, engine, model_sha256, text, words, audio_sha256, "
                "created_by, source) VALUES (:i, :s, :t, :e, :m, :x, '[]'::jsonb, :h, 'SYSTEM:voicelab', "
                "'PROVIDER_TRANSCRIPT')"
            ),
            {
                "i": uuid.uuid4(),
                "s": session_id,
                "t": track,
                "e": engine,
                "m": "0" * 64,
                "x": txt,
                "h": _sha(txt.encode()),
            },
        )


def purge_expired(
    db: Session, rs: EncryptedObjectStore | None, retention_hours: int, *, now: datetime | None = None
) -> dict[str, int]:
    """Retention (owner decision: the local 168 h policy): delete session audio objects and blank session transcripts
    older than the retention period. Rows, checksums, metrics, events and evaluation history are kept. Synthetic test
    fixtures (golden dataset audio and their transcripts) are test assets, not recordings, and are kept."""
    cutoff = (now or _now()) - timedelta(hours=retention_hours)
    media = _all(db, "SELECT id, object_key FROM lab_media WHERE purged_at IS NULL AND created_at < :c", c=cutoff)
    for m in media:
        if rs is not None:
            rs.delete(m["object_key"])
        db.execute(
            text("UPDATE lab_media SET purged_at = now(), purge_reason = :r WHERE id = :i"),
            {"r": f"retention {retention_hours} h", "i": m["id"]},
        )
    tr = db.execute(
        text(
            "UPDATE lab_transcript SET purged_at = now(), purge_reason = :r, text = '', words = '[]'::jsonb "
            "WHERE purged_at IS NULL AND session_id IS NOT NULL AND created_at < :c RETURNING id"
        ),
        {"r": f"retention {retention_hours} h", "c": cutoff},
    ).all()
    return {"media": len(media), "transcripts": len(tr)}


def abandon_unconnected(db: Session, older_than_s: int = 90) -> list[str]:
    rows = _all(
        db,
        "SELECT id FROM lab_session WHERE status = 'CREATED' AND mode = 'INTERACTIVE' AND created_at < "
        "now() - make_interval(secs => :s)",
        s=older_than_s,
    )
    for r in rows:
        finish_session(db, r["id"], reason="NEVER_CONNECTED", metrics={}, status="ENDED")
    return [str(r["id"]) for r in rows]


def recover(db: Session) -> dict[str, int]:
    """At startup nothing is live: end open sessions and running experiments. Mock sessions reconcile at the reserved
    maximum (conservative); experiments at the trials' measured cost; a GPT-Live session that had connected keeps its
    reservation HELD with termination UNCONFIRMED (the provider session may still have been billed)."""
    n_s = n_e = 0
    for r in _all(db, "SELECT id, provider, status FROM lab_session WHERE status IN ('CREATED', 'LIVE')"):
        if r["provider"] in GPT_PROVIDERS:
            finish_session(
                db,
                r["id"],
                reason="SERVER_RESTART",
                metrics={},
                provider_outcome={"termination": "NOT_STARTED" if r["status"] == "CREATED" else "UNCONFIRMED"},
            )
            n_s += 1
            continue
        held = _one(db, "SELECT reserved_usd FROM lab_reservation WHERE session_id = :i AND status = 'HELD'", i=r["id"])
        if held:
            lc.close(db, session_id=r["id"], actual=held["reserved_usd"], now=_now())
        db.execute(
            text(
                "UPDATE lab_session SET status = 'ENDED', ended_at = now(), end_reason = 'SERVER_RESTART', "
                "row_version = row_version + 1 WHERE id = :i"
            ),
            {"i": r["id"]},
        )
        append_event(db, r["id"], "SESSION_ENDED", details={"reason": "SERVER_RESTART"})
        n_s += 1
    for e in _all(db, "SELECT id FROM lab_experiment WHERE status = 'RUNNING'"):
        _finish_experiment(db, e["id"], "FAILED", "SERVER_RESTART")
        n_e += 1
    db.execute(text("UPDATE lab_session SET transcript_status = 'FAILED' WHERE transcript_status = 'PENDING'"))
    return {"sessions": n_s, "experiments": n_e}


# ---- server-side recording (interactive sessions) ------------------------------------------------------------------
class LabRecorder:
    """Records both directions on the server's clock: microphone frames as received, provider frames as sent (placed
    at their send time; up to ~100 ms sent just before an interruption may not have been played by the browser)."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.mic = bytearray()
        self.out = bytearray()
        self.out_samples = 0

    def _pos(self) -> int:
        return int((time.monotonic() - self.t0) * SAMPLE_RATE) * 2

    def on_mic(self, pcm: bytes) -> None:
        self.mic += pcm

    def on_provider(self, pcm: bytes) -> None:
        pos = max(self._pos(), len(self.out))
        if pos > len(self.out):
            self.out += b"\x00" * (pos - len(self.out))
        self.out += pcm
        self.out_samples += len(pcm) // 2

    def tracks(self) -> dict[str, bytes]:
        n = max(len(self.mic), len(self.out))
        return {
            "MIC": bytes(self.mic) + b"\x00" * (n - len(self.mic)),
            "PROVIDER_PLAYBACK": bytes(self.out) + b"\x00" * (n - len(self.out)),
        }


BASIS = {
    "MIC": "Server-side capture of the microphone audio as received by the server",
    "PROVIDER_PLAYBACK": (
        "Server-side capture of the provider audio SENT to the browser, placed at its send time — not a record of "
        "what the browser played: queued audio cleared by an interruption may be included, and provider audio "
        "dropped after an interruption is excluded (it was never sent)"
    ),
}


def save_recording(db: Session, rs: EncryptedObjectStore, session_id: uuid.UUID, rec: LabRecorder, actor: str) -> None:
    for track, pcm in rec.tracks().items():
        if not pcm:
            continue
        key = obj_key(session_id, track)
        rs.put(key, pcm)
        db.execute(
            text(
                "INSERT INTO lab_media (id, session_id, track, object_key, samples, sha256, basis, created_by) VALUES "
                "(:i, :s, :t, :k, :n, :h, :b, :by)"
            ),
            {
                "i": uuid.uuid4(),
                "s": session_id,
                "t": track,
                "k": key,
                "n": len(pcm) // 2,
                "h": _sha(pcm),
                "b": BASIS[track],
                "by": actor,
            },
        )
    append_event(db, session_id, "RECORDING_SAVED", details={"tracks": list(rec.tracks())})


def audio(db: Session, rs: EncryptedObjectStore | None, session_id: uuid.UUID, track: str) -> bytes | None:
    m = _one(db, "SELECT object_key, sha256 FROM lab_media WHERE session_id = :s AND track = :t", s=session_id, t=track)
    if m is None or rs is None:
        return None
    pcm = rs.get(m["object_key"])
    if pcm is None or _sha(pcm) != m["sha256"]:
        return None
    return pcm


def fixture_audio(db: Session, rs: EncryptedObjectStore | None, revision_id: uuid.UUID) -> bytes | None:
    r = case_revision(db, revision_id)
    if not r["audio_object_key"] or rs is None:
        return None
    pcm = rs.get(r["audio_object_key"])
    if pcm is None or _sha(pcm) != r["audio_sha256"]:
        return None
    return pcm


def transcribe_session(app: Any, session_id: uuid.UUID) -> str:
    """Independent post-session transcript of each recorded track with the local faster-whisper engine (S1-D)."""
    from app.voice import transcript as tr

    sf = app.state.session_factory
    rs = store_for(app)
    try:
        engine = tr.engine_for(app)
    except Exception:  # noqa: BLE001 — a misconfigured engine leaves the transcript unavailable, never a crash
        engine = None
    with sf() as db, db.begin():
        if engine is None:
            db.execute(
                text("UPDATE lab_session SET transcript_status = 'NOT_AVAILABLE' WHERE id = :i"), {"i": session_id}
            )
            return "NOT_AVAILABLE"
        db.execute(text("UPDATE lab_session SET transcript_status = 'PENDING' WHERE id = :i"), {"i": session_id})
    status = "COMPLETED"
    for track in TRACKS:
        with sf() as db:
            pcm = audio(db, rs, session_id, track)
        if pcm is None:
            continue
        try:
            words, txt = _transcribe(engine, pcm)
        except Exception:  # noqa: BLE001
            log.exception("lab transcription failed")
            status = "FAILED"
            continue
        with sf() as db, db.begin():
            db.execute(
                text(
                    "INSERT INTO lab_transcript (id, session_id, track, engine, model_sha256, text, words, "
                    "audio_sha256, created_by) VALUES (:i, :s, :t, :e, :m, :x, CAST(:w AS jsonb), "
                    ":h, 'SYSTEM:voicelab')"
                ),
                {
                    "i": uuid.uuid4(),
                    "s": session_id,
                    "t": track,
                    "e": f"{engine.name} {engine.model_id}",
                    "m": engine.model_sha256,
                    "x": txt,
                    "w": _j(words),
                    "h": _sha(pcm),
                },
            )
    with sf() as db, db.begin():
        db.execute(
            text("UPDATE lab_session SET transcript_status = :st WHERE id = :i"), {"st": status, "i": session_id}
        )
        append_event(db, session_id, "TRANSCRIPT_" + status)
    return status


def _transcribe(engine: Any, pcm: bytes) -> tuple[list[dict[str, Any]], str]:
    res = engine.transcribe(pcm)
    words = [
        {"w": w.text.strip(), "start": round(w.start, 2), "end": round(w.end, 2), "p": round(w.probability, 3)}
        for r in res
        for w in r.words
    ]
    return words, " ".join(r.text.strip() for r in res).strip()


# ---- experiments ---------------------------------------------------------------------------------------------------
def create_experiment(db: Session, actor: str, body: dict[str, Any]) -> dict[str, Any]:
    ds = dataset(db, body["dataset_id"])
    pv = prompt_version(db, body["prompt_version_id"])
    p = _check_provider_config(pv["provider"], pv["model"], pv["voice"])
    current = {str(c["id"]): c for c in ds["cases"] if not c["retired"]}
    chosen = [str(x) for x in body.get("case_revision_ids") or current]
    unknown = [x for x in chosen if x not in current]
    if unknown or not chosen:
        raise LabError(422, "TESTS_INVALID", "Select current, non-retired test cases of this dataset")
    if p.code in GPT_PROVIDERS and p.spend_class != "PAID":
        raise LabError(
            422,
            "EXPERIMENT_PROVIDER_UNSUPPORTED",
            "Experiments run on the keyless mock providers only; "
            "the GPT-Live adapter is used interactively in the Playground",
        )
    if p.spend_class == "PAID":
        raise LabError(
            409,
            "PAID_DISABLED",
            "Refused by Voice Lab cost controls",
            ["PAID_DISABLED: paid batch experiments are not permitted"],
        )
    reps, max_s = int(body["repetitions"]), int(body["max_duration_s"])
    try:
        per = lc.estimate_session(p, max_s)
    except lc.BudgetError as exc:
        raise LabError(exc.status, exc.code, exc.message) from exc
    est = per * len(chosen) * reps
    max_spend = Decimal(str(body["max_spend_usd"]))
    reasons = []
    if est > max_spend:
        reasons.append(
            f"SPEND_LIMIT_BELOW_ESTIMATE: estimated maximum USD {est} exceeds your maximum authorised spend "
            f"USD {max_spend}"
        )
    if p.spend_class == "SIMULATED":
        b = lc.budget(db, "SIMULATED")
        if max_spend > b["per_experiment_usd"]:
            reasons.append(
                f"PER_EXPERIMENT_LIMIT: maximum spend USD {max_spend} exceeds the per-experiment budget "
                f"USD {b['per_experiment_usd']}"
            )
    if lc.control(db)["kill_switch"]:
        reasons.append("KILL_SWITCH: the Voice Lab emergency stop is engaged")
    if reasons:
        raise LabError(409, reasons[0].split(":", 1)[0], "Refused by Voice Lab cost controls", reasons)
    eid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO lab_experiment (id, experiment_ref, name, dataset_id, prompt_version_id, "
            "provider, model, voice, "
            "spend_class, case_revision_ids, repetitions, max_duration_s, max_spend_usd, estimated_max_usd, rate_card, "
            "status, created_by) VALUES (:i, :r, :n, :d, :pv, :p, :m, :v, :c, CAST(:ids AS jsonb), "
            ":rep, :mx, :ms, :est, "
            "CAST(:rc AS jsonb), :st, :by)"
        ),
        {
            "i": eid,
            "r": next_ref(db, "lab_experiment", "experiment_ref", "LAB-E-"),
            "n": body["name"],
            "d": body["dataset_id"],
            "pv": body["prompt_version_id"],
            "p": p.code,
            "m": pv["model"],
            "v": pv["voice"],
            "c": p.spend_class,
            "ids": _j(chosen),
            "rep": reps,
            "mx": max_s,
            "ms": max_spend,
            "est": est,
            "rc": _j(p.rates.as_json()),
            "st": "READY" if est == 0 else "AWAITING_AUTHORISATION",
            "by": actor,
        },
    )
    return experiment(db, eid)


def experiment(db: Session, experiment_id: uuid.UUID, *, trials: bool = True) -> dict[str, Any]:
    e = _one(
        db,
        "SELECT e.*, d.dataset_ref, d.name AS dataset_name, p.prompt_ref, pv.version_no AS prompt_version_no, "
        "r.status AS reservation_status, r.reserved_usd FROM lab_experiment e JOIN lab_dataset d ON "
        "d.id = e.dataset_id "
        "JOIN lab_prompt_version pv ON pv.id = e.prompt_version_id JOIN lab_prompt p ON p.id = pv.prompt_id "
        "LEFT JOIN lab_reservation r ON r.experiment_id = e.id WHERE e.id = :i",
        i=experiment_id,
    )
    if e is None:
        raise LabError(404, "NOT_FOUND", "Experiment not found")
    e["trials"] = (
        _all(
            db,
            "SELECT t.*, r.name AS case_name, r.revision AS case_revision, c.case_ref, r.expected_statement, "
            "r.expected_behaviour, r.audio_object_key IS NOT NULL AS has_audio, s.session_ref FROM lab_trial t "
            "JOIN lab_test_case_revision r ON r.id = t.test_case_revision_id JOIN lab_test_case c ON "
            "c.id = r.test_case_id "
            "LEFT JOIN lab_session s ON s.id = t.session_id WHERE t.experiment_id = :i ORDER BY "
            "c.case_ref, t.repetition",
            i=experiment_id,
        )
        if trials
        else []
    )
    for t in e["trials"]:
        t["speech_result"] = le.speech_result(t["metrics"]) if t["status"] == "COMPLETED" else None
        t["assessments"] = _all(
            db,
            "SELECT result, notes, listened, assessed_by, assessed_at FROM lab_speech_assessment WHERE trial_id = :t "
            "ORDER BY assessed_at DESC",
            t=t["id"],
        )
    return e


def experiments(db: Session) -> list[dict[str, Any]]:
    ids = db.execute(text("SELECT id FROM lab_experiment ORDER BY created_at DESC LIMIT 100")).scalars().all()
    return [experiment(db, i, trials=False) for i in ids]


def authorise(db: Session, actor: str, experiment_id: uuid.UUID, reason: str, confirm_usd: Decimal) -> dict[str, Any]:
    e = _one(db, "SELECT * FROM lab_experiment WHERE id = :i FOR UPDATE", i=experiment_id)
    if e is None:
        raise LabError(404, "NOT_FOUND", "Experiment not found")
    if e["status"] != "AWAITING_AUTHORISATION":
        raise LabError(409, "NOT_AWAITING_AUTHORISATION", f"The experiment is {e['status']}")
    if e["created_by"] == actor:
        raise LabError(403, "SELF_AUTHORISATION", "Spend for an experiment is authorised by a different user")
    if confirm_usd != e["estimated_max_usd"]:
        raise LabError(422, "AMOUNT_MISMATCH", f"Confirm the estimated maximum exactly: USD {e['estimated_max_usd']}")
    db.execute(
        text(
            "UPDATE lab_experiment SET status = 'READY', authorised_by = :by, authorised_at = now(), "
            "authorisation_reason = :r, authorised_usd = :a, row_version = row_version + 1 WHERE id = :i"
        ),
        {"by": actor, "r": reason, "a": e["estimated_max_usd"], "i": experiment_id},
    )
    return experiment(db, experiment_id)


def start_experiment(db: Session, actor: str, experiment_id: uuid.UUID) -> dict[str, Any]:
    e = _one(db, "SELECT * FROM lab_experiment WHERE id = :i FOR UPDATE", i=experiment_id)
    if e is None:
        raise LabError(404, "NOT_FOUND", "Experiment not found")
    if e["created_by"] != actor:  # the author runs it; a manager only authorises spend
        raise LabError(403, "FORBIDDEN", "Only the experiment's author starts it")
    if e["status"] == "AWAITING_AUTHORISATION":
        raise LabError(409, "AUTHORISATION_REQUIRED", "This metered experiment needs explicit spend authorisation")
    if e["status"] != "READY":
        raise LabError(409, "NOT_READY", f"The experiment is {e['status']}; experiments are never re-run automatically")
    p = lc.provider(e["provider"])
    try:
        lc.reserve(
            db,
            p,
            e["estimated_max_usd"],
            actor=actor,
            now=_now(),
            experiment_id=experiment_id,
            basis={
                "estimate": "trials × repetitions × maximum duration × rate card",
                "authorised_usd": str(e["authorised_usd"]) if e["authorised_usd"] is not None else None,
            },
        )
    except lc.BudgetError as exc:
        raise LabError(exc.status, exc.code, exc.message, exc.details) from exc
    db.execute(
        text(
            "UPDATE lab_experiment SET status = 'RUNNING', started_at = now(), row_version = row_version + 1 "
            "WHERE id = :i"
        ),
        {"i": experiment_id},
    )
    return experiment(db, experiment_id)


def _finish_experiment(db: Session, experiment_id: uuid.UUID, status: str, reason: str) -> None:
    trials = _all(db, "SELECT status, verdict, cost_usd FROM lab_trial WHERE experiment_id = :i", i=experiment_id)
    actual = sum((t["cost_usd"] for t in trials), Decimal(0))
    e = _one(db, "SELECT spend_class FROM lab_experiment WHERE id = :i", i=experiment_id)
    assert e is not None
    if e["spend_class"] == "SIMULATED":
        lc.close(db, experiment_id=experiment_id, actual=actual, now=_now())
    summary = {
        "trials": len(trials),
        "completed": sum(t["status"] == "COMPLETED" for t in trials),
        "failed": sum(t["status"] == "FAILED" for t in trials),
        "cancelled": sum(t["status"] == "CANCELLED" for t in trials),
        "verdicts": {
            v: sum(t["verdict"] == v for t in trials) for v in ("PASS", "FAIL", "NEEDS_HUMAN_REVIEW", "NOT_EVALUATED")
        },
    }
    db.execute(
        text(
            "UPDATE lab_experiment SET status = :st, finished_at = now(), actual_usd = :a, summary = "
            "CAST(:s AS jsonb), "
            "end_reason = :r, row_version = row_version + 1 WHERE id = :i"
        ),
        {"st": status, "a": actual, "s": _j(summary), "r": reason, "i": experiment_id},
    )


def mock_extract(expected: dict[str, Any], response: str) -> dict[str, Any]:
    """The mock provider's deterministic extraction from the synthetic customer response (keyword rules, labelled
    ``MOCK_KEYWORD_EXTRACTION/1``): yes / no words, the first number, or the expected label when it is present."""
    words = set(re.findall(r"[a-z']+", response.lower()))
    out: dict[str, Any] = {}
    for k, want in expected.items():
        w = str(want).upper()
        if w in ("YES", "NO"):
            yes = bool(words & {"yes", "yeah", "correct", "agree", "ok", "okay", "sure"})
            no = bool(words & {"no", "not", "don't", "disagree", "nope"})
            out[k] = "YES" if yes and not no else ("NO" if no and not yes else None)
        elif re.fullmatch(r"-?\d+(\.\d+)?", w):
            m = re.search(r"-?\d+(\.\d+)?", response)
            out[k] = m.group(0) if m else None
        else:
            out[k] = want if str(want).lower() in response.lower() else None
    return out


class _TimingChannel:
    """In-memory channel driving the real mock provider: silence, then a synthetic loud onset (barge-in)."""

    def __init__(self, interrupt_at_ms: int, stop_at_ms: int) -> None:
        self.t0 = time.monotonic()
        self.first_audio_ms: int | None = None
        self.onset_ms: int | None = None
        self.clear_ms: int | None = None
        self.frames_out = 0
        self.interrupt_at, self.stop_at = interrupt_at_ms, stop_at_ms
        self.n = 0
        loud = array("h", (int(9000 * ((i // 8) % 2 * 2 - 1)) for i in range(FRAME_BYTES // 2)))
        self.loud, self.quiet = loud.tobytes(), b"\x00" * FRAME_BYTES

    def _ms(self) -> int:
        return int((time.monotonic() - self.t0) * 1000)

    async def receive(self) -> Inbound | None:
        await asyncio.sleep(FRAME_MS / 1000)
        self.n += 1
        t = self.n * FRAME_MS
        if t >= self.stop_at or (self.clear_ms is not None and t >= self.interrupt_at + 400):
            return Inbound(event={"type": "session.stop", "reason": "TRIAL_COMPLETE"})
        if t >= self.interrupt_at:
            if self.onset_ms is None:
                self.onset_ms = self._ms()
            return Inbound(audio=self.loud)
        return Inbound(audio=self.quiet)

    async def send_audio(self, response: int, pcm: bytes) -> None:
        if self.first_audio_ms is None:
            self.first_audio_ms = self._ms()
        self.frames_out += 1

    async def send_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "playback.clear" and self.clear_ms is None:
            self.clear_ms = self._ms()


def mock_timing(max_duration_s: int, interrupt_at_ms: int = 600) -> dict[str, Any]:
    ch = _TimingChannel(interrupt_at_ms, min(max_duration_s * 1000, interrupt_at_ms + 1500))
    stats = SessionStats()
    asyncio.run(MockVoiceProvider().run(ch, stats))
    return {
        "first_audio_ms": ch.first_audio_ms,
        "interruption_ms": (ch.clear_ms - ch.onset_ms) if ch.clear_ms is not None and ch.onset_ms is not None else None,
        "timing_duration_ms": ch._ms(),
        "barge_ins": stats.barge_ins,
        "input_audio_s": round(ch.n * FRAME_MS / 1000, 3),
    }


def _heard(app: Any, db: Session, rs: EncryptedObjectStore | None, rev: dict[str, Any]) -> tuple[str | None, str]:
    """Independent transcript of the case's audio fixture (cached per revision: the fixture never changes)."""
    if not rev["audio_object_key"]:
        return None, "NO_AUDIO_FIXTURE"
    cached = _one(db, "SELECT text FROM lab_transcript WHERE test_case_revision_id = :r", r=rev["id"])
    if cached:
        return cached["text"], "CACHED"
    from app.voice import transcript as tr

    engine = tr.engine_for(app)
    if engine is None:
        return None, "ENGINE_NOT_CONFIGURED"
    pcm = fixture_audio(db, rs, rev["id"])
    if pcm is None:
        raise LabError(500, "AUDIO_MISSING", "The audio fixture is missing or fails its checksum")
    words, txt = _transcribe(engine, pcm)
    db.execute(
        text(
            "INSERT INTO lab_transcript (id, test_case_revision_id, track, engine, model_sha256, text, words, "
            "audio_sha256, created_by) VALUES (:i, :r, 'PROVIDER_PLAYBACK', :e, :m, :x, CAST(:w AS jsonb), :h, "
            "'SYSTEM:voicelab')"
        ),
        {
            "i": uuid.uuid4(),
            "r": rev["id"],
            "e": f"{engine.name} {engine.model_id}",
            "m": engine.model_sha256,
            "x": txt,
            "w": _j(words),
            "h": rev["audio_sha256"],
        },
    )
    return txt, "TRANSCRIBED"


def run_trial(app: Any, e: dict[str, Any], rev: dict[str, Any], rep: int) -> dict[str, Any]:
    started = _now()
    t0 = time.monotonic()
    rs = store_for(app)
    timing = mock_timing(e["max_duration_s"])
    said = rev["mock_output"] if rev["mock_output"] is not None else rev["expected_statement"]
    with app.state.session_factory() as db, db.begin():
        heard, heard_basis = _heard(app, db, rs, rev)
    out_s = round(rev["audio_samples"] / SAMPLE_RATE, 3) if rev["audio_samples"] else round(len(said.split()) / 2.5, 3)
    extracted = mock_extract(rev["expected_answer"], rev["customer_response"]) if rev["expected_answer"] else None
    attributions = le.attribute(rev["expected_statement"], said, heard)
    metrics: dict[str, Any] = {
        "said": le.wording(rev["expected_statement"], said),
        "heard": le.wording(rev["expected_statement"], heard),
        "heard_basis": heard_basis,
        "attributions": attributions,
        "needs_listening": any(
            a["attribution"] in ("SUSPECTED_TRANSCRIPTION_ERROR", "UNATTRIBUTED") for a in attributions
        ),
        "answer": le.answer_accuracy(rev["expected_answer"], extracted),
        "first_audio_ms": timing["first_audio_ms"],
        "interruption_ms": timing["interruption_ms"],
        "output_audio_s": out_s,
        "output_audio_basis": "AUDIO_FIXTURE" if rev["audio_samples"] else "ESTIMATED_FROM_TEXT (2.5 words/s)",
        "input_audio_s": timing["input_audio_s"],
        "timing_basis": TIMING_BASIS,
        "content_basis": CONTENT_BASIS,
        "extraction": EXTRACTION,
        "evaluator": le.VERSION,
        "behaviour": "HUMAN_ASSESSMENT_REQUIRED" if rev["expected_behaviour"] else None,
    }
    metrics["session_duration_ms"] = int((time.monotonic() - t0) * 1000)
    verdict, checks = le.check(rev["criteria"], metrics)
    cost = (
        lc.measured_cost(e["rate_card"], timing["input_audio_s"], out_s)
        if e["spend_class"] == "SIMULATED"
        else (Decimal(0))
    )
    return {
        "started": started,
        "said": said,
        "heard": heard,
        "extracted": extracted,
        "metrics": metrics,
        "verdict": verdict,
        "checks": checks,
        "cost": cost,
    }


def execute(app: Any, experiment_id: uuid.UUID) -> str:
    """Run every trial once, sequentially (no automatic retries). The kill switch and the reservation are checked
    before each trial; a failed trial is recorded as FAILED and the experiment continues."""
    sf = app.state.session_factory
    with sf() as db:
        e = experiment(db, experiment_id, trials=False)
        revs = [case_revision(db, uuid.UUID(r)) for r in e["case_revision_ids"]]
    per_trial_max = lc.estimate_session(lc.provider(e["provider"]), e["max_duration_s"])
    spent = Decimal(0)
    outcome, reason = "COMPLETED", "ALL_TRIALS_RUN"
    for rev in revs:
        for rep in range(1, e["repetitions"] + 1):
            with sf() as db:
                killed = lc.control(db)["kill_switch"]
            stop = (
                "KILL_SWITCH"
                if killed
                else (
                    "BUDGET_EXHAUSTED"
                    if e["reserved_usd"] is not None and spent + per_trial_max > e["reserved_usd"]
                    else None
                )
            )
            if stop or outcome == "CANCELLED":
                outcome, reason = "CANCELLED", reason if outcome == "CANCELLED" else str(stop)
                _insert_trial(sf, e, rev, rep, None, status="CANCELLED", failure=f"Not run: {reason}")
                continue
            try:
                res = run_trial(app, e, rev, rep)
            except Exception as exc:  # noqa: BLE001 — recorded as an execution failure, never retried
                log.exception("lab trial failed")
                _insert_trial(sf, e, rev, rep, None, status="FAILED", failure=f"{type(exc).__name__}: {exc}"[:300])
                continue
            spent += res["cost"]
            _insert_trial(sf, e, rev, rep, res, status="COMPLETED")
    with sf() as db, db.begin():
        _finish_experiment(db, experiment_id, outcome, reason)
    return outcome


def _insert_trial(
    sf: Any,
    e: dict[str, Any],
    rev: dict[str, Any],
    rep: int,
    res: dict[str, Any] | None,
    *,
    status: str,
    failure: str | None = None,
) -> None:
    now = _now()
    with sf() as db, db.begin():
        sid = None
        if res is not None:
            sid = uuid.uuid4()
            db.execute(
                text(
                    "INSERT INTO lab_session (id, session_ref, mode, prompt_version_id, "
                    "experiment_id, provider, model, "
                    "voice, spend_class, rate_card, status, record, max_duration_s, idle_timeout_s, estimated_max_usd, "
                    "reconciled_usd, started_at, ended_at, end_reason, metrics, transcript_status, created_by) VALUES "
                    "(:i, :r, 'EXPERIMENT', :pv, :e, :p, :m, :v, :c, CAST(:rc AS jsonb), 'ENDED', false, :mx, 0, :est, "
                    ":cost, :st, :t, 'TRIAL_COMPLETE', CAST(:mt AS jsonb), :ts, :by)"
                ),
                {
                    "i": sid,
                    "r": next_ref(db, "lab_session", "session_ref", "LAB-S-", 5),
                    "pv": e["prompt_version_id"],
                    "e": e["id"],
                    "p": e["provider"],
                    "m": e["model"],
                    "v": e["voice"],
                    "c": e["spend_class"],
                    "rc": _j(e["rate_card"]),
                    "mx": e["max_duration_s"],
                    "est": lc.estimate_session(lc.provider(e["provider"]), e["max_duration_s"]),
                    "cost": res["cost"],
                    "st": res["started"],
                    "t": now,
                    "mt": _j(
                        {
                            k: res["metrics"][k]
                            for k in (
                                "first_audio_ms",
                                "interruption_ms",
                                "output_audio_s",
                                "input_audio_s",
                                "session_duration_ms",
                            )
                        }
                    ),
                    "ts": "COMPLETED" if res["heard"] is not None else "NOT_AVAILABLE",
                    "by": e["created_by"],
                },
            )
            append_event(
                db,
                sid,
                "TRIAL_RUN",
                source="PROVIDER",
                details={
                    "case": rev["case_ref"],
                    "revision": rev["revision"],
                    "repetition": rep,
                    "first_audio_ms": res["metrics"]["first_audio_ms"],
                    "interruption_ms": res["metrics"]["interruption_ms"],
                    "cost_usd": str(res["cost"]),
                },
            )
        db.execute(
            text(
                "INSERT INTO lab_trial (id, experiment_id, test_case_revision_id, session_id, "
                "repetition, status, verdict, "
                "provider_text, heard_text, extracted_answer, metrics, checks, failure, cost_usd, started_at, "
                "finished_at, created_by) VALUES (:i, :e, :r, :s, :rep, :st, :v, :pt, :ht, CAST(:ea AS jsonb), "
                "CAST(:m AS jsonb), CAST(:c AS jsonb), :f, :cost, :sa, :fa, :by)"
            ),
            {
                "i": uuid.uuid4(),
                "e": e["id"],
                "r": rev["id"],
                "s": sid,
                "rep": rep,
                "st": status,
                "v": res["verdict"] if res else "NOT_EVALUATED",
                "pt": res["said"] if res else None,
                "ht": res["heard"] if res else None,
                "ea": _j(res["extracted"]) if res and res["extracted"] else None,
                "m": _j(res["metrics"] if res else {}),
                "c": _j(res["checks"] if res else []),
                "f": failure,
                "cost": res["cost"] if res else Decimal(0),
                "sa": res["started"] if res else now,
                "fa": now,
                "by": e["created_by"],
            },
        )


def start_background(app: Any, experiment_id: uuid.UUID) -> None:
    if getattr(app.state, "voicelab_inline", False):
        execute(app, experiment_id)
        return
    threading.Thread(target=_safe_execute, args=(app, experiment_id), daemon=True, name="voicelab-experiment").start()


def _safe_execute(app: Any, experiment_id: uuid.UUID) -> None:
    try:
        execute(app, experiment_id)
    except Exception:  # noqa: BLE001
        log.exception("lab experiment failed")
        with contextlib.suppress(Exception), app.state.session_factory() as db, db.begin():
            _finish_experiment(db, experiment_id, "FAILED", "EXECUTION_ERROR")


def mock_message() -> list[str]:
    return list(FIXED_MESSAGE)


# ---- human speech assessment (S1-E.2) -------------------------------------------------------------------------------
def assess_trial(
    db: Session, actor: str, trial_id: uuid.UUID, result: str, notes: str, listened: bool
) -> dict[str, Any]:
    if result not in le.HUMAN_RESULTS:
        raise LabError(422, "RESULT_INVALID", "Unknown assessment result")
    if not listened:
        raise LabError(422, "LISTENING_REQUIRED", "A human speech result needs the audio to have been listened to")
    t = _one(
        db,
        "SELECT t.id, r.audio_object_key FROM lab_trial t JOIN lab_test_case_revision r ON r.id = "
        "t.test_case_revision_id WHERE t.id = :i",
        i=trial_id,
    )
    if t is None:
        raise LabError(404, "NOT_FOUND", "Trial not found")
    if t["audio_object_key"] is None:
        raise LabError(409, "NO_AUDIO", "This trial has no audio to listen to; it stays insufficient audio evidence")
    aid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO lab_speech_assessment (id, trial_id, result, notes, listened, assessed_by) VALUES (:i, :t, "
            ":r, :n, :l, :by)"
        ),
        {"i": aid, "t": trial_id, "r": result, "n": notes, "l": listened, "by": actor},
    )
    return _one(db, "SELECT * FROM lab_speech_assessment WHERE id = :i", i=aid) or {}
