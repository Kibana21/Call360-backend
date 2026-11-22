# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""SS-03B — simulations and call plans of PUBLISHED survey versions, stored apart from everything operational.

The run of a simulation is never stored as a thing that could drift: only the immutable inputs are, in order, and the
run is the deterministic replay of them through ``execution.execute_inputs`` on the version's own pinned documents. A
simulation can therefore always be reproduced exactly, and replaying the same inputs proves it.

Nothing here reads or writes a callback case, contact attempt, conversation session, operational survey run,
recording, transcript or finding, and nothing here can start, authorise or schedule a call.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey import store
from app.domain.survey.callplan import SCHEMA as PLAN_CONTRACT
from app.domain.survey.callplan import assemble
from app.domain.survey.canonical import CanonicalError, sha256_hex
from app.domain.survey.documents import Bundle
from app.domain.survey.execution import CONTRACT, execute_inputs
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

RECORD_CLASS = "SIMULATION"
NOTE = (
    "SIMULATION ONLY. Synthetic facts and unapproved wording. Not operational evidence, and not an authorisation or "
    "eligibility for any customer call."
)
ANSWER_KEYS = ("choice", "choices", "text", "other_text", "number", "acknowledged")
MAX_FACTS, MAX_INPUTS, MAX_TEXT = 60, 400, 4000


def _version(db: Session, vid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    """A PUBLISHED version in the caller's markets, whose manifest still matches every document it pins."""
    v = store.version(db, vid, markets)
    if store.status_of(db, v["id"]) not in store.PUBLISHED_VERSION_EVENTS:
        raise SurveyError(409, "VERSION_NOT_PUBLISHED", "Only a published survey version can be simulated")
    cand = store.candidate(db, v["candidate_id"], markets)
    problems = store.manifest_problems(db, cand)
    if problems:
        # never execute documents that are not the ones the version pinned
        raise SurveyError(
            409,
            "MANIFEST_MISMATCH",
            "The version does not match the documents it pins",
            [{"problem": p} for p in problems],
        )
    return v


def version_bundle(db: Session, v: Mapping[str, Any]) -> Bundle:
    """The version's own pinned documents and the governed catalogs — what is executed, and nothing newer."""
    return store.load_bundle(db, v["content"])


def check_facts(bundle: Bundle, facts: Any) -> dict[str, Any]:
    """A fact snapshot is a flat object of catalog fields with scalar values. Nothing is coerced, defaulted or added."""
    if not isinstance(facts, Mapping) or len(facts) > MAX_FACTS:
        raise SurveyError(422, "FACTS_INVALID", f"Facts are one object of at most {MAX_FACTS} fields")
    unknown = sorted(k for k in facts if k not in bundle.fields)
    if unknown:
        raise SurveyError(
            422,
            "FACT_UNKNOWN",
            "A fact names a field the governed catalog does not have",
            [{"field": k} for k in unknown],
        )
    for k, v in facts.items():
        if not (v is None or isinstance(v, str | int | float | bool)) or (isinstance(v, str) and len(v) > MAX_TEXT):
            raise SurveyError(422, "FACTS_INVALID", f"The value of {k} is not text, a number, yes/no or empty")
    out = dict(facts)
    try:
        sha256_hex(out)
    except CanonicalError as exc:
        raise SurveyError(422, "FACTS_INVALID", "A fact value cannot be recorded exactly") from exc
    return out


def check_answer(answer: Any) -> dict[str, Any]:
    """A typed input: only the answer fields of the contract. An unknown field is refused, never ignored."""
    if not isinstance(answer, Mapping):
        raise SurveyError(422, "ANSWER_INVALID", "An answer is an object")
    extra = sorted(k for k in answer if k not in ANSWER_KEYS)
    if extra:
        raise SurveyError(
            422, "ANSWER_INVALID", "An answer has a field the contract does not define", [{"field": k} for k in extra]
        )
    a = dict(answer)
    # Only the SHAPE is checked here: a value is a scalar (or, for `choices`, a list of scalars) of a recordable size.
    # Whether it is a valid answer to the question is decided by the engine alone, which records a refusal with its
    # stable code — "abc" offered as a number is a rejected answer, not a malformed request.

    def scalar(v: Any) -> bool:
        return v is None or (isinstance(v, str | int | float | bool) and (not isinstance(v, str) or len(v) <= MAX_TEXT))

    bad = any(
        not (isinstance(v, list) and len(v) <= 200 and all(scalar(c) and c is not None for c in v)) if k == "choices" and v is not None else not scalar(v)
        for k, v in a.items()
    )  # fmt: skip
    if bad:
        raise SurveyError(422, "ANSWER_INVALID", "An answer field has the wrong shape")
    try:
        sha256_hex(a)
    except CanonicalError as exc:
        raise SurveyError(422, "ANSWER_INVALID", "An answer value cannot be recorded exactly") from exc
    return a


def _run_sha(run: Mapping[str, Any]) -> str:
    return sha256_hex(json.loads(json.dumps(run, default=str)))


# --------------------------------------------------------------------------------------------------- simulations
def create(
    db: Session, vid: uuid.UUID, markets: Sequence[str], facts: Any, label: str, actor: Actor, meta: RequestMeta | None = None
) -> uuid.UUID:  # fmt: skip
    v = _version(db, vid, markets)
    bundle = version_bundle(db, v)
    clean = check_facts(bundle, facts)
    sim = uuid.uuid4()
    # the run before any input is fingerprinted too, so a simulation that never took an input can still detect drift.
    # The facts are read back through JSON exactly as they will be on every later replay.
    initial = _run_sha(execute_inputs(bundle, json.loads(json.dumps(clean)), []))
    db.execute(
        text(
            "INSERT INTO survey_simulation (id, survey_version_id, survey_definition_id, content_sha256, manifest_sha256, "
            "facts, facts_sha256, engine_contract, initial_run_sha256, label, created_by) "
            "VALUES (:i, :v, :d, :c, :m, CAST(:f AS jsonb), :fh, :ec, :ir, :l, :by)"
        ),
        {
            "i": sim, "v": v["id"], "d": v["survey_definition_id"], "c": v["content_sha256"], "m": v["manifest_sha256"],
            "f": json.dumps(clean), "fh": sha256_hex(clean), "ec": CONTRACT, "ir": initial, "l": label.strip()[:160],
            "by": _ref(actor),
        },
    )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.SIMULATION_CREATED", "survey_simulation", sim,
        {"record_class": RECORD_CLASS, "version": str(v["id"]), "facts_sha256": sha256_hex(clean), "engine_contract": CONTRACT},
    )  # fmt: skip
    return sim


def _row(db: Session, sim: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT s.*, d.market_code, d.code AS survey_code, d.name AS survey_name, v.label AS version_label, "
        "v.candidate_id FROM survey_simulation s JOIN survey_definition d ON d.id = s.survey_definition_id "
        "JOIN survey_version v ON v.id = s.survey_version_id WHERE s.id = :i AND d.market_code = ANY(:m)"
        + (" FOR UPDATE OF s" if lock else ""),
        i=sim, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Simulation not found or not available to you")
    return row


def _inputs(db: Session, sim: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT seq, item_key, answer, accepted, rejection_code, run_status, run_sha256, created_at "
        "FROM survey_simulation_input WHERE simulation_id = :s ORDER BY seq",
        s=sim,
    )


def _replay(
    db: Session, row: Mapping[str, Any], inputs: Sequence[Mapping[str, Any]], markets: Sequence[str]
) -> dict[str, Any]:
    v = _version(db, row["survey_version_id"], markets)
    if (v["content_sha256"], v["manifest_sha256"]) != (row["content_sha256"], row["manifest_sha256"]):
        raise SurveyError(409, "MANIFEST_MISMATCH", "The version is not the one this simulation was created for")
    return execute_inputs(
        version_bundle(db, v), row["facts"], [{"key": i["item_key"], "answer": i["answer"]} for i in inputs]
    )


def state(db: Session, sim: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    """The simulation as it stands: replayed, now, from its recorded inputs."""
    row = _row(db, sim, markets)
    inputs = _inputs(db, sim)
    run = _replay(db, row, inputs, markets)
    return _view(row, inputs, run)


def drift_of(
    row: Mapping[str, Any], inputs: Sequence[Mapping[str, Any]], run: Mapping[str, Any]
) -> dict[str, Any] | None:
    """None when the recomputed run is exactly the one recorded. Otherwise what differs: the simulation was recorded
    under one execution contract or engine behaviour and recomputes differently now. Reported, never hidden."""
    recorded = inputs[-1]["run_sha256"] if inputs else row["initial_run_sha256"]
    recomputed = _run_sha(run)
    contract_changed = row["engine_contract"] != CONTRACT
    if recorded == recomputed and not contract_changed:
        return None
    return {
        "code": "REPLAY_DRIFT",
        "recorded_engine_contract": row["engine_contract"], "current_engine_contract": CONTRACT,
        "recorded_run_sha256": recorded, "recomputed_run_sha256": recomputed,
        "result_differs": recorded != recomputed, "after_inputs": len(inputs),
    }  # fmt: skip


def _view(row: Mapping[str, Any], inputs: Sequence[Mapping[str, Any]], run: Mapping[str, Any]) -> dict[str, Any]:
    drift = drift_of(row, inputs, run)
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": NOTE,
        "survey_id": row["survey_definition_id"], "survey_code": row["survey_code"], "survey_name": row["survey_name"],
        "version_id": row["survey_version_id"], "version_label": row["version_label"],
        "content_sha256": row["content_sha256"], "manifest_sha256": row["manifest_sha256"],
        "facts": row["facts"], "facts_sha256": row["facts_sha256"], "label": row["label"], "created_at": row["created_at"],
        "engine_contract": row["engine_contract"], "current_engine_contract": CONTRACT,
        "initial_run_sha256": row["initial_run_sha256"],
        "inputs": [
            {
                "seq": i["seq"], "key": i["item_key"], "answer": i["answer"], "accepted": i["accepted"],
                "rejection_code": i["rejection_code"], "run_status": i["run_status"], "run_sha256": i["run_sha256"],
            }
            for i in inputs
        ],
        # the run shown is the one recomputed NOW. If it is not the one recorded, `drift` says so and `status` of the
        # simulation is REPLAY_DRIFT: a historical simulation never silently appears unchanged.
        "status": "REPLAY_DRIFT" if drift else run["status"], "run_status": run["status"],
        "run": run, "run_sha256": _run_sha(run), "replay_consistent": drift is None, "drift": drift,
    }  # fmt: skip


def advance(
    db: Session, sim: uuid.UUID, markets: Sequence[str], expected_inputs: int, key: str, answer: Any, actor: Actor,
    meta: RequestMeta | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Give ONE typed input to the question that is current. An input for any other question, or to a run that has
    ended, is refused and nothing is recorded. An answer the engine rejects IS recorded — as refused, with its stable
    code — and the same question stays current."""
    row = _row(db, sim, markets, lock=True)
    inputs = _inputs(db, sim)
    if len(inputs) != expected_inputs:
        raise SurveyError(
            409, "STALE_SIMULATION", f"The simulation has {len(inputs)} inputs; this one was given against {expected_inputs}",
            [{"current_inputs": len(inputs), "expected_inputs": expected_inputs}],
        )  # fmt: skip
    if len(inputs) >= MAX_INPUTS:
        raise SurveyError(409, "SIMULATION_FULL", f"A simulation holds at most {MAX_INPUTS} inputs")
    before = _replay(db, row, inputs, markets)
    drift = drift_of(row, inputs, before)
    if drift:
        # what was recorded is no longer what the engine computes: nothing is appended to a history that has moved
        raise SurveyError(
            409, "REPLAY_DRIFT", "This simulation no longer recomputes to its recorded result; start a new one", [drift]
        )
    if before["status"] == "TERMINAL":
        raise SurveyError(409, "SIMULATION_ENDED", "This simulation has ended; start another to try something else")
    current = (before["pending"] or {}).get("key")
    if key != current:
        raise SurveyError(
            409,
            "INPUT_NOT_CURRENT",
            "That is not the question the simulation is waiting for",
            [{"current": current, "given": key}],
        )
    clean = check_answer(answer)
    seq = len(inputs) + 1
    after = execute_inputs(
        version_bundle(db, _version(db, row["survey_version_id"], markets)), row["facts"],
        [*({"key": i["item_key"], "answer": i["answer"]} for i in inputs), {"key": key, "answer": clean}],
    )  # fmt: skip
    rejection = next((e["code"] for e in reversed(after["events"]) if e["kind"] == "REJECT" and e["key"] == key), None)
    accepted = key in after["asked"]
    db.execute(
        text(
            "INSERT INTO survey_simulation_input (id, simulation_id, seq, item_key, answer, accepted, rejection_code, "
            "run_status, run_sha256, created_by) VALUES (:i, :s, :n, :k, CAST(:a AS jsonb), :ok, :code, :st, :h, :by)"
        ),
        {
            "i": uuid.uuid4(), "s": sim, "n": seq, "k": key, "a": json.dumps(clean), "ok": accepted,
            "code": None if accepted else (rejection or "REJECTED"), "st": after["status"], "h": _run_sha(after), "by": _ref(actor),
        },
    )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.SIMULATION_INPUT", "survey_simulation", sim,
        {"record_class": RECORD_CLASS, "seq": seq, "key": key, "accepted": accepted, "status": after["status"]},
    )  # fmt: skip
    return _view(row, _inputs(db, sim), after)


# ----------------------------------------------------------------------------------------------------- call plans
def create_plan(
    db: Session, vid: uuid.UUID, markets: Sequence[str], facts: Any, actor: Actor, meta: RequestMeta | None = None
) -> uuid.UUID:
    v = _version(db, vid, markets)
    bundle = version_bundle(db, v)
    clean = check_facts(bundle, facts)
    plan = assemble(bundle, clean)
    pid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_call_plan (id, survey_version_id, survey_definition_id, content_sha256, manifest_sha256, "
            "facts, facts_sha256, plan, plan_status, plan_contract, fingerprint, created_by) VALUES (:i, :v, :d, :c, :m, "
            "CAST(:f AS jsonb), :fh, CAST(:p AS jsonb), :st, :pc, :fp, :by)"
        ),
        {
            "i": pid, "v": v["id"], "d": v["survey_definition_id"], "c": v["content_sha256"], "m": v["manifest_sha256"],
            "f": json.dumps(clean), "fh": sha256_hex(clean), "p": json.dumps(plan), "st": plan["status"],
            "pc": PLAN_CONTRACT, "fp": plan["fingerprint"], "by": _ref(actor),
        },
    )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.CALL_PLAN_GENERATED", "survey_call_plan", pid,
        {"record_class": RECORD_CLASS, "version": str(v["id"]), "status": plan["status"], "fingerprint": plan["fingerprint"]},
    )  # fmt: skip
    return pid


def plan(db: Session, pid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT p.*, d.code AS survey_code, d.name AS survey_name, v.label AS version_label FROM survey_call_plan p "
        "JOIN survey_definition d ON d.id = p.survey_definition_id JOIN survey_version v ON v.id = p.survey_version_id "
        "WHERE p.id = :i AND d.market_code = ANY(:m)",
        i=pid, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Call plan not found or not available to you")
    # the stored plan is the record; it is also assembled again now, and a difference is reported, never hidden
    v = _version(db, row["survey_version_id"], markets)
    recomputed = assemble(version_bundle(db, v), row["facts"])["fingerprint"]
    return {
        "plan_contract": row["plan_contract"], "current_plan_contract": PLAN_CONTRACT,
        "recomputed_fingerprint": recomputed,
        "recompute_consistent": recomputed == row["fingerprint"] and row["plan_contract"] == PLAN_CONTRACT,
        "id": row["id"], "record_class": RECORD_CLASS, "note": NOTE,
        "survey_id": row["survey_definition_id"], "survey_code": row["survey_code"], "survey_name": row["survey_name"],
        "version_id": row["survey_version_id"], "version_label": row["version_label"],
        "content_sha256": row["content_sha256"], "manifest_sha256": row["manifest_sha256"],
        "facts": row["facts"], "facts_sha256": row["facts_sha256"], "created_at": row["created_at"],
        "status": row["plan_status"], "fingerprint": row["fingerprint"], "plan": row["plan"],
        # the stored plan still hashes to its recorded fingerprint
        "fingerprint_verified": sha256_hex({k: v for k, v in row["plan"].items() if k != "fingerprint"}) == row["fingerprint"],
    }  # fmt: skip
