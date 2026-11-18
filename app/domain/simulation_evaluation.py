"""S3-A: answer evaluation of interactive simulation runs (insert-only ``simulation_answer_evaluation`` evidence).

Inputs are immutable and pinned: the run's recorded controller events (the exact prefix evaluated, by count and
SHA-256), the run's plan (applicability decided at start), the exact script content (the draft's content snapshot for a
version test, the published manifest otherwise) and the run's policy fact snapshot (id + SHA-256) — never the mutable
current policy record. The engine is pure, so the same inputs reproduce the same results; ``replay`` re-derives them
from the stored inputs and reports whether they still agree. Writes only simulation records.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import question_controller as qc
from app.domain import script_authoring
from app.domain import script_simulation as ss
from app.domain.digest import sha256_of


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def content_for(db: Session, run: Mapping[str, Any]) -> tuple[str, dict[str, Any], str]:
    """(content checksum, content, source). A version test uses its snapshot, never the draft's live rows."""
    if run.get("content_sha256"):
        r = _one(db, "SELECT content FROM simulation_content_snapshot WHERE sha256 = :s", s=run["content_sha256"])
        assert r is not None
        return str(run["content_sha256"]), dict(r["content"]), "CONTENT_SNAPSHOT"
    v = _one(
        db,
        "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "WHERE v.id = :v",
        v=run["script_version_id"],
    )
    assert v is not None
    c = script_authoring.content_of(db, v)  # published: the frozen manifest (immutable)
    return sha256_of(c), c, "PUBLISHED_MANIFEST"


def _facts(db: Session, run: Mapping[str, Any]) -> tuple[ae.FactSource, dict[str, Any]]:
    snap = _one(
        db, "SELECT id, sha256, facts FROM policy_fact_snapshot WHERE id = :s", s=run["policy_fact_snapshot_id"]
    )
    assert snap is not None
    return ae.FactSource("POLICY_FACT_SNAPSHOT", str(snap["id"]), snap["sha256"], dict(snap["facts"] or {})), snap


def evaluate_controller(
    db: Session, run: Mapping[str, Any], ctrl: qc.Controller
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sha, content, src = content_for(db, run)
    facts, snap = _facts(db, run)
    results = ae.evaluate(content, ctrl, facts)
    return results, {"content_sha256": sha, "content_source": src, "fact_source": facts.as_dict(), "snapshot": snap}


def _inputs(run: Mapping[str, Any], events: Sequence[Mapping[str, Any]], meta: Mapping[str, Any]) -> dict[str, Any]:
    evs = [{k: e[k] for k in ("seq", "event_type", "question_code", "action_id", "data")} for e in events]
    events_sha = sha256_of(evs)
    return {
        "events_sha256": events_sha,
        "input_sha256": sha256_of(
            {
                "engine": ae.ENGINE,
                "plan_sha256": run["plan_sha256"],
                "content_sha256": meta["content_sha256"],
                "events_sha256": events_sha,
                "policy_fact_snapshot_sha256": meta["fact_source"]["sha256"],
            }
        ),
    }


def evaluate_run(db: Session, run_id: uuid.UUID, markets: Sequence[str], actor: str) -> tuple[dict[str, Any], bool]:
    """Evaluate the run's answers as recorded now. Returns (record, created); identical inputs reuse the record."""
    run = ss.run_row(db, run_id, markets, lock=True)
    ctrl, rows = ss.controller_for(db, run)
    if not ctrl.started:
        raise ss.SimulationError(409, "NOT_STARTED", "The simulation has not started")
    results, meta = evaluate_controller(db, run, ctrl)
    inp = _inputs(run, rows, meta)
    prior = _one(
        db,
        "SELECT id FROM simulation_answer_evaluation WHERE run_id = :r AND input_sha256 = :i",
        r=run_id,
        i=inp["input_sha256"],
    )
    if prior:
        return get(db, prior["id"], markets), False
    eid = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM simulation_answer_evaluation")).scalar_one()
    st = ctrl.state()["status"]
    db.execute(
        text(
            "INSERT INTO simulation_answer_evaluation (id, evaluation_ref, market_code, run_id, events_evaluated, "
            "events_sha256, script_version_id, content_sha256, content_source, policy_fact_snapshot_id, "
            "policy_fact_snapshot_sha256, engine_version, input_sha256, controller_status, controller_outcome, "
            "results, "
            "totals, created_by) VALUES (:i, :ref, :m, :r, :n, :es, :v, :c, :src, :f, :fs, :eng, :inp, :st, :o, "
            "CAST(:res AS jsonb), CAST(:t AS jsonb), :by)"
        ),
        {
            "i": eid,
            "ref": f"EVL-{n:04d}",
            "m": run["market_code"],
            "r": run_id,
            "n": len(rows),
            "es": inp["events_sha256"],
            "v": run["script_version_id"],
            "c": meta["content_sha256"],
            "src": meta["content_source"],
            "f": meta["snapshot"]["id"],
            "fs": meta["snapshot"]["sha256"],
            "eng": ae.ENGINE,
            "inp": inp["input_sha256"],
            "st": st,
            "o": ctrl.ended,
            "res": json.dumps(results, default=str),
            "t": json.dumps(ae.totals(results)),
            "by": actor,
        },
    )
    return get(db, eid, markets), True


def _row(db: Session, eval_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT e.*, r.sim_ref, r.mode, c.case_ref, p.display_name, f.code || ' v' || v.version_label AS script_label, "
        "v.status AS version_status FROM simulation_answer_evaluation e "
        "JOIN script_simulation_run r ON r.id = e.run_id JOIN callback_case c ON c.id = r.callback_case_id "
        "JOIN script_version v ON v.id = e.script_version_id JOIN script_family f ON f.id = v.script_family_id "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.created_by WHERE e.id = :e AND e.market_code = ANY(:m)",
        e=eval_id,
        m=list(markets),
    )
    if r is None:
        raise ss.SimulationError(404, "NOT_FOUND", "Evaluation not found or not available to you")
    return r


def replay(db: Session, rec: Mapping[str, Any]) -> dict[str, Any]:
    """Re-derive the results from the stored inputs (event prefix, content, fact snapshot) and compare."""
    run = _one(db, "SELECT * FROM script_simulation_run WHERE id = :r", r=rec["run_id"])
    assert run is not None
    rows = ss.events_of(db, rec["run_id"])[: rec["events_evaluated"]]
    events = [qc.Event(e["event_type"], e["question_code"], e["action_id"], e["data"] or {}) for e in rows]
    ctrl = qc.Controller(ss.plan_from_json(run["plan"]), events)
    content = _one(db, "SELECT content FROM simulation_content_snapshot WHERE sha256 = :s", s=rec["content_sha256"])
    if content is not None:
        c = dict(content["content"])
    else:
        sha, c, _ = content_for(db, run | {"content_sha256": None})
        if sha != rec["content_sha256"]:
            return {"matches": False, "detail": "The published content no longer matches the recorded checksum"}
    facts, snap = _facts(db, run)
    if snap["sha256"] != rec["policy_fact_snapshot_sha256"]:
        return {"matches": False, "detail": "The policy fact snapshot no longer matches the recorded checksum"}
    again = json.loads(json.dumps(ae.evaluate(c, ctrl, facts), default=str))
    same = again == rec["results"]
    return {
        "matches": same,
        "detail": "Re-derived from the stored inputs: identical results"
        if same
        else "Re-derived results differ from the recorded results",
    }


def get(db: Session, eval_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    rec = _row(db, eval_id, markets)
    return rec | {"replay": replay(db, rec)}


def for_run(db: Session, run_id: uuid.UUID, markets: Sequence[str]) -> list[dict[str, Any]]:
    ss.run_row(db, run_id, markets)
    return [
        dict(r)
        for r in db.execute(
            text(
                "SELECT e.id, e.evaluation_ref, e.events_evaluated, e.engine_version, e.controller_status, "
                "e.controller_outcome, e.totals, e.created_at, p.display_name FROM simulation_answer_evaluation e "
                "LEFT JOIN principal p ON CAST(p.id AS text) = e.created_by WHERE e.run_id = :r "
                "ORDER BY e.created_at DESC"
            ),
            {"r": run_id},
        ).mappings()
    ]
