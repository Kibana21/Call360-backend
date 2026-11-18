"""S3-B simulated finding generation for interactive runs, and the operational finding writer (synthetic fixtures only).

Simulation: findings are generated from a recorded answer evaluation (``simulation_answer_evaluation``) with the
published finding rule set — or, for testing, an explicitly chosen draft / approved version (labelled) — and stored
insert-only in ``simulation_finding_set`` / ``simulation_finding``. Identical inputs (evaluation, rule set checksum,
engine) return the existing set; finding keys are unique, so repeated generation never duplicates a finding. Nothing
here touches operational findings, case state or KPIs.

Operational (design for later use with real callback evidence): ``persist_operational`` writes one engine finding to
the operational ``finding`` table for a question execution, idempotently by finding key. It refuses anything that is
not an explicitly synthetic case and is not exposed through any API in S3-B; no real voice session is evaluated.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import finding_rules as fr
from app.domain import script_simulation as ss
from app.domain import simulation_evaluation as se
from app.domain.digest import sha256_of


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def choose_rule_set(db: Session, market: str, markets: Sequence[str], vid: uuid.UUID | None) -> dict[str, Any]:
    if vid is not None:
        v = fr.version(db, vid, markets)
        if v["status"] == "ABANDONED":
            raise ss.SimulationError(409, "RULE_SET_ABANDONED", "That finding rule set was abandoned")
        return v
    pub = fr.published(db, market)
    if pub is None:
        raise ss.SimulationError(
            409, "NO_PUBLISHED_FINDING_RULES", "No finding rule set is published; publish one or choose a draft to test"
        )
    return pub


def context_of(rec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "execution_ref": f"{rec['sim_ref']}/{rec['evaluation_ref']}",
        "case_ref": rec["case_ref"],
        "script_label": rec["script_label"],
        "script_version_id": str(rec["script_version_id"]),
        "content_sha256": rec["content_sha256"],
        "evaluation_ref": rec["evaluation_ref"],
        "evaluation_engine": rec["engine_version"],
        "fact_source": {
            "kind": "POLICY_FACT_SNAPSHOT",
            "ref": str(rec["policy_fact_snapshot_id"]),
            "sha256": rec["policy_fact_snapshot_sha256"],
        },
    }


def generate(
    db: Session,
    run_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    markets: Sequence[str],
    actor: str,
    rule_set_version_id: uuid.UUID | None = None,
) -> tuple[dict[str, Any], bool]:
    rec = se.get(db, evaluation_id, markets)
    if rec["run_id"] != run_id:
        raise ss.SimulationError(404, "NOT_FOUND", "Evaluation not found or not available to you")
    v = choose_rule_set(db, rec["market_code"], markets, rule_set_version_id)
    rs = fr.rule_set(v)
    run = _one(db, "SELECT * FROM script_simulation_run WHERE id = :r", r=run_id)
    assert run is not None
    sha, content, _ = se.content_for(db, run)
    if sha != rec["content_sha256"]:
        raise ss.SimulationError(409, "CONTENT_CHANGED", "The evaluated script content can no longer be reproduced")
    g = fe.generate(rec["results"], content, rs, context_of(rec))
    input_sha = sha256_of({"engine": fe.ENGINE, "evaluation": rec["input_sha256"], "rule_set": rs.sha256})
    prior = _one(
        db,
        "SELECT id FROM simulation_finding_set WHERE evaluation_id = :e AND input_sha256 = :i",
        e=evaluation_id,
        i=input_sha,
    )
    if prior:
        return get(db, prior["id"], markets), False
    sid = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM simulation_finding_set")).scalar_one()
    d = g.as_dict()
    db.execute(
        text(
            "INSERT INTO simulation_finding_set (id, finding_set_ref, market_code, evaluation_id, rule_set_version_id, "
            "rule_set_status, rule_set_sha256, engine_version, input_sha256, findings, not_converted, "
            "human_assessment, summary, created_by) VALUES (:i, :ref, :m, :e, :v, :st, :rs, :eng, :inp, "
            "CAST(:f AS jsonb), CAST(:nc AS jsonb), CAST(:ha AS jsonb), CAST(:s AS jsonb), :by)"
        ),
        {
            "i": sid,
            "ref": f"FGS-{n:04d}",
            "m": rec["market_code"],
            "e": evaluation_id,
            "v": v["id"],
            "st": v["status"],
            "rs": rs.sha256,
            "eng": fe.ENGINE,
            "inp": input_sha,
            "f": json.dumps(d["findings"], default=str),
            "nc": json.dumps(d["not_converted"], default=str),
            "ha": json.dumps(d["human_assessment"], default=str),
            "s": json.dumps(d["summary"]),
            "by": actor,
        },
    )
    for f in d["findings"]:
        db.execute(
            text(
                "INSERT INTO simulation_finding (id, finding_set_id, finding_key, question_code, finding_class, "
                "category, severity, review_required, rule_code, data) VALUES (:i, :s, :k, :q, :c, :cat, :sev, :rr, "
                ":rule, CAST(:d AS jsonb))"
            ),
            {
                "i": uuid.uuid4(),
                "s": sid,
                "k": f["finding_key"],
                "q": f["question_code"],
                "c": f["finding_class"],
                "cat": f["category"],
                "sev": f["severity"],
                "rr": f["review_required"],
                "rule": f["rule"]["rule_code"],
                "d": json.dumps(f, default=str),
            },
        )
    return get(db, sid, markets), True


def get(db: Session, set_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT s.*, e.evaluation_ref, e.run_id, v.version_no, v.market_code AS rs_market, "
        "v.status AS rule_set_current_status, p.display_name "
        "FROM simulation_finding_set s JOIN simulation_answer_evaluation e ON e.id = s.evaluation_id "
        "JOIN finding_rule_set_version v ON v.id = s.rule_set_version_id "
        "LEFT JOIN principal p ON CAST(p.id AS text) = s.created_by WHERE s.id = :s AND s.market_code = ANY(:m)",
        s=set_id,
        m=list(markets),
    )
    if r is None:
        raise ss.SimulationError(404, "NOT_FOUND", "Finding set not found or not available to you")
    r["rule_set_label"] = fr.label(
        {"market_code": r["rs_market"], "version_no": r["version_no"], "status": r["rule_set_status"]}
    )
    r["replay"] = replay(db, r, markets)
    return r


def replay(db: Session, rec: Mapping[str, Any], markets: Sequence[str]) -> dict[str, Any]:
    """Re-derive the findings from the stored evaluation and the (immutable outside DRAFT) rule set version."""
    v = fr.version(db, rec["rule_set_version_id"], markets)
    rs = fr.rule_set(v)
    if rs.sha256 != rec["rule_set_sha256"]:
        return {"matches": False, "detail": "The draft rule set was edited after generation; generate again to compare"}
    ev = se.get(db, rec["evaluation_id"], markets)
    run = _one(db, "SELECT * FROM script_simulation_run WHERE id = :r", r=ev["run_id"])
    assert run is not None
    _, content, _ = se.content_for(db, run)
    again = json.loads(json.dumps(fe.generate(ev["results"], content, rs, context_of(ev)).findings, default=str))
    same = again == rec["findings"]
    return {
        "matches": same,
        "detail": "Re-derived from the stored evaluation and rule set: identical findings"
        if same
        else "Re-derived findings differ from the recorded findings",
    }


def for_evaluation(db: Session, evaluation_id: uuid.UUID, markets: Sequence[str]) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in db.execute(
            text(
                "SELECT s.id, s.finding_set_ref, s.rule_set_status, s.summary, s.created_at, v.version_no, "
                "v.market_code, p.display_name FROM simulation_finding_set s JOIN finding_rule_set_version v ON "
                "v.id = s.rule_set_version_id LEFT JOIN principal p ON CAST(p.id AS text) = s.created_by "
                "WHERE s.evaluation_id = :e AND s.market_code = ANY(:m) ORDER BY s.created_at DESC"
            ),
            {"e": evaluation_id, "m": list(markets)},
        ).mappings()
    ]


# ---- scenarios -----------------------------------------------------------------------------------------------------
def scenario_findings(
    evaluations: Sequence[Mapping[str, Any]], content: Mapping[str, Any], rs: fe.RuleSet, ctx: Mapping[str, Any]
) -> dict[str, Any]:
    g = fe.generate(evaluations, content, rs, ctx)
    return g.as_dict() | {"rule_set": rs.ref(), "expected_view": fe.finding_set(g.findings)}


# ---- operational (synthetic fixtures only; no API in S3-B) -----------------------------------------------------------
def persist_operational(
    db: Session, finding: Mapping[str, Any], question_execution_id: uuid.UUID, actor: str
) -> tuple[uuid.UUID, bool]:
    """Write one engine finding to the operational ``finding`` table (idempotent by finding key). Refuses a case that
    is not explicitly synthetic. Returns (finding id, created)."""
    qe = _one(
        db,
        "SELECT qe.id, ca.callback_case_id, c.is_synthetic FROM question_execution qe JOIN survey_run sr "
        "ON sr.id = qe.survey_run_id JOIN conversation_session cs ON cs.id = sr.session_id JOIN contact_attempt ca "
        "ON ca.id = cs.contact_attempt_id JOIN callback_case c ON c.id = ca.callback_case_id WHERE qe.id = :q",
        q=question_execution_id,
    )
    if qe is None:
        raise ValueError("question execution not found")
    if not qe["is_synthetic"]:
        raise PermissionError("S3-B writes operational findings for explicitly synthetic fixtures only")
    if finding["rule"]["rule_set"].get("status") != "PUBLISHED":
        raise PermissionError("Operational findings use the published finding rule set only (approved severity)")
    prior = _one(db, "SELECT id FROM finding WHERE evidence_refs->>'finding_key' = :k", k=finding["finding_key"])
    if prior:
        return prior["id"], False
    now = datetime.now(UTC)
    fid = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM finding WHERE finding_ref LIKE 'FND-ENG-%'")).scalar_one()
    db.execute(
        text(
            "INSERT INTO finding (id, finding_ref, callback_case_id, question_execution_id, category, severity, "
            "status, evidence_refs, origin, raised_at, created_by, source_type, source_system, source_reference, "
            "recorded_at, is_synthetic, record_origin) VALUES (:i, :ref, :c, :q, :cat, :sev, 'OPEN', "
            "CAST(:ev AS jsonb), 'RULE_EVALUATION', :t, :by, 'INTERNAL_API', 'CALL360_FINDING_ENGINE', :src, :t, true, "
            "'CALL360_RUNTIME')"
        ),
        {
            "i": fid,
            "ref": f"FND-ENG-{n:05d}",
            "c": qe["callback_case_id"],
            "q": question_execution_id,
            "cat": finding["category"],
            "sev": finding["severity"],
            "ev": json.dumps(
                {
                    "finding_key": finding["finding_key"],
                    "question_execution_id": str(question_execution_id),
                    "rule": finding["rule"],
                    "finding_class": finding["finding_class"],
                    "severity_justification": finding["severity_justification"],
                    "review_required": finding["review_required"],
                    "controls": finding["controls"],
                    "evidence": finding["evidence"],
                    "engine": finding["engine"],
                    "evaluation_engine": ae.ENGINE,
                    "transcript": "NOT_AVAILABLE",
                    "label": "Synthetic fixture finding generated by the S3-B engine (not a customer compliance issue)",
                },
                default=str,
            ),
            "t": now,
            "by": actor,
            "src": f"{finding['rule']['rule_code']}:{finding['finding_key'][:16]}",
        },
    )
    return fid, True
