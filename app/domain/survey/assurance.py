# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""EVAL-2B — execution-assurance runs of SYNTHETIC journeys: loading the recorded evidence, pinning, recording.

The journey is the one EVAL-1 evaluates: a single-survey simulation or a coordinated simulation. Its evidence is read
through the SS-03B and ASG-2B services, exactly as they record it; each survey's trace is verified by
``execution_assurance`` (pure). Nothing is executed here except the authoritative engine's own replay, which is how a
simulation is read in the first place.

Records are isolated ``SIMULATION`` records, insert-only. The same journey verified from the same inputs IS the same
assurance run; changed evidence, a changed contract or another control evaluation gives a NEW one. On reading, a run
is computed again from the evidence as it stands and a difference is reported as drift. Control outcomes are never
computed here: when a control evaluation is named, its recorded outcomes are shown beside what was verified about
the execution evidence each one rests on.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey import coordination, simulation
from app.domain.survey import execution_assurance as ea
from app.domain.survey import journey_evaluation as je
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.execution import CONTRACT as EXECUTION_CONTRACT
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

RECORD_CLASS = simulation.RECORD_CLASS
ENTITY = "survey_execution_assurance"
#: how far the execution evidence under one control result was verified — never a control outcome
TRUST = (
    "EXECUTION_VERIFIED",
    "EXECUTION_INCOMPLETE",
    "DEVIATION_IN_EVIDENCE",
    "INTEGRITY_FAILED",
    "NOT_ASSESSABLE",
    "NO_EXECUTION_EVIDENCE",
)
TRUST_OF = {
    "VERIFIED": "EXECUTION_VERIFIED",
    "INCOMPLETE": "EXECUTION_INCOMPLETE",
    "DEVIATION_DETECTED": "DEVIATION_IN_EVIDENCE",
    "INTEGRITY_FAILED": "INTEGRITY_FAILED",
    "NOT_ASSESSABLE": "NOT_ASSESSABLE",
}
WORST = ("INTEGRITY_FAILED", "DEVIATION_IN_EVIDENCE", "NOT_ASSESSABLE", "EXECUTION_INCOMPLETE", "EXECUTION_VERIFIED")


def _recorded(db: Session, markets: Sequence[str], execution: Mapping[str, Any]) -> dict[str, Any]:
    """What was RECORDED for one survey's simulation: its inputs with the fingerprint recorded after each, and
    whether the run still recomputes to them — at the end, and after every single input."""
    sim = simulation.state(db, execution["simulation_id"], markets)
    inputs = [
        {
            "key": i["key"],
            "answer": i["answer"],
            "accepted": i["accepted"],
            "rejection_code": i["rejection_code"],
            "run_sha256": i["run_sha256"],
        }
        for i in sim["inputs"]
    ]
    mismatches = []
    replayed: list[dict[str, Any]] = []
    # the engine the simulation service itself replays with — the authoritative one, never a second executor
    replay = simulation.execute_inputs  # type: ignore[attr-defined]
    initial = simulation._run_sha(replay(execution["bundle"], sim["facts"], []))
    if initial != sim["initial_run_sha256"]:
        mismatches.append({"after_inputs": 0, "recorded": sim["initial_run_sha256"], "recomputed": initial})
    for n, i in enumerate(inputs, start=1):
        replayed.append({"key": i["key"], "answer": i["answer"]})
        now = simulation._run_sha(replay(execution["bundle"], sim["facts"], replayed))
        if now != i["run_sha256"]:
            mismatches.append({"after_inputs": n, "recorded": i["run_sha256"], "recomputed": now})
    return {
        "inputs": inputs, "facts": sim["facts"], "replay_consistent": bool(sim["replay_consistent"]), "drift": sim["drift"],
        "steps_consistent": not mismatches, "step_mismatches": mismatches, "engine_contract": sim["engine_contract"],
    }  # fmt: skip


def _coordination(db: Session, markets: Sequence[str], coordinated_id: uuid.UUID) -> dict[str, Any]:
    """ASG-2B's own records of the journey: the composite's governed selection, the surveys as they stand, and every
    start the coordinator recorded."""
    row = coordination._row(db, coordinated_id, markets)
    co = coordination.state(db, coordinated_id, markets)
    comp, _ = coordination._plan(db, row, markets)
    chosen = {s["group"]: s for s in comp["composite"]["selected"]}
    order = list((comp["composite"].get("ordering") or {}).get("order") or [])
    selected = [chosen[g] for g in order if g in chosen] + [
        s for s in comp["composite"]["selected"] if s["group"] not in order
    ]
    return {
        "composite_plan_id": str(row["composite_plan_id"]), "composite_fingerprint": row["composite_fingerprint"], "composite_intact": bool(co["composite_intact"]),
        "selected": [{"group": s["group"], "survey_version_id": str(s["survey_version_id"]), "survey_code": s["survey_code"]} for s in selected],
        "surveys": [{"position": s["position"], "group": s["group"]["code"], "survey_version_id": str(s["survey_version_id"]), "state": s["state"], "simulation_id": str(s["simulation_id"]) if s["simulation_id"] else None} for s in co["surveys"]],
        "steps": [{"position": s["position"], "group_code": s["group_code"], "survey_version_id": str(s["survey_version_id"]), "simulation_id": str(s["simulation_id"]), "started_because": s["started_because"]} for s in coordination._steps(db, coordinated_id)],
        "decisions": co["decisions"], "stop": co["stop"],
    }  # fmt: skip


def _control_evidence(evaluation: Mapping[str, Any], surveys: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The control results AS RECORDED by the control evaluation, each beside what was verified about the execution
    evidence it rests on. No outcome is computed, changed or repeated in another engine."""
    by_sim = {str(s["simulation_id"]): s for s in surveys if s.get("simulation_id")}
    by_position = {s["position"]: s for s in surveys}
    out = []
    for c in evaluation["controls"]:
        evidence = _lines(c, by_sim, by_position)
        concrete = [x["execution"] for x in evidence if x["execution"] != "NO_EXECUTION_EVIDENCE"]
        trust = next((w for w in WORST if w in concrete), "NO_EXECUTION_EVIDENCE")
        out.append(
            {
                "control_code": c["control_code"], "obligation": c.get("obligation"), "control_name": c.get("control_name"),
                # copied from the control evaluation exactly as it recorded them
                "outcome": c["outcome"], "coverage": c.get("coverage"), "execution_evidence": trust,
                "result_is_trustworthy": trust not in ("INTEGRITY_FAILED", "DEVIATION_IN_EVIDENCE", "NOT_ASSESSABLE"),
                "evidence": evidence,
            }
        )  # fmt: skip
    return out


def _lines(
    c: Mapping[str, Any], by_sim: Mapping[str, Mapping[str, Any]], by_position: Mapping[int, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    out = []
    for o in c["observations"]:
        position = (o.get("survey") or {}).get("position")
        s = by_sim.get(str(o.get("simulation_id"))) or (
            by_position.get(int(position)) if position is not None else None
        )
        line: dict[str, Any] = {
            "seq": o["seq"],
            "placement": o.get("placement"),
            "survey_position": (o.get("survey") or {}).get("position"),
            "simulation_id": o.get("simulation_id"),
            "result": o["result"],
            "gap": o.get("gap"),
        }
        if s is None:
            out.append(
                line
                | {
                    "execution": "NO_EXECUTION_EVIDENCE",
                    "survey_status": None,
                    "delivery": "NOT_DELIVERED",
                    "not_delivered_class": None,
                    "why": "No survey of this journey contains this item, so no execution exists to verify",
                    "deviations": [],
                }
            )
            continue
        delivery = next((d for d in s["deliveries"] if d["placement"] == o.get("placement")), None)
        absent = next((x for x in s["exclusions"] if x["placement"] == o.get("placement")), None)
        out.append(
            line | {
                "execution": TRUST_OF[s["status"]], "survey_status": s["status"], "delivery": delivery["wording"] if delivery else "NOT_DELIVERED",
                "not_delivered_class": absent["class"] if absent else None, "why": absent["why"] if absent else None,
                "deviations": [f["code"] for ch in s["checks"] for f in ch["findings"] if f["evidence"].get("placement") == o.get("placement")],
            }
        )  # fmt: skip
    return out


def compute(
    db: Session,
    markets: Sequence[str],
    simulation_id: uuid.UUID | None,
    coordinated_id: uuid.UUID | None,
    evaluation_id: uuid.UUID | None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """(result, pins, market) for the journey as it stands. Nothing is written."""
    journey = je.journey_of(db, markets, simulation_id, coordinated_id)
    surveys = []
    for x in journey["executions"]:
        ref = {
            "position": x["position"], "survey_code": x["survey_code"], "survey_name": x["survey_name"], "version_label": x["version_label"],
            "survey_version_id": str(x["survey_version_id"]), "content_sha256": x["content_sha256"], "manifest_sha256": x["manifest_sha256"],
            "state": x["state"], "simulation_id": str(x["simulation_id"]) if x["simulation_id"] else None, "run_sha256": x["run_sha256"],
            "engine_contract": x["engine_contract"],
        }  # fmt: skip
        if x["simulation_id"] is None:
            surveys.append(ref | {"result": ea.not_started(), "inputs": 0})
            continue
        recorded = _recorded(db, markets, x)
        if recorded["engine_contract"] != EXECUTION_CONTRACT:
            result = ea.not_assessable(
                "EXECUTION_CONTRACT_NOT_SUPPORTED",
                f"This simulation was recorded under {recorded['engine_contract']}; this assurance contract verifies {EXECUTION_CONTRACT} only",
            )
        else:
            result = ea.verify_survey(x["bundle"], recorded["facts"], x["run"], recorded)
        surveys.append(ref | {"result": result, "inputs": len(recorded["inputs"])})
    context: dict[str, Any] = {
        "kind": journey["kind"],
        "id": journey["id"],
        "status": journey["status"],
        "complete": journey["complete"],
    }
    composite = None
    if coordinated_id is not None:
        composite = _coordination(db, markets, coordinated_id)
        context |= composite
    result = ea.assure_journey(context, surveys)
    evaluation = None
    if evaluation_id is not None:
        evaluation = je.get(db, evaluation_id, markets)
        if (evaluation["simulation_id"], evaluation["coordinated_id"]) != (simulation_id, coordinated_id):
            raise SurveyError(409, "EVALUATION_OF_ANOTHER_JOURNEY", "That control evaluation is of another journey")
        same = [e["run_sha256"] for e in evaluation["pins"]["executions"]] == [
            x["run_sha256"] for x in journey["executions"]
        ]
        body = {k: v for k, v in result.items() if k != "result_sha256"} | {
            "control_evaluation": {
                "id": str(evaluation["id"]), "result_sha256": evaluation["result_sha256"], "processing_status": evaluation["processing_status"],
                "coverage_status": evaluation["coverage"]["status"], "policy": evaluation.get("policy"), "of_this_evidence": same,
                "note": "Control outcomes and coverage are shown exactly as the control evaluation recorded them. Nothing is evaluated again here.",
            },
            # when the evidence is no longer what the evaluation was made from, its results are still shown as it
            # recorded them — and none of them is presented as trustworthy
            "control_evidence": [
                c if same else c | {"result_is_trustworthy": False, "evidence_changed_since_evaluation": True}
                for c in _control_evidence(evaluation, result["surveys"])
            ],
        }  # fmt: skip
        result = body | {"result_sha256": sha256_hex(body)}
    pins = {
        "contract": ea.CONTRACT, "execution_contract": EXECUTION_CONTRACT,
        "journey": {"kind": journey["kind"], "id": str(journey["id"]), "replay_sha256": journey["replay_sha256"], "application_sha256": journey["application_sha256"]},
        "composite": {"plan_id": composite["composite_plan_id"], "fingerprint": composite["composite_fingerprint"], "selected": composite["selected"]} if composite else None,
        "executions": [
            {"position": s["position"], "survey_version_id": s["survey_version_id"], "content_sha256": s["content_sha256"], "manifest_sha256": s["manifest_sha256"], "simulation_id": s["simulation_id"], "run_sha256": s["run_sha256"], "engine_contract": s["engine_contract"], "inputs": s["inputs"]}
            for s in result["surveys"]
        ],
        "control_evaluation": {"id": str(evaluation["id"]), "result_sha256": evaluation["result_sha256"]} if evaluation else None,
    }  # fmt: skip
    return result, pins, journey["market_code"]


def create(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None, evaluation_id: uuid.UUID | None,
    actor: Actor, meta: RequestMeta | None = None,
) -> tuple[uuid.UUID, bool]:  # fmt: skip
    """Verify the journey's recorded execution as it stands. Returns (assurance id, created): identical inputs give
    the assurance run that already exists."""
    result, pins, market = compute(db, markets, simulation_id, coordinated_id, evaluation_id)
    input_sha = sha256_hex(pins)
    column = "simulation_id" if simulation_id else "coordinated_id"
    journey_id = simulation_id or coordinated_id
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"survey_execution_assurance:{journey_id}"})
    prior = _one(
        db,
        f"SELECT id FROM survey_execution_assurance WHERE {column} = :j AND input_sha256 = :i",
        j=journey_id,
        i=input_sha,
    )
    if prior:
        return prior["id"], False
    aid = uuid.uuid4()
    summary = {k: v for k, v in result.items() if k not in ("surveys", "result_sha256")}
    db.execute(
        text(
            "INSERT INTO survey_execution_assurance (id, market_code, journey_kind, simulation_id, coordinated_id, evaluation_id, contract, "
            "pins, input_sha256, status, summary, result_sha256, created_by) VALUES (:i, :m, :k, :s, :c, :e, :con, CAST(:p AS jsonb), :inp, "
            ":st, CAST(:sum AS jsonb), :res, :by)"
        ),
        {
            "i": aid, "m": market, "k": result["journey"]["kind"], "s": simulation_id, "c": coordinated_id, "e": evaluation_id, "con": ea.CONTRACT,
            "p": json.dumps(pins), "inp": input_sha, "st": result["status"], "sum": json.dumps(summary, default=str), "res": result["result_sha256"], "by": _ref(actor),
        },
    )  # fmt: skip
    for s in result["surveys"]:
        db.execute(
            text(
                "INSERT INTO survey_execution_assurance_survey (assurance_id, position, survey_version_id, simulation_id, status, detail) "
                "VALUES (:a, :n, :v, :s, :st, CAST(:d AS jsonb))"
            ),
            {
                "a": aid,
                "n": s["position"],
                "v": s["survey_version_id"],
                "s": s["simulation_id"],
                "st": s["status"],
                "d": json.dumps(s, default=str),
            },
        )
    _audit(
        db, actor, meta, "SURVEY.EXECUTION_ASSURED", ENTITY, aid,
        {"journey": f"{result['journey']['kind']} {result['journey']['id']}", "status": result["status"], "findings": result["summary"]["findings"], "input_sha256": input_sha, "result_sha256": result["result_sha256"]},
    )  # fmt: skip
    return aid, True


def _row(db: Session, aid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db, "SELECT * FROM survey_execution_assurance WHERE id = :i AND market_code = ANY(:m)", i=aid, m=list(markets)
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Execution-assurance result not found or not available to you")
    return row


def _recompute(db: Session, row: Mapping[str, Any], markets: Sequence[str]) -> dict[str, Any]:
    """The run computed again NOW from the evidence as it stands. None of it is stored."""
    pins = row["pins"]
    try:
        result, now, _ = compute(db, markets, row["simulation_id"], row["coordinated_id"], row["evaluation_id"])
    except SurveyError as exc:
        return {
            "consistent": False,
            "code": "ASSURANCE_DRIFT",
            "reasons": [{"code": exc.code, "text": exc.message}],
            "recorded_result_sha256": row["result_sha256"],
            "recomputed_result_sha256": None,
        }
    reasons = [
        {"code": code, "text": text_}
        for code, text_, same in (
            ("EVIDENCE_CHANGED", "The journey's execution evidence is not what was verified (inputs were added, a survey was started, or a simulation recomputes differently)", now["journey"] == pins["journey"] and now["executions"] == pins["executions"]),
            ("COMPOSITE_CHANGED", "The composite plan of the journey is not what was verified", now["composite"] == pins["composite"]),
            ("CONTRACT_CHANGED", "The assurance or the execution contract has another version now", (now["contract"], now["execution_contract"]) == (pins["contract"], pins["execution_contract"])),
            ("CONTROL_EVALUATION_CHANGED", "The control evaluation shown beside this result does not read as it did", now["control_evaluation"] == pins["control_evaluation"]),
        )
        if not same
    ]  # fmt: skip
    same_result = result["result_sha256"] == row["result_sha256"]
    if not same_result and not reasons:
        reasons.append({"code": "RESULT_DIFFERS", "text": "The same pinned inputs give a different result now"})
    return {
        "consistent": same_result and not reasons, "code": None if same_result and not reasons else "ASSURANCE_DRIFT", "reasons": reasons,
        "recorded_result_sha256": row["result_sha256"], "recomputed_result_sha256": result["result_sha256"],
    }  # fmt: skip


def get(db: Session, aid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _row(db, aid, markets)
    surveys = [
        s["detail"]
        for s in _all(
            db, "SELECT detail FROM survey_execution_assurance_survey WHERE assurance_id = :a ORDER BY position", a=aid
        )
    ]
    s = row["summary"]
    replay = _recompute(db, row, markets)
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": ea.NOTE, "contract": row["contract"], "execution_contract": s["execution_contract"],
        "market_code": row["market_code"], "created_at": row["created_at"], "created_by": row["created_by"],
        "journey_kind": row["journey_kind"], "simulation_id": row["simulation_id"], "coordinated_id": row["coordinated_id"], "evaluation_id": row["evaluation_id"],
        "journey": s["journey"], "status": row["status"], "summary": s["summary"], "surveys": surveys, "journey_checks": s["journey_checks"],
        "findings": s["findings"], "control_evaluation": s.get("control_evaluation"), "control_evidence": s.get("control_evidence") or [],
        "pins": row["pins"], "input_sha256": row["input_sha256"], "result_sha256": row["result_sha256"],
        "replay": replay, "current_status": "ASSURANCE_DRIFT" if not replay["consistent"] else row["status"],
        "operational_call_eligibility": ea.ELIGIBILITY,
    }  # fmt: skip


def for_journey(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None
) -> list[dict[str, Any]]:
    if (simulation_id is None) == (coordinated_id is None):
        raise SurveyError(422, "JOURNEY_REQUIRED", "Name exactly one journey: a simulation or a coordinated simulation")
    column = "simulation_id" if simulation_id else "coordinated_id"
    return _all(
        db,
        "SELECT id, journey_kind, status, evaluation_id, input_sha256, result_sha256, created_at, created_by, summary->'summary' AS summary "
        f"FROM survey_execution_assurance WHERE {column} = :j AND market_code = ANY(:m) ORDER BY created_at, id",
        j=simulation_id or coordinated_id, m=list(markets),
    )  # fmt: skip
