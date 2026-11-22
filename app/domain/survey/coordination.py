# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""ASG-2B — coordinated SIMULATION of every survey of one composite plan. A thin coordinating layer.

There is no execution here. Each survey of the composite is run by its own SS-03B simulation
(``simulation.create`` / ``simulation.advance`` / ``simulation.state``): its own published version, its own inputs and
rejected inputs, its own trace, status, drift detection and run fingerprint. The coordinator only

  * refuses to start unless the composite's selection and governed order are settled, every individual plan can be
    computed, and no survey version is required twice;
  * starts the first survey of the governed order;
  * sends each input to the survey that is current;
  * starts the next survey when — and only when — the current one reaches COMPLETED;
  * stops, and says why, in every other case.

It merges no graph, removes no statement or question, and decides nothing about what a real call would do. The rule
"COMPLETED lets the next survey start" is authorised for TECHNICAL SIMULATION ONLY. An escalation, a refusal, an
incomplete answer or any other ending stops the coordinated run with ``CROSS_SURVEY_POLICY_UNRESOLVED``: nobody has
decided what follows. ``ALL_SURVEYS_COMPLETED`` reports progress; it is not a business outcome of anything.

Nothing is stored that could drift: the state is computed from the recorded steps and the replay of each individual
simulation, every time.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey import assignment_groups as ag
from app.domain.survey import simulation
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

CONTRACT = "call360.survey.coordinated-simulation/1"
RECORD_CLASS = simulation.RECORD_CLASS
NOTE = (
    "COORDINATED SIMULATION ONLY, for a synthetic application. It is not a call and not a record of one. The rule that a "
    "completed survey lets the next one start is a technical simulation rule: it approves nothing about real calls."
)
STATUSES = ("RUNNING", "POLICY_UNRESOLVED", "CROSS_SURVEY_POLICY_UNRESOLVED", "ALL_SURVEYS_COMPLETED", "REPLAY_DRIFT")
MAX_SURVEYS = 20


def _row(db: Session, cid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT * FROM survey_coordinated_simulation WHERE id = :i AND market_code = ANY(:m)" + (" FOR UPDATE" if lock else ""),
        i=cid, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Coordinated simulation not found or not available to you")
    return row


def _steps(db: Session, cid: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db, "SELECT * FROM survey_coordinated_simulation_step WHERE coordinated_id = :c ORDER BY position", c=cid
    )


def _plan(db: Session, row: Mapping[str, Any], markets: Sequence[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The recorded composite and its selected surveys in the GOVERNED order the coordinator was started with."""
    comp = ag.composite(db, row["composite_plan_id"], markets)
    by_group = {s["group"]: s for s in comp["composite"]["selected"]}
    return comp, [by_group[g] for g in row["governed_order"]]


def _start_step(
    db: Session,
    row: Mapping[str, Any],
    position: int,
    survey: Mapping[str, Any],
    comp: Mapping[str, Any],
    because: str,
    actor: Actor,
    meta: RequestMeta | None,
) -> uuid.UUID:
    """Start the individual SS-03B simulation of one survey — its own record, exactly as a single-survey simulation."""
    group_id = next(
        r["group"]["id"] for r in comp["composite"]["requirements"] if r["group"]["code"] == survey["group"]
    )
    sim = simulation.create(
        db, uuid.UUID(survey["survey_version_id"]), [row["market_code"]], comp["composite"]["application"]["facts"],
        f"Coordinated {str(row['id'])[:8]} · {position}. {survey['group']}", actor, meta,
    )  # fmt: skip
    db.execute(
        text(
            "INSERT INTO survey_coordinated_simulation_step (coordinated_id, position, group_id, group_code, survey_version_id, "
            "simulation_id, started_because, started_by) VALUES (:c, :p, :g, :gc, :v, :s, :b, :by)"
        ),
        {
            "c": row["id"],
            "p": position,
            "g": group_id,
            "gc": survey["group"],
            "v": survey["survey_version_id"],
            "s": sim,
            "b": because,
            "by": _ref(actor),
        },
    )
    _audit(
        db, actor, meta, "SURVEY.COORDINATED_SIMULATION_SURVEY_STARTED", "survey_coordinated_simulation", row["id"],
        {"record_class": RECORD_CLASS, "position": position, "group": survey["group"], "simulation": str(sim), "because": because},
    )  # fmt: skip
    return sim


def _continue(
    db: Session, row: Mapping[str, Any], markets: Sequence[str], actor: Actor, meta: RequestMeta | None
) -> None:
    """Start the next survey for as long as the last started one is COMPLETED. Any other state stops here."""
    comp, order = _plan(db, row, markets)
    for _ in range(MAX_SURVEYS):
        steps = _steps(db, row["id"])
        if len(steps) >= len(order):
            return
        if steps:
            last = simulation.state(db, steps[-1]["simulation_id"], markets)
            done = last["status"] == "TERMINAL" and (last["run"]["terminal"] or {}).get("state") == "COMPLETED"
            if not done:
                return  # pending, unresolved policy, a non-completed ending, or drift: the coordinator stays there
        _start_step(
            db,
            row,
            len(steps) + 1,
            order[len(steps)],
            comp,
            "PREVIOUS_COMPLETED" if steps else "FIRST_IN_ORDER",
            actor,
            meta,
        )


def create(
    db: Session,
    composite_id: uuid.UUID,
    markets: Sequence[str],
    label: str,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> uuid.UUID:
    """Start a coordinated simulation of a recorded composite — or refuse, saying which thing is unresolved."""
    comp = ag.composite(db, composite_id, markets)
    blockers = comp["states"]["coordinated_simulation"]["blockers"]
    if blockers:
        # never started "as if it were ready": the first blocker is the error code, and all of them are listed
        raise SurveyError(
            409, blockers[0]["code"], "A coordinated simulation of this composite cannot be started", blockers
        )
    doc = comp["composite"]
    order = doc["ordering"]["order"]
    if not order or len(order) > MAX_SURVEYS:
        raise SurveyError(409, "ORDER_UNRESOLVED", "The composite has no governed order of surveys")
    cid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_coordinated_simulation (id, composite_plan_id, market_code, application_sha256, composite_fingerprint, "
            "contract, governed_order, label, created_by) VALUES (:i, :c, :m, :a, :f, :k, CAST(:o AS jsonb), :l, :by)"
        ),
        {
            "i": cid, "c": composite_id, "m": comp["market_code"], "a": comp["application_sha256"], "f": comp["fingerprint"],
            "k": CONTRACT, "o": json.dumps(order), "l": label.strip()[:160], "by": _ref(actor),
        },
    )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.COORDINATED_SIMULATION_CREATED", "survey_coordinated_simulation", cid,
        {"record_class": RECORD_CLASS, "composite": str(composite_id), "composite_fingerprint": comp["fingerprint"], "order": order},
    )  # fmt: skip
    _continue(db, _row(db, cid, markets), markets, actor, meta)
    return cid


def state(db: Session, cid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    """The coordinated simulation as it stands: computed now from its steps and the replay of each individual run."""
    row = _row(db, cid, markets)
    comp, order = _plan(db, row, markets)
    steps = {s["position"]: s for s in _steps(db, cid)}
    surveys: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    status, stop, current = "RUNNING", None, None
    names = {r["group"]["code"]: r["group"] for r in comp["composite"]["requirements"]}
    for n, s in enumerate(order, start=1):
        step = steps.get(n)
        entry: dict[str, Any] = {
            "position": n, "group": {k: names[s["group"]][k] for k in ("code", "kind", "name", "purpose", "sequence")},
            "survey_code": s["survey_code"], "survey_name": s["survey_name"], "version_label": s["version_label"],
            "survey_version_id": s["survey_version_id"], "content_sha256": s["content_sha256"], "manifest_sha256": s["manifest_sha256"],
            "rule": s["rule"], "binding_id": s["binding_id"], "plan_fingerprint": s["plan_fingerprint"],
            "state": "NOT_STARTED", "simulation_id": None, "simulation": None, "run_sha256": None, "engine_contract": None,
            "started_because": None, "inputs": 0, "refused_inputs": 0, "delivered": 0,
        }  # fmt: skip
        if step:
            sim = simulation.state(db, step["simulation_id"], markets)
            terminal = (sim["run"]["terminal"] or {}).get("state")
            entry.update(
                simulation_id=sim["id"], simulation=sim, run_sha256=sim["run_sha256"], engine_contract=sim["engine_contract"],
                started_because=step["started_because"], inputs=len(sim["inputs"]), refused_inputs=sum(not i["accepted"] for i in sim["inputs"]),
                delivered=len(sim["run"]["delivered"]),
            )  # fmt: skip
            if sim["status"] == "REPLAY_DRIFT":
                entry["state"], status = "DRIFTED", "REPLAY_DRIFT"
                stop = {
                    "code": "REPLAY_DRIFT",
                    "at": s["group"],
                    "reason": "This survey's simulation no longer recomputes to its recorded result.",
                }
            elif sim["status"] == "TERMINAL" and terminal == "COMPLETED":
                entry["state"] = "COMPLETED"
                if n < len(order):
                    # the ONE continuation rule, authorised for technical simulation only
                    decisions.append(
                        {
                            "after": s["group"],
                            "ending": "COMPLETED",
                            "decision": "PROCEED",
                            "rule": "SIMULATION_ONLY_COMPLETED_PROCEEDS",
                            "to": order[n]["group"],
                        }
                    )
            elif sim["status"] == "TERMINAL":
                entry["state"], status = "STOPPED", "CROSS_SURVEY_POLICY_UNRESOLVED"
                stop = {
                    "code": "CROSS_SURVEY_POLICY_UNRESOLVED", "at": s["group"], "ending": sim["run"]["terminal"],
                    "reason": "This survey ended without COMPLETED. Whether another survey may then proceed has not been decided, so none is started. No outcome is given to the composite.",
                }  # fmt: skip
                decisions.append(
                    {
                        "after": s["group"],
                        "ending": terminal,
                        "decision": "STOP",
                        "rule": "CROSS_SURVEY_POLICY_UNRESOLVED",
                        "to": None,
                    }
                )
            elif sim["status"] == "POLICY_UNRESOLVED":
                entry["state"], status = "CURRENT", "POLICY_UNRESOLVED"
                stop = {
                    "code": "POLICY_UNRESOLVED",
                    "at": s["group"],
                    "detail": sim["run"]["policy_unresolved"],
                    "reason": "A non-answer whose handling is an open business decision. The question stays current.",
                }
                current = entry
            else:
                entry["state"], current = "CURRENT", entry
        surveys.append(entry)
        if entry["state"] != "COMPLETED":
            break
    surveys += [
        {
            "position": n, "group": {k: names[s["group"]][k] for k in ("code", "kind", "name", "purpose", "sequence")},
            "survey_code": s["survey_code"], "survey_name": s["survey_name"], "version_label": s["version_label"],
            "survey_version_id": s["survey_version_id"], "content_sha256": s["content_sha256"], "manifest_sha256": s["manifest_sha256"],
            "rule": s["rule"], "binding_id": s["binding_id"], "plan_fingerprint": s["plan_fingerprint"],
            "state": "NOT_STARTED", "simulation_id": None, "simulation": None, "run_sha256": None, "engine_contract": None,
            "started_because": None, "inputs": 0, "refused_inputs": 0, "delivered": 0,
        }
        for n, s in enumerate(order, start=1) if n > len(surveys)
    ]  # fmt: skip
    if status == "RUNNING" and all(x["state"] == "COMPLETED" for x in surveys):
        status = "ALL_SURVEYS_COMPLETED"
    pending = (current["simulation"]["run"]["pending"] if current else None) or None
    replay = {
        "contract": row["contract"], "composite_fingerprint": row["composite_fingerprint"], "application_sha256": row["application_sha256"],
        "order": list(row["governed_order"]), "status": status, "decisions": decisions,
        "surveys": [{"group": x["group"]["code"], "survey_version_id": x["survey_version_id"], "state": x["state"], "run_sha256": x["run_sha256"], "engine_contract": x["engine_contract"]} for x in surveys],
    }  # fmt: skip
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": NOTE, "contract": row["contract"], "current_contract": CONTRACT,
        "market_code": row["market_code"], "label": row["label"], "created_at": row["created_at"],
        "composite_plan_id": row["composite_plan_id"], "composite_fingerprint": row["composite_fingerprint"],
        # the composite this was started from must still be the recorded one
        "composite_intact": comp["fingerprint"] == row["composite_fingerprint"] and comp["fingerprint_verified"],
        "application_sha256": row["application_sha256"], "application": comp["composite"]["application"],
        "input_consistency": comp["composite"]["input_consistency"],
        "governed_order": list(row["governed_order"]),
        "status": status, "stop": stop, "decisions": decisions, "surveys": surveys,
        "current": (
            {"position": current["position"], "group": current["group"]["code"], "survey_code": current["survey_code"], "simulation_id": current["simulation_id"], "pending": pending}
            if current else None
        ),
        "progress": {
            "surveys_total": len(surveys), "surveys_completed": sum(x["state"] == "COMPLETED" for x in surveys),
            "surveys_started": sum(x["simulation_id"] is not None for x in surveys),
            "inputs": sum(x["inputs"] for x in surveys), "refused_inputs": sum(x["refused_inputs"] for x in surveys),
            "items_delivered": sum(x["delivered"] for x in surveys),
        },
        "execution_contracts": sorted({x["engine_contract"] for x in surveys if x["engine_contract"]}),
        "replay_sha256": sha256_hex(json.loads(json.dumps(replay, default=str))),
        "operational_call_eligibility": ag.OPERATIONAL_ELIGIBILITY,
    }  # fmt: skip


def advance(
    db: Session, cid: uuid.UUID, markets: Sequence[str], expected_inputs: int, key: str, answer: Any, actor: Actor,
    meta: RequestMeta | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Give ONE typed input to the question that is current in the survey that is current. The individual simulation
    decides everything about it (validity, refusal, drift). Only if that survey thereby reaches COMPLETED is the next
    one started."""
    row = _row(db, cid, markets, lock=True)
    before = state(db, cid, markets)
    if before["progress"]["inputs"] != expected_inputs:
        raise SurveyError(
            409,
            "STALE_SIMULATION",
            f"The coordinated simulation has {before['progress']['inputs']} inputs; this one was given against {expected_inputs}",
            [{"current_inputs": before["progress"]["inputs"]}],
        )
    if before["status"] in ("CROSS_SURVEY_POLICY_UNRESOLVED", "ALL_SURVEYS_COMPLETED", "REPLAY_DRIFT"):
        raise SurveyError(
            409,
            before["status"],
            "This coordinated simulation takes no further input",
            [before["stop"]] if before["stop"] else [],
        )
    current = before["current"]
    if current is None:
        raise SurveyError(409, "NOTHING_CURRENT", "No survey is waiting for an answer")
    sim = next(x["simulation"] for x in before["surveys"] if x["position"] == current["position"])
    simulation.advance(
        db, uuid.UUID(str(current["simulation_id"])), markets, len(sim["inputs"]), key, answer, actor, meta
    )
    _continue(db, row, markets, actor, meta)
    return state(db, cid, markets)
