"""S2-D text simulation: runs the pure question controller over a case's pinned script, persisting only simulation
records (``script_simulation_run`` + insert-only ``script_simulation_event``). Never creates contact attempts, sessions,
survey runs, answers, findings or verification outcomes, and never changes holds or case state.

S2-E version testing (mode VERSION_TEST): any visible draft or published version can be run on a synthetic case from a
content snapshot; the case's latest policy fact snapshot and final SBQ band are used and no script assignment is read or
written.

Pins (TEXT_SIMULATION) come from the case's current script assignment (S2-C or seeded): the published script
version and its manifest
checksum, the policy fact snapshot and the SBQ risk assessment. The callback contact is validated against the case's
current eligible contact selections (and must be the contact the assignment used when it recorded one).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import question_controller as qc
from app.domain import script_assignment as sx
from app.domain import script_authoring
from app.domain.digest import sha256_of
from app.domain.rule_engine import Contact

OPEN = ("IN_PROGRESS", "SEQUENCE_FINISHED")


class SimulationError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


# ---- context ----------------------------------------------------------------------------------------------------
def eligible_cases(
    db: Session, markets: Sequence[str], q: str | None, limit: int = 50, include_unassigned: bool = False
) -> list[dict[str, Any]]:
    if include_unassigned:  # S2-E version testing: any synthetic case with a policy fact snapshot
        return _all(
            db,
            "SELECT c.id AS case_id, c.case_ref, c.state, "
            "coalesce(f.code || ' v' || v.version_label, 'No pinned script') "
            "AS script_label, coalesce(a.origin, 'NONE') AS origin, (SELECT count(*) FROM script_simulation_run r "
            "WHERE r.callback_case_id = c.id) AS simulations FROM callback_case c LEFT JOIN script_assignment a ON "
            "a.callback_case_id = c.id AND NOT EXISTS (SELECT 1 FROM script_assignment x WHERE x.supersedes_id = a.id) "
            "LEFT JOIN script_version v ON v.id = a.script_version_id LEFT JOIN script_family f ON f.id = "
            "v.script_family_id WHERE c.market_code = ANY(:m) AND EXISTS (SELECT 1 FROM policy_fact_snapshot s WHERE "
            "s.sale_event_id = c.sale_event_id) AND (CAST(:q AS text) IS NULL OR c.case_ref ILIKE :like) "
            "ORDER BY c.case_ref DESC LIMIT :n",
            m=list(markets),
            q=q,
            like=f"%{q}%" if q else None,
            n=limit,
        )
    return _all(
        db,
        "SELECT c.id AS case_id, c.case_ref, c.state, f.code || ' v' || v.version_label AS script_label, a.origin, "
        "(SELECT count(*) FROM script_simulation_run r WHERE r.callback_case_id = c.id) AS simulations "
        "FROM callback_case c JOIN script_assignment a ON a.callback_case_id = c.id AND NOT EXISTS ("
        "SELECT 1 FROM script_assignment x WHERE x.supersedes_id = a.id) JOIN script_version v "
        "ON v.id = a.script_version_id JOIN script_family f ON f.id = v.script_family_id "
        "WHERE c.market_code = ANY(:m) AND (CAST(:q AS text) IS NULL OR c.case_ref ILIKE :like) "
        "ORDER BY a.assigned_at DESC, c.case_ref LIMIT :n",
        m=list(markets),
        q=q,
        like=f"%{q}%" if q else None,
        n=limit,
    )


def version_context(
    db: Session, c: dict[str, Any], markets: Sequence[str], version_id: uuid.UUID, *, persist: bool
) -> dict[str, Any]:
    """S2-E: a chosen (draft or published) version on a synthetic case, from a content snapshot; no assignment."""
    from app.domain import simulation_workbench as wb

    try:
        v = wb.version(db, version_id, markets)
    except wb.WorkbenchError as exc:
        raise SimulationError(404, "VERSION_NOT_FOUND", exc.message) from exc
    if v["status"] == "ABANDONED":
        raise SimulationError(409, "VERSION_ABANDONED", "That draft was abandoned")
    snap = _one(
        db,
        "SELECT id, facts FROM policy_fact_snapshot WHERE sale_event_id = :s ORDER BY captured_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    if snap is None:
        raise SimulationError(409, "NO_FACT_SNAPSHOT", "The case has no policy fact snapshot")
    risk = _one(
        db,
        "SELECT id, band_code FROM risk_assessment WHERE sale_event_id = :s AND status = 'FINAL' "
        "ORDER BY valid_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    sha, content = wb.snapshot(db, v) if persist else wb.content(db, v)
    plan = wb.build(content, v, sha, snap["facts"] or {}, risk["band_code"] if risk else None)
    return {
        "case": c,
        "assignment": None,
        "version": v | {"manifest_sha256": sha},
        "content_sha256": sha,
        "snapshot": snap,
        "risk": risk,
        "plan": plan,
        "contacts": sx.contacts(db, c["id"]),
        "assignment_contact": None,
        "content_approval_status": v["content_approval_status"],
        "live_eligibility": wb.live_eligibility(content),
    }


def context(
    db: Session,
    case_id: uuid.UUID,
    markets: Sequence[str],
    version_id: uuid.UUID | None = None,
    *,
    persist: bool = False,
) -> dict[str, Any]:
    c = _one(db, "SELECT * FROM callback_case WHERE id = :c AND market_code = ANY(:m)", c=case_id, m=list(markets))
    if c is None:
        raise SimulationError(404, "NOT_FOUND", "Not found or not available to you")
    if version_id is not None:
        return version_context(db, c, markets, version_id, persist=persist)
    a = sx.current_assignment(db, case_id)
    if a is None:
        raise SimulationError(409, "NO_SCRIPT_ASSIGNED", "The case has no pinned script; assign one first (S2-C)")
    v = _one(
        db,
        "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "WHERE v.id = :v",
        v=a["script_version_id"],
    )
    assert v is not None
    if v["manifest_sha256"] != a["script_manifest_sha256"]:
        raise SimulationError(409, "PIN_MISMATCH", "The pinned script no longer matches its manifest checksum")
    snap = _one(db, "SELECT id, facts FROM policy_fact_snapshot WHERE id = :s", s=a["policy_fact_snapshot_id"])
    risk = (
        _one(db, "SELECT id, band_code FROM risk_assessment WHERE id = :r", r=a["risk_assessment_id"])
        if a["risk_assessment_id"]
        else None
    )
    assert snap is not None
    content = script_authoring.content_of(db, v)
    label = f"{v['family']} v{v['version_label']}"
    plan = qc.build_plan(
        content,
        script_label=label,
        manifest_sha256=v["manifest_sha256"],
        facts=snap["facts"] or {},
        band=risk["band_code"] if risk else None,
    )
    selected = (a.get("input_snapshot") or {}).get("selected_contact")
    return {
        "case": c,
        "assignment": a,
        "version": v,
        "snapshot": snap,
        "risk": risk,
        "plan": plan,
        "contacts": sx.contacts(db, case_id),
        "assignment_contact": selected,
        "content_approval_status": v["content_approval_status"],
        "content_sha256": None,
        "live_eligibility": None,
    }


def plan_json(plan: qc.Plan) -> dict[str, Any]:
    return asdict(plan)


def plan_from_json(d: dict[str, Any]) -> qc.Plan:
    return qc.Plan(
        d["script_label"],
        d["manifest_sha256"],
        tuple(qc.PlannedSection(**s) for s in d["sections"]),
        tuple(qc.PlannedQuestion(**{**q, "options": tuple(q["options"])}) for q in d["questions"]),
    )


def resolve_contact(ctx: dict[str, Any], selection_id: uuid.UUID | None) -> Contact:
    people = ctx["contacts"]
    pinned = ctx["assignment_contact"]
    if selection_id is not None:
        chosen = next((p for p in people if p.ref == str(selection_id)), None)
        if chosen is None:
            raise SimulationError(
                422, "CONTACT_NOT_ELIGIBLE", "That contact is not a current eligible callback contact"
            )
    elif pinned:
        chosen = next((p for p in people if p.ref == pinned["selection_id"]), None)
        if chosen is None:
            raise SimulationError(
                409, "ASSIGNMENT_CONTACT_NOT_ELIGIBLE", "The contact the script was assigned for is no longer eligible"
            )
    elif len(people) == 1:
        chosen = people[0]
    elif not people:
        raise SimulationError(409, "NO_ELIGIBLE_CONTACT", "The case has no eligible callback contact")
    else:
        raise SimulationError(422, "CONTACT_REQUIRED", "Choose which eligible callback contact the simulation calls")
    if pinned and chosen.ref != pinned["selection_id"]:
        raise SimulationError(
            409,
            "CONTACT_NOT_ASSIGNMENT_CONTACT",
            f"The script was assigned for the {pinned['role']} contact; simulate with that contact",
        )
    result: Contact = chosen
    return result


# ---- runs -------------------------------------------------------------------------------------------------------
def _append(db: Session, run_id: uuid.UUID, start_seq: int, events: list[qc.Event], actor: str) -> int:
    seq = start_seq
    for e in events:
        seq += 1
        db.execute(
            text(
                "INSERT INTO script_simulation_event (id, run_id, seq, event_type, question_code, action_id, data, "
                "actor_ref) VALUES (:i, :r, :s, :t, :q, :a, CAST(:d AS jsonb), :by)"
            ),
            {
                "i": uuid.uuid4(),
                "r": run_id,
                "s": seq,
                "t": e.type,
                "q": e.question_code,
                "a": e.action_id,
                "d": json.dumps(dict(e.data), default=str),
                "by": actor,
            },
        )
    return seq


def start(
    db: Session,
    case_id: uuid.UUID,
    markets: Sequence[str],
    actor: str,
    contact_selection_id: uuid.UUID | None,
    version_id: uuid.UUID | None = None,
) -> uuid.UUID:
    ctx = context(db, case_id, markets, version_id, persist=True)
    contact = resolve_contact(ctx, contact_selection_id)
    plan = ctx["plan"]
    pj = plan_json(plan)
    run_id = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM script_simulation_run")).scalar_one()
    ref = f"SIM-{ctx['case']['case_ref'][3:]}-{n:04d}"
    controller = qc.Controller(plan)
    events = controller.start()
    db.execute(
        text(
            "INSERT INTO script_simulation_run (id, sim_ref, callback_case_id, script_assignment_id, "
            "script_version_id, script_manifest_sha256, policy_fact_snapshot_id, risk_assessment_id, "
            "contact_selection_id, contact_role, plan, plan_sha256, status, started_by, started_at, mode, "
            "content_sha256) VALUES (:i, :ref, :c, :a, :v, :sha, :snap, :risk, :cs, "
            ":role, CAST(:plan AS jsonb), :psha, :st, :by, :t, :mode, :csha)"
        ),
        {
            "i": run_id,
            "ref": ref,
            "c": case_id,
            "a": ctx["assignment"]["id"] if ctx["assignment"] else None,
            "mode": "VERSION_TEST" if ctx["assignment"] is None else "TEXT_SIMULATION",
            "csha": ctx["content_sha256"],
            "v": ctx["version"]["id"],
            "sha": ctx["version"]["manifest_sha256"],
            "snap": ctx["snapshot"]["id"],
            "risk": ctx["risk"]["id"] if ctx["risk"] else None,
            "cs": uuid.UUID(contact.ref),
            "role": contact.role,
            "plan": json.dumps(pj),
            "psha": sha256_of(pj),
            "st": controller.state()["status"],
            "by": actor,
            "t": datetime.now(UTC),
        },
    )
    _append(db, run_id, 0, events, actor)
    return run_id


def run_row(db: Session, run_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT r.*, c.case_ref, c.market_code FROM script_simulation_run r JOIN callback_case c "
        "ON c.id = r.callback_case_id WHERE r.id = :r AND c.market_code = ANY(:m)"
        + (" FOR UPDATE OF r" if lock else ""),
        r=run_id,
        m=list(markets),
    )
    if r is None:
        raise SimulationError(404, "NOT_FOUND", "Not found or not available to you")
    return r


def events_of(db: Session, run_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT e.*, p.display_name FROM script_simulation_event e LEFT JOIN principal p "
        "ON CAST(p.id AS text) = e.actor_ref WHERE e.run_id = :r ORDER BY e.seq",
        r=run_id,
    )


def controller_for(db: Session, run: dict[str, Any]) -> tuple[qc.Controller, list[dict[str, Any]]]:
    rows = events_of(db, run["id"])
    events = [qc.Event(e["event_type"], e["question_code"], e["action_id"], e["data"] or {}) for e in rows]
    return qc.Controller(plan_from_json(run["plan"]), events), rows


def act(db: Session, run_id: uuid.UUID, markets: Sequence[str], actor: str, op: str, **kw: Any) -> list[qc.Event]:
    """Apply one controller operation to a run (serialised by a row lock) and persist the resulting events."""
    run = run_row(db, run_id, markets, lock=True)
    ctrl, rows = controller_for(db, run)
    if op == "delivery":
        new = ctrl.record_delivery(kw["action_id"], kw["delivered"], kw.get("note"))
    elif op == "answer":
        new = ctrl.submit_answer(kw["action_id"], kw["kind"], kw.get("value"), kw.get("verbatim"))
    elif op == "clarification":
        new = ctrl.request_clarification(kw["action_id"], kw["reason"])
    elif op == "skip":
        new = ctrl.skip(kw["action_id"])
    elif op == "report":
        new = ctrl.report(kw["kind"], kw.get("note"))
    elif op == "end":
        new = ctrl.end(abandon=kw["abandon"], reason=kw.get("reason"))
    else:
        raise SimulationError(422, "UNKNOWN_OPERATION", op)
    if new:
        _append(db, run_id, len(rows), new, actor)
        st = ctrl.state()["status"]
        outcome = ctrl.ended
        db.execute(
            text(
                "UPDATE script_simulation_run SET status = :s, outcome = CAST(:o AS text), ended_at = CASE WHEN "
                "CAST(:o AS text) IS NULL THEN NULL ELSE now() END, row_version = row_version + 1 WHERE id = :r"
            ),
            {"s": outcome if outcome else st, "o": outcome, "r": run_id},
        )
    return new


def runs_for_case(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT r.id, r.sim_ref, r.status, r.outcome, r.started_at, r.ended_at, r.contact_role, p.display_name, "
        "r.mode, "
        "f.code || ' v' || v.version_label AS script_label FROM script_simulation_run r LEFT JOIN principal p "
        "ON CAST(p.id AS text) = r.started_by JOIN script_version v ON v.id = r.script_version_id "
        "JOIN script_family f ON f.id = v.script_family_id "
        "WHERE r.callback_case_id = :c ORDER BY r.started_at DESC",
        c=case_id,
    )
