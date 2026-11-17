"""S2-C deterministic script assignment (SCR-004, SCR-011; SCRIPT_GOVERNANCE_AND_ASSIGNMENT "Assignment engine").

Uses the pure S2-B matcher (``rule_engine``) unchanged, over published rule versions effective at the evaluation time,
with the selected callback contact (D-62 as clarified). One decision per case:

- ``SELECTED`` / ``SELECTED_BY_FALLBACK`` → pin the published, effective script version in an immutable
  ``script_assignment`` (manifest checksum, matched rule version, full trace, input snapshot and SHA-256,
  origin ENGINE), release the case's ``AWAITING_SCRIPT_ASSIGNMENT`` hold (and an ``AWAITING_SCRIPT_REVIEW`` hold this
  engine placed earlier). Every other hold is untouched; the case state is not changed.
- ``AMBIGUOUS`` / ``AMBIGUOUS_SAME_TARGET`` → nothing is pinned; an ``AWAITING_SCRIPT_REVIEW`` hold is placed (once).
- ``NO_MATCH`` / ``INPUT_MISSING`` / ``TARGET_NOT_EFFECTIVE`` / ``CONTACT_UNRESOLVED`` → nothing is pinned; the case
  keeps its holds. No silent fallback: only an explicitly configured, approved fallback rule can select a script.

Each applied evaluation is recorded in the insert-only ``script_assignment_attempt`` ledger. A case that already has a
script assignment is never reassigned (``ALREADY_ASSIGNED``); a retried request with the same Idempotency-Key replays
the stored result. Assignment never creates a compliance outcome and never marks a case verified.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import rule_engine as re_
from app.domain import rule_inputs as ri
from app.domain.digest import sha256_of

ENGINE = "call360.assignment-engine/1 (S2-C)"
SOURCE_SYSTEM = "CALL360_ASSIGNMENT_ENGINE"
TERMINAL = ("VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED")
ASSIGN_HOLD, REVIEW_HOLD = "AWAITING_SCRIPT_ASSIGNMENT", "AWAITING_SCRIPT_REVIEW"
SUCCESS = ("SELECTED", "SELECTED_BY_FALLBACK")
AMBIGUOUS = ("AMBIGUOUS", "AMBIGUOUS_SAME_TARGET")


class AssignmentError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or {}


def _now() -> datetime:
    return datetime.now(UTC)


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def key_digest(key: str) -> str:
    return hashlib.sha256(f"script-assignment:{key}".encode()).hexdigest()


# ---- reading ----------------------------------------------------------------------------------------------------
def case_row(db: Session, case_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    c = _one(
        db,
        "SELECT * FROM callback_case WHERE id = :c AND market_code = ANY(:m)" + (" FOR UPDATE" if lock else ""),
        c=case_id,
        m=list(markets),
    )
    if c is None:
        raise AssignmentError(404, "NOT_FOUND", "Not found or not available to you")
    return c


def current_assignment(db: Session, case_id: uuid.UUID) -> dict[str, Any] | None:
    return _one(
        db,
        "SELECT a.*, f.id AS family_id, f.code AS family, v.version_label, rv.rule_code, rv.version AS rule_version "
        "FROM script_assignment a JOIN script_version v ON v.id = a.script_version_id JOIN script_family f "
        "ON f.id = v.script_family_id LEFT JOIN script_assignment_rule_version rv ON rv.id = a.matched_rule_version_id "
        "WHERE a.callback_case_id = :c AND NOT EXISTS (SELECT 1 FROM script_assignment x WHERE x.supersedes_id = a.id) "
        "ORDER BY a.assigned_at DESC LIMIT 1",
        c=case_id,
    )


def active_holds(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT id, hold_reason, is_blocking, placed_at, source, placed_reason FROM case_hold "
        "WHERE callback_case_id = :c AND released_at IS NULL ORDER BY placed_at, hold_reason",
        c=case_id,
    )


def contacts(db: Session, case_id: uuid.UUID) -> list[re_.Contact]:
    """Current eligible callback contact selections (never PII: role and the party's synthetic display alias)."""
    rows = _all(
        db,
        "SELECT s.id, ppr.role, coalesce(p.display_alias, p.party_ref) AS label FROM case_contact_selection s "
        "JOIN policy_party_role ppr ON ppr.id = s.policy_party_role_id JOIN party p ON p.id = s.party_id "
        "WHERE s.callback_case_id = :c AND s.eligible AND NOT EXISTS (SELECT 1 FROM case_contact_selection x "
        "WHERE x.supersedes_id = s.id) ORDER BY ppr.role, s.id",
        c=case_id,
    )
    return [re_.Contact(str(r["id"]), r["role"], r["label"] or "") for r in rows]


def _trace_json(d: re_.Decision) -> list[dict[str, Any]]:
    return [
        {
            "ref": t.ref,
            "rule_code": t.rule_code,
            "priority": t.priority,
            "specificity": t.specificity,
            "is_fallback": t.is_fallback,
            "target_label": t.target_label,
            "eligible": t.eligible,
            "excluded_reason": t.excluded_reason,
            "match": t.match,
            "selected": t.selected,
            "tied": t.tied,
            "conditions": [c.__dict__ for c in t.conditions],
        }
        for t in d.trace
    ]


def evaluate(db: Session, case_id: uuid.UUID, markets: Sequence[str], at: datetime) -> dict[str, Any]:
    """The deterministic decision for one case at ``at`` (read-only). Includes eligibility, inputs, contact
    resolution, trace, the holds that applying would release or place, and a decision SHA-256 for apply."""
    c = case_row(db, case_id, markets)
    existing = current_assignment(db, case_id)
    holds = active_holds(db, case_id)
    found = ri.case_inputs(db, markets, [case_id])
    inputs = found[0].inputs if found else {}
    snap = _one(
        db,
        "SELECT id, captured_at FROM policy_fact_snapshot WHERE sale_event_id = :s ORDER BY captured_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    risk = _one(
        db,
        "SELECT id, band_code FROM risk_assessment WHERE sale_event_id = :s AND status = 'FINAL' "
        "ORDER BY valid_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    rules = [r for r in ri.published_candidates(db, markets, at)]
    people = contacts(db, case_id)
    decision, resolution = re_.evaluate_for_contacts(rules, inputs, people, at)
    if snap is None and decision.outcome in SUCCESS:  # the pin needs the policy fact snapshot it was based on
        decision = re_.Decision(
            "INPUT_MISSING",
            None,
            None,
            [],
            "No policy fact snapshot for the case sale; assignment needs triage",
            decision.trace,
        )
    eligible, blocked = True, None
    if c["state"] in TERMINAL:
        eligible, blocked = False, f"The case is {c['state'].replace('_', ' ').lower()}; no script is assigned"
    elif existing is not None:
        eligible, blocked = False, "The case already has a pinned script version; it is never reassigned automatically"
    winner = next((r for r in rules if decision.winning_rules and r.ref == decision.winning_rules[0]), None)
    target = (
        _one(
            db,
            "SELECT v.id, v.manifest_sha256, v.version_label, v.content_approval_status, f.id AS family_id, "
            "f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id WHERE v.id = :v",
            v=uuid.UUID(decision.selected_target_id),
        )
        if decision.selected_target_id
        else None
    )
    labels = ri.labels(ri.options(db, markets))
    explanation = (
        re_.explain(
            list(winner.conditions), winner.target_label, winner.priority, is_fallback=winner.is_fallback, labels=labels
        )
        if winner is not None and decision.outcome in SUCCESS  # a tie or failure selects nothing: no "Assign …" text
        else None
    )
    release = (
        [
            h["hold_reason"]
            for h in holds
            if h["hold_reason"] == ASSIGN_HOLD or (h["hold_reason"] == REVIEW_HOLD and h["source"] == "SYSTEM")
        ]
        if decision.outcome in SUCCESS
        else []
    )
    place = (
        [REVIEW_HOLD]
        if decision.outcome in AMBIGUOUS and not any(h["hold_reason"] == REVIEW_HOLD for h in holds)
        else []
    )
    remaining = [h["hold_reason"] for h in holds if h["is_blocking"] and h["hold_reason"] not in release]
    snapshot = {
        "engine": ENGINE,
        "case_ref": c["case_ref"],
        "evaluated_at": at.isoformat(),
        "inputs": inputs,
        "selected_contact": {"selection_id": resolution.selected.ref, "role": resolution.selected.role}
        if resolution.selected
        else None,
        "contact_resolution": resolution.status,
        "policy_fact_snapshot_id": str(snap["id"]) if snap else None,
        "risk_assessment_id": str(risk["id"]) if risk else None,
        "rules_considered": sorted(r.ref for r in rules),
    }
    decision_json = {
        "outcome": decision.outcome,
        "reason": decision.reason,
        "selected_script_version_id": decision.selected_target_id,
        "selected_script_label": decision.selected_target_label,
        "determinable_script_label": decision.determinable_target_label,
        "winning_rules": decision.winning_rules,
        "explanation": explanation,
        "contact_resolution": {
            "status": resolution.status,
            "selected": {
                "selection_id": resolution.selected.ref,
                "role": resolution.selected.role,
                "label": resolution.selected.label,
            }
            if resolution.selected
            else None,
            "considered": resolution.considered,
            "explanation": resolution.explanation,
        },
        "trace": _trace_json(decision),
        "precedence": "priority (lower wins), then specificity (higher wins); equal rank fails closed (D-58)",
    }
    return {
        "case": c,
        "eligible": eligible,
        "blocked_reason": blocked,
        "existing": existing,
        "holds": holds,
        "decision": decision,
        "decision_json": decision_json,
        "winner": winner,
        "target": target,
        "risk": risk,
        "snapshot_row": snap,
        "input_snapshot": snapshot,
        "input_sha256": sha256_of(
            snapshot["inputs"]
            | {
                "selected_contact": snapshot["selected_contact"],
                "policy_fact_snapshot_id": snapshot["policy_fact_snapshot_id"],
                "risk_assessment_id": snapshot["risk_assessment_id"],
            }
        ),
        "decision_sha256": sha256_of(
            {
                "outcome": decision.outcome,
                "target": decision.selected_target_id,
                "rules": decision.winning_rules,
                "inputs": snapshot["inputs"],
                "contact": snapshot["selected_contact"],
            }
        ),
        "would_release": release,
        "would_place": place,
        "remaining_blocking": remaining,
    }


# ---- applying ---------------------------------------------------------------------------------------------------
def _event(
    db: Session, case_id: uuid.UUID, kind: str, actor: str, summary: str, entity: tuple[str, Any] | None, now: datetime
) -> None:
    db.execute(
        text(
            "INSERT INTO case_event (id, callback_case_id, event_type, occurred_at, actor_ref, related_entity_type, "
            "related_entity_id, summary, created_by) VALUES (:i, :c, :k, :t, :a, :et, :eid, :s, :a)"
        ),
        {
            "i": uuid.uuid4(),
            "c": case_id,
            "k": kind,
            "t": now,
            "a": actor,
            "et": entity[0] if entity else None,
            "eid": entity[1] if entity else None,
            "s": summary[:500],
        },
    )


def _replay(db: Session, digest: str, case_id: uuid.UUID) -> dict[str, Any] | None:
    a = _one(db, "SELECT * FROM script_assignment_attempt WHERE idempotency_key_sha256 = :k", k=digest)
    if a is None:
        return None
    if a["callback_case_id"] != case_id:
        raise AssignmentError(409, "IDEMPOTENCY_KEY_REUSED", "This Idempotency-Key was used for another case")
    return a


def apply(
    db: Session,
    case_id: uuid.UUID,
    markets: Sequence[str],
    actor_ref: str,
    *,
    idempotency_key: str,
    expected_decision_sha256: str | None,
    trigger: str = "CASE",
) -> dict[str, Any]:
    """Apply the deterministic decision to one case inside the caller's transaction. Returns a summary dict with
    ``status`` ASSIGNED | NOT_ASSIGNED | ALREADY_ASSIGNED | REPLAYED and the attempt / assignment ids."""
    digest = key_digest(idempotency_key)
    prior = _replay(db, digest, case_id)
    if prior is not None:
        return {"status": "REPLAYED", "attempt": prior}
    case_row(db, case_id, markets, lock=True)  # serialise concurrent applies on one case
    now = _now()
    ev = evaluate(db, case_id, markets, now)
    if ev["existing"] is not None:
        return {"status": "ALREADY_ASSIGNED", "existing": ev["existing"], "evaluation": ev}
    if not ev["eligible"]:
        raise AssignmentError(409, "CASE_NOT_ELIGIBLE", ev["blocked_reason"] or "Not eligible for assignment")
    if expected_decision_sha256 and expected_decision_sha256 != ev["decision_sha256"]:
        raise AssignmentError(
            409,
            "PREVIEW_STALE",
            "The rules or case inputs changed since your preview; preview again before applying",
            {"decision_sha256": ev["decision_sha256"]},
        )
    d: re_.Decision = ev["decision"]
    c = ev["case"]
    assignment_id = None
    released: list[str] = []
    placed: list[str] = []
    if d.outcome in SUCCESS:
        winner, target = ev["winner"], ev["target"]
        rv = _one(
            db,
            "SELECT id FROM script_assignment_rule_version WHERE rule_code = :c AND version = :v",
            c=winner.rule_code,
            v=winner.version,
        )
        assert rv is not None and target is not None
        trace = {
            "label": "Deterministic assignment by the Call360 assignment engine (S2-C); no compliance outcome",
            "engine": ENGINE,
            "matched": winner.ref,
            "excluded": [
                {
                    "rule": t["ref"],
                    "reason": t["excluded_reason"]
                    or ("lower precedence" if t["match"] == "MATCH" else t["match"].replace("_", " ").lower()),
                }
                for t in ev["decision_json"]["trace"]
                if t["ref"] != winner.ref
            ],
            "precedence": ev["decision_json"]["precedence"],
            "decision": ev["decision_json"],
        }
        assignment_id = uuid.uuid4()
        db.execute(
            text(
                "INSERT INTO script_assignment (id, callback_case_id, script_version_id, script_manifest_sha256, "
                "risk_assessment_id, policy_fact_snapshot_id, matched_rule_version_id, rule_trace, input_snapshot, "
                "input_sha256, origin, assigned_at, assigned_by, created_by, source_type, source_system, "
                "source_reference, source_observed_at, recorded_at, is_synthetic) VALUES (:id, :c, :v, :sha, :risk, "
                ":snap, :rv, CAST(:trace AS jsonb), CAST(:inp AS jsonb), :inh, 'ENGINE', :t, :by, :by, 'INTERNAL_API', "
                ":ss, :sr, :t, :t, true)"
            ),
            {
                "id": assignment_id,
                "c": case_id,
                "v": target["id"],
                "sha": target["manifest_sha256"],
                "risk": ev["risk"]["id"] if ev["risk"] else None,
                "snap": ev["snapshot_row"]["id"],
                "rv": rv["id"],
                "trace": json.dumps(trace, default=str),
                "inp": json.dumps(ev["input_snapshot"], default=str),
                "inh": ev["input_sha256"],
                "t": now,
                "by": actor_ref,
                "ss": SOURCE_SYSTEM,
                "sr": f"assignment:{c['case_ref']}:{winner.ref}"[:160],
            },
        )
        _event(
            db,
            case_id,
            "SCRIPT_ASSIGNED",
            actor_ref,
            f"Script {target['family']} v{target['version_label']} pinned by rule {winner.ref}"
            f"{' (default fallback)' if winner.is_fallback else ''}",
            ("script_assignment", assignment_id),
            now,
        )
        for h in ev["holds"]:
            if h["hold_reason"] in ev["would_release"]:
                db.execute(
                    text(
                        "UPDATE case_hold SET released_at = :t, released_by = :by, release_reason = :r, "
                        "updated_at = :t, updated_by = :by, row_version = row_version + 1 WHERE id = :i"
                    ),
                    {
                        "t": now,
                        "by": actor_ref,
                        "i": h["id"],
                        "r": f"Script assigned: {target['family']} v{target['version_label']} by rule {winner.ref}",
                    },
                )
                released.append(h["hold_reason"])
                _event(
                    db,
                    case_id,
                    "HOLD_RELEASED",
                    actor_ref,
                    f"Hold released: {h['hold_reason']} (script assigned)",
                    ("case_hold", h["id"]),
                    now,
                )
    elif d.outcome in AMBIGUOUS and ev["would_place"]:
        lv = _one(
            db,
            "SELECT lv.id FROM code_list_version lv JOIN code_list l ON l.id = lv.code_list_id "
            "WHERE l.code = 'case_hold_reason' AND lv.status = 'ACTIVE'",
        )
        assert lv is not None
        hid = uuid.uuid4()
        db.execute(
            text(
                "INSERT INTO case_hold (id, callback_case_id, hold_reason, hold_reason_list_version_id, is_blocking, "
                "placed_at, placed_by, placed_reason, source, created_by) VALUES (:i, :c, :r, :lv, false, :t, :by, "
                ":pr, 'SYSTEM', :by)"
            ),
            {
                "i": hid,
                "c": case_id,
                "r": REVIEW_HOLD,
                "lv": lv["id"],
                "t": now,
                "by": actor_ref,
                "pr": f"Ambiguous script assignment: {', '.join(d.winning_rules)} tie (D-58, T-40)"[:500],
            },
        )
        placed.append(REVIEW_HOLD)
        _event(
            db,
            case_id,
            "HOLD_PLACED",
            actor_ref,
            f"Hold placed: {REVIEW_HOLD} (ambiguous script rules)",
            ("case_hold", hid),
            now,
        )
    attempt_id = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO script_assignment_attempt (id, callback_case_id, outcome, applied, script_assignment_id, "
            "reason, decision, input_snapshot, input_sha256, decision_sha256, holds_released, holds_placed, "
            "idempotency_key_sha256, trigger, actor_ref, evaluated_at) VALUES (:i, :c, :o, :ap, :sa, :r, "
            "CAST(:d AS jsonb), CAST(:inp AS jsonb), :inh, :dh, CAST(:rel AS jsonb), CAST(:pl AS jsonb), :k, :tr, "
            ":a, :t)"
        ),
        {
            "i": attempt_id,
            "c": case_id,
            "o": d.outcome,
            "ap": assignment_id is not None,
            "sa": assignment_id,
            "r": d.reason,
            "d": json.dumps(ev["decision_json"], default=str),
            "inp": json.dumps(ev["input_snapshot"], default=str),
            "inh": ev["input_sha256"],
            "dh": ev["decision_sha256"],
            "rel": json.dumps(released),
            "pl": json.dumps(placed),
            "k": digest,
            "tr": trigger,
            "a": actor_ref,
            "t": now,
        },
    )
    attempt = _one(db, "SELECT * FROM script_assignment_attempt WHERE id = :i", i=attempt_id)
    return {"status": "ASSIGNED" if assignment_id else "NOT_ASSIGNED", "attempt": attempt, "evaluation": ev}


def attempts(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT a.*, p.display_name FROM script_assignment_attempt a LEFT JOIN principal p "
        "ON CAST(p.id AS text) = a.actor_ref WHERE a.callback_case_id = :c ORDER BY a.created_at DESC",
        c=case_id,
    )


def unassigned_cases(db: Session, markets: Sequence[str], case_ids: Sequence[uuid.UUID] | None) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT c.id, c.case_ref, c.state FROM callback_case c WHERE c.market_code = ANY(:m) "
        "AND c.state NOT IN ('VERIFIED', 'CLOSED_UNVERIFIED', 'CANCELLED') "
        "AND NOT EXISTS (SELECT 1 FROM script_assignment a WHERE a.callback_case_id = c.id) "
        "AND (CAST(:ids AS uuid[]) IS NULL OR c.id = ANY(CAST(:ids AS uuid[]))) ORDER BY c.case_ref",
        m=list(markets),
        ids=list(case_ids) if case_ids is not None else None,
    )
