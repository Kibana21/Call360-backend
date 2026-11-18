"""S3-C human review and case resolution (REV-002/003/004, COMP-007 inputs, COMP-009, S3-A5; BRD §3.1, UX-07).

Everything is deterministic and backend-owned; no LLM and no autonomous approval.

**Finding dispositions** (finding statuses are the S0 set OPEN / UNDER_REVIEW / CONFIRMED / DISMISSED / CLOSED):
START_REVIEW OPEN → UNDER_REVIEW; CONFIRM OPEN|UNDER_REVIEW → CONFIRMED; DISMISS OPEN|UNDER_REVIEW → DISMISSED;
REQUEST_INFORMATION (recorded; OPEN → UNDER_REVIEW); RESOLVE CONFIRMED → CLOSED. Dismissing or resolving a
**material** finding (severity in the governed ``finding_materiality_policy``) is a protected outcome: it becomes a
request that a different user holding ``review.approve`` approves (REV-004, S3-A5). The original finding and its
evidence never change; every action is an insert-only ``review_decision`` with a reason.

**Case actions** (existing BRD §3.1 states): REQUEST_CALLBACK AWAITING_REVIEW|ESCALATED → AWAITING_CALLBACK;
ESCALATE AWAITING_REVIEW|AWAITING_CALLBACK|IN_PROGRESS → ESCALATED with a REV-003 reason code; RETURN_TO_REVIEW
ESCALATED|AWAITING_CALLBACK → AWAITING_REVIEW. RAISE_FINDING (reviewer-origin finding for an unconverted discrepancy or
a concern) and ASSESS_ANSWER (human assessment of a narrative answer) are recorded review actions.

**Case decisions** are always maker-checker: a reviewer proposes VERIFY (AWAITING_REVIEW → VERIFIED) or
CLOSE_UNVERIFIED (AWAITING_REVIEW|ESCALATED|AWAITING_CALLBACK → CLOSED_UNVERIFIED with a governed closure reason); a
different user with ``review.approve`` approves or rejects. VERIFY is refused unless every readiness check passes, and
the checks run again at approval. A case is never verified merely because the conversation completed, answers matched
or no finding exists: identity and lifecycle gates, evidence completeness, unresolved mandatory questions, unconverted
discrepancies, human assessments, outstanding findings, pending approvals and blocking holds are all checked; missing
evidence is never success. Optimistic concurrency (case and finding row versions; a proposal goes STALE when they
change) and idempotency keys (a repeated submission returns the original) prevent overwrites and duplicates.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import governed, script_authoring
from app.domain import question_controller as qc

DECIDE = "review.decide"
APPROVE = "review.approve"
TERMINAL_FINDING = ("DISMISSED", "CLOSED")
FINDING_ACTIONS: dict[str, dict[str, Any]] = {
    "START_REVIEW": {"from": ("OPEN",), "to": "UNDER_REVIEW", "label": "Start review"},
    "CONFIRM": {"from": ("OPEN", "UNDER_REVIEW"), "to": "CONFIRMED", "label": "Confirm discrepancy"},
    "DISMISS": {
        "from": ("OPEN", "UNDER_REVIEW"),
        "to": "DISMISSED",
        "label": "Dismiss with justification",
        "protected": True,
    },
    "REQUEST_INFORMATION": {
        "from": ("OPEN", "UNDER_REVIEW", "CONFIRMED"),
        "to": None,
        "label": "Request additional information",
    },
    "RESOLVE": {"from": ("CONFIRMED",), "to": "CLOSED", "label": "Resolve", "protected": True},
}
CASE_ACTIONS: dict[str, dict[str, Any]] = {
    "REQUEST_CALLBACK": {
        "from": ("AWAITING_REVIEW", "ESCALATED"),
        "to": "AWAITING_CALLBACK",
        "label": "Request a further callback",
    },
    "ESCALATE": {
        "from": ("AWAITING_REVIEW", "AWAITING_CALLBACK", "IN_PROGRESS"),
        "to": "ESCALATED",
        "label": "Escalate for investigation",
    },
    "RETURN_TO_REVIEW": {
        "from": ("ESCALATED", "AWAITING_CALLBACK"),
        "to": "AWAITING_REVIEW",
        "label": "Return to review",
    },
}
DECISIONS: dict[str, dict[str, Any]] = {
    "VERIFY": {"from": ("AWAITING_REVIEW",), "to": "VERIFIED", "label": "Verify the case"},
    "CLOSE_UNVERIFIED": {
        "from": ("AWAITING_REVIEW", "ESCALATED", "AWAITING_CALLBACK"),
        "to": "CLOSED_UNVERIFIED",
        "label": "Close unverified",
    },
}
# REV-003 escalation reasons (requirement text: mis-selling concern, complaint, human request, fraud). Pending
# business confirmation of the list; nothing else is assumed.
ESCALATION_REASONS = {
    "MIS_SELLING_CONCERN": "Mis-selling concern",
    "COMPLAINT": "Complaint",
    "HUMAN_REQUEST": "Customer asked for a person",
    "FRAUD_SUSPECTED": "Suspected fraud",
}
ASSESSMENTS = ("SATISFACTORY", "CONCERN")
NON_ANSWER_STATES = ("UNKNOWN", "UNCLEAR", "REFUSED", "NOT_ASKED")
MEDIA_INCOMPLETE = ("CAPTURE_PENDING", "CAPTURING", "UPLOADING", "FAILED")
CLASS_OF_RESULT = {"MISMATCH": "CUSTOMER_DISCREPANCY", "INDETERMINATE": "MISSING_EVIDENCE"}


class ReviewError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


@dataclass(frozen=True)
class Actor:
    principal_id: str
    permissions: frozenset[str]
    markets: tuple[str, ...]


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def _need(actor: Actor, perm: str) -> None:
    if perm not in actor.permissions:
        raise ReviewError(403, "FORBIDDEN", f"You need {perm} for this action")


def _reason(reason: str | None) -> str:
    r = (reason or "").strip()
    if not 5 <= len(r) <= 1000:
        raise ReviewError(422, "REASON_REQUIRED", "Give a reason (5–1000 characters); every review action needs one")
    return r


def material_severities(db: Session) -> list[str]:
    return [
        r["code"]
        for r in _all(
            db,
            "SELECT v.code FROM code_value v WHERE v.code_list_version_id = :lv "
            "AND (v.attributes->>'material')::boolean",
            lv=governed.version_id("finding_materiality_policy"),
        )
    ]


# ---- loading ---------------------------------------------------------------------------------------------------
def case_row(db: Session, case_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    c = _one(
        db,
        "SELECT * FROM callback_case WHERE id = :c AND market_code = ANY(:m)" + (" FOR UPDATE" if lock else ""),
        c=case_id,
        m=list(markets),
    )
    if c is None:
        raise ReviewError(404, "NOT_FOUND", "Case not found or not available to you")
    return c


def finding_row(db: Session, finding_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    f = _one(
        db,
        "SELECT f.* FROM finding f JOIN callback_case c ON c.id = f.callback_case_id WHERE f.id = :f "
        "AND c.market_code = ANY(:m)" + (" FOR UPDATE OF f" if lock else ""),
        f=finding_id,
        m=list(markets),
    )
    if f is None:
        raise ReviewError(404, "NOT_FOUND", "Finding not found or not available to you")
    return f


def latest_run(db: Session, case_id: uuid.UUID) -> dict[str, Any] | None:
    return _one(
        db,
        "SELECT r.*, cs.id AS session_id, cs.session_ref, cs.state AS session_state, cs.transport, cs.media_status, "
        "cs.transcript_status, cs.record_origin AS session_origin, cs.risk_assessment_id, "
        "cs.policy_fact_snapshot_sha256, a.attempt_ref, a.status AS attempt_status FROM survey_run r "
        "JOIN conversation_session cs ON cs.id = r.session_id JOIN contact_attempt a ON a.id = cs.contact_attempt_id "
        "WHERE a.callback_case_id = :c ORDER BY (r.status = 'COMPLETED') DESC, r.started_at DESC LIMIT 1",
        c=case_id,
    )


def _executions(db: Session, run_id: uuid.UUID) -> dict[str, dict[str, Any]]:
    rows = _all(
        db,
        "SELECT qe.id, qe.position, qe.delivery_status, qbi.question_code, qe.question_revision_id, "
        "ao.id AS observation_id, ao.answer_state, ao.typed_value, ao.verbatim_text_redacted, ao.extraction_engine, "
        "re.id AS rule_evaluation_id, re.rule_ref, re.rule_version, re.expected, re.observed, re.result "
        "FROM question_execution qe JOIN question_revision qr ON qr.id = qe.question_revision_id "
        "JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id "
        "LEFT JOIN LATERAL (SELECT * FROM answer_observation ao WHERE ao.question_execution_id = qe.id AND NOT EXISTS "
        "  (SELECT 1 FROM answer_observation x WHERE x.supersedes_id = ao.id) ORDER BY ao.created_at DESC LIMIT 1) ao "
        "  ON true "
        "LEFT JOIN LATERAL (SELECT * FROM rule_evaluation re WHERE re.question_execution_id = qe.id "
        "  ORDER BY re.evaluated_at DESC LIMIT 1) re ON true WHERE qe.survey_run_id = :r ORDER BY qe.position",
        r=run_id,
    )
    return {r["question_code"]: r for r in rows}


def _plan(db: Session, run: Mapping[str, Any]) -> tuple[qc.Plan, dict[str, Any], dict[str, Any]]:
    v = _one(
        db,
        "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "WHERE v.id = :v",
        v=run["script_version_id"],
    )
    assert v is not None
    content = script_authoring.content_of(db, v)
    snap = _one(
        db, "SELECT id, sha256, facts FROM policy_fact_snapshot WHERE id = :f", f=run["policy_fact_snapshot_id"]
    )
    risk = _one(db, "SELECT band_code FROM risk_assessment WHERE id = :r", r=run["risk_assessment_id"])
    facts = dict((snap or {}).get("facts") or {})
    plan = qc.build_plan(
        content,
        script_label=f"{v['family']} v{v['version_label']}",
        manifest_sha256=run["script_manifest_sha256"],
        facts=facts,
        band=(risk or {}).get("band_code"),
    )
    return plan, content, {"version": v, "snapshot": snap, "facts": facts, "band": (risk or {}).get("band_code")}


def findings_of(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT f.*, qbi.question_code, (SELECT a.id FROM review_approval a WHERE a.finding_id = f.id AND "
        "a.status = 'PENDING') AS pending_approval_id FROM finding f "
        "LEFT JOIN question_execution qe ON qe.id = f.question_execution_id "
        "LEFT JOIN question_revision qr ON qr.id = qe.question_revision_id "
        "LEFT JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id "
        "WHERE f.callback_case_id = :c ORDER BY f.raised_at, f.finding_ref",
        c=case_id,
    )


def assessments_of(db: Session, case_id: uuid.UUID) -> dict[uuid.UUID, dict[str, Any]]:
    out: dict[uuid.UUID, dict[str, Any]] = {}
    for r in _all(
        db,
        "SELECT * FROM review_decision WHERE callback_case_id = :c AND action = 'ASSESS_ANSWER' ORDER BY decided_at",
        c=case_id,
    ):
        out[r["question_execution_id"]] = r  # latest wins (insert-only history keeps the earlier ones)
    return out


def finding_class(f: Mapping[str, Any], result: str | None) -> str:
    ev = f.get("evidence_refs") or {}
    if ev.get("finding_class"):
        return str(ev["finding_class"])
    if f.get("origin") == "NARRATIVE_FLAG":
        return "HUMAN_ASSESSMENT"
    return CLASS_OF_RESULT.get(str(result), "CUSTOMER_DISCREPANCY")


# ---- readiness -------------------------------------------------------------------------------------------------
def readiness(db: Session, case: Mapping[str, Any], *, exclude_approval_id: Any = None) -> dict[str, Any]:
    """Every check a VERIFY decision needs. Missing evidence fails a check; nothing is assumed. When a checker decides
    an approval request, that request itself is excluded from the pending-approval check (``exclude_approval_id``);
    every other pending request still blocks."""
    checks: list[dict[str, Any]] = []

    def add(code: str, label: str, ok: bool, detail: str) -> None:
        checks.append({"code": code, "label": label, "ok": ok, "detail": detail})

    add(
        "CASE_STATE",
        "Case is awaiting review",
        case["state"] == "AWAITING_REVIEW",
        f"Case state is {case['state']}"
        + ("" if case["state"] == "AWAITING_REVIEW" else "; VERIFY needs AWAITING_REVIEW"),
    )
    add(
        "NO_BLOCKING_HOLD",
        "No blocking hold",
        not case["has_blocking_hold"],
        "No active blocking hold"
        if not case["has_blocking_hold"]
        else "An active blocking hold must be released first",
    )
    pending = _one(
        db,
        "SELECT approval_ref FROM review_approval WHERE callback_case_id = :c AND status = 'PENDING' "
        "AND (CAST(:x AS uuid) IS NULL OR id <> CAST(:x AS uuid)) ORDER BY approval_ref LIMIT 1",
        c=case["id"],
        x=str(exclude_approval_id) if exclude_approval_id else None,
    )
    add(
        "NO_PENDING_APPROVAL",
        "No other pending approval" if exclude_approval_id else "No pending approval",
        pending is None,
        ("None besides this request" if exclude_approval_id else "None")
        if pending is None
        else f"{pending['approval_ref']} is awaiting a checker",
    )
    run = latest_run(db, case["id"])
    if run is None:
        add(
            "CONVERSATION_COMPLETED",
            "A conversation was completed",
            False,
            "No conversation is recorded for this case: there is no evidence to verify",
        )
        return {"ready": False, "checks": checks, "run": None}
    add(
        "CONVERSATION_COMPLETED",
        "A conversation was completed",
        run["status"] == "COMPLETED" and run["session_state"] in ("COMPLETED", "FINALIZED"),
        f"{run['session_ref']}: survey run {run['status']}, session {run['session_state']}",
    )
    plan, content, ctx = _plan(db, run)
    ex = _executions(db, run["id"])
    rules = ae.rules_of(content)
    applicable = [q for q in plan.questions if q.applicable]

    def answered_yes(q: qc.PlannedQuestion) -> bool:
        e = ex.get(q.code)
        return bool(e and e["answer_state"] == "YES")

    ident = [q for q in applicable if q.role == "IDENTITY_CHECK"]
    add(
        "IDENTITY_GATE",
        "Identity check answered (simulated outcome — not identity assurance)",
        bool(ident) and all(answered_yes(q) for q in ident),
        "The pinned script has no identity check, so identity was not evidenced (PARTY-006)"
        if not ident
        else ", ".join(f"{q.code}: {(ex.get(q.code) or {}).get('answer_state') or 'not recorded'}" for q in ident)
        + " — a scripted synthetic answer; no real identity verification was performed",
    )
    gate_problems = []
    proceed = [q for q in applicable if q.role == "CONSENT_TO_PROCEED"]
    if not proceed:
        gate_problems.append("no consent to proceed item in the pinned script")
    for q in proceed:
        st = (ex.get(q.code) or {}).get("answer_state")
        if st != "YES":
            gate_problems.append(f"{q.code}: consent to proceed {st or 'not recorded'}")
    for q in (q for q in applicable if q.role == "DISCLOSURE"):
        if (ex.get(q.code) or {}).get("delivery_status") != "DELIVERED":
            gate_problems.append(f"{q.code}: disclosure not delivered")
    add(
        "LIFECYCLE_GATES",
        "Consent to proceed given and disclosures delivered",
        not gate_problems,
        "; ".join(gate_problems) or "Consent to proceed given; disclosures delivered",
    )
    # Recording consent: the decision must be RECORDED (granted or declined); GRANTED is reported separately and is
    # what permits a recording. A declined decision is valid, but a recording made despite it fails.
    rec_items = [q for q in applicable if q.role == "RECORDING_CONSENT"]
    rec_states = {q.code: (ex.get(q.code) or {}).get("answer_state") for q in rec_items}
    media_status = run.get("media_status")
    rec_problems = [
        f"{c}: no recording-consent decision ({st or 'not recorded'})"
        for c, st in rec_states.items()
        if st not in ("YES", "NO")
    ]
    if not rec_items:
        rec_problems.append("no recording consent item in the pinned script")
    declined = any(st == "NO" for st in rec_states.values())
    if declined and media_status not in (None, "NOT_REQUIRED", "NOT_RECORDED"):
        rec_problems.append(f"recording consent DECLINED but the session media status is {media_status}")
    add(
        "RECORDING_CONSENT",
        "Recording consent decision recorded (granted or declined)",
        not rec_problems,
        "; ".join(rec_problems)
        or "; ".join(
            f"{c}: recorded — "
            + ("GRANTED (recording permitted)" if st == "YES" else "DECLINED (recording not permitted)")
            for c, st in rec_states.items()
        ),
    )
    unresolved = []
    for q in applicable:
        if not q.mandatory or q.completes_on_delivery:
            continue
        e = ex.get(q.code)
        if e is None or e["observation_id"] is None or e["answer_state"] in NON_ANSWER_STATES:
            unresolved.append(f"{q.code} ({(e or {}).get('answer_state') or 'no answer recorded'})")
    add(
        "MANDATORY_ANSWERED",
        "Every applicable mandatory question answered",
        not unresolved,
        "Unresolved: " + "; ".join(unresolved) if unresolved else "All answered",
    )
    missing = []
    for sec in content.get("sections", []):
        for qd in sec.get("questions", []):
            code = qd["question_code"]
            if not any(q.code == code for q in applicable) or not qd.get("evidence_required"):
                continue
            e = ex.get(code)
            if e is None or e["delivery_status"] != "DELIVERED" or e["observation_id"] is None:
                missing.append(
                    f"{code}: {'not executed' if e is None else e['delivery_status'].lower().replace('_', ' ')}"
                )
    if run["media_status"] in MEDIA_INCOMPLETE:
        missing.append(f"recording {run['media_status'].lower().replace('_', ' ')}")
    add(
        "EVIDENCE_COMPLETE",
        "Required evidence present",
        not missing,
        "; ".join(missing)
        if missing
        else f"Structured answers present; recording {run['media_status'].lower()}; "
        f"transcript {run['transcript_status'].lower()} (not required for synthetic structured fixtures)",
    )
    findings = findings_of(db, case["id"])
    by_qe: dict[Any, list[dict[str, Any]]] = {}
    for f in findings:
        by_qe.setdefault(f["question_execution_id"], []).append(f)
    assessed = assessments_of(db, case["id"])
    unconverted, undisposed = [], []
    for code, e in ex.items():
        if e["result"] not in ("MISMATCH", "INDETERMINATE"):
            continue
        fs = by_qe.get(e["id"], [])
        if not fs:
            unconverted.append(f"{code} ({e['result'].lower()}, no finding)")
        elif not all(f["status"] in TERMINAL_FINDING for f in fs):
            undisposed.append(code)
    add(
        "DISCREPANCIES_DISPOSITIONED",
        "Every discrepancy raised as a finding and dispositioned",
        not unconverted and not undisposed,
        "; ".join([*unconverted, *(f"{c}: finding not yet dismissed or resolved" for c in undisposed)]) or "None open",
    )
    narrative = []
    for q in applicable:
        r = rules.get(q.code)
        if not q.mandatory or not r or r.method != "NARRATIVE_REVIEW":
            continue
        e = ex.get(q.code)
        if e is None:
            continue
        a = assessed.get(e["id"])
        fs = by_qe.get(e["id"], [])
        ok = (a is not None and a["reason_code"] == "SATISFACTORY") or (
            bool(fs) and all(f["status"] in TERMINAL_FINDING for f in fs)
        )
        if not ok:
            narrative.append(q.code)
    add(
        "HUMAN_ASSESSMENT",
        "Narrative answers assessed by a person",
        not narrative,
        "Not yet assessed: " + ", ".join(narrative) if narrative else "None outstanding",
    )
    open_f = [
        f"{f['finding_ref']} ({f['status'].lower().replace('_', ' ')})"
        for f in findings
        if f["status"] not in TERMINAL_FINDING
    ]
    add(
        "FINDINGS_DISPOSITIONED",
        "No outstanding findings",
        not open_f,
        "Outstanding: " + ", ".join(open_f) if open_f else f"{len(findings)} finding(s), all dismissed or resolved",
    )
    return {
        "ready": all(c["ok"] for c in checks),
        "checks": checks,
        "run": {"survey_run_id": str(run["id"]), "session_ref": run["session_ref"], "status": run["status"]},
    }


# ---- recording decisions ---------------------------------------------------------------------------------------
def _existing(db: Session, key: str, actor: Actor) -> dict[str, Any] | None:
    r = _one(db, "SELECT * FROM review_decision WHERE idempotency_key = :k", k=key)
    if r is not None and r["actor_ref"] != actor.principal_id:
        raise ReviewError(409, "IDEMPOTENCY_KEY_REUSED", "That submission key belongs to another action")
    return r


def _record(
    db: Session,
    *,
    case: Mapping[str, Any],
    action: str,
    reason: str,
    actor: Actor,
    permission: str,
    key: str,
    case_after: str | None = None,
    finding_id: Any = None,
    qe_id: Any = None,
    approval_id: Any = None,
    from_status: str | None = None,
    to_status: str | None = None,
    reason_code: str | None = None,
    checker: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    did = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM review_decision")).scalar_one()
    db.execute(
        text(
            "INSERT INTO review_decision (id, decision_ref, callback_case_id, finding_id, question_execution_id, "
            "approval_id, action, from_status, to_status, case_state_before, case_state_after, reason, reason_code, "
            "details, actor_ref, actor_permission, checker_ref, idempotency_key) VALUES (:i, :ref, :c, :f, :q, :a, "
            ":act, :fs, :ts, :cb, :ca, :r, :rc, CAST(:d AS jsonb), :by, :perm, :chk, :k)"
        ),
        {
            "i": did,
            "ref": f"RVD-{n:05d}",
            "c": case["id"],
            "f": finding_id,
            "q": qe_id,
            "a": approval_id,
            "act": action,
            "fs": from_status,
            "ts": to_status,
            "cb": case["state"],
            "ca": case_after or case["state"],
            "r": reason,
            "rc": reason_code,
            "d": json.dumps(dict(details or {}), default=str),
            "by": actor.principal_id,
            "perm": permission,
            "chk": checker,
            "k": key,
        },
    )
    db.execute(
        text(
            "INSERT INTO case_event (id, callback_case_id, event_type, occurred_at, actor_ref, related_entity_type, "
            "related_entity_id, summary, created_by) VALUES (:i, :c, :k, now(), :by, 'review_decision', :d, :s, :by)"
        ),
        {
            "i": uuid.uuid4(),
            "c": case["id"],
            "k": f"REVIEW_{action}"[:40],
            "by": actor.principal_id,
            "d": did,
            "s": f"{action.replace('_', ' ').lower()}: {reason}"[:1000],
        },
    )
    r = _one(db, "SELECT * FROM review_decision WHERE id = :i", i=did)
    assert r is not None
    return r


def _set_case(db: Session, case: Mapping[str, Any], to: str, actor: str, extra: str = "", **p: Any) -> None:
    res = db.execute(
        text(
            f"UPDATE callback_case SET state = :to, {extra}updated_at = now(), updated_by = :by, "  # noqa: S608
            "row_version = row_version + 1 WHERE id = :c AND row_version = :rv"
        ),
        {"to": to, "by": actor, "c": case["id"], "rv": case["row_version"], **p},
    )
    if res.rowcount != 1:  # type: ignore[attr-defined]
        raise ReviewError(409, "STALE_CASE", "The case changed since you loaded it; reload and review again")


def _set_finding(db: Session, f: Mapping[str, Any], to: str, actor: str) -> None:
    res = db.execute(
        text(
            "UPDATE finding SET status = CAST(:to AS text), review_assigned_at = coalesce(review_assigned_at, now()), "
            "assigned_reviewer_id = coalesce(assigned_reviewer_id, CAST(:pid AS uuid)), review_closed_at = CASE WHEN "
            "CAST(:to2 AS text) IN ('DISMISSED', 'CLOSED') THEN now() ELSE review_closed_at END, updated_at = now(), "
            "updated_by = :by, row_version = row_version + 1 WHERE id = :f AND row_version = :rv"
        ),
        {"to": to, "to2": to, "pid": actor, "by": actor, "f": f["id"], "rv": f["row_version"]},
    )
    if res.rowcount != 1:  # type: ignore[attr-defined]
        raise ReviewError(409, "STALE_FINDING", "The finding changed since you loaded it; reload and review again")


# ---- finding actions -------------------------------------------------------------------------------------------
def finding_action(
    db: Session,
    finding_id: uuid.UUID,
    actor: Actor,
    action: str,
    reason: str | None,
    expected_row_version: int,
    key: str,
) -> dict[str, Any]:
    _need(actor, DECIDE)
    prior = _existing(db, key, actor)
    if prior is not None:
        return prior | {"replayed": True}
    spec = FINDING_ACTIONS.get(action)
    if spec is None:
        raise ReviewError(422, "UNKNOWN_ACTION", f"Unknown finding action {action}")
    why = _reason(reason)
    f = finding_row(db, finding_id, actor.markets, lock=True)
    case = case_row(db, f["callback_case_id"], actor.markets, lock=True)
    if case["state"] in ("VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED"):
        raise ReviewError(409, "CASE_FINAL", f"The case is {case['state']}; its findings can no longer change")
    if f["row_version"] != expected_row_version:
        raise ReviewError(409, "STALE_FINDING", "The finding changed since you loaded it; reload and review again")
    if f["status"] not in spec["from"]:
        raise ReviewError(
            409,
            "INVALID_TRANSITION",
            f"{spec['label']} is not possible from {f['status'].lower().replace('_', ' ')}",
        )
    if _one(db, "SELECT 1 FROM review_approval WHERE finding_id = :f AND status = 'PENDING'", f=finding_id):
        raise ReviewError(409, "APPROVAL_PENDING", "A disposition of this finding is awaiting a checker")
    to = spec["to"] or ("UNDER_REVIEW" if f["status"] == "OPEN" else f["status"])
    if spec.get("protected") and f["severity"] in material_severities(db):
        aid = _approval(db, case, actor, "FINDING_DISPOSITION", action, to, why, finding=f)
        return _record(
            db,
            case=case,
            action=f"PROPOSE_{action}",
            reason=why,
            actor=actor,
            permission=DECIDE,
            key=key,
            finding_id=f["id"],
            approval_id=aid,
            from_status=f["status"],
            to_status=f["status"],
            details={
                "proposed_to_status": to,
                "material": True,
                "severity": f["severity"],
                "note": "Protected outcome: a different checker must approve (REV-004)",
            },
        )
    if to != f["status"]:
        _set_finding(db, f, to, actor.principal_id)
    return _record(
        db,
        case=case,
        action=action,
        reason=why,
        actor=actor,
        permission=DECIDE,
        key=key,
        finding_id=f["id"],
        from_status=f["status"],
        to_status=to,
        details={"finding_ref": f["finding_ref"], "severity": f["severity"], "category": f["category"]},
    )


# ---- case actions ----------------------------------------------------------------------------------------------
def case_action(
    db: Session,
    case_id: uuid.UUID,
    actor: Actor,
    action: str,
    reason: str | None,
    expected_row_version: int,
    key: str,
    *,
    reason_code: str | None = None,
    question_code: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    severity_justification: str | None = None,
) -> dict[str, Any]:
    _need(actor, DECIDE)
    prior = _existing(db, key, actor)
    if prior is not None:
        return prior | {"replayed": True}
    why = _reason(reason)
    case = case_row(db, case_id, actor.markets, lock=True)
    if case["row_version"] != expected_row_version:
        raise ReviewError(409, "STALE_CASE", "The case changed since you loaded it; reload and review again")
    if action in CASE_ACTIONS:
        spec = CASE_ACTIONS[action]
        if case["state"] not in spec["from"]:
            raise ReviewError(
                409,
                "INVALID_TRANSITION",
                f"{spec['label']} is not possible from {case['state'].lower().replace('_', ' ')}",
            )
        if action == "ESCALATE" and reason_code not in ESCALATION_REASONS:
            raise ReviewError(
                422, "ESCALATION_REASON_REQUIRED", f"Choose an escalation reason ({', '.join(ESCALATION_REASONS)})"
            )
        if _one(
            db,
            "SELECT 1 FROM review_approval WHERE callback_case_id = :c AND kind = 'CASE_DECISION' AND "
            "status = 'PENDING'",
            c=case_id,
        ):
            raise ReviewError(
                409, "APPROVAL_PENDING", "A case decision is awaiting a checker; it must be decided first"
            )
        _set_case(db, case, spec["to"], actor.principal_id)
        return _record(
            db,
            case=case,
            action=action,
            reason=why,
            actor=actor,
            permission=DECIDE,
            key=key,
            case_after=spec["to"],
            reason_code=reason_code if action == "ESCALATE" else None,
            details={"escalation_reason": ESCALATION_REASONS.get(reason_code or "")} if action == "ESCALATE" else {},
        )
    if action not in ("RAISE_FINDING", "ASSESS_ANSWER"):
        raise ReviewError(422, "UNKNOWN_ACTION", f"Unknown case action {action}")
    if case["state"] in ("VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED"):
        raise ReviewError(409, "CASE_FINAL", f"The case is {case['state']}")
    run = latest_run(db, case_id)
    if run is None:
        raise ReviewError(409, "NO_CONVERSATION", "No conversation is recorded for this case")
    e = _executions(db, run["id"]).get(question_code or "")
    if e is None:
        raise ReviewError(422, "UNKNOWN_QUESTION", f"{question_code} was not executed in {run['session_ref']}")
    if action == "ASSESS_ANSWER":
        if reason_code not in ASSESSMENTS:
            raise ReviewError(422, "ASSESSMENT_REQUIRED", "Choose SATISFACTORY or CONCERN")
        return _record(
            db,
            case=case,
            action=action,
            reason=why,
            actor=actor,
            permission=DECIDE,
            key=key,
            qe_id=e["id"],
            reason_code=reason_code,
            details={
                "question_code": question_code,
                "answer_state": e["answer_state"],
                "note": "Human assessment of a free-text answer; a concern needs a raised finding",
            },
        )
    # RAISE_FINDING: a reviewer-origin finding (governed category; severity is the reviewer's justified judgement)
    if category not in fe.CATEGORIES:
        raise ReviewError(422, "INVALID_CATEGORY", f"Category must be one of {', '.join(fe.CATEGORIES)}")
    if severity not in fe.SEVERITIES:
        raise ReviewError(422, "INVALID_SEVERITY", f"Severity must be one of {', '.join(fe.SEVERITIES)}")
    just = (severity_justification or "").strip()
    if not 10 <= len(just) <= 300:
        raise ReviewError(422, "JUSTIFICATION_REQUIRED", "Give the severity justification (10–300 characters)")
    cls = CLASS_OF_RESULT.get(str(e["result"]), "HUMAN_ASSESSMENT" if e["result"] is None else "CUSTOMER_DISCREPANCY")
    fid = uuid.uuid4()
    now = datetime.now(UTC)
    n = db.execute(text("SELECT count(*) + 1 FROM finding WHERE finding_ref LIKE 'FND-RVW-%'")).scalar_one()
    ref = f"FND-RVW-{n:05d}"
    db.execute(
        text(
            "INSERT INTO finding (id, finding_ref, callback_case_id, question_execution_id, category, severity, "
            "status, "
            "evidence_refs, origin, raised_at, created_by, source_type, source_system, source_reference, recorded_at, "
            "is_synthetic, record_origin) VALUES (:i, :ref, :c, :q, :cat, :sev, 'OPEN', CAST(:ev AS jsonb), "
            "'REVIEWER', :t, :by, 'MANUAL', 'CALL360-REVIEW', :src, :t, :syn, 'CALL360_RUNTIME')"
        ),
        {
            "i": fid,
            "ref": ref,
            "c": case_id,
            "q": e["id"],
            "cat": category,
            "sev": severity,
            "ev": json.dumps(
                {
                    "question_execution_id": str(e["id"]),
                    "answer_observation_id": str(e["observation_id"]) if e["observation_id"] else None,
                    "rule_evaluation_id": str(e["rule_evaluation_id"]) if e["rule_evaluation_id"] else None,
                    "finding_class": cls,
                    "severity_justification": just,
                    "severity_source": "Reviewer judgement (recorded with justification)",
                    "raised_by": actor.principal_id,
                    "reason": why,
                    "transcript": "NOT_AVAILABLE",
                }
            ),
            "t": now,
            "by": actor.principal_id,
            "src": f"review:{key}"[:160],
            "syn": bool(case["is_synthetic"]),
        },
    )
    return _record(
        db,
        case=case,
        action=action,
        reason=why,
        actor=actor,
        permission=DECIDE,
        key=key,
        finding_id=fid,
        qe_id=e["id"],
        to_status="OPEN",
        details={
            "finding_ref": ref,
            "category": category,
            "severity": severity,
            "severity_justification": just,
            "finding_class": cls,
            "question_code": question_code,
        },
    )


# ---- maker-checker ---------------------------------------------------------------------------------------------
def _approval(
    db: Session,
    case: Mapping[str, Any],
    actor: Actor,
    kind: str,
    action: str,
    to: str,
    reason: str,
    *,
    finding: Mapping[str, Any] | None = None,
    closure_reason: str | None = None,
    ready: Mapping[str, Any] | None = None,
) -> uuid.UUID:
    aid = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM review_approval")).scalar_one()
    db.execute(
        text(
            "INSERT INTO review_approval (id, approval_ref, callback_case_id, finding_id, kind, proposed_action, "
            "proposed_to_status, closure_reason, reason, readiness, case_row_version, finding_row_version, "
            "proposed_by) VALUES (:i, :ref, :c, :f, :k, :a, :to, :cr, :r, CAST(:rd AS jsonb), :crv, :frv, :by)"
        ),
        {
            "i": aid,
            "ref": f"RVA-{n:04d}",
            "c": case["id"],
            "f": finding["id"] if finding else None,
            "k": kind,
            "a": action,
            "to": to,
            "cr": closure_reason,
            "r": reason,
            "rd": json.dumps(dict(ready or {}), default=str),
            "crv": case["row_version"],
            "frv": finding["row_version"] if finding else None,
            "by": actor.principal_id,
        },
    )
    return aid


def propose_decision(
    db: Session,
    case_id: uuid.UUID,
    actor: Actor,
    decision: str,
    reason: str | None,
    expected_row_version: int,
    key: str,
    closure_reason: str | None = None,
) -> dict[str, Any]:
    _need(actor, DECIDE)
    prior = _existing(db, key, actor)
    if prior is not None:
        return prior | {"replayed": True}
    spec = DECISIONS.get(decision)
    if spec is None:
        raise ReviewError(422, "UNKNOWN_DECISION", "Decision must be VERIFY or CLOSE_UNVERIFIED")
    why = _reason(reason)
    case = case_row(db, case_id, actor.markets, lock=True)
    if case["row_version"] != expected_row_version:
        raise ReviewError(409, "STALE_CASE", "The case changed since you loaded it; reload and review again")
    if case["state"] not in spec["from"]:
        raise ReviewError(
            409, "INVALID_TRANSITION", f"{spec['label']} is not possible from {case['state'].lower().replace('_', ' ')}"
        )
    if _one(
        db,
        "SELECT 1 FROM review_approval WHERE callback_case_id = :c AND kind = 'CASE_DECISION' AND status = 'PENDING'",
        c=case_id,
    ):
        raise ReviewError(409, "APPROVAL_PENDING", "A case decision is already awaiting a checker")
    ready = readiness(db, case)
    if decision == "VERIFY":
        blocking = [f"{c['label']}: {c['detail']}" for c in ready["checks"] if not c["ok"]]
        if blocking:
            raise ReviewError(409, "NOT_READY_TO_VERIFY", "The case cannot be verified yet", blocking)
    else:
        codes = {
            v["code"]
            for v in _all(
                db,
                "SELECT code FROM code_value WHERE code_list_version_id = :lv",
                lv=governed.version_id("case_closure_reason"),
            )
        }
        if closure_reason not in codes:
            raise ReviewError(422, "CLOSURE_REASON_REQUIRED", f"Choose a closure reason ({', '.join(sorted(codes))})")
    aid = _approval(
        db, case, actor, "CASE_DECISION", decision, spec["to"], why, closure_reason=closure_reason, ready=ready
    )
    return _record(
        db,
        case=case,
        action=f"PROPOSE_{decision}",
        reason=why,
        actor=actor,
        permission=DECIDE,
        key=key,
        approval_id=aid,
        reason_code=closure_reason,
        details={
            "proposed_state": spec["to"],
            "readiness": ready,
            "note": "Final case decisions need a different checker (maker-checker)",
        },
    )


def decide_approval(
    db: Session, approval_id: uuid.UUID, actor: Actor, decision: str, reason: str | None, key: str
) -> dict[str, Any]:
    _need(actor, APPROVE)
    prior = _existing(db, key, actor)
    if prior is not None:
        return prior | {"replayed": True}
    why = _reason(reason)
    a = _one(
        db,
        "SELECT a.* FROM review_approval a JOIN callback_case c ON c.id = a.callback_case_id WHERE a.id = :a AND "
        "c.market_code = ANY(:m) FOR UPDATE OF a",
        a=approval_id,
        m=list(actor.markets),
    )
    if a is None:
        raise ReviewError(404, "NOT_FOUND", "Approval request not found or not available to you")
    if a["status"] != "PENDING":
        raise ReviewError(409, "APPROVAL_DECIDED", f"This request is already {a['status'].lower()}")
    if a["proposed_by"] == actor.principal_id:
        raise ReviewError(403, "MAKER_CANNOT_APPROVE", "You proposed this outcome; a different checker must decide it")
    if decision not in ("APPROVE", "REJECT"):
        raise ReviewError(422, "INVALID_DECISION", "Decision must be APPROVE or REJECT")
    case = case_row(db, a["callback_case_id"], actor.markets, lock=True)
    finding = finding_row(db, a["finding_id"], actor.markets, lock=True) if a["finding_id"] else None

    def close(status: str) -> None:
        db.execute(
            text(
                "UPDATE review_approval SET status = :s, decided_by = :by, decided_at = now(), decision_reason = :r, "
                "row_version = row_version + 1 WHERE id = :a"
            ),
            {"s": status, "by": actor.principal_id, "r": why, "a": approval_id},
        )

    stale = case["row_version"] != a["case_row_version"] or (
        finding is not None and finding["row_version"] != a["finding_row_version"]
    )
    if stale:
        close("STALE")
        _record(
            db,
            case=case,
            action="APPROVAL_STALE",
            reason=why,
            actor=actor,
            permission=APPROVE,
            key=key,
            approval_id=approval_id,
            finding_id=a["finding_id"],
            details={"approval_ref": a["approval_ref"], "note": "The case or finding changed after the proposal"},
        )
        db.commit()
        raise ReviewError(
            409,
            "STALE_PROPOSAL",
            "The case or finding changed after this proposal; it must be proposed again on the current state",
        )
    if decision == "REJECT":
        close("REJECTED")
        return _record(
            db,
            case=case,
            action="REJECT_PROPOSAL",
            reason=why,
            actor=actor,
            permission=APPROVE,
            key=key,
            approval_id=approval_id,
            finding_id=a["finding_id"],
            checker=actor.principal_id,
            details={"approval_ref": a["approval_ref"], "proposed_action": a["proposed_action"]},
        )
    if a["kind"] == "CASE_DECISION":
        if a["proposed_action"] == "VERIFY":
            ready = readiness(db, case | {"state": case["state"]}, exclude_approval_id=approval_id)
            blocking = [f"{c['label']}: {c['detail']}" for c in ready["checks"] if not c["ok"]]
            if blocking:
                raise ReviewError(
                    409, "NOT_READY_TO_VERIFY", "The case no longer meets every verification check", blocking
                )
            _set_case(db, case, "VERIFIED", actor.principal_id, "verified_at = now(), ")
        else:
            _set_case(
                db,
                case,
                "CLOSED_UNVERIFIED",
                actor.principal_id,
                "closed_at = now(), closure_reason = :cr, closure_reason_list_version_id = :lv, ",
                cr=a["closure_reason"],
                lv=governed.version_id("case_closure_reason"),
            )
        close("APPROVED")
        return _record(
            db,
            case=case,
            action=f"APPROVE_{a['proposed_action']}",
            reason=why,
            actor=actor,
            permission=APPROVE,
            key=key,
            approval_id=approval_id,
            case_after=a["proposed_to_status"],
            reason_code=a["closure_reason"],
            checker=actor.principal_id,
            details={"approval_ref": a["approval_ref"], "maker": a["proposed_by"], "maker_reason": a["reason"]},
        )
    assert finding is not None
    _set_finding(db, finding, a["proposed_to_status"], actor.principal_id)
    close("APPROVED")
    return _record(
        db,
        case=case,
        action=f"APPROVE_{a['proposed_action']}",
        reason=why,
        actor=actor,
        permission=APPROVE,
        key=key,
        approval_id=approval_id,
        finding_id=finding["id"],
        from_status=finding["status"],
        to_status=a["proposed_to_status"],
        checker=actor.principal_id,
        details={
            "approval_ref": a["approval_ref"],
            "maker": a["proposed_by"],
            "maker_reason": a["reason"],
            "finding_ref": finding["finding_ref"],
        },
    )


def approvals(db: Session, markets: Sequence[str], status: str | None = "PENDING") -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT a.*, c.case_ref, c.state AS case_state, f.finding_ref, f.severity, p.display_name AS proposed_by_name "
        "FROM review_approval a JOIN callback_case c ON c.id = a.callback_case_id LEFT JOIN finding f ON "
        "f.id = a.finding_id LEFT JOIN principal p ON CAST(p.id AS text) = a.proposed_by WHERE c.market_code = ANY(:m) "
        "AND (CAST(:s AS text) IS NULL OR a.status = :s) ORDER BY a.proposed_at DESC LIMIT 200",
        m=list(markets),
        s=status,
    )
