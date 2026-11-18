"""S3-C review dossier: everything a reviewer needs for one case, read-only and access-scoped.

Case and policy summary, pinned script version, conversation status, customer answers with expected policy facts and
evaluation results, findings with severity and its justification (or an explicit "not recorded" for seeded S0
findings), finding class, compliance controls, recording and transcript references (only with ``recording.read``;
otherwise the reason), readiness checks for a verification decision, pending approvals, the insert-only review history
and case events. Unavailable evidence is stated explicitly, never hidden or assumed.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import review as rv


def dossier(db: Session, case_id: uuid.UUID, actor: rv.Actor) -> dict[str, Any]:
    case = rv.case_row(db, case_id, actor.markets)
    pol = rv._one(  # noqa: SLF001 - shared helper
        db,
        "SELECT p.id AS policy_id, p.policy_ref, p.product_code, s.sale_ref, s.selling_channel, s.sold_at, "
        "(SELECT band_code FROM risk_assessment ra WHERE ra.sale_event_id = s.id AND ra.status = 'FINAL' "
        " ORDER BY ra.valid_at DESC LIMIT 1) AS band FROM sale_event s JOIN policy p ON p.id = s.policy_id "
        "WHERE s.id = :s",
        s=case["sale_event_id"],
    )
    assignment = rv._one(  # noqa: SLF001
        db,
        "SELECT a.id, a.assigned_at, a.script_version_id, f.code || ' v' || v.version_label AS script_label, "
        "v.status AS version_status, v.manifest_sha256 FROM script_assignment a JOIN script_version v ON "
        "v.id = a.script_version_id JOIN script_family f ON f.id = v.script_family_id WHERE a.callback_case_id = :c "
        "ORDER BY a.assigned_at DESC LIMIT 1",
        c=case_id,
    )
    holds = rv._all(  # noqa: SLF001
        db,
        "SELECT hold_reason, is_blocking, placed_at, placed_reason, released_at FROM case_hold "
        "WHERE callback_case_id = :c "
        "ORDER BY placed_at DESC",
        c=case_id,
    )
    attempts = rv._all(  # noqa: SLF001
        db,
        "SELECT a.attempt_ref, a.status, a.transport, a.record_origin, a.started_at, cs.session_ref, cs.state AS "
        "session_state, cs.media_status, cs.transcript_status, cs.id AS session_id, a.created_by "
        "FROM contact_attempt a "
        "LEFT JOIN conversation_session cs ON cs.contact_attempt_id = a.id WHERE a.callback_case_id = :c "
        "ORDER BY a.sequence",
        c=case_id,
    )
    for a in attempts:
        a["fixture"] = a.pop("created_by") == "SYSTEM:s3c-fixture"
        a["is_browser_voice"] = a["transport"] == "BROWSER"
    run = rv.latest_run(db, case_id)
    questions: list[dict[str, Any]] = []
    facts: dict[str, Any] = {}
    run_info = None
    if run is not None:
        plan, content, ctx = rv._plan(db, run)  # noqa: SLF001
        facts = ctx["facts"]
        ex = rv._executions(db, run["id"])  # noqa: SLF001
        controls = {
            q["question_code"]: q.get("controls") or [] for s in content.get("sections", []) for q in s["questions"]
        }
        rules = ae.rules_of(content)
        assessed = rv.assessments_of(db, case_id)
        for pq in plan.questions:
            e = ex.get(pq.code)
            r = rules.get(pq.code)
            asm = assessed.get(e["id"]) if e else None
            questions.append(
                {
                    "code": pq.code,
                    "wording": pq.wording,
                    "revision": pq.revision,
                    "question_revision_id": pq.revision_id,
                    "mandatory": pq.mandatory,
                    "role": pq.role,
                    "stage": pq.stage,
                    "applicable": pq.applicable,
                    "skip_reason": pq.skip_reason,
                    "method": r.method if r else None,
                    "rule_text": ae.describe_rule(r) if r else None,
                    "executed": e is not None,
                    "question_execution_id": str(e["id"]) if e else None,
                    "delivery_status": e["delivery_status"] if e else None,
                    "answer_state": e["answer_state"] if e else None,
                    "typed_value": e["typed_value"] if e else None,
                    "verbatim": e["verbatim_text_redacted"] if e else None,
                    "extraction_engine": e["extraction_engine"] if e else None,
                    "expected": e["expected"] if e else None,
                    "observed": e["observed"] if e else None,
                    "evaluation_result": e["result"] if e else None,
                    "rule_ref": f"{e['rule_ref']} {e['rule_version']}" if e and e["rule_ref"] else None,
                    "controls": [
                        {
                            "control_code": c.get("control_code"),
                            "control_name": c.get("control_name"),
                            "mapping_status": c.get("mapping_status"),
                        }
                        for c in controls.get(pq.code, [])
                    ],
                    "assessment": {
                        "outcome": asm["reason_code"],
                        "reason": asm["reason"],
                        "decided_at": asm["decided_at"],
                    }
                    if asm
                    else None,
                }
            )
        run_info = {
            "survey_run_id": str(run["id"]),
            "status": run["status"],
            "session_ref": run["session_ref"],
            "session_state": run["session_state"],
            "transport": run["transport"],
            "media_status": run["media_status"],
            "transcript_status": run["transcript_status"],
            "record_origin": run["session_origin"],
            "script_label": ctx["version"]["family"] + " v" + ctx["version"]["version_label"],
            "script_manifest_sha256": run["script_manifest_sha256"],
            "policy_fact_snapshot_id": str(run["policy_fact_snapshot_id"]),
            "policy_fact_snapshot_sha256": run["policy_fact_snapshot_sha256"],
        }
    results = {q["question_execution_id"]: q["evaluation_result"] for q in questions if q["question_execution_id"]}
    material = rv.material_severities(db)
    findings = []
    for f in rv.findings_of(db, case_id):
        ev = f["evidence_refs"] or {}
        findings.append(
            {
                "id": f["id"],
                "finding_ref": f["finding_ref"],
                "question_code": f["question_code"],
                "category": f["category"],
                "severity": f["severity"],
                "material": f["severity"] in material,
                "status": f["status"],
                "origin": f["origin"],
                "record_origin": f["record_origin"],
                "raised_at": f["raised_at"],
                "row_version": f["row_version"],
                "finding_class": rv.finding_class(f, results.get(str(f["question_execution_id"]))),
                "severity_justification": ev.get("severity_justification")
                or "Not recorded — seeded S0 synthetic finding (no S3-B rule)",
                "severity_source": ev.get("severity_source")
                or (
                    f"Finding rule {ev['rule']['rule_code']} ({ev['rule']['rule_set']['label']})"
                    if ev.get("rule")
                    else "Seeded S0 synthetic fixture"
                ),
                "rule": ev.get("rule"),
                "controls": ev.get("controls"),
                "explanation": (ev.get("evidence") or {}).get("evaluation_explanation"),
                "evidence_refs": ev,
                "pending_approval_id": f["pending_approval_id"],
                "allowed_actions": [
                    k
                    for k, s in rv.FINDING_ACTIONS.items()
                    if f["status"] in s["from"]
                    and not f["pending_approval_id"]
                    and rv.DECIDE in actor.permissions
                    and case["state"] not in ("VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED")
                ],
            }
        )
    can_media = "recording.read" in actor.permissions
    media = []
    for a in attempts:
        if not a["session_id"]:
            continue
        if not can_media:
            media.append(
                {
                    "session_ref": a["session_ref"],
                    "available": False,
                    "detail": "Recording and transcript references need recording.read",
                }
            )
            continue
        assets = rv._all(  # noqa: SLF001
            db,
            "SELECT asset_ref, track, status, coverage FROM media_asset WHERE conversation_session_id = :s",
            s=a["session_id"],
        )
        transcripts = rv._all(  # noqa: SLF001
            db,
            "SELECT run_ref, status, revision FROM transcript_run WHERE conversation_session_id = :s",
            s=a["session_id"],
        )
        media.append(
            {
                "session_ref": a["session_ref"],
                "available": bool(assets),
                "recordings": assets,
                "transcripts": transcripts,
                "detail": None
                if assets
                else f"No recording exists (media status {a['media_status']}); transcript {a['transcript_status']}",
            }
        )
    history = rv._all(  # noqa: SLF001
        db,
        "SELECT d.decision_ref, d.action, d.from_status, d.to_status, d.case_state_before, d.case_state_after, "
        "d.reason, d.reason_code, d.details, d.actor_permission, d.decided_at, d.approval_id, f.finding_ref, "
        "p.display_name AS actor_name, cp.display_name AS checker_name FROM review_decision d LEFT JOIN finding f "
        "ON f.id = d.finding_id LEFT JOIN principal p ON CAST(p.id AS text) = d.actor_ref LEFT JOIN principal cp ON "
        "CAST(cp.id AS text) = d.checker_ref WHERE d.callback_case_id = :c ORDER BY d.decided_at, d.decision_ref",
        c=case_id,
    )
    events = rv._all(  # noqa: SLF001
        db,
        "SELECT event_type, occurred_at, summary, actor_ref FROM case_event WHERE callback_case_id = :c "
        "ORDER BY occurred_at DESC LIMIT 60",
        c=case_id,
    )
    pending = [a for a in rv.approvals(db, actor.markets, "PENDING") if a["callback_case_id"] == case_id]
    decision_pending = any(a["kind"] == "CASE_DECISION" for a in pending)
    ready = rv.readiness(db, case)
    can_decide = rv.DECIDE in actor.permissions and not decision_pending  # a pending decision is decided first
    allowed_case = [k for k, s in rv.CASE_ACTIONS.items() if case["state"] in s["from"]] if can_decide else []
    allowed_decisions = [k for k, s in rv.DECISIONS.items() if case["state"] in s["from"]] if can_decide else []
    return {
        "case": {
            "id": case["id"],
            "case_ref": case["case_ref"],
            "state": case["state"],
            "row_version": case["row_version"],
            "due_at": case["due_at"],
            "has_blocking_hold": case["has_blocking_hold"],
            "verified_at": case["verified_at"],
            "closed_at": case["closed_at"],
            "closure_reason": case["closure_reason"],
            "is_synthetic": case["is_synthetic"],
            "market_code": case["market_code"],
        },
        "policy": pol,
        "facts": facts,
        "assignment": assignment,
        "holds": holds,
        "attempts": attempts,
        "conversation": run_info,
        "questions": questions,
        "findings": findings,
        "media": media,
        "readiness": ready,
        "pending_approvals": pending,
        "history": history,
        "events": events,
        "allowed": {
            "case_actions": allowed_case,
            "decisions": allowed_decisions,
            "approve": rv.APPROVE in actor.permissions,
        },
    }


def queue_cases(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    """Cases with something to review: awaiting review / escalated / awaiting callback with findings, or pending
    approvals (the checker's queue)."""
    return rv._all(  # noqa: SLF001
        db,
        "SELECT c.id, c.case_ref, c.state, c.row_version, c.due_at, (SELECT count(*) FROM finding f WHERE "
        "f.callback_case_id = c.id AND f.status NOT IN ('DISMISSED', 'CLOSED')) AS open_findings, (SELECT count(*) "
        "FROM review_approval a WHERE a.callback_case_id = c.id AND a.status = 'PENDING') AS pending_approvals "
        "FROM callback_case c WHERE c.market_code = ANY(:m) AND (c.state IN ('AWAITING_REVIEW', 'ESCALATED') OR "
        "EXISTS (SELECT 1 FROM review_approval a WHERE a.callback_case_id = c.id AND a.status = 'PENDING')) "
        "ORDER BY c.due_at LIMIT 200",
        m=list(markets),
    )
