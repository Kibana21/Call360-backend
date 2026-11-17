"""S2-C deterministic script assignment API (SCR-004, SCR-011).

- ``GET /cases/{case_id}/script-assignment/preview`` (``case.read``): the pinned script (if any), the read-only
  preview of what the published rules would decide now (outcome, rule, explanation, trace, contact resolution,
  holds that would be released or placed, remaining blocking holds) and the attempt history. Evaluated in a READ ONLY
  transaction.
- ``POST /cases/{case_id}/script-assignment/apply`` (``script.assign``, ``Idempotency-Key`` required): apply the
  decision. A retried key replays the stored result; an assigned case is never reassigned; an optional
  ``expected_decision_sha256`` refuses the apply when the decision changed since the preview.
- ``POST /script-assignments/run`` (``script.assign``): preview (``dry_run``) or apply the decision for eligible
  unassigned cases in your markets, one transaction per case.

Assignment never creates a compliance outcome, never changes the case state and never releases any hold other than the
script-assignment holds. Audited (``CASE.SCRIPT_*``, ``CASE.HOLD_*``).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.case_detail import _deny
from app.api.deps import csrf_protected
from app.api.schemas import (
    ApplyAssignmentIn,
    ApplyAssignmentOut,
    AssignmentAttemptOut,
    AssignmentBatchCase,
    AssignmentBatchIn,
    AssignmentBatchOut,
    AssignmentHold,
    AssignmentPreview,
    CaseScriptAssignment,
    ErrorResponse,
    PinnedAssignment,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import script_assignment as sx
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["script-assignment"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 428, 429)}
_KEY = re.compile(r"[A-Za-z0-9._:-]{8,128}")
NOTE = (
    "Synthetic test-only scripts. Assigning a script never verifies a case, never creates a compliance outcome and "
    "never starts a call."
)


def _err(exc: sx.AssignmentError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=[exc.details] if exc.details else None)


def _key(value: str | None) -> str:
    if value is None or not _KEY.fullmatch(value):
        raise AppError(
            428, "IDEMPOTENCY_KEY_REQUIRED", "Send an Idempotency-Key header (8–128 characters: A-Z a-z 0-9 . _ : -)"
        )
    return value


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    case_ref: str,
    after: dict[str, Any],
    reason: str | None = None,
) -> None:
    write_audit(
        db,
        action=action,
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="callback_case",
        entity_id=case_ref,
        reason=reason,
        after=after,
    )


def _pinned(db: Session, a: dict[str, Any] | None) -> PinnedAssignment | None:
    if a is None:
        return None
    trace = a["rule_trace"] or {}
    by = db.execute(
        text("SELECT display_name FROM principal WHERE CAST(id AS text) = :r"), {"r": a["assigned_by"]}
    ).scalar()
    return PinnedAssignment(
        script_assignment_id=a["id"],
        script_version_id=a["script_version_id"],
        script_family_id=a["family_id"],
        script_label=f"{a['family']} v{a['version_label']}",
        manifest_sha256=a["script_manifest_sha256"],
        matched_rule=f"{a['rule_code']} v{a['rule_version']}" if a["rule_code"] else None,
        origin=a["origin"],
        assigned_at=a["assigned_at"],
        assigned_by=by or a["assigned_by"],
        explanation=(trace.get("decision") or {}).get("explanation"),
        input_sha256=a["input_sha256"],
    )


def _preview(ev: dict[str, Any]) -> AssignmentPreview:
    d = ev["decision_json"]
    return AssignmentPreview(
        outcome=d["outcome"],
        reason=d["reason"],
        would_assign=d["outcome"] in sx.SUCCESS and ev["eligible"],
        script_version_id=d["selected_script_version_id"],
        script_family_id=ev["target"]["family_id"] if ev["target"] else None,
        script_label=d["selected_script_label"],
        determinable_script_label=d["determinable_script_label"],
        winning_rules=d["winning_rules"],
        explanation=d["explanation"],
        contact_resolution=d["contact_resolution"],
        trace=d["trace"],
        inputs=ev["input_snapshot"]["inputs"],
        would_release=ev["would_release"],
        would_place=ev["would_place"],
        remaining_blocking=ev["remaining_blocking"],
        decision_sha256=ev["decision_sha256"],
        evaluated_at=datetime.fromisoformat(ev["input_snapshot"]["evaluated_at"]),
    )


def _attempt(a: dict[str, Any]) -> AssignmentAttemptOut:
    return AssignmentAttemptOut(
        id=a["id"],
        outcome=a["outcome"],
        applied=a["applied"],
        reason=a["reason"],
        script_label=(a["decision"] or {}).get("selected_script_label"),
        winning_rules=(a["decision"] or {}).get("winning_rules") or [],
        holds_released=a["holds_released"],
        holds_placed=a["holds_placed"],
        trigger=a["trigger"],
        actor=a.get("display_name") or a["actor_ref"],
        evaluated_at=a["evaluated_at"],
        decision_sha256=a["decision_sha256"],
    )


@router.get(
    "/cases/{case_id}/script-assignment/preview",
    response_model=CaseScriptAssignment,
    operation_id="case_script_assignment_preview",
    responses=_ERR,
)
def case_script_assignment_preview(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> CaseScriptAssignment:
    """Assignment status, the read-only preview of the deterministic decision and the attempt history."""
    markets = sorted(auth.markets)
    db.rollback()
    db.execute(text("SET TRANSACTION READ ONLY"))
    try:
        ev = sx.evaluate(db, case_id, markets, datetime.now(UTC))
        history = sx.attempts(db, case_id)
    except sx.AssignmentError as exc:
        db.rollback()
        if exc.status == 404:
            raise _deny(db, request, auth, "callback_case", case_id) from exc
        raise _err(exc) from exc
    finally:
        db.rollback()
    c = ev["case"]
    status = (
        "ASSIGNED"
        if ev["existing"] is not None
        else "NOT_ELIGIBLE"
        if not ev["eligible"]
        else "READY_TO_ASSIGN"
        if ev["decision"].outcome in sx.SUCCESS
        else "BLOCKED"
    )
    return CaseScriptAssignment(
        case_id=c["id"],
        case_ref=c["case_ref"],
        state=c["state"],
        status=status,
        blocked_reason=ev["blocked_reason"],
        current=_pinned(db, ev["existing"]),
        preview=_preview(ev),
        holds=[
            AssignmentHold(
                hold_reason=h["hold_reason"],
                is_blocking=h["is_blocking"],
                placed_at=h["placed_at"],
                source=h["source"],
                placed_reason=h["placed_reason"],
            )
            for h in ev["holds"]
        ],
        attempts=[_attempt(a) for a in history],
        can_apply="script.assign" in auth.permissions and status in ("READY_TO_ASSIGN", "BLOCKED"),
        note=NOTE,
    )


def _apply_one(
    db: Session, request: Request, auth: AuthContext, case_id: uuid.UUID, key: str, expected: str | None, trigger: str
) -> dict[str, Any]:
    out = sx.apply(
        db,
        case_id,
        sorted(auth.markets),
        str(auth.principal_id),
        idempotency_key=key,
        expected_decision_sha256=expected,
        trigger=trigger,
    )
    if out["status"] in ("ASSIGNED", "NOT_ASSIGNED"):
        a, c = out["attempt"], out["evaluation"]["case"]
        if a["applied"]:
            _audit(
                db,
                request,
                auth,
                "CASE.SCRIPT_ASSIGNED",
                c["case_ref"],
                {
                    "script": a["decision"]["selected_script_label"],
                    "rules": a["decision"]["winning_rules"],
                    "attempt": str(a["id"]),
                    "input_sha256": a["input_sha256"],
                },
            )
        else:
            _audit(
                db,
                request,
                auth,
                "CASE.SCRIPT_ASSIGNMENT_BLOCKED",
                c["case_ref"],
                {"outcome": a["outcome"], "attempt": str(a["id"])},
                reason=a["reason"][:500],
            )
        for h in a["holds_released"]:
            _audit(
                db,
                request,
                auth,
                "CASE.HOLD_RELEASED",
                c["case_ref"],
                {"hold_reason": h, "source": "SCRIPT_ASSIGNMENT"},
            )
        for h in a["holds_placed"]:
            _audit(
                db, request, auth, "CASE.HOLD_PLACED", c["case_ref"], {"hold_reason": h, "source": "SCRIPT_ASSIGNMENT"}
            )
    return out


def _apply_out(case_id: uuid.UUID, out: dict[str, Any], db: Session) -> ApplyAssignmentOut:
    if out["status"] == "ALREADY_ASSIGNED":
        return ApplyAssignmentOut(
            case_id=case_id, status="ALREADY_ASSIGNED", attempt=None, current=_pinned(db, out["existing"])
        )
    a = out["attempt"]
    return ApplyAssignmentOut(
        case_id=case_id,
        status=out["status"],
        attempt=_attempt(a),
        current=_pinned(db, sx.current_assignment(db, case_id)),
    )


@router.post(
    "/cases/{case_id}/script-assignment/apply",
    response_model=ApplyAssignmentOut,
    operation_id="case_script_assignment_apply",
    responses=_ERR,
)
@csrf_protected
def case_script_assignment_apply(
    case_id: uuid.UUID,
    body: ApplyAssignmentIn,
    request: Request,
    auth: AuthContext = Depends(require("script.assign")),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=128),
) -> ApplyAssignmentOut:
    """Apply the deterministic decision to one case (never reassigns; idempotent)."""
    _guard(request, auth)
    key = _key(idempotency_key)
    try:
        out = _apply_one(db, request, auth, case_id, key, body.expected_decision_sha256, "CASE")
    except sx.AssignmentError as exc:
        db.rollback()
        if exc.status == 404:
            raise _deny(db, request, auth, "callback_case", case_id) from exc
        raise _err(exc) from exc
    result = _apply_out(case_id, out, db)
    db.commit()
    return result


@router.post(
    "/script-assignments/run",
    response_model=AssignmentBatchOut,
    operation_id="script_assignments_run",
    responses=_ERR,
)
@csrf_protected
def script_assignments_run(
    body: AssignmentBatchIn,
    request: Request,
    auth: AuthContext = Depends(require("script.assign")),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=128),
) -> AssignmentBatchOut:
    """Preview (``dry_run``) or apply the deterministic decision for eligible unassigned cases in your markets.
    Each case is applied in its own transaction; assigned and terminal cases are never touched."""
    _guard(request, auth)
    markets = sorted(auth.markets)
    key = None if body.dry_run else _key(idempotency_key)
    cases = sx.unassigned_cases(db, markets, body.case_ids)[: body.limit]
    db.rollback()
    results: list[AssignmentBatchCase] = []
    for c in cases:
        try:
            if body.dry_run:
                db.execute(text("SET TRANSACTION READ ONLY"))
                ev = sx.evaluate(db, c["id"], markets, datetime.now(UTC))
                db.rollback()
                d = ev["decision_json"]
                results.append(
                    AssignmentBatchCase(
                        case_id=c["id"],
                        case_ref=c["case_ref"],
                        status="PREVIEW",
                        outcome=d["outcome"],
                        script_label=d["selected_script_label"],
                        winning_rules=d["winning_rules"],
                        reason=d["reason"],
                        would_release=ev["would_release"],
                        would_place=ev["would_place"],
                    )
                )
                continue
            assert key is not None
            out = _apply_one(db, request, auth, c["id"], f"{key}:{c['id']}", None, "BATCH")
            db.commit()
            a = out.get("attempt")
            results.append(
                AssignmentBatchCase(
                    case_id=c["id"],
                    case_ref=c["case_ref"],
                    status=out["status"],
                    outcome=a["outcome"] if a else None,
                    script_label=(a["decision"] or {}).get("selected_script_label") if a else None,
                    winning_rules=(a["decision"] or {}).get("winning_rules") or [] if a else [],
                    reason=a["reason"] if a else "Already assigned",
                    would_release=a["holds_released"] if a else [],
                    would_place=a["holds_placed"] if a else [],
                )
            )
        except sx.AssignmentError as exc:
            db.rollback()
            results.append(
                AssignmentBatchCase(
                    case_id=c["id"],
                    case_ref=c["case_ref"],
                    status="ERROR",
                    outcome=None,
                    script_label=None,
                    winning_rules=[],
                    reason=exc.message,
                    would_release=[],
                    would_place=[],
                )
            )
    summary: dict[str, int] = {}
    for r in results:
        k = r.outcome or r.status
        summary[k] = summary.get(k, 0) + 1
    return AssignmentBatchOut(dry_run=body.dry_run, cases=len(results), summary=summary, results=results, note=NOTE)
