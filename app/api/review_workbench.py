"""S3-C Review Workbench API (REV-002/003/004, COMP-009, S3-A5): case review dossier, finding dispositions, case
actions, maker-checker case decisions and approvals.

Reads need ``queue.read`` and ``case.read``; review actions and decision proposals need ``review.decide`` (USER, S&C
checker); approving protected outcomes needs ``review.approve`` (S&C checker) and a user other than the proposer. ADMIN
holds neither. Singapore-scoped (D-39). Every write is CSRF-protected, rate-limited, idempotent (``idempotency_key``),
optimistic-concurrency checked, recorded in the insert-only ``review_decision`` ledger and audited (``REVIEW.*``).
Nothing here evaluates a real voice session, approves autonomously or overwrites evidence.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    ApprovalDecisionIn,
    CaseActionIn,
    CaseDecisionIn,
    ErrorResponse,
    FindingActionIn,
    PickCode,
    ReviewActionOut,
    ReviewApprovalList,
    ReviewApprovalOut,
    ReviewCaseList,
    ReviewCaseOut,
    ReviewCaseSummary,
    ReviewOptions,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import finding_engine as fe
from app.domain import governed
from app.domain import review as rv
from app.domain import review_dossier as rd
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["review-workbench"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
NOTE = (
    "Synthetic Singapore data only. Findings are flagged concerns for human review; decisions are recorded with "
    "reasons and never overwrite evidence. Final case decisions and dispositions of material findings need a second, "
    "different checker. Unavailable evidence is shown as unavailable and never counts as success."
)


def _actor(auth: AuthContext) -> rv.Actor:
    return rv.Actor(str(auth.principal_id), frozenset(auth.permissions), tuple(sorted(auth.markets)))


def _err(exc: rv.ReviewError) -> AppError:
    return AppError(
        exc.status, exc.code, exc.message, details=[{"message": d} for d in exc.details] if exc.details else None
    )


def _read(auth: AuthContext) -> None:
    if "case.read" not in auth.permissions:
        raise AppError(403, "FORBIDDEN", "You do not have permission for this action")


def _out(d: dict[str, Any]) -> ReviewActionOut:
    return ReviewActionOut(
        decision_ref=d["decision_ref"],
        action=d["action"],
        from_status=d["from_status"],
        to_status=d["to_status"],
        case_state_before=d["case_state_before"],
        case_state_after=d["case_state_after"],
        approval_id=d["approval_id"],
        replayed=bool(d.get("replayed")),
    )


def _audit(db: Session, request: Request, auth: AuthContext, d: dict[str, Any], reason: str) -> None:
    if d.get("replayed"):
        return
    ref = db.execute(text("SELECT case_ref FROM callback_case WHERE id = :c"), {"c": d["callback_case_id"]}).scalar()
    write_audit(
        db,
        action=f"REVIEW.{d['action']}"[:64],
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="callback_case",
        entity_id=str(ref),
        before={"case_state": d["case_state_before"], "finding_status": d["from_status"]},
        after={
            "decision": d["decision_ref"],
            "case_state": d["case_state_after"],
            "finding_status": d["to_status"],
            "approval": str(d["approval_id"]) if d["approval_id"] else None,
            "permission": d["actor_permission"],
        },
        reason=reason,
    )


def _approval(a: dict[str, Any]) -> ReviewApprovalOut:
    return ReviewApprovalOut(**{k: a.get(k) for k in ReviewApprovalOut.model_fields})


@router.get("/review/options", response_model=ReviewOptions, operation_id="review_options", responses=_ERR)
def review_options(auth: AuthContext = Depends(require("queue.read")), db: Session = Depends(get_db)) -> ReviewOptions:
    closures = db.execute(
        text("SELECT code, label FROM code_value WHERE code_list_version_id = :lv ORDER BY sort_order"),
        {"lv": governed.version_id("case_closure_reason")},
    ).mappings()
    return ReviewOptions(
        finding_actions={k: v["label"] for k, v in rv.FINDING_ACTIONS.items()},
        case_actions={k: v["label"] for k, v in rv.CASE_ACTIONS.items()},
        decisions={k: v["label"] for k, v in rv.DECISIONS.items()},
        escalation_reasons=rv.ESCALATION_REASONS,
        closure_reasons=[PickCode(code=r["code"], label=r["label"]) for r in closures],
        assessments=list(rv.ASSESSMENTS),
        categories=list(fe.CATEGORIES),
        severities=list(fe.SEVERITIES),
        material_severities=rv.material_severities(db),
        note=NOTE,
    )


@router.get("/review/cases", response_model=ReviewCaseList, operation_id="review_cases", responses=_ERR)
def review_cases(auth: AuthContext = Depends(require("queue.read")), db: Session = Depends(get_db)) -> ReviewCaseList:
    """Cases awaiting review or escalated, and cases with a pending approval."""
    _read(auth)
    return ReviewCaseList(items=[ReviewCaseSummary(**r) for r in rd.queue_cases(db, sorted(auth.markets))])


@router.get("/review/cases/{case_id}", response_model=ReviewCaseOut, operation_id="review_case", responses=_ERR)
def review_case(
    case_id: uuid.UUID, auth: AuthContext = Depends(require("queue.read")), db: Session = Depends(get_db)
) -> ReviewCaseOut:
    """The review dossier: case, policy, pinned script, conversation, answers, expected facts, evaluation results,
    findings, controls, evidence references, readiness checks, approvals and history."""
    _read(auth)
    try:
        d = rd.dossier(db, case_id, _actor(auth))
    except rv.ReviewError as exc:
        raise _err(exc) from exc
    pending = [_approval(a) for a in d.pop("pending_approvals")]
    return ReviewCaseOut(**d, pending_approvals=pending, note=NOTE)


@router.post(
    "/review/findings/{finding_id}/actions",
    response_model=ReviewActionOut,
    operation_id="review_finding_action",
    responses=_ERR,
)
@csrf_protected
def review_finding_action(
    finding_id: uuid.UUID,
    body: FindingActionIn,
    request: Request,
    auth: AuthContext = Depends(require("review.decide")),
    db: Session = Depends(get_db),
) -> ReviewActionOut:
    """Disposition of one finding. Dismissing or resolving a material finding creates an approval request."""
    _guard(request, auth)
    try:
        d = rv.finding_action(
            db, finding_id, _actor(auth), body.action, body.reason, body.expected_row_version, body.idempotency_key
        )
    except rv.ReviewError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, d, body.reason)
    db.commit()
    return _out(d)


@router.post(
    "/review/cases/{case_id}/actions",
    response_model=ReviewActionOut,
    operation_id="review_case_action",
    responses=_ERR,
)
@csrf_protected
def review_case_action(
    case_id: uuid.UUID,
    body: CaseActionIn,
    request: Request,
    auth: AuthContext = Depends(require("review.decide")),
    db: Session = Depends(get_db),
) -> ReviewActionOut:
    """Further callback, escalation (REV-003 reason), return to review, raise a finding, assess a narrative answer."""
    _guard(request, auth)
    try:
        d = rv.case_action(
            db,
            case_id,
            _actor(auth),
            body.action,
            body.reason,
            body.expected_row_version,
            body.idempotency_key,
            reason_code=body.reason_code,
            question_code=body.question_code,
            category=body.category,
            severity=body.severity,
            severity_justification=body.severity_justification,
        )
    except rv.ReviewError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, d, body.reason)
    db.commit()
    return _out(d)


@router.post(
    "/review/cases/{case_id}/decisions",
    response_model=ReviewActionOut,
    operation_id="review_case_decision",
    responses=_ERR,
)
@csrf_protected
def review_case_decision(
    case_id: uuid.UUID,
    body: CaseDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("review.decide")),
    db: Session = Depends(get_db),
) -> ReviewActionOut:
    """Propose VERIFY (only when every readiness check passes) or CLOSE_UNVERIFIED (governed closure reason). A
    different checker must approve it."""
    _guard(request, auth)
    try:
        d = rv.propose_decision(
            db,
            case_id,
            _actor(auth),
            body.decision,
            body.reason,
            body.expected_row_version,
            body.idempotency_key,
            body.closure_reason,
        )
    except rv.ReviewError as exc:
        db.rollback()
        if exc.code == "NOT_READY_TO_VERIFY":
            ref = db.execute(text("SELECT case_ref FROM callback_case WHERE id = :c"), {"c": case_id}).scalar()
            write_audit(
                db,
                action="REVIEW.VERIFY_BLOCKED",
                outcome="DENIED",
                actor=auth.actor,
                meta=request_meta(request),
                entity_type="callback_case",
                entity_id=str(ref),
                after={"blocking": exc.details},
                reason=body.reason,
            )
            db.commit()
        raise _err(exc) from exc
    _audit(db, request, auth, d, body.reason)
    db.commit()
    return _out(d)


@router.get("/review/approvals", response_model=ReviewApprovalList, operation_id="review_approvals", responses=_ERR)
def review_approvals(
    status: str | None = Query("PENDING", max_length=16),
    auth: AuthContext = Depends(require("queue.read")),
    db: Session = Depends(get_db),
) -> ReviewApprovalList:
    _read(auth)
    return ReviewApprovalList(items=[_approval(a) for a in rv.approvals(db, sorted(auth.markets), status or None)])


@router.post(
    "/review/approvals/{approval_id}/decide",
    response_model=ReviewActionOut,
    operation_id="review_approval_decide",
    responses=_ERR,
)
@csrf_protected
def review_approval_decide(
    approval_id: uuid.UUID,
    body: ApprovalDecisionIn,
    request: Request,
    auth: AuthContext = Depends(require("review.approve")),
    db: Session = Depends(get_db),
) -> ReviewActionOut:
    """A different checker approves or rejects a proposed case decision or material finding disposition. Stale
    proposals (the case or finding changed) are refused and marked STALE."""
    _guard(request, auth)
    try:
        d = rv.decide_approval(db, approval_id, _actor(auth), body.decision, body.reason, body.idempotency_key)
    except rv.ReviewError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, d, body.reason)
    db.commit()
    return _out(d)
