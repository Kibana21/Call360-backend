"""S2-D text simulation API over the deterministic question controller (SUR-008, VOICE-011).

The server decides every next action; the client only reports delivery and answers against the current ``action_id``.
Simulation writes only simulation records: no contact attempt, session, survey run, answer observation, finding, hold or
case-state change, so outcomes and KPIs are unaffected. ``script.simulate`` (USER, SC_CHECKER) for writes,
``case.read`` + ``script.read`` to read; Singapore-scoped; writes are CSRF-protected, rate-limited and audited
(``SIMULATION.STARTED`` / ``SIMULATION.ENDED``; each step is in the run's insert-only event log).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.case_detail import _deny
from app.api.deps import csrf_protected
from app.api.schemas import (
    ErrorResponse,
    ScenarioPreviewIn,
    SimActionOut,
    SimAnswerIn,
    SimClarificationIn,
    SimContactOut,
    SimDeliveryIn,
    SimEligibleCase,
    SimEligibleCases,
    SimEndIn,
    SimEvaluationList,
    SimEvaluationOut,
    SimEvaluationSummary,
    SimEventIn,
    SimEventOut,
    SimPlanOut,
    SimPlanQuestion,
    SimPlanSection,
    SimQuestionState,
    SimRunList,
    SimRunOut,
    SimRunSummary,
    SimSkipIn,
    SimStartIn,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import lifecycle as lc
from app.domain import question_controller as qc
from app.domain import script_simulation as ss
from app.domain import simulation_evaluation as se
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["script-simulation"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
NOTE = (
    "Text simulation only: no customer is contacted, no identity is verified, no answer is evaluated for compliance "
    "(S3-A answer evaluation compares answers with expected values only) and no case outcome, hold or KPI changes. "
    "Scripts are synthetic and not production-approved wording."
)


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _who(auth: AuthContext) -> str:
    return str(auth.principal_id)


def _err(exc: ss.SimulationError | qc.ControllerError) -> AppError:
    return AppError(exc.status, exc.code, exc.message)


def _read(auth: AuthContext) -> None:
    if "script.read" not in auth.permissions:
        raise AppError(403, "FORBIDDEN", "You do not have permission for this action")


@router.get(
    "/script-simulations/cases", response_model=SimEligibleCases, operation_id="simulation_cases", responses=_ERR
)
def simulation_cases(
    q: str | None = Query(default=None, max_length=40),
    include_unassigned: bool = False,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimEligibleCases:
    """Cases in your markets that have a pinned script (newest assignment first); with ``include_unassigned``, any
    synthetic case with a policy fact snapshot (for testing a chosen script version)."""
    _read(auth)
    rows = ss.eligible_cases(db, _markets(auth), q, include_unassigned=include_unassigned)
    return SimEligibleCases(items=[SimEligibleCase(**r) for r in rows])


@router.get("/script-simulations/plan", response_model=SimPlanOut, operation_id="simulation_plan", responses=_ERR)
def simulation_plan(
    case_id: uuid.UUID,
    request: Request,
    script_version_id: uuid.UUID | None = None,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimPlanOut:
    """The modules and questions the controller would run for the case, with each applicability reason."""
    _read(auth)
    try:
        ctx = ss.context(db, case_id, _markets(auth), script_version_id)
    except ss.SimulationError as exc:
        if exc.status == 404 and exc.code == "NOT_FOUND":
            raise _deny(db, request, auth, "callback_case", case_id) from exc
        raise _err(exc) from exc
    plan, v = ctx["plan"], ctx["version"]
    pinned = ctx["assignment_contact"]
    return SimPlanOut(
        case_id=case_id,
        case_ref=ctx["case"]["case_ref"],
        script_label=plan.script_label,
        script_version_id=v["id"],
        script_family_id=v["script_family_id"],
        manifest_sha256=plan.manifest_sha256,
        content_approval_status=ctx["content_approval_status"],
        facts={
            k: ctx["snapshot"]["facts"].get(k)
            for k in ("product_family", "is_ilp", "selling_channel", "premium_frequency", "product_code")
        },
        risk_band=ctx["risk"]["band_code"] if ctx["risk"] else None,
        sections=[SimPlanSection(**s.__dict__) for s in plan.sections],
        questions=[SimPlanQuestion(**{**q.__dict__, "options": list(q.options)}) for q in plan.questions],
        contacts=[
            SimContactOut(
                selection_id=c.ref,
                role=c.role,
                label=c.label,
                assignment_contact=bool(pinned and pinned["selection_id"] == c.ref),
            )
            for c in ctx["contacts"]
        ],
        note=NOTE,
        identity_gate_configured=plan.identity_configured,
        stages=list(lc.STAGES),
        assumptions=list(lc.ASSUMPTIONS),
        mode="VERSION_TEST" if ctx["assignment"] is None else "TEXT_SIMULATION",
        version_status=v["status"],
        live_eligibility=ctx["live_eligibility"],
    )


def _run_out(db: Session, run_id: uuid.UUID, markets: list[str], replayed: bool = False) -> SimRunOut:
    run = ss.run_row(db, run_id, markets)
    ctrl, rows = ss.controller_for(db, run)
    st = ctrl.state()
    nxt = ctrl.next_action()
    label = ctrl.plan.script_label
    return SimRunOut(
        id=run["id"],
        sim_ref=run["sim_ref"],
        case_id=run["callback_case_id"],
        case_ref=run["case_ref"],
        script_label=label,
        script_version_id=run["script_version_id"],
        manifest_sha256=run["script_manifest_sha256"],
        contact_role=run["contact_role"],
        status=run["status"],
        outcome=run["outcome"],
        started_at=run["started_at"],
        ended_at=run["ended_at"],
        next_action=SimActionOut(**nxt.__dict__),
        summary=st["summary"],
        lifecycle=st["lifecycle"],
        questions=[SimQuestionState(**q) for q in st["questions"]],
        trace=[
            SimEventOut(
                seq=e["seq"],
                event_type=e["event_type"],
                question_code=e["question_code"],
                action_id=e["action_id"],
                data=e["data"] or {},
                actor=e["display_name"] or e["actor_ref"],
                occurred_at=e["occurred_at"],
            )
            for e in rows
        ],
        replayed=replayed,
        note=NOTE,
    )


@router.post(
    "/script-simulations", response_model=SimRunOut, status_code=201, operation_id="simulation_start", responses=_ERR
)
@csrf_protected
def simulation_start(
    body: SimStartIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Start a new text simulation (restarting = starting a new run; earlier runs are kept)."""
    _guard(request, auth)
    try:
        run_id = ss.start(
            db, body.case_id, _markets(auth), _who(auth), body.contact_selection_id, body.script_version_id
        )
    except ss.SimulationError as exc:
        db.rollback()
        if exc.status == 404 and exc.code == "NOT_FOUND":
            raise _deny(db, request, auth, "callback_case", body.case_id) from exc
        raise _err(exc) from exc
    case_ref = db.execute(text("SELECT case_ref FROM callback_case WHERE id = :c"), {"c": body.case_id}).scalar_one()
    write_audit(
        db,
        action="SIMULATION.STARTED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="callback_case",
        entity_id=case_ref,
        after={
            "run": str(run_id),
            "mode": "VERSION_TEST" if body.script_version_id else "TEXT_SIMULATION",
            "script_version_id": str(body.script_version_id) if body.script_version_id else None,
        },
    )
    db.commit()
    return _run_out(db, run_id, _markets(auth))


@router.get("/script-simulations/{run_id}", response_model=SimRunOut, operation_id="simulation_get", responses=_ERR)
def simulation_get(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Current state, next permitted action, mandatory progress and the full event trace."""
    _read(auth)
    try:
        return _run_out(db, run_id, _markets(auth))
    except ss.SimulationError as exc:
        raise _err(exc) from exc


def _step(request: Request, auth: AuthContext, db: Session, run_id: uuid.UUID, op: str, **kw: Any) -> SimRunOut:
    _guard(request, auth)
    try:
        new = ss.act(db, run_id, _markets(auth), _who(auth), op, **kw)
    except (ss.SimulationError, qc.ControllerError) as exc:
        db.rollback()
        raise _err(exc) from exc
    if op == "end" and new:
        run = ss.run_row(db, run_id, _markets(auth))
        write_audit(
            db,
            action="SIMULATION.ENDED",
            outcome="SUCCEEDED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="callback_case",
            entity_id=run["case_ref"],
            after={"run": str(run_id), "outcome": run["outcome"]},
            reason=kw.get("reason"),
        )
    db.commit()
    return _run_out(db, run_id, _markets(auth), replayed=not new)


@router.post(
    "/script-simulations/{run_id}/delivery",
    response_model=SimRunOut,
    operation_id="simulation_delivery",
    responses=_ERR,
)
@csrf_protected
def simulation_delivery(
    run_id: uuid.UUID,
    body: SimDeliveryIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Report whether the requested question was presented (simulated delivery)."""
    return _step(
        request, auth, db, run_id, "delivery", action_id=body.action_id, delivered=body.delivered, note=body.note
    )


@router.post(
    "/script-simulations/{run_id}/answer", response_model=SimRunOut, operation_id="simulation_answer", responses=_ERR
)
@csrf_protected
def simulation_answer(
    run_id: uuid.UUID,
    body: SimAnswerIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Submit the answer to the current action (a duplicate of the same answer is replayed, not re-applied)."""
    return _step(
        request,
        auth,
        db,
        run_id,
        "answer",
        action_id=body.action_id,
        kind=body.kind,
        value=body.value,
        verbatim=body.verbatim,
    )


@router.post(
    "/script-simulations/{run_id}/clarification",
    response_model=SimRunOut,
    operation_id="simulation_clarification",
    responses=_ERR,
)
@csrf_protected
def simulation_clarification(
    run_id: uuid.UUID,
    body: SimClarificationIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """The customer needs clarification: re-prompt within the approved limit, else the question is unresolved."""
    return _step(request, auth, db, run_id, "clarification", action_id=body.action_id, reason=body.reason)


@router.post(
    "/script-simulations/{run_id}/skip", response_model=SimRunOut, operation_id="simulation_skip", responses=_ERR
)
@csrf_protected
def simulation_skip(
    run_id: uuid.UUID,
    body: SimSkipIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Always refused: questions are skipped only by approved conditions (shown for completeness and testing)."""
    return _step(request, auth, db, run_id, "skip", action_id=body.action_id)


@router.post(
    "/script-simulations/{run_id}/event", response_model=SimRunOut, operation_id="simulation_event", responses=_ERR
)
@csrf_protected
def simulation_event(
    run_id: uuid.UUID,
    body: SimEventIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """Report a conversation event (simulated): wrong person, callback requested, declined to continue or
    interrupted. Each terminates the conversation; only closing statements marked for termination are then offered."""
    return _step(request, auth, db, run_id, "report", kind=body.kind, note=body.note)


@router.post(
    "/script-simulations/{run_id}/end", response_model=SimRunOut, operation_id="simulation_end", responses=_ERR
)
@csrf_protected
def simulation_end(
    run_id: uuid.UUID,
    body: SimEndIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimRunOut:
    """End (COMPLETED only when every applicable mandatory question is completed) or abandon the run."""
    return _step(request, auth, db, run_id, "end", abandon=body.abandon, reason=body.reason)


@router.get(
    "/cases/{case_id}/script-simulations", response_model=SimRunList, operation_id="case_simulations", responses=_ERR
)
def case_simulations(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimRunList:
    _read(auth)
    ok = db.execute(
        text("SELECT 1 FROM callback_case WHERE id = :c AND market_code = ANY(:m)"), {"c": case_id, "m": _markets(auth)}
    ).scalar()
    if not ok:
        raise _deny(db, request, auth, "callback_case", case_id)
    return SimRunList(
        items=[SimRunSummary(**{**r, "started_by": r["display_name"]}) for r in ss.runs_for_case(db, case_id)]
    )


@router.get(
    "/script-simulations/{run_id}/as-scenario",
    response_model=ScenarioPreviewIn,
    operation_id="simulation_as_scenario",
    responses=_ERR,
)
def simulation_as_scenario(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> ScenarioPreviewIn:
    """S2-E: structured scenario content reproducing an interactive run (responses that differ from the default
    response) with its actual result as expectations. Nothing is saved; review it, then save it as a scenario."""
    _read(auth)
    from app.domain import simulation_workbench as wb

    try:
        run = ss.run_row(db, run_id, _markets(auth))
        rows = ss.events_of(db, run_id)
    except ss.SimulationError as exc:
        raise _err(exc) from exc
    return ScenarioPreviewIn(**wb.scenario_from_run(db, run, rows, _markets(auth)))


# ---- S3-A: deterministic answer evaluation of a simulation run -------------------------------------------------
EVAL_NOTE = (
    "Deterministic evaluation of simulated structured answers against each question revision's approved rule and the "
    "run's immutable policy fact snapshot. A match is not a compliance pass and a mismatch is a discrepancy for "
    "review, "
    "not a finding or breach; no case, verification, finding or KPI changes."
)


def _eval_out(rec: dict[str, Any], created: bool = False) -> SimEvaluationOut:
    return SimEvaluationOut(**rec, created_by_name=rec.get("display_name"), created=created, note=EVAL_NOTE)


@router.post(
    "/script-simulations/{run_id}/evaluations",
    response_model=SimEvaluationOut,
    operation_id="simulation_evaluate",
    responses=_ERR,
)
@csrf_protected
def simulation_evaluate(
    run_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimEvaluationOut:
    """Evaluate the run's answers as recorded so far. Identical inputs return the existing evaluation (``created`` is
    false); new answers create a new evaluation and earlier ones are kept."""
    _guard(request, auth)
    try:
        rec, created = se.evaluate_run(db, run_id, _markets(auth), _who(auth))
    except ss.SimulationError as exc:
        db.rollback()
        raise _err(exc) from exc
    if created:
        write_audit(
            db,
            action="SIMULATION.ANSWERS_EVALUATED",
            outcome="SUCCEEDED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="callback_case",
            entity_id=rec["case_ref"],
            after={"run": str(run_id), "evaluation": rec["evaluation_ref"], "totals": rec["totals"]},
        )
    db.commit()
    return _eval_out(rec, created)


@router.get(
    "/script-simulations/{run_id}/evaluations",
    response_model=SimEvaluationList,
    operation_id="simulation_evaluations",
    responses=_ERR,
)
def simulation_evaluations(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimEvaluationList:
    _read(auth)
    try:
        rows = se.for_run(db, run_id, _markets(auth))
    except ss.SimulationError as exc:
        raise _err(exc) from exc
    return SimEvaluationList(items=[SimEvaluationSummary(**r, created_by_name=r.get("display_name")) for r in rows])


@router.get(
    "/script-simulations/{run_id}/evaluations/{evaluation_id}",
    response_model=SimEvaluationOut,
    operation_id="simulation_evaluation_get",
    responses=_ERR,
)
def simulation_evaluation_get(
    run_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SimEvaluationOut:
    """One evaluation with its evidence trace and a replay check (re-derived from the stored inputs)."""
    _read(auth)
    try:
        rec = se.get(db, evaluation_id, _markets(auth))
    except ss.SimulationError as exc:
        raise _err(exc) from exc
    if rec["run_id"] != run_id:
        raise AppError(404, "NOT_FOUND", "Evaluation not found or not available to you")
    return _eval_out(rec)
