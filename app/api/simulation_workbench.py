"""S2-E callback simulation workbench API (SUR-010): scenario library, automated and batch runs, coverage and
script-version comparison over the existing deterministic question controller.

Reads need ``script.read``; writes (scenario changes, runs, dry runs) need ``script.simulate`` (USER, SC_CHECKER; not
ADMIN). Singapore-scoped; writes are CSRF-protected, rate-limited and audited (``SIMULATION.SCENARIO_*``,
``SIMULATION.BATCH_RUN``). Only simulation records are written: never a script assignment, contact attempt, session,
survey run, finding, hold, case state or KPI input. Pass / fail is an exact deterministic comparison; no LLM is used.
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
    CaseFactsOut,
    ErrorResponse,
    ScenarioContent,
    ScenarioCopyIn,
    ScenarioList,
    ScenarioOut,
    ScenarioPreviewIn,
    ScenarioPreviewOut,
    ScenarioReviseIn,
    ScenarioRevisionSummary,
    ScenarioRunIn,
    ScenarioStatusIn,
    ScenarioSummary,
    SimBatchList,
    SimBatchOut,
    SimBatchSummary,
    SimPlanQuestion,
    SimPlanSection,
    SimResultOut,
    WorkbenchOptions,
    WorkbenchPlanIn,
    WorkbenchPlanOut,
    WorkbenchVersion,
    WorkbenchVersions,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import lifecycle as lc
from app.domain import scenario_runner as sr
from app.domain import script_authoring as sa
from app.domain import simulation_workbench as wb
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["simulation-workbench"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
NOTE = (
    "Simulation only: scenarios run the deterministic controller on synthetic facts. Pass / fail compares expected and "
    "actual controller behaviour exactly; identity and consent are simulated; answers are evaluated deterministically "
    "against the approved expected values (a match is not a compliance pass; a mismatch is not a finding) and no "
    "case, assignment, hold, attempt or KPI changes. Coverage is structural, not compliance quality or readiness."
)
GATE_STATUSES = (
    "CONFIRMED",
    "PENDING",
    "NOT_CONFIGURED",
    "FAILED",
    "INCONCLUSIVE",
    "WRONG_PERSON",
    "AGREED",
    "DECLINED",
    "CALLBACK_REQUESTED",
    "GRANTED",
    "NOT_ASKED",
)


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _who(auth: AuthContext) -> str:
    return str(auth.principal_id)


def _err(exc: wb.WorkbenchError) -> AppError:
    details = [{"message": d} for d in exc.details] if exc.details else None
    return AppError(exc.status, exc.code, exc.message, details=details)


def _read(auth: AuthContext) -> None:
    if "script.read" not in auth.permissions:
        raise AppError(403, "FORBIDDEN", "You do not have permission for this action")


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    entity_type: str,
    entity_id: str,
    after: dict[str, Any],
    reason: str | None = None,
) -> None:
    write_audit(
        db,
        action=action,
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type=entity_type,
        entity_id=entity_id,
        after=after,
        reason=reason,
    )


@router.get(
    "/simulation-workbench/options", response_model=WorkbenchOptions, operation_id="workbench_options", responses=_ERR
)
def workbench_options(auth: AuthContext = Depends(require("script.read"))) -> WorkbenchOptions:
    """Structured vocabulary for scenarios: step kinds, events, outcomes, termination reasons, gates and facts."""
    return WorkbenchOptions(
        step_kinds=list(sr.STEP_KINDS),
        events=dict(lc.EVENTS),
        outcomes=list(sr.OUTCOMES),
        termination_reasons=list(sr.TERMINATION_REASONS),
        gates=list(sr.GATES),
        gate_statuses=list(GATE_STATUSES),
        question_states=list(sr.QUESTION_STATES),
        default_responses=list(sr.DEFAULT_RESPONSES),
        condition_facts={k: list(v) for k, v in sa.CONDITION_FACTS.items()},
        risk_bands=list(sa.RISK_BANDS),
        note=NOTE,
        evaluation_results=list(sr.EVALUATION_RESULTS),
        evaluation_facts=list(wb.EVALUATION_FACT_KEYS),
        expectation_bases=list(sr.EXPECTATION_BASES),
    )


@router.get(
    "/simulation-workbench/versions",
    response_model=WorkbenchVersions,
    operation_id="workbench_versions",
    responses=_ERR,
)
def workbench_versions(
    auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> WorkbenchVersions:
    """Every script version you can test: drafts (labelled), in review, published and superseded."""
    return WorkbenchVersions(items=[WorkbenchVersion(**r) for r in wb.versions(db, _markets(auth))])


@router.post(
    "/simulation-workbench/plan", response_model=WorkbenchPlanOut, operation_id="workbench_plan", responses=_ERR
)
@csrf_protected
def workbench_plan(
    body: WorkbenchPlanIn,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> WorkbenchPlanOut:
    """Read-only: the modules and questions a version would run for the given synthetic facts and SBQ band."""
    try:
        wb.normalise(
            {
                "name": "plan",
                "script_version_id": body.script_version_id,
                "facts": body.facts,
                "risk_band": body.risk_band,
            }
        )
        plan, v, live = wb.plan_for(db, _markets(auth), body.script_version_id, body.facts, body.risk_band)
    except wb.WorkbenchError as exc:
        raise _err(exc) from exc
    return WorkbenchPlanOut(
        script_version_id=v["id"],
        script_label=plan.script_label,
        version_status=v["status"],
        content_approval_status=v["content_approval_status"],
        content_sha256=plan.manifest_sha256,
        live_eligibility=live,
        sections=[SimPlanSection(**s.__dict__) for s in plan.sections],
        questions=[SimPlanQuestion(**{**q.__dict__, "options": list(q.options)}) for q in plan.questions],
    )


@router.get(
    "/simulation-workbench/case-facts", response_model=CaseFactsOut, operation_id="workbench_case_facts", responses=_ERR
)
def workbench_case_facts(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> CaseFactsOut:
    """The applicability facts and SBQ band of a synthetic case's latest snapshot (to seed a scenario)."""
    _read(auth)
    try:
        return CaseFactsOut(**wb.case_facts(db, case_id, _markets(auth)))
    except wb.WorkbenchError as exc:
        if exc.status == 404:
            raise _deny(db, request, auth, "callback_case", case_id) from exc
        raise _err(exc) from exc


# ---- scenarios ---------------------------------------------------------------------------------------------------
@router.get("/simulation-scenarios", response_model=ScenarioList, operation_id="scenario_list", responses=_ERR)
def scenario_list(
    family_id: uuid.UUID | None = None,
    q: str | None = Query(default=None, max_length=60),
    include_archived: bool = False,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScenarioList:
    """The scenario library (newest change first) with each scenario's latest result."""
    rows = wb.scenarios(db, _markets(auth), family_id, q, include_archived)
    return ScenarioList(items=[ScenarioSummary(**r) for r in rows])


def _scenario_out(db: Session, scenario_id: uuid.UUID, markets: list[str], revision: int | None = None) -> ScenarioOut:
    s = wb.scenario_row(db, scenario_id, markets)
    rev = wb.revision_row(db, scenario_id, revision)
    v = wb.version(db, rev["script_version_id"], markets)
    copied = (
        db.execute(
            text("SELECT scenario_ref FROM simulation_scenario WHERE id = :i"), {"i": s["copied_from_id"]}
        ).scalar()
        if s["copied_from_id"]
        else None
    )
    case_ref = (
        db.execute(text("SELECT case_ref FROM callback_case WHERE id = :c"), {"c": rev["source_case_id"]}).scalar()
        if rev["source_case_id"]
        else None
    )
    revs = (
        db.execute(
            text(
                "SELECT r.revision, r.created_at, coalesce(p.display_name, r.created_by) AS created_by, r.change_note, "
                "f.code || ' v' || v.version_label AS version_label FROM simulation_scenario_revision r "
                "LEFT JOIN principal p ON CAST(p.id AS text) = r.created_by JOIN script_version v "
                "ON v.id = r.script_version_id JOIN script_family f ON f.id = v.script_family_id "
                "WHERE r.scenario_id = :s ORDER BY r.revision DESC"
            ),
            {"s": scenario_id},
        )
        .mappings()
        .all()
    )
    runs = (
        db.execute(
            text(
                "SELECT x.batch_id, b.batch_ref, x.side, x.status, x.stale, r.revision, x.created_at, "
                "f.code || ' v' || v.version_label AS version_label FROM simulation_result x JOIN simulation_batch b "
                "ON b.id = x.batch_id JOIN simulation_scenario_revision r ON r.id = x.scenario_revision_id "
                "JOIN script_version v ON v.id = x.script_version_id JOIN script_family f ON f.id = v.script_family_id "
                "WHERE x.scenario_id = :s ORDER BY x.created_at DESC LIMIT 20"
            ),
            {"s": scenario_id},
        )
        .mappings()
        .all()
    )
    return ScenarioOut(
        id=s["id"],
        scenario_ref=s["scenario_ref"],
        name=s["name"],
        status=s["status"],
        row_version=s["row_version"],
        family_id=s["script_family_id"],
        family=s["family"],
        copied_from_ref=copied,
        revision=rev["revision"],
        version_label=wb.label(v),
        version_status=v["status"],
        script_content_sha256=rev["script_content_sha256"],
        source_case_ref=case_ref,
        content=ScenarioContent(**wb.body_of(rev)),
        revisions=[ScenarioRevisionSummary(**r) for r in revs],
        runs=[{**dict(r), "batch_id": str(r["batch_id"]), "created_at": r["created_at"].isoformat()} for r in runs],
    )


@router.post(
    "/simulation-scenarios", response_model=ScenarioOut, status_code=201, operation_id="scenario_create", responses=_ERR
)
@csrf_protected
def scenario_create(
    body: ScenarioContent,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> ScenarioOut:
    """Create a scenario (revision 1). Steps and expectations are structured data, never code."""
    _guard(request, auth)
    try:
        sid = wb.create(db, _markets(auth), _who(auth), body.model_dump(mode="json"))
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    ref = db.execute(text("SELECT scenario_ref FROM simulation_scenario WHERE id = :i"), {"i": sid}).scalar_one()
    _audit(
        db,
        request,
        auth,
        "SIMULATION.SCENARIO_CREATED",
        "simulation_scenario",
        ref,
        {"scenario": str(sid), "name": body.name, "script_version_id": str(body.script_version_id)},
    )
    db.commit()
    return _scenario_out(db, sid, _markets(auth))


@router.post(
    "/simulation-scenarios/preview", response_model=ScenarioPreviewOut, operation_id="scenario_preview", responses=_ERR
)
@csrf_protected
def scenario_preview(
    body: ScenarioPreviewIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> ScenarioPreviewOut:
    """Dry run of unsaved scenario content against the controller (nothing is written)."""
    try:
        r = wb.preview(db, _markets(auth), body.model_dump(mode="json"))
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.rollback()  # a dry run writes nothing
    return ScenarioPreviewOut(
        status=r["status"],
        version_label=wb.label(r["version"]),
        problems=r["problems"],
        failures=r["failures"],
        error=r["error"],
        stale_reasons=r["stale_reasons"],
        actual=r["actual"],
        response_log=r["response_log"],
    )


@router.get(
    "/simulation-scenarios/{scenario_id}", response_model=ScenarioOut, operation_id="scenario_get", responses=_ERR
)
def scenario_get(
    scenario_id: uuid.UUID,
    revision: int | None = Query(default=None, ge=1),
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScenarioOut:
    """A scenario (current or a given revision), its revision history and recent results."""
    try:
        return _scenario_out(db, scenario_id, _markets(auth), revision)
    except wb.WorkbenchError as exc:
        raise _err(exc) from exc


@router.put(
    "/simulation-scenarios/{scenario_id}", response_model=ScenarioOut, operation_id="scenario_revise", responses=_ERR
)
@csrf_protected
def scenario_revise(
    scenario_id: uuid.UUID,
    body: ScenarioReviseIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> ScenarioOut:
    """Save a new revision (earlier revisions and their results are kept unchanged)."""
    _guard(request, auth)
    try:
        wb.revise(
            db,
            scenario_id,
            _markets(auth),
            _who(auth),
            body.expected_row_version,
            body.content.model_dump(mode="json"),
            body.change_note,
        )
        s = wb.scenario_row(db, scenario_id, _markets(auth))
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "SIMULATION.SCENARIO_REVISED",
        "simulation_scenario",
        s["scenario_ref"],
        {"scenario": str(scenario_id), "revision": s["current_revision"]},
        body.change_note,
    )
    db.commit()
    return _scenario_out(db, scenario_id, _markets(auth))


@router.post(
    "/simulation-scenarios/{scenario_id}/copy",
    response_model=ScenarioOut,
    status_code=201,
    operation_id="scenario_copy",
    responses=_ERR,
)
@csrf_protected
def scenario_copy(
    scenario_id: uuid.UUID,
    body: ScenarioCopyIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> ScenarioOut:
    """Copy the current revision into a new scenario (for reuse or another version)."""
    _guard(request, auth)
    try:
        sid = wb.copy(db, scenario_id, _markets(auth), _who(auth), body.name)
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    ref = db.execute(text("SELECT scenario_ref FROM simulation_scenario WHERE id = :i"), {"i": sid}).scalar_one()
    _audit(
        db,
        request,
        auth,
        "SIMULATION.SCENARIO_COPIED",
        "simulation_scenario",
        ref,
        {"scenario": str(sid), "copied_from": str(scenario_id)},
    )
    db.commit()
    return _scenario_out(db, sid, _markets(auth))


@router.post(
    "/simulation-scenarios/{scenario_id}/status",
    response_model=ScenarioOut,
    operation_id="scenario_status",
    responses=_ERR,
)
@csrf_protected
def scenario_status(
    scenario_id: uuid.UUID,
    body: ScenarioStatusIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> ScenarioOut:
    """Archive or restore a scenario (never deleted)."""
    _guard(request, auth)
    try:
        wb.set_status(db, scenario_id, _markets(auth), body.expected_row_version, body.status)
        s = wb.scenario_row(db, scenario_id, _markets(auth))
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        f"SIMULATION.SCENARIO_{'ARCHIVED' if body.status == 'ARCHIVED' else 'RESTORED'}",
        "simulation_scenario",
        s["scenario_ref"],
        {"scenario": str(scenario_id), "status": body.status},
    )
    db.commit()
    return _scenario_out(db, scenario_id, _markets(auth))


# ---- automated runs ----------------------------------------------------------------------------------------------
def _batch_out(db: Session, batch_id: uuid.UUID, markets: list[str]) -> SimBatchOut:
    d = wb.batch(db, batch_id, markets)
    b = d["batch"]
    va = db.execute(
        text(
            "SELECT f.code || ' v' || v.version_label FROM script_version v JOIN script_family f "
            "ON f.id = v.script_family_id WHERE v.id = :v"
        ),
        {"v": b["version_a_id"]},
    ).scalar()
    vb = db.execute(
        text(
            "SELECT f.code || ' v' || v.version_label FROM script_version v JOIN script_family f "
            "ON f.id = v.script_family_id WHERE v.id = :v"
        ),
        {"v": b["version_b_id"]},
    ).scalar()
    return SimBatchOut(
        id=b["id"],
        batch_ref=b["batch_ref"],
        kind=b["kind"],
        totals=b["totals"],
        started_at=b["started_at"],
        started_by=b["display_name"] or b["started_by"],
        version_a=va,
        version_b=vb,
        results=[SimResultOut(**{k: r[k] for k in SimResultOut.model_fields}) for r in d["results"]],
        coverage=d["coverage"],
        comparison=d["comparison"],
        note=NOTE,
    )


@router.post(
    "/simulation-runs", response_model=SimBatchOut, status_code=201, operation_id="scenario_run", responses=_ERR
)
@csrf_protected
def scenario_run(
    body: ScenarioRunIn,
    request: Request,
    auth: AuthContext = Depends(require("script.simulate")),
    db: Session = Depends(get_db),
) -> SimBatchOut:
    """Run one or more scenarios (each against its own version, or all against one version; with a second version
    this is a comparison). Results are recorded with the exact content snapshot and scenario revision used."""
    _guard(request, auth)
    try:
        bid = wb.run(
            db, _markets(auth), _who(auth), body.scenario_ids, body.script_version_id, body.compare_with_version_id
        )
    except wb.WorkbenchError as exc:
        db.rollback()
        raise _err(exc) from exc
    ref, totals = db.execute(text("SELECT batch_ref, totals FROM simulation_batch WHERE id = :b"), {"b": bid}).one()
    _audit(
        db,
        request,
        auth,
        "SIMULATION.BATCH_RUN",
        "simulation_batch",
        ref,
        {
            "batch": str(bid),
            "scenarios": len(body.scenario_ids),
            "totals": totals,
            "comparison": body.compare_with_version_id is not None,
        },
    )
    db.commit()
    return _batch_out(db, bid, _markets(auth))


@router.get("/simulation-runs", response_model=SimBatchList, operation_id="scenario_run_list", responses=_ERR)
def scenario_run_list(
    scenario_id: uuid.UUID | None = None,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> SimBatchList:
    """Recent test runs (newest first), optionally those that included a scenario."""
    rows = wb.batches(db, _markets(auth), scenario_id)
    return SimBatchList(items=[SimBatchSummary(**{**r, "started_by": r["display_name"]}) for r in rows])


@router.get("/simulation-runs/{batch_id}", response_model=SimBatchOut, operation_id="scenario_run_get", responses=_ERR)
def scenario_run_get(
    batch_id: uuid.UUID, auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> SimBatchOut:
    """A test run: each result with its explained failures, coverage per script snapshot and any comparison."""
    try:
        return _batch_out(db, batch_id, _markets(auth))
    except wb.WorkbenchError as exc:
        raise _err(exc) from exc
