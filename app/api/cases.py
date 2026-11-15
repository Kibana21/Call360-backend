"""Callback case register, facets and work queues (F2: API-035, API-036, API-076). Read-only.

Scope (D-39: SG only) is applied when the facts are loaded, before any filter, count or facet, so out-of-scope
records can never be inferred (SEARCH-006). KPI drilldowns reuse the Overview predicate functions (BE-KPI-02).
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.schemas import CaseFacets, CaseList, CaseRow, ErrorResponse, PageInfo, WorkQueueList
from app.core.errors import AppError
from app.domain.kpis import Facts, load_facts
from app.domain.register import (
    Filters,
    InvalidFilter,
    Row,
    apply,
    facets,
    page,
    predicates,
    queue_counts,
    term_hash,
)
from app.domain.register import load_rows as _load_rows
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1", tags=["cases"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 422, 429)}
log = logging.getLogger("call360.search")


def scoped(db: Session, auth: AuthContext) -> tuple[Facts, list[Row]]:
    conn = db.connection()
    schema = conn.execute(text("SELECT current_schema()")).scalar_one()
    f = load_facts(conn, schema, sorted(auth.markets), datetime.now(UTC))
    return f, _load_rows(conn, f)


def filters(
    q: str | None = Query(None, description="Case, policy, attempt or session ref; or an exact phone / email"),
    state: list[str] = Query([]),
    outcome: list[str] = Query([]),
    band: list[str] = Query([], description="Effective SBQ band code, or NOT_ASSESSED"),
    hold_reason: list[str] = Query([]),
    product_family: list[str] = Query([]),
    ilp: bool | None = Query(None),
    overdue: bool | None = Query(None),
    on_hold: bool | None = Query(None),
    due_from: date | None = Query(None, description="Inclusive local date (Asia/Singapore)"),
    due_to: date | None = Query(None, description="Exclusive local date (Asia/Singapore)"),
    queue: str | None = Query(None, description="DUE_TODAY | OVERDUE | AWAITING_CALLBACK | ON_HOLD"),
    kpi: str | None = Query(None, description="Dashboard drilldown KPI (case grain)"),
    kpi_set: str | None = Query(None, description="numerator | denominator"),
    kpi_from: date | None = Query(None, alias="from", description="KPI range start (local date)"),
    kpi_to: date | None = Query(None, alias="to", description="KPI range end, exclusive (local date)"),
) -> Filters:
    flt = Filters(
        q,
        state,
        outcome,
        band,
        hold_reason,
        product_family,
        ilp,
        overdue,
        on_hold,
        due_from,
        due_to,
        queue,
        kpi,
        kpi_set,
        kpi_from,
        kpi_to,
    )
    try:
        flt.validate()
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return flt


def to_row(r: Row, now: datetime) -> CaseRow:
    c = r.case
    return CaseRow(
        case_id=c.id,
        case_ref=c.ref,
        policy_id=r.policy_id,
        policy_ref=r.policy_ref,
        policyholder=r.policyholder,
        product_family=r.product_family,
        product_subtype=r.product_subtype,
        is_ilp=r.is_ilp,
        risk_band=r.band,
        state=c.state,
        outcome=c.category,
        holds=sorted({h for h, _ in c.holds}),
        blocking_hold=any(b for _, b in c.holds),
        overdue=c.category == "OPEN" and c.due_at < now,
        due_at=c.due_at,
        attempts=r.attempts,
        latest_attempt_status=r.latest_attempt,
        sessions=r.sessions,
        script=r.script,
        evidence="NOT_AVAILABLE",
        is_synthetic=c.is_synthetic,
        route=f"/cases/{c.id}",
    )


@router.get("/cases", response_model=CaseList, operation_id="cases_list", responses=_ERR)
def list_cases(
    request: Request,
    flt: Filters = Depends(filters),
    sort: str = Query("due_at", description="due_at | case_ref | state | risk_band | attempts; prefix - for desc"),
    limit: int = Query(25, ge=1, le=100),
    cursor: str | None = Query(None, max_length=512),
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> CaseList:
    f, rows = scoped(db, auth)
    if flt.q:
        log.info("case register search", extra={"q_sha256": term_hash(flt.q), "cid": request.state.correlation_id})
    matched = apply(rows, predicates(f, flt, request.app.state.data_protection))
    try:
        chunk, nxt = page(matched, sort, limit, cursor)
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return CaseList(
        items=[to_row(r, f.now) for r in chunk],
        total=len(matched),
        page=PageInfo(next_cursor=nxt, limit=limit, sort=sort),
        markets=f.markets,
        data_as_of=f.now,
        synthetic_badge=any(r.case.is_synthetic for r in matched),
    )


@router.get("/cases/facets", response_model=CaseFacets, operation_id="cases_facets", responses=_ERR)
def case_facets(
    request: Request,
    flt: Filters = Depends(filters),
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> CaseFacets:
    f, rows = scoped(db, auth)
    preds = predicates(f, flt, request.app.state.data_protection)
    return CaseFacets(total=len(apply(rows, preds)), facets=facets(rows, preds, f), markets=f.markets, data_as_of=f.now)


@router.get("/work-queues", response_model=WorkQueueList, operation_id="work_queues", responses=_ERR)
def work_queues(auth: AuthContext = Depends(require("queue.read")), db: Session = Depends(get_db)) -> WorkQueueList:
    conn = db.connection()
    schema = conn.execute(text("SELECT current_schema()")).scalar_one()
    f = load_facts(conn, schema, sorted(auth.markets), datetime.now(UTC))
    return WorkQueueList.model_validate(
        {
            "items": queue_counts(f),
            "markets": f.markets,
            "data_as_of": f.now,
            "time_zone": "Asia/Singapore",
            "synthetic_badge": any(c.is_synthetic for c in f.cases.values()),
        }
    )
