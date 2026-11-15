"""Overview (Command Centre) APIs: API-030…034 (F1; S0_KPI_DEFINITIONS). Read-only, `dashboard.read`.

Every query is filtered to the caller's effective markets (D-39: SG only) before aggregation. A principal with
no market scope receives empty results, never an error that reveals data.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.schemas import (
    ActivityItem,
    ActivityList,
    AttentionItem,
    AttentionList,
    AttentionReason,
    ErrorResponse,
    KpiList,
    KpiOut,
    KpiTrend,
    RiskBucket,
    RiskDistribution,
    TrendPoint,
)
from app.core.errors import AppError
from app.domain.kpis import TREND_KPIS, Facts, attention, compute_kpis, default_range, load_facts, risk_distribution
from app.domain.kpis import trend as trend_points
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 422, 429)}
RISK_NOTE = "Risk affects script selection and handling priority, not an automatic misconduct verdict."


def _facts(db: Session, auth: AuthContext) -> Facts:
    conn = db.connection()
    schema = conn.execute(text("SELECT current_schema()")).scalar_one()
    return load_facts(conn, schema, sorted(auth.markets), datetime.now(UTC))


def _synthetic(f: Facts) -> bool:
    return any(c.is_synthetic for c in f.cases.values())


@router.get("/kpis", response_model=KpiList, operation_id="dashboard_kpis", responses=_ERR)
def get_kpis(
    start: date | None = Query(None, alias="from", description="Inclusive local date (Asia/Singapore)"),
    end: date | None = Query(None, alias="to", description="Exclusive local date (Asia/Singapore)"),
    auth: AuthContext = Depends(require("dashboard.read")),
    db: Session = Depends(get_db),
) -> KpiList:
    f = _facts(db, auth)
    d_from, d_to = default_range(f.now)
    start, end = start or d_from, end or d_to
    if start >= end or (end - start) > timedelta(days=366):
        raise AppError(422, "INVALID_RANGE", "The range must satisfy from < to and span at most 366 days")
    items = [KpiOut.model_validate(k) for k in compute_kpis(f, start, end, auth.permissions)]
    return KpiList.model_validate(
        {
            "items": items,
            "range": {"from": start, "to": end},
            "markets": f.markets,
            "data_as_of": f.now,
            "synthetic_badge": _synthetic(f),
        }
    )


@router.get("/trend", response_model=KpiTrend, operation_id="dashboard_trend", responses=_ERR)
def get_trend(
    kpi: str = Query("KPI-02", pattern="^KPI-(02|03|13)$"),
    days: int = Query(7),
    auth: AuthContext = Depends(require("dashboard.read")),
    db: Session = Depends(get_db),
) -> KpiTrend:
    if days not in (7, 30):
        raise AppError(422, "INVALID_RANGE", "days must be 7 or 30")
    f = _facts(db, auth)
    return KpiTrend(
        definition_id=kpi,
        label=TREND_KPIS[kpi],
        days=days,
        time_zone="Asia/Singapore",
        markets=f.markets,
        data_as_of=f.now,
        synthetic_badge=_synthetic(f),
        points=[TrendPoint(**p) for p in trend_points(f, kpi, days)],
    )


@router.get("/attention", response_model=AttentionList, operation_id="dashboard_attention", responses=_ERR)
def get_attention(
    limit: int = Query(8, ge=1, le=20),
    auth: AuthContext = Depends(require("dashboard.read")),
    db: Session = Depends(get_db),
) -> AttentionList:
    f = _facts(db, auth)
    rows = attention(f, limit)
    labels: dict[Any, tuple[str, str]] = {}
    if rows:
        for r in db.execute(
            text(
                "SELECT c.id, p.policy_ref, (SELECT pa.masked_name FROM policy_party_role r JOIN party pa "
                "ON pa.id = r.party_id WHERE r.policy_id = p.id AND r.role = 'OWNER' ORDER BY pa.party_ref LIMIT 1) "
                "AS owner FROM callback_case c JOIN sale_event s ON s.id = c.sale_event_id JOIN policy p "
                "ON p.id = s.policy_id WHERE c.id = ANY(:ids) AND c.market_code = ANY(:m)"
            ),
            {"ids": [x["case"].id for x in rows], "m": f.markets},
        ):
            labels[r.id] = (r.policy_ref, r.owner or "—")
    items = [
        AttentionItem(
            case_id=x["case"].id,
            case_ref=x["case"].ref,
            policy_ref=labels[x["case"].id][0],
            policyholder=labels[x["case"].id][1],
            state=x["case"].state,
            due_at=x["case"].due_at,
            risk_band=x["case"].band,
            holds=x["holds"],
            reasons=[AttentionReason(**r) for r in x["reasons"]],
            priority=x["priority"],
            route=f"/cases/{x['case'].id}",
        )
        for x in rows
    ]
    return AttentionList(items=items, markets=f.markets, data_as_of=f.now, synthetic_badge=_synthetic(f))


@router.get("/activity", response_model=ActivityList, operation_id="dashboard_activity", responses=_ERR)
def get_activity(
    limit: int = Query(10, ge=1, le=50),
    auth: AuthContext = Depends(require("dashboard.read")),
    db: Session = Depends(get_db),
) -> ActivityList:
    markets = sorted(auth.markets)
    rows = db.execute(
        text(
            "SELECT e.id, e.occurred_at, e.event_type, e.summary, c.id AS case_id, c.case_ref, e.related_entity_type, "
            "c.is_synthetic FROM case_event e JOIN callback_case c ON c.id = e.callback_case_id "
            "WHERE c.market_code = ANY(:m) AND e.occurred_at <= now() ORDER BY e.occurred_at DESC, e.id LIMIT :n"
        ),
        {"m": markets, "n": limit},
    ).all()
    items = [
        ActivityItem(
            event_id=r.id,
            occurred_at=r.occurred_at,
            event_type=r.event_type,
            summary=r.summary,
            case_id=r.case_id,
            case_ref=r.case_ref,
            related_entity_type=r.related_entity_type,
        )
        for r in rows
    ]
    return ActivityList(items=items, markets=markets, synthetic_badge=any(r.is_synthetic for r in rows))


@router.get(
    "/risk-distribution", response_model=RiskDistribution, operation_id="dashboard_risk_distribution", responses=_ERR
)
def get_risk_distribution(
    auth: AuthContext = Depends(require("dashboard.read")), db: Session = Depends(get_db)
) -> RiskDistribution:
    f = _facts(db, auth)
    buckets = risk_distribution(f)
    return RiskDistribution(
        items=[RiskBucket(**b) for b in buckets],
        total_open=sum(b["count"] for b in buckets),
        markets=f.markets,
        data_as_of=f.now,
        synthetic_badge=_synthetic(f),
        note=RISK_NOTE,
    )
