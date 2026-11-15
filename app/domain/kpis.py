"""Overview KPIs and operational counts (S0_KPI_DEFINITIONS §1–§4; API-030…034).

Every number is derived from persisted rows **after** the caller's market scope is applied (SEARCH-006, D-39:
SG only). Each KPI is one predicate function over scoped case facts returning (denominator ids, numerator ids),
so the Call Explorer drilldown (F2) can reuse the identical predicate (APP-004, BE-KPI-02). NOT_MEASURED KPIs
never return a number. NOT_VERIFIED, CANCELLED and SLA breach describe the callback verification, never the sale.
"""

from __future__ import annotations

import statistics
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import Connection, Result, text

from app.domain.outcomes import derive_outcomes

SGT = ZoneInfo("Asia/Singapore")
REPORTING_VERSION = "S0-KPI-2"
REOPEN = "NOT_SUPPORTED_IN_S0"
TERMINAL_ATTEMPTS = {"NO_ANSWER", "BUSY", "WRONG_PARTY", "FAILED", "CONNECTED", "IN_SESSION", "ENDED"}
CONNECTED_ATTEMPTS = {"CONNECTED", "IN_SESSION", "ENDED"}
OUTCOMES = ("VERIFIED_COMPLIANT", "VERIFIED_WITH_FINDINGS", "NOT_VERIFIED", "CANCELLED", "OPEN")
GUARD = "VERIFIED_CONTROL_EVIDENCE_INCOMPLETE"
VERIFIED = {"VERIFIED_COMPLIANT", "VERIFIED_WITH_FINDINGS"}


@dataclass
class Case:
    id: uuid.UUID
    ref: str
    state: str
    due_at: datetime
    created_at: datetime
    source_type: str
    verified_at: datetime | None
    closure_reason: str | None
    cancellation_reason: str | None
    cancellation_version: uuid.UUID | None
    cancelled_recorded_at: datetime | None
    authorised: bool
    is_synthetic: bool
    sale_event_id: uuid.UUID
    category: str = "OPEN"
    attempts: list[tuple[int, str, datetime | None]] = field(default_factory=list)
    holds: list[tuple[str, bool]] = field(default_factory=list)
    band: str | None = None


@dataclass
class Facts:
    markets: list[str]
    now: datetime
    cases: dict[uuid.UUID, Case]
    attempts: list[tuple[uuid.UUID, uuid.UUID, str, datetime | None]]  # id, case, status, started_at
    runs: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    exempt_eligible: dict[tuple[uuid.UUID, str], bool]
    material: set[str]
    materiality_version: int | None
    bands: list[tuple[str, str, dict[str, Any]]]  # active sbq_risk_band (code, label, attributes)

    def due_in(self, start: datetime, end: datetime) -> list[Case]:
        return [c for c in self.cases.values() if start <= c.due_at < end]


def local_range(start: date, end: date) -> tuple[datetime, datetime]:
    """[from, to) local dates (Asia/Singapore) → UTC instants."""
    return (
        datetime.combine(start, time(), SGT).astimezone(UTC),
        datetime.combine(end, time(), SGT).astimezone(UTC),
    )


def default_range(now: datetime) -> tuple[date, date]:
    today = now.astimezone(SGT).date()
    return today - timedelta(days=29), today + timedelta(days=1)


def load_facts(conn: Connection, schema: str, markets: Sequence[str], now: datetime) -> Facts:
    """All scoped rows the Overview needs. Scope (``market_code = ANY(:m)``) is in every query."""
    m = {"m": list(markets)}

    def q(sql: str, **params: Any) -> Result[Any]:
        return conn.execute(text(sql), {**m, **params})

    cases: dict[uuid.UUID, Case] = {}
    for r in q(
        "SELECT id, case_ref, state, due_at, created_at, source_type, verified_at, closure_reason, "
        "cancellation_reason, cancellation_reason_list_version_id, cancelled_recorded_at, "
        "(cancellation_authorized_by IS NOT NULL AND cancellation_authorization_ref IS NOT NULL) AS authorised, "
        "is_synthetic, sale_event_id FROM callback_case WHERE market_code = ANY(:m)"
    ):
        cases[r.id] = Case(
            r.id,
            r.case_ref,
            r.state,
            r.due_at,
            r.created_at,
            r.source_type,
            r.verified_at,
            r.closure_reason,
            r.cancellation_reason,
            r.cancellation_reason_list_version_id,
            r.cancelled_recorded_at,
            r.authorised,
            r.is_synthetic,
            r.sale_event_id,
        )
    outcomes = derive_outcomes(conn, schema, markets)
    for c in cases.values():
        c.category = outcomes[c.ref].category
    attempts = []
    for r in q(
        "SELECT a.id, a.callback_case_id, a.sequence, a.status, a.started_at FROM contact_attempt a "
        "JOIN callback_case c ON c.id = a.callback_case_id WHERE c.market_code = ANY(:m) ORDER BY a.sequence"
    ):
        cases[r.callback_case_id].attempts.append((r.sequence, r.status, r.started_at))
        attempts.append((r.id, r.callback_case_id, r.status, r.started_at))
    for r in q(
        "SELECT h.callback_case_id, h.hold_reason, h.is_blocking FROM case_hold h JOIN callback_case c "
        "ON c.id = h.callback_case_id WHERE c.market_code = ANY(:m) AND h.released_at IS NULL"
    ):
        cases[r.callback_case_id].holds.append((r.hold_reason, r.is_blocking))
    for r in q(
        "SELECT DISTINCT ON (ra.sale_event_id) ra.sale_event_id, ra.band_code FROM risk_assessment ra "
        "JOIN callback_case c ON c.sale_event_id = ra.sale_event_id WHERE c.market_code = ANY(:m) "
        "AND ra.status = 'FINAL' ORDER BY ra.sale_event_id, ra.valid_at DESC"
    ):
        for c in cases.values():
            if c.sale_event_id == r.sale_event_id:
                c.band = r.band_code
    runs = [
        dict(r._mapping)
        for r in q(
            "SELECT r.id, a.callback_case_id AS case_id, r.status, r.started_at, r.completed_at, "
            "EXISTS (SELECT 1 FROM rule_evaluation e JOIN question_execution qe ON qe.id = e.question_execution_id "
            "WHERE qe.survey_run_id = r.id) AS evaluated FROM survey_run r JOIN conversation_session s "
            "ON s.id = r.session_id JOIN contact_attempt a ON a.id = s.contact_attempt_id JOIN callback_case c "
            "ON c.id = a.callback_case_id WHERE c.market_code = ANY(:m)"
        )
    ]
    findings = [
        dict(r._mapping)
        for r in q(
            "SELECT f.id, f.callback_case_id AS case_id, f.severity, f.status, f.raised_at, f.review_assigned_at, "
            "f.review_closed_at, qe.survey_run_id AS run_id FROM finding f JOIN callback_case c "
            "ON c.id = f.callback_case_id LEFT JOIN question_execution qe ON qe.id = f.question_execution_id "
            "WHERE c.market_code = ANY(:m)"
        )
    ]
    eligible = {
        (r.code_list_version_id, r.code): bool(r.attributes.get("sla_exempt_eligible"))
        for r in q(
            "SELECT cv.code_list_version_id, cv.code, cv.attributes FROM code_value cv JOIN code_list_version v "
            "ON v.id = cv.code_list_version_id JOIN code_list l ON l.id = v.code_list_id "
            "WHERE l.code = 'case_cancellation_reason'"
        )
    }
    active = {
        r.list: (r.version, r.values)
        for r in q(
            "SELECT l.code AS list, v.version, jsonb_agg(jsonb_build_object('code', cv.code, 'label', cv.label, "
            "'attributes', cv.attributes, 'sort', cv.sort_order) ORDER BY cv.sort_order) AS values "
            "FROM code_list l JOIN code_list_version v ON v.code_list_id = l.id AND v.status = 'ACTIVE' "
            "JOIN code_value cv ON cv.code_list_version_id = v.id "
            "WHERE l.code IN ('finding_materiality_policy', 'sbq_risk_band') GROUP BY l.code, v.version"
        )
    }
    mat_version, mat_values = active.get("finding_materiality_policy", (None, []))
    material = {v["code"] for v in mat_values if v["attributes"].get("material")}
    bands = [(v["code"], v["label"], v["attributes"]) for v in active.get("sbq_risk_band", (None, []))[1]]
    return Facts(list(markets), now, cases, attempts, runs, findings, eligible, material, mat_version, bands)


# ---- helpers -----------------------------------------------------------------------------------------------
def sla_exempt(f: Facts, c: Case) -> bool:
    """SLA-EX-001 (D-18): eligible reason + recorded authorisation + recorded strictly before due_at."""
    return bool(
        c.state == "CANCELLED"
        and c.cancellation_version is not None
        and f.exempt_eligible.get((c.cancellation_version, c.cancellation_reason or ""), False)
        and c.authorised
        and c.cancelled_recorded_at is not None
        and c.cancelled_recorded_at < c.due_at
    )


def breached(c: Case) -> bool:
    return c.verified_at is None or c.verified_at > c.due_at


def pct(num: int, den: int) -> float | None:
    return round(100 * num / den, 1) if den else None


IdSet = set[uuid.UUID]
Predicate = Callable[[Facts, datetime, datetime], tuple[IdSet, IdSet]]


def _ids(cases: list[Case]) -> IdSet:
    return {c.id for c in cases}


# ---- KPI predicates: (denominator case ids, numerator case ids) for case-grain KPIs --------------------------
def kpi_01(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.state != "CANCELLED"]
    return _ids(den), {c.id for c in den if any(st != "SCHEDULED" for _, st, _ in c.attempts)}


def kpi_04(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.state != "CANCELLED"]
    return _ids(den), {c.id for c in den if c.category in VERIFIED}


def kpi_05(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.state != "CANCELLED"]
    return _ids(den), {c.id for c in den if c.category == "NOT_VERIFIED" and c.closure_reason == "ATTEMPTS_EXHAUSTED"}


def kpi_10(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.due_at < f.now and not sla_exempt(f, c)]
    return _ids(den), {c.id for c in den if breached(c)}


def kpi_12(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if sum(st != "SCHEDULED" for _, st, _ in c.attempts) >= 2]

    def first_connected_late(c: Case) -> bool:
        seqs = sorted(seq for seq, st, _ in c.attempts if st == "CONNECTED")
        return bool(seqs) and seqs[0] >= 2

    return _ids(den), {c.id for c in den if first_connected_late(c)}


def kpi_16(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.category in VERIFIED]
    return _ids(den), {c.id for c in den if c.category == "VERIFIED_WITH_FINDINGS"}


def kpi_17(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = [c for c in f.due_in(s, e) if c.category not in {"CANCELLED", "OPEN"}]
    return _ids(den), {c.id for c in den if c.category == "NOT_VERIFIED"}


def kpi_18(f: Facts, s: datetime, e: datetime) -> tuple[IdSet, IdSet]:
    den = f.due_in(s, e)
    return _ids(den), {c.id for c in den if c.category == "CANCELLED"}


CASE_PREDICATES: dict[str, Predicate] = {
    "KPI-01": kpi_01,
    "KPI-04": kpi_04,
    "KPI-05": kpi_05,
    "KPI-10": kpi_10,
    "KPI-12": kpi_12,
    "KPI-16": kpi_16,
    "KPI-17": kpi_17,
    "KPI-18": kpi_18,
}


# ---- payload assembly --------------------------------------------------------------------------------------
@dataclass
class Ctx:
    f: Facts
    start: date
    end: date
    s: datetime
    e: datetime

    def base(self, kid: str, label: str, grain: str, cohort: str, unit: str = "percent", **kw: Any) -> dict[str, Any]:
        synthetic = any(c.is_synthetic for c in self.f.cases.values())
        out: dict[str, Any] = {
            "definition_id": kid,
            "label": label,
            "grain": grain,
            "numerator": None,
            "denominator": None,
            "value": None,
            "unit": unit,
            "status": "MEASURED",
            "stage_note": None,
            "cohort_basis": cohort,
            "range": {"from": self.start, "to": self.end},
            "time_zone": "Asia/Singapore",
            "filter_scope": {"markets": self.f.markets},
            "dedup_rule": "",
            "eligibility_rule": "",
            "exclusions": {},
            "exemptions_applied": [],
            "materiality_policy_version": None,
            "reopen_handling": REOPEN,
            "data_as_of": self.f.now,
            "reporting_version": REPORTING_VERSION,
            "synthetic_badge": synthetic,
            "drilldown": {"numerator": None, "denominator": None},
            "breakdown": {},
        }
        out.update(kw)
        return out

    def drill(self, kid: str) -> dict[str, str]:
        q = f"from={self.start.isoformat()}&to={self.end.isoformat()}"
        return {s: f"/calls?kpi={kid}&kpi_set={s}&{q}" for s in ("numerator", "denominator")}

    def case_kpi(
        self,
        kid: str,
        label: str,
        eligibility: str,
        *,
        held: bool = True,
        cancelled_excluded: bool,
        breakdown: dict[str, Any] | None = None,
        **kw: Any,
    ) -> dict[str, Any]:
        den, num = CASE_PREDICATES[kid](self.f, self.s, self.e)
        return self.base(
            kid,
            label,
            "case",
            "callback_case.due_at ∈ range",
            numerator=len(num),
            denominator=len(den),
            value=pct(len(num), len(den)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule=eligibility,
            exclusions={"excluded_cancelled": cancelled_excluded, "held_in_denominator": held},
            drilldown=self.drill(kid),
            breakdown=breakdown or {},
            **kw,
        )


def _not_measured(ctx: Ctx, kid: str, label: str, grain: str, note: str) -> dict[str, Any]:
    return ctx.base(kid, label, grain, "—", status="NOT_MEASURED", stage_note=note)


def compute_kpis(f: Facts, start: date, end: date, permissions: frozenset[str]) -> list[dict[str, Any]]:
    s, e = local_range(start, end)
    ctx = Ctx(f, start, end, s, e)
    due = f.due_in(s, e)
    out: list[dict[str, Any]] = []

    out.append(
        ctx.case_kpi(
            "KPI-01",
            "Callback coverage",
            "Cases due in range, excluding CANCELLED; held included",
            cancelled_excluded=True,
        )
    )
    att = [a for a in f.attempts if a[3] is not None and s <= a[3] < e and a[2] in TERMINAL_ATTEMPTS]
    conn_n = sum(1 for a in att if a[2] in CONNECTED_ATTEMPTS)
    out.append(
        ctx.base(
            "KPI-02",
            "Connection rate",
            "attempt",
            "contact_attempt.started_at ∈ range",
            numerator=conn_n,
            denominator=len(att),
            value=pct(conn_n, len(att)),
            dedup_rule="COUNT(contact_attempt.id)",
            eligibility_rule="Attempts in a terminal outcome (in-flight excluded)",
            exclusions={"held_in_denominator": True, "cancelled_cases_included": True},
        )
    )
    runs = [r for r in f.runs if s <= r["started_at"] < e and r["status"] != "NOT_STARTED"]
    done = sum(1 for r in runs if r["status"] == "COMPLETED")
    out.append(
        ctx.base(
            "KPI-03",
            "Survey completion (completed / started)",
            "survey run",
            "survey_run.started_at ∈ range",
            numerator=done,
            denominator=len(runs),
            value=pct(done, len(runs)),
            dedup_rule="COUNT(survey_run.id)",
            eligibility_rule="Runs with status ≠ NOT_STARTED",
        )
    )
    v_parts = Counter(c.category for c in due if c.state != "CANCELLED" and c.category in VERIFIED)
    out.append(
        ctx.case_kpi(
            "KPI-04",
            "Verification rate",
            "Cases due in range, excluding CANCELLED; held included",
            cancelled_excluded=True,
            breakdown={k: v_parts.get(k, 0) for k in sorted(VERIFIED)},
        )
    )
    out.append(
        ctx.case_kpi("KPI-05", "Contact exhaustion", "Cases due in range, excluding CANCELLED", cancelled_excluded=True)
    )

    done_runs = [
        r
        for r in f.runs
        if r["status"] == "COMPLETED"
        and r["completed_at"] is not None
        and s <= r["completed_at"] < e
        and r["evaluated"]
    ]
    run_ids = {r["id"] for r in done_runs}
    den6 = {r["case_id"] for r in done_runs}
    num6 = {x["case_id"] for x in f.findings if x["run_id"] in run_ids and x["severity"] in f.material}
    out.append(
        ctx.base(
            "KPI-06",
            "Compliance exception rate",
            "case",
            "survey_run.completed_at ∈ range",
            numerator=len(num6),
            denominator=len(den6),
            value=pct(len(num6), len(den6)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule="Cases with ≥1 COMPLETED run in range that has ≥1 rule evaluation",
            materiality_policy_version=f.materiality_version,
            breakdown={"material_severities": sorted(f.material)},
        )
    )

    crit = [x for x in f.findings if x["severity"] == "CRITICAL" and x["status"] in {"OPEN", "UNDER_REVIEW"}]
    ages: Counter[str] = Counter()
    for x in crit:
        d = (f.now - x["raised_at"]).days
        ages["0-2d" if d <= 2 else "3-7d" if d <= 7 else "8-14d" if d <= 14 else ">14d"] += 1
    out.append(
        ctx.base(
            "KPI-07",
            "Critical exception backlog",
            "finding",
            "snapshot at data_as_of",
            unit="count",
            numerator=len(crit),
            value=float(len(crit)),
            dedup_rule="COUNT(finding.id)",
            eligibility_rule="CRITICAL findings OPEN or UNDER_REVIEW",
            breakdown={k: ages.get(k, 0) for k in ("0-2d", "3-7d", "8-14d", ">14d")},
        )
    )
    out.append(
        _not_measured(ctx, "KPI-08", "Recording integrity", "session", "No recordings are captured before Stage S1")
    )
    out.append(
        _not_measured(ctx, "KPI-09", "Transcript integrity", "session", "Transcripts are captured from Stage S1")
    )

    matured = [c for c in due if c.due_at < f.now]
    exempt = [c for c in matured if sla_exempt(f, c)]
    _, num10 = kpi_10(f, s, e)
    by_cat = Counter(f.cases[i].category for i in num10)
    out.append(
        ctx.case_kpi(
            "KPI-10",
            "SLA breach rate",
            "Matured cases due in range, including held and non-exempt CANCELLED",
            cancelled_excluded=False,
            cohort_basis="callback_case.due_at ∈ range and due_at < data_as_of",
            exemptions_applied=[{"rule": "SLA-EX-001", "count": len(exempt)}],
            breakdown={
                "breached_by_outcome": {k: by_cat.get(k, 0) for k in (*OUTCOMES, GUARD)},
                "note": "Timeliness indicator, not a compliance outcome",
            },
        )
    )

    closed = [
        x for x in f.findings if x["review_assigned_at"] and x["review_closed_at"] and s <= x["review_closed_at"] < e
    ]
    hours = sorted((x["review_closed_at"] - x["review_assigned_at"]).total_seconds() / 3600 for x in closed)
    p90 = hours[min(len(hours) - 1, int(0.9 * len(hours)))] if hours else None
    out.append(
        ctx.base(
            "KPI-11",
            "Review turnaround (median hours)",
            "finding review",
            "finding.review_closed_at ∈ range",
            unit="hours",
            numerator=len(closed),
            denominator=len(closed),
            value=round(statistics.median(hours), 1) if hours else None,
            dedup_rule="COUNT(finding.id)",
            eligibility_rule="Findings with assigned and closed reviews",
            stage_note=None if hours else "No reviews closed in range; review decisions arrive in S3",
            breakdown={"p90_hours": round(p90, 1) if p90 is not None else None},
        )
    )
    out.append(
        ctx.case_kpi("KPI-12", "Retry conversion", "Cases with ≥2 non-scheduled attempts", cancelled_excluded=False)
    )
    created = [c for c in f.cases.values() if s <= c.created_at < e]
    out.append(
        ctx.base(
            "KPI-13",
            "New cases (intake cohort)",
            "case",
            "callback_case.created_at ∈ range",
            unit="count",
            numerator=len(created),
            value=float(len(created)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule="Cases created in range",
            breakdown={"by_source_type": dict(Counter(c.source_type for c in created))},
        )
    )
    if "intake.read" in permissions:
        out.append(
            _not_measured(
                ctx, "KPI-14", "Intake runs", "intake run", "Intake runs are recorded from Data Intake (CP0.4)"
            )
        )
    cats = Counter(c.category for c in due)
    breach_all = Counter(c.category for c in matured if not sla_exempt(f, c) and breached(c))
    out.append(
        ctx.base(
            "KPI-15",
            "Outcome distribution",
            "case",
            "callback_case.due_at ∈ range",
            unit="count",
            numerator=len(due),
            denominator=len(due),
            value=float(len(due)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule="All cases due in range (including CANCELLED, OPEN and held)",
            exclusions={"held_in_denominator": True, "excluded_cancelled": False},
            breakdown={
                "counts": {k: cats.get(k, 0) for k in OUTCOMES},
                "shares": {k: pct(cats.get(k, 0), len(due)) for k in OUTCOMES},
                "guard_count": cats.get(GUARD, 0),
                "sla_breached": {k: breach_all.get(k, 0) for k in OUTCOMES},
            },
            drilldown=ctx.drill("KPI-15"),
        )
    )
    out.append(
        ctx.case_kpi("KPI-16", "Findings rate among verified", "Verified cases due in range", cancelled_excluded=True)
    )
    nv = Counter(c.closure_reason for c in due if c.category == "NOT_VERIFIED")
    out.append(
        ctx.case_kpi(
            "KPI-17",
            "Not-verified rate",
            "Terminal cases due in range, excluding CANCELLED and OPEN",
            cancelled_excluded=True,
            breakdown={"by_closure_reason": dict(nv)},
        )
    )
    canc = [c for c in due if c.category == "CANCELLED"]
    out.append(
        ctx.case_kpi(
            "KPI-18",
            "Cancellation rate",
            "All cases due in range",
            cancelled_excluded=False,
            breakdown={
                "by_reason": dict(Counter(c.cancellation_reason for c in canc)),
                "sla_exempt_eligible": sum(sla_exempt(f, c) for c in canc),
            },
        )
    )
    out.extend(_ops(ctx, due))
    return out


def _ops(ctx: Ctx, due: list[Case]) -> list[dict[str, Any]]:
    f = ctx.f
    today = f.now.astimezone(SGT).date()
    t0, t1 = local_range(today, today + timedelta(days=1))
    open_cases = [c for c in f.cases.values() if c.category == "OPEN"]
    snap = "snapshot at data_as_of"

    def count(kid: str, label: str, cases: list[Case], rule: str, **kw: Any) -> dict[str, Any]:
        return ctx.base(
            kid,
            label,
            "case",
            kw.pop("cohort", snap),
            unit="count",
            numerator=len(cases),
            value=float(len(cases)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule=rule,
            **kw,
        )

    held = [c for c in open_cases if c.holds]
    by_reason = Counter(r for c in held for r, _ in c.holds)
    blocking = sum(1 for c in held if any(b for _, b in c.holds))
    high = {code for code, _, attrs in f.bands if attrs.get("high_priority") is True}
    _, num4 = kpi_04(f, ctx.s, ctx.e)
    den4, _ = kpi_04(f, ctx.s, ctx.e)
    parts = Counter(f.cases[i].category for i in num4)
    canc = [c for c in due if c.category == "CANCELLED"]
    out = [
        count(
            "OPS-01",
            "Open callback cases",
            open_cases,
            "Outcome category OPEN",
            breakdown={"overdue": sum(1 for c in open_cases if c.due_at < f.now)},
            drilldown={"numerator": "/calls?outcome=OPEN", "denominator": None},
        ),
        count(
            "OPS-02",
            "Due today",
            [c for c in open_cases if t0 <= c.due_at < t1],
            "OPEN cases due on today's local date",
            drilldown={"numerator": "/calls?queue=DUE_TODAY", "denominator": None},
        ),
        count(
            "OPS-03",
            "On hold",
            held,
            "OPEN cases with ≥1 active hold (SLA clock still running)",
            breakdown={"by_reason": dict(by_reason), "blocking": blocking},
            drilldown={"numerator": "/calls?queue=ON_HOLD", "denominator": None},
        ),
        count(
            "OPS-04",
            "Awaiting review",
            [c for c in f.cases.values() if c.state == "AWAITING_REVIEW"],
            "Cases in state AWAITING_REVIEW",
            drilldown={"numerator": "/calls?state=AWAITING_REVIEW", "denominator": None},
        ),
        ctx.base(
            "OPS-05",
            "Verified cases",
            "case",
            "callback_case.due_at ∈ range",
            unit="count",
            numerator=len(num4),
            denominator=len(den4),
            value=float(len(num4)),
            dedup_rule="COUNT(DISTINCT callback_case.id)",
            eligibility_rule="KPI-04 numerator",
            breakdown={k: parts.get(k, 0) for k in sorted(VERIFIED)},
            drilldown=ctx.drill("KPI-04"),
        ),
    ]
    if high:
        due_high = [c for c in open_cases if ctx.s <= c.due_at < ctx.e and c.band in high]
        out.append(
            count(
                "OPS-06",
                "High-risk due",
                due_high,
                "OPEN cases due in range with a high-priority band",
                cohort="callback_case.due_at ∈ range",
            )
        )
    else:
        out.append(
            _not_measured(
                ctx, "OPS-06", "High-risk due", "case", "The active sbq_risk_band version marks no band high_priority"
            )
        )
    out.append(
        count(
            "OPS-07",
            "Cancelled",
            canc,
            "KPI-18 numerator",
            cohort="callback_case.due_at ∈ range",
            drilldown={"numerator": ctx.drill("KPI-18")["numerator"], "denominator": None},
            breakdown={"by_reason": dict(Counter(c.cancellation_reason for c in canc))},
        )
    )
    return out


# ---- API-031…034 -------------------------------------------------------------------------------------------
TREND_KPIS = {
    "KPI-02": "Connection rate",
    "KPI-03": "Survey completion (completed / started)",
    "KPI-13": "New cases (intake cohort)",
}


def trend(f: Facts, kid: str, days: int) -> list[dict[str, Any]]:
    today = f.now.astimezone(SGT).date()
    points = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        s, e = local_range(d, d + timedelta(days=1))
        if kid == "KPI-02":
            att = [a for a in f.attempts if a[3] is not None and s <= a[3] < e and a[2] in TERMINAL_ATTEMPTS]
            num, den = sum(1 for a in att if a[2] in CONNECTED_ATTEMPTS), len(att)
        elif kid == "KPI-03":
            runs = [r for r in f.runs if s <= r["started_at"] < e and r["status"] != "NOT_STARTED"]
            num, den = sum(1 for r in runs if r["status"] == "COMPLETED"), len(runs)
        else:
            num = den = sum(1 for c in f.cases.values() if s <= c.created_at < e)
        value = float(num) if kid == "KPI-13" else pct(num, den)
        points.append({"date": d, "numerator": num, "denominator": den, "value": value})
    return points


def risk_distribution(f: Facts) -> list[dict[str, Any]]:
    open_cases = [c for c in f.cases.values() if c.category == "OPEN"]
    counts = Counter(c.band or "NOT_ASSESSED" for c in open_cases)
    rows = [(code, label) for code, label, _ in f.bands] + [("NOT_ASSESSED", "No SBQ assessment (risk triage)")]
    total = len(open_cases)
    return [
        {
            "band": code,
            "label": label,
            "count": counts.get(code, 0),
            "share": pct(counts.get(code, 0), total),
            "drilldown": f"/calls?outcome=OPEN&band={code}",
        }
        for code, label in rows
    ]


ATTENTION_WEIGHTS = {
    "CRITICAL_FINDING": 50,
    "OVERDUE": 30,
    "BLOCKING_HOLD": 20,
    "HIGH_FINDING": 15,
    "AWAITING_REVIEW": 10,
    "DUE_TODAY": 8,
}
ATTENTION_LABELS = {
    "CRITICAL_FINDING": "Critical finding open",
    "OVERDUE": "Past due (SLA clock running)",
    "BLOCKING_HOLD": "Blocking hold",
    "HIGH_FINDING": "High-severity finding open",
    "AWAITING_REVIEW": "Awaiting review",
    "DUE_TODAY": "Due today",
}


def attention(f: Facts, limit: int) -> list[dict[str, Any]]:
    today = f.now.astimezone(SGT).date()
    t0, t1 = local_range(today, today + timedelta(days=1))
    open_findings: dict[uuid.UUID, set[str]] = {}
    for x in f.findings:
        if x["status"] in {"OPEN", "UNDER_REVIEW"}:
            open_findings.setdefault(x["case_id"], set()).add(x["severity"])
    items = []
    for c in f.cases.values():
        if c.category != "OPEN":
            continue
        reasons = []
        sev = open_findings.get(c.id, set())
        if "CRITICAL" in sev:
            reasons.append("CRITICAL_FINDING")
        if c.due_at < f.now:
            reasons.append("OVERDUE")
        if any(b for _, b in c.holds):
            reasons.append("BLOCKING_HOLD")
        if "HIGH" in sev:
            reasons.append("HIGH_FINDING")
        if c.state == "AWAITING_REVIEW":
            reasons.append("AWAITING_REVIEW")
        if t0 <= c.due_at < t1:
            reasons.append("DUE_TODAY")
        if reasons:
            items.append((sum(ATTENTION_WEIGHTS[r] for r in reasons), c, reasons))
    items.sort(key=lambda t: (-t[0], t[1].due_at, t[1].ref))
    return [
        {
            "case": c,
            "priority": p,
            "reasons": [{"code": r, "label": ATTENTION_LABELS[r]} for r in rs],
            "holds": [h for h, _ in c.holds],
        }
        for p, c, rs in items[:limit]
    ]
