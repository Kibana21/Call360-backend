"""SBQ Risk Workbench register (F5: API-056; RISK-001…006). One row per stored SBQ callback-selection assessment.

Read-only over persisted records: no score, band or threshold is computed here (RISK-008 is Stage S2). Every query
repeats ``market_code = ANY(:m)`` through the assessment's sale and policy (D-39: SG only), so no out-of-scope row,
count or facet can appear. Two derived flags only compare stored rows of the same sale:
- ``effective``: the latest FINAL assessment of the sale (as ``load_facts`` and Call Detail);
- ``discrepancy``: the sale's latest FINAL SOURCE_ASSIGNED band differs from its latest FINAL RULE_ASSESSED band.
Investment suitability (fact snapshots) and finding severity are separate records and never enter this register.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from app.domain.register import BAND_RANK, MAX_Q, InvalidFilter, decode_cursor, encode_cursor, normalise_ref

SORTS = ("valid_at", "band", "sale_ref", "origin")
ORIGIN_RANK = {"RULE_ASSESSED": 0, "SOURCE_ASSIGNED": 1, "MANUAL": 2}


@dataclass
class Assessment:
    id: uuid.UUID
    sale_event_id: uuid.UUID
    sale_ref: str
    sale_event_type: str
    sold_at: datetime
    policy_id: uuid.UUID
    policy_ref: str
    product_family: str
    is_ilp: bool
    channel: str | None
    fsc_ref: str | None
    origin: str
    status: str
    band: str | None
    score: float | None
    reason_codes: list[str]
    source_original_value: str | None
    rule_set: str | None
    assessed_at: datetime | None
    valid_at: datetime
    input_snapshot_sha256: str | None
    supersedes_id: uuid.UUID | None
    is_synthetic: bool
    matched_factors: list[str] = field(default_factory=list)
    superseded_by: uuid.UUID | None = None
    effective: bool = False
    discrepancy: bool = False
    cases: list[tuple[uuid.UUID, str]] = field(default_factory=list)

    @property
    def band_code(self) -> str:
        return self.band or "NO_BAND"


def latest_final(rows: list[Assessment], origin: str | None = None) -> Assessment | None:
    finals = [a for a in rows if a.status == "FINAL" and (origin is None or a.origin == origin)]
    return max(finals, key=lambda a: (a.valid_at, str(a.id))) if finals else None


def load_assessments(conn: Connection, markets: list[str]) -> list[Assessment]:
    m = {"m": markets}
    rows: dict[uuid.UUID, Assessment] = {}
    for r in conn.execute(
        text(
            "SELECT ra.*, s.sale_ref, s.sale_event_type, s.sold_at, s.selling_channel, p.id AS pid, p.policy_ref, "
            "p.product_family, p.is_ilp, f.fsc_ref, rs.code || ' v' || rs.version AS rule_set "
            "FROM risk_assessment ra JOIN sale_event s ON s.id = ra.sale_event_id JOIN policy p ON p.id = s.policy_id "
            "LEFT JOIN fsc_representative f ON f.id = s.fsc_id "
            "LEFT JOIN risk_rule_set_version rs ON rs.id = ra.rule_set_version_id WHERE p.market_code = ANY(:m)"
        ),
        m,
    ).mappings():
        rows[r["id"]] = Assessment(
            r["id"],
            r["sale_event_id"],
            r["sale_ref"],
            r["sale_event_type"],
            r["sold_at"],
            r["pid"],
            r["policy_ref"],
            r["product_family"],
            r["is_ilp"],
            r["selling_channel"],
            r["fsc_ref"],
            r["origin"],
            r["status"],
            r["band_code"],
            float(r["score"]) if r["score"] is not None else None,
            list(r["reason_codes"] or []),
            r["source_original_value"],
            r["rule_set"],
            r["assessed_at"],
            r["valid_at"],
            r["input_snapshot_sha256"],
            r["supersedes_id"],
            r["is_synthetic"],
        )
    for fr in conn.execute(
        text(
            "SELECT fr.assessment_id, fr.factor_code FROM risk_factor_result fr "
            "JOIN risk_assessment ra ON ra.id = fr.assessment_id JOIN sale_event s ON s.id = ra.sale_event_id "
            "JOIN policy p ON p.id = s.policy_id WHERE p.market_code = ANY(:m) AND fr.result = 'MATCHED' "
            "ORDER BY fr.factor_code"
        ),
        m,
    ):
        rows[fr.assessment_id].matched_factors.append(fr.factor_code)
    by_sale: dict[uuid.UUID, list[Assessment]] = {}
    for a in rows.values():
        by_sale.setdefault(a.sale_event_id, []).append(a)
        if a.supersedes_id in rows:
            rows[a.supersedes_id].superseded_by = a.id
    for cr in conn.execute(
        text(
            "SELECT c.id, c.case_ref, c.sale_event_id FROM callback_case c JOIN sale_event s ON s.id = c.sale_event_id "
            "JOIN policy p ON p.id = s.policy_id WHERE c.market_code = ANY(:m) AND p.market_code = ANY(:m) "
            "ORDER BY c.case_ref"
        ),
        m,
    ):
        for a in by_sale.get(cr.sale_event_id, []):
            a.cases.append((cr.id, cr.case_ref))
    for sale_rows in by_sale.values():
        eff = latest_final(sale_rows)
        if eff:
            eff.effective = True
        src, rule = latest_final(sale_rows, "SOURCE_ASSIGNED"), latest_final(sale_rows, "RULE_ASSESSED")
        if src and rule and src.band != rule.band:
            src.discrepancy = rule.discrepancy = True
    return list(rows.values())


def sale_population(conn: Connection, markets: list[str]) -> int:
    return int(
        conn.execute(
            text("SELECT count(*) FROM sale_event s JOIN policy p ON p.id = s.policy_id WHERE p.market_code = ANY(:m)"),
            {"m": markets},
        ).scalar_one()
    )


def summary(rows: Sequence[Assessment], sales: int) -> dict[str, Any]:
    """Two explicitly separate populations: assessments (one row each) and sale events (effective band per sale)."""
    effective = [a for a in rows if a.effective]
    assessed_sales = {a.sale_event_id for a in rows}
    return {
        "assessments": {
            "total": len(rows),
            "by_origin": dict(sorted(Counter(a.origin for a in rows).items())),
            "by_status": dict(sorted(Counter(a.status for a in rows).items())),
            "by_band": dict(sorted(Counter(a.band_code for a in rows).items())),
            "superseded": sum(1 for a in rows if a.superseded_by or a.status == "SUPERSEDED"),
        },
        "sales": {
            "total": sales,
            "by_effective_band": dict(sorted(Counter(a.band_code for a in effective).items())),
            "without_assessment": sales - len(assessed_sales),
            "without_final_assessment": len(assessed_sales) - len({a.sale_event_id for a in effective}),
            "source_rule_discrepancies": len({a.sale_event_id for a in rows if a.discrepancy}),
        },
    }


# ---- filters -----------------------------------------------------------------------------------------------
@dataclass
class RiskFilters:
    q: str | None = None
    band: list[str] = field(default_factory=list)
    factor: list[str] = field(default_factory=list)
    origin: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    rule_set: list[str] = field(default_factory=list)
    product_family: list[str] = field(default_factory=list)
    channel: list[str] = field(default_factory=list)
    fsc: list[str] = field(default_factory=list)
    effective: bool | None = None
    discrepancy: bool | None = None

    def validate(self) -> None:
        if self.q is not None and len(self.q) > MAX_Q:
            raise InvalidFilter("QUERY_TOO_LONG", f"q must be at most {MAX_Q} characters")


Pred = Callable[[Assessment], bool]


def _any(values: list[str], get: Callable[[Assessment], Any]) -> Pred:
    wanted = set(values)
    return lambda a: get(a) in wanted


def risk_predicates(flt: RiskFilters) -> dict[str, Pred]:
    p: dict[str, Pred] = {}
    if flt.q and flt.q.strip():
        q = normalise_ref(flt.q)

        def text_match(a: Assessment) -> bool:
            refs = [a.sale_ref, a.policy_ref, a.fsc_ref or "", *(ref for _, ref in a.cases)]
            return any(r.startswith(q) or (len(q) >= 4 and q in r) for r in refs if r)

        p["q"] = text_match
    if flt.band:
        p["band"] = _any(flt.band, lambda a: a.band_code)
    if flt.factor:
        factors = set(flt.factor)
        p["factor"] = lambda a: bool(factors & set(a.matched_factors))
    if flt.origin:
        p["origin"] = _any(flt.origin, lambda a: a.origin)
    if flt.status:
        p["status"] = _any(flt.status, lambda a: a.status)
    if flt.rule_set:
        p["rule_set"] = _any(flt.rule_set, lambda a: a.rule_set or "NONE")
    if flt.product_family:
        p["product_family"] = _any(flt.product_family, lambda a: a.product_family)
    if flt.channel:
        p["channel"] = _any(flt.channel, lambda a: a.channel)
    if flt.fsc:
        p["fsc"] = _any(flt.fsc, lambda a: a.fsc_ref)
    if flt.effective is not None:
        eff = flt.effective
        p["effective"] = lambda a: a.effective is eff
    if flt.discrepancy is not None:
        disc = flt.discrepancy
        p["discrepancy"] = lambda a: a.discrepancy is disc
    return p


def apply(rows: Sequence[Assessment], preds: dict[str, Pred], *, skip: str | None = None) -> list[Assessment]:
    active = [fn for k, fn in preds.items() if k != skip]
    return [r for r in rows if all(fn(r) for fn in active)]


FACET_DIMENSIONS: dict[str, Callable[[Assessment], list[str]]] = {
    "band": lambda a: [a.band_code],
    "factor": lambda a: a.matched_factors,
    "origin": lambda a: [a.origin],
    "status": lambda a: [a.status],
    "rule_set": lambda a: [a.rule_set or "NONE"],
    "product_family": lambda a: [a.product_family],
    "channel": lambda a: [a.channel] if a.channel else [],
    "fsc": lambda a: [a.fsc_ref] if a.fsc_ref else [],
    "effective": lambda a: ["true" if a.effective else "false"],
    "discrepancy": lambda a: ["true" if a.discrepancy else "false"],
}


def risk_facets(rows: Sequence[Assessment], preds: dict[str, Pred]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for dim, values in FACET_DIMENSIONS.items():
        counts: Counter[str] = Counter()
        for r in apply(rows, preds, skip=dim):
            counts.update(values(r))
        out[dim] = dict(sorted(counts.items()))
    return out


def _sort_key(a: Assessment, name: str) -> tuple[Any, ...]:
    primary: Any = {
        "valid_at": a.valid_at.timestamp(),
        "band": BAND_RANK.get(a.band_code, 9),
        "sale_ref": a.sale_ref,
        "origin": ORIGIN_RANK.get(a.origin, 9),
    }[name]
    return (primary, f"{a.sale_ref}/{a.id}")


def risk_page(rows: list[Assessment], sort: str, limit: int, cursor: str | None) -> tuple[list[Assessment], str | None]:
    """Keyset pagination over (sort value, sale_ref/id), as the case and policy registers."""
    desc = sort.startswith("-")
    name = sort[1:] if desc else sort
    if name not in SORTS:
        raise InvalidFilter("INVALID_FILTER", f"sort must be one of {', '.join(SORTS)} (prefix - for descending)")
    ordered = sorted(rows, key=lambda a: _sort_key(a, name), reverse=desc)
    if cursor:
        after = decode_cursor(cursor, sort)
        ordered = [a for a in ordered if (_sort_key(a, name) < after if desc else _sort_key(a, name) > after)]
    chunk = ordered[:limit]
    nxt = encode_cursor(sort, _sort_key(chunk[-1], name)) if len(ordered) > limit else None
    return chunk, nxt
