"""Policy register (F4: API-050; POL-002/003, SEARCH-002…006). One row per policy in scope.

Every query repeats ``market_code = ANY(:m)`` (D-39: SG only), so out-of-scope policies, their sales, parties and
cases never enter a row, count or facet. Case state and outcome come from the same scoped ``Facts`` as the Overview
and the case register; the effective SBQ band is the latest FINAL assessment of a sale (as ``load_facts``). Names
and contact values are returned in their stored masked form only; phone and email search compares the protected
HMAC token and never decrypts a value.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from app.domain.kpis import Facts
from app.domain.protection import DataProtection
from app.domain.register import (
    BAND_RANK,
    MAX_Q,
    NOT_ASSESSED,
    OUTCOME_CODES,
    InvalidFilter,
    contact_tokens,
    decode_cursor,
    encode_cursor,
    normalise_ref,
)

SORTS = ("latest_sold_at", "policy_ref", "premium_amount", "risk_band", "cases")


@dataclass
class PolicyCase:
    id: uuid.UUID
    ref: str
    sale_event_id: uuid.UUID
    state: str
    outcome: str
    created_at: datetime
    script: str | None


@dataclass
class Sale:
    id: uuid.UUID
    ref: str
    type: str
    sold_at: datetime
    channel: str | None
    location: str | None
    fsc_ref: str | None
    fsc_name: str | None
    band: str = NOT_ASSESSED


@dataclass
class PolicyRegisterRow:
    id: uuid.UUID
    ref: str
    product_code: str
    product_family: str
    product_subtype: str
    is_ilp: bool
    premium_amount: float | None
    currency: str | None
    premium_frequency: str | None
    is_synthetic: bool
    owners: list[str] = field(default_factory=list)
    insured: list[str] = field(default_factory=list)
    sales: list[Sale] = field(default_factory=list)
    cases: list[PolicyCase] = field(default_factory=list)
    refs: set[str] = field(default_factory=set)  # sale, party, case and FSC refs for text search
    contact_tokens: set[str] = field(default_factory=set)

    @property
    def latest_sale(self) -> Sale | None:
        return self.sales[-1] if self.sales else None

    @property
    def band(self) -> str:
        return self.latest_sale.band if self.latest_sale else NOT_ASSESSED

    @property
    def latest_case(self) -> PolicyCase | None:
        return max(self.cases, key=lambda c: (c.created_at, c.ref)) if self.cases else None


def load_policy_rows(conn: Connection, f: Facts) -> list[PolicyRegisterRow]:
    m = {"m": f.markets}
    rows: dict[uuid.UUID, PolicyRegisterRow] = {}
    for r in conn.execute(
        text(
            "SELECT id, policy_ref, product_code, product_family, product_subtype, is_ilp, premium_amount, currency, "
            "premium_frequency, is_synthetic FROM policy WHERE market_code = ANY(:m)"
        ),
        m,
    ):
        rows[r.id] = PolicyRegisterRow(
            r.id,
            r.policy_ref,
            r.product_code,
            r.product_family,
            r.product_subtype,
            r.is_ilp,
            float(r.premium_amount) if r.premium_amount is not None else None,
            r.currency,
            r.premium_frequency,
            r.is_synthetic,
        )
    for r in conn.execute(
        text(
            "SELECT pr.policy_id, pr.role, pa.party_ref, pa.masked_name FROM policy_party_role pr "
            "JOIN party pa ON pa.id = pr.party_id JOIN policy p ON p.id = pr.policy_id "
            "WHERE p.market_code = ANY(:m) AND pr.valid_to IS NULL ORDER BY pa.party_ref, pr.role"
        ),
        m,
    ):
        row = rows[r.policy_id]
        row.refs.add(r.party_ref)
        if r.role == "OWNER" and r.masked_name not in row.owners:
            row.owners.append(r.masked_name)
        if r.role == "INSURED" and r.masked_name not in row.insured:
            row.insured.append(r.masked_name)
    sales: dict[uuid.UUID, Sale] = {}
    for r in conn.execute(
        text(
            "SELECT s.id, s.policy_id, s.sale_ref, s.sale_event_type, s.sold_at, s.selling_channel, "
            "s.selling_location, f.fsc_ref, f.display_name FROM sale_event s JOIN policy p ON p.id = s.policy_id "
            "LEFT JOIN fsc_representative f ON f.id = s.fsc_id WHERE p.market_code = ANY(:m) "
            "ORDER BY s.sold_at, s.sale_ref"
        ),
        m,
    ):
        sale = Sale(
            r.id,
            r.sale_ref,
            r.sale_event_type,
            r.sold_at,
            r.selling_channel,
            r.selling_location,
            r.fsc_ref,
            r.display_name,
        )
        sales[r.id] = sale
        rows[r.policy_id].sales.append(sale)
        rows[r.policy_id].refs.update(x for x in (r.sale_ref, r.fsc_ref) if x)
    for r in conn.execute(
        text(
            "SELECT DISTINCT ON (ra.sale_event_id) ra.sale_event_id, ra.band_code FROM risk_assessment ra "
            "JOIN sale_event s ON s.id = ra.sale_event_id JOIN policy p ON p.id = s.policy_id "
            "WHERE p.market_code = ANY(:m) AND ra.status = 'FINAL' ORDER BY ra.sale_event_id, ra.valid_at DESC"
        ),
        m,
    ):
        if r.band_code:
            sales[r.sale_event_id].band = r.band_code
    for r in conn.execute(
        text(
            "SELECT c.id, s.policy_id, "
            "(SELECT sf.code || ' v' || sv.version_label FROM script_assignment sa JOIN script_version sv "
            " ON sv.id = sa.script_version_id JOIN script_family sf ON sf.id = sv.script_family_id "
            " WHERE sa.callback_case_id = c.id ORDER BY sa.assigned_at DESC LIMIT 1) AS script "
            "FROM callback_case c JOIN sale_event s ON s.id = c.sale_event_id JOIN policy p ON p.id = s.policy_id "
            "WHERE c.market_code = ANY(:m) AND p.market_code = ANY(:m)"
        ),
        m,
    ):
        case = f.cases.get(r.id)
        if case is None:
            continue
        rows[r.policy_id].cases.append(
            PolicyCase(case.id, case.ref, case.sale_event_id, case.state, case.category, case.created_at, r.script)
        )
        rows[r.policy_id].refs.add(case.ref)
    for r in conn.execute(
        text(
            "SELECT DISTINCT pr.policy_id, cm.value_hmac FROM contact_method cm JOIN policy_party_role pr "
            "ON pr.party_id = cm.party_id JOIN policy p ON p.id = pr.policy_id WHERE p.market_code = ANY(:m)"
        ),
        m,
    ):
        rows[r.policy_id].contact_tokens.add(r.value_hmac)
    return list(rows.values())


# ---- filters -----------------------------------------------------------------------------------------------
@dataclass
class PolicyFilters:
    q: str | None = None
    product_family: list[str] = field(default_factory=list)
    ilp: bool | None = None
    band: list[str] = field(default_factory=list)
    channel: list[str] = field(default_factory=list)
    sale_type: list[str] = field(default_factory=list)
    multi_sale: bool | None = None
    case_state: list[str] = field(default_factory=list)
    outcome: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.q is not None and len(self.q) > MAX_Q:
            raise InvalidFilter("QUERY_TOO_LONG", f"q must be at most {MAX_Q} characters")
        bad = [o for o in self.outcome if o not in OUTCOME_CODES]
        if bad:
            raise InvalidFilter("INVALID_FILTER", f"Unknown outcome: {bad[0]}")


Pred = Callable[[PolicyRegisterRow], bool]


def _text_match(row: PolicyRegisterRow, q: str, tokens: set[str]) -> bool:
    if tokens & row.contact_tokens:
        return True
    return any(ref.startswith(q) or (len(q) >= 4 and q in ref) for ref in (row.ref, *row.refs))


def policy_predicates(flt: PolicyFilters, dp: DataProtection | None) -> dict[str, Pred]:
    """One predicate per facet dimension, so each facet excludes its own selection (disjunctive counts)."""
    p: dict[str, Pred] = {}
    if flt.q and flt.q.strip():
        q, tokens = normalise_ref(flt.q), contact_tokens(dp, flt.q)
        p["q"] = lambda r: _text_match(r, q, tokens)
    if flt.product_family:
        fams = set(flt.product_family)
        p["product_family"] = lambda r: r.product_family in fams
    if flt.ilp is not None:
        ilp = flt.ilp
        p["ilp"] = lambda r: r.is_ilp is ilp
    if flt.band:
        bands = set(flt.band)
        p["band"] = lambda r: r.band in bands
    if flt.channel:
        channels = set(flt.channel)
        p["channel"] = lambda r: r.latest_sale is not None and r.latest_sale.channel in channels
    if flt.sale_type:
        types = set(flt.sale_type)
        p["sale_type"] = lambda r: any(s.type in types for s in r.sales)
    if flt.multi_sale is not None:
        multi = flt.multi_sale
        p["multi_sale"] = lambda r: (len(r.sales) > 1) is multi
    if flt.case_state:
        states = set(flt.case_state)
        p["case_state"] = lambda r: r.latest_case is not None and r.latest_case.state in states
    if flt.outcome:
        outs = set(flt.outcome)
        p["outcome"] = lambda r: r.latest_case is not None and r.latest_case.outcome in outs
    return p


def apply(
    rows: Sequence[PolicyRegisterRow], preds: dict[str, Pred], *, skip: str | None = None
) -> list[PolicyRegisterRow]:
    active = [fn for k, fn in preds.items() if k != skip]
    return [r for r in rows if all(fn(r) for fn in active)]


FACET_DIMENSIONS: dict[str, Callable[[PolicyRegisterRow], list[str]]] = {
    "product_family": lambda r: [r.product_family],
    "ilp": lambda r: ["true" if r.is_ilp else "false"],
    "band": lambda r: [r.band],
    "channel": lambda r: [r.latest_sale.channel] if r.latest_sale and r.latest_sale.channel else [],
    "sale_type": lambda r: sorted({s.type for s in r.sales}),
    "multi_sale": lambda r: ["true" if len(r.sales) > 1 else "false"],
    "case_state": lambda r: [r.latest_case.state] if r.latest_case else [],
    "outcome": lambda r: [r.latest_case.outcome] if r.latest_case else [],
}


def policy_facets(rows: Sequence[PolicyRegisterRow], preds: dict[str, Pred]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for dim, values in FACET_DIMENSIONS.items():
        counts: Counter[str] = Counter()
        for r in apply(rows, preds, skip=dim):
            counts.update(values(r))
        out[dim] = dict(sorted(counts.items()))
    return out


# ---- sorting and cursors -----------------------------------------------------------------------------------
def _sort_key(r: PolicyRegisterRow, name: str) -> tuple[Any, ...]:
    latest = r.latest_sale
    primary: Any = {
        "latest_sold_at": latest.sold_at.timestamp() if latest else 0.0,
        "policy_ref": "",
        "premium_amount": r.premium_amount if r.premium_amount is not None else -1.0,
        "risk_band": BAND_RANK.get(r.band, 9),
        "cases": len(r.cases),
    }[name]
    return (primary, r.ref)


def policy_page(
    rows: list[PolicyRegisterRow], sort: str, limit: int, cursor: str | None
) -> tuple[list[PolicyRegisterRow], str | None]:
    """Keyset pagination over (sort value, policy_ref), as the case register."""
    desc = sort.startswith("-")
    name = sort[1:] if desc else sort
    if name not in SORTS:
        raise InvalidFilter("INVALID_FILTER", f"sort must be one of {', '.join(SORTS)} (prefix - for descending)")
    ordered = sorted(rows, key=lambda r: _sort_key(r, name), reverse=desc)
    if cursor:
        after = decode_cursor(cursor, sort)
        ordered = [r for r in ordered if (_sort_key(r, name) < after if desc else _sort_key(r, name) > after)]
    chunk = ordered[:limit]
    nxt = encode_cursor(sort, _sort_key(chunk[-1], name)) if len(ordered) > limit else None
    return chunk, nxt
