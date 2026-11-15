"""Callback case register, work queues and search (F2: API-035/036/070/071/076; SEARCH-002…007, APP-004/005).

Rows are built from the same scoped ``Facts`` as the Overview (``app.domain.kpis``), so a KPI drilldown applies the
identical predicate function (BE-KPI-02) and queue counts equal the OPS-0x cards. Scope (D-39: SG only) is applied
in every query before any filter, count, facet or suggestion. Personal data is returned masked only; phone and
email search compares the protected HMAC token (``contact_method.value_hmac``) and never decrypts a value.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from sqlalchemy import Connection, text

from app.domain.kpis import CASE_PREDICATES, GUARD, OUTCOMES, SGT, Case, Facts, local_range
from app.domain.protection import DataProtection

NOT_ASSESSED = "NOT_ASSESSED"
BAND_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3, NOT_ASSESSED: 4}
OUTCOME_CODES = (*OUTCOMES, GUARD)
QUEUES = {
    "DUE_TODAY": ("Due today", "OPEN cases due on today's local date (Asia/Singapore); equals OPS-02"),
    "OVERDUE": ("Overdue", "OPEN cases whose due_at has passed; equals the OPS-01 overdue breakdown"),
    "AWAITING_CALLBACK": ("Awaiting callback", "OPEN cases in state AWAITING_CALLBACK"),
    "ON_HOLD": ("On hold", "OPEN cases with ≥1 active hold (SLA clock still running); equals OPS-03"),
}
SORTS = ("due_at", "case_ref", "state", "risk_band", "attempts")
MAX_Q = 64


class InvalidFilter(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---- rows --------------------------------------------------------------------------------------------------
@dataclass
class Row:
    case: Case
    policy_id: uuid.UUID
    policy_ref: str
    policyholder: str
    product_family: str
    product_subtype: str
    is_ilp: bool
    script: str | None
    latest_attempt: str | None
    attempt_refs: list[tuple[str, uuid.UUID]] = field(default_factory=list)
    session_refs: list[tuple[str, uuid.UUID]] = field(default_factory=list)
    sessions: int = 0
    contact_tokens: set[str] = field(default_factory=set)

    @property
    def band(self) -> str:
        return self.case.band or NOT_ASSESSED

    @property
    def attempts(self) -> int:
        return len(self.case.attempts)


def load_rows(conn: Connection, f: Facts) -> list[Row]:
    """Display columns for every scoped case. Every query repeats ``market_code = ANY(:m)``."""
    m = {"m": f.markets}
    rows: dict[uuid.UUID, Row] = {}
    for r in conn.execute(
        text(
            "SELECT c.id, p.id AS policy_id, p.policy_ref, p.product_family, p.product_subtype, p.is_ilp, "
            "(SELECT pa.masked_name FROM policy_party_role pr JOIN party pa ON pa.id = pr.party_id "
            " WHERE pr.policy_id = p.id AND pr.role = 'OWNER' ORDER BY pa.party_ref LIMIT 1) AS owner, "
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
        rows[r.id] = Row(
            case,
            r.policy_id,
            r.policy_ref,
            r.owner or "—",
            r.product_family,
            r.product_subtype,
            r.is_ilp,
            r.script,
            None,
        )
    for r in conn.execute(
        text(
            "SELECT a.callback_case_id, a.id AS attempt_id, a.attempt_ref, a.status, s.id AS session_id, s.session_ref "
            "FROM contact_attempt a "
            "JOIN callback_case c ON c.id = a.callback_case_id LEFT JOIN conversation_session s "
            "ON s.contact_attempt_id = a.id WHERE c.market_code = ANY(:m) ORDER BY a.sequence"
        ),
        m,
    ):
        row = rows.get(r.callback_case_id)
        if row is None:
            continue
        row.attempt_refs.append((r.attempt_ref, r.attempt_id))
        row.latest_attempt = r.status
        if r.session_ref:
            row.session_refs.append((r.session_ref, r.session_id))
            row.sessions += 1
    by_policy: dict[uuid.UUID, list[Row]] = {}
    for row in rows.values():
        by_policy.setdefault(row.policy_id, []).append(row)
    for r in conn.execute(
        text(
            "SELECT DISTINCT pr.policy_id, cm.value_hmac FROM contact_method cm JOIN policy_party_role pr "
            "ON pr.party_id = cm.party_id JOIN policy p ON p.id = pr.policy_id WHERE p.market_code = ANY(:m)"
        ),
        m,
    ):
        for row in by_policy.get(r.policy_id, []):
            row.contact_tokens.add(r.value_hmac)
    return list(rows.values())


# ---- query text --------------------------------------------------------------------------------------------
def normalise_ref(q: str) -> str:
    return "".join(q.split()).upper()


def contact_tokens(dp: DataProtection | None, q: str) -> set[str]:
    """Exact-match HMAC tokens for a phone or email query (never stored, never logged)."""
    if dp is None or not q.strip():
        return set()
    return {dp.token("EMAIL", q)} if "@" in q else {dp.token("PHONE", q)}


def term_hash(q: str) -> str:
    """Search terms are logged and audited only as this normalised SHA-256 (S-14, BE-SRCH-08)."""
    return hashlib.sha256(" ".join(q.split()).casefold().encode()).hexdigest()


def match_kind(q: str, ref: str) -> str | None:
    """EXACT > PREFIX > FUZZY. Identifiers get no edit-distance matching (a near-miss reference must not surface a
    different record); FUZZY is a contained substring of at least four characters."""
    if ref == q:
        return "EXACT"
    if ref.startswith(q):
        return "PREFIX"
    if len(q) >= 4 and q in ref:
        return "FUZZY"
    return None


def text_match(row: Row, q: str, tokens: set[str]) -> bool:
    if tokens & row.contact_tokens:
        return True
    refs = [row.case.ref, row.policy_ref, *(a for a, _ in row.attempt_refs), *(s for s, _ in row.session_refs)]
    return any(ref.startswith(q) or (len(q) >= 4 and q in ref) for ref in refs)


# ---- filters -----------------------------------------------------------------------------------------------
@dataclass
class Filters:
    q: str | None = None
    state: list[str] = field(default_factory=list)
    outcome: list[str] = field(default_factory=list)
    band: list[str] = field(default_factory=list)
    hold_reason: list[str] = field(default_factory=list)
    product_family: list[str] = field(default_factory=list)
    ilp: bool | None = None
    overdue: bool | None = None
    on_hold: bool | None = None
    due_from: date | None = None
    due_to: date | None = None
    queue: str | None = None
    kpi: str | None = None
    kpi_set: str | None = None
    kpi_from: date | None = None
    kpi_to: date | None = None

    def validate(self) -> None:
        if self.q is not None and len(self.q) > MAX_Q:
            raise InvalidFilter("QUERY_TOO_LONG", f"q must be at most {MAX_Q} characters")
        bad = [o for o in self.outcome if o not in OUTCOME_CODES]
        if bad:
            raise InvalidFilter("INVALID_FILTER", f"Unknown outcome: {bad[0]}")
        if self.queue is not None and self.queue not in QUEUES:
            raise InvalidFilter("INVALID_FILTER", f"Unknown queue: {self.queue}")
        if self.due_from and self.due_to and self.due_from >= self.due_to:
            raise InvalidFilter("INVALID_FILTER", "due_from must be before due_to")
        if self.kpi is not None:
            if self.kpi not in CASE_PREDICATES and self.kpi != "KPI-15":
                raise InvalidFilter("INVALID_FILTER", f"{self.kpi} has no case-grain drilldown")
            if self.kpi_set not in {"numerator", "denominator"} or not self.kpi_from or not self.kpi_to:
                raise InvalidFilter("INVALID_FILTER", "kpi needs kpi_set=numerator|denominator, from and to")
            if self.kpi_from >= self.kpi_to or (self.kpi_to - self.kpi_from) > timedelta(days=366):
                raise InvalidFilter("INVALID_RANGE", "The range must satisfy from < to and span at most 366 days")
        elif self.kpi_set is not None:
            raise InvalidFilter("INVALID_FILTER", "kpi_set needs kpi")


def kpi_ids(f: Facts, kid: str, kset: str, start: date, end: date) -> set[uuid.UUID]:
    s, e = local_range(start, end)
    if kid == "KPI-15":  # outcome distribution: every case due in range (numerator = denominator)
        return {c.id for c in f.due_in(s, e)}
    den, num = CASE_PREDICATES[kid](f, s, e)
    return num if kset == "numerator" else den


def queue_member(f: Facts, c: Case, queue: str) -> bool:
    if c.category != "OPEN":
        return False
    if queue == "DUE_TODAY":
        today = f.now.astimezone(SGT).date()
        t0, t1 = local_range(today, today + timedelta(days=1))
        return t0 <= c.due_at < t1
    if queue == "OVERDUE":
        return c.due_at < f.now
    if queue == "AWAITING_CALLBACK":
        return c.state == "AWAITING_CALLBACK"
    return bool(c.holds)  # ON_HOLD


Pred = Callable[[Row], bool]


def predicates(f: Facts, flt: Filters, dp: DataProtection | None) -> dict[str, Pred]:
    """One predicate per facet dimension, so facets can exclude their own dimension (disjunctive counts)."""
    p: dict[str, Pred] = {}
    if flt.q and flt.q.strip():
        q, tokens = normalise_ref(flt.q), contact_tokens(dp, flt.q)
        p["q"] = lambda r: text_match(r, q, tokens)
    if flt.state:
        states = set(flt.state)
        p["state"] = lambda r: r.case.state in states
    if flt.outcome:
        outs = set(flt.outcome)
        p["outcome"] = lambda r: r.case.category in outs
    if flt.band:
        bands = set(flt.band)
        p["band"] = lambda r: r.band in bands
    if flt.hold_reason:
        reasons = set(flt.hold_reason)
        p["hold_reason"] = lambda r: any(h in reasons for h, _ in r.case.holds)
    if flt.product_family:
        fams = set(flt.product_family)
        p["product_family"] = lambda r: r.product_family in fams
    if flt.ilp is not None:
        ilp = flt.ilp
        p["ilp"] = lambda r: r.is_ilp is ilp
    if flt.overdue is not None:
        want = flt.overdue
        p["overdue"] = lambda r: (r.case.category == "OPEN" and r.case.due_at < f.now) is want
    if flt.on_hold is not None:
        held = flt.on_hold
        p["on_hold"] = lambda r: bool(r.case.holds) is held
    if flt.due_from or flt.due_to:
        lo = local_range(flt.due_from, flt.due_from)[0] if flt.due_from else None
        hi = local_range(flt.due_to, flt.due_to)[0] if flt.due_to else None
        p["due"] = lambda r: (lo is None or r.case.due_at >= lo) and (hi is None or r.case.due_at < hi)
    if flt.queue:
        queue = flt.queue
        p["queue"] = lambda r: queue_member(f, r.case, queue)
    if flt.kpi and flt.kpi_set and flt.kpi_from and flt.kpi_to:
        ids = kpi_ids(f, flt.kpi, flt.kpi_set, flt.kpi_from, flt.kpi_to)
        p["kpi"] = lambda r: r.case.id in ids
    return p


def apply(rows: Sequence[Row], preds: dict[str, Pred], *, skip: str | None = None) -> list[Row]:
    active = [fn for k, fn in preds.items() if k != skip]
    return [r for r in rows if all(fn(r) for fn in active)]


# ---- sorting and cursors -----------------------------------------------------------------------------------
def sort_key(r: Row, field_: str) -> tuple[Any, ...]:
    primary: Any = {
        "due_at": r.case.due_at.timestamp(),
        "case_ref": "",
        "state": r.case.state,
        "risk_band": BAND_RANK.get(r.band, 9),
        "attempts": r.attempts,
    }[field_]
    return (primary, r.case.ref)


def parse_sort(sort: str) -> tuple[str, bool]:
    desc = sort.startswith("-")
    name = sort[1:] if desc else sort
    if name not in SORTS:
        raise InvalidFilter("INVALID_FILTER", f"sort must be one of {', '.join(SORTS)} (prefix - for descending)")
    return name, desc


def encode_cursor(sort: str, key: tuple[Any, ...]) -> str:
    return base64.urlsafe_b64encode(json.dumps({"s": sort, "k": list(key)}).encode()).decode().rstrip("=")


def decode_cursor(cursor: str, sort: str) -> tuple[Any, ...]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if data["s"] != sort or not isinstance(data["k"], list) or len(data["k"]) != 2:
            raise ValueError
        return (data["k"][0], str(data["k"][1]))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidFilter("INVALID_CURSOR", "The cursor is invalid or belongs to a different sort") from exc


def page(rows: list[Row], sort: str, limit: int, cursor: str | None) -> tuple[list[Row], str | None]:
    """Keyset pagination over (sort value, case_ref): rows inserted between pages never duplicate or shift
    rows already returned (SEARCH-005, BE-SRCH-04)."""
    name, desc = parse_sort(sort)
    ordered = sorted(rows, key=lambda r: sort_key(r, name), reverse=desc)
    if cursor:
        after = decode_cursor(cursor, sort)
        ordered = [r for r in ordered if (sort_key(r, name) < after if desc else sort_key(r, name) > after)]
    chunk = ordered[:limit]
    nxt = encode_cursor(sort, sort_key(chunk[-1], name)) if len(ordered) > limit else None
    return chunk, nxt


# ---- facets and queues -------------------------------------------------------------------------------------
FACET_DIMENSIONS: dict[str, Callable[[Row], list[str]]] = {
    "state": lambda r: [r.case.state],
    "outcome": lambda r: [r.case.category],
    "band": lambda r: [r.band],
    "hold_reason": lambda r: sorted({h for h, _ in r.case.holds}),
    "product_family": lambda r: [r.product_family],
    "ilp": lambda r: ["true" if r.is_ilp else "false"],
}


def facets(rows: Sequence[Row], preds: dict[str, Pred], f: Facts) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for dim, values in FACET_DIMENSIONS.items():
        counts: Counter[str] = Counter()
        for r in apply(rows, preds, skip=dim):
            counts.update(values(r))
        out[dim] = dict(sorted(counts.items()))
    od = apply(rows, preds, skip="overdue")
    out["overdue"] = {"true": sum(1 for r in od if r.case.category == "OPEN" and r.case.due_at < f.now)}
    return out


def queue_counts(f: Facts) -> list[dict[str, Any]]:
    out = []
    for code, (label, rule) in QUEUES.items():
        members = [c for c in f.cases.values() if queue_member(f, c, code)]
        entry: dict[str, Any] = {
            "code": code,
            "label": label,
            "count": len(members),
            "rule": rule,
            "route": f"/queues?queue={code}",
            "register_route": f"/calls?queue={code}",
            "by_reason": [],
        }
        if code == "ON_HOLD":
            reasons = Counter(h for c in members for h in {r for r, _ in c.holds})
            entry["by_reason"] = [
                {
                    "hold_reason": h,
                    "count": n,
                    "blocking": sum(1 for c in members if any(r == h and b for r, b in c.holds)),
                    "register_route": f"/calls?queue=ON_HOLD&hold_reason={h}",
                }
                for h, n in sorted(reasons.items())
            ]
        out.append(entry)
    return out


# ---- global search (API-070/071) ---------------------------------------------------------------------------
TYPE_ORDER = {"case": 0, "policy": 1, "attempt": 2, "session": 3}
KIND_ORDER = {"EXACT": 0, "PREFIX": 1, "FUZZY": 2}


def search_hits(rows: Sequence[Row], q: str, dp: DataProtection | None, types: set[str]) -> list[dict[str, Any]]:
    """Ranked hits over approved identifiers inside scope: exact > prefix > fuzzy, then type, then ref."""
    nq = normalise_ref(q)
    tokens = contact_tokens(dp, q)
    hits: dict[tuple[str, str], dict[str, Any]] = {}

    def add(kind: str, etype: str, eid: uuid.UUID, ref: str, display: str, fld: str, route: str, reg: str) -> None:
        key = (etype, ref)
        if key in hits and KIND_ORDER[hits[key]["match_kind"]] <= KIND_ORDER[kind]:
            return
        hits[key] = {
            "entity_type": etype,
            "id": eid,
            "ref": ref,
            "masked_display": display,
            "matched_field": fld,
            "match_kind": kind,
            "route": route,
            "register_route": reg,
        }

    for r in rows:
        c = r.case
        reg = f"/calls?q={c.ref}"
        summary = f"{r.policyholder} · {r.policy_ref} · {c.state}"
        if "case" in types:
            if tokens & r.contact_tokens:
                fld = "contact_email" if "@" in q else "contact_phone"
                add("EXACT", "case", c.id, c.ref, summary, fld, f"/cases/{c.id}", reg)
            k = match_kind(nq, c.ref)
            if k:
                add(k, "case", c.id, c.ref, summary, "case_ref", f"/cases/{c.id}", reg)
        if "policy" in types:
            k = match_kind(nq, r.policy_ref)
            if k:
                disp = f"{r.policyholder} · {r.product_family} · {r.product_subtype}"
                add(
                    k,
                    "policy",
                    r.policy_id,
                    r.policy_ref,
                    disp,
                    "policy_ref",
                    f"/policies/{r.policy_id}",
                    f"/calls?q={r.policy_ref}",
                )
        for etype, refs in (("attempt", r.attempt_refs), ("session", r.session_refs)):
            if etype not in types:
                continue
            for ref, eid in refs:
                k = match_kind(nq, ref)
                if k:
                    add(
                        k,
                        etype,
                        eid,
                        ref,
                        f"{c.ref} · {summary}",
                        f"{etype}_ref",
                        f"/cases/{c.id}?{etype}={eid}",
                        f"/calls?q={ref}",
                    )
    return sorted(hits.values(), key=lambda h: (KIND_ORDER[h["match_kind"]], TYPE_ORDER[h["entity_type"]], h["ref"]))


def search_cursor(offset: int, qh: str) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset, "h": qh}).encode()).decode().rstrip("=")


def search_offset(cursor: str | None, qh: str) -> int:
    if not cursor:
        return 0
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if data["h"] != qh or not isinstance(data["o"], int) or data["o"] < 0:
            raise ValueError
        return int(data["o"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidFilter("INVALID_CURSOR", "The cursor is invalid or belongs to a different query") from exc
