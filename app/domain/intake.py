"""CP0.4a manual transaction intake (ING-002…004, POL-007 create path, PARTY-004, GOV-001; ADR-0008 §1, §6).

One synthetic Singapore policy-sale transaction is validated, planned and, on commit, written in the caller's
single database transaction. Only existing Stage 0 rules are applied:

- **Risk:** the band the source assigned is stored as ``SOURCE_ASSIGNED`` with its original value. No band,
  score or threshold is calculated (RISK-008 is S2).
- **Script:** no resolver runs; every intake-created case is held ``AWAITING_SCRIPT_ASSIGNMENT`` (BE-ING-10).
- **Contact eligibility:** the governed ``callable_party_roles`` list and the database eligibility check
  (D-36), the same rule the seed records; no eligible contact → ``NO_ELIGIBLE_CONTACT`` hold (BE-ING-08).
- **ILP without risk** → ``RISK_TRIAGE`` hold (BE-ING-09). A ``DATA_CONFLICT`` hold needs two assessments of the
  same sale; an intake sale is always new, so it never applies in CP0.4a.
- **Due date and priority** are source-provided (owner decision, CP0.4a); nothing is scheduled or prioritised.
- **Existing policy:** a new sale attaches only when every material policy field matches; nothing is
  overwritten. Parties are never matched on name or contact value; existing parties are named by ``party_ref``.

Every row is ``source_type = MANUAL`` with provenance, ``intake_item_id`` and ``is_synthetic = true``; seeded
rows are never updated. Errors carry field locations and codes only, never submitted values.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import MetaData, Table, insert, text
from sqlalchemy.orm import Session

from app.api.schemas import IntakeOutcome, IntakeParty, IntakeTransaction
from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.errors import AppError
from app.domain.digest import sha256_of
from app.domain.protection import DataProtection, aad, mask_contact, mask_name_strict, matches_any, normalise_contact

SGT = ZoneInfo("Asia/Singapore")
MAPPING_VERSION = "CP0.4a-manual-1"
INTAKE_LOCK_KEY = 360_0004  # pg_advisory_xact_lock: serialises reference allocation and duplicate checks
CLOCK_SKEW = timedelta(minutes=5)
# The synthetic product set of S0-SEED-1 (app.domain.seed.build_sales); there is no governed product list in S0.
SYNTHETIC_PRODUCTS = {
    ("SYN-PROT-TERM", "PROTECTION", "TERM_LIFE"),
    ("SYN-ILP-GROWTH", "ILP", "ILP_SINGLE"),
    ("SYN-ILP-GROWTH", "ILP", "ILP_REGULAR"),
    ("SYN-END-SAVER", "ENDOWMENT", "ENDOWMENT"),
}
MARKET_CURRENCY = {"SG": "SGD"}  # Stage 0 is Singapore-only (D-39); all SG records are in SGD
MATERIAL_POLICY_FIELDS = (
    "product_code",
    "product_family",
    "product_subtype",
    "status",
    "premium_amount",
    "currency",
    "premium_frequency",
    "premium_term_years",
    "sum_assured",
    "sum_assured_currency",
    "effective_from",
)
CANDIDATE_ROLES = ("OWNER", "AUTHORIZED_CONTACT", "INSURED")  # as recorded by the seed (_Seeder._selections)
RESERVED_SOURCE_SYSTEMS = {"SYN-SEED"}


class IntakeRejected(AppError):
    """A rejected transaction; ``audit_code`` is recorded in the rejection audit event."""


def _issue(loc: Sequence[str | int], code: str, message: str) -> dict[str, Any]:
    return {"loc": [str(p) for p in loc], "code": code, "message": message}


@dataclass
class Governed:
    version: uuid.UUID
    values: dict[str, dict[str, Any]]
    labels: dict[str, str]


@dataclass
class PartyPlan:
    index: int
    spec: IntakeParty
    existing_id: uuid.UUID | None = None
    existing_ref: str | None = None
    masked_name: str = ""
    contacts: list[dict[str, Any]] = field(default_factory=list)  # normalised values (new parties only)
    new_id: uuid.UUID | None = None
    new_ref: str | None = None


@dataclass
class Plan:
    body: IntakeTransaction
    digest: str
    now: datetime
    policy: dict[str, Any] | None  # existing policy row, or None for a new policy
    parties: list[PartyPlan]
    role_edges: list[dict[str, Any]]  # existing edges (reused policy) or planned edges (new policy)
    methods: dict[str, list[dict[str, Any]]]  # party key -> contact methods
    fsc_id: uuid.UUID
    eligibility: list[dict[str, Any]]
    holds: list[str]
    governed: dict[str, Governed]
    risk_note: str | None


def governed(db: Session, list_code: str) -> Governed:
    rows = db.execute(
        text(
            "SELECT v.id AS version, cv.code, cv.label, cv.attributes FROM code_list l "
            "JOIN code_list_version v ON v.code_list_id = l.id AND v.status = 'ACTIVE' "
            "JOIN code_value cv ON cv.code_list_version_id = v.id WHERE l.code = :c ORDER BY cv.sort_order"
        ),
        {"c": list_code},
    ).all()
    if not rows:
        raise AppError(503, "INGEST_REFERENCE_DATA_UNAVAILABLE", f"No active {list_code} list", retryable=True)
    return Governed(rows[0].version, {r.code: dict(r.attributes) for r in rows}, {r.code: r.label for r in rows})


def payload_digest(body: IntakeTransaction) -> str:
    return sha256_of(body.model_dump(mode="json"))


# ---- validation --------------------------------------------------------------------------------------------------
def _guards(db: Session, body: IntakeTransaction, markets: frozenset[str]) -> Governed:
    """GOV-001 and D-39 guards, each with its own audited error code (ADR-0008 §6)."""
    if not body.is_synthetic:
        raise IntakeRejected(
            422,
            "INGEST_NON_SYNTHETIC_REJECTED",
            "Only synthetic transactions are accepted (DATA_POLICY=SYNTHETIC_ONLY)",
        )
    market = body.policy.market_code
    if (
        market not in markets
        or not body.policy.policy_ref.startswith(f"POL-{market}-")
        or not (body.sale.sale_ref.startswith(f"SALE-{market}-"))
    ):
        raise IntakeRejected(
            422,
            "INGEST_MARKET_NOT_IN_SCOPE",
            "The transaction's market is not in your scope (Stage 0 is Singapore-only)",
            details=[_issue(["body", "policy", "market_code"], "MARKET_NOT_IN_SCOPE", "Use SG references")],
        )
    ranges = governed(db, "synthetic_contact_ranges")
    patterns: dict[str, list[str]] = {}
    for attrs in ranges.values.values():
        patterns.setdefault(attrs["channel"], []).append(attrs["pattern"])
    bad = [
        _issue(
            ["body", "parties", i, "contacts", j, "value"], "CONTACT_NOT_SYNTHETIC", "Not a reserved synthetic value"
        )
        for i, p in enumerate(body.parties)
        for j, c in enumerate(p.contacts)
        if not matches_any(normalise_contact(c.channel, c.value), patterns.get(c.channel, []))
    ]
    if bad:
        raise IntakeRejected(
            422, "INGEST_CONTACT_NOT_SYNTHETIC", "Contact values must be reserved synthetic identifiers", details=bad
        )
    return ranges


def _field_issues(db: Session, body: IntakeTransaction, now: datetime, bands: Governed) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pol, sale, req = body.policy, body.sale, body.callback_request
    if not body.source_system.startswith("SYN-") or body.source_system in RESERVED_SOURCE_SYSTEMS:
        out.append(_issue(["body", "source_system"], "SOURCE_SYSTEM_NOT_SYNTHETIC", "Use a SYN- source system"))
    if (pol.product_code, pol.product_family, pol.product_subtype) not in SYNTHETIC_PRODUCTS:
        out.append(_issue(["body", "policy", "product_code"], "UNKNOWN_PRODUCT", "Not a synthetic Stage 0 product"))
    currency = MARKET_CURRENCY.get(pol.market_code)
    for loc, value in (
        (["body", "policy", "currency"], pol.currency),
        (["body", "sale", "currency"], sale.currency),
        (["body", "policy", "sum_assured_currency"], pol.sum_assured_currency),
    ):
        if value is not None and value != currency:
            out.append(_issue(loc, "CURRENCY_NOT_ALLOWED", f"Currency must be {currency}"))
    if (pol.sum_assured is None) != (pol.sum_assured_currency is None):
        out.append(_issue(["body", "policy", "sum_assured"], "INCOMPLETE_AMOUNT", "Amount and currency go together"))
    if pol.premium_frequency == "SINGLE" and pol.premium_term_years is not None:
        out.append(_issue(["body", "policy", "premium_term_years"], "TERM_NOT_ALLOWED", "Single premium has no term"))
    if sale.sold_at > now + CLOCK_SKEW:
        out.append(_issue(["body", "sale", "sold_at"], "IN_FUTURE", "The sale cannot be in the future"))
    if req.due_at < sale.sold_at:
        out.append(_issue(["body", "callback_request", "due_at"], "BEFORE_SALE", "Due date is before the sale"))
    if body.source_observed_at is not None and body.source_observed_at > now + CLOCK_SKEW:
        out.append(_issue(["body", "source_observed_at"], "IN_FUTURE", "Observation time cannot be in the future"))
    fsc = db.execute(
        text("SELECT channel, status FROM fsc_representative WHERE fsc_ref = :r"), {"r": sale.fsc_ref}
    ).first()
    if fsc is None or fsc.status != "ACTIVE":
        out.append(_issue(["body", "sale", "fsc_ref"], "UNKNOWN_FSC", "No active representative with this reference"))
    elif fsc.channel != sale.selling_channel:
        out.append(_issue(["body", "sale", "selling_channel"], "CHANNEL_MISMATCH", "Differs from the FSC's channel"))
    risk = body.source_risk
    if risk is not None:
        if risk.band_code not in bands.values:
            out.append(_issue(["body", "source_risk", "band_code"], "UNKNOWN_BAND", "Not an active SBQ risk band"))
        if risk.assessed_at > now + CLOCK_SKEW:
            out.append(_issue(["body", "source_risk", "assessed_at"], "IN_FUTURE", "Cannot be in the future"))
        for i, code in enumerate(risk.reason_codes):
            if not code or len(code) > 40 or not all(ch.isalnum() or ch in "_-" for ch in code):
                out.append(_issue(["body", "source_risk", "reason_codes", i], "INVALID_CODE", "Use A-Z, 0-9, _ or -"))
    return out


def _party_issues(body: IntakeTransaction, reused: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    roles: list[str] = []
    seen: set[str] = set()
    for i, p in enumerate(body.parties):
        loc: list[str | int] = ["body", "parties", i]
        if len(set(p.roles)) != len(p.roles):
            out.append(_issue([*loc, "roles"], "DUPLICATE_ROLE", "A role is listed twice"))
        roles += p.roles
        if p.party_ref is not None:
            if p.kind or p.name or p.date_of_birth_year or p.contacts or p.source_party_id:
                out.append(_issue(loc, "EXISTING_PARTY_FIELDS", "An existing party is named by party_ref only"))
            if p.party_ref in seen:
                out.append(_issue([*loc, "party_ref"], "DUPLICATE_PARTY", "The party is listed twice"))
            seen.add(p.party_ref)
        elif reused:
            out.append(_issue(loc, "ROLE_CHANGE_NOT_SUPPORTED", "New parties on an existing policy are CP0.4b"))
        elif not p.kind or not p.name:
            out.append(_issue(loc, "PARTY_REQUIRED_FIELDS", "A new party needs kind and name"))
        if p.authorization is not None:
            if "AUTHORIZED_CONTACT" not in p.roles:
                out.append(_issue([*loc, "authorization"], "AUTHORIZATION_WITHOUT_ROLE", "Only for AUTHORIZED_CONTACT"))
            elif p.authorization.valid_to is not None and p.authorization.valid_to <= p.authorization.valid_from:
                out.append(_issue([*loc, "authorization", "valid_to"], "INVALID_INTERVAL", "Must follow valid_from"))
        ranks = [(c.channel, c.preference_rank) for c in p.contacts]
        if len(set(ranks)) != len(ranks):
            out.append(_issue([*loc, "contacts"], "DUPLICATE_RANK", "One contact per channel and preference rank"))
    if not reused:
        if not body.parties:
            out.append(_issue(["body", "parties"], "PARTIES_REQUIRED", "A new policy needs its parties"))
        for role in ("OWNER", "INSURED"):
            if body.parties and role not in roles:
                out.append(_issue(["body", "parties"], f"{role}_REQUIRED", f"A new policy needs an {role} party"))
    return out


def _reject_issues(issues: list[dict[str, Any]]) -> None:
    if issues:
        raise IntakeRejected(422, "INGEST_VALIDATION_FAILED", "The transaction failed validation", details=issues)


def _conflicts(db: Session, body: IntakeTransaction, markets: frozenset[str]) -> dict[str, Any] | None:
    """409s: duplicate source event, existing sale reference, policy conflicts. Returns the reused policy row."""
    dup = db.execute(
        text(
            "SELECT 1 FROM intake_item WHERE source_system = :s AND source_event_id = :e AND status = 'ACCEPTED' "
            "UNION ALL SELECT 1 FROM sale_event WHERE source_system = :s AND source_reference = :e"
        ),
        {"s": body.source_system, "e": body.source_event_id},
    ).first()
    if dup is not None:
        raise IntakeRejected(
            409, "INGEST_DUPLICATE_SOURCE_EVENT", "This source event has already been accepted; nothing was changed"
        )
    if db.execute(text("SELECT 1 FROM sale_event WHERE sale_ref = :r"), {"r": body.sale.sale_ref}).first():
        raise IntakeRejected(
            409,
            "INGEST_SALE_REF_EXISTS",
            "A sale event with this reference already exists",
            details=[_issue(["body", "sale", "sale_ref"], "EXISTS", "Sale references are unique")],
        )
    row = (
        db.execute(text("SELECT * FROM policy WHERE policy_ref = :r"), {"r": body.policy.policy_ref}).mappings().first()
    )
    if row is None:
        return None
    if row["market_code"] not in markets:
        raise IntakeRejected(409, "INGEST_POLICY_REF_UNAVAILABLE", "This policy reference cannot be used")
    submitted = body.policy.model_dump()
    differs = [
        _issue(["body", "policy", f], "DIFFERS_FROM_EXISTING", "Differs from the existing policy")
        for f in MATERIAL_POLICY_FIELDS
        if not _same(row[f], submitted[f])
    ]
    if differs:
        raise IntakeRejected(
            409,
            "INGEST_POLICY_FIELDS_DIFFER",
            "The policy exists with different material fields; corrections arrive in CP0.4b",
            details=differs,
        )
    if (
        body.sale.sale_event_type == "NEW_BUSINESS"
        and db.execute(
            text("SELECT 1 FROM sale_event WHERE policy_id = :p AND sale_event_type = 'NEW_BUSINESS'"), {"p": row["id"]}
        ).first()
    ):
        raise IntakeRejected(
            409,
            "INGEST_DUPLICATE_NEW_BUSINESS",
            "The existing policy already has a new-business sale",
            details=[_issue(["body", "sale", "sale_event_type"], "NEW_BUSINESS_EXISTS", "Use the sale's actual type")],
        )
    return dict(row)


def _same(stored: Any, submitted: Any) -> bool:
    if isinstance(stored, Decimal) or isinstance(submitted, Decimal):
        return stored is not None and submitted is not None and Decimal(stored) == Decimal(submitted)
    if isinstance(stored, datetime) and isinstance(submitted, datetime):
        return stored == submitted
    return bool(stored == submitted)


def _resolve_parties(
    db: Session, body: IntakeTransaction, policy: dict[str, Any] | None, markets: frozenset[str]
) -> tuple[list[PartyPlan], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Party plans, role edges and contact methods (keyed by party key: party id or ``new:<index>``)."""
    plans: list[PartyPlan] = []
    issues: list[dict[str, Any]] = []
    for i, p in enumerate(body.parties):
        plan = PartyPlan(i, p)
        if p.party_ref is not None:
            row = db.execute(
                text(
                    "SELECT pa.id, pa.party_ref, pa.masked_name FROM party pa WHERE pa.party_ref = :r AND EXISTS "
                    "(SELECT 1 FROM policy_party_role r JOIN policy po ON po.id = r.policy_id "
                    "WHERE r.party_id = pa.id AND po.market_code = ANY(:m))"
                ),
                {"r": p.party_ref, "m": sorted(markets)},
            ).first()
            if row is None:  # missing and out of scope look the same
                issues.append(_issue(["body", "parties", i, "party_ref"], "UNKNOWN_PARTY", "No such party in scope"))
                continue
            plan.existing_id, plan.existing_ref, plan.masked_name = row.id, row.party_ref, row.masked_name
        else:
            assert p.name is not None
            plan.masked_name = mask_name_strict(p.name)
            if (
                p.source_party_id
                and db.execute(
                    text(
                        "SELECT 1 FROM external_reference WHERE source_system = :s AND object_type = 'PARTY' "
                        "AND external_id = :e"
                    ),
                    {"s": body.source_system, "e": p.source_party_id},
                ).first()
            ):
                issues.append(
                    _issue(
                        ["body", "parties", i, "source_party_id"],
                        "PARTY_EXISTS",
                        "A party with this source identifier exists; name it by party_ref",
                    )
                )
            plan.contacts = [{**c.model_dump(), "value": normalise_contact(c.channel, c.value)} for c in p.contacts]
        plans.append(plan)
    _reject_issues(issues)
    sold = body.sale.sold_at
    if policy is not None:
        edges = [
            dict(r)
            for r in db.execute(
                text(
                    "SELECT r.id, r.party_id, pa.party_ref, pa.masked_name, r.role, r.valid_from, r.valid_to, "
                    "r.authorization_ref, r.authorization_valid_from, r.authorization_valid_to "
                    "FROM policy_party_role r JOIN party pa ON pa.id = r.party_id WHERE r.policy_id = :p "
                    "ORDER BY r.valid_from, r.id"
                ),
                {"p": policy["id"]},
            ).mappings()
        ]
        active = {(e["party_ref"], e["role"]) for e in edges if e["valid_to"] is None}
        missing = [
            _issue(["body", "parties", pl.index], "ROLE_CHANGE_NOT_SUPPORTED", "Role changes are corrections (CP0.4b)")
            for pl in plans
            for role in pl.spec.roles
            if (pl.existing_ref, role) not in active
        ]
        _reject_issues(missing)
        for e in edges:
            e["key"] = str(e["party_id"])
        party_ids = sorted({e["party_id"] for e in edges})
        methods: dict[str, list[dict[str, Any]]] = {}
        for m in db.execute(
            text(
                "SELECT id, party_id, channel, masked_value, preference_rank, suppressed, consent_status, valid_from, "
                "valid_to FROM contact_method WHERE party_id = ANY(:p) ORDER BY preference_rank, valid_from"
            ),
            {"p": party_ids},
        ).mappings():
            methods.setdefault(str(m["party_id"]), []).append(dict(m))
        return plans, edges, methods
    edges, methods = [], {}
    for pl in plans:
        key = str(pl.existing_id) if pl.existing_id else f"new:{pl.index}"
        auth = pl.spec.authorization
        for role in pl.spec.roles:
            edges.append(
                {
                    "id": None,
                    "key": key,
                    "party_ref": pl.existing_ref,
                    "masked_name": pl.masked_name,
                    "role": role,
                    "valid_from": sold,
                    "valid_to": None,
                    "authorization_ref": auth.reference if auth and role == "AUTHORIZED_CONTACT" else None,
                    "authorization_valid_from": auth.valid_from if auth and role == "AUTHORIZED_CONTACT" else None,
                    "authorization_valid_to": auth.valid_to if auth and role == "AUTHORIZED_CONTACT" else None,
                }
            )
        if pl.existing_id is not None:
            methods[key] = [
                dict(m)
                for m in db.execute(
                    text(
                        "SELECT id, party_id, channel, masked_value, preference_rank, suppressed, consent_status, "
                        "valid_from, valid_to FROM contact_method WHERE party_id = :p "
                        "ORDER BY preference_rank, valid_from"
                    ),
                    {"p": pl.existing_id},
                ).mappings()
            ]
        else:
            methods[key] = [
                {
                    "id": None,
                    "channel": c["channel"],
                    "masked_value": mask_contact(c["channel"], c["value"]),
                    "preference_rank": c["preference_rank"],
                    "suppressed": c["suppressed"],
                    "consent_status": c["consent_status"],
                    "valid_from": sold,
                    "valid_to": None,
                    "_plan": (pl.index, j),
                }
                for j, c in enumerate(pl.contacts)
            ]
    return plans, edges, methods


def _valid_at(start: datetime | None, end: datetime | None, at: datetime) -> bool:
    return start is not None and start <= at and (end is None or at < end)


def eligibility(
    edges: list[dict[str, Any]], methods: dict[str, list[dict[str, Any]]], roles: Governed, at: datetime
) -> list[dict[str, Any]]:
    """PARTY-004 / D-36 with the governed ``callable_party_roles`` attributes, in the order the seed records it."""
    owners = {e["key"] for e in edges if e["role"] == "OWNER" and _valid_at(e["valid_from"], e["valid_to"], at)}
    out = []
    for e in edges:
        if e["role"] not in CANDIDATE_ROLES or not _valid_at(e["valid_from"], e["valid_to"], at):
            continue
        if e["role"] == "INSURED" and e["key"] in owners:
            continue
        attrs = roles.values.get(e["role"], {})
        phone = next(
            (
                m
                for m in methods.get(e["key"], [])
                if m["channel"] == "PHONE" and _valid_at(m["valid_from"], m["valid_to"], at)
            ),
            None,
        )
        reason = None
        if not attrs.get("callable"):
            reason = "ROLE_NOT_CALLABLE"
        elif attrs.get("requires_authorization_evidence", True) and not (
            e["authorization_ref"] and _valid_at(e["authorization_valid_from"], e["authorization_valid_to"], at)
        ):
            reason = "AUTHORIZATION_NOT_EVIDENCED"
        elif phone is None:
            reason = "NO_CONTACT_METHOD"
        elif phone["suppressed"]:
            reason = "CONTACT_SUPPRESSED"
        elif phone["consent_status"] != "GRANTED":
            reason = "CONSENT_NOT_GRANTED"
        out.append({"edge": e, "method": phone, "eligible": reason is None, "reason": reason})
    return out


def plan(db: Session, body: IntakeTransaction, markets: frozenset[str], now: datetime) -> Plan:
    """Validate and plan without writing (API-084 and the first half of API-085)."""
    _guards(db, body, markets)
    bands = governed(db, "sbq_risk_band")
    issues = _field_issues(db, body, now, bands)
    policy = None
    if not issues:
        policy = _conflicts(db, body, markets)
    issues += _party_issues(body, reused=policy is not None)
    _reject_issues(issues)
    fsc_id = db.execute(text("SELECT id FROM fsc_representative WHERE fsc_ref = :r"), {"r": body.sale.fsc_ref}).scalar()
    assert fsc_id is not None
    parties, edges, methods = _resolve_parties(db, body, policy, markets)
    roles = governed(db, "callable_party_roles")
    elig = eligibility(edges, methods, roles, now)
    holds = ["AWAITING_SCRIPT_ASSIGNMENT"]  # no resolver runs at intake (ADR-0008 §1)
    if not any(x["eligible"] for x in elig):
        holds.append("NO_ELIGIBLE_CONTACT")
    is_ilp = body.policy.product_family == "ILP"
    risk_note = None
    if body.source_risk is None:
        risk_note = "No SBQ risk supplied; Call360 does not calculate one"
        if is_ilp:
            holds.append("RISK_TRIAGE")
            risk_note += " (ILP sale held for risk triage)"
    return Plan(
        body,
        payload_digest(body),
        now,
        policy,
        parties,
        edges,
        methods,
        fsc_id,
        elig,
        holds,
        {"sbq_risk_band": bands, "callable_party_roles": roles, "case_hold_reason": governed(db, "case_hold_reason")},
        risk_note,
    )


# ---- outcome ------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Ids:
    policy_id: uuid.UUID
    sale_id: uuid.UUID
    case_id: uuid.UUID
    case_ref: str
    risk_id: uuid.UUID | None
    run_id: uuid.UUID
    run_ref: str


def describe(p: Plan, ids: Ids | None = None) -> dict[str, Any]:
    """The preview (``ids`` None) or committed outcome as JSON-ready data: masked names and contacts only."""
    body = p.body
    pol, sale, req, risk = body.policy, body.sale, body.callback_request, body.source_risk
    ref_of = {f"new:{pl.index}": pl.new_ref for pl in p.parties} | {
        str(pl.existing_id): pl.existing_ref for pl in p.parties if pl.existing_id
    }
    holds = p.governed["case_hold_reason"]
    sid = str(ids.sale_id) if ids else None
    return {
        "mode": "COMMITTED" if ids else "PREVIEW",
        "replayed": False,
        "run_id": str(ids.run_id) if ids else None,
        "run_ref": ids.run_ref if ids else None,
        "payload_digest": p.digest,
        "source_system": body.source_system,
        "source_event_id": body.source_event_id,
        "policy": {
            "outcome": "REUSED" if p.policy else "NEW",
            "policy_ref": pol.policy_ref,
            "policy_id": str(ids.policy_id) if ids else (str(p.policy["id"]) if p.policy else None),
        },
        "sale_ref": sale.sale_ref,
        "sale_event_id": sid,
        "parties": [
            {
                "outcome": "EXISTING" if pl.existing_id else "NEW",
                "party_ref": pl.existing_ref or pl.new_ref,
                "party_id": str(pl.existing_id or pl.new_id) if (pl.existing_id or pl.new_id) else None,
                "masked_name": pl.masked_name,
                "roles": list(pl.spec.roles),
                "contacts": [mask_contact(c["channel"], c["value"]) for c in pl.contacts],
            }
            for pl in p.parties
        ],
        "eligibility": [
            {
                "party_ref": e["edge"].get("party_ref") or ref_of.get(e["edge"]["key"]),
                "masked_name": e["edge"]["masked_name"],
                "role": e["edge"]["role"],
                "eligible": e["eligible"],
                "ineligibility_reason": e["reason"],
                "contact_masked": e["method"]["masked_value"] if e["method"] else None,
            }
            for e in p.eligibility
        ],
        "risk": (
            {
                "origin": "SOURCE_ASSIGNED",
                "band_code": risk.band_code,
                "status": risk.status,
                "source_original_value": risk.source_original_value,
                "assessment_id": str(ids.risk_id) if ids and ids.risk_id else None,
            }
            if risk
            else None
        ),
        "risk_note": p.risk_note,
        "case": {
            "case_id": str(ids.case_id) if ids else None,
            "case_ref": ids.case_ref if ids else None,
            "state": "VALIDATED",
            "obligation_type": "SALE_VERIFICATION",
            "source_request_ref": req.source_request_ref,
            "due_at": req.due_at.isoformat(),
            "priority": req.priority,
            "callable": not any(holds.values[h].get("blocking") for h in p.holds),
        },
        "holds": [
            {"reason": h, "label": holds.labels.get(h, h), "blocking": bool(holds.values[h].get("blocking"))}
            for h in p.holds
        ],
        "script_routing": "NOT_EVALUATED_IN_S0",
        "compliance_outcome": "NOT_EVALUATED_IN_S0",
        "routes": ({"policy": f"/policies/{ids.policy_id}?sale={sid}", "case": f"/cases/{ids.case_id}"} if ids else {}),
    }


# ---- commit ------------------------------------------------------------------------------------------------------
_TABLES: dict[str, dict[str, Table]] = {}
_WRITTEN = (
    "party",
    "contact_method",
    "policy",
    "policy_party_role",
    "sale_event",
    "policy_fact_snapshot",
    "external_reference",
    "risk_assessment",
    "callback_case",
    "case_hold",
    "case_contact_selection",
    "case_event",
    "intake_run",
    "intake_item",
)


def _tables(db: Session, schema: str) -> dict[str, Table]:
    if schema not in _TABLES:
        assert schema in {"call360", "call360_test"}, schema
        md = MetaData(schema=schema)
        md.reflect(bind=db.connection(), only=lambda name, _: name in _WRITTEN)
        _TABLES[schema] = {t.name: t for t in md.tables.values()}
    return _TABLES[schema]


class _Writer:
    def __init__(self, db: Session, schema: str, p: Plan, actor: Actor, item_id: uuid.UUID) -> None:
        self.db, self.p, self.actor, self.item_id = db, p, actor, item_id
        self.t = _tables(db, schema)
        self.by = str(actor.principal_id)
        self.who = actor.username or self.by

    def ins(self, table: str, ref_suffix: str | None = None, *, p: bool = True, **cols: Any) -> uuid.UUID:
        row_id = cols.pop("id", None) or uuid.uuid4()
        values: dict[str, Any] = {"id": row_id, "created_by": self.by, **cols}
        if p:
            body = self.p.body
            values = {
                "source_type": "MANUAL",
                "source_system": body.source_system,
                "source_reference": f"{body.source_event_id}:{ref_suffix or table}",
                "source_observed_at": body.source_observed_at,
                "recorded_at": self.p.now,
                "mapping_version": MAPPING_VERSION,
                "intake_item_id": self.item_id,
                "is_synthetic": True,
                **values,
            }
        self.db.execute(insert(self.t[table]).values(**values))
        return row_id

    def external(self, object_type: str, external_id: str, entity_id: uuid.UUID) -> None:
        self.ins(
            "external_reference",
            p=False,
            source_system=self.p.body.source_system,
            object_type=object_type,
            external_id=external_id,
            entity_id=entity_id,
        )

    def event(self, case_id: uuid.UUID, kind: str, summary: str, entity: tuple[str, uuid.UUID] | None = None) -> None:
        self.ins(
            "case_event",
            p=False,
            callback_case_id=case_id,
            event_type=kind,
            occurred_at=self.p.now,
            actor_ref=self.who,
            related_entity_type=entity[0] if entity else None,
            related_entity_id=entity[1] if entity else None,
            summary=f"{summary} (manual intake)",
        )


def _next_number(db: Session, sql: str, prefix: str, start: int) -> int:
    current = db.execute(text(sql), {"p": f"{prefix}%"}).scalar()
    return max(int(current[len(prefix) :]) + 1 if current else start, start)


def commit(
    db: Session, schema: str, p: Plan, *, actor: Actor, meta: RequestMeta, idempotency_key: str, dp: DataProtection
) -> dict[str, Any]:
    """Write the planned transaction in the caller's transaction and return the result summary (no PII).
    The caller holds ``INTAKE_LOCK_KEY``, so reference allocation cannot race."""
    body, now = p.body, p.now
    pol, sale, req = body.policy, body.sale, body.callback_request
    year = now.astimezone(SGT).year
    # Allocate every identifier first: intake_run and intake_item are insert-only and are written before the
    # business rows that reference them, so the run's result must be known up front.
    run_no = _next_number(db, "SELECT max(run_ref) FROM intake_run WHERE run_ref LIKE :p", f"IR-{year}-", 1)
    run_ref = f"IR-{year}-{run_no:06d}"
    case_no = _next_number(
        db,
        "SELECT max(case_ref) FROM callback_case WHERE case_ref LIKE :p AND substr(case_ref, 9, 1) = '1'",
        f"CB-{year}-",
        10001,
    )
    case_ref = f"CB-{year}-{case_no:05d}"
    party_no = _next_number(db, "SELECT max(party_ref) FROM party WHERE party_ref LIKE :p", "PTY-", 1)
    for pl in p.parties:
        if pl.existing_id is None:
            pl.new_id, pl.new_ref = uuid.uuid4(), f"PTY-{party_no:06d}"
            party_no += 1
    run_id, item_id, sale_id, case_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    policy_id = p.policy["id"] if p.policy else uuid.uuid4()
    risk_id = uuid.uuid4() if body.source_risk is not None else None
    ids = Ids(policy_id, sale_id, case_id, case_ref, risk_id, run_id, run_ref)
    result = IntakeOutcome(**describe(p, ids)).model_dump(mode="json")  # stored as served, for replay
    w = _Writer(db, schema, p, actor, item_id)
    w.ins(
        "intake_run",
        p=False,
        id=run_id,
        run_ref=run_ref,
        source_type="MANUAL",
        source_system=body.source_system,
        market_code=pol.market_code,
        status="ACCEPTED",
        started_at=now,
        finished_at=now,
        requested_by=w.by,
        idempotency_key=idempotency_key,
        payload_digest=p.digest,
        received_count=1,
        new_count=1,
        result=result,
    )
    w.ins(
        "intake_item",
        p=False,
        id=item_id,
        intake_run_id=run_id,
        source_system=body.source_system,
        source_event_id=body.source_event_id,
        entity_type="SALE_TRANSACTION",
        status="ACCEPTED",
        errors=[],
        payload_digest=p.digest,
        raw_payload_ref=f"sha256:{p.digest}",
    )
    if p.policy is None:
        w.ins(
            "policy",
            "policy",
            id=policy_id,
            policy_ref=pol.policy_ref,
            market_code=pol.market_code,
            product_code=pol.product_code,
            product_family=pol.product_family,
            product_subtype=pol.product_subtype,
            is_ilp=pol.product_family == "ILP",
            status=pol.status,
            premium_amount=pol.premium_amount,
            currency=pol.currency,
            premium_frequency=pol.premium_frequency,
            premium_term_years=pol.premium_term_years,
            sum_assured=pol.sum_assured,
            sum_assured_currency=pol.sum_assured_currency,
            effective_from=pol.effective_from,
        )
        w.external("POLICY", pol.policy_ref, policy_id)
    # New parties and their contact methods; existing parties are referenced, never changed.
    party_ids: dict[str, uuid.UUID] = {}
    method_ids: dict[tuple[int, int], uuid.UUID] = {}
    for pl in p.parties:
        if pl.existing_id is not None:
            party_ids[str(pl.existing_id)] = pl.existing_id
            continue
        spec = pl.spec
        assert spec.name is not None and spec.kind is not None and pl.new_id and pl.new_ref
        pid = pl.new_id
        w.ins(
            "party",
            f"party:{pl.index}",
            id=pid,
            party_ref=pl.new_ref,
            kind=spec.kind,
            display_alias=f"Synthetic party {pl.new_ref[4:]}",
            name_ciphertext=dp.encrypt(spec.name, aad=aad("party", "name", pid)),
            masked_name=pl.masked_name,
            date_of_birth_year=spec.date_of_birth_year,
            personal_data_class="SYNTHETIC_PERSONAL",
        )
        if spec.source_party_id:
            w.external("PARTY", spec.source_party_id, pid)
        party_ids[f"new:{pl.index}"] = pid
        for j, c in enumerate(pl.contacts):
            cid = uuid.uuid4()
            w.ins(
                "contact_method",
                f"party:{pl.index}:contact:{j}",
                id=cid,
                party_id=pid,
                channel=c["channel"],
                value_ciphertext=dp.encrypt(c["value"], aad=aad("contact_method", "value", cid)),
                value_hmac=dp.token(c["channel"], c["value"]),
                masked_value=mask_contact(c["channel"], c["value"]),
                is_verified=c["is_verified"],
                preference_rank=c["preference_rank"],
                language=c["language"],
                timezone="Asia/Singapore",
                consent_status=c["consent_status"],
                suppressed=c["suppressed"],
                valid_from=sale.sold_at,
            )
            method_ids[(pl.index, j)] = cid
    if p.policy is None:
        for k, e in enumerate(p.role_edges):
            e["id"] = w.ins(
                "policy_party_role",
                f"role:{k}",
                policy_id=policy_id,
                party_id=party_ids[e["key"]],
                role=e["role"],
                valid_from=e["valid_from"],
                authorization_ref=e["authorization_ref"],
                authorization_valid_from=e["authorization_valid_from"],
                authorization_valid_to=e["authorization_valid_to"],
            )
    is_ilp = pol.product_family == "ILP"
    w.ins(
        "sale_event",
        id=sale_id,
        sale_ref=sale.sale_ref,
        policy_id=policy_id,
        sale_event_type=sale.sale_event_type,
        sold_at=sale.sold_at,
        fsc_id=p.fsc_id,
        selling_channel=sale.selling_channel,
        selling_location=sale.selling_location,
        campaign_code=sale.campaign_code,
        proposal_ref=sale.proposal_ref,
        product_snapshot={
            "product_code": pol.product_code,
            "product_family": pol.product_family,
            "product_subtype": pol.product_subtype,
            "is_ilp": is_ilp,
            "premium_amount_band": sale.premium_amount_band,
        },
        premium_amount=sale.premium_amount,
        currency=sale.currency,
        source_reference=body.source_event_id,  # UNIQUE (source_system, source_reference): one sale per event
    )
    w.external("SALE_EVENT", sale.sale_ref, sale_id)
    facts = {
        "policy_ref": pol.policy_ref,
        "market": pol.market_code,
        "product_code": pol.product_code,
        "product_family": pol.product_family,
        "product_subtype": pol.product_subtype,
        "is_ilp": is_ilp,
        "premium_amount": str(sale.premium_amount),
        "currency": sale.currency,
        "premium_frequency": pol.premium_frequency,
        "premium_term_years": pol.premium_term_years,
        "sale_ref": sale.sale_ref,
        "sale_event_type": sale.sale_event_type,
        "selling_channel": sale.selling_channel,
    }
    as_of = sale.sold_at.astimezone(SGT).date().isoformat()
    w.ins(
        "policy_fact_snapshot",
        "snapshot",
        policy_id=policy_id,
        sale_event_id=sale_id,
        captured_at=now,
        schema_version="1",
        facts=facts,
        field_provenance={k: {"source_system": body.source_system, "as_of": as_of} for k in facts},
        sha256=sha256_of(facts),
    )
    risk = body.source_risk
    if risk is not None and risk_id is not None:
        w.ins(
            "risk_assessment",
            "risk",
            id=risk_id,
            sale_event_id=sale_id,
            kind="CALLBACK_SELECTION",
            origin="SOURCE_ASSIGNED",
            status=risk.status,
            band_code=risk.band_code,
            band_list_version_id=p.governed["sbq_risk_band"].version,
            score=None,
            reason_codes=risk.reason_codes,
            explanation=(
                f"Band supplied by source system {body.source_system} (original value "
                f"{risk.source_original_value}) through manual intake; not calculated by Call360"
            ),
            source_original_value=risk.source_original_value,
            rule_set_version_id=None,
            assessed_at=risk.assessed_at,
            valid_at=risk.assessed_at,
            input_snapshot_sha256=sha256_of(
                {
                    "origin": "SOURCE_ASSIGNED",
                    "source_original_value": risk.source_original_value,
                    "reason_codes": risk.reason_codes,
                    "source_reference": f"{body.source_event_id}:risk",
                }
            ),
            supersedes_id=None,
        )
    w.ins(
        "callback_case",
        "case",
        id=case_id,
        case_ref=case_ref,
        sale_event_id=sale_id,
        obligation_type="SALE_VERIFICATION",
        source_request_ref=req.source_request_ref,
        market_code=pol.market_code,
        state="VALIDATED",  # BRD §3.1: created and validated by intake; a held case is never READY
        priority=req.priority,
        due_at=req.due_at,
        created_at=now,
    )
    w.event(case_id, "CASE_CREATED", f"Callback obligation created for {sale.sale_ref}")
    if risk is not None and risk_id is not None:
        w.event(
            case_id,
            "RISK_RECORDED",
            f"SBQ selection risk {risk.band_code} recorded (SOURCE_ASSIGNED, {risk.status})",
            ("risk_assessment", risk_id),
        )
    roles = p.governed["callable_party_roles"]
    for k, x in enumerate(p.eligibility):
        e, m = x["edge"], x["method"]
        method_id = (m["id"] or method_ids[m["_plan"]]) if m else None
        w.ins(
            "case_contact_selection",
            f"selection:{k}",
            callback_case_id=case_id,
            party_id=party_ids.get(e["key"]) or e["party_id"],
            policy_party_role_id=e["id"],
            contact_method_id=method_id,
            eligible=x["eligible"],
            ineligibility_reason=x["reason"],
            rule_basis=e["role"],
            rule_basis_list_version_id=roles.version,
            decided_at=now,
            decided_by=w.who,
        )
    w.event(
        case_id,
        "CONTACTS_SELECTED",
        f"{sum(x['eligible'] for x in p.eligibility)} eligible contact(s) of {len(p.eligibility)} considered",
    )
    hold_list = p.governed["case_hold_reason"]
    for reason in p.holds:
        hid = w.ins(
            "case_hold",
            p=False,
            callback_case_id=case_id,
            hold_reason=reason,
            hold_reason_list_version_id=hold_list.version,
            is_blocking=False,  # set by case_hold_guard from the pinned list value
            placed_at=now,
            placed_by=w.who,
            placed_reason=_hold_reason(reason),
            source="INTAKE",
        )
        write_audit(
            db,
            action="CASE.HOLD_PLACED",
            outcome="SUCCEEDED",
            actor=actor,
            meta=meta,
            entity_type="callback_case",
            entity_id=case_ref,
            reason=_hold_reason(reason),
            after={"hold_reason": reason, "source": "INTAKE", "intake_run": run_ref},
        )
        w.event(case_id, "HOLD_PLACED", f"Hold placed: {reason}", ("case_hold", hid))
    return result


def _hold_reason(reason: str) -> str:
    return {
        "AWAITING_SCRIPT_ASSIGNMENT": "Intake-created case: script routing is not evaluated in Stage 0",
        "NO_ELIGIBLE_CONTACT": "No eligible callback contact under the governed callable-role rule",
        "RISK_TRIAGE": "ILP sale received without SBQ selection risk",
    }.get(reason, reason)


def now_utc() -> datetime:
    return datetime.now(UTC)
