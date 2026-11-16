"""Policy Explorer and Policy Detail read APIs (F4: API-050…055). Read-only; `policy.read` (API-052: `party.read`).

Every object is fetched through its policy with the caller's markets in the WHERE clause (D-39: SG only); a sale is
fetched through its policy and a case additionally carries its own ``market_code`` check. A missing or out-of-scope
id returns the same audited 404 (BE-SEC-02). Case outcomes reuse ``app.domain.outcomes`` and the effective SBQ band
is the latest FINAL assessment (as ``load_facts``); nothing here adds a business rule. Names and contact values leave
the server only in their stored masked form; ciphertext columns are never selected. The `field_change` ledger is
built with intake (CP0.4), so API-055 returns the stored record-level lineage and says the ledger is not available.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.case_detail import _assessments, _deny, _num, _one, _pin, _schema, _snapshot
from app.api.schemas import (
    ContactCard,
    EligibilityOut,
    ErrorResponse,
    ExternalRefOut,
    FieldChangeAvailability,
    FscOut,
    LineageItem,
    MaterialField,
    PageInfo,
    PartyCard,
    PartyList,
    PolicyCaseSummary,
    PolicyDetail,
    PolicyHistory,
    PolicyList,
    PolicyOut,
    PolicyRow,
    Provenance,
    RoleEdge,
    SaleContext,
    SaleList,
    SaleOut,
    SaleSummary,
)
from app.core.errors import AppError
from app.domain.kpis import load_facts
from app.domain.outcomes import derive_outcomes
from app.domain.policy_register import (
    PolicyFilters,
    PolicyRegisterRow,
    apply,
    load_policy_rows,
    policy_facets,
    policy_page,
    policy_predicates,
)
from app.domain.register import NOT_ASSESSED, InvalidFilter, term_hash
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1", tags=["policies"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 422, 429)}
log = logging.getLogger("call360.search")
FIELD_LEDGER_MESSAGE = (
    "Field-level change history is not available yet: field corrections, which write the field_change ledger, "
    "arrive in CP0.4b. Record-level source lineage is shown instead."
)
MATERIAL_FIELDS = (
    "product_code",
    "product_family",
    "product_subtype",
    "is_ilp",
    "status",
    "premium_amount",
    "currency",
    "premium_frequency",
    "premium_term_years",
    "sum_assured",
    "effective_from",
)


# ---- helpers ---------------------------------------------------------------------------------------------------
def _policy(db: Session, request: Request, auth: AuthContext, policy_id: uuid.UUID) -> dict[str, Any]:
    row = _one(db, "SELECT * FROM policy WHERE id = :i AND market_code = ANY(:m)", i=policy_id, m=sorted(auth.markets))
    if row is None:
        raise _deny(db, request, auth, "policy", policy_id)
    return row


def _provenance(r: dict[str, Any]) -> Provenance:
    return Provenance(**{k: r.get(k) for k in Provenance.model_fields})


def _external_refs(db: Session, entity_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[ExternalRefOut]]:
    out: dict[uuid.UUID, list[ExternalRefOut]] = {}
    for r in db.execute(
        text(
            "SELECT entity_id, source_system, object_type, external_id FROM external_reference "
            "WHERE entity_id = ANY(:e) ORDER BY source_system, external_id"
        ),
        {"e": entity_ids},
    ).mappings():
        out.setdefault(r["entity_id"], []).append(ExternalRefOut(**{k: r[k] for k in ExternalRefOut.model_fields}))
    return out


def _policy_out(p: dict[str, Any]) -> dict[str, Any]:
    return {
        **{k: p[k] for k in PolicyOut.model_fields if k not in {"premium_amount", "sum_assured"}},
        "premium_amount": _num(p["premium_amount"]),
        "sum_assured": _num(p["sum_assured"]),
    }


def _sale_out(s: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **{k: s[k] for k in SaleOut.model_fields if k not in {"premium_amount", "fsc"}},
        "premium_amount": _num(s["premium_amount"]),
        "fsc": FscOut(
            fsc_ref=s["fsc_ref"], display_name=s["fsc_name"], channel=s["fsc_channel"], status=s["fsc_status"]
        )
        if s["fsc_ref"]
        else None,
    }


_SALE_SQL = (
    "SELECT s.*, f.fsc_ref, f.display_name AS fsc_name, f.channel AS fsc_channel, f.status AS fsc_status, "
    "(SELECT ra.band_code FROM risk_assessment ra WHERE ra.sale_event_id = s.id AND ra.status = 'FINAL' "
    " ORDER BY ra.valid_at DESC LIMIT 1) AS band, "
    "(SELECT count(*) FROM policy_fact_snapshot pfs WHERE pfs.sale_event_id = s.id) AS snapshots, "
    "p.policy_ref FROM sale_event s JOIN policy p ON p.id = s.policy_id "
    "LEFT JOIN fsc_representative f ON f.id = s.fsc_id WHERE p.market_code = ANY(:m) "
)


def _sales(db: Session, auth: AuthContext, policy_id: uuid.UUID) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in db.execute(
            text(_SALE_SQL + "AND s.policy_id = :p ORDER BY s.sold_at, s.sale_ref"),
            {"p": policy_id, "m": sorted(auth.markets)},
        ).mappings()
    ]


def _cases(
    db: Session, auth: AuthContext, *, policy_id: uuid.UUID | None = None, sale_id: uuid.UUID | None = None
) -> list[PolicyCaseSummary]:
    """Callback cases for a policy or sale, each carrying its verification outcome and pinned script."""
    markets = sorted(auth.markets)
    rows = list(
        db.execute(
            text(
                "SELECT c.id, c.case_ref, c.sale_event_id, c.state, c.due_at, c.verified_at, c.closed_at, "
                "s.sale_ref, s.sale_event_type, "
                "(SELECT ra.band_code FROM risk_assessment ra WHERE ra.sale_event_id = s.id AND ra.status = 'FINAL' "
                " ORDER BY ra.valid_at DESC LIMIT 1) AS band, "
                "a.script_version_id, a.origin AS assignment_origin, a.rule_trace, "
                "rv.rule_code || ' v' || rv.version AS matched_rule "
                "FROM callback_case c JOIN sale_event s ON s.id = c.sale_event_id JOIN policy p ON p.id = s.policy_id "
                "LEFT JOIN LATERAL (SELECT * FROM script_assignment x WHERE x.callback_case_id = c.id "
                " ORDER BY x.assigned_at DESC LIMIT 1) a ON true "
                "LEFT JOIN script_assignment_rule_version rv ON rv.id = a.matched_rule_version_id "
                "WHERE c.market_code = ANY(:m) AND p.market_code = ANY(:m) "
                "AND (CAST(:p AS uuid) IS NULL OR p.id = :p) AND (CAST(:s AS uuid) IS NULL OR s.id = :s) "
                "ORDER BY s.sold_at, c.case_ref"
            ),
            {"m": markets, "p": policy_id, "s": sale_id},
        ).mappings()
    )
    if not rows:
        return []
    outcomes = derive_outcomes(db.connection(), _schema(db), markets)
    out = []
    for r in rows:
        o = outcomes[r["case_ref"]]
        out.append(
            PolicyCaseSummary(
                case_id=r["id"],
                case_ref=r["case_ref"],
                sale_event_id=r["sale_event_id"],
                sale_ref=r["sale_ref"],
                sale_event_type=r["sale_event_type"],
                state=r["state"],
                outcome=o.category,
                controls_satisfied=o.controls_satisfied if r["state"] == "VERIFIED" else None,
                open_findings=o.open_findings,
                risk_band=r["band"] or NOT_ASSESSED,
                due_at=r["due_at"],
                verified_at=r["verified_at"],
                closed_at=r["closed_at"],
                script=_pin(db, r["script_version_id"]) if r["script_version_id"] else None,
                matched_rule=r["matched_rule"],
                assignment_origin=r["assignment_origin"],
                script_rationale=r["rule_trace"] or {},
                route=f"/cases/{r['id']}",
            )
        )
    return out


# ---- API-050 ---------------------------------------------------------------------------------------------------
def policy_filters(
    q: str | None = Query(None, description="Policy, sale, party, case or FSC ref; or an exact phone / email"),
    product_family: list[str] = Query([]),
    ilp: bool | None = Query(None),
    band: list[str] = Query([], description="Effective SBQ band of the latest sale, or NOT_ASSESSED"),
    channel: list[str] = Query([], description="Selling channel of the latest sale event"),
    sale_type: list[str] = Query([], description="Policies with at least one sale event of this type"),
    multi_sale: bool | None = Query(None, description="More than one sale event (e.g. a top-up)"),
    case_state: list[str] = Query([], description="State of the latest callback case"),
    outcome: list[str] = Query([], description="Verification outcome of the latest callback case"),
) -> PolicyFilters:
    flt = PolicyFilters(q, product_family, ilp, band, channel, sale_type, multi_sale, case_state, outcome)
    try:
        flt.validate()
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return flt


def _row(r: PolicyRegisterRow) -> PolicyRow:
    latest, case = r.latest_sale, r.latest_case
    return PolicyRow(
        policy_id=r.id,
        policy_ref=r.ref,
        owner=" & ".join(r.owners) or "—",
        insured=" & ".join(r.insured) or "—",
        product_code=r.product_code,
        product_family=r.product_family,
        product_subtype=r.product_subtype,
        is_ilp=r.is_ilp,
        premium_amount=r.premium_amount,
        currency=r.currency,
        premium_frequency=r.premium_frequency,
        sales=len(r.sales),
        sale_types=sorted({s.type for s in r.sales}),
        latest_sale_ref=latest.ref if latest else None,
        latest_sold_at=latest.sold_at if latest else None,
        selling_channel=latest.channel if latest else None,
        selling_location=latest.location if latest else None,
        fsc_ref=latest.fsc_ref if latest else None,
        fsc_name=latest.fsc_name if latest else None,
        risk_band=r.band,
        script=case.script if case else None,
        cases=len(r.cases),
        latest_case_id=case.id if case else None,
        latest_case_ref=case.ref if case else None,
        latest_case_state=case.state if case else None,
        latest_case_outcome=case.outcome if case else None,
        is_synthetic=r.is_synthetic,
        route=f"/policies/{r.id}",
    )


@router.get("/policies", response_model=PolicyList, operation_id="policies_list", responses=_ERR)
def list_policies(
    request: Request,
    flt: PolicyFilters = Depends(policy_filters),
    sort: str = Query(
        "-latest_sold_at", description="latest_sold_at | policy_ref | premium_amount | risk_band | cases; - for desc"
    ),
    limit: int = Query(25, ge=1, le=100),
    cursor: str | None = Query(None, max_length=512),
    auth: AuthContext = Depends(require("policy.read")),
    db: Session = Depends(get_db),
) -> PolicyList:
    conn = db.connection()
    f = load_facts(conn, _schema(db), sorted(auth.markets), datetime.now(UTC))
    rows = load_policy_rows(conn, f)
    if flt.q:
        log.info("policy register search", extra={"q_sha256": term_hash(flt.q), "cid": request.state.correlation_id})
    preds = policy_predicates(flt, request.app.state.data_protection)
    matched = apply(rows, preds)
    try:
        chunk, nxt = policy_page(matched, sort, limit, cursor)
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return PolicyList(
        items=[_row(r) for r in chunk],
        total=len(matched),
        page=PageInfo(next_cursor=nxt, limit=limit, sort=sort),
        facets=policy_facets(rows, preds),
        markets=f.markets,
        data_as_of=f.now,
        synthetic_badge=any(r.is_synthetic for r in matched),
    )


# ---- API-051 ---------------------------------------------------------------------------------------------------
@router.get("/policies/{policy_id}", response_model=PolicyDetail, operation_id="policy_detail", responses=_ERR)
def policy_detail(
    policy_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("policy.read")),
    db: Session = Depends(get_db),
) -> PolicyDetail:
    p = _policy(db, request, auth, policy_id)
    roles = db.execute(
        text(
            "SELECT r.role, pa.masked_name FROM policy_party_role r JOIN party pa ON pa.id = r.party_id "
            "WHERE r.policy_id = :p AND r.valid_to IS NULL AND r.role IN ('OWNER', 'INSURED') ORDER BY pa.party_ref"
        ),
        {"p": policy_id},
    ).all()
    sales = _sales(db, auth, policy_id)
    as_of = p["source_observed_at"] or p["recorded_at"]
    return PolicyDetail(
        **_policy_out(p),
        market=p["market_code"],
        provenance=_provenance(p),
        material_fields=[
            MaterialField(
                field=k,
                value=_num(p[k]) if k in {"premium_amount", "sum_assured"} else p[k],
                source_system=p["source_system"],
                source_reference=p["source_reference"],
                as_of=as_of,
            )
            for k in MATERIAL_FIELDS
        ],
        external_refs=_external_refs(db, [policy_id]).get(policy_id, []),
        owners=list(dict.fromkeys(n for role, n in roles if role == "OWNER")),
        insured=list(dict.fromkeys(n for role, n in roles if role == "INSURED")),
        sales=len(sales),
        top_ups=sum(1 for s in sales if s["sale_event_type"] == "TOP_UP"),
        latest_sale_id=sales[-1]["id"] if sales else None,
        risk_band=(sales[-1]["band"] if sales else None) or NOT_ASSESSED,
        cases=_cases(db, auth, policy_id=policy_id),
        data_as_of=datetime.now(UTC),
    )


# ---- API-052 ---------------------------------------------------------------------------------------------------
@router.get("/policies/{policy_id}/parties", response_model=PartyList, operation_id="policy_parties", responses=_ERR)
def policy_parties(
    policy_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("party.read")),
    db: Session = Depends(get_db),
) -> PartyList:
    p = _policy(db, request, auth, policy_id)
    parties: dict[uuid.UUID, PartyCard] = {}
    for r in db.execute(
        text(
            "SELECT pa.id AS party_id, pa.party_ref, pa.kind, pa.masked_name, pa.personal_data_class, "
            "pa.source_type, pa.source_system, pa.source_reference, pa.source_observed_at, pa.recorded_at, "
            "pa.mapping_version, pa.intake_item_id, pa.is_synthetic, r.role, r.valid_from, r.valid_to, "
            "r.authorization_ref, r.authorization_valid_from, r.authorization_valid_to, "
            "r.source_system AS role_source FROM policy_party_role r JOIN party pa ON pa.id = r.party_id "
            "WHERE r.policy_id = :p ORDER BY pa.party_ref, r.valid_to NULLS FIRST, r.role"
        ),
        {"p": policy_id},
    ).mappings():
        card = parties.setdefault(
            r["party_id"],
            PartyCard(
                party_ref=r["party_ref"],
                kind=r["kind"],
                masked_name=r["masked_name"],
                personal_data_class=r["personal_data_class"],
                roles=[],
                contacts=[],
                eligibility=[],
                provenance=_provenance(dict(r)),
            ),
        )
        card.roles.append(
            RoleEdge(
                role=r["role"],
                valid_from=r["valid_from"],
                valid_to=r["valid_to"],
                current=r["valid_to"] is None,
                authorization_ref=r["authorization_ref"],
                authorization_valid_from=r["authorization_valid_from"],
                authorization_valid_to=r["authorization_valid_to"],
                source_system=r["role_source"],
            )
        )
    ids = list(parties)
    for r in db.execute(
        text(
            "SELECT party_id, channel, masked_value, is_verified, preference_rank, language, timezone, consent_status, "
            "suppressed, valid_from, valid_to, source_system, source_observed_at FROM contact_method "
            "WHERE party_id = ANY(:ids) ORDER BY valid_to NULLS FIRST, preference_rank NULLS LAST, channel"
        ),
        {"ids": ids},
    ).mappings():
        parties[r["party_id"]].contacts.append(
            ContactCard(**{k: r[k] for k in ContactCard.model_fields if k != "current"}, current=r["valid_to"] is None)
        )
    for r in db.execute(
        text(
            "SELECT sel.party_id, c.id AS case_id, c.case_ref, ppr.role, cm.channel, "
            "cm.masked_value AS masked_contact, "
            "sel.eligible, sel.ineligibility_reason, sel.rule_basis, sel.decided_at, sel.decided_by, "
            "EXISTS (SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = sel.id) AS superseded "
            "FROM case_contact_selection sel JOIN callback_case c ON c.id = sel.callback_case_id "
            "JOIN sale_event s ON s.id = c.sale_event_id "
            "JOIN policy_party_role ppr ON ppr.id = sel.policy_party_role_id "
            "LEFT JOIN contact_method cm ON cm.id = sel.contact_method_id "
            "WHERE s.policy_id = :p AND c.market_code = ANY(:m) ORDER BY sel.decided_at, c.case_ref, ppr.role"
        ),
        {"p": policy_id, "m": sorted(auth.markets)},
    ).mappings():
        if r["party_id"] in parties:
            parties[r["party_id"]].eligibility.append(EligibilityOut(**{k: r[k] for k in EligibilityOut.model_fields}))
    return PartyList(policy_id=policy_id, policy_ref=p["policy_ref"], items=list(parties.values()))


# ---- API-053 ---------------------------------------------------------------------------------------------------
@router.get("/policies/{policy_id}/sales", response_model=SaleList, operation_id="policy_sales", responses=_ERR)
def policy_sales(
    policy_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("policy.read")),
    db: Session = Depends(get_db),
) -> SaleList:
    p = _policy(db, request, auth, policy_id)
    cases = _cases(db, auth, policy_id=policy_id)
    items = [
        SaleSummary(
            **_sale_out(s),
            source_reference=s["source_reference"],
            source_observed_at=s["source_observed_at"],
            risk_band=s["band"] or NOT_ASSESSED,
            fact_snapshots=s["snapshots"],
            cases=[c for c in cases if c.sale_event_id == s["id"]],
        )
        for s in _sales(db, auth, policy_id)
    ]
    return SaleList(policy_id=policy_id, policy_ref=p["policy_ref"], items=items)


# ---- API-054 ---------------------------------------------------------------------------------------------------
@router.get("/sales/{sale_event_id}", response_model=SaleContext, operation_id="sale_context", responses=_ERR)
def sale_context(
    sale_event_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("policy.read")),
    db: Session = Depends(get_db),
) -> SaleContext:
    s = _one(db, _SALE_SQL + "AND s.id = :s", s=sale_event_id, m=sorted(auth.markets))
    if s is None:
        raise _deny(db, request, auth, "sale_event", sale_event_id)
    effective = _one(
        db,
        "SELECT id FROM risk_assessment WHERE sale_event_id = :s AND status = 'FINAL' ORDER BY valid_at DESC LIMIT 1",
        s=sale_event_id,
    )
    return SaleContext(
        sale=SaleOut(**_sale_out(s)),
        policy_id=s["policy_id"],
        policy_ref=s["policy_ref"],
        provenance=_provenance(s),
        external_refs=_external_refs(db, [sale_event_id]).get(sale_event_id, []),
        fact_snapshots=[
            _snapshot(dict(r))
            for r in db.execute(
                text("SELECT * FROM policy_fact_snapshot WHERE sale_event_id = :s ORDER BY captured_at"),
                {"s": sale_event_id},
            ).mappings()
        ],
        risk_assessments=_assessments(db, sale_event_id, effective["id"] if effective else None),
        cases=_cases(db, auth, sale_id=sale_event_id),
    )


# ---- API-055 ---------------------------------------------------------------------------------------------------
_LINEAGE_SQL = (
    "SELECT 'policy' AS entity_type, p.id, p.policy_ref AS ref, p.product_code AS label, p.source_type, "
    "p.source_system, p.source_reference, p.source_observed_at, p.recorded_at, p.mapping_version, p.intake_item_id, "
    "p.is_synthetic FROM policy p WHERE p.id = :p "
    "UNION ALL SELECT 'sale_event', s.id, s.sale_ref, s.sale_event_type, s.source_type, s.source_system, "
    "s.source_reference, s.source_observed_at, s.recorded_at, s.mapping_version, s.intake_item_id, s.is_synthetic "
    "FROM sale_event s WHERE s.policy_id = :p "
    "UNION ALL SELECT 'policy_party_role', r.id, pa.party_ref, r.role, r.source_type, r.source_system, "
    "r.source_reference, r.source_observed_at, r.recorded_at, r.mapping_version, r.intake_item_id, r.is_synthetic "
    "FROM policy_party_role r JOIN party pa ON pa.id = r.party_id WHERE r.policy_id = :p "
    "UNION ALL SELECT 'policy_fact_snapshot', f.id, s.sale_ref, 'schema v' || f.schema_version, f.source_type, "
    "f.source_system, f.source_reference, f.source_observed_at, f.recorded_at, f.mapping_version, f.intake_item_id, "
    "f.is_synthetic FROM policy_fact_snapshot f JOIN sale_event s ON s.id = f.sale_event_id WHERE f.policy_id = :p "
    "UNION ALL SELECT 'risk_assessment', ra.id, s.sale_ref, ra.origin || ' ' || coalesce(ra.band_code, 'NO BAND'), "
    "ra.source_type, ra.source_system, ra.source_reference, ra.source_observed_at, ra.recorded_at, "
    "ra.mapping_version, ra.intake_item_id, ra.is_synthetic FROM risk_assessment ra "
    "JOIN sale_event s ON s.id = ra.sale_event_id WHERE s.policy_id = :p "
    "ORDER BY recorded_at, entity_type, ref"
)


@router.get(
    "/policies/{policy_id}/history", response_model=PolicyHistory, operation_id="policy_history", responses=_ERR
)
def policy_history(
    policy_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("policy.read")),
    db: Session = Depends(get_db),
) -> PolicyHistory:
    p = _policy(db, request, auth, policy_id)
    rows = [dict(r) for r in db.execute(text(_LINEAGE_SQL), {"p": policy_id}).mappings()]
    refs = _external_refs(db, [r["id"] for r in rows])
    return PolicyHistory(
        policy_id=policy_id,
        policy_ref=p["policy_ref"],
        lineage=[
            LineageItem(
                entity_type=r["entity_type"],
                entity_ref=r["ref"],
                label=r["label"],
                provenance=_provenance(r),
                external_refs=refs.get(r["id"], []),
            )
            for r in rows
        ],
        field_changes=FieldChangeAvailability(
            availability="NOT_AVAILABLE", reason="LEDGER_ARRIVES_CP0_4", message=FIELD_LEDGER_MESSAGE
        ),
    )
