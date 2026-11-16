"""SBQ Risk Workbench read APIs (F5: API-056…058). Read-only; `risk.read`.

The register and detail read stored SBQ callback-selection assessments only; no score, band or threshold is
calculated (RISK-008 is Stage S2) and there is no override workflow. Scope (D-39: SG only) is applied through the
assessment's sale and policy in every query; a missing or out-of-scope assessment returns the same audited 404
(BE-SEC-02). Investment suitability and finding severity are separate records and are not returned here.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.case_detail import _deny, _one
from app.api.policies import _provenance
from app.api.schemas import (
    CaseLink,
    ErrorResponse,
    FactorVocabularyItem,
    PageInfo,
    RiskAssessmentDetail,
    RiskComparison,
    RiskFactorDetail,
    RiskFactorVocabulary,
    RiskList,
    RiskRow,
    RiskSummary,
    RuleSetOut,
)
from app.core.errors import AppError
from app.domain.register import InvalidFilter, term_hash
from app.domain.risk_register import (
    Assessment,
    RiskFilters,
    apply,
    latest_final,
    load_assessments,
    risk_facets,
    risk_page,
    risk_predicates,
    sale_population,
    summary,
)
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1", tags=["risk"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 422, 429)}
log = logging.getLogger("call360.search")


def _row(a: Assessment) -> RiskRow:
    return RiskRow(
        id=a.id,
        sale_event_id=a.sale_event_id,
        sale_ref=a.sale_ref,
        sale_event_type=a.sale_event_type,
        sold_at=a.sold_at,
        policy_id=a.policy_id,
        policy_ref=a.policy_ref,
        product_family=a.product_family,
        is_ilp=a.is_ilp,
        channel=a.channel,
        fsc_ref=a.fsc_ref,
        origin=a.origin,
        status=a.status,
        band_code=a.band,
        score=a.score,
        reason_codes=a.reason_codes,
        source_original_value=a.source_original_value,
        rule_set=a.rule_set,
        assessed_at=a.assessed_at,
        valid_at=a.valid_at,
        input_snapshot_sha256=a.input_snapshot_sha256,
        matched_factors=a.matched_factors,
        effective=a.effective,
        supersedes_id=a.supersedes_id,
        superseded_by=a.superseded_by,
        discrepancy=a.discrepancy,
        cases=[CaseLink(case_id=i, case_ref=ref, route=f"/cases/{i}") for i, ref in a.cases],
        is_synthetic=a.is_synthetic,
        route=f"/risk-assessments?assessment={a.id}",
    )


# ---- API-056 ---------------------------------------------------------------------------------------------------
def risk_filters(
    q: str | None = Query(None, description="Sale, policy, case or FSC ref"),
    band: list[str] = Query([], description="Stored SBQ band code (NO_BAND when none)"),
    factor: list[str] = Query([], description="Assessments where this factor was MATCHED"),
    origin: list[str] = Query([], description="SOURCE_ASSIGNED | RULE_ASSESSED | MANUAL"),
    status: list[str] = Query([], description="Stored assessment status, e.g. FINAL | SUPERSEDED"),
    rule_set: list[str] = Query([], description="Rule-set version label, e.g. 'SYN-SBQ-RULES v2' (NONE when absent)"),
    product_family: list[str] = Query([]),
    channel: list[str] = Query([], description="Selling channel of the assessed sale"),
    fsc: list[str] = Query([], description="FSC ref of the assessed sale"),
    effective: bool | None = Query(None, description="Latest FINAL assessment of its sale"),
    discrepancy: bool | None = Query(None, description="Sale whose source-assigned and rule-assessed bands differ"),
) -> RiskFilters:
    flt = RiskFilters(q, band, factor, origin, status, rule_set, product_family, channel, fsc, effective, discrepancy)
    try:
        flt.validate()
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return flt


@router.get("/risk-assessments", response_model=RiskList, operation_id="risk_assessments_list", responses=_ERR)
def list_risk_assessments(
    request: Request,
    flt: RiskFilters = Depends(risk_filters),
    sort: str = Query("-valid_at", description="valid_at | band | sale_ref | origin; prefix - for descending"),
    limit: int = Query(25, ge=1, le=100),
    cursor: str | None = Query(None, max_length=512),
    auth: AuthContext = Depends(require("risk.read")),
    db: Session = Depends(get_db),
) -> RiskList:
    markets = sorted(auth.markets)
    conn = db.connection()
    rows = load_assessments(conn, markets)
    if flt.q:
        log.info("risk register search", extra={"q_sha256": term_hash(flt.q), "cid": request.state.correlation_id})
    preds = risk_predicates(flt)
    matched = apply(rows, preds)
    try:
        chunk, nxt = risk_page(matched, sort, limit, cursor)
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    return RiskList(
        items=[_row(a) for a in chunk],
        total=len(matched),
        page=PageInfo(next_cursor=nxt, limit=limit, sort=sort),
        facets=risk_facets(rows, preds),
        summary=RiskSummary.model_validate(summary(rows, sale_population(conn, markets))),
        markets=markets,
        data_as_of=datetime.now(UTC),
        synthetic_badge=any(a.is_synthetic for a in matched),
    )


# ---- API-057 ---------------------------------------------------------------------------------------------------
@router.get(
    "/risk-assessments/{assessment_id}",
    response_model=RiskAssessmentDetail,
    operation_id="risk_assessment_detail",
    responses=_ERR,
)
def risk_assessment_detail(
    assessment_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("risk.read")),
    db: Session = Depends(get_db),
) -> RiskAssessmentDetail:
    markets = sorted(auth.markets)
    r = _one(
        db,
        "SELECT ra.* FROM risk_assessment ra JOIN sale_event s ON s.id = ra.sale_event_id "
        "JOIN policy p ON p.id = s.policy_id WHERE ra.id = :i AND p.market_code = ANY(:m)",
        i=assessment_id,
        m=markets,
    )
    if r is None:
        raise _deny(db, request, auth, "risk_assessment", assessment_id)
    sale_rows = [a for a in load_assessments(db.connection(), markets) if a.sale_event_id == r["sale_event_id"]]
    this = next(a for a in sale_rows if a.id == assessment_id)
    labels: dict[str, str] = dict(
        db.execute(
            text(
                "SELECT cv.code, cv.label FROM code_value cv "
                "JOIN code_list_version v ON v.id = cv.code_list_version_id "
                "JOIN code_list l ON l.id = v.code_list_id WHERE l.code = 'risk_factor'"
            )
        ).all()
    )
    factors = [
        RiskFactorDetail(
            factor_code=f["factor_code"],
            label=labels.get(f["factor_code"]),
            value_type=f["value_type"],
            value=f["value"],
            source=f["source"],
            matched_rule_id=f["matched_rule_id"],
            weight=float(f["weight"]) if f["weight"] is not None else None,
            result=f["result"],
        )
        for f in db.execute(
            text("SELECT * FROM risk_factor_result WHERE assessment_id = :a ORDER BY factor_code"), {"a": assessment_id}
        ).mappings()
    ]
    rs = (
        _one(db, "SELECT * FROM risk_rule_set_version WHERE id = :i", i=r["rule_set_version_id"])
        if r["rule_set_version_id"]
        else None
    )

    src, rule = latest_final(sale_rows, "SOURCE_ASSIGNED"), latest_final(sale_rows, "RULE_ASSESSED")
    eff = latest_final(sale_rows)
    return RiskAssessmentDetail(
        **_row(this).model_dump(),
        kind=r["kind"],
        explanation=r["explanation"],
        factors=factors,
        rule_set_version=RuleSetOut(**{k: rs[k] for k in RuleSetOut.model_fields}) if rs else None,
        provenance=_provenance(r),
        history=[_row(a) for a in sorted(sale_rows, key=lambda a: (a.valid_at, a.origin, str(a.id)))],
        comparison=RiskComparison(
            source_band=src.band if src else None,
            rule_band=rule.band if rule else None,
            effective_band=eff.band if eff else None,
            effective_id=eff.id if eff else None,
            discrepancy=bool(src and rule and src.band != rule.band),
        ),
    )


# ---- API-058 ---------------------------------------------------------------------------------------------------
@router.get("/risk-factors", response_model=RiskFactorVocabulary, operation_id="risk_factors", responses=_ERR)
def risk_factors(
    auth: AuthContext = Depends(require("risk.read")), db: Session = Depends(get_db)
) -> RiskFactorVocabulary:
    def active(code: str) -> tuple[dict[str, Any], list[FactorVocabularyItem]]:
        v = _one(
            db,
            "SELECT v.id, v.version, v.status FROM code_list_version v JOIN code_list l ON l.id = v.code_list_id "
            "WHERE l.code = :c AND v.status = 'ACTIVE' ORDER BY v.version DESC LIMIT 1",
            c=code,
        )
        if v is None:
            return {"version": 0, "status": "NONE"}, []
        items = [
            FactorVocabularyItem(code=x["code"], label=x["label"], attributes=x["attributes"] or {})
            for x in db.execute(
                text(
                    "SELECT code, label, attributes FROM code_value WHERE code_list_version_id = :v "
                    "ORDER BY sort_order, code"
                ),
                {"v": v["id"]},
            ).mappings()
        ]
        return v, items

    fv, factors = active("risk_factor")
    _, bands = active("sbq_risk_band")
    return RiskFactorVocabulary(
        list_code="risk_factor", version=fv["version"], status=fv["status"], items=factors, bands=bands
    )
