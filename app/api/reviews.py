"""Review Workbench and Voice Studio read APIs (F7: API-077, API-078). Read-only.

- ``GET /review-queue`` (API-077, ``queue.read``): compliance findings of in-scope cases (D-39: Singapore only) with
  their case, policy and sale, the recorded question, answer and rule evaluation they point at, and linked controls.
  Server-side search, filters, sorting and offset paging. Finding *severity* is a compliance attribute; the case's
  SBQ callback-selection band is returned separately as context; investment suitability is not part of a finding.
  No review decision, assignment or adjudication exists in Stage 0 (S3).
- API-078 (voice preflight) moved to ``app/api/voice.py`` in S1-A.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.schemas import ErrorResponse, ReviewEvidence, ReviewItem, ReviewQueue
from app.domain.kpis import load_facts
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1", tags=["reviews"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 422)}
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Status = Literal["OPEN", "UNDER_REVIEW", "CONFIRMED", "DISMISSED", "CLOSED"]
Origin = Literal["RULE_EVALUATION", "NARRATIVE_FLAG", "REVIEWER"]
AWAITING = {"OPEN", "UNDER_REVIEW"}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SORTS = {
    "-raised_at": (lambda i: i.raised_at, True),
    "raised_at": (lambda i: i.raised_at, False),
    "severity": (lambda i: (SEVERITY_RANK.get(i.severity, 9), i.finding_ref), False),
    "case_ref": (lambda i: (i.case_ref, i.finding_ref), False),
    "finding_ref": (lambda i: i.finding_ref, False),
}

_SQL = """
SELECT f.*, c.case_ref, c.state AS case_state, s.id AS sale_event_id, s.sale_ref, p.id AS policy_id, p.policy_ref,
       qbi.id AS item_id, qbi.question_code, qr.customer_wording,
       ao.answer_state, ao.typed_value, ao.verbatim_text_redacted,
       re.rule_ref, re.rule_version, re.expected, re.observed, re.result
FROM finding f
JOIN callback_case c ON c.id = f.callback_case_id
JOIN sale_event s ON s.id = c.sale_event_id
JOIN policy p ON p.id = s.policy_id
LEFT JOIN question_execution qe ON qe.id = f.question_execution_id
LEFT JOIN question_revision qr ON qr.id = qe.question_revision_id
LEFT JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id
LEFT JOIN answer_observation ao ON ao.id = CAST(f.evidence_refs->>'answer_observation_id' AS uuid)
LEFT JOIN rule_evaluation re ON re.id = CAST(f.evidence_refs->>'rule_evaluation_id' AS uuid)
WHERE c.market_code = ANY(:m)
"""


def _material(db: Session) -> list[str]:
    return list(
        db.execute(
            text(
                "SELECT cv.code FROM code_value cv JOIN code_list_version v ON v.id = cv.code_list_version_id "
                "AND v.status = 'ACTIVE' JOIN code_list l ON l.id = v.code_list_id "
                "WHERE l.code = 'finding_materiality_policy' AND (cv.attributes->>'material')::boolean ORDER BY cv.code"
            )
        ).scalars()
    )


def _controls(db: Session) -> dict[Any, list[str]]:
    out: dict[Any, list[str]] = {}
    for r in db.execute(
        text(
            "SELECT DISTINCT cm.question_bank_item_id, ct.control_code FROM control_mapping cm "
            "JOIN control ct ON ct.id = cm.control_id ORDER BY ct.control_code"
        )
    ):
        out.setdefault(r.question_bank_item_id, []).append(r.control_code)
    return out


# ---- API-077 ---------------------------------------------------------------------------------------------------
@router.get("/review-queue", response_model=ReviewQueue, operation_id="review_queue", responses=_ERR)
def review_queue(
    auth: AuthContext = Depends(require("queue.read")),
    db: Session = Depends(get_db),
    queue: Literal["AWAITING_REVIEW", "ALL"] = "AWAITING_REVIEW",
    q: str | None = Query(None, max_length=80, description="Finding, case, policy or sale reference, or question code"),
    severity: list[Severity] = Query(default_factory=list),
    status: list[Status] = Query(default_factory=list),
    category: list[str] = Query(default_factory=list, max_length=20),
    origin: list[Origin] = Query(default_factory=list),
    material: bool | None = None,
    sort: Literal["-raised_at", "raised_at", "severity", "case_ref", "finding_ref"] = "severity",
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
) -> ReviewQueue:
    markets = sorted(auth.markets)
    conn = db.connection()
    schema = conn.execute(text("SELECT current_schema()")).scalar_one()
    facts = load_facts(conn, schema, markets, datetime.now(UTC))  # effective SBQ band per case, as elsewhere
    material_codes = set(_material(db))
    controls = _controls(db)
    rows = db.execute(text(_SQL), {"m": markets}).mappings().all()
    every = []
    for r in rows:
        ev = r["evidence_refs"] or {}
        fc = facts.cases.get(r["callback_case_id"])
        every.append(
            ReviewItem(
                **{k: r[k] for k in ("id", "finding_ref", "category", "severity", "status", "origin", "record_origin")},
                material=r["severity"] in material_codes,
                raised_at=r["raised_at"],
                review_assigned_at=r["review_assigned_at"],
                review_closed_at=r["review_closed_at"],
                reviewer_assigned=r["assigned_reviewer_id"] is not None,
                case_id=r["callback_case_id"],
                case_ref=r["case_ref"],
                case_state=r["case_state"],
                policy_id=r["policy_id"],
                policy_ref=r["policy_ref"],
                sale_event_id=r["sale_event_id"],
                sale_ref=r["sale_ref"],
                selection_risk_band=(fc.band if fc and fc.band else "NOT_ASSESSED"),
                evidence=ReviewEvidence(
                    question_code=r["question_code"],
                    question_wording=r["customer_wording"],
                    controls=controls.get(r["item_id"], []),
                    answer_state=r["answer_state"],
                    typed_value=r["typed_value"],
                    verbatim_redacted=r["verbatim_text_redacted"],
                    rule_ref=r["rule_ref"],
                    rule_version=None if r["rule_version"] is None else str(r["rule_version"]),
                    rule_expected=r["expected"],
                    rule_observed=r["observed"],
                    rule_result=r["result"],
                    transcript=str(ev.get("transcript") or "NOT_AVAILABLE"),
                    recording="NOT_AVAILABLE",  # no recording exists before Stage S1
                    label=ev.get("label"),
                ),
            )
        )
    in_queue = [i for i in every if queue == "ALL" or i.status in AWAITING]
    facets: dict[str, dict[str, int]] = {"severity": {}, "status": {}, "category": {}, "origin": {}}
    for i in in_queue:
        for k in facets:
            v = getattr(i, k)
            facets[k][v] = facets[k].get(v, 0) + 1
    needle = q.strip().upper() if q else ""
    items = [
        i
        for i in in_queue
        if (not severity or i.severity in severity)
        and (not status or i.status in status)
        and (not category or i.category in category)
        and (not origin or i.origin in origin)
        and (material is None or i.material == material)
        and (
            not needle
            or any(
                needle in (v or "").upper()
                for v in (i.finding_ref, i.case_ref, i.policy_ref, i.sale_ref, i.evidence.question_code)
            )
        )
    ]
    key, reverse = SORTS[sort]
    items.sort(key=key, reverse=reverse)
    return ReviewQueue(
        items=items[offset : offset + limit],
        total=len(items),
        limit=limit,
        offset=offset,
        facets=facets,
        material_severities=sorted(material_codes),
        markets=markets,
    )
