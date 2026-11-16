"""Script Studio and Assignment Rules read APIs (F6: API-060…062, API-064…066). Read-only, ``script.read``.

Scripts, rules, regulatory references and question links are restricted to the caller's markets (D-39: Singapore
only in Stage 0); an out-of-scope or missing family is a 404 with an access-denied audit event. Nothing here edits,
publishes, evaluates an assignment rule or releases a hold: those are Stage S2. The library's product, risk-band and
channel filters match the *content conditions* written on each version's modules (which module applies to which
product, band or channel); they do not evaluate any case.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.case_detail import _deny, _one, _pin
from app.api.schemas import (
    AssignmentRuleList,
    AssignmentRuleOut,
    ControlList,
    ControlOut,
    ControlQuestionLink,
    ErrorResponse,
    RegulatoryReferenceList,
    RegulatoryReferenceOut,
    RuleCaseRef,
    ScriptFamilyDetail,
    ScriptLibrary,
    ScriptModuleSummary,
    ScriptVersionList,
    ScriptVersionSummary,
)
from app.security.authz import AuthContext, get_db, require

router = APIRouter(prefix="/api/v1", tags=["scripts"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 422)}
VersionStatus = Literal[
    "DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED", "SCHEDULED", "PUBLISHED", "SUPERSEDED", "WITHDRAWN"
]
RECENT_CASES = 10


def _markets(auth: AuthContext, market_code: str | None = None) -> list[str]:
    scope = set(auth.markets)
    return sorted(scope & {market_code} if market_code else scope)


def content_tags(condition: Any) -> dict[str, set[str]]:
    """What a module's inclusion condition names: product families (``is_ilp`` → ``ILP``), risk bands, channels."""
    tags: dict[str, set[str]] = {"product_family": set(), "risk_band": set(), "channel": set()}
    if not isinstance(condition, dict):
        return tags
    for part in condition.get("all", []) + condition.get("any", []):
        for k, v in content_tags(part).items():
            tags[k] |= v
    fact, equals = condition.get("fact"), condition.get("equals")
    if fact == "product_family" and isinstance(equals, str):
        tags["product_family"].add(equals)
    elif fact == "is_ilp" and equals is True:
        tags["product_family"].add("ILP")
    elif fact == "selling_channel" and isinstance(equals, str):
        tags["channel"].add(equals)
    for band in condition.get("risk_band_in", []) or []:
        tags["risk_band"].add(str(band))
    return tags


def _summaries(db: Session, markets: list[str], family_id: uuid.UUID | None = None) -> list[ScriptVersionSummary]:
    rows = (
        db.execute(
            text(
                "SELECT v.*, f.code AS family, f.name AS family_name, f.market_code, f.purpose, "
                "p.version_label AS supersedes_label FROM script_version v "
                "JOIN script_family f ON f.id = v.script_family_id "
                "LEFT JOIN script_version p ON p.id = v.supersedes_id "
                "WHERE f.market_code = ANY(:m) AND (CAST(:f AS uuid) IS NULL OR f.id = CAST(:f AS uuid)) "
                "ORDER BY f.code, v.effective_from NULLS LAST, v.version_label"
            ),
            {"m": markets, "f": family_id},
        )
        .mappings()
        .all()
    )
    ids = [r["id"] for r in rows]
    if not ids:
        return []
    modules: dict[uuid.UUID, list[ScriptModuleSummary]] = {}
    mandatory: dict[uuid.UUID, int] = {}
    for m in db.execute(
        text(
            "SELECT ss.script_version_id, ss.position, ss.inclusion_condition, sm.code, sm.name, sm.kind, sm.revision, "
            "count(mq.id) AS questions, count(mq.id) FILTER (WHERE qr.mandatory) AS mandatory "
            "FROM script_section ss JOIN script_module sm ON sm.id = ss.script_module_id "
            "LEFT JOIN module_question mq ON mq.script_module_id = sm.id "
            "LEFT JOIN question_revision qr ON qr.id = mq.question_revision_id "
            "WHERE ss.script_version_id = ANY(:v) "
            "GROUP BY ss.script_version_id, ss.position, ss.inclusion_condition, "
            "sm.code, sm.name, sm.kind, sm.revision "
            "ORDER BY ss.position"
        ),
        {"v": ids},
    ).mappings():
        modules.setdefault(m["script_version_id"], []).append(
            ScriptModuleSummary(
                position=m["position"],
                module_code=m["code"],
                module_name=m["name"],
                module_kind=m["kind"],
                module_revision=m["revision"],
                inclusion_condition=m["inclusion_condition"],
                questions=m["questions"],
            )
        )
        mandatory[m["script_version_id"]] = mandatory.get(m["script_version_id"], 0) + m["mandatory"]
    cases: dict[uuid.UUID, int] = dict(
        db.execute(
            text(
                "SELECT a.script_version_id, count(DISTINCT a.callback_case_id) FROM script_assignment a "
                "JOIN callback_case c ON c.id = a.callback_case_id WHERE a.script_version_id = ANY(:v) "
                "AND c.market_code = ANY(:m) GROUP BY a.script_version_id"
            ),
            {"v": ids, "m": markets},
        ).all()
    )
    rules: dict[uuid.UUID, list[str]] = {}
    for rv in db.execute(
        text(
            "SELECT target_script_version_id, rule_code, version FROM script_assignment_rule_version "
            "WHERE target_script_version_id = ANY(:v) ORDER BY rule_code, version"
        ),
        {"v": ids},
    ):
        rules.setdefault(rv.target_script_version_id, []).append(f"{rv.rule_code} v{rv.version}")
    out = []
    for r in rows:
        mods = modules.get(r["id"], [])
        out.append(
            ScriptVersionSummary(
                **{k: r[k] for k in ScriptVersionSummary.model_fields if k in r and k not in {"market"}},
                market=r["market_code"],
                modules=mods,
                questions=sum(m.questions for m in mods),
                mandatory_questions=mandatory.get(r["id"], 0),
                cases_assigned=cases.get(r["id"], 0),
                rules_targeting=rules.get(r["id"], []),
            )
        )
    return out


def _tags(v: ScriptVersionSummary) -> dict[str, set[str]]:
    tags: dict[str, set[str]] = {"product_family": set(), "risk_band": set(), "channel": set()}
    for m in v.modules:
        for k, vals in content_tags(m.inclusion_condition).items():
            tags[k] |= vals
    return tags


def _effective_on(v: ScriptVersionSummary, day: date) -> bool:
    start, end = datetime.combine(day, time.min, UTC), datetime.combine(day, time.max, UTC)
    return (
        v.effective_from is not None and v.effective_from <= end and (v.effective_to is None or v.effective_to > start)
    )


# ---- API-060 ---------------------------------------------------------------------------------------------------
@router.get("/scripts", response_model=ScriptLibrary, operation_id="scripts_list", responses=_ERR)
def scripts_list(
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
    market_code: str | None = Query(None, pattern=r"^[A-Z]{2}$"),
    status: list[VersionStatus] = Query(default_factory=list),
    language: str | None = Query(None, pattern=r"^[a-z]{2}(-[A-Z]{2})?$"),
    effective_on: date | None = None,
    product_family: str | None = Query(None, max_length=40),
    risk_band: str | None = Query(None, max_length=40),
    channel: str | None = Query(None, max_length=40),
    q: str | None = Query(None, max_length=80),
) -> ScriptLibrary:
    markets = _markets(auth, market_code)
    every = _summaries(db, markets) if markets else []
    facets: dict[str, dict[str, int]] = {
        "status": {},
        "language": {},
        "product_family": {},
        "risk_band": {},
        "channel": {},
    }
    items = []
    needle = q.strip().lower() if q else ""
    for v in every:
        tags = _tags(v)
        for k in ("product_family", "risk_band", "channel"):
            for t in tags[k]:
                facets[k][t] = facets[k].get(t, 0) + 1
        facets["status"][v.status] = facets["status"].get(v.status, 0) + 1
        facets["language"][v.language] = facets["language"].get(v.language, 0) + 1
        if status and v.status not in status:
            continue
        if language and v.language != language:
            continue
        if effective_on and not _effective_on(v, effective_on):
            continue
        if product_family and product_family not in tags["product_family"]:
            continue
        if risk_band and risk_band not in tags["risk_band"]:
            continue
        if channel and channel not in tags["channel"]:
            continue
        hay = " ".join([v.family, v.family_name, v.version_label, *(m.module_code for m in v.modules)]).lower()
        if needle and needle not in hay:
            continue
        items.append(v)
    return ScriptLibrary(items=items, total=len(items), facets=facets, markets=markets)


def _family(db: Session, request: Request, auth: AuthContext, family_id: uuid.UUID) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT * FROM script_family WHERE id = :i AND market_code = ANY(:m)",
        i=family_id,
        m=sorted(auth.markets),
    )
    if row is None:
        raise _deny(db, request, auth, "script_family", family_id)
    return row


# ---- API-061 ---------------------------------------------------------------------------------------------------
@router.get(
    "/scripts/{script_family_id}", response_model=ScriptFamilyDetail, operation_id="script_family", responses=_ERR
)
def script_family(
    script_family_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScriptFamilyDetail:
    f = _family(db, request, auth, script_family_id)
    return ScriptFamilyDetail(
        id=f["id"],
        code=f["code"],
        name=f["name"],
        market=f["market_code"],
        purpose=f["purpose"],
        description=f["description"],
        versions=_summaries(db, [f["market_code"]], f["id"]),
    )


# ---- API-062 ---------------------------------------------------------------------------------------------------
@router.get(
    "/scripts/{script_family_id}/versions",
    response_model=ScriptVersionList,
    operation_id="script_family_versions",
    responses=_ERR,
)
def script_family_versions(
    script_family_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScriptVersionList:
    f = _family(db, request, auth, script_family_id)
    return ScriptVersionList(
        script_family_id=f["id"], family=f["code"], items=_summaries(db, [f["market_code"]], f["id"])
    )


# ---- API-064 ---------------------------------------------------------------------------------------------------
@router.get(
    "/script-assignment-rules", response_model=AssignmentRuleList, operation_id="assignment_rules", responses=_ERR
)
def assignment_rules(
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> AssignmentRuleList:
    """Seeded rule versions as recorded; a rule's market is its target script family's market."""
    markets = sorted(auth.markets)
    rows = (
        db.execute(
            text(
                "SELECT r.*, f.market_code, f.id AS family_id FROM script_assignment_rule_version r "
                "JOIN script_version v ON v.id = r.target_script_version_id "
                "JOIN script_family f ON f.id = v.script_family_id WHERE f.market_code = ANY(:m) "
                "ORDER BY r.rule_code, r.version"
            ),
            {"m": markets},
        )
        .mappings()
        .all()
    )
    ids = [r["id"] for r in rows]
    counts: dict[uuid.UUID, int] = {}
    recent: dict[uuid.UUID, list[RuleCaseRef]] = {}
    if ids:
        for c in db.execute(
            text(
                "SELECT a.matched_rule_version_id AS rid, c.id, c.case_ref, a.assigned_at, "
                "row_number() OVER (PARTITION BY a.matched_rule_version_id ORDER BY a.assigned_at DESC, c.case_ref) "
                "AS n, count(*) OVER (PARTITION BY a.matched_rule_version_id) AS total "
                "FROM script_assignment a JOIN callback_case c ON c.id = a.callback_case_id "
                "WHERE a.matched_rule_version_id = ANY(:r) AND c.market_code = ANY(:m)"
            ),
            {"r": ids, "m": markets},
        ).mappings():
            counts[c["rid"]] = c["total"]
            if c["n"] <= RECENT_CASES:
                recent.setdefault(c["rid"], []).append(
                    RuleCaseRef(case_id=c["id"], case_ref=c["case_ref"], assigned_at=c["assigned_at"])
                )
    items = [
        AssignmentRuleOut(
            **{k: r[k] for k in AssignmentRuleOut.model_fields if k in r},
            market=r["market_code"],
            target=_pin(db, r["target_script_version_id"]),
            target_family_id=r["family_id"],
            cases_assigned=counts.get(r["id"], 0),
            recent_cases=recent.get(r["id"], []),
        )
        for r in rows
    ]
    return AssignmentRuleList(items=items, total=len(items))


# ---- API-065 ---------------------------------------------------------------------------------------------------
@router.get(
    "/regulatory-references",
    response_model=RegulatoryReferenceList,
    operation_id="regulatory_references",
    responses=_ERR,
)
def regulatory_references(
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> RegulatoryReferenceList:
    rows = (
        db.execute(
            text(
                "SELECT rr.*, coalesce(array_agg(DISTINCT ct.control_code) FILTER (WHERE ct.id IS NOT NULL), '{}') "
                "AS controls FROM regulatory_reference rr LEFT JOIN control_mapping cm "
                "ON cm.regulatory_reference_id = rr.id LEFT JOIN control ct ON ct.id = cm.control_id "
                "WHERE rr.market_code = ANY(:m) GROUP BY rr.id ORDER BY rr.market_code, rr.title"
            ),
            {"m": sorted(auth.markets)},
        )
        .mappings()
        .all()
    )
    return RegulatoryReferenceList(
        items=[
            RegulatoryReferenceOut(
                **{k: r[k] for k in RegulatoryReferenceOut.model_fields if k in r and k != "market"},
                market=r["market_code"],
            )
            for r in rows
        ]
    )


# ---- API-066 ---------------------------------------------------------------------------------------------------
@router.get("/controls", response_model=ControlList, operation_id="controls_list", responses=_ERR)
def controls_list(
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ControlList:
    """Controls linked to questions of in-scope script versions; regulatory links only from in-scope markets."""
    markets = sorted(auth.markets)
    in_versions: dict[uuid.UUID, list[str]] = {}
    for iv in db.execute(
        text(
            "SELECT DISTINCT qr.question_bank_item_id, f.code, v.version_label FROM script_version v "
            "JOIN script_family f ON f.id = v.script_family_id JOIN script_section ss ON ss.script_version_id = v.id "
            "JOIN module_question mq ON mq.script_module_id = ss.script_module_id "
            "JOIN question_revision qr ON qr.id = mq.question_revision_id WHERE f.market_code = ANY(:m) "
            "ORDER BY f.code, v.version_label"
        ),
        {"m": markets},
    ):
        in_versions.setdefault(iv.question_bank_item_id, []).append(f"{iv.code} v{iv.version_label}")
    controls: dict[uuid.UUID, ControlOut] = {}
    for r in db.execute(
        text(
            "SELECT ct.id, ct.control_code, ct.name, ct.owner_role, ct.content_approval_status, "
            "qbi.id AS item_id, qbi.question_code, qbi.intent, cm.rationale, cm.status AS mapping_status, "
            "rr.id AS rr_id, rr.title AS rr_title FROM control ct JOIN control_mapping cm ON cm.control_id = ct.id "
            "JOIN question_bank_item qbi ON qbi.id = cm.question_bank_item_id "
            "LEFT JOIN regulatory_reference rr ON rr.id = cm.regulatory_reference_id AND rr.market_code = ANY(:m) "
            "ORDER BY ct.control_code, qbi.question_code"
        ),
        {"m": markets},
    ).mappings():
        if r["item_id"] not in in_versions:
            continue  # the question is not used by any script version in scope
        c = controls.setdefault(
            r["id"],
            ControlOut(
                id=r["id"],
                control_code=r["control_code"],
                name=r["name"],
                owner_role=r["owner_role"],
                content_approval_status=r["content_approval_status"],
                questions=[],
            ),
        )
        c.questions.append(
            ControlQuestionLink(
                question_code=r["question_code"],
                intent=r["intent"],
                rationale=r["rationale"],
                mapping_status=r["mapping_status"],
                regulatory_reference_id=r["rr_id"],
                regulatory_reference_title=r["rr_title"],
                script_versions=in_versions[r["item_id"]],
            )
        )
    return ControlList(items=list(controls.values()))
