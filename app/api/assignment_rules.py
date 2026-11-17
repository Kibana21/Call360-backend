"""S2-B Assignment Rules API: authoring, validation, maker-checker lifecycle, history, diff and simulation (SCR-011).

Writes are CSRF-protected, rate-limited (shared with Script Studio), market-scoped and audited. Drafts change with an
optimistic-concurrency token. ``script.edit`` (USER) authors; ``script.approve`` / ``script.publish`` (SC_CHECKER)
review and publish, never their own work; ``script.read`` reads, explains and simulates. ADMIN holds none of the
authoring or approval permissions (D-54).

Simulation runs in a READ ONLY database transaction (so it cannot change assignments, case states, holds or KPI
inputs); only its audit event is written afterwards, in a separate transaction. Publishing never reassigns a case.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    ErrorResponse,
    RuleAbandonIn,
    RuleAnalysis,
    RuleChangeEventOut,
    RuleCondition,
    RuleConflictOut,
    RuleCreate,
    RuleDiff,
    RuleDraftChanged,
    RuleDraftCreated,
    RuleDraftOut,
    RuleDraftSummary,
    RuleDraftUpdate,
    RuleExplainIn,
    RuleHistory,
    RuleLifecycleOut,
    RuleOptions,
    RulePublishIn,
    RuleRegistry,
    RuleReviewIn,
    RuleSimulateIn,
    RuleSimulation,
    RuleSubmitIn,
    RuleSummary,
    RuleTargetOption,
    RuleTargetRef,
    RuleVersionCreate,
    RuleVersionOut,
)
from app.api.script_authoring import _guard
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain import rule_authoring as ra
from app.domain import rule_engine as re_
from app.domain import rule_inputs as ri
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["assignment-rules"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
PRECEDENCE = [
    "Only published rules that are effective at the evaluation time are considered (drafts only in simulation).",
    "Priority first: a lower number wins (1 is the highest priority).",
    "Equal priority: the rule with the higher specificity wins (specificity = number of constrained fields, "
    "calculated automatically).",
    "Equal priority and specificity with different scripts: AMBIGUOUS — held for authorised review, never chosen.",
    "Equal priority and specificity with the same script: kept in the trace and held for review (T-40).",
    "A default fallback rule applies only when no other rule matches; it never resolves ambiguity.",
    "Missing case inputs or a winning rule whose script is not effective fail closed (no lower rule is used).",
]
SIM_NOTE = (
    "Simulation only: evaluated in a read-only transaction. No case assignment, case state, hold or KPI was changed. "
    "Automatic assignment is Stage S2-C."
)


def _err(exc: ra.RuleAuthoringError) -> AppError:
    details = exc.details.get("issues") or ([exc.details] if exc.details else None)
    return AppError(exc.status, exc.code, exc.message, details=details)


def _who(auth: AuthContext) -> tuple[str, str]:
    return str(auth.principal_id), auth.display_name


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    entity_id: Any,
    after: dict[str, Any],
    *,
    outcome: str = "SUCCEEDED",
    reason: str | None = None,
    entity_type: str = "assignment_rule_draft",
) -> None:
    write_audit(
        db,
        action=action,
        outcome=outcome,
        actor=auth.actor,
        meta=request_meta(request),
        entity_type=entity_type,
        entity_id=str(entity_id),
        reason=reason,
        after=after,
    )


# ---- reading ----------------------------------------------------------------------------------------------------
def _people(db: Session, refs: set[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    ids = []
    for r in refs:
        try:
            ids.append(uuid.UUID(r))
        except ValueError:
            continue
    if ids:
        for row in db.execute(text("SELECT id, display_name FROM principal WHERE id = ANY(:i)"), {"i": ids}):
            out[str(row.id)] = row.display_name
    return out


def _targets(db: Session, ids: list[Any]) -> dict[str, dict[str, Any]]:
    if not ids:
        return {}
    return {
        str(r["id"]): dict(r)
        for r in db.execute(
            text(
                "SELECT v.id, v.status, v.version_label, v.effective_from, v.effective_to, f.id AS family_id, "
                "f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
                "WHERE v.id = ANY(:i)"
            ),
            {"i": ids},
        ).mappings()
    }


def _target_ref(t: dict[str, Any] | None, tid: Any) -> RuleTargetRef | None:
    if tid is None:
        return None
    return RuleTargetRef(
        id=tid,
        label=ri.target_label(t),
        script_family_id=t["family_id"] if t else None,
        status=t["status"] if t else None,
    )


def _version_outs(db: Session, markets: list[str], rule_code: str | None = None) -> list[RuleVersionOut]:
    rows = (
        db.execute(
            text(
                "SELECT r.*, p.name, p.is_fallback, p.published_by FROM script_assignment_rule_version r "
                "JOIN script_version v ON v.id = r.target_script_version_id JOIN script_family f "
                "ON f.id = v.script_family_id LEFT JOIN assignment_rule_publication p ON p.rule_version_id = r.id "
                "WHERE f.market_code = ANY(:m) AND (CAST(:c AS text) IS NULL OR r.rule_code = :c) "
                "ORDER BY r.rule_code, r.version"
            ),
            {"m": markets, "c": rule_code},
        )
        .mappings()
        .all()
    )
    targets = _targets(db, [r["target_script_version_id"] for r in rows])
    counts = {
        r.rid: r.n
        for r in db.execute(
            text(
                "SELECT matched_rule_version_id AS rid, count(*) AS n FROM script_assignment "
                "WHERE matched_rule_version_id = ANY(:i) GROUP BY 1"
            ),
            {"i": [r["id"] for r in rows]},
        )
    }
    opts = ri.options(db, markets)
    lab = ri.labels(opts)
    names = _people(db, {x for r in rows for x in (r["author_ref"], r["checker_ref"], r["published_by"]) if x})
    out = []
    for r in rows:
        conds = re_.parse_predicate(r["predicate"])
        t = targets.get(str(r["target_script_version_id"]))
        out.append(
            RuleVersionOut(
                id=r["id"],
                rule_code=r["rule_code"],
                version=r["version"],
                name=r["name"] or r["rule_code"],
                status=r["status"],
                priority=r["priority"],
                specificity=r["specificity"],
                is_fallback=bool(r["is_fallback"]),
                conditions=[RuleCondition(field=c.field, values=list(c.values)) for c in conds],
                explanation=re_.explain(
                    conds, ri.target_label(t), r["priority"], is_fallback=bool(r["is_fallback"]), labels=lab
                ),
                target=_target_ref(t, r["target_script_version_id"]) or RuleTargetRef(id=None, label="—"),
                effective_from=r["effective_from"],
                effective_to=r["effective_to"],
                checksum=r["checksum"],
                author_ref=r["author_ref"],
                checker_ref=r["checker_ref"],
                published_by=r["published_by"],
                cases_assigned=counts.get(r["id"], 0),
                authored_in_rule_studio=r["source_system"] == ra.SOURCE_SYSTEM,
                people={k: v for k, v in names.items() if k in (r["author_ref"], r["checker_ref"], r["published_by"])},
            )
        )
    return out


def _draft_summary(d: dict[str, Any]) -> RuleDraftSummary:
    return RuleDraftSummary(
        id=d["id"],
        planned_version=d["planned_version"],
        status=d["status"],
        name=d["name"],
        author_ref=d["author_ref"],
        updated_at=d["updated_at"],
        created_at=d["created_at"],
    )


@router.get("/assignment-rules/options", response_model=RuleOptions, operation_id="rule_options", responses=_ERR)
def rule_options(auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)) -> RuleOptions:
    """Approved condition fields and governed values, unsupported fields with reasons, target script versions and the
    precedence semantics (D-58…D-61)."""
    markets = _markets(auth)
    opts = ri.options(db, markets)
    now = datetime.now(UTC)
    rows = (
        db.execute(
            text(
                "SELECT v.id, v.status, v.version_label, v.effective_from, v.effective_to, v.content_approval_status, "
                "f.code AS family, f.market_code FROM script_version v JOIN script_family f "
                "ON f.id = v.script_family_id WHERE f.market_code = ANY(:m) AND v.status IN ('PUBLISHED', "
                "'SUPERSEDED', 'WITHDRAWN') ORDER BY f.code, v.version_label"
            ),
            {"m": markets},
        )
        .mappings()
        .all()
    )
    return RuleOptions(
        fields=opts["fields"],
        unsupported=opts["unsupported"],
        targets=[
            RuleTargetOption(
                id=r["id"],
                label=ri.target_label(r),
                family=r["family"],
                version_label=r["version_label"],
                status=r["status"],
                effective_from=r["effective_from"],
                effective_to=r["effective_to"],
                content_approval_status=r["content_approval_status"],
                selectable=ri.target_effective(r, now),
            )
            for r in (dict(x) for x in rows)
        ],
        precedence=PRECEDENCE,
        priority_range=[1, 999],
    )


@router.get("/assignment-rules", response_model=RuleRegistry, operation_id="rule_registry", responses=_ERR)
def rule_registry(auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)) -> RuleRegistry:
    """Every rule in scope: its live version, version history, drafts, and conflicts among live rules."""
    markets = _markets(auth)
    versions = _version_outs(db, markets)
    drafts = [
        dict(r)
        for r in db.execute(
            text("SELECT * FROM assignment_rule_draft WHERE market_code = ANY(:m) ORDER BY rule_code, planned_version"),
            {"m": markets},
        ).mappings()
    ]
    codes = sorted({v.rule_code for v in versions} | {d["rule_code"] for d in drafts})
    items = []
    for code in codes:
        vs = [v for v in versions if v.rule_code == code]
        ds = [d for d in drafts if d["rule_code"] == code]
        live = next((v for v in reversed(vs) if v.status == "PUBLISHED"), None)
        open_d = next((d for d in ds if d["status"] in ra.OPEN), None)
        name = (live.name if live else None) or (open_d["name"] if open_d else None) or (vs[-1].name if vs else code)
        market = ds[0]["market_code"] if ds else "SG"
        items.append(
            RuleSummary(
                rule_code=code,
                name=name,
                market=market,
                live=live,
                versions=vs,
                open_draft=_draft_summary(open_d) if open_d else None,
                drafts=[_draft_summary(d) for d in ds],
            )
        )
    now = datetime.now(UTC)
    live_c = [
        r for r in ri.published_candidates(db, markets, now) if r.status == "PUBLISHED" and re_.effective_at(r, now)
    ]
    conflicts = [RuleConflictOut(**c.__dict__, against="PUBLISHED") for c in re_.conflicts(live_c)]
    return RuleRegistry(items=items, total=len(items), conflicts=conflicts)


def _draft_out(db: Session, d: dict[str, Any], markets: list[str]) -> RuleDraftOut:
    t = _targets(db, [d["target_script_version_id"]] if d["target_script_version_id"] else [])
    analysis = ra.analyse(db, d, markets)
    refs: dict[str, str | None] = {}
    for key, col in (("base", "base_rule_version_id"), ("copied", "copied_from_rule_version_id")):
        if d[col]:
            r = db.execute(
                text("SELECT rule_code, version FROM script_assignment_rule_version WHERE id = :i"), {"i": d[col]}
            ).first()
            refs[key] = f"{r.rule_code} v{r.version}" if r else None
    live = ra.live_version(db, d["rule_code"])
    mk = sorted(ra.makers(db, d))
    return RuleDraftOut(
        id=d["id"],
        rule_code=d["rule_code"],
        name=d["name"],
        description=d["description"],
        market=d["market_code"],
        planned_version=d["planned_version"],
        status=d["status"],
        conditions=[RuleCondition(**c) for c in d["conditions"]],
        priority=d["priority"],
        is_fallback=d["is_fallback"],
        target=_target_ref(t.get(str(d["target_script_version_id"])), d["target_script_version_id"]),
        effective_from=d["effective_from"],
        effective_to=d["effective_to"],
        validation_status=d["validation_status"],
        manifest_sha256=d["manifest_sha256"],
        author_ref=d["author_ref"],
        reviewer_ref=d["reviewer_ref"],
        publisher_ref=d["publisher_ref"],
        published_rule_version_id=d["published_rule_version_id"],
        base_rule_version_id=d["base_rule_version_id"],
        base_ref=refs.get("base"),
        copied_from_ref=refs.get("copied"),
        live_rule_version_id=live["id"] if live and d["status"] != "PUBLISHED" else None,
        live_ref=f"{d['rule_code']} v{live['version']}" if live and d["status"] != "PUBLISHED" else None,
        row_version=d["row_version"],
        makers=mk,
        people=_people(db, {*mk, d["reviewer_ref"] or "", d["publisher_ref"] or ""}),
        analysis=RuleAnalysis(**{k: analysis[k] for k in RuleAnalysis.model_fields}),
        created_at=d["created_at"],
        updated_at=d["updated_at"],
    )


@router.get(
    "/assignment-rule-drafts/{draft_id}", response_model=RuleDraftOut, operation_id="rule_draft", responses=_ERR
)
def rule_draft(
    draft_id: uuid.UUID, auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> RuleDraftOut:
    try:
        d = ra.draft_row(db, draft_id, _markets(auth))
    except ra.RuleAuthoringError as exc:
        raise _err(exc) from exc
    return _draft_out(db, d, _markets(auth))


@router.get(
    "/assignment-rules/{rule_code}/history", response_model=RuleHistory, operation_id="rule_history", responses=_ERR
)
def rule_history(
    rule_code: str, auth: AuthContext = Depends(require("script.read")), db: Session = Depends(get_db)
) -> RuleHistory:
    markets = _markets(auth)
    versions = _version_outs(db, markets, rule_code)
    drafts = [
        dict(r)
        for r in db.execute(
            text(
                "SELECT * FROM assignment_rule_draft WHERE rule_code = :c AND market_code = ANY(:m) "
                "ORDER BY planned_version"
            ),
            {"c": rule_code, "m": markets},
        ).mappings()
    ]
    if not versions and not drafts:
        raise AppError(404, "NOT_FOUND", "Not found or not available to you")
    events = (
        db.execute(
            text(
                "SELECT e.*, d.planned_version FROM assignment_rule_change_event e JOIN assignment_rule_draft d "
                "ON d.id = e.draft_id WHERE e.rule_code = :c AND d.market_code = ANY(:m) ORDER BY e.occurred_at, e.seq"
            ),
            {"c": rule_code, "m": markets},
        )
        .mappings()
        .all()
    )
    return RuleHistory(
        rule_code=rule_code,
        events=[RuleChangeEventOut(**{k: e[k] for k in RuleChangeEventOut.model_fields}) for e in events],
        versions=versions,
        drafts=[_draft_summary(d) for d in drafts],
    )


@router.get("/assignment-rules/{rule_code}/diff", response_model=RuleDiff, operation_id="rule_diff", responses=_ERR)
def rule_diff(
    rule_code: str,
    target: str = Query(max_length=80, description="'version:<id>' or 'draft:<id>'"),
    base: str | None = Query(default=None, max_length=80, description="'version:<id>' or 'draft:<id>'"),
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> RuleDiff:
    """Compare two versions or drafts of one rule: condition changes (more or less permissive) and settings."""
    markets = _markets(auth)

    def snap(ref: str) -> dict[str, Any]:
        kind, _, raw = ref.partition(":")
        try:
            rid = uuid.UUID(raw)
        except ValueError as exc:
            raise AppError(422, "INVALID_REFERENCE", "Use 'version:<id>' or 'draft:<id>'") from exc
        try:
            if kind == "version":
                row = ra._version_row(db, rid, markets)
                out = ra.snapshot_of_version(row)
            elif kind == "draft":
                row = ra.draft_row(db, rid, markets)
                out = ra.snapshot_of_draft(row)
            else:
                raise AppError(422, "INVALID_REFERENCE", "Use 'version:<id>' or 'draft:<id>'")
        except ra.RuleAuthoringError as exc:
            raise _err(exc) from exc
        if row["rule_code"] != rule_code:
            raise AppError(422, "DIFFERENT_RULE", "Compare versions of the same rule")
        return out

    return RuleDiff(**ra.diff(snap(base) if base else None, snap(target)))


@router.post("/assignment-rules/explain", response_model=RuleAnalysis, operation_id="rule_explain", responses=_ERR)
@csrf_protected
def rule_explain(
    body: RuleExplainIn,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> RuleAnalysis:
    """Immediate feedback for unsaved editor content: validation issues, conflicts, specificity and explanation.
    Nothing is stored."""
    if body.market not in auth.markets:
        raise AppError(403, "MARKET_NOT_IN_SCOPE", "Not available in your markets")
    draft = {
        **body.model_dump(),
        "conditions": [c.model_dump() for c in body.conditions],
        "market_code": body.market,
        "rule_code": body.rule_code or "UNSAVED",
        "planned_version": 0,
        "status": "DRAFT",
        "id": None,
    }
    a = ra.analyse(db, draft, _markets(auth))
    db.rollback()
    return RuleAnalysis(**{k: a[k] for k in RuleAnalysis.model_fields})


@router.post("/assignment-rules/simulate", response_model=RuleSimulation, operation_id="rule_simulate", responses=_ERR)
@csrf_protected
def rule_simulate(
    body: RuleSimulateIn,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> RuleSimulation:
    """Evaluate the live ruleset and the ruleset with the given drafts published against the synthetic cases in your
    markets. Read-only: no assignment, case state, hold or KPI changes (S2-C assigns)."""
    markets = _markets(auth)
    now = datetime.now(UTC)
    at = body.as_of or now
    db.rollback()  # start a fresh transaction for the read-only evaluation
    db.execute(text("SET TRANSACTION READ ONLY"))
    try:
        result = ra.simulate(db, markets, body.draft_ids, at=at, scope=body.scope, now=now)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    finally:
        db.rollback()
    _audit(
        db,
        request,
        auth,
        "RULE.SIMULATED",
        str(body.draft_ids[0]) if len(body.draft_ids) == 1 else "ruleset",
        {
            "drafts": [str(d) for d in body.draft_ids],
            "as_of": at.isoformat(),
            "scope": body.scope,
            "cases": result["summary"]["cases"],
            "proposed": result["summary"]["proposed"],
            "changed": result["summary"]["changed"],
        },
        entity_type="assignment_ruleset",
    )
    db.commit()
    return RuleSimulation(**result, note=SIM_NOTE)


# ---- authoring --------------------------------------------------------------------------------------------------
@router.post(
    "/assignment-rules", response_model=RuleDraftCreated, status_code=201, operation_id="rule_create", responses=_ERR
)
@csrf_protected
def rule_create(
    body: RuleCreate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleDraftCreated:
    """Create a rule (draft version 1), optionally copying an existing rule version's conditions and settings."""
    _guard(request, auth)
    try:
        did = ra.create_rule(
            db,
            _markets(auth),
            *_who(auth),
            code=body.code,
            name=body.name,
            description=body.description,
            market=body.market,
            copy_from_rule_version_id=body.copy_from_rule_version_id,
        )
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    d = ra.draft_row(db, did, _markets(auth))
    _audit(
        db,
        request,
        auth,
        "RULE.DRAFT_CREATED",
        did,
        {"rule_code": d["rule_code"], "planned_version": 1, "copied_from": str(body.copy_from_rule_version_id or "")},
    )
    db.commit()
    return RuleDraftCreated(draft_id=did, rule_code=d["rule_code"], planned_version=d["planned_version"])


@router.post(
    "/assignment-rules/{rule_code}/drafts",
    response_model=RuleDraftCreated,
    status_code=201,
    operation_id="rule_version_create",
    responses=_ERR,
)
@csrf_protected
def rule_version_create(
    rule_code: str,
    body: RuleVersionCreate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleDraftCreated:
    """New draft version of a rule (one open draft per rule), from its live version or a chosen one."""
    _guard(request, auth)
    try:
        did = ra.create_version(db, _markets(auth), *_who(auth), rule_code, body.base_rule_version_id)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    d = ra.draft_row(db, did, _markets(auth))
    _audit(
        db, request, auth, "RULE.DRAFT_CREATED", did, {"rule_code": rule_code, "planned_version": d["planned_version"]}
    )
    db.commit()
    return RuleDraftCreated(draft_id=did, rule_code=rule_code, planned_version=d["planned_version"])


@router.put(
    "/assignment-rule-drafts/{draft_id}",
    response_model=RuleDraftChanged,
    operation_id="rule_draft_update",
    responses=_ERR,
)
@csrf_protected
def rule_draft_update(
    draft_id: uuid.UUID,
    body: RuleDraftUpdate,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleDraftChanged:
    _guard(request, auth)
    content = body.content.model_dump()
    content["conditions"] = [c.model_dump() for c in body.content.conditions]
    try:
        rv = ra.update_draft(db, draft_id, _markets(auth), body.expected_row_version, *_who(auth), content=content)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "RULE.CHANGED", draft_id, {"row_version": rv})
    db.commit()
    return RuleDraftChanged(draft_id=draft_id, row_version=rv)


@router.post(
    "/assignment-rule-drafts/{draft_id}/validate",
    response_model=RuleAnalysis,
    operation_id="rule_draft_validate",
    responses=_ERR,
)
@csrf_protected
def rule_draft_validate(
    draft_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleAnalysis:
    _guard(request, auth)
    try:
        d = ra.draft_row(db, draft_id, _markets(auth), lock=True)
        if d["status"] != "DRAFT":
            raise ra.RuleAuthoringError(409, "RULE_NOT_EDITABLE", "Only drafts are validated")
        a = ra.analyse(db, d, _markets(auth))
        ra.record_validation(db, d, a, *_who(auth))
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return RuleAnalysis(**{k: a[k] for k in RuleAnalysis.model_fields})


@router.post(
    "/assignment-rule-drafts/{draft_id}/submit",
    response_model=RuleLifecycleOut,
    operation_id="rule_draft_submit",
    responses=_ERR,
)
@csrf_protected
def rule_draft_submit(
    draft_id: uuid.UUID,
    body: RuleSubmitIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleLifecycleOut:
    """Validate (conflicts and target eligibility), freeze the manifest (SHA-256) and lock the draft for review."""
    _guard(request, auth)
    try:
        out = ra.submit(db, draft_id, _markets(auth), body.expected_row_version, *_who(auth), body.change_summary)
    except ra.RuleAuthoringError as exc:
        if exc.code == "VALIDATION_FAILED":
            db.commit()  # keep the recorded INVALID validation result
        else:
            db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "RULE.SUBMITTED",
        draft_id,
        {"manifest_sha256": out["manifest_sha256"]},
        reason=body.change_summary,
    )
    db.commit()
    return RuleLifecycleOut(
        draft_id=draft_id, status="SUBMITTED_FOR_REVIEW", manifest_sha256=out["manifest_sha256"], issues=out["issues"]
    )


@router.post(
    "/assignment-rule-drafts/{draft_id}/abandon",
    response_model=RuleLifecycleOut,
    operation_id="rule_draft_abandon",
    responses=_ERR,
)
@csrf_protected
def rule_draft_abandon(
    draft_id: uuid.UUID,
    body: RuleAbandonIn,
    request: Request,
    auth: AuthContext = Depends(require("script.edit")),
    db: Session = Depends(get_db),
) -> RuleLifecycleOut:
    """Abandon a draft (its author or an editor, with a reason). Nothing is deleted."""
    _guard(request, auth)
    try:
        ra.abandon(db, draft_id, _markets(auth), body.expected_row_version, *_who(auth), body.reason)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "RULE.ABANDONED", draft_id, {"status": "ABANDONED"}, reason=body.reason)
    db.commit()
    return RuleLifecycleOut(draft_id=draft_id, status="ABANDONED")


@router.post(
    "/assignment-rule-drafts/{draft_id}/review",
    response_model=RuleLifecycleOut,
    operation_id="rule_draft_review",
    responses=_ERR,
)
@csrf_protected
def rule_draft_review(
    draft_id: uuid.UUID,
    body: RuleReviewIn,
    request: Request,
    auth: AuthContext = Depends(require("script.approve")),
    db: Session = Depends(get_db),
) -> RuleLifecycleOut:
    """Checker decision: approve, or return the rule to its author. Never your own rule."""
    _guard(request, auth)
    try:
        status = ra.review(db, draft_id, _markets(auth), *_who(auth), body.decision, body.reason)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        if exc.code == "SELF_REVIEW_DENIED":
            _audit(db, request, auth, "RULE.REVIEW_DENIED", draft_id, {"reason": exc.code}, outcome="DENIED")
            db.commit()
        raise _err(exc) from exc
    action = "RULE.APPROVED" if status == "APPROVED" else "RULE.CHANGES_REQUESTED"
    _audit(db, request, auth, action, draft_id, {"status": status}, reason=body.reason)
    db.commit()
    return RuleLifecycleOut(draft_id=draft_id, status=status)


@router.post(
    "/assignment-rule-drafts/{draft_id}/publish",
    response_model=RuleLifecycleOut,
    operation_id="rule_draft_publish",
    responses=_ERR,
)
@csrf_protected
def rule_draft_publish(
    draft_id: uuid.UUID,
    body: RulePublishIn,
    request: Request,
    auth: AuthContext = Depends(require("script.publish")),
    db: Session = Depends(get_db),
) -> RuleLifecycleOut:
    """Publish an approved rule after re-validating it against the current ruleset and target. Superseding the
    rule's live version must be confirmed explicitly. No case is reassigned (S2-C)."""
    _guard(request, auth)
    try:
        out = ra.publish(db, draft_id, _markets(auth), *_who(auth), body.supersede_rule_version_id, body.reason)
    except ra.RuleAuthoringError as exc:
        db.rollback()
        if exc.code == "SELF_PUBLISH_DENIED":
            _audit(db, request, auth, "RULE.PUBLISH_DENIED", draft_id, {"reason": exc.code}, outcome="DENIED")
            db.commit()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "RULE.PUBLISHED",
        draft_id,
        {
            "rule_version_id": str(out["rule_version_id"]),
            "version": out["version"],
            "superseded": out["superseded"],
            "effective_from": out["effective_from"].isoformat(),
        },
        reason=body.reason,
    )
    db.commit()
    return RuleLifecycleOut(
        draft_id=draft_id,
        status="PUBLISHED",
        rule_version_id=out["rule_version_id"],
        version=out["version"],
        superseded=out["superseded"],
    )
