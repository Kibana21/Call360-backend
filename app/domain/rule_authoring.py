"""S2-B editable script-assignment rules: drafts, validation, maker-checker lifecycle, history, diff, simulation.

Same governance as S2-A Script Studio (D-54…D-57): ``script.edit`` (USER) creates and edits drafts; a different
``script.approve`` / ``script.publish`` holder (SC_CHECKER) approves and publishes; nobody who authored or edited a
draft may approve or publish it. Submitted content is locked (database guard), published rule versions are immutable
(only an explicit supersede or withdrawal retires one), every change bumps ``row_version`` (optimistic concurrency) and
is recorded in ``assignment_rule_change_event`` and the audit trail.

Publishing never reassigns a case: existing ``script_assignment`` rows (and their holds and states) are untouched;
automatic assignment arrives with S2-C. Simulation (``simulate``) runs in a read-only transaction.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import rule_engine as re_
from app.domain import rule_inputs as ri
from app.domain.digest import sha256_of

MANIFEST_SCHEMA = "call360.rule-manifest/1"
SOURCE_SYSTEM = "CALL360_RULE_STUDIO"
OPEN = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED")
RULE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,39}$")
DEFAULT_PRIORITY = 100


class RuleAuthoringError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or {}


def _now() -> datetime:
    return datetime.now(UTC)


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def _prov(actor_ref: str, what: str) -> dict[str, Any]:
    now = _now()
    return {
        "source_type": "MANUAL",
        "source_system": SOURCE_SYSTEM,
        "source_reference": f"rule-studio:{what}:{actor_ref}"[:160],
        "source_observed_at": now,
        "recorded_at": now,
        "is_synthetic": True,
        "created_by": actor_ref,
    }


# ---- rows, events, makers ---------------------------------------------------------------------------------------
def draft_row(db: Session, draft_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    d = _one(
        db,
        "SELECT * FROM assignment_rule_draft WHERE id = :d AND market_code = ANY(:m)" + (" FOR UPDATE" if lock else ""),
        d=draft_id,
        m=list(markets),
    )
    if d is None:
        raise RuleAuthoringError(404, "NOT_FOUND", "Not found or not available to you")
    return d


def _editable(db: Session, draft_id: uuid.UUID, markets: Sequence[str], rv: int) -> dict[str, Any]:
    d = draft_row(db, draft_id, markets, lock=True)
    if d["status"] != "DRAFT":
        raise RuleAuthoringError(
            409, "RULE_NOT_EDITABLE", f"This rule draft is {d['status'].replace('_', ' ').lower()}"
        )
    if d["row_version"] != rv:
        raise RuleAuthoringError(
            409,
            "STALE_DRAFT",
            "This rule draft was changed by someone else; reload it before editing",
            {"current_row_version": d["row_version"]},
        )
    return d


def add_event(
    db: Session,
    draft: Mapping[str, Any],
    event_type: str,
    actor_ref: str,
    actor_name: str,
    *,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    seq = db.execute(
        text("SELECT coalesce(max(seq), 0) + 1 FROM assignment_rule_change_event WHERE draft_id = :d"),
        {"d": draft["id"]},
    ).scalar_one()
    db.execute(
        text(
            "INSERT INTO assignment_rule_change_event (id, draft_id, rule_code, seq, event_type, actor_ref, "
            "actor_name, reason, details) VALUES (:i, :d, :c, :s, :t, :a, :n, :r, CAST(:x AS jsonb))"
        ),
        {
            "i": uuid.uuid4(),
            "d": draft["id"],
            "c": draft["rule_code"],
            "s": seq,
            "t": event_type,
            "a": actor_ref,
            "n": actor_name[:120],
            "r": reason,
            "x": json.dumps(details or {}, default=str),
        },
    )


def makers(db: Session, draft: Mapping[str, Any]) -> set[str]:
    rows = db.execute(
        text(
            "SELECT DISTINCT actor_ref FROM assignment_rule_change_event WHERE draft_id = :d "
            "AND event_type IN ('DRAFT_CREATED', 'CONTENT_CHANGED')"
        ),
        {"d": draft["id"]},
    ).scalars()
    return {draft["author_ref"], *rows}


def _next_version(db: Session, rule_code: str) -> int:
    return int(
        db.execute(
            text(
                "SELECT greatest(coalesce((SELECT max(version) FROM script_assignment_rule_version "
                "WHERE rule_code = :c), 0), coalesce((SELECT max(planned_version) FROM assignment_rule_draft "
                "WHERE rule_code = :c AND status <> 'ABANDONED'), 0)) + 1"
            ),
            {"c": rule_code},
        ).scalar_one()
    )


def _version_row(db: Session, rule_version_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT r.*, f.market_code, p.name, p.description, p.is_fallback FROM script_assignment_rule_version r "
        "JOIN script_version v ON v.id = r.target_script_version_id JOIN script_family f "
        "ON f.id = v.script_family_id LEFT JOIN assignment_rule_publication p ON p.rule_version_id = r.id "
        "WHERE r.id = :r AND f.market_code = ANY(:m)",
        r=rule_version_id,
        m=list(markets),
    )
    if r is None:
        raise RuleAuthoringError(404, "NOT_FOUND", "Rule version not found or not available to you")
    return r


def _conditions_json(conds: Sequence[re_.Condition]) -> list[dict[str, Any]]:
    return [{"field": c.field, "values": list(c.values)} for c in conds]


def _insert_draft(db: Session, actor_ref: str, actor_name: str, **v: Any) -> uuid.UUID:
    did = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO assignment_rule_draft (id, rule_code, name, description, market_code, planned_version, "
            "base_rule_version_id, copied_from_rule_version_id, status, conditions, priority, is_fallback, "
            "target_script_version_id, effective_from, effective_to, author_ref, created_by, source_type, "
            "source_system, source_reference, source_observed_at, recorded_at, is_synthetic) VALUES (:id, :code, "
            ":name, :descr, :market, :ver, :base, :copied, 'DRAFT', CAST(:conds AS jsonb), :prio, :fb, :target, :ef, "
            ":et, :author, :created_by, :source_type, :source_system, :source_reference, :source_observed_at, "
            ":recorded_at, :is_synthetic)"
        ),
        {
            "id": did,
            "code": v["rule_code"],
            "name": v["name"],
            "descr": v.get("description", ""),
            "market": v["market"],
            "ver": v["version"],
            "base": v.get("base"),
            "copied": v.get("copied"),
            "conds": json.dumps(v["conditions"]),
            "prio": v["priority"],
            "fb": v["is_fallback"],
            "target": v.get("target"),
            "ef": v.get("effective_from"),
            "et": v.get("effective_to"),
            "author": actor_ref,
            **_prov(actor_ref, f"rule:{v['rule_code']}:{v['version']}"),
        },
    )
    d = _one(db, "SELECT * FROM assignment_rule_draft WHERE id = :d", d=did)
    assert d is not None
    add_event(
        db,
        d,
        "DRAFT_CREATED",
        actor_ref,
        actor_name,
        details={
            "planned_version": v["version"],
            "based_on": v.get("base_ref"),
            "copied_from": v.get("copied_ref"),
        },
    )
    return did


# ---- creation ---------------------------------------------------------------------------------------------------
def _check_name(name: str) -> str:
    name = (name or "").strip()
    if not 3 <= len(name) <= 120:
        raise RuleAuthoringError(422, "INVALID_NAME", "Rule name must be 3–120 characters")
    return name


def _free_code(db: Session, code: str) -> str:
    code = (code or "").strip().upper()
    if not RULE_CODE_RE.match(code):
        raise RuleAuthoringError(422, "INVALID_CODE", "Rule code: 3–40 capital letters, digits, '_' or '-'")
    if _one(db, "SELECT 1 FROM script_assignment_rule_version WHERE rule_code = :c", c=code) or _one(
        db, "SELECT 1 FROM assignment_rule_draft WHERE rule_code = :c", c=code
    ):
        raise RuleAuthoringError(409, "CODE_IN_USE", f"A rule {code} already exists; choose another code")
    return code


def create_rule(
    db: Session,
    markets: Sequence[str],
    actor_ref: str,
    actor_name: str,
    *,
    code: str,
    name: str,
    description: str,
    market: str,
    copy_from_rule_version_id: uuid.UUID | None,
) -> uuid.UUID:
    """A new rule (version 1) — empty apart from its market, or a copy of an existing rule version's settings."""
    if market not in markets:
        raise RuleAuthoringError(403, "MARKET_NOT_IN_SCOPE", "You can only create rules in your markets")
    code = _free_code(db, code)
    values: dict[str, Any] = {
        "rule_code": code,
        "name": _check_name(name),
        "description": (description or "").strip()[:1000],
        "market": market,
        "version": 1,
        "conditions": [{"field": "market", "values": [market]}],
        "priority": DEFAULT_PRIORITY,
        "is_fallback": False,
    }
    if copy_from_rule_version_id is not None:
        src = _version_row(db, copy_from_rule_version_id, markets)
        values.update(
            conditions=_conditions_json(re_.parse_predicate(src["predicate"])),
            priority=src["priority"],
            is_fallback=bool(src["is_fallback"]),
            target=src["target_script_version_id"],
            copied=src["id"],
            copied_ref=f"{src['rule_code']} v{src['version']}",
            market=src["market_code"],
        )
    return _insert_draft(db, actor_ref, actor_name, **values)


def create_version(
    db: Session,
    markets: Sequence[str],
    actor_ref: str,
    actor_name: str,
    rule_code: str,
    base_rule_version_id: uuid.UUID | None,
) -> uuid.UUID:
    """A new draft version of an existing rule, from its live published version (or a chosen version)."""
    open_d = _one(
        db,
        "SELECT planned_version, status FROM assignment_rule_draft WHERE rule_code = :c AND status = ANY(:s)",
        c=rule_code,
        s=list(OPEN),
    )
    if open_d:
        raise RuleAuthoringError(
            409,
            "OPEN_DRAFT_EXISTS",
            f"v{open_d['planned_version']} of {rule_code} is still {open_d['status'].replace('_', ' ').lower()}; "
            "finish or abandon it first",
        )
    if base_rule_version_id is not None:
        base = _version_row(db, base_rule_version_id, markets)
        if base["rule_code"] != rule_code:
            raise RuleAuthoringError(422, "INVALID_BASE", "The base version belongs to another rule")
    else:
        live = _one(
            db,
            "SELECT id FROM script_assignment_rule_version WHERE rule_code = :c ORDER BY (status = 'PUBLISHED') DESC, "
            "version DESC LIMIT 1",
            c=rule_code,
        )
        if live is None:
            raise RuleAuthoringError(404, "NOT_FOUND", f"No published rule {rule_code}")
        base = _version_row(db, live["id"], markets)
    return _insert_draft(
        db,
        actor_ref,
        actor_name,
        rule_code=rule_code,
        name=base["name"] or rule_code,
        description=base["description"] or "",
        market=base["market_code"],
        version=_next_version(db, rule_code),
        conditions=_conditions_json(re_.parse_predicate(base["predicate"])),
        priority=base["priority"],
        is_fallback=bool(base["is_fallback"]),
        target=base["target_script_version_id"],
        base=base["id"],
        base_ref=f"{rule_code} v{base['version']}",
    )


# ---- editing ----------------------------------------------------------------------------------------------------
def update_draft(
    db: Session,
    draft_id: uuid.UUID,
    markets: Sequence[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    *,
    content: Mapping[str, Any],
) -> int:
    """Replace a draft's content (from the visual editor). Conditions must use approved fields and values (422
    otherwise); everything else — target eligibility, dates, conflicts — is reported by validation."""
    d = _editable(db, draft_id, markets, rv)
    opts = ri.options(db, markets)
    conds, problems = ri.validate_conditions(content.get("conditions") or [], opts)
    if problems:
        raise RuleAuthoringError(422, "INVALID_CONDITION", problems[0], {"problems": problems})
    prio = content.get("priority")
    if not isinstance(prio, int) or not 1 <= prio <= 999:
        raise RuleAuthoringError(422, "INVALID_PRIORITY", "Priority must be a whole number from 1 (highest) to 999")
    ef, et = content.get("effective_from"), content.get("effective_to")
    if ef is not None and et is not None and et <= ef:
        raise RuleAuthoringError(422, "INVALID_DATES", "The end must be after the start")
    new = {
        "name": _check_name(content.get("name") or ""),
        "description": (content.get("description") or "").strip()[:1000],
        "conditions": _conditions_json(conds),
        "priority": prio,
        "is_fallback": bool(content.get("is_fallback")),
        "target_script_version_id": content.get("target_script_version_id"),
        "effective_from": ef,
        "effective_to": et,
    }
    before = {k: d[k] for k in new}
    changed = [k for k in new if _norm(before[k]) != _norm(new[k])]
    if not changed:
        return int(d["row_version"])
    db.execute(
        text(
            "UPDATE assignment_rule_draft SET name = :name, description = :description, conditions = "
            "CAST(:conditions AS jsonb), priority = :priority, is_fallback = :is_fallback, target_script_version_id = "
            ":target_script_version_id, effective_from = :effective_from, effective_to = :effective_to, "
            "validation_status = 'NOT_VALIDATED', row_version = row_version + 1, updated_at = now(), updated_by = :by "
            "WHERE id = :id"
        ),
        {**new, "conditions": json.dumps(new["conditions"]), "by": actor_ref, "id": draft_id},
    )
    add_event(
        db,
        d,
        "CONTENT_CHANGED",
        actor_ref,
        actor_name,
        details={"fields": changed, "changes": {k: {"before": before[k], "after": new[k]} for k in changed}},
    )
    return int(d["row_version"]) + 1


def _norm(v: Any) -> Any:
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, datetime):
        return v.astimezone(UTC).isoformat()
    return v


# ---- validation -------------------------------------------------------------------------------------------------
def _issue(sev: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"severity": sev, "code": code, "message": message, **extra}


def analyse(
    db: Session, draft: Mapping[str, Any], markets: Sequence[str], *, at: datetime | None = None
) -> dict[str, Any]:
    """Validation issues, conflicts with the live ruleset and other open drafts, specificity and the plain-English
    explanation of a draft (or of unsaved editor content shaped like one)."""
    now = at or _now()
    opts = ri.options(db, markets)
    lab = ri.labels(opts)
    issues: list[dict[str, Any]] = []
    conds, problems = ri.validate_conditions(draft.get("conditions") or [], opts)
    for p in problems:
        issues.append(_issue("ERROR", "INVALID_CONDITION", p))
    fields = {c.field: c for c in conds}
    target_row = None
    tid = draft.get("target_script_version_id")
    if tid:
        target_row = _one(
            db,
            "SELECT v.id, v.status, v.effective_from, v.effective_to, v.version_label, v.content_approval_status, "
            "f.code AS family, f.market_code FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
            "WHERE v.id = :v AND f.market_code = ANY(:m)",
            v=tid,
            m=list(markets),
        )
    market = draft.get("market_code") or (markets[0] if markets else None)
    if "market" not in fields:
        issues.append(_issue("ERROR", "MARKET_REQUIRED", "Every rule must name its market"))
    elif list(fields["market"].values) != [market]:
        issues.append(_issue("ERROR", "MARKET_MISMATCH", f"This rule belongs to market {market}"))
    if not tid:
        issues.append(_issue("ERROR", "NO_TARGET", "Choose the published script version this rule assigns"))
    elif target_row is None:
        issues.append(_issue("ERROR", "TARGET_NOT_FOUND", "The target script version is not available to you"))
    else:
        label = ri.target_label(target_row)
        if target_row["market_code"] != market:
            issues.append(_issue("ERROR", "TARGET_MARKET", f"{label} belongs to another market"))
        if target_row["status"] != "PUBLISHED":
            issues.append(
                _issue(
                    "ERROR",
                    "TARGET_NOT_PUBLISHED",
                    f"{label} is {target_row['status'].replace('_', ' ').lower()}; a rule can target only a "
                    "published, effective script version",
                )
            )
        else:
            start = draft.get("effective_from") or now
            if target_row["effective_from"] and target_row["effective_from"] > start:
                issues.append(
                    _issue("ERROR", "TARGET_NOT_YET_EFFECTIVE", f"{label} is not effective when the rule starts")
                )
            if target_row["effective_to"] is not None and (
                draft.get("effective_to") is None or draft["effective_to"] > target_row["effective_to"]
            ):
                issues.append(
                    _issue(
                        "WARNING",
                        "TARGET_RETIRES_FIRST",
                        f"{label} stops being effective before this rule ends; affected cases would fail closed",
                    )
                )
        if target_row["content_approval_status"] != "APPROVED_BY_SC":
            issues.append(
                _issue(
                    "WARNING",
                    "TARGET_SYNTHETIC",
                    f"{label} is synthetic content, not production-approved wording (local testing only)",
                )
            )
    ef, et = draft.get("effective_from"), draft.get("effective_to")
    if ef is not None and ef < now:
        issues.append(
            _issue(
                "ERROR",
                "START_IN_PAST",
                "The start date has passed; leave it empty (starts on publication) or choose a future date",
            )
        )
    if et is not None and et <= (ef or now):
        issues.append(_issue("ERROR", "END_BEFORE_START", "The end must be after the start"))
    if len(conds) <= 1 and not draft.get("is_fallback"):
        issues.append(
            _issue(
                "WARNING", "BROAD_RULE", "Only the market is constrained: this rule matches every case in the market"
            )
        )
    if draft.get("is_fallback"):
        issues.append(
            _issue(
                "WARNING",
                "FALLBACK",
                "Default fallback: considered only when no other rule matches, and never used to resolve ambiguity",
            )
        )
    # Conflicts with the live ruleset (errors) and with other open drafts (warnings).
    conflicts: list[dict[str, Any]] = []
    cand = None
    if not problems:
        cand = ri.draft_candidate(db, {**draft, "conditions": _conditions_json(conds)}, now)
        if draft.get("effective_from") is None:
            cand = replace(cand, effective_from=now)
        live = [
            r
            for r in ri.published_candidates(db, markets, now)
            if r.status == "PUBLISHED" and (r.effective_to is None or r.effective_to > now)
        ]
        ruleset = ri.proposed_ruleset(live, [cand])
        for c in re_.conflicts(ruleset, focus=[cand.ref]):
            conflicts.append({**c.__dict__, "against": "PUBLISHED"})
            if c.severity == "ERROR":
                issues.append(_issue("ERROR", f"CONFLICT_{c.kind}", c.message, rules=c.rules))
            elif c.kind == "SHADOWED":
                issues.append(_issue("WARNING", "CONFLICT_SHADOWED", c.message, rules=c.rules))
        others = _all(
            db,
            "SELECT * FROM assignment_rule_draft WHERE status = ANY(:s) AND market_code = ANY(:m) AND rule_code <> :c",
            s=list(OPEN),
            m=list(markets),
            c=draft.get("rule_code") or "",
        )
        other_cands = []
        for o in others:
            oc = ri.draft_candidate(db, o, now)
            if o["effective_from"] is None:
                oc = replace(oc, effective_from=now)
            other_cands.append(oc)
        for c in re_.conflicts([cand, *other_cands], focus=[cand.ref]):
            if c.severity in ("ERROR", "WARNING"):
                conflicts.append({**c.__dict__, "severity": "WARNING", "against": "OPEN_DRAFT"})
                issues.append(
                    _issue(
                        "WARNING", "OPEN_DRAFT_OVERLAP", f"With another unpublished draft: {c.message}", rules=c.rules
                    )
                )
    explanation = re_.explain(
        conds,
        ri.target_label(target_row) if target_row else "the chosen script version",
        int(draft.get("priority") or DEFAULT_PRIORITY),
        is_fallback=bool(draft.get("is_fallback")),
        labels=lab,
    )
    return {
        "issues": issues,
        "conflicts": conflicts,
        "specificity": re_.specificity(conds),
        "explanation": explanation,
        "predicate": re_.to_predicate(conds),
        "valid": not any(i["severity"] == "ERROR" for i in issues),
    }


def record_validation(
    db: Session, d: Mapping[str, Any], result: Mapping[str, Any], actor_ref: str, actor_name: str
) -> str:
    status = "VALID" if result["valid"] else "INVALID"
    db.execute(
        text("UPDATE assignment_rule_draft SET validation_status = :s WHERE id = :i"), {"s": status, "i": d["id"]}
    )
    add_event(
        db,
        d,
        "VALIDATED",
        actor_ref,
        actor_name,
        details={
            "result": status,
            "errors": sum(i["severity"] == "ERROR" for i in result["issues"]),
            "warnings": sum(i["severity"] == "WARNING" for i in result["issues"]),
        },
    )
    return status


# ---- lifecycle --------------------------------------------------------------------------------------------------
def manifest(db: Session, d: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    t = ri._target_labels(db, [d["target_script_version_id"]]).get(str(d["target_script_version_id"]))
    return {
        "schema": MANIFEST_SCHEMA,
        "rule_code": d["rule_code"],
        "planned_version": d["planned_version"],
        "name": d["name"],
        "description": d["description"],
        "market": d["market_code"],
        "conditions": d["conditions"],
        "predicate": result["predicate"],
        "priority": d["priority"],
        "specificity": result["specificity"],
        "is_fallback": d["is_fallback"],
        "target_script_version_id": str(d["target_script_version_id"]),
        "target_label": ri.target_label(t),
        "effective_from": _norm(d["effective_from"]),
        "effective_to": _norm(d["effective_to"]),
        "base_rule_version_id": str(d["base_rule_version_id"]) if d["base_rule_version_id"] else None,
        "explanation": result["explanation"],
        "content_approval_status": "SYNTHETIC_UNAPPROVED",
    }


def submit(
    db: Session, draft_id: uuid.UUID, markets: Sequence[str], rv: int, actor_ref: str, actor_name: str, summary: str
) -> dict[str, Any]:
    d = _editable(db, draft_id, markets, rv)
    if not 10 <= len(summary.strip()) <= 2000:
        raise RuleAuthoringError(422, "INVALID_SUMMARY", "Describe the change (10–2000 characters) for the reviewer")
    result = analyse(db, d, markets)
    if not result["valid"]:
        record_validation(db, d, result, actor_ref, actor_name)
        raise RuleAuthoringError(
            422, "VALIDATION_FAILED", "Fix the validation errors before submitting", {"issues": result["issues"]}
        )
    m = manifest(db, d, result)
    sha = sha256_of(m)
    db.execute(
        text(
            "UPDATE assignment_rule_draft SET status = 'SUBMITTED_FOR_REVIEW', validation_status = 'VALID', manifest = "
            "CAST(:m AS jsonb), manifest_sha256 = :h, row_version = row_version + 1, updated_at = now(), updated_by = "
            ":by WHERE id = :i"
        ),
        {"m": json.dumps(m), "h": sha, "by": actor_ref, "i": draft_id},
    )
    add_event(
        db,
        d,
        "SUBMITTED",
        actor_ref,
        actor_name,
        reason=summary.strip(),
        details={
            "manifest_sha256": sha,
            "warnings": [i["code"] for i in result["issues"]],
            "specificity": result["specificity"],
        },
    )
    return {"manifest_sha256": sha, "issues": result["issues"]}


def review(
    db: Session,
    draft_id: uuid.UUID,
    markets: Sequence[str],
    actor_ref: str,
    actor_name: str,
    decision: str,
    reason: str,
) -> str:
    d = draft_row(db, draft_id, markets, lock=True)
    if d["status"] != "SUBMITTED_FOR_REVIEW":
        raise RuleAuthoringError(409, "NOT_SUBMITTED", "This rule is not awaiting review")
    if actor_ref in makers(db, d):
        raise RuleAuthoringError(
            403, "SELF_REVIEW_DENIED", "You authored or edited this rule; another checker must review it"
        )
    if not 5 <= len(reason.strip()) <= 2000:
        raise RuleAuthoringError(422, "INVALID_REASON", "Give a reason (5–2000 characters)")
    if decision == "APPROVE":
        db.execute(
            text(
                "UPDATE assignment_rule_draft SET status = 'APPROVED', reviewer_ref = :r, "
                "row_version = row_version + 1, updated_at = now(), updated_by = :r WHERE id = :i"
            ),
            {"r": actor_ref, "i": draft_id},
        )
        add_event(
            db,
            d,
            "APPROVED",
            actor_ref,
            actor_name,
            reason=reason.strip(),
            details={"manifest_sha256": d["manifest_sha256"]},
        )
        return "APPROVED"
    db.execute(
        text(
            "UPDATE assignment_rule_draft SET status = 'DRAFT', validation_status = 'NOT_VALIDATED', manifest = NULL, "
            "manifest_sha256 = NULL, row_version = row_version + 1, updated_at = now(), updated_by = :r WHERE id = :i"
        ),
        {"r": actor_ref, "i": draft_id},
    )
    add_event(db, d, "CHANGES_REQUESTED", actor_ref, actor_name, reason=reason.strip())
    return "DRAFT"


def live_version(db: Session, rule_code: str) -> dict[str, Any] | None:
    return _one(
        db,
        "SELECT * FROM script_assignment_rule_version WHERE rule_code = :c AND status = 'PUBLISHED' "
        "ORDER BY version DESC LIMIT 1",
        c=rule_code,
    )


def publish(
    db: Session,
    draft_id: uuid.UUID,
    markets: Sequence[str],
    actor_ref: str,
    actor_name: str,
    supersede_rule_version_id: uuid.UUID | None,
    reason: str | None,
) -> dict[str, Any]:
    """Publish an approved rule: re-validate against the ruleset as it is now, insert the immutable rule version and
    (when confirmed) supersede the rule's live version. Cases are never reassigned (S2-C)."""
    d = draft_row(db, draft_id, markets, lock=True)
    if d["status"] != "APPROVED":
        raise RuleAuthoringError(409, "NOT_APPROVED", "The rule must be approved before publishing")
    if actor_ref in makers(db, d):
        raise RuleAuthoringError(
            403, "SELF_PUBLISH_DENIED", "You authored or edited this rule; another checker must publish it"
        )
    now = _now()
    result = analyse(db, d, markets, at=now)
    frozen = d["manifest"] or {}
    if (
        sha256_of(frozen) != d["manifest_sha256"]
        or frozen.get("conditions") != d["conditions"]
        or frozen.get("priority") != d["priority"]
        or frozen.get("target_script_version_id") != str(d["target_script_version_id"])
        or frozen.get("predicate") != result["predicate"]
    ):
        raise RuleAuthoringError(409, "MANIFEST_MISMATCH", "The approved content no longer matches its manifest")
    if not result["valid"]:
        raise RuleAuthoringError(
            409,
            "PUBLISH_VALIDATION_FAILED",
            "The rule is no longer valid against the current ruleset or target script; return it for changes",
            {"issues": result["issues"]},
        )
    live = live_version(db, d["rule_code"])
    if live is not None and (supersede_rule_version_id is None or str(supersede_rule_version_id) != str(live["id"])):
        raise RuleAuthoringError(
            422,
            "SUPERSEDE_CONFIRMATION_REQUIRED",
            f"{d['rule_code']} v{live['version']} is published; confirm that this version supersedes it",
            {"live_rule_version_id": str(live["id"])},
        )
    if live is None and supersede_rule_version_id is not None:
        raise RuleAuthoringError(422, "INVALID_SUPERSEDE", "There is no published version of this rule to supersede")
    start = d["effective_from"] or now
    version = d["planned_version"]
    if _one(
        db,
        "SELECT 1 FROM script_assignment_rule_version WHERE rule_code = :c AND version = :v",
        c=d["rule_code"],
        v=version,
    ):
        version = _next_version(db, d["rule_code"])
    body = {
        "rule_code": d["rule_code"],
        "version": version,
        "predicate": result["predicate"],
        "target": str(d["target_script_version_id"]),
        "priority": d["priority"],
        "specificity": result["specificity"],
        "is_fallback": d["is_fallback"],
        "effective_from": _norm(start),
        "effective_to": _norm(d["effective_to"]),
        "manifest_sha256": d["manifest_sha256"],
    }
    rid = uuid.uuid4()
    p = _prov(actor_ref, f"rule-version:{d['rule_code']}:{version}")
    db.execute(
        text(
            "INSERT INTO script_assignment_rule_version (id, rule_code, version, predicate, priority, specificity, "
            "target_script_version_id, effective_from, effective_to, status, checksum, author_ref, checker_ref, "
            "created_by, source_type, source_system, source_reference, source_observed_at, recorded_at, is_synthetic) "
            "VALUES (:id, :code, :ver, CAST(:pred AS jsonb), :prio, :spec, :target, :ef, :et, 'PUBLISHED', :sum, "
            ":author, :checker, :created_by, :source_type, :source_system, :source_reference, :source_observed_at, "
            ":recorded_at, :is_synthetic)"
        ),
        {
            "id": rid,
            "code": d["rule_code"],
            "ver": version,
            "pred": json.dumps(result["predicate"]),
            "prio": d["priority"],
            "spec": result["specificity"],
            "target": d["target_script_version_id"],
            "ef": start,
            "et": d["effective_to"],
            "sum": sha256_of(body),
            "author": d["author_ref"],
            "checker": d["reviewer_ref"],
            **p,
        },
    )
    db.execute(
        text(
            "INSERT INTO assignment_rule_publication (rule_version_id, draft_id, name, description, is_fallback, "
            "approved_by, published_by, published_at) VALUES (:r, :d, :n, :descr, :fb, :a, :p, :t)"
        ),
        {
            "r": rid,
            "d": draft_id,
            "n": d["name"],
            "descr": d["description"],
            "fb": d["is_fallback"],
            "a": d["reviewer_ref"],
            "p": actor_ref,
            "t": now,
        },
    )
    db.execute(
        text(
            "UPDATE assignment_rule_draft SET status = 'PUBLISHED', publisher_ref = :p, "
            "published_rule_version_id = :r, row_version = row_version + 1, updated_at = now(), updated_by = :p "
            "WHERE id = :i"
        ),
        {"p": actor_ref, "r": rid, "i": draft_id},
    )
    add_event(
        db,
        d,
        "PUBLISHED",
        actor_ref,
        actor_name,
        reason=reason,
        details={
            "rule_version": version,
            "effective_from": _norm(start),
            "checksum": sha256_of(body),
            "supersedes": f"v{live['version']}" if live else None,
        },
    )
    if live is not None:
        end = start if live["effective_to"] is None or start < live["effective_to"] else live["effective_to"]
        db.execute(
            text("UPDATE script_assignment_rule_version SET status = 'SUPERSEDED', effective_to = :t WHERE id = :i"),
            {"t": end, "i": live["id"]},
        )
        add_event(
            db,
            d,
            "SUPERSEDED",
            actor_ref,
            actor_name,
            reason=reason,
            details={"superseded": f"v{live['version']}", "effective_to": _norm(end)},
        )
    return {
        "rule_version_id": rid,
        "version": version,
        "superseded": f"v{live['version']}" if live else None,
        "effective_from": start,
    }


def abandon(
    db: Session, draft_id: uuid.UUID, markets: Sequence[str], rv: int, actor_ref: str, actor_name: str, reason: str
) -> None:
    d = _editable(db, draft_id, markets, rv)
    if actor_ref not in makers(db, d):
        raise RuleAuthoringError(403, "NOT_A_MAKER", "Only the author or an editor of this draft can abandon it")
    if not 5 <= len(reason.strip()) <= 2000:
        raise RuleAuthoringError(422, "INVALID_REASON", "Give a reason (5–2000 characters)")
    db.execute(
        text(
            "UPDATE assignment_rule_draft SET status = 'ABANDONED', row_version = row_version + 1, updated_at = now(), "
            "updated_by = :by WHERE id = :i"
        ),
        {"by": actor_ref, "i": draft_id},
    )
    add_event(db, d, "ABANDONED", actor_ref, actor_name, reason=reason.strip())


# ---- comparison -------------------------------------------------------------------------------------------------
def snapshot_of_version(r: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "ref": f"{r['rule_code']} v{r['version']}",
        "kind": "VERSION",
        "status": r["status"],
        "name": r.get("name") or r["rule_code"],
        "conditions": _conditions_json(re_.parse_predicate(r["predicate"])),
        "priority": r["priority"],
        "specificity": r["specificity"],
        "is_fallback": bool(r.get("is_fallback")),
        "target_script_version_id": str(r["target_script_version_id"]),
        "effective_from": _norm(r["effective_from"]),
        "effective_to": _norm(r["effective_to"]),
    }


def snapshot_of_draft(d: Mapping[str, Any]) -> dict[str, Any]:
    conds = [re_.Condition(c["field"], tuple(c["values"])) for c in d["conditions"]]
    return {
        "ref": f"{d['rule_code']} v{d['planned_version']} ({d['status'].replace('_', ' ').lower()})",
        "kind": "DRAFT",
        "status": d["status"],
        "name": d["name"],
        "conditions": d["conditions"],
        "priority": d["priority"],
        "specificity": re_.specificity(conds),
        "is_fallback": bool(d["is_fallback"]),
        "target_script_version_id": str(d["target_script_version_id"]) if d["target_script_version_id"] else None,
        "effective_from": _norm(d["effective_from"]),
        "effective_to": _norm(d["effective_to"]),
    }


def diff(base: Mapping[str, Any] | None, target: Mapping[str, Any]) -> dict[str, Any]:
    """Field-level comparison of two rule snapshots, with per-condition permissiveness."""
    bc = {c["field"]: c["values"] for c in (base or {}).get("conditions", [])}
    tc = {c["field"]: c["values"] for c in target["conditions"]}
    conds = []
    for f in [x.key for x in re_.FIELDS if x.key in bc or x.key in tc]:
        b, t = bc.get(f), tc.get(f)
        if b == t:
            continue
        if b is None:
            effect = "MORE_RESTRICTIVE"  # a new constraint narrows the rule
        elif t is None:
            effect = "MORE_PERMISSIVE"
        elif set(t) > set(b):
            effect = "MORE_PERMISSIVE"
        elif set(t) < set(b):
            effect = "MORE_RESTRICTIVE"
        else:
            effect = "CHANGED"
        conds.append({"field": f, "label": re_.FIELD_BY_KEY[f].label, "before": b, "after": t, "effect": effect})
    fields = []
    for k in (
        "name",
        "priority",
        "specificity",
        "is_fallback",
        "target_script_version_id",
        "effective_from",
        "effective_to",
    ):
        bv = (base or {}).get(k)
        if bv != target.get(k):
            fields.append({"field": k, "before": bv, "after": target.get(k)})
    return {"base": base.get("ref") if base else None, "target": target["ref"], "conditions": conds, "fields": fields}


# ---- simulation -------------------------------------------------------------------------------------------------
def _trace_json(t: re_.RuleTrace) -> dict[str, Any]:
    return {
        "ref": t.ref,
        "rule_code": t.rule_code,
        "origin": t.origin,
        "priority": t.priority,
        "specificity": t.specificity,
        "is_fallback": t.is_fallback,
        "target_label": t.target_label,
        "eligible": t.eligible,
        "excluded_reason": t.excluded_reason,
        "match": t.match,
        "selected": t.selected,
        "tied": t.tied,
        "conditions": [c.__dict__ for c in t.conditions],
    }


def _decision_json(dec: re_.Decision, *, trace: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "outcome": dec.outcome,
        "selected_script_label": dec.selected_target_label,
        "selected_script_version_id": dec.selected_target_id,
        "winning_rules": dec.winning_rules,
        "reason": dec.reason,
        "determinable_script_label": dec.determinable_target_label,
    }
    if trace:
        out["trace"] = [_trace_json(t) for t in dec.trace]
    return out


def simulate(
    db: Session,
    markets: Sequence[str],
    draft_ids: Sequence[uuid.UUID],
    *,
    at: datetime,
    scope: str,
    case_ids: Sequence[uuid.UUID] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate the live ruleset (baseline) and the ruleset after publishing ``draft_ids`` (proposed) against the
    synthetic cases in scope. Read-only: the caller runs it inside a READ ONLY transaction."""
    drafts = [draft_row(db, d, markets) for d in draft_ids]
    codes = [d["rule_code"] for d in drafts]
    if len(set(codes)) != len(codes):
        raise RuleAuthoringError(422, "DUPLICATE_RULE", "Simulate one draft per rule")
    for d in drafts:
        if d["status"] in ("PUBLISHED", "ABANDONED"):
            raise RuleAuthoringError(
                422, "DRAFT_CLOSED", f"{d['rule_code']} v{d['planned_version']} is {d['status'].lower()}"
            )
    opts = ri.options(db, markets)
    for d in drafts:
        _, problems = ri.validate_conditions(d["conditions"], opts)
        if problems or not d["target_script_version_id"]:
            raise RuleAuthoringError(
                422,
                "DRAFT_INCOMPLETE",
                f"{d['rule_code']}: {problems[0] if problems else 'choose a target script version'} before simulating",
            )
    published = ri.published_candidates(db, markets, at)
    proposals = [ri.draft_candidate(db, d, at) for d in drafts]
    # A draft without a start date starts on publication: as if published now (not at a past "as of" time).
    start = now or _now()
    proposals = [p if p.effective_from is not None else replace(p, effective_from=start) for p in proposals]
    proposed = ri.proposed_ruleset(published, proposals)
    cases = ri.case_inputs(db, markets, case_ids)
    if scope == "OPEN":
        cases = [c for c in cases if c.state not in ("CLOSED", "CANCELLED", "VERIFIED")]
    elif scope == "UNASSIGNED":
        cases = [c for c in cases if c.existing is None]
    rows = []
    counts: dict[str, dict[str, int]] = {"baseline": {}, "proposed": {}}
    changed = 0
    differs_from_existing = 0
    by_rule: dict[str, int] = {}
    for c in cases:
        base = re_.evaluate(published, c.inputs, at)
        prop = re_.evaluate(proposed, c.inputs, at)
        counts["baseline"][base.outcome] = counts["baseline"].get(base.outcome, 0) + 1
        counts["proposed"][prop.outcome] = counts["proposed"].get(prop.outcome, 0) + 1
        is_changed = (base.outcome, base.selected_target_id, base.winning_rules) != (
            prop.outcome,
            prop.selected_target_id,
            prop.winning_rules,
        )
        changed += is_changed
        existing_id = c.existing["script_version_id"] if c.existing else None
        vs_existing = prop.selected_target_id is not None and prop.selected_target_id != existing_id
        differs_from_existing += vs_existing
        if prop.selected_target_id is not None:  # only cases where the rule actually selects a script (no ties)
            for w in prop.winning_rules:
                by_rule[w] = by_rule.get(w, 0) + 1
        rows.append(
            {
                "case_id": str(c.case_id),
                "case_ref": c.case_ref,
                "state": c.state,
                "has_blocking_hold": c.has_blocking_hold,
                "inputs": c.inputs,
                "existing": c.existing,
                "baseline": _decision_json(base, trace=False),
                "proposed": _decision_json(prop, trace=True),
                "changed": is_changed,
                "differs_from_existing": vs_existing,
            }
        )
    rule_conflicts = [
        c.__dict__
        for c in re_.conflicts(
            [
                r
                for r in proposed
                if r.status in ("PUBLISHED", "DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED") and re_.effective_at(r, at)
            ],
            focus=[p.ref for p in proposals] or None,
        )
    ]
    lab = ri.labels(opts)
    return {
        "as_of": at,
        "scope": scope,
        "drafts": [str(d["id"]) for d in drafts],
        "rules": [
            {
                "ref": r.ref,
                "rule_code": r.rule_code,
                "origin": r.origin,
                "status": r.status,
                "priority": r.priority,
                "specificity": r.specificity,
                "is_fallback": r.is_fallback,
                "target_label": r.target_label,
                "target_effective": r.target_effective,
                "effective_from": r.effective_from,
                "effective_to": r.effective_to,
                "effective_now": re_.effective_at(r, at) and (r.origin == "PROPOSED" or r.status == "PUBLISHED"),
                "explanation": re_.explain(
                    list(r.conditions), r.target_label, r.priority, is_fallback=r.is_fallback, labels=lab
                ),
                "conditions": _conditions_json(r.conditions),
                "cases_won": by_rule.get(r.ref, 0),
            }
            for r in sorted(proposed, key=lambda x: (x.priority, -x.specificity, x.ref))
        ],
        "conflicts": rule_conflicts,
        "summary": {
            "cases": len(cases),
            "baseline": counts["baseline"],
            "proposed": counts["proposed"],
            "changed": changed,
            "differs_from_existing": differs_from_existing,
        },
        "cases": rows,
    }
