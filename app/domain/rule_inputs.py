"""Read-only loaders for script-assignment rules (S2-B simulation; reused by S2-C assignment).

- ``options``: the approved condition fields and their allowed values, each from an existing governed source (no new
  business classification is introduced). Fields that the data model cannot support are reported, not invented.
- ``case_inputs``: the facts a rule is evaluated on, per case, from persisted records only: market and callback
  purpose (case), product, ILP and channel facts (the sale's latest policy fact snapshot), the effective SBQ band
  (the sale's latest FINAL assessment, ``UNASSESSED`` when none), eligible contact roles (current eligible contact
  selections) and the existing pinned script assignment.
- ``published_candidates`` / ``draft_candidate``: rule versions and drafts as ``rule_engine.RuleCandidate``.

Nothing here writes.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import rule_engine as re_
from app.domain.intake import SYNTHETIC_PRODUCTS

# Unsupported fields named in the owner's list: reported with the reason instead of being invented.
UNSUPPORTED_FIELDS: tuple[dict[str, str], ...] = (
    {
        "field": "language",
        "label": "Language",
        "reason": "No language is recorded on cases, parties or contacts, and every script version is English (en). "
        "A language condition would have nothing to evaluate; it needs a governed language field first.",
    },
)


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def _active_codes(db: Session, list_code: str) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT v.code, v.label FROM code_value v JOIN code_list_version lv ON lv.id = v.code_list_version_id "
        "JOIN code_list l ON l.id = lv.code_list_id WHERE l.code = :c AND lv.status = 'ACTIVE' ORDER BY v.sort_order, "
        "v.code",
        c=list_code,
    )


def _check_values(db: Session, constraint: str) -> list[str]:
    """Allowed values of an existing enumeration CHECK constraint (the schema is the governed source)."""
    expr = db.execute(
        text(
            "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE c.conname = :n AND n.nspname = current_schema()"
        ),
        {"n": constraint},
    ).scalar()
    if not expr:
        return []
    import re

    return re.findall(r"'([^']+)'", str(expr))


def options(db: Session, markets: Sequence[str]) -> dict[str, Any]:
    """Approved rule fields and values with their governed source. Labels are display text only."""
    from app.domain.script_authoring import CONDITION_FACTS

    bands = _active_codes(db, "sbq_risk_band")
    roles = _active_codes(db, "callable_party_roles")
    markets_list = [m for m in _active_codes(db, "market") if m["code"] in markets]
    products = sorted({(code, fam) for code, fam, _ in SYNTHETIC_PRODUCTS})
    fields: list[dict[str, Any]] = [
        {
            "field": "market",
            "values": [{"value": m["code"], "label": m["label"]} for m in markets_list],
            "source": "Governed code list 'market' (enabled markets in your scope, D-39)",
            "required": True,
        },
        {
            "field": "case_purpose",
            "values": [
                {"value": v, "label": v.replace("_", " ").capitalize()}
                for v in _check_values(db, "ck_callback_case_obligation")
            ],
            "source": "Callback case obligation types (schema enumeration)",
            "required": False,
        },
        {
            "field": "product_family",
            "values": [
                {"value": v, "label": v.title() if v != "ILP" else "ILP"} for v in CONDITION_FACTS["product_family"]
            ],
            "source": "Approved condition facts (S2-A, policy fact snapshot)",
            "required": False,
        },
        {
            "field": "product_code",
            "values": [
                {"value": code, "label": f"{code} ({fam.title() if fam != 'ILP' else 'ILP'})"} for code, fam in products
            ],
            "source": "Synthetic Stage 0 product catalogue (intake validator)",
            "required": False,
        },
        {
            "field": "is_ilp",
            "values": [{"value": True, "label": "ILP"}, {"value": False, "label": "Not ILP"}],
            "source": "Policy fact snapshot",
            "required": False,
        },
        {
            "field": "risk_band",
            "values": [{"value": b["code"], "label": b["label"]} for b in bands]
            + [{"value": re_.RISK_UNASSESSED, "label": "Unassessed (no final SBQ assessment)"}],
            "source": "Governed code list 'sbq_risk_band' plus the explicit unassessed status (D-59)",
            "required": False,
        },
        {
            "field": "selling_channel",
            "values": [{"value": v, "label": v.title()} for v in CONDITION_FACTS["selling_channel"]],
            "source": "Approved condition facts (S2-A, sale event)",
            "required": False,
        },
        {
            "field": "premium_frequency",
            "values": [
                {"value": v, "label": v.replace("_", " ").capitalize()} for v in CONDITION_FACTS["premium_frequency"]
            ],
            "source": "Approved condition facts (S2-A, policy fact snapshot)",
            "required": False,
        },
        {
            "field": "contact_role",
            "values": [{"value": r["code"], "label": r["label"]} for r in roles],
            "source": "Governed code list 'callable_party_roles' (matches when any eligible contact has the role)",
            "required": False,
        },
    ]
    for f in fields:
        f["label"] = re_.FIELD_BY_KEY[f["field"]].label
    return {"fields": fields, "unsupported": list(UNSUPPORTED_FIELDS)}


def labels(opts: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    return {f["field"]: {str(v["value"]): v["label"] for v in f["values"]} for f in opts["fields"]}


def validate_conditions(
    raw: Sequence[Mapping[str, Any]], opts: Mapping[str, Any]
) -> tuple[list[re_.Condition], list[str]]:
    """Structured conditions from the editor → (conditions, problems). Only approved fields and values pass."""
    allowed = {f["field"]: [v["value"] for v in f["values"]] for f in opts["fields"]}
    out: list[re_.Condition] = []
    problems: list[str] = []
    seen: set[str] = set()
    for i, c in enumerate(raw):
        f = str(c.get("field") or "")
        vals = list(c.get("values") or [])
        if f not in allowed:
            problems.append(f"Condition {i + 1}: '{f}' is not an approved rule field")
            continue
        if f in seen:
            problems.append(f"Condition {i + 1}: {re_.FIELD_BY_KEY[f].label} is already constrained")
            continue
        seen.add(f)
        if not vals:
            problems.append(
                f"Condition {i + 1}: choose at least one {re_.FIELD_BY_KEY[f].label.lower()} value "
                "(or remove the condition to allow any)"
            )
            continue
        bad = [v for v in vals if v not in allowed[f] or (f == "is_ilp") != isinstance(v, bool)]
        if bad:
            problems.append(f"Condition {i + 1}: {bad!r} is not an approved value of {re_.FIELD_BY_KEY[f].label}")
            continue
        out.append(re_.Condition(f, re_._dedupe(vals)))
    out.sort(key=lambda c: re_.ORDER[c.field])
    return out, problems


# ---- case inputs ------------------------------------------------------------------------------------------------
@dataclass
class CaseInputs:
    case_id: uuid.UUID
    case_ref: str
    state: str
    has_blocking_hold: bool
    inputs: dict[str, Any]
    existing: dict[str, Any] | None  # current pinned assignment (script version and rule), if any


def case_inputs(db: Session, markets: Sequence[str], case_ids: Sequence[uuid.UUID] | None = None) -> list[CaseInputs]:
    rows = _all(
        db,
        "SELECT c.id, c.case_ref, c.state, c.has_blocking_hold, c.market_code, c.obligation_type, c.sale_event_id, "
        "se.selling_channel AS sale_channel, snap.facts, band.band_code FROM callback_case c "
        "JOIN sale_event se ON se.id = c.sale_event_id "
        "LEFT JOIN LATERAL (SELECT facts FROM policy_fact_snapshot s WHERE s.sale_event_id = c.sale_event_id "
        "ORDER BY s.captured_at DESC LIMIT 1) snap ON true "
        "LEFT JOIN LATERAL (SELECT band_code FROM risk_assessment ra WHERE ra.sale_event_id = c.sale_event_id "
        "AND ra.status = 'FINAL' ORDER BY ra.valid_at DESC LIMIT 1) band ON true "
        "WHERE c.market_code = ANY(:m) AND (CAST(:ids AS uuid[]) IS NULL OR c.id = ANY(CAST(:ids AS uuid[]))) "
        "ORDER BY c.case_ref",
        m=list(markets),
        ids=list(case_ids) if case_ids is not None else None,
    )
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    roles: dict[uuid.UUID, set[str]] = {}
    for r in _all(
        db,
        "SELECT s.callback_case_id, ppr.role FROM case_contact_selection s JOIN policy_party_role ppr "
        "ON ppr.id = s.policy_party_role_id WHERE s.callback_case_id = ANY(:i) AND s.eligible "
        "AND NOT EXISTS (SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = s.id)",
        i=ids,
    ):
        roles.setdefault(r["callback_case_id"], set()).add(r["role"])
    existing: dict[uuid.UUID, dict[str, Any]] = {}
    for r in _all(
        db,
        "SELECT a.callback_case_id, a.script_version_id, a.origin, a.assigned_at, f.code AS family, v.version_label, "
        "rv.rule_code, rv.version AS rule_version FROM script_assignment a JOIN script_version v "
        "ON v.id = a.script_version_id JOIN script_family f ON f.id = v.script_family_id "
        "LEFT JOIN script_assignment_rule_version rv ON rv.id = a.matched_rule_version_id "
        "WHERE a.callback_case_id = ANY(:i) AND NOT EXISTS (SELECT 1 FROM script_assignment x "
        "WHERE x.supersedes_id = a.id)",
        i=ids,
    ):
        existing[r["callback_case_id"]] = {
            "script_version_id": str(r["script_version_id"]),
            "script_label": f"{r['family']} v{r['version_label']}",
            "rule": f"{r['rule_code']} v{r['rule_version']}" if r["rule_code"] else None,
            "origin": r["origin"],
            "assigned_at": r["assigned_at"],
        }
    out = []
    for r in rows:
        facts = r["facts"] or {}
        inputs: dict[str, Any] = {
            "market": r["market_code"],
            "case_purpose": r["obligation_type"],
            "product_family": facts.get("product_family"),
            "product_code": facts.get("product_code"),
            "is_ilp": facts.get("is_ilp"),
            "selling_channel": facts.get("selling_channel") or r["sale_channel"],
            "premium_frequency": facts.get("premium_frequency"),
            "risk_band": r["band_code"] or re_.RISK_UNASSESSED,
            "contact_role": sorted(roles.get(r["id"], set())),
        }
        out.append(
            CaseInputs(r["id"], r["case_ref"], r["state"], r["has_blocking_hold"], inputs, existing.get(r["id"]))
        )
    return out


# ---- rule candidates --------------------------------------------------------------------------------------------
def _target_labels(db: Session, ids: Sequence[uuid.UUID]) -> dict[str, dict[str, Any]]:
    if not ids:
        return {}
    return {
        str(r["id"]): r
        for r in _all(
            db,
            "SELECT v.id, v.status, v.effective_from, v.effective_to, v.version_label, f.code AS family, "
            "f.market_code FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
            "WHERE v.id = ANY(:i)",
            i=list(ids),
        )
    }


def target_effective(t: Mapping[str, Any] | None, at: datetime) -> bool:
    """A script version is selectable at ``at`` only when published and inside its effective window."""
    if t is None or t["status"] != "PUBLISHED" or t["effective_from"] is None:
        return False
    return bool(t["effective_from"] <= at and (t["effective_to"] is None or at < t["effective_to"]))


def target_label(t: Mapping[str, Any] | None) -> str:
    return f"{t['family']} v{t['version_label']}" if t else "no target script"


def published_candidates(db: Session, markets: Sequence[str], at: datetime) -> list[re_.RuleCandidate]:
    """Every rule version in scope (any status: the engine excludes non-published ones with a reason)."""
    rows = _all(
        db,
        "SELECT r.*, p.is_fallback, p.name FROM script_assignment_rule_version r JOIN script_version v "
        "ON v.id = r.target_script_version_id JOIN script_family f ON f.id = v.script_family_id "
        "LEFT JOIN assignment_rule_publication p ON p.rule_version_id = r.id WHERE f.market_code = ANY(:m) "
        "ORDER BY r.rule_code, r.version",
        m=list(markets),
    )
    targets = _target_labels(db, [r["target_script_version_id"] for r in rows])
    out = []
    for r in rows:
        t = targets.get(str(r["target_script_version_id"]))
        out.append(
            re_.RuleCandidate(
                ref=f"{r['rule_code']} v{r['version']}",
                rule_code=r["rule_code"],
                version=r["version"],
                origin="PUBLISHED",
                status=r["status"],
                conditions=tuple(re_.parse_predicate(r["predicate"])),
                priority=r["priority"],
                is_fallback=bool(r["is_fallback"]),
                target_id=str(r["target_script_version_id"]),
                target_label=target_label(t),
                effective_from=r["effective_from"],
                effective_to=r["effective_to"],
                target_effective=target_effective(t, at),
            )
        )
    return out


def draft_candidate(db: Session, draft: Mapping[str, Any], at: datetime) -> re_.RuleCandidate:
    """A draft as it would behave once published (effective from its start date, or from ``at`` when unset)."""
    conds = [re_.Condition(c["field"], tuple(c["values"])) for c in draft["conditions"]]
    tid = draft["target_script_version_id"]
    t = _target_labels(db, [tid]).get(str(tid)) if tid else None
    return re_.RuleCandidate(
        ref=f"{draft['rule_code']} v{draft['planned_version']} (proposed)",
        rule_code=draft["rule_code"],
        version=draft["planned_version"],
        origin="PROPOSED",
        status=draft["status"],
        conditions=tuple(sorted(conds, key=lambda c: re_.ORDER[c.field])),
        priority=draft["priority"],
        is_fallback=bool(draft["is_fallback"]),
        target_id=str(tid) if tid else "",
        target_label=target_label(t),
        effective_from=draft["effective_from"],
        effective_to=draft["effective_to"],
        target_effective=target_effective(t, at),
        draft_id=str(draft["id"]),
    )


def proposed_ruleset(
    published: Sequence[re_.RuleCandidate], drafts: Sequence[re_.RuleCandidate]
) -> list[re_.RuleCandidate]:
    """The ruleset as it would be after publishing the drafts: each draft replaces the live version of its rule
    code (a new version supersedes it; a new rule is added)."""
    starts = {d.rule_code: d.effective_from for d in drafts}
    out: list[re_.RuleCandidate] = []
    for r in published:
        if r.rule_code in starts and r.status == "PUBLISHED":
            start = starts[r.rule_code]
            if start is None:
                continue  # replaced on publication
            end = start if r.effective_to is None or start < r.effective_to else r.effective_to
            r = replace(r, effective_to=end)  # live until the new version starts
        out.append(r)
    return out + list(drafts)
