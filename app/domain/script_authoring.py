"""S2-A Script Studio authoring on the S0 script model (ADR-0007, SCRIPT_GOVERNANCE_AND_ASSIGNMENT).

Shape (unchanged from 0005): a ``script_version`` orders ``script_section`` rows; each section places one
``script_module`` (with an inclusion condition); a module orders ``module_question`` rows; each points at an immutable
``question_revision`` of a stable ``question_bank_item``. Controls and regulatory references attach to the question
concept through ``control_mapping``.

Authoring rules:

- Only DRAFT content changes. Every change checks the draft's ``row_version`` (optimistic concurrency), bumps it,
  resets validation and appends a ``script_change_event``.
- Published modules are never edited: the first change to a published module inside a draft creates the module's next
  revision as a DRAFT owned by that draft (copy-on-write). Question edits never update a revision: a changed question
  is a new ``question_revision`` (insert-only), so historic versions and sessions keep their exact text.
- Conditions use only the S0 predicate language (``fact``/``equals``, ``risk_band_in``, ``all``) over an allowlist of
  approved facts and values. Nothing is evaluated from free text or code.
- Submit validates and freezes a manifest (full question snapshot, controls included) and its SHA-256. Approve and
  publish require a different principal from every maker of the draft (author and editors). Publishing publishes the
  draft's modules and the version together; superseding the family's current version is an explicit choice.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain.digest import sha256_of

MANIFEST_SCHEMA = "call360.script-manifest/2"
SOURCE_SYSTEM = "CALL360_SCRIPT_STUDIO"
OPEN_STATUSES = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED")
MODULE_KINDS = ("COMMON", "PRODUCT", "RISK", "LANGUAGE")
DELIVERY_MODES = ("CONVERSATIONAL", "CONTROLLED_TTS", "EXACT_AUDIO")
ANSWER_TYPES = ("YES_NO", "NUMERIC", "ENUM", "FREE_TEXT", "ACKNOWLEDGEMENT")
POLICIES = ("EXACT_BOOLEAN", "NUMERIC_MATCH_POLICY_FACT", "ACKNOWLEDGEMENT", "NARRATIVE_REVIEW", "COLLECT_ONLY")
CATEGORIES = (
    "SALES_CONDUCT",
    "PRODUCT_UNDERSTANDING",
    "POLICY_FACT",
    "ELEVATED_RISK",
    "IDENTITY",
    "DISCLOSURE",
    "OTHER",
)
# Approved condition facts and values (the facts recorded in the pinned policy fact snapshot, D-30 / seed).
CONDITION_FACTS: dict[str, tuple[Any, ...]] = {
    "product_family": ("PROTECTION", "ILP", "ENDOWMENT"),
    "is_ilp": (True, False),
    "selling_channel": ("AGENCY", "BANCASSURANCE", "BROKER", "DIRECT"),
    "premium_frequency": ("SINGLE", "MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"),
}
RISK_BANDS = ("LOW", "MEDIUM", "HIGH")
# Policy facts a NUMERIC_MATCH_POLICY_FACT question may be compared with.
FACT_KEYS: dict[str, str] = {
    "premium_term_years": "Premium payment term in years (policy fact snapshot)",
    "premium_amount": "Premium amount (policy fact snapshot, decimal string)",
}
CODE_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,39}$")
QUESTION_CODE_RE = re.compile(r"^Q-[A-Z0-9_-]{3,57}$")
LABEL_RE = re.compile(r"^(\d+)\.(\d+)$")


class AuthoringError(Exception):
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
        "source_reference": f"script-studio:{what}:{actor_ref}"[:160],
        "source_observed_at": now,
        "recorded_at": now,
        "is_synthetic": True,
        "created_by": actor_ref,
    }


# ---- conditions -------------------------------------------------------------------------------------------------
def check_condition(cond: Any, where: str = "condition") -> list[str]:
    """Problems with a stored or proposed condition; [] when it is valid in the approved predicate language."""
    if cond is None:
        return []
    if not isinstance(cond, dict):
        return [f"{where} must be an object"]
    keys = set(cond)
    if keys == {"all"}:
        parts = cond["all"]
        if not isinstance(parts, list) or not parts:
            return [f"{where}: 'all' needs at least one condition"]
        out: list[str] = []
        for i, p in enumerate(parts):
            if isinstance(p, dict) and "all" in p:
                out.append(f"{where}: nested 'all' is not supported")
            out += check_condition(p, f"{where}[{i}]")
        return out
    if keys == {"risk_band_in"}:
        bands = cond["risk_band_in"]
        if not isinstance(bands, list) or not bands or any(b not in RISK_BANDS for b in bands):
            return [f"{where}: risk bands must be a non-empty subset of {', '.join(RISK_BANDS)}"]
        return []
    if keys == {"fact", "equals"}:
        fact, value = cond["fact"], cond["equals"]
        if fact not in CONDITION_FACTS:
            return [f"{where}: '{fact}' is not an approved condition fact"]
        if value not in CONDITION_FACTS[fact] or (isinstance(value, bool) != (fact == "is_ilp")):
            return [f"{where}: {value!r} is not an approved value of {fact}"]
        return []
    return [f"{where}: unsupported condition (use fact/equals, risk_band_in or all)"]


def _require_condition(cond: Any, where: str) -> None:
    problems = check_condition(cond, where)
    if problems:
        raise AuthoringError(422, "INVALID_CONDITION", problems[0], {"problems": problems})


# ---- question content -------------------------------------------------------------------------------------------
QUESTION_FIELDS = (
    "intent",
    "category",
    "customer_wording",
    "delivery_mode",
    "answer_type",
    "answer_schema",
    "mandatory",
    "expected_answer_policy",
    "expected_value",
    "acceptable_variants",
    "unacceptable_outcomes",
    "policy_fact_key",
    "not_applicable_predicate",
    "evidence_required",
    "escalation_rule_ref",
    "max_reprompts",
)
# S2-A.1: intent and category belong to each revision (question_revision_detail), so every content field is a
# revision field and the shared question_bank_item is never changed by a draft.
REVISION_FIELDS = QUESTION_FIELDS
# A question revision with its effective intent and category (seeded revisions have no detail row and use the
# bank item's values, which the seed set and authoring no longer changes).
REV_SQL = (
    "SELECT qr.*, coalesce(d.intent, i.intent) AS rev_intent, coalesce(d.category, i.category) AS rev_category "
    "FROM question_revision qr JOIN question_bank_item i ON i.id = qr.question_bank_item_id "
    "LEFT JOIN question_revision_detail d ON d.question_revision_id = qr.id"
)
# Revisions that are part of published (or since superseded) content and so may be reused from the question bank.
PUBLISHED_REVISION_SQL = (
    "EXISTS (SELECT 1 FROM module_question pmq JOIN script_module pm ON pm.id = pmq.script_module_id "
    "WHERE pmq.question_revision_id = qr.id AND pm.status IN ('PUBLISHED', 'SUPERSEDED'))"
)
# Versions whose control links are their own rows in script_version_control_link (S2-A.1).
ROW_LINK_STATUSES = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED", "ABANDONED")


def normalise_question(q: dict[str, Any]) -> dict[str, Any]:
    """Validate one question's content and return the stored form (answer schema and expected value derived)."""

    def bad(msg: str) -> AuthoringError:
        return AuthoringError(422, "INVALID_QUESTION", msg)

    wording = (q.get("customer_wording") or "").strip()
    intent = (q.get("intent") or "").strip()
    if len(wording) < 10 or len(wording) > 1000:
        raise bad("Customer wording must be 10–1000 characters")
    if len(intent) < 5 or len(intent) > 300:
        raise bad("Intent must be 5–300 characters")
    category = q.get("category") or "OTHER"
    if category not in CATEGORIES:
        raise bad(f"Category must be one of {', '.join(CATEGORIES)}")
    mode, atype, policy = q.get("delivery_mode"), q.get("answer_type"), q.get("expected_answer_policy")
    if mode not in DELIVERY_MODES:
        raise bad("Unknown delivery mode")
    if atype not in ANSWER_TYPES:
        raise bad("Unknown answer type")
    if policy not in POLICIES:
        raise bad("Unknown expected-answer policy")
    options = [str(o).strip() for o in (q.get("enum_options") or []) if str(o).strip()]
    if atype == "ENUM":
        if len(options) < 2 or len(set(options)) != len(options):
            raise bad("A choice question needs at least two distinct options")
        schema: dict[str, Any] = {"type": "string", "enum": options}
    else:
        schema = {"type": atype.lower()}
    expected: Any = None
    fact_key = q.get("policy_fact_key") or None
    if policy == "EXACT_BOOLEAN":
        if atype != "YES_NO":
            raise bad("An exact yes/no expectation needs a yes/no question")
        if not isinstance(q.get("expected_boolean"), bool):
            raise bad("Choose the expected answer (yes or no)")
        expected = {"value": q["expected_boolean"]}
    if policy == "NUMERIC_MATCH_POLICY_FACT":
        if atype != "NUMERIC":
            raise bad("Matching a policy fact needs a numeric question")
        if fact_key not in FACT_KEYS:
            raise bad(f"Choose an approved policy fact ({', '.join(FACT_KEYS)})")
    else:
        fact_key = None
    if policy == "ACKNOWLEDGEMENT" and atype != "ACKNOWLEDGEMENT":
        raise bad("An acknowledgement expectation needs an acknowledgement question")
    if policy == "NARRATIVE_REVIEW" and atype != "FREE_TEXT":
        raise bad("Narrative review needs a free-text question")
    na = q.get("not_applicable_predicate")
    _require_condition(na, "not-applicable condition")
    reprompts = q.get("max_reprompts", 1)
    if not isinstance(reprompts, int) or not 0 <= reprompts <= 5:
        raise bad("Maximum re-prompts must be between 0 and 5")
    esc = (q.get("escalation_rule_ref") or "").strip() or None
    if esc and len(esc) > 40:
        raise bad("Escalation reference must be at most 40 characters")

    def clean(xs: Any) -> list[str]:
        return [str(x).strip() for x in (xs or []) if str(x).strip()][:20]

    return {
        "intent": intent,
        "category": category,
        "customer_wording": wording,
        "delivery_mode": mode,
        "answer_type": atype,
        "answer_schema": schema,
        "mandatory": bool(q.get("mandatory")),
        "expected_answer_policy": policy,
        "expected_value": expected,
        "acceptable_variants": clean(q.get("acceptable_variants")),
        "unacceptable_outcomes": clean(q.get("unacceptable_outcomes")),
        "policy_fact_key": fact_key,
        "not_applicable_predicate": na,
        "evidence_required": bool(q.get("evidence_required", q.get("mandatory"))),
        "escalation_rule_ref": esc,
        "max_reprompts": reprompts,
    }


# ---- versions, events, makers -----------------------------------------------------------------------------------
def version_row(db: Session, version_id: uuid.UUID, markets: list[str], *, lock: bool = False) -> dict[str, Any]:
    v = _one(
        db,
        "SELECT v.*, f.code AS family, f.name AS family_name, f.market_code FROM script_version v "
        "JOIN script_family f ON f.id = v.script_family_id WHERE v.id = :v AND f.market_code = ANY(:m)"
        + (" FOR UPDATE OF v" if lock else ""),
        v=version_id,
        m=markets,
    )
    if v is None:
        raise AuthoringError(404, "NOT_FOUND", "Not found or not available to you")
    return v


def _editable(db: Session, version_id: uuid.UUID, markets: list[str], expected_row_version: int) -> dict[str, Any]:
    v = version_row(db, version_id, markets, lock=True)
    if v["status"] != "DRAFT":
        raise AuthoringError(
            409, "VERSION_NOT_EDITABLE", f"Version v{v['version_label']} is {v['status']}; only drafts change"
        )
    if v["row_version"] != expected_row_version:
        raise AuthoringError(
            409,
            "STALE_DRAFT",
            "This draft was changed by someone else; reload it before editing",
            {"current_row_version": v["row_version"]},
        )
    return v


def add_event(
    db: Session,
    version_id: uuid.UUID,
    event_type: str,
    actor_ref: str,
    actor_name: str,
    *,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    seq = db.execute(
        text("SELECT coalesce(max(seq), 0) + 1 FROM script_change_event WHERE script_version_id = :v"),
        {"v": version_id},
    ).scalar_one()
    import json

    db.execute(
        text(
            "INSERT INTO script_change_event (id, script_version_id, seq, event_type, actor_ref, actor_name, reason, "
            "details) VALUES (:i, :v, :s, :t, :a, :n, :r, CAST(:d AS jsonb))"
        ),
        {
            "i": uuid.uuid4(),
            "v": version_id,
            "s": seq,
            "t": event_type,
            "a": actor_ref,
            "n": actor_name[:120],
            "r": reason,
            "d": json.dumps(details or {}, default=str),
        },
    )


def _touch(
    db: Session, v: dict[str, Any], actor_ref: str, actor_name: str, action: str, details: dict[str, Any]
) -> int:
    """Record one content change: bump the draft's row version, reset validation, append the change event."""
    new_rv = int(v["row_version"]) + 1
    db.execute(
        text(
            "UPDATE script_version SET row_version = :rv, validation_status = 'NOT_VALIDATED', updated_at = now(), "
            "updated_by = :by WHERE id = :i"
        ),
        {"rv": new_rv, "by": actor_ref, "i": v["id"]},
    )
    add_event(db, v["id"], "CONTENT_CHANGED", actor_ref, actor_name, details={"action": action, **details})
    return new_rv


def makers(db: Session, version_id: uuid.UUID, author_ref: str) -> set[str]:
    """Everyone who authored or changed the draft content: none of them may approve or publish it."""
    rows = db.execute(
        text(
            "SELECT DISTINCT actor_ref FROM script_change_event WHERE script_version_id = :v "
            "AND event_type IN ('DRAFT_CREATED', 'CONTENT_CHANGED')"
        ),
        {"v": version_id},
    ).scalars()
    return {author_ref, *rows}


def next_label(db: Session, family_id: uuid.UUID) -> str:
    labels = db.execute(
        text("SELECT version_label FROM script_version WHERE script_family_id = :f"), {"f": family_id}
    ).scalars()
    parsed = sorted((int(m.group(1)), int(m.group(2))) for lab in labels if (m := LABEL_RE.match(lab)))
    if not parsed:
        return "1.0"
    major, minor = parsed[-1]
    return f"{major}.{minor + 1}"


def create_family(
    db: Session, *, code: str, name: str, purpose: str, description: str, market: str, actor_ref: str, actor_name: str
) -> tuple[uuid.UUID, uuid.UUID]:
    code = code.strip().upper()
    if not CODE_RE.match(code):
        raise AuthoringError(422, "INVALID_CODE", "Family code: 3–40 capital letters, digits, '_' or '-'")
    if _one(db, "SELECT 1 FROM script_family WHERE code = :c", c=code):
        raise AuthoringError(409, "CODE_IN_USE", f"A script family {code} already exists")
    fid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO script_family (id, code, name, market_code, purpose, description, source_type, source_system, "
            "source_reference, source_observed_at, recorded_at, is_synthetic, created_by) VALUES (:id, :code, :name, "
            ":market, :purpose, :descr, :source_type, :source_system, :source_reference, :source_observed_at, "
            ":recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": fid,
            "code": code,
            "name": name.strip(),
            "market": market,
            "purpose": purpose,
            "descr": description.strip(),
            **_prov(actor_ref, f"family:{code}"),
        },
    )
    vid = _new_version(db, fid, None, actor_ref, actor_name)
    return fid, vid


def _new_version(
    db: Session, family_id: uuid.UUID, base: dict[str, Any] | None, actor_ref: str, actor_name: str
) -> uuid.UUID:
    vid = uuid.uuid4()
    label = next_label(db, family_id)
    db.execute(
        text(
            "INSERT INTO script_version (id, script_family_id, version_label, status, validation_status, language, "
            "author_ref, content_approval_status, supersedes_id, source_type, source_system, source_reference, "
            "source_observed_at, recorded_at, is_synthetic, created_by) VALUES (:id, :f, :label, 'DRAFT', "
            "'NOT_VALIDATED', 'en', :author, 'SYNTHETIC_UNAPPROVED', :base, :source_type, :source_system, "
            ":source_reference, :source_observed_at, :recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": vid,
            "f": family_id,
            "label": label,
            "author": actor_ref,
            "base": base["id"] if base else None,
            **_prov(actor_ref, f"version:{label}"),
        },
    )
    copied = 0
    if base is not None:
        for s in _all(db, "SELECT * FROM script_section WHERE script_version_id = :v ORDER BY position", v=base["id"]):
            module = _one(db, "SELECT status FROM script_module WHERE id = :m", m=s["script_module_id"])
            assert module is not None
            if module["status"] == "DRAFT":
                raise AuthoringError(409, "BASE_HAS_DRAFT_MODULES", "The base version still has unpublished modules")
            _insert_section(db, vid, s["script_module_id"], s["position"], s["inclusion_condition"], actor_ref)
            copied += 1
        # The draft gets its own copy of the base version's control links (S2-A.1 isolation).
        for link in link_rows(db, base):
            _insert_link(db, vid, link, "BASE_VERSION", actor_ref, f"base:{base['version_label']}")
    add_event(
        db,
        vid,
        "DRAFT_CREATED",
        actor_ref,
        actor_name,
        details={"version_label": label, "based_on": base["version_label"] if base else None, "sections": copied},
    )
    return vid


def create_draft(
    db: Session, family_id: uuid.UUID, markets: list[str], base_id: uuid.UUID | None, actor_ref: str, actor_name: str
) -> uuid.UUID:
    fam = _one(
        db, "SELECT * FROM script_family WHERE id = :f AND market_code = ANY(:m) FOR UPDATE", f=family_id, m=markets
    )
    if fam is None:
        raise AuthoringError(404, "NOT_FOUND", "Not found or not available to you")
    open_v = _one(
        db,
        "SELECT version_label, status FROM script_version WHERE script_family_id = :f AND status = ANY(:s)",
        f=family_id,
        s=list(OPEN_STATUSES),
    )
    if open_v:
        raise AuthoringError(
            409,
            "OPEN_VERSION_EXISTS",
            f"v{open_v['version_label']} is still {open_v['status'].replace('_', ' ').lower()}; finish it first",
        )
    base = None
    if base_id is not None:
        base = _one(db, "SELECT * FROM script_version WHERE id = :v AND script_family_id = :f", v=base_id, f=family_id)
        if base is None:
            raise AuthoringError(422, "INVALID_BASE", "The base version is not in this family")
    else:
        base = _one(
            db,
            "SELECT * FROM script_version WHERE script_family_id = :f AND status = 'PUBLISHED' "
            "ORDER BY published_at DESC LIMIT 1",
            f=family_id,
        )
    return _new_version(db, family_id, base, actor_ref, actor_name)


# ---- sections and modules ---------------------------------------------------------------------------------------
def _insert_section(
    db: Session, vid: uuid.UUID, module_id: uuid.UUID, position: int, cond: Any, actor_ref: str
) -> uuid.UUID:
    import json

    sid = uuid.uuid4()
    p = _prov(actor_ref, f"section:{vid}:{position}")
    db.execute(
        text(
            "INSERT INTO script_section (id, script_version_id, script_module_id, position, inclusion_condition, "
            "source_type, source_system, source_reference, source_observed_at, recorded_at, is_synthetic, created_by) "
            "VALUES (:id, :v, :m, :pos, CAST(:c AS jsonb), :source_type, :source_system, :source_reference, "
            ":source_observed_at, :recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": sid,
            "v": vid,
            "m": module_id,
            "pos": position,
            "c": json.dumps(cond) if cond is not None else None,
            **p,
        },
    )
    return sid


def _section(db: Session, vid: uuid.UUID, section_id: uuid.UUID) -> dict[str, Any]:
    s = _one(
        db,
        "SELECT s.*, m.code AS module_code, m.revision AS module_revision, m.status AS module_status, m.name AS "
        "module_name, m.kind AS module_kind FROM script_section s JOIN script_module m ON m.id = s.script_module_id "
        "WHERE s.id = :s AND s.script_version_id = :v",
        s=section_id,
        v=vid,
    )
    if s is None:
        raise AuthoringError(404, "NOT_FOUND", "Section not found in this draft")
    return s


def _new_module(db: Session, code: str, revision: int, kind: str, name: str, actor_ref: str) -> uuid.UUID:
    mid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO script_module (id, code, revision, kind, status, name, source_type, source_system, "
            "source_reference, source_observed_at, recorded_at, is_synthetic, created_by) VALUES (:id, :code, :rev, "
            ":kind, 'DRAFT', :name, :source_type, :source_system, :source_reference, :source_observed_at, "
            ":recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": mid,
            "code": code,
            "rev": revision,
            "kind": kind,
            "name": name,
            **_prov(actor_ref, f"module:{code}:{revision}"),
        },
    )
    return mid


def _insert_mq(
    db: Session, module_id: uuid.UUID, revision_id: uuid.UUID, position: int, branch: Any, actor_ref: str
) -> uuid.UUID:
    import json

    mqid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO module_question (id, script_module_id, question_revision_id, position, branch_condition, "
            "source_type, source_system, source_reference, source_observed_at, recorded_at, is_synthetic, created_by) "
            "VALUES (:id, :m, :q, :pos, CAST(:b AS jsonb), :source_type, :source_system, :source_reference, "
            ":source_observed_at, :recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": mqid,
            "m": module_id,
            "q": revision_id,
            "pos": position,
            "b": json.dumps(branch) if branch is not None else None,
            **_prov(actor_ref, f"module-question:{module_id}:{position}"),
        },
    )
    return mqid


def _owned_module(db: Session, v: dict[str, Any], section: dict[str, Any], actor_ref: str) -> uuid.UUID:
    """The section's module as a DRAFT owned by this draft: copy-on-write when it is published."""
    if section["module_status"] == "DRAFT":
        return uuid.UUID(str(section["script_module_id"]))
    rev = db.execute(
        text("SELECT max(revision) FROM script_module WHERE code = :c"), {"c": section["module_code"]}
    ).scalar_one()
    mid = _new_module(
        db, section["module_code"], int(rev) + 1, section["module_kind"], section["module_name"], actor_ref
    )
    for q in _all(
        db, "SELECT * FROM module_question WHERE script_module_id = :m ORDER BY position", m=section["script_module_id"]
    ):
        _insert_mq(db, mid, q["question_revision_id"], q["position"], q["branch_condition"], actor_ref)
    db.execute(
        text(
            "UPDATE script_section SET script_module_id = :m, updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE id = :s"
        ),
        {"m": mid, "by": actor_ref, "s": section["id"]},
    )
    section.update(script_module_id=mid, module_status="DRAFT", module_revision=int(rev) + 1)
    return mid


def add_section(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    *,
    module_id: uuid.UUID | None,
    code: str | None,
    name: str | None,
    kind: str | None,
    condition: Any,
) -> int:
    v = _editable(db, vid, markets, rv)
    _require_condition(condition, "inclusion condition")
    if module_id is not None:
        m = _one(db, "SELECT * FROM script_module WHERE id = :m", m=module_id)
        if m is None or m["status"] != "PUBLISHED":
            raise AuthoringError(422, "INVALID_MODULE", "Only a published module can be reused")
        target, label = m["id"], f"{m['code']} r{m['revision']}"
    else:
        code = (code or "").strip().upper()
        if not CODE_RE.match(code):
            raise AuthoringError(422, "INVALID_CODE", "Module code: 3–40 capital letters, digits, '_' or '-'")
        if _one(db, "SELECT 1 FROM script_module WHERE code = :c", c=code):
            raise AuthoringError(409, "CODE_IN_USE", f"Module {code} exists; reuse it or choose another code")
        if kind not in MODULE_KINDS:
            raise AuthoringError(422, "INVALID_KIND", f"Module kind must be one of {', '.join(MODULE_KINDS)}")
        if not name or not 3 <= len(name.strip()) <= 120:
            raise AuthoringError(422, "INVALID_NAME", "Module name must be 3–120 characters")
        target, label = _new_module(db, code, 1, kind, name.strip(), actor_ref), code
    if _one(
        db,
        "SELECT 1 FROM script_section s JOIN script_module m ON m.id = s.script_module_id "
        "WHERE s.script_version_id = :v AND m.code = (SELECT code FROM script_module WHERE id = :t)",
        v=vid,
        t=target,
    ):
        raise AuthoringError(409, "MODULE_ALREADY_IN_VERSION", "This module is already a section of the draft")
    pos = db.execute(
        text("SELECT coalesce(max(position), 0) + 1 FROM script_section WHERE script_version_id = :v"), {"v": vid}
    ).scalar_one()
    _insert_section(db, vid, target, pos, condition, actor_ref)
    if module_id is not None:  # reused questions bring their published control links as this draft's own
        for item in db.execute(
            text(
                "SELECT DISTINCT qr.question_bank_item_id FROM module_question mq JOIN question_revision qr "
                "ON qr.id = mq.question_revision_id WHERE mq.script_module_id = :m"
            ),
            {"m": target},
        ).scalars():
            _copy_question_links(db, vid, item, actor_ref)
    return _touch(db, v, actor_ref, actor_name, "SECTION_ADDED", {"module": label, "position": pos})


def update_section(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    section_id: uuid.UUID,
    *,
    condition: Any,
    name: str | None,
) -> int:
    import json

    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    _require_condition(condition, "inclusion condition")
    changes: dict[str, Any] = {}
    if condition != s["inclusion_condition"]:
        db.execute(
            text(
                "UPDATE script_section SET inclusion_condition = CAST(:c AS jsonb), updated_at = now(), updated_by = "
                ":by, "
                "row_version = row_version + 1 WHERE id = :s"
            ),
            {"c": json.dumps(condition) if condition is not None else None, "by": actor_ref, "s": section_id},
        )
        changes["inclusion_condition"] = {"before": s["inclusion_condition"], "after": condition}
    if name is not None and name.strip() != s["module_name"]:
        if not 3 <= len(name.strip()) <= 120:
            raise AuthoringError(422, "INVALID_NAME", "Module name must be 3–120 characters")
        mid = _owned_module(db, v, s, actor_ref)
        db.execute(
            text(
                "UPDATE script_module SET name = :n, updated_at = now(), updated_by = :by, row_version = row_version "
                "+ 1 "
                "WHERE id = :m"
            ),
            {"n": name.strip(), "by": actor_ref, "m": mid},
        )
        changes["module_name"] = {"before": s["module_name"], "after": name.strip()}
    if not changes:
        return int(v["row_version"])
    return _touch(db, v, actor_ref, actor_name, "SECTION_CHANGED", {"module": s["module_code"], "changes": changes})


def remove_section(
    db: Session, vid: uuid.UUID, markets: list[str], rv: int, actor_ref: str, actor_name: str, section_id: uuid.UUID
) -> int:
    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    db.execute(text("DELETE FROM script_section WHERE id = :s"), {"s": section_id})
    if s["module_status"] == "DRAFT":  # an unpublished module created for this draft goes with it
        db.execute(text("DELETE FROM module_question WHERE script_module_id = :m"), {"m": s["script_module_id"]})
        db.execute(text("DELETE FROM script_module WHERE id = :m"), {"m": s["script_module_id"]})
    _repack(db, "script_section", "script_version_id", vid)
    return _touch(
        db, v, actor_ref, actor_name, "SECTION_REMOVED", {"module": s["module_code"], "position": s["position"]}
    )


def _repack(db: Session, table: str, parent_col: str, parent: uuid.UUID, order: list[uuid.UUID] | None = None) -> None:
    rows = _all(db, f"SELECT id FROM {table} WHERE {parent_col} = :p ORDER BY position", p=parent)  # noqa: S608
    ids = [r["id"] for r in rows]
    if order is not None:
        if sorted(map(str, order)) != sorted(map(str, ids)):
            raise AuthoringError(422, "INVALID_ORDER", "The new order must list every item exactly once")
        ids = order
    for i, rid in enumerate(ids, start=1):  # two passes keep (parent, position) unique throughout
        db.execute(text(f"UPDATE {table} SET position = :p WHERE id = :i"), {"p": -i, "i": rid})  # noqa: S608
    for i, rid in enumerate(ids, start=1):
        db.execute(text(f"UPDATE {table} SET position = :p WHERE id = :i"), {"p": i, "i": rid})  # noqa: S608


def reorder_sections(
    db: Session, vid: uuid.UUID, markets: list[str], rv: int, actor_ref: str, actor_name: str, order: list[uuid.UUID]
) -> int:
    v = _editable(db, vid, markets, rv)
    before = [
        r["code"]
        for r in _all(
            db,
            "SELECT m.code FROM script_section s JOIN script_module m ON m.id = s.script_module_id "
            "WHERE s.script_version_id = :v ORDER BY s.position",
            v=vid,
        )
    ]
    _repack(db, "script_section", "script_version_id", vid, order)
    after = [
        r["code"]
        for r in _all(
            db,
            "SELECT m.code FROM script_section s JOIN script_module m ON m.id = s.script_module_id "
            "WHERE s.script_version_id = :v ORDER BY s.position",
            v=vid,
        )
    ]
    return _touch(db, v, actor_ref, actor_name, "SECTIONS_REORDERED", {"before": before, "after": after})


# ---- questions --------------------------------------------------------------------------------------------------
def _latest_revision(db: Session, item_id: uuid.UUID) -> dict[str, Any] | None:
    """The latest *published* English revision of a question: the only content another draft may reuse. Revisions
    that exist only inside some draft are never offered to other drafts (S2-A.1 draft isolation)."""
    return _one(
        db,
        f"{REV_SQL} WHERE qr.question_bank_item_id = :i AND qr.language = 'en' AND {PUBLISHED_REVISION_SQL} "
        "ORDER BY qr.revision DESC LIMIT 1",
        i=item_id,
    )


def _revision(db: Session, revision_id: uuid.UUID) -> dict[str, Any]:
    r = _one(db, f"{REV_SQL} WHERE qr.id = :r", r=revision_id)
    assert r is not None
    return r


def _insert_revision(
    db: Session, item_id: uuid.UUID, content: dict[str, Any], actor_ref: str, reason: str | None
) -> uuid.UUID:
    import json

    rev = db.execute(
        text(
            "SELECT coalesce(max(revision), 0) + 1 FROM question_revision WHERE question_bank_item_id = :i AND "
            "language = 'en'"
        ),
        {"i": item_id},
    ).scalar_one()
    rid = uuid.uuid4()
    p = _prov(actor_ref, f"question-revision:{item_id}:{rev}")
    p["source_reference"] = (p["source_reference"] + (f":{reason}" if reason else ""))[:160]
    j = json.dumps
    db.execute(
        text(
            "INSERT INTO question_revision (id, question_bank_item_id, revision, language, customer_wording, "
            "delivery_mode, answer_type, answer_schema, mandatory, expected_answer_policy, expected_value, "
            "acceptable_variants, policy_fact_key, unacceptable_outcomes, not_applicable_predicate, evidence_required, "
            "escalation_rule_ref, max_reprompts, content_approval_status, source_type, source_system, "
            "source_reference, "
            "source_observed_at, recorded_at, is_synthetic, created_by) VALUES (:id, :item, :rev, 'en', :w, :mode, "
            ":atype, CAST(:schema AS jsonb), :mand, :policy, CAST(:exp AS jsonb), CAST(:acc AS jsonb), :fact, "
            "CAST(:unacc AS jsonb), CAST(:na AS jsonb), :evid, :esc, :rep, 'SYNTHETIC_UNAPPROVED', :source_type, "
            ":source_system, :source_reference, :source_observed_at, :recorded_at, :is_synthetic, :created_by)"
        ),
        {
            "id": rid,
            "item": item_id,
            "rev": rev,
            "w": content["customer_wording"],
            "mode": content["delivery_mode"],
            "atype": content["answer_type"],
            "schema": j(content["answer_schema"]),
            "mand": content["mandatory"],
            "policy": content["expected_answer_policy"],
            "exp": j(content["expected_value"]) if content["expected_value"] is not None else None,
            "acc": j(content["acceptable_variants"]),
            "fact": content["policy_fact_key"],
            "unacc": j(content["unacceptable_outcomes"]),
            "na": j(content["not_applicable_predicate"]) if content["not_applicable_predicate"] is not None else None,
            "evid": content["evidence_required"],
            "esc": content["escalation_rule_ref"],
            "rep": content["max_reprompts"],
            **p,
        },
    )
    db.execute(
        text(
            "INSERT INTO question_revision_detail (question_revision_id, intent, category, created_by) "
            "VALUES (:r, :i, :c, :by)"
        ),
        {"r": rid, "i": content["intent"], "c": content["category"], "by": actor_ref},
    )
    return rid


def _revision_content(r: dict[str, Any]) -> dict[str, Any]:
    """Comparable content of a revision row selected with ``REV_SQL``."""
    out = {f: r[f] for f in REVISION_FIELDS if f not in ("intent", "category")}
    out["intent"], out["category"] = r["rev_intent"], r["rev_category"]
    return out


def add_question(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    section_id: uuid.UUID,
    *,
    question_code: str,
    content: dict[str, Any] | None,
    branch: Any,
    reason: str | None,
) -> int:
    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    code = question_code.strip().upper()
    if not QUESTION_CODE_RE.match(code):
        raise AuthoringError(422, "INVALID_CODE", "Question code: 'Q-' then 3–57 capital letters, digits, '_' or '-'")
    _require_condition(branch, "asked-when condition")
    if _one(
        db,
        "SELECT 1 FROM script_section s JOIN module_question mq ON mq.script_module_id = s.script_module_id "
        "JOIN question_revision qr ON qr.id = mq.question_revision_id JOIN question_bank_item i "
        "ON i.id = qr.question_bank_item_id WHERE s.script_version_id = :v AND i.question_code = :c",
        v=vid,
        c=code,
    ):
        raise AuthoringError(409, "QUESTION_ALREADY_IN_VERSION", f"{code} is already in this draft")
    item = _one(db, "SELECT * FROM question_bank_item WHERE question_code = :c", c=code)
    if item is None:
        if content is None:
            raise AuthoringError(404, "UNKNOWN_QUESTION", f"{code} is not in the question bank; provide its content")
        clean = normalise_question(content)
        item_id = uuid.uuid4()
        db.execute(
            text(
                "INSERT INTO question_bank_item (id, question_code, intent, category, source_type, source_system, "
                "source_reference, source_observed_at, recorded_at, is_synthetic, created_by) VALUES (:id, :c, "
                ":intent, "
                ":cat, :source_type, :source_system, :source_reference, :source_observed_at, :recorded_at, "
                ":is_synthetic, :created_by)"
            ),
            {
                "id": item_id,
                "c": code,
                "intent": clean["intent"],
                "cat": clean["category"],
                **_prov(actor_ref, f"question:{code}"),
            },
        )
        revision_id = _insert_revision(db, item_id, clean, actor_ref, reason)
        how = "NEW_QUESTION"
    else:
        latest = _latest_revision(db, item["id"])
        if latest is None:
            raise AuthoringError(
                409,
                "QUESTION_NOT_PUBLISHED",
                f"{code} exists only in an unpublished draft; it can be reused once a version containing it is "
                "published",
            )
        revision_id = latest["id"]
        how = "REUSED_QUESTION"
        if content is not None:
            clean = normalise_question(content)
            if clean != _revision_content(latest):
                revision_id = _insert_revision(db, item["id"], clean, actor_ref, reason)
                how = "REUSED_QUESTION_REVISED"
        _copy_question_links(db, vid, item["id"], actor_ref)
    mid = _owned_module(db, v, s, actor_ref)
    pos = db.execute(
        text("SELECT coalesce(max(position), 0) + 1 FROM module_question WHERE script_module_id = :m"), {"m": mid}
    ).scalar_one()
    _insert_mq(db, mid, revision_id, pos, branch, actor_ref)
    return _touch(
        db,
        v,
        actor_ref,
        actor_name,
        "QUESTION_ADDED",
        {"question_code": code, "module": s["module_code"], "position": pos, "how": how},
    )


def _mq(db: Session, vid: uuid.UUID, section: dict[str, Any], mq_id: uuid.UUID) -> dict[str, Any]:
    q = _one(
        db,
        "SELECT mq.*, qr.question_bank_item_id, qr.revision, i.question_code FROM module_question mq "
        "JOIN question_revision qr ON qr.id = mq.question_revision_id JOIN question_bank_item i "
        "ON i.id = qr.question_bank_item_id WHERE mq.id = :q AND mq.script_module_id = :m",
        q=mq_id,
        m=section["script_module_id"],
    )
    if q is None:
        raise AuthoringError(404, "NOT_FOUND", "Question not found in this section")
    return q


def _by_position(db: Session, module_id: uuid.UUID, position: int) -> uuid.UUID:
    return uuid.UUID(
        str(
            db.execute(
                text("SELECT id FROM module_question WHERE script_module_id = :m AND position = :p"),
                {"m": module_id, "p": position},
            ).scalar_one()
        )
    )


def update_question(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    section_id: uuid.UUID,
    mq_id: uuid.UUID,
    *,
    content: dict[str, Any],
    branch: Any,
    reason: str | None,
) -> int:
    import json

    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    q = _mq(db, vid, s, mq_id)
    _require_condition(branch, "asked-when condition")
    clean = normalise_question(content)
    item = _one(db, "SELECT * FROM question_bank_item WHERE id = :i", i=q["question_bank_item_id"])
    assert item is not None
    before = _revision_content(_revision(db, q["question_revision_id"]))
    changed = [f for f in QUESTION_FIELDS if before[f] != clean[f]]
    branch_changed = branch != q["branch_condition"]
    if not changed and not branch_changed:
        return int(v["row_version"])
    mid = _owned_module(db, v, s, actor_ref)
    target = _by_position(db, mid, q["position"]) if mid != q["script_module_id"] else mq_id
    revision_id = q["question_revision_id"]
    if changed:
        revision_id = _insert_revision(db, item["id"], clean, actor_ref, reason)
    db.execute(
        text(
            "UPDATE module_question SET question_revision_id = :r, branch_condition = CAST(:b AS jsonb), "
            "updated_at = now(), updated_by = :by, row_version = row_version + 1 WHERE id = :q"
        ),
        {"r": revision_id, "b": json.dumps(branch) if branch is not None else None, "by": actor_ref, "q": target},
    )
    return _touch(
        db,
        v,
        actor_ref,
        actor_name,
        "QUESTION_CHANGED",
        {
            "question_code": q["question_code"],
            "fields": changed + (["branch_condition"] if branch_changed else []),
            "new_revision": revision_id != q["question_revision_id"],
            "reason": reason,
        },
    )


def remove_question(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    section_id: uuid.UUID,
    mq_id: uuid.UUID,
) -> int:
    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    q = _mq(db, vid, s, mq_id)
    mid = _owned_module(db, v, s, actor_ref)
    target = _by_position(db, mid, q["position"]) if mid != q["script_module_id"] else mq_id
    db.execute(text("DELETE FROM module_question WHERE id = :q"), {"q": target})
    _repack(db, "module_question", "script_module_id", mid)
    return _touch(
        db,
        v,
        actor_ref,
        actor_name,
        "QUESTION_REMOVED",
        {"question_code": q["question_code"], "module": s["module_code"]},
    )


def reorder_questions(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    section_id: uuid.UUID,
    order: list[uuid.UUID],
) -> int:
    v = _editable(db, vid, markets, rv)
    s = _section(db, vid, section_id)
    old = _all(
        db,
        "SELECT mq.id, mq.position, i.question_code FROM module_question mq JOIN question_revision qr "
        "ON qr.id = mq.question_revision_id JOIN question_bank_item i ON i.id = qr.question_bank_item_id "
        "WHERE mq.script_module_id = :m ORDER BY mq.position",
        m=s["script_module_id"],
    )
    if sorted(map(str, order)) != sorted(str(r["id"]) for r in old):
        raise AuthoringError(422, "INVALID_ORDER", "The new order must list every question exactly once")
    codes = {str(r["id"]): r["question_code"] for r in old}
    new_codes = [codes[str(i)] for i in order]
    mid = _owned_module(db, v, s, actor_ref)  # ids differ after copy-on-write, so reorder by question code
    by_code = {
        r["question_code"]: r["id"]
        for r in _all(
            db,
            "SELECT mq.id, i.question_code FROM module_question mq JOIN question_revision qr ON qr.id = "
            "mq.question_revision_id JOIN question_bank_item i ON i.id = qr.question_bank_item_id "
            "WHERE mq.script_module_id = :m",
            m=mid,
        )
    }
    _repack(db, "module_question", "script_module_id", mid, [by_code[c] for c in new_codes])
    return _touch(
        db,
        v,
        actor_ref,
        actor_name,
        "QUESTIONS_REORDERED",
        {"module": s["module_code"], "before": [r["question_code"] for r in old], "after": new_codes},
    )


def _link_source(version: dict[str, Any]) -> str:
    """Where a version's control links live: its own rows (drafts and every Script Studio version, S2-A.1), its frozen
    manifest (submitted and later Script Studio content) or, for seeded S0 versions, the concept-level library."""
    if version["status"] in ROW_LINK_STATUSES:
        return "ROWS"
    if (version.get("manifest") or {}).get("schema") == MANIFEST_SCHEMA:
        return "MANIFEST"
    if version.get("source_system") == SOURCE_SYSTEM:
        return "ROWS"
    return "LIBRARY"


def link_rows(
    db: Session, version: dict[str, Any], item_ids: list[uuid.UUID] | None = None, *, source: str | None = None
) -> list[dict[str, Any]]:
    """A version's active control links as ``{item_id, control_id, ref_id, rationale, status}``."""
    src = source or _link_source(version)
    if src == "ROWS":
        rows = _all(
            db,
            "SELECT question_bank_item_id AS item_id, control_id, regulatory_reference_id AS ref_id, rationale, status "
            "FROM script_version_control_link WHERE script_version_id = :v AND status <> 'RETIRED'",
            v=version["id"],
        )
    elif src == "MANIFEST":
        rev_items = {
            str(r["id"]): r["question_bank_item_id"]
            for r in _all(
                db,
                "SELECT id, question_bank_item_id FROM question_revision WHERE id = ANY(:r)",
                r=[uuid.UUID(x) for x in version["manifest"].get("question_revision_ids", [])],
            )
        }
        codes = {r["control_code"]: r["id"] for r in _all(db, "SELECT id, control_code FROM control")}
        rows = []
        for sec in version["manifest"]["sections"]:
            for q in sec["questions"]:
                for c in q.get("controls", []):
                    ref = c.get("regulatory_reference")
                    rows.append(
                        {
                            "item_id": rev_items.get(q["question_revision_id"]),
                            "control_id": codes.get(c["control_code"]),
                            "ref_id": uuid.UUID(ref["id"]) if ref else None,
                            "rationale": c["rationale"],
                            "status": c["mapping_status"],
                        }
                    )
    else:
        rows = _all(
            db,
            "SELECT question_bank_item_id AS item_id, control_id, regulatory_reference_id AS ref_id, rationale, status "
            "FROM control_mapping WHERE status <> 'RETIRED'",
        )
    wanted = {str(i) for i in item_ids} if item_ids is not None else None
    return [r for r in rows if r["control_id"] and (wanted is None or str(r["item_id"]) in wanted)]


def _insert_link(db: Session, vid: uuid.UUID, link: dict[str, Any], origin: str, actor_ref: str, what: str) -> None:
    db.execute(
        text(
            "INSERT INTO script_version_control_link (id, script_version_id, question_bank_item_id, control_id, "
            "regulatory_reference_id, rationale, status, copied_from, created_by, source_type, source_system, "
            "source_reference, source_observed_at, recorded_at, is_synthetic) VALUES (:id, :v, :i, :c, :r, :ra, "
            "'PROPOSED', :o, :created_by, :source_type, :source_system, :source_reference, :source_observed_at, "
            ":recorded_at, :is_synthetic) ON CONFLICT DO NOTHING"
        ),
        {
            "id": uuid.uuid4(),
            "v": vid,
            "i": link["item_id"],
            "c": link["control_id"],
            "r": link["ref_id"],
            "ra": link["rationale"],
            "o": origin,
            **_prov(actor_ref, f"control-link:{what}"),
        },
    )


def _copy_question_links(db: Session, vid: uuid.UUID, item_id: uuid.UUID, actor_ref: str) -> None:
    """A question entering a draft brings the links of its latest published version (or, for a seeded question
    never republished, the concept library) as the draft's own proposals — unless the draft already has some."""
    if _one(
        db,
        "SELECT 1 FROM script_version_control_link WHERE script_version_id = :v AND question_bank_item_id = :i "
        "AND status <> 'RETIRED'",
        v=vid,
        i=item_id,
    ):
        return
    pub = _one(
        db,
        "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "JOIN script_section s ON s.script_version_id = v.id JOIN module_question mq "
        "ON mq.script_module_id = s.script_module_id JOIN question_revision qr ON qr.id = mq.question_revision_id "
        "WHERE qr.question_bank_item_id = :i AND v.status = 'PUBLISHED' ORDER BY v.published_at DESC LIMIT 1",
        i=item_id,
    )
    if pub is not None:
        rows, origin = link_rows(db, pub, [item_id]), "PUBLISHED_QUESTION"
    else:
        rows, origin = (
            link_rows(db, {"id": None, "status": "PUBLISHED"}, [item_id], source="LIBRARY"),
            ("CONCEPT_LIBRARY"),
        )
    for r in rows:
        _insert_link(db, vid, r, origin, actor_ref, str(item_id))


def set_controls(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    rv: int,
    actor_ref: str,
    actor_name: str,
    question_code: str,
    links: list[dict[str, Any]],
) -> int:
    """Link a question in **this draft** to existing controls (and optionally a regulatory reference). The links are
    the draft's own rows (S2-A.1): other drafts, seeded versions and the concept library are not changed. New links
    are PROPOSED; removed links are RETIRED (rows are never deleted). Submission freezes them into the manifest."""
    v = _editable(db, vid, markets, rv)
    item = _one(
        db,
        "SELECT i.* FROM question_bank_item i JOIN question_revision qr ON qr.question_bank_item_id = i.id "
        "JOIN module_question mq ON mq.question_revision_id = qr.id JOIN script_section s "
        "ON s.script_module_id = mq.script_module_id WHERE s.script_version_id = :v AND i.question_code = :c LIMIT 1",
        v=vid,
        c=question_code,
    )
    if item is None:
        raise AuthoringError(404, "NOT_FOUND", f"{question_code} is not in this draft")
    wanted: dict[tuple[str, str | None], str] = {}
    for link in links:
        ctl = _one(db, "SELECT id, control_code FROM control WHERE id = :c", c=link["control_id"])
        if ctl is None:
            raise AuthoringError(422, "UNKNOWN_CONTROL", "Unknown control")
        ref = link.get("regulatory_reference_id")
        if ref is not None and not _one(
            db, "SELECT 1 FROM regulatory_reference WHERE id = :r AND market_code = ANY(:m)", r=ref, m=markets
        ):
            raise AuthoringError(422, "UNKNOWN_REFERENCE", "Unknown regulatory reference")
        rationale = (link.get("rationale") or "").strip()
        if not 5 <= len(rationale) <= 500:
            raise AuthoringError(422, "INVALID_RATIONALE", "Each link needs a rationale of 5–500 characters")
        wanted[(str(ctl["id"]), str(ref) if ref else None)] = rationale
    current = _all(
        db,
        "SELECT * FROM script_version_control_link WHERE script_version_id = :v AND question_bank_item_id = :i "
        "AND status <> 'RETIRED'",
        v=vid,
        i=item["id"],
    )
    have = {
        (str(c["control_id"]), str(c["regulatory_reference_id"]) if c["regulatory_reference_id"] else None): c
        for c in current
    }
    added, retired = [], []
    for key, row in have.items():
        if key not in wanted:
            db.execute(
                text(
                    "UPDATE script_version_control_link SET status = 'RETIRED', updated_at = now(), updated_by = :by, "
                    "row_version = row_version + 1 WHERE id = :i"
                ),
                {"by": actor_ref, "i": row["id"]},
            )
            retired.append(key[0])
    for key, rationale in wanted.items():
        if key not in have:
            _insert_link(
                db,
                vid,
                {"item_id": item["id"], "control_id": key[0], "ref_id": key[1], "rationale": rationale},
                "AUTHOR",
                actor_ref,
                question_code,
            )
            added.append(key[0])
    if not added and not retired:
        return int(v["row_version"])
    return _touch(
        db,
        v,
        actor_ref,
        actor_name,
        "CONTROLS_CHANGED",
        {"question_code": question_code, "added": len(added), "retired": len(retired)},
    )


# ---- manifest, validation, diff ---------------------------------------------------------------------------------
def format_controls(db: Session, rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Link rows → manifest control entries, grouped by question bank item id."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not rows:
        return out
    ctl = {
        r["id"]: r
        for r in _all(
            db, "SELECT id, control_code, name FROM control WHERE id = ANY(:c)", c=[r["control_id"] for r in rows]
        )
    }
    refs = {
        r["id"]: r
        for r in _all(
            db,
            "SELECT id, title, document_version, interpretation_status FROM regulatory_reference WHERE id = ANY(:r)",
            r=[r["ref_id"] for r in rows if r["ref_id"]],
        )
    }
    for r in rows:
        c = ctl[r["control_id"]]
        ref = refs.get(r["ref_id"]) if r["ref_id"] else None
        out.setdefault(str(r["item_id"]), []).append(
            {
                "control_code": c["control_code"],
                "control_name": c["name"],
                "rationale": r["rationale"],
                "mapping_status": r["status"],
                "regulatory_reference": {
                    "id": str(ref["id"]),
                    "title": ref["title"],
                    "document_version": ref["document_version"],
                    "interpretation_status": ref["interpretation_status"],
                }
                if ref
                else None,
            }
        )
    for v in out.values():
        v.sort(key=lambda x: (x["control_code"], (x["regulatory_reference"] or {}).get("title") or ""))
    return out


def build_manifest(db: Session, version: dict[str, Any]) -> dict[str, Any]:
    """The full, reproducible content of a version from its rows (questions snapshotted with their controls)."""
    sections = _all(
        db,
        "SELECT s.position, s.inclusion_condition, m.id AS module_id, m.code, m.revision, m.name, m.kind "
        "FROM script_section s JOIN script_module m ON m.id = s.script_module_id WHERE s.script_version_id = :v "
        "ORDER BY s.position",
        v=version["id"],
    )
    qrows = _all(
        db,
        "SELECT mq.script_module_id, mq.position, mq.branch_condition, i.id AS item_id, i.question_code, "
        "coalesce(d.intent, i.intent) AS intent, coalesce(d.category, i.category) AS category, qr.* "
        "FROM module_question mq JOIN question_revision qr ON qr.id = mq.question_revision_id "
        "JOIN question_bank_item i ON i.id = qr.question_bank_item_id LEFT JOIN question_revision_detail d "
        "ON d.question_revision_id = qr.id WHERE mq.script_module_id = ANY(:m) ORDER BY mq.position",
        m=[s["module_id"] for s in sections],
    )
    item_ids = list({q["item_id"] for q in qrows})
    src = "ROWS" if version["status"] in ROW_LINK_STATUSES or version.get("source_system") == SOURCE_SYSTEM else None
    controls = format_controls(db, link_rows(db, version, item_ids, source=src or "LIBRARY"))
    out_sections, ids = [], []
    for s in sections:
        qs = []
        for q in (q for q in qrows if q["script_module_id"] == s["module_id"]):
            qs.append(
                {
                    "question_code": q["question_code"],
                    "question_revision_id": str(q["id"]),
                    "revision": q["revision"],
                    "position": q["position"],
                    "intent": q["intent"],
                    "category": q["category"],
                    "customer_wording": q["customer_wording"],
                    "delivery_mode": q["delivery_mode"],
                    "answer_type": q["answer_type"],
                    "answer_schema": q["answer_schema"],
                    "mandatory": q["mandatory"],
                    "expected_answer_policy": q["expected_answer_policy"],
                    "expected_value": q["expected_value"],
                    "acceptable_variants": q["acceptable_variants"],
                    "unacceptable_outcomes": q["unacceptable_outcomes"],
                    "policy_fact_key": q["policy_fact_key"],
                    "not_applicable_predicate": q["not_applicable_predicate"],
                    "evidence_required": q["evidence_required"],
                    "escalation_rule_ref": q["escalation_rule_ref"],
                    "max_reprompts": q["max_reprompts"],
                    "branch_condition": q["branch_condition"],
                    "content_approval_status": q["content_approval_status"],
                    "controls": controls.get(str(q["item_id"]), []),
                }
            )
            ids.append(str(q["id"]))
        out_sections.append(
            {
                "module_code": s["code"],
                "module_revision": s["revision"],
                "module_id": str(s["module_id"]),
                "module_name": s["name"],
                "module_kind": s["kind"],
                "position": s["position"],
                "inclusion_condition": s["inclusion_condition"],
                "questions": qs,
            }
        )
    return {
        "schema": MANIFEST_SCHEMA,
        "family": version["family"],
        "version_label": version["version_label"],
        "language": version["language"],
        "content_approval_status": version["content_approval_status"],
        "sections": out_sections,
        "question_revision_ids": ids,
    }


def content_of(db: Session, version: dict[str, Any]) -> dict[str, Any]:
    """A comparable view of any version: its frozen manifest (S0 manifests enriched from the immutable question
    revisions) or, for a draft, the live rows."""
    m = version.get("manifest")
    if version["status"] == "DRAFT" or not m:
        return build_manifest(db, version)
    if m.get("schema") == MANIFEST_SCHEMA:
        return dict(m)
    # An S0 manifest lists the same immutable question revisions and published modules the rows hold; it did not
    # freeze question text or control links, so those come from the (immutable) revisions and current mappings.
    return build_manifest(db, version)


def validate(db: Session, version: dict[str, Any]) -> list[dict[str, Any]]:
    m = build_manifest(db, version)
    issues: list[dict[str, Any]] = []

    def add(sev: str, code: str, msg: str, **loc: Any) -> None:
        issues.append({"severity": sev, "code": code, "message": msg, **loc})

    if not m["sections"]:
        add("ERROR", "NO_SECTIONS", "Add at least one section")
    seen_codes: dict[str, str] = {}
    mandatory = 0
    for s in m["sections"]:
        where = {"module_code": s["module_code"]}
        for p in check_condition(s["inclusion_condition"], "inclusion condition"):
            add("ERROR", "INVALID_CONDITION", p, **where)
        if not s["questions"]:
            add("ERROR", "EMPTY_SECTION", f"Section {s['module_code']} has no questions", **where)
        if s["module_kind"] == "COMMON" and s["inclusion_condition"] is not None:
            add(
                "WARNING", "COMMON_CONDITIONAL", f"Common module {s['module_code']} applies only conditionally", **where
            )
        for q in s["questions"]:
            loc = {**where, "question_code": q["question_code"]}
            if q["question_code"] in seen_codes:
                add(
                    "ERROR",
                    "DUPLICATE_QUESTION",
                    f"{q['question_code']} appears in {seen_codes[q['question_code']]} and {s['module_code']}",
                    **loc,
                )
            seen_codes[q["question_code"]] = s["module_code"]
            mandatory += q["mandatory"]
            try:
                normalise_question(
                    {
                        **q,
                        "enum_options": (q["answer_schema"] or {}).get("enum"),
                        "expected_boolean": (q["expected_value"] or {}).get("value"),
                    }
                )
            except AuthoringError as exc:
                add("ERROR", "INVALID_QUESTION", f"{q['question_code']}: {exc.message}", **loc)
            for p in check_condition(q["branch_condition"], "asked-when condition"):
                add("ERROR", "INVALID_CONDITION", f"{q['question_code']}: {p}", **loc)
            if q["delivery_mode"] == "EXACT_AUDIO":
                add(
                    "WARNING",
                    "EXACT_AUDIO_ASSET",
                    f"{q['question_code']}: exact-audio delivery needs an approved audio "
                    "asset, which cannot be attached yet (SCR-019)",
                    **loc,
                )
            if q["mandatory"] and not q["controls"]:
                add("WARNING", "NO_CONTROL", f"{q['question_code']} is mandatory but linked to no control", **loc)
            if q["mandatory"] and q["expected_answer_policy"] == "COLLECT_ONLY":
                add(
                    "WARNING",
                    "MANDATORY_COLLECT_ONLY",
                    f"{q['question_code']} is mandatory with no expected-answer check",
                    **loc,
                )
    if m["sections"] and not mandatory:
        add("WARNING", "NO_MANDATORY", "The script has no mandatory question")
    return issues


def record_validation(
    db: Session, version: dict[str, Any], issues: list[dict[str, Any]], actor_ref: str, actor_name: str
) -> str:
    status = "INVALID" if any(i["severity"] == "ERROR" for i in issues) else "VALID"
    db.execute(
        text("UPDATE script_version SET validation_status = :s WHERE id = :i"), {"s": status, "i": version["id"]}
    )
    add_event(
        db,
        version["id"],
        "VALIDATED",
        actor_ref,
        actor_name,
        details={
            "result": status,
            "errors": sum(i["severity"] == "ERROR" for i in issues),
            "warnings": sum(i["severity"] == "WARNING" for i in issues),
        },
    )
    return status


DIFF_FIELDS = (
    "customer_wording",
    "intent",
    "category",
    "delivery_mode",
    "answer_type",
    "answer_schema",
    "mandatory",
    "expected_answer_policy",
    "expected_value",
    "acceptable_variants",
    "unacceptable_outcomes",
    "policy_fact_key",
    "not_applicable_predicate",
    "evidence_required",
    "escalation_rule_ref",
    "max_reprompts",
    "branch_condition",
)


def diff(base: dict[str, Any] | None, target: dict[str, Any]) -> dict[str, Any]:
    """Semantic diff: sections and questions added, removed, moved or changed (with field-level before/after)."""
    bs = {s["module_code"]: s for s in (base or {}).get("sections", [])}
    ts = {s["module_code"]: s for s in target["sections"]}
    sections = []
    for code in list(bs) + [c for c in ts if c not in bs]:
        b, t = bs.get(code), ts.get(code)
        if b and not t:
            sections.append(
                {
                    "module_code": code,
                    "change": "REMOVED",
                    "from_position": b["position"],
                    "to_position": None,
                    "fields": [],
                }
            )
        elif t and not b:
            sections.append(
                {
                    "module_code": code,
                    "change": "ADDED",
                    "from_position": None,
                    "to_position": t["position"],
                    "fields": [],
                }
            )
        else:
            assert b and t
            fields = [
                {"field": f, "before": b.get(f), "after": t.get(f)}
                for f in ("inclusion_condition", "module_name", "module_kind", "module_revision")
                if b.get(f) != t.get(f)
            ]
            change = "CHANGED" if fields else ("MOVED" if b["position"] != t["position"] else "UNCHANGED")
            sections.append(
                {
                    "module_code": code,
                    "change": change,
                    "from_position": b["position"],
                    "to_position": t["position"],
                    "fields": fields,
                }
            )
    bq = {q["question_code"]: (s["module_code"], q) for s in (base or {}).get("sections", []) for q in s["questions"]}
    tq = {q["question_code"]: (s["module_code"], q) for s in target["sections"] for q in s["questions"]}
    questions = []
    for code in list(bq) + [c for c in tq if c not in bq]:
        b, t = bq.get(code), tq.get(code)
        if b and not t:
            questions.append(
                {
                    "question_code": code,
                    "change": "REMOVED",
                    "from_module": b[0],
                    "to_module": None,
                    "from_position": b[1]["position"],
                    "to_position": None,
                    "fields": [],
                }
            )
            continue
        if t and not b:
            questions.append(
                {
                    "question_code": code,
                    "change": "ADDED",
                    "from_module": None,
                    "to_module": t[0],
                    "from_position": None,
                    "to_position": t[1]["position"],
                    "fields": [{"field": "customer_wording", "before": None, "after": t[1]["customer_wording"]}],
                }
            )
            continue
        assert b and t
        fields = [
            {"field": f, "before": b[1].get(f), "after": t[1].get(f)} for f in DIFF_FIELDS if b[1].get(f) != t[1].get(f)
        ]
        bc = sorted(c["control_code"] for c in b[1].get("controls", []))
        tc = sorted(c["control_code"] for c in t[1].get("controls", []))
        if bc != tc:
            fields.append({"field": "controls", "before": bc, "after": tc})
        moved = b[0] != t[0] or b[1]["position"] != t[1]["position"]
        if any(f["field"] == "customer_wording" for f in fields):
            change = "REWORDED"
        elif fields:
            change = "CHANGED"
        else:
            change = "MOVED" if moved else "UNCHANGED"
        questions.append(
            {
                "question_code": code,
                "change": change,
                "from_module": b[0],
                "to_module": t[0],
                "from_position": b[1]["position"],
                "to_position": t[1]["position"],
                "fields": fields,
                "moved": moved,
            }
        )
    summary: dict[str, int] = {}
    for q in questions:
        summary[q["change"]] = summary.get(q["change"], 0) + 1
    return {"sections": sections, "questions": questions, "summary": summary}


# ---- lifecycle --------------------------------------------------------------------------------------------------
def submit(
    db: Session, vid: uuid.UUID, markets: list[str], rv: int, actor_ref: str, actor_name: str, change_summary: str
) -> dict[str, Any]:
    import json

    v = _editable(db, vid, markets, rv)
    if not 10 <= len(change_summary.strip()) <= 2000:
        raise AuthoringError(422, "INVALID_SUMMARY", "Describe the change (10–2000 characters) for the reviewer")
    issues = validate(db, v)
    if any(i["severity"] == "ERROR" for i in issues):
        record_validation(db, v, issues, actor_ref, actor_name)
        raise AuthoringError(
            422, "VALIDATION_FAILED", "Fix the validation errors before submitting", {"issues": issues}
        )
    manifest = build_manifest(db, v)
    sha = sha256_of(manifest)
    base = (
        _one(
            db,
            "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
            "WHERE v.id = :i",
            i=v["supersedes_id"],
        )
        if v["supersedes_id"]
        else None
    )
    d = diff(content_of(db, base), manifest) if base else diff(None, manifest)
    db.execute(
        text(
            "UPDATE script_version SET manifest = CAST(:m AS jsonb), manifest_sha256 = :h, validation_status = "
            "'VALID', "
            "status = 'SUBMITTED_FOR_REVIEW', updated_at = now(), updated_by = :by, row_version = row_version + 1 "
            "WHERE id = :i"
        ),
        {"m": json.dumps(manifest), "h": sha, "by": actor_ref, "i": vid},
    )
    add_event(
        db,
        vid,
        "SUBMITTED",
        actor_ref,
        actor_name,
        reason=change_summary.strip(),
        details={
            "manifest_sha256": sha,
            "warnings": len(issues),
            "diff_summary": d["summary"],
            "base": base["version_label"] if base else None,
        },
    )
    return {"manifest_sha256": sha, "issues": issues}


def unmapped_mandatory(content: dict[str, Any]) -> list[str]:
    """Mandatory questions with no control link: flagged for, and acknowledged by, the checker (S2-A.1)."""
    return [
        q["question_code"]
        for sec in content.get("sections", [])
        for q in sec["questions"]
        if q["mandatory"] and not q.get("controls")
    ]


def abandon(
    db: Session, vid: uuid.UUID, markets: list[str], rv: int, actor_ref: str, actor_name: str, reason: str
) -> None:
    """Abandon a draft (S2-A.1): DRAFT → ABANDONED with a reason. Only someone who authored or edited the draft may
    abandon it. Nothing is deleted; the content, links and history stay readable and frozen, and the family can start
    a new draft."""
    v = _editable(db, vid, markets, rv)
    if actor_ref not in makers(db, vid, v["author_ref"]):
        raise AuthoringError(403, "NOT_A_MAKER", "Only the author or an editor of this draft can abandon it")
    if not 5 <= len(reason.strip()) <= 2000:
        raise AuthoringError(422, "INVALID_REASON", "Give a reason (5–2000 characters)")
    db.execute(
        text(
            "UPDATE script_version SET status = 'ABANDONED', updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE id = :i"
        ),
        {"by": actor_ref, "i": vid},
    )
    sections = db.execute(
        text("SELECT count(*) FROM script_section WHERE script_version_id = :v"), {"v": vid}
    ).scalar_one()
    add_event(db, vid, "ABANDONED", actor_ref, actor_name, reason=reason.strip(), details={"sections": sections})


def review(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    actor_ref: str,
    actor_name: str,
    decision: str,
    reason: str,
    acknowledged_unmapped: list[str] | None = None,
) -> str:
    v = version_row(db, vid, markets, lock=True)
    if v["status"] != "SUBMITTED_FOR_REVIEW":
        raise AuthoringError(409, "NOT_SUBMITTED", f"v{v['version_label']} is not awaiting review")
    if actor_ref in makers(db, vid, v["author_ref"]):
        raise AuthoringError(
            403, "SELF_REVIEW_DENIED", "You authored or edited this version; another checker must review it"
        )
    if not 5 <= len(reason.strip()) <= 2000:
        raise AuthoringError(422, "INVALID_REASON", "Give a reason (5–2000 characters)")
    if decision == "APPROVE":
        if sha256_of(build_manifest(db, v)) != v["manifest_sha256"]:
            raise AuthoringError(409, "MANIFEST_MISMATCH", "The submitted content no longer matches its manifest")
        unmapped = unmapped_mandatory(v["manifest"] or {})
        if sorted(acknowledged_unmapped or []) != sorted(unmapped):
            raise AuthoringError(
                422,
                "UNMAPPED_MANDATORY_NOT_ACKNOWLEDGED",
                f"{len(unmapped)} mandatory question(s) have no mapped control; review and acknowledge each before "
                "approving",
                {"unmapped_mandatory": unmapped},
            )
        db.execute(
            text(
                "UPDATE script_version SET status = 'APPROVED', reviewer_ref = :r, updated_at = now(), updated_by = "
                ":r, "
                "row_version = row_version + 1 WHERE id = :i"
            ),
            {"r": actor_ref, "i": vid},
        )
        add_event(
            db,
            vid,
            "APPROVED",
            actor_ref,
            actor_name,
            reason=reason.strip(),
            details={"manifest_sha256": v["manifest_sha256"], "acknowledged_unmapped_mandatory": unmapped},
        )
        return "APPROVED"
    db.execute(
        text(
            "UPDATE script_version SET status = 'DRAFT', updated_at = now(), updated_by = :r, "
            "row_version = row_version + 1 WHERE id = :i"
        ),
        {"r": actor_ref, "i": vid},
    )
    # Back in DRAFT the content may change again: it must be re-validated before the next submission.
    db.execute(text("UPDATE script_version SET validation_status = 'NOT_VALIDATED' WHERE id = :i"), {"i": vid})
    add_event(db, vid, "CHANGES_REQUESTED", actor_ref, actor_name, reason=reason.strip())
    return "DRAFT"


def publish(
    db: Session,
    vid: uuid.UUID,
    markets: list[str],
    actor_ref: str,
    actor_name: str,
    supersede_id: uuid.UUID | None,
    reason: str | None,
) -> dict[str, Any]:
    v = version_row(db, vid, markets, lock=True)
    if v["status"] != "APPROVED":
        raise AuthoringError(409, "NOT_APPROVED", f"v{v['version_label']} must be approved before publishing")
    if actor_ref in makers(db, vid, v["author_ref"]):
        raise AuthoringError(
            403, "SELF_PUBLISH_DENIED", "You authored or edited this version; another checker must publish it"
        )
    if sha256_of(build_manifest(db, v)) != v["manifest_sha256"]:
        raise AuthoringError(409, "MANIFEST_MISMATCH", "The approved content no longer matches its manifest")
    old = None
    if supersede_id is not None:
        old = _one(
            db,
            "SELECT * FROM script_version WHERE id = :o AND script_family_id = :f FOR UPDATE",
            o=supersede_id,
            f=v["script_family_id"],
        )
        if old is None or old["status"] != "PUBLISHED":
            raise AuthoringError(422, "INVALID_SUPERSEDE", "Only a published version of this family can be superseded")
    now = _now()
    modules = (
        db.execute(
            text(
                "SELECT m.id, m.code, m.revision FROM script_section s JOIN script_module m ON m.id = "
                "s.script_module_id "
                "WHERE s.script_version_id = :v AND m.status = 'DRAFT'"
            ),
            {"v": vid},
        )
        .mappings()
        .all()
    )
    for m in modules:
        db.execute(
            text(
                "UPDATE script_module SET status = 'PUBLISHED', updated_at = now(), updated_by = :by, "
                "row_version = row_version + 1 WHERE id = :i"
            ),
            {"by": actor_ref, "i": m["id"]},
        )
    db.execute(
        text(
            "UPDATE script_version SET status = 'PUBLISHED', published_at = :t, effective_from = :t, updated_at = "
            "now(), "
            "updated_by = :by, row_version = row_version + 1 WHERE id = :i"
        ),
        {"t": now, "by": actor_ref, "i": vid},
    )
    add_event(
        db,
        vid,
        "PUBLISHED",
        actor_ref,
        actor_name,
        reason=reason,
        details={
            "manifest_sha256": v["manifest_sha256"],
            "effective_from": now.isoformat(),
            "modules_published": [f"{m['code']} r{m['revision']}" for m in modules],
            "supersedes": old["version_label"] if old else None,
        },
    )
    if old is not None:
        db.execute(
            text(
                "UPDATE script_version SET status = 'SUPERSEDED', effective_to = :t, updated_at = now(), updated_by = "
                ":by, "
                "row_version = row_version + 1 WHERE id = :i"
            ),
            {"t": now, "by": actor_ref, "i": old["id"]},
        )
        add_event(
            db,
            old["id"],
            "SUPERSEDED",
            actor_ref,
            actor_name,
            reason=reason,
            details={"superseded_by": v["version_label"], "effective_to": now.isoformat()},
        )
    return {"published_at": now, "superseded": old["version_label"] if old else None}
