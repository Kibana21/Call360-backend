"""S3-B governed finding rule sets: versioned, maker-checker, immutable once published.

One market has at most one open version (DRAFT / SUBMITTED_FOR_REVIEW / APPROVED) and one PUBLISHED version. A new
draft starts as a copy of the published rules (or empty). Authors (``script.edit``) edit and submit drafts; a
different S&C checker (``script.approve``) approves or returns it, and a checker (``script.publish``) who did not
author it publishes it, superseding the previous published version. Every step is an insert-only event; the database
guard keeps rules immutable outside DRAFT. All rules are synthetic development configuration, not approved policy.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import finding_engine as fe
from app.domain.digest import sha256_of

OPEN = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED")


class RuleSetError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def label(v: Mapping[str, Any]) -> str:
    return f"{v['market_code']} finding rules v{v['version_no']}" + (
        "" if v["status"] in ("PUBLISHED", "SUPERSEDED") else f" ({v['status'].lower().replace('_', ' ')})"
    )


def rule_set(v: Mapping[str, Any]) -> fe.RuleSet:
    return fe.RuleSet.of(str(v["id"]), label(v), v["status"], v["rules"] or [])


def _event(db: Session, vid: uuid.UUID, action: str, actor: str, reason: str | None = None, **details: Any) -> None:
    db.execute(
        text(
            "INSERT INTO finding_rule_set_event (id, rule_set_version_id, action, actor_ref, reason, details) "
            "VALUES (:i, :v, :a, :by, :r, CAST(:d AS jsonb))"
        ),
        {"i": uuid.uuid4(), "v": vid, "a": action, "by": actor, "r": reason, "d": json.dumps(details, default=str)},
    )


def versions(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT v.id, v.market_code, v.version_no, v.status, v.rules_sha256, v.change_summary, v.created_at, "
        "v.published_at, jsonb_array_length(v.rules) AS rules_count, p.display_name AS created_by_name "
        "FROM finding_rule_set_version v LEFT JOIN principal p ON CAST(p.id AS text) = v.created_by "
        "WHERE v.market_code = ANY(:m) ORDER BY v.version_no DESC",
        m=list(markets),
    )


def version(db: Session, vid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    v = _one(
        db,
        "SELECT * FROM finding_rule_set_version WHERE id = :v AND market_code = ANY(:m)"
        + (" FOR UPDATE" if lock else ""),
        v=vid,
        m=list(markets),
    )
    if v is None:
        raise RuleSetError(404, "NOT_FOUND", "Finding rule set not found or not available to you")
    return v


def published(db: Session, market: str) -> dict[str, Any] | None:
    return _one(db, "SELECT * FROM finding_rule_set_version WHERE market_code = :m AND status = 'PUBLISHED'", m=market)


def makers(db: Session, vid: uuid.UUID) -> set[str]:
    return {
        r["actor_ref"]
        for r in _all(
            db,
            "SELECT DISTINCT actor_ref FROM finding_rule_set_event WHERE rule_set_version_id = :v "
            "AND action IN ('CREATED', 'EDITED', 'SUBMITTED')",
            v=vid,
        )
    }


def history(db: Session, vid: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT e.action, e.reason, e.details, e.occurred_at, p.display_name FROM finding_rule_set_event e "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.rule_set_version_id = :v "
        "ORDER BY e.occurred_at, e.id",
        v=vid,
    )


def create_draft(db: Session, market: str, actor: str, *, empty: bool = False) -> uuid.UUID:
    if _one(
        db,
        "SELECT id FROM finding_rule_set_version WHERE market_code = :m AND status = ANY(:o)",
        m=market,
        o=list(OPEN),
    ):
        raise RuleSetError(409, "OPEN_VERSION_EXISTS", "An unpublished finding rule set already exists; continue it")
    base = published(db, market)
    rules = [] if empty or base is None else list(base["rules"])
    n = db.execute(
        text("SELECT coalesce(max(version_no), 0) + 1 FROM finding_rule_set_version WHERE market_code = :m"),
        {"m": market},
    ).scalar_one()
    vid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO finding_rule_set_version (id, market_code, version_no, rules, rules_sha256, based_on_id, "
            "created_by) VALUES (:i, :m, :n, CAST(:r AS jsonb), :s, :b, :by)"
        ),
        {
            "i": vid,
            "m": market,
            "n": n,
            "r": json.dumps(rules),
            "s": sha256_of(rules),
            "b": base["id"] if base and not empty else None,
            "by": actor,
        },
    )
    _event(db, vid, "CREATED", actor, based_on=str(base["id"]) if base and not empty else None, rules=len(rules))
    return vid


def update(
    db: Session,
    vid: uuid.UUID,
    markets: Sequence[str],
    actor: str,
    expected_row_version: int,
    rules: Sequence[Mapping[str, Any]],
    change_summary: str | None,
) -> None:
    v = version(db, vid, markets, lock=True)
    if v["row_version"] != expected_row_version:
        raise RuleSetError(409, "STALE_RULE_SET", "This finding rule set was changed by someone else; reload it")
    if v["status"] != "DRAFT":
        raise RuleSetError(409, "NOT_DRAFT", "Only a draft can be edited")
    try:
        clean = fe.normalise_rules(rules)
    except fe.RulesInvalid as exc:
        raise RuleSetError(422, "INVALID_FINDING_RULES", "The finding rules are not valid", exc.problems) from exc
    before = {r["rule_code"]: r for r in v["rules"] or []}
    after = {r["rule_code"]: r for r in clean}
    db.execute(
        text(
            "UPDATE finding_rule_set_version SET rules = CAST(:r AS jsonb), rules_sha256 = :s, change_summary = "
            "coalesce(:c, change_summary), updated_at = now(), row_version = row_version + 1 WHERE id = :v"
        ),
        {"r": json.dumps(clean), "s": sha256_of(clean), "c": change_summary, "v": vid},
    )
    _event(
        db,
        vid,
        "EDITED",
        actor,
        change_summary,
        added=sorted(set(after) - set(before)),
        removed=sorted(set(before) - set(after)),
        changed=sorted(c for c in set(after) & set(before) if after[c] != before[c]),
    )


def _transition(db: Session, vid: uuid.UUID, frm: tuple[str, ...], to: str, sets: str, **p: Any) -> None:
    db.execute(
        text(
            f"UPDATE finding_rule_set_version SET status = :to, {sets}updated_at = now(), "  # noqa: S608 - fixed SQL
            "row_version = row_version + 1 WHERE id = :v AND status = ANY(:frm)"
        ),
        {"to": to, "v": vid, "frm": list(frm), **p},
    )


def submit(db: Session, vid: uuid.UUID, markets: Sequence[str], actor: str, rv: int, summary: str) -> None:
    v = version(db, vid, markets, lock=True)
    if v["row_version"] != rv:
        raise RuleSetError(409, "STALE_RULE_SET", "This finding rule set was changed by someone else; reload it")
    if v["status"] != "DRAFT":
        raise RuleSetError(409, "NOT_DRAFT", "Only a draft can be submitted")
    if not v["rules"]:
        raise RuleSetError(422, "NO_RULES", "Add at least one finding rule before submitting")
    if not summary or not 5 <= len(summary.strip()) <= 500:
        raise RuleSetError(422, "INVALID_SUMMARY", "Give a change summary for the reviewer (5–500 characters)")
    _transition(
        db,
        vid,
        ("DRAFT",),
        "SUBMITTED_FOR_REVIEW",
        "submitted_by = :by, submitted_at = now(), change_summary = :c, ",
        by=actor,
        c=summary.strip(),
    )
    _event(db, vid, "SUBMITTED", actor, summary.strip(), rules_sha256=v["rules_sha256"])


def review(db: Session, vid: uuid.UUID, markets: Sequence[str], actor: str, decision: str, reason: str) -> None:
    v = version(db, vid, markets, lock=True)
    if v["status"] != "SUBMITTED_FOR_REVIEW":
        raise RuleSetError(409, "NOT_SUBMITTED", "Only a submitted finding rule set can be reviewed")
    if actor in makers(db, vid):
        raise RuleSetError(403, "MAKER_CANNOT_REVIEW", "You authored this version; another S&C checker must review it")
    if not reason or not 5 <= len(reason.strip()) <= 500:
        raise RuleSetError(422, "INVALID_REASON", "Give a review reason (5–500 characters)")
    if decision == "APPROVE":
        _transition(
            db,
            vid,
            ("SUBMITTED_FOR_REVIEW",),
            "APPROVED",
            "reviewed_by = :by, review_reason = :r, reviewed_at = now(), ",
            by=actor,
            r=reason.strip(),
        )
    elif decision == "RETURN":
        _transition(
            db,
            vid,
            ("SUBMITTED_FOR_REVIEW",),
            "DRAFT",
            "reviewed_by = :by, review_reason = :r, reviewed_at = now(), ",
            by=actor,
            r=reason.strip(),
        )
    else:
        raise RuleSetError(422, "INVALID_DECISION", "Decision must be APPROVE or RETURN")
    _event(db, vid, "APPROVED" if decision == "APPROVE" else "RETURNED", actor, reason.strip())


def publish(db: Session, vid: uuid.UUID, markets: Sequence[str], actor: str) -> uuid.UUID | None:
    v = version(db, vid, markets, lock=True)
    if v["status"] != "APPROVED":
        raise RuleSetError(409, "NOT_APPROVED", "Only an approved finding rule set can be published")
    if actor in makers(db, vid):
        raise RuleSetError(
            403, "MAKER_CANNOT_PUBLISH", "You authored this version; another S&C checker must publish it"
        )
    prev = published(db, v["market_code"])
    if prev:
        _transition(db, prev["id"], ("PUBLISHED",), "SUPERSEDED", "superseded_at = now(), ")
        _event(db, prev["id"], "SUPERSEDED", actor, superseded_by=str(vid))
    _transition(db, vid, ("APPROVED",), "PUBLISHED", "published_by = :by, published_at = now(), ", by=actor)
    _event(db, vid, "PUBLISHED", actor, rules_sha256=v["rules_sha256"], supersedes=str(prev["id"]) if prev else None)
    return prev["id"] if prev else None


def abandon(db: Session, vid: uuid.UUID, markets: Sequence[str], actor: str, reason: str) -> None:
    v = version(db, vid, markets, lock=True)
    if v["status"] not in OPEN:
        raise RuleSetError(409, "NOT_OPEN", "Only an unpublished version can be abandoned")
    if not reason or len(reason.strip()) < 5:
        raise RuleSetError(422, "INVALID_REASON", "Give a reason (at least 5 characters)")
    _transition(db, vid, OPEN, "ABANDONED", "")
    _event(db, vid, "ABANDONED", actor, reason.strip())


def diff(a: Sequence[Mapping[str, Any]], b: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ra, rb = {r["rule_code"]: r for r in a}, {r["rule_code"]: r for r in b}
    changed = []
    for c in sorted(set(ra) & set(rb)):
        fields = {k: {"from": ra[c].get(k), "to": rb[c].get(k)} for k in rb[c] if ra[c].get(k) != rb[c].get(k)}
        if fields:
            changed.append({"rule_code": c, "changes": fields})
    return {
        "added": [fe.describe_rule(rb[c]) for c in sorted(set(rb) - set(ra))],
        "removed": [fe.describe_rule(ra[c]) for c in sorted(set(ra) - set(rb))],
        "changed": changed,
    }


def warnings(db: Session, rules: Sequence[Mapping[str, Any]]) -> list[str]:
    """Advisory checks against the library (a rule may target questions or controls not yet in any script)."""
    out = []
    qs = {r["question_code"] for r in _all(db, "SELECT question_code FROM question_bank_item")}
    cs = {r["control_code"] for r in _all(db, "SELECT control_code FROM control")}
    for r in rules:
        if r["scope"] == "QUESTION" and r["target"] not in qs:
            out.append(f"{r['rule_code']}: question {r['target']} is not in the question bank yet")
        if r["scope"] == "CONTROL" and r["target"] not in cs:
            out.append(f"{r['rule_code']}: control {r['target']} does not exist")
    return out


def controls(db: Session) -> list[dict[str, Any]]:
    return _all(db, "SELECT control_code AS code, name AS label FROM control ORDER BY control_code")
