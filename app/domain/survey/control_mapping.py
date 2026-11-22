# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""EVAL-1 — the GOVERNED mapping between published Survey Studio evidence and a control of the existing register.

A mapping is not part of any question. It is its own artifact: one immutable revision per control and market, proposed,
approved and published by three different people (the service refuses otherwise, and so does a database trigger).
It names EXACT survey items (code and version) that are pinned by a published survey version of the market; for an
answer it carries a rule in the existing S3-A rule language, validated by ``answer_evaluation.configure``; it declares
how the control's evidence combines and, optionally, a published condition that says when the control applies.

No association is inferred from a label, and the control register itself is not changed.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain import answer_evaluation as ae
from app.domain.survey import store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import inputs_of, params_of
from app.domain.survey.control_evaluation import ANSWER_TYPE, COMBINATIONS, EVIDENCE_TYPES, control_sha256
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

OPEN = ("PROPOSED", "APPROVED")
KEY_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,39}$")
MAX_ENTRIES = 50
ENTITY = "survey_control_mapping"
SQL = (
    "SELECT m.*, c.name AS control_name, "
    "(SELECT event FROM survey_control_mapping_event e WHERE e.mapping_id = m.id ORDER BY seq DESC LIMIT 1) AS status, "
    "(SELECT actor_ref FROM survey_control_mapping_event e WHERE e.mapping_id = m.id AND e.event = 'APPROVED' ORDER BY seq DESC LIMIT 1) AS approved_by, "
    "(SELECT actor_ref FROM survey_control_mapping_event e WHERE e.mapping_id = m.id AND e.event = 'PUBLISHED' ORDER BY seq DESC LIMIT 1) AS published_by "
    "FROM survey_control_mapping m JOIN control c ON c.id = m.control_id "
)


def controls(db: Session) -> list[dict[str, Any]]:
    """The existing control register, as it is. It has no market, no revision and no lifecycle of its own."""
    return _all(
        db, "SELECT id, control_code, name, owner_role, content_approval_status FROM control ORDER BY control_code"
    )


def register(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    """Every control with the mapping revisions that exist for it in the caller's markets."""
    rows = mappings(db, markets)
    out = []
    for c in controls(db):
        mine = [m for m in rows if m["control_id"] == c["id"]]
        out.append(
            c | {
                "control_sha256": control_sha256(c),
                "published": [{"id": m["id"], "market_code": m["market_code"], "revision": m["revision"]} for m in mine if m["status"] == "PUBLISHED"],
                "open": [{"id": m["id"], "market_code": m["market_code"], "revision": m["revision"], "status": m["status"]} for m in mine if m["status"] in OPEN],
            }
        )  # fmt: skip
    return out


def mappings(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    return _all(db, SQL + "WHERE m.market_code = ANY(:m) ORDER BY m.control_code, m.revision", m=list(markets))


def mapping(db: Session, mid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    if lock:
        db.execute(text("SELECT 1 FROM survey_control_mapping WHERE id = :i FOR UPDATE"), {"i": mid})
    row = _one(db, SQL + "WHERE m.id = :i AND m.market_code = ANY(:m)", i=mid, m=list(markets))
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Control mapping not found or not available to you")
    row["history"] = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.comment, e.occurred_at, p.display_name FROM survey_control_mapping_event e "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.mapping_id = :m ORDER BY e.seq",
        m=mid,
    )
    return row


def published(db: Session, market: str) -> dict[str, dict[str, Any]]:
    """control code → the ONE published mapping revision of that control in this market."""
    return {m["control_code"]: m for m in mappings(db, [market]) if m["status"] == "PUBLISHED"}


def by_ids(db: Session, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Mapping revisions by id, whatever their status now: a revision is immutable, so a pinned one can be read again."""
    rows = _all(db, SQL + "WHERE CAST(m.id AS text) = ANY(:i)", i=list(ids))
    return {m["control_code"]: m for m in rows}


def _event(db: Session, mid: uuid.UUID, event: str, actor: Actor, comment: str = "") -> None:
    db.execute(
        text(
            "INSERT INTO survey_control_mapping_event (mapping_id, event, actor_ref, comment) VALUES (:m, :e, :a, :c)"
        ),
        {"m": mid, "e": event, "a": _ref(actor), "c": comment.strip()},
    )


def _bad(code: str, message: str, where: str = "") -> SurveyError:
    return SurveyError(422, code, f"{where}: {message}" if where else message)


def _entries(db: Session, market: str, raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_ENTRIES:
        raise _bad("ENTRIES_INVALID", f"A mapping names between 1 and {MAX_ENTRIES} pieces of evidence")
    index = store.published_index(db, [market])
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str, str, str]] = set()
    for n, e in enumerate(raw, start=1):
        where = f"Evidence {n}"
        item = e.get("item") if isinstance(e, Mapping) else None
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("code"), str)
            or not isinstance(item.get("version"), int)
        ):
            raise _bad("ENTRY_INVALID", "name the exact item: its code and its version", where)
        code, version = item["code"], int(item["version"])
        pinned_by = index.get(("ITEM", code, version))
        if not pinned_by:
            raise _bad(
                "ITEM_NOT_PUBLISHED",
                f"{code} v{version} is not pinned by any published survey version of market {market}",
                where,
            )
        doc = store._doc(db, "ITEM", code, version)
        assert doc is not None
        content = doc["content"]
        kind = e.get("evidence_type")
        if kind not in EVIDENCE_TYPES:
            raise _bad("EVIDENCE_TYPE_INVALID", f"evidence type is one of {', '.join(EVIDENCE_TYPES)}", where)
        context = e.get("survey_code") or None
        if context is not None and context not in {v["survey_code"] for v in pinned_by}:
            raise _bad(
                "CONTEXT_INVALID", f"survey {context} has no published version that pins {code} v{version}", where
            )
        # EVAL-2A: an entry may say which evidence requirement of a control policy it supplies
        obligation, requirement = e.get("obligation") or None, e.get("requirement") or None
        for label, v in (("obligation", obligation), ("requirement", requirement)):
            if v is not None and not (isinstance(v, str) and KEY_RE.match(v)):
                raise _bad(
                    "REQUIREMENT_INVALID",
                    f"the {label} key is a short key of the control policy (capital letters, digits, hyphens)",
                    where,
                )
        key = (code, version, kind, context or "", obligation or "", requirement or "")
        if key in seen:
            raise _bad("ENTRY_DUPLICATE", f"{code} v{version} is named twice for the same evidence and context", where)
        seen.add(key)
        rule: dict[str, Any] | None = None
        answer_type = content["answer_type"]
        if kind == "DELIVERY":
            if e.get("rule"):
                raise _bad("RULE_NOT_ALLOWED", "delivery evidence has no evaluation rule", where)
        else:
            if answer_type == "STATEMENT":
                raise _bad(
                    "ANSWER_TYPE_UNSUPPORTED", "a statement takes no answer; its evidence is its delivery", where
                )
            if answer_type not in ANSWER_TYPE:
                raise _bad(
                    "ANSWER_TYPE_UNSUPPORTED",
                    f"the existing evaluator has no method for a {answer_type.replace('_', ' ').lower()} answer",
                    where,
                )
            r = e.get("rule")
            if not isinstance(r, Mapping) or not isinstance(r.get("method"), str):
                raise _bad("RULE_REQUIRED", "answer evidence needs an evaluation rule (its method)", where)
            options: list[str] = []
            ref = content.get("option_set")
            if ref:
                os_doc = store._doc(db, "OPTION_SET", ref["code"], int(ref["version"]))
                options = [o["code"] for o in (os_doc or {}).get("content", {}).get("options", [])]
            mapped = ANSWER_TYPE[answer_type]
            try:
                expected, fact_key = ae.configure(
                    r["method"], mapped, options if mapped in ("ENUM", "MULTI_SELECT") else [],
                    expected_boolean=r.get("expected_boolean"), evaluation=r.get("evaluation"), fact_key=r.get("fact_key"),
                )  # fmt: skip
            except ae.RuleInvalid as exc:
                raise _bad("RULE_INVALID", str(exc), where) from exc
            if e.get("required", True) and r["method"] == "COLLECT_ONLY":
                raise _bad(
                    "RULE_INVALID",
                    "required evidence needs a rule that evaluates the answer; collect-only evidence can only be optional",
                    where,
                )
            rule = {
                "method": r["method"],
                "answer_type": mapped,
                "options": options if mapped in ("ENUM", "MULTI_SELECT") else [],
                "expected": expected,
                "fact_key": fact_key,
            }
        out.append(
            {
                "item": {"code": code, "version": version}, "item_sha256": doc["sha256"], "item_answer_type": answer_type,
                "evidence_type": kind, "required": bool(e.get("required", True)), "survey_code": context, "rule": rule,
                **({"obligation": obligation} if obligation else {}), **({"requirement": requirement} if requirement else {}),
                "rule_text": ae.describe_rule(ae.Rule(code, f"{code}@{version}", version, rule["method"], rule["answer_type"], tuple(rule["options"]), rule["expected"], rule["fact_key"])) if rule else "The exact pinned wording is delivered",
            }
        )  # fmt: skip
    if not any(e["required"] for e in out):
        raise _bad("NO_REQUIRED_EVIDENCE", "A mapping names at least one piece of REQUIRED evidence")
    return out


def _applicability(db: Session, market: str, raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    cond = raw.get("condition") if isinstance(raw, Mapping) else None
    if (
        not isinstance(cond, Mapping)
        or not isinstance(cond.get("code"), str)
        or not isinstance(cond.get("version"), int)
    ):
        raise _bad("APPLICABILITY_INVALID", "Applicability names a published condition: its code and version")
    code, version = cond["code"], int(cond["version"])
    if not store.published_index(db, [market]).get(("CONDITION", code, version)):
        raise _bad(
            "CONDITION_NOT_PUBLISHED",
            f"Condition {code} v{version} is not pinned by any published survey version of market {market}",
        )
    doc = store._doc(db, "CONDITION", code, version)
    assert doc is not None
    ast = doc["content"].get("ast") or {}
    if inputs_of(ast):
        raise _bad(
            "APPLICABILITY_READS_ANSWERS", "An applicability condition reads application facts only, not answers"
        )
    params = raw.get("params") or {}
    if not isinstance(params, Mapping) or sorted(params) != sorted(params_of(ast)):
        raise _bad(
            "APPLICABILITY_PARAMS",
            f"Give exactly the condition's parameters: {', '.join(sorted(params_of(ast))) or 'none'}",
        )
    return {
        "condition": {"code": code, "version": version, "sha256": doc["sha256"]},
        "ast": ast,
        "params": dict(params),
    }


def propose(
    db: Session, markets: Sequence[str], market: str, control_code: str, combination: str, applicability: Any, entries: Any,
    source: str, actor: Actor, meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot govern control mappings of this market")
    c = _one(
        db,
        "SELECT id, control_code, name, owner_role, content_approval_status FROM control WHERE control_code = :c",
        c=control_code,
    )
    if c is None:
        raise SurveyError(404, "CONTROL_NOT_FOUND", "No control of the register has this code")
    if combination not in COMBINATIONS:
        raise _bad(
            "COMBINATION_UNSUPPORTED",
            f"Evidence combination is one of {', '.join(COMBINATIONS)}; no other combination has an approved meaning",
        )
    if len(source.strip()) < 10:
        raise _bad("SOURCE_REQUIRED", "State where this mapping comes from (at least 10 characters)")
    docs = _entries(db, market, entries)
    app = _applicability(db, market, applicability)
    for other in _all(
        db, "SELECT id FROM survey_control_mapping WHERE control_id = :c AND market_code = :m", c=c["id"], m=market
    ):
        if status_of(db, other["id"]) in OPEN:
            raise SurveyError(
                409,
                "MAPPING_OPEN",
                "This control already has a mapping awaiting a decision or publication in this market",
            )
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"survey_control_mapping:{market}:{control_code}"}
    )
    revision = db.execute(
        text(
            "SELECT coalesce(max(revision), 0) + 1 FROM survey_control_mapping WHERE control_id = :c AND market_code = :m"
        ),
        {"c": c["id"], "m": market},
    ).scalar_one()
    csha = control_sha256(c)
    body = {
        "control_code": control_code,
        "control_sha256": csha,
        "market_code": market,
        "combination": combination,
        "applicability": app,
        "entries": docs,
        "source": source.strip(),
    }
    mid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_control_mapping (id, market_code, control_id, control_code, control_sha256, revision, combination, "
            "applicability, entries, source, mapping_sha256, proposed_by) VALUES (:i, :m, :c, :cc, :cs, :r, :comb, "
            "CAST(:app AS jsonb), CAST(:e AS jsonb), :src, :sha, :by)"
        ),
        {
            "i": mid, "m": market, "c": c["id"], "cc": control_code, "cs": csha, "r": revision, "comb": combination,
            "app": json.dumps(app) if app is not None else None, "e": json.dumps(docs), "src": source.strip(),
            "sha": sha256_hex(body), "by": _ref(actor),
        },
    )  # fmt: skip
    _event(db, mid, "PROPOSED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.CONTROL_MAPPING_PROPOSED",
        ENTITY,
        mid,
        {"control": control_code, "market": market, "revision": revision},
    )
    return mid


def status_of(db: Session, mid: uuid.UUID) -> str | None:
    row = _one(
        db, "SELECT event FROM survey_control_mapping_event WHERE mapping_id = :m ORDER BY seq DESC LIMIT 1", m=mid
    )
    return row["event"] if row else None


def decide(
    db: Session,
    mid: uuid.UUID,
    markets: Sequence[str],
    verdict: str,
    comment: str,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> None:
    m = mapping(db, mid, markets, lock=True)
    if m["status"] != "PROPOSED":
        raise SurveyError(409, "NOT_PROPOSED", "This mapping is not waiting for a decision")
    if _ref(actor) == m["proposed_by"]:
        _audit(db, actor, meta, "SURVEY.CONTROL_MAPPING_DENIED", ENTITY, mid, {"rule": "SELF_REVIEW_DENIED"})
        raise SurveyError(403, "SELF_REVIEW_DENIED", "The person who proposed a mapping cannot approve or reject it")
    if verdict == "REJECT" and len(comment.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "A rejection needs a comment of at least 10 characters")
    event = "APPROVED" if verdict == "APPROVE" else "REJECTED"
    _event(db, mid, event, actor, comment)
    _audit(db, actor, meta, f"SURVEY.CONTROL_MAPPING_{event}", ENTITY, mid, {})


def publish(db: Session, mid: uuid.UUID, markets: Sequence[str], actor: Actor, meta: RequestMeta | None = None) -> None:
    m = mapping(db, mid, markets, lock=True)
    if m["status"] != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved mapping can be published")
    me = _ref(actor)
    if me in (m["proposed_by"], m["approved_by"]):
        code = "SELF_PUBLISH_DENIED" if me == m["proposed_by"] else "APPROVER_PUBLISH_DENIED"
        _audit(db, actor, meta, "SURVEY.CONTROL_MAPPING_DENIED", ENTITY, mid, {"rule": code})
        raise SurveyError(
            403, code, "The proposer and the approver of a mapping cannot publish it: a third person must"
        )
    # everything it pins is checked again at the moment it takes effect
    c = _one(
        db,
        "SELECT id, control_code, name, owner_role, content_approval_status FROM control WHERE id = :i",
        i=m["control_id"],
    )
    if c is None or control_sha256(c) != m["control_sha256"]:
        raise SurveyError(
            409, "CONTROL_CHANGED", "The control was changed after this mapping was proposed; propose it again"
        )
    index = store.published_index(db, [m["market_code"]])
    gone = [
        f"{e['item']['code']} v{e['item']['version']}"
        for e in m["entries"]
        if not index.get(("ITEM", e["item"]["code"], int(e["item"]["version"])))
    ]
    if gone:
        raise SurveyError(409, "ITEM_NOT_PUBLISHED", f"No published survey version pins {', '.join(gone)} any more")
    for other in _all(
        db,
        "SELECT id FROM survey_control_mapping WHERE control_id = :c AND market_code = :m AND id <> :i",
        c=m["control_id"],
        m=m["market_code"],
        i=mid,
    ):
        if status_of(db, other["id"]) == "PUBLISHED":
            _event(db, other["id"], "SUPERSEDED", actor, f"superseded by mapping revision {m['revision']}")
    _event(db, mid, "PUBLISHED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.CONTROL_MAPPING_PUBLISHED",
        ENTITY,
        mid,
        {
            "control": m["control_code"],
            "market": m["market_code"],
            "revision": m["revision"],
            "sha256": m["mapping_sha256"],
        },
    )


def withdraw(
    db: Session,
    mid: uuid.UUID,
    markets: Sequence[str],
    reason: str,
    actor: Actor,
    may_unpublish: bool,
    meta: RequestMeta | None = None,
) -> None:
    """An open proposal is withdrawn by its proposer; a PUBLISHED mapping by a person who may publish. The control
    then has no mapping, and an evaluation reports it as unresolved — it does not disappear."""
    m = mapping(db, mid, markets, lock=True)
    if len(reason.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Withdrawing needs a reason of at least 10 characters")
    if m["status"] in OPEN:
        if _ref(actor) != m["proposed_by"]:
            raise SurveyError(403, "NOT_PROPOSER", "Only the person who proposed a mapping can withdraw the proposal")
    elif m["status"] == "PUBLISHED":
        if not may_unpublish:
            raise SurveyError(403, "FORBIDDEN", "Withdrawing a published mapping needs the permission to publish")
    else:
        raise SurveyError(409, "NOT_OPEN", "This mapping is closed")
    _event(db, mid, "WITHDRAWN", actor, reason)
    _audit(db, actor, meta, "SURVEY.CONTROL_MAPPING_WITHDRAWN", ENTITY, mid, {"was": m["status"]})


def as_mapping(db: Session, market: str, body: Mapping[str, Any]) -> dict[str, Any]:
    """A proposed mapping, validated exactly as a proposal is, in the shape the evaluation reads — WITHOUT recording
    it. Used to try a mapping out against a simulated journey before it is proposed."""
    c = _one(
        db,
        "SELECT id, control_code, name, owner_role, content_approval_status FROM control WHERE control_code = :c",
        c=str(body.get("control_code") or ""),
    )
    if c is None:
        raise SurveyError(404, "CONTROL_NOT_FOUND", "No control of the register has this code")
    if body.get("combination") not in COMBINATIONS:
        raise _bad(
            "COMBINATION_UNSUPPORTED",
            f"Evidence combination is one of {', '.join(COMBINATIONS)}; no other combination has an approved meaning",
        )
    docs = _entries(db, market, body.get("entries"))
    app = _applicability(db, market, body.get("applicability"))
    doc = {
        "control_code": c["control_code"],
        "control_sha256": control_sha256(c),
        "market_code": market,
        "combination": body["combination"],
        "applicability": app,
        "entries": docs,
        "source": "DRAFT — not proposed",
    }
    return doc | {
        "id": "00000000-0000-0000-0000-000000000000",
        "revision": 0,
        "mapping_sha256": sha256_hex(doc),
        "control_id": c["id"],
    }
