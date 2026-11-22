# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""EVAL-2A — governed CONTROL POLICIES: which controls of the existing register must be assessed in a market, what
each is for, when each obligation applies and what evidence it requires. Independent of any survey question.

The register itself is not changed: a policy refers to a control by code and id and pins a fingerprint of its row.
One immutable revision per (market, code); proposed, approved and published by three different people (the service
refuses otherwise, and so does a database trigger). Applicability conditions are published Survey Studio conditions
that read application facts only, evaluated by the existing three-valued evaluator.

A policy creates no insurance obligation: it is a governed container, and everything in it is what its three
governors put there.
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
from app.domain.survey import store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import inputs_of, params_of
from app.domain.survey.control_evaluation import COMBINATIONS, EVIDENCE_TYPES, control_sha256
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

OPEN = ("PROPOSED", "APPROVED")
ENTITY = "survey_control_policy"
CODE_RE = re.compile(r"^[A-Z][A-Z0-9-]{2,39}$")
KEY_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,39}$")
COMPLETENESS = ("DECLARED_COMPLETE", "PARTIAL")
MAX_CONTROLS, MAX_OBLIGATIONS, MAX_EVIDENCE = 100, 10, 20
SQL = (
    "SELECT p.*, "
    "(SELECT event FROM survey_control_policy_event e WHERE e.policy_id = p.id ORDER BY seq DESC LIMIT 1) AS status, "
    "(SELECT actor_ref FROM survey_control_policy_event e WHERE e.policy_id = p.id AND e.event = 'APPROVED' ORDER BY seq DESC LIMIT 1) AS approved_by, "
    "(SELECT actor_ref FROM survey_control_policy_event e WHERE e.policy_id = p.id AND e.event = 'PUBLISHED' ORDER BY seq DESC LIMIT 1) AS published_by "
    "FROM survey_control_policy p "
)


def _bad(code: str, message: str, where: str = "") -> SurveyError:
    return SurveyError(422, code, f"{where}: {message}" if where else message, [{"where": where}] if where else [])


def condition_ref(db: Session, market: str, raw: Any, where: str) -> dict[str, Any] | None:
    """A published condition that reads application facts only, with exactly its parameters. None = no condition."""
    if raw is None:
        return None
    cond = raw.get("condition") if isinstance(raw, Mapping) else None
    if (
        not isinstance(cond, Mapping)
        or not isinstance(cond.get("code"), str)
        or not isinstance(cond.get("version"), int)
    ):
        raise _bad("APPLICABILITY_INVALID", "choose a published condition (its code and version)", where)
    code, version = cond["code"], int(cond["version"])
    if not store.published_index(db, [market]).get(("CONDITION", code, version)):
        raise _bad(
            "CONDITION_NOT_PUBLISHED",
            f"condition {code} v{version} is not pinned by any published survey version of market {market}",
            where,
        )
    doc = store._doc(db, "CONDITION", code, version)
    assert doc is not None
    ast = doc["content"].get("ast") or {}
    if inputs_of(ast):
        raise _bad("APPLICABILITY_READS_ANSWERS", "a condition here reads application facts only, not answers", where)
    params = raw.get("params") or {}
    if not isinstance(params, Mapping) or sorted(params) != sorted(params_of(ast)):
        raise _bad(
            "APPLICABILITY_PARAMS",
            f"give exactly the condition's values: {', '.join(sorted(params_of(ast))) or 'none'}",
            where,
        )
    if any(v is None or v == "" for v in params.values()):
        raise _bad("APPLICABILITY_PARAMS", "every value of the condition must be given", where)
    return {
        "condition": {
            "code": code,
            "version": version,
            "sha256": doc["sha256"],
            "name": doc["content"].get("name") or code,
        },
        "ast": ast,
        "params": dict(params),
    }


def _text(v: Any, least: int, most: int) -> str | None:
    s = v.strip() if isinstance(v, str) else ""
    return s if least <= len(s) <= most else None


def document(db: Session, market: str, body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a proposed policy and return its stored form. Raises SurveyError (422) saying what is wrong, where."""
    code = str(body.get("code") or "").strip().upper()
    if not CODE_RE.match(code):
        raise _bad("CODE_INVALID", "A policy code is 3–40 capital letters, digits or hyphens, starting with a letter")
    name, statement = _text(body.get("name"), 3, 160), _text(body.get("scope_statement"), 10, 2000)
    owner, source = _text(body.get("owner"), 2, 160), _text(body.get("source"), 10, 2000)
    if name is None:
        raise _bad("NAME_REQUIRED", "Give the policy a name (3–160 characters)")
    if statement is None:
        raise _bad("SCOPE_STATEMENT_REQUIRED", "Say in words what this policy covers (at least 10 characters)")
    if owner is None:
        raise _bad("OWNER_REQUIRED", "Say who answers for this policy")
    if source is None:
        raise _bad("SOURCE_REQUIRED", "State where this policy comes from (at least 10 characters)")
    if body.get("completeness") not in COMPLETENESS:
        raise _bad(
            "COMPLETENESS_REQUIRED", "Say whether this policy's list of controls is declared complete or partial"
        )
    raw = body.get("controls")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_CONTROLS:
        raise _bad("CONTROLS_INVALID", f"A policy names between 1 and {MAX_CONTROLS} controls")
    register = {
        c["control_code"]: c
        for c in _all(db, "SELECT id, control_code, name, owner_role, content_approval_status FROM control")
    }
    controls: list[dict[str, Any]] = []
    for n, c in enumerate(raw, start=1):
        cc = str((c or {}).get("control_code") or "") if isinstance(c, Mapping) else ""
        where = f"Control {n}" + (f" ({cc})" if cc else "")
        row = register.get(cc)
        if row is None:
            raise _bad(
                "CONTROL_NOT_FOUND", "choose a control of the register; a policy does not create controls", where
            )
        if cc in {x["control"]["code"] for x in controls}:
            raise _bad("CONTROL_DUPLICATE", "this control is named twice; give it several obligations instead", where)
        purpose = _text(c.get("purpose"), 10, 600)
        if purpose is None:
            raise _bad("PURPOSE_REQUIRED", "say what this control is for (10–600 characters)", where)
        obs = c.get("obligations")
        if not isinstance(obs, list) or not 1 <= len(obs) <= MAX_OBLIGATIONS:
            raise _bad("OBLIGATIONS_INVALID", f"a control has between 1 and {MAX_OBLIGATIONS} obligations", where)
        obligations: list[dict[str, Any]] = []
        for ob in obs:
            key = str((ob or {}).get("key") or "").strip().upper() if isinstance(ob, Mapping) else ""
            w = f"{where}, obligation {key or len(obligations) + 1}"
            if not KEY_RE.match(key) or key in {x["key"] for x in obligations}:
                raise _bad(
                    "OBLIGATION_KEY_INVALID",
                    "give each obligation its own short key (capital letters, digits, hyphens)",
                    w,
                )
            title = _text(ob.get("title"), 3, 200)
            if title is None:
                raise _bad("OBLIGATION_TITLE_REQUIRED", "say what must be verified (3–200 characters)", w)
            if ob.get("combination") not in COMBINATIONS:
                raise _bad(
                    "COMBINATION_UNSUPPORTED",
                    f"evidence combines as one of: {', '.join(COMBINATIONS)}; no other combination has an approved meaning",
                    w,
                )
            ev = ob.get("evidence")
            if not isinstance(ev, list) or not 1 <= len(ev) <= MAX_EVIDENCE:
                raise _bad(
                    "EVIDENCE_INVALID", f"an obligation names between 1 and {MAX_EVIDENCE} pieces of evidence", w
                )
            evidence: list[dict[str, Any]] = []
            for e in ev:
                ek = str((e or {}).get("key") or "").strip().upper() if isinstance(e, Mapping) else ""
                if not KEY_RE.match(ek) or ek in {x["key"] for x in evidence}:
                    raise _bad("EVIDENCE_KEY_INVALID", "give each piece of evidence its own short key", w)
                desc = _text(e.get("description"), 5, 300)
                if desc is None:
                    raise _bad(
                        "EVIDENCE_DESCRIPTION_REQUIRED", f"describe evidence {ek} in words (5–300 characters)", w
                    )
                if e.get("evidence_type") not in EVIDENCE_TYPES:
                    raise _bad("EVIDENCE_TYPE_INVALID", f"evidence {ek} is an answer or a delivery", w)
                evidence.append(
                    {
                        "key": ek,
                        "description": desc,
                        "evidence_type": e["evidence_type"],
                        "required": bool(e.get("required", True)),
                    }
                )
            if not any(e["required"] for e in evidence):
                # an empty required-evidence set must never satisfy a control by default
                raise _bad("NO_REQUIRED_EVIDENCE", "name at least one piece of REQUIRED evidence", w)
            obligations.append(
                {"key": key, "title": title, "applicability": condition_ref(db, market, ob.get("applicability"), w), "combination": ob["combination"], "evidence": evidence}
            )  # fmt: skip
        controls.append(
            {
                "control": {"code": cc, "id": str(row["id"]), "sha256": control_sha256(row), "name": row["name"]},
                "purpose": purpose, "description": _text(c.get("description"), 0, 2000) or "", "obligations": obligations,
            }
        )  # fmt: skip
    return {
        "market_code": market, "code": code, "name": name, "scope_statement": statement,
        "scope": condition_ref(db, market, body.get("scope"), "Policy scope"), "completeness": body["completeness"],
        "empty_set_is_complete": bool(body.get("empty_set_is_complete", False)), "controls": controls, "owner": owner, "source": source,
    }  # fmt: skip


def as_policy(doc: Mapping[str, Any], *, pid: Any = None, revision: int = 0) -> dict[str, Any]:
    """A validated document in the shape the evaluation reads (also for a draft that is only being tried out)."""
    return dict(doc) | {
        "id": pid or "00000000-0000-0000-0000-000000000000",
        "revision": revision,
        "policy_sha256": sha256_hex(dict(doc)),
    }


HISTORY_SQL = (
    "SELECT e.seq, e.event, e.actor_ref, e.comment, e.occurred_at, p.display_name FROM survey_control_policy_event e "
    "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.policy_id = :p ORDER BY e.seq"
)


def policies(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    rows = _all(db, SQL + "WHERE p.market_code = ANY(:m) ORDER BY p.code, p.revision", m=list(markets))
    for row in rows:
        row["history"] = _all(db, HISTORY_SQL, p=row["id"])
    return rows


def policy(db: Session, pid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    if lock:
        db.execute(text("SELECT 1 FROM survey_control_policy WHERE id = :i FOR UPDATE"), {"i": pid})
    row = _one(db, SQL + "WHERE p.id = :i AND p.market_code = ANY(:m)", i=pid, m=list(markets))
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Control policy not found or not available to you")
    row["history"] = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.comment, e.occurred_at, p.display_name FROM survey_control_policy_event e "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.policy_id = :p ORDER BY e.seq",
        p=pid,
    )
    return row


def by_id(db: Session, pid: Any) -> dict[str, Any] | None:
    """A policy revision whatever its status now: revisions are immutable, so a pinned one can always be read again."""
    return _one(db, SQL + "WHERE CAST(p.id AS text) = :i", i=str(pid))


def status_of(db: Session, pid: uuid.UUID) -> str | None:
    row = _one(
        db, "SELECT event FROM survey_control_policy_event WHERE policy_id = :p ORDER BY seq DESC LIMIT 1", p=pid
    )
    return row["event"] if row else None


def _event(db: Session, pid: uuid.UUID, event: str, actor: Actor, comment: str = "") -> None:
    db.execute(
        text("INSERT INTO survey_control_policy_event (policy_id, event, actor_ref, comment) VALUES (:p, :e, :a, :c)"),
        {"p": pid, "e": event, "a": _ref(actor), "c": comment.strip()},
    )


def propose(
    db: Session, markets: Sequence[str], body: Mapping[str, Any], actor: Actor, meta: RequestMeta | None = None
) -> uuid.UUID:
    market = str(body.get("market_code") or "")
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot govern control policies of this market")
    doc = document(db, market, body)
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"survey_control_policy:{market}:{doc['code']}"}
    )
    for other in _all(
        db, "SELECT id FROM survey_control_policy WHERE market_code = :m AND code = :c", m=market, c=doc["code"]
    ):
        if status_of(db, other["id"]) in OPEN:
            raise SurveyError(
                409, "POLICY_OPEN", "This policy already has a revision awaiting a decision or publication"
            )
    revision = db.execute(
        text("SELECT coalesce(max(revision), 0) + 1 FROM survey_control_policy WHERE market_code = :m AND code = :c"),
        {"m": market, "c": doc["code"]},
    ).scalar_one()
    pid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_control_policy (id, market_code, code, revision, name, scope_statement, scope, completeness, "
            "empty_set_is_complete, controls, owner, source, policy_sha256, proposed_by) VALUES (:i, :m, :c, :r, :n, :ss, "
            "CAST(:sc AS jsonb), :comp, :empty, CAST(:ctl AS jsonb), :o, :src, :sha, :by)"
        ),
        {
            "i": pid, "m": market, "c": doc["code"], "r": revision, "n": doc["name"], "ss": doc["scope_statement"],
            "sc": json.dumps(doc["scope"]) if doc["scope"] is not None else None, "comp": doc["completeness"],
            "empty": doc["empty_set_is_complete"], "ctl": json.dumps(doc["controls"]), "o": doc["owner"], "src": doc["source"],
            "sha": sha256_hex(doc), "by": _ref(actor),
        },
    )  # fmt: skip
    _event(db, pid, "PROPOSED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.CONTROL_POLICY_PROPOSED",
        ENTITY,
        pid,
        {"policy": doc["code"], "market": market, "revision": revision, "controls": len(doc["controls"])},
    )
    return pid


def decide(
    db: Session,
    pid: uuid.UUID,
    markets: Sequence[str],
    verdict: str,
    comment: str,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> None:
    p = policy(db, pid, markets, lock=True)
    if p["status"] != "PROPOSED":
        raise SurveyError(409, "NOT_PROPOSED", "This policy revision is not waiting for a decision")
    if _ref(actor) == p["proposed_by"]:
        _audit(db, actor, meta, "SURVEY.CONTROL_POLICY_DENIED", ENTITY, pid, {"rule": "SELF_REVIEW_DENIED"})
        raise SurveyError(403, "SELF_REVIEW_DENIED", "The person who proposed a policy cannot approve or reject it")
    if verdict == "REJECT" and len(comment.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "A rejection needs a comment of at least 10 characters")
    event = "APPROVED" if verdict == "APPROVE" else "REJECTED"
    _event(db, pid, event, actor, comment)
    _audit(db, actor, meta, f"SURVEY.CONTROL_POLICY_{event}", ENTITY, pid, {})


def publish(db: Session, pid: uuid.UUID, markets: Sequence[str], actor: Actor, meta: RequestMeta | None = None) -> None:
    p = policy(db, pid, markets, lock=True)
    if p["status"] != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved policy revision can be published")
    me = _ref(actor)
    if me in (p["proposed_by"], p["approved_by"]):
        code = "SELF_PUBLISH_DENIED" if me == p["proposed_by"] else "APPROVER_PUBLISH_DENIED"
        _audit(db, actor, meta, "SURVEY.CONTROL_POLICY_DENIED", ENTITY, pid, {"rule": code})
        raise SurveyError(403, code, "The proposer and the approver of a policy cannot publish it: a third person must")
    # everything it pins is checked again at the moment it takes effect
    register = {
        c["control_code"]: c
        for c in _all(db, "SELECT id, control_code, name, owner_role, content_approval_status FROM control")
    }
    changed = [
        c["control"]["code"]
        for c in p["controls"]
        if c["control"]["code"] not in register
        or control_sha256(register[c["control"]["code"]]) != c["control"]["sha256"]
    ]
    if changed:
        raise SurveyError(
            409,
            "CONTROL_CHANGED",
            f"{', '.join(changed)} changed in the register after this policy was proposed; propose it again",
        )
    for other in _all(
        db,
        "SELECT id FROM survey_control_policy WHERE market_code = :m AND code = :c AND id <> :i",
        m=p["market_code"],
        c=p["code"],
        i=pid,
    ):
        if status_of(db, other["id"]) == "PUBLISHED":
            _event(db, other["id"], "SUPERSEDED", actor, f"superseded by revision {p['revision']}")
    _event(db, pid, "PUBLISHED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.CONTROL_POLICY_PUBLISHED",
        ENTITY,
        pid,
        {"policy": p["code"], "market": p["market_code"], "revision": p["revision"], "sha256": p["policy_sha256"]},
    )


def withdraw(
    db: Session,
    pid: uuid.UUID,
    markets: Sequence[str],
    reason: str,
    actor: Actor,
    may_unpublish: bool,
    meta: RequestMeta | None = None,
) -> None:
    """An open proposal is withdrawn by its proposer; a PUBLISHED revision by a person who may publish. Evaluations
    made under it keep it: a revision is never deleted."""
    p = policy(db, pid, markets, lock=True)
    if len(reason.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Withdrawing needs a reason of at least 10 characters")
    if p["status"] in OPEN:
        if _ref(actor) != p["proposed_by"]:
            raise SurveyError(403, "NOT_PROPOSER", "Only the person who proposed a policy can withdraw the proposal")
    elif p["status"] == "PUBLISHED":
        if not may_unpublish:
            raise SurveyError(403, "FORBIDDEN", "Withdrawing a published policy needs the permission to publish")
    else:
        raise SurveyError(409, "NOT_OPEN", "This policy revision is closed")
    _event(db, pid, "WITHDRAWN", actor, reason)
    _audit(db, actor, meta, "SURVEY.CONTROL_POLICY_WITHDRAWN", ENTITY, pid, {"was": p["status"]})
