# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""ASG-1 — which published survey version the EXISTING governed assignment rules select for a synthetic application.

There is no second rule engine and no second rule language here. The published assignment rules are loaded by the
existing loader (``rule_inputs.published_candidates``) and decided by the existing pure engine
(``rule_engine.evaluate``): the same conditions, the same precedence (priority, then specificity), the same explicit
fallback, the same fail-closed outcomes. This module adds exactly one thing: a governed, immutable BINDING that says
which published survey version a published rule version stands for. Each candidate is re-targeted to its bound survey
version before the engine decides; nothing about the rule itself is changed or copied.

A rule without a published binding still takes part with its full precedence. If it wins, the result is
``SURVEY_NOT_BOUND`` — it is never skipped in favour of a lower rule, and no fallback survey is ever chosen silently.

SIMULATION ONLY. A selection is recorded as a simulation record for a SYNTHETIC application. Nothing here creates or
changes a callback case, a script assignment, a contact attempt or a session, and nothing assigns a survey to a
customer. The Script Studio assignment of script versions to cases (``script_assignment.py``) is untouched.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain import rule_engine as re_
from app.domain import rule_inputs as ri
from app.domain.rule_authoring import _trace_json
from app.domain.survey import simulation, store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

#: the existing assignment engine, used through the survey binding
ENGINE = "call360.assignment-engine/1 + survey-binding/1"
RECORD_CLASS = simulation.RECORD_CLASS
NOTE = (
    "SIMULATION ONLY, for a synthetic application. A selected survey and a computed plan are not an assignment of a "
    "survey to any customer case, and not an authorisation or eligibility for any call."
)
OPEN = ("PROPOSED", "APPROVED")
UNBOUND = "unbound:"
#: how the engine's outcome reads as a selection
SELECTION = {
    "SELECTED": "MATCHED", "SELECTED_BY_FALLBACK": "MATCHED", "NO_MATCH": "NO_MATCH", "AMBIGUOUS": "AMBIGUOUS",
    "AMBIGUOUS_SAME_TARGET": "AMBIGUOUS", "INPUT_MISSING": "UNKNOWN_INPUT", "TARGET_NOT_EFFECTIVE": "TARGET_UNAVAILABLE",
    "SURVEY_NOT_BOUND": "TARGET_UNAVAILABLE", "CONTACT_UNRESOLVED": "UNKNOWN_INPUT",
}  # fmt: skip


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------------------------------------------ bindings
def binding_status(db: Session, bid: uuid.UUID) -> str | None:
    row = _one(
        db, "SELECT event FROM survey_assignment_binding_event WHERE binding_id = :b ORDER BY seq DESC LIMIT 1", b=bid
    )
    return row["event"] if row else None


def _event(db: Session, bid: uuid.UUID, event: str, actor: Actor, comment: str = "") -> None:
    db.execute(
        text(
            "INSERT INTO survey_assignment_binding_event (binding_id, event, actor_ref, comment) VALUES (:b, :e, :a, :c)"
        ),
        {"b": bid, "e": event, "a": _ref(actor), "c": comment.strip()},
    )


BINDING_SQL = (
    "SELECT b.*, v.label AS version_label, d.code AS survey_code, d.name AS survey_name, "
    "(SELECT event FROM survey_assignment_binding_event e WHERE e.binding_id = b.id ORDER BY seq DESC LIMIT 1) AS status, "
    "(SELECT actor_ref FROM survey_assignment_binding_event e WHERE e.binding_id = b.id AND e.event = 'APPROVED' ORDER BY seq DESC LIMIT 1) AS approved_by, "
    "(SELECT actor_ref FROM survey_assignment_binding_event e WHERE e.binding_id = b.id AND e.event = 'PUBLISHED' ORDER BY seq DESC LIMIT 1) AS published_by "
    "FROM survey_assignment_binding b JOIN survey_version v ON v.id = b.survey_version_id "
    "JOIN survey_definition d ON d.id = b.survey_definition_id "
)


def bindings(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    rows = _all(db, BINDING_SQL + "WHERE b.market_code = ANY(:m) ORDER BY b.proposed_at, b.id", m=list(markets))
    for r in rows:
        r["survey_version_status"] = store.status_of(db, r["survey_version_id"])
    return rows


def binding(db: Session, bid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    if lock:
        db.execute(text("SELECT 1 FROM survey_assignment_binding WHERE id = :i FOR UPDATE"), {"i": bid})
    row = _one(db, BINDING_SQL + "WHERE b.id = :i AND b.market_code = ANY(:m)", i=bid, m=list(markets))
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Binding not found or not available to you")
    row["survey_version_status"] = store.status_of(db, row["survey_version_id"])
    row["history"] = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.comment, e.occurred_at, p.display_name FROM survey_assignment_binding_event e "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.binding_id = :b ORDER BY e.seq",
        b=bid,
    )
    return row


def _rule_version(db: Session, rule_code: str, version: int, markets: Sequence[str]) -> dict[str, Any]:
    """A rule version of the EXISTING assignment rules, in the caller's markets (its market is its script family's)."""
    row = _one(
        db,
        "SELECT r.id, r.rule_code, r.version, r.status, f.market_code FROM script_assignment_rule_version r "
        "JOIN script_version v ON v.id = r.target_script_version_id JOIN script_family f ON f.id = v.script_family_id "
        "WHERE r.rule_code = :c AND r.version = :v AND f.market_code = ANY(:m)",
        c=rule_code, v=version, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "RULE_NOT_FOUND", "Assignment rule version not found or not available to you")
    return row


def propose(
    db: Session, markets: Sequence[str], rule_code: str, rule_version: int, survey_version_id: uuid.UUID, note: str,
    actor: Actor, meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    """Propose that an exact PUBLISHED rule version stands for an exact PUBLISHED survey version of the same market."""
    rule = _rule_version(db, rule_code, rule_version, markets)
    if rule["status"] != "PUBLISHED":
        raise SurveyError(
            409,
            "RULE_NOT_PUBLISHED",
            f"Rule version {rule_code} v{rule_version} is {rule['status'].lower()}; only a published rule version can be bound",
        )
    v = simulation._version(db, survey_version_id, markets)  # published, in scope, manifest intact
    if store.status_of(db, v["id"]) != "PUBLISHED":
        raise SurveyError(409, "VERSION_NOT_PUBLISHED", "Only the currently published survey version can be bound")
    market = _one(db, "SELECT market_code FROM survey_definition WHERE id = :i", i=v["survey_definition_id"])
    assert market is not None
    if market["market_code"] != rule["market_code"]:
        raise SurveyError(409, "MARKET_MISMATCH", "The rule and the survey version belong to different markets")
    for b in _all(db, "SELECT id FROM survey_assignment_binding WHERE rule_version_id = :r", r=rule["id"]):
        if binding_status(db, b["id"]) in OPEN:
            raise SurveyError(
                409, "BINDING_OPEN", "This rule version already has a binding awaiting a decision or publication"
            )
    bid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_assignment_binding (id, rule_version_id, rule_code, rule_version, market_code, "
            "survey_version_id, survey_definition_id, content_sha256, manifest_sha256, note, proposed_by) "
            "VALUES (:i, :r, :c, :n, :m, :v, :d, :cs, :ms, :note, :by)"
        ),
        {
            "i": bid, "r": rule["id"], "c": rule_code, "n": rule_version, "m": rule["market_code"], "v": v["id"],
            "d": v["survey_definition_id"], "cs": v["content_sha256"], "ms": v["manifest_sha256"], "note": note.strip(),
            "by": _ref(actor),
        },
    )  # fmt: skip
    _event(db, bid, "PROPOSED", actor, note)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.ASSIGNMENT_BINDING_PROPOSED",
        "survey_assignment_binding",
        bid,
        {"rule": f"{rule_code} v{rule_version}", "survey_version": str(v["id"])},
    )
    return bid


def decide(
    db: Session,
    bid: uuid.UUID,
    markets: Sequence[str],
    verdict: str,
    comment: str,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> None:
    b = binding(db, bid, markets, lock=True)
    if b["status"] != "PROPOSED":
        raise SurveyError(409, "NOT_PROPOSED", "This binding is not waiting for a decision")
    if _ref(actor) == b["proposed_by"]:
        _audit(
            db,
            actor,
            meta,
            "SURVEY.ASSIGNMENT_BINDING_DENIED",
            "survey_assignment_binding",
            bid,
            {"rule": "SELF_REVIEW_DENIED"},
        )
        raise SurveyError(403, "SELF_REVIEW_DENIED", "The person who proposed a binding cannot approve or reject it")
    if verdict == "REJECT" and len(comment.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "A rejection needs a comment of at least 10 characters")
    _event(db, bid, "APPROVED" if verdict == "APPROVE" else "REJECTED", actor, comment)
    _audit(
        db,
        actor,
        meta,
        f"SURVEY.ASSIGNMENT_BINDING_{'APPROVED' if verdict == 'APPROVE' else 'REJECTED'}",
        "survey_assignment_binding",
        bid,
        {},
    )


def publish(db: Session, bid: uuid.UUID, markets: Sequence[str], actor: Actor, meta: RequestMeta | None = None) -> None:
    b = binding(db, bid, markets, lock=True)
    if b["status"] != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved binding can be published")
    me = _ref(actor)
    if me == b["proposed_by"] or me == b["approved_by"]:
        code = "SELF_PUBLISH_DENIED" if me == b["proposed_by"] else "APPROVER_PUBLISH_DENIED"
        _audit(db, actor, meta, "SURVEY.ASSIGNMENT_BINDING_DENIED", "survey_assignment_binding", bid, {"rule": code})
        raise SurveyError(
            403, code, "The proposer and the approver of a binding cannot publish it: a third person must"
        )
    # everything it pins is checked again at the moment it takes effect
    rule = _one(db, "SELECT status FROM script_assignment_rule_version WHERE id = :i", i=b["rule_version_id"])
    if rule is None or rule["status"] != "PUBLISHED":
        raise SurveyError(409, "RULE_NOT_PUBLISHED", "The rule version is no longer published")
    v = simulation._version(db, b["survey_version_id"], markets)
    if store.status_of(db, v["id"]) != "PUBLISHED" or (v["content_sha256"], v["manifest_sha256"]) != (
        b["content_sha256"],
        b["manifest_sha256"],
    ):
        raise SurveyError(
            409, "VERSION_NOT_PUBLISHED", "The survey version is no longer the published version this binding pinned"
        )
    for other in _all(
        db,
        "SELECT id FROM survey_assignment_binding WHERE rule_version_id = :r AND id <> :i",
        r=b["rule_version_id"],
        i=bid,
    ):
        if binding_status(db, other["id"]) == "PUBLISHED":
            _event(db, other["id"], "SUPERSEDED", actor, f"superseded by binding {bid}")
    _event(db, bid, "PUBLISHED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.ASSIGNMENT_BINDING_PUBLISHED",
        "survey_assignment_binding",
        bid,
        {"rule": f"{b['rule_code']} v{b['rule_version']}", "survey_version": str(b["survey_version_id"])},
    )


def withdraw(
    db: Session, bid: uuid.UUID, markets: Sequence[str], reason: str, actor: Actor, may_unpublish: bool, meta: RequestMeta | None = None
) -> None:  # fmt: skip
    """An open proposal is withdrawn by its proposer. A PUBLISHED binding is withdrawn by a person who may publish:
    the rule then has no survey, and a selection that reaches it fails closed."""
    b = binding(db, bid, markets, lock=True)
    if len(reason.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Withdrawing needs a reason of at least 10 characters")
    if b["status"] in OPEN:
        if _ref(actor) != b["proposed_by"]:
            raise SurveyError(403, "NOT_PROPOSER", "Only the person who proposed a binding can withdraw the proposal")
    elif b["status"] == "PUBLISHED":
        if not may_unpublish:
            raise SurveyError(403, "FORBIDDEN", "Withdrawing a published binding needs the permission to publish")
    else:
        raise SurveyError(409, "NOT_OPEN", "This binding is closed")
    _event(db, bid, "WITHDRAWN", actor, reason)
    _audit(
        db, actor, meta, "SURVEY.ASSIGNMENT_BINDING_WITHDRAWN", "survey_assignment_binding", bid, {"was": b["status"]}
    )


# ------------------------------------------------------------------------------------------------ inputs and policy
def options(db: Session, markets: Sequence[str]) -> dict[str, Any]:
    """The governed assignment inputs and their values — the existing rule options, unchanged."""
    return ri.options(db, markets)


def check_inputs(db: Session, markets: Sequence[str], inputs: Any) -> dict[str, Any]:
    """Assignment inputs are the fields of the existing rule language with governed values. A field that is absent or
    null is UNKNOWN — it is never given a default. A value outside the governed list is refused, not left to
    silently fail to match."""
    if not isinstance(inputs, Mapping):
        raise SurveyError(422, "INPUTS_INVALID", "Assignment inputs are one object")
    unknown = sorted(k for k in inputs if k not in re_.FIELD_BY_KEY)
    if unknown:
        raise SurveyError(
            422,
            "INPUT_UNKNOWN",
            "An input names a field the assignment rules do not have",
            [{"field": k} for k in unknown],
        )
    market = inputs.get("market")
    if not isinstance(market, str) or not market:
        raise SurveyError(422, "MARKET_REQUIRED", "A synthetic application states its market")
    if market not in markets:
        # another market's rules and surveys do not exist for this person
        raise SurveyError(404, "NOT_FOUND", "That market is not available to you")
    allowed = {f["field"]: [v["value"] for v in f["values"]] for f in ri.options(db, [market])["fields"]}
    out: dict[str, Any] = {}
    for k, v in inputs.items():
        if v is None:
            continue
        multi = re_.FIELD_BY_KEY[k].multi_valued_input
        values = v if multi else [v]
        if multi and not isinstance(v, list):
            raise SurveyError(422, "INPUTS_INVALID", f"{k} is a list")
        bad = [x for x in values if not any(x == a and type(x) is type(a) for a in allowed[k])]
        if bad:
            raise SurveyError(
                422,
                "INPUT_VALUE_UNKNOWN",
                f"{k} has a value outside its governed list",
                [{"field": k, "value": x} for x in bad],
            )
        out[k] = sorted(v) if multi else v
    return out


def _published_bindings(db: Session, market: str) -> dict[tuple[str, int], dict[str, Any]]:
    return {(b["rule_code"], b["rule_version"]): b for b in bindings(db, [market]) if b["status"] == "PUBLISHED"}


def candidates(db: Session, market: str, at: datetime) -> tuple[list[re_.RuleCandidate], dict[str, dict[str, Any]]]:
    """The existing published rules of one market, each re-targeted to the survey version its published binding pins.
    Returns the candidates and, by rule reference, the binding used."""
    bound = _published_bindings(db, market)
    out: list[re_.RuleCandidate] = []
    used: dict[str, dict[str, Any]] = {}
    for c in ri.published_candidates(db, [market], at):
        b = bound.get((c.rule_code, c.version or 0))
        if b is None:
            # still a candidate with its full precedence: if it wins, the selection fails closed
            out.append(
                dataclasses.replace(
                    c, target_id=UNBOUND + c.ref, target_label="no survey bound", target_effective=False
                )
            )
            continue
        used[c.ref] = b
        out.append(
            dataclasses.replace(
                c, target_id=str(b["survey_version_id"]), target_label=f"{b['survey_code']} v{b['version_label']}",
                # exactly the rule the engine applies to script versions: published, and nothing else
                target_effective=b["survey_version_status"] == "PUBLISHED" and b["market_code"] == market,
            )
        )  # fmt: skip
    return out, used


def select(db: Session, market: str, inputs: Mapping[str, Any], at: datetime) -> dict[str, Any]:
    """The decision of the existing engine, with the survey binding of every rule. Pure given the database state."""
    cands, used = candidates(db, market, at)
    return decide_candidates(cands, used, inputs, at)


def decide_candidates(
    cands: Sequence[re_.RuleCandidate], used: Mapping[str, Mapping[str, Any]], inputs: Mapping[str, Any], at: datetime
) -> dict[str, Any]:
    """The existing engine's decision over the given candidates (all of a market for ASG-1; the members of one
    requirement group for ASG-2A), read as a survey selection. Pure."""
    dec = re_.evaluate(cands, inputs, at)
    outcome = dec.outcome
    winners = [c for c in cands if c.ref in dec.winning_rules]
    if outcome == "TARGET_NOT_EFFECTIVE" and winners and winners[0].target_id.startswith(UNBOUND):
        outcome = "SURVEY_NOT_BOUND"
    reason = (
        dec.reason.replace("script versions", "survey versions")
        .replace("script version", "survey version")
        .replace("no script can be selected", "no survey can be selected")
    )
    if outcome == "SURVEY_NOT_BOUND":
        reason = f"{winners[0].ref} wins, but no survey version is bound to it by a published binding; fails closed (no lower-precedence rule is used, and no fallback survey is chosen)"
    selected = used.get(dec.winning_rules[0]) if dec.selected_target_id and dec.winning_rules else None
    trace = []
    for t in dec.trace:
        line = _trace_json(t)
        b = used.get(t.ref)
        line["binding_id"] = str(b["id"]) if b else None
        line["survey_version_id"] = str(b["survey_version_id"]) if b else None
        line["survey_version_status"] = b["survey_version_status"] if b else None
        trace.append(line)
    missing = sorted(
        {c["field"] for t in trace if t["match"] == "UNKNOWN" for c in t["conditions"] if c["result"] == "UNKNOWN"}
    )
    return {
        "outcome": outcome, "selection": SELECTION[outcome], "reason": reason, "winning_rules": dec.winning_rules,
        "by_fallback": outcome == "SELECTED_BY_FALLBACK", "missing_inputs": missing,
        "selected": (
            {
                "rule": dec.winning_rules[0], "rule_version_id": str(selected["rule_version_id"]), "binding_id": str(selected["id"]),
                "survey_version_id": str(selected["survey_version_id"]), "survey_code": selected["survey_code"],
                "survey_name": selected["survey_name"], "version_label": selected["version_label"],
                "content_sha256": selected["content_sha256"], "manifest_sha256": selected["manifest_sha256"],
            }
            if selected else None
        ),
        "trace": trace,
    }  # fmt: skip


def policy(db: Session, markets: Sequence[str]) -> dict[str, Any]:
    """The assignment policy as a person reads it: the existing published rules in precedence order, each with the
    survey version bound to it, and every binding with its state."""
    at = _now()
    labels = ri.labels(ri.options(db, markets))
    all_bindings = bindings(db, markets)
    names = {
        (r["rule_code"], r["version"]): r
        for r in _all(
            db,
            "SELECT r.rule_code, r.version, r.id, p.name, f.market_code FROM script_assignment_rule_version r "
            "JOIN script_version v ON v.id = r.target_script_version_id JOIN script_family f ON f.id = v.script_family_id "
            "LEFT JOIN assignment_rule_publication p ON p.rule_version_id = r.id WHERE f.market_code = ANY(:m)",
            m=list(markets),
        )
    }
    rules = []
    for c in sorted(
        ri.published_candidates(db, list(markets), at), key=lambda x: (x.priority, -x.specificity, x.rule_code, x.ref)
    ):
        if c.status != "PUBLISHED":
            continue
        meta = names.get((c.rule_code, c.version or 0), {})
        mine = [b for b in all_bindings if (b["rule_code"], b["rule_version"]) == (c.rule_code, c.version)]
        rules.append(
            {
                "ref": c.ref, "rule_code": c.rule_code, "rule_version": c.version, "rule_version_id": meta.get("id"),
                "name": meta.get("name") or c.rule_code, "market_code": meta.get("market_code"),
                "priority": c.priority, "specificity": c.specificity, "is_fallback": c.is_fallback,
                "effective_now": re_.effective_at(c, at), "effective_from": c.effective_from, "effective_to": c.effective_to,
                "when": [re_.condition_text(x, labels) for x in c.conditions],
                "published_binding": next((str(b["id"]) for b in mine if b["status"] == "PUBLISHED"), None),
                "open_binding": next((str(b["id"]) for b in mine if b["status"] in OPEN), None),
            }
        )  # fmt: skip
    return {"rules": rules, "bindings": all_bindings, "engine": ENGINE, "note": NOTE}


# ------------------------------------------------------------------------------------------------------ evaluations
def evaluate(
    db: Session, markets: Sequence[str], assignment_inputs: Any, facts: Any, actor: Actor, meta: RequestMeta | None = None,
    at: datetime | None = None,
) -> uuid.UUID:  # fmt: skip
    """Select, verify, plan and record — for one synthetic application. The selected version's manifest is verified
    and the SS-03B assembler computes the plan; a selection without a version records no plan."""
    inputs = check_inputs(db, markets, assignment_inputs)
    market = inputs["market"]
    at = at or _now()
    decision = select(db, market, inputs, at)
    sel = decision["selected"]
    plan_id = fingerprint = None
    clean_facts = dict(facts) if isinstance(facts, Mapping) else None
    if clean_facts is None:
        raise SurveyError(422, "FACTS_INVALID", "Facts are one object")
    if sel:
        # the manifest of the selected version is verified, and the facts are checked against ITS catalog, inside
        plan_id = simulation.create_plan(db, uuid.UUID(sel["survey_version_id"]), [market], clean_facts, actor, meta)
        fingerprint = simulation.plan(db, plan_id, [market])["fingerprint"]
    elif len(json.dumps(clean_facts, default=str)) > 20000:
        raise SurveyError(422, "FACTS_INVALID", "The facts are too large")
    eid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_assignment_evaluation (id, market_code, assignment_inputs, facts, inputs_sha256, evaluated_at, "
            "engine, outcome, selection, decision, decision_sha256, rule_version_id, binding_id, survey_version_id, call_plan_id, "
            "plan_fingerprint, created_by) VALUES (:i, :m, CAST(:ai AS jsonb), CAST(:f AS jsonb), :ih, :at, :en, :o, :s, "
            "CAST(:d AS jsonb), :dh, :rv, :b, :sv, :cp, :fp, :by)"
        ),
        {
            "i": eid, "m": market, "ai": json.dumps(inputs), "f": json.dumps(clean_facts),
            "ih": sha256_hex({"assignment_inputs": inputs, "facts": json.loads(json.dumps(clean_facts))}), "at": at, "en": ENGINE,
            "o": decision["outcome"], "s": decision["selection"], "d": json.dumps(decision, default=str),
            "dh": sha256_hex(json.loads(json.dumps(decision, default=str))),
            "rv": sel["rule_version_id"] if sel else None, "b": sel["binding_id"] if sel else None,
            "sv": sel["survey_version_id"] if sel else None, "cp": plan_id, "fp": fingerprint, "by": _ref(actor),
        },
    )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.ASSIGNMENT_EVALUATED", "survey_assignment_evaluation", eid,
        {"record_class": RECORD_CLASS, "outcome": decision["outcome"], "survey_version": sel["survey_version_id"] if sel else None, "plan_fingerprint": fingerprint},
    )  # fmt: skip
    return eid


def evaluation(db: Session, eid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db, "SELECT * FROM survey_assignment_evaluation WHERE id = :i AND market_code = ANY(:m)", i=eid, m=list(markets)
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Selection not found or not available to you")
    plan = simulation.plan(db, row["call_plan_id"], markets) if row["call_plan_id"] else None
    # the selection is decided again now, at the recorded time, and a difference is reported — never hidden
    now = select(db, row["market_code"], row["assignment_inputs"], row["evaluated_at"])
    recomputed = sha256_hex(json.loads(json.dumps(now, default=str)))
    sims = _all(
        db,
        "SELECT simulation_id, created_at FROM survey_assignment_simulation WHERE evaluation_id = :e ORDER BY created_at, simulation_id",
        e=eid,
    )
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": NOTE, "market_code": row["market_code"],
        "assignment_inputs": row["assignment_inputs"], "facts": row["facts"], "inputs_sha256": row["inputs_sha256"],
        "evaluated_at": row["evaluated_at"], "created_at": row["created_at"], "engine": row["engine"],
        "outcome": row["outcome"], "selection": row["selection"], "decision": row["decision"],
        "decision_sha256": row["decision_sha256"], "recomputed_decision_sha256": recomputed,
        # false when the published rules or bindings in force at that time no longer give the recorded decision
        "recompute_consistent": recomputed == row["decision_sha256"] and row["engine"] == ENGINE,
        "survey_version_id": row["survey_version_id"], "binding_id": row["binding_id"],
        "call_plan_id": row["call_plan_id"], "plan_fingerprint": row["plan_fingerprint"], "call_plan": plan,
        "simulations": [str(s["simulation_id"]) for s in sims],
    }  # fmt: skip


def start_simulation(
    db: Session, eid: uuid.UUID, markets: Sequence[str], actor: Actor, meta: RequestMeta | None = None
) -> uuid.UUID:
    """A server simulation of the version this selection chose, with the same facts — linked to the selection."""
    row = _one(
        db, "SELECT * FROM survey_assignment_evaluation WHERE id = :i AND market_code = ANY(:m)", i=eid, m=list(markets)
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Selection not found or not available to you")
    if not row["survey_version_id"]:
        raise SurveyError(
            409, "NOTHING_SELECTED", "This selection chose no survey version, so there is nothing to simulate"
        )
    sim = simulation.create(
        db, row["survey_version_id"], markets, row["facts"], f"Assignment selection {str(eid)[:8]}", actor, meta
    )
    db.execute(
        text(
            "INSERT INTO survey_assignment_simulation (evaluation_id, simulation_id, created_by) VALUES (:e, :s, :by)"
        ),
        {"e": eid, "s": sim, "by": _ref(actor)},
    )
    return sim
