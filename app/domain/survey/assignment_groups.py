# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""ASG-2A — one application, several surveys: governed requirement groups and SIMULATED composite plans.

Semantics: ``Call360-specs/docs/plans/survey-studio/34_ASG-2A_GROUPING_AND_MATCHING_SEMANTICS.md``.

Nothing of the rule engine is changed or copied. ASG-1 calls it once over every published rule of a market and gets
one survey. Here it is called once PER REQUIREMENT GROUP, over that group's member rules only — so a rule competes
with the rules of its own requirement, and a complementary requirement is never discarded because another rule has a
higher global rank. The members are the same candidates ASG-1 uses, re-targeted through the same governed bindings
(``assignment.candidates`` / ``assignment.decide_candidates``).

For every selected survey the SS-03B assembler computes that survey's own plan, unchanged, with its own fingerprint.
The composite REFERS to those plans. There is no second executor, no merged routing graph, no de-duplication of
surveys or questions, and no decision about what happens between surveys: cross-survey continuation is reported as
UNRESOLVED, and ordering is used only where it was governed.

SIMULATION ONLY, for a synthetic application. Nothing here assigns a survey to a customer case.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain import rule_engine as re_
from app.domain.survey import assignment, simulation
from app.domain.survey.callplan import assemble
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

CONTRACT = "call360.survey.composite-plan/1"
KINDS = ("PRIMARY", "ADD_REQUIRED", "ALTERNATIVE")
CODE_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,39}$")
OPEN = assignment.OPEN
RECORD_CLASS = simulation.RECORD_CLASS
NOTE = (
    "SIMULATION ONLY, for a synthetic application. A set of selected surveys and a composite plan are not an "
    "assignment of any survey to any customer case, and not an authorisation or eligibility for any call."
)
INPUT_CONSISTENCY = {
    "status": "UNVERIFIED",
    "reason": (
        "The assignment inputs and the call-plan facts are two separate parts of the application snapshot. No approved "
        "mapping connects them, so nothing checks that they describe the same application."
    ),
}
CROSS_SURVEY_UNRESOLVED = (
    "Whether an escalation, a refusal, an incomplete answer or a terminal outcome in one survey allows another survey "
    "to proceed has not been decided. No combined run is built."
)
#: how a group's engine outcome reads as the state of its requirement
SELECTED = ("SELECTED", "SELECTED_BY_FALLBACK")


# ---------------------------------------------------------------------------------------------------------- groups
GROUP_SQL = (
    "SELECT g.*, "
    "(SELECT event FROM survey_assignment_group_event e WHERE e.group_id = g.id ORDER BY seq DESC LIMIT 1) AS status, "
    "(SELECT actor_ref FROM survey_assignment_group_event e WHERE e.group_id = g.id AND e.event = 'APPROVED' ORDER BY seq DESC LIMIT 1) AS approved_by "
    "FROM survey_assignment_group g "
)


def _members(db: Session, gid: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT m.rule_version_id, m.rule_code, m.rule_version, r.status AS rule_status FROM survey_assignment_group_member m "
        "JOIN script_assignment_rule_version r ON r.id = m.rule_version_id WHERE m.group_id = :g ORDER BY m.rule_code, m.rule_version",
        g=gid,
    )


def groups(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    rows = _all(db, GROUP_SQL + "WHERE g.market_code = ANY(:m) ORDER BY g.code, g.version", m=list(markets))
    for r in rows:
        r["members"] = _members(db, r["id"])
    return rows


def group(db: Session, gid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    if lock:
        db.execute(text("SELECT 1 FROM survey_assignment_group WHERE id = :i FOR UPDATE"), {"i": gid})
    row = _one(db, GROUP_SQL + "WHERE g.id = :i AND g.market_code = ANY(:m)", i=gid, m=list(markets))
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Group not found or not available to you")
    row["members"] = _members(db, gid)
    row["history"] = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.comment, e.occurred_at, p.display_name FROM survey_assignment_group_event e "
        "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref WHERE e.group_id = :g ORDER BY e.seq",
        g=gid,
    )
    return row


def _event(db: Session, gid: uuid.UUID, event: str, actor: Actor, comment: str = "") -> None:
    db.execute(
        text("INSERT INTO survey_assignment_group_event (group_id, event, actor_ref, comment) VALUES (:g, :e, :a, :c)"),
        {"g": gid, "e": event, "a": _ref(actor), "c": comment.strip()},
    )


def structure_problems(
    kind: str, members: Sequence[tuple[str, int]], bound: Mapping[tuple[str, int], Mapping[str, Any]]
) -> list[str]:
    """What makes a group's composition contradict its kind (semantics §4). Unbound members cannot be judged and are
    left to fail closed at selection."""
    out: list[str] = []
    surveys = {str(bound[m]["survey_definition_id"]) for m in members if m in bound}
    if not members:
        out.append("a group has at least one member rule")
    if kind == "ADD_REQUIRED" and len(surveys) > 1:
        out.append("an additional required survey is ONE survey: its member rules are bound to different surveys")
    if kind == "ALTERNATIVE":
        if len(members) < 2:
            out.append("an alternative group needs at least two member rules: with one, nothing competes")
        elif len([m for m in members if m in bound]) == len(members) and len(surveys) < 2:
            out.append(
                "an alternative group needs rules bound to at least two different surveys: with one, nothing competes"
            )
    return out


def propose(
    db: Session, markets: Sequence[str], code: str, kind: str, name: str, purpose: str, sequence: int | None,
    members: Sequence[Mapping[str, Any]], note: str, actor: Actor, meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    """Propose a new version of a requirement group: its kind, its stated purpose, its optional position in a governed
    ordering, and the exact published rule versions that compete to satisfy it."""
    if not CODE_RE.match(code):
        raise SurveyError(
            422, "GROUP_INVALID", "A group code is capitals, digits, hyphens and underscores, 3 to 40 characters"
        )
    if kind not in KINDS:
        raise SurveyError(422, "GROUP_INVALID", "A group is PRIMARY, ADD_REQUIRED or ALTERNATIVE")
    if len(name.strip()) < 3 or len(purpose.strip()) < 10:
        raise SurveyError(422, "PURPOSE_REQUIRED", "A group has a name and a stated purpose of at least 10 characters")
    if sequence is not None and sequence < 1:
        raise SurveyError(422, "GROUP_INVALID", "A position in the ordering is a whole number from 1")
    keys = [(str(m.get("rule_code")), int(m.get("rule_version") or 0)) for m in members]
    if len(set(keys)) != len(keys):
        raise SurveyError(422, "GROUP_INVALID", "A rule version is a member once")
    rules = [assignment._rule_version(db, c, v, markets) for c, v in keys]
    for r in rules:
        if r["status"] != "PUBLISHED":
            raise SurveyError(
                409,
                "RULE_NOT_PUBLISHED",
                f"Rule version {r['rule_code']} v{r['version']} is {r['status'].lower()}; only published rule versions can be members",
            )
    market_set = {r["market_code"] for r in rules}
    if len(market_set) > 1:
        raise SurveyError(409, "MARKET_MISMATCH", "The member rules belong to different markets")
    earlier = _all(
        db,
        "SELECT id, market_code, kind, version FROM survey_assignment_group WHERE code = :c ORDER BY version",
        c=code,
    )
    market = next(iter(market_set)) if market_set else (earlier[-1]["market_code"] if earlier else None)
    if market is None or market not in markets:
        raise SurveyError(422, "GROUP_INVALID", "A group needs at least one member rule of a market you work in")
    for e in earlier:
        if e["market_code"] != market or e["kind"] != kind:
            raise SurveyError(
                409, "GROUP_IDENTITY", "A group keeps its market and its kind across versions; use another code"
            )
        if _status(db, e["id"]) in OPEN:
            raise SurveyError(409, "GROUP_OPEN", "This group already has a version awaiting a decision or publication")
    problems = structure_problems(kind, keys, assignment._published_bindings(db, market))
    if problems:
        raise SurveyError(
            422,
            "GROUP_STRUCTURE_INVALID",
            "The members do not fit the kind of the group",
            [{"problem": p} for p in problems],
        )
    gid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_assignment_group (id, code, version, market_code, kind, name, purpose, sequence, note, proposed_by) "
            "VALUES (:i, :c, :v, :m, :k, :n, :p, :s, :note, :by)"
        ),
        {
            "i": gid,
            "c": code,
            "v": (earlier[-1]["version"] + 1) if earlier else 1,
            "m": market,
            "k": kind,
            "n": name.strip(),
            "p": purpose.strip(),
            "s": sequence,
            "note": note.strip(),
            "by": _ref(actor),
        },
    )
    for r in rules:
        db.execute(
            text(
                "INSERT INTO survey_assignment_group_member (group_id, rule_version_id, rule_code, rule_version) VALUES (:g, :r, :c, :v)"
            ),
            {"g": gid, "r": r["id"], "c": r["rule_code"], "v": r["version"]},
        )
    _event(db, gid, "PROPOSED", actor, note)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.ASSIGNMENT_GROUP_PROPOSED",
        "survey_assignment_group",
        gid,
        {"code": code, "kind": kind, "members": [f"{c} v{v}" for c, v in keys]},
    )
    return gid


def _status(db: Session, gid: uuid.UUID) -> str | None:
    row = _one(
        db, "SELECT event FROM survey_assignment_group_event WHERE group_id = :g ORDER BY seq DESC LIMIT 1", g=gid
    )
    return row["event"] if row else None


def decide(
    db: Session,
    gid: uuid.UUID,
    markets: Sequence[str],
    verdict: str,
    comment: str,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> None:
    g = group(db, gid, markets, lock=True)
    if g["status"] != "PROPOSED":
        raise SurveyError(409, "NOT_PROPOSED", "This group version is not waiting for a decision")
    if _ref(actor) == g["proposed_by"]:
        _audit(
            db,
            actor,
            meta,
            "SURVEY.ASSIGNMENT_GROUP_DENIED",
            "survey_assignment_group",
            gid,
            {"rule": "SELF_REVIEW_DENIED"},
        )
        raise SurveyError(403, "SELF_REVIEW_DENIED", "The person who proposed a group cannot approve or reject it")
    if verdict == "REJECT" and len(comment.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "A rejection needs a comment of at least 10 characters")
    _event(db, gid, "APPROVED" if verdict == "APPROVE" else "REJECTED", actor, comment)
    _audit(
        db,
        actor,
        meta,
        f"SURVEY.ASSIGNMENT_GROUP_{'APPROVED' if verdict == 'APPROVE' else 'REJECTED'}",
        "survey_assignment_group",
        gid,
        {},
    )


def publish(db: Session, gid: uuid.UUID, markets: Sequence[str], actor: Actor, meta: RequestMeta | None = None) -> None:
    g = group(db, gid, markets, lock=True)
    if g["status"] != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved group version can be published")
    me = _ref(actor)
    if me == g["proposed_by"] or me == g["approved_by"]:
        code = "SELF_PUBLISH_DENIED" if me == g["proposed_by"] else "APPROVER_PUBLISH_DENIED"
        _audit(db, actor, meta, "SURVEY.ASSIGNMENT_GROUP_DENIED", "survey_assignment_group", gid, {"rule": code})
        raise SurveyError(403, code, "The proposer and the approver of a group cannot publish it: a third person must")
    # everything is checked again at the moment it takes effect
    keys = [(m["rule_code"], m["rule_version"]) for m in g["members"]]
    if any(m["rule_status"] != "PUBLISHED" for m in g["members"]):
        raise SurveyError(409, "RULE_NOT_PUBLISHED", "A member rule version is no longer published")
    problems = structure_problems(g["kind"], keys, assignment._published_bindings(db, g["market_code"]))
    others = [x for x in groups(db, [g["market_code"]]) if x["status"] == "PUBLISHED" and x["code"] != g["code"]]
    if g["kind"] == "PRIMARY" and any(x["kind"] == "PRIMARY" for x in others):
        problems.append("the market already has a published PRIMARY group: an application has one primary survey")
    taken = {(m["rule_code"], m["rule_version"]): x["code"] for x in others for m in x["members"]}
    problems += [
        f"{c} v{v} is already a member of published group {taken[(c, v)]}: a rule serves one requirement"
        for c, v in keys
        if (c, v) in taken
    ]
    if problems:
        raise SurveyError(
            409,
            "GROUP_STRUCTURE_INVALID",
            "This group cannot be published as it stands",
            [{"problem": p} for p in problems],
        )
    for other in _all(db, "SELECT id FROM survey_assignment_group WHERE code = :c AND id <> :i", c=g["code"], i=gid):
        if _status(db, other["id"]) == "PUBLISHED":
            _event(db, other["id"], "SUPERSEDED", actor, f"superseded by version {g['version']}")
    _event(db, gid, "PUBLISHED", actor)
    _audit(
        db,
        actor,
        meta,
        "SURVEY.ASSIGNMENT_GROUP_PUBLISHED",
        "survey_assignment_group",
        gid,
        {"code": g["code"], "version": g["version"], "kind": g["kind"]},
    )


def withdraw(
    db: Session,
    gid: uuid.UUID,
    markets: Sequence[str],
    reason: str,
    actor: Actor,
    may_unpublish: bool,
    meta: RequestMeta | None = None,
) -> None:
    g = group(db, gid, markets, lock=True)
    if len(reason.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Withdrawing needs a reason of at least 10 characters")
    if g["status"] in OPEN:
        if _ref(actor) != g["proposed_by"]:
            raise SurveyError(
                403, "NOT_PROPOSER", "Only the person who proposed a group version can withdraw the proposal"
            )
    elif g["status"] == "PUBLISHED":
        if not may_unpublish:
            raise SurveyError(403, "FORBIDDEN", "Withdrawing a published group needs the permission to publish")
    else:
        raise SurveyError(409, "NOT_OPEN", "This group version is closed")
    _event(db, gid, "WITHDRAWN", actor, reason)
    _audit(db, actor, meta, "SURVEY.ASSIGNMENT_GROUP_WITHDRAWN", "survey_assignment_group", gid, {"was": g["status"]})


# ------------------------------------------------------------------------------------------------------- selection
def _group_ref(g: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(g["id"]),
        "code": g["code"],
        "version": g["version"],
        "kind": g["kind"],
        "name": g["name"],
        "purpose": g["purpose"],
        "sequence": g["sequence"],
    }


def select_set(db: Session, market: str, inputs: Mapping[str, Any], at: datetime) -> dict[str, Any]:
    """Every requirement of one application: the existing engine once per published group, over that group's rules."""
    cands, used = assignment.candidates(db, market, at)
    bound = assignment._published_bindings(db, market)
    published = sorted(
        (g for g in groups(db, [market]) if g["status"] == "PUBLISHED"),
        key=lambda g: (KINDS.index(g["kind"]), g["code"]),
    )
    issues: list[dict[str, Any]] = []
    primaries = [g for g in published if g["kind"] == "PRIMARY"]
    if not primaries:
        issues.append(
            {
                "code": "PRIMARY_GROUP_MISSING",
                "at": market,
                "detail": "No PRIMARY group is published for this market: the primary survey cannot be determined",
            }
        )
    if len(primaries) > 1:
        issues.append(
            {
                "code": "PRIMARY_GROUP_CONFLICT",
                "at": ", ".join(g["code"] for g in primaries),
                "detail": "More than one PRIMARY group is published: an application has one primary survey",
            }
        )
    owner: dict[tuple[str, int], list[str]] = {}
    for g in published:
        for m in g["members"]:
            owner.setdefault((m["rule_code"], m["rule_version"]), []).append(g["code"])
    shared = {k: v for k, v in owner.items() if len(v) > 1}
    for (shared_code, shared_version), codes in sorted(shared.items()):
        issues.append(
            {
                "code": "RULE_IN_SEVERAL_GROUPS",
                "at": f"{shared_code} v{shared_version}",
                "detail": f"Member of {', '.join(codes)}: which requirement it serves is not determinable",
            }
        )

    requirements: list[dict[str, Any]] = []
    for g in published:
        keys = [(m["rule_code"], m["rule_version"]) for m in g["members"]]
        problems = structure_problems(g["kind"], keys, bound)
        live = [m for m in g["members"] if m["rule_status"] == "PUBLISHED"]
        if not live:
            problems.append("no member rule version is published any more")
        if problems:
            issues.append(
                {
                    "code": "GROUP_STRUCTURE_INVALID" if live else "MEMBER_NOT_PUBLISHED",
                    "at": g["code"],
                    "detail": "; ".join(problems),
                }
            )
        subset = [x for x in cands if (x.rule_code, x.version or 0) in keys]
        d = assignment.decide_candidates(subset, used, inputs, at)
        outcome = d["outcome"]
        if outcome in SELECTED and not problems and not any(k in shared for k in keys):
            state = "SELECTED"
        elif outcome == "NO_MATCH" and g["kind"] != "PRIMARY" and not problems:
            state = "NOT_APPLICABLE"
        else:
            state = "UNRESOLVED"
        requirements.append(
            {
                "group": _group_ref(g),
                "state": state,
                **d,
                "selected": d["selected"] if state == "SELECTED" else None,
                "would_select": d["selected"],
            }
        )

    # rules that carry a survey but belong to no requirement: never dropped silently when they bear on the application
    grouped = set(owner)
    ignored_script_rules = 0
    ungrouped: list[dict[str, Any]] = []
    for cand in cands:
        if (
            (cand.rule_code, cand.version or 0) in grouped
            or cand.status != "PUBLISHED"
            or not re_.effective_at(cand, at)
        ):
            continue
        if cand.ref not in used:
            ignored_script_rules += 1  # a script rule with no survey: it takes no part in survey assignment
            continue
        match, _ = re_.match_rule(cand, inputs)
        ungrouped.append({"rule": cand.ref, "match": match, "survey": cand.target_label})
        if match in ("MATCH", "UNKNOWN"):
            issues.append({
                "code": "BOUND_RULE_UNGROUPED", "at": cand.ref,
                "detail": f"Bound to {cand.target_label} and {'matches' if match == 'MATCH' else 'may match'} this application, but belongs to no requirement group: its role is not governed",
            })  # fmt: skip

    status = (
        "UNRESOLVED_CONFIGURATION"
        if issues
        else "UNRESOLVED_REQUIREMENT"
        if any(r["state"] == "UNRESOLVED" for r in requirements)
        else "RESOLVED"
    )
    return {
        "selection_status": status, "configuration_issues": issues, "requirements": requirements,
        "ungrouped_bound_rules": ungrouped, "ignored_script_rules": ignored_script_rules,
    }  # fmt: skip


def ordering_of(selected: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Only a governed order is an order (semantics §8). Otherwise the surveys are listed, and the listing says it is
    not an order of execution."""
    listing = [r["group"]["code"] for r in selected]
    if len(selected) <= 1:
        return {"status": "NOT_APPLICABLE", "reason": None, "order": listing, "listing": listing}
    seqs = [r["group"]["sequence"] for r in selected]
    reason = (
        "ABSENT"
        if all(s is None for s in seqs)
        else "PARTIAL"
        if any(s is None for s in seqs)
        else "CONFLICTING"
        if len(set(seqs)) != len(seqs)
        else None
    )
    if reason:
        return {
            "status": "UNRESOLVED",
            "reason": reason,
            "order": None,
            "listing": listing,
            "note": "The listing is not an order of execution: no complete, unambiguous ordering is governed.",
        }
    return {
        "status": "GOVERNED",
        "reason": None,
        "order": [r["group"]["code"] for r in sorted(selected, key=lambda r: r["group"]["sequence"])],
        "listing": listing,
    }


def _plan_summary(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": plan["status"], "fingerprint": plan["fingerprint"], "issues": plan["issues"],
        "missing_facts": [i["field"] for i in plan["inputs"] if i["state"] != "PRESENT"],
        "open_points": sum(len(m["open"]) for m in plan["modules"] if m["status"] != "OUT"),
        "modules": [{"instance": m["instance"], "name": m["name"], "status": m["status"]} for m in plan["modules"]],
        "items": plan["counts"]["items"],
    }  # fmt: skip


def compose_pure(
    db: Session, market: str, inputs: Mapping[str, Any], facts: Mapping[str, Any], at: datetime
) -> dict[str, Any]:
    """The composite for one application, computed without recording anything: the selection, then the SS-03B
    assembler once for each selected survey version, on that version's own pinned documents."""
    sel = select_set(db, market, inputs, at)
    chosen = [r for r in sel["requirements"] if r["state"] == "SELECTED"]
    for r in chosen:
        v = simulation._version(db, uuid.UUID(r["selected"]["survey_version_id"]), [market])  # manifest verified
        clean = simulation.check_facts(simulation.version_bundle(db, v), facts)
        r["plan"] = _plan_summary(assemble(simulation.version_bundle(db, v), json.loads(json.dumps(clean))))
    ordering = ordering_of(chosen)
    settled = sel["selection_status"] == "RESOLVED" and ordering["status"] in ("GOVERNED", "NOT_APPLICABLE")
    plan_status = (
        "UNRESOLVED" if not settled else "READY" if all(r["plan"]["status"] == "READY" for r in chosen) else "BLOCKED"
    )
    application = {"assignment_inputs": dict(inputs), "facts": json.loads(json.dumps(dict(facts)))}
    composite: dict[str, Any] = {
        "schema": CONTRACT, "engine": assignment.ENGINE, "market": market,
        "application": {**application, "sha256": sha256_hex(application)},
        "input_consistency": INPUT_CONSISTENCY,
        "policy": {
            "groups": [{k: r["group"][k] for k in ("id", "code", "version", "kind", "sequence")} for r in sel["requirements"]],
            "rules": sorted({t["ref"] for r in sel["requirements"] for t in r["trace"]}),
            "bindings": sorted({t["binding_id"] for r in sel["requirements"] for t in r["trace"] if t["binding_id"]}),
        },
        "configuration_issues": sel["configuration_issues"],
        "requirements": [{k: v for k, v in r.items() if k != "would_select"} | {"would_select": r["would_select"] if r["state"] == "UNRESOLVED" else None} for r in sel["requirements"]],
        "selected": [
            {
                "group": r["group"]["code"], "kind": r["group"]["kind"], "rule": r["selected"]["rule"], "binding_id": r["selected"]["binding_id"],
                "survey_version_id": r["selected"]["survey_version_id"], "survey_code": r["selected"]["survey_code"], "survey_name": r["selected"]["survey_name"],
                "version_label": r["selected"]["version_label"], "content_sha256": r["selected"]["content_sha256"], "manifest_sha256": r["selected"]["manifest_sha256"],
                "reason": r["reason"], "by_fallback": r["by_fallback"], "plan_status": r["plan"]["status"], "plan_fingerprint": r["plan"]["fingerprint"],
            }
            for r in chosen
        ],
        "ungrouped_bound_rules": sel["ungrouped_bound_rules"], "ignored_script_rules": sel["ignored_script_rules"],
        "ordering": ordering,
        "cross_survey_policy": {"status": "UNRESOLVED", "note": CROSS_SURVEY_UNRESOLVED} if len(chosen) > 1 else {"status": "NOT_APPLICABLE", "note": "One survey: nothing happens between surveys."},
        "missing_inputs": sorted({m for r in sel["requirements"] for m in r["missing_inputs"]}),
        "missing_facts": sorted({m for r in chosen for m in r["plan"]["missing_facts"]}),
        "selection_status": sel["selection_status"], "plan_status": plan_status,
    }  # fmt: skip
    composite["fingerprint"] = sha256_hex(json.loads(json.dumps(composite, default=str)))
    return composite


def compose(
    db: Session, markets: Sequence[str], assignment_inputs: Any, facts: Any, actor: Actor, meta: RequestMeta | None = None,
    at: datetime | None = None,
) -> uuid.UUID:  # fmt: skip
    """Select, verify, plan each selected survey with the SS-03B assembler, and record the composite."""
    inputs = assignment.check_inputs(db, markets, assignment_inputs)
    market = inputs["market"]
    if not isinstance(facts, Mapping) or len(json.dumps(dict(facts), default=str)) > 20000:
        raise SurveyError(422, "FACTS_INVALID", "Facts are one object of governed catalog fields")
    at = at or assignment._now()
    composite = compose_pure(db, market, inputs, facts, at)
    cid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_composite_plan (id, market_code, assignment_inputs, facts, application_sha256, evaluated_at, contract, "
            "selection_status, ordering_status, plan_status, composite, fingerprint, created_by) VALUES (:i, :m, CAST(:ai AS jsonb), "
            "CAST(:f AS jsonb), :ah, :at, :c, :ss, :os, :ps, CAST(:j AS jsonb), :fp, :by)"
        ),
        {
            "i": cid, "m": market, "ai": json.dumps(inputs), "f": json.dumps(dict(facts)), "ah": composite["application"]["sha256"], "at": at, "c": CONTRACT,
            "ss": composite["selection_status"], "os": composite["ordering"]["status"], "ps": composite["plan_status"],
            "j": json.dumps(composite, default=str), "fp": composite["fingerprint"], "by": _ref(actor),
        },
    )  # fmt: skip
    for n, r in enumerate(composite["requirements"], start=1):
        sel = r["selected"]
        plan_id = None
        if sel:
            # the individual plan is recorded as its own SS-03B call plan, with its own fingerprint
            plan_id = simulation.create_plan(db, uuid.UUID(sel["survey_version_id"]), [market], facts, actor, meta)
            if simulation.plan(db, plan_id, [market])["fingerprint"] != r["plan"]["fingerprint"]:
                raise SurveyError(
                    500,
                    "PLAN_FINGERPRINT_MISMATCH",
                    "The recorded plan is not the plan the composite was computed from",
                )
        db.execute(
            text(
                "INSERT INTO survey_composite_plan_member (composite_id, position, group_id, kind, state, outcome, rule_version_id, binding_id, "
                "survey_version_id, call_plan_id, plan_fingerprint) VALUES (:c, :n, :g, :k, :s, :o, :rv, :b, :sv, :cp, :fp)"
            ),
            {
                "c": cid, "n": n, "g": r["group"]["id"], "k": r["group"]["kind"], "s": r["state"], "o": r["outcome"],
                "rv": sel["rule_version_id"] if sel else None, "b": sel["binding_id"] if sel else None,
                "sv": sel["survey_version_id"] if sel else None, "cp": plan_id, "fp": r["plan"]["fingerprint"] if sel else None,
            },
        )  # fmt: skip
    _audit(
        db, actor, meta, "SURVEY.COMPOSITE_PLAN_GENERATED", "survey_composite_plan", cid,
        {"record_class": RECORD_CLASS, "selection_status": composite["selection_status"], "plan_status": composite["plan_status"], "surveys": len(composite["selected"]), "fingerprint": composite["fingerprint"]},
    )  # fmt: skip
    return cid


#: Three different questions, never merged (owner decision of ASG-2A acceptance). A plan that can be computed does not
#: mean a coordinated simulation may run, and neither says anything about a real call.
OPERATIONAL_ELIGIBILITY = {
    "status": "NOT_ESTABLISHED",
    "note": "Whether any of this may be used on a real customer call has not been established, and nothing here establishes it.",
}


def coordination_blockers(composite_doc: Mapping[str, Any], recompute_consistent: bool) -> list[dict[str, Any]]:
    """Why a coordinated SIMULATION of this composite may not start. Empty = it may. Pure. Each blocker is a stable
    code; none is a business decision — each names one that has not been made, or a fact that is missing."""
    out: list[dict[str, Any]] = []
    selected = list(composite_doc["selected"])
    if composite_doc["selection_status"] != "RESOLVED":
        out.append(
            {
                "code": "SELECTION_UNRESOLVED",
                "at": composite_doc["selection_status"],
                "detail": "Which surveys the application requires is not settled.",
            }
        )
    if not selected:
        out.append({"code": "NOTHING_SELECTED", "at": "", "detail": "No survey is selected."})
    ordering = composite_doc["ordering"]
    if ordering["status"] == "UNRESOLVED":
        out.append(
            {
                "code": "ORDER_UNRESOLVED",
                "at": ordering.get("reason") or "",
                "detail": "No complete, unambiguous order of the surveys is governed.",
            }
        )
    for s in selected:
        if s["plan_status"] != "READY":
            out.append(
                {
                    "code": "PLAN_BLOCKED",
                    "at": s["group"],
                    "detail": f"The call plan of {s['survey_code']} v{s['version_label']} is blocked: it cannot be computed for this application.",
                }
            )
    versions: dict[str, list[str]] = {}
    for s in selected:
        versions.setdefault(s["survey_version_id"], []).append(s["group"])
    for by in versions.values():
        if len(by) > 1:
            out.append({
                "code": "DUPLICATE_SURVEY_REQUIREMENT_UNRESOLVED", "at": ", ".join(by),
                "detail": "Two requirements select the same survey version. Whether it is run once or twice has not been decided: neither is done.",
            })  # fmt: skip
    if not recompute_consistent:
        out.append(
            {
                "code": "COMPOSITE_STALE",
                "at": "",
                "detail": "The rules, bindings, groups or survey versions have changed since this composite was recorded. Generate a new one.",
            }
        )
    return out


def three_states(composite_doc: Mapping[str, Any], recompute_consistent: bool) -> dict[str, Any]:
    blockers = coordination_blockers(composite_doc, recompute_consistent)
    plan = composite_doc["plan_status"]
    return {
        "call_plan": {
            "status": "COMPUTABLE" if plan == "READY" else "NOT_COMPUTABLE" if plan == "BLOCKED" else "UNRESOLVED"
        },
        "coordinated_simulation": {"status": "BLOCKED" if blockers else "PERMITTED", "blockers": blockers},
        "operational_call_eligibility": OPERATIONAL_ELIGIBILITY,
    }


def composite(db: Session, cid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db, "SELECT * FROM survey_composite_plan WHERE id = :i AND market_code = ANY(:m)", i=cid, m=list(markets)
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Composite plan not found or not available to you")
    members = _all(
        db,
        "SELECT position, group_id, kind, state, outcome, rule_version_id, binding_id, survey_version_id, call_plan_id, plan_fingerprint "
        "FROM survey_composite_plan_member WHERE composite_id = :c ORDER BY position",
        c=cid,
    )
    # the recorded composite is what is returned. It is also computed again for the recorded time; a difference — a
    # newer survey version, a changed binding or group — is reported and never applied to the record.
    try:
        recomputed = compose_pure(db, row["market_code"], row["assignment_inputs"], row["facts"], row["evaluated_at"])[
            "fingerprint"
        ]
    except SurveyError:
        recomputed = None
    plans = [
        p for p in (simulation.plan(db, m["call_plan_id"], markets) if m["call_plan_id"] else None for m in members)
    ]
    stored = dict(row["composite"])
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": NOTE, "market_code": row["market_code"],
        "contract": row["contract"], "evaluated_at": row["evaluated_at"], "created_at": row["created_at"],
        "application_sha256": row["application_sha256"], "selection_status": row["selection_status"],
        "ordering_status": row["ordering_status"], "plan_status": row["plan_status"], "fingerprint": row["fingerprint"],
        "fingerprint_verified": sha256_hex({k: v for k, v in stored.items() if k != "fingerprint"}) == row["fingerprint"],
        "recomputed_fingerprint": recomputed,
        "recompute_consistent": recomputed == row["fingerprint"] and row["contract"] == CONTRACT,
        "states": three_states(stored, recomputed == row["fingerprint"] and row["contract"] == CONTRACT),
        "composite": stored,
        "members": [
            {
                **{k: m[k] for k in ("position", "group_id", "kind", "state", "outcome", "rule_version_id", "binding_id", "survey_version_id", "call_plan_id", "plan_fingerprint")},
                # each individual plan is still the plan that was recorded, with the fingerprint it had
                "plan_intact": p is None or (p["fingerprint"] == m["plan_fingerprint"] and p["fingerprint_verified"]),
            }
            for m, p in zip(members, plans, strict=True)
        ],
    }  # fmt: skip
