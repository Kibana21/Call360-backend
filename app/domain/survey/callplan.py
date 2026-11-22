# ruff: noqa: E501 — plan records are kept one per line so each can be read against the contract
"""SS-03B.2 — the deterministic pre-call plan. SIMULATION ONLY. Pure.

What can be settled BEFORE a call from one immutable fact snapshot and one survey definition:
  * which modules are IN, OUT, CONDITIONAL on what happens during the call, or HALT because they cannot be decided;
  * for every item that may be delivered, the exact pinned wording rendered with these facts — or that it cannot be;
  * every point still OPEN, where a customer's answer (not the plan) decides the route, with its alternatives;
  * the facts it read and how each stood; stable issue codes; and a fingerprint of the whole plan.

The same definition and the same facts always give the same plan and the same fingerprint. UNKNOWN is never read as
FALSE; a missing fact is never guessed or defaulted; a number is never rounded or truncated; an item that cannot be
delivered blocks the plan.

**A computed plan is not evidence that a real call may be made.** ``status`` answers ONE question — can a technical
plan be computed from these facts — and says nothing about approval of wording, consent, assignment, channel or any
undecided policy. Live-call eligibility is a separate concern and is not computed here at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import ConditionError, evaluate, fields_of
from app.domain.survey.documents import SINGLE_ROUTE_TYPES, Bundle
from app.domain.survey.validator import routes_from, variables_of
from app.domain.survey.wording import format_value, is_missing, render

Doc = Mapping[str, Any]
SCHEMA = "call360.survey.call-plan/1"
ISSUE_CODES = ("WORDING_VALUE_MISSING", "ELIGIBILITY_UNKNOWN", "MODULE_MISSING", "CONDITION_INVALID")
MODULE_STATUSES = ("IN", "OUT", "CONDITIONAL", "HALTS")


def fact_state(field: Doc | None, v: Any) -> dict[str, Any]:
    """How one fact stands: PRESENT with the value as it would be shown, MISSING, or INVALID. Never coerced."""
    if is_missing(v):
        return {"state": "MISSING", "value": None}
    if field and field.get("type") == "BOOLEAN":
        return {"state": "PRESENT", "value": v} if isinstance(v, bool) else {"state": "INVALID", "value": None}
    shown = format_value(field, v) if field else None
    return {"state": "INVALID", "value": None} if shown is None else {"state": "PRESENT", "value": shown}


def reachable(module: Doc) -> list[str]:
    """The nodes a run can reach from the module's entry, in the document's own order."""
    by = {n["node"]: n for n in module["nodes"]}
    seen: set[str] = set()
    stack = [module["entry"]] if module.get("entry") in by else []
    while stack:
        nid = stack.pop()
        if nid in seen or nid not in by:
            continue
        seen.add(nid)
        stack.extend(to["node"] for _, to in routes_from(module, by[nid]) if isinstance(to, Mapping) and "node" in to)
    return [n["node"] for n in module["nodes"] if n["node"] in seen]


def on_every_path(module: Doc, node_id: str) -> bool:
    """True when every path from the entry to any ending passes through ``node_id``."""
    entry = module.get("entry")
    if not entry:
        return False
    if entry == node_id:
        return True
    by = {n["node"]: n for n in module["nodes"]}
    seen, stack = {node_id}, [entry]  # walk the module as if this node were not there
    while stack:
        nid = stack.pop()
        if nid in seen or nid not in by:
            continue
        seen.add(nid)
        for _, to in routes_from(module, by[nid]):
            if "outcome" in to:
                return False  # an ending is reachable without it
            if "node" in to:
                stack.append(to["node"])
    return True


def _open_point(module: Doc, node: Doc, kind: str, options: list[Doc]) -> list[dict[str, Any]] | None:
    """The alternatives at a question where the ANSWER decides the route; None when every answer leads to one place."""
    r = node.get("routing") or {}
    mode = r.get("mode")
    if kind in SINGLE_ROUTE_TYPES or mode == "ALL_TO_NEXT":
        return None
    edges = [e for e in module["edges"] if e["from"] == node["node"]]
    if mode == "PER_CHOICE":
        alts = []
        for o in options:
            edge = next((e for e in edges if e["on"] == o["code"]), None) or next(
                (e for e in edges if e["on"] == "ANY"), None
            )
            alts.append({"on": o["code"], "to": edge["to"] if edge else None})
        # open only when the answer really chooses: every answer leading to the same place settles nothing
        return alts if len({sha256_hex(a["to"]) for a in alts}) > 1 else None
    if mode == "ORDERED_RULES":
        return [
            *({"on": f"RULE:{rule['rule']}", "to": rule.get("to")} for rule in r.get("rules") or []),
            {"on": "FALLBACK", "to": r.get("fallback")},
        ]
    out: list[dict[str, Any]] = []
    for f in r.get("followups") or []:
        nodes = f.get("nodes") or []
        out.append({"on": f"FOLLOWUP:{f['option']}", "to": {"node": nodes[0]} if nodes else None})
    for i in r.get("interrupts") or []:
        policy = i.get("policy", "STOP_ESCALATE")
        nodes = i.get("nodes") or []
        to = (
            ({"outcome": i["outcome"]} if i.get("outcome") else None)
            if policy == "STOP_ESCALATE"
            else i.get("rejoin")
            if policy == "STOP_REJOIN"
            else {"node": nodes[0]}
            if nodes
            else None
        )
        out.append({"on": f"INTERRUPT:{i['option']}", "to": to})
    out.append({"on": "REJOIN", "to": r.get("rejoin")})
    return out


def assemble(bundle: Bundle, facts: Mapping[str, Any]) -> dict[str, Any]:
    """The call plan of one survey definition for one fact snapshot."""
    clean = {k: v for k, v in facts.items() if not is_missing(v)}
    issues: list[dict[str, str]] = []
    used: dict[str, list[str]] = {}

    def note(code: str, by: str) -> None:
        if by not in used.setdefault(code, []):
            used[code].append(by)

    modules: list[dict[str, Any]] = []
    for inst in bundle.survey.get("sequence") or []:
        iid = inst["instance"]
        m = bundle.module_of(inst)
        base = {"instance": iid, "module": dict(inst.get("module") or {}), "name": str((m or {}).get("name") or iid)}
        if m is None:
            issues.append({"code": "MODULE_MISSING", "at": iid})
            modules.append(
                {**base, "status": "HALTS", "reason": "MODULE_MISSING", "eligibility": None, "items": [], "open": []}
            )
            continue
        # ---- selection and eligibility: everything here is decided from the facts alone ----
        status, reason, eligibility = "IN", "NO_CONDITION", None
        elig, act = inst.get("eligibility"), inst.get("activation")
        if elig:
            cond = bundle.condition_of(elig)
            result = "UNKNOWN"
            reads: list[dict[str, Any]] = []
            if cond:
                try:
                    result = evaluate(cond.get("ast") or {}, elig.get("params") or {}, clean, {}).result
                except ConditionError as exc:
                    issues.append({"code": "CONDITION_INVALID", "at": iid})
                    reason = exc.code
                for code in sorted(fields_of(cond.get("ast") or {})):
                    note(code, f"ELIGIBILITY:{iid}")
                    reads.append({"field": code, **fact_state(bundle.fields.get(code), facts.get(code))})
            policy = elig.get("unknown_policy")
            if result == "TRUE":
                reason = "ELIGIBLE"
            elif result == "FALSE":
                status, reason = "OUT", "NOT_ELIGIBLE"
            elif policy == "SKIP_WITH_REASON":
                status, reason = "OUT", "UNKNOWN_SKIPPED"  # recorded as "information missing", never as "did not match"
            else:
                status, reason = "HALTS", "UNKNOWN_HALTS"
                issues.append({"code": "ELIGIBILITY_UNKNOWN", "at": iid})
            eligibility = {
                "result": result,
                "unknown_policy": policy,
                "condition": dict(elig.get("condition") or {}),
                "reads": reads,
            }
        if status == "IN" and act:
            status, reason = "CONDITIONAL", "ON_OUTCOME"  # selected only by what happens during the call
        if status == "OUT":
            modules.append(
                {
                    **base,
                    "status": status,
                    "reason": reason,
                    "eligibility": eligibility,
                    "activation": act,
                    "items": [],
                    "open": [],
                }
            )
            continue

        # ---- the items that may be delivered, with the exact wording for these facts ----
        items: list[dict[str, Any]] = []
        opens: list[dict[str, Any]] = []
        by = {n["node"]: n for n in m["nodes"]}
        for nid in reachable(m):
            n = by[nid]
            key = f"{iid}/{nid}"
            if n.get("type") == "DECISION":
                edges = {e["on"]: e["to"] for e in m["edges"] if e["from"] == nid}
                opens.append(
                    {
                        "key": key,
                        "kind": "CONDITION",
                        "alternatives": [{"on": on, "to": edges.get(on)} for on in ("MATCH", "NO_MATCH", "UNKNOWN")],
                    }
                )
                continue
            item, wording = bundle.item_of(n), bundle.wording_of(n)
            if item is None or wording is None:
                continue
            statement = item["answer_type"] == "STATEMENT"
            source = str(wording.get("text") or "").strip()
            rendered = render(source, bundle.fields, facts)
            for v in variables_of(str(wording.get("text") or "")):
                if v in bundle.fields:
                    note(v, f"WORDING:{key}")
            if rendered["text"] is None:
                issues.append({"code": "WORDING_VALUE_MISSING", "at": key})  # an undeliverable item blocks the plan
            items.append(
                {
                    "key": key,
                    "node": nid,
                    "item": {"code": n["item"]["code"], "version": n["item"]["version"]},
                    "statement": statement,
                    "answer_type": item["answer_type"],
                    "role": (item.get("statement_role") or "TRANSITION") if statement else item.get("lifecycle_role"),
                    "mandatory": item.get("response_obligation") == "MANDATORY",
                    "delivery_mode": wording.get("delivery_mode"),
                    "wording_version": n["item"]["wording_version"],
                    "source": source,
                    "text": rendered["text"],
                    "values": rendered["values"],
                    "errors": rendered["errors"],
                    "certainty": "ALWAYS" if n.get("role") != "FOLLOWUP" and on_every_path(m, nid) else "SOME",
                }
            )
            alternatives = _open_point(m, n, item["answer_type"], bundle.options_of(item))
            if alternatives:
                opens.append({"key": key, "kind": "ANSWER", "alternatives": alternatives})
        # ---- where the module's own ending leads in the survey ----
        outs = [o for o in m.get("outcomes") or [] if o in bundle.outcomes]
        if len(outs) > 1:
            routes = inst.get("routes") or {}
            opens.append(
                {
                    "key": f"{iid}:outcome",
                    "kind": "OUTCOME",
                    "alternatives": [
                        {"on": o, "to": {"survey_outcome": o} if bundle.outcomes[o] == "ESCALATION" else routes.get(o)}
                        for o in outs
                    ],
                }
            )
        modules.append(
            {
                **base,
                "status": status,
                "reason": reason,
                "eligibility": eligibility,
                "activation": act,
                "items": items,
                "open": opens,
            }
        )

    inputs = [
        {"field": code, "type": f.get("type"), **fact_state(f, facts.get(code)), "used_by": used[code]}
        for code, f in bundle.fields.items()
        if code in used
    ]
    live = [x for x in modules if x["status"] != "OUT"]
    all_items = [i for x in live for i in x["items"]]
    plan: dict[str, Any] = {
        "schema": SCHEMA,
        "survey": bundle.survey.get("code"),
        # QUESTION A ONLY: can a technical plan be computed from these facts? Nothing here says a call may be made.
        "status": "BLOCKED" if issues else "READY",
        "issues": sorted(issues, key=lambda i: (i["at"], i["code"])),
        "inputs": inputs,
        "modules": modules,
        "counts": {
            "modules_in": sum(x["status"] == "IN" for x in modules),
            "modules_out": sum(x["status"] == "OUT" for x in modules),
            "modules_conditional": sum(x["status"] == "CONDITIONAL" for x in modules),
            "modules_halt": sum(x["status"] == "HALTS" for x in modules),
            "items": len(all_items),
            "items_always": sum(i["certainty"] == "ALWAYS" for i in all_items),
            "open_points": sum(len(x["open"]) for x in live),
        },
    }
    plan["fingerprint"] = sha256_hex(plan)
    return plan
