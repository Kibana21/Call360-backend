"""Server-side structural and semantic validation of a survey bundle (SS-03A §4; contract §2–§8).

One validator, stable codes. A finding is identified by its ``code`` and ``at`` — never by its message, which is for
people and may be reworded. Every finding here is a BLOCKER: a draft with any of them cannot become a candidate.

Each rule records the fixture schema version that introduced it (``RULE_SINCE``), so the historical golden fixtures can
be read under the rules they were written for. The server itself applies every rule.

This validator decides nothing about live-call eligibility, and it contains no non-answer, refusal, repeat, consent or
timeout rule: those are open business and Compliance decisions.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from app.domain.survey.conditions import READABLE_ANSWER_TYPES_V1, check_condition, option_codes_compared
from app.domain.survey.documents import (
    INTERRUPT_POLICIES,
    PUBLISHABLE_DELIVERY_MODES,
    SINGLE_ROUTE_TYPES,
    Bundle,
    Doc,
)

#: code -> the fixture schema version that introduced the rule. 6 = approved mechanisms with no golden fixture yet.
RULE_SINCE: dict[str, int] = {
    # structure
    "SURVEY_EMPTY": 1,
    "MODULE_MISSING": 1,
    "MODULE_EMPTY": 1,
    "MODULE_ENTRY_MISSING": 1,
    "NODE_UNREACHABLE": 1,
    "MODULE_HAS_CYCLE": 1,
    "TARGET_NODE_UNKNOWN": 1,
    "OUTCOME_UNKNOWN": 1,
    "OUTCOME_NOT_DECLARED": 1,
    # items and routing
    "ITEM_MISSING": 1,
    "WORDING_MISSING": 1,
    "WORDING_TEXT_MISSING": 1,
    "OPTIONS_TOO_FEW": 1,
    "OPTION_LABEL_MISSING": 1,
    "ROUTE_MISSING": 1,
    "SELECTION_LIMITS_INVALID": 2,
    "RULE_EMPTY": 2,
    "RULE_ROUTE_MISSING": 2,
    "FALLBACK_MISSING": 2,
    "FOLLOWUP_BEHAVIOUR_UNDECLARED": 2,
    "INTERRUPT_NOT_PERMITTED": 2,
    "INTERRUPT_OUTCOME_MISSING": 2,
    "INTERRUPT_RESUME_EMPTY": 2,
    "INTERRUPT_REJOIN_MISSING": 2,
    "REJOIN_MISSING": 1,
    # conditions
    "DECISION_CONDITION_MISSING": 1,
    "CONDITION_PARAM_MISSING": 1,
    "CONDITION_INPUT_UNBOUND": 1,
    "CONDITION_INPUT_NOT_AVAILABLE": 1,
    "CONDITION_INPUT_WRONG_ITEM": 2,
    "CONDITION_INPUT_TYPE_MISMATCH": 2,
    "CONDITION_INPUT_OPTION_UNKNOWN": 2,
    "DECISION_ROUTE_MISSING": 1,
    "DECISION_UNKNOWN_UNDECIDED": 1,
    "CONDITION_FIELD_UNKNOWN": 1,
    "CONDITION_PARAM_UNDECLARED": 1,
    "CONDITION_INPUT_UNDECLARED": 2,
    "CONDITION_INPUT_TYPE_UNSUPPORTED": 2,
    "CONDITION_OPERATOR_UNKNOWN": 1,
    "CONDITION_OPERATOR_TYPE_MISMATCH": 2,
    "CONDITION_EMPTY_GROUP": 1,
    "CONDITION_OPERAND_INVALID": 1,
    # survey
    "SURVEY_ROUTE_MISSING": 1,
    "SURVEY_ROUTE_TARGET_UNKNOWN": 1,
    "SURVEY_ROUTE_BACKWARD": 1,
    "ELIGIBILITY_CONDITION_MISSING": 1,
    "UNKNOWN_POLICY_MISSING": 1,
    "ACTIVATION_SOURCE_INVALID": 1,
    "ACTIVATION_OUTCOMES_EMPTY": 1,
    "SKIP_DISPOSITION_MISSING": 2,
    "SKIP_DISPOSITION_TARGET_UNKNOWN": 2,
    "SKIP_DISPOSITION_BACKWARD": 2,
    # escalation
    "MANDATORY_ESCALATION_WEAKENED": 2,
    "MANDATORY_ESCALATION_OVERRIDDEN": 3,
    "ESCALATION_NOT_TERMINAL": 4,
    # statements, typed items, wording and delivery (schema /5)
    "NODE_ITEM_KIND_MISMATCH": 5,
    "STATEMENT_NOT_A_QUESTION": 5,
    "SINGLE_ROUTE_ITEM_BRANCHES": 5,
    "UNKNOWN_VARIABLE": 5,
    "VARIABLE_TYPE_NOT_ALLOWED": 5,
    "VARIABLE_MALFORMED": 5,
    "DELIVERY_CONVERSATIONAL_BLOCKED": 5,
    "RECORDING_ASSET_MISSING": 5,
    "RECORDING_WITH_VARIABLE": 5,
    "NUMBER_RULE_INVALID": 5,
    # approved mechanisms without a golden fixture yet (schema /6 is reserved, not defined)
    "VARIABLE_NOT_PERMITTED": 6,
    "RESPONSE_OBLIGATION_UNKNOWN": 6,
}

VARIABLE = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")


@dataclass(frozen=True)
class Finding:
    code: str
    at: str
    message: str
    severity: str = "BLOCKER"

    @property
    def since(self) -> int:
        return RULE_SINCE[self.code]


def variables_of(text: str) -> list[str]:
    out: list[str] = []
    for m in VARIABLE.finditer(text):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


# ------------------------------------------------------------------------------------------------------ graph helpers
def routes_from(module: Doc, node: Doc) -> list[tuple[str, Doc]]:
    """Every place a node can lead to, whatever kind of route it is."""
    out: list[tuple[str, Doc]] = [(e["on"], e["to"]) for e in module["edges"] if e["from"] == node["node"]]
    r = node.get("routing") or {}
    if r.get("rejoin"):
        out.append(("REJOIN", r["rejoin"]))
    for f in r.get("followups") or []:
        out.extend((f"FOLLOWUP:{f['option']}", {"node": n}) for n in f.get("nodes") or [])
    for i in r.get("interrupts") or []:
        out.extend((f"INTERRUPT:{i['option']}", {"node": n}) for n in i.get("nodes") or [])
        if i.get("policy") == "STOP_REJOIN" and i.get("rejoin"):
            out.append((f"INTERRUPT:{i['option']}", i["rejoin"]))
        if i.get("policy", "STOP_ESCALATE") == "STOP_ESCALATE" and i.get("outcome"):
            out.append((f"INTERRUPT:{i['option']}", {"outcome": i["outcome"]}))
    for rule in r.get("rules") or []:
        if rule.get("to"):
            out.append((f"RULE:{rule['rule']}", rule["to"]))
    if r.get("mode") == "ORDERED_RULES" and r.get("fallback"):
        out.append(("FALLBACK", r["fallback"]))
    return out


def _successors(module: Doc) -> dict[str, list[str]]:
    by = {n["node"]: n for n in module["nodes"]}
    out: dict[str, list[str]] = {k: [] for k in by}
    for n in module["nodes"]:
        for _, to in routes_from(module, n):
            if "node" in to and to["node"] in by:
                out[n["node"]].append(to["node"])
    # a follow-up returns to its parent's queue, i.e. to wherever the parent leads afterwards
    for n in module["nodes"]:
        r = n.get("routing") or {}
        rejoin = r.get("rejoin") or {}
        if "node" not in rejoin:
            continue
        kids = [x for f in r.get("followups") or [] for x in f.get("nodes") or []]
        kids += [x for i in r.get("interrupts") or [] for x in i.get("nodes") or []]
        for k in kids:
            if k in out and any(to.get("return") for _, to in routes_from(module, by[k])):
                out[k].append(rejoin["node"])
    return out


def _reachable(module: Doc) -> set[str]:
    succ, seen = _successors(module), set()
    stack = [module["entry"]] if module.get("entry") else []
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in succ:
            continue
        seen.add(cur)
        stack.extend(succ[cur])
    return seen


def _has_cycle(module: Doc) -> bool:
    succ = _successors(module)
    state: dict[str, int] = {}

    def visit(n: str) -> bool:
        state[n] = 1
        for nxt in succ.get(n, []):
            if state.get(nxt) == 1 or (state.get(nxt) is None and visit(nxt)):
                return True
        state[n] = 2
        return False

    return any(state.get(n) is None and visit(n) for n in succ)


def _ancestors(module: Doc, node_id: str) -> set[str]:
    succ = _successors(module)
    pred: dict[str, list[str]] = {k: [] for k in succ}
    for a, bs in succ.items():
        for b in bs:
            pred[b].append(a)
    seen: set[str] = set()
    stack = list(pred.get(node_id, []))
    while stack:
        cur = stack.pop()
        if cur not in seen:
            seen.add(cur)
            stack.extend(pred[cur])
    return seen


def _edge(module: Doc, node_id: str, on: str) -> Doc | None:
    hits = [e for e in module["edges"] if e["from"] == node_id and e["on"] == on]
    return hits[0]["to"] if len(hits) == 1 else None


# ---------------------------------------------------------------------------------------------- selections and rules
def valid_selections(options: list[Doc], selection: Mapping[str, Any] | None) -> list[list[str]]:
    """Every selection a customer could validly give to a multiple-choice question (exclusive options stand alone)."""
    codes = [o["code"] for o in options]
    exclusive = {o["code"] for o in options if o.get("exclusive")}
    lo = int((selection or {}).get("min", 0))
    hi = int((selection or {}).get("max", len(codes)))
    out: list[list[str]] = []
    for size in range(max(lo, 0), min(hi, len(codes)) + 1):
        for combo in combinations(codes, size):
            if size > 1 and exclusive & set(combo):
                continue
            out.append(list(combo))
    return out


def rule_winner(routing: Doc, chosen: Iterable[str]) -> Doc | None:
    """The destination of the first rule the selection meets, else the fallback."""
    got = set(chosen)
    for rule in routing.get("rules") or []:
        when = rule.get("when") or {}
        wanted = set(when.get("options") or [])
        if not wanted:
            continue
        kind = when.get("kind")
        if (
            (kind == "ANY" and got & wanted)
            or (kind == "ALL" and wanted <= got)
            or (kind == "NONE" and not got & wanted)
        ):
            to: Doc | None = rule.get("to")
            return to
    fallback: Doc | None = routing.get("fallback")
    return fallback


def mandatory_outcomes(bundle: Bundle, module: Doc) -> set[str]:
    """Outcomes the module can end with BECAUSE a mandatory-escalation answer was given."""
    out: set[str] = set()
    for n in module["nodes"]:
        if n["type"] == "DECISION":
            continue
        item = bundle.item_of(n)
        if item is None:
            continue
        options = bundle.options_of(item)
        r = n.get("routing") or {}
        for o in (x for x in options if x.get("interrupt") == "MANDATORY"):
            if r.get("mode") == "PER_CHOICE":
                to = _edge(module, n["node"], o["code"])
                if to and "outcome" in to:
                    out.add(to["outcome"])
            elif r.get("mode") == "ORDERED_RULES":
                for sel in valid_selections(options, item.get("selection")):
                    if o["code"] in sel:
                        to = rule_winner(r, sel)
                        if to and "outcome" in to:
                            out.add(to["outcome"])
            else:
                for i in r.get("interrupts") or []:
                    if (
                        i["option"] == o["code"]
                        and i.get("policy", "STOP_ESCALATE") == "STOP_ESCALATE"
                        and i.get("outcome")
                    ):
                        out.add(i["outcome"])
    return {o for o in out if bundle.outcomes.get(o) == "ESCALATION"}


def _permitted_interrupts(cls: str | None) -> tuple[str, ...]:
    return ("STOP_ESCALATE",) if cls == "MANDATORY" else INTERRUPT_POLICIES if cls == "OPTIONAL" else ()


# ------------------------------------------------------------------------------------------------------------ validate
def validate(bundle: Bundle) -> list[Finding]:
    """Every blocker in the bundle: survey-level findings in sequence order, then each module version once,
    node by node."""
    out: list[Finding] = []
    seq: list[Doc] = list(bundle.survey.get("sequence") or [])
    if not seq:
        out.append(Finding("SURVEY_EMPTY", str(bundle.survey.get("code", "")), "The survey has no modules."))
    index = {inst["instance"]: i for i, inst in enumerate(seq)}

    def is_escalation(o: str) -> bool:
        return bundle.outcomes.get(o) == "ESCALATION"

    def jump_sources(target: str) -> bool:
        for other in seq:
            routes = list((other.get("routes") or {}).values()) + [
                other.get("if_ineligible"),
                other.get("if_skipped_in_sequence"),
            ]
            if any(isinstance(t, dict) and t.get("instance") == target for t in routes):
                return True
        return False

    def check_survey_target(inst: Doc, i: int, to: Any, at: str, missing: str, unknown: str, backward: str) -> None:
        if to is None:
            out.append(Finding(missing, at, "No destination has been chosen."))
        elif isinstance(to, dict) and "instance" in to:
            j = index.get(to["instance"])
            if j is None:
                out.append(Finding(unknown, at, "The destination is a module that is not in the survey."))
            elif j <= i:
                out.append(Finding(backward, at, "A route may only lead to a later module."))
        elif isinstance(to, dict) and "survey_outcome" in to:
            if to["survey_outcome"] not in bundle.outcomes:
                out.append(Finding("OUTCOME_UNKNOWN", at, f"{to['survey_outcome']} is not in the outcome catalog."))

    for i, inst in enumerate(seq):
        name = inst["instance"]
        module = bundle.module_of(inst)
        if module is None:
            out.append(Finding("MODULE_MISSING", name, "The module version this placement pins does not exist."))
            continue
        routes: Mapping[str, Any] = inst.get("routes") or {}
        for o in module["outcomes"]:
            check_survey_target(
                inst,
                i,
                routes.get(o),
                f"{name}:{o}",
                "SURVEY_ROUTE_MISSING",
                "SURVEY_ROUTE_TARGET_UNKNOWN",
                "SURVEY_ROUTE_BACKWARD",
            )
        elig = inst.get("eligibility")
        if elig is not None:
            cond = bundle.condition_of(elig)
            if cond is None:
                out.append(Finding("ELIGIBILITY_CONDITION_MISSING", name, "Its eligibility condition does not exist."))
            elif any((elig.get("params") or {}).get(p) in (None, "") for p in cond.get("params") or {}):
                out.append(Finding("CONDITION_PARAM_MISSING", name, "The eligibility condition needs a value."))
            if not elig.get("unknown_policy"):
                # missing information is never treated as "no": the author must say what happens
                out.append(
                    Finding("UNKNOWN_POLICY_MISSING", name, "It does not say what happens when information is missing.")
                )
        act = inst.get("activation")
        if act is not None:
            j = index.get(act.get("of"))
            if j is None or j >= i:
                out.append(
                    Finding("ACTIVATION_SOURCE_INVALID", name, "It waits for a module that does not run before it.")
                )
            elif not act.get("outcomes"):
                out.append(Finding("ACTIVATION_OUTCOMES_EMPTY", name, "It names no outcome that activates it."))
        # an escalation is terminal for the survey however the module reached it;
        # a mandatory one can never be overridden
        must = mandatory_outcomes(bundle, module)
        for o in module["outcomes"]:
            if not is_escalation(o):
                continue
            to = routes.get(o)
            if to is None or to == {"survey_outcome": o}:
                continue
            code = "MANDATORY_ESCALATION_OVERRIDDEN" if o in must else "ESCALATION_NOT_TERMINAL"
            out.append(Finding(code, f"{name}:{o}", f"{o} must end the call with {o}."))
        # a jump only names this module as the next candidate; if it can be ineligible, what happens then must be chosen
        if elig is not None:
            seq_skip = inst.get("if_skipped_in_sequence", "@CONTINUE")
            if seq_skip is None:
                out.append(
                    Finding(
                        "SKIP_DISPOSITION_MISSING",
                        f"{name}:@SKIP_SEQ",
                        "It does not say what happens if it is reached in sequence and does not apply.",
                    )
                )
            elif isinstance(seq_skip, dict):
                check_survey_target(
                    inst,
                    i,
                    seq_skip,
                    f"{name}:@SKIP_SEQ",
                    "SKIP_DISPOSITION_MISSING",
                    "SKIP_DISPOSITION_TARGET_UNKNOWN",
                    "SKIP_DISPOSITION_BACKWARD",
                )
            after_jump = inst.get("if_ineligible")
            if after_jump is None:
                if jump_sources(name):
                    out.append(
                        Finding(
                            "SKIP_DISPOSITION_MISSING",
                            f"{name}:@SKIP",
                            "It does not say what happens if it is jumped to and does not apply.",
                        )
                    )
            elif isinstance(after_jump, dict):
                check_survey_target(
                    inst,
                    i,
                    after_jump,
                    f"{name}:@SKIP",
                    "SKIP_DISPOSITION_MISSING",
                    "SKIP_DISPOSITION_TARGET_UNKNOWN",
                    "SKIP_DISPOSITION_BACKWARD",
                )

    done: set[tuple[str, int]] = set()
    for inst in seq:
        module = bundle.module_of(inst)
        if module is None or (module["code"], module["revision"]) in done:
            continue
        done.add((module["code"], module["revision"]))
        out.extend(_validate_module(bundle, module))
    for cond in {id(c): c for inst in seq for c in _conditions_used(bundle, inst)}.values():
        out.extend(
            Finding(code, f"{cond['code']}@{cond['version']}", detail)
            for code, detail in check_condition(cond, bundle.fields)
        )
    return out


def _conditions_used(bundle: Bundle, inst: Doc) -> list[Doc]:
    used = [bundle.condition_of(inst.get("eligibility"))]
    module = bundle.module_of(inst)
    for n in (module or {}).get("nodes", []):
        if n["type"] == "DECISION":
            used.append(bundle.condition_of(n.get("binding")))
    return [c for c in used if c is not None]


def _validate_module(bundle: Bundle, module: Doc) -> list[Finding]:
    out: list[Finding] = []
    code = module["code"]

    def add(rule: str, node: str | None, message: str) -> None:
        out.append(Finding(rule, f"{code}/{node}" if node else code, message))

    nodes: list[Doc] = list(module["nodes"])
    by = {n["node"]: n for n in nodes}
    if not nodes:
        add("MODULE_EMPTY", None, "The module has nothing in it.")
        return out
    if not module.get("entry") or module["entry"] not in by:
        add("MODULE_ENTRY_MISSING", None, "The module has no first step.")

    def check_target(node: str, to: Any) -> None:
        if not isinstance(to, dict):
            return
        if "node" in to and to["node"] not in by:
            add("TARGET_NODE_UNKNOWN", node, f"A route leads to {to['node']}, which is not in the module.")
        if "outcome" in to:
            if to["outcome"] not in bundle.outcomes:
                add("OUTCOME_UNKNOWN", node, f"{to['outcome']} is not in the outcome catalog.")
            elif to["outcome"] not in module["outcomes"]:
                add("OUTCOME_NOT_DECLARED", node, f"The module does not declare the outcome {to['outcome']}.")

    for n in nodes:
        nid = n["node"]
        for _, to in routes_from(module, n):
            check_target(nid, to)
        if n["type"] == "DECISION":
            out.extend(_validate_decision(bundle, module, n, add))
            continue
        item, wording = bundle.item_of(n), bundle.wording_of(n)
        if item is None:
            add("ITEM_MISSING", nid, "The item version this step places does not exist.")
            continue
        if wording is None:
            add("WORDING_MISSING", nid, "The wording version this step pins does not exist.")
            continue
        t = item["answer_type"]
        stmt = t == "STATEMENT"
        text: str = wording.get("text") or ""
        r: Doc = n.get("routing") or {}
        mode = r.get("mode")
        options = bundle.options_of(item)
        if not text.strip():
            add("WORDING_TEXT_MISSING", nid, "The wording is empty.")
        # ---- statements and typed items (schema /5), in the order the contract lists them (§8.4)
        if (n["type"] == "STATEMENT") != stmt:
            add(
                "NODE_ITEM_KIND_MISMATCH",
                nid,
                "A statement step must place a statement, and a question step a question.",
            )
        if stmt and (item.get("response_obligation") or item.get("lifecycle_role")):
            add(
                "STATEMENT_NOT_A_QUESTION",
                nid,
                "A statement is delivered, not answered: it has no obligation and no question role.",
            )
        if t in SINGLE_ROUTE_TYPES and n.get("role") != "FOLLOWUP":
            outs = [e for e in module["edges"] if e["from"] == nid]
            if mode != "ALL_TO_NEXT" or len(outs) > 1 or any(e["on"] != "AFTER_CAPTURE" for e in outs):
                # the item node only: a later Decision may branch on its answer in a later schema version (TS-2)
                add("SINGLE_ROUTE_ITEM_BRANCHES", nid, "This item has one way on and cannot branch.")
        for v in variables_of(text):
            f = bundle.fields.get(v)
            if f is None:
                add("UNKNOWN_VARIABLE", nid, f"{{{{{v}}}}} is not a field of the catalog.")
            elif f.get("type") == "BOOLEAN":
                add("VARIABLE_TYPE_NOT_ALLOWED", nid, f"{{{{{v}}}}} is a yes/no fact and has no spoken form.")
            elif f.get("speakable") is not True:
                # default-deny (owner decision D-181): a field may be spoken only when the catalog allowlists it
                add("VARIABLE_NOT_PERMITTED", nid, f"{{{{{v}}}}} is not allowlisted for use in wording.")
        rest = VARIABLE.sub("", text)
        if "{{" in rest or "}}" in rest:
            add("VARIABLE_MALFORMED", nid, "The wording has an unfinished variable.")
        delivery = wording.get("delivery_mode")
        if delivery not in PUBLISHABLE_DELIVERY_MODES:
            add("DELIVERY_CONVERSATIONAL_BLOCKED", nid, "Wording in the assistant's own words is not publishable.")
        elif delivery == "EXACT_AUDIO":
            if variables_of(text):
                add("RECORDING_WITH_VARIABLE", nid, "A recording cannot contain a variable.")
            elif not _usable_asset(wording.get("asset")):
                add("RECORDING_ASSET_MISSING", nid, "An approved recording is required and none is attached.")
        rule = item.get("number_rule") or {}
        if t == "NUMERIC" and "min" in rule and "max" in rule and rule["min"] > rule["max"]:
            add("NUMBER_RULE_INVALID", nid, "The lowest number is above the highest.")
        if (
            bundle.obligations is not None
            and item.get("response_obligation")
            and item["response_obligation"] not in bundle.obligations
        ):
            add("RESPONSE_OBLIGATION_UNKNOWN", nid, "The response obligation is not in the governed catalog.")
        # ---- answers and routing
        if t in ("SINGLE_SELECT", "MULTI_SELECT"):
            if len(options) < 2:
                add("OPTIONS_TOO_FEW", nid, "A choice question needs at least two options.")
            if any(not str(o.get("label", "")).strip() for o in options):
                add("OPTION_LABEL_MISSING", nid, "An option has no label.")
        default_on = "AFTER_CAPTURE" if t in SINGLE_ROUTE_TYPES else "ANY"
        if mode == "ALL_TO_NEXT" and _edge(module, nid, default_on) is None and n.get("role") != "FOLLOWUP":
            add("ROUTE_MISSING", nid, "It does not lead anywhere.")
        if mode == "PER_CHOICE":
            fallback = _edge(module, nid, "ANY")
            for o in options:
                if _edge(module, nid, o["code"]) is None and fallback is None:
                    add("ROUTE_MISSING", nid, f"The answer {o['code']} has no destination.")
        sel = item.get("selection")
        if t == "MULTI_SELECT" and sel:
            combinable = len([o for o in options if not o.get("exclusive")])
            lo, hi = sel.get("min", 0), sel.get("max", len(options))
            if lo < 0 or hi < 1 or lo > hi or (lo > 1 and lo > combinable) or hi > max(combinable, 1):
                add("SELECTION_LIMITS_INVALID", nid, "The selection limits cannot be met.")
        if mode == "ORDERED_RULES":
            for k, ru in enumerate(r.get("rules") or []):
                if not (ru.get("when") or {}).get("options"):
                    add("RULE_EMPTY", nid, f"Rule {k + 1} looks for no answers.")
                elif not ru.get("to"):
                    add("RULE_ROUTE_MISSING", nid, f"Rule {k + 1} has no destination.")
            if not r.get("fallback"):
                add("FALLBACK_MISSING", nid, "It does not say where to go when no rule matches.")
        # a mandatory escalation holds in every routing mode: no placement may weaken it
        for o in (x for x in options if x.get("interrupt") == "MANDATORY"):
            weak = False
            dest: Doc | None
            if mode == "ALL_TO_NEXT":
                weak = True
            elif mode == "PER_CHOICE":
                dest = _edge(module, nid, o["code"])
                weak = dest is not None and not (
                    "outcome" in dest and bundle.outcomes.get(dest["outcome"]) == "ESCALATION"
                )
            elif mode == "ORDERED_RULES":
                for s in valid_selections(options, sel):
                    if o["code"] in s:
                        dest = rule_winner(r, s)
                        if not (dest and "outcome" in dest and bundle.outcomes.get(dest["outcome"]) == "ESCALATION"):
                            weak = True
            else:
                hit = [
                    i
                    for i in r.get("interrupts") or []
                    if i["option"] == o["code"] and i.get("policy", "STOP_ESCALATE") == "STOP_ESCALATE"
                ]
                weak = not hit or any(bundle.outcomes.get(i.get("outcome", "")) != "ESCALATION" for i in hit)
            if weak:
                add(
                    "MANDATORY_ESCALATION_WEAKENED",
                    nid,
                    f"The answer {o['code']} is a mandatory escalation and must end with an escalation outcome.",
                )
        if mode == "SEQUENTIAL_FOLLOWUPS":
            declared_any = "no_followup" in r
            for o in options:
                declared = (
                    any(f["option"] == o["code"] for f in r.get("followups") or [])
                    or o["code"] in (r.get("no_followup") or [])
                    or any(i["option"] == o["code"] for i in r.get("interrupts") or [])
                )
                if declared_any and not declared and o.get("interrupt") != "MANDATORY":
                    add("FOLLOWUP_BEHAVIOUR_UNDECLARED", nid, f"It does not say what the answer {o['code']} does.")
            for i in r.get("interrupts") or []:
                opt = next((x for x in options if x["code"] == i["option"]), None)
                policy = i.get("policy", "STOP_ESCALATE")
                if "policy" in i and policy not in _permitted_interrupts((opt or {}).get("interrupt")):
                    add(
                        "INTERRUPT_NOT_PERMITTED",
                        nid,
                        f"The answer {i['option']} is not allowed to interrupt in this way.",
                    )
                elif policy == "STOP_ESCALATE" and not i.get("outcome"):
                    add(
                        "INTERRUPT_OUTCOME_MISSING",
                        nid,
                        f"The answer {i['option']} stops the follow-ups but has no outcome.",
                    )
                elif policy == "RESUME" and not i.get("nodes"):
                    add(
                        "INTERRUPT_RESUME_EMPTY",
                        nid,
                        f"The answer {i['option']} has nothing to ask before the follow-ups continue.",
                    )
                elif policy == "STOP_REJOIN" and not i.get("rejoin"):
                    add(
                        "INTERRUPT_REJOIN_MISSING",
                        nid,
                        f"The answer {i['option']} has no destination after stopping the follow-ups.",
                    )
            if not r.get("rejoin"):
                add("REJOIN_MISSING", nid, "It does not say where to continue after the follow-ups.")

    reach = _reachable(module)
    for n in nodes:
        if n["node"] not in reach and module.get("entry") in by:
            add("NODE_UNREACHABLE", n["node"], "Nothing leads to this step.")
    if _has_cycle(module):
        add("MODULE_HAS_CYCLE", None, "A route leads back to an earlier step.")
    return out


def _usable_asset(asset: Any) -> bool:
    """A recording is usable only with an identified, hashed, APPROVED asset. Nothing in SS-03A can create one."""
    return (
        isinstance(asset, dict)
        and bool(asset.get("id"))
        and bool(asset.get("sha256"))
        and asset.get("approval") == "APPROVED"
    )


def _validate_decision(bundle: Bundle, module: Doc, n: Doc, add: Any) -> list[Finding]:
    nid = n["node"]
    b = n.get("binding")
    cond = bundle.condition_of(b)
    if cond is None or b is None:
        add("DECISION_CONDITION_MISSING", nid, "The decision has no condition.")
    else:
        if any((b.get("params") or {}).get(p) in (None, "") for p in cond.get("params") or {}):
            add("CONDITION_PARAM_MISSING", nid, "The condition needs a value.")
        before = _ancestors(module, nid)
        by = {x["node"]: x for x in module["nodes"]}
        compared = option_codes_compared(cond.get("ast") or {})
        for name, decl in (cond.get("inputs") or {}).items():
            mapped = ((b.get("inputs") or {}).get(name) or {}).get("node")
            target = by.get(mapped) if mapped else None
            if target is None or target["type"] == "DECISION":
                add("CONDITION_INPUT_UNBOUND", nid, f"It does not say which earlier answer is {name}.")
                continue
            if mapped not in before:
                add(
                    "CONDITION_INPUT_NOT_AVAILABLE",
                    nid,
                    f"It reads the answer to {mapped}, which is not asked before it.",
                )
                continue
            actual = bundle.item_of(target)
            declared_item = (decl.get("item") or {}).get("code")
            if actual is None:
                continue
            if declared_item and actual["code"] != declared_item:
                add(
                    "CONDITION_INPUT_WRONG_ITEM",
                    nid,
                    f"{name} is bound to a different question from the one the condition reads.",
                )
            elif decl.get("answer_type") and actual["answer_type"] != decl["answer_type"]:
                add("CONDITION_INPUT_TYPE_MISMATCH", nid, f"The answer type of {mapped} does not fit the condition.")
            elif actual["answer_type"] in READABLE_ANSWER_TYPES_V1:
                known = {o["code"] for o in bundle.options_of(actual)}
                gone = [c for c in compared.get(name, []) if c not in known]
                if gone:
                    add(
                        "CONDITION_INPUT_OPTION_UNKNOWN",
                        nid,
                        f"It compares {mapped} with an answer that does not exist ({', '.join(gone)}).",
                    )
    for on in ("MATCH", "NO_MATCH"):
        if _edge(module, nid, on) is None:
            add("DECISION_ROUTE_MISSING", nid, f"It has no destination for {on}.")
    policy = (b or {}).get("unknown_policy")
    if not policy or (policy != "BLOCK" and _edge(module, nid, "UNKNOWN") is None):
        # missing information is never treated as "does not match"
        add("DECISION_UNKNOWN_UNDECIDED", nid, "It does not say what happens when information is missing.")
    return []
