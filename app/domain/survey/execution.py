# ruff: noqa: E501 — the event records are kept one per line so each can be read against the contract
"""SS-03B.1 — the authoritative, deterministic execution of a survey definition. SIMULATION ONLY.

Pure: no database, clock, network or model. Given the resolved documents of a survey (``Bundle``), an immutable fact
snapshot and the answers supplied so far, it returns the complete run — what was delivered, every decision with what it
read, every route taken, the module results and how the run stands. The same inputs always give the same run.

What it implements is the SS-01 execution contract as fixed by the 82 expected runs of the 27 golden fixtures: module
sequencing, activation and eligibility; graph navigation; decisions on three-valued conditions; per-answer routing;
multi-select with ordered follow-up queues and interruptions; first-matching-rule routing; forward-only jumps;
mandatory-escalation precedence; typed answer validation; statements; and the terminal states.

What it never does:
  * write, complete or rephrase wording — an item is delivered as its pinned wording version renders, or not at all;
  * treat UNKNOWN as FALSE, or guess a missing fact;
  * advance past an answer that was rejected;
  * decide what a call does when a customer refuses or does not answer. That is undecided (D-NA-1…17). A question that
    needs an answer stays pending, and a "not acknowledged" is reported as ``POLICY_UNRESOLVED`` — a simulation status,
    never a business outcome, never an escalation or a completion;
  * make anything eligible for a real call. Nothing here speaks, dials or reads an operational record.

It is not the operational conversation runtime (``app/domain/lifecycle.py``, the script engine), which is untouched.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from app.domain.survey.conditions import ConditionError, Explanation, evaluate, fields_of, inputs_of
from app.domain.survey.documents import SINGLE_ROUTE_TYPES, Bundle
from app.domain.survey.wording import is_missing, render

Doc = Mapping[str, Any]
Answer = Mapping[str, Any]
#: supplies the answer for a question instance (``<instance>/<node>``) at an attempt number, or None when none is given
Supplier = Callable[[str, int], Answer | None]

#: The execution contract a run is computed under. It changes whenever the engine's results can change for the same
#: documents, facts and inputs — so a stored simulation can tell that it was computed under another one.
CONTRACT = "call360.survey.execution/1"
TERMINAL_STATES = (
    "COMPLETED", "ENDED_WITH_OUTCOME", "MANDATORY_ESCALATION", "REVIEW_REQUIRED", "MISSING_INFORMATION_HALT",
    "DRAFT_INVALID",
)  # fmt: skip
MODULE_STATUSES = (
    "ACTIVATED", "RUNNING", "SKIPPED_FALSE", "SKIPPED_UNKNOWN", "SKIPPED_PRIOR_OUTCOME", "SKIPPED_BY_ROUTE",
    "HALTED_MISSING_INFORMATION", "NOT_REACHED",
)  # fmt: skip
#: A non-answer whose handling is an open business decision. Reported, recorded as an observation, never accepted.
POLICY_UNRESOLVED_CODES = ("NON_ANSWER_POLICY_UNRESOLVED",)
TRAVERSAL_LIMIT, REJECTION_LIMIT = 200, 20


class _Stop(Exception):
    def __init__(self, status: str, reason: str, where: str) -> None:
        super().__init__(reason)
        self.status, self.reason, self.where = status, reason, where


# ------------------------------------------------------------------------------------------------- answer validation
def validate_answer(item: Doc, options: Sequence[Doc], a: Answer) -> str | None:
    """The stable rejection code for an answer, or None when it is accepted (contract 04 §3.7, §8)."""
    kind = item["answer_type"]
    if kind == "STATEMENT":
        return None
    if kind == "NUMERIC":
        rule = item.get("number_rule") or {"integer": False}
        n = a.get("number")
        if (
            n is None
            or isinstance(n, bool)
            or not isinstance(n, int | float)
            or n != n
            or n in (float("inf"), -float("inf"))
        ):
            return "NUMBER_REQUIRED"
        if rule.get("integer") and n != int(n):
            return "NUMBER_NOT_WHOLE"
        if rule.get("min") is not None and n < rule["min"]:
            return "NUMBER_TOO_LOW"
        if rule.get("max") is not None and n > rule["max"]:
            return "NUMBER_TOO_HIGH"
        return None
    if kind == "ACKNOWLEDGEMENT":
        # "not acknowledged" is a NON-ANSWER: what a call does then is undecided, so it is never accepted, refused on the
        # customer's behalf, or defaulted
        ack = a.get("acknowledged")
        return None if ack is True else "NON_ANSWER_POLICY_UNRESOLVED" if ack is False else "ACKNOWLEDGEMENT_REQUIRED"
    if kind == "FREE_TEXT":
        text = str(a.get("text") or "").strip()
        rule = item.get("text_rule") or {"required": True, "min_length": 0, "max_length": 2000}
        if rule.get("required") and not text:
            return "TEXT_REQUIRED"
        if len(text) < int(rule.get("min_length", 0)):
            return "TEXT_TOO_SHORT"
        if len(text) > int(rule.get("max_length", 2000)):
            return "TEXT_TOO_LONG"
        return None
    single = kind != "MULTI_SELECT"
    if single and a.get("choice") is None:
        return "CHOICE_REQUIRED"
    chosen = [a["choice"]] if single else list(a.get("choices") or [])
    opts = {o["code"]: o for o in options}
    if any(c not in opts for c in chosen):
        return "UNKNOWN_OPTION"
    if len(set(chosen)) != len(chosen):
        return "DUPLICATE_OPTION"
    if not single:
        sel = item.get("selection") or {"min": 0, "max": len(options)}
        if len(chosen) < sel["min"]:
            return "TOO_FEW_SELECTED"
        if len(chosen) > sel["max"]:
            return "TOO_MANY_SELECTED"
        if len(chosen) > 1 and any(opts[c].get("exclusive") for c in chosen):
            return "EXCLUSIVE_OPTION_CONFLICT"
    other = next((opts[c] for c in chosen if opts[c].get("is_other")), None)
    text = str(a.get("other_text") or "").strip()
    if other is None:
        return "OTHER_TEXT_NOT_ALLOWED" if a.get("other_text") is not None else None
    rule = other.get("other_text") or {"required": False, "min_length": 0, "max_length": 500}
    if rule.get("required") and not text:
        return "OTHER_TEXT_REQUIRED"
    if text and len(text) < int(rule.get("min_length", 0)):
        return "OTHER_TEXT_TOO_SHORT"
    if len(text) > int(rule.get("max_length", 500)):
        return "OTHER_TEXT_TOO_LONG"
    return None


def answer_state(item: Doc, a: Answer) -> str:
    """How an answer stands as evidence: the states that must never be merged."""
    kind = item["answer_type"]
    if kind == "STATEMENT":
        return "DELIVERED"
    if kind == "FREE_TEXT":
        return "ANSWERED" if str(a.get("text") or "").strip() else "UNANSWERED"
    if kind == "MULTI_SELECT" and not (a.get("choices") or []):
        return "ANSWERED_EMPTY"  # a KNOWN empty selection: not the same as unanswered
    return "ANSWERED"


def _explain(e: Explanation) -> dict[str, Any]:
    return {
        "op": e.op, "result": e.result, "reads": [{"kind": k, "name": n, "value": v} for k, n, v in e.reads],
        "children": [_explain(c) for c in e.children],
    }  # fmt: skip


def _rule_fit(rule: Doc, chosen: set[str]) -> bool:
    when = rule.get("when") or {}
    wanted = set(when.get("options") or [])
    if not wanted:
        return False
    kind = when.get("kind")
    return bool(
        (kind == "ANY" and chosen & wanted) or (kind == "ALL" and wanted <= chosen) or (kind == "NONE" and not chosen & wanted)
    )  # fmt: skip


# ------------------------------------------------------------------------------------------------------- the run
def execute(bundle: Bundle, facts: Mapping[str, Any], supplier: Supplier) -> dict[str, Any]:  # noqa: C901
    """One run of the survey for one fact snapshot. ``supplier`` gives the answer for a question instance; None stops
    the run there with that question pending. A rejected answer is recorded and the SAME question is asked again
    (attempt + 1): validation can never be skipped."""
    survey = bundle.survey
    seq: list[Doc] = list(survey.get("sequence") or [])
    events: list[dict[str, Any]] = []
    asked: list[str] = []
    edges: list[str] = []
    evidence: list[dict[str, Any]] = []
    trace: list[str] = []
    delivered: list[dict[str, Any]] = []
    visited: set[str] = set()
    answers: dict[str, Answer] = {}
    outcomes: dict[str, str] = {}
    status: dict[str, dict[str, Any]] = {}
    state: dict[str, Any] = {"pending": None, "terminal": None, "unresolved": None}

    def push(kind: str, **data: Any) -> None:
        events.append({"at": len(events), "kind": kind, **data})

    def outcome_class(code: str) -> str | None:
        return bundle.outcomes.get(code)

    def module_name(inst: Doc) -> str:
        m = bundle.module_of(inst)
        return str(m.get("name") or inst["instance"]) if m else str(inst["instance"])

    def judge(binding: Doc, module: Doc | None, inst: str) -> dict[str, Any]:
        cond = bundle.condition_of(binding)
        if cond is None:
            raise _Stop("INVALID", "CONDITION_MISSING", inst)
        by_input: dict[str, Any] = {}
        reads: list[dict[str, Any]] = []
        for code in sorted(fields_of(cond.get("ast") or {})):
            v = facts.get(code)
            reads.append(
                {
                    "what": "FACT",
                    "name": code,
                    "state": "MISSING" if is_missing(v) else "KNOWN",
                    "value": None if is_missing(v) else v,
                }
            )
        bound = binding.get("inputs") or {}
        for name in sorted(inputs_of(cond.get("ast") or {})):
            node_id = (bound.get(name) or {}).get("node")
            node = next((n for n in (module or {}).get("nodes", []) if n["node"] == node_id), None) if node_id else None
            item = bundle.item_of(node) if node and node.get("type") != "DECISION" else None
            a = answers.get(f"{inst}/{node_id}") if node_id else None
            if not node_id or item is None or a is None:
                # not collected on the path actually taken: UNKNOWN — never read as "no", and never as an empty selection
                reads.append({"what": "ANSWER", "name": name, "node": node_id, "state": "SKIPPED", "value": None})
                continue
            kind = item["answer_type"]
            value: Any = (
                list(a.get("choices") or []) if kind == "MULTI_SELECT"
                else a.get("text") if kind == "FREE_TEXT"
                else (None if a.get("number") is None else a.get("number")) if kind == "NUMERIC"
                else a.get("choice")
            )  # fmt: skip
            by_input[name] = value
            reads.append(
                {"what": "ANSWER", "name": name, "node": node_id, "state": answer_state(item, a), "value": value}
            )
        clean = {k: v for k, v in facts.items() if not is_missing(v)}
        try:
            ex = evaluate(cond.get("ast") or {}, binding.get("params") or {}, clean, by_input)
        except ConditionError as exc:
            raise _Stop("INVALID", exc.code, inst) from exc
        return {
            "result": ex.result, "explanation": _explain(ex), "reads": reads,
            "condition": {"code": cond["code"], "version": cond["version"]},
        }  # fmt: skip

    def run_module(inst: Doc, m: Doc) -> tuple[str, bool]:
        iid = inst["instance"]
        nodes = {n["node"]: n for n in m["nodes"]}
        mandatory = False  # true when the step that ended the module was a mandatory-escalation answer

        def follow(node: str, code: str) -> tuple[Doc, str, bool]:
            specific = [e for e in m["edges"] if e["from"] == node and e["on"] == code]
            cands = specific or [e for e in m["edges"] if e["from"] == node and e["on"] == "ANY"]
            if len(cands) != 1:
                raise _Stop("INVALID", "AMBIGUOUS_ROUTE" if cands else "ROUTE_MISSING", f"{iid}/{node}")
            edges.append(f"{iid}/{cands[0]['edge']}")
            return cands[0]["to"], cands[0]["edge"], bool(specific)

        def ask(node_id: str, followup: bool, queue: list[dict[str, Any]] | None = None) -> tuple[Doc, Doc, Answer]:
            node = nodes.get(node_id)
            key = f"{iid}/{node_id}"
            if node is None or node.get("type") == "DECISION":
                raise _Stop("INVALID", "NODE_MISSING", key)
            if key in visited:
                raise _Stop("INVALID", "REPEATED_EXECUTION", key)
            if len(visited) > TRAVERSAL_LIMIT:
                raise _Stop("INVALID", "TRAVERSAL_LIMIT", key)
            item, wording = bundle.item_of(node), bundle.wording_of(node)
            if item is None or wording is None:
                raise _Stop("INVALID", "ITEM_MISSING" if item is None else "WORDING_MISSING", key)
            options = bundle.options_of(item)
            statement = item["answer_type"] == "STATEMENT"
            ref = node["item"]
            # the pinned wording is rendered for THESE facts before anything is delivered; an unusable value stops here
            rendered = render(str(wording.get("text") or "").strip(), bundle.fields, facts)
            if rendered["text"] is None:
                state["undeliverable"] = {"key": key, "errors": rendered["errors"], "values": rendered["values"]}
                raise _Stop("MISSING", "WORDING_VALUE_MISSING", key)
            text = rendered["text"]
            common = {
                "key": key,
                "instance": iid,
                "node": node_id,
                "item": {"code": ref["code"], "version": ref["version"], "wording_version": ref["wording_version"]},
            }

            def mark_delivered() -> None:
                visited.add(key)
                delivered.append(
                    {
                        "key": key, "item": f"{ref['code']}@{ref['version']}", "statement": statement,
                        "wording_version": ref["wording_version"], "delivery_mode": wording.get("delivery_mode"),
                        "text": text, "values": rendered["values"],
                    }
                )  # fmt: skip

            if statement:
                mark_delivered()
                push(
                    "SAY", **common, text=text, role=item.get("statement_role") or "TRANSITION",
                    delivery_mode=wording.get("delivery_mode"), values=rendered["values"],
                )  # fmt: skip
                answers[key] = {}
                return node, item, {}
            push("ASK", **common, text=text, followup=followup, answer_type=item["answer_type"])
            attempt = 0
            while True:
                a = supplier(key, attempt)
                if a is None:
                    state["pending"] = {
                        **common, "text": text, "followup": followup, "answer_type": item["answer_type"],
                        "delivery_mode": wording.get("delivery_mode"), "values": rendered["values"],
                        "options": [{"code": o["code"], "label": o.get("label", "")} for o in options],
                        "selection": item.get("selection"), "number_rule": item.get("number_rule"),
                        "text_rule": item.get("text_rule"), "attempt": attempt,
                        **({"queue": queue} if queue else {}),
                    }  # fmt: skip
                    raise _Stop("PENDING", "AWAITING_ANSWER", key)
                code = validate_answer(item, options, a)
                if code:
                    push("REJECT", key=key, instance=iid, node=node_id, code=code, answer=dict(a), attempt=attempt)
                    state["unresolved"] = (
                        {"key": key, "code": "POLICY_UNRESOLVED", "reason": code}
                        if code in POLICY_UNRESOLVED_CODES
                        else None
                    )
                    if attempt > REJECTION_LIMIT:
                        raise _Stop("INVALID", "ANSWER_REJECTED", key)
                    attempt += 1
                    continue
                state["unresolved"] = None
                asked.append(key)
                mark_delivered()
                answers[key] = dict(a)
                evidence.append(
                    {
                        "question_instance": key, "question": f"{ref['code']}@{ref['version']}",
                        "wording_version": ref["wording_version"], "answer": dict(a),
                    }
                )  # fmt: skip
                push("ANSWER", **common, text=text, answer=dict(a), state=answer_state(item, a))
                return node, item, a

        cur: Doc | None = {"node": m["entry"]} if m.get("entry") else None
        while True:
            if not cur:
                raise _Stop("INVALID", "ROUTE_MISSING", iid)
            if cur.get("return"):
                raise _Stop("INVALID", "RETURN_OUTSIDE_QUEUE", iid)
            if "outcome" in cur:
                return str(cur["outcome"]), mandatory
            n = nodes.get(cur.get("node", ""))
            if n is None:
                raise _Stop("INVALID", "NODE_MISSING", f"{iid}/{cur.get('node')}")
            key = f"{iid}/{n['node']}"

            if n.get("type") == "DECISION":
                binding = n.get("binding")
                if not binding or not (binding.get("condition") or {}).get("code"):
                    raise _Stop("INVALID", "CONDITION_MISSING", key)
                j = judge(binding, m, iid)
                trace.append(f"{key}: {j['result']}")
                via = {"TRUE": "MATCH", "FALSE": "NO_MATCH", "UNKNOWN": "UNKNOWN"}[j["result"]]
                edge = next((e for e in m["edges"] if e["from"] == n["node"] and e["on"] == via), None)
                if edge is None:
                    # missing information is never treated as "otherwise"
                    raise _Stop("INVALID", "ROUTE_MISSING", key)
                edges.append(f"{iid}/{edge['edge']}")
                push("DECISION", key=key, instance=iid, node=n["node"], via=via, edge=edge["edge"], to=edge["to"], **j)
                cur = edge["to"]
                continue

            node, item, a = ask(n["node"], False)
            options = bundle.options_of(item)
            interrupt_of = {o["code"]: o.get("interrupt") for o in options}
            mandatory = False  # it describes only the step that ends the module
            r = node.get("routing") or {}
            kind = item["answer_type"]
            if r.get("mode") == "SEQUENTIAL_FOLLOWUPS":
                chosen = list(a.get("choices") or [])
                order_of = {o["code"]: i for i, o in enumerate(options)}
                interrupts = list(r.get("interrupts") or [])
                # a mandatory escalation leads; then the configured order; then the order of the answers
                hits = sorted(
                    (i for i in interrupts if i["option"] in chosen),
                    key=lambda i: (0 if interrupt_of.get(i["option"]) == "MANDATORY" else 1, interrupts.index(i), order_of.get(i["option"], 0)),
                )  # fmt: skip
                queue_ids: list[str] = []
                deduped: list[str] = []
                because: dict[str, list[str]] = {}
                for f in (x for x in r.get("followups") or [] if x["option"] in chosen):
                    for t in f.get("nodes") or []:
                        (deduped if t in queue_ids else queue_ids).append(t)
                        because.setdefault(t, []).append(f["option"])
                not_asked: list[str] = []
                for f in (x for x in r.get("followups") or [] if x["option"] not in chosen):
                    for t in f.get("nodes") or []:
                        if t not in queue_ids and t not in not_asked:
                            not_asked.append(t)
                hit = hits[0] if hits else None
                policy = (hit or {}).get("policy", "STOP_ESCALATE") if hit else None
                if hit and policy == "STOP_ESCALATE":
                    if not hit.get("outcome"):
                        raise _Stop("INVALID", "ROUTE_MISSING", key)
                    must = interrupt_of.get(hit["option"]) == "MANDATORY"
                    trace.append(f"{key}: INTERRUPT {hit['option']} -> {hit['outcome']}; skipped {queue_ids!r}")
                    push(
                        "QUEUE", key=key, instance=iid, node=n["node"], queued=[], deduped_nodes=[], not_asked=queue_ids,
                        interrupt={"option": hit["option"], "policy": policy, "outcome": hit["outcome"], "skipped_nodes": queue_ids, "mandatory": must},
                    )  # fmt: skip
                    return str(hit["outcome"]), must
                if hit and policy == "STOP_REJOIN":
                    if not hit.get("rejoin"):
                        raise _Stop("INVALID", "ROUTE_MISSING", key)
                    push(
                        "QUEUE", key=key, instance=iid, node=n["node"], queued=[], deduped_nodes=[], not_asked=queue_ids,
                        interrupt={"option": hit["option"], "policy": policy, "skipped_nodes": queue_ids, "mandatory": False, "rejoin": hit["rejoin"]},
                    )  # fmt: skip
                    cur = hit["rejoin"]
                    continue
                first = list(hit.get("nodes") or []) if hit and policy == "RESUME" else []
                order = [x for x in first if x not in queue_ids] + queue_ids
                trace.append(f"{key}: QUEUE {queue_ids!r}" + (f"; deduped {deduped!r}" if deduped else ""))
                push(
                    "QUEUE", key=key, instance=iid, node=n["node"],
                    queued=[{"node": q, "because": because.get(q) or [hit["option"]] if hit else because.get(q, [])} for q in order],
                    deduped_nodes=deduped, not_asked=not_asked,
                    **({"interrupt": {"option": hit["option"], "policy": policy, "skipped_nodes": [], "mandatory": False}} if hit else {}),
                )  # fmt: skip
                early: str | None = None
                for i, child in enumerate(order):
                    view = [
                        {"node": q, "state": "DONE" if k < i else "NOW" if k == i else "NEXT"}
                        for k, q in enumerate(order)
                    ]
                    _, f_item, f_a = ask(child, True, view)
                    f_kind = f_item["answer_type"]
                    to, edge_id, _ = follow(
                        child,
                        "AFTER_CAPTURE"
                        if f_kind in SINGLE_ROUTE_TYPES
                        else "ANY"
                        if f_kind == "MULTI_SELECT"
                        else f_a["choice"],
                    )
                    if "outcome" in to:
                        early = str(to["outcome"])
                        push(
                            "ROUTE", key=f"{iid}/{child}", instance=iid, node=child, via="FOLLOWUP", edge=edge_id, to=to
                        )
                        break
                    if not to.get("return"):
                        raise _Stop("INVALID", "FOLLOWUP_MUST_RETURN", f"{iid}/{child}")
                if early:
                    return early, False
                if not r.get("rejoin"):
                    raise _Stop("INVALID", "ROUTE_MISSING", key)
                push("ROUTE", key=key, instance=iid, node=n["node"], via="REJOIN", to=r["rejoin"])
                cur = r["rejoin"]
                continue
            if r.get("mode") == "ORDERED_RULES":
                chosen_set = set(a.get("choices") or [])
                rules = list(r.get("rules") or [])
                fits = [i for i, rule in enumerate(rules) if _rule_fit(rule, chosen_set)]
                index = fits[0] if fits else -1
                rule_to: Doc | None = rules[index].get("to") if index >= 0 else r.get("fallback")
                if not rule_to:
                    raise _Stop("INVALID", "ROUTE_MISSING", key)
                push(
                    "ROUTE", key=key, instance=iid, node=n["node"], to=rule_to,
                    via=f"RULE:{rules[index]['rule']}" if index >= 0 else "FALLBACK",
                    also_rules=[rules[i]["rule"] for i in fits[1:]],
                )  # fmt: skip
                # a mandatory-escalation answer stays mandatory under rule-based routing: whatever rule wins
                mandatory = any(interrupt_of.get(c) == "MANDATORY" for c in chosen_set)
                cur = rule_to
                continue
            code = "AFTER_CAPTURE" if kind in SINGLE_ROUTE_TYPES else "ANY" if kind == "MULTI_SELECT" else a["choice"]
            to, edge_id, specific = follow(n["node"], code)
            mandatory = interrupt_of.get(a.get("choice")) == "MANDATORY" if a.get("choice") is not None else False
            push(
                "ROUTE",
                key=key,
                instance=iid,
                node=n["node"],
                via=code,
                edge=edge_id,
                to=to,
                specific=specific,
                mandatory=mandatory,
            )
            cur = to

    # ---- the survey: modules in sequence. Three different things decide whether a module runs (D-135):
    #   ROUTING / JUMP  names the next CANDIDATE module;  ACTIVATION  when it is selected at all;
    #   ELIGIBILITY     whether the candidate may execute, with an explicit policy for UNKNOWN.
    # A jump never bypasses eligibility. A module is considered at most once and every move is forward.
    pos = 0
    jump: dict[str, str] | None = None

    def end_call(outcome: str, inst: Doc, mandatory: bool) -> None:
        terminal = (
            "COMPLETED" if outcome == "COMPLETED"
            else "MANDATORY_ESCALATION" if mandatory and outcome_class(outcome) == "ESCALATION"
            else "ENDED_WITH_OUTCOME"
        )  # fmt: skip
        state["terminal"] = {"state": terminal, "survey_outcome": outcome}
        push("END", instance=inst.get("instance", ""), status=terminal, survey_outcome=outcome)

    def go(inst: Doc, to: Any, mandatory: bool) -> bool:
        nonlocal pos, jump
        if to == "@CONTINUE":
            pos += 1
            jump = None
            return True
        if "survey_outcome" in to:
            end_call(str(to["survey_outcome"]), inst, mandatory)
            return False
        target = next((i for i, x in enumerate(seq) if x["instance"] == to.get("instance")), -1)
        if target < 0:
            raise _Stop("INVALID", "ROUTE_MISSING", inst["instance"])
        if target <= pos:
            raise _Stop("INVALID", "BACKWARD_ROUTE", inst["instance"])
        for skipped in seq[pos + 1 : target]:
            status[skipped["instance"]] = {"instance": skipped["instance"], "status": "SKIPPED_BY_ROUTE"}
        pos = target
        jump = {"from": inst["instance"]}
        return True

    try:
        ended = False
        while pos < len(seq) and not ended:
            inst = seq[pos]
            iid = inst["instance"]
            m = bundle.module_of(inst)
            if m is None:
                raise _Stop("INVALID", "MODULE_MISSING", iid)
            act, elig = inst.get("activation"), inst.get("eligibility")
            arrival = "JUMP" if jump else "SEQUENCE"
            mstate = "ACTIVATED"
            # 1. ACTIVATION — is the module selected at all? In sequence, by a named earlier outcome, or by a jump.
            if act and not jump:
                got = outcomes.get(act.get("of"))
                if not (got and got in (act.get("outcomes") or [])):
                    mstate = "SKIPPED_PRIOR_OUTCOME"
                    push(
                        "ENTRY",
                        instance=iid,
                        status=mstate,
                        mode="ON_OUTCOME",
                        arrival=arrival,
                        activation=act,
                        prior_outcome=got,
                    )
            # 2. ELIGIBILITY — may the selected module execute? Being selected (even by a jump) never bypasses this.
            if mstate == "ACTIVATED" and not elig:
                push("ENTRY", instance=iid, status="ACTIVATED", mode="ON_OUTCOME" if act else "ALWAYS", arrival=arrival)
            elif mstate == "ACTIVATED" and elig:
                j = judge(elig, None, iid)
                trace.append(f"{iid}: entry {j['result']}")
                policy = elig.get("unknown_policy")
                if j["result"] == "UNKNOWN" and not policy:
                    raise _Stop("INVALID", "UNKNOWN_POLICY_MISSING", iid)
                mstate = (
                    "ACTIVATED" if j["result"] == "TRUE" else "SKIPPED_FALSE" if j["result"] == "FALSE"
                    else "SKIPPED_UNKNOWN" if policy == "SKIP_WITH_REASON" else "HALTED_MISSING_INFORMATION"
                )  # fmt: skip
                push("ENTRY", instance=iid, status=mstate, mode="RULE", arrival=arrival, unknown_policy=policy, **j)
                if mstate == "HALTED_MISSING_INFORMATION":
                    status[iid] = {"instance": iid, "status": mstate}
                    raise _Stop("MISSING", "ELIGIBILITY_UNKNOWN", iid)
            if mstate != "ACTIVATED":
                status[iid] = {"instance": iid, "status": mstate}
                # a module that was never SELECTED is not "ineligible": the next module is simply considered
                if mstate == "SKIPPED_PRIOR_OUTCOME":
                    pos += 1
                    continue
                has = "if_ineligible" if jump else "if_skipped_in_sequence"
                if not jump and has not in inst:
                    pos += 1  # in sequence the normal default is to consider the next module
                    continue
                d = inst.get(has)
                if d is None:  # after a jump it must have been chosen; nothing is invented
                    raise _Stop("INVALID", "SKIP_DISPOSITION_MISSING", iid)
                push("DISPOSITION", instance=iid, status=mstate, to=d, after_jump=bool(jump))
                ended = not go(inst, d, False)
                continue
            jump = None
            status[iid] = {"instance": iid, "status": "RUNNING"}
            out, by_mandatory = run_module(inst, m)
            outcomes[iid] = out
            status[iid] = {"instance": iid, "status": "ACTIVATED", "outcome": out}
            push("MODULE_END", instance=iid, outcome=out)
            if outcome_class(out) == "REVIEW_HALT":
                raise _Stop("REVIEW", "REVIEW_REQUIRED", iid)
            # a mandatory escalation cannot be weakened or overridden by survey routing (A-4)
            if by_mandatory and outcome_class(out) != "ESCALATION":
                raise _Stop("INVALID", "MANDATORY_ESCALATION_WEAKENED", iid)
            configured = (inst.get("routes") or {}).get(out)
            honoured = isinstance(configured, dict) and configured.get("survey_outcome") == out
            # Escalate is TERMINAL for the survey however the module reached it: never continued, never re-routed
            terminal_escalation = outcome_class(out) == "ESCALATION"
            to = {"survey_outcome": out} if terminal_escalation else configured
            if to is None:
                raise _Stop("INVALID", "ROUTE_MISSING", f"{iid}:{out}")
            skipped: list[str] = []
            if isinstance(to, dict) and "instance" in to:
                target = next((i for i, x in enumerate(seq) if x["instance"] == to["instance"]), -1)
                skipped = [x["instance"] for x in seq[pos + 1 : target]] if target > pos else []
            push(
                "SURVEY_ROUTE", instance=iid, outcome=out, to=to, skipped=skipped,
                **({"mandatory": True} if by_mandatory and isinstance(to, dict) and "survey_outcome" in to else {}),
                **({"overridden": not honoured} if terminal_escalation else {}),
            )  # fmt: skip
            ended = not go(inst, to, by_mandatory)
        if not ended:
            end_call("COMPLETED", seq[-1] if seq else {"instance": ""}, False)
    except _Stop as stop:
        if stop.status != "PENDING":
            if stop.status == "REVIEW":
                state["terminal"] = {
                    "state": "REVIEW_REQUIRED",
                    "survey_outcome": "REVIEW_REQUIRED",
                    "reason": stop.reason,
                    "at": stop.where,
                }
            elif stop.status == "MISSING":
                state["terminal"] = {"state": "MISSING_INFORMATION_HALT", "reason": stop.reason, "at": stop.where}
            else:
                # the definition is incomplete or invalid at this point: nothing was decided and nothing is guessed
                state["terminal"] = {"state": "DRAFT_INVALID", "reason": stop.reason, "at": stop.where}
            push(
                "END",
                instance=stop.where.split("/")[0].split(":")[0],
                status=state["terminal"]["state"],
                **{("where" if k == "at" else k): v for k, v in state["terminal"].items() if k != "state"},
            )

    modules = []
    for inst in seq:
        line = dict(status.get(inst["instance"]) or {"instance": inst["instance"], "status": "NOT_REACHED"})
        line["module"] = dict(inst.get("module") or {})
        line["name"] = module_name(inst)
        modules.append(line)

    # every item of every module that ran, and how it stands: answered, answered-empty, unanswered, delivered, skipped
    evidence_states: dict[str, str] = {}
    for inst in seq:
        ran = status.get(inst["instance"])
        if not ran or ran["status"] not in ("ACTIVATED", "RUNNING"):
            continue
        m = bundle.module_of(inst)
        for n in (m or {}).get("nodes", []):
            if n.get("type") == "DECISION":
                continue
            key = f"{inst['instance']}/{n['node']}"
            item = bundle.item_of(n)
            given = answers.get(key)
            evidence_states[key] = (
                answer_state(item, given) if given is not None and item is not None
                else "NOT_REACHED" if ran["status"] == "RUNNING" else "SKIPPED"
            )  # fmt: skip

    pending, unresolved = state["pending"], state["unresolved"]
    if pending is None:
        unresolved = None
    return {
        # PENDING: a question needs an answer. POLICY_UNRESOLVED: the last thing said to it was a non-answer whose
        # handling is an open business decision — NOT a business outcome. TERMINAL: the run has ended.
        "status": "TERMINAL" if state["terminal"] else "POLICY_UNRESOLVED" if unresolved else "PENDING",
        "terminal": state["terminal"], "pending": pending, "policy_unresolved": unresolved,
        "undeliverable": state.get("undeliverable"),
        "asked": asked, "delivered": delivered, "modules": modules, "evidence": evidence,
        "evidence_states": evidence_states, "edges": edges, "trace": trace, "events": events,
        "rejections": [{"at": e["key"], "error": e["code"]} for e in events if e["kind"] == "REJECT"],
    }  # fmt: skip


def execute_inputs(bundle: Bundle, facts: Mapping[str, Any], inputs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """A run driven by an ordered list of inputs ``{key, answer}`` — what a simulation stores. Each input must be for
    the question that is current when it is consumed; one that is not is reported and nothing after it is applied.
    Replaying the same inputs always gives the same run."""
    consumed = 0
    mismatch: dict[str, Any] | None = None

    def supplier(key: str, _attempt: int) -> Answer | None:
        nonlocal consumed, mismatch
        if mismatch is not None or consumed >= len(inputs):
            return None
        given = inputs[consumed]
        if given.get("key") != key:
            mismatch = {"index": consumed, "expected": key, "got": given.get("key")}
            return None
        consumed += 1
        answer = given.get("answer")
        return answer if isinstance(answer, Mapping) else {}

    run = execute(bundle, facts, supplier)
    run["inputs_consumed"] = consumed
    run["input_mismatch"] = mismatch
    return run
