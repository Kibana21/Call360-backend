"""One applicability policy applied to one set of typed facts: the deterministic survey-selection plan.

Selection is ADDITIVE: every requirement whose condition holds contributes its surveys; nothing "wins". Combination
effects are only the ones written down — ``replaces`` (named requirements, and only while the replacer is active) and
``CHOOSE_ONE`` (exactly one eligible alternative, never the first in the list). ``order`` is the governed delivery
order and never affects what is selected. Anything that cannot be decided is reported as unresolved, with the facts
that would settle it; it is never guessed. The plan is a synthetic result and grants nothing.
"""

from __future__ import annotations

from typing import Any

from app.domain.survey.applicability.logic import (
    CONTRACT,
    FALSE,
    TRUE,
    UNKNOWN,
    ApplicabilityError,
    Evaluation,
    Workspace,
    needs,
    variables_of,
)
from app.domain.survey.canonical import sha256_hex

MAX_REQUIREMENTS = 200
STATE = {TRUE: "APPLIES", FALSE: "DOES_NOT_APPLY", UNKNOWN: "UNRESOLVED"}
ALWAYS: dict[str, Any] = {"op": "all", "path": "", "result": TRUE, "children": [], "text": "always"}


def survey_key(ref: dict[str, Any]) -> str:
    return str(ref.get("code"))


def surveys_of(req: dict[str, Any]) -> list[dict[str, Any]]:
    action = req.get("action") or {}
    if action.get("kind") == "CHOOSE_ONE":
        return [dict(a.get("survey") or {}) for a in action.get("alternatives") or []]
    return [dict(s) for s in action.get("surveys") or []]


def policy_variables(ws: Workspace, policy: dict[str, Any]) -> list[str]:
    """Every variable the policy reads, in first-use order."""
    seen: set[str] = set()
    out: list[str] = []
    exprs = [policy.get("scope")]
    for r in policy.get("requirements") or []:
        exprs.append(r.get("when"))
        if (r.get("action") or {}).get("kind") == "CHOOSE_ONE":
            exprs.extend(a.get("when") for a in r["action"].get("alternatives") or [])
    for e in exprs:
        for v in variables_of(ws, e, seen):
            if v not in out:
                out.append(v)
    return out


def bundle(ws: Workspace, policy: dict[str, Any]) -> dict[str, Any]:
    """What a published revision pins: the policy and the exact definitions it reads. Its hash is the fingerprint."""
    used = policy_variables(ws, policy)
    conditions: dict[str, Any] = {}

    def refs(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "ref":
            code = str(node.get("condition"))
            key = f"{code}@{node.get('version')}"
            if key not in conditions and code in ws.conditions:
                try:
                    expr = ws.condition_expr(code, node.get("version"))
                except ApplicabilityError:
                    return
                conditions[key] = expr
                refs(expr)
        for a in node.get("args") or []:
            refs(a)
        refs(node.get("arg"))

    refs(policy.get("scope"))
    for r in policy.get("requirements") or []:
        refs(r.get("when"))
        for a in (r.get("action") or {}).get("alternatives") or []:
            refs(a.get("when"))
    variables = {}
    for code in sorted({*used, *(c for c, v in ws.variables.items() if v.get("derived"))}):
        v = ws.variables.get(code)
        if v is not None:
            variables[code] = {k: v.get(k) for k in ("type", "values", "currency", "min", "max", "derived", "version")}
    body = {
        k: policy.get(k) for k in ("code", "market", "profiles", "scope", "shared_deliveries", "requirements", "order")
    }
    return {"contract": CONTRACT, "policy": body, "variables": variables, "conditions": conditions}


def fingerprint(ws: Workspace, policy: dict[str, Any]) -> str:
    return sha256_hex(bundle(ws, policy))


def _choose(ev: Evaluation, req: dict[str, Any]) -> dict[str, Any]:
    """Exactly one eligible alternative, or an explicit reason why not. List order never decides."""
    alts = []
    for i, a in enumerate((req.get("action") or {}).get("alternatives") or []):
        when = a.get("when")
        fallback = bool(a.get("fallback"))
        trace = ev.expr(dict(when), f"alt{i}") if when and not fallback else None
        alts.append(
            {
                "index": i,
                "survey": dict(a.get("survey") or {}),
                "otherwise": fallback,
                "missing_criterion": not when and not fallback,
                "trace": trace,
                "result": trace["result"] if trace else None,
            }
        )
    trues = [a for a in alts if a["result"] == TRUE]
    unknowns = [a for a in alts if a["result"] == UNKNOWN]
    otherwise = [a for a in alts if a["otherwise"]]
    chosen: dict[str, Any] | None = None
    if len(trues) > 1:
        outcome, why = "AMBIGUOUS", f"{len(trues)} alternatives are eligible and no rule says which one to use"
    elif len(otherwise) > 1:
        outcome, why = "AMBIGUOUS", "more than one alternative is marked 'otherwise'"
    elif unknowns:
        outcome, why = "UNRESOLVED", "whether an alternative is eligible is not known"
    elif len(trues) == 1:
        outcome, why, chosen = "CHOSEN", "it is the only eligible alternative", trues[0]
    elif otherwise:
        outcome, why, chosen = "CHOSEN", "no other alternative is eligible", otherwise[0]
    else:
        outcome, why = "NO_ALTERNATIVE", "no alternative is eligible and there is no 'otherwise'"
    for a in alts:
        a["chosen"] = chosen is not None and a["index"] == chosen["index"]
    return {"outcome": outcome, "reason": why, "alternatives": alts, "chosen": chosen["survey"] if chosen else None}


def evaluate(
    ws: Workspace, policy: dict[str, Any], facts: dict[str, Any] | None, profiles: list[str] | None = None
) -> dict[str, Any]:
    """The selection plan of one policy for one application. Pure: the same input gives the same bytes."""
    reqs = [dict(r) for r in policy.get("requirements") or []]
    if len(reqs) > MAX_REQUIREMENTS:
        raise ApplicabilityError("TOO_LARGE", f"A policy holds at most {MAX_REQUIREMENTS} requirements")
    ids = [str(r.get("id")) for r in reqs]
    if len(set(ids)) != len(ids):
        raise ApplicabilityError("DUPLICATE_REQUIREMENT", "Two requirements share an identifier")
    # Profiles describe an application; they never decide whether a policy applies. Only the profiles an application
    # itself states are used, and only to check its facts. A policy's reach is its explicit `scope`.
    ev = Evaluation(ws, facts, list(profiles or []) or None)
    diagnostics: list[dict[str, Any]] = []
    head = {
        "contract": CONTRACT,
        "policy": {
            "code": policy.get("code"),
            "name": policy.get("name"),
            "version": policy.get("version"),
            "status": policy.get("status"),
            "fingerprint": fingerprint(ws, policy),
        },
        "record_class": "SIMULATION",
        "note": "A synthetic selection result. It is not an assignment and gives no permission to call anyone.",
    }

    def finish(body: dict[str, Any]) -> dict[str, Any]:
        used = policy_variables(ws, policy)
        states = {code: ev.fact(code) for code in used if code in ws.variables}
        # a worked-out fact is shown with the value it was given, wherever it can be worked out
        for code, var in ws.variables.items():
            if var.get("derived") and code not in states:
                try:
                    states[code] = ev.fact(code)
                except ApplicabilityError:
                    continue
        for code, f in states.items():
            if f["state"] == "INVALID":
                diagnostics.append(
                    {
                        "severity": "WARNING",
                        "code": f"FACT_{f['state']}",
                        "variable": code,
                        "message": f"{f['name']}: {f['reason']}. It is treated as not known.",
                    }
                )
        out = {**head, **body, "facts": states, "facts_fingerprint": sha256_hex(ev.facts), "diagnostics": diagnostics}
        out["fingerprint"] = sha256_hex({k: v for k, v in out.items() if k != "fingerprint"})
        return out

    empty: dict[str, Any] = {"requirements": [], "selected": [], "pending": [], "excluded": [], "needs": []}
    # ---- scope
    scope = ev.expr(dict(policy["scope"]), "scope") if policy.get("scope") else None
    if scope is not None and scope["result"] != TRUE:
        status = "OUT_OF_SCOPE" if scope["result"] == FALSE else "SCOPE_UNRESOLVED"
        say = (
            "This policy does not cover this application."
            if status == "OUT_OF_SCOPE"
            else "Whether this policy covers this application is not known."
        )
        return finish({**empty, "status": status, "scope": scope, "needs": needs(scope), "explanation": [say]})

    # ---- every requirement's condition
    rows: dict[str, dict[str, Any]] = {}
    for r in reqs:
        rid = str(r.get("id"))
        trace = ev.expr(dict(r["when"]), rid) if r.get("when") else dict(ALWAYS, path=rid)
        rows[rid] = {
            "id": rid,
            "name": r.get("name") or rid,
            "state": STATE[str(trace["result"])],
            "trace": trace,
            "action": (r.get("action") or {}).get("kind") or "INCLUDE",
            "replaces": [str(x) for x in r.get("replaces") or []],
            "surveys": surveys_of(r),
            "needs": needs(trace),
        }
    replaced_by: dict[str, list[str]] = {rid: [] for rid in rows}
    for rid, row in rows.items():
        for target in row["replaces"]:
            if target == rid or target not in rows:
                raise ApplicabilityError(
                    "INVALID_REPLACEMENT",
                    f"'{row['name']}' replaces something that is not a requirement of this policy",
                    rid,
                )
            replaced_by[target].append(rid)

    # ---- a circle of replacements is an error of its own (it is also a chain; say the more precise thing)
    for rid in rows:
        seen_ids, todo = set(), list(rows[rid]["replaces"])
        while todo:
            t = todo.pop()
            if t == rid:
                raise ApplicabilityError("REPLACEMENT_CYCLE", "Requirements replace each other in a circle", rid)
            if t not in seen_ids:
                seen_ids.add(t)
                todo.extend(rows[t]["replaces"])
    # ---- AP-1: a replacement names its FINAL targets. A chain (the replaced requirement itself replaces something)
    # is refused, never resolved by a rule the author did not write.
    for rid, row in rows.items():
        for target in row["replaces"]:
            if rows[target]["replaces"]:
                raise ApplicabilityError(
                    "REPLACEMENT_CHAIN",
                    f"'{row['name']}' replaces '{rows[target]['name']}', which itself replaces another requirement. "
                    "Name the final targets on one requirement",
                    rid,
                )
    visiting: list[str] = []

    def outcome(rid: str) -> str:
        row = rows[rid]
        if "outcome" in row:
            return str(row["outcome"])
        if rid in visiting:
            raise ApplicabilityError("REPLACEMENT_CYCLE", "Requirements replace each other in a circle", rid)
        visiting.append(rid)
        if row["state"] == "UNRESOLVED":
            result = "UNRESOLVED"
        elif row["state"] == "DOES_NOT_APPLY":
            result = "INACTIVE"
        else:
            theirs = {x: outcome(x) for x in replaced_by[rid]}
            active = [x for x, o in theirs.items() if o == "ACTIVE"]
            maybe = [x for x, o in theirs.items() if o in ("UNRESOLVED", "PENDING")]
            if active:
                result, row["replaced_by"] = "REPLACED", active
            elif maybe:
                result, row["may_be_replaced_by"] = "PENDING", maybe
            else:
                result = "ACTIVE"
        visiting.pop()
        row["outcome"] = result
        return result

    for rid in rows:
        outcome(rid)

    # ---- what each requirement contributes
    selected: dict[str, dict[str, Any]] = {}
    pending: dict[str, dict[str, Any]] = {}
    unresolved = False

    def add(into: dict[str, dict[str, Any]], ref: dict[str, Any], rid: str) -> None:
        entry = into.setdefault(survey_key(ref), {"survey": ref, "required_by": [], "versions": []})
        entry["required_by"].append(rid)
        if ref.get("version") not in entry["versions"]:
            entry["versions"].append(ref.get("version"))

    by_id = {str(r.get("id")): r for r in reqs}
    for rid, row in rows.items():
        choice = None
        if row["action"] == "CHOOSE_ONE" and row["outcome"] in ("ACTIVE", "PENDING", "UNRESOLVED"):
            choice = _choose(ev, by_id[rid])
            row["choice"] = choice
        if row["outcome"] == "ACTIVE":
            if choice is None:
                for ref in row["surveys"]:
                    add(selected, ref, rid)
            elif choice["outcome"] == "CHOSEN":
                add(selected, choice["chosen"], rid)
            else:
                unresolved = True
                row["outcome"] = choice["outcome"] if choice["outcome"] != "UNRESOLVED" else "CHOICE_UNRESOLVED"
                for a in choice["alternatives"]:
                    row["needs"] = [
                        *row["needs"],
                        *[n for n in (needs(a["trace"]) if a["trace"] else []) if n not in row["needs"]],
                    ]
                    add(pending, a["survey"], rid)
        elif row["outcome"] in ("PENDING", "UNRESOLVED"):
            unresolved = True
            for ref in [choice["chosen"]] if choice and choice["outcome"] == "CHOSEN" else row["surveys"]:
                add(pending, ref, rid)

    # ---- AP-2: the same survey required by several requirements is never merged silently. It is one delivery only
    # where the author said so FOR THOSE REQUIREMENTS; every contributing requirement stays on the record.
    shared: list[tuple[str, set[str]]] = [
        (str(d.get("survey")), {str(x) for x in d.get("requirements") or []})
        for d in policy.get("shared_deliveries") or []
    ]
    for key, entry in selected.items():
        label = entry["survey"].get("name") or key
        if len(entry["versions"]) > 1:
            unresolved = True
            versions = ", ".join(str(v) for v in entry["versions"])
            diagnostics.append(
                {
                    "severity": "BLOCKER",
                    "code": "SURVEY_VERSION_CONFLICT",
                    "survey": key,
                    "message": f"{label} is required in different versions ({versions}).",
                }
            )
        if len(entry["required_by"]) > 1:
            names = ", ".join(f"‘{rows[r]['name']}’" for r in entry["required_by"])
            agreed = any(code == key and set(entry["required_by"]) <= members for code, members in shared)
            if agreed:
                entry["obligations"] = len(entry["required_by"])
                diagnostics.append(
                    {
                        "severity": "INFO",
                        "code": "SURVEY_SHARED_DELIVERY",
                        "survey": key,
                        "requirements": list(entry["required_by"]),
                        "message": f"{label} is required by {names}. As stated in this policy, one delivery satisfies each of them.",  # noqa: E501
                    }
                )
            else:
                unresolved = True
                entry["conflict"] = True
                diagnostics.append(
                    {
                        "severity": "BLOCKER",
                        "code": "DUPLICATE_SURVEY",
                        "survey": key,
                        "requirements": list(entry["required_by"]),
                        "message": f"{label} is required by {names}. Nothing says whether that is one delivery or several: resolve it for these requirements.",  # noqa: E501
                    }
                )

    # ---- the governed order: where each selected survey goes; never which surveys
    order = [str(k) for k in policy.get("order") or []]
    position = {k: i for i, k in enumerate(order)}
    final = sorted(
        selected.values(), key=lambda e: (position.get(survey_key(e["survey"]), len(order)), survey_key(e["survey"]))
    )
    for i, e in enumerate(final):
        e["position"] = i + 1
        e.pop("versions", None)
        if survey_key(e["survey"]) not in position:
            diagnostics.append(
                {
                    "severity": "BLOCKER",
                    "code": "ORDER_MISSING",
                    "survey": survey_key(e["survey"]),
                    "message": f"{name(e)} has no place in the delivery order.",
                }
            )
    # pending surveys in the governed delivery order too
    waiting = [
        dict(e, versions=None)
        for k, e in sorted(pending.items(), key=lambda kv: (position.get(kv[0], len(order)), kv[0]))
        if k not in selected
    ]
    for e in waiting:
        e.pop("versions", None)

    # ---- everything this policy can require that this application does not get, and why
    excluded: list[dict[str, Any]] = []
    seen = {*selected, *pending}
    for row in rows.values():
        for ref in row["surveys"]:
            key = survey_key(ref)
            if key in seen:
                continue
            seen.add(key)
            why = []
            for other, orow in rows.items():
                if key not in {survey_key(s) for s in orow["surveys"]}:
                    continue
                if orow["outcome"] == "INACTIVE":
                    why.append(
                        {"requirement": other, "reason": "NOT_APPLICABLE", "text": f"‘{orow['name']}’ does not apply"}
                    )
                elif orow["outcome"] == "REPLACED":
                    by = ", ".join(f"‘{rows[x]['name']}’" for x in orow.get("replaced_by", []))
                    why.append(
                        {
                            "requirement": other,
                            "reason": "REPLACED",
                            "text": f"‘{orow['name']}’ applies but is replaced by {by}",
                        }
                    )
                elif orow.get("choice"):
                    why.append(
                        {
                            "requirement": other,
                            "reason": "ALTERNATIVE_NOT_CHOSEN",
                            "text": f"‘{orow['name']}’ chose another alternative",
                        }
                    )
            excluded.append({"survey": ref, "why": why})

    # ---- in words
    def quoted(ids: list[str]) -> str:
        return ", ".join(f"‘{rows[x]['name']}’" for x in ids)

    explanation: list[str] = []
    for row in rows.values():
        who, o = f"‘{row['name']}’", row["outcome"]
        cond = row["trace"]["text"]
        if o == "ACTIVE":
            got = row["choice"]["chosen"] if row.get("choice") else None
            what = (got.get("name") if got else None) or ", ".join(
                str(s.get("name") or s.get("code")) for s in row["surveys"]
            )
            explanation.append(f"{who} applies ({cond}) and requires {what}.")
        elif o == "REPLACED":
            explanation.append(f"{who} applies ({cond}) but is replaced by {quoted(row['replaced_by'])}.")
        elif o == "PENDING":
            explanation.append(
                f"{who} applies ({cond}), but it may be replaced by {quoted(row['may_be_replaced_by'])}, "
                "which cannot be decided yet."
            )
        elif o == "UNRESOLVED":
            lack = "; ".join(f"{n['name']} — {n['reason']}" for n in row["needs"]) or "a value is not known"
            explanation.append(f"{who} cannot be decided: {lack}.")
        elif o in ("AMBIGUOUS", "NO_ALTERNATIVE", "CHOICE_UNRESOLVED"):
            explanation.append(
                f"{who} applies ({cond}), but no single survey can be chosen: {row['choice']['reason']}."
            )
        else:
            explanation.append(f"{who} does not apply.")
    all_needs: list[dict[str, Any]] = []
    for row in rows.values():
        if row["outcome"] in ("UNRESOLVED", "CHOICE_UNRESOLVED") or (row["outcome"] == "PENDING"):
            src = (
                row["needs"]
                if row["outcome"] != "PENDING"
                else [n for x in row["may_be_replaced_by"] for n in rows[x]["needs"]]
            )
            for n in src:
                if not any(a["variable"] == n["variable"] for a in all_needs):
                    all_needs.append(n)
    return finish(
        {
            "status": "UNRESOLVED" if unresolved else "RESOLVED",
            "scope": scope,
            "requirements": list(rows.values()),
            "selected": final,
            "pending": waiting,
            "excluded": excluded,
            "needs": all_needs,
            "explanation": explanation,
            "summary": _summary(final, waiting, unresolved),
        }
    )


def _summary(final: list[dict[str, Any]], waiting: list[dict[str, Any]], unresolved: bool) -> str:
    names = [str(e["survey"].get("name") or e["survey"].get("code")) for e in final]
    if unresolved:
        base = f"Not decided yet. Definitely required: {', '.join(names)}." if names else "Not decided yet."
        more = [str(e["survey"].get("name") or e["survey"].get("code")) for e in waiting]
        return f"{base} Possibly also: {', '.join(more)}." if more else base
    return f"Required, in this order: {', '.join(names)}." if names else "No survey is required."


def _low(outcome: str) -> str:
    return outcome.lower().replace("_", " ")


def name(e: dict[str, Any]) -> str:
    return str(e["survey"].get("name") or e["survey"].get("code"))


def signature(plan: dict[str, Any]) -> tuple[Any, ...]:
    """What makes two results the same result: status, each requirement's outcome, the ordered surveys, the pending."""
    return (
        plan["status"],
        tuple((r["id"], r["outcome"]) for r in plan["requirements"]),
        tuple((survey_key(e["survey"]), e["survey"].get("version")) for e in plan["selected"]),
        tuple(survey_key(e["survey"]) for e in plan["pending"]),
    )


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """What changes for one application between two policies, and which requirements are the reason."""
    a = {survey_key(e["survey"]): e for e in before["selected"]}
    b = {survey_key(e["survey"]): e for e in after["selected"]}
    added = [name(b[k]) for k in b if k not in a]
    removed = [name(a[k]) for k in a if k not in b]
    revised = [
        f"{name(b[k])} (version {a[k]['survey'].get('version')} → {b[k]['survey'].get('version')})"
        for k in b
        if k in a and a[k]["survey"].get("version") != b[k]["survey"].get("version")
    ]
    order = [k for k in a if k in b] != [k for k in b if k in a]
    ra = {r["id"]: r for r in before["requirements"]}
    rb = {r["id"]: r for r in after["requirements"]}
    because = []
    for rid in [*rb, *(x for x in ra if x not in rb)]:
        x, y = ra.get(rid), rb.get(rid)
        if x is None and y is not None:
            if y["outcome"] != "INACTIVE":
                because.append(
                    {
                        "requirement": rid,
                        "name": y["name"],
                        "change": "NEW",
                        "text": f"‘{y['name']}’ is new and is {_low(y['outcome'])}",
                    }
                )
        elif y is None and x is not None:
            if x["outcome"] != "INACTIVE":
                because.append(
                    {
                        "requirement": rid,
                        "name": x["name"],
                        "change": "REMOVED",
                        "text": f"‘{x['name']}’ no longer exists (it was {_low(x['outcome'])})",
                    }
                )
        elif x is not None and y is not None:
            sx = [(survey_key(s), s.get("version")) for s in x["surveys"]]
            sy = [(survey_key(s), s.get("version")) for s in y["surveys"]]
            if x["outcome"] != y["outcome"]:
                because.append(
                    {
                        "requirement": rid,
                        "name": y["name"],
                        "change": "OUTCOME",
                        "text": f"‘{y['name']}’ was {_low(x['outcome'])} and is now {_low(y['outcome'])}",
                    }
                )
            elif sx != sy and y["outcome"] != "INACTIVE":
                because.append(
                    {
                        "requirement": rid,
                        "name": y["name"],
                        "change": "SURVEYS",
                        "text": f"‘{y['name']}’ now requires different surveys",
                    }
                )
    new_unknown = before["status"] == "RESOLVED" and after["status"] != "RESOLVED"
    changed = bool(added or removed or revised or order or before["status"] != after["status"])
    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "revised": revised,
        "order_changed": order,
        "status_before": before["status"],
        "status_after": after["status"],
        "new_unknown": new_unknown,
        "because": because if changed else [],
    }


def resolve_policy(ws: Workspace, policies: list[dict[str, Any]], facts: dict[str, Any] | None) -> dict[str, Any]:
    """Which ONE policy covers an application. More than one in scope is never settled silently."""
    rows = []
    for p in policies:
        ev = Evaluation(ws, facts, list(p.get("profiles") or []) or None)
        result = ev.expr(dict(p["scope"]), "scope")["result"] if p.get("scope") else TRUE
        rows.append({"code": p.get("code"), "name": p.get("name"), "scope": result})
    yes = [r for r in rows if r["scope"] == TRUE]
    maybe = [r for r in rows if r["scope"] == UNKNOWN]
    if len(yes) == 1 and not maybe:
        return {"status": "ONE_POLICY", "policy": yes[0]["code"], "policies": rows}
    if not yes and not maybe:
        return {"status": "NO_POLICY", "policy": None, "policies": rows}
    status = "MULTIPLE_POLICIES" if len(yes) > 1 else "POLICY_UNRESOLVED"
    return {"status": status, "policy": None, "policies": rows}
