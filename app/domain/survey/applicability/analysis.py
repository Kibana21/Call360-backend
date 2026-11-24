"""Static analysis of applicability documents, and scenario generation.

Structural checks are exact. Claims about behaviour ("can never match", "can be eligible together") are made only when
the variables involved can be enumerated completely — every enum value, yes/no, "not known", and for numbers and dates
one representative point in every region the thresholds cut out. When that would be too large the analysis says
``NOT_CHECKED``; it never reports "fine" for something it did not examine.
"""

from __future__ import annotations

import itertools
from datetime import date
from typing import Any

from app.domain.survey.applicability import evaluator as ev_
from app.domain.survey.applicability.logic import (
    FALSE,
    NUMERIC,
    OPERATORS,
    PRESENCE,
    TRUE,
    TYPES,
    ApplicabilityError,
    Evaluation,
    Workspace,
    label_of,
    variables_of,
)
from app.domain.survey.canonical import canonical_text

MAX_COMBINATIONS = 20000
MAX_SCENARIOS = 60


def _d(severity: str, code: str, message: str, /, **at: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "message": message, "at": at}


# ------------------------------------------------------------------------------------------------------ structure
def check_expr(
    ws: Workspace, expr: Any, where: dict[str, Any], out: list[dict[str, Any]], trail: tuple[str, ...] = ()
) -> None:
    """Every structural problem of one expression, each located by the path of its node."""

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            out.append(_d("BLOCKER", "EMPTY_CONDITION", "A condition is missing here", **where, path=path))
            return
        op = node.get("op")
        if op in ("all", "any"):
            args = list(node.get("args") or [])
            if not args:
                out.append(_d("WARNING", "EMPTY_GROUP", "This group is empty", **where, path=path))
            seen: dict[str, int] = {}
            for i, a in enumerate(args):
                key = canonical_text(a)
                if key in seen:
                    out.append(
                        _d(
                            "WARNING",
                            "DUPLICATE_PREDICATE",
                            "This repeats another part of the same group",
                            **where,
                            path=_p(path, i),
                        )
                    )
                seen[key] = i
                walk(a, _p(path, i))
        elif op == "not":
            walk(node.get("arg"), _p(path, 0))
        elif op == "ref":
            code = str(node.get("condition"))
            if code not in ws.conditions:
                out.append(
                    _d(
                        "BLOCKER",
                        "UNKNOWN_CONDITION",
                        f"The saved condition '{code}' does not exist",
                        **where,
                        path=path,
                    )
                )
            elif code in trail:
                out.append(
                    _d(
                        "BLOCKER",
                        "CONDITION_CYCLE",
                        f"'{ws.conditions[code].get('name') or code}' ends up referring to itself",
                        **where,
                        path=path,
                    )
                )
            else:
                try:
                    inner = ws.condition_expr(code, node.get("version"))
                except ApplicabilityError as exc:
                    out.append(_d("BLOCKER", exc.code, exc.message, **where, path=path))
                    return
                nested: list[dict[str, Any]] = []
                check_expr(ws, inner, where, nested, (*trail, code))
                out.extend(x for x in nested if x["code"] == "CONDITION_CYCLE")
        elif op == "test":
            code, operator = str(node.get("variable")), str(node.get("operator"))
            var = ws.variables.get(code)
            if var is None:
                out.append(
                    _d("BLOCKER", "UNKNOWN_VARIABLE", f"The variable '{code}' does not exist", **where, path=path)
                )
                return
            name, kind = var.get("name") or code, str(var.get("type"))
            if var.get("status") == "DEPRECATED":
                out.append(_d("WARNING", "DEPRECATED_VARIABLE", f"{name} is deprecated", **where, path=path))
            if operator not in PRESENCE and operator not in OPERATORS.get(kind, ()):
                out.append(
                    _d(
                        "BLOCKER",
                        "OPERATOR_NOT_ALLOWED",
                        f"'{operator}' cannot be used with {name}",
                        **where,
                        path=path,
                    )
                )
                return
            allowed = [o.get("value") for o in var.get("values") or []]
            if operator in ("equals", "not_equals", "gt", "gte", "lt", "lte", "on", "before", "after"):
                _value(var, node.get("value"), allowed, name, where, path, out)
            elif operator == "between":
                _value(var, node.get("min"), allowed, name, where, path, out)
                _value(var, node.get("max"), allowed, name, where, path, out)
                lo, hi = node.get("min"), node.get("max")
                if lo is not None and hi is not None and str(type(lo)) == str(type(hi)) and lo > hi:
                    out.append(
                        _d("BLOCKER", "RANGE_REVERSED", f"{name}: the range starts after it ends", **where, path=path)
                    )
            elif operator in ("in", "not_in", "includes_any", "includes_all", "includes_none"):
                values = node.get("values") or []
                if not values:
                    out.append(_d("BLOCKER", "NO_VALUE", f"{name}: choose at least one value", **where, path=path))
                for v in values:
                    _value(var, v, allowed, name, where, path, out)
        else:
            out.append(_d("BLOCKER", "UNKNOWN_NODE", f"'{op}' is not a kind of condition", **where, path=path))

    walk(expr, "")


def _p(path: str, i: int) -> str:
    return f"{path}.{i}" if path else str(i)


def _value(
    var: dict[str, Any],
    value: Any,
    allowed: list[Any],
    name: str,
    where: dict[str, Any],
    path: str,
    out: list[dict[str, Any]],
) -> None:
    kind = var.get("type")
    if value is None or value == "":
        out.append(_d("BLOCKER", "NO_VALUE", f"{name}: a value is missing", **where, path=path))
    elif kind in ("ENUM", "MULTI_ENUM") and value not in allowed:
        out.append(
            _d("BLOCKER", "VALUE_NOT_ALLOWED", f"{name}: '{value}' is not one of its values", **where, path=path)
        )
    elif kind in NUMERIC and (isinstance(value, bool) or not isinstance(value, (int, float))):
        out.append(_d("BLOCKER", "TYPE_MISMATCH", f"{name}: '{value}' is not a number", **where, path=path))
    elif kind == "DATE":
        try:
            date.fromisoformat(str(value))
        except ValueError:
            out.append(_d("BLOCKER", "TYPE_MISMATCH", f"{name}: '{value}' is not a date", **where, path=path))


# ----------------------------------------------------------------------------------------------------- enumeration
def _thresholds(ws: Workspace, exprs: list[Any]) -> dict[str, set[Any]]:
    found: dict[str, set[Any]] = {}
    seen: set[str] = set()

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "test":
            code = str(node.get("variable"))
            var = ws.variables.get(code)
            if var is not None and var.get("derived") and code not in seen:
                seen.add(code)
                walk(var["derived"].get("expr"))
            for k in ("value", "min", "max"):
                if node.get(k) is not None:
                    found.setdefault(code, set()).add(node[k])
            for v in node.get("values") or []:
                found.setdefault(code, set()).add(v)
        elif op == "ref":
            key = f"{node.get('condition')}@{node.get('version')}"
            if key not in seen and str(node.get("condition")) in ws.conditions:
                seen.add(key)
                try:
                    walk(ws.condition_expr(str(node.get("condition")), node.get("version")))
                except ApplicabilityError:
                    return
        else:
            for a in node.get("args") or []:
                walk(a)
            walk(node.get("arg"))

    for e in exprs:
        walk(e)
    return found


def domain(var: dict[str, Any], mentioned: set[Any], unknown: bool = True) -> tuple[list[Any], bool]:
    """Representative values of one variable and whether they cover every behaviour of the tests that read it."""
    kind = var.get("type")
    tail: list[Any] = [None] if unknown else []
    values = [o.get("value") for o in var.get("values") or []]
    if kind == "BOOLEAN":
        return [True, False, *tail], True
    if kind == "ENUM":
        return [*values, *tail], True
    if kind == "MULTI_ENUM":
        if len(values) <= 4:
            subsets = [list(c) for n in range(len(values) + 1) for c in itertools.combinations(values, n)]
            return [*subsets, *tail], True
        picks = [[], *[[v] for v in values if v in mentioned], [v for v in values if v in mentioned], values]
        unique = [list(x) for x in dict.fromkeys(tuple(p) for p in picks)]
        return [*unique, *tail], False
    if kind in NUMERIC:
        points = sorted(x for x in mentioned if isinstance(x, (int, float)) and not isinstance(x, bool))
        if not points:
            return [0, *tail], True
        step = 1 if kind == "NUMBER" else 0.01
        out: list[Any] = [points[0] - step]
        for i, p in enumerate(points):
            out.append(p)
            nxt = points[i + 1] if i + 1 < len(points) else None
            between = p + step if nxt is None or p + step < nxt else None
            if between is not None:
                out.append(round(between, 2) if kind != "NUMBER" else int(between))
        lo, hi = var.get("min"), var.get("max")
        kept = [
            x
            for x in out
            if (not isinstance(lo, (int, float)) or x >= lo) and (not isinstance(hi, (int, float)) or x <= hi)
        ]
        return [*(kept or [points[0]]), *tail], True
    if kind == "DATE":
        days = sorted({date.fromisoformat(str(x)).toordinal() for x in mentioned if _is_date(x)})
        if not days:
            return ["2026-01-01", *tail], True
        marks = [days[0] - 1]
        for d in days:
            marks.extend([d, d + 1])
        return [*[date.fromordinal(m).isoformat() for m in dict.fromkeys(marks)], *tail], True
    if kind == "STRING":
        return [*sorted(str(x) for x in mentioned), "(another value)", *tail], True
    return [*tail], False


def _is_date(x: Any) -> bool:
    try:
        date.fromisoformat(str(x))
    except ValueError:
        return False
    return True


def enumerate_facts(ws: Workspace, exprs: list[Any], unknown: bool = True) -> dict[str, Any]:
    """Every combination of the variables some expressions read — or a statement that there are too many."""
    codes: list[str] = []
    seen: set[str] = set()
    for e in exprs:
        for v in variables_of(ws, e if isinstance(e, dict) else None, seen):
            if v not in codes:
                codes.append(v)
    marks = _thresholds(ws, exprs)
    domains, exhaustive = [], True
    for c in codes:
        var = ws.variables.get(c)
        if var is None:
            return {
                "variables": codes,
                "checked": False,
                "reason": f"the variable '{c}' does not exist",
                "combinations": [],
            }
        values, full = domain(var, marks.get(c, set()), unknown)
        domains.append(values)
        exhaustive = exhaustive and full
    size = 1
    for d in domains:
        size *= max(len(d), 1)
    if size > MAX_COMBINATIONS:
        return {"variables": codes, "checked": False, "size": size, "combinations": [],
                "reason": f"{size:,} combinations of {len(codes)} variables are too many to examine"}  # fmt: skip
    combos = [dict(zip(codes, c, strict=True)) for c in itertools.product(*domains)] if codes else [{}]
    return {"variables": codes, "checked": True, "exhaustive": exhaustive, "size": size, "combinations": combos}


def _results(ws: Workspace, expr: dict[str, Any], combos: list[dict[str, Any]]) -> list[str]:
    return [Evaluation(ws, facts).expr(dict(expr), "")["result"] for facts in combos]


def facts_text(ws: Workspace, facts: dict[str, Any]) -> str:
    return (
        ", ".join(f"{ws.variables[c].get('name') or c} = {label_of(ws.variables[c], v)}" for c, v in facts.items())
        or "any application"
    )


def check_reach(
    ws: Workspace, expr: Any, where: dict[str, Any], out: list[dict[str, Any]], what: str = "This condition"
) -> None:
    """Can it ever be true? Is it always true? Only said when every combination was examined."""
    if not isinstance(expr, dict):
        return
    try:
        space = enumerate_facts(ws, [expr], unknown=False)
        if not space["checked"]:
            out.append(
                _d("INFO", "NOT_CHECKED", f"{what} was not checked for contradictions: {space['reason']}", **where)
            )
            return
        if not space["variables"]:
            return
        results = _results(ws, expr, space["combinations"])
    except ApplicabilityError:
        return
    if not space["exhaustive"]:
        return
    if TRUE not in results:
        out.append(_d("WARNING", "NEVER_TRUE", f"{what} can never be true: its parts contradict each other", **where))
    elif all(r == TRUE for r in results):
        out.append(
            _d("WARNING", "ALWAYS_TRUE", f"{what} is true for every application, so it restricts nothing", **where)
        )


# --------------------------------------------------------------------------------------------------------- analyse
def analyse(ws: Workspace, policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every diagnostic of a workspace and, when given, of one policy. BLOCKER stops submission; WARNING does not."""
    out: list[dict[str, Any]] = []
    names: dict[str, str] = {}
    for code, v in ws.variables.items():
        where = {"kind": "variable", "code": code}
        if v.get("type") not in TYPES:
            out.append(_d("BLOCKER", "UNKNOWN_TYPE", f"{v.get('name') or code} has no valid type", **where))
        if v.get("type") in ("ENUM", "MULTI_ENUM") and not v.get("values"):
            out.append(_d("BLOCKER", "NO_VALUES", f"{v.get('name') or code} has no allowed values", **where))
        if v.get("type") == "MONEY" and not v.get("currency"):
            out.append(_d("BLOCKER", "NO_CURRENCY", f"{v.get('name') or code} has no currency", **where))
        key = str(v.get("name") or "").strip().lower()
        if key and key in names:
            out.append(
                _d("WARNING", "DUPLICATE_NAME", f"'{v.get('name')}' is also the name of '{names[key]}'", **where)
            )
        names.setdefault(key, code)
        if v.get("derived"):
            if v.get("type") != "BOOLEAN":
                out.append(
                    _d(
                        "BLOCKER",
                        "DERIVED_TYPE",
                        f"{v.get('name') or code}: a derived variable is a yes/no value",
                        **where,
                    )
                )
            check_expr(ws, v["derived"].get("expr"), where, out)
            try:
                Evaluation(ws, {}).fact(code)
            except ApplicabilityError as exc:
                out.append(_d("BLOCKER", exc.code, exc.message, **where))
    for code, p in ws.profiles.items():
        where = {"kind": "profile", "code": code}
        for s in p.get("sections") or []:
            for var in s.get("variables") or []:
                if var not in ws.variables:
                    out.append(_d("BLOCKER", "UNKNOWN_VARIABLE", f"The variable '{var}' does not exist", **where))
        try:
            members, rules = ws.profile_variables([code])
        except ApplicabilityError as exc:
            out.append(_d("BLOCKER", exc.code, exc.message, **where))
            continue
        for var in p.get("required") or []:
            if var not in members:
                out.append(
                    _d("BLOCKER", "REQUIRED_NOT_INCLUDED", f"'{var}' is required but is not in this profile", **where)
                )
        out.extend(profile_conflicts(ws, rules, where))
    for code, c in ws.conditions.items():
        where = {"kind": "condition", "code": code}
        before = len(out)
        check_expr(ws, c.get("expr"), where, out, (code,))
        if not any(x["severity"] == "BLOCKER" for x in out[before:]):
            check_reach(ws, c.get("expr"), where, out)
    if policy is not None:
        out.extend(analyse_policy(ws, policy))
    return out


def profile_conflicts(
    ws: Workspace, rules: dict[str, list[dict[str, Any]]], where: dict[str, Any]
) -> list[dict[str, Any]]:
    """Composed profiles that restrict one variable to sets with nothing in common: no application can satisfy both."""
    out: list[dict[str, Any]] = []
    for var, items in rules.items():
        sets = [(r["profile"], set(r["allowed"])) for r in items if isinstance(r.get("allowed"), list)]
        for (pa, a), (pb, b) in itertools.combinations(sets, 2):
            if not a & b:
                name = (ws.variables.get(var) or {}).get("name") or var
                text = f"{name}: '{pa}' allows only {sorted(a)} and '{pb}' allows only {sorted(b)} — no application fits both"  # noqa: E501
                out.append(_d("BLOCKER", "PROFILE_CONFLICT", text, **where, variable=var))
    return out


def analyse_policy(ws: Workspace, policy: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pol = {"kind": "policy", "code": policy.get("code")}
    reqs = [dict(r) for r in policy.get("requirements") or []]
    ids = [str(r.get("id")) for r in reqs]
    by_id = dict(zip(ids, reqs, strict=True))
    name = {i: str(r.get("name") or i) for i, r in by_id.items()}
    if not reqs:
        out.append(_d("WARNING", "NO_REQUIREMENT", "This policy has no requirement yet: it selects nothing", **pol))
    for n, d in enumerate(policy.get("shared_deliveries") or []):
        members = [str(x) for x in d.get("requirements") or []]
        at = {**pol, "field": "shared_deliveries", "index": n, "survey": d.get("survey")}
        if len(members) < 2:
            out.append(
                _d("BLOCKER", "SHARED_DELIVERY_TOO_FEW", "A shared delivery names at least two requirements", **at)
            )
        for m in members:
            if m not in by_id:
                text = "A shared delivery names a requirement that does not exist"
                out.append(_d("BLOCKER", "SHARED_DELIVERY_UNKNOWN", text, **at))
            elif str(d.get("survey")) not in {ev_.survey_key(x) for x in ev_.surveys_of(by_id[m])}:
                text = f"‘{name[m]}’ does not ask for the survey this shared delivery is about"
                out.append(_d("BLOCKER", "SHARED_DELIVERY_MISMATCH", text, **at))
    profiles = [str(p) for p in policy.get("profiles") or []]
    supported: set[str] | None = None
    try:
        if profiles:
            supported, rules = ws.profile_variables(profiles)
            out.extend(profile_conflicts(ws, rules, pol))
    except ApplicabilityError as exc:
        out.append(_d("BLOCKER", exc.code, exc.message, **pol))
    if policy.get("scope"):
        check_expr(ws, policy["scope"], {**pol, "part": "scope"}, out)

    order = [str(k) for k in policy.get("order") or []]
    if len(set(order)) != len(order):
        out.append(
            _d("BLOCKER", "ORDER_DUPLICATE", "A survey appears twice in the delivery order", **pol, field="order")
        )
    versions: dict[str, set[Any]] = {}
    used: set[str] = set()
    shapes: dict[str, str] = {}
    for rid, r in by_id.items():
        where = {"kind": "requirement", "id": rid}
        before = len(out)
        if r.get("when"):
            check_expr(ws, r["when"], {**where, "part": "when"}, out)
            if supported is not None:
                for v in variables_of(ws, r["when"]):
                    if v not in supported:
                        vn = (ws.variables.get(v) or {}).get("name") or v
                        out.append(
                            _d(
                                "WARNING",
                                "VARIABLE_OUTSIDE_PROFILES",
                                f"{vn} is not in this policy's profiles: it will always be unknown",
                                **where,
                                variable=v,
                            )
                        )
        action = r.get("action") or {}
        refs = ev_.surveys_of(r)
        if not refs:
            out.append(_d("BLOCKER", "NO_SURVEY", f"‘{name[rid]}’ names no survey", **where, part="action"))
        if action.get("kind") == "CHOOSE_ONE":
            alts = action.get("alternatives") or []
            if len(alts) < 2:
                out.append(
                    _d(
                        "WARNING",
                        "ONE_ALTERNATIVE",
                        f"‘{name[rid]}’ offers one alternative: there is nothing to choose",
                        **where,
                        part="action",
                    )
                )
            for i, a in enumerate(alts):
                what = (a.get("survey") or {}).get("name") or "this alternative"
                if a.get("fallback") and a.get("when"):
                    text = f"‘{name[rid]}’: a fallback has no criterion of its own"
                    out.append(_d("BLOCKER", "FALLBACK_WITH_CRITERION", text, **where, part=f"alternative {i + 1}"))
                elif not a.get("fallback") and not a.get("when"):
                    text = f"‘{name[rid]}’: say when {what} is the one to use, or mark it as the fallback"
                    out.append(_d("BLOCKER", "MISSING_CRITERION", text, **where, part=f"alternative {i + 1}"))
            if sum(1 for a in alts if a.get("fallback")) > 1:
                text = f"‘{name[rid]}’ has more than one fallback"
                out.append(_d("BLOCKER", "SEVERAL_FALLBACKS", text, **where, part="action"))
            for i, a in enumerate(alts):
                if a.get("when"):
                    check_expr(ws, a["when"], {**where, "part": f"alternative {i + 1}"}, out)
        seen_here: set[str] = set()
        for ref in refs:
            key = ev_.survey_key(ref)
            if not ref.get("code") or not ref.get("version"):
                out.append(
                    _d(
                        "BLOCKER",
                        "SURVEY_NOT_PINNED",
                        f"‘{name[rid]}’: {ref.get('name') or ref.get('code') or 'a survey'} is not pinned to a version published in Survey Studio",  # noqa: E501
                        **where,
                        part="action",
                    )
                )
                continue
            if key in seen_here:
                out.append(
                    _d(
                        "WARNING",
                        "SURVEY_REPEATED",
                        f"‘{name[rid]}’ names {ref.get('name') or key} twice",
                        **where,
                        part="action",
                    )
                )
            seen_here.add(key)
            used.add(key)
            versions.setdefault(key, set()).add(ref.get("version"))
            if key not in order:
                out.append(
                    _d(
                        "BLOCKER",
                        "ORDER_MISSING",
                        f"{ref.get('name') or key} has no place in the delivery order",
                        **where,
                        survey=key,
                    )
                )
        for target in r.get("replaces") or []:
            if str(target) == rid:
                out.append(_d("BLOCKER", "REPLACES_ITSELF", f"‘{name[rid]}’ replaces itself", **where, part="replaces"))
            elif str(target) not in by_id:
                out.append(
                    _d(
                        "BLOCKER",
                        "REPLACES_UNKNOWN",
                        f"‘{name[rid]}’ replaces a requirement that does not exist",
                        **where,
                        part="replaces",
                    )
                )
        if not any(x["severity"] == "BLOCKER" for x in out[before:]):
            check_reach(ws, r.get("when"), {**where, "part": "when"}, out, f"The condition of ‘{name[rid]}’")
        shape = canonical_text({"when": r.get("when"), "action": action})
        if shape in shapes:
            out.append(
                _d("WARNING", "DUPLICATE_REQUIREMENT", f"‘{name[rid]}’ is the same as ‘{name[shapes[shape]]}’", **where)
            )
        shapes.setdefault(shape, rid)
    for key, vs in versions.items():
        if len(vs) > 1:
            out.append(
                _d(
                    "BLOCKER",
                    "SURVEY_VERSION_CONFLICT",
                    f"{key} is named in different versions ({', '.join(sorted(str(v) for v in vs))})",
                    **pol,
                    survey=key,
                )
            )
    for key in order:
        if key not in used:
            out.append(
                _d(
                    "INFO",
                    "ORDER_UNUSED",
                    f"{key} is in the delivery order but no requirement names it",
                    **pol,
                    survey=key,
                )
            )

    # ---- replacement: cycles are errors; a chain is legal but worth seeing
    graph = {
        rid: [str(t) for t in r.get("replaces") or [] if str(t) in by_id and str(t) != rid] for rid, r in by_id.items()
    }
    cyc = _cycle(graph)
    if cyc:
        loop = " → ".join(f"‘{name[x]}’" for x in cyc)
        # said on every requirement of the circle, where the author will look
        for rid in dict.fromkeys(cyc):
            text = f"These requirements replace each other in a circle: {loop}. Remove one of the replacements"
            out.append(
                _d("BLOCKER", "REPLACEMENT_CYCLE", text, kind="requirement", id=rid, part="replaces", requirements=cyc)
            )
    else:
        for rid, targets in graph.items():
            for t in targets:
                if graph.get(t):
                    again = ", ".join(f"‘{name[x]}’" for x in graph[t])
                    text = (
                        f"‘{name[rid]}’ replaces ‘{name[t]}’, which itself replaces {again}. Chains are not allowed: "
                        f"name everything ‘{name[rid]}’ should replace on ‘{name[rid]}’ itself"
                    )
                    out.append(_d("BLOCKER", "REPLACEMENT_CHAIN", text, kind="requirement", id=rid, part="replaces"))
    if any(x["severity"] == "BLOCKER" for x in out):
        return out
    out.extend(_behaviour(ws, policy, by_id, name))
    return out


def _cycle(graph: dict[str, list[str]]) -> list[str]:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(n: str) -> list[str]:
        state[n] = 1
        stack.append(n)
        for m in graph.get(n, []):
            if state.get(m) == 1:
                return [*stack[stack.index(m) :], m]
            if state.get(m) is None:
                found = visit(m)
                if found:
                    return found
        stack.pop()
        state[n] = 2
        return []

    for n in graph:
        if state.get(n) is None:
            found = visit(n)
            if found:
                return found
    return []


def _exprs(policy: dict[str, Any]) -> list[Any]:
    out: list[Any] = [policy.get("scope")]
    for r in policy.get("requirements") or []:
        out.append(r.get("when"))
        out.extend(a.get("when") for a in (r.get("action") or {}).get("alternatives") or [])
    return [e for e in out if e]


def _behaviour(
    ws: Workspace, policy: dict[str, Any], by_id: dict[str, dict[str, Any]], name: dict[str, str]
) -> list[dict[str, Any]]:
    """What only running every combination shows: alternatives eligible together, a requirement always replaced,
    the same survey asked for twice under CONFLICT."""
    out: list[dict[str, Any]] = []
    pol = {"kind": "policy", "code": policy.get("code")}
    try:
        space = enumerate_facts(ws, _exprs(policy), unknown=False)
        if not space["checked"]:
            return [
                _d(
                    "INFO",
                    "NOT_CHECKED",
                    f"Interactions between requirements were not checked: {space['reason']}",
                    **pol,
                )
            ]
        plans = [(f, ev_.evaluate(ws, policy, f, [])) for f in space["combinations"]]
    except ApplicabilityError as exc:
        return [_d("BLOCKER", exc.code, exc.message, **pol)]
    told: set[tuple[str, str]] = set()
    active: set[str] = set()
    applies: set[str] = set()
    for facts, plan in plans:
        for r in plan["requirements"]:
            if r["state"] == "APPLIES":
                applies.add(r["id"])
            if r["outcome"] == "ACTIVE":
                active.add(r["id"])
            if r["outcome"] in ("AMBIGUOUS", "NO_ALTERNATIVE") and (r["id"], r["outcome"]) not in told:
                told.add((r["id"], r["outcome"]))
                what = (
                    "more than one alternative is eligible"
                    if r["outcome"] == "AMBIGUOUS"
                    else "no alternative is eligible"
                )
                text = f"‘{name[r['id']]}’: {what} when {facts_text(ws, facts)}"
                out.append(
                    _d(
                        "WARNING",
                        f"CAN_BE_{r['outcome']}",
                        text,
                        kind="requirement",
                        id=r["id"],
                        part="action",
                        example=facts,
                    )
                )
        for d in plan["diagnostics"]:
            key = ("same", f"{d.get('survey')}:{','.join(d.get('requirements') or [])}")
            if d["code"] == "DUPLICATE_SURVEY" and key not in told:
                told.add(key)
                out.append(
                    _d(
                        "BLOCKER",
                        "DUPLICATE_SURVEY",
                        f"{d['message']} For example when {facts_text(ws, facts)}",
                        **pol,
                        survey=d["survey"],
                        requirements=d.get("requirements"),
                        example=facts,
                    )
                )
    if space["exhaustive"]:
        for rid in by_id:
            if rid in applies and rid not in active:
                out.append(
                    _d(
                        "WARNING",
                        "ALWAYS_REPLACED",
                        f"‘{name[rid]}’ is replaced whenever it applies: it never contributes",
                        kind="requirement",
                        id=rid,
                    )
                )
    return out


# -------------------------------------------------------------------------------------------------------- generate
def generate(ws: Workspace, policy: dict[str, Any], limit: int = MAX_SCENARIOS) -> dict[str, Any]:
    """One synthetic application for every distinct result the policy can give, with what was and was not covered."""
    limit = max(1, min(int(limit), MAX_SCENARIOS))
    space = enumerate_facts(ws, _exprs(policy), unknown=True)
    variables = [{"code": c, "name": (ws.variables.get(c) or {}).get("name") or c} for c in space["variables"]]
    if not space["checked"]:
        return {"scenarios": [], "coverage": {"checked": False, "variables": variables, "reason": space["reason"],
                "not_covered": ["Nothing was generated. Narrow the policy or add scenarios by hand."]}}  # fmt: skip
    # the most completely known applications first, so each result is shown by its plainest example
    combos = sorted(space["combinations"], key=lambda f: sum(1 for v in f.values() if v is None))
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for facts in combos:
        plan = ev_.evaluate(ws, policy, facts, [])
        sig = ev_.signature(plan)
        if sig not in seen:
            seen[sig] = {"facts": facts, "plan": plan}
    picked = list(seen.values())[:limit]
    scenarios = []
    for i, item in enumerate(picked):
        facts, plan = item["facts"], item["plan"]
        got = ", ".join(ev_.name(e) for e in plan["selected"]) or (
            "not decided" if plan["status"] != "RESOLVED" else "no survey"
        )
        scenarios.append({
            "id": f"gen-{i + 1}", "name": f"{facts_text(ws, facts)}", "description": f"Generated. Expected today: {got}.",  # noqa: E501
            "profiles": list(policy.get("profiles") or []), "facts": facts, "generated": True, "kind": "COMBINATION",
            "status": plan["status"],
        })  # fmt: skip
    # negative cases: a value no variable allows, and an application that says nothing
    extra = []
    for c in space["variables"]:
        var = ws.variables[c]
        if var.get("type") == "ENUM":
            extra.append({"id": "gen-invalid", "name": f"Invalid input: {var.get('name') or c} has a value that is not allowed",  # noqa: E501
                          "description": "Generated negative case: the value is reported as invalid and treated as not known.",  # noqa: E501
                          "profiles": list(policy.get("profiles") or []), "facts": {**picked[0]["facts"], c: "NOT-A-VALUE"},  # noqa: E501
                          "generated": True, "kind": "INVALID_INPUT"})  # fmt: skip
            break
    if space["variables"]:
        extra.append({"id": "gen-empty", "name": "Nothing provided", "description": "Generated negative case: no fact is given at all.",  # noqa: E501
                      "profiles": list(policy.get("profiles") or []), "facts": {}, "generated": True, "kind": "MISSING_INPUT"})  # fmt: skip  # noqa: E501
    notes = []
    if not space["exhaustive"]:
        notes.append("Variables with many selectable values were sampled, not exhausted.")
    if len(seen) > limit:
        notes.append(f"{len(seen) - limit} further distinct results exist beyond the {limit} shown.")
    notes.append("Only variables this policy reads were varied; the others cannot change its result.")
    notes.append(
        "Each distinct result is shown once, by one example. Other applications giving the same result are not listed."
    )
    return {
        "scenarios": [*scenarios, *extra],
        "coverage": {
            "checked": True, "exhaustive": space["exhaustive"], "variables": variables, "combinations_examined": space["size"],  # noqa: E501
            "distinct_results": len(seen), "shown": len(picked), "not_covered": notes,
            "requirements": _coverage(policy, [p["plan"] for p in seen.values()]),
        },
    }  # fmt: skip


def _coverage(policy: dict[str, Any], plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per requirement: which outcomes some generated application reaches."""
    rows = []
    for r in policy.get("requirements") or []:
        rid = str(r.get("id"))
        outcomes = sorted({q["outcome"] for p in plans for q in p["requirements"] if q["id"] == rid})
        rows.append(
            {"id": rid, "name": r.get("name") or rid, "outcomes": outcomes, "never_active": "ACTIVE" not in outcomes}
        )
    return rows


__all__ = ["FALSE", "analyse", "analyse_policy", "check_expr", "enumerate_facts", "generate"]
