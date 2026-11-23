"""Three-valued evaluation of the restricted, typed applicability expression tree.

An expression is one of five nodes — ``all``, ``any``, ``not``, ``test``, ``ref`` — and evaluates to exactly one of
TRUE, FALSE, UNKNOWN. Unknown never becomes false. Every branch is evaluated and recorded (no short-circuit in the
trace), and each child is marked ``decisive`` when it is a reason for its parent's value, so an explanation can point
at the branch responsible. No user-supplied code is executed: operators are a closed set, checked per variable type.
"""

from __future__ import annotations

from datetime import date
from typing import Any

CONTRACT = "call360.survey-applicability/0"
TRUE, FALSE, UNKNOWN = "TRUE", "FALSE", "UNKNOWN"

NUMERIC = ("NUMBER", "DECIMAL", "MONEY")
TYPES = ("BOOLEAN", "ENUM", "MULTI_ENUM", *NUMERIC, "DATE", "STRING")
PRESENCE = ("is_known", "is_unknown")
OPERATORS: dict[str, tuple[str, ...]] = {
    "BOOLEAN": ("is_true", "is_false"),
    "ENUM": ("equals", "not_equals", "in", "not_in"),
    "STRING": ("equals", "not_equals", "in", "not_in"),
    "MULTI_ENUM": ("includes_any", "includes_all", "includes_none"),
    "NUMBER": ("equals", "not_equals", "gt", "gte", "lt", "lte", "between"),
    "DECIMAL": ("equals", "not_equals", "gt", "gte", "lt", "lte", "between"),
    "MONEY": ("equals", "not_equals", "gt", "gte", "lt", "lte", "between"),
    "DATE": ("on", "before", "after", "between"),
}
#: how an operator reads in a sentence
WORDS = {
    "is_true": "is yes", "is_false": "is no", "equals": "is", "not_equals": "is not", "in": "is one of",
    "not_in": "is none of", "includes_any": "includes any of", "includes_all": "includes all of",
    "includes_none": "includes none of", "gt": "is more than", "gte": "is at least", "lt": "is less than",
    "lte": "is at most", "between": "is between", "on": "is on", "before": "is before", "after": "is after",
    "is_known": "is known", "is_unknown": "is not known",
}  # fmt: skip
MAX_NODES = 400
MAX_DEPTH = 40


class ApplicabilityError(Exception):
    """A document that cannot be evaluated at all (never a business outcome)."""

    def __init__(self, code: str, message: str, at: str = "") -> None:
        super().__init__(message)
        self.code, self.message, self.at = code, message, at


def and3(values: list[str]) -> str:
    if FALSE in values:
        return FALSE
    return UNKNOWN if UNKNOWN in values else TRUE


def or3(values: list[str]) -> str:
    if TRUE in values:
        return TRUE
    return UNKNOWN if UNKNOWN in values else FALSE


def not3(value: str) -> str:
    return {TRUE: FALSE, FALSE: TRUE}.get(value, UNKNOWN)


def _tv(flag: bool) -> str:
    return TRUE if flag else FALSE


# ------------------------------------------------------------------------------------------------------- workspace
class Workspace:
    """The definitions an evaluation reads: variables, saved conditions and profiles, by code."""

    def __init__(self, raw: dict[str, Any] | None) -> None:
        raw = raw or {}
        self.variables: dict[str, dict[str, Any]] = {str(v.get("code")): v for v in raw.get("variables") or []}
        self.conditions: dict[str, dict[str, Any]] = {str(c.get("code")): c for c in raw.get("conditions") or []}
        self.profiles: dict[str, dict[str, Any]] = {str(p.get("code")): p for p in raw.get("profiles") or []}

    def condition_expr(self, code: str, version: Any) -> dict[str, Any]:
        """The expression a saved condition had at one exact version: a reference is to a version, never to 'latest'."""
        c = self.conditions.get(code)
        if c is None:
            raise ApplicabilityError("UNKNOWN_CONDITION", f"The saved condition '{code}' does not exist", code)
        if version in (None, c.get("version")):
            return dict(c.get("expr") or {})
        for h in c.get("history") or []:
            if h.get("version") == version:
                return dict(h.get("expr") or {})
        raise ApplicabilityError("UNKNOWN_CONDITION_VERSION", f"'{code}' has no version {version}", code)

    def profile_variables(self, codes: list[str]) -> tuple[set[str], dict[str, list[dict[str, Any]]]]:
        """Every variable of the composed profiles, and the constraints each profile puts on a variable."""
        seen: set[str] = set()
        variables: set[str] = set()
        constraints: dict[str, list[dict[str, Any]]] = {}

        def walk(code: str, trail: tuple[str, ...]) -> None:
            if code in trail:
                raise ApplicabilityError("PROFILE_CYCLE", f"Profile '{code}' includes itself", code)
            if code in seen:
                return
            seen.add(code)
            p = self.profiles.get(code)
            if p is None:
                raise ApplicabilityError("UNKNOWN_PROFILE", f"The profile '{code}' does not exist", code)
            for parent in p.get("extends") or []:
                walk(str(parent), (*trail, code))
            for s in p.get("sections") or []:
                variables.update(str(v) for v in s.get("variables") or [])
            for var, rule in (p.get("constraints") or {}).items():
                constraints.setdefault(str(var), []).append({"profile": code, **dict(rule or {})})

        for c in codes:
            walk(str(c), ())
        return variables, constraints


# ----------------------------------------------------------------------------------------------------------- facts
def label_of(var: dict[str, Any], value: Any) -> str:
    """A value as a person reads it."""
    if value is None:
        return "not known"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(label_of(var, v) for v in value) or "none"
    for o in var.get("values") or []:
        if o.get("value") == value:
            return str(o.get("label") or value)
    if var.get("type") == "MONEY" and isinstance(value, (int, float)):
        return f"{var.get('currency', '')} {value:,}".strip()
    return str(value)


def _check_value(var: dict[str, Any], value: Any) -> str | None:
    """Why a value is not valid for a variable, or None."""
    kind = var.get("type")
    allowed = [o.get("value") for o in var.get("values") or []]
    if kind == "BOOLEAN":
        return None if isinstance(value, bool) else "expected yes or no"
    if kind == "ENUM":
        return None if isinstance(value, str) and value in allowed else f"'{value}' is not one of the allowed values"
    if kind == "MULTI_ENUM":
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            return "expected a list of values"
        bad = [v for v in value if v not in allowed]
        return f"'{bad[0]}' is not one of the allowed values" if bad else None
    if kind in NUMERIC:
        if isinstance(value, dict) and kind == "MONEY":
            if value.get("currency") != var.get("currency"):
                return f"the amount is in {value.get('currency')}, not {var.get('currency')}"
            value = value.get("amount")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "expected a number"
        if kind == "NUMBER" and isinstance(value, float) and not value.is_integer():
            return "expected a whole number"
        lo, hi = var.get("min"), var.get("max")
        if isinstance(lo, (int, float)) and value < lo:
            return f"{value} is below the minimum {lo}"
        if isinstance(hi, (int, float)) and value > hi:
            return f"{value} is above the maximum {hi}"
        return None
    if kind == "DATE":
        try:
            date.fromisoformat(str(value))
        except ValueError:
            return f"'{value}' is not a date"
        return None
    if kind == "STRING":
        return None if isinstance(value, str) else "expected text"
    return f"unknown variable type '{kind}'"


def _plain(var: dict[str, Any], value: Any) -> Any:
    return value.get("amount") if isinstance(value, dict) and var.get("type") == "MONEY" else value


class Evaluation:
    """One evaluation: a workspace, one set of facts and the profiles in play."""

    def __init__(self, ws: Workspace, facts: dict[str, Any] | None, profiles: list[str] | None = None) -> None:
        self.ws = ws
        self.facts = dict(facts or {})
        self.supported: set[str] | None = None
        self.constraints: dict[str, list[dict[str, Any]]] = {}
        if profiles:
            self.supported, self.constraints = ws.profile_variables(profiles)
        self._states: dict[str, dict[str, Any]] = {}
        self._deriving: list[str] = []
        self._refs: list[str] = []
        self.nodes = 0

    def fact(self, code: str) -> dict[str, Any]:
        """The state of one variable for this application: KNOWN, UNKNOWN, NOT_PROVIDED, INVALID or UNSUPPORTED."""
        if code in self._states:
            return self._states[code]
        var = self.ws.variables.get(code)
        if var is None:
            raise ApplicabilityError("UNKNOWN_VARIABLE", f"The variable '{code}' does not exist", code)
        out: dict[str, Any]
        derived = var.get("derived")
        if derived:
            if code in self._deriving:
                raise ApplicabilityError("DERIVED_CYCLE", f"'{code}' is derived from itself", code)
            self._deriving.append(code)
            node = self.expr(dict(derived.get("expr") or {}), "")
            self._deriving.pop()
            if node["result"] == UNKNOWN:
                out = {"state": "UNKNOWN", "value": None, "reason": "it is derived from a value that is not known"}
            else:
                out = {"state": "KNOWN", "value": node["result"] == TRUE, "reason": "derived"}
            out["derived"] = True
        elif self.supported is not None and code not in self.supported:
            out = {"state": "UNSUPPORTED", "value": None, "reason": "it is not part of this application's profiles"}
        elif code not in self.facts:
            out = {"state": "NOT_PROVIDED", "value": None, "reason": "no value was given"}
        elif self.facts[code] is None:
            out = {"state": "UNKNOWN", "value": None, "reason": "the application says it is not known"}
        else:
            raw = self.facts[code]
            why = _check_value(var, raw)
            value = _plain(var, raw)
            if why is None:
                for rule in self.constraints.get(code, []):
                    allowed = rule.get("allowed")
                    values = value if isinstance(value, list) else [value]
                    if isinstance(allowed, list) and any(v not in allowed for v in values):
                        why = f"profile '{rule['profile']}' does not allow {label_of(var, value)}"
                        break
            if why is None:
                out = {"state": "KNOWN", "value": value, "reason": ""}
            else:
                out = {"state": "INVALID", "value": None, "given": raw, "reason": why}
        out["variable"] = code
        out["name"] = var.get("name") or code
        out["label"] = (
            label_of(var, out["value"]) if out["state"] == "KNOWN" else out["state"].replace("_", " ").lower()
        )
        self._states[code] = out
        return out

    # ------------------------------------------------------------------------------------------------ expressions
    def expr(self, node: dict[str, Any], path: str, depth: int = 0) -> dict[str, Any]:
        self.nodes += 1
        if self.nodes > MAX_NODES * 20 or depth > MAX_DEPTH:
            raise ApplicabilityError("TOO_LARGE", "The expression is too large or too deeply nested", path)
        op = node.get("op")
        if op in ("all", "any"):
            kids = [
                self.expr(dict(a), f"{path}.{i}" if path else str(i), depth + 1)
                for i, a in enumerate(node.get("args") or [])
            ]
            values = [k["result"] for k in kids]
            result = and3(values) if op == "all" else or3(values)
            # which children are the reason for this result
            strong = FALSE if op == "all" else TRUE
            for k in kids:
                k["decisive"] = k["result"] == result if result in (strong, UNKNOWN) else True
            joiner = " and " if op == "all" else " or "
            text = joiner.join(f"({k['text']})" if k["op"] in ("all", "any") else k["text"] for k in kids)
            return {
                "op": op,
                "path": path,
                "result": result,
                "children": kids,
                "text": text or ("always" if op == "all" else "never"),
            }
        if op == "not":
            kid = self.expr(dict(node.get("arg") or {}), f"{path}.0" if path else "0", depth + 1)
            kid["decisive"] = True
            inner = f"({kid['text']})" if kid["op"] in ("all", "any") else kid["text"]
            return {"op": "not", "path": path, "result": not3(kid["result"]), "children": [kid], "text": f"not {inner}"}
        if op == "ref":
            code = str(node.get("condition"))
            if code in self._refs:
                raise ApplicabilityError("CONDITION_CYCLE", f"The saved condition '{code}' refers to itself", path)
            self._refs.append(code)
            kid = self.expr(self.ws.condition_expr(code, node.get("version")), f"{path}.0" if path else "0", depth + 1)
            self._refs.pop()
            kid["decisive"] = True
            c = self.ws.conditions[code]
            return {
                "op": "ref", "path": path, "result": kid["result"], "children": [kid], "condition": code,
                "version": node.get("version") or c.get("version"), "text": f"“{c.get('name') or code}”",
            }  # fmt: skip
        if op == "test":
            return self._test(node, path)
        raise ApplicabilityError("UNKNOWN_NODE", f"'{op}' is not a kind of condition", path)

    def _test(self, node: dict[str, Any], path: str) -> dict[str, Any]:
        code, operator = str(node.get("variable")), str(node.get("operator"))
        var = self.ws.variables.get(code)
        if var is None:
            raise ApplicabilityError("UNKNOWN_VARIABLE", f"The variable '{code}' does not exist", path)
        kind = str(var.get("type"))
        if operator not in PRESENCE and operator not in OPERATORS.get(kind, ()):
            raise ApplicabilityError(
                "OPERATOR_NOT_ALLOWED", f"'{operator}' cannot be used with {var.get('name')}", path
            )
        fact = self.fact(code)
        known = fact["state"] == "KNOWN"
        operand = _operand_text(var, node, operator)
        text = f"{var.get('name') or code} {WORDS[operator]}{(' ' + operand) if operand else ''}"
        out = {"op": "test", "path": path, "variable": code, "operator": operator, "text": text, "fact": fact}
        if operator == "is_known":
            return {**out, "result": _tv(known), "reason": "" if known else fact["reason"]}
        if operator == "is_unknown":
            return {**out, "result": _tv(not known), "reason": ""}
        if not known:
            return {**out, "result": UNKNOWN, "reason": f"{var.get('name') or code}: {fact['reason']}"}
        return {**out, "result": _tv(_compare(kind, operator, fact["value"], node, path)), "reason": ""}


def _operand_text(var: dict[str, Any], node: dict[str, Any], operator: str) -> str:
    if operator in ("is_true", "is_false", *PRESENCE):
        return ""
    if operator == "between":
        return f"{label_of(var, node.get('min'))} and {label_of(var, node.get('max'))}"
    if operator in ("in", "not_in", "includes_any", "includes_all", "includes_none"):
        return ", ".join(label_of(var, v) for v in node.get("values") or []) or "(nothing chosen)"
    return label_of(var, node.get("value"))


def _ordered(kind: str, value: Any, path: str) -> Any:
    if kind == "DATE":
        try:
            return date.fromisoformat(str(value)).toordinal()
        except ValueError as exc:
            raise ApplicabilityError("INVALID_OPERAND", f"'{value}' is not a date", path) from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApplicabilityError("INVALID_OPERAND", f"'{value}' is not a number", path)
    return value


def _compare(kind: str, operator: str, value: Any, node: dict[str, Any], path: str) -> bool:
    if operator == "is_true":
        return value is True
    if operator == "is_false":
        return value is False
    if kind in ("ENUM", "STRING"):
        if operator in ("equals", "not_equals"):
            return bool(value == node.get("value")) == (operator == "equals")
        return (value in (node.get("values") or [])) == (operator == "in")
    if kind == "MULTI_ENUM":
        have, want = set(value), set(node.get("values") or [])
        if operator == "includes_any":
            return bool(have & want)
        if operator == "includes_all":
            return bool(want) and want <= have
        return not bool(have & want)
    v = _ordered(kind, value, path)
    if operator == "between":
        return bool(_ordered(kind, node.get("min"), path) <= v <= _ordered(kind, node.get("max"), path))
    w = _ordered(kind, node.get("value"), path)
    return bool(
        {"equals": v == w, "on": v == w, "not_equals": v != w, "gt": v > w, "after": v > w, "gte": v >= w,
         "lt": v < w, "before": v < w, "lte": v <= w}[operator]
    )  # fmt: skip


def needs(node: dict[str, Any]) -> list[dict[str, Any]]:
    """The facts whose state keeps a traced expression UNKNOWN: the decisive tests that are themselves unknown."""
    out: list[dict[str, Any]] = []

    def walk(n: dict[str, Any]) -> None:
        if n["result"] != UNKNOWN:
            return
        if n["op"] == "test":
            f = n["fact"]
            if not any(o["variable"] == f["variable"] for o in out):
                out.append({"variable": f["variable"], "name": f["name"], "state": f["state"], "reason": f["reason"]})
            return
        for k in n.get("children") or []:
            if k.get("decisive", True):
                walk(k)

    walk(node)
    return out


def variables_of(ws: Workspace, node: dict[str, Any] | None, seen: set[str] | None = None) -> list[str]:
    """Every variable an expression reads, through saved conditions and derived variables, in first-use order."""
    out: list[str] = []
    refs: set[str] = seen if seen is not None else set()

    def add(code: str) -> None:
        var = ws.variables.get(code)
        if var and var.get("derived"):
            key = f"v:{code}"
            if key not in refs:
                refs.add(key)
                walk(dict(var["derived"].get("expr") or {}))
        elif code not in out:
            out.append(code)

    def walk(n: dict[str, Any]) -> None:
        op = n.get("op")
        if op in ("all", "any"):
            for a in n.get("args") or []:
                walk(dict(a))
        elif op == "not":
            walk(dict(n.get("arg") or {}))
        elif op == "test":
            add(str(n.get("variable")))
        elif op == "ref":
            key = f"c:{n.get('condition')}:{n.get('version')}"
            if key not in refs:
                refs.add(key)
                c = ws.conditions.get(str(n.get("condition")))
                if c is not None:
                    try:
                        walk(ws.condition_expr(str(n.get("condition")), n.get("version")))
                    except ApplicabilityError:
                        pass

    if node:
        walk(node)
    return out
