"""The deterministic, three-valued condition engine (SS-03A §5; contract §5).

``evaluate`` is a pure function of (condition, binding, facts, answers). It returns TRUE, FALSE or UNKNOWN with an
explanation tree. A missing fact or an unanswered question is UNKNOWN — never FALSE. The engine never resolves UNKNOWN:
the binding's stated policy says what the CALLER does with it.

The AST is the whole language: there is no expression syntax, no code and no free text.

Schema version 1 reads yes/no and choice answers only (owner decision TS-10). That is a restriction of version 1, not of
the model: an input declares its answer type, and an unsupported type is an explicit error, never ignored.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

Tri = Literal["TRUE", "FALSE", "UNKNOWN"]

LOGICAL = ("AND", "OR", "NOT")
ORDERING = ("GT", "GTE", "LT", "LTE")
EQUALITY = ("EQ", "NEQ")
SET_OPS = ("INCLUDES_ANY", "INCLUDES_ALL", "INCLUDES_NONE")
OPERATORS = (*LOGICAL, *ORDERING, *EQUALITY, *SET_OPS)

#: The answer types a version-1 condition may read. Extending this tuple is how a later version lifts TS-10.
READABLE_ANSWER_TYPES_V1 = ("YES_NO", "SINGLE_SELECT", "MULTI_SELECT")
NUMERIC_FIELD_TYPES = ("MONEY", "INTEGER")


class ConditionError(ValueError):
    """The condition or its binding is malformed. Carries a stable code; it is never a three-valued result."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Explanation:
    """Why a (sub-)condition evaluated as it did. ``reads`` lists every operand value that was looked up."""

    op: str
    result: Tri
    children: tuple[Explanation, ...] = ()
    reads: tuple[tuple[str, str, Any], ...] = field(default_factory=tuple)  # (operand kind, name, value or None)


def _and(values: list[Tri]) -> Tri:
    return "FALSE" if "FALSE" in values else "UNKNOWN" if "UNKNOWN" in values else "TRUE"


def _or(values: list[Tri]) -> Tri:
    return "TRUE" if "TRUE" in values else "UNKNOWN" if "UNKNOWN" in values else "FALSE"


def _decimal(v: Any) -> Decimal:
    if isinstance(v, bool) or not isinstance(v, int | float | Decimal | str):
        raise ConditionError("CONDITION_OPERAND_NOT_NUMERIC", repr(v))
    try:
        return Decimal(str(v))
    except InvalidOperation as e:
        raise ConditionError("CONDITION_OPERAND_NOT_NUMERIC", repr(v)) from e


def _is_number(v: Any) -> bool:
    return isinstance(v, int | float | Decimal) and not isinstance(v, bool)


def _operand(
    o: Mapping[str, Any], params: Mapping[str, Any], facts: Mapping[str, Any], answers: Mapping[str, Any]
) -> tuple[bool, Any, tuple[str, str, Any]]:
    """Returns (known, value, read). An absent, null or empty-string value is NOT known."""
    if "literal" in o:
        return True, o["literal"], ("literal", "", o["literal"])
    if "field" in o:
        kind, name, v = "field", str(o["field"]), facts.get(o["field"])
    elif "param" in o:
        kind, name, v = "param", str(o["param"]), params.get(o["param"])
    elif "input" in o:
        kind, name, v = "input", str(o["input"]), answers.get(o["input"])
    else:
        raise ConditionError("CONDITION_OPERAND_INVALID", repr(dict(o)))
    known = not (v is None or v == "")  # an empty LIST is known: a multiple-choice answer with nothing selected
    return known, v if known else None, (kind, name, v if known else None)


def evaluate(
    ast: Mapping[str, Any],
    params: Mapping[str, Any] | None = None,
    facts: Mapping[str, Any] | None = None,
    answers: Mapping[str, Any] | None = None,
) -> Explanation:
    """Evaluates one AST. ``answers`` maps the condition's INPUT NAMES to the answer value each is bound to: an option
    code, a list of option codes, or absent/None when the question was not answered on the path taken."""
    p, f, a = params or {}, facts or {}, answers or {}
    op = ast.get("op")
    if op in ("AND", "OR"):
        children = tuple(evaluate(x, p, f, a) for x in ast.get("args", ()))
        if not children:
            raise ConditionError("CONDITION_EMPTY_GROUP", str(op))
        results = [c.result for c in children]
        return Explanation(str(op), _and(results) if op == "AND" else _or(results), children)
    if op == "NOT":
        child = evaluate(ast["arg"], p, f, a)
        flipped: Tri = "FALSE" if child.result == "TRUE" else "TRUE" if child.result == "FALSE" else "UNKNOWN"
        return Explanation("NOT", flipped, (child,))
    if op not in OPERATORS:
        raise ConditionError("CONDITION_OPERATOR_UNKNOWN", str(op))
    lk, lv, lr = _operand(ast["left"], p, f, a)
    rk, rv, rr = _operand(ast["right"], p, f, a)
    reads = (lr, rr)
    if not lk or not rk:
        return Explanation(str(op), "UNKNOWN", (), reads)
    if op in ORDERING:
        x, y = _decimal(lv), _decimal(rv)
        hit = {"GT": x > y, "GTE": x >= y, "LT": x < y, "LTE": x <= y}[str(op)]
    elif op in EQUALITY:
        same = _decimal(lv) == _decimal(rv) if _is_number(lv) and _is_number(rv) else lv == rv
        hit = same if op == "EQ" else not same
    else:
        if not isinstance(lv, list) or not isinstance(rv, list):
            raise ConditionError("CONDITION_OPERAND_NOT_A_SELECTION", str(op))
        chosen, wanted = set(lv), set(rv)
        hit = {
            "INCLUDES_ANY": bool(chosen & wanted),
            "INCLUDES_ALL": wanted <= chosen,
            "INCLUDES_NONE": not (chosen & wanted),
        }[str(op)]
    return Explanation(str(op), "TRUE" if hit else "FALSE", (), reads)


def fields_of(ast: Mapping[str, Any]) -> list[str]:
    """Catalog fields a condition reads, in order of first appearance."""
    return _collect(ast, "field")


def inputs_of(ast: Mapping[str, Any]) -> list[str]:
    """Named earlier answers a condition reads, in order of first appearance."""
    return _collect(ast, "input")


def params_of(ast: Mapping[str, Any]) -> list[str]:
    return _collect(ast, "param")


def _collect(ast: Mapping[str, Any], kind: str) -> list[str]:
    out: list[str] = []

    def walk(node: Mapping[str, Any]) -> None:
        if node.get("op") in ("AND", "OR"):
            for x in node.get("args", ()):
                walk(x)
        elif node.get("op") == "NOT":
            walk(node["arg"])
        else:
            for side in ("left", "right"):
                o = node.get(side) or {}
                if kind in o and o[kind] not in out:
                    out.append(str(o[kind]))

    walk(ast)
    return out


def option_codes_compared(ast: Mapping[str, Any]) -> dict[str, list[str]]:
    """For each input, the option codes the condition compares it with (literals only)."""
    out: dict[str, list[str]] = {}

    def walk(node: Mapping[str, Any]) -> None:
        if node.get("op") in ("AND", "OR"):
            for x in node.get("args", ()):
                walk(x)
        elif node.get("op") == "NOT":
            walk(node["arg"])
        else:
            left, right = node.get("left") or {}, node.get("right") or {}
            for a, b in ((left, right), (right, left)):
                if "input" in a and "literal" in b:
                    lit = b["literal"]
                    codes = lit if isinstance(lit, list) else [lit]
                    out.setdefault(str(a["input"]), []).extend(str(c) for c in codes if isinstance(c, str))

    walk(ast)
    return out


def check_condition(condition: Mapping[str, Any], fields: Mapping[str, Mapping[str, Any]]) -> list[tuple[str, str]]:
    """Authoring-time problems in a condition version, as (stable code, detail). Typed dependencies are checked here so
    that evaluation can never meet an operand of the wrong kind."""
    out: list[tuple[str, str]] = []
    params = condition.get("params") or {}
    inputs = condition.get("inputs") or {}

    def kind_of(o: Mapping[str, Any]) -> str | None:
        """NUMBER, CODE, SELECTION, BOOLEAN, TEXT or None when it cannot be told."""
        if "field" in o:
            fdef = fields.get(o["field"])
            if fdef is None:
                out.append(("CONDITION_FIELD_UNKNOWN", str(o["field"])))
                return None
            t = fdef.get("type")
            return (
                "NUMBER"
                if t in NUMERIC_FIELD_TYPES
                else "BOOLEAN"
                if t == "BOOLEAN"
                else "TEXT"
                if t == "TEXT"
                else "CODE"
            )
        if "param" in o:
            pdef = params.get(o["param"])
            if pdef is None:
                out.append(("CONDITION_PARAM_UNDECLARED", str(o["param"])))
                return None
            t = pdef.get("type")
            return "NUMBER" if t in NUMERIC_FIELD_TYPES else "BOOLEAN" if t == "BOOLEAN" else "CODE"
        if "input" in o:
            idef = inputs.get(o["input"])
            if idef is None:
                out.append(("CONDITION_INPUT_UNDECLARED", str(o["input"])))
                return None
            t = idef.get("answer_type")
            if t not in READABLE_ANSWER_TYPES_V1:
                out.append(("CONDITION_INPUT_TYPE_UNSUPPORTED", f"{o['input']}: {t}"))
                return None
            return "SELECTION" if t == "MULTI_SELECT" else "CODE"
        if "literal" in o:
            lit = o["literal"]
            if isinstance(lit, bool):
                return "BOOLEAN"
            if isinstance(lit, int | float):
                return "NUMBER"
            return "SELECTION" if isinstance(lit, list) else "CODE"
        out.append(("CONDITION_OPERAND_INVALID", repr(dict(o))))
        return None

    def walk(node: Mapping[str, Any]) -> None:
        op = node.get("op")
        if op in ("AND", "OR"):
            args = node.get("args") or ()
            if not args:
                out.append(("CONDITION_EMPTY_GROUP", str(op)))
            for x in args:
                walk(x)
            return
        if op == "NOT":
            walk(node.get("arg") or {})
            return
        if op not in OPERATORS:
            out.append(("CONDITION_OPERATOR_UNKNOWN", str(op)))
            return
        lk, rk = kind_of(node.get("left") or {}), kind_of(node.get("right") or {})
        if lk is None or rk is None:
            return
        if op in ORDERING and (lk != "NUMBER" or rk != "NUMBER"):
            out.append(("CONDITION_OPERATOR_TYPE_MISMATCH", f"{op} needs two numbers"))
        elif op in SET_OPS and (lk != "SELECTION" or rk != "SELECTION"):
            out.append(
                ("CONDITION_OPERATOR_TYPE_MISMATCH", f"{op} needs a multiple-choice answer and a list of option codes")
            )
        elif op in EQUALITY and {lk, rk} not in ({"NUMBER"}, {"CODE"}, {"BOOLEAN"}, {"CODE", "TEXT"}, {"TEXT"}):
            out.append(("CONDITION_OPERATOR_TYPE_MISMATCH", f"{op} compares {lk} with {rk}"))

    walk(condition.get("ast") or {})
    return out
