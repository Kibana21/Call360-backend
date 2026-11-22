"""SS-03B — controlled variables in approved wording (contract 04 §8). Pure.

A variable is written ``{{field_code}}`` and names ONE field of the governed catalog. Rendering is deterministic: the
same wording and the same facts always give the same sentence. Nothing here writes, completes or rephrases wording: a
variable without a usable value makes the sentence UNDELIVERABLE (``text`` is None) and says why. A value is never
guessed, defaulted, rounded or truncated to fit.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from app.domain.survey.validator import VARIABLE, variables_of

Doc = Mapping[str, Any]
#: PRESENT is the only state in which a value is spoken. NOT_PERMITTED: the catalog says the field may not be spoken.
VALUE_STATES = ("PRESENT", "MISSING", "INVALID", "UNKNOWN_VARIABLE", "MALFORMED", "NOT_PERMITTED")
_LEFTOVER = re.compile(r"\{\{|\}\}")


def is_missing(v: Any) -> bool:
    return v is None or v == ""


def _decimal(v: Any) -> Decimal | None:
    if isinstance(v, bool) or not isinstance(v, int | float | Decimal):
        return None
    try:
        d = v if isinstance(v, Decimal) else Decimal(str(v))
    except InvalidOperation:
        return None
    return d if d.is_finite() else None


def _group(whole: int) -> str:
    return f"{whole:,}"


def format_value(field: Doc, v: Any) -> str | None:
    """One stated format per field type; None when the value cannot be used. No locale lookup: the output never depends
    on the machine. A whole-number field must hold a whole number, an amount at most two decimals — never rounded."""
    kind = field.get("type")
    if kind in ("MONEY", "INTEGER"):
        d = _decimal(v)
        if d is None:
            return None
        if kind == "INTEGER" and d != d.to_integral_value():
            return None
        if kind == "MONEY" and (d * 100) != (d * 100).to_integral_value():
            return None
        whole = int(abs(d))
        cents = int((abs(d) * 100) % 100) if kind == "MONEY" else 0
        body = f"{'-' if d < 0 else ''}{_group(whole)}{f'.{cents:02d}' if cents else ''}"
        return f"{field.get('unit') or ''} {body}".strip() if kind == "MONEY" else body
    if kind == "ENUM":
        values = field.get("values")
        if not isinstance(v, str) or (values and v not in values):
            return None
        return v if len(v) <= 3 else v[0] + v[1:].lower().replace("_", " ")
    if kind == "TEXT":
        return v.strip() if isinstance(v, str) and v.strip() else None
    return None  # BOOLEAN and anything else has no spoken form


def render(text: str, fields: Mapping[str, Doc], facts: Mapping[str, Any]) -> dict[str, Any]:
    """``{text, values, errors}``. ``text`` is the exact sentence, or None when it cannot be built. ``values`` lists
    every variable with the value used and its state — the evidence of what was put into the wording. ``errors`` are
    stable ``{code, variable}`` pairs, never prose for a customer."""
    values: list[dict[str, Any]] = []
    for variable in variables_of(text):
        f = fields.get(variable)
        if not f or f.get("type") == "BOOLEAN":
            values.append({"variable": variable, "value": None, "state": "UNKNOWN_VARIABLE"})
        elif f.get("speakable") is False:
            # default-deny (owner decision D-181): a field the catalog says may not be spoken is never rendered
            values.append({"variable": variable, "value": None, "state": "NOT_PERMITTED"})
        elif is_missing(facts.get(variable)):
            values.append({"variable": variable, "value": None, "state": "MISSING"})
        else:
            out = format_value(f, facts.get(variable))
            values.append({"variable": variable, "value": out, "state": "INVALID" if out is None else "PRESENT"})
    if _LEFTOVER.search(VARIABLE.sub("", text)):  # an unfinished variable is never spoken with its braces
        values.append({"variable": "", "value": None, "state": "MALFORMED"})
    errors = [{"code": v["state"], "variable": v["variable"]} for v in values if v["state"] != "PRESENT"]
    if errors:
        return {"text": None, "values": values, "errors": errors}
    by = {v["variable"]: v["value"] for v in values}
    return {"text": VARIABLE.sub(lambda m: by.get(m.group(1), ""), text), "values": values, "errors": []}
