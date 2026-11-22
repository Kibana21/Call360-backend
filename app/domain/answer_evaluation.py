"""S3-A deterministic answer evaluation engine (COMP-003, COMP-006, SCR-020; provider-independent, no LLM).

Pure: no database, clock, randomness or model. It evaluates the **structured** answers the question controller
recorded against each question revision's approved evaluation rule and an **immutable** fact source (a policy fact
snapshot, or a simulation scenario's synthetic facts). The same inputs always give the same results.

Evaluation methods are the question's ``expected_answer_policy`` (SCRIPT_GOVERNANCE_AND_ASSIGNMENT.md, "Answer is not
only YES/NO"), extended in S3-A with three structured methods:

- ``EXACT_BOOLEAN``              yes/no answer equals the approved expected answer
- ``ACKNOWLEDGEMENT``            the customer acknowledged (yes)
- ``NUMERIC_COMPARE``            number vs an approved value: operator, unit and (only where approved) a tolerance
- ``NUMERIC_MATCH_POLICY_FACT``  number vs a mapped numeric policy fact (operator, unit conversion, approved tolerance)
- ``ENUM_MATCH``                 choice is one of the approved accepted options (exact value comparison)
- ``ENUM_MATCH_POLICY_FACT``     choice equals a mapped enumerated policy fact
- ``COLLECT_ONLY``               captured, never evaluated (``NOT_EVALUATED``)
- ``NARRATIVE_REVIEW``           captured for a person to assess (``HUMAN_ASSESSMENT_REQUIRED``)

Results: ``MATCH``, ``MISMATCH``, ``UNRESOLVED`` (presented but no usable answer — unclear, refused, unknown, not
delivered, re-prompts exhausted), ``NOT_ASKED`` (applicable, never presented), ``MISSING_EXPECTED_FACT``,
``NOT_APPLICABLE``, ``NOT_EVALUATED`` and ``HUMAN_ASSESSMENT_REQUIRED``. Missing information, unclear answers and
refusals never produce ``MATCH``. A ``MISMATCH`` is a discrepancy between the answer and the expected value; it is not
a compliance finding, a regulatory breach, a severity or a case decision (S3-B/S3-C, not built).

No threshold, tolerance or business rule is assumed: comparisons are exact unless the question revision itself carries
an approved tolerance (with its approval reference) that passed maker-checker review. Tolerance bounds are inclusive.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

ENGINE = "call360.answer-evaluation/1 (S3-A deterministic)"
METHODS = (
    "EXACT_BOOLEAN",
    "ACKNOWLEDGEMENT",
    "NUMERIC_COMPARE",
    "NUMERIC_MATCH_POLICY_FACT",
    "ENUM_MATCH",
    "ENUM_MATCH_POLICY_FACT",
    "COLLECT_ONLY",
    "NARRATIVE_REVIEW",
)
#: SET_MATCH (EVAL-2A, owner's technical decision of 2026-11-22): a multiple-choice answer compared, as a SET, with an
#: approved set of the question's own options. Technical answer matching only — no compliance meaning is attached.
#: It is NOT one of ``METHODS``: those are the expected-answer policies Script Studio offers for script questions, and
#: that list is unchanged. ``ALL_METHODS`` is what this engine can evaluate.
SET_MODES: dict[str, str] = {
    "INCLUDES_ALL": "every one of",
    "INCLUDES_ANY": "at least one of",
    "INCLUDES_NONE": "none of",
    "EQUALS": "exactly",
}
ALL_METHODS = (*METHODS, "SET_MATCH")
METHOD_ANSWER_TYPES: dict[str, tuple[str, ...]] = {
    "EXACT_BOOLEAN": ("YES_NO",),
    "ACKNOWLEDGEMENT": ("ACKNOWLEDGEMENT",),
    "NUMERIC_COMPARE": ("NUMERIC",),
    "NUMERIC_MATCH_POLICY_FACT": ("NUMERIC",),
    "ENUM_MATCH": ("ENUM",),
    "ENUM_MATCH_POLICY_FACT": ("ENUM",),
    "COLLECT_ONLY": ("YES_NO", "NUMERIC", "ENUM", "FREE_TEXT", "ACKNOWLEDGEMENT"),
    "NARRATIVE_REVIEW": ("FREE_TEXT",),
    "SET_MATCH": ("MULTI_SELECT",),
}
FACT_METHODS = ("NUMERIC_MATCH_POLICY_FACT", "ENUM_MATCH_POLICY_FACT")
VALUE_METHODS = ("EXACT_BOOLEAN", "NUMERIC_COMPARE", "ENUM_MATCH", "SET_MATCH")  # carry an approved expected value
RESULTS = (
    "MATCH",
    "MISMATCH",
    "UNRESOLVED",
    "NOT_ASKED",
    "MISSING_EXPECTED_FACT",
    "NOT_APPLICABLE",
    "NOT_EVALUATED",
    "HUMAN_ASSESSMENT_REQUIRED",
)
# The seeded operational rule_evaluation vocabulary (S0) these results correspond to; MATCH is never a compliance PASS.
RULE_EVALUATION_EQUIVALENT = {
    "MATCH": "MATCH",
    "MISMATCH": "MISMATCH",
    "UNRESOLVED": "INDETERMINATE",
    "NOT_ASKED": "INDETERMINATE",
    "MISSING_EXPECTED_FACT": "INDETERMINATE",
    "NOT_APPLICABLE": "NOT_EVALUATED",
    "NOT_EVALUATED": "NOT_EVALUATED",
    "HUMAN_ASSESSMENT_REQUIRED": "NOT_EVALUATED",
}
OPERATORS: dict[str, str] = {
    "EQ": "equal to",
    "GTE": "at least",
    "LTE": "at most",
    "GT": "more than",
    "LT": "less than",
}
UNITS: dict[str, str] = {"YEARS": "years", "MONTHS": "months", "SGD": "SGD", "COUNT": "count"}
# Exact, definitional conversions only (no business assumption).
_CONVERT: dict[tuple[str, str], Decimal] = {("YEARS", "MONTHS"): Decimal(12)}  # fact unit -> answer unit
# Approved fact mappings: facts recorded in the immutable policy fact snapshot (S0 seed / intake schema v1).
EVALUATION_FACTS: dict[str, dict[str, Any]] = {
    "premium_term_years": {
        "kind": "NUMERIC",
        "unit": "YEARS",
        "units": ("YEARS", "MONTHS"),
        "label": "Premium payment term in years (policy fact snapshot)",
    },
    "premium_amount": {
        "kind": "NUMERIC",
        "unit_fact": "currency",
        "units": ("SGD",),
        "label": "Premium amount in the policy currency (policy fact snapshot, decimal string)",
    },
    "premium_frequency": {
        "kind": "ENUM",
        "values": ("SINGLE", "MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"),
        "label": "Premium payment frequency (policy fact snapshot)",
    },
}
MAX_TOLERANCE_REF = 120


class RuleInvalid(ValueError):
    """An evaluation rule that cannot be configured (incompatible answer type, operator, unit or fact mapping)."""


# ---- numbers -----------------------------------------------------------------------------------------------------
def dec(v: Any) -> Decimal | None:
    if v is None or isinstance(v, bool):
        return None
    try:
        d = Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        return None
    return d if d.is_finite() else None


def fmt(d: Decimal | None) -> str | None:
    if d is None:
        return None
    s = format(d.normalize(), "f")
    return s.rstrip("0").rstrip(".") if "." in s else s


# ---- rules -------------------------------------------------------------------------------------------------------
def configure(
    method: str,
    answer_type: str,
    options: Sequence[str],
    *,
    expected_boolean: Any = None,
    evaluation: Mapping[str, Any] | None = None,
    fact_key: str | None = None,
) -> tuple[Any, str | None]:
    """Validate an authored rule and return the stored ``(expected_value, policy_fact_key)``. Raises ``RuleInvalid``."""
    ev = dict(evaluation or {})
    if method not in ALL_METHODS:
        raise RuleInvalid("Unknown evaluation method")
    if answer_type not in METHOD_ANSWER_TYPES[method]:
        raise RuleInvalid(_TYPE_MESSAGES.get(method, "The evaluation method does not suit this answer type"))
    if method == "EXACT_BOOLEAN":
        if not isinstance(expected_boolean, bool):
            raise RuleInvalid("Choose the expected answer (yes or no)")
        return {"value": expected_boolean}, None
    if method in ("NUMERIC_COMPARE", "NUMERIC_MATCH_POLICY_FACT"):
        fact = EVALUATION_FACTS.get(fact_key or "") if method == "NUMERIC_MATCH_POLICY_FACT" else None
        if method == "NUMERIC_MATCH_POLICY_FACT" and (fact is None or fact["kind"] != "NUMERIC"):
            raise RuleInvalid(
                "Choose an approved policy fact (numeric: "
                + ", ".join(k for k, f in EVALUATION_FACTS.items() if f["kind"] == "NUMERIC")
                + ")"
            )
        op = ev.get("operator") or "EQ"
        if op not in OPERATORS:
            raise RuleInvalid(f"Unsupported comparison operator {op!r} (use {', '.join(OPERATORS)})")
        unit = ev.get("unit") or (fact.get("unit") if fact else None) or ("SGD" if fact else None)
        if unit not in UNITS:
            raise RuleInvalid(f"Choose the answer's unit ({', '.join(UNITS)})")
        if fact is not None and unit not in fact["units"]:
            raise RuleInvalid(f"{fact_key} can be compared in {' or '.join(fact['units'])}, not {unit}")
        tol = dec(ev.get("tolerance") if ev.get("tolerance") not in (None, "") else "0")
        if tol is None or tol < 0:
            raise RuleInvalid("Tolerance must be a non-negative number")
        ref = str(ev.get("tolerance_reference") or "").strip() or None
        if tol > 0:
            if op != "EQ":
                raise RuleInvalid("A tolerance applies only to an 'equal to' comparison")
            if not ref or len(ref) < 3 or len(ref) > MAX_TOLERANCE_REF:
                raise RuleInvalid(
                    "A tolerance needs the reference of its business approval (3–120 characters); no tolerance is "
                    "assumed"
                )
        stored: dict[str, Any] = {
            "operator": op,
            "unit": unit,
            "tolerance": fmt(tol),
            "tolerance_reference": ref if tol > 0 else None,
        }
        if method == "NUMERIC_COMPARE":
            value = dec(ev.get("value"))
            if value is None:
                raise RuleInvalid("Enter the expected number")
            stored["value"] = fmt(value)
            return stored, None
        return stored, fact_key
    if method == "ENUM_MATCH":
        accepted = [str(a) for a in (ev.get("accepted") or [])]
        if not accepted or len(set(accepted)) != len(accepted):
            raise RuleInvalid("Choose at least one accepted option")
        unknown = [a for a in accepted if a not in options]
        if unknown:
            raise RuleInvalid(f"Accepted options must be the question's options ({', '.join(unknown)} is not)")
        if len(accepted) == len(options):
            raise RuleInvalid("Accepting every option is not an evaluation; use collect only")
        return {"accepted": accepted}, None
    if method == "SET_MATCH":
        mode = ev.get("mode")
        if mode not in SET_MODES:
            raise RuleInvalid(f"Choose how the selection is compared ({', '.join(SET_MODES)})")
        raw = ev.get("options")
        if not isinstance(raw, list | tuple) or not raw or not all(isinstance(o, str) for o in raw):
            raise RuleInvalid(
                "Choose at least one expected option; an empty expected set is not a supported comparison"
            )
        expected_set = [str(o) for o in raw]
        if len(set(expected_set)) != len(expected_set):
            raise RuleInvalid("An expected option is listed twice; list each option once")
        if not options:
            raise RuleInvalid("A set comparison needs the question's published options")
        unknown = [o for o in expected_set if o not in options]
        if unknown:
            raise RuleInvalid(f"Expected options must be the question's options ({', '.join(unknown)} is not)")
        # stored in the order of the question's own option set: the comparison never depends on any order
        return {"mode": mode, "options": [o for o in options if o in expected_set]}, None
    if method == "ENUM_MATCH_POLICY_FACT":
        fact = EVALUATION_FACTS.get(fact_key or "")
        if fact is None or fact["kind"] != "ENUM":
            raise RuleInvalid(
                "Choose an approved policy fact (enumerated: "
                + ", ".join(k for k, f in EVALUATION_FACTS.items() if f["kind"] == "ENUM")
                + ")"
            )
        foreign = [o for o in options if o not in fact["values"]]
        if foreign:
            raise RuleInvalid(
                f"Options must be approved values of {fact_key} ({', '.join(fact['values'])}); "
                f"{', '.join(foreign)} is not"
            )
        return None, fact_key
    return None, None  # ACKNOWLEDGEMENT, COLLECT_ONLY, NARRATIVE_REVIEW


_TYPE_MESSAGES = {
    "EXACT_BOOLEAN": "An exact yes/no expectation needs a yes/no question",
    "ACKNOWLEDGEMENT": "An acknowledgement expectation needs an acknowledgement question",
    "NUMERIC_COMPARE": "A numeric comparison needs a numeric question",
    "NUMERIC_MATCH_POLICY_FACT": "Matching a numeric policy fact needs a numeric question",
    "ENUM_MATCH": "An expected-choice comparison needs a choice question",
    "ENUM_MATCH_POLICY_FACT": "Matching an enumerated policy fact needs a choice question",
    "NARRATIVE_REVIEW": "Narrative review needs a free-text question",
    "SET_MATCH": "A set comparison needs a multiple-choice question",
}


@dataclass(frozen=True)
class Rule:
    question_code: str
    question_revision_id: str
    revision: int
    method: str
    answer_type: str
    options: tuple[str, ...]
    expected: Mapping[str, Any] | None
    fact_key: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "answer_type": self.answer_type,
            "options": list(self.options),
            "expected": dict(self.expected) if self.expected is not None else None,
            "fact_key": self.fact_key,
        }


def rule_of(q: Mapping[str, Any]) -> Rule:
    """The evaluation rule of one question revision in frozen script content (legacy S0/S2 rules get the exact
    defaults: equal to, no tolerance, the fact's own unit)."""
    method = q.get("expected_answer_policy") or "COLLECT_ONLY"
    expected = q.get("expected_value")
    if method == "NUMERIC_MATCH_POLICY_FACT" and not expected:
        fact = EVALUATION_FACTS.get(q.get("policy_fact_key") or "") or {}
        expected = {"operator": "EQ", "unit": fact.get("unit") or "SGD", "tolerance": "0", "tolerance_reference": None}
    return Rule(
        question_code=q["question_code"],
        question_revision_id=str(q.get("question_revision_id") or q.get("id") or ""),
        revision=int(q.get("revision") or 1),
        method=method,
        answer_type=q.get("answer_type") or "FREE_TEXT",
        options=tuple((q.get("answer_schema") or {}).get("enum") or ()),
        expected=expected,
        fact_key=q.get("policy_fact_key"),
    )


def rules_of(content: Mapping[str, Any]) -> dict[str, Rule]:
    return {q["question_code"]: rule_of(q) for sec in content.get("sections", []) for q in sec.get("questions", [])}


def describe_rule(r: Rule) -> str:
    """Plain-language statement of what the rule expects."""
    e = dict(r.expected or {})
    if r.method == "EXACT_BOOLEAN":
        return f"Expected answer: {'yes' if e.get('value') else 'no'}"
    if r.method == "ACKNOWLEDGEMENT":
        return "Expected: the customer acknowledges"
    if r.method in ("NUMERIC_COMPARE", "NUMERIC_MATCH_POLICY_FACT"):
        target = e.get("value") if r.method == "NUMERIC_COMPARE" else f"policy fact {r.fact_key}"
        tol = dec(e.get("tolerance")) or Decimal(0)
        return (
            f"Expected: {OPERATORS.get(e.get('operator') or 'EQ', 'equal to')} {target} "
            f"{UNITS.get(str(e.get('unit')), '')}"
        ).rstrip() + (f" ± {fmt(tol)} (approved tolerance, ref {e.get('tolerance_reference')})" if tol > 0 else "")
    if r.method == "ENUM_MATCH":
        return f"Expected choice: {' or '.join(e.get('accepted') or [])}"
    if r.method == "ENUM_MATCH_POLICY_FACT":
        return f"Expected choice: the policy fact {r.fact_key}"
    if r.method == "SET_MATCH":
        return f"Expected selection: {SET_MODES.get(str(e.get('mode')), '?')} {', '.join(e.get('options') or [])}"
    if r.method == "NARRATIVE_REVIEW":
        return "Captured for human assessment"
    return "Captured only; no expected answer"


def rule_changes(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Evaluation-rule differences between two script contents, per common question."""
    ra, rb = rules_of(a), rules_of(b)
    out = []
    for code, x in ra.items():
        y = rb.get(code)
        if y is not None and (x.method, x.expected, x.fact_key) != (y.method, y.expected, y.fact_key):
            out.append({"question": code, "from": describe_rule(x), "to": describe_rule(y)})
    return out


# ---- evaluation --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class FactSource:
    """The immutable facts used: a policy fact snapshot (id + SHA-256) or a scenario revision's synthetic facts."""

    kind: str  # POLICY_FACT_SNAPSHOT | SCENARIO_FACTS
    ref: str | None
    sha256: str | None
    facts: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "sha256": self.sha256}


def _answer_view(rule: Rule, answer: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not answer:
        return None
    return {
        "kind": answer.get("answer_kind"),
        "state": answer.get("answer_state"),
        "value": answer.get("value"),
        "verbatim": answer.get("verbatim"),
    }


def _expected_number(rule: Rule, facts: FactSource) -> tuple[Decimal | None, str, dict[str, Any], str | None]:
    """(expected value in the answer's unit, source label, expected record, problem when the fact is unusable)."""
    e = dict(rule.expected or {})
    unit = e.get("unit")
    if rule.method == "NUMERIC_COMPARE":
        d = dec(e.get("value"))
        return d, "RULE", {"value": fmt(d), "unit": unit, "source": "RULE"}, None
    fact = EVALUATION_FACTS.get(rule.fact_key or "") or {}
    raw = facts.facts.get(rule.fact_key or "")
    rec: dict[str, Any] = {"value": None, "unit": unit, "source": f"POLICY_FACT:{rule.fact_key}", "fact_value": raw}
    if raw is None:
        return None, rec["source"], rec, f"The fact source has no {rule.fact_key}"
    d = dec(raw)
    if d is None:
        return None, rec["source"], rec, f"{rule.fact_key} ({raw!r}) is not a number"
    fact_unit = fact.get("unit") or facts.facts.get(fact.get("unit_fact") or "")
    rec["fact_unit"] = fact_unit
    if fact_unit is None:
        return None, rec["source"], rec, f"The fact source does not state the unit of {rule.fact_key}"
    if fact_unit != unit:
        factor = _CONVERT.get((str(fact_unit), str(unit)))
        if factor is None:
            return None, rec["source"], rec, f"{rule.fact_key} is in {fact_unit} and cannot be compared in {unit}"
        d = d * factor
        rec["converted_from"] = f"{fmt(dec(raw))} {UNITS.get(fact_unit, fact_unit)}"
    rec["value"] = fmt(d)
    return d, rec["source"], rec, None


def _compare(op: str, got: Decimal, want: Decimal, tol: Decimal) -> bool:
    if op == "EQ":
        return abs(got - want) <= tol
    return {"GTE": got >= want, "LTE": got <= want, "GT": got > want, "LT": got < want}[op]


def evaluate_one(  # noqa: PLR0911, PLR0912
    rule: Rule,
    status: str,
    applicable: bool,
    skip_reason: str | None,
    answer: Any,
    unresolved_reason: str | None,
    facts: FactSource,
) -> dict[str, Any]:
    """One question. ``status`` is the controller's final item state; ``answer`` its last recorded answer."""
    av = _answer_view(rule, answer)
    base: dict[str, Any] = {
        "question_code": rule.question_code,
        "question_revision_id": rule.question_revision_id,
        "revision": rule.revision,
        "method": rule.method,
        "rule": rule.as_dict(),
        "rule_text": describe_rule(rule),
        "answer": av,
        "normalized_answer": None,
        "expected": None,
        "result": "NOT_EVALUATED",
        "explanation": "",
    }

    def res(result: str, why: str, **extra: Any) -> dict[str, Any]:
        out = base | extra | {"result": result, "explanation": why}
        out["rule_evaluation_equivalent"] = RULE_EVALUATION_EQUIVALENT[result]
        return out

    if not applicable or status == "SKIPPED_BY_CONDITION":
        return res("NOT_APPLICABLE", f"Not applicable: {skip_reason or 'excluded by an approved condition'}")
    if rule.method == "COLLECT_ONLY":
        captured = "captured" if av and av["kind"] == "ANSWER" else "not captured"
        return res("NOT_EVALUATED", f"Capture-only question (answer {captured}); no deterministic evaluation applies")
    if status in ("PENDING", "REQUESTED") or (av is None and status != "UNRESOLVED"):
        return res("NOT_ASKED", "Applicable but never presented to the customer, so there is no answer to evaluate")
    if status == "UNRESOLVED" or av is None or av["kind"] != "ANSWER":
        why = {
            "REFUSED": "The customer refused to answer",
            "UNKNOWN": "The customer did not know",
            "RETRY_LIMIT": "No usable answer within the approved re-prompts",
            "UNCLEAR_ANSWER": "The answer was unclear",
        }.get(str(unresolved_reason or (av or {}).get("kind") or ""), "No usable answer was recorded")
        if av and av["kind"] == "UNCLEAR":
            why = "The answer was unclear" + (
                " and the approved re-prompts were used" if status == "UNRESOLVED" else ""
            )
        return res("UNRESOLVED", f"{why}; an unresolved answer is never treated as a match")
    if status != "COMPLETED":
        return res("UNRESOLVED", "The answer has not been completed; it is not evaluated as a match")
    value = av["value"]
    if rule.method == "NARRATIVE_REVIEW":
        return res(
            "HUMAN_ASSESSMENT_REQUIRED",
            "Free-text answer captured; it needs a person's assessment (no automated judgement)",
            normalized_answer=str(value) if value is not None else None,
        )
    if rule.method in ("EXACT_BOOLEAN", "ACKNOWLEDGEMENT"):
        if not isinstance(value, bool):
            return res("UNRESOLVED", f"The recorded answer {value!r} is not a valid yes/no; it is not evaluated")
        want = bool((rule.expected or {}).get("value")) if rule.method == "EXACT_BOOLEAN" else True
        got_s, want_s = ("yes" if value else "no"), ("yes" if want else "no")
        exp: dict[str, Any] = {"value": want_s.upper(), "source": "RULE"}
        if rule.method == "ACKNOWLEDGEMENT":
            if value:
                return res("MATCH", "The customer acknowledged", normalized_answer="YES", expected=exp)
            return res(
                "MISMATCH",
                "The customer did not acknowledge (answered no); a mismatch is a discrepancy for review, not a "
                "breach finding",
                normalized_answer="NO",
                expected=exp,
            )
        if value == want:
            return res("MATCH", f"Answered {got_s}; expected {want_s}", normalized_answer=got_s.upper(), expected=exp)
        return res(
            "MISMATCH",
            f"Answered {got_s}; expected {want_s}. A mismatch is a discrepancy for review, not a breach finding",
            normalized_answer=got_s.upper(),
            expected=exp,
        )
    if rule.method in ("NUMERIC_COMPARE", "NUMERIC_MATCH_POLICY_FACT"):
        got = dec(value)
        e = dict(rule.expected or {})
        unit_s = UNITS.get(str(e.get("unit")), str(e.get("unit") or ""))
        if got is None:
            return res("UNRESOLVED", f"The recorded answer {value!r} is not a number; it is not evaluated")
        target_d, _, exp, problem = _expected_number(rule, facts)
        if problem or target_d is None:
            return res(
                "MISSING_EXPECTED_FACT",
                f"{problem or 'No expected value'}; the answer cannot be compared and is never treated as a match",
                normalized_answer=fmt(got),
                expected=exp,
            )
        op = e.get("operator") or "EQ"
        tol = dec(e.get("tolerance")) or Decimal(0)
        exp |= {"operator": op, "tolerance": fmt(tol), "tolerance_reference": e.get("tolerance_reference")}
        src = f"policy fact {rule.fact_key}" if rule.method == "NUMERIC_MATCH_POLICY_FACT" else "the approved value"
        conv = f" (converted from {exp['converted_from']})" if exp.get("converted_from") else ""
        target = f"{OPERATORS[op]} {fmt(target_d)} {unit_s}".rstrip() + (f" ± {fmt(tol)}" if tol > 0 else "")
        ok = _compare(op, got, target_d, tol)
        diff = f"; differs by {fmt(abs(got - target_d))}" if op == "EQ" and got != target_d else ""
        why = f"Answered {fmt(got)} {unit_s}".rstrip() + f"; expected {target} from {src}{conv}{diff}"
        if ok:
            if tol > 0 and got != target_d:
                why += f" — within the approved tolerance (ref {e.get('tolerance_reference')}, bounds inclusive)"
            return res("MATCH", why, normalized_answer=fmt(got), expected=exp)
        if tol > 0:
            why += f" — outside the approved tolerance (ref {e.get('tolerance_reference')})"
        return res(
            "MISMATCH",
            why + ". A mismatch is a discrepancy for review, not a breach finding",
            normalized_answer=fmt(got),
            expected=exp,
        )
    if rule.method in ("ENUM_MATCH", "ENUM_MATCH_POLICY_FACT"):
        if value not in rule.options:
            return res("UNRESOLVED", f"The recorded answer {value!r} is not an approved option; it is not evaluated")
        if rule.method == "ENUM_MATCH":
            accepted = list((rule.expected or {}).get("accepted") or [])
            exp = {"value": accepted, "source": "RULE"}
        else:
            raw = facts.facts.get(rule.fact_key or "")
            exp = {"value": raw, "source": f"POLICY_FACT:{rule.fact_key}", "fact_value": raw}
            if raw is None:
                return res(
                    "MISSING_EXPECTED_FACT",
                    f"The fact source has no {rule.fact_key}; the answer cannot be compared and is never treated as "
                    "a match",
                    normalized_answer=value,
                    expected=exp,
                )
            if raw not in rule.options:
                return res(
                    "MISSING_EXPECTED_FACT",
                    f"{rule.fact_key} is {raw}, which is not one of this question's options; the answer cannot be "
                    "compared",
                    normalized_answer=value,
                    expected=exp,
                )
            accepted = [raw]
        src = f"policy fact {rule.fact_key}" if rule.method == "ENUM_MATCH_POLICY_FACT" else "the approved options"
        why = f"Answered {value}; expected {' or '.join(map(str, accepted))} from {src}"
        if value in accepted:
            return res("MATCH", why, normalized_answer=value, expected=exp)
        return res(
            "MISMATCH",
            why + ". A mismatch is a discrepancy for review, not a breach finding",
            normalized_answer=value,
            expected=exp,
        )
    if rule.method == "SET_MATCH":
        e = dict(rule.expected or {})
        mode, wanted = e.get("mode"), list(e.get("options") or [])
        # an unsupported configuration is said, never evaluated
        if (
            mode not in SET_MODES
            or not wanted
            or len(set(wanted)) != len(wanted)
            or any(o not in rule.options for o in wanted)
        ):
            return res(
                "NOT_EVALUATED", "The set comparison is not a supported configuration; the selection is not evaluated"
            )
        if not isinstance(value, list | tuple) or not all(isinstance(v, str) for v in value):
            return res(
                "UNRESOLVED", f"The recorded answer {value!r} is not a selection of options; it is not evaluated"
            )
        chosen = [str(v) for v in value]
        if len(set(chosen)) != len(chosen):
            # duplicates are never collapsed on the customer's behalf: the selection is not a well-formed set
            return res("UNRESOLVED", "An option is recorded twice in the selection; it is not evaluated")
        foreign = [v for v in chosen if v not in rule.options]
        if foreign:
            return res(
                "UNRESOLVED",
                f"The selection contains {', '.join(foreign)}, not an approved option; it is not evaluated",
            )
        got_set, want_set = set(chosen), set(wanted)
        hit = {
            "INCLUDES_ALL": want_set <= got_set,
            "INCLUDES_ANY": bool(got_set & want_set),
            "INCLUDES_NONE": not (got_set & want_set),
            "EQUALS": got_set == want_set,
        }[str(mode)]
        normal = [o for o in rule.options if o in got_set]  # the question's own order: no order of the answer matters
        said = ", ".join(normal) if normal else "nothing (an explicit empty selection)"
        why = f"Selected {said}; expected {SET_MODES[str(mode)]} {', '.join(wanted)}"
        exp = {"mode": mode, "value": wanted, "source": "RULE"}
        if hit:
            return res("MATCH", why, normalized_answer=normal, expected=exp)
        return res(
            "MISMATCH",
            why + ". A mismatch is a discrepancy for review, not a breach finding",
            normalized_answer=normal,
            expected=exp,
        )
    return res("NOT_EVALUATED", f"No deterministic evaluation for method {rule.method}")


def evaluate(content: Mapping[str, Any], ctrl: Any, facts: FactSource) -> list[dict[str, Any]]:
    """Evaluate every planned question of a controller (``question_controller.Controller``) in plan order."""
    rules = rules_of(content)
    out = []
    for pq in ctrl.plan.questions:
        rule = rules.get(pq.code)
        qs = ctrl.q[pq.code]
        if rule is None:  # defensive: a plan item without a rule in the content used
            rule = Rule(pq.code, pq.revision_id, pq.revision, "COLLECT_ONLY", pq.answer_type, pq.options, None, None)
        if pq.completes_on_delivery:
            out.append(
                {
                    "question_code": pq.code,
                    "question_revision_id": rule.question_revision_id,
                    "revision": rule.revision,
                    "method": rule.method,
                    "rule": rule.as_dict(),
                    "rule_text": "Statement delivered by the system; no customer answer to evaluate",
                    "answer": None,
                    "normalized_answer": None,
                    "expected": None,
                    "result": "NOT_APPLICABLE" if not pq.applicable else "NOT_EVALUATED",
                    "explanation": (
                        f"Not applicable: {pq.skip_reason}"
                        if not pq.applicable
                        else f"Statement ({pq.role.replace('_', ' ').lower()}): delivery is recorded by the "
                        "controller; there is no answer to evaluate"
                    ),
                    "rule_evaluation_equivalent": "NOT_EVALUATED",
                }
            )
            continue
        out.append(
            evaluate_one(rule, qs.status, pq.applicable, pq.skip_reason, qs.answer, qs.reason, facts)
            | {"stage": pq.stage, "role": pq.role, "mandatory": pq.mandatory, "wording": pq.wording}
        )
    for r in out:
        r.setdefault("stage", None)
    return out


def totals(results: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    t = dict.fromkeys(RESULTS, 0)
    for r in results:
        t[r["result"]] += 1
    return t


def result_map(results: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    return {r["question_code"]: r["result"] for r in results}
