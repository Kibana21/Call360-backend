"""Deterministic script-assignment rule matching (S2-B; reused unchanged by S2-C).

Pure functions only: no database, clock or randomness. Inputs are already-loaded rule candidates and case inputs;
the output is a decision with a complete trace. Owner decisions (2026-11-17, recorded as D-58…D-61):

- **Precedence** (D-58): priority first — a *lower* number wins (1 is highest); on equal priority the rule with the
  higher specificity wins. Equal priority and specificity with different target script versions → ``AMBIGUOUS``.
  Equal priority and specificity with the *same* target → every tied rule is kept in the trace and the decision fails
  closed as ``AMBIGUOUS_SAME_TARGET`` (T-40: equal precedence is held for authorised review, never auto-selected).
- **Specificity** (D-59) is calculated, never entered: the number of distinct explicitly constrained fields. An
  unrestricted ("any") field does not count; several values in one field count once; explicitly matching the
  ``UNASSESSED`` risk status counts as a constraint.
- **Fallback** (D-60): a rule explicitly configured (and approved) as the default fallback is considered only when no
  other rule matches. A fallback never resolves ambiguity.
- **Fail closed** (D-61, proposed): an eligible rule that cannot be evaluated because a case input is missing gives
  ``INPUT_MISSING``; a winning rule whose target script version is not published and effective gives
  ``TARGET_NOT_EFFECTIVE``. Neither falls through to a lower-precedence rule.

Rule predicates are stored in the S0 predicate language, extended with ``in``:
``{"all": [{"fact": f, "equals": v} | {"fact": f, "in": [v, ...]} | {"risk_band_in": [...]}, ...]}``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

RISK_UNASSESSED = "UNASSESSED"


@dataclass(frozen=True)
class FieldSpec:
    key: str
    label: str
    multi_valued_input: bool = False  # the case may hold several values (contact roles): "any of" semantics


# Approved condition fields, in display and canonical order. Values come from governed sources (rule_inputs.options).
FIELDS: tuple[FieldSpec, ...] = (
    FieldSpec("market", "Market"),
    FieldSpec("case_purpose", "Callback purpose"),
    FieldSpec("product_family", "Product family"),
    FieldSpec("product_code", "Product"),
    FieldSpec("is_ilp", "ILP indicator"),
    FieldSpec("risk_band", "SBQ sale-selection risk band"),
    FieldSpec("selling_channel", "Sales channel"),
    FieldSpec("premium_frequency", "Premium frequency"),
    FieldSpec("contact_role", "Eligible contact role", multi_valued_input=True),
)
FIELD_BY_KEY = {f.key: f for f in FIELDS}
ORDER = {f.key: i for i, f in enumerate(FIELDS)}


class RuleError(ValueError):
    """A predicate outside the approved rule language."""


@dataclass(frozen=True)
class Condition:
    field: str
    values: tuple[Any, ...]


def parse_predicate(pred: Any) -> list[Condition]:
    """Stored predicate → conditions (one per field). Raises ``RuleError`` for anything outside the language."""
    if pred is None:
        return []
    if not isinstance(pred, Mapping):
        raise RuleError("predicate must be an object")
    parts: Sequence[Any] = pred["all"] if set(pred) == {"all"} else [pred]
    if not isinstance(parts, list | tuple):
        raise RuleError("'all' must be a list")
    by_field: dict[str, list[Any]] = {}
    for p in parts:
        if not isinstance(p, Mapping):
            raise RuleError("each condition must be an object")
        keys = set(p)
        if keys == {"risk_band_in"}:
            f, vals = "risk_band", list(p["risk_band_in"])
        elif keys == {"fact", "equals"}:
            f, vals = str(p["fact"]), [p["equals"]]
        elif keys == {"fact", "in"}:
            f, vals = str(p["fact"]), list(p["in"])
        else:
            raise RuleError(f"unsupported condition {dict(p)!r}")
        if f not in FIELD_BY_KEY:
            raise RuleError(f"'{f}' is not an approved rule field")
        if f in by_field:
            raise RuleError(f"'{f}' is constrained twice")
        if not vals:
            raise RuleError(f"'{f}' needs at least one value")
        by_field[f] = vals
    return [Condition(f, _dedupe(v)) for f, v in sorted(by_field.items(), key=lambda kv: ORDER[kv[0]])]


def _dedupe(values: Iterable[Any]) -> tuple[Any, ...]:
    out: list[Any] = []
    for v in values:
        if v not in out:
            out.append(v)
    return tuple(sorted(out, key=lambda x: (str(type(x)), str(x))))


def to_predicate(conditions: Sequence[Condition]) -> dict[str, Any]:
    """Canonical stored form (fields in fixed order, values sorted; one value → ``equals``)."""
    parts: list[dict[str, Any]] = []
    for c in sorted(conditions, key=lambda c: ORDER[c.field]):
        vals = list(_dedupe(c.values))
        parts.append({"fact": c.field, "equals": vals[0]} if len(vals) == 1 else {"fact": c.field, "in": vals})
    return {"all": parts}


def specificity(conditions: Sequence[Condition]) -> int:
    """D-59: distinct explicitly constrained fields (empty or unrestricted fields are not conditions)."""
    return len({c.field for c in conditions if c.values})


# ---- explanation ------------------------------------------------------------------------------------------------
def _value_text(f: str, v: Any, labels: Mapping[str, Mapping[str, str]]) -> str:
    if f == "is_ilp":
        return "an ILP" if v is True else "not an ILP"
    return labels.get(f, {}).get(str(v), str(v))


def _lower(label: str) -> str:
    """Sentence-case a field label without lower-casing acronyms ("SBQ …", "ILP …")."""
    first = label.split(" ", 1)[0]
    return label if first.isupper() and len(first) > 1 else label[:1].lower() + label[1:]


def condition_text(c: Condition, labels: Mapping[str, Mapping[str, str]] | None = None) -> str:
    labels = labels or {}
    name = FIELD_BY_KEY[c.field].label
    vals = [_value_text(c.field, v, labels) for v in c.values]
    if c.field == "is_ilp":
        return f"the product is {' or '.join(vals)}"
    if c.field == "contact_role":
        return f"the case has an eligible contact who is {' or '.join(vals)}"
    if c.field == "risk_band":
        named = [v for v in vals]
        return f"the {name} is {' or '.join(named)}"
    return f"the {_lower(name)} is {' or '.join(vals)}"


def explain(
    conditions: Sequence[Condition],
    target_label: str,
    priority: int,
    *,
    is_fallback: bool = False,
    labels: Mapping[str, Mapping[str, str]] | None = None,
) -> str:
    """Plain-English description of what a rule does (shown in the editor, trace and review)."""
    lead = "As the default fallback (only when no other rule matches), assign" if is_fallback else "Assign"
    when = " and ".join(condition_text(c, labels) for c in conditions) if conditions else "for every case"
    unrestricted = [f.label for f in FIELDS if f.key not in {c.field for c in conditions}]
    tail = f" Any {', '.join(_lower(u) for u in unrestricted)}." if unrestricted else ""
    return (
        f"{lead} {target_label} when {when}. Priority {priority} (1 is highest), specificity "
        f"{specificity(conditions)}.{tail}"
    )


# ---- evaluation -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RuleCandidate:
    ref: str  # stable reference: "<rule_code> v<version>" or "<rule_code> (draft)"
    rule_code: str
    version: int | None
    origin: str  # PUBLISHED | PROPOSED
    status: str
    conditions: tuple[Condition, ...]
    priority: int
    is_fallback: bool
    target_id: str
    target_label: str
    effective_from: datetime | None  # None for a proposal effective on publication
    effective_to: datetime | None
    # Whether the target script version is published and effective at the evaluation time (pre-computed by the
    # loader so this module stays pure).
    target_effective: bool = True
    draft_id: str | None = None

    @property
    def specificity(self) -> int:
        return specificity(self.conditions)


@dataclass
class ConditionResult:
    field: str
    expected: list[Any]
    actual: Any
    result: str  # PASS | FAIL | UNKNOWN


@dataclass
class RuleTrace:
    ref: str
    rule_code: str
    origin: str
    priority: int
    specificity: int
    is_fallback: bool
    target_id: str
    target_label: str
    eligible: bool
    excluded_reason: str | None
    match: str  # MATCH | NO_MATCH | UNKNOWN | NOT_EVALUATED
    conditions: list[ConditionResult] = field(default_factory=list)
    selected: bool = False
    tied: bool = False


@dataclass
class Decision:
    outcome: str  # one of OUTCOMES
    selected_target_id: str | None
    selected_target_label: str | None
    winning_rules: list[str]
    reason: str
    trace: list[RuleTrace]
    determinable_target_label: str | None = None  # same-target tie: the script that would apply after review


OUTCOMES = (
    "SELECTED",
    "SELECTED_BY_FALLBACK",
    "NO_MATCH",
    "AMBIGUOUS",
    "AMBIGUOUS_SAME_TARGET",
    "INPUT_MISSING",
    "TARGET_NOT_EFFECTIVE",
    "CONTACT_UNRESOLVED",
)


def effective_at(rule: RuleCandidate, at: datetime) -> bool:
    start_ok = rule.effective_from is None or rule.effective_from <= at
    return start_ok and (rule.effective_to is None or at < rule.effective_to)


def _check(c: Condition, inputs: Mapping[str, Any]) -> ConditionResult:
    spec = FIELD_BY_KEY[c.field]
    actual = inputs.get(c.field)
    if c.field == "risk_band" and actual is None:
        actual = RISK_UNASSESSED  # no FINAL assessment is a value, not a missing input (D-59)
    if spec.multi_valued_input:
        roles = sorted(actual or [])
        return ConditionResult(c.field, list(c.values), roles, "PASS" if set(roles) & set(c.values) else "FAIL")
    if actual is None:
        return ConditionResult(c.field, list(c.values), None, "UNKNOWN")
    return ConditionResult(c.field, list(c.values), actual, "PASS" if actual in c.values else "FAIL")


def match_rule(rule: RuleCandidate, inputs: Mapping[str, Any]) -> tuple[str, list[ConditionResult]]:
    results = [_check(c, inputs) for c in rule.conditions]
    if any(r.result == "FAIL" for r in results):
        return "NO_MATCH", results
    if any(r.result == "UNKNOWN" for r in results):
        return "UNKNOWN", results
    return "MATCH", results


def _rank(r: RuleCandidate) -> tuple[int, int]:
    return (r.priority, -r.specificity)


def evaluate(rules: Sequence[RuleCandidate], inputs: Mapping[str, Any], at: datetime) -> Decision:
    """Decide which script version the rules select for one case at time ``at`` (see module docstring)."""
    traces: dict[str, RuleTrace] = {}
    matched: list[RuleCandidate] = []
    unknown: list[RuleCandidate] = []
    for r in sorted(rules, key=lambda x: (*_rank(x), x.rule_code, x.ref)):
        t = RuleTrace(
            ref=r.ref,
            rule_code=r.rule_code,
            origin=r.origin,
            priority=r.priority,
            specificity=r.specificity,
            is_fallback=r.is_fallback,
            target_id=r.target_id,
            target_label=r.target_label,
            eligible=True,
            excluded_reason=None,
            match="NOT_EVALUATED",
        )
        traces[r.ref] = t
        if r.origin == "PUBLISHED" and r.status != "PUBLISHED":
            t.eligible, t.excluded_reason = False, f"rule version is {r.status.lower()}"
            continue
        if not effective_at(r, at):
            t.eligible, t.excluded_reason = False, "not effective at the evaluation time"
            continue
        t.match, t.conditions = match_rule(r, inputs)
        if t.match == "MATCH":
            matched.append(r)
        elif t.match == "UNKNOWN":
            unknown.append(r)
    ordered = list(traces.values())

    def done(
        outcome: str,
        reason: str,
        winners: Sequence[RuleCandidate] = (),
        target: RuleCandidate | None = None,
        determinable: str | None = None,
    ) -> Decision:
        for w in winners:
            traces[w.ref].tied = len(winners) > 1
            traces[w.ref].selected = target is not None
        return Decision(
            outcome=outcome,
            selected_target_id=target.target_id if target else None,
            selected_target_label=target.target_label if target else None,
            winning_rules=[w.ref for w in winners],
            reason=reason,
            trace=ordered,
            determinable_target_label=determinable,
        )

    if unknown:
        missing = sorted({c.field for r in unknown for c in traces[r.ref].conditions if c.result == "UNKNOWN"})
        return done(
            "INPUT_MISSING",
            f"Required case input missing ({', '.join(FIELD_BY_KEY[m].label for m in missing)}); "
            "assignment needs triage, no rule is selected",
            unknown,
        )
    for pool, ok_outcome in (
        ([r for r in matched if not r.is_fallback], "SELECTED"),
        ([r for r in matched if r.is_fallback], "SELECTED_BY_FALLBACK"),
    ):
        if not pool:
            continue
        best = min(_rank(r) for r in pool)
        top = sorted((r for r in pool if _rank(r) == best), key=lambda r: r.ref)
        if len(top) > 1:
            targets = {r.target_id for r in top}
            if len(targets) > 1:
                return done(
                    "AMBIGUOUS",
                    f"{len(top)} rules match with equal priority {best[0]} and specificity {-best[1]} but select "
                    "different script versions; held for authorised review, never chosen arbitrarily",
                    top,
                )
            return done(
                "AMBIGUOUS_SAME_TARGET",
                f"{len(top)} rules match with equal priority {best[0]} and specificity {-best[1]}; they select the "
                "same script version, but equal precedence is held for authorised review (T-40), not auto-selected",
                top,
                determinable=top[0].target_label,
            )
        win = top[0]
        if not win.target_effective:
            return done(
                "TARGET_NOT_EFFECTIVE",
                f"{win.ref} wins but its target {win.target_label} is not published and effective; "
                "fails closed (no lower-precedence rule is used)",
                [win],
            )
        how = "the default fallback" if win.is_fallback else "the highest-precedence matching rule"
        return done(
            ok_outcome, f"{win.ref} is {how} (priority {win.priority}, specificity {win.specificity})", [win], win
        )
    return done("NO_MATCH", "No published, effective rule matches this case; no script can be selected")


# ---- assignment with the selected callback contact (D-62 as clarified for S2-C) --------------------------------
@dataclass(frozen=True)
class Contact:
    ref: str  # selection id
    role: str
    label: str = ""


@dataclass
class ContactResolution:
    status: str  # SINGLE | NOT_NEEDED | SAME_RESULT_FOR_ALL | UNRESOLVED
    selected: Contact | None
    considered: list[dict[str, Any]]
    explanation: str


def _key(d: Decision) -> tuple[Any, ...]:
    return (d.outcome, d.selected_target_id, tuple(d.winning_rules))


def roles_matter(rules: Sequence[RuleCandidate], at: datetime) -> bool:
    """Whether any rule that could apply at ``at`` constrains the contact role."""
    return any(
        c.field == "contact_role" and (r.origin == "PROPOSED" or r.status == "PUBLISHED") and effective_at(r, at)
        for r in rules
        for c in r.conditions
    )


def evaluate_for_contacts(
    rules: Sequence[RuleCandidate], inputs: Mapping[str, Any], contacts: Sequence[Contact], at: datetime
) -> tuple[Decision, ContactResolution]:
    """Evaluate for the case's selected callback contact (S2-C). One eligible contact → its role. Several → evaluate per
    contact; if they all lead to the same decision the choice does not matter, otherwise fail closed. None → fail closed
    only if some applicable rule depends on the contact role."""
    if len(contacts) == 1:
        c = contacts[0]
        d = evaluate(rules, {**inputs, "contact_role": [c.role]}, at)
        return d, ContactResolution(
            "SINGLE",
            c,
            [{"contact": c.label or c.ref, "role": c.role, "outcome": d.outcome}],
            f"The selected callback contact ({c.label or c.ref}, {c.role}) was used",
        )
    if not contacts:
        if roles_matter(rules, at):
            d = evaluate(rules, {**inputs, "contact_role": []}, at)
            return (
                Decision(
                    "CONTACT_UNRESOLVED",
                    None,
                    None,
                    [],
                    "No eligible callback contact is selected and an applicable rule depends on the contact role; "
                    "assignment fails closed instead of guessing",
                    d.trace,
                ),
                ContactResolution("UNRESOLVED", None, [], "No eligible callback contact"),
            )
        d = evaluate(rules, {**inputs, "contact_role": []}, at)
        return d, ContactResolution(
            "NOT_NEEDED", None, [], "No eligible contact; no applicable rule uses the contact role"
        )
    results = [(c, evaluate(rules, {**inputs, "contact_role": [c.role]}, at)) for c in contacts]
    considered = [
        {
            "contact": c.label or c.ref,
            "role": c.role,
            "outcome": d.outcome,
            "script": d.selected_target_label,
            "rules": d.winning_rules,
        }
        for c, d in results
    ]
    if len({_key(d) for _, d in results}) == 1:
        return results[0][1], ContactResolution(
            "SAME_RESULT_FOR_ALL",
            None,
            considered,
            f"{len(contacts)} eligible contacts; every one leads to the same decision, so the choice does not matter",
        )
    return (
        Decision(
            "CONTACT_UNRESOLVED",
            None,
            None,
            [],
            f"{len(contacts)} eligible contacts lead to different script decisions and no single callback contact "
            "is selected; assignment fails closed instead of guessing",
            results[0][1].trace,
        ),
        ContactResolution("UNRESOLVED", None, considered, "The script depends on which eligible contact is called"),
    )


# ---- static conflict analysis -----------------------------------------------------------------------------------
@dataclass
class Conflict:
    kind: str  # AMBIGUOUS | SAME_TARGET_TIE | OVERLAP | SHADOWED
    severity: str  # ERROR | WARNING | INFO
    rules: list[str]
    message: str


def _windows_overlap(a: RuleCandidate, b: RuleCandidate) -> bool:
    a_end, b_end = a.effective_to, b.effective_to
    a_start, b_start = a.effective_from, b.effective_from
    if a_end is not None and b_start is not None and a_end <= b_start:
        return False
    return not (b_end is not None and a_start is not None and b_end <= a_start)


def can_both_match(a: RuleCandidate, b: RuleCandidate) -> bool:
    """Whether some case could satisfy both predicates. Unconstrained fields match anything; contact roles are
    "any of", so two role conditions never make rules disjoint (a case can have several eligible contacts)."""
    ca = {c.field: set(c.values) for c in a.conditions}
    cb = {c.field: set(c.values) for c in b.conditions}
    for f in set(ca) & set(cb):
        if FIELD_BY_KEY[f].multi_valued_input:
            continue
        if not ca[f] & cb[f]:
            return False
    return True


def covers(general: RuleCandidate, specific: RuleCandidate) -> bool:
    """Every case matched by ``specific`` is also matched by ``general`` (contact roles compared as sets)."""
    cg = {c.field: set(c.values) for c in general.conditions}
    cs = {c.field: set(c.values) for c in specific.conditions}
    return all(f in cs and cs[f] <= vals for f, vals in cg.items())


def conflicts(rules: Sequence[RuleCandidate], focus: Iterable[str] | None = None) -> list[Conflict]:
    """Pairwise analysis of rules that can be live at the same time. ``focus``: only pairs involving these refs."""
    focus_set = set(focus) if focus is not None else None
    out: list[Conflict] = []
    rs = sorted(rules, key=lambda r: r.ref)
    for i, a in enumerate(rs):
        for b in rs[i + 1 :]:
            if focus_set is not None and a.ref not in focus_set and b.ref not in focus_set:
                continue
            if a.rule_code == b.rule_code or a.is_fallback != b.is_fallback:
                continue
            if not _windows_overlap(a, b) or not can_both_match(a, b):
                continue
            pair = [a.ref, b.ref]
            if _rank(a) == _rank(b):
                if a.target_id != b.target_id:
                    out.append(
                        Conflict(
                            "AMBIGUOUS",
                            "ERROR",
                            pair,
                            f"{a.ref} and {b.ref} can match the same case with equal priority {a.priority} and "
                            f"specificity {a.specificity} but select different scripts ({a.target_label} vs "
                            f"{b.target_label}); such cases would be ambiguous",
                        )
                    )
                else:
                    out.append(
                        Conflict(
                            "SAME_TARGET_TIE",
                            "ERROR",
                            pair,
                            f"{a.ref} and {b.ref} can match the same case with equal priority and specificity; even "
                            "with "
                            "the same target this is held for review (T-40). Change a priority or narrow a condition",
                        )
                    )
                continue
            hi, lo = (a, b) if _rank(a) < _rank(b) else (b, a)
            if covers(hi, lo):
                out.append(
                    Conflict(
                        "SHADOWED",
                        "WARNING",
                        [hi.ref, lo.ref],
                        f"{lo.ref} can never be selected while {hi.ref} is live: every case it matches is also "
                        "matched by "
                        "a higher-precedence rule",
                    )
                )
            else:
                out.append(
                    Conflict(
                        "OVERLAP",
                        "INFO",
                        [hi.ref, lo.ref],
                        f"{hi.ref} and {lo.ref} overlap; for cases matching both, {hi.ref} wins (priority "
                        f"{hi.priority}, specificity {hi.specificity})",
                    )
                )
    return out
