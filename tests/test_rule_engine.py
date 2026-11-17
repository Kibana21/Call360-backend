"""S2-B deterministic rule matching (pure; reused by S2-C): precedence, specificity, ties, fallback, fail-closed
outcomes, effective dates and static conflict analysis (owner decisions D-58…D-61)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.domain import rule_engine as e
from app.domain.rule_engine import Condition as C

NOW = datetime(2026, 11, 17, tzinfo=UTC)
CASE = {
    "market": "SG",
    "case_purpose": "SALE_VERIFICATION",
    "product_family": "ILP",
    "product_code": "SYN-ILP-GROWTH",
    "is_ilp": True,
    "selling_channel": "AGENCY",
    "premium_frequency": "MONTHLY",
    "risk_band": "HIGH",
    "contact_role": ["OWNER", "PAYER"],
}


def rule(ref: str, conds: list[C], prio: int = 10, target: str = "T1", **kw: object) -> e.RuleCandidate:
    base = e.RuleCandidate(
        ref=ref,
        rule_code=ref,
        version=1,
        origin="PUBLISHED",
        status="PUBLISHED",
        conditions=tuple(conds),
        priority=prio,
        is_fallback=False,
        target_id=target,
        target_label=f"Script {target}",
        effective_from=NOW - timedelta(days=30),
        effective_to=None,
    )
    return replace(base, **kw)  # type: ignore[arg-type]


SG = C("market", ("SG",))


def test_specificity_counts_distinct_constrained_fields_only() -> None:
    assert e.specificity([SG]) == 1
    assert e.specificity([SG, C("risk_band", ("HIGH", "MEDIUM", "LOW"))]) == 2  # several values count once
    assert e.specificity([SG, C("risk_band", ("UNASSESSED",))]) == 2  # explicit unassessed is a constraint
    assert e.specificity([SG, C("product_family", ())]) == 1  # an unrestricted field does not count
    seeded = {"all": [{"fact": "market", "equals": "SG"}, {"fact": "case_purpose", "equals": "SALE_VERIFICATION"}]}
    conds = e.parse_predicate(seeded)
    assert e.specificity(conds) == 2 and e.to_predicate(conds) == seeded  # seeded rules round-trip unchanged
    assert e.parse_predicate({"all": [{"risk_band_in": ["HIGH"]}]}) == [C("risk_band", ("HIGH",))]
    for bad in (
        {"all": [{"fact": "language", "equals": "en"}]},
        {"sql": "1=1"},
        {"all": [{"fact": "market", "equals": "SG"}, {"fact": "market", "equals": "SG"}]},
    ):
        with pytest.raises(e.RuleError):
            e.parse_predicate(bad)


def test_priority_first_then_specificity() -> None:
    broad = rule("BROAD", [SG], prio=10, target="T1")
    ilp = rule("ILP", [SG, C("is_ilp", (True,))], prio=10, target="T2")
    high_low_prio = rule("HIGH", [SG, C("is_ilp", (True,)), C("risk_band", ("HIGH",))], prio=20, target="T3")
    d = e.evaluate([broad, ilp, high_low_prio], CASE, NOW)
    assert (d.outcome, d.selected_target_id, d.winning_rules) == ("SELECTED", "T2", ["ILP"])  # same priority: specific
    top = rule("TOP", [SG], prio=1, target="T4")
    d = e.evaluate([broad, ilp, high_low_prio, top], CASE, NOW)
    assert d.selected_target_id == "T4"  # priority 1 beats any specificity
    assert [t.ref for t in d.trace][0] == "TOP" and {t.ref: t.match for t in d.trace}["HIGH"] == "MATCH"


def test_equal_precedence_is_never_resolved_arbitrarily() -> None:
    a = rule("A", [SG, C("is_ilp", (True,))], target="T1")
    b = rule("B", [SG, C("risk_band", ("HIGH",))], target="T2")
    d = e.evaluate([a, b], CASE, NOW)
    assert d.outcome == "AMBIGUOUS" and d.selected_target_id is None and set(d.winning_rules) == {"A", "B"}
    same = replace(b, target_id="T1", target_label="Script T1")
    d = e.evaluate([a, same], CASE, NOW)
    assert d.outcome == "AMBIGUOUS_SAME_TARGET" and d.selected_target_id is None  # T-40: fail closed
    assert d.determinable_target_label == "Script T1" and all(t.tied for t in d.trace)


def test_fallback_only_when_nothing_else_matches_and_never_resolves_ambiguity() -> None:
    fb = rule("FALLBACK", [SG], prio=999, target="TF", is_fallback=True)
    protection = rule("PROT", [SG, C("product_family", ("PROTECTION",))], target="T1")
    d = e.evaluate([fb, protection], CASE, NOW)
    assert (d.outcome, d.selected_target_id) == ("SELECTED_BY_FALLBACK", "TF")
    d = e.evaluate([fb, rule("ANY", [SG], prio=500, target="T9")], CASE, NOW)
    assert (d.outcome, d.selected_target_id) == ("SELECTED", "T9")  # a normal rule beats the fallback
    a = rule("A", [SG, C("is_ilp", (True,))], target="T1")
    b = rule("B", [SG, C("risk_band", ("HIGH",))], target="T2")
    assert e.evaluate([a, b, fb], CASE, NOW).outcome == "AMBIGUOUS"
    assert e.evaluate([protection], CASE, NOW).outcome == "NO_MATCH"


def test_unassessed_band_contact_roles_and_fail_closed_outcomes() -> None:
    unassessed = {**CASE, "risk_band": None}
    r_unassessed = rule("U", [SG, C("risk_band", ("UNASSESSED",))], target="TU")
    r_high = rule("H", [SG, C("risk_band", ("HIGH",))], target="TH")
    assert e.evaluate([r_unassessed, r_high], unassessed, NOW).selected_target_id == "TU"
    assert e.evaluate([r_unassessed, r_high], CASE, NOW).selected_target_id == "TH"
    unrestricted = rule("ANYBAND", [SG], prio=50, target="TA")
    assert e.evaluate([unrestricted], unassessed, NOW).selected_target_id == "TA"  # "any band" includes unassessed
    payer = rule("PAYER", [SG, C("contact_role", ("PAYER", "INSURED"))], target="TP")
    assert e.evaluate([payer], CASE, NOW).selected_target_id == "TP"  # any eligible contact with the role
    assert e.evaluate([payer], {**CASE, "contact_role": []}, NOW).outcome == "NO_MATCH"
    missing = {**CASE, "product_family": None}
    d = e.evaluate([rule("P", [SG, C("product_family", ("ILP",))])], missing, NOW)
    assert d.outcome == "INPUT_MISSING" and "Product family" in d.reason
    d = e.evaluate([rule("X", [SG], prio=1, target_effective=False), rule("Y", [SG], prio=2, target="T2")], CASE, NOW)
    assert d.outcome == "TARGET_NOT_EFFECTIVE" and d.selected_target_id is None  # no fall-through to Y


def test_effective_dates_and_status() -> None:
    future = rule("F", [SG], prio=1, target="TF", effective_from=NOW + timedelta(days=1))
    ended = rule("E", [SG], prio=1, target="TE", effective_to=NOW)
    withdrawn = rule("W", [SG], prio=1, target="TW", status="WITHDRAWN")
    live = rule("L", [SG], prio=10, target="TL")
    d = e.evaluate([future, ended, withdrawn, live], CASE, NOW)
    assert d.selected_target_id == "TL"
    reasons = {t.ref: t.excluded_reason for t in d.trace}
    assert reasons["F"] == reasons["E"] == "not effective at the evaluation time"
    assert reasons["W"] == "rule version is withdrawn"
    assert e.evaluate([future, live], CASE, NOW + timedelta(days=2)).selected_target_id == "TF"


def test_static_conflicts() -> None:
    a = rule("A", [SG, C("is_ilp", (True,))], target="T1")
    b = rule("B", [SG, C("risk_band", ("HIGH",))], target="T2")
    kinds = {c.kind for c in e.conflicts([a, b])}
    assert kinds == {"AMBIGUOUS"}
    assert {c.kind for c in e.conflicts([a, replace(b, target_id="T1")])} == {"SAME_TARGET_TIE"}
    disjoint = rule("D", [SG, C("is_ilp", (False,)), C("risk_band", ("HIGH",))], target="T2")
    assert e.conflicts([a, disjoint]) == []  # no case can match both
    roles_a = rule("RA", [SG, C("contact_role", ("OWNER",))], target="T1")
    roles_b = rule("RB", [SG, C("contact_role", ("PAYER",))], target="T2")
    assert {c.kind for c in e.conflicts([roles_a, roles_b])} == {"AMBIGUOUS"}  # a case can have both contacts
    broad = rule("BROAD", [SG], prio=50, target="T3")
    narrow_lower = rule("NARROW", [SG, C("is_ilp", (True,))], prio=60, target="T4")
    shadow = e.conflicts([broad, narrow_lower])
    assert [c.kind for c in shadow] == ["SHADOWED"] and shadow[0].severity == "WARNING"
    assert [c.kind for c in e.conflicts([replace(broad, priority=70), narrow_lower])] == ["OVERLAP"]
    later = replace(b, effective_from=NOW + timedelta(days=10))
    assert e.conflicts([replace(a, effective_to=NOW + timedelta(days=5)), later]) == []  # windows do not overlap


def test_explanation_is_plain_english() -> None:
    text = e.explain(
        [SG, C("is_ilp", (True,)), C("risk_band", ("HIGH", "UNASSESSED"))],
        "SALES_VERIFICATION_SG v1.1",
        5,
        labels={"risk_band": {"HIGH": "High", "UNASSESSED": "Unassessed"}},
    )
    assert text.startswith("Assign SALES_VERIFICATION_SG v1.1 when the market is SG and the product is an ILP and the")
    assert "High or Unassessed" in text and "Priority 5 (1 is highest), specificity 3." in text
    assert "Any callback purpose" in text


def test_assignment_uses_the_selected_contact_and_fails_closed_when_unresolved() -> None:
    owner, payer = e.Contact("s1", "OWNER", "A"), e.Contact("s2", "PAYER", "B")
    generic = rule("GEN", [SG], prio=50, target="TG")
    d, r = e.evaluate_for_contacts([generic], CASE, [owner, payer], NOW)
    assert (d.outcome, r.status) == ("SELECTED", "SAME_RESULT_FOR_ALL")  # the contact does not change the script
    by_role = rule("PAYER-ONLY", [SG, C("contact_role", ("PAYER",))], prio=10, target="TP")
    d, r = e.evaluate_for_contacts([generic, by_role], CASE, [payer], NOW)
    assert (d.selected_target_id, r.status, r.selected) == ("TP", "SINGLE", payer)
    d, r = e.evaluate_for_contacts([generic, by_role], CASE, [owner, payer], NOW)
    assert (d.outcome, r.status) == ("CONTACT_UNRESOLVED", "UNRESOLVED") and d.selected_target_id is None
    assert {c["role"] for c in r.considered} == {"OWNER", "PAYER"}
    d, r = e.evaluate_for_contacts([generic, by_role], CASE, [], NOW)
    assert d.outcome == "CONTACT_UNRESOLVED"  # no contact while a rule depends on the role
    d, r = e.evaluate_for_contacts([generic], CASE, [], NOW)
    assert (d.outcome, r.status) == ("SELECTED", "NOT_NEEDED")
