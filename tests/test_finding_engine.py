"""S3-B deterministic findings engine (pure): approved mismatch triggers, unresolved mandatory questions, missing policy
facts, human-assessment routing, correct answers without discrepancy findings, several findings in one execution,
severity only from configuration, precedence, unmapped controls, absent rules, deterministic keys and replay, rule
validation and scenario expected findings. No database, clock or LLM."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import question_controller as qc
from app.domain import scenario_runner as sr
from tests.test_answer_evaluation import CORRECT, FACTS, SCRIPT, with_step

CONTENT = copy.deepcopy(SCRIPT)
for s in CONTENT["sections"]:
    for q in s["questions"]:
        if q["question_code"] in ("Q-TERM", "Q-ADVICE"):
            q["controls"] = [
                {
                    "control_code": "SYN-CTRL-04" if q["question_code"] == "Q-TERM" else "SYN-CTRL-09",
                    "control_name": "Synthetic control",
                    "mapping_status": "PROPOSED",
                    "regulatory_reference": None,
                }
            ]


def rule(
    code: str, trigger: str, category: str, severity: str, scope: str = "ANY_QUESTION", **kw: Any
) -> dict[str, Any]:
    return {
        "rule_code": code,
        "scope": scope,
        "target": kw.pop("target", None),
        "trigger": trigger,
        "category": category,
        "severity": severity,
        "description": f"Synthetic rule {code} (test)",
        "severity_justification": "Synthetic test severity, not an approved threshold",
        **kw,
    }


RULES = fe.normalise_rules(
    [
        rule("FR-TERM-MISMATCH", "MISMATCH", "FACT_MISMATCH", "HIGH", "QUESTION", target="Q-TERM"),
        rule("FR-ADVICE-CTRL", "MISMATCH", "DISCLOSURE_CONCERN", "MEDIUM", "CONTROL", target="SYN-CTRL-09"),
        rule("FR-MANDATORY-UNRESOLVED", "UNRESOLVED", "MISSING_MANDATORY_ANSWER", "MEDIUM", mandatory_only=True),
        rule("FR-FACT-MISSING", "MISSING_EXPECTED_FACT", "POLICY_DATA_ISSUE", "LOW", review_required=False),
        rule("FR-NARRATIVE", "HUMAN_ASSESSMENT_REQUIRED", "NARRATIVE_REVIEW", "MEDIUM", review_required=False),
        rule("FR-ANY-MISMATCH", "MISMATCH", "UNCLEAR_UNDERSTANDING", "LOW", mandatory_only=True),
    ]
)
RS = fe.RuleSet.of("rs-1", "SG finding rules v1", "PUBLISHED", RULES)
CTX = {"execution_ref": "test-run", "script_label": "EV v1", "content_sha256": "e" * 64}


def evaluations(steps: list[dict[str, Any]], facts: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    f = facts or FACTS
    plan = qc.build_plan(CONTENT, script_label="EV v1", manifest_sha256="e" * 64, facts=f, band="LOW")
    src = ae.FactSource("SCENARIO_FACTS", "test", "f" * 64, f)
    ex = sr.execute(plan, steps, {}, "AFFIRMATIVE", lambda ctrl: ae.evaluate(CONTENT, ctrl, src))
    return list(ex.actual["evaluations"])


def gen(steps: list[dict[str, Any]], rules: fe.RuleSet = RS, **kw: Any) -> fe.Generation:
    return fe.generate(evaluations(steps, **kw), CONTENT, rules, CTX)


def by_q(g: fe.Generation) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in g.findings:
        out.setdefault(f["question_code"], []).append(f)
    return out


def test_correct_answers_produce_no_discrepancy_findings_and_route_human_assessment() -> None:
    g = gen(CORRECT)
    assert [f["finding_class"] for f in g.findings] == ["HUMAN_ASSESSMENT"]
    (h,) = g.findings
    assert h["question_code"] == "Q-NARRATIVE" and h["review_required"] is True  # forced for human assessment
    assert [x["question_code"] for x in g.human_assessment] == ["Q-NARRATIVE"]
    assert g.not_converted == []
    assert g.summary()["by_class"] == {"HUMAN_ASSESSMENT": 1}


def test_mismatches_become_findings_only_where_an_approved_rule_applies() -> None:
    a = {s["question"]: s for s in CORRECT}
    g = gen(
        [
            {"question": "Q-TERM", "kind": "ANSWER", "value": 5},
            {"question": "Q-ADVICE", "kind": "ANSWER", "value": False},
            a["Q-AMOUNT"],
            a["Q-TERM-MONTHS"],
            a["Q-AGE"],
            {"question": "Q-FREQ", "kind": "ANSWER", "value": "MONTHLY"},
            a["Q-CHANNEL"],
        ]
    )
    f = by_q(g)
    (term,) = f["Q-TERM"]  # the question rule beats the any-mandatory rule (specificity)
    assert (term["category"], term["severity"], term["finding_class"]) == (
        "FACT_MISMATCH",
        "HIGH",
        "CUSTOMER_DISCREPANCY",
    )
    assert term["rule"]["rule_code"] == "FR-TERM-MISMATCH" and term["rule"]["rule_set"]["sha256"] == RS.sha256
    assert term["severity_source"] == "Finding rule FR-TERM-MISMATCH in rule set SG finding rules v1"
    assert term["severity_justification"].startswith("Synthetic test severity")
    assert term["controls"][0]["control_code"] == "SYN-CTRL-04" and term["control_unmapped"] is False
    ev = term["evidence"]
    assert ev["answer"]["value"] == 5.0 and ev["expected"]["fact_value"] == 10 and ev["evaluation_result"] == "MISMATCH"
    assert "rule FR-TERM-MISMATCH applies because its rule targets Q-TERM" in term["explanation"]
    assert "not a breach determination" in term["explanation"]
    (adv,) = f["Q-ADVICE"]  # control rule beats the any-question rule
    assert adv["category"] == "DISCLOSURE_CONCERN" and adv["controls"][0]["control_code"] == "SYN-CTRL-09"
    assert "linked to control SYN-CTRL-09" in adv["explanation"]
    (freq,) = f["Q-FREQ"]  # no question / control rule: the any-mandatory-mismatch rule applies
    assert freq["rule"]["rule_code"] == "FR-ANY-MISMATCH" and freq["control_unmapped"] is True
    assert len(g.findings) >= 4  # several findings in one execution (plus the human-assessment item)


def test_not_every_mismatch_is_a_finding_when_no_rule_applies() -> None:
    only_term = fe.RuleSet.of("rs-2", "v2", "DRAFT", [r for r in RULES if r["rule_code"] == "FR-TERM-MISMATCH"])
    g = gen(
        [
            {"question": "Q-TERM", "kind": "ANSWER", "value": 5},
            {"question": "Q-ADVICE", "kind": "ANSWER", "value": False},
        ],
        only_term,
    )
    assert [f["question_code"] for f in g.findings] == ["Q-TERM"]
    nc = {x["question_code"]: x for x in g.not_converted}
    assert nc["Q-ADVICE"]["result"] == "MISMATCH" and "no finding is generated" in nc["Q-ADVICE"]["reason"]
    assert nc["Q-NARRATIVE"]["finding_class"] == "HUMAN_ASSESSMENT"  # still listed for human assessment
    empty = fe.RuleSet.of(None, "empty", "DRAFT", [])
    g2 = gen([{"question": "Q-TERM", "kind": "ANSWER", "value": 5}], empty)
    assert g2.findings == [] and {x["question_code"] for x in g2.not_converted} >= {"Q-TERM", "Q-NARRATIVE"}


@pytest.mark.parametrize("kind", ["REFUSED", "UNKNOWN"])
def test_unresolved_mandatory_question_is_missing_evidence(kind: str) -> None:
    g = gen(with_step("Q-TERM", kind))
    (f,) = by_q(g)["Q-TERM"]
    assert (f["category"], f["finding_class"], f["severity"]) == (
        "MISSING_MANDATORY_ANSWER",
        "MISSING_EVIDENCE",
        "MEDIUM",
    )


def test_missing_policy_fact_is_a_system_data_issue() -> None:
    facts = {k: v for k, v in FACTS.items() if k != "premium_term_years"}
    g = gen(CORRECT, facts=facts)
    for code in ("Q-TERM", "Q-TERM-MONTHS"):
        (f,) = by_q(g)[code]
        assert (f["category"], f["finding_class"], f["review_required"]) == (
            "POLICY_DATA_ISSUE",
            "SYSTEM_DATA_ISSUE",
            False,
        )


def test_not_asked_without_a_rule_is_reported_not_converted() -> None:
    g = gen([{"question": "Q-ID-NAME", "kind": "ANSWER", "value": False}])
    assert not any(f["trigger"] == "NOT_ASKED" for f in g.findings)
    assert {x["question_code"] for x in g.not_converted if x["result"] == "NOT_ASKED"} >= {"Q-TERM", "Q-ADVICE"}


def test_generation_is_deterministic_and_keys_depend_on_execution_and_rule_set() -> None:
    steps = with_step("Q-TERM", value=5)
    a, b = gen(steps), gen(steps)
    assert a.as_dict() == b.as_dict()
    keys = [f["finding_key"] for f in a.findings]
    assert len(set(keys)) == len(keys)
    other = fe.RuleSet.of("rs-1", "SG finding rules v1", "PUBLISHED", [*RULES[:-1]])
    assert {f["finding_key"] for f in gen(steps, other).findings}.isdisjoint(keys)
    elsewhere = fe.generate(evaluations(steps), CONTENT, RS, CTX | {"execution_ref": "another-run"})
    assert {f["finding_key"] for f in elsewhere.findings}.isdisjoint(keys)


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ({"rule_code": "TERM"}, "rule code"),
        ({"trigger": "MATCH"}, "trigger must be one of"),
        ({"category": "POLICY_DATA_ISSUE"}, "category for a mismatch trigger"),
        ({"severity": "SEVERE"}, "severity must be one of"),
        ({"severity_justification": ""}, "no severity is assumed"),
        ({"scope": "QUESTION", "target": None}, "question code"),
        ({"scope": "CONTROL", "target": "x"}, "control code"),
        ({"description": "short"}, "description"),
    ],
)
def test_rule_validation_uses_governed_values(bad: dict[str, Any], message: str) -> None:
    base = rule("FR-OK-RULE", "MISMATCH", "FACT_MISMATCH", "HIGH", "QUESTION", target="Q-TERM")
    with pytest.raises(fe.RulesInvalid, match=message):
        fe.normalise_rules([base | bad])


def test_duplicate_and_ambiguous_rules_are_rejected() -> None:
    a = rule("FR-A-RULE", "MISMATCH", "FACT_MISMATCH", "HIGH", "QUESTION", target="Q-TERM")
    with pytest.raises(fe.RulesInvalid, match="duplicate rule code"):
        fe.normalise_rules([a, a])
    with pytest.raises(fe.RulesInvalid, match="ambiguous"):
        fe.normalise_rules([a, a | {"rule_code": "FR-B-RULE", "severity": "LOW"}])
    (h,) = fe.normalise_rules(
        [rule("FR-H-RULE", "HUMAN_ASSESSMENT_REQUIRED", "NARRATIVE_REVIEW", "LOW", review_required=False)]
    )
    assert h["review_required"] is True and h["finding_class"] == "HUMAN_ASSESSMENT"


def test_scenario_expected_findings_pass_and_fail_with_explanations() -> None:
    plan = qc.build_plan(CONTENT, script_label="EV v1", manifest_sha256="e" * 64, facts=FACTS, band="LOW")
    src = ae.FactSource("SCENARIO_FACTS", "test", "f" * 64, FACTS)

    def finder(evs: list[dict[str, Any]]) -> dict[str, Any]:
        g = fe.generate(evs, CONTENT, RS, CTX)
        return g.as_dict() | {"rule_set": RS.ref(), "expected_view": fe.finding_set(g.findings)}

    def run(steps: list[dict[str, Any]], exp: dict[str, Any]) -> sr.Execution:
        return sr.execute(plan, steps, exp, "AFFIRMATIVE", lambda c: ae.evaluate(CONTENT, c, src), finder)

    want = [
        {"question": "Q-TERM", "category": "FACT_MISMATCH", "severity": "HIGH"},
        {"question": "Q-NARRATIVE", "category": "NARRATIVE_REVIEW"},
    ]
    ok = run(with_step("Q-TERM", value=5), {"findings": want})
    assert ok.status == "PASSED", ok.failures
    bad = run(CORRECT, {"findings": want})
    assert bad.status == "FAILED"
    assert bad.failures[0]["message"] == "Expected finding(s) not generated: Q-TERM fact mismatch (HIGH)"
    none = run(with_step("Q-TERM", value=5), {"findings": []})
    assert none.failures[0]["message"].startswith("No findings were expected, but generated: ")
    no_rules = sr.execute(plan, CORRECT, {"findings": []}, "AFFIRMATIVE", lambda c: ae.evaluate(CONTENT, c, src))
    assert "no finding rule set was available" in no_rules.failures[0]["message"]
