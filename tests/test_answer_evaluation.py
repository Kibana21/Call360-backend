"""S3-A deterministic answer evaluation engine (pure): every evaluation method, tolerance boundaries and units, policy
fact comparisons, missing facts, invalid response types, unclear / refused / unknown answers, conditional, capture-only
and human-assessment questions, legacy (historical) rules, a completed conversation that still contains mismatches,
scenario evaluation expectations and deterministic replay. No database, clock or LLM."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from app.domain import answer_evaluation as ae
from app.domain import question_controller as qc
from app.domain import scenario_runner as sr
from tests.test_conversation_lifecycle import CONTENT, item, sec


def rule(code: str, atype: str, pos: int, method: str, **kw: Any) -> dict[str, Any]:
    q = item(code, atype, pos, mandatory=kw.pop("mandatory", True), **kw)
    return q | {"expected_answer_policy": method}


SCRIPT = copy.deepcopy(CONTENT)
for s in SCRIPT["sections"]:
    for q in s["questions"]:
        if q["question_code"] == "Q-TERM":  # the S0 seeded shape: fact mapping, no stored rule (legacy defaults)
            q |= {"expected_answer_policy": "NUMERIC_MATCH_POLICY_FACT", "policy_fact_key": "premium_term_years"}
SCRIPT["sections"].append(
    sec(
        "EVAL",
        "COMMON",
        8,
        rule("Q-ADVICE", "YES_NO", 1, "EXACT_BOOLEAN", expected_value={"value": True}),
        rule("Q-UNDERSTOOD", "ACKNOWLEDGEMENT", 2, "ACKNOWLEDGEMENT"),
        rule(
            "Q-AMOUNT",
            "NUMERIC",
            3,
            "NUMERIC_MATCH_POLICY_FACT",
            policy_fact_key="premium_amount",
            expected_value={"operator": "EQ", "unit": "SGD", "tolerance": "5", "tolerance_reference": "SYN-TOL-001"},
        ),
        rule(
            "Q-TERM-MONTHS",
            "NUMERIC",
            4,
            "NUMERIC_MATCH_POLICY_FACT",
            policy_fact_key="premium_term_years",
            expected_value={"operator": "EQ", "unit": "MONTHS", "tolerance": "0", "tolerance_reference": None},
        ),
        rule(
            "Q-AGE",
            "NUMERIC",
            5,
            "NUMERIC_COMPARE",
            expected_value={"operator": "GTE", "value": "18", "unit": "COUNT", "tolerance": "0"},
        ),
        rule(
            "Q-FREQ",
            "ENUM",
            6,
            "ENUM_MATCH_POLICY_FACT",
            policy_fact_key="premium_frequency",
            answer_schema={"type": "string", "enum": ["MONTHLY", "QUARTERLY", "ANNUAL"]},
        ),
        rule(
            "Q-CHANNEL",
            "ENUM",
            7,
            "ENUM_MATCH",
            answer_schema={"type": "string", "enum": ["BRANCH", "PHONE", "ONLINE"]},
            expected_value={"accepted": ["BRANCH"]},
        ),
        rule("Q-NOTES", "FREE_TEXT", 8, "COLLECT_ONLY", mandatory=False),
        rule("Q-NARRATIVE", "FREE_TEXT", 9, "NARRATIVE_REVIEW"),
    )
)
SCRIPT["sections"].append(
    {
        **sec("ILP", "PRODUCT", 9, rule("Q-ILP-RISK", "YES_NO", 1, "EXACT_BOOLEAN", expected_value={"value": True})),
        "inclusion_condition": {"fact": "is_ilp", "equals": True},
    }
)
FACTS = {
    "is_ilp": False,
    "premium_term_years": 10,
    "premium_amount": "250.00",
    "currency": "SGD",
    "premium_frequency": "ANNUAL",
}
CORRECT = [
    {"question": "Q-TERM", "kind": "ANSWER", "value": 10},
    {"question": "Q-AMOUNT", "kind": "ANSWER", "value": 250},
    {"question": "Q-TERM-MONTHS", "kind": "ANSWER", "value": 120},
    {"question": "Q-AGE", "kind": "ANSWER", "value": 40},
    {"question": "Q-FREQ", "kind": "ANSWER", "value": "ANNUAL"},
    {"question": "Q-CHANNEL", "kind": "ANSWER", "value": "BRANCH"},
]


def execute(
    steps: list[dict[str, Any]], exp: dict[str, Any] | None = None, facts: dict[str, Any] | None = None
) -> sr.Execution:
    f = facts or FACTS
    plan = qc.build_plan(SCRIPT, script_label="EV v1", manifest_sha256="e" * 64, facts=f, band="LOW")
    src = ae.FactSource("SCENARIO_FACTS", "test", "f" * 64, f)
    return sr.execute(plan, steps, exp or {}, "AFFIRMATIVE", lambda ctrl: ae.evaluate(SCRIPT, ctrl, src))


def results(ex: sr.Execution) -> dict[str, str]:
    return dict(ex.actual["evaluation_results"])


def why(ex: sr.Execution, code: str) -> str:
    return next(r["explanation"] for r in ex.actual["evaluations"] if r["question_code"] == code)


def with_step(code: str, kind: str = "ANSWER", value: Any = None) -> list[dict[str, Any]]:
    step = {"question": code, "kind": kind, **({"value": value} if kind == "ANSWER" else {})}
    assert any(s["question"] == code for s in CORRECT)
    return [step if s["question"] == code else s for s in CORRECT]


def test_correct_answers_match_and_statements_capture_and_narrative_are_distinct() -> None:
    ex = execute(CORRECT)
    r = results(ex)
    assert ex.actual["outcome"] == "COMPLETED"
    for code in ("Q-TERM", "Q-ADVICE", "Q-UNDERSTOOD", "Q-AMOUNT", "Q-TERM-MONTHS", "Q-AGE", "Q-FREQ", "Q-CHANNEL"):
        assert r[code] == "MATCH", (code, why(ex, code))
    assert r["Q-NOTES"] == "NOT_EVALUATED" and "Capture-only" in why(ex, "Q-NOTES")
    assert r["Q-NARRATIVE"] == "HUMAN_ASSESSMENT_REQUIRED"
    assert r["Q-OPEN"] == r["Q-DISC"] == "NOT_EVALUATED"  # statements: nothing to evaluate
    assert r["Q-ILP-RISK"] == "NOT_APPLICABLE" and "is ilp" in why(ex, "Q-ILP-RISK")
    assert "converted from 10 years" in why(ex, "Q-TERM-MONTHS")
    assert ex.actual["evaluation_engine"] == ae.ENGINE and ex.actual["compliance_outcome"] == "NOT_EVALUATED"


def test_completed_conversation_can_still_contain_mismatches() -> None:
    wrong = [
        {"question": "Q-TERM", "kind": "ANSWER", "value": 5},  # S3-A1: 5-year answer vs 10-year term
        {"question": "Q-ADVICE", "kind": "ANSWER", "value": False},
        {"question": "Q-UNDERSTOOD", "kind": "ANSWER", "value": False},
        {"question": "Q-AGE", "kind": "ANSWER", "value": 17},
        {"question": "Q-FREQ", "kind": "ANSWER", "value": "MONTHLY"},
        {"question": "Q-CHANNEL", "kind": "ANSWER", "value": "PHONE"},
    ]
    ex = execute(wrong)
    r = results(ex)
    assert ex.actual["outcome"] == "COMPLETED" and ex.actual["mandatory_complete"] is True  # completion is separate
    for code in ("Q-ADVICE", "Q-UNDERSTOOD", "Q-TERM", "Q-AGE", "Q-FREQ", "Q-CHANNEL"):
        assert r[code] == "MISMATCH", code
    t = why(ex, "Q-TERM")
    assert "Answered 5 years; expected equal to 10 years from policy fact premium_term_years" in t
    assert "differs by 5" in t and "not a breach finding" in t
    item_ = next(x for x in ex.actual["evaluations"] if x["question_code"] == "Q-TERM")
    assert item_["expected"]["source"] == "POLICY_FACT:premium_term_years" and item_["expected"]["fact_value"] == 10
    assert item_["rule_evaluation_equivalent"] == "MISMATCH" and item_["normalized_answer"] == "5"
    assert item_["answer"]["value"] == 5.0 and item_["answer"]["state"] == "VALUE"


@pytest.mark.parametrize(
    ("value", "result"),
    [(245, "MATCH"), (255, "MATCH"), (250.5, "MATCH"), (244.99, "MISMATCH"), (255.01, "MISMATCH")],
)
def test_approved_tolerance_boundaries_are_inclusive(value: float, result: str) -> None:
    ex = execute(with_step("Q-AMOUNT", value=value))
    assert results(ex)["Q-AMOUNT"] == result, why(ex, "Q-AMOUNT")
    assert "SYN-TOL-001" in why(ex, "Q-AMOUNT")


def test_units_convert_exactly_and_without_tolerance_a_near_miss_is_a_mismatch() -> None:
    assert results(execute(with_step("Q-TERM-MONTHS", value=119)))["Q-TERM-MONTHS"] == "MISMATCH"
    assert results(execute(with_step("Q-TERM", value=10.0)))["Q-TERM"] == "MATCH"
    assert results(execute(with_step("Q-TERM", value=10.01)))["Q-TERM"] == "MISMATCH"  # exact: no tolerance assumed


def test_missing_or_unusable_expected_facts_are_never_matches() -> None:
    single = FACTS | {"premium_term_years": None, "premium_frequency": "SINGLE"}
    ex = execute(CORRECT, facts={k: v for k, v in single.items() if v is not None})
    r = results(ex)
    assert r["Q-TERM"] == r["Q-TERM-MONTHS"] == "MISSING_EXPECTED_FACT"
    assert r["Q-FREQ"] == "MISSING_EXPECTED_FACT" and "SINGLE, which is not one of this question's options" in why(
        ex, "Q-FREQ"
    )
    myr = execute(CORRECT, facts=FACTS | {"currency": "MYR"})
    assert results(myr)["Q-AMOUNT"] == "MISSING_EXPECTED_FACT" and "cannot be compared in SGD" in why(myr, "Q-AMOUNT")
    nocur = execute(CORRECT, facts={k: v for k, v in FACTS.items() if k != "currency"})
    assert results(nocur)["Q-AMOUNT"] == "MISSING_EXPECTED_FACT"


@pytest.mark.parametrize("kind", ["REFUSED", "UNKNOWN"])
def test_refused_and_unknown_answers_are_unresolved(kind: str) -> None:
    ex = execute(with_step("Q-TERM", kind))
    assert results(ex)["Q-TERM"] == "UNRESOLVED" and "never treated as a match" in why(ex, "Q-TERM")
    assert ex.actual["outcome"] == "INCOMPLETE"


def test_unclear_answers_after_reprompts_are_unresolved_and_a_clear_reprompt_is_evaluated() -> None:
    twice = [s for s in CORRECT if s["question"] != "Q-TERM"]
    steps = [{"question": "Q-TERM", "kind": "UNCLEAR"}, {"question": "Q-TERM", "kind": "UNCLEAR"}, *twice]
    ex = execute(steps)
    assert results(ex)["Q-TERM"] == "UNRESOLVED" and "unclear" in why(ex, "Q-TERM")
    once = [{"question": "Q-TERM", "kind": "UNCLEAR"}, {"question": "Q-TERM", "kind": "ANSWER", "value": 10}, *twice]
    assert results(execute(once))["Q-TERM"] == "MATCH"


def test_invalid_response_types_are_rejected_by_the_controller_and_never_matched_by_the_engine() -> None:
    ex = execute(with_step("Q-TERM", value="ten"))
    assert ex.status == "ERROR" and "INVALID_ANSWER" in (ex.error or "")
    r = ae.rule_of(next(q for s in SCRIPT["sections"] for q in s["questions"] if q["question_code"] == "Q-TERM"))
    src = ae.FactSource("SCENARIO_FACTS", None, None, FACTS)
    for value in ("ten", True, None):
        out = ae.evaluate_one(r, "COMPLETED", True, None, {"answer_kind": "ANSWER", "value": value}, None, src)
        assert out["result"] == "UNRESOLVED", value
    yn = ae.rule_of(next(q for s in SCRIPT["sections"] for q in s["questions"] if q["question_code"] == "Q-ADVICE"))
    assert (
        ae.evaluate_one(yn, "COMPLETED", True, None, {"answer_kind": "ANSWER", "value": "yes"}, None, src)["result"]
        == "UNRESOLVED"
    )


def test_questions_never_reached_after_termination_are_not_asked() -> None:
    ex = execute([{"question": "Q-ID-NAME", "kind": "ANSWER", "value": False}])
    r = results(ex)
    assert ex.actual["outcome"] == "TERMINATED"
    assert r["Q-ID-NAME"] == "NOT_EVALUATED"  # no evaluation rule configured on this identity check (capture only)
    assert r["Q-TERM"] == r["Q-ADVICE"] == "NOT_ASKED"
    assert r["Q-NOTES"] == "NOT_EVALUATED" and r["Q-NARRATIVE"] == "NOT_ASKED"


def test_conditional_question_is_evaluated_only_when_included() -> None:
    ex = execute(
        [*CORRECT, {"question": "Q-ILP-RISK", "kind": "ANSWER", "value": False}], facts=FACTS | {"is_ilp": True}
    )
    assert results(ex)["Q-ILP-RISK"] == "MISMATCH"
    assert results(execute(CORRECT))["Q-ILP-RISK"] == "NOT_APPLICABLE"


def test_scenario_evaluation_expectations_pass_and_fail_with_explanations() -> None:
    exp = {"outcome": "COMPLETED", "evaluations": {"Q-TERM": "MISMATCH", "Q-ADVICE": "MATCH"}}
    ok = execute(with_step("Q-TERM", value=5), exp)
    assert ok.status == "PASSED", ok.failures
    bad = execute(CORRECT, exp)
    assert bad.status == "FAILED"
    (f,) = bad.failures
    assert f["check"] == "evaluation:Q-TERM" and f["expected"] == "MISMATCH" and f["actual"] == "MATCH"
    assert "answer evaluation: expected mismatch, got match" in f["message"]


def test_deterministic_replay_gives_identical_results() -> None:
    a, b = execute(with_step("Q-AMOUNT", value=262)), execute(with_step("Q-AMOUNT", value=262))
    assert a.actual["evaluations"] == b.actual["evaluations"]
    plan = qc.build_plan(SCRIPT, script_label="EV v1", manifest_sha256="e" * 64, facts=FACTS, band="LOW")
    replayed = qc.Controller(plan, [qc.Event.from_dict(e) for e in a.events])
    src = ae.FactSource("SCENARIO_FACTS", "test", "f" * 64, FACTS)
    assert ae.evaluate(SCRIPT, replayed, src) == a.actual["evaluations"]


def test_legacy_rules_without_a_stored_rule_evaluate_exactly() -> None:
    r = ae.rule_of(
        {
            "question_code": "Q-L",
            "answer_type": "NUMERIC",
            "expected_answer_policy": "NUMERIC_MATCH_POLICY_FACT",
            "policy_fact_key": "premium_term_years",
            "expected_value": None,
        }
    )
    assert r.expected == {"operator": "EQ", "unit": "YEARS", "tolerance": "0", "tolerance_reference": None}
    assert ae.describe_rule(r) == "Expected: equal to policy fact premium_term_years years"


@pytest.mark.parametrize(
    ("method", "atype", "kw", "message"),
    [
        ("EXACT_BOOLEAN", "NUMERIC", {"expected_boolean": True}, "yes/no question"),
        ("NUMERIC_COMPARE", "YES_NO", {}, "numeric question"),
        ("ENUM_MATCH", "FREE_TEXT", {}, "choice question"),
        (
            "NUMERIC_COMPARE",
            "NUMERIC",
            {"evaluation": {"operator": "BETWEEN", "value": 1, "unit": "COUNT"}},
            "operator",
        ),
        ("NUMERIC_COMPARE", "NUMERIC", {"evaluation": {"value": 1}}, "unit"),
        ("NUMERIC_COMPARE", "NUMERIC", {"evaluation": {"unit": "COUNT"}}, "expected number"),
        (
            "NUMERIC_COMPARE",
            "NUMERIC",
            {"evaluation": {"value": 1, "unit": "COUNT", "tolerance": "-1"}},
            "non-negative",
        ),
        ("NUMERIC_COMPARE", "NUMERIC", {"evaluation": {"value": 1, "unit": "COUNT", "tolerance": "1"}}, "approval"),
        (
            "NUMERIC_COMPARE",
            "NUMERIC",
            {
                "evaluation": {
                    "operator": "GTE",
                    "value": 1,
                    "unit": "COUNT",
                    "tolerance": "1",
                    "tolerance_reference": "X-1",
                }
            },
            "only to an 'equal to'",
        ),
        ("NUMERIC_MATCH_POLICY_FACT", "NUMERIC", {"fact_key": "annual_income"}, "approved policy fact"),
        ("NUMERIC_MATCH_POLICY_FACT", "NUMERIC", {"fact_key": "premium_frequency"}, "approved policy fact"),
        (
            "NUMERIC_MATCH_POLICY_FACT",
            "NUMERIC",
            {"fact_key": "premium_amount", "evaluation": {"unit": "YEARS"}},
            "SGD",
        ),
        ("ENUM_MATCH_POLICY_FACT", "ENUM", {"fact_key": "premium_term_years"}, "approved policy fact"),
        ("ENUM_MATCH_POLICY_FACT", "ENUM", {"fact_key": "premium_frequency"}, "approved values"),
        ("ENUM_MATCH", "ENUM", {"evaluation": {"accepted": ["X"]}}, "question's options"),
        ("ENUM_MATCH", "ENUM", {"evaluation": {"accepted": ["A", "B"]}}, "collect only"),
    ],
)
def test_rule_configuration_rejects_incompatible_rules(
    method: str, atype: str, kw: dict[str, Any], message: str
) -> None:
    with pytest.raises(ae.RuleInvalid, match=message):
        ae.configure(method, atype, ["A", "B"], **kw)


def test_rule_configuration_stores_structured_rules() -> None:
    assert ae.configure("EXACT_BOOLEAN", "YES_NO", [], expected_boolean=False) == ({"value": False}, None)
    stored, fact = ae.configure(
        "NUMERIC_MATCH_POLICY_FACT",
        "NUMERIC",
        [],
        fact_key="premium_amount",
        evaluation={"tolerance": "2.50", "tolerance_reference": "SYN-TOL-9"},
    )
    assert fact == "premium_amount" and stored == {
        "operator": "EQ",
        "unit": "SGD",
        "tolerance": "2.5",
        "tolerance_reference": "SYN-TOL-9",
    }
    assert ae.configure("ENUM_MATCH_POLICY_FACT", "ENUM", ["MONTHLY", "ANNUAL"], fact_key="premium_frequency") == (
        None,
        "premium_frequency",
    )
    assert ae.configure("NARRATIVE_REVIEW", "FREE_TEXT", []) == (None, None)
