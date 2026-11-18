"""S2-E scenario runner (pure) over the S2-D / S2-D.1 controller: every scenario kind the owner listed (normal,
identity failure, consent refusal, recording refusal, missing disclosure, mandatory refusal, interruption, callback
request, attempted gate bypass), explained failures, strict and invalid scenarios, deterministic replay, coverage
accuracy and version comparison."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from app.domain import question_controller as qc
from app.domain import scenario_runner as sr
from tests.test_conversation_lifecycle import CONTENT, item, sec

# The S2-D.1 lifecycle script plus a conditional ILP module (included only when is_ilp is true).
SCRIPT = copy.deepcopy(CONTENT)
SCRIPT["sections"].append(
    {
        **sec("ILP", "PRODUCT", 7, item("Q-ILP-CHARGES", "YES_NO", 1)),
        "inclusion_condition": {"fact": "is_ilp", "equals": True},
    }
)
NORMAL_SEQUENCE = [
    "Q-OPEN",
    "Q-ID-NAME",
    "Q-ID-DOB",
    "Q-DISC",
    "Q-PROCEED",
    "Q-REC",
    "Q-CLOUD",
    "Q-POLICY-SUMMARY",
    "Q-TERM",
    "Q-CLOSE",
]


def plan(content: dict[str, Any] = SCRIPT, facts: dict[str, Any] | None = None) -> qc.Plan:
    return qc.build_plan(
        content, script_label="LC v1", manifest_sha256="c" * 64, facts=facts or {"is_ilp": False}, band="LOW"
    )


def run(steps: list[dict[str, Any]], exp: dict[str, Any], default: str = "AFFIRMATIVE", **kw: Any) -> sr.Execution:
    return sr.execute(plan(**kw), steps, exp, default)


def ans(code: str, value: Any) -> dict[str, Any]:
    return {"question": code, "kind": "ANSWER", "value": value}


def test_normal_conversation_passes_and_reports_actual() -> None:
    ex = run(
        [ans("Q-TERM", 12)],
        {
            "outcome": "COMPLETED",
            "termination_reason": "NONE",
            "mandatory_complete": True,
            "gates": {"identity": "CONFIRMED", "willingness": "AGREED"},
            "sequence": NORMAL_SEQUENCE,
            "applicable_questions": NORMAL_SEQUENCE,
        },
    )
    assert ex.status == "PASSED", ex.failures
    assert ex.actual["identity_simulated"] and ex.actual["compliance_outcome"] == "NOT_EVALUATED"
    assert ex.actual["question_states"]["Q-ILP-CHARGES"] == "SKIPPED_BY_CONDITION"
    assert [x["by"] for x in ex.log].count("step 1") == 1  # one scripted response, the rest default


@pytest.mark.parametrize(
    ("steps", "outcome", "reason", "gates"),
    [
        ([ans("Q-ID-NAME", False)], "TERMINATED", "IDENTITY_FAILED", {"identity": "FAILED"}),
        (
            [{"question": "Q-ID-DOB", "kind": "UNCLEAR"}, {"question": "Q-ID-DOB", "kind": "UNCLEAR"}],
            "TERMINATED",
            "IDENTITY_INCONCLUSIVE",
            {"identity": "INCONCLUSIVE"},
        ),
        ([ans("Q-PROCEED", False)], "TERMINATED", "DECLINED_TO_PROCEED", {"willingness": "DECLINED"}),
        ([ans("Q-REC", False)], "COMPLETED", "NONE", {"recording_consent": "DECLINED", "willingness": "AGREED"}),
        (
            [{"question": "Q-DISC", "kind": "NOT_DELIVERED"}, {"question": "Q-DISC", "kind": "NOT_DELIVERED"}],
            "TERMINATED",
            "MANDATORY_DISCLOSURE_NOT_DELIVERED",
            {"identity": "CONFIRMED"},
        ),
        ([{"question": "Q-TERM", "kind": "REFUSED"}], "INCOMPLETE", "NONE", {"identity": "CONFIRMED"}),
        ([{"question": "Q-PROCEED", "kind": "EVENT", "event": "INTERRUPTED"}], "TERMINATED", "INTERRUPTED", {}),
        (
            [{"question": "Q-POLICY-SUMMARY", "kind": "EVENT", "event": "CALLBACK_REQUESTED"}],
            "TERMINATED",
            "CALLBACK_REQUESTED",
            {"willingness": "CALLBACK_REQUESTED"},
        ),
        (
            [{"question": "Q-ID-NAME", "kind": "EVENT", "event": "WRONG_PERSON"}],
            "TERMINATED",
            "WRONG_PERSON",
            {"identity": "WRONG_PERSON"},
        ),
    ],
    ids=[
        "identity-failed",
        "identity-inconclusive",
        "consent-refused",
        "recording-refused",
        "missing-disclosure",
        "mandatory-refused",
        "interrupted",
        "callback-requested",
        "wrong-person",
    ],
)
def test_each_lifecycle_scenario_passes_its_expectations(
    steps: list[dict[str, Any]], outcome: str, reason: str, gates: dict[str, str]
) -> None:
    ex = run(steps, {"outcome": outcome, "termination_reason": reason, "gates": gates})
    assert ex.status == "PASSED", ex.failures
    if reason in ("IDENTITY_FAILED", "WRONG_PERSON", "IDENTITY_INCONCLUSIVE"):
        assert "Q-POLICY-SUMMARY" not in ex.actual["sequence"]  # nothing disclosed before identity
    if reason == "INTERRUPTED":
        assert "Q-CLOSE" not in ex.actual["sequence"]
    if outcome == "INCOMPLETE":
        assert ex.actual["mandatory_unresolved"] == ["Q-TERM"] and not ex.actual["mandatory_complete"]


def test_failures_are_explained_in_plain_language() -> None:
    ex = run(
        [ans("Q-ID-NAME", False)],
        {
            "outcome": "COMPLETED",
            "gates": {"identity": "CONFIRMED"},
            "mandatory_complete": True,
            "question_states": {"Q-POLICY-SUMMARY": "COMPLETED"},
            "sequence": NORMAL_SEQUENCE,
        },
    )
    assert ex.status == "FAILED"
    messages = {f["check"]: f["message"] for f in ex.failures}
    assert "expected completed, got terminated — Identity failed at Q-ID-NAME" in messages["outcome"]
    assert messages["gate:identity"] == "Gate identity (simulated): expected confirmed, got failed"
    assert messages["sequence"].startswith("Question sequence differs at position 3: expected Q-ID-DOB, asked Q-CLOSE")
    assert "expected completed, got pending" in messages["question:Q-POLICY-SUMMARY"]


def test_attempted_gate_bypass_cannot_reach_policy_information() -> None:
    # Steps that try to answer the policy-disclosing item first: the controller still asks identity first.
    ex = run(
        [ans("Q-POLICY-SUMMARY", True), ans("Q-ID-NAME", False)],
        {"outcome": "TERMINATED", "termination_reason": "IDENTITY_FAILED"},
        default="AFFIRMATIVE",
    )
    assert ex.status == "FAILED"
    seq = ex.actual["sequence"]
    assert seq.index("Q-POLICY-SUMMARY") > seq.index("Q-ID-DOB")  # still only after identity was confirmed
    assert ex.actual["gates"]["identity"] == "CONFIRMED"
    assert any("Step 2 (Q-ID-NAME: answer no) was never reached" in f["message"] for f in ex.failures)
    # Without an identity gate, the policy-disclosing item is withheld whatever the scenario says.
    no_id = {"sections": [s for s in SCRIPT["sections"] if s["module_kind"] != "IDENTITY"]}
    ex2 = sr.execute(plan(no_id), [], {"question_states": {"Q-POLICY-SUMMARY": "COMPLETED"}})
    assert ex2.status == "FAILED" and ex2.actual["blocked_by_identity_gate"] == ["Q-POLICY-SUMMARY"]
    assert "BLOCKED_BY_IDENTITY_GATE" in ex2.failures[0]["message"]


def test_strict_invalid_and_error_scenarios() -> None:
    strict = run([ans("Q-ID-NAME", True)], {}, default="STRICT")
    assert strict.status == "ERROR" and strict.error and "No scripted response for Q-OPEN" in strict.error
    with pytest.raises(sr.ScenarioInvalid) as e:
        run(
            [
                ans("Q-NOT-THERE", True),
                {"question": "Q-OPEN", "kind": "UNCLEAR"},
                {"question": "Q-TERM", "kind": "DELIVERED"},
            ],
            {"question_states": {"Q-GONE": "COMPLETED"}},
        )
    assert len(e.value.problems) == 4 and "Q-NOT-THERE is not in this script version" in e.value.problems[0]
    bad = run([ans("Q-TERM", "twelve")], {})
    assert bad.status == "ERROR" and bad.error and bad.error.startswith("INVALID_ANSWER")


def test_execution_is_deterministic() -> None:
    steps = [
        {"question": "Q-ID-NAME", "kind": "CLARIFICATION", "note": "Who is calling?"},
        ans("Q-REC", False),
        {"question": "Q-TERM", "kind": "UNKNOWN"},
    ]
    a, b = run(steps, {"outcome": "INCOMPLETE"}), run(steps, {"outcome": "INCOMPLETE"})
    assert a.status == b.status == "PASSED"
    assert a.events == b.events and a.actual == b.actual and a.log == b.log


def test_coverage_is_structural_and_accurate() -> None:
    p = plan()
    runs = [run([], {}).actual, run([ans("Q-ID-NAME", False)], {}).actual, run([], {}, facts={"is_ilp": True}).actual]
    cov = sr.coverage(p, runs)
    assert cov["runs"] == 3 and cov["questions_total"] == 11
    assert set(cov["questions_exercised"]) == {*NORMAL_SEQUENCE, "Q-ILP-CHARGES"}
    assert cov["questions_not_exercised"] == []
    assert cov["conditional_modules"] == ["ILP"] and cov["conditional_modules_exercised"] == ["ILP"]
    assert {"NORMAL_COMPLETION", "IDENTITY_FAILED"} <= set(cov["lifecycle_paths_exercised"])
    assert "DECLINED_TO_PROCEED" in cov["lifecycle_paths_not_exercised"]
    assert cov["mandatory_never_completed"] == [] and "not a measure of compliance" in cov["note"]
    # Declined consent paths follow each item's configured failure behaviour (continued vs terminated).
    assert "RECORDING_CONSENT_DECLINED_CONTINUED" in cov["lifecycle_paths_possible"]
    assert "RECORDING_CONSENT_DECLINED" not in cov["lifecycle_paths_possible"]
    declined = sr.coverage(p, [run([ans("Q-REC", False)], {}).actual])
    assert "RECORDING_CONSENT_DECLINED_CONTINUED" in declined["lifecycle_paths_exercised"]
    only_fail = sr.coverage(p, [run([ans("Q-ID-NAME", False)], {}).actual])
    assert "Q-TERM" in only_fail["questions_not_exercised"] and "ILP" in only_fail["conditional_modules_not_exercised"]
    assert "Q-TERM" in only_fail["mandatory_never_completed"]


def test_version_comparison_reports_applicability_order_and_outcome_differences() -> None:
    b_content = copy.deepcopy(SCRIPT)
    core = next(s for s in b_content["sections"] if s["module_code"] == "CORE")
    core["questions"] = [q for q in core["questions"] if q["question_code"] != "Q-TERM"]  # removed in B
    core["questions"].append(item("Q-NEW", "YES_NO", 3, mandatory=False))
    pa, pb = plan(), plan(b_content)
    d = sr.plan_diff(pa, pb)
    assert d["only_in_a"] == ["Q-TERM"] and d["only_in_b"] == ["Q-NEW"]
    assert d["applicable_only_in_a"] == ["Q-TERM"] and not d["order_changed"]
    steps = [{"question": "Q-TERM", "kind": "REFUSED"}]
    a = sr.execute(pa, steps, {})
    with pytest.raises(sr.ScenarioInvalid):  # the scenario refers to a question B no longer has
        sr.execute(pb, steps, {})
    b = sr.execute(pb, [], {})
    diff = {x["field"] for x in sr.outcome_diff(a.actual, b.actual)}
    assert {"outcome", "mandatory_complete", "sequence", "mandatory_unresolved"} <= diff
