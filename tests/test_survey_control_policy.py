# ruff: noqa: E501, F811
"""EVAL-2A — governed control policies, applicability and coverage of SYNTHETIC journeys: real HTTP, real PostgreSQL
(``call360_test``), and the pure engine for the truth tables.

Every control, obligation, condition, mapping, rule and severity here is a TEST FIXTURE on the seeded synthetic
register. None is an insurance obligation, and nothing is established about a real application."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain.survey import control_evaluation as ce
from app.domain.survey import policy_evaluation as pe
from app.domain.survey import simulation as simulation_module
from app.main import create_app
from tests.support import make_account
from tests.survey_support import fixture_bundle
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import compose, group
from tests.test_survey_evaluation import (
    ACK,
    ALL,
    BOOL_YES,
    K8_FACTS,
    RULES_V1,
    SETTINGS_ON,
    YES,
    _control,
    _entry,
    _execution,
    _journey,
    _mapping,
    control,
    entry,
    evaluate,
    items_of,
    mapped,
    publish_finding_rules,
    rule,
    simulate,
)  # fmt: skip
from tests.test_survey_lib1 import build, draft, empty_survey, pin_module, publish
from tests.test_survey_simulation import give, start

E = "/api/v1/survey-evaluation"
A = "/api/v1/survey-assignment"
SG = {"field": "market", "values": ["SG"]}
ON = SETTINGS_ON | {"survey_control_policy_enabled": True}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(settings.model_copy(update=ON))
    with_grants(app)
    return app


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL
    return _trio


# ----------------------------------------------------------------------------------------------- building a policy
def ev(key: str, kind: str = "ANSWER", required: bool = True, description: str = "") -> dict[str, Any]:
    return {
        "key": key,
        "description": description or f"Synthetic evidence {key}",
        "evidence_type": kind,
        "required": required,
    }


def ob(
    key: str,
    evidence: list[dict[str, Any]],
    applicability: dict[str, Any] | None = None,
    combination: str = "ALL_REQUIRED",
) -> dict[str, Any]:
    return {
        "key": key,
        "title": f"Synthetic obligation {key}",
        "applicability": applicability,
        "combination": combination,
        "evidence": evidence,
    }


def pc(code: str, obligations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "control_code": code,
        "purpose": f"Synthetic purpose of {code} for the tests",
        "description": "",
        "obligations": obligations,
    }


def policy_body(controls: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    return {
        "market_code": "SG", "code": "POL-TEST", "name": "Synthetic test policy", "scope_statement": "Synthetic applications of the tests only",
        "scope": None, "completeness": "DECLARED_COMPLETE", "empty_set_is_complete": False, "controls": controls,
        "owner": "Test owner (synthetic)", "source": "Synthetic test policy; not a business policy",
    } | over  # fmt: skip


def published_policy(people: Any, body: dict[str, Any]) -> dict[str, Any]:
    r = post(people[0], f"{E}/control-policies", body)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert post(people[1], f"{E}/control-policies/{pid}/decision", {"verdict": "APPROVE"}).status_code == 200
    r = post(people[2], f"{E}/control-policies/{pid}/publish")
    assert r.status_code == 200, r.text
    return r.json()


def under(
    c: TestClient,
    policy_id: str,
    *,
    simulation_id: str | None = None,
    coordinated: str | None = None,
    expect: int = 201,
) -> dict[str, Any]:
    r = post(
        c,
        f"{E}/evaluations",
        {"simulation_id": simulation_id, "coordinated_simulation_id": coordinated, "control_policy_id": policy_id},
    )
    assert r.status_code == expect, r.text
    return r.json()


def instance(e: dict[str, Any], code: str, obligation: str) -> dict[str, Any]:
    return next(c for c in e["controls"] if c["control_code"] == code and c["obligation"] == obligation)


def cover(e: dict[str, Any]) -> dict[str, str]:
    return {f"{c['control_code']}/{c['obligation']}": c["coverage"] for c in e["controls"]}


# ------------------------------------------------------------------------------------------- pure: the truth tables
def _doc(controls: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    """A policy in the stored shape, for the pure engine (no database)."""
    out = []
    for c in controls:
        row = _control(c["control_code"])
        out.append(
            {
                "control": {
                    "code": row["control_code"],
                    "id": str(row["id"]),
                    "sha256": ce.control_sha256(row),
                    "name": row["name"],
                },
                "purpose": c["purpose"],
                "description": "",
                "obligations": c["obligations"],
            }
        )
    doc = {
        "id": uuid.uuid5(uuid.NAMESPACE_URL, "pol"),
        "code": "POL",
        "revision": 1,
        "name": "p",
        "scope_statement": "synthetic",
        "scope": None,
        "completeness": "DECLARED_COMPLETE",
        "empty_set_is_complete": False,
        "controls": out,
    } | over
    return doc | {"policy_sha256": ce.sha256_hex({k: v for k, v in doc.items() if k != "id"})}


def _bound(item: str, rule: dict[str, Any] | None, requirement: str, obligation: str | None = None) -> dict[str, Any]:
    return _entry(item, rule) | {"requirement": requirement} | ({"obligation": obligation} if obligation else {})


K1 = {p["key"]: p["item_code"] for p in ce.placements(fixture_bundle("K1"))}
K8 = fixture_bundle("K8")
OLDER = {
    "condition": {"code": "C-OLDER", "version": 1},
    "ast": next(c for c in K8.conditions.values() if c["code"] == "C-OLDER")["ast"],
    "params": {"minimum_age": 60},
}
YES_RUN = [("mi-call/n2", {"choice": "YES"}), ("mi-call/n5", {"choice": "YES"})]


def _instance(
    result: str | None, *, required: bool = True, conflict: bool = False
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    obs = [] if result is None else [{"required": required, "result": result}]
    reasons = [{"code": "EVIDENCE_CONFLICT"}] if conflict else []
    outcome = (
        "REQUIRES_REVIEW"
        if conflict
        else "SATISFIED"
        if result in ("MATCH", "DELIVERED")
        else "NOT_SATISFIED"
        if result == "MISMATCH"
        else "INSUFFICIENT_EVIDENCE"
    )
    return outcome, reasons, obs


@pytest.mark.parametrize(
    ("result", "conflict", "expected"),
    [
        ("MATCH", False, "EVIDENCED"), ("DELIVERED", False, "EVIDENCED"),
        ("MISMATCH", False, "EVIDENCED"),  # evidence exists and is deterministic: coverage is not about the result
        ("NOT_ASKED", False, "EVIDENCE_MISSING"), ("UNRESOLVED", False, "EVIDENCE_MISSING"), ("NOT_DELIVERED", False, "EVIDENCE_MISSING"),
        ("MISSING_EXPECTED_FACT", False, "EVIDENCE_MISSING"), ("NOT_APPLICABLE", False, "EVIDENCE_MISSING"),
        ("UNSUPPORTED_EVIDENCE", False, "EVALUATION_UNSUPPORTED"), ("NOT_EVALUATED", False, "EVALUATION_UNSUPPORTED"),
        ("HUMAN_ASSESSMENT_REQUIRED", False, "HUMAN_ASSESSMENT_PENDING"),
        ("MATCH", True, "EVIDENCE_CONFLICTING"), ("NOT_ASKED", True, "EVIDENCE_CONFLICTING"),
        (None, False, "EVALUATION_UNSUPPORTED"),  # no required evidence at all is never 'evidenced'
    ],
)  # fmt: skip
def test_instance_coverage_truth_table(result: str | None, conflict: bool, expected: str) -> None:
    outcome, reasons, obs = _instance(result, conflict=conflict)
    assert pe.instance_coverage(outcome, reasons, obs) == expected
    # a mismatch beside a gap: the evidence is not complete, whatever the control outcome says
    if result == "MISMATCH":
        both = [{"required": True, "result": "MISMATCH"}, {"required": True, "result": "NOT_ASKED"}]
        assert pe.instance_coverage("NOT_SATISFIED", [], both) == "EVIDENCE_MISSING"


def _cov(*coverages: str) -> list[dict[str, Any]]:
    return [{"control_code": f"C{n}", "obligation": "O", "coverage": c} for n, c in enumerate(coverages)]


COMPLETE = {"completeness": "DECLARED_COMPLETE", "empty_set_is_complete": False}
JOURNEY_TABLE: list[tuple[str, dict[str, Any], str, bool, list[str], str, str]] = [
    ("every required instance evidenced", COMPLETE, "IN_SCOPE", True, ["EVIDENCED", "EVIDENCED", "NOT_REQUIRED"], "COMPLETE_WITHIN_POLICY_SCOPE", "ALL_REQUIRED_EVIDENCED"),
    ("one required instance has no mapping", COMPLETE, "IN_SCOPE", True, ["EVIDENCED", "NOT_MAPPED"], "INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED"),
    ("evidence missing", COMPLETE, "IN_SCOPE", True, ["EVIDENCED", "EVIDENCE_MISSING"], "INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED"),
    ("conflicting evidence", COMPLETE, "IN_SCOPE", True, ["EVIDENCE_CONFLICTING"], "INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED"),
    ("evaluation unsupported", COMPLETE, "IN_SCOPE", True, ["EVALUATION_UNSUPPORTED"], "INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED"),
    ("human assessment pending", COMPLETE, "IN_SCOPE", True, ["EVIDENCED", "HUMAN_ASSESSMENT_PENDING"], "INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED"),
    ("applicability unknown: the required set is not known", COMPLETE, "IN_SCOPE", True, ["EVIDENCED", "APPLICABILITY_UNKNOWN"], "INCOMPLETE", "APPLICABILITY_UNKNOWN"),
    ("a PARTIAL policy never asserts completeness", {"completeness": "PARTIAL", "empty_set_is_complete": False}, "IN_SCOPE", True, ["EVIDENCED"], "NOT_ASSERTED", "POLICY_PARTIAL"),
    ("outside the policy's scope", COMPLETE, "OUT_OF_SCOPE", True, ["EVIDENCED"], "NOT_ASSERTED", "OUT_OF_POLICY_SCOPE"),
    ("scope unknown", COMPLETE, "UNKNOWN", True, ["EVIDENCED"], "NOT_ASSERTED", "POLICY_SCOPE_UNKNOWN"),
    ("evidence not trusted", COMPLETE, "IN_SCOPE", False, ["INTEGRITY_FAILED"], "NOT_ASSERTED", "EVIDENCE_NOT_TRUSTED"),
    ("nothing applies: not complete by default", COMPLETE, "IN_SCOPE", True, ["NOT_REQUIRED", "NOT_REQUIRED"], "NOT_ASSERTED", "EMPTY_APPLICABLE_SET"),
    ("nothing applies, and the policy says that is complete", COMPLETE | {"empty_set_is_complete": True}, "IN_SCOPE", True, ["NOT_REQUIRED"], "COMPLETE_WITHIN_POLICY_SCOPE", "EMPTY_SET_DECLARED_COMPLETE"),
    ("partial beats everything but trust", {"completeness": "PARTIAL", "empty_set_is_complete": True}, "IN_SCOPE", True, ["NOT_REQUIRED"], "NOT_ASSERTED", "POLICY_PARTIAL"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("name", "policy", "scope", "trusted", "coverages", "status", "reason"),
    JOURNEY_TABLE,
    ids=[t[0] for t in JOURNEY_TABLE],
)
def test_journey_coverage_truth_table(
    name: str, policy: dict[str, Any], scope: str, trusted: bool, coverages: list[str], status: str, reason: str
) -> None:
    got = pe.journey_coverage(policy, scope, trusted, _cov(*coverages))
    assert (got["status"], got["reason"]) == (status, reason), name
    assert got["required"] == sum(c not in ("NOT_REQUIRED", "APPLICABILITY_UNKNOWN") for c in coverages)
    assert [g["coverage"] for g in got["gaps"]] == [c for c in coverages if c not in ("EVIDENCED", "NOT_REQUIRED")]
    assert "not mean the controls are satisfied" in got["note"]


def test_obligations_are_the_control_instances_and_coverage_is_never_inferred() -> None:
    """Engine level: instances come from the POLICY, not from what happened to be mapped."""
    a, b, c = (
        pc("CTRL-A", [ob("ID", [ev("E-ID")]), ob("SENIOR", [ev("E-ACK")], OLDER)]),
        pc("CTRL-B", [ob("MAIN", [ev("E-Q5")])]),
        pc("CTRL-C", [ob("MAIN", [ev("E-X")])]),
    )
    policy = _doc([a, b, c])
    controls = [_control(x) for x in ("CTRL-A", "CTRL-B", "CTRL-C", "CTRL-OUTSIDE")]
    m = {
        "CTRL-A": _mapping(
            controls[0],
            [_bound(K1["mi-call/n2"], BOOL_YES, "E-ID", "ID"), _bound(K1["mi-call/n5"], BOOL_YES, "E-ACK", "SENIOR")],
        ),
        "CTRL-B": _mapping(controls[1], [_bound(K1["mi-call/n5"], BOOL_YES, "E-Q5")]),
    }  # CTRL-C: required by the policy, mapped by nobody
    yes = _execution(1, "K1", YES_RUN)

    # ---- every question of the survey was answered, the survey COMPLETED — and coverage is INCOMPLETE
    r = pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 70}), controls, m, None, policy)
    assert yes["state"] == "COMPLETED" and [
        (i["control_code"], i["obligation"], i["outcome"], i["coverage"]) for i in r["controls"]
    ] == [
        ("CTRL-A", "ID", "SATISFIED", "EVIDENCED"),
        ("CTRL-A", "SENIOR", "SATISFIED", "EVIDENCED"),  # 9. two obligations of ONE control are two results
        ("CTRL-B", "MAIN", "SATISFIED", "EVIDENCED"),
        ("CTRL-C", "MAIN", "UNRESOLVED", "NOT_MAPPED"),  # 5. required and missing, found without any mapping
    ]
    assert (
        r["coverage"]["status"],
        r["coverage"]["reason"],
        r["coverage"]["required"],
        r["coverage"]["evidenced"],
    ) == ("INCOMPLETE", "REQUIRED_CONTROLS_NOT_EVIDENCED", 4, 3)
    assert r["coverage"]["gaps"] == [{"control_code": "CTRL-C", "obligation": "MAIN", "coverage": "NOT_MAPPED"}]
    assert instance_of(r, "CTRL-C", "MAIN")["reasons"][0]["code"] == "MAPPING_MISSING" and r["coverage"][
        "controls_outside_policy"
    ] == ["CTRL-OUTSIDE"]
    assert (
        r["operational_compliance_eligibility"]["status"] == "NOT_ESTABLISHED"
        and r["applicability"]["input_lineage"]["status"] == "UNVERIFIED"
    )
    # the same item (n5) serves two controls: two instances, each with its own observation — nothing is merged
    assert (
        instance_of(r, "CTRL-A", "SENIOR")["observations"][0]["placement"]
        == instance_of(r, "CTRL-B", "MAIN")["observations"][0]["placement"]
        == "mi-call/n5"
    )

    # ---- 3, 4. applicability comes from the application's facts; unknown stays unknown and names what is missing
    young = pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 40}), controls, m, None, policy)
    assert (instance_of(young, "CTRL-A", "SENIOR")["outcome"], instance_of(young, "CTRL-A", "SENIOR")["coverage"]) == (
        "NOT_APPLICABLE",
        "NOT_REQUIRED",
    )
    unknown = pe.evaluate_under_policy(_journey([yes]), controls, m, None, policy)
    s = instance_of(unknown, "CTRL-A", "SENIOR")
    assert (s["outcome"], s["coverage"], s["reasons"][0]["code"], s["applicability"]["missing"]) == (
        "UNRESOLVED",
        "APPLICABILITY_UNKNOWN",
        "APPLICABILITY_UNKNOWN",
        ["customer.age_years"],
    )
    assert unknown["applicability"]["missing_inputs"] == ["customer.age_years"] and unknown["coverage"]["reason"] in (
        "REQUIRED_CONTROLS_NOT_EVIDENCED",
        "APPLICABILITY_UNKNOWN",
    )
    assert len(s["observations"]) == 1  # the evidence that exists is still shown
    # the determination has a fingerprint: same policy and facts, same fingerprint; other facts, another
    d1, d2 = pe.determine(policy, {"customer.age_years": 70}), pe.determine(policy, {"customer.age_years": 70})
    assert d1 == d2 and d1["fingerprint"] != pe.determine(policy, {"customer.age_years": 40})["fingerprint"]
    assert (
        d1["counts"] == {"APPLICABLE": 4, "NOT_APPLICABLE": 0, "UNKNOWN": 0}
        and r["applicability"]["fingerprint"] == d1["fingerprint"]
    )

    # ---- 6, 7. a complete, scoped policy can be covered; the same content declared PARTIAL can never assert it
    full_map = m | {"CTRL-C": _mapping(controls[2], [_bound(K1["mi-call/n2"], BOOL_YES, "E-X")])}
    done = pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 70}), controls, full_map, None, policy)
    assert (done["coverage"]["status"], done["processing_status"], done["summary"]["by_outcome"]["SATISFIED"]) == (
        "COMPLETE_WITHIN_POLICY_SCOPE",
        "COMPLETED",
        4,
    )
    assert (
        "not a statement that they are satisfied" in done["coverage"]["explanation"]
        and done["operational_compliance_eligibility"]["status"] == "NOT_ESTABLISHED"
    )
    partial = pe.evaluate_under_policy(
        _journey([yes], facts={"customer.age_years": 70}),
        controls,
        full_map,
        None,
        _doc([a, b, c], completeness="PARTIAL"),
    )
    assert (
        partial["coverage"]["status"],
        partial["coverage"]["reason"],
        partial["summary"]["by_outcome"]["SATISFIED"],
    ) == ("NOT_ASSERTED", "POLICY_PARTIAL", 4)
    # complete coverage with a control NOT satisfied: coverage is about evidence, not about results
    no = _execution(1, "K1", [("mi-call/n2", {"choice": "NO"})])
    wrong = pe.evaluate_under_policy(
        _journey([no]),
        controls,
        {"CTRL-B": _mapping(controls[1], [_bound(K1["mi-call/n2"], BOOL_YES, "E-Q5")])},
        None,
        _doc([b]),
    )
    assert (wrong["controls"][0]["outcome"], wrong["coverage"]["status"]) == (
        "NOT_SATISFIED",
        "COMPLETE_WITHIN_POLICY_SCOPE",
    )
    # the policy's own scope
    scoped = _doc([b], scope=OLDER)
    assert (
        pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 40}), controls, m, None, scoped)[
            "coverage"
        ]["reason"]
        == "OUT_OF_POLICY_SCOPE"
    )
    assert (
        pe.evaluate_under_policy(_journey([yes]), controls, m, None, scoped)["coverage"]["reason"]
        == "POLICY_SCOPE_UNKNOWN"
    )
    # nothing applies
    none = _doc([pc("CTRL-B", [ob("MAIN", [ev("E-Q5")], OLDER)])])
    assert (
        pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 40}), controls, m, None, none)[
            "coverage"
        ]["reason"]
        == "EMPTY_APPLICABLE_SET"
    )

    # ---- inconsistent or incomplete mappings are found, and never counted
    for entries, code in (
        ([_entry(K1["mi-call/n5"], BOOL_YES)], "MAPPING_ENTRY_NOT_BOUND"),  # an EVAL-1 mapping names no requirement
        ([_bound(K1["mi-call/n5"], BOOL_YES, "E-GONE")], "MAPPING_ENTRY_NOT_IN_POLICY"),
        ([_bound(K1["mi-call/n5"], None, "E-Q5")], "MAPPING_EVIDENCE_TYPE_DIFFERS"),
    ):
        bad = pe.evaluate_under_policy(
            _journey([yes]), controls, {"CTRL-B": _mapping(controls[1], entries)}, None, _doc([b])
        )
        line = bad["controls"][0]
        assert (line["outcome"], line["coverage"]) == ("UNRESOLVED", "NOT_MAPPED") and code in [
            x["code"] for x in line["reasons"]
        ], code
    two = _doc([pc("CTRL-B", [ob("MAIN", [ev("E-Q5"), ev("E-OTHER"), ev("E-OPT", required=False)])])])
    half = pe.evaluate_under_policy(_journey([yes]), controls, m, None, two)["controls"][0]
    assert [x["code"] for x in half["reasons"]] == ["REQUIRED_EVIDENCE_NOT_MAPPED"] and half["reasons"][0][
        "requirement"
    ] == "E-OTHER"
    assert [(q["key"], q["status"]) for q in half["requirements"]] == [
        ("E-Q5", "MAPPED"),
        ("E-OTHER", "NOT_MAPPED"),
        ("E-OPT", "NOT_MAPPED"),
    ]
    assert (
        half["observations"][0]["result"] == "MATCH" and half["coverage"] == "NOT_MAPPED"
    )  # what IS mapped is shown, and it is not enough
    # 'required' is the POLICY's: a mapping cannot make required evidence optional
    opt = pe.evaluate_under_policy(
        _journey([_execution(1, "K1", [])]),
        controls,
        {"CTRL-B": _mapping(controls[1], [_bound(K1["mi-call/n5"], BOOL_YES, "E-Q5") | {"required": False}])},
        None,
        _doc([b]),
    )
    assert (
        opt["controls"][0]["observations"][0]["required"] is True
        and opt["controls"][0]["outcome"] == "INSUFFICIENT_EVIDENCE"
    )
    # integrity: nothing is asserted
    broken = pe.evaluate_under_policy(
        _journey([yes], trusted=False, problems=[{"code": "REPLAY_DRIFT"}]), controls, full_map, None, policy
    )
    assert {i["coverage"] for i in broken["controls"]} == {"INTEGRITY_FAILED"} and (
        broken["coverage"]["reason"],
        broken["processing_status"],
    ) == ("EVIDENCE_NOT_TRUSTED", "FAILED_TECHNICALLY")
    # a control changed in the register after the policy was governed
    renamed = [controls[0], controls[1] | {"name": "Renamed"}, controls[2], controls[3]]
    assert (
        instance_of(pe.evaluate_under_policy(_journey([yes]), renamed, m, None, policy), "CTRL-B", "MAIN")["reasons"][
            0
        ]["code"]
        == "CONTROL_CHANGED_SINCE_POLICY"
    )
    # deterministic
    assert pe.evaluate_under_policy(_journey([yes], facts={"customer.age_years": 70}), controls, m, None, policy) == r


def instance_of(r: dict[str, Any], code: str, obligation: str) -> dict[str, Any]:
    return next(i for i in r["controls"] if i["control_code"] == code and i["obligation"] == obligation)


def test_answer_types_are_evaluated_by_the_existing_operators_or_not_at_all() -> None:
    """Step 8: every Survey Studio answer type against the EXISTING evaluator. Nothing new judges anything."""
    c = _control("CTRL-A")
    rules = fe.RuleSet.of(
        "11111111-1111-1111-1111-111111111111",
        "test rules",
        "PUBLISHED",
        fe.normalise_rules([rule("FR-NARRATIVE", "HUMAN_ASSESSMENT_REQUIRED", "NARRATIVE_REVIEW", "LOW")]),
    )

    def one(
        prefix: str, key: str, answers: list[tuple[str, dict[str, Any]]], rule_: dict[str, Any] | None
    ) -> dict[str, Any]:
        items = {p["key"]: p for p in ce.placements(fixture_bundle(prefix))}
        r = pe.evaluate_under_policy(
            _journey([_execution(1, prefix, answers)]),
            [c],
            {"CTRL-A": _mapping(c, [_bound(items[key]["item_code"], rule_, "E")])},
            rules,
            _doc([pc("CTRL-A", [ob("MAIN", [ev("E", "ANSWER" if rule_ else "DELIVERY")])])]),
        )
        return r["controls"][0] | {"findings_list": r["findings"]}

    # yes/no, acknowledgement, numeric: as in EVAL-1
    assert one("K1", "mi-call/n2", YES_RUN, BOOL_YES)["observations"][0]["result"] == "MATCH"
    assert one("K4", "mi-ack/n2", [("mi-ack/n2", {"acknowledged": True})], ACK)["coverage"] == "EVIDENCED"
    number = {
        "method": "NUMERIC_COMPARE",
        "answer_type": "NUMERIC",
        "options": [],
        "expected": {"operator": "GTE", "unit": "COUNT", "tolerance": "0", "tolerance_reference": None, "value": "18"},
        "fact_key": None,
    }
    assert (
        one("K3", "mi-numbers/n1", [("mi-numbers/n1", {"number": 20})], number)["observations"][0]["evaluation"][
            "method"
        ]
        == "NUMERIC_COMPARE"
    )
    # single choice: the existing ENUM_MATCH, with the question's own options
    choice = {
        "method": "ENUM_MATCH",
        "answer_type": "ENUM",
        "options": ["PREMIUM", "BENEFITS", "CLAIMS", "NONE"],
        "expected": {"accepted": ["NONE"]},
        "fact_key": None,
    }
    picked = one("F3", "mi-concerns/n1", [("mi-concerns/n1", {"choice": "BENEFITS"})], choice)
    assert (picked["observations"][0]["result"], picked["outcome"], picked["coverage"]) == (
        "MISMATCH",
        "NOT_SATISFIED",
        "EVIDENCED",
    )
    assert (
        picked["observations"][0]["evaluation"]["normalized_answer"] == "BENEFITS"
        and "expected NONE" in picked["observations"][0]["explanation"]
    )
    assert one("F3", "mi-concerns/n1", [("mi-concerns/n1", {"choice": "NONE"})], choice)["outcome"] == "SATISFIED"
    # free text: never judged automatically — the existing NARRATIVE_REVIEW hands it to a person
    narrative = {
        "method": "NARRATIVE_REVIEW",
        "answer_type": "FREE_TEXT",
        "options": [],
        "expected": None,
        "fact_key": None,
    }
    f1 = [
        ("mi-general/n1", {"choice": "YES"}),
        ("mi-general/n2", {"choice": "YES"}),
        ("mi-general/n3", {"text": "The representative was clear."}),
    ]
    text_ = one("F1", "mi-general/n3", f1, narrative)
    assert (text_["observations"][0]["result"], text_["outcome"], text_["coverage"]) == (
        "HUMAN_ASSESSMENT_REQUIRED",
        "REQUIRES_REVIEW",
        "HUMAN_ASSESSMENT_PENDING",
    )
    assert [f["rule"]["rule_code"] for f in text_["findings_list"]] == [
        "FR-NARRATIVE"
    ]  # only because a governed rule says so
    blank = one("F1", "mi-general/n3", [*f1[:2], ("mi-general/n3", {"text": ""})], narrative)
    assert (blank["observations"][0]["result"], blank["observations"][0]["gap"], blank["coverage"]) == (
        "UNRESOLVED",
        "ANSWERED_BLANK",
        "EVIDENCE_MISSING",
    )
    # a statement: delivery evidence, no evaluation
    said = one("K1", "mi-call/n1", YES_RUN, None)
    assert (said["observations"][0]["result"], said["observations"][0]["evaluation"], said["coverage"]) == (
        "DELIVERED",
        None,
        "EVIDENCED",
    )
    # multiple choice: the SET_MATCH operator of the same engine (below). A kind with no method is still unsupported
    assert (
        ce.ANSWER_TYPE["MULTI_SELECT"] == "MULTI_SELECT"
        and "SET_MATCH" not in ae.METHODS
        and "SET_MATCH" in ae.ALL_METHODS
    )


# ------------------------------------------------------------------------------------------ SET_MATCH (owner, §3)
OPTS = ("PREMIUM", "BENEFITS", "CLAIMS", "CRITICAL_RISK", "NONE")


def _set_rule(mode: str, options: list[str]) -> ae.Rule:
    expected, _ = ae.configure("SET_MATCH", "MULTI_SELECT", OPTS, evaluation={"mode": mode, "options": options})
    return ae.Rule("Q-M", "Q-M@1", 1, "SET_MATCH", "MULTI_SELECT", OPTS, expected, None)


def _set(mode: str, expected: list[str], selected: Any) -> dict[str, Any]:
    answer = {"answer_kind": "ANSWER", "answer_state": "ANSWERED", "value": selected, "verbatim": None}
    return ae.evaluate_one(_set_rule(mode, expected), "COMPLETED", True, None, answer, None, ce.NO_FACTS)


SET_TABLE = [
    # mode, expected, selected, result
    ("INCLUDES_ALL", ["PREMIUM", "BENEFITS"], ["PREMIUM", "BENEFITS"], "MATCH"),
    (
        "INCLUDES_ALL",
        ["PREMIUM", "BENEFITS"],
        ["BENEFITS", "CLAIMS", "PREMIUM"],
        "MATCH",
    ),  # more than expected, any order
    ("INCLUDES_ALL", ["PREMIUM", "BENEFITS"], ["PREMIUM"], "MISMATCH"),
    ("INCLUDES_ALL", ["PREMIUM"], [], "MISMATCH"),
    ("INCLUDES_ANY", ["PREMIUM", "BENEFITS"], ["CLAIMS", "BENEFITS"], "MATCH"),
    ("INCLUDES_ANY", ["PREMIUM", "BENEFITS"], ["CLAIMS"], "MISMATCH"),
    ("INCLUDES_ANY", ["PREMIUM"], [], "MISMATCH"),
    ("INCLUDES_NONE", ["CRITICAL_RISK"], ["PREMIUM", "CLAIMS"], "MATCH"),
    ("INCLUDES_NONE", ["CRITICAL_RISK"], ["PREMIUM", "CRITICAL_RISK"], "MISMATCH"),
    ("INCLUDES_NONE", ["CRITICAL_RISK"], [], "MATCH"),  # an explicit empty selection is an answer, and it includes none
    ("EQUALS", ["PREMIUM", "BENEFITS"], ["BENEFITS", "PREMIUM"], "MATCH"),  # order never matters
    ("EQUALS", ["PREMIUM", "BENEFITS"], ["PREMIUM"], "MISMATCH"),
    ("EQUALS", ["PREMIUM", "BENEFITS"], ["PREMIUM", "BENEFITS", "CLAIMS"], "MISMATCH"),
    ("EQUALS", ["NONE"], ["NONE"], "MATCH"),
    ("EQUALS", ["NONE"], [], "MISMATCH"),
    # not a well-formed selection of the published options: never evaluated, never a match, never a mismatch
    ("INCLUDES_ANY", ["PREMIUM"], ["PREMIUM", "PREMIUM"], "UNRESOLVED"),  # duplicates are not collapsed
    ("INCLUDES_ANY", ["PREMIUM"], ["PREMIUM", "INVENTED"], "UNRESOLVED"),
    ("INCLUDES_ANY", ["PREMIUM"], "PREMIUM", "UNRESOLVED"),
    ("INCLUDES_ANY", ["PREMIUM"], [1, 2], "UNRESOLVED"),
    ("EQUALS", ["PREMIUM"], None, "UNRESOLVED"),
]


@pytest.mark.parametrize(("mode", "expected", "selected", "result"), SET_TABLE)
def test_set_match_truth_table(mode: str, expected: list[str], selected: Any, result: str) -> None:
    got = _set(mode, expected, selected)
    assert got["result"] == result and got["method"] == "SET_MATCH"
    if result in ("MATCH", "MISMATCH"):
        # the same selection in any order gives the same result and the same normalised answer
        other = _set(mode, list(reversed(expected)), list(reversed(selected)))
        assert (other["result"], other["normalized_answer"]) == (result, got["normalized_answer"])
        assert got["normalized_answer"] == [o for o in OPTS if o in selected] and got["expected"]["mode"] == mode
    else:
        assert got["normalized_answer"] is None and "not evaluated" in got["explanation"]


def test_set_match_is_configured_strictly_and_missing_answers_stay_missing() -> None:
    assert sorted(ae.SET_MODES) == ["EQUALS", "INCLUDES_ALL", "INCLUDES_ANY", "INCLUDES_NONE"]
    assert ae.METHOD_ANSWER_TYPES["SET_MATCH"] == ("MULTI_SELECT",)
    # ---- unsupported configurations are refused, with the reason — never silently evaluated
    for evaluation, why in (
        ({"mode": "MOSTLY", "options": ["PREMIUM"]}, "how the selection is compared"),
        ({"mode": "EQUALS", "options": []}, "at least one expected option"),
        ({"mode": "EQUALS"}, "at least one expected option"),
        ({"mode": "EQUALS", "options": ["PREMIUM", "PREMIUM"]}, "listed twice"),
        ({"mode": "EQUALS", "options": ["INVENTED"]}, "must be the question's options"),
        ({"mode": "EQUALS", "options": [1]}, "at least one expected option"),
    ):
        with pytest.raises(ae.RuleInvalid, match=why):
            ae.configure("SET_MATCH", "MULTI_SELECT", OPTS, evaluation=evaluation)
    with pytest.raises(ae.RuleInvalid, match="multiple-choice question"):
        ae.configure("SET_MATCH", "ENUM", OPTS, evaluation={"mode": "EQUALS", "options": ["PREMIUM"]})
    with pytest.raises(ae.RuleInvalid, match="published options"):
        ae.configure("SET_MATCH", "MULTI_SELECT", (), evaluation={"mode": "EQUALS", "options": ["PREMIUM"]})
    # the expected set is stored once, in the question's own order
    assert ae.configure(
        "SET_MATCH", "MULTI_SELECT", OPTS, evaluation={"mode": "EQUALS", "options": ["CLAIMS", "PREMIUM"]}
    ) == ({"mode": "EQUALS", "options": ["PREMIUM", "CLAIMS"]}, None)
    assert (
        ae.describe_rule(_set_rule("INCLUDES_ANY", ["CLAIMS", "PREMIUM"]))
        == "Expected selection: at least one of PREMIUM, CLAIMS"
    )
    # a rule that reaches the evaluator malformed is said to be unsupported; it does not evaluate
    bad = ae.Rule(
        "Q-M", "Q-M@1", 1, "SET_MATCH", "MULTI_SELECT", OPTS, {"mode": "EQUALS", "options": ["INVENTED"]}, None
    )
    answer = {"answer_kind": "ANSWER", "answer_state": "ANSWERED", "value": ["PREMIUM"], "verbatim": None}
    assert ae.evaluate_one(bad, "COMPLETED", True, None, answer, None, ce.NO_FACTS)["result"] == "NOT_EVALUATED"
    # ---- an explicit empty selection is an ANSWER; an unanswered, refused or unasked question is not
    r = _set_rule("INCLUDES_NONE", ["CRITICAL_RISK"])
    empty = {"answer_kind": "ANSWER", "answer_state": "ANSWERED_EMPTY", "value": [], "verbatim": None}
    assert ae.evaluate_one(r, "COMPLETED", True, None, empty, None, ce.NO_FACTS)["result"] == "MATCH"
    assert (
        "explicit empty selection"
        in ae.evaluate_one(r, "COMPLETED", True, None, empty, None, ce.NO_FACTS)["explanation"]
    )
    assert ae.evaluate_one(r, "PENDING", True, None, None, None, ce.NO_FACTS)["result"] == "NOT_ASKED"
    assert ae.evaluate_one(r, "UNRESOLVED", True, None, None, None, ce.NO_FACTS)["result"] == "UNRESOLVED"
    # Script Studio's own list of expected-answer policies is exactly what it was
    from app.domain import script_authoring

    assert (
        script_authoring.POLICIES == ae.METHODS
        and len(ae.METHODS) == 8
        and "SET_MATCH" not in script_authoring.POLICIES
    )

    # ---- through the adapter and the journey evaluation (pure): the fixture's own multiple-choice question
    c = _control("CTRL-A")
    f4 = {p["key"]: p for p in ce.placements(fixture_bundle("F4"))}
    code = f4["mi-clar/n1"]["item_code"]
    rule_ = {
        "method": "SET_MATCH",
        "answer_type": "MULTI_SELECT",
        "options": list(OPTS),
        "expected": {"mode": "INCLUDES_NONE", "options": ["CRITICAL_RISK"]},
        "fact_key": None,
    }
    policy = _doc([pc("CTRL-A", [ob("MAIN", [ev("E")])])])

    def run(answers: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        return pe.evaluate_under_policy(
            _journey([_execution(1, "F4", answers)]),
            [c],
            {"CTRL-A": _mapping(c, [_bound(code, rule_, "E")])},
            None,
            policy,
        )["controls"][0]

    ok = run([("mi-clar/n1", {"choices": ["BENEFITS", "PREMIUM"]})])
    assert (
        ok["observations"][0]["result"],
        ok["observations"][0]["evaluation"]["normalized_answer"],
        ok["outcome"],
        ok["coverage"],
    ) == ("MATCH", ["PREMIUM", "BENEFITS"], "SATISFIED", "EVIDENCED")
    risk = run([("mi-clar/n1", {"choices": ["PREMIUM", "CRITICAL_RISK"]})])
    assert (risk["observations"][0]["result"], risk["outcome"], risk["coverage"]) == (
        "MISMATCH",
        "NOT_SATISFIED",
        "EVIDENCED",
    )
    unanswered = run([])
    assert (unanswered["observations"][0]["result"], unanswered["observations"][0]["gap"], unanswered["coverage"]) == (
        "NOT_ASKED",
        "AWAITING_ANSWER",
        "EVIDENCE_MISSING",
    )
    for bad_answer, refusal in (
        ({"choices": []}, "TOO_FEW_SELECTED"),
        ({"choices": ["PREMIUM", "PREMIUM"]}, "DUPLICATE_OPTION"),
        ({"choices": ["INVENTED"]}, "UNKNOWN_OPTION"),
    ):
        refused = run([("mi-clar/n1", bad_answer)])["observations"][0]  # the survey itself refuses it: not an answer
        assert (refused["result"], refused["gap"], refused["refused_inputs"], refused["evaluation"]["answer"]) == (
            "UNRESOLVED",
            "ASKED_NO_ACCEPTED_ANSWER",
            [refusal],
            None,
        )
    # two surveys, the same selection in a different order: the same answer, no conflict; a different selection: a conflict
    a1, a2 = (
        _execution(1, "F4", [("mi-clar/n1", {"choices": ["BENEFITS", "PREMIUM"]})], "S-ONE"),
        _execution(2, "F4", [("mi-clar/n1", {"choices": ["PREMIUM", "BENEFITS"]})], "S-TWO"),
    )
    a3 = _execution(2, "F4", [("mi-clar/n1", {"choices": ["CLAIMS"]})], "S-TWO")
    same = pe.evaluate_under_policy(
        _journey([a1, a2]), [c], {"CTRL-A": _mapping(c, [_bound(code, rule_, "E")])}, None, policy
    )["controls"][0]
    differ = pe.evaluate_under_policy(
        _journey([a1, a3]), [c], {"CTRL-A": _mapping(c, [_bound(code, rule_, "E")])}, None, policy
    )["controls"][0]
    assert (same["outcome"], len(same["observations"])) == ("SATISFIED", 2) and (
        differ["outcome"],
        differ["coverage"],
    ) == ("REQUIRES_REVIEW", "EVIDENCE_CONFLICTING")


# --------------------------------------------------------------------------------------- real HTTP, real PostgreSQL
def k8_policy(renamed: dict[str, str], **over: Any) -> dict[str, Any]:
    high = {"condition": {"code": renamed["C-HIGH-PREMIUM"], "version": 1}, "params": {"threshold": 12000}}
    older = {"condition": {"code": renamed["C-OLDER"], "version": 1}, "params": {"minimum_age": 60}}
    return policy_body(
        [
            # one control, TWO obligations: each is its own result
            pc("SYN-CTRL-01", [ob("IDENTITY", [ev("E-ID", description="The customer confirms who they are")]), ob("OPENING", [ev("E-HELLO", "DELIVERY", description="The opening statement is delivered")])]),
            pc("SYN-CTRL-02", [ob("HIGH-VALUE", [ev("E-FUNDS")], high)]),
            pc("SYN-CTRL-03", [ob("SENIOR", [ev("E-ACK")], older)]),
        ],
        **over,
    )  # fmt: skip


def test_a_control_policy_is_governed_and_a_journey_is_covered_or_not_under_it(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, settings: Settings
) -> None:
    author, checker, publisher, people = trio
    operational_before = counts(db, OPERATIONAL)
    register_before = [
        tuple(r)
        for r in db.execute(
            text("SELECT control_code, name, owner_role, content_approval_status, row_version FROM control ORDER BY 1")
        )
    ]
    publish_finding_rules(db, RULES_V1)
    sid, _, renamed = build(author, "K8", "Application survey")
    vid = publish(trio, sid)[1]
    it = items_of(db, vid)

    # ---- what a policy can be built from: published conditions and items only, in business terms
    options = author.get(f"{E}/builder-options").json()
    assert options["combinations"] == ["ALL_REQUIRED"] and options["completeness"] == ["DECLARED_COMPLETE", "PARTIAL"]
    older = next(c for c in options["conditions"] if c["code"] == renamed["C-OLDER"])
    assert (older["params"], older["fields"], older["usable"]) == (["minimum_age"], ["customer.age_years"], True)
    question = next(i for i in options["items"] if i["code"] == it["mi-opening/n2"]["code"])
    assert (question["answer_type"], question["evidence"], question["methods"], len(question["surveys"])) == (
        "YES_NO",
        ["ANSWER", "DELIVERY"],
        ["EXACT_BOOLEAN"],
        1,
    )
    statement = next(i for i in options["items"] if i["code"] == it["mi-opening/n1"]["code"])
    assert (statement["evidence"], statement["methods"]) == (["DELIVERY"], [])
    assert "customer.age_years" in options["fields"]

    # ---- 1. nothing is governed that is not exact, published and meaningful: each refusal says what and where
    good = k8_policy(renamed)
    for change, code in (
        ({"code": "x"}, "CODE_INVALID"),
        ({"scope_statement": "short"}, "SCOPE_STATEMENT_REQUIRED"),
        ({"completeness": "MOSTLY"}, "COMPLETENESS_REQUIRED"),
        ({"owner": ""}, "OWNER_REQUIRED"),
        ({"source": "x"}, "SOURCE_REQUIRED"),
        ({"controls": []}, "CONTROLS_INVALID"),
        (
            {"controls": [pc("NEW-CONTROL", [ob("A", [ev("E")])])]},
            "CONTROL_NOT_FOUND",
        ),  # a policy does not create controls
        (
            {"controls": [pc("SYN-CTRL-01", [ob("A", [ev("E")])]), pc("SYN-CTRL-01", [ob("B", [ev("E")])])]},
            "CONTROL_DUPLICATE",
        ),
        ({"controls": [pc("SYN-CTRL-01", [ob("A", [ev("E")]), ob("A", [ev("E")])])]}, "OBLIGATION_KEY_INVALID"),
        ({"controls": [pc("SYN-CTRL-01", [ob("A", [ev("E")], combination="ANY_ONE")])]}, "COMBINATION_UNSUPPORTED"),
        (
            {"controls": [pc("SYN-CTRL-01", [ob("A", [ev("E", required=False)])])]},
            "NO_REQUIRED_EVIDENCE",
        ),  # an empty required set never satisfies
        ({"controls": [pc("SYN-CTRL-01", [ob("A", [])])]}, "EVIDENCE_INVALID"),
        ({"controls": [pc("SYN-CTRL-01", [ob("A", [ev("E", "OPINION")])])]}, "EVIDENCE_TYPE_INVALID"),
        (
            {
                "controls": [
                    pc(
                        "SYN-CTRL-01",
                        [ob("A", [ev("E")], {"condition": {"code": "C-INVENTED", "version": 1}, "params": {}})],
                    )
                ]
            },
            "CONDITION_NOT_PUBLISHED",
        ),
        (
            {
                "controls": [
                    pc(
                        "SYN-CTRL-01",
                        [ob("A", [ev("E")], {"condition": {"code": renamed["C-OLDER"], "version": 1}, "params": {}})],
                    )
                ]
            },
            "APPLICABILITY_PARAMS",
        ),
        (
            {"scope": {"condition": {"code": renamed["C-OLDER"], "version": 9}, "params": {"minimum_age": 1}}},
            "CONDITION_NOT_PUBLISHED",
        ),
    ):
        r = post(author, f"{E}/control-policies", good | change)
        assert (r.status_code, r.json()["code"]) == (404 if code == "CONTROL_NOT_FOUND" and False else 422, code), (
            change,
            r.text,
        )
    assert db.execute(text("SELECT count(*) FROM survey_control_policy")).scalar_one() == 0

    # ---- 1, 2. lifecycle: three different people; immutable once proposed
    r = post(author, f"{E}/control-policies", good)
    assert r.status_code == 201, r.text
    p = r.json()
    assert (p["status"], p["revision"], p["completeness"], len(p["policy_sha256"]), p["is_proposer"]) == (
        "PROPOSED",
        1,
        "DECLARED_COMPLETE",
        64,
        True,
    )
    first = p["controls"][0]
    assert (
        first["control"]["code"] == "SYN-CTRL-01"
        and len(first["control"]["sha256"]) == 64
        and [o["key"] for o in first["obligations"]] == ["IDENTITY", "OPENING"]
    )
    assert p["controls"][2]["obligations"][0]["applicability"]["condition"]["code"] == renamed["C-OLDER"]
    assert (post(author, f"{E}/control-policies", good).json()["code"]) == "POLICY_OPEN"
    pid = p["id"]
    for who, path, body, status, code in (
        (author, "decision", {"verdict": "APPROVE"}, 403, "SELF_REVIEW_DENIED"),
        (publisher, "publish", {}, 409, "NOT_APPROVED"),
        (checker, "decision", {"verdict": "REJECT", "comment": "no"}, 422, "COMMENT_REQUIRED"),
    ):
        r = post(who, f"{E}/control-policies/{pid}/{path}", body)
        assert (r.status_code, r.json()["code"]) == (status, code)
    assert post(checker, f"{E}/control-policies/{pid}/decision", {"verdict": "APPROVE"}).json()["status"] == "APPROVED"
    for who, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        r = post(who, f"{E}/control-policies/{pid}/publish")
        assert (r.status_code, r.json()["code"]) == (403, code)
    done = post(publisher, f"{E}/control-policies/{pid}/publish").json()
    assert done["status"] == "PUBLISHED" and [h["event"] for h in done["history"]] == [
        "PROPOSED",
        "APPROVED",
        "PUBLISHED",
    ]
    assert len({done["proposed_by"], done["approved_by"], done["published_by"]}) == 3
    for sql in (
        f"UPDATE survey_control_policy SET completeness = 'PARTIAL' WHERE id = '{pid}'",
        f"DELETE FROM survey_control_policy_event WHERE policy_id = '{pid}'",
        f"INSERT INTO survey_control_policy_event (policy_id, event, actor_ref) VALUES ('{pid}', 'PROPOSED', 'x')",
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as c:
                c.execute(text(sql))
    # the register itself is exactly as it was: a policy refers to controls, it does not rewrite them
    assert [
        tuple(r)
        for r in db.execute(
            text("SELECT control_code, name, owner_role, content_approval_status, row_version FROM control ORDER BY 1")
        )
    ] == register_before

    # ---- 3, 4. applicability from synthetic application facts — before any survey, mapping or journey exists
    def applies(facts: dict[str, Any]) -> dict[str, Any]:
        r = post(author, f"{E}/applicability", {"control_policy_id": pid, "facts": facts})
        assert r.status_code == 200, r.text
        return r.json()

    ordinary = applies(K8_FACTS)
    assert {(o["control_code"], o["obligation"]): o["status"] for o in ordinary["obligations"]} == {
        ("SYN-CTRL-01", "IDENTITY"): "APPLICABLE", ("SYN-CTRL-01", "OPENING"): "APPLICABLE",
        ("SYN-CTRL-02", "HIGH-VALUE"): "NOT_APPLICABLE", ("SYN-CTRL-03", "SENIOR"): "NOT_APPLICABLE",
    }  # fmt: skip
    assert (
        ordinary["recorded"],
        ordinary["scope"]["status"],
        ordinary["input_lineage"]["status"],
        ordinary["operational_compliance_eligibility"]["status"],
    ) == (False, "IN_SCOPE", "UNVERIFIED", "NOT_ESTABLISHED")
    assert applies(K8_FACTS)["fingerprint"] == ordinary["fingerprint"]
    senior = applies({"policy.annual_premium": 25000, "customer.age_years": 67})
    assert (
        senior["counts"] == {"APPLICABLE": 4, "NOT_APPLICABLE": 0, "UNKNOWN": 0}
        and senior["fingerprint"] != ordinary["fingerprint"]
    )
    unknown = applies({"policy.annual_premium": 3000})
    assert unknown["counts"]["UNKNOWN"] == 1 and unknown["missing_inputs"] == [
        "customer.age_years"
    ]  # unknown, and what is missing
    assert (
        post(author, f"{E}/applicability", {"control_policy_id": pid, "facts": {"not.a.field": 1}}).json()["code"]
        == "FACT_UNKNOWN"
    )
    # a policy that is not proposed yet can be tried out the same way; an invalid one says why
    trial = post(author, f"{E}/applicability", {"policy": good | {"code": "POL-TRIAL"}, "facts": K8_FACTS})
    assert trial.status_code == 200 and trial.json()["policy"]["revision"] == 0
    assert (
        post(author, f"{E}/applicability", {"policy": good | {"completeness": "?"}, "facts": {}}).json()["code"]
        == "COMPLETENESS_REQUIRED"
    )
    assert (
        db.execute(text("SELECT count(*) FROM survey_control_policy")).scalar_one() == 1
    )  # nothing was recorded by trying

    # ---- mappings that say which requirement each item supplies; SYN-CTRL-03 is deliberately left unmapped
    def bound(
        key: str, rule_: dict[str, Any] | None, requirement: str, obligation: str | None = None
    ) -> dict[str, Any]:
        return entry(it[key], rule_) | {"requirement": requirement, "obligation": obligation}

    draft_01 = {
        "control_code": "SYN-CTRL-01",
        "combination": "ALL_REQUIRED",
        "applicability": None,
        "entries": [
            bound("mi-opening/n2", YES, "E-ID", "IDENTITY"),
            bound("mi-opening/n1", None, "E-HELLO", "OPENING"),
        ],
    }
    sim = simulate(author, vid, K8_FACTS, {"mi-opening/n2": {"choice": "YES"}})

    # ---- "test the mapping against a synthetic journey" before proposing anything: nothing is recorded
    r = post(author, f"{E}/evaluations/preview", {"simulation_id": sim["id"], "control_policy_id": pid})
    before = r.json()
    assert (
        r.status_code == 200
        and before["recorded"] is False
        and cover(before)["SYN-CTRL-01/IDENTITY"] == "NOT_MAPPED"
        and before["coverage"]["status"] == "INCOMPLETE"
    )
    r = post(
        author,
        f"{E}/evaluations/preview",
        {"simulation_id": sim["id"], "control_policy_id": pid, "mappings": [draft_01]},
    )
    tried = r.json()
    assert r.status_code == 200 and tried["preview"]["drafted_mappings"] == ["SYN-CTRL-01"]
    assert cover(tried) == {
        "SYN-CTRL-01/IDENTITY": "EVIDENCED",
        "SYN-CTRL-01/OPENING": "EVIDENCED",
        "SYN-CTRL-02/HIGH-VALUE": "NOT_REQUIRED",
        "SYN-CTRL-03/SENIOR": "NOT_REQUIRED",
    }
    assert tried["coverage"]["status"] == "COMPLETE_WITHIN_POLICY_SCOPE"
    r = post(
        author,
        f"{E}/evaluations/preview",
        {
            "simulation_id": sim["id"],
            "control_policy_id": pid,
            "mappings": [draft_01 | {"entries": [bound("mi-opening/n1", YES, "E-ID", "IDENTITY")]}],
        },
    )
    assert (r.status_code, r.json()["code"]) == (422, "ANSWER_TYPE_UNSUPPORTED") and "Evidence 1" in r.json()[
        "message"
    ]  # why it is invalid, and where
    assert (
        db.execute(
            text(
                "SELECT (SELECT count(*) FROM survey_control_mapping) + (SELECT count(*) FROM survey_journey_evaluation)"
            )
        ).scalar_one()
        == 0
    )

    mapped(trio, "SYN-CTRL-01", draft_01["entries"])
    mapped(trio, "SYN-CTRL-02", [bound("mi-high-value/n2", YES, "E-FUNDS")])

    # ---- 6. a complete, scoped policy, an ordinary application: coverage is COMPLETE within the policy's scope
    e = under(author, pid, simulation_id=sim["id"])
    assert (e["control_policy_id"], e["policy"]["code"], e["policy"]["revision"], e["pins"]["policy"]["sha256"]) == (
        pid,
        "POL-TEST",
        1,
        done["policy_sha256"],
    )
    assert cover(e) == {
        "SYN-CTRL-01/IDENTITY": "EVIDENCED",
        "SYN-CTRL-01/OPENING": "EVIDENCED",
        "SYN-CTRL-02/HIGH-VALUE": "NOT_REQUIRED",
        "SYN-CTRL-03/SENIOR": "NOT_REQUIRED",
    }
    assert (e["coverage"]["status"], e["coverage"]["required"], e["coverage"]["evidenced"], e["processing_status"]) == (
        "COMPLETE_WITHIN_POLICY_SCOPE",
        2,
        2,
        "COMPLETED",
    )
    # four statuses, kept apart — and complete coverage is not compliance
    assert (
        e["operational_compliance_eligibility"]["status"] == "NOT_ESTABLISHED"
        and e["summary"]["by_outcome"]["SATISFIED"] == 2
    )
    assert e["applicability"]["fingerprint"] == ordinary["fingerprint"] and e["coverage"][
        "controls_outside_policy"
    ] == ["SYN-CTRL-04", "SYN-CTRL-05"]
    # 9. the two obligations of SYN-CTRL-01 are two results, each with its own evidence and requirement
    ident, opening = instance(e, "SYN-CTRL-01", "IDENTITY"), instance(e, "SYN-CTRL-01", "OPENING")
    assert [(o["placement"], o["requirement"], o["result"]) for o in ident["observations"]] == [
        ("mi-opening/n2", "E-ID", "MATCH")
    ]
    assert [(o["placement"], o["requirement"], o["result"]) for o in opening["observations"]] == [
        ("mi-opening/n1", "E-HELLO", "DELIVERED")
    ]
    assert ident["observations"][0]["simulation_id"] == sim["id"] and ident["purpose"].startswith("Synthetic purpose")
    assert (
        db.execute(
            text(
                "SELECT count(*) FROM survey_obligation_result WHERE evaluation_id = :e AND control_code = 'SYN-CTRL-01'"
            ),
            {"e": e["id"]},
        ).scalar_one()
        == 2
    )
    assert (
        e["replay"]["consistent"] is True and under(author, pid, simulation_id=sim["id"], expect=200)["id"] == e["id"]
    )

    # ---- 5. a REQUIRED control that nobody mapped is found — from the policy, not from any survey mapping
    high_facts = {"policy.annual_premium": 25000, "policy.is_replacement": True, "customer.age_years": 67}
    rich = simulate(
        author,
        vid,
        high_facts,
        {
            "mi-opening/n2": {"choice": "YES"},
            "mi-high-value/n2": {"choice": "YES"},
            "mi-replacement/n1": {"choice": "YES"},
            "mi-senior/n1": {"acknowledged": True},
        },
    )
    assert rich["run"]["terminal"]["state"] == "COMPLETED"
    e2 = under(author, pid, simulation_id=rich["id"])
    assert cover(e2) == {
        "SYN-CTRL-01/IDENTITY": "EVIDENCED",
        "SYN-CTRL-01/OPENING": "EVIDENCED",
        "SYN-CTRL-02/HIGH-VALUE": "EVIDENCED",
        "SYN-CTRL-03/SENIOR": "NOT_MAPPED",
    }
    senior_line = instance(e2, "SYN-CTRL-03", "SENIOR")
    assert (
        senior_line["outcome"],
        senior_line["mapping"],
        senior_line["reasons"][0]["code"],
        senior_line["applicability"]["status"],
    ) == ("UNRESOLVED", None, "MAPPING_MISSING", "APPLICABLE")
    # every question was answered and the survey COMPLETED — and coverage is INCOMPLETE
    assert (e2["journey"]["complete"], e2["coverage"]["status"], e2["coverage"]["gaps"]) == (
        True,
        "INCOMPLETE",
        [{"control_code": "SYN-CTRL-03", "obligation": "SENIOR", "coverage": "NOT_MAPPED"}],
    )
    # ---- 4. unknown applicability is its own coverage result
    halted = simulate(
        author,
        vid,
        {"policy.annual_premium": 3000, "policy.is_replacement": None, "customer.age_years": None},
        {"mi-opening/n2": {"choice": "YES"}},
    )
    e3 = under(author, pid, simulation_id=halted["id"])
    assert cover(e3)["SYN-CTRL-03/SENIOR"] == "APPLICABILITY_UNKNOWN" and (
        e3["coverage"]["status"],
        e3["coverage"]["reason"],
    ) == ("INCOMPLETE", "APPLICABILITY_UNKNOWN")
    assert e3["applicability"]["missing_inputs"] == ["customer.age_years"]

    # ---- the same journey WITHOUT a policy is the EVAL-1 evaluation: nothing about coverage is asserted
    plain = evaluate(author, simulation_id=sim["id"])
    assert plain["id"] != e["id"] and (plain["control_policy_id"], plain["policy"], plain["coverage"]["status"]) == (
        None,
        None,
        "NOT_ASSERTED",
    )
    assert control(plain, "SYN-CTRL-01")["outcome"] == "SATISFIED" and "obligation" not in control(plain, "SYN-CTRL-01")
    assert plain["operational_compliance_eligibility"]["status"] == "NOT_ESTABLISHED"

    # ---- 7, 15. a revised policy — the same content declared PARTIAL — is a NEW revision; past evaluations stay
    r = post(author, f"{E}/control-policies", good | {"completeness": "PARTIAL"})
    rev2 = r.json()["id"]
    assert r.json()["revision"] == 2
    r = post(author, f"{E}/evaluations", {"simulation_id": sim["id"], "control_policy_id": rev2})
    assert (r.status_code, r.json()["code"]) == (409, "POLICY_NOT_PUBLISHED")  # only a published revision
    post(checker, f"{E}/control-policies/{rev2}/decision", {"verdict": "APPROVE"})
    assert post(publisher, f"{E}/control-policies/{rev2}/publish").json()["status"] == "PUBLISHED"
    assert {x["revision"]: x["status"] for x in author.get(f"{E}/control-policies").json()["items"]} == {
        1: "SUPERSEDED",
        2: "PUBLISHED",
    }
    e_partial = under(author, rev2, simulation_id=sim["id"])
    assert e_partial["id"] != e["id"] and (e_partial["coverage"]["status"], e_partial["coverage"]["reason"]) == (
        "NOT_ASSERTED",
        "POLICY_PARTIAL",
    )
    assert (
        e_partial["summary"]["by_outcome"]["SATISFIED"] == 2
    )  # everything evidenced and satisfied — and still not asserted
    old = author.get(f"{E}/evaluations/{e['id']}").json()
    assert (
        old["result_sha256"],
        old["coverage"]["status"],
        old["replay"]["consistent"],
        old["policy"]["revision"],
    ) == (e["result_sha256"], "COMPLETE_WITHIN_POLICY_SCOPE", True, 1)
    assert [s["code"] for s in old["superseded_by_current_governance"]] == ["POLICY_REVISED"]
    r = post(author, f"{E}/evaluations", {"simulation_id": sim["id"], "control_policy_id": pid})
    assert (r.status_code, r.json()["code"]) == (
        409,
        "POLICY_NOT_PUBLISHED",
    )  # a superseded revision is not evaluated under again
    listed = author.get(f"{E}/evaluations", params={"simulation_id": sim["id"]}).json()["items"]
    assert [(x["policy"]["revision"] if x["policy"] else None, x["coverage_status"]) for x in listed] == [
        (1, "COMPLETE_WITHIN_POLICY_SCOPE"),
        (None, "NOT_ASSERTED"),
        (2, "NOT_ASSERTED"),
    ]
    assert [j["kind"] for j in author.get(f"{E}/journeys").json()["items"]] == ["SINGLE_SURVEY"] * 3

    # ---- 13, 14. the existing engines stay authoritative; nothing unapproved is created
    assert (
        e2["engines"]["answer_evaluation"] == ae.ENGINE
        and e2["engines"]["findings"] == fe.ENGINE
        and e2["findings"] == []
    )
    assert ident["observations"][0]["evaluation"]["rule_evaluation_equivalent"] == "MATCH"

    # ---- 16. permissions, market, CSRF, audit
    reader = make_account(db, prefix="polreader")
    GRANTS[reader.principal_id] = ALL - {"survey.evaluate", "survey.edit", "survey.approve", "survey.publish"}
    c = _client(survey_app, reader)
    assert c.get(f"{E}/control-policies/{pid}").status_code == 200 and c.get(f"{E}/builder-options").status_code == 200
    for path, body in (
        ("control-policies", good | {"code": "POL-OTHER"}),
        (f"control-policies/{rev2}/decision", {"verdict": "APPROVE"}),
        (f"control-policies/{rev2}/publish", {}),
        ("applicability", {"control_policy_id": pid, "facts": {}}),
        ("evaluations/preview", {"simulation_id": sim["id"]}),
    ):
        assert post(c, f"{E}/{path}", body).status_code == 403, path
    assert (
        (post(c, f"{E}/control-policies/{rev2}/withdraw", {"reason": "not mine to withdraw"}).json()["code"])
        == "FORBIDDEN"
    )
    GRANTS[reader.principal_id] = ALL - {"survey.evaluation.read"}
    for path in ("control-policies", f"control-policies/{pid}", "builder-options", "journeys"):
        assert c.get(f"{E}/{path}").status_code == 403, path
    c.__exit__(None, None, None)
    GRANTS.pop(reader.principal_id)
    outsider = make_account(db, prefix="polmy")
    GRANTS[outsider.principal_id] = ALL
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    c = _client(survey_app, outsider)
    assert (
        c.get(f"{E}/control-policies").json()["items"] == []
        and c.get(f"{E}/control-policies/{pid}").status_code == 404
        and c.get(f"{E}/journeys").json()["items"] == []
    )
    assert (post(c, f"{E}/control-policies", good | {"code": "POL-MY"}).json()["code"]) == "MARKET_NOT_IN_SCOPE"
    assert post(c, f"{E}/applicability", {"control_policy_id": pid, "facts": {}}).status_code == 404
    assert post(c, f"{E}/evaluations", {"simulation_id": sim["id"], "control_policy_id": pid}).status_code == 404
    c.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)
    assert author.post(f"{E}/control-policies", json=good).status_code == 403  # no CSRF token
    actions = set(
        db.execute(text("SELECT DISTINCT action FROM audit_event WHERE action LIKE 'SURVEY.CONTROL_POLICY%'")).scalars()
    )
    assert actions == {
        "SURVEY.CONTROL_POLICY_PROPOSED",
        "SURVEY.CONTROL_POLICY_APPROVED",
        "SURVEY.CONTROL_POLICY_PUBLISHED",
        "SURVEY.CONTROL_POLICY_DENIED",
    }
    assert (
        db.execute(text("SELECT count(*) FROM audit_event WHERE action = 'SURVEY.CONTROL_POLICY_DENIED'")).scalar_one()
        == 3
    )
    assert (
        db.execute(
            text(
                "SELECT after->>'coverage' FROM audit_event WHERE action = 'SURVEY.JOURNEY_EVALUATED' AND entity_id = :e"
            ),
            {"e": e["id"]},
        ).scalar_one()
        == "COMPLETE_WITHIN_POLICY_SCOPE"
    )
    assert verify_chain(db).ok

    # ---- 17. nothing operational; simulation records only; a governed policy survives a schema change
    assert counts(db, OPERATIONAL) == operational_before
    assert set(db.execute(text("SELECT DISTINCT record_class FROM survey_journey_evaluation")).scalars()) == {
        "SIMULATION"
    }
    assert db.execute(text("SELECT count(*) FROM survey_evaluation_policy")).scalar_one() == 4
    from tests.support import migrate

    db.rollback()
    with pytest.raises(RuntimeError, match="governed control policies exist"):
        migrate(settings, "0033_survey_control_evaluation", down=True)


def test_two_surveys_give_one_control_instance_conflicting_answers_and_neither_wins(
    clean_rules: None, trio: Any, survey_app: Any, db: Session
) -> None:
    """Step 7, through persisted simulations: two DIFFERENT published surveys legitimately reuse ONE published
    question revision; a coordinated simulation answers it differently in each."""
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    operational_before = counts(db, OPERATIONAL)
    rules_id = publish_finding_rules(
        db,
        [
            rule("FR-MISMATCH", "MISMATCH", "FACT_MISMATCH", "MEDIUM"),
            rule("FR-NOT-ASKED", "NOT_ASKED", "MISSING_MANDATORY_ANSWER", "LOW", mandatory_only=True),
        ],
    )
    # ---- survey A publishes a module; survey B, another survey, pins the SAME published module revision (LIB-1)
    a_sid, a_code, _ = build(author, "K3", "Survey A (numbers)")
    version_a = publish(trio, a_sid)[1]
    b_sid, b_code = empty_survey(author, "Survey B (reuses A's question)")
    assert pin_module(author, b_sid, draft(author, a_sid)).status_code == 200
    version_b = publish(trio, b_sid)[1]
    a, b = items_of(db, version_a), items_of(db, version_b)
    assert (
        version_a != version_b and a["mi-numbers/n1"] == b["mi-shared/n1"]
    )  # one question revision, two surveys, two placements
    shared = a["mi-numbers/n1"]
    item = next(i for i in author.get(f"{E}/builder-options").json()["items"] if i["code"] == shared["code"])
    assert sorted(s["survey_code"] for s in item["surveys"]) == sorted(
        [a_code, b_code]
    )  # the builder shows the implication

    publish_rule(maker, rule_checker, "P-A", [SG, {"field": "product_family", "values": ["PROTECTION"]}], 1)
    publish_rule(maker, rule_checker, "R-B", [SG, {"field": "premium_frequency", "values": ["SINGLE"]}], 2)
    bind(trio, "P-A", version_a)
    bind(trio, "R-B", version_b)
    group(trio, "PRIMARY-SG", "PRIMARY", ["P-A"], sequence=1)
    group(trio, "ADD-B", "ADD_REQUIRED", ["R-B"], sequence=2)
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    application = {
        "market": "SG", "product_family": "PROTECTION", "selling_channel": "AGENCY", "premium_frequency": "SINGLE",
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": False,
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip
    # ---- ONE obligation, evidenced by the shared question wherever it is asked; a second control whose question is not in the journey
    policy = published_policy(
        trio,
        policy_body(
            [
                pc("SYN-CTRL-01", [ob("TERM", [ev("E-TERM", description="The customer states the term")])]),
                pc("SYN-CTRL-02", [ob("OTHER", [ev("E-OTHER")])]),
            ]
        ),
    )
    exactly_20 = {"method": "NUMERIC_COMPARE", "evaluation": {"operator": "EQ", "value": 20, "unit": "COUNT"}}
    mapped(trio, "SYN-CTRL-01", [entry(shared, exactly_20) | {"requirement": "E-TERM"}])
    k8_sid, _, _ = build(author, "K8", "A survey that is not in this journey")
    elsewhere = items_of(db, publish(trio, k8_sid)[1])
    mapped(trio, "SYN-CTRL-02", [entry(elsewhere["mi-opening/n2"], YES) | {"requirement": "E-OTHER"}])

    comp = compose(author, application)
    co = post(author, f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "conflict"}).json()
    answers = {
        1: {"n1": 20, "n2": 12.5, "n3": -3},
        2: {"n1": 30, "n2": 12.5, "n3": -3},
    }  # the SAME question: 20 in survey A, 30 in survey B
    while co["status"] == "RUNNING":
        key = co["current"]["pending"]["key"]
        co = post(
            author,
            f"{A}/coordinated-simulations/{co['id']}/inputs",
            {
                "expected_inputs": co["progress"]["inputs"],
                "key": key,
                "answer": {"number": answers[co["current"]["position"]][key.split("/")[1]]},
            },
        ).json()
    assert co["status"] == "ALL_SURVEYS_COMPLETED" and [s["survey_version_id"] for s in co["surveys"]] == [
        version_a,
        version_b,
    ]
    sims = [s["simulation_id"] for s in co["surveys"]]

    e = under(author, policy["id"], coordinated=co["id"])
    # ---- ONE control instance receives both observations; both execution identities are kept
    assert [(c["control_code"], c["obligation"]) for c in e["controls"]] == [
        ("SYN-CTRL-01", "TERM"),
        ("SYN-CTRL-02", "OTHER"),
    ]
    term = instance(e, "SYN-CTRL-01", "TERM")
    assert [
        (
            o["survey"]["position"],
            o["simulation_id"],
            o["survey"]["survey_version_id"],
            o["placement"],
            o["item"]["code"],
            o["evaluation"]["answer"]["value"],
            o["result"],
        )
        for o in term["observations"]
    ] == [
        (1, sims[0], version_a, "mi-numbers/n1", shared["code"], 20, "MATCH"),
        (2, sims[1], version_b, "mi-shared/n1", shared["code"], 30, "MISMATCH"),
    ]
    assert [o["run_sha256"] for o in term["observations"]] == [s["run_sha256"] for s in co["surveys"]]
    # ---- the conflict requires review; neither answer overrides the other; the mismatch is still explained
    assert (term["outcome"], term["coverage"], e["processing_status"]) == (
        "REQUIRES_REVIEW",
        "EVIDENCE_CONFLICTING",
        "REQUIRES_REVIEW",
    )
    conflict = term["reasons"][0]
    assert (
        conflict["code"] == "EVIDENCE_CONFLICT"
        and [x["value"] for x in conflict["answers"]] == ["20", "30"]
        and "none is chosen" in conflict["text"]
    )
    assert [r["code"] for r in term["reasons"]] == ["EVIDENCE_CONFLICT", "EVIDENCE_MISMATCH"]
    # ---- the finding engine is called only under its governed rules: one finding for the mismatch, none for the conflict
    by_control = {
        (f["control_code"], f["rule"]["rule_code"], f["simulation_id"], f["placement"]) for f in e["findings"]
    }
    assert by_control == {
        ("SYN-CTRL-01", "FR-MISMATCH", sims[1], "mi-shared/n1"),
        ("SYN-CTRL-02", "FR-NOT-ASKED", None, None),
    }
    assert all(f["rule"]["rule_set"]["version_id"] == rules_id and f["engine"] == fe.ENGINE for f in e["findings"])
    assert not [f for f in e["findings"] if "CONFLICT" in f["category"] or "conflict" in f["description"].lower()]
    # ---- a REQUIRED control with missing evidence, and its governed finding
    other = instance(e, "SYN-CTRL-02", "OTHER")
    assert (
        other["outcome"],
        other["coverage"],
        other["observations"][0]["result"],
        other["observations"][0]["gap"],
    ) == ("INSUFFICIENT_EVIDENCE", "EVIDENCE_MISSING", "NOT_ASKED", "ITEM_NOT_IN_JOURNEY")
    missing = next(f for f in e["findings"] if f["control_code"] == "SYN-CTRL-02")
    assert (missing["finding_class"], missing["evidence"]["answer"], missing["obligation"]) == (
        "MISSING_EVIDENCE",
        None,
        "OTHER",
    )
    assert (
        e["coverage"]["status"],
        e["coverage"]["by_instance"]["EVIDENCE_CONFLICTING"],
        e["coverage"]["by_instance"]["EVIDENCE_MISSING"],
    ) == ("INCOMPLETE", 1, 1)
    # ---- recorded as it was evaluated, and it recomputes
    again = author.get(f"{E}/evaluations/{e['id']}").json()
    assert again["result_sha256"] == e["result_sha256"] and again["replay"]["consistent"] is True
    assert [len(c["observations"]) for c in again["controls"]] == [2, 1]
    assert (
        db.execute(
            text(
                "SELECT count(DISTINCT simulation_id) FROM survey_obligation_observation WHERE evaluation_id = :e AND control_code = 'SYN-CTRL-01' AND obligation = 'TERM'"
            ),
            {"e": e["id"]},
        ).scalar_one()
        == 2
    )
    # the same answer in both surveys is no conflict: one instance, two observations, satisfied
    co2 = post(
        author,
        f"{A}/composite-plans/{compose(author, application)['id']}/coordinated-simulations",
        {"label": "agreeing"},
    ).json()
    while co2["status"] == "RUNNING":
        key = co2["current"]["pending"]["key"]
        co2 = post(
            author,
            f"{A}/coordinated-simulations/{co2['id']}/inputs",
            {
                "expected_inputs": co2["progress"]["inputs"],
                "key": key,
                "answer": {"number": answers[1][key.split("/")[1]]},
            },
        ).json()
    agree = instance(under(author, policy["id"], coordinated=co2["id"]), "SYN-CTRL-01", "TERM")
    assert (agree["outcome"], agree["coverage"], len(agree["observations"])) == ("SATISFIED", "EVIDENCED", 2)
    assert counts(db, OPERATIONAL) == operational_before
    for cx in (maker, rule_checker):
        cx.__exit__(None, None, None)


def test_control_policies_are_off_by_default_and_evaluation_works_without_them(
    clean_rules: None, settings: Settings, engine: Engine, db: Session
) -> None:
    assert Settings.model_fields["survey_control_policy_enabled"].default is False
    people = [make_account(db, prefix=p) for p in ("offa", "offc", "offp")]
    for person in people:
        GRANTS[person.principal_id] = ALL
    for update, registered in (
        (SETTINGS_ON, False),  # evaluation on, policies off
        (
            {k: v for k, v in ON.items() if k != "survey_evaluation_enabled"},
            False,
        ),  # policies without evaluation are not on
        (ON, True),
    ):
        app = create_app(settings.model_copy(update=update))
        with_grants(app)
        operations = [
            (m, p)
            for p, item in app.openapi()["paths"].items()
            if p.startswith(E)
            and ("control-polic" in p or p.endswith(("/applicability", "/preview", "/builder-options", "/journeys")))
            for m in item
        ]
        assert len(operations) == (10 if registered else 0)
        c = _client(app, people[0])
        assert c.get("/health/ready").status_code == 200
        c.__exit__(None, None, None)
    # with policies OFF the EVAL-1 evaluation still records and reads, and naming a policy is refused, not ignored
    app = create_app(settings.model_copy(update=SETTINGS_ON))
    with_grants(app)
    trio_ = tuple(_client(app, p) for p in people)
    sid, _, _ = build(trio_[0], "K1", "Evaluated with policies off")
    sim = simulate(
        trio_[0], publish(trio_, sid)[1], {}, {"mi-call/n2": {"choice": "YES"}, "mi-call/n5": {"choice": "YES"}}
    )
    e = evaluate(trio_[0], simulation_id=sim["id"])
    assert (e["control_policy_id"], e["coverage"]["status"], e["replay"]["consistent"]) == (None, "NOT_ASSERTED", True)
    assert trio_[0].get(f"{E}/control-policies").status_code == 404
    r = post(trio_[0], f"{E}/evaluations", {"simulation_id": sim["id"], "control_policy_id": str(uuid.uuid4())})
    assert r.status_code == 404
    assert (
        db.execute(text("SELECT count(*) FROM survey_evaluation_policy")).scalar_one() == 0
    )  # written to the EVAL-1 tables only
    for c in trio_:
        c.__exit__(None, None, None)
    for person in people:
        GRANTS.pop(person.principal_id)


def build_controlled(c: TestClient, prefix: str, name: str) -> str:
    """A golden fixture saved as a survey with every wording delivered as CONTROLLED text. (F4's wordings are in the
    'assistant's own words' mode, which the server refuses to publish; the questions and options are the fixture's.)"""
    from tests.survey_support import new_code, operations_for
    from tests.test_survey_fi1 import save
    from tests.test_survey_lib1 import issue

    code = new_code()
    r = post(c, "/api/v1/survey-definitions", {"code": code, "name": name, "purpose": "synthetic"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    b = fixture_bundle(prefix)
    old = {
        "OPTION_SET": [k[0] for k in b.option_sets],
        "ITEM": sorted({k[0] for k in b.items}),
        "CONDITION": sorted({k[0] for k in b.conditions}),
        "MODULE": sorted({k[0] for k in b.modules}),
    }
    got = issue(c, sid, **{k: len(v) for k, v in old.items()})
    ops_text = json.dumps(operations_for(b, code))
    for kind in old:
        for o, n in zip(old[kind], got.get(kind, []), strict=True):
            ops_text = ops_text.replace(json.dumps(o), json.dumps(n))
    ops = json.loads(ops_text)
    for op in ops:
        if op.get("kind") == "WORDING":
            op["document"]["delivery_mode"] = "CONTROLLED_TTS"
    r = save(c, sid, 0, ops)
    assert r.status_code == 200, r.text
    return sid


def test_a_multiple_choice_answer_is_evaluated_by_set_match_through_persisted_simulations(
    clean_rules: None, trio: Any, survey_app: Any, db: Session
) -> None:
    """§3, persisted: a published multiple-choice question, a governed mapping with SET_MATCH, real simulations."""
    author = trio[0]
    publish_finding_rules(
        db,
        [
            rule("FR-MISMATCH", "MISMATCH", "FACT_MISMATCH", "MEDIUM"),
            rule("FR-UNRESOLVED", "UNRESOLVED", "MISSING_MANDATORY_ANSWER", "LOW", mandatory_only=True),
        ],
    )
    sid = build_controlled(author, "F4", "Clarification survey (multiple choice)")
    vid = publish(trio, sid)[1]
    multi = items_of(db, vid)["mi-clar/n1"]
    offered = next(i for i in author.get(f"{E}/builder-options").json()["items"] if i["code"] == multi["code"])
    assert (offered["answer_type"], offered["methods"], offered["evidence"]) == (
        "MULTI_SELECT",
        ["SET_MATCH"],
        ["ANSWER", "DELIVERY"],
    )
    assert sorted(author.get(f"{E}/builder-options").json()["set_modes"]) == [
        "EQUALS",
        "INCLUDES_ALL",
        "INCLUDES_ANY",
        "INCLUDES_NONE",
    ]
    policy = published_policy(
        trio,
        policy_body(
            [pc("SYN-CTRL-01", [ob("AREAS", [ev("E-AREAS", description="The areas the customer wants clarified")])])]
        ),
    )

    def with_rule(evaluation: dict[str, Any]) -> dict[str, Any]:
        return entry(multi, {"method": "SET_MATCH", "evaluation": evaluation}) | {"requirement": "E-AREAS"}

    # ---- configuration is validated against the PUBLISHED option set, by the existing validator
    for evaluation, why in (
        ({"mode": "EQUALS", "options": ["INVENTED"]}, "must be the question's options"),
        ({"mode": "EQUALS", "options": []}, "at least one expected option"),
        ({"mode": "SOME", "options": ["PREMIUM"]}, "how the selection is compared"),
        ({"mode": "EQUALS", "options": ["PREMIUM", "PREMIUM"]}, "listed twice"),
    ):
        r = post(
            author,
            f"{E}/mappings",
            {
                "market_code": "SG",
                "control_code": "SYN-CTRL-01",
                "combination": "ALL_REQUIRED",
                "applicability": None,
                "entries": [with_rule(evaluation)],
                "source": "Synthetic test mapping",
            },
        )
        assert (r.status_code, r.json()["code"]) == (422, "RULE_INVALID") and why in r.json()["message"], r.text
    m = mapped(trio, "SYN-CTRL-01", [with_rule({"mode": "INCLUDES_NONE", "options": ["CRITICAL_RISK"]})])
    assert m["entries"][0]["rule"] == {
        "method": "SET_MATCH",
        "answer_type": "MULTI_SELECT",
        "options": list(OPTS),
        "expected": {"mode": "INCLUDES_NONE", "options": ["CRITICAL_RISK"]},
        "fact_key": None,
    }
    assert m["entries"][0]["rule_text"] == "Expected selection: none of CRITICAL_RISK"

    def journey(selection: list[str] | None, bad: dict[str, Any] | None = None) -> dict[str, Any]:
        sim = start(author, vid, {})
        if bad is not None:
            sim = give(author, sim, "mi-clar/n1", bad).json()
        if selection is not None:
            sim = give(author, sim, "mi-clar/n1", {"choices": selection}).json()
        return instance(under(author, policy["id"], simulation_id=sim["id"]), "SYN-CTRL-01", "AREAS") | {
            "sim": sim["id"]
        }

    ok = journey(["BENEFITS", "PREMIUM"])
    o = ok["observations"][0]
    assert (
        o["result"],
        o["evaluation"]["method"],
        o["evaluation"]["answer"]["value"],
        o["evaluation"]["normalized_answer"],
    ) == ("MATCH", "SET_MATCH", ["BENEFITS", "PREMIUM"], ["PREMIUM", "BENEFITS"])
    assert (ok["outcome"], ok["coverage"], o["simulation_id"], o["item"]["answer_type"]) == (
        "SATISFIED",
        "EVIDENCED",
        ok["sim"],
        "MULTI_SELECT",
    )
    risk = journey(["PREMIUM", "CRITICAL_RISK"])
    assert (risk["observations"][0]["result"], risk["outcome"], risk["coverage"], risk["findings"]) == (
        "MISMATCH",
        "NOT_SATISFIED",
        "EVIDENCED",
        1,
    )
    # ---- unanswered, and refused, are their own evidence states — not answers, and not mismatches
    waiting = journey(None)
    assert (waiting["observations"][0]["result"], waiting["observations"][0]["gap"], waiting["outcome"]) == (
        "NOT_ASKED",
        "AWAITING_ANSWER",
        "INSUFFICIENT_EVIDENCE",
    )
    for bad, code in (
        ({"choices": []}, "TOO_FEW_SELECTED"),
        ({"choices": ["PREMIUM", "PREMIUM"]}, "DUPLICATE_OPTION"),
        ({"choices": ["INVENTED"]}, "UNKNOWN_OPTION"),
    ):
        refused = journey(None, bad)
        x = refused["observations"][0]
        assert (x["result"], x["gap"], x["refused_inputs"], refused["outcome"], refused["coverage"]) == (
            "UNRESOLVED",
            "ASKED_NO_ACCEPTED_ANSWER",
            [code],
            "INSUFFICIENT_EVIDENCE",
            "EVIDENCE_MISSING",
        )
    # a refused selection followed by an accepted one: the accepted answer is evaluated, the refusal stays on record
    recovered = journey(["CLAIMS"], {"choices": []})
    assert (recovered["observations"][0]["result"], recovered["observations"][0]["refused_inputs"]) == (
        "MATCH",
        ["TOO_FEW_SELECTED"],
    )


def test_history_survives_revisions_withdrawal_and_drift_under_a_policy(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    author, checker, publisher, people = trio
    sid, _, _ = build(author, "K1", "Evaluated survey")
    vid = publish(trio, sid)[1]
    it = items_of(db, vid)
    policy = published_policy(trio, policy_body([pc("SYN-CTRL-01", [ob("MAIN", [ev("E-Q")])])]))
    mapped(trio, "SYN-CTRL-01", [entry(it["mi-call/n2"], YES) | {"requirement": "E-Q"}])
    sim = simulate(author, vid, {}, {"mi-call/n2": {"choice": "YES"}, "mi-call/n5": {"choice": "YES"}})
    e = under(author, policy["id"], simulation_id=sim["id"])
    assert (e["coverage"]["status"], instance(e, "SYN-CTRL-01", "MAIN")["outcome"]) == (
        "COMPLETE_WITHIN_POLICY_SCOPE",
        "SATISFIED",
    )
    # a synthetic DECLARED_COMPLETE policy is complete only WITHIN ITS OWN SCOPE: nothing wider is claimed anywhere
    assert e["coverage"]["controls_outside_policy"] == ["SYN-CTRL-02", "SYN-CTRL-03", "SYN-CTRL-04", "SYN-CTRL-05"]
    assert (
        "Within this policy's declared scope" in e["coverage"]["explanation"]
        and e["operational_compliance_eligibility"]["status"] == "NOT_ESTABLISHED"
    )
    assert not [k for k in e if "complian" in k.lower() and k != "operational_compliance_eligibility"]

    # ---- a revised MAPPING (now expecting "no"): a new evaluation is NOT_SATISFIED with coverage still COMPLETE; the old one stays
    mapped(
        trio,
        "SYN-CTRL-01",
        [entry(it["mi-call/n2"], {"method": "EXACT_BOOLEAN", "expected_boolean": False}) | {"requirement": "E-Q"}],
    )
    e2 = under(author, policy["id"], simulation_id=sim["id"])
    line = instance(e2, "SYN-CTRL-01", "MAIN")
    assert e2["id"] != e["id"] and (line["outcome"], line["coverage"], e2["coverage"]["status"]) == (
        "NOT_SATISFIED",
        "EVIDENCED",
        "COMPLETE_WITHIN_POLICY_SCOPE",
    )  # coverage is not satisfaction
    old = author.get(f"{E}/evaluations/{e['id']}").json()
    assert (old["result_sha256"], instance(old, "SYN-CTRL-01", "MAIN")["outcome"], old["replay"]["consistent"]) == (
        e["result_sha256"],
        "SATISFIED",
        True,
    )
    assert [x["code"] for x in old["superseded_by_current_governance"]] == ["MAPPING_REVISED"]

    # ---- the policy is WITHDRAWN: no new evaluation under it; every past one still reads and recomputes
    r = post(author, f"{E}/control-policies/{policy['id']}/withdraw", {"reason": "short"})
    assert (r.status_code, r.json()["code"]) == (422, "COMMENT_REQUIRED")
    gone = post(
        publisher, f"{E}/control-policies/{policy['id']}/withdraw", {"reason": "No longer the governed policy"}
    ).json()
    assert gone["status"] == "WITHDRAWN" and [h["event"] for h in gone["history"]] == [
        "PROPOSED",
        "APPROVED",
        "PUBLISHED",
        "WITHDRAWN",
    ]
    listed = author.get(f"{E}/control-policies").json()["items"]
    assert [(p["status"], [h["event"] for h in p["history"]][-1]) for p in listed] == [
        ("WITHDRAWN", "WITHDRAWN")
    ]  # the list carries the review history
    assert (
        (
            post(author, f"{E}/evaluations", {"simulation_id": sim["id"], "control_policy_id": policy["id"]}).json()[
                "code"
            ]
        )
        == "POLICY_NOT_PUBLISHED"
    )
    assert (
        (
            post(
                publisher, f"{E}/control-policies/{policy['id']}/withdraw", {"reason": "Withdrawn a second time"}
            ).json()["code"]
        )
        == "NOT_OPEN"
    )
    kept = author.get(f"{E}/evaluations/{e2['id']}").json()
    assert (kept["result_sha256"], kept["replay"]["consistent"], kept["policy"]["revision"]) == (
        e2["result_sha256"],
        True,
        1,
    )
    assert "POLICY_REVISED" in [x["code"] for x in kept["superseded_by_current_governance"]]
    assert db.execute(text("SELECT count(*) FROM survey_control_policy")).scalar_one() == 1  # withdrawn, never deleted

    # ---- replay drift: an evaluation under a policy never rests on a simulation that recomputes differently
    real = simulation_module.execute_inputs

    def changed(bundle: Any, facts: Any, inputs: Any) -> Any:
        out = real(bundle, facts, inputs)
        out["trace"] = [*out["trace"], "changed engine"]
        return out

    monkeypatch.setattr(simulation_module, "execute_inputs", changed)
    drifted = author.get(f"{E}/evaluations/{e2['id']}").json()
    assert (drifted["status"], drifted["processing_status"], drifted["replay"]["consistent"]) == (
        "EVALUATION_DRIFT",
        e2["processing_status"],
        False,
    )
    assert (
        "EVIDENCE_CHANGED" in [x["code"] for x in drifted["replay"]["reasons"]]
        and drifted["result_sha256"] == e2["result_sha256"]
    )  # the record itself is not rewritten
    r = post(
        author,
        f"{E}/evaluations/preview",
        {
            "simulation_id": sim["id"],
            "policy": policy_body([pc("SYN-CTRL-01", [ob("MAIN", [ev("E-Q")])])], code="POL-DRIFT"),
        },
    )
    untrusted = r.json()
    assert r.status_code == 200 and (
        untrusted["processing_status"],
        untrusted["coverage"]["status"],
        untrusted["coverage"]["reason"],
    ) == ("FAILED_TECHNICALLY", "NOT_ASSERTED", "EVIDENCE_NOT_TRUSTED")
    assert (
        {c["coverage"] for c in untrusted["controls"]} == {"INTEGRITY_FAILED"}
        and untrusted["summary"]["by_outcome"]["SATISFIED"] == 0
        and untrusted["findings"] == []
    )


def _digest(engine: Engine, tables: tuple[str, ...]) -> dict[str, Any]:
    """Every row of the tables, exactly as stored, and their columns and keys."""
    out: dict[str, Any] = {}
    with engine.connect() as c:
        for t in tables:
            out[t] = sorted(str(dict(r)) for r in c.execute(text(f"SELECT * FROM call360_test.{t}")).mappings())
            out[t + ":columns"] = [
                tuple(r)
                for r in c.execute(
                    text(
                        "SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'call360_test' AND table_name = :t ORDER BY ordinal_position"
                    ),
                    {"t": t},
                )
            ]
            out[t + ":constraints"] = sorted(
                tuple(r) for r in c.execute(text(
                    "SELECT k.conname, k.contype::text, pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class r ON r.oid = k.conrelid "
                    "JOIN pg_namespace n ON n.oid = r.relnamespace WHERE n.nspname = 'call360_test' AND r.relname = :t"
                ), {"t": t})
            )  # fmt: skip
            out[t + ":indexes"] = sorted(
                tuple(r)
                for r in c.execute(
                    text(
                        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'call360_test' AND tablename = :t"
                    ),
                    {"t": t},
                )
            )
            out[t + ":triggers"] = sorted(
                r[0]
                for r in c.execute(
                    text(
                        "SELECT tgname FROM pg_trigger g JOIN pg_class r ON r.oid = g.tgrelid JOIN pg_namespace n ON n.oid = r.relnamespace WHERE n.nspname = 'call360_test' AND r.relname = :t AND NOT tgisinternal"
                    ),
                    {"t": t},
                )
            )
    return out


EVAL1 = (
    "survey_journey_evaluation",
    "survey_control_result",
    "survey_evidence_observation",
    "survey_evaluation_finding",
    "survey_control_mapping",
    "survey_control_mapping_event",
)
NEW_0034 = {
    "survey_control_policy",
    "survey_control_policy_event",
    "survey_evaluation_policy",
    "survey_obligation_result",
    "survey_obligation_observation",
    "survey_obligation_finding",
}


def test_zz_migration_0034_is_additive_over_a_database_populated_by_eval1(
    clean_rules: None, settings: Settings, engine: Engine, db: Session
) -> None:
    """§2: a schema at 0033 holding real EVAL-1 evaluations is upgraded, failed half-way, recovered, downgraded and
    upgraded again. Every EVAL-1 row, column, key, index and trigger is identical throughout, and reads the same."""
    from tests.support import migrate

    def head() -> str:
        with engine.connect() as c:
            return str(c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one())

    def tables() -> set[str]:
        with engine.connect() as c:
            return set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())

    # ---- a schema at 0033, populated the way EVAL-1 populated development: mappings, evaluations, results, findings
    db.rollback()
    migrate(settings, "0033_survey_control_evaluation", down=True)
    assert head() == "0033_survey_control_evaluation" and not (tables() & NEW_0034)
    people = [make_account(db, prefix=p) for p in ("m34a", "m34c", "m34p")]
    for person in people:
        GRANTS[person.principal_id] = ALL
    old_app = create_app(
        settings.model_copy(update=SETTINGS_ON)
    )  # evaluation on, control policies OFF: the EVAL-1 server
    with_grants(old_app)
    trio_ = tuple(_client(old_app, p) for p in people)
    publish_finding_rules(db, RULES_V1)
    sid, _, _ = build(trio_[0], "K8", "EVAL-1 survey")
    vid = publish(trio_, sid)[1]
    it = items_of(db, vid)
    mapped(trio_, "SYN-CTRL-01", [entry(it["mi-opening/n2"], YES), entry(it["mi-opening/n1"])])
    mapped(trio_, "SYN-CTRL-04", [entry(it["mi-replacement/n1"], YES)])
    yes = simulate(trio_[0], vid, K8_FACTS, {"mi-opening/n2": {"choice": "YES"}})
    no = simulate(trio_[0], vid, K8_FACTS, {"mi-opening/n2": {"choice": "NO"}})
    recorded = [evaluate(trio_[0], simulation_id=yes["id"]), evaluate(trio_[0], simulation_id=no["id"])]
    assert [len(e["findings"]) for e in recorded] == [0, 2] and all(e["replay"]["consistent"] for e in recorded)
    db.rollback()
    before = _digest(engine, EVAL1)
    assert [len(before[t]) for t in EVAL1] == [
        2,
        10,
        6,
        2,
        2,
        6,
    ]  # evaluations, control results, observations, findings, mappings, events
    audit_before = db.execute(text("SELECT count(*), max(seq) FROM audit_event")).one()
    db.rollback()

    def reads_the_same(c: TestClient) -> None:
        for e in recorded:
            now = c.get(f"{E}/evaluations/{e['id']}").json()
            assert {
                k: now[k]
                for k in (
                    "id",
                    "result_sha256",
                    "input_sha256",
                    "pins",
                    "controls",
                    "findings",
                    "coverage",
                    "summary",
                    "journey",
                    "processing_status",
                    "status",
                )
            } == {
                k: e[k]
                for k in (
                    "id",
                    "result_sha256",
                    "input_sha256",
                    "pins",
                    "controls",
                    "findings",
                    "coverage",
                    "summary",
                    "journey",
                    "processing_status",
                    "status",
                )
            }
            assert (
                now["replay"]["consistent"] is True
                and now["control_policy_id"] is None
                and all("obligation" not in x for x in now["controls"])
            )

    reads_the_same(trio_[0])

    # ---- 6. the migration FAILS at its last table: PostgreSQL rolls the whole revision back; nothing of it remains
    with engine.begin() as c:
        c.execute(text("CREATE TABLE call360_test.survey_obligation_finding (blocker integer)"))
    with pytest.raises(Exception, match="survey_obligation_finding"):
        migrate(settings, "0034_survey_control_policy")
    assert head() == "0033_survey_control_evaluation" and tables() & NEW_0034 == {
        "survey_obligation_finding"
    }  # only the blocker
    with engine.connect() as c:
        assert (
            c.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'call360_test' AND p.proname = 'survey_control_policy_event_guard'"
                )
            ).scalar_one()
            == 0
        )
    assert _digest(engine, EVAL1) == before
    reads_the_same(trio_[0])
    with engine.begin() as c:
        c.execute(text("DROP TABLE call360_test.survey_obligation_finding"))

    # ---- 1–5, 9. the upgrade: six new tables; every EVAL-1 row, column, key, index and trigger exactly as it was
    existing = tables()
    migrate(settings, "0034_survey_control_policy")
    assert head() == "0034_survey_control_policy" and tables() == existing | NEW_0034
    assert _digest(engine, EVAL1) == before
    assert tuple(db.execute(text("SELECT count(*), max(seq) FROM audit_event")).one()) == tuple(audit_before)
    db.rollback()
    reads_the_same(trio_[0])  # the EVAL-1 server still reads them …
    new_app = create_app(settings.model_copy(update=ON))
    with_grants(new_app)
    new_trio = tuple(_client(new_app, p) for p in people)
    reads_the_same(new_trio[0])  # … and so does the server with control policies on: no obligation key, no policy
    assert (
        evaluate(new_trio[0], simulation_id=yes["id"], expect=200)["id"] == recorded[0]["id"]
    )  # the same inputs are still the same evaluation
    assert verify_chain(db).ok
    db.rollback()

    # ---- 7. an EMPTY 0034 goes down and up; the EVAL-1 records are identical each time
    migrate(settings, "0033_survey_control_evaluation", down=True)
    assert head() == "0033_survey_control_evaluation" and not (tables() & NEW_0034) and _digest(engine, EVAL1) == before
    reads_the_same(trio_[0])
    migrate(settings, "0034_survey_control_policy")
    assert _digest(engine, EVAL1) == before

    # ---- 7, 8. POPULATED: a governed policy and an evaluation under it. The downgrade refuses; nothing is destroyed
    policy = published_policy(
        new_trio,
        policy_body([pc("SYN-CTRL-01", [ob("IDENTITY", [ev("E-ID")]), ob("OPENING", [ev("E-HELLO", "DELIVERY")])])]),
    )
    mapped(
        new_trio,
        "SYN-CTRL-01",
        [
            entry(it["mi-opening/n2"], YES) | {"requirement": "E-ID", "obligation": "IDENTITY"},
            entry(it["mi-opening/n1"]) | {"requirement": "E-HELLO", "obligation": "OPENING"},
        ],
    )
    scoped = under(new_trio[0], policy["id"], simulation_id=yes["id"])
    assert scoped["coverage"]["status"] == "COMPLETE_WITHIN_POLICY_SCOPE"
    db.rollback()
    with pytest.raises(RuntimeError, match="governed control policies exist"):
        migrate(settings, "0033_survey_control_evaluation", down=True)
    assert head() == "0034_survey_control_policy" and NEW_0034 <= tables()
    # the old evaluations: the same rows (only the new mapping and its events were added, by the new work above)
    after = _digest(engine, EVAL1)
    for t in ("survey_control_result", "survey_evidence_observation", "survey_evaluation_finding"):
        assert after[t] == before[t], t  # a policy-scoped evaluation writes NOTHING into the EVAL-1 result tables
    assert (
        set(before["survey_journey_evaluation"]) < set(after["survey_journey_evaluation"])
        and len(after["survey_journey_evaluation"]) == 3
    )
    assert db.execute(
        text(
            "SELECT (SELECT count(*) FROM survey_obligation_result), (SELECT count(*) FROM survey_obligation_observation), (SELECT count(*) FROM survey_evaluation_policy)"
        )
    ).one() == (2, 2, 1)
    reads_the_same(new_trio[0])
    assert new_trio[0].get(f"{E}/evaluations/{scoped['id']}").json()["result_sha256"] == scoped["result_sha256"]
    for c in (*trio_, *new_trio):
        c.__exit__(None, None, None)
    for person in people:
        GRANTS.pop(person.principal_id)
