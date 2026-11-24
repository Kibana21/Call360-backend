# ruff: noqa: E501, F811 — long document literals; fixtures imported from the other survey test modules
"""APPL-X1 — the Survey Applicability evaluator and its four stateless prototype operations.

Three-valued logic by its truth tables · unknown never becomes false · the four reasons a fact is not usable stay
distinct · additive selection · explicit replacement, only of named requirements and only while the replacer is
active · choose-one never decided by list order · the same survey asked for twice means only what the policy states ·
order never changes selection · exact condition versions · stable fingerprints · static analysis that claims only what
it enumerated · generated scenarios with an honest coverage statement · and an API that reads and writes nothing."""

from __future__ import annotations

import copy
import itertools
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.survey.applicability import analysis as A
from app.domain.survey.applicability import evaluator as E
from app.domain.survey.applicability.logic import (
    FALSE,
    TRUE,
    UNKNOWN,
    ApplicabilityError,
    Evaluation,
    Workspace,
    and3,
    not3,
    or3,
)
from app.main import create_app
from tests.support import make_account
from tests.test_survey_api import GRANTS, _client, post, with_grants

P = "/api/v1/survey-applicability/prototype"
T, F, U = TRUE, FALSE, UNKNOWN


def S(letter: str, version: int = 1) -> dict[str, Any]:
    return {
        "code": f"S-{letter}",
        "version": version,
        "name": f"Survey {letter}",
        "fingerprint": f"sha-{letter}-{version}",
    }


WS: dict[str, Any] = {
    "variables": [
        {"code": "product_family", "name": "Product family", "type": "ENUM",
         "values": [{"value": "ILP", "label": "Investment-linked"}, {"value": "PROTECTION", "label": "Protection"}]},
        {"code": "is_ilp", "name": "Is ILP", "type": "BOOLEAN",
         "derived": {"expr": {"op": "test", "variable": "product_family", "operator": "equals", "value": "ILP"}}},
        {"code": "nftf", "name": "NFTF applies", "type": "BOOLEAN"},
        {"code": "annual_premium", "name": "Annual premium", "type": "MONEY", "currency": "SGD", "min": 0},
        {"code": "riders", "name": "Selected riders", "type": "MULTI_ENUM",
         "values": [{"value": "CI", "label": "Critical illness"}, {"value": "WOP", "label": "Waiver of premium"}]},
        {"code": "commencement", "name": "Commencement date", "type": "DATE"},
        {"code": "channel", "name": "Sales channel", "type": "ENUM",
         "values": [{"value": "AGENCY", "label": "Agency"}, {"value": "DIRECT", "label": "Direct"}]},
    ],
    "conditions": [
        {"code": "ilp", "name": "Is ILP", "version": 1, "expr": {"op": "test", "variable": "is_ilp", "operator": "is_true"}},
        {"code": "nftf", "name": "NFTF applies", "version": 1, "expr": {"op": "test", "variable": "nftf", "operator": "is_true"}},
        {"code": "high_premium", "name": "High premium", "version": 2,
         "expr": {"op": "test", "variable": "annual_premium", "operator": "gte", "value": 50000},
         "history": [{"version": 1, "expr": {"op": "test", "variable": "annual_premium", "operator": "gte", "value": 20000}}]},
    ],
    "profiles": [
        {"code": "common", "name": "Common", "sections": [{"name": "Core", "variables": ["product_family", "channel", "annual_premium"]}]},
        {"code": "ilp_ext", "name": "ILP extension", "extends": ["common"], "sections": [{"name": "ILP", "variables": ["is_ilp"]}],
         "constraints": {"product_family": {"allowed": ["ILP"]}}},
        {"code": "prot_ext", "name": "Protection extension", "extends": ["common"], "sections": [],
         "constraints": {"product_family": {"allowed": ["PROTECTION"]}}},
        {"code": "nftf_ext", "name": "NFTF extension", "sections": [{"name": "NFTF", "variables": ["nftf"]}]},
    ],
}  # fmt: skip
ILP, NFTF = {"op": "ref", "condition": "ilp", "version": 1}, {"op": "ref", "condition": "nftf", "version": 1}
BOTH = {"op": "all", "args": [ILP, NFTF]}


def ws() -> Workspace:
    return Workspace(copy.deepcopy(WS))


def req(rid: str, when: Any, *letters: str, replaces: tuple[str, ...] = (), name: str | None = None) -> dict[str, Any]:
    return {"id": rid, "name": name or rid, "when": when, "action": {"kind": "INCLUDE", "surveys": [S(x) for x in letters]},
            "replaces": list(replaces)}  # fmt: skip


def policy(
    *reqs: dict[str, Any], shared: tuple[tuple[str, tuple[str, ...]], ...] = (), order: str = "ABCDE", **more: Any
) -> dict[str, Any]:
    return {"code": "P", "name": "Test policy", "market": "SG", "version": 1, "status": "DRAFT", "profiles": [], "scope": None,
            "shared_deliveries": [{"survey": f"S-{k}", "requirements": list(r)} for k, r in shared],
            "requirements": list(reqs), "order": [f"S-{x}" for x in order], **more}  # fmt: skip


def run(p: dict[str, Any], facts: dict[str, Any], profiles: list[str] | None = None) -> dict[str, Any]:
    return E.evaluate(ws(), p, facts, profiles)


def picked(plan: dict[str, Any]) -> list[str]:
    return [e["survey"]["code"][-1] for e in plan["selected"]]


def waiting(plan: dict[str, Any]) -> list[str]:
    return [e["survey"]["code"][-1] for e in plan["pending"]]


def outcomes(plan: dict[str, Any]) -> dict[str, str]:
    return {r["id"]: r["outcome"] for r in plan["requirements"]}


ILP_YES, ILP_NO = {"product_family": "ILP"}, {"product_family": "PROTECTION"}


# ------------------------------------------------------------------------------------------------- three-valued logic
def test_the_truth_tables_are_exactly_the_stated_ones() -> None:
    table_and = {(T, T): T, (T, F): F, (T, U): U, (F, F): F, (F, U): F, (U, U): U}
    table_or = {(T, T): T, (T, F): T, (T, U): T, (F, F): F, (F, U): U, (U, U): U}
    for (a, b), want in table_and.items():
        assert and3([a, b]) == and3([b, a]) == want
    for (a, b), want in table_or.items():
        assert or3([a, b]) == or3([b, a]) == want
    assert [not3(x) for x in (T, F, U)] == [F, T, U]
    assert and3([]) == T and or3([]) == F
    # and over every triple, the operators agree with the tables applied pairwise
    for trio in itertools.product((T, F, U), repeat=3):
        assert and3(list(trio)) == and3([and3(list(trio[:2])), trio[2]])
        assert or3(list(trio)) == or3([or3(list(trio[:2])), trio[2]])


def test_unknown_never_becomes_false_and_the_branch_responsible_is_marked() -> None:
    ev = Evaluation(ws(), {"product_family": "ILP", "nftf": None})
    trace = ev.expr(BOTH, "")
    assert trace["result"] == U and trace["text"] == "“Is ILP” and “NFTF applies”"
    ilp, nftf = trace["children"]
    assert (ilp["result"], ilp["decisive"]) == (T, False) and (nftf["result"], nftf["decisive"]) == (U, True)
    assert Evaluation(ws(), {"product_family": "PROTECTION", "nftf": None}).expr(BOTH, "")["result"] == F
    either = {"op": "any", "args": [ILP, NFTF]}
    assert Evaluation(ws(), {"product_family": "ILP", "nftf": None}).expr(either, "")["result"] == T
    assert Evaluation(ws(), {"product_family": "PROTECTION", "nftf": None}).expr(either, "")["result"] == U
    assert Evaluation(ws(), {"nftf": None}).expr({"op": "not", "arg": NFTF}, "")["result"] == U
    # the explicit checks are the only way to turn "not known" into yes or no
    known = {"op": "test", "variable": "nftf", "operator": "is_known"}
    assert Evaluation(ws(), {"nftf": None}).expr(known, "")["result"] == F
    assert Evaluation(ws(), {}).expr({"op": "test", "variable": "nftf", "operator": "is_unknown"}, "")["result"] == T


def test_the_reasons_a_fact_is_not_usable_stay_distinct() -> None:
    ev = Evaluation(
        ws(),
        {"product_family": "EQUITY", "nftf": None, "annual_premium": {"amount": 100, "currency": "USD"}},
        ["common"],
    )
    states = {c: ev.fact(c)["state"] for c in ("product_family", "nftf", "channel", "annual_premium")}
    assert states == {
        "product_family": "INVALID",
        "nftf": "UNKNOWN",
        "channel": "NOT_PROVIDED",
        "annual_premium": "INVALID",
    }
    assert ev.fact("nftf")["outside_profiles"] is True and "outside_profiles" not in ev.fact("channel")
    assert "not SGD" in ev.fact("annual_premium")["reason"]
    assert Evaluation(ws(), {"nftf": None}).fact("nftf")["state"] == "UNKNOWN"
    # a derived fact is known when its source is, unknown when it is not — never guessed
    derived = Evaluation(ws(), ILP_YES).fact("is_ilp")
    assert (derived["state"], derived["value"]) == ("KNOWN", True)
    assert Evaluation(ws(), {}).fact("is_ilp")["state"] == "UNKNOWN"
    # a malformed document is an error, not a business outcome
    with pytest.raises(ApplicabilityError) as bad:
        Evaluation(ws(), {}).expr({"op": "test", "variable": "nftf", "operator": "gt", "value": 1}, "")
    assert bad.value.code == "OPERATOR_NOT_ALLOWED"


def test_typed_operators() -> None:
    def val(expr: dict[str, Any], facts: dict[str, Any]) -> str:
        return str(Evaluation(ws(), facts).expr(expr, "")["result"])

    t = lambda v, o, **k: {"op": "test", "variable": v, "operator": o, **k}  # noqa: E731
    assert val(t("annual_premium", "between", min=1000, max=5000), {"annual_premium": 5000}) == T
    assert val(t("annual_premium", "gt", value=5000), {"annual_premium": 5000}) == F
    assert val(t("annual_premium", "gte", value=5000), {"annual_premium": {"amount": 5000, "currency": "SGD"}}) == T
    assert val(t("annual_premium", "gte", value=5000), {"annual_premium": -1}) == U  # below the minimum: invalid
    assert val(t("riders", "includes_any", values=["CI"]), {"riders": ["WOP", "CI"]}) == T
    assert val(t("riders", "includes_all", values=["CI", "WOP"]), {"riders": ["CI"]}) == F
    assert val(t("riders", "includes_none", values=["CI"]), {"riders": []}) == T
    assert val(t("channel", "in", values=["DIRECT", "AGENCY"]), {"channel": "DIRECT"}) == T
    assert val(t("channel", "not_in", values=["DIRECT"]), {"channel": "DIRECT"}) == F
    assert val(t("commencement", "before", value="2026-07-01"), {"commencement": "2026-06-30"}) == T
    assert val(t("commencement", "between", min="2026-01-01", max="2026-12-31"), {"commencement": "2027-01-01"}) == F
    assert val(t("commencement", "on", value="2026-01-01"), {"commencement": "not a date"}) == U


# ------------------------------------------------------------------------------------------- the ten mandatory cases
def test_case_1_independent_requirements_select_both() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"))
    assert picked(run(p, {**ILP_YES, "nftf": True})) == ["A", "B"]
    assert picked(run(p, {**ILP_YES, "nftf": False})) == ["A"]
    assert picked(run(p, {**ILP_NO, "nftf": True})) == ["B"]
    none = run(p, {**ILP_NO, "nftf": False})
    assert (none["status"], picked(none), none["summary"]) == ("RESOLVED", [], "No survey is required.")


def test_case_2_a_joined_requirement_needs_both() -> None:
    p = policy(req("c", BOTH, "C"))
    assert picked(run(p, {**ILP_YES, "nftf": True})) == ["C"]
    assert picked(run(p, {**ILP_YES, "nftf": False})) == picked(run(p, {**ILP_NO, "nftf": True})) == []


def test_case_3_additive_overlap_selects_all_three() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C"))
    plan = run(p, {**ILP_YES, "nftf": True})
    assert (plan["status"], picked(plan)) == ("RESOLVED", ["A", "B", "C"])
    assert set(outcomes(plan).values()) == {"ACTIVE"}


def test_case_4_explicit_replacement_removes_only_the_named_requirements() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("d", ILP, "D"), req("c", BOTH, "C", replaces=("a", "b")))
    plan = run(p, {**ILP_YES, "nftf": True})
    assert picked(plan) == ["C", "D"]  # D is unrelated and stays
    assert outcomes(plan) == {"a": "REPLACED", "b": "REPLACED", "d": "ACTIVE", "c": "ACTIVE"}
    assert {x["survey"]["code"]: x["why"][0]["reason"] for x in plan["excluded"]} == {
        "S-A": "REPLACED",
        "S-B": "REPLACED",
    }
    # the replacer does not apply: nothing is replaced
    assert picked(run(p, {**ILP_YES, "nftf": False})) == ["A", "D"]
    # AP-1: a chain is refused — by validation, with the fix named, and by the evaluator. Nothing transitive is applied
    chain = policy(*p["requirements"], req("x", ILP, "E", replaces=("c",), name="X"))
    blockers = [d for d in A.analyse_policy(ws(), chain) if d["severity"] == "BLOCKER"]
    assert [d["code"] for d in blockers] == ["REPLACEMENT_CHAIN"] and "Chains are not allowed" in blockers[0]["message"]
    assert blockers[0]["at"] == {"kind": "requirement", "id": "x", "part": "replaces"}
    with pytest.raises(ApplicabilityError) as exc:
        run(chain, {**ILP_YES, "nftf": True})
    assert exc.value.code == "REPLACEMENT_CHAIN"
    # the explicit form: X names every final target itself
    flat = policy(*p["requirements"][:3], req("x", BOTH, "E", replaces=("a", "b", "d"), name="X"))
    assert not [d for d in A.analyse_policy(ws(), flat) if d["severity"] == "BLOCKER"]
    assert outcomes(run(flat, {**ILP_YES, "nftf": True})) == {
        "a": "REPLACED",
        "b": "REPLACED",
        "d": "REPLACED",
        "x": "ACTIVE",
    }


def test_case_5_one_condition_several_surveys() -> None:
    assert picked(run(policy(req("m", BOTH, "A", "B", "C")), {**ILP_YES, "nftf": True})) == ["A", "B", "C"]


def test_case_6_choose_one_is_never_decided_by_list_order() -> None:
    high = {"op": "test", "variable": "annual_premium", "operator": "gte", "value": 50000}
    direct = {"op": "test", "variable": "channel", "operator": "equals", "value": "DIRECT"}

    def choose(*alts: tuple[str, Any]) -> dict[str, Any]:
        rows = [
            {"survey": S(k), "when": None, "fallback": True} if w == "FALLBACK" else {"survey": S(k), "when": w}
            for k, w in alts
        ]
        return policy(
            {"id": "x", "name": "Pick one", "when": ILP, "action": {"kind": "CHOOSE_ONE", "alternatives": rows}}
        )

    p = choose(("A", high), ("B", direct))
    facts = {**ILP_YES, "annual_premium": 60000, "channel": "AGENCY"}
    assert picked(run(p, facts)) == ["A"]  # one eligible
    assert picked(run(p, {**facts, "annual_premium": 10, "channel": "DIRECT"})) == ["B"]
    both = run(p, {**facts, "channel": "DIRECT"})  # more than one eligible
    assert (both["status"], outcomes(both), picked(both), waiting(both)) == (
        "UNRESOLVED",
        {"x": "AMBIGUOUS"},
        [],
        ["A", "B"],
    )
    assert (
        picked(run(choose(("B", direct), ("A", high)), {**facts, "channel": "DIRECT"})) == []
    )  # reversed: still nothing
    neither = run(p, {**facts, "annual_premium": 10})  # none eligible, no fallback
    assert (neither["status"], outcomes(neither)) == ("UNRESOLVED", {"x": "NO_ALTERNATIVE"})
    assert picked(run(choose(("A", high), ("B", "FALLBACK")), {**facts, "annual_premium": 10})) == [
        "B"
    ]  # an explicit fallback
    unknown = run(p, {**ILP_YES, "annual_premium": 60000})  # an unknown criterion: B might be eligible too
    assert (unknown["status"], outcomes(unknown), [n["variable"] for n in unknown["needs"]]) == (
        "UNRESOLVED",
        {"x": "CHOICE_UNRESOLVED"},
        ["channel"],
    )
    assert {d["code"] for d in A.analyse_policy(ws(), p)} >= {"CAN_BE_AMBIGUOUS", "CAN_BE_NO_ALTERNATIVE"}
    # AP-8: an alternative with no criterion is NOT a fallback. It is incomplete, and nothing is ever chosen through it
    bare = choose(("A", high), ("B", None))
    assert outcomes(run(bare, {**facts, "annual_premium": 10})) == {"x": "NO_ALTERNATIVE"}
    assert [d["code"] for d in A.analyse_policy(ws(), bare) if d["severity"] == "BLOCKER"] == ["MISSING_CRITERION"]
    assert "SEVERAL_FALLBACKS" in [
        d["code"] for d in A.analyse_policy(ws(), choose(("A", "FALLBACK"), ("B", "FALLBACK")))
    ]


def test_case_7_the_same_survey_twice_is_resolved_per_collision_never_silently() -> None:
    hp = {"op": "ref", "condition": "high_premium", "version": 2}
    reqs = (
        req("a", ILP, "A", name="ILP needs A"),
        req("b", NFTF, "A", name="NFTF needs A"),
        req("h", hp, "A", name="High premium needs A"),
    )
    both = {**ILP_YES, "nftf": True, "annual_premium": 10}
    # AP-2: nothing said → unresolved, naming exactly the requirements that collide; both stay on the record
    silent = run(policy(*reqs), both)
    assert silent["status"] == "UNRESOLVED"
    assert [(d["code"], d["requirements"]) for d in silent["diagnostics"]] == [("DUPLICATE_SURVEY", ["a", "b"])]
    assert silent["selected"][0]["required_by"] == ["a", "b"] and silent["selected"][0]["conflict"] is True
    # the author resolves THIS collision: one delivery satisfies a and b
    stated = policy(*reqs, shared=(("A", ("a", "b")),))
    once = run(stated, both)
    assert (once["status"], picked(once), once["selected"][0]["required_by"], once["selected"][0]["obligations"]) == (
        "RESOLVED",
        ["A"],
        ["a", "b"],
        2,
    )
    assert [d["code"] for d in once["diagnostics"]] == ["SURVEY_SHARED_DELIVERY"]
    # …and that statement does not silently cover a different collision of the same survey
    three = run(stated, {**both, "annual_premium": 90000})
    assert (three["status"], [(d["code"], d["requirements"]) for d in three["diagnostics"]]) == (
        "UNRESOLVED",
        [("DUPLICATE_SURVEY", ["a", "b", "h"])],
    )
    # validation finds an unresolved collision before any scenario is run, with an example
    found = [d for d in A.analyse_policy(ws(), policy(*reqs[:2])) if d["code"] == "DUPLICATE_SURVEY"]
    assert len(found) == 1 and found[0]["severity"] == "BLOCKER" and "For example when" in found[0]["message"]
    assert not [
        d for d in A.analyse_policy(ws(), policy(*reqs[:2], shared=(("A", ("a", "b")),))) if d["severity"] == "BLOCKER"
    ]
    # requirements that can never apply together do not collide
    apart = policy(req("a", ILP, "A"), req("n", {"op": "not", "arg": ILP}, "A"))
    assert not [d for d in A.analyse_policy(ws(), apart) if d["code"] == "DUPLICATE_SURVEY"]
    # a shared delivery must be about requirements that ask for that survey
    wrong = policy(req("a", ILP, "A"), req("b", NFTF, "B"), shared=(("A", ("a", "b")),))
    assert "SHARED_DELIVERY_MISMATCH" in [d["code"] for d in A.analyse_policy(ws(), wrong)]
    # different versions of one survey are always an error
    v = policy(req("a", ILP, "A"), {**req("b", NFTF), "action": {"kind": "INCLUDE", "surveys": [S("A", 2)]}})
    assert "SURVEY_VERSION_CONFLICT" in [d["code"] for d in A.analyse_policy(ws(), v)]


def test_case_8_a_missing_fact_leaves_the_joined_requirement_unresolved() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C", replaces=("a", "b")))
    plan = run(p, {**ILP_YES, "nftf": None})
    assert plan["status"] == "UNRESOLVED"
    assert outcomes(plan) == {"a": "PENDING", "b": "UNRESOLVED", "c": "UNRESOLVED"}  # A may yet be replaced
    assert (picked(plan), waiting(plan)) == ([], ["A", "B", "C"])
    assert plan["needs"] == [
        {
            "variable": "nftf",
            "name": "NFTF applies",
            "state": "UNKNOWN",
            "reason": "the application says it is not known",
        }
    ]
    assert "cannot be decided" in plan["explanation"][1] and "may be replaced" in plan["explanation"][0]
    # without replacement the part that IS decided is still shown, separately from the pending part
    additive = run(policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C")), ILP_YES)
    assert (additive["status"], picked(additive), waiting(additive)) == ("UNRESOLVED", ["A"], ["B", "C"])
    assert additive["needs"][0]["state"] == "NOT_PROVIDED"
    # an unknown that cannot matter does not block: the product is not ILP, so the joined condition is false
    assert run(policy(req("c", BOTH, "C")), {**ILP_NO, "nftf": None})["status"] == "RESOLVED"


def test_case_9_contradictory_and_circular_replacement_is_found_by_validation() -> None:
    circle = policy(req("a", ILP, "A", replaces=("b",)), req("b", NFTF, "B", replaces=("a",)))
    codes = [d["code"] for d in A.analyse_policy(ws(), circle)]
    assert "REPLACEMENT_CYCLE" in codes
    with pytest.raises(ApplicabilityError) as exc:
        run(circle, {**ILP_YES, "nftf": True})
    assert exc.value.code == "REPLACEMENT_CYCLE"
    bad = policy(req("a", ILP, "A", replaces=("a", "ghost")))
    assert {d["code"] for d in A.analyse_policy(ws(), bad)} >= {"REPLACES_ITSELF", "REPLACES_UNKNOWN"}
    # a requirement that is replaced every time it applies never contributes
    always = policy(req("a", ILP, "A"), req("b", ILP, "B", replaces=("a",)))
    assert "ALWAYS_REPLACED" in [d["code"] for d in A.analyse_policy(ws(), always)]


def test_case_10_several_policies_in_scope_are_never_settled_silently() -> None:
    ilp_scope = {"op": "test", "variable": "product_family", "operator": "equals", "value": "ILP"}
    one, two = policy(scope=ilp_scope, code="ONE"), policy(scope=None, code="TWO")
    three = policy(
        scope={"op": "test", "variable": "product_family", "operator": "equals", "value": "PROTECTION"}, code="THREE"
    )
    assert E.resolve_policy(ws(), [one, three], ILP_YES) == {"status": "ONE_POLICY", "policy": "ONE", "policies": [
        {"code": "ONE", "name": "Test policy", "scope": T}, {"code": "THREE", "name": "Test policy", "scope": F}]}  # fmt: skip
    assert E.resolve_policy(ws(), [one, two], ILP_YES)["status"] == "MULTIPLE_POLICIES"
    assert E.resolve_policy(ws(), [one, three], {})["status"] == "POLICY_UNRESOLVED"
    assert E.resolve_policy(ws(), [three], ILP_YES)["status"] == "NO_POLICY"
    assert run(policy(req("a", None, "A"), scope=ilp_scope), ILP_NO)["status"] == "OUT_OF_SCOPE"
    assert run(policy(req("a", None, "A"), scope=ilp_scope), {})["status"] == "SCOPE_UNRESOLVED"


# -------------------------------------------------------------------------------------- order, versions, fingerprints
def test_order_places_surveys_and_never_selects_them() -> None:
    reqs = (req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C"))
    facts = {**ILP_YES, "nftf": True}
    assert picked(run(policy(*reqs, order="CBA"), facts)) == ["C", "B", "A"]
    assert [e["position"] for e in run(policy(*reqs, order="CBA"), facts)["selected"]] == [1, 2, 3]
    assert sorted(picked(run(policy(*reqs, order="BAC"), facts))) == ["A", "B", "C"]
    # the order of the requirements themselves changes nothing
    assert picked(run(policy(*reversed(reqs)), facts)) == ["A", "B", "C"]
    missing = A.analyse_policy(ws(), policy(*reqs, order="AB"))
    assert [(d["severity"], d["code"]) for d in missing] == [("BLOCKER", "ORDER_MISSING")]


def test_a_policy_keeps_the_exact_condition_version_it_names() -> None:
    old = policy(req("h", {"op": "ref", "condition": "high_premium", "version": 1}, "A"))
    new = policy(req("h", {"op": "ref", "condition": "high_premium", "version": 2}, "A"))
    facts = {"annual_premium": 30000}  # at least 20,000 (version 1) but not 50,000 (version 2)
    assert (picked(run(old, facts)), picked(run(new, facts))) == (["A"], [])
    assert E.fingerprint(ws(), old) != E.fingerprint(ws(), new)
    # a newer version of the condition changes nothing for the policy that names version 1
    later = copy.deepcopy(WS)
    hp = next(c for c in later["conditions"] if c["code"] == "high_premium")
    hp["history"].append({"version": 2, "expr": hp["expr"]})
    hp.update(version=3, expr={"op": "test", "variable": "annual_premium", "operator": "gte", "value": 99999})
    assert picked(E.evaluate(Workspace(later), old, facts)) == ["A"]
    assert E.fingerprint(Workspace(later), old) == E.fingerprint(ws(), old)
    with pytest.raises(ApplicabilityError) as exc:
        run(policy(req("h", {"op": "ref", "condition": "high_premium", "version": 9}, "A")), facts)
    assert exc.value.code == "UNKNOWN_CONDITION_VERSION"


def test_the_same_input_gives_the_same_bytes_and_any_change_gives_another_fingerprint() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C", replaces=("a", "b")))
    one = run(p, {"product_family": "ILP", "nftf": True})
    two = run(copy.deepcopy(p), {"nftf": True, "product_family": "ILP"})  # another key order
    assert one == two and one["fingerprint"] == two["fingerprint"]
    assert one["record_class"] == "SIMULATION" and "not an assignment" in one["note"]
    assert run(p, {"product_family": "ILP", "nftf": False})["fingerprint"] != one["fingerprint"]
    renamed = copy.deepcopy(p)
    renamed["requirements"][2]["replaces"] = ["a"]
    assert (
        run(renamed, {"product_family": "ILP", "nftf": True})["policy"]["fingerprint"] != one["policy"]["fingerprint"]
    )
    cmp = E.compare(run(policy(req("a", ILP, "A"), req("b", NFTF, "B")), {**ILP_YES, "nftf": True}), one)
    assert (cmp["changed"], cmp["added"], cmp["removed"]) == (True, ["Survey C"], ["Survey A", "Survey B"])
    assert [b["change"] for b in cmp["because"]] == ["OUTCOME", "OUTCOME", "NEW"]
    same = E.compare(one, one)
    assert (same["changed"], same["because"]) == (False, [])


# ---------------------------------------------------------------------------------------- profiles, analysis, generate
def test_profiles_compose_and_incompatible_ones_are_reported_not_merged() -> None:
    members, rules = ws().profile_variables(["ilp_ext", "nftf_ext"])
    assert members == {"product_family", "channel", "annual_premium", "is_ilp", "nftf"}
    assert [r["profile"] for r in rules["product_family"]] == ["ilp_ext"]
    # a value the profile does not allow is invalid, not silently accepted
    assert Evaluation(ws(), {"product_family": "PROTECTION"}, ["ilp_ext"]).fact("product_family")["state"] == "INVALID"
    clash = [
        d
        for d in A.analyse_policy(ws(), policy(req("a", ILP, "A"), profiles=["ilp_ext", "prot_ext"]))
        if d["code"] == "PROFILE_CONFLICT"
    ]
    assert len(clash) == 1 and "no application fits both" in clash[0]["message"]
    outside = policy(req("b", NFTF, "B"), profiles=["common"])
    assert [d["code"] for d in A.analyse_policy(ws(), outside) if d["severity"] == "WARNING"] == [
        "VARIABLE_OUTSIDE_PROFILES"
    ]
    # a policy's profiles never decide whether it applies: only its explicit scope does. The fact is still read
    assert picked(run(outside, {"nftf": True})) == ["B"]
    # the profiles an APPLICATION states are used to check its own facts
    stated = run(outside, {"nftf": True}, ["common"])
    assert (picked(stated), stated["facts"]["nftf"]["state"], stated["facts"]["nftf"]["outside_profiles"]) == (
        ["B"],
        "KNOWN",
        True,
    )
    # …where a profile narrows a value, a value outside it is invalid
    assert Evaluation(ws(), {"product_family": "PROTECTION"}, ["ilp_ext"]).fact("product_family")["state"] == "INVALID"


def test_analysis_claims_only_what_it_enumerated() -> None:
    w = copy.deepcopy(WS)
    w["conditions"] += [
        {
            "code": "never",
            "name": "ILP and not ILP",
            "version": 1,
            "expr": {"op": "all", "args": [ILP, {"op": "not", "arg": ILP}]},
        },
        {
            "code": "always",
            "name": "ILP or not ILP",
            "version": 1,
            "expr": {"op": "any", "args": [ILP, {"op": "not", "arg": ILP}]},
        },
        {"code": "twice", "name": "Says it twice", "version": 1, "expr": {"op": "all", "args": [NFTF, NFTF]}},
        {"code": "loop_a", "name": "Loop A", "version": 1, "expr": {"op": "ref", "condition": "loop_b", "version": 1}},
        {"code": "loop_b", "name": "Loop B", "version": 1, "expr": {"op": "ref", "condition": "loop_a", "version": 1}},
        {
            "code": "wrong",
            "name": "Wrong value",
            "version": 1,
            "expr": {"op": "test", "variable": "channel", "operator": "equals", "value": "PHONE"},
        },
        {
            "code": "range",
            "name": "Backwards",
            "version": 1,
            "expr": {"op": "test", "variable": "annual_premium", "operator": "between", "min": 9, "max": 1},
        },
    ]
    found = {(d["at"].get("code"), d["code"]) for d in A.analyse(Workspace(w))}
    assert found >= {("never", "NEVER_TRUE"), ("always", "ALWAYS_TRUE"), ("twice", "DUPLICATE_PREDICATE"), ("loop_a", "CONDITION_CYCLE"),
                     ("loop_b", "CONDITION_CYCLE"), ("wrong", "VALUE_NOT_ALLOWED"), ("range", "RANGE_REVERSED")}  # fmt: skip
    assert not [d for d in A.analyse(ws()) if d["severity"] == "BLOCKER"]
    # too many combinations: it says it did not check, never that all is well
    big = copy.deepcopy(WS)
    big["variables"] += [
        {
            "code": f"e{i}",
            "name": f"E{i}",
            "type": "ENUM",
            "values": [{"value": str(n), "label": str(n)} for n in range(9)],
        }
        for i in range(6)
    ]
    wide = {
        "op": "all",
        "args": [{"op": "test", "variable": f"e{i}", "operator": "equals", "value": "1"} for i in range(6)],
    }
    out: list[dict[str, Any]] = []
    A.check_reach(Workspace(big), wide, {"kind": "condition", "code": "wide"}, out)
    assert [d["code"] for d in out] == ["NOT_CHECKED"]
    # numeric thresholds are examined at, below and above
    space = A.enumerate_facts(
        ws(), [{"op": "test", "variable": "annual_premium", "operator": "gte", "value": 50000}], unknown=False
    )
    assert [f["annual_premium"] for f in space["combinations"]] == [49999.99, 50000, 50000.01] and space["exhaustive"]


def test_generated_scenarios_cover_each_distinct_result_and_say_what_is_not_covered() -> None:
    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C", replaces=("a", "b")))
    g = A.generate(ws(), p)
    cov = g["coverage"]
    assert (cov["checked"], cov["exhaustive"], cov["combinations_examined"], cov["distinct_results"]) == (
        True,
        True,
        9,
        9,
    )
    assert [v["code"] for v in cov["variables"]] == ["product_family", "nftf"]  # only what the policy reads
    kinds = [s["kind"] for s in g["scenarios"]]
    assert kinds.count("COMBINATION") == 9 and kinds[-2:] == ["INVALID_INPUT", "MISSING_INPUT"]
    first = g["scenarios"][0]
    assert first["facts"] == {"product_family": "ILP", "nftf": True} and "Survey C" in first["description"]
    assert {r["id"]: r["never_active"] for r in cov["requirements"]} == {"a": False, "b": False, "c": False}
    assert any("Only variables this policy reads" in n for n in cov["not_covered"])
    invalid = run(p, g["scenarios"][-2]["facts"])
    assert invalid["facts"]["product_family"]["state"] == "INVALID" and "FACT_INVALID" in [
        d["code"] for d in invalid["diagnostics"]
    ]


# ------------------------------------------------------------------------------------------------------------- the API
@pytest.fixture()
def appl_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_applicability_prototype_enabled": True,
                "transcription_worker": False,
            }
        )
    )
    with_grants(app)
    return app


def test_the_prototype_operations_are_stateless_permissioned_and_off_by_default(
    appl_app: Any, settings: Settings, db: Session
) -> None:
    reader, outsider = make_account(db, prefix="applreader"), make_account(db, prefix="applnone")
    GRANTS[reader.principal_id] = {"survey.read"}
    GRANTS[outsider.principal_id] = {"script.read", "assignment_rule.read"}
    tables = [
        r[0]
        for r in db.execute(
            text(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name NOT IN ('audit_event', 'auth_session', 'principal', 'identity_binding', 'local_credential', 'group_membership', 'app_group', 'refresh_token', 'rate_limit_bucket')"
            )
        )
    ]

    def rows() -> dict[str, int]:
        db.rollback()
        return {t: db.execute(text(f'SELECT count(*) FROM "{t}"')).scalar_one() for t in tables}  # noqa: S608 — names from the catalogue

    p = policy(req("a", ILP, "A"), req("b", NFTF, "B"), req("c", BOTH, "C", replaces=("a", "b")))
    before = policy(req("a", ILP, "A"), req("b", NFTF, "B"))
    body = {"workspace": WS, "policy": p, "compare_with": before,
            "scenarios": [{"id": "both", "facts": {"product_family": "ILP", "nftf": True}}, {"id": "unknown", "facts": {"product_family": "ILP"}}]}  # fmt: skip
    try:
        with _client(appl_app, reader) as c, _client(appl_app, outsider) as other:
            had = rows()
            r = post(c, f"{P}/evaluate", body)
            assert r.status_code == 200, r.text
            out = r.json()
            assert out["contract"] == "call360.survey-applicability/0" and "nothing is stored" in out["note"]
            both, unknown = out["result"]["results"]
            assert picked(both["plan"]) == ["C"] and picked(both["before"]) == ["A", "B"]
            assert both["comparison"]["added"] == ["Survey C"] and both["comparison"]["removed"] == [
                "Survey A",
                "Survey B",
            ]
            assert unknown["plan"]["status"] == "UNRESOLVED" and unknown["comparison"]["new_unknown"] is False
            assert post(c, f"{P}/evaluate", body).json() == out  # the same request, the same answer
            assert out["result"]["policy_fingerprint"] == E.fingerprint(ws(), p)

            t = post(
                c,
                f"{P}/condition-test",
                {"workspace": WS, "expr": BOTH, "facts": {"product_family": "ILP", "nftf": None}},
            ).json()["result"]
            assert (t["status"], t["result"], t["needs"][0]["variable"]) == ("OK", "UNKNOWN", "nftf")
            bad = post(
                c,
                f"{P}/condition-test",
                {"workspace": WS, "expr": {"op": "test", "variable": "ghost", "operator": "is_true"}, "facts": {}},
            ).json()["result"]
            assert (bad["status"], bad["diagnostics"][0]["code"]) == ("INVALID", "UNKNOWN_VARIABLE")

            a = post(c, f"{P}/analyse", {"workspace": WS, "policy": policy(req("a", ILP, "A"), order="B")}).json()[
                "result"
            ]
            assert (a["status"], a["blockers"], a["diagnostics"][0]["code"]) == ("BLOCKED", 1, "ORDER_MISSING")
            assert post(c, f"{P}/analyse", {"workspace": WS, "policy": p}).json()["result"]["status"] == "OK"

            g = post(c, f"{P}/scenarios", {"workspace": WS, "policy": p, "limit": 5}).json()["result"]
            assert g["coverage"]["shown"] == 5 and any(
                "further distinct results" in n for n in g["coverage"]["not_covered"]
            )

            # a document the evaluator cannot run is reported as an error of that scenario, not a server failure
            broken = post(c, f"{P}/evaluate", {**body, "policy": policy(req("a", ILP, "A", replaces=("a",)))}).json()[
                "result"
            ]["results"][0]["plan"]
            assert (broken["status"], broken["error"]["code"]) == ("ERROR", "INVALID_REPLACEMENT")
            assert (
                post(
                    c, f"{P}/evaluate", {**body, "scenarios": [{"id": str(i), "facts": {}} for i in range(301)]}
                ).status_code
                == 422
            )

            for path, payload in ((f"{P}/evaluate", body), (f"{P}/analyse", {"workspace": WS}), (f"{P}/scenarios", {"workspace": WS, "policy": p}),
                                  (f"{P}/condition-test", {"workspace": WS, "expr": ILP})):  # fmt: skip
                assert post(other, path, payload).status_code == 403
                assert c.post(path, json=payload).status_code == 403  # no CSRF token
            assert rows() == had  # nothing was written anywhere
    finally:
        GRANTS.pop(reader.principal_id, None)
        GRANTS.pop(outsider.principal_id, None)
    # off by default: the routes do not exist
    off = create_app(settings.model_copy(update={"survey_definitions_enabled": True, "transcription_worker": False}))
    assert not [p for p in off.openapi()["paths"] if "survey-applicability" in p]
    assert sorted(p.rsplit("/", 1)[1] for p in appl_app.openapi()["paths"] if "survey-applicability" in p) == [
        "analyse", "condition-test", "evaluate", "scenarios",
    ]  # fmt: skip
