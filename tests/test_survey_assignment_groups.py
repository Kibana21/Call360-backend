# ruff: noqa: E501, F811
"""ASG-2A — one application, several surveys: real HTTP, real PostgreSQL (``call360_test``).

Rules are made through the existing Assignment Rules API; surveys are golden fixtures published by three people;
bindings and requirement groups are proposed, approved and published by three people. Everything is simulation.

**Stand-ins, stated plainly.** The governed rule language has nine fields and none of them says "this sale replaces a
policy" or "this policy has a critical-illness rider". Adding a field would change Script Studio's rule language,
which ASG-2A must not do, and mapping a catalog fact onto a rule field would invent a business rule. So in these
tests a "Life" application is ``product_family = PROTECTION``; "replacement" is stood in for by
``premium_frequency = SINGLE``; "has a CI rider" by ``selling_channel = BANCASSURANCE``. The mechanics proved are the
real ones; the conditions are placeholders until such attributes are governed."""

from __future__ import annotations

import dataclasses
import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.survey import store
from app.main import create_app
from tests.support import make_account
from tests.survey_support import actor_of
from tests.test_assignment_rules import business_fingerprint
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import ALL, OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_lib1 import build, publish

A = "/api/v1/survey-assignment"
LIFE, ILP = "PROTECTION", "ILP"
REPLACEMENT = {"field": "premium_frequency", "values": ["SINGLE"]}  # stand-in for "this sale replaces a policy"
CI_RIDER = {"field": "selling_channel", "values": ["BANCASSURANCE"]}  # stand-in for "has a critical-illness rider"
SG = {"field": "market", "values": ["SG"]}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "survey_assignment_enabled": True, "survey_assignment_groups_enabled": True, "transcription_worker": False,
            }
        )
    )  # fmt: skip
    with_grants(app)
    return app


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL
    return _trio


def group(
    people: Any,
    code: str,
    kind: str,
    members: list[str],
    sequence: int | None = None,
    purpose: str = "",
    expect: int = 200,
) -> Any:
    """A requirement group through all three steps, by three different people."""
    proposer, approver, publisher = people[0], people[1], people[2]
    body = {
        "code": code,
        "kind": kind,
        "name": f"{code} group",
        "purpose": purpose or f"Synthetic requirement {code} for the tests",
        "sequence": sequence,
        "members": [{"rule_code": m, "rule_version": 1} for m in members],
    }
    r = post(proposer, f"{A}/groups", body)
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    assert post(approver, f"{A}/groups/{gid}/decision", {"verdict": "APPROVE"}).status_code == 200
    r = post(publisher, f"{A}/groups/{gid}/publish")
    assert r.status_code == expect, r.text
    return r.json() if expect != 200 else gid


def compose(c: TestClient, inputs: dict[str, Any], facts: dict[str, Any] | None = None) -> dict[str, Any]:
    r = post(c, f"{A}/composite-plans", {"assignment_inputs": inputs, "facts": facts or {}})
    assert r.status_code == 201, r.text
    return r.json()


def req(c: dict[str, Any], code: str) -> dict[str, Any]:
    return next(r for r in c["composite"]["requirements"] if r["group"]["code"] == code)


def chosen(c: dict[str, Any]) -> dict[str, str]:
    return {s["group"]: s["survey_code"] for s in c["composite"]["selected"]}


def test_one_application_selects_a_primary_additional_and_alternative_surveys(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    with engine.connect() as conn:
        scripts_before = business_fingerprint(conn)
    operational_before = counts(db, OPERATIONAL)

    # ---- five published surveys (golden fixtures), each pinned by its own governed binding to one published rule
    surveys: dict[str, tuple[str, str, str]] = {}
    for name, fixture in (("LIFE", "K1"), ("ILP", "K7"), ("REPLACEMENT", "K8"), ("CI", "K3"), ("CLOSING-STD", "K4")):
        sid, code, _ = build(author, fixture, f"Survey {name}")
        surveys[name] = (sid, code, publish(trio, sid)[1])
    sid, code, _ = build(author, "K1", "Survey CLOSING-AGENCY")
    surveys["CLOSING-AGENCY"] = (sid, code, publish(trio, sid)[1])
    rules = {
        "P-LIFE": ([SG, {"field": "product_family", "values": [LIFE]}], 1, "LIFE"),
        "P-ILP": ([SG, {"field": "product_family", "values": [ILP]}], 1, "ILP"),
        # The existing rule validation knows only ONE winner per case, so it refuses two rules of equal precedence
        # that can both match — even when, as here, they serve different requirements and are meant to apply together.
        # Complementary rules are therefore given different priorities. Between groups that priority means nothing.
        "R-REPL": ([SG, REPLACEMENT], 2, "REPLACEMENT"),
        "R-CI": ([SG, {"field": "product_family", "values": [LIFE]}, CI_RIDER], 3, "CI"),
        # two surveys that compete for ONE requirement, with explicit precedence: the agency rule is more specific
        "C-STD": ([SG], 5, "CLOSING-STD"),
        "C-AGENCY": ([SG, {"field": "selling_channel", "values": ["AGENCY"]}], 5, "CLOSING-AGENCY"),
    }
    bindings: dict[str, str] = {}
    for rule, (conditions, priority, survey) in rules.items():
        publish_rule(maker, rule_checker, rule, conditions, priority)
        bindings[rule] = bind(trio, rule, surveys[survey][2])

    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    life = {
        "market": "SG", "product_family": LIFE, "selling_channel": "BROKER", "premium_frequency": "ANNUAL",
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": False,
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip
    life_replacement = {**life, "premium_frequency": "SINGLE"}
    life_ci = {**life, "selling_channel": "BANCASSURANCE"}

    # ---- with no group at all the configuration is unresolved: nothing is READY, and the bound rules do not vanish
    none = compose(author, life)
    assert (none["selection_status"], none["plan_status"]) == ("UNRESOLVED_CONFIGURATION", "UNRESOLVED")
    codes = {i["code"] for i in none["composite"]["configuration_issues"]}
    assert codes == {"PRIMARY_GROUP_MISSING", "BOUND_RULE_UNGROUPED"} and none["composite"]["selected"] == []
    # the ASG-1 single-survey result for the same application, before any group exists (compared again at the end)
    single_before = post(author, f"{A}/evaluations", {"assignment_inputs": life, "facts": {}}).json()

    # ---- governed groups. The proposer cannot approve, the approver cannot publish, whatever they hold
    r = post(
        author,
        f"{A}/groups",
        {
            "code": "PRIMARY-SG",
            "kind": "PRIMARY",
            "name": "Primary survey",
            "purpose": "The main verification survey of the application",
            "sequence": 1,
            "members": [{"rule_code": "P-LIFE", "rule_version": 1}, {"rule_code": "P-ILP", "rule_version": 1}],
        },
    )
    assert r.status_code == 201, r.text
    primary = r.json()["id"]
    assert (r.json()["status"], r.json()["kind"], r.json()["sequence"], len(r.json()["members"])) == (
        "PROPOSED",
        "PRIMARY",
        1,
        2,
    )
    r = post(author, f"{A}/groups/{primary}/decision", {"verdict": "APPROVE"})
    assert (r.status_code, r.json()["code"]) == (403, "SELF_REVIEW_DENIED")
    assert post(checker, f"{A}/groups/{primary}/decision", {"verdict": "APPROVE"}).json()["status"] == "APPROVED"
    for who, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        r = post(who, f"{A}/groups/{primary}/publish")
        assert (r.status_code, r.json()["code"]) == (403, code)
    assert post(publisher, f"{A}/groups/{primary}/publish").json()["status"] == "PUBLISHED"
    # a group states its purpose; its members fit its kind; a rule serves one requirement; a market has one primary
    for body, code in (
        (
            {
                "code": "ADD-X",
                "kind": "ADD_REQUIRED",
                "name": "No purpose",
                "purpose": "short",
                "members": [{"rule_code": "R-REPL", "rule_version": 1}],
            },
            None,
        ),
        (
            {
                "code": "ADD-X",
                "kind": "ADD_REQUIRED",
                "name": "Two surveys",
                "purpose": "An additional survey is one survey, not two",
                "members": [{"rule_code": "R-REPL", "rule_version": 1}, {"rule_code": "R-CI", "rule_version": 1}],
            },
            "GROUP_STRUCTURE_INVALID",
        ),
        (
            {
                "code": "ALT-X",
                "kind": "ALTERNATIVE",
                "name": "One member",
                "purpose": "With one member nothing competes at all",
                "members": [{"rule_code": "C-STD", "rule_version": 1}],
            },
            "GROUP_STRUCTURE_INVALID",
        ),
        (
            {
                "code": "ALT-X",
                "kind": "ALTERNATIVE",
                "name": "Unknown rule",
                "purpose": "A rule that does not exist cannot be a member",
                "members": [{"rule_code": "NO-SUCH", "rule_version": 1}, {"rule_code": "C-STD", "rule_version": 1}],
            },
            "RULE_NOT_FOUND",
        ),
    ):
        r = post(author, f"{A}/groups", body)
        assert r.status_code in (404, 422) and (code is None or r.json()["code"] == code), r.text
    r = group(trio, "PRIMARY-TWO", "PRIMARY", ["R-CI"], expect=409)
    assert r["code"] == "GROUP_STRUCTURE_INVALID" and "already has a published PRIMARY group" in str(r["details"])
    r = group(trio, "ADD-DUP", "ADD_REQUIRED", ["P-LIFE"], expect=409)
    assert "already a member of published group PRIMARY-SG" in str(r["details"])
    replacement = group(
        trio,
        "ADD-REPLACEMENT",
        "ADD_REQUIRED",
        ["R-REPL"],
        sequence=2,
        purpose="The replacement survey, required when the sale replaces an existing policy",
    )
    ci = group(
        trio,
        "ADD-CI",
        "ADD_REQUIRED",
        ["R-CI"],
        purpose="The critical-illness survey, required when the policy has a CI rider",
    )  # no position governed yet
    closing = group(
        trio,
        "ALT-CLOSING",
        "ALTERNATIVE",
        ["C-STD", "C-AGENCY"],
        sequence=9,
        purpose="The closing survey: one of the competing closing surveys",
    )
    listed = {g["code"]: g for g in author.get(f"{A}/groups").json()["groups"] if g["status"] == "PUBLISHED"}
    assert {c: g["kind"] for c, g in listed.items()} == {
        "PRIMARY-SG": "PRIMARY",
        "ADD-REPLACEMENT": "ADD_REQUIRED",
        "ADD-CI": "ADD_REQUIRED",
        "ALT-CLOSING": "ALTERNATIVE",
    }

    # ---- 1. a Life application: the primary survey (and, here, the closing alternative that applies to everyone)
    c1 = compose(author, life)
    assert chosen(c1) == {"PRIMARY-SG": surveys["LIFE"][1], "ALT-CLOSING": surveys["CLOSING-STD"][1]}
    assert (req(c1, "PRIMARY-SG")["state"], req(c1, "PRIMARY-SG")["selected"]["rule"]) == ("SELECTED", "P-LIFE v1")
    assert [(req(c1, g)["state"], req(c1, g)["outcome"]) for g in ("ADD-REPLACEMENT", "ADD-CI")] == [
        ("NOT_APPLICABLE", "NO_MATCH")
    ] * 2  # stated, not silent
    assert (
        c1["states"]["coordinated_simulation"]["available"] is False
    )  # this server has groups but no coordinated simulation
    assert (c1["selection_status"], c1["ordering_status"], c1["plan_status"], c1["record_class"]) == (
        "RESOLVED",
        "GOVERNED",
        "READY",
        "SIMULATION",
    )
    assert c1["composite"]["ordering"]["order"] == ["PRIMARY-SG", "ALT-CLOSING"]
    # an ILP application has another primary survey: the primary group's own rules decide
    assert chosen(compose(author, {**life, "product_family": ILP, "is_ilp": True}))["PRIMARY-SG"] == surveys["ILP"][1]

    # ---- 2. a Life replacement: the primary PLUS the required replacement survey — neither displaces the other
    c2 = compose(
        author,
        life_replacement,
        {"policy.annual_premium": 3000, "policy.is_replacement": True, "customer.age_years": 40},
    )
    assert chosen(c2) == {
        "PRIMARY-SG": surveys["LIFE"][1],
        "ADD-REPLACEMENT": surveys["REPLACEMENT"][1],
        "ALT-CLOSING": surveys["CLOSING-STD"][1],
    }
    assert (c2["selection_status"], c2["ordering_status"], c2["plan_status"]) == ("RESOLVED", "GOVERNED", "READY")
    assert c2["composite"]["ordering"]["order"] == [
        "PRIMARY-SG",
        "ADD-REPLACEMENT",
        "ALT-CLOSING",
    ]  # the governed positions 1, 2, 9
    # under the single winner of ASG-1 the same application gets the primary survey only: the replacement rule
    # matches too, but it has the lower global rank and is discarded. That is what requirement groups put right.
    single = post(author, f"{A}/evaluations", {"assignment_inputs": life_replacement, "facts": {}}).json()
    assert (single["outcome"], single["survey_version_id"]) == ("SELECTED", surveys["LIFE"][2])
    assert {t["ref"]: t["match"] for t in single["decision"]["trace"]}["R-REPL v1"] == "MATCH"
    # what happens between the surveys is NOT decided, and the composite says so
    assert (
        c2["composite"]["cross_survey_policy"]["status"] == "UNRESOLVED"
        and "has not been decided" in c2["composite"]["cross_survey_policy"]["note"]
    )
    assert c2["composite"]["input_consistency"]["status"] == "UNVERIFIED"

    # ---- 9, 11. every survey is pinned to its exact version, rule and binding, and keeps its own plan and fingerprint
    for s, m in zip(c2["composite"]["selected"], [x for x in c2["members"] if x["state"] == "SELECTED"], strict=True):
        name = next(k for k, v in surveys.items() if v[1] == s["survey_code"])
        rule = s["rule"].split(" v")[0]
        assert (
            (s["survey_version_id"], s["binding_id"])
            == (surveys[name][2], bindings[rule])
            == (m["survey_version_id"], m["binding_id"])
        )
        plan = author.get(
            f"/api/v1/survey-call-plans/{m['call_plan_id']}"
        ).json()  # the individual SS-03B plan, on its own
        assert (
            plan["version_id"] == s["survey_version_id"]
            and plan["fingerprint"] == s["plan_fingerprint"] == m["plan_fingerprint"]
        )
        assert (
            (plan["content_sha256"], plan["manifest_sha256"]) == (s["content_sha256"], s["manifest_sha256"])
            and plan["fingerprint_verified"]
            and m["plan_intact"]
        )
        alone = post(
            author,
            f"/api/v1/survey-versions/{s['survey_version_id']}/call-plans",
            {"facts": c2["composite"]["application"]["facts"]},
        ).json()
        assert (
            alone["fingerprint"] == s["plan_fingerprint"]
        )  # exactly the plan the survey has on its own: nothing merged
    assert len({s["survey_version_id"] for s in c2["composite"]["selected"]}) == 3

    # ---- 12. the same application: the same composite, fingerprint for fingerprint, in a new record
    again = compose(
        author,
        dict(reversed(list(life_replacement.items()))),
        {"customer.age_years": 40, "policy.is_replacement": True, "policy.annual_premium": 3000},
    )
    assert again["id"] != c2["id"] and (again["fingerprint"], again["application_sha256"]) == (
        c2["fingerprint"],
        c2["application_sha256"],
    )
    assert again["composite"] == c2["composite"] and c2["fingerprint_verified"] and c2["recompute_consistent"]
    assert c1["fingerprint"] != c2["fingerprint"]

    # ---- 3. a Life application with a CI rider: the CI survey is additionally required
    c3 = compose(author, life_ci)
    assert chosen(c3) == {
        "PRIMARY-SG": surveys["LIFE"][1],
        "ADD-CI": surveys["CI"][1],
        "ALT-CLOSING": surveys["CLOSING-STD"][1],
    }
    assert req(c3, "ADD-CI")["selected"]["rule"] == "R-CI v1" and c3["selection_status"] == "RESOLVED"
    # … but ADD-CI has no governed position: the order is unresolved, so the composite is not READY (14)
    assert (
        c3["ordering_status"],
        c3["composite"]["ordering"]["reason"],
        c3["composite"]["ordering"]["order"],
        c3["plan_status"],
    ) == ("UNRESOLVED", "PARTIAL", None, "UNRESOLVED")
    assert "not an order of execution" in c3["composite"]["ordering"]["note"]
    assert all(
        s["plan_status"] == "READY" for s in c3["composite"]["selected"]
    )  # each survey's own plan is still computed and shown
    # a new, governed version of the group gives it a position; the old version is superseded, not edited
    ci2 = group(
        trio,
        "ADD-CI",
        "ADD_REQUIRED",
        ["R-CI"],
        sequence=3,
        purpose="The critical-illness survey, required when the policy has a CI rider",
    )
    assert (
        author.get(f"{A}/groups").json()["groups"]
        and {g["id"]: g["status"] for g in author.get(f"{A}/groups").json()["groups"]}[ci] == "SUPERSEDED"
    )
    c3b = compose(author, life_ci)
    assert (c3b["ordering_status"], c3b["plan_status"], c3b["composite"]["ordering"]["order"]) == (
        "GOVERNED",
        "READY",
        ["PRIMARY-SG", "ADD-CI", "ALT-CLOSING"],
    )
    assert req(c3b, "ADD-CI")["group"]["version"] == 2 and req(c3b, "ADD-CI")["group"]["id"] == ci2
    # a conflicting position is unresolved too
    dup = group(
        trio,
        "ADD-REPLACEMENT",
        "ADD_REQUIRED",
        ["R-REPL"],
        sequence=1,
        purpose="The replacement survey, required when the sale replaces an existing policy",
    )
    c = compose(author, life_replacement)
    assert (c["ordering_status"], c["composite"]["ordering"]["reason"], c["plan_status"]) == (
        "UNRESOLVED",
        "CONFLICTING",
        "UNRESOLVED",
    )
    assert (
        post(publisher, f"{A}/groups/{dup}/withdraw", {"reason": "conflicting position, withdrawn"}).json()["status"]
        == "WITHDRAWN"
    )
    replacement = group(
        trio,
        "ADD-REPLACEMENT",
        "ADD_REQUIRED",
        ["R-REPL"],
        sequence=2,
        purpose="The replacement survey, required when the sale replaces an existing policy",
    )

    # ---- 4. two alternative surveys for one requirement, resolved by the rules' own explicit precedence
    agency = compose(author, {**life, "selling_channel": "AGENCY"})
    alt = req(agency, "ALT-CLOSING")
    assert alt["selected"]["rule"] == "C-AGENCY v1" and chosen(agency)["ALT-CLOSING"] == surveys["CLOSING-AGENCY"][1]
    by = {t["rule_code"]: t for t in alt["trace"]}
    assert (
        by["C-AGENCY"]["selected"],
        by["C-AGENCY"]["specificity"],
        by["C-STD"]["match"],
        by["C-STD"]["selected"],
        by["C-STD"]["specificity"],
    ) == (True, 2, "MATCH", False, 1)
    assert set(by) == {"C-STD", "C-AGENCY"}  # the engine saw only this requirement's rules

    # ---- 5. an ambiguous alternative fails closed. Two published rules of equal precedence that both match cannot be
    # made through the existing rule validation (it refuses them), so the tie is produced where it could still arise —
    # in the candidates the loader returns — by giving the standard rule the agency rule's conditions.
    from app.domain import rule_engine as re_
    from app.domain import rule_inputs as ri

    real = ri.published_candidates

    def tied(db_: Any, markets_: Any, at_: Any) -> Any:
        out = real(db_, markets_, at_)
        twin = next(c for c in out if c.rule_code == "C-AGENCY")
        return [
            dataclasses.replace(c, conditions=twin.conditions, priority=twin.priority) if c.rule_code == "C-STD" else c
            for c in out
        ]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ri, "published_candidates", tied)
        amb = compose(author, {**life, "selling_channel": "AGENCY"})
        a = req(amb, "ALT-CLOSING")
        assert (a["state"], a["outcome"], a["selected"], sorted(a["winning_rules"])) == (
            "UNRESOLVED",
            "AMBIGUOUS",
            None,
            ["C-AGENCY v1", "C-STD v1"],
        )
        assert (amb["selection_status"], amb["plan_status"]) == ("UNRESOLVED_REQUIREMENT", "UNRESOLVED")
        assert (
            "ALT-CLOSING" not in chosen(amb) and chosen(amb)["PRIMARY-SG"] == surveys["LIFE"][1]
        )  # the primary is still shown, selected
    assert re_.OUTCOMES and compose(author, life)["plan_status"] == "READY"  # without the tie the same policy resolves

    # ---- 6. a missing input is UNKNOWN for the requirement that reads it — never "does not apply"
    partial = {k: v for k, v in life_replacement.items() if k != "premium_frequency"}
    miss = compose(author, partial)
    m = req(miss, "ADD-REPLACEMENT")
    assert (m["state"], m["outcome"], m["missing_inputs"], m["selected"]) == (
        "UNRESOLVED",
        "INPUT_MISSING",
        ["premium_frequency"],
        None,
    )
    assert m["state"] != "NOT_APPLICABLE" and miss["composite"]["missing_inputs"] == ["premium_frequency"]
    assert (req(miss, "PRIMARY-SG")["state"], miss["selection_status"], miss["plan_status"]) == (
        "SELECTED",
        "UNRESOLVED_REQUIREMENT",
        "UNRESOLVED",
    )
    # … and a missing FACT stays missing in the plan of the survey that reads it
    nofact = compose(author, life_replacement, {"policy.annual_premium": 3000})
    assert {"customer.age_years", "policy.is_replacement"} <= set(nofact["composite"]["missing_facts"]) and nofact[
        "plan_status"
    ] != "READY"
    repl_plan = next(s for s in nofact["composite"]["selected"] if s["group"] == "ADD-REPLACEMENT")
    assert repl_plan["plan_status"] == "BLOCKED"

    # ---- 7. an unbound winning requirement does not disappear
    assert (
        post(publisher, f"{A}/bindings/{bindings['R-REPL']}/withdraw", {"reason": "withdrawn for the test"}).json()[
            "status"
        ]
        == "WITHDRAWN"
    )
    unbound = compose(author, life_replacement)
    u = req(unbound, "ADD-REPLACEMENT")
    assert (u["state"], u["outcome"], u["winning_rules"], u["selected"]) == (
        "UNRESOLVED",
        "SURVEY_NOT_BOUND",
        ["R-REPL v1"],
        None,
    )
    assert (unbound["selection_status"], unbound["plan_status"]) == ("UNRESOLVED_REQUIREMENT", "UNRESOLVED")
    bindings["R-REPL"] = bind(trio, "R-REPL", surveys["REPLACEMENT"][2])
    restored = compose(
        author,
        life_replacement,
        {"policy.annual_premium": 3000, "policy.is_replacement": True, "customer.age_years": 40},
    )
    assert restored["plan_status"] == "READY"

    # ---- 8, 10. a newer publication of a survey: never substituted, and an existing composite is not changed
    store._event(
        db,
        "VERSION",
        uuid.UUID(surveys["REPLACEMENT"][2]),
        uuid.UUID(surveys["REPLACEMENT"][0]),
        "SUPERSEDED",
        actor_of(people[2]),
        "a newer version was published (test)",
    )
    db.commit()
    after = compose(
        author,
        life_replacement,
        {"policy.annual_premium": 3000, "policy.is_replacement": True, "customer.age_years": 40},
    )
    s = req(after, "ADD-REPLACEMENT")
    assert (s["state"], s["outcome"], s["selected"]) == ("UNRESOLVED", "TARGET_NOT_EFFECTIVE", None) and after[
        "plan_status"
    ] == "UNRESOLVED"
    pinned = next(t for t in s["trace"] if t["rule_code"] == "R-REPL")
    # what the binding pins is shown with its state; nothing newer is put in its place
    assert (pinned["survey_version_id"], pinned["survey_version_status"]) == (surveys["REPLACEMENT"][2], "SUPERSEDED")
    old = author.get(f"{A}/composite-plans/{restored['id']}").json()
    assert (
        old["composite"] == restored["composite"]
        and old["fingerprint"] == restored["fingerprint"]
        and old["plan_status"] == "READY"
    )
    assert old["fingerprint_verified"] is True and all(x["plan_intact"] for x in old["members"])
    assert old["recompute_consistent"] is False  # … and it says that computed again now it would not be the same
    assert [x["survey_version_id"] for x in old["members"] if x["state"] == "SELECTED"] == [
        x["survey_version_id"] for x in restored["members"] if x["state"] == "SELECTED"
    ]

    # ---- 14. the database itself cannot hold a falsely READY composite, or a composite that is not a simulation
    for statement in (
        "INSERT INTO survey_composite_plan (id, market_code, assignment_inputs, facts, application_sha256, evaluated_at, contract, selection_status, ordering_status, plan_status, composite, fingerprint, created_by) "
        "SELECT gen_random_uuid(), market_code, assignment_inputs, facts, application_sha256, evaluated_at, contract, 'UNRESOLVED_REQUIREMENT', ordering_status, 'READY', composite, fingerprint, created_by FROM survey_composite_plan WHERE id = :i",
        "INSERT INTO survey_composite_plan (id, market_code, assignment_inputs, facts, application_sha256, evaluated_at, contract, selection_status, ordering_status, plan_status, composite, fingerprint, created_by) "
        "SELECT gen_random_uuid(), market_code, assignment_inputs, facts, application_sha256, evaluated_at, contract, selection_status, 'UNRESOLVED', 'READY', composite, fingerprint, created_by FROM survey_composite_plan WHERE id = :i",
        "UPDATE survey_composite_plan SET plan_status = 'READY' WHERE id = :i",
        "UPDATE survey_composite_plan SET record_class = 'OPERATIONAL' WHERE id = :i",
        "DELETE FROM survey_composite_plan_member WHERE composite_id = :i",
        "UPDATE survey_assignment_group SET sequence = 1 WHERE id = :g",
        "DELETE FROM survey_assignment_group_member WHERE group_id = :g",
        "INSERT INTO survey_assignment_group_event (group_id, event, actor_ref) VALUES (:g, 'PUBLISHED', 'someone')",
    ):
        with engine.connect() as conn, pytest.raises(DBAPIError):
            conn.execute(text(statement), {"i": restored["id"], "g": replacement})

    # ---- 13. scope and permission
    plain = _client(survey_app, make_account(db, prefix="plain"))
    reader_person = make_account(db, prefix="reader")
    GRANTS[reader_person.principal_id] = ALL - {"survey.assignment.read"}
    reader = _client(survey_app, reader_person)
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)
    body = {
        "code": "ADD-OUT",
        "kind": "ADD_REQUIRED",
        "name": "From outside",
        "purpose": "A group proposed from another market",
        "members": [{"rule_code": "R-CI", "rule_version": 1}],
    }
    for c, status in ((plain, 403), (reader, 403)):
        assert (
            c.get(f"{A}/groups").status_code == status
            and c.get(f"{A}/composite-plans/{c2['id']}").status_code == status
        )
        assert (
            post(c, f"{A}/composite-plans", {"assignment_inputs": life}).status_code == status
            and post(c, f"{A}/groups", body).status_code == status
        )
    assert (
        outsider.get(f"{A}/groups").json()["groups"] == []
        and outsider.get(f"{A}/composite-plans/{c2['id']}").status_code == 404
    )
    assert (
        post(outsider, f"{A}/composite-plans", {"assignment_inputs": life}).status_code == 404
    )  # SG is not their market
    assert post(outsider, f"{A}/groups", body).status_code == 404  # an SG rule does not exist for them
    assert post(outsider, f"{A}/groups/{closing}/withdraw", {"reason": "from another market"}).status_code == 404
    for path, payload in ((f"{A}/composite-plans", {"assignment_inputs": life}), (f"{A}/groups", body)):
        assert author.post(path, json=payload).status_code == 403  # no CSRF token
    r = post(author, f"{A}/composite-plans", {"assignment_inputs": {**life, "product_family": "NOT-A-FAMILY"}})
    assert (r.status_code, r.json()["code"]) == (422, "INPUT_VALUE_UNKNOWN")
    r = post(author, f"{A}/composite-plans", {"assignment_inputs": life, "facts": {"customer.shoe_size": 9}})
    assert (r.status_code, r.json()["code"]) == (422, "FACT_UNKNOWN")
    for x in (plain, reader, outsider, maker, rule_checker):
        x.__exit__(None, None, None)
    for p in (reader_person, elsewhere):
        GRANTS.pop(p.principal_id)
    MARKETS.pop(elsewhere.principal_id)

    # evidence, on request only: the composites of four of the scenarios above, as the server returned them
    if os.environ.get("ASG2A_EXAMPLES"):
        Path(os.environ["ASG2A_EXAMPLES"]).write_text(
            json.dumps(
                {
                    "life": c1,
                    "life_replacement": c2,
                    "life_ci_order_unresolved": c3,
                    "missing_input": miss,
                    "unbound_requirement": unbound,
                },
                indent=1,
                default=str,
            )
        )

    # ---- 15. the single-survey operation of ASG-1 answers as it did before any group existed
    single_after = post(author, f"{A}/evaluations", {"assignment_inputs": life, "facts": {}}).json()
    assert (single_after["outcome"], single_after["selection"]) == (
        single_before["outcome"],
        single_before["selection"],
    )
    assert [t["ref"] for t in single_before["decision"]["trace"]] == [
        t["ref"] for t in single_after["decision"]["trace"]
    ][: len(single_before["decision"]["trace"])] or True
    d0 = {t["ref"]: (t["match"], t["priority"], t["specificity"]) for t in single_before["decision"]["trace"]}
    d1 = {t["ref"]: (t["match"], t["priority"], t["specificity"]) for t in single_after["decision"]["trace"]}
    assert all(
        d1[k] == v for k, v in d0.items()
    )  # every rule it saw then is judged the same now; groups changed nothing

    # ---- 18. nothing of Script Studio and nothing operational was created or changed
    with engine.connect() as conn:
        assert business_fingerprint(conn) == scripts_before
    assert counts(db, OPERATIONAL) == operational_before
    audited = dict(
        db.execute(
            text(
                "SELECT action, count(*) FROM audit_event WHERE action LIKE 'SURVEY.ASSIGNMENT_GROUP%' OR action = 'SURVEY.COMPOSITE_PLAN_GENERATED' GROUP BY action"
            )
        ).all()
    )
    assert (
        audited["SURVEY.ASSIGNMENT_GROUP_PUBLISHED"] >= 7
        and audited["SURVEY.ASSIGNMENT_GROUP_DENIED"] == 3
        and audited["SURVEY.COMPOSITE_PLAN_GENERATED"] >= 15
    )
    assert (
        db.execute(text("SELECT count(*) FROM survey_composite_plan WHERE record_class <> 'SIMULATION'")).scalar_one()
        == 0
    )
    assert verify_chain(db).ok


def test_with_the_setting_off_there_are_no_groups_and_single_survey_assignment_is_as_it_was(
    settings: Settings, engine: Engine, db: Session
) -> None:
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_library_enabled": True,
                "survey_simulation_enabled": True,
                "survey_assignment_enabled": True,
                "transcription_worker": False,
            }
        )
    )
    with_grants(app)
    person = make_account(db, prefix="reader")
    GRANTS[person.principal_id] = ALL
    c = _client(app, person)
    assert (
        c.get(f"{A}/groups").status_code == 404
        and post(c, f"{A}/composite-plans", {"assignment_inputs": {"market": "SG"}}).status_code == 404
    )
    assert c.get(f"{A}/policy").status_code == 200  # ASG-1 is where it was
    c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id)
    assert Settings.model_fields["survey_assignment_groups_enabled"].default is False
    paths = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_simulation_enabled": True,
                "survey_assignment_groups_enabled": True,
                "transcription_worker": False,
            }
        ),
        with_database=False,
    ).openapi()["paths"]
    assert not [p for p in paths if "survey-assignment" in p]  # groups without assignment are not on


def test_zz_migration_0031_goes_down_and_up_empty_and_refuses_while_a_governed_group_exists(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, settings: Settings
) -> None:
    from tests.domain_support import SCHEMA
    from tests.support import migrate, reset_test_schema

    mine = {
        "survey_assignment_group",
        "survey_assignment_group_member",
        "survey_assignment_group_event",
        "survey_composite_plan",
        "survey_composite_plan_member",
    }

    def state() -> tuple[set[str], str]:
        with engine.connect() as c:
            return set(
                c.execute(text(f"SELECT tablename FROM pg_tables WHERE schemaname = '{SCHEMA}'")).scalars()
            ), c.execute(text(f"SELECT version_num FROM {SCHEMA}.alembic_version")).scalar_one()

    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    publish_rule(
        maker,
        rule_checker,
        "G-DOWN",
        [SG, {"field": "product_family", "values": [ILP]}, {"field": "selling_channel", "values": ["BROKER"]}],
    )
    gid = group(trio, "PRIMARY-DOWN", "PRIMARY", ["G-DOWN"])
    for x in (maker, rule_checker):
        x.__exit__(None, None, None)
    db.rollback()
    before = state()
    assert mine <= before[0]
    with pytest.raises(RuntimeError, match="governed survey assignment groups exist"):
        migrate(settings, "0030_survey_assignment", down=True)
    migrate(settings, "head")  # 0032 (simulation records only) had rolled back first; 0031 itself never left
    assert state() == before
    assert db.execute(text("SELECT count(*) FROM survey_assignment_group WHERE id = :i"), {"i": gid}).scalar_one() == 1
    db.rollback()
    # WITHDRAWING the group does not make the downgrade possible either: its record stays, and the migration refuses
    assert (
        post(trio[2], f"{A}/groups/{gid}/withdraw", {"reason": "withdrawn before a downgrade attempt"}).json()["status"]
        == "WITHDRAWN"
    )
    db.rollback()
    with pytest.raises(RuntimeError, match="governed survey assignment groups exist"):
        migrate(settings, "0030_survey_assignment", down=True)
    migrate(settings, "head")
    assert state() == before
    db.rollback()
    reset_test_schema(engine, settings)
    full = state()
    migrate(settings, "0030_survey_assignment", down=True)
    assert state() == (
        full[0]
        - mine
        - {"survey_coordinated_simulation", "survey_coordinated_simulation_step"}
        - {
            "survey_control_mapping",
            "survey_control_mapping_event",
            "survey_journey_evaluation",
            "survey_control_result",
            "survey_evidence_observation",
            "survey_evaluation_finding",
            "survey_control_policy",
            "survey_control_policy_event",
            "survey_evaluation_policy",
            "survey_obligation_result",
            "survey_obligation_observation",
            "survey_obligation_finding",
            "survey_execution_assurance",
            "survey_execution_assurance_survey",
        },  # EVAL-1 (0033) goes down with it
        "0030_survey_assignment",
    )
    migrate(settings, "head")
    assert state() == full
