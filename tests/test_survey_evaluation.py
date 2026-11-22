# ruff: noqa: E501, F811
"""EVAL-1 — governed control mappings and journey-level control evaluation of SYNTHETIC simulations: real HTTP, real
PostgreSQL (``call360_test``).

Answers are judged by the EXISTING deterministic evaluator and findings come from the EXISTING finding engine and a
finding rule set published through its existing lifecycle. The controls are the seeded synthetic register; the
mappings, rules and severities made here are TEST FIXTURES, not business policy."""

from __future__ import annotations

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
from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import finding_rules
from app.domain.survey import control_evaluation as ce
from app.domain.survey import simulation
from app.domain.survey.execution import execute_inputs
from app.main import create_app
from tests.support import make_account
from tests.survey_fixtures import load_all
from tests.survey_support import fixture_bundle
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import ALL as ASSIGNMENT_ALL
from tests.test_survey_assignment import OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import compose, group
from tests.test_survey_lib1 import build, publish
from tests.test_survey_simulation import give, start

E = "/api/v1/survey-evaluation"
A = "/api/v1/survey-assignment"
EVAL = frozenset({"survey.evaluation.read", "survey.evaluate"})
ALL = ASSIGNMENT_ALL | EVAL
FX = {fx["fixture"][:2]: fx for fx in load_all()}
SG = {"field": "market", "values": ["SG"]}
SETTINGS_ON = {
    "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
    "survey_assignment_enabled": True, "survey_assignment_groups_enabled": True,
    "survey_coordinated_simulation_enabled": True, "survey_evaluation_enabled": True, "transcription_worker": False,
}  # fmt: skip
EVALUATION_TABLES = (
    "survey_control_mapping", "survey_control_mapping_event", "survey_journey_evaluation", "survey_control_result",
    "survey_evidence_observation", "survey_evaluation_finding",
)  # fmt: skip
YES = {"method": "EXACT_BOOLEAN", "expected_boolean": True}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(settings.model_copy(update=SETTINGS_ON))
    with_grants(app)
    return app


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL  # every permission: only the identity rules can stop them
    return _trio


def items_of(db: Session, version_id: str) -> dict[str, dict[str, Any]]:
    """placement → the exact item (code, version) the published version pins there."""
    v = simulation._version(db, uuid.UUID(version_id), ["SG"])
    return {
        p["key"]: {"code": p["item_code"], "version": p["item_version"]}
        for p in ce.placements(simulation.version_bundle(db, v))
    }


def entry(
    item: dict[str, Any], rule: dict[str, Any] | None = None, *, required: bool = True, survey_code: str | None = None
) -> dict[str, Any]:
    return {
        "item": item,
        "evidence_type": "ANSWER" if rule else "DELIVERY",
        "required": required,
        "survey_code": survey_code,
        "rule": rule,
    }


def propose(
    c: TestClient, control: str, entries: list[dict[str, Any]], applicability: dict[str, Any] | None = None, **over: Any
) -> Any:
    body = {
        "market_code": "SG", "control_code": control, "combination": "ALL_REQUIRED", "applicability": applicability,
        "entries": entries, "source": "Synthetic test mapping; not a business mapping",
    }  # fmt: skip
    return post(c, f"{E}/mappings", body | over)


def mapped(
    people: Any, control: str, entries: list[dict[str, Any]], applicability: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A mapping through all three steps, by three different people."""
    r = propose(people[0], control, entries, applicability)
    assert r.status_code == 201, r.text
    mid = r.json()["id"]
    assert post(people[1], f"{E}/mappings/{mid}/decision", {"verdict": "APPROVE"}).status_code == 200
    r = post(people[2], f"{E}/mappings/{mid}/publish")
    assert r.status_code == 200, r.text
    return r.json()


def rule(
    code: str,
    trigger: str,
    category: str,
    severity: str,
    scope: str = "ANY_QUESTION",
    target: str | None = None,
    mandatory_only: bool = False,
) -> dict[str, Any]:
    return {
        "rule_code": code, "scope": scope, "target": target, "mandatory_only": mandatory_only, "trigger": trigger, "category": category,
        "severity": severity, "severity_justification": "Synthetic severity for the tests only", "description": f"Synthetic test rule for {trigger.lower()}",
        "review_required": True,
    }  # fmt: skip


def publish_finding_rules(db: Session, rules: list[dict[str, Any]]) -> str:
    """A finding rule set through its EXISTING lifecycle (maker, then another person reviews and publishes)."""
    vid = finding_rules.create_draft(db, "SG", "test.maker", empty=True)
    finding_rules.update(db, vid, ["SG"], "test.maker", 1, rules, None)
    rv = finding_rules.version(db, vid, ["SG"])["row_version"]
    finding_rules.submit(db, vid, ["SG"], "test.maker", rv, "Synthetic rules for the tests")
    finding_rules.review(db, vid, ["SG"], "test.checker", "APPROVE", "Synthetic approval")
    finding_rules.publish(db, vid, ["SG"], "test.checker")
    db.commit()
    return str(vid)


def evaluate(
    c: TestClient, *, simulation_id: str | None = None, coordinated: str | None = None, expect: int = 201
) -> dict[str, Any]:
    r = post(c, f"{E}/evaluations", {"simulation_id": simulation_id, "coordinated_simulation_id": coordinated})
    assert r.status_code == expect, r.text
    return r.json()


def control(ev: dict[str, Any], code: str) -> dict[str, Any]:
    return next(c for c in ev["controls"] if c["control_code"] == code)


def outcomes(ev: dict[str, Any]) -> dict[str, str]:
    return {c["control_code"]: c["outcome"] for c in ev["controls"]}


def simulate(c: TestClient, vid: str, facts: dict[str, Any], answers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    sim = start(c, vid, facts)
    while sim["status"] == "PENDING" and sim["run"]["pending"]["key"] in answers:
        r = give(c, sim, sim["run"]["pending"]["key"], answers[sim["run"]["pending"]["key"]])
        assert r.status_code == 200, r.text
        sim = r.json()
    return sim


RULES_V1 = [
    rule("FR-EVAL-MISMATCH", "MISMATCH", "FACT_MISMATCH", "MEDIUM", "CONTROL", "SYN-CTRL-01"),
    rule("FR-EVAL-NOT-ASKED", "NOT_ASKED", "MISSING_MANDATORY_ANSWER", "LOW", mandatory_only=True),
]
K8_FACTS = {"policy.annual_premium": 3000, "policy.is_replacement": False, "customer.age_years": 40}


def k8(trio: Any, db: Session) -> tuple[str, dict[str, dict[str, Any]], dict[str, str]]:
    """The K8 golden fixture published, four controls of the seeded register mapped to it, one left unmapped."""
    sid, _, renamed = build(trio[0], "K8", "Application survey")
    vid = publish(trio, sid)[1]
    it = items_of(db, vid)
    mapped(trio, "SYN-CTRL-01", [entry(it["mi-opening/n2"], YES), entry(it["mi-opening/n1"])])
    mapped(
        trio,
        "SYN-CTRL-02",
        [entry(it["mi-high-value/n2"], YES)],
        {"condition": {"code": renamed["C-HIGH-PREMIUM"], "version": 1}, "params": {"threshold": 12000}},
    )
    mapped(
        trio,
        "SYN-CTRL-03",
        [entry(it["mi-senior/n1"], {"method": "ACKNOWLEDGEMENT"})],
        {"condition": {"code": renamed["C-OLDER"], "version": 1}, "params": {"minimum_age": 60}},
    )
    mapped(trio, "SYN-CTRL-04", [entry(it["mi-replacement/n1"], YES)])
    return vid, it, renamed


def test_a_single_survey_simulation_is_evaluated_against_governed_controls(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine
) -> None:
    author, checker, publisher, people = trio
    operational_before = counts(db, OPERATIONAL)
    rules_v1 = publish_finding_rules(db, RULES_V1)
    vid, it, renamed = k8(trio, db)

    # ---- 1. a completed single-survey journey: the same model, with one survey execution in the journey
    sim = simulate(author, vid, K8_FACTS, {"mi-opening/n2": {"choice": "YES"}})
    assert sim["run"]["terminal"]["state"] == "COMPLETED"
    ev = evaluate(author, simulation_id=sim["id"])
    assert (ev["record_class"], ev["journey_kind"], ev["simulation_id"], ev["coordinated_id"]) == (
        "SIMULATION",
        "SINGLE_SURVEY",
        sim["id"],
        None,
    )
    assert ev["journey"]["complete"] is True and [x["survey_version_id"] for x in ev["journey"]["executions"]] == [vid]
    # one control instance per control of the register — including the one no question refers to
    assert outcomes(ev) == {
        "SYN-CTRL-01": "SATISFIED", "SYN-CTRL-02": "NOT_APPLICABLE", "SYN-CTRL-03": "NOT_APPLICABLE",
        "SYN-CTRL-04": "INSUFFICIENT_EVIDENCE", "SYN-CTRL-05": "UNRESOLVED",
    }  # fmt: skip
    # a COMPLETED survey is not a completed evaluation, and not satisfied controls: three statuses, kept apart
    assert ev["processing_status"] == ev["status"] == "INCOMPLETE" and ev["summary"]["surveys_completed"] == 1
    one = control(ev, "SYN-CTRL-01")
    assert [(o["placement"], o["evidence_type"], o["result"]) for o in one["observations"]] == [
        ("mi-opening/n2", "ANSWER", "MATCH"),
        ("mi-opening/n1", "DELIVERY", "DELIVERED"),
    ]
    answer, delivery = one["observations"]
    # every observation names the exact execution evidence: survey version and manifest, simulation, item revision,
    # the wording as delivered, the trace events, the run fingerprint
    assert (answer["simulation_id"], answer["run_sha256"], answer["survey"]["survey_version_id"], answer["survey"]["manifest_sha256"]) == (
        sim["id"], sim["run_sha256"], vid, sim["manifest_sha256"],
    )  # fmt: skip
    assert answer["item"] | {"name": 0, "answer_type": 0} == it["mi-opening/n2"] | {"name": 0, "answer_type": 0}
    assert answer["wording"]["text"] == next(d["text"] for d in sim["run"]["delivered"] if d["key"] == "mi-opening/n2")
    assert (
        answer["trace"] == [e["at"] for e in sim["run"]["events"] if e.get("key") == "mi-opening/n2"]
        and answer["trace"]
    )
    # the EXISTING evaluator judged it, in its own vocabulary and words
    assert (
        answer["evaluation"]["method"],
        answer["evaluation"]["result"],
        answer["evaluation"]["rule_evaluation_equivalent"],
    ) == ("EXACT_BOOLEAN", "MATCH", "MATCH")
    assert answer["evaluation"]["answer"] == {"kind": "ANSWER", "state": "ANSWERED", "value": True, "verbatim": None}
    assert ev["engines"] == {"answer_evaluation": ae.ENGINE, "findings": fe.ENGINE, "control_evaluation": ce.CONTRACT}
    assert one["mapping"]["revision"] == 1 and one["mapping"]["combination"] == "ALL_REQUIRED"
    assert delivery["wording"]["text"] and delivery["evaluation"] is None

    # ---- applicability is governed and three-valued
    assert control(ev, "SYN-CTRL-02")["applicability"]["status"] == "NOT_APPLICABLE" and control(ev, "SYN-CTRL-02")[
        "applicability"
    ]["reads"] == ["policy.annual_premium"]
    # a control whose evidence the SURVEY left out by its own condition is not thereby unnecessary: evidence gap
    four = control(ev, "SYN-CTRL-04")
    assert (four["applicability"]["status"], four["observations"][0]["result"], four["observations"][0]["gap"]) == (
        "APPLICABLE",
        "NOT_APPLICABLE",
        "MODULE_EXCLUDED_BY_CONDITION",
    )
    # ---- 9. an unmapped control is reported, never satisfied and never dropped; coverage is never asserted
    five = control(ev, "SYN-CTRL-05")
    assert (five["outcome"], five["mapping"], five["applicability"]["status"], five["reasons"][0]["code"]) == (
        "UNRESOLVED",
        None,
        "NOT_DETERMINED",
        "MAPPING_MISSING",
    )
    assert ev["coverage"]["status"] == "NOT_ASSERTED" and ev["coverage"]["controls_without_mapping"] == ["SYN-CTRL-05"]
    # … and so is every item of the journey that no mapping names
    assert sorted(u["placement"] for u in ev["coverage"]["items_without_mapping"]) == [
        "mi-closing/n1",
        "mi-high-value/n1",
    ]
    assert (
        ev["findings"] == [] and ev["findings_status"] == "GENERATED" and ev["finding_rules"]["version_id"] == rules_v1
    )

    # ---- 14. identical inputs: the SAME evaluation and the same fingerprints; nothing new is recorded
    again = evaluate(author, simulation_id=sim["id"], expect=200)
    assert (again["id"], again["input_sha256"], again["result_sha256"]) == (
        ev["id"],
        ev["input_sha256"],
        ev["result_sha256"],
    )
    assert ev["replay"] == {
        "consistent": True,
        "code": None,
        "reasons": [],
        "recorded_result_sha256": ev["result_sha256"],
        "recomputed_result_sha256": ev["result_sha256"],
    }
    assert db.execute(text("SELECT count(*) FROM survey_journey_evaluation")).scalar_one() == 1

    # ---- a different journey of the same survey: the control is NOT satisfied, and the existing rules make findings
    no = simulate(author, vid, K8_FACTS, {"mi-opening/n2": {"choice": "NO"}})
    assert no["run"]["terminal"] == {"state": "ENDED_WITH_OUTCOME", "survey_outcome": "UNABLE_TO_VERIFY"}
    ev_no = evaluate(author, simulation_id=no["id"])
    assert outcomes(ev_no)["SYN-CTRL-01"] == "NOT_SATISFIED" and ev_no["processing_status"] == "INCOMPLETE"
    # ---- 8. a required question that was never reached is an evidence gap
    gap = control(ev_no, "SYN-CTRL-04")
    assert (gap["outcome"], gap["observations"][0]["result"], gap["observations"][0]["gap"]) == (
        "INSUFFICIENT_EVIDENCE",
        "NOT_ASKED",
        "NOT_REACHED",
    )
    # ---- 12, 13. findings: the existing engine, the published rule set; each traceable to rule revision and evidence
    assert [
        (f["control_code"], f["rule"]["rule_code"], f["trigger"], f["finding_class"], f["category"], f["severity"])
        for f in ev_no["findings"]
    ] == [
        ("SYN-CTRL-01", "FR-EVAL-MISMATCH", "MISMATCH", "CUSTOMER_DISCREPANCY", "FACT_MISMATCH", "MEDIUM"),
        ("SYN-CTRL-04", "FR-EVAL-NOT-ASKED", "NOT_ASKED", "MISSING_EVIDENCE", "MISSING_MANDATORY_ANSWER", "LOW"),
    ]
    f = ev_no["findings"][0]
    assert (
        f["engine"] == fe.ENGINE
        and f["rule"]["rule_set"]["version_id"] == rules_v1
        and f["severity_source"].startswith("Finding rule FR-EVAL-MISMATCH")
    )
    assert (
        f["rule"]["rule_set"]["sha256"]
        == ev_no["finding_rules"]["sha256"]
        == ev_no["pins"]["finding_rule_set"]["sha256"]
    )
    assert (f["simulation_id"], f["placement"], f["item"]["code"], f["survey"]["survey_version_id"]) == (
        no["id"],
        "mi-opening/n2",
        it["mi-opening/n2"]["code"],
        vid,
    )
    assert f["evidence"]["answer"]["value"] is False and f["evidence"]["expected"] == {"value": "YES", "source": "RULE"}
    assert "not a breach determination" in f["explanation"] and f["controls"][0]["control_code"] == "SYN-CTRL-01"
    assert control(ev_no, "SYN-CTRL-01")["observations"][0]["seq"] == f["observation_seq"]
    missing = ev_no["findings"][1]
    assert (
        missing["evidence"]["answer"] is None and missing["evidence"]["evaluation_result"] == "NOT_ASKED"
    )  # the missing evidence itself

    # ---- 7. a required question asked and not yet answered: no automatic pass
    waiting = start(author, vid, K8_FACTS)
    ev_wait = evaluate(author, simulation_id=waiting["id"])
    first = control(ev_wait, "SYN-CTRL-01")
    assert (first["outcome"], first["observations"][0]["result"], first["observations"][0]["gap"]) == (
        "INSUFFICIENT_EVIDENCE",
        "NOT_ASKED",
        "AWAITING_ANSWER",
    )
    assert ev_wait["processing_status"] == "INCOMPLETE" and ev_wait["journey"]["complete"] is False
    # an answer the survey refused is not an answer, and not a failure of the customer
    refused = give(author, waiting, "mi-opening/n2", {}).json()
    ev_refused = evaluate(author, simulation_id=refused["id"])
    o = control(ev_refused, "SYN-CTRL-01")["observations"][0]
    assert (o["result"], o["gap"], o["refused_inputs"]) == (
        "UNRESOLVED",
        "ASKED_NO_ACCEPTED_ANSWER",
        ["CHOICE_REQUIRED"],
    )
    assert outcomes(ev_refused)["SYN-CTRL-01"] == "INSUFFICIENT_EVIDENCE" and ev_refused["id"] != ev_wait["id"]

    # ---- 10. unknown applicability stays unknown; missing information is 'not asked', never 'not applicable'
    unknown = simulate(
        author,
        vid,
        {"policy.annual_premium": 3000, "policy.is_replacement": None, "customer.age_years": None},
        {"mi-opening/n2": {"choice": "YES"}},
    )
    assert unknown["run"]["terminal"]["state"] == "MISSING_INFORMATION_HALT"
    ev_unknown = evaluate(author, simulation_id=unknown["id"])
    three = control(ev_unknown, "SYN-CTRL-03")
    assert (three["outcome"], three["applicability"]["status"], three["applicability"]["missing"], three["reasons"][0]["code"]) == (
        "UNRESOLVED", "UNKNOWN", ["customer.age_years"], "APPLICABILITY_UNKNOWN",
    )  # fmt: skip
    assert (three["observations"][0]["result"], three["observations"][0]["gap"]) == (
        "NOT_ASKED",
        "MODULE_HALTED_MISSING_INFORMATION",
    )
    assert ev_unknown["coverage"]["controls_with_unknown_applicability"] == ["SYN-CTRL-03"]
    skipped = control(ev_unknown, "SYN-CTRL-04")["observations"][0]
    assert (skipped["result"], skipped["gap"]) == ("NOT_ASKED", "MODULE_ELIGIBILITY_UNKNOWN")  # UNKNOWN is not FALSE
    assert not [
        f for f in ev_unknown["findings"] if f["control_code"] == "SYN-CTRL-03"
    ]  # no finding while applicability is unknown

    # ---- 15. revised finding rules: a NEW evaluation; the old one is not rewritten, and says what it did not use
    rules_v2 = publish_finding_rules(
        db, [rule("FR-EVAL-MISMATCH", "MISMATCH", "FACT_MISMATCH", "HIGH", "CONTROL", "SYN-CTRL-01")]
    )
    ev_no2 = evaluate(author, simulation_id=no["id"])
    assert (
        ev_no2["id"] != ev_no["id"]
        and ev_no2["input_sha256"] != ev_no["input_sha256"]
        and ev_no2["result_sha256"] != ev_no["result_sha256"]
    )
    assert [
        (f["rule"]["rule_code"], f["severity"], f["rule"]["rule_set"]["version_id"]) for f in ev_no2["findings"]
    ] == [("FR-EVAL-MISMATCH", "HIGH", rules_v2)]
    # the NOT_ASKED trigger is no longer covered: reported as not converted, never silently dropped
    assert [(n["control_code"], n["result"]) for n in ev_no2["not_converted"]] == [("SYN-CTRL-04", "NOT_ASKED")]
    old = author.get(f"{E}/evaluations/{ev_no['id']}").json()
    assert (old["result_sha256"], [f["severity"] for f in old["findings"]], old["replay"]["consistent"]) == (
        ev_no["result_sha256"],
        ["MEDIUM", "LOW"],
        True,
    )
    assert [s["code"] for s in old["superseded_by_current_governance"]] == ["FINDING_RULES_REVISED"] and ev_no2[
        "superseded_by_current_governance"
    ] == []
    # … and a revised MAPPING likewise
    r = propose(
        author, "SYN-CTRL-01", [entry(it["mi-opening/n2"], {"method": "EXACT_BOOLEAN", "expected_boolean": False})]
    )
    assert r.status_code == 201 and r.json()["revision"] == 2
    assert post(checker, f"{E}/mappings/{r.json()['id']}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert post(publisher, f"{E}/mappings/{r.json()['id']}/publish").status_code == 200
    statuses = {
        m["revision"]: m["status"]
        for m in author.get(f"{E}/mappings").json()["items"]
        if m["control_code"] == "SYN-CTRL-01"
    }
    assert statuses == {1: "SUPERSEDED", 2: "PUBLISHED"}
    ev3 = evaluate(author, simulation_id=sim["id"])
    assert (
        ev3["id"] != ev["id"]
        and outcomes(ev3)["SYN-CTRL-01"] == "NOT_SATISFIED"
        and control(ev3, "SYN-CTRL-01")["mapping"]["revision"] == 2
    )
    first_again = author.get(f"{E}/evaluations/{ev['id']}").json()
    assert (
        outcomes(first_again)["SYN-CTRL-01"] == "SATISFIED" and first_again["replay"]["consistent"] is True
    )  # recomputed from ITS pinned revision
    assert sorted(s["code"] for s in first_again["superseded_by_current_governance"]) == [
        "FINDING_RULES_REVISED",
        "MAPPING_REVISED",
    ]
    listed = author.get(f"{E}/evaluations", params={"simulation_id": sim["id"]}).json()["items"]
    assert [x["id"] for x in listed] == [ev["id"], ev3["id"]]

    # ---- new evidence after an evaluation: the old evaluation says it no longer describes the journey
    answered = give(author, refused, "mi-opening/n2", {"choice": "YES"}).json()
    assert answered["status"] == "TERMINAL"
    stale = author.get(f"{E}/evaluations/{ev_refused['id']}").json()
    assert (stale["status"], stale["processing_status"], stale["replay"]["consistent"]) == (
        "EVALUATION_DRIFT",
        "INCOMPLETE",
        False,
    )
    assert "EVIDENCE_CHANGED" in [r["code"] for r in stale["replay"]["reasons"]]

    # ---- 16. isolated, insert-only, audited; nothing operational exists or changed
    assert counts(db, OPERATIONAL) == operational_before
    assert db.execute(text("SELECT count(*) FROM finding WHERE source_reference LIKE '%survey%'")).scalar_one() == 0
    assert set(db.execute(text("SELECT DISTINCT record_class FROM survey_journey_evaluation")).scalars()) == {
        "SIMULATION"
    }
    for table in EVALUATION_TABLES:
        assert db.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() > 0, table
        for change in (
            f"UPDATE {table} SET evaluation_id = evaluation_id"
            if "evaluation" in table or "result" in table or "observation" in table
            else f"UPDATE {table} SET mapping_id = mapping_id"
            if table.endswith("_event")
            else f"UPDATE {table} SET source = source",
            f"DELETE FROM {table}",
        ):
            with pytest.raises(DBAPIError):
                with engine.begin() as c:
                    c.execute(
                        text(
                            change
                            if table != "survey_journey_evaluation"
                            else change.replace("evaluation_id = evaluation_id", "contract = contract")
                        )
                    )
    actions = set(db.execute(text("SELECT DISTINCT action FROM audit_event WHERE action LIKE 'SURVEY.%'")).scalars())
    assert {
        "SURVEY.CONTROL_MAPPING_PROPOSED",
        "SURVEY.CONTROL_MAPPING_APPROVED",
        "SURVEY.CONTROL_MAPPING_PUBLISHED",
        "SURVEY.JOURNEY_EVALUATED",
    } <= actions
    assert verify_chain(db).ok


def test_a_coordinated_journey_gets_one_evaluation_with_evidence_from_each_survey(
    clean_rules: None, trio: Any, survey_app: Any, db: Session
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    operational_before = counts(db, OPERATIONAL)
    publish_finding_rules(db, RULES_V1)
    # ---- two surveys, required together by STAND-IN conditions (ASG-2A: placeholders, not business requirements)
    version: dict[str, str] = {}
    for name, fixture in (("A", "K1"), ("B", "K3")):
        sid, _, _ = build(author, fixture, f"Survey {name}")
        version[name] = publish(trio, sid)[1]
    publish_rule(maker, rule_checker, "P-A", [SG, {"field": "product_family", "values": ["PROTECTION"]}], 1)
    publish_rule(maker, rule_checker, "R-B", [SG, {"field": "premium_frequency", "values": ["SINGLE"]}], 2)
    bind(trio, "P-A", version["A"])
    bind(trio, "R-B", version["B"])
    group(trio, "PRIMARY-SG", "PRIMARY", ["P-A"], sequence=1)
    group(trio, "ADD-B", "ADD_REQUIRED", ["R-B"], sequence=2)
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    application = {
        "market": "SG", "product_family": "PROTECTION", "selling_channel": "AGENCY", "premium_frequency": "SINGLE",
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": False,
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip
    a, b = items_of(db, version["A"]), items_of(db, version["B"])
    # ---- 4. ONE control takes evidence from BOTH surveys; another from one
    at_least_18 = {"method": "NUMERIC_COMPARE", "evaluation": {"operator": "GTE", "value": 18, "unit": "COUNT"}}
    mapped(trio, "SYN-CTRL-01", [entry(a["mi-call/n2"], YES), entry(b["mi-numbers/n1"], at_least_18)])
    mapped(trio, "SYN-CTRL-02", [entry(a["mi-call/n5"], YES)])

    def journey(answers_b: dict[str, Any]) -> dict[str, Any]:
        comp = compose(author, application)
        r = post(author, f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "evaluation test"})
        assert r.status_code == 201, r.text
        co = r.json()
        stages = [co]
        answers = {"mi-call/n2": {"choice": "YES"}, "mi-call/n5": {"choice": "YES"}} | answers_b
        while co["status"] == "RUNNING":
            key = co["current"]["pending"]["key"]
            co = post(
                author,
                f"{A}/coordinated-simulations/{co['id']}/inputs",
                {"expected_inputs": co["progress"]["inputs"], "key": key, "answer": answers[key]},
            ).json()
            stages.append(co)
        return {"final": co, "start": stages[0]}

    # ---- 7 (journeys). an interrupted journey can be evaluated: what is missing stays missing
    comp = compose(author, application)
    co = post(author, f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "interrupted"}).json()
    early = evaluate(author, coordinated=co["id"])
    assert (early["journey_kind"], early["journey"]["complete"], early["processing_status"]) == (
        "COORDINATED",
        False,
        "INCOMPLETE",
    )
    assert [(x["position"], x["state"], x["simulation_id"] is None) for x in early["journey"]["executions"]] == [
        (1, "CURRENT", False),
        (2, "NOT_STARTED", True),
    ]
    obs = control(early, "SYN-CTRL-01")["observations"]
    assert [(o["survey"]["position"], o["result"], o["gap"], o["simulation_id"] is None) for o in obs] == [
        (1, "NOT_ASKED", "AWAITING_ANSWER", False),
        (2, "NOT_ASKED", "SURVEY_NOT_STARTED", True),
    ]
    assert outcomes(early)["SYN-CTRL-01"] == "INSUFFICIENT_EVIDENCE"

    # ---- 2, 3, 5. both surveys complete: ONE journey-level evaluation, independent evidence per survey
    done = journey(
        {"mi-numbers/n1": {"number": 20}, "mi-numbers/n2": {"number": 12.5}, "mi-numbers/n3": {"number": -3}}
    )["final"]
    assert done["status"] == "ALL_SURVEYS_COMPLETED"
    ev = evaluate(author, coordinated=done["id"])
    assert (ev["journey_kind"], ev["coordinated_id"], ev["simulation_id"], ev["journey"]["complete"]) == (
        "COORDINATED",
        done["id"],
        None,
        True,
    )
    sims = [s["simulation_id"] for s in done["surveys"]]
    assert [
        (x["survey_version_id"], x["simulation_id"], x["run_sha256"], x["ending"]) for x in ev["journey"]["executions"]
    ] == [
        (version["A"], sims[0], done["surveys"][0]["run_sha256"], "COMPLETED"),
        (version["B"], sims[1], done["surveys"][1]["run_sha256"], "COMPLETED"),
    ]
    assert ev["pins"]["journey"]["replay_sha256"] == done["replay_sha256"] and len(ev["pins"]["executions"]) == 2
    # the control appears ONCE, with evidence from two surveys — each observation naming its own survey's simulation
    assert [c["control_code"] for c in ev["controls"]] == [
        "SYN-CTRL-01",
        "SYN-CTRL-02",
        "SYN-CTRL-03",
        "SYN-CTRL-04",
        "SYN-CTRL-05",
    ]
    one = control(ev, "SYN-CTRL-01")
    assert [
        (
            o["survey"]["survey_code"] == done["surveys"][i]["survey_code"],
            o["simulation_id"],
            o["survey"]["survey_version_id"],
            o["result"],
        )
        for i, o in enumerate(one["observations"])
    ] == [
        (True, sims[0], version["A"], "MATCH"),
        (True, sims[1], version["B"], "MATCH"),
    ]
    assert one["outcome"] == "SATISFIED" and outcomes(ev)["SYN-CTRL-02"] == "SATISFIED"
    assert (
        one["observations"][1]["evaluation"]["method"] == "NUMERIC_COMPARE"
        and one["observations"][1]["evaluation"]["normalized_answer"] == "20"
    )
    # all surveys COMPLETED and two controls SATISFIED is still not a completed evaluation: three controls have no mapping
    assert (ev["processing_status"], ev["summary"]["by_outcome"]["UNRESOLVED"], ev["coverage"]["status"]) == (
        "INCOMPLETE",
        3,
        "NOT_ASSERTED",
    )
    assert ev["findings"] == []

    # ---- 6. both surveys complete, and the control is NOT satisfied
    low = journey({"mi-numbers/n1": {"number": 1}, "mi-numbers/n2": {"number": 100}, "mi-numbers/n3": {"number": 0}})[
        "final"
    ]
    assert low["status"] == "ALL_SURVEYS_COMPLETED" and [s["state"] for s in low["surveys"]] == [
        "COMPLETED",
        "COMPLETED",
    ]
    ev_low = evaluate(author, coordinated=low["id"])
    assert outcomes(ev_low)["SYN-CTRL-01"] == "NOT_SATISFIED" and ev_low["journey"]["complete"] is True
    assert [o["result"] for o in control(ev_low, "SYN-CTRL-01")["observations"]] == ["MATCH", "MISMATCH"]
    # the finding comes from the existing rules and points at survey B's own simulation and answer
    (f,) = ev_low["findings"]
    assert (f["control_code"], f["rule"]["rule_code"], f["simulation_id"], f["placement"], f["survey"]["position"]) == (
        "SYN-CTRL-01",
        "FR-EVAL-MISMATCH",
        low["surveys"][1]["simulation_id"],
        "mi-numbers/n1",
        2,
    )
    assert f["evidence"]["normalized_answer"] == "1" and "at least 18" in f["evidence"]["evaluation_explanation"]
    assert ev_low["id"] != ev["id"] and ev_low["result_sha256"] != ev["result_sha256"]

    # ---- one survey of the journey evaluated on its own is the same model with one execution: the other survey's
    #      evidence does not exist there, and that is an evidence gap
    alone = evaluate(author, simulation_id=sims[0])
    assert (alone["journey_kind"], len(alone["journey"]["executions"])) == ("SINGLE_SURVEY", 1)
    o = control(alone, "SYN-CTRL-01")["observations"][1]
    assert (o["result"], o["gap"], o["survey"], o["simulation_id"]) == ("NOT_ASKED", "ITEM_NOT_IN_JOURNEY", None, None)
    assert outcomes(alone)["SYN-CTRL-01"] == "INSUFFICIENT_EVIDENCE" and outcomes(alone)["SYN-CTRL-02"] == "SATISFIED"

    # ---- 17. security: permissions, market, CSRF
    reader = make_account(db, prefix="evalreader")
    GRANTS[reader.principal_id] = ASSIGNMENT_ALL | {"survey.evaluation.read"}
    c = _client(survey_app, reader)
    assert c.get(f"{E}/evaluations/{ev['id']}").status_code == 200
    assert (
        post(c, f"{E}/evaluations", {"coordinated_simulation_id": done["id"]}).status_code == 403
    )  # reading is not evaluating
    GRANTS[reader.principal_id] = ASSIGNMENT_ALL | {"survey.evaluate"}
    assert c.get(f"{E}/evaluations/{ev['id']}").status_code == 403 and c.get(f"{E}/controls").status_code == 403
    assert (
        post(c, f"{E}/evaluations", {"coordinated_simulation_id": done["id"]}).status_code == 403
    )  # evaluating needs reading too
    GRANTS[reader.principal_id] = ASSIGNMENT_ALL  # every other survey permission opens nothing here
    for path in (
        "/controls",
        "/mappings",
        f"/evaluations/{ev['id']}",
        f"/evaluations?coordinated_simulation_id={done['id']}",
    ):
        assert c.get(E + path).status_code == 403, path
    c.__exit__(None, None, None)
    GRANTS.pop(reader.principal_id)
    outsider = make_account(db, prefix="evalmy")
    GRANTS[outsider.principal_id] = ALL
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    c = _client(survey_app, outsider)
    assert c.get(f"{E}/evaluations/{ev['id']}").status_code == 404
    assert c.get(f"{E}/evaluations", params={"coordinated_simulation_id": done["id"]}).json()["items"] == []
    assert post(c, f"{E}/evaluations", {"coordinated_simulation_id": done["id"]}).status_code == 404
    assert post(c, f"{E}/evaluations", {"simulation_id": sims[0]}).status_code == 404
    assert c.get(f"{E}/mappings").json()["items"] == []
    r = propose(c, "SYN-CTRL-03", [entry(a["mi-call/n2"], YES)])
    assert (r.status_code, r.json()["code"]) == (403, "MARKET_NOT_IN_SCOPE")
    r = propose(c, "SYN-CTRL-03", [entry(a["mi-call/n2"], YES)], market_code="MY")
    assert (r.status_code, r.json()["code"]) == (422, "ITEM_NOT_PUBLISHED")  # nothing of SG is published in MY
    c.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)
    assert (
        author.post(f"{E}/evaluations", json={"coordinated_simulation_id": done["id"]}).status_code == 403
    )  # no CSRF token
    r = post(author, f"{E}/evaluations", {"simulation_id": sims[0], "coordinated_simulation_id": done["id"]})
    assert (r.status_code, r.json()["code"]) == (422, "JOURNEY_REQUIRED")
    assert post(author, f"{E}/evaluations", {"coordinated_simulation_id": str(uuid.uuid4())}).status_code == 404
    denied = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' AND reason LIKE '%survey.evaluat%'"
        )
    ).scalar_one()
    assert denied >= 4
    # ---- 16. nothing operational
    assert counts(db, OPERATIONAL) == operational_before
    for cx in (maker, rule_checker):
        cx.__exit__(None, None, None)


def test_a_mapping_is_governed_by_three_people_and_names_only_published_evidence(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, settings: Settings
) -> None:
    author, checker, publisher, people = trio
    sid, _, renamed = build(author, "K8", "Application survey")
    vid = publish(trio, sid)[1]
    it = items_of(db, vid)
    question, statement, ack = it["mi-opening/n2"], it["mi-opening/n1"], it["mi-senior/n1"]
    register = author.get(f"{E}/controls").json()
    assert [c["control_code"] for c in register["items"]] == [f"SYN-CTRL-0{n}" for n in range(1, 6)]
    assert register["combinations"] == ["ALL_REQUIRED"] and all(
        c["published"] == [] and c["content_approval_status"] == "SYNTHETIC_UNAPPROVED" for c in register["items"]
    )

    # ---- nothing is mapped that is not exact, published and evaluable by the existing rule language
    for body, status, code in (
        ({"control_code": "NO-SUCH-CONTROL"}, 404, "CONTROL_NOT_FOUND"),
        ({"combination": "ANY_ONE"}, 422, "COMBINATION_UNSUPPORTED"),  # no other combination has an approved meaning
        ({"source": "short"}, 422, "SOURCE_REQUIRED"),
        (
            {"entries": [entry({"code": question["code"], "version": 9}, YES)]},
            422,
            "ITEM_NOT_PUBLISHED",
        ),  # the exact revision
        ({"entries": [entry({"code": "Q-INVENTED", "version": 1}, YES)]}, 422, "ITEM_NOT_PUBLISHED"),
        ({"entries": [entry(statement, YES)]}, 422, "ANSWER_TYPE_UNSUPPORTED"),  # a statement takes no answer
        (
            {"entries": [entry(question, {"method": "NUMERIC_COMPARE", "evaluation": {"value": 1, "unit": "COUNT"}})]},
            422,
            "RULE_INVALID",
        ),  # the existing validator
        (
            {"entries": [entry(question, {"method": "EXACT_BOOLEAN"})]},
            422,
            "RULE_INVALID",
        ),  # no expected answer is assumed
        ({"entries": [entry(question, {"method": "COLLECT_ONLY"})]}, 422, "RULE_INVALID"),
        ({"entries": [entry(question, YES, required=False)]}, 422, "NO_REQUIRED_EVIDENCE"),
        ({"entries": [entry(question, YES), entry(question, YES)]}, 422, "ENTRY_DUPLICATE"),
        ({"entries": [entry(question, YES, survey_code="S-NOWHERE")]}, 422, "CONTEXT_INVALID"),
        ({"entries": [{**entry(statement), "rule": YES}]}, 422, "RULE_NOT_ALLOWED"),
        (
            {"applicability": {"condition": {"code": "C-INVENTED", "version": 1}, "params": {}}},
            422,
            "CONDITION_NOT_PUBLISHED",
        ),
        (
            {"applicability": {"condition": {"code": renamed["C-OLDER"], "version": 1}, "params": {}}},
            422,
            "APPLICABILITY_PARAMS",
        ),
    ):
        over = dict(body)
        r = propose(
            author,
            over.pop("control_code", "SYN-CTRL-01"),
            over.pop("entries", [entry(question, YES)]),
            over.pop("applicability", None),
            **over,
        )
        assert (r.status_code, r.json()["code"]) == (status, code), (body, r.text)
    assert db.execute(text("SELECT count(*) FROM survey_control_mapping")).scalar_one() == 0

    # ---- one reusable question serves different controls; one control takes several pieces of evidence
    r = propose(
        author,
        "SYN-CTRL-01",
        [entry(question, YES), entry(statement), entry(ack, {"method": "ACKNOWLEDGEMENT"}, required=False)],
    )
    assert r.status_code == 201, r.text
    m = r.json()
    assert (m["status"], m["revision"], m["is_proposer"], len(m["mapping_sha256"])) == ("PROPOSED", 1, True, 64)
    assert [(e["item"], e["evidence_type"], e["required"], e["rule_text"]) for e in m["entries"]] == [
        (question, "ANSWER", True, "Expected answer: yes"),
        (statement, "DELIVERY", True, "The exact pinned wording is delivered"),
        (ack, "ANSWER", False, "Expected: the customer acknowledges"),
    ]
    assert all(len(e["item_sha256"]) == 64 for e in m["entries"])
    r = propose(author, "SYN-CTRL-01", [entry(question, YES)])
    assert (r.status_code, r.json()["code"]) == (409, "MAPPING_OPEN")
    assert (
        propose(
            author, "SYN-CTRL-02", [entry(question, {"method": "EXACT_BOOLEAN", "expected_boolean": False})]
        ).status_code
        == 201
    )  # the same question, another control, another expectation

    # ---- maker, checker, publisher: three different people, whatever they hold
    mid = m["id"]
    r = post(author, f"{E}/mappings/{mid}/decision", {"verdict": "APPROVE"})
    assert (r.status_code, r.json()["code"]) == (403, "SELF_REVIEW_DENIED")
    r = post(publisher, f"{E}/mappings/{mid}/publish")
    assert (r.status_code, r.json()["code"]) == (409, "NOT_APPROVED")
    r = post(checker, f"{E}/mappings/{mid}/decision", {"verdict": "REJECT", "comment": "no"})
    assert (r.status_code, r.json()["code"]) == (422, "COMMENT_REQUIRED")
    assert post(checker, f"{E}/mappings/{mid}/decision", {"verdict": "APPROVE"}).json()["status"] == "APPROVED"
    for person, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        r = post(person, f"{E}/mappings/{mid}/publish")
        assert (r.status_code, r.json()["code"]) == (403, code)
    done = post(publisher, f"{E}/mappings/{mid}/publish").json()
    assert done["status"] == "PUBLISHED" and [h["event"] for h in done["history"]] == [
        "PROPOSED",
        "APPROVED",
        "PUBLISHED",
    ]
    assert len({done["proposed_by"], done["approved_by"], done["published_by"]}) == 3
    # the database refuses what the service refuses, and a published revision cannot be edited
    for sql in (
        f"INSERT INTO survey_control_mapping_event (mapping_id, event, actor_ref) VALUES ('{mid}', 'PROPOSED', 'x')",
        f"UPDATE survey_control_mapping SET entries = '[]' WHERE id = '{mid}'",
        f"DELETE FROM survey_control_mapping_event WHERE mapping_id = '{mid}'",
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as c:
                c.execute(text(sql))
    other = author.get(f"{E}/mappings").json()["items"][1]
    with pytest.raises(DBAPIError, match="proposer cannot decide"):
        with engine.begin() as c:
            c.execute(
                text(
                    "INSERT INTO survey_control_mapping_event (mapping_id, event, actor_ref) VALUES (:m, 'APPROVED', :a)"
                ),
                {"m": other["id"], "a": other["proposed_by"]},
            )
    denials = db.execute(
        text("SELECT count(*) FROM audit_event WHERE action = 'SURVEY.CONTROL_MAPPING_DENIED'")
    ).scalar_one()
    assert denials == 3

    # ---- a withdrawn mapping: the control is unresolved again — it does not disappear
    sim = simulate(author, vid, K8_FACTS, {"mi-opening/n2": {"choice": "YES"}})
    before = evaluate(author, simulation_id=sim["id"])
    assert (
        outcomes(before)["SYN-CTRL-01"] == "SATISFIED" and before["findings_status"] == "FINDING_RULES_MISSING"
    )  # no published rule set: said, not zero
    optional = control(before, "SYN-CTRL-01")["observations"][2]
    assert (optional["required"], optional["result"]) == (
        False,
        "NOT_APPLICABLE",
    )  # optional evidence does not decide the control
    GRANTS[people[0].principal_id] = ALL - {
        "survey.publish"
    }  # withdrawing what is published needs the permission to publish
    r = post(author, f"{E}/mappings/{mid}/withdraw", {"reason": "No longer the governed mapping"})
    assert (r.status_code, r.json()["code"]) == (403, "FORBIDDEN")
    GRANTS[people[0].principal_id] = ALL
    assert (
        post(publisher, f"{E}/mappings/{mid}/withdraw", {"reason": "No longer the governed mapping"}).json()["status"]
        == "WITHDRAWN"
    )
    after = evaluate(author, simulation_id=sim["id"])
    assert after["id"] != before["id"] and control(after, "SYN-CTRL-01")["reasons"][0]["code"] == "MAPPING_MISSING"
    assert outcomes(author.get(f"{E}/evaluations/{before['id']}").json())["SYN-CTRL-01"] == "SATISFIED"

    # ---- a governed decision is not thrown away by a schema change
    from tests.support import migrate

    db.rollback()
    with pytest.raises(RuntimeError, match="governed control mappings exist"):
        migrate(settings, "0032_survey_coordinated_sim", down=True)


def _control(code: str) -> dict[str, Any]:
    return {
        "id": uuid.uuid5(uuid.NAMESPACE_URL, code),
        "control_code": code,
        "name": f"{code} (synthetic)",
        "owner_role": "S&C (proposed)",
        "content_approval_status": "SYNTHETIC_UNAPPROVED",
    }


def _mapping(c: dict[str, Any], entries: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    return {
        "id": uuid.uuid5(uuid.NAMESPACE_URL, "m:" + c["control_code"]),
        "revision": 1,
        "mapping_sha256": "0" * 64,
        "combination": "ALL_REQUIRED",
        "source": "test",
        "control_sha256": ce.control_sha256(c),
        "applicability": None,
        "entries": entries,
    } | over


def _execution(
    position: int, prefix: str, answers: list[tuple[str, dict[str, Any]]], code: str | None = None
) -> dict[str, Any]:
    bundle = fixture_bundle(prefix)
    run = execute_inputs(bundle, {}, [{"key": k, "answer": a} for k, a in answers])
    ended = (run["terminal"] or {}).get("state")
    return {
        "position": position, "survey_code": code or f"S-{prefix}", "survey_name": prefix, "version_label": "1.0", "survey_version_id": uuid.uuid5(uuid.NAMESPACE_URL, f"{prefix}{position}"),
        "content_sha256": "1" * 64, "manifest_sha256": "2" * 64, "state": "COMPLETED" if ended == "COMPLETED" else "STOPPED" if ended else "CURRENT", "bundle": bundle,
        "simulation_id": uuid.uuid5(uuid.NAMESPACE_URL, f"sim{prefix}{position}"), "run": run, "run_sha256": "3" * 64, "engine_contract": "x",
    }  # fmt: skip


def _journey(executions: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    return {
        "kind": "COORDINATED",
        "id": uuid.uuid5(uuid.NAMESPACE_URL, "j"),
        "status": "X",
        "complete": all(x["state"] == "COMPLETED" for x in executions),
        "trusted": True,
        "problems": [],
        "facts": {},
        "executions": executions,
    } | over


def _entry(item_code: str, rule: dict[str, Any] | None, required: bool = True) -> dict[str, Any]:
    return {
        "item": {"code": item_code, "version": 1},
        "evidence_type": "ANSWER" if rule else "DELIVERY",
        "required": required,
        "survey_code": None,
        "rule": rule,
    }


BOOL_YES = {
    "method": "EXACT_BOOLEAN",
    "answer_type": "YES_NO",
    "options": [],
    "expected": {"value": True},
    "fact_key": None,
}
ACK = {"method": "ACKNOWLEDGEMENT", "answer_type": "ACKNOWLEDGEMENT", "options": [], "expected": None, "fact_key": None}


def test_the_engine_never_reconciles_passes_or_invents() -> None:
    """Engine level (pure, no database): the cases a governed journey cannot easily be put into."""
    k1 = {p["key"]: p["item_code"] for p in ce.placements(fixture_bundle("K1"))}
    c1 = _control("CTRL-A")
    m = {"CTRL-A": _mapping(c1, [_entry(k1["mi-call/n2"], BOOL_YES)])}
    rules = fe.RuleSet.of(
        "11111111-1111-1111-1111-111111111111",
        "test rules",
        "PUBLISHED",
        fe.normalise_rules(
            [
                rule("FR-ANY-MISMATCH", "MISMATCH", "FACT_MISMATCH", "LOW"),
                rule("FR-ANY-UNRESOLVED", "UNRESOLVED", "MISSING_MANDATORY_ANSWER", "LOW"),
            ]
        ),
    )
    yes = _execution(1, "K1", [("mi-call/n2", {"choice": "YES"}), ("mi-call/n5", {"choice": "YES"})], "S-ONE")
    no = _execution(2, "K1", [("mi-call/n2", {"choice": "NO"})], "S-TWO")

    # ---- 11. contradictory evidence about the same item is reported and requires review; no answer is chosen
    r = ce.evaluate_journey(_journey([yes, no]), [c1], m, rules)
    line = r["controls"][0]
    assert (line["outcome"], r["processing_status"]) == ("REQUIRES_REVIEW", "REQUIRES_REVIEW")
    conflict = line["reasons"][0]
    assert conflict["code"] == "EVIDENCE_CONFLICT" and [a["value"] for a in conflict["answers"]] == ["False", "True"]
    assert [o["result"] for o in line["observations"]] == ["MATCH", "MISMATCH"]  # both kept, each with its own survey
    assert (
        len(r["findings"]) == 1 and r["findings"][0]["survey"]["survey_code"] == "S-TWO"
    )  # no finding is merged or dropped
    # the same answer twice is not a conflict, and gives two observations, not one
    twice = ce.evaluate_journey(
        _journey([yes, {**yes, "position": 2, "survey_code": "S-TWO", "simulation_id": uuid.uuid4()}]), [c1], m, rules
    )
    assert twice["controls"][0]["outcome"] == "SATISFIED" and len(twice["controls"][0]["observations"]) == 2
    # one of two placements unanswered: the control is not satisfied by the other
    half = ce.evaluate_journey(_journey([yes, _execution(2, "K1", [], "S-TWO")]), [c1], m, rules)
    assert half["controls"][0]["outcome"] == "INSUFFICIENT_EVIDENCE"

    # ---- 14. deterministic: the same inputs, the same result and fingerprint
    again = ce.evaluate_journey(_journey([yes, no]), [c1], m, rules)
    assert again == r and len(r["result_sha256"]) == 64

    # ---- a journey whose evidence cannot be trusted: FAILED_TECHNICALLY, and nothing passes
    failed = ce.evaluate_journey(_journey([yes], trusted=False, problems=[{"code": "REPLAY_DRIFT"}]), [c1], m, rules)
    assert (
        failed["processing_status"],
        failed["controls"][0]["outcome"],
        failed["controls"][0]["reasons"][0]["code"],
    ) == ("FAILED_TECHNICALLY", "UNRESOLVED", "EVIDENCE_INTEGRITY_FAILED")
    assert (
        failed["findings"] == []
        and failed["findings_status"] == "NOT_GENERATED_EVIDENCE_NOT_TRUSTED"
        and failed["summary"]["by_outcome"]["SATISFIED"] == 0
    )

    # ---- a NON-ANSWER whose policy is undecided is not turned into a business failure
    k4 = {p["key"]: p["item_code"] for p in ce.placements(fixture_bundle("K4"))}
    m4 = {"CTRL-A": _mapping(c1, [_entry(k4["mi-ack/n2"], ACK)])}
    refused = _execution(1, "K4", [("mi-ack/n2", {"acknowledged": False})])
    assert refused["run"]["status"] == "POLICY_UNRESOLVED"
    r4 = ce.evaluate_journey(_journey([refused]), [c1], m4, rules)
    o = r4["controls"][0]["observations"][0]
    assert (o["result"], o["gap"], o["refused_inputs"]) == (
        "UNRESOLVED",
        "NON_ANSWER_POLICY_UNRESOLVED",
        ["NON_ANSWER_POLICY_UNRESOLVED"],
    )
    assert o["evaluation"]["answer"] is None  # no answer is manufactured, and no refusal reason is claimed
    assert (r4["controls"][0]["outcome"], r4["processing_status"]) == (
        "INSUFFICIENT_EVIDENCE",
        "INCOMPLETE",
    )  # not NOT_SATISFIED
    assert [(f["trigger"], f["finding_class"]) for f in r4["findings"]] == [
        ("UNRESOLVED", "MISSING_EVIDENCE")
    ]  # the existing class: not a customer discrepancy
    accepted = ce.evaluate_journey(
        _journey([_execution(1, "K4", [("mi-ack/n2", {"acknowledged": True})])]), [c1], m4, rules
    )
    assert accepted["controls"][0]["observations"][0]["result"] == "MATCH"

    # ---- what the existing engines cannot decide is never decided here
    unsupported = ce.observe(
        yes,
        {
            "key": "mi-call/n2",
            "instance": "mi-call",
            "node": "n2",
            "item_code": "Q-X",
            "item_version": 1,
            "item_name": "x",
            "answer_type": "RANKING",  # a kind of answer the evaluator has no method for
        },
        _entry("Q-X", BOOL_YES),
    )
    assert (unsupported["result"], unsupported["gap"]) == ("UNSUPPORTED_EVIDENCE", "ANSWER_TYPE_NOT_EVALUABLE")
    assert ce._decide([unsupported])[0] == "INSUFFICIENT_EVIDENCE"
    other = ce.evaluate_journey(
        _journey([yes]), [c1], {"CTRL-A": _mapping(c1, m["CTRL-A"]["entries"], combination="ANY_ONE")}, rules
    )
    assert (
        other["controls"][0]["reasons"][0]["code"] == "COMBINATION_UNSUPPORTED"
        and other["controls"][0]["outcome"] == "UNRESOLVED"
    )
    changed = ce.evaluate_journey(_journey([yes]), [c1 | {"name": "Renamed after the mapping"}], m, rules)
    assert changed["controls"][0]["reasons"][0]["code"] == "CONTROL_CHANGED_SINCE_MAPPING"
    fact = {
        "method": "NUMERIC_MATCH_POLICY_FACT",
        "answer_type": "NUMERIC",
        "options": [],
        "expected": {"operator": "EQ", "unit": "YEARS", "tolerance": "0", "tolerance_reference": None},
        "fact_key": "premium_term_years",
    }
    k3 = {p["key"]: p["item_code"] for p in ce.placements(fixture_bundle("K3"))}
    numbers = _execution(1, "K3", [("mi-numbers/n1", {"number": 20})])
    r3 = ce.evaluate_journey(
        _journey([numbers]), [c1], {"CTRL-A": _mapping(c1, [_entry(k3["mi-numbers/n1"], fact)])}, rules
    )
    # the application's catalog facts are not the evaluator's policy facts: nothing maps them, so nothing is compared
    assert (r3["controls"][0]["observations"][0]["result"], r3["controls"][0]["outcome"]) == (
        "MISSING_EXPECTED_FACT",
        "INSUFFICIENT_EVIDENCE",
    )
    human = {
        "method": "NARRATIVE_REVIEW",
        "answer_type": "FREE_TEXT",
        "options": [],
        "expected": None,
        "fact_key": None,
    }
    assert (
        ce._decide(
            [
                {
                    "required": True,
                    "result": "HUMAN_ASSESSMENT_REQUIRED",
                    "evidence_type": "ANSWER",
                    "item": {"code": "Q", "version": 1},
                    "survey": None,
                    "placement": None,
                    "gap": None,
                    "explanation": "",
                    "evaluation": None,
                }
            ]
        )[0]
        == "REQUIRES_REVIEW"
    )
    assert human["method"] in ae.METHODS

    # ---- 18. no model, no provider, no network: the three modules import only the deterministic domain
    root = Path(__file__).resolve().parents[1] / "app" / "domain" / "survey"
    for name in (
        "control_evaluation.py", "control_mapping.py", "journey_evaluation.py", "control_policy.py", "policy_evaluation.py",
    ):  # fmt: skip
        imports = [ln for ln in (root / name).read_text().splitlines() if ln.startswith(("from ", "import "))]
        assert imports and all(
            ln.startswith(
                (
                    "from __future__",
                    "import json",
                    "import re",
                    "import uuid",
                    "from collections",
                    "from typing",
                    "from sqlalchemy",
                    "from app.audit.chain",
                    "from app.domain",
                )
            )
            for ln in imports
        ), name
        assert not [
            ln
            for ln in imports
            if any(w in ln for w in ("voice", "provider", "llm", "openai", "azure", "httpx", "requests"))
        ]


def test_evaluation_is_off_by_default_and_needs_simulation(settings: Settings, engine: Engine, db: Session) -> None:
    assert Settings.model_fields["survey_evaluation_enabled"].default is False
    person = make_account(db, prefix="evaloff")
    GRANTS[person.principal_id] = ALL
    for update, registered in (
        ({k: v for k, v in SETTINGS_ON.items() if k != "survey_evaluation_enabled"}, False),
        (
            {"survey_definitions_enabled": True, "survey_evaluation_enabled": True, "transcription_worker": False},
            False,
        ),  # without simulation
        (
            {
                "survey_definitions_enabled": True,
                "survey_simulation_enabled": True,
                "survey_evaluation_enabled": True,
                "transcription_worker": False,
            },
            True,
        ),
    ):
        app = create_app(settings.model_copy(update=update))
        with_grants(app)
        operations = [(m, p) for p, item in app.openapi()["paths"].items() if p.startswith(E) for m in item]
        assert len(operations) == (10 if registered else 0)
        c = _client(app, person)
        assert c.get(f"{E}/controls").status_code == (200 if registered else 404)
        assert c.get("/health/ready").status_code == 200
        c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id)


def test_zz_migration_0033_goes_down_and_up_and_changes_nothing_else(
    fresh_schema: None, engine: Engine, settings: Settings
) -> None:
    from tests.support import migrate

    def state() -> tuple[set[str], str, int, int]:
        with engine.connect() as c:
            return (
                set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars()),
                c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one(),
                c.execute(
                    text(
                        "SELECT count(*) FROM call360_test.permission WHERE code IN ('survey.evaluate', 'survey.evaluation.read')"
                    )
                ).scalar_one(),
                c.execute(
                    text(
                        "SELECT count(*) FROM call360_test.role_permission rp JOIN call360_test.permission p ON p.id = rp.permission_id WHERE p.code LIKE 'survey.evalua%'"
                    )
                ).scalar_one(),
            )

    full = state()
    assert set(EVALUATION_TABLES) <= full[0] and full[1:] == (
        "0035_survey_execution_assurance",
        2,
        0,
    )  # granted to nobody
    migrate(settings, "0032_survey_coordinated_sim", down=True)
    # EVAL-2A (0034) sits above 0033 and goes down with it
    assert state() == (
        full[0]
        - set(EVALUATION_TABLES)
        - {
            "survey_control_policy",
            "survey_control_policy_event",
            "survey_evaluation_policy",
            "survey_obligation_result",
            "survey_obligation_observation",
            "survey_obligation_finding",
            "survey_execution_assurance",
            "survey_execution_assurance_survey",
        },
        "0032_survey_coordinated_sim",
        0,
        0,
    )
    migrate(settings, "head")
    assert state() == full


def _obs(
    result: str, *, required: bool = True, item: str = "Q-A", value: Any = None, where: str = "S-ONE:p"
) -> dict[str, Any]:
    answered = result in ("MATCH", "MISMATCH", "HUMAN_ASSESSMENT_REQUIRED", "NOT_EVALUATED")
    delivery = result in ("DELIVERED", "NOT_DELIVERED")
    return {
        "required": required, "result": result, "evidence_type": "DELIVERY" if delivery else "ANSWER", "item": {"code": item, "version": 1},
        "survey": {"survey_code": where.split(":")[0]}, "placement": where.split(":")[1], "gap": None if answered or result == "DELIVERED" else "GAP",
        "explanation": result.lower(),
        "evaluation": {"answer": {"kind": "ANSWER", "value": value if value is not None else result == "MATCH"}} if answered else None,
    }  # fmt: skip


M, X, D = "MATCH", "MISMATCH", "DELIVERED"
TRUTH_TABLE: list[tuple[str, list[dict[str, Any]], str, set[str]]] = [
    # ---- rule 1: all required evidence matches or is delivered
    ("one match", [_obs(M)], "SATISFIED", set()),
    ("match and delivery", [_obs(M), _obs(D, item="S-B")], "SATISFIED", set()),
    ("optional gap beside required match", [_obs(M), _obs("NOT_ASKED", required=False, item="Q-B")], "SATISFIED", set()),
    ("optional mismatch does not decide", [_obs(M), _obs(X, required=False, item="Q-B")], "SATISFIED", set()),
    # ---- an empty required-evidence set never satisfies
    ("no evidence at all", [], "UNRESOLVED", {"NO_EVALUABLE_REQUIRED_EVIDENCE"}),
    ("only optional matches", [_obs(M, required=False)], "UNRESOLVED", {"NO_EVALUABLE_REQUIRED_EVIDENCE"}),
    ("required evidence the evaluator did not evaluate", [_obs("NOT_EVALUATED")], "UNRESOLVED", {"EVIDENCE_NOT_EVALUATED", "NO_EVALUABLE_REQUIRED_EVIDENCE"}),
    # ---- rule 2: an unambiguous required mismatch
    ("one mismatch", [_obs(X)], "NOT_SATISFIED", {"EVIDENCE_MISMATCH"}),
    ("match and mismatch of different items", [_obs(M), _obs(X, item="Q-B")], "NOT_SATISFIED", {"EVIDENCE_MISMATCH"}),
    ("mismatch and a gap: both explanations kept", [_obs(X), _obs("NOT_ASKED", item="Q-B")], "NOT_SATISFIED", {"EVIDENCE_MISMATCH", "EVIDENCE_NOT_ASKED"}),
    ("mismatch and human assessment", [_obs(X), _obs("HUMAN_ASSESSMENT_REQUIRED", item="Q-B", value="text")], "NOT_SATISFIED", {"EVIDENCE_MISMATCH", "EVIDENCE_HUMAN_ASSESSMENT_REQUIRED"}),
    ("mismatch and undelivered statement", [_obs(X), _obs("NOT_DELIVERED", item="S-B")], "NOT_SATISFIED", {"EVIDENCE_MISMATCH", "EVIDENCE_NOT_DELIVERED"}),
    # ---- rule 3: missing required evidence without an established mismatch
    *[
        (f"match and {gap.lower()}", [_obs(M), _obs(gap, item="Q-B")], "INSUFFICIENT_EVIDENCE", {f"EVIDENCE_{gap}"})
        for gap in ("UNRESOLVED", "NOT_ASKED", "MISSING_EXPECTED_FACT", "NOT_APPLICABLE", "NOT_DELIVERED", "UNSUPPORTED_EVIDENCE")
    ],
    ("only gaps", [_obs("NOT_ASKED"), _obs("UNRESOLVED", item="Q-B")], "INSUFFICIENT_EVIDENCE", {"EVIDENCE_NOT_ASKED", "EVIDENCE_UNRESOLVED"}),
    ("gap and human assessment: the gap comes first", [_obs("NOT_ASKED"), _obs("HUMAN_ASSESSMENT_REQUIRED", item="Q-B", value="t")], "INSUFFICIENT_EVIDENCE", {"EVIDENCE_NOT_ASKED", "EVIDENCE_HUMAN_ASSESSMENT_REQUIRED"}),
    ("one placement matched, another of the same item not asked", [_obs(M), _obs("NOT_ASKED", where="S-TWO:p")], "INSUFFICIENT_EVIDENCE", {"EVIDENCE_NOT_ASKED"}),
    # ---- rule 4: conflicting evidence — before everything else, and nothing is lost
    ("the same item answered differently", [_obs(M, value=True), _obs(X, value=False, where="S-TWO:p")], "REQUIRES_REVIEW", {"EVIDENCE_CONFLICT", "EVIDENCE_MISMATCH"}),
    ("conflict and a gap elsewhere", [_obs(M, value=True), _obs(X, value=False, where="S-TWO:p"), _obs("NOT_ASKED", item="Q-B")], "REQUIRES_REVIEW", {"EVIDENCE_CONFLICT", "EVIDENCE_MISMATCH", "EVIDENCE_NOT_ASKED"}),
    ("two different answers that both match (a numeric range)", [_obs(M, value=20), _obs(M, value=30, where="S-TWO:p")], "REQUIRES_REVIEW", {"EVIDENCE_CONFLICT"}),
    ("conflict in OPTIONAL evidence still needs a person", [_obs(M, item="Q-R"), _obs(M, required=False, value=1), _obs(M, required=False, value=2, where="S-TWO:p")], "REQUIRES_REVIEW", {"EVIDENCE_CONFLICT"}),
    ("the same answer twice is no conflict", [_obs(M, value=True), _obs(M, value=True, where="S-TWO:p")], "SATISFIED", set()),
    # ---- human assessment, with nothing missing and nothing mismatched
    ("match and human assessment", [_obs(M), _obs("HUMAN_ASSESSMENT_REQUIRED", item="Q-B", value="text")], "REQUIRES_REVIEW", {"EVIDENCE_HUMAN_ASSESSMENT_REQUIRED"}),
]  # fmt: skip


@pytest.mark.parametrize(("name", "observations", "outcome", "codes"), TRUTH_TABLE, ids=[t[0] for t in TRUTH_TABLE])
def test_all_required_truth_table(name: str, observations: list[dict[str, Any]], outcome: str, codes: set[str]) -> None:
    """D-287 as approved: ALL_REQUIRED, its precedence, and every explanation kept whatever the outcome."""
    got, reasons = ce._decide(observations)
    assert got == outcome, name
    assert {r["code"] for r in reasons} == codes, name
    assert ce._decide(list(reversed(observations)))[0] == outcome  # the order of the evidence decides nothing


def test_the_rules_above_the_combination_and_what_satisfied_never_means() -> None:
    """D-287 rules 5–7, which are decided before any evidence is combined; and SATISFIED is never 'compliant'."""
    k1 = {p["key"]: p["item_code"] for p in ce.placements(fixture_bundle("K1"))}
    k8 = fixture_bundle("K8")
    older = next(c for c in k8.conditions.values() if c["code"] == "C-OLDER")
    c1, c2 = _control("CTRL-A"), _control("CTRL-B")
    entries = [_entry(k1["mi-call/n2"], BOOL_YES)]
    yes = _execution(1, "K1", [("mi-call/n2", {"choice": "YES"}), ("mi-call/n5", {"choice": "YES"})])
    when = {"condition": {"code": "C-OLDER", "version": 1}, "ast": older["ast"], "params": {"minimum_age": 60}}

    def outcome(mapping: dict[str, Any] | None, **journey: Any) -> tuple[str, str, dict[str, Any]]:
        r = ce.evaluate_journey(_journey([yes], **journey), [c1], {"CTRL-A": mapping} if mapping else {}, None)
        return (
            r["controls"][0]["outcome"],
            r["controls"][0]["reasons"][0]["code"] if r["controls"][0]["reasons"] else "",
            r,
        )

    assert outcome(_mapping(c1, entries))[:2] == ("SATISFIED", "")
    assert outcome(None)[:2] == ("UNRESOLVED", "MAPPING_MISSING")  # rule 5
    assert outcome(_mapping(c1, entries, applicability=when))[:2] == ("UNRESOLVED", "APPLICABILITY_UNKNOWN")  # rule 5
    assert outcome(_mapping(c1, entries, applicability=when), facts={"customer.age_years": 70})[:2] == ("SATISFIED", "")
    assert outcome(_mapping(c1, entries, applicability=when), facts={"customer.age_years": 40})[:2] == (
        "NOT_APPLICABLE",
        "APPLICABILITY_FALSE",
    )  # rule 6
    out, code, r = outcome(_mapping(c1, entries), trusted=False, problems=[{"code": "REPLAY_DRIFT"}])  # rule 7
    assert (out, code, r["processing_status"], r["summary"]["by_outcome"]["SATISFIED"]) == (
        "UNRESOLVED",
        "EVIDENCE_INTEGRITY_FAILED",
        "FAILED_TECHNICALLY",
        0,
    )
    # a mapping whose every entry is optional could never be proposed; if one existed, it would satisfy nothing
    assert outcome(_mapping(c1, [_entry(k1["mi-call/n2"], BOOL_YES, required=False)]))[:2] == (
        "UNRESOLVED",
        "NO_EVALUABLE_REQUIRED_EVIDENCE",
    )
    # every control SATISFIED and the evaluation COMPLETED still says nothing of the application as a whole
    r = ce.evaluate_journey(
        _journey([yes]), [c1, c2], {"CTRL-A": _mapping(c1, entries), "CTRL-B": _mapping(c2, entries)}, None
    )
    assert (r["processing_status"], r["summary"]["by_outcome"]["SATISFIED"], r["coverage"]["status"]) == (
        "COMPLETED",
        2,
        "NOT_ASSERTED",
    )
    assert "not a compliance verdict" in ce.NOTE and not [
        k for k in r if "complian" in k.lower() or "eligib" in k.lower()
    ]


def test_zz_a_recorded_evaluation_is_not_destroyed_by_a_downgrade(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, settings: Settings
) -> None:
    from tests.support import migrate

    sid, _, _ = build(trio[0], "K1", "Evaluated survey")
    sim = start(trio[0], publish(trio, sid)[1], {})
    ev = evaluate(trio[0], simulation_id=sim["id"])
    assert (
        db.execute(text("SELECT count(*) FROM survey_control_mapping")).scalar_one() == 0
    )  # no mapping: only the evaluation
    db.rollback()
    with pytest.raises(RuntimeError, match="recorded journey evaluations exist"):
        migrate(settings, "0032_survey_coordinated_sim", down=True)
    assert trio[0].get(f"{E}/evaluations/{ev['id']}").json()["result_sha256"] == ev["result_sha256"]
