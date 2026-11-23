# ruff: noqa: E501, F811
"""ASG-2B — coordinated SIMULATION of the surveys of one composite plan: real HTTP, real PostgreSQL (``call360_test``).

Each survey is run by its own SS-03B simulation; the coordinator only starts them in the governed order and stops
where nothing has been decided. The conditions that make an application need several surveys are the stand-ins of
ASG-2A (the rule language has no replacement or rider attribute): they are placeholders, not business requirements."""

from __future__ import annotations

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
from app.domain.survey import simulation
from app.main import create_app
from tests.support import make_account
from tests.survey_fixtures import load_all
from tests.test_assignment_rules import business_fingerprint
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import ALL, OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import compose, group
from tests.test_survey_lib1 import build, publish

A = "/api/v1/survey-assignment"
FX = {fx["fixture"][:2]: fx for fx in load_all()}
SG = {"field": "market", "values": ["SG"]}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "survey_assignment_enabled": True, "survey_assignment_groups_enabled": True,
                "survey_coordinated_simulation_enabled": True, "transcription_worker": False,
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


def start(c: TestClient, composite_id: str, expect: int = 201) -> dict[str, Any]:
    r = post(c, f"{A}/composite-plans/{composite_id}/coordinated-simulations", {"label": "test"})
    assert r.status_code == expect, r.text
    return r.json()


def give(c: TestClient, co: dict[str, Any], answer: dict[str, Any], key: str | None = None) -> Any:
    return post(
        c,
        f"{A}/coordinated-simulations/{co['id']}/inputs",
        {"expected_inputs": co["progress"]["inputs"], "key": key or co["current"]["pending"]["key"], "answer": answer},
    )


def answer_for(pending: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    return run["answers"][pending["key"]]


def states(co: dict[str, Any]) -> list[str]:
    return [s["state"] for s in co["surveys"]]


def test_two_surveys_are_simulated_in_their_governed_order_each_by_its_own_engine_run(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    with engine.connect() as conn:
        scripts_before = business_fingerprint(conn)
    operational_before = counts(db, OPERATIONAL)

    # ---- surveys, rules, bindings, groups. The conditions are STAND-INS (see the module note)
    version: dict[str, str] = {}
    for name, fixture in (("A", "K1"), ("B", "K3"), ("C", "K4"), ("D", "K8")):
        sid, _, _ = build(author, fixture, f"Survey {name}")
        version[name] = publish(trio, sid)[1]
    for rule, conditions, priority, survey in (
        ("P-A", [SG, {"field": "product_family", "values": ["PROTECTION"]}], 1, "A"),
        ("R-B", [SG, {"field": "premium_frequency", "values": ["SINGLE"]}], 2, "B"),
        ("R-C", [SG, {"field": "selling_channel", "values": ["BANCASSURANCE"]}], 3, "C"),
        ("R-D", [SG, {"field": "selling_channel", "values": ["DIRECT"]}], 4, "D"),
        (
            "R-DUP",
            [SG, {"field": "premium_frequency", "values": ["MONTHLY"]}],
            5,
            "A",
        ),  # a second requirement that selects survey A again
        ("R-N", [SG, {"field": "premium_frequency", "values": ["QUARTERLY"]}], 6, "B"),
    ):
        publish_rule(maker, rule_checker, rule, conditions, priority)
        bind(trio, rule, version[survey])
    group(trio, "PRIMARY-SG", "PRIMARY", ["P-A"], sequence=1)
    group(trio, "ADD-B", "ADD_REQUIRED", ["R-B"], sequence=2)
    group(trio, "ADD-C", "ADD_REQUIRED", ["R-C"], sequence=3)
    group(trio, "ADD-D", "ADD_REQUIRED", ["R-D"], sequence=4)
    group(trio, "ADD-DUP", "ADD_REQUIRED", ["R-DUP"], sequence=5)
    group(trio, "ADD-N", "ADD_REQUIRED", ["R-N"])  # no governed position
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    base = {
        "market": "SG", "product_family": "PROTECTION", "selling_channel": "AGENCY", "premium_frequency": "ANNUAL",
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": False,
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip
    run_a, run_b = FX["K1"]["expected_runs"][0], next(r for r in FX["K3"]["expected_runs"] if r.get("rejected"))

    # ---- 1. one application selects two required surveys in a governed order; the three states are told apart
    comp = compose(author, {**base, "premium_frequency": "SINGLE"})
    assert [s["group"] for s in comp["composite"]["selected"]] == ["PRIMARY-SG", "ADD-B"] and comp["composite"][
        "ordering"
    ]["order"] == ["PRIMARY-SG", "ADD-B"]
    assert comp["states"]["call_plan"]["status"] == "COMPUTABLE"
    assert comp["states"]["coordinated_simulation"] == {"status": "PERMITTED", "blockers": [], "available": True}
    assert (
        comp["states"]["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"
    )  # a READY plan says nothing of a call

    # ---- 2. the coordinator starts Survey A — and only Survey A
    co = start(author, comp["id"])
    assert (co["record_class"], co["status"], co["governed_order"], states(co)) == (
        "SIMULATION",
        "RUNNING",
        ["PRIMARY-SG", "ADD-B"],
        ["CURRENT", "NOT_STARTED"],
    )
    assert (co["current"]["position"], co["current"]["group"]) == (1, "PRIMARY-SG") and co["surveys"][1][
        "simulation_id"
    ] is None
    assert (
        co["surveys"][0]["started_because"] == "FIRST_IN_ORDER"
        and co["surveys"][0]["survey_version_id"] == version["A"]
    )
    assert (co["composite_fingerprint"], co["application_sha256"], co["composite_intact"]) == (
        comp["fingerprint"],
        comp["application_sha256"],
        True,
    )
    assert (
        co["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"
        and co["input_consistency"]["status"] == "UNVERIFIED"
    )
    question = co["current"]["pending"]
    assert (
        question["text"]
        == author.get(f"/api/v1/survey-simulations/{co['surveys'][0]['simulation_id']}").json()["run"]["pending"][
            "text"
        ]
    )  # the exact wording is the survey's own

    # ---- 8, 9. an invalid answer does not advance the survey; a pending answer does not start the next survey
    r = give(author, co, {})
    assert r.status_code == 200
    refused = r.json()
    assert (
        refused["status"],
        states(refused),
        refused["current"]["pending"]["key"],
        refused["progress"]["refused_inputs"],
    ) == ("RUNNING", ["CURRENT", "NOT_STARTED"], question["key"], 1)
    assert (
        refused["surveys"][0]["simulation"]["inputs"][-1]["rejection_code"] == "CHOICE_REQUIRED"
        and refused["surveys"][1]["simulation_id"] is None
    )
    r = give(author, co, {"choice": "YES"})  # against a stale count
    assert (r.status_code, r.json()["code"]) == (409, "STALE_SIMULATION")
    r = give(
        author, refused, {"choice": "YES"}, key="mi-nowhere/n1"
    )  # not the current question: the survey's own simulation refuses
    assert (r.status_code, r.json()["code"]) == (409, "INPUT_NOT_CURRENT")
    co = refused

    # ---- 3, 4. Survey A reaches COMPLETED, and only then does the simulation proceed to Survey B
    co = give(author, co, answer_for(co["current"]["pending"], run_a)).json()
    assert states(co) == ["CURRENT", "NOT_STARTED"]  # one question answered, one to go: B is still not started
    co = give(author, co, answer_for(co["current"]["pending"], run_a)).json()
    assert states(co) == ["COMPLETED", "CURRENT"] and (
        co["current"]["position"],
        co["current"]["group"],
        co["status"],
    ) == (2, "ADD-B", "RUNNING")
    assert co["surveys"][0]["simulation"]["run"]["terminal"] == {"state": "COMPLETED", "survey_outcome": "COMPLETED"}
    assert (
        co["surveys"][1]["started_because"] == "PREVIOUS_COMPLETED"
        and co["surveys"][1]["survey_version_id"] == version["B"]
    )
    assert co["decisions"] == [
        {
            "after": "PRIMARY-SG",
            "ending": "COMPLETED",
            "decision": "PROCEED",
            "rule": "SIMULATION_ONLY_COMPLETED_PROCEEDS",
            "to": "ADD-B",
        }
    ]
    assert co["progress"] == {
        "surveys_total": 2,
        "surveys_completed": 1,
        "surveys_started": 2,
        "inputs": 3,
        "refused_inputs": 1,
        "items_delivered": co["progress"]["items_delivered"],
    }

    # ---- 8 again, in Survey B: each invalid number is refused by B's own run and B stays current
    recorded: list[tuple[str, dict[str, Any]]] = []
    bad = {b["at"]: b for b in run_b["rejected"]}
    while co["status"] == "RUNNING":
        p = co["current"]["pending"]
        if p["key"] in bad and p["attempt"] == 0:
            nxt = give(author, co, bad[p["key"]]["answer"]).json()
            assert (
                nxt["current"]["pending"]["key"] == p["key"]
                and nxt["surveys"][1]["simulation"]["inputs"][-1]["rejection_code"] == bad[p["key"]]["error"]
            )
            recorded.append((p["key"], bad[p["key"]]["answer"]))
            co = nxt
            p = co["current"]["pending"]
        recorded.append((p["key"], answer_for(p, run_b)))
        co = give(author, co, answer_for(p, run_b)).json()

    # ---- 5. Survey B reaches COMPLETED. The composite is given NO outcome: only progress is reported
    assert (co["status"], states(co), co["current"], co["stop"]) == (
        "ALL_SURVEYS_COMPLETED",
        ["COMPLETED", "COMPLETED"],
        None,
        None,
    )
    assert co["progress"]["surveys_completed"] == 2 and "outcome" not in co and "terminal" not in co
    r = give(author, {**co, "current": {"pending": {"key": "x/y"}}}, {"choice": "YES"})
    assert (r.status_code, r.json()["code"]) == (409, "ALL_SURVEYS_COMPLETED")

    # ---- 6. both surveys keep their own simulation, trace, inputs, contract and fingerprint — readable on their own
    for s, name, fixture_run in ((co["surveys"][0], "A", run_a), (co["surveys"][1], "B", run_b)):
        own = author.get(f"/api/v1/survey-simulations/{s['simulation_id']}").json()
        assert (own["version_id"], own["run_sha256"], own["record_class"]) == (
            version[name],
            s["run_sha256"],
            "SIMULATION",
        )
        assert (
            own["run"] == s["simulation"]["run"]
            and own["replay_consistent"]
            and own["engine_contract"] == s["engine_contract"] == "call360.survey.execution/1"
        )
        assert (
            own["run"]["asked"] == fixture_run["expect"]["asked"]
        )  # exactly the golden run of that survey: nothing merged, skipped or added
        assert [d["text"] for d in own["run"]["delivered"]] == [
            d["text"] for d in fixture_run["expect"]["delivered"]
        ]  # every statement and question, in full
        assert {e["instance"] for e in own["run"]["events"] if "instance" in e} <= {
            m["instance"] for m in own["run"]["modules"]
        }
    assert co["surveys"][0]["run_sha256"] != co["surveys"][1]["run_sha256"] and co["execution_contracts"] == [
        "call360.survey.execution/1"
    ]
    # ---- 17. the single-survey simulation is what it was: Survey A alone, with the same inputs, has the same run
    alone = post(author, f"/api/v1/survey-versions/{version['A']}/simulations", {"facts": {}}).json()
    for i in co["surveys"][0]["simulation"]["inputs"]:
        alone = post(
            author,
            f"/api/v1/survey-simulations/{alone['id']}/inputs",
            {"expected_inputs": len(alone["inputs"]), "key": i["key"], "answer": i["answer"]},
        ).json()
    assert alone["run_sha256"] == co["surveys"][0]["run_sha256"]

    # ---- 7. replaying identical inputs in a new coordinated simulation gives the identical coordinated result
    again = start(author, comp["id"])
    for s in co["surveys"]:
        for i in s["simulation"]["inputs"]:
            again = give(author, again, i["answer"], key=i["key"]).json()
    assert (
        again["id"] != co["id"]
        and again["replay_sha256"] == co["replay_sha256"]
        and again["status"] == "ALL_SURVEYS_COMPLETED"
    )
    assert [s["run_sha256"] for s in again["surveys"]] == [s["run_sha256"] for s in co["surveys"]]
    assert [s["simulation_id"] for s in again["surveys"]] != [s["simulation_id"] for s in co["surveys"]]
    assert author.get(f"{A}/coordinated-simulations/{co['id']}").json()["replay_sha256"] == co["replay_sha256"]

    # ---- 10. POLICY_UNRESOLVED stops the coordinator: a non-answer in the current survey
    comp_c = compose(author, {**base, "selling_channel": "BANCASSURANCE"})
    c = start(author, comp_c["id"])
    while c["current"]["group"] == "PRIMARY-SG":
        c = give(author, c, answer_for(c["current"]["pending"], run_a)).json()
    assert c["current"]["group"] == "ADD-C" and c["current"]["pending"]["answer_type"] == "ACKNOWLEDGEMENT"
    stopped = give(author, c, {"acknowledged": False}).json()
    assert (stopped["status"], stopped["stop"]["code"], stopped["stop"]["at"], states(stopped)) == (
        "POLICY_UNRESOLVED",
        "POLICY_UNRESOLVED",
        "ADD-C",
        ["COMPLETED", "CURRENT"],
    )
    assert (
        stopped["stop"]["detail"]["reason"] == "NON_ANSWER_POLICY_UNRESOLVED"
        and stopped["surveys"][1]["simulation"]["run"]["terminal"] is None
    )
    assert (
        stopped["current"]["pending"]["key"] == c["current"]["pending"]["key"]
    )  # the question stays current; nothing was synthesised
    assert (
        give(author, stopped, {"acknowledged": True}).json()["status"] == "ALL_SURVEYS_COMPLETED"
    )  # the status was never an ending

    # ---- 11. a non-COMPLETED ending stops without invented continuation
    e = start(author, comp["id"])
    ended = give(author, e, {"choice": "NO"}).json()
    assert ended["surveys"][0]["simulation"]["run"]["terminal"] == {
        "state": "ENDED_WITH_OUTCOME",
        "survey_outcome": "UNABLE_TO_VERIFY",
    }
    assert (ended["status"], ended["stop"]["code"], states(ended), ended["current"]) == (
        "CROSS_SURVEY_POLICY_UNRESOLVED",
        "CROSS_SURVEY_POLICY_UNRESOLVED",
        ["STOPPED", "NOT_STARTED"],
        None,
    )
    assert ended["surveys"][1]["simulation_id"] is None and "has not been decided" in ended["stop"]["reason"]
    assert ended["decisions"] == [
        {
            "after": "PRIMARY-SG",
            "ending": "ENDED_WITH_OUTCOME",
            "decision": "STOP",
            "rule": "CROSS_SURVEY_POLICY_UNRESOLVED",
            "to": None,
        }
    ]
    assert (
        "outcome" not in ended and ended["progress"]["surveys_completed"] == 0
    )  # the composite has no outcome of its own
    r = give(author, {**ended, "current": {"pending": {"key": "x/y"}}}, {"choice": "YES"})
    assert (r.status_code, r.json()["code"]) == (409, "CROSS_SURVEY_POLICY_UNRESOLVED")
    assert (
        db.execute(
            text("SELECT count(*) FROM survey_coordinated_simulation_step WHERE coordinated_id = :c"),
            {"c": ended["id"]},
        ).scalar_one()
        == 1
    )
    db.rollback()

    # ---- 12. two requirements that select the same survey version: explicitly unresolved; nothing is run once or twice
    dup = compose(author, {**base, "premium_frequency": "MONTHLY"})
    assert [s["survey_version_id"] for s in dup["composite"]["selected"]] == [version["A"], version["A"]] and dup[
        "plan_status"
    ] == "READY"
    assert [b["code"] for b in dup["states"]["coordinated_simulation"]["blockers"]] == [
        "DUPLICATE_SURVEY_REQUIREMENT_UNRESOLVED"
    ]
    assert (dup["states"]["call_plan"]["status"], dup["states"]["coordinated_simulation"]["status"]) == (
        "COMPUTABLE",
        "BLOCKED",
    )  # computable is not permitted
    r = start(author, dup["id"], expect=409)
    assert r["code"] == "DUPLICATE_SURVEY_REQUIREMENT_UNRESOLVED" and "PRIMARY-SG, ADD-DUP" in str(r["details"])

    # ---- 13. a missing or conflicting order, or an unsettled selection, prevents a coordinated run
    no_order = compose(author, {**base, "premium_frequency": "QUARTERLY"})
    assert (
        no_order["ordering_status"] == "UNRESOLVED"
        and start(author, no_order["id"], expect=409)["code"] == "ORDER_UNRESOLVED"
    )
    unsettled = compose(author, {k: v for k, v in base.items() if k != "premium_frequency"})
    r = start(author, unsettled["id"], expect=409)
    assert r["code"] == "SELECTION_UNRESOLVED" and unsettled["states"]["coordinated_simulation"]["status"] == "BLOCKED"

    # ---- 14. missing application facts: the plan that needs them is blocked, and that is explained — not run as if ready
    blocked = compose(author, {**base, "selling_channel": "DIRECT"}, {"policy.annual_premium": 3000})
    assert (blocked["plan_status"], blocked["states"]["call_plan"]["status"]) == (
        "BLOCKED",
        "NOT_COMPUTABLE",
    ) and "customer.age_years" in blocked["composite"]["missing_facts"]
    r = start(author, blocked["id"], expect=409)
    assert r["code"] == "PLAN_BLOCKED" and "ADD-D" in str(r["details"])
    for refused_composite in (dup, no_order, unsettled, blocked):
        assert (
            db.execute(
                text("SELECT count(*) FROM survey_coordinated_simulation WHERE composite_plan_id = :c"),
                {"c": refused_composite["id"]},
            ).scalar_one()
            == 0
        )
    db.rollback()
    # a composite that would no longer be computed the same is not started either
    from app.domain.survey import assignment_groups as ag

    real_states = ag.three_states
    monkeypatch.setattr(ag, "three_states", lambda doc, _consistent: real_states(doc, False))
    assert start(author, comp["id"], expect=409)["code"] == "COMPOSITE_STALE"
    monkeypatch.setattr(ag, "three_states", real_states)

    # ---- replay drift of an individual survey is the coordinator's too: never hidden
    real = simulation.execute_inputs

    def changed(bundle: Any, facts: Any, inputs: Any) -> Any:
        out = real(bundle, facts, inputs)
        out["trace"] = [*out["trace"], "changed engine"]
        return out

    monkeypatch.setattr(simulation, "execute_inputs", changed)
    drifted = author.get(f"{A}/coordinated-simulations/{co['id']}").json()
    assert (drifted["status"], drifted["stop"]["code"], drifted["surveys"][0]["state"]) == (
        "REPLAY_DRIFT",
        "REPLAY_DRIFT",
        "DRIFTED",
    )
    assert drifted["replay_sha256"] != co["replay_sha256"]
    monkeypatch.setattr(simulation, "execute_inputs", real)
    assert author.get(f"{A}/coordinated-simulations/{co['id']}").json()["replay_sha256"] == co["replay_sha256"]

    # evidence, on request only: coordinated simulations of the scenarios above, as the server returned them
    if os.environ.get("ASG2B_EXAMPLES"):
        Path(os.environ["ASG2B_EXAMPLES"]).write_text(
            json.dumps(
                {
                    "two_surveys_completed": co,
                    "policy_unresolved": stopped,
                    "non_completed_ending": ended,
                    "refused_starts": {
                        "duplicate": dup["states"],
                        "no_order": no_order["states"],
                        "unsettled": unsettled["states"],
                        "plan_blocked": blocked["states"],
                    },
                },
                indent=1,
                default=str,
            )
        )

    # ---- 15. scope and permission
    plain = _client(survey_app, make_account(db, prefix="plain"))
    person = make_account(db, prefix="reader")
    reader = _client(survey_app, person)
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)
    create, inputs, read = (
        f"{A}/composite-plans/{comp['id']}/coordinated-simulations",
        f"{A}/coordinated-simulations/{e['id']}/inputs",
        f"{A}/coordinated-simulations/{co['id']}",
    )
    body = {"expected_inputs": 0, "key": "mi-call/n2", "answer": {"choice": "YES"}}
    for held, can_read in (
        (frozenset(), False),
        (ALL - {"survey.simulate"}, True),
        (ALL - {"survey.assignment.read"}, False),
        (frozenset({"survey.read", "survey.simulate"}), False),
    ):
        GRANTS[person.principal_id] = held
        assert post(reader, create, {}).status_code == 403 and post(reader, inputs, body).status_code == 403, held
        assert reader.get(read).status_code == (200 if can_read else 403), held
    assert plain.get(read).status_code == 403
    assert (
        post(outsider, create, {}).status_code == 404
        and post(outsider, inputs, body).status_code == 404
        and outsider.get(read).status_code == 404
    )
    for path, payload in ((create, {}), (inputs, body)):
        assert author.post(path, json=payload).status_code == 403  # no CSRF token
    assert start(author, str(uuid.uuid4()), expect=404)["code"] == "NOT_FOUND"
    for x in (plain, reader, outsider, maker, rule_checker):
        x.__exit__(None, None, None)
    for p_ in (person, elsewhere):
        GRANTS.pop(p_.principal_id, None)
    MARKETS.pop(elsewhere.principal_id)

    # ---- the records: SIMULATION only, insert-only, and tied to nothing operational
    for statement in (
        "UPDATE survey_coordinated_simulation SET record_class = 'OPERATIONAL' WHERE id = :i",
        "UPDATE survey_coordinated_simulation SET governed_order = jsonb_build_array('ADD-B') WHERE id = :i",
        "DELETE FROM survey_coordinated_simulation_step WHERE coordinated_id = :i",
        "UPDATE survey_coordinated_simulation_step SET started_because = 'FIRST_IN_ORDER' WHERE coordinated_id = :i AND position = 2",
        "INSERT INTO survey_coordinated_simulation_step (coordinated_id, position, group_id, group_code, survey_version_id, simulation_id, started_because, started_by) "
        "SELECT coordinated_id, 1, group_id, group_code, survey_version_id, gen_random_uuid(), 'PREVIOUS_COMPLETED', started_by FROM survey_coordinated_simulation_step WHERE coordinated_id = :i AND position = 1",
    ):
        with engine.connect() as conn, pytest.raises(DBAPIError):
            conn.execute(text(statement), {"i": co["id"]})
    refs = (
        db.execute(
            text(
                "SELECT DISTINCT f.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class f ON f.oid = k.confrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE k.contype = 'f' AND n.nspname = 'call360_test' AND c.relname LIKE 'survey_coordinated%'"
            )
        )
        .scalars()
        .all()
    )
    assert set(refs) == {
        "survey_composite_plan",
        "survey_coordinated_simulation",
        "survey_assignment_group",
        "survey_version",
        "survey_simulation",
    }
    inbound = set(
        db.execute(
            text(
                "SELECT c.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class f ON f.oid = k.confrelid WHERE k.contype = 'f' AND f.relname LIKE 'survey_coordinated%' AND c.relname NOT LIKE 'survey_coordinated%'"
            )
        ).scalars()
    )
    # nothing operational refers to a coordinated simulation; from EVAL-1 only the evaluation of that journey does
    assert inbound <= {
        "survey_journey_evaluation",
        "survey_execution_assurance",
    }  # EVAL-2B: the assurance of that journey

    # ---- 16. nothing of Script Studio and nothing operational was created or changed; everything is audited
    with engine.connect() as conn:
        assert business_fingerprint(conn) == scripts_before
    assert counts(db, OPERATIONAL) == operational_before
    audited = dict(
        db.execute(
            text("SELECT action, count(*) FROM audit_event WHERE action LIKE 'SURVEY.COORDINATED%' GROUP BY action")
        ).all()
    )
    assert (
        audited["SURVEY.COORDINATED_SIMULATION_CREATED"] == 4
        and audited["SURVEY.COORDINATED_SIMULATION_SURVEY_STARTED"] == 7
    )
    assert verify_chain(db).ok


def test_with_the_setting_off_there_is_no_coordinated_simulation(
    settings: Settings, engine: Engine, db: Session
) -> None:
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_library_enabled": True,
                "survey_simulation_enabled": True,
                "survey_assignment_enabled": True,
                "survey_assignment_groups_enabled": True,
                "transcription_worker": False,
            }
        )
    )
    with_grants(app)
    person = make_account(db, prefix="reader")
    GRANTS[person.principal_id] = ALL
    c = _client(app, person)
    assert post(c, f"{A}/composite-plans/{uuid.uuid4()}/coordinated-simulations", {}).status_code == 404
    assert c.get(f"{A}/coordinated-simulations/{uuid.uuid4()}").status_code == 404
    assert c.get(f"{A}/groups").status_code == 200  # requirement groups are where they were
    # … and a composite on this server says the coordinated simulation is not AVAILABLE here, whatever its own state
    from app.domain.survey import assignment_groups as ag_

    doc = {
        "selection_status": "RESOLVED",
        "selected": [],
        "ordering": {"status": "NOT_APPLICABLE"},
        "plan_status": "READY",
    }
    assert ag_.three_states(doc, True)["coordinated_simulation"]["status"] == "BLOCKED"  # nothing selected
    c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id)
    assert Settings.model_fields["survey_coordinated_simulation_enabled"].default is False
    paths = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_simulation_enabled": True,
                "survey_assignment_enabled": True,
                "survey_coordinated_simulation_enabled": True,
                "transcription_worker": False,
            }
        ),
        with_database=False,
    ).openapi()["paths"]
    assert not [p for p in paths if "coordinated" in p]  # coordinated simulation without requirement groups is not on


def test_zz_migration_0032_goes_down_and_up_and_changes_nothing_else(
    fresh_schema: None, engine: Engine, settings: Settings
) -> None:
    from tests.support import migrate

    mine = {
        "survey_coordinated_simulation", "survey_coordinated_simulation_step",
        # EVAL-1 (0033) sits above 0032 and goes down with it: evaluation records are simulation records
        "survey_control_mapping", "survey_control_mapping_event", "survey_journey_evaluation", "survey_control_result",
        "survey_evidence_observation", "survey_evaluation_finding", "survey_control_policy", "survey_control_policy_event", "survey_evaluation_policy", "survey_obligation_result", "survey_obligation_observation", "survey_obligation_finding", "survey_execution_assurance", "survey_execution_assurance_survey",
    }  # fmt: skip

    def state() -> tuple[set[str], str]:
        with engine.connect() as c:
            return set(
                c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars()
            ), c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one()

    full = state()
    assert mine <= full[0] and full[1] == "0037_shared_rule_services"
    migrate(settings, "0031_survey_assignment_groups", down=True)
    assert state() == (full[0] - mine, "0031_survey_assignment_groups")
    migrate(settings, "head")
    assert state() == full
