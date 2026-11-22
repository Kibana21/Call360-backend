# ruff: noqa: E501, F811
"""EVAL-2B — execution assurance of SYNTHETIC journeys: the pure verifier against every golden run and against
TAMPERED copies of real runs, and real HTTP with real PostgreSQL (``call360_test``).

A deviation cannot be produced by the authoritative executor. Every negative case here is therefore an INJECTED or
TAMPERED recording, made in the test from a real run and named as such. None is a defect of the executor."""

from __future__ import annotations

import copy
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.survey import execution_assurance as ea
from app.domain.survey import simulation as simulation_module
from app.domain.survey.execution import execute_inputs
from app.main import create_app
from tests.support import make_account
from tests.survey_fixtures import load_all, to_bundle
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import compose, group
from tests.test_survey_control_policy import ON as POLICY_ON
from tests.test_survey_control_policy import ev, instance, ob, pc, policy_body, published_policy, under
from tests.test_survey_evaluation import (
    ALL,
    K8_FACTS,
    RULES_V1,
    YES,
    entry,
    evaluate,
    items_of,
    mapped,
    publish_finding_rules,
    simulate,
)
from tests.test_survey_lib1 import build, draft, empty_survey, pin_module, publish
from tests.test_survey_simulation import give, start

E = "/api/v1/survey-evaluation"
A = "/api/v1/survey-assignment"
SG = {"field": "market", "values": ["SG"]}
ON = POLICY_ON | {"survey_execution_assurance_enabled": True}
TABLES = ("survey_execution_assurance", "survey_execution_assurance_survey")


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


# --------------------------------------------------------------------------------- pure: every golden run, as it is
def _play(fx: dict[str, Any], r: dict[str, Any]) -> tuple[Any, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Drive a golden run the way the simulation API is driven: refused answers first, then its own. Returns the
    bundle, the facts, the run and the recorded inputs."""
    bundle, facts = to_bundle(fx), r.get("facts") or r.get("profile") or {}
    bad: dict[str, list[Any]] = {}
    for x in r.get("rejected") or []:
        bad.setdefault(x["at"], []).append(x["answer"])
    inputs: list[dict[str, Any]] = []
    recorded: list[dict[str, Any]] = []
    run = execute_inputs(bundle, facts, inputs)
    while run["status"] == "PENDING":
        key = run["pending"]["key"]
        if bad.get(key):
            answer = bad[key].pop(0)
        elif key in (r.get("answers") or {}):
            answer = r["answers"][key]
        else:
            break
        before = len(run["rejections"])
        inputs.append({"key": key, "answer": answer})
        run = execute_inputs(bundle, facts, inputs)
        refused = len(run["rejections"]) > before
        recorded.append(
            {
                "key": key,
                "answer": answer,
                "accepted": not refused,
                "rejection_code": run["rejections"][-1]["error"] if refused else None,
            }
        )
    return bundle, facts, run, recorded


GOLDEN = [(fx, r) for fx in load_all() for r in fx["expected_runs"]]
OK = {"replay_consistent": True, "steps_consistent": True}


@pytest.mark.parametrize(("fx", "r"), GOLDEN, ids=[f"{fx['fixture'][:2]}-{n}" for n, (fx, _) in enumerate(GOLDEN)])
def test_every_golden_run_is_verified_with_no_finding(fx: dict[str, Any], r: dict[str, Any]) -> None:
    """1, 3. The authoritative executor's own runs — all 82, with their refused answers — raise nothing. Correct
    conditional branching, skipped modules and early endings are exclusions with a stated reason, never violations."""
    bundle, facts, run, recorded = _play(fx, r)
    got = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    assert [(c["check"], f["code"]) for c in got["checks"] for f in c["findings"]] == []
    assert [c["check"] for c in got["checks"]] == list(ea.SURVEY_CHECKS)
    assert got["status"] == ("VERIFIED" if run["status"] == "TERMINAL" else "INCOMPLETE")
    # every placement is either delivered in its exact pinned wording, or has a stated reason for not being delivered
    assert all(d["wording"] == "EXACT" and len(d["wording_sha256"]) == 64 for d in got["deliveries"])
    assert {x["class"] for x in got["exclusions"]} <= {
        "VALID_CONDITIONAL_EXCLUSION",
        "EXCLUDED_INFORMATION_MISSING",
        "VALID_ROUTING_EXCLUSION",
        "NOT_ON_PATH_TAKEN",
        "SURVEY_ENDED_BEFORE",
        "AWAITING_ANSWER",
        "NOT_YET_REACHED",
    }
    assert got["counts"]["delivered"] + len(got["exclusions"]) == got["counts"]["placements"]
    assert got["counts"]["refused_inputs"] == sum(not i["accepted"] for i in recorded)  # 11. refusals stay refusals
    if run["terminal"]:
        assert got["ending"]["state"] == run["terminal"]["state"]  # 12. the ending is preserved, whatever it is
    # the golden runs themselves are unchanged: what the verifier reads is exactly what the fixture expects
    assert run["asked"] == r.get("asked", run["asked"])


def test_golden_totals_are_what_they_were() -> None:
    assert len(GOLDEN) == 82 and len(load_all()) == 27  # 20. the same 82 runs of the same 27 fixtures
    statuses = [ea.verify_survey(*(_play(fx, r)[:3]), OK | {"inputs": _play(fx, r)[3]})["status"] for fx, r in GOLDEN]
    assert set(statuses) <= {"VERIFIED", "INCOMPLETE"} and statuses.count("VERIFIED") >= 70


# ------------------------------------------------------------- pure: TAMPERED copies of a real run (injected faults)
def _real(prefix: str, n: int = 0) -> tuple[Any, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    fx = next(f for f in load_all() if f["fixture"].startswith(prefix))
    return _play(fx, fx["expected_runs"][n])


def _codes(result: dict[str, Any]) -> dict[str, list[str]]:
    return {c["check"]: [f["code"] for f in c["findings"]] for c in result["checks"] if c["findings"]}


def _renumber(run: dict[str, Any]) -> dict[str, Any]:
    for n, e in enumerate(run["events"]):
        e["at"] = n
    return run


def test_tampered_recordings_are_detected_each_by_the_check_that_asks_about_it() -> None:
    """5–8, 11–13. Each case is a real K8 run, copied and TAMPERED with in one way. The verifier is not told which."""
    bundle, facts, real, recorded = _real("K8", 2)  # the high-premium application: every module runs
    rec = OK | {"inputs": recorded}
    clean = ea.verify_survey(bundle, facts, real, rec)
    assert (
        clean["status"] == "VERIFIED"
        and clean["counts"]["findings"] == 0
        and clean["counts"]["delivered"] == clean["counts"]["placements"]
    )

    def tampered(change: Any, recorded_: dict[str, Any] | None = None) -> dict[str, Any]:
        run = copy.deepcopy(real)
        change(run)
        return ea.verify_survey(bundle, facts, run, recorded_ or rec)

    ask = next(e for e in real["events"] if e["kind"] == "ASK")
    say = next(e for e in real["events"] if e["kind"] == "SAY")

    # ---- 5. INJECTED: a delivery of something the pinned version does not place anywhere
    def unexpected(run: dict[str, Any]) -> None:
        run["events"].insert(
            2,
            {
                "at": 0,
                "kind": "SAY",
                "key": "mi-opening/n99",
                "instance": "mi-opening",
                "node": "n99",
                "item": {"code": "S-INVENTED", "version": 1, "wording_version": 1},
                "text": "An extra sentence.",
            },
        )
        _renumber(run)

    r = tampered(unexpected)
    assert r["status"] == "DEVIATION_DETECTED" and "UNEXPECTED_DELIVERY" in _codes(r)["DELIVERIES_EXPECTED"]
    assert next(f for c in r["checks"] for f in c["findings"] if f["code"] == "UNEXPECTED_DELIVERY")["evidence"] == {
        "placement": "mi-opening/n99",
        "event": 2,
    }

    # ---- 6. TAMPERED: the recorded wording of a question differs from its pinned wording
    def reworded(run: dict[str, Any]) -> None:
        for e in run["events"]:
            if e.get("key") == ask["key"] and "text" in e:
                e["text"] = e["text"] + " Just say yes."
        for d in run["delivered"]:
            if d["key"] == ask["key"]:
                d["text"] = d["text"] + " Just say yes."

    r = tampered(reworded)
    f = next(f for c in r["checks"] for f in c["findings"] if f["code"] == "WORDING_ALTERED")
    assert r["status"] == "DEVIATION_DETECTED" and list(_codes(r)) == ["WORDING_EXACT"]
    assert (
        f["evidence"]["placement"] == ask["key"]
        and f["evidence"]["expected"] == ask["text"]
        and f["evidence"]["recorded"].endswith("Just say yes.")
    )
    line = next(d for d in r["deliveries"] if d["placement"] == ask["key"])
    assert (line["wording"], line["expected_text"], line["wording_version"]) == ("ALTERED", ask["text"], 1) and len(
        line["wording_sha256"]
    ) == 64
    # … and a statement, in the record of deliveries only
    r = tampered(lambda run: next(d for d in run["delivered"] if d["key"] == say["key"]).update(text="Hello."))
    assert _codes(r) == {"WORDING_EXACT": ["WORDING_ALTERED"]}

    # ---- 7. TAMPERED: a delivery is missing from the record of deliveries; and an event is missing from the trace
    r = tampered(lambda run: run["delivered"].remove(next(d for d in run["delivered"] if d["key"] == say["key"])))
    assert _codes(r) == {"DELIVERIES_EXPECTED": ["MISSING_RECORDED_DELIVERY"]} and r["status"] == "DEVIATION_DETECTED"
    r = tampered(lambda run: run["events"].remove(next(e for e in run["events"] if e["kind"] == "SAY")))
    assert (
        "MISSING_EVENT" in _codes(r)["TRACE_WELL_FORMED"]
        and "DELIVERY_WITHOUT_EVENT" in _codes(r)["DELIVERIES_EXPECTED"]
    )

    # ---- 8. TAMPERED: an execution event is recorded twice
    def twice(run: dict[str, Any]) -> None:
        i = run["events"].index(next(e for e in run["events"] if e["kind"] == "ASK"))
        run["events"].insert(i + 1, copy.deepcopy(run["events"][i]))

    r = tampered(twice)
    assert (
        "DUPLICATE_EVENT" in _codes(r)["TRACE_WELL_FORMED"] and "DUPLICATE_DELIVERY" in _codes(r)["DELIVERIES_EXPECTED"]
    )
    r = tampered(
        lambda run: (twice(run), _renumber(run))
    )  # renumbered, so the trace looks whole: the delivery is still twice
    assert _codes(r)["DELIVERIES_EXPECTED"] == ["DUPLICATE_DELIVERY"]

    # ---- 11. TAMPERED: an answer the survey's own validation refuses is recorded as accepted
    def invalid(run: dict[str, Any]) -> None:
        next(e for e in run["events"] if e["kind"] == "ANSWER")["answer"] = {"choice": "MAYBE"}

    r = tampered(invalid)
    assert (
        "INVALID_ANSWER_ACCEPTED" in _codes(r)["ANSWERS_AND_REJECTIONS"]
        and "ANSWER_NOT_AS_RECORDED" in _codes(r)["ANSWERS_AND_REJECTIONS"]
    )
    # … and a refusal that the recorded inputs have, and the trace does not
    refused_bundle, refused_facts, refused_run, refused_rec = _real("K3", 2)
    honest = ea.verify_survey(refused_bundle, refused_facts, refused_run, OK | {"inputs": refused_rec})
    assert (
        honest["status"] == "VERIFIED"
        and honest["counts"]["refused_inputs"] == 7
        and [x["code"] for x in honest["rejections"]][:2] == ["NUMBER_REQUIRED", "NUMBER_REQUIRED"]
    )
    hidden = copy.deepcopy(refused_run)
    hidden["events"] = [e for e in hidden["events"] if e["kind"] != "REJECT"]
    assert (
        "REJECTION_NOT_RECORDED"
        in _codes(ea.verify_survey(refused_bundle, refused_facts, _renumber(hidden), OK | {"inputs": refused_rec}))[
            "ANSWERS_AND_REJECTIONS"
        ]
    )

    # ---- branching: TAMPERED routes
    route = next(e for e in real["events"] if e["kind"] == "ROUTE" and e.get("edge"))
    r = tampered(lambda run: next(e for e in run["events"] if e["at"] == route["at"]).update(edge="e-invented"))
    assert _codes(r)["BRANCHING"] == ["ROUTE_NOT_IN_VERSION"]
    r = tampered(
        lambda run: next(e for e in run["events"] if e["at"] == route["at"]).update(to={"outcome": "COMPLETED"})
    )
    assert "ROUTE_DIFFERS_FROM_VERSION" in _codes(r)["BRANCHING"]

    def omitted(run: dict[str, Any]) -> None:  # the route led to the question; the question was never asked
        run["events"] = [
            e
            for e in run["events"]
            if not (e.get("key") == "mi-opening/n2" and e["kind"] in ("ASK", "ANSWER", "ROUTE"))
        ]
        run["delivered"] = [d for d in run["delivered"] if d["key"] != "mi-opening/n2"]
        _renumber(run)

    r = tampered(omitted, OK | {"inputs": [i for i in recorded if i["key"] != "mi-opening/n2"]})
    assert "EXECUTION_OMISSION" in _codes(r)["BRANCHING"]
    assert (
        next(x for x in r["exclusions"] if x["placement"] == "mi-opening/n2")["class"] == "OMISSION"
    )  # 4. not a valid exclusion

    # ---- module order and ending: TAMPERED
    def swapped(run: dict[str, Any]) -> None:
        entries = [e for e in run["events"] if e["kind"] == "ENTRY"]
        entries[0]["instance"], entries[1]["instance"] = entries[1]["instance"], entries[0]["instance"]

    assert "MODULE_ORDER_DIFFERS" in _codes(tampered(swapped))["MODULE_SEQUENCE"]
    r = tampered(lambda run: run["events"].pop())
    assert _codes(r)["TERMINATION"] == ["MISSING_EVENT"]
    r = tampered(lambda run: next(e for e in run["events"] if e["kind"] == "END").update(status="ENDED_WITH_OUTCOME"))
    assert _codes(r)["TERMINATION"] == ["UNEXPECTED_TERMINATION"]
    r = tampered(
        lambda run: next(m for m in run["modules"] if m["instance"] == "mi-closing").update(status="NOT_REACHED")
    )
    assert "UNEXPECTED_TERMINATION" in _codes(r)["TERMINATION"]  # recorded as completed with a module never reached

    # ---- 13. integrity: a recording that no longer recomputes gives NO trustworthy result, whatever else is true
    r = ea.verify_survey(
        bundle,
        facts,
        real,
        {"inputs": recorded, "replay_consistent": False, "steps_consistent": True, "drift": {"code": "REPLAY_DRIFT"}},
    )
    assert (r["status"], _codes(r)) == ("INTEGRITY_FAILED", {"INTEGRITY": ["REPLAY_DRIFT"]})
    r = ea.verify_survey(
        bundle,
        facts,
        real,
        {
            "inputs": recorded,
            "replay_consistent": True,
            "steps_consistent": False,
            "step_mismatches": [{"after_inputs": 1}],
        },
    )
    assert (r["status"], _codes(r)) == ("INTEGRITY_FAILED", {"INTEGRITY": ["STEP_FINGERPRINT_DIFFERS"]})
    both = copy.deepcopy(real)
    reworded(both)
    assert (
        ea.verify_survey(
            bundle, facts, both, {"inputs": recorded, "replay_consistent": False, "steps_consistent": True}
        )["status"]
        == "INTEGRITY_FAILED"
    )  # integrity first


def test_valid_exclusions_are_told_apart_from_omissions_and_from_missing_evidence() -> None:
    """3, 4. The published survey logic leaving something out is not a violation; neither is a survey that ended."""
    bundle, facts, run, recorded = _real("K8", 0)  # ordinary application: three modules are not eligible
    r = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    by = {x["placement"]: (x["class"], x["module_status"]) for x in r["exclusions"]}
    assert (
        r["status"] == "VERIFIED"
        and by["mi-high-value/n2"] == ("VALID_CONDITIONAL_EXCLUSION", "SKIPPED_FALSE")
        and by["mi-senior/n1"] == ("VALID_CONDITIONAL_EXCLUSION", "SKIPPED_FALSE")
    )
    assert all(x["event"] is not None for x in r["exclusions"])  # each exclusion points at the event that explains it
    bundle, facts, run, recorded = _real("K8", 1)  # identity not confirmed: the survey ends there
    r = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    assert r["status"] == "VERIFIED" and r["ending"] == {
        "state": "ENDED_WITH_OUTCOME",
        "survey_outcome": "UNABLE_TO_VERIFY",
        "reason": None,
        "completed": False,
        "routed_by_event": r["ending"]["routed_by_event"],
    }
    assert {x["class"] for x in r["exclusions"]} == {
        "SURVEY_ENDED_BEFORE"
    }  # 12. a non-completed outcome is preserved, and it is not a deviation
    bundle, facts, run, recorded = _real("K8", 3)  # information missing
    r = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    assert (
        r["status"] == "VERIFIED"
        and "EXCLUDED_INFORMATION_MISSING" in {x["class"] for x in r["exclusions"]}
        and r["ending"]["state"] == "MISSING_INFORMATION_HALT"
    )
    bundle, facts, run, recorded = _real(
        "F3", 0
    )  # a single-choice branch: the other branches are not on the path taken
    r = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    assert r["status"] == "VERIFIED" and "NOT_ON_PATH_TAKEN" in {x["class"] for x in r["exclusions"]}
    assert all(b["edge"] and b["via"] for b in r["branches"] if b["kind"] == "ROUTE" and b["edge"])
    bundle, facts, run, recorded = _real(
        "K4", 1
    )  # a non-answer whose policy is unresolved: nothing ended, nothing is assumed
    r = ea.verify_survey(bundle, facts, run, OK | {"inputs": recorded})
    assert (r["status"], r["ending"], r["pending"]) == ("INCOMPLETE", None, "mi-ack/n2") and [
        x["code"] for x in r["rejections"]
    ] == ["NON_ANSWER_POLICY_UNRESOLVED"]
    assert next(c for c in r["checks"] if c["check"] == "TERMINATION")["status"] == "INCOMPLETE"


def _coordinated(**over: Any) -> dict[str, Any]:
    v = [str(uuid.uuid5(uuid.NAMESPACE_URL, x)) for x in ("va", "vb", "vc")]
    s = [str(uuid.uuid5(uuid.NAMESPACE_URL, x)) for x in ("sa", "sb", "sc")]
    base = {
        "kind": "COORDINATED", "id": uuid.uuid5(uuid.NAMESPACE_URL, "co"), "status": "ALL_SURVEYS_COMPLETED", "complete": True, "composite_intact": True,
        "selected": [{"group": g, "survey_version_id": x} for g, x in zip(("G1", "G2", "G3"), v, strict=True)],
        "surveys": [{"position": n + 1, "group": g, "survey_version_id": v[n], "state": "COMPLETED", "simulation_id": s[n]} for n, g in enumerate(("G1", "G2", "G3"))],
        "steps": [{"position": n + 1, "group_code": g, "survey_version_id": v[n], "simulation_id": s[n], "started_because": "FIRST_IN_ORDER" if n == 0 else "PREVIOUS_COMPLETED"} for n, g in enumerate(("G1", "G2", "G3"))],
    }  # fmt: skip
    return base | over


def test_coordination_records_are_verified_and_tampered_ones_are_detected() -> None:
    """2, 9, 10. ASG-2B's own records, as they are; and TAMPERED copies of them (the coordinator cannot produce these)."""
    good = _coordinated()
    assert [(c["check"], c["status"]) for c in ea.verify_coordination(good)] == [
        (n, "PASSED") for n in ea.JOURNEY_CHECKS
    ]

    def codes(j: dict[str, Any]) -> dict[str, list[str]]:
        return {c["check"]: [f["code"] for f in c["findings"]] for c in ea.verify_coordination(j) if c["findings"]}

    # ---- 9. TAMPERED: the surveys were started in another order than the governed one
    wrong = copy.deepcopy(good)
    wrong["steps"][1], wrong["steps"][2] = wrong["steps"][2] | {"position": 2}, wrong["steps"][1] | {"position": 3}
    assert (
        codes(wrong)["GOVERNED_ORDER"] == ["ORDER_DIFFERS", "ORDER_DIFFERS"]
        and "EVIDENCE_REFERENCE_DIFFERS" in codes(wrong)["OWN_EVIDENCE"]
    )
    # ---- 10. TAMPERED: survey 3 was started although survey 2 never reached COMPLETED
    bypass = copy.deepcopy(good)
    bypass["surveys"][1]["state"] = "STOPPED"
    assert codes(bypass) == {"NO_BYPASS": ["SURVEY_BYPASSED"]}
    unresolved = copy.deepcopy(good)
    unresolved["surveys"][1]["state"] = (
        "CURRENT"  # a non-answer is unresolved in survey 2 — and survey 3 was started anyway
    )
    assert codes(unresolved) == {"NO_BYPASS": ["SURVEY_BYPASSED"]}
    # the real thing: survey 2 stopped, survey 3 NOT started — nothing was bypassed
    stopped = _coordinated(status="CROSS_SURVEY_POLICY_UNRESOLVED", complete=False)
    stopped["surveys"][1]["state"], stopped["surveys"][2] = (
        "STOPPED",
        stopped["surveys"][2] | {"state": "NOT_STARTED", "simulation_id": None},
    )
    stopped["steps"] = stopped["steps"][:2]
    assert codes(stopped) == {}
    # ---- the selection: a requirement disappeared; a survey replaced; the composite changed; evidence shared; a duplicate
    gone = copy.deepcopy(good)
    gone["surveys"], gone["steps"] = gone["surveys"][:2], gone["steps"][:2]
    assert codes(gone) == {"SELECTION_RECORDED": ["SELECTION_DIFFERS"], "NO_DEDUPLICATION": ["REQUIREMENT_MISSING"]}
    replaced = copy.deepcopy(good)
    replaced["surveys"][2]["survey_version_id"] = str(uuid.uuid4())
    assert "SELECTION_DIFFERS" in codes(replaced)["SELECTION_RECORDED"]
    assert codes(_coordinated(composite_intact=False)) == {"SELECTION_RECORDED": ["COMPOSITE_NOT_INTACT"]}
    shared = copy.deepcopy(good)
    shared["steps"][2]["simulation_id"] = shared["steps"][1]["simulation_id"]
    assert "EVIDENCE_SHARED" in codes(shared)["OWN_EVIDENCE"]
    duplicate = copy.deepcopy(good)
    duplicate["selected"][2]["survey_version_id"] = duplicate["selected"][1]["survey_version_id"]
    assert (
        "DUPLICATE_REQUIREMENT_UNRESOLVED" in codes(duplicate)["NO_DEDUPLICATION"]
    )  # explicitly unresolved, never merged

    # ---- the journey status, its precedence, and what VERIFIED never means (16)
    def survey(status: str, position: int = 1) -> dict[str, Any]:
        base = ea.not_assessable("X", "x") | {"status": status}
        return {"position": position, "survey_code": f"S{position}", "simulation_id": "s", "result": base}

    def status(*statuses: str, journey: dict[str, Any] | None = None) -> str:
        return str(
            ea.assure_journey(
                journey or {"kind": "SINGLE_SURVEY", "id": "j", "status": "X", "complete": True},
                [survey(s, n + 1) for n, s in enumerate(statuses)],
            )["status"]
        )

    assert status("VERIFIED", "VERIFIED") == "VERIFIED" and status("VERIFIED", "INCOMPLETE") == "INCOMPLETE"
    assert (
        status("INCOMPLETE", "NOT_ASSESSABLE") == "NOT_ASSESSABLE"
        and status("NOT_ASSESSABLE", "DEVIATION_DETECTED") == "DEVIATION_DETECTED"
    )
    assert status("DEVIATION_DETECTED", "INTEGRITY_FAILED") == "INTEGRITY_FAILED"
    assert (
        status("VERIFIED", "VERIFIED", "VERIFIED", journey=bypass) == "DEVIATION_DETECTED"
    )  # the surveys are fine; the journey is not
    assert (
        status("VERIFIED", "VERIFIED", "VERIFIED", journey=_coordinated(composite_intact=False)) == "INTEGRITY_FAILED"
    )
    verified = ea.assure_journey(
        {"kind": "SINGLE_SURVEY", "id": "j", "status": "X", "complete": True}, [survey("VERIFIED")]
    )
    assert (
        verified["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"
        and "including VERIFIED" in verified["operational_call_eligibility"]["note"]
    )
    assert "does not show that a person" in verified["note"] and "not a compliance outcome" in verified["note"].lower()
    assert not [
        k
        for k in verified
        if "complian" in k.lower() or ("eligib" in k.lower() and k != "operational_call_eligibility")
    ]
    assert (
        ea.assure_journey({"kind": "SINGLE_SURVEY", "id": "j", "status": "X", "complete": True}, [survey("VERIFIED")])
        == verified
    )  # deterministic


# --------------------------------------------------------------------------------------- real HTTP, real PostgreSQL
def assure(
    c: TestClient,
    *,
    simulation_id: str | None = None,
    coordinated: str | None = None,
    evaluation: str | None = None,
    expect: int = 201,
) -> dict[str, Any]:
    r = post(
        c,
        f"{E}/assurance",
        {"simulation_id": simulation_id, "coordinated_simulation_id": coordinated, "evaluation_id": evaluation},
    )
    assert r.status_code == expect, r.text
    return r.json()


def checks(survey: dict[str, Any]) -> dict[str, str]:
    return {c["check"]: c["status"] for c in survey["checks"]}


def test_a_single_survey_journey_is_verified_and_shown_beside_its_control_evaluation(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    author, checker, publisher, people = trio
    operational_before = counts(db, OPERATIONAL)
    publish_finding_rules(db, RULES_V1)
    sid, _, _ = build(author, "K8", "Application survey")
    vid = publish(trio, sid)[1]
    it = items_of(db, vid)
    mapped(trio, "SYN-CTRL-01", [entry(it["mi-opening/n2"], YES), entry(it["mi-opening/n1"])])
    mapped(
        trio, "SYN-CTRL-04", [entry(it["mi-replacement/n1"], YES)]
    )  # its module is not eligible for an ordinary application

    # ---- 1. a complete single-survey execution passes every applicable check
    sim = simulate(author, vid, K8_FACTS, {"mi-opening/n2": {"choice": "YES"}})
    evaluation = evaluate(author, simulation_id=sim["id"])
    a = assure(author, simulation_id=sim["id"], evaluation=evaluation["id"])
    assert (a["record_class"], a["journey_kind"], a["status"], a["current_status"], a["evaluation_id"]) == (
        "SIMULATION",
        "SINGLE_SURVEY",
        "VERIFIED",
        "VERIFIED",
        evaluation["id"],
    )
    (s,) = a["surveys"]
    assert (
        set(checks(s).values()) == {"PASSED"}
        and list(checks(s)) == list(ea.SURVEY_CHECKS)
        and a["findings"] == []
        and a["journey_checks"] == []
    )
    assert (s["simulation_id"], s["survey_version_id"], s["run_sha256"], s["manifest_sha256"]) == (
        sim["id"],
        vid,
        sim["run_sha256"],
        sim["manifest_sha256"],
    )
    # every delivery: the exact pinned wording, its version and fingerprint, the event that delivered it
    assert [(d["placement"], d["wording"], d["wording_version"]) for d in s["deliveries"]] == [
        (d["key"], "EXACT", d["wording_version"]) for d in sim["run"]["delivered"]
    ]
    assert all(
        d["recorded_text"] == d["expected_text"] and len(d["wording_sha256"]) == 64 and isinstance(d["event"], int)
        for d in s["deliveries"]
    )
    # ---- 3. modules the published logic left out are valid exclusions, each with the event that explains it
    left_out = {x["placement"]: x for x in s["exclusions"]}
    assert left_out["mi-replacement/n1"]["class"] == "VALID_CONDITIONAL_EXCLUSION" and isinstance(
        left_out["mi-replacement/n1"]["event"], int
    )
    assert s["counts"]["not_delivered"] == {"VALID_CONDITIONAL_EXCLUSION": 4} and s["ending"]["completed"] is True
    assert a["pins"]["executions"][0] | {"inputs": 0} == {
        "position": 1,
        "survey_version_id": vid,
        "content_sha256": sim["content_sha256"],
        "manifest_sha256": sim["manifest_sha256"],
        "simulation_id": sim["id"],
        "run_sha256": sim["run_sha256"],
        "engine_contract": sim["engine_contract"],
        "inputs": 0,
    }
    assert (a["pins"]["contract"], a["pins"]["control_evaluation"]) == (
        ea.CONTRACT,
        {"id": evaluation["id"], "result_sha256": evaluation["result_sha256"]},
    )

    # ---- 14. control results are COPIED from the control evaluation, never computed again
    assert (
        a["control_evaluation"]["of_this_evidence"] is True
        and a["control_evaluation"]["result_sha256"] == evaluation["result_sha256"]
    )
    assert [(c["control_code"], c["outcome"]) for c in a["control_evidence"]] == [
        (c["control_code"], c["outcome"]) for c in evaluation["controls"]
    ]
    by = {c["control_code"]: c for c in a["control_evidence"]}
    assert (
        by["SYN-CTRL-01"]["outcome"],
        by["SYN-CTRL-01"]["execution_evidence"],
        by["SYN-CTRL-01"]["result_is_trustworthy"],
    ) == ("SATISFIED", "EXECUTION_VERIFIED", True)
    assert [(x["placement"], x["delivery"], x["execution"]) for x in by["SYN-CTRL-01"]["evidence"]] == [
        ("mi-opening/n2", "EXACT", "EXECUTION_VERIFIED"),
        ("mi-opening/n1", "EXACT", "EXECUTION_VERIFIED"),
    ]
    # ---- 4. missing required evidence is a COVERAGE matter, and the execution was correct: two different statements
    four = by["SYN-CTRL-04"]
    assert (
        four["outcome"],
        four["execution_evidence"],
        four["evidence"][0]["delivery"],
        four["evidence"][0]["not_delivered_class"],
    ) == ("INSUFFICIENT_EVIDENCE", "EXECUTION_VERIFIED", "NOT_DELIVERED", "VALID_CONDITIONAL_EXCLUSION")
    assert (
        by["SYN-CTRL-05"]["execution_evidence"] == "NO_EXECUTION_EVIDENCE"
        and by["SYN-CTRL-05"]["outcome"] == "UNRESOLVED"
    )
    # 16. five statements, kept apart; VERIFIED establishes no eligibility and is not a control result
    assert (
        a["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"
        and evaluation["processing_status"] == "INCOMPLETE"
        and a["status"] == "VERIFIED"
    )
    # D-291 (d), (e) are untouched: the evaluation's own reading of an excluded module is unchanged, and assurance adds no finding
    assert evaluation["controls"][3]["observations"][0]["result"] == "NOT_APPLICABLE" and "findings" not in four
    assert author.get(f"{E}/evaluations/{evaluation['id']}").json()["result_sha256"] == evaluation["result_sha256"]

    # ---- 18. identical inputs: the same assurance run; it recomputes; without the evaluation it is another run
    assert assure(author, simulation_id=sim["id"], evaluation=evaluation["id"], expect=200)["id"] == a["id"]
    assert a["replay"] == {
        "consistent": True,
        "code": None,
        "reasons": [],
        "recorded_result_sha256": a["result_sha256"],
        "recomputed_result_sha256": a["result_sha256"],
    }
    plain = assure(author, simulation_id=sim["id"])
    assert (
        plain["id"] != a["id"]
        and plain["control_evidence"] == []
        and plain["control_evaluation"] is None
        and plain["status"] == "VERIFIED"
    )
    assert [x["id"] for x in author.get(f"{E}/assurance", params={"simulation_id": sim["id"]}).json()["items"]] == [
        a["id"],
        plain["id"],
    ]

    # ---- 11. an invalid answer stays refused, with its refusal on record; 12. a non-completed ending is preserved
    waiting = start(author, vid, K8_FACTS)
    early = assure(author, simulation_id=waiting["id"])
    assert (early["status"], early["surveys"][0]["pending"], checks(early["surveys"][0])["TERMINATION"]) == (
        "INCOMPLETE",
        "mi-opening/n2",
        "INCOMPLETE",
    )
    asked = next(d for d in early["surveys"][0]["deliveries"] if d["placement"] == "mi-opening/n2")
    assert (asked["wording"], asked["awaiting_answer"]) == (
        "EXACT",
        True,
    )  # asked in its exact wording, and waiting: not an omission
    assert set(early["surveys"][0]["counts"]["not_delivered"]) == {"NOT_YET_REACHED"}
    refused = give(author, waiting, "mi-opening/n2", {}).json()
    no = give(author, refused, "mi-opening/n2", {"choice": "NO"}).json()
    ended = assure(author, simulation_id=no["id"])
    es = ended["surveys"][0]
    assert (ended["status"], es["rejections"], es["counts"]["refused_inputs"]) == (
        "VERIFIED",
        [
            {
                "placement": "mi-opening/n2",
                "event": es["rejections"][0]["event"],
                "code": "CHOICE_REQUIRED",
                "answer": {},
            }
        ],
        1,
    )
    assert (es["ending"]["state"], es["ending"]["survey_outcome"], es["ending"]["completed"]) == (
        "ENDED_WITH_OUTCOME",
        "UNABLE_TO_VERIFY",
        False,
    )
    assert ended["summary"]["surveys_ended_without_completed"] == 1 and set(checks(es).values()) == {
        "PASSED"
    }  # faithful execution of a survey that did not complete
    assert es["counts"]["not_delivered"] == {"SURVEY_ENDED_BEFORE": 5}
    # new evidence after an assurance run: the earlier run says it no longer describes the journey; it is not rewritten
    stale = author.get(f"{E}/assurance/{early['id']}").json()
    assert (stale["current_status"], stale["status"], stale["result_sha256"]) == (
        "ASSURANCE_DRIFT",
        "INCOMPLETE",
        early["result_sha256"],
    )
    assert "EVIDENCE_CHANGED" in [r["code"] for r in stale["replay"]["reasons"]]

    # ---- 17. security
    reader = make_account(db, prefix="assread")
    GRANTS[reader.principal_id] = ALL - {"survey.evaluate"}
    c = _client(survey_app, reader)
    assert (
        c.get(f"{E}/assurance/{a['id']}").status_code == 200
        and post(c, f"{E}/assurance", {"simulation_id": sim["id"]}).status_code == 403
    )
    GRANTS[reader.principal_id] = ALL - {"survey.evaluation.read"}
    assert (
        c.get(f"{E}/assurance/{a['id']}").status_code == 403
        and c.get(f"{E}/assurance", params={"simulation_id": sim["id"]}).status_code == 403
    )
    assert post(c, f"{E}/assurance", {"simulation_id": sim["id"]}).status_code == 403
    c.__exit__(None, None, None)
    GRANTS.pop(reader.principal_id)
    outsider = make_account(db, prefix="assmy")
    GRANTS[outsider.principal_id] = ALL
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    c = _client(survey_app, outsider)
    assert (
        c.get(f"{E}/assurance/{a['id']}").status_code == 404
        and c.get(f"{E}/assurance", params={"simulation_id": sim["id"]}).json()["items"] == []
    )
    assert post(c, f"{E}/assurance", {"simulation_id": sim["id"]}).status_code == 404
    c.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)
    assert author.post(f"{E}/assurance", json={"simulation_id": sim["id"]}).status_code == 403  # no CSRF token
    r = post(author, f"{E}/assurance", {"simulation_id": sim["id"], "coordinated_simulation_id": str(uuid.uuid4())})
    assert (r.status_code, r.json()["code"]) == (422, "JOURNEY_REQUIRED")
    r = post(author, f"{E}/assurance", {"simulation_id": no["id"], "evaluation_id": evaluation["id"]})
    assert (r.status_code, r.json()["code"]) == (409, "EVALUATION_OF_ANOTHER_JOURNEY")
    assert (
        db.execute(text("SELECT count(*) FROM audit_event WHERE action = 'SURVEY.EXECUTION_ASSURED'")).scalar_one() == 4
    )
    assert verify_chain(db).ok

    # ---- 19. simulation records only, insert-only; nothing operational
    assert counts(db, OPERATIONAL) == operational_before
    assert set(db.execute(text("SELECT DISTINCT record_class FROM survey_execution_assurance")).scalars()) == {
        "SIMULATION"
    }
    for sql in (
        "UPDATE survey_execution_assurance SET status = 'VERIFIED'",
        "DELETE FROM survey_execution_assurance_survey",
        "UPDATE survey_execution_assurance_survey SET status = 'VERIFIED'",
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as cx:
                cx.execute(text(sql))

    # ---- 13. replay drift (INJECTED: the engine's output is altered inside this test): no trustworthy result
    real = simulation_module.execute_inputs

    def changed(bundle: Any, facts: Any, inputs: Any) -> Any:
        out = real(bundle, facts, inputs)
        out["trace"] = [*out["trace"], "changed engine"]
        return out

    monkeypatch.setattr(simulation_module, "execute_inputs", changed)
    recorded_before = author.get(f"{E}/assurance/{a['id']}").json()
    assert (recorded_before["current_status"], recorded_before["status"], recorded_before["result_sha256"]) == (
        "ASSURANCE_DRIFT",
        "VERIFIED",
        a["result_sha256"],
    )
    drifted = assure(author, simulation_id=sim["id"], evaluation=evaluation["id"])
    assert drifted["id"] != a["id"] and (drifted["status"], drifted["surveys"][0]["status"]) == (
        "INTEGRITY_FAILED",
        "INTEGRITY_FAILED",
    )
    integrity = next(c for c in drifted["surveys"][0]["checks"] if c["check"] == "INTEGRITY")
    assert sorted(f["code"] for f in integrity["findings"]) == ["REPLAY_DRIFT", "STEP_FINGERPRINT_DIFFERS"]
    # the control results that rest on that evidence are NOT presented as trustworthy — and they are not recalculated
    # the evidence is no longer what the control evaluation was made from; its results are shown as it recorded them,
    # and NONE of them is presented as trustworthy
    assert drifted["control_evaluation"]["of_this_evidence"] is False
    assert {c["result_is_trustworthy"] for c in drifted["control_evidence"]} == {False} and all(
        c["evidence_changed_since_evaluation"] for c in drifted["control_evidence"]
    )
    assert {c["control_code"]: c["execution_evidence"] for c in drifted["control_evidence"]} == {
        "SYN-CTRL-01": "INTEGRITY_FAILED", "SYN-CTRL-02": "NO_EXECUTION_EVIDENCE", "SYN-CTRL-03": "NO_EXECUTION_EVIDENCE",
        "SYN-CTRL-04": "INTEGRITY_FAILED", "SYN-CTRL-05": "NO_EXECUTION_EVIDENCE",
    }  # fmt: skip
    assert [c["outcome"] for c in drifted["control_evidence"]] == [c["outcome"] for c in evaluation["controls"]]
    assert drifted["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"


def test_a_coordinated_journey_is_verified_survey_by_survey_and_as_a_journey(
    clean_rules: None, trio: Any, survey_app: Any, db: Session
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    operational_before = counts(db, OPERATIONAL)
    publish_finding_rules(db, RULES_V1)
    a_sid, a_code, _ = build(author, "K3", "Survey A (numbers)")
    version_a = publish(trio, a_sid)[1]
    b_sid, b_code = empty_survey(author, "Survey B (reuses A's question)")
    assert pin_module(author, b_sid, draft(author, a_sid)).status_code == 200
    version_b = publish(trio, b_sid)[1]
    shared = items_of(db, version_a)["mi-numbers/n1"]
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
    policy = published_policy(trio, policy_body([pc("SYN-CTRL-01", [ob("TERM", [ev("E-TERM")])])]))
    mapped(
        trio,
        "SYN-CTRL-01",
        [
            entry(shared, {"method": "NUMERIC_COMPARE", "evaluation": {"operator": "EQ", "value": 20, "unit": "COUNT"}})
            | {"requirement": "E-TERM"}
        ],
    )

    def journey(until: int | None = None, bad_first: bool = False) -> dict[str, Any]:
        comp = compose(author, application)
        co = post(author, f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "assurance"}).json()
        if bad_first:
            co = post(
                author,
                f"{A}/coordinated-simulations/{co['id']}/inputs",
                {"expected_inputs": 0, "key": co["current"]["pending"]["key"], "answer": {"number": "twenty"}},
            ).json()
        n = 0
        numbers = {1: {"n1": 20, "n2": 12.5, "n3": -3}, 2: {"n1": 30, "n2": 12.5, "n3": -3}}
        while co["status"] == "RUNNING" and (until is None or n < until):
            key = co["current"]["pending"]["key"]
            co = post(
                author,
                f"{A}/coordinated-simulations/{co['id']}/inputs",
                {
                    "expected_inputs": co["progress"]["inputs"],
                    "key": key,
                    "answer": {"number": numbers[co["current"]["position"]][key.split("/")[1]]},
                },
            ).json()
            n += 1
        return co | {"composite": comp}

    # ---- 2. a complete coordinated execution: each survey verified on its own, and the journey as a journey
    co = journey(bad_first=True)
    assert co["status"] == "ALL_SURVEYS_COMPLETED"
    evaluation = under(author, policy["id"], coordinated=co["id"])
    a = assure(author, coordinated=co["id"], evaluation=evaluation["id"])
    assert (
        a["journey_kind"],
        a["status"],
        a["summary"]["by_status"]["VERIFIED"],
        a["summary"]["surveys_completed"],
    ) == ("COORDINATED", "VERIFIED", 2, 2)
    assert [(c["check"], c["status"]) for c in a["journey_checks"]] == [(n, "PASSED") for n in ea.JOURNEY_CHECKS]
    assert [
        (s["position"], s["survey_version_id"], s["simulation_id"], s["status"], s["run_sha256"]) for s in a["surveys"]
    ] == [
        (1, version_a, co["surveys"][0]["simulation_id"], "VERIFIED", co["surveys"][0]["run_sha256"]),
        (2, version_b, co["surveys"][1]["simulation_id"], "VERIFIED", co["surveys"][1]["run_sha256"]),
    ]  # each survey keeps its own evidence
    assert a["surveys"][0]["rejections"][0]["code"] == "NUMBER_REQUIRED" and a["summary"]["refused_inputs"] == 1  # 11
    assert a["pins"]["composite"] == {
        "plan_id": co["composite"]["id"],
        "fingerprint": co["composite"]["fingerprint"],
        "selected": a["pins"]["composite"]["selected"],
    }
    assert [(s["group"], s["survey_version_id"]) for s in a["pins"]["composite"]["selected"]] == [
        ("PRIMARY-SG", version_a),
        ("ADD-B", version_b),
    ]
    # the SAME published question, delivered in both surveys, in the same exact pinned wording
    w = [next(d for d in s["deliveries"] if d["item"]["code"] == shared["code"]) for s in a["surveys"]]
    assert (w[0]["wording"], w[1]["wording"], w[0]["wording_sha256"]) == (
        "EXACT",
        "EXACT",
        w[1]["wording_sha256"],
    ) and (w[0]["placement"], w[1]["placement"]) == ("mi-numbers/n1", "mi-shared/n1")

    # ---- 15. the conflict EVAL-2A found stays exactly as it found it, and is traceable to two VERIFIED executions
    (term,) = a["control_evidence"]
    assert (
        term["control_code"],
        term["obligation"],
        term["outcome"],
        term["coverage"],
        term["execution_evidence"],
        term["result_is_trustworthy"],
    ) == ("SYN-CTRL-01", "TERM", "REQUIRES_REVIEW", "EVIDENCE_CONFLICTING", "EXECUTION_VERIFIED", True)
    assert [
        (x["survey_position"], x["simulation_id"], x["result"], x["delivery"], x["execution"]) for x in term["evidence"]
    ] == [
        (1, co["surveys"][0]["simulation_id"], "MATCH", "EXACT", "EXECUTION_VERIFIED"),
        (2, co["surveys"][1]["simulation_id"], "MISMATCH", "EXACT", "EXECUTION_VERIFIED"),
    ]  # both answers were faithfully recorded: the conflict is in what was said, not in how it was executed
    assert (
        instance(author.get(f"{E}/evaluations/{evaluation['id']}").json(), "SYN-CTRL-01", "TERM")["outcome"]
        == "REQUIRES_REVIEW"
    )
    assert (
        a["status"],
        evaluation["processing_status"],
        evaluation["coverage"]["status"],
        a["operational_call_eligibility"]["status"],
    ) == ("VERIFIED", "REQUIRES_REVIEW", "INCOMPLETE", "NOT_ESTABLISHED")

    # ---- 10. an unfinished survey does not silently advance: the second survey is not started, and nothing is bypassed
    part = journey(until=1)
    assert [s["state"] for s in part["surveys"]] == ["CURRENT", "NOT_STARTED"]
    b = assure(author, coordinated=part["id"])
    assert (b["status"], [s["status"] for s in b["surveys"]]) == ("INCOMPLETE", ["INCOMPLETE", "INCOMPLETE"])
    assert b["surveys"][1]["not_assessable"]["code"] == "NOT_STARTED" and b["surveys"][1]["simulation_id"] is None
    assert {c["check"]: c["status"] for c in b["journey_checks"]} == dict.fromkeys(ea.JOURNEY_CHECKS, "PASSED")
    assert b["journey"]["complete"] is False and b["summary"]["surveys_completed"] == 0
    assert counts(db, OPERATIONAL) == operational_before
    for cx in (maker, rule_checker):
        cx.__exit__(None, None, None)


def test_assurance_is_off_by_default_and_its_migration_is_additive(
    clean_rules: None, settings: Settings, engine: Engine, db: Session
) -> None:
    from tests.support import migrate

    assert Settings.model_fields["survey_execution_assurance_enabled"].default is False
    people = [make_account(db, prefix=p) for p in ("easa", "easc", "easp")]
    for person in people:
        GRANTS[person.principal_id] = ALL
    for update, registered in (
        (POLICY_ON, False),
        (
            {k: v for k, v in ON.items() if k != "survey_evaluation_enabled"},
            False,
        ),  # assurance without evaluation is not on
        (ON, True),
    ):
        app = create_app(settings.model_copy(update=update))
        operations = [
            (m, p) for p, item in app.openapi()["paths"].items() if p.startswith(f"{E}/assurance") for m in item
        ]
        assert len(operations) == (3 if registered else 0)
    app = create_app(settings.model_copy(update=ON))
    with_grants(app)
    trio_ = tuple(_client(app, p) for p in people)
    sid, _, _ = build(trio_[0], "K1", "Assured survey")
    sim = simulate(
        trio_[0], publish(trio_, sid)[1], {}, {"mi-call/n2": {"choice": "YES"}, "mi-call/n5": {"choice": "YES"}}
    )
    evaluation = evaluate(trio_[0], simulation_id=sim["id"])
    a = assure(trio_[0], simulation_id=sim["id"], evaluation=evaluation["id"])
    assert a["status"] == "VERIFIED"
    off = create_app(settings.model_copy(update=POLICY_ON))
    with_grants(off)
    c = _client(off, people[0])
    assert (
        c.get(f"{E}/assurance/{a['id']}").status_code == 404
        and c.get(f"{E}/evaluations/{evaluation['id']}").status_code == 200
    )
    c.__exit__(None, None, None)

    def state() -> tuple[set[str], str]:
        with engine.connect() as cx:
            return set(
                cx.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars()
            ), str(cx.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one())

    def others() -> list[Any]:
        with engine.connect() as cx:
            return [tuple(r) for r in cx.execute(text("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'call360_test' AND table_name NOT LIKE 'survey_execution_assurance%' AND table_name <> 'alembic_version' AND column_name <> 'artifact_kind' ORDER BY 1, 2"))] + [
                tuple(r) for r in cx.execute(text("SELECT r.relname, k.conname, pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class r ON r.oid = k.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace WHERE n.nspname = 'call360_test' AND r.relname NOT LIKE 'survey_execution_assurance%' AND k.conname <> 'ck_survey_definition_artifact_kind' ORDER BY 1, 2"))
            ]  # fmt: skip

    # ---- a recorded assurance result is not destroyed by a downgrade
    full, structure = state(), others()
    assert set(TABLES) <= full[0] and full[1] == "0036_survey_module_authoring"
    db.rollback()
    with pytest.raises(RuntimeError, match="recorded execution-assurance results exist"):
        migrate(settings, "0034_survey_control_policy", down=True)
    # 0036 (LIB-2, one column, no standalone module here) rolled back first; 0035 then refused and kept every result
    assert state() == (full[0], "0035_survey_execution_assurance")
    migrate(settings, "head")
    assert state() == full and trio_[0].get(f"{E}/assurance/{a['id']}").json()["result_sha256"] == a["result_sha256"]
    for cx in trio_:
        cx.__exit__(None, None, None)
    for person in people:
        GRANTS.pop(person.principal_id)
    # ---- empty: down removes exactly the two tables and nothing else changes; up puts them back
    from app.domain.protection import DataProtection
    from app.domain.seed import seed
    from tests.support import reset_test_schema

    reset_test_schema(engine, settings)
    with engine.begin() as cx:
        seed(cx, settings.target_schema, DataProtection.from_settings(settings))
    full, structure = state(), others()
    migrate(settings, "0034_survey_control_policy", down=True)
    assert state() == (full[0] - set(TABLES), "0034_survey_control_policy") and others() == structure
    migrate(settings, "head")
    assert state() == full and others() == structure
