"""S2-D text simulation over the API: plan with conditional modules, start with the validated callback contact,
progression to completion, incomplete runs, duplicates and invalid transitions, restart, no operational side effects
(no attempts / sessions / survey runs / answers / findings / holds / case state / KPIs), historical script preservation,
Singapore-only access and permissions."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_script_authoring import ok

pytestmark = pytest.mark.usefixtures("seeded")


def case_where(db: Session, facts: str, contacts: int) -> str:
    """A seeded Singapore case with a pinned script, matching fact filter and number of eligible contacts."""
    cid = db.execute(
        text(
            f"SELECT c.id FROM {SCHEMA}.callback_case c JOIN {SCHEMA}.script_assignment a ON a.callback_case_id = c.id "
            f"JOIN {SCHEMA}.policy_fact_snapshot s ON s.id = a.policy_fact_snapshot_id "
            f"LEFT JOIN {SCHEMA}.risk_assessment r ON r.id = a.risk_assessment_id "
            f"WHERE c.market_code = 'SG' AND {facts} AND (SELECT count(*) FROM {SCHEMA}.case_contact_selection x "
            f"WHERE x.callback_case_id = c.id AND x.eligible AND NOT EXISTS (SELECT 1 FROM "
            f"{SCHEMA}.case_contact_selection y WHERE y.supersedes_id = x.id)) = :n ORDER BY c.case_ref LIMIT 1"
        ),
        {"n": contacts},
    ).scalar()
    db.rollback()
    assert cid, facts
    return str(cid)


def fingerprint(db: Session) -> str:
    h = hashlib.sha256()
    for t in (
        "contact_attempt",
        "conversation_session",
        "survey_run",
        "question_execution",
        "answer_observation",
        "rule_evaluation",
        "finding",
        "script_assignment",
    ):
        h.update(f"{t}:{db.execute(text(f'SELECT count(*) FROM {SCHEMA}.{t}')).scalar()}".encode())
    for row in db.execute(
        text(f"SELECT id, state, has_blocking_hold, row_version, verified_at FROM {SCHEMA}.callback_case ORDER BY id")
    ):
        h.update(repr(tuple(row)).encode())
    for row in db.execute(text(f"SELECT id, released_at FROM {SCHEMA}.case_hold ORDER BY id")):
        h.update(repr(tuple(row)).encode())
    for row in db.execute(text(f"SELECT id, manifest_sha256, status FROM {SCHEMA}.script_version ORDER BY id")):
        h.update(repr(tuple(row)).encode())
    db.rollback()
    return h.hexdigest()


def measures(body: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [(k["definition_id"], k.get("numerator"), k.get("denominator"), k.get("value")) for k in body["items"]]


def post(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
    r = c.post(f"/api/v1{path}", json=body, headers=csrf_header(c))
    assert r.status_code == status, r.text
    return dict(r.json())


VALUES = {"YES_NO": True, "ACKNOWLEDGEMENT": True, "NUMERIC": 10, "FREE_TEXT": "Synthetic free-text answer"}


def run_to_end(c: TestClient, run: dict[str, Any]) -> dict[str, Any]:
    while run["next_action"]["kind"] in ("ASK", "REPROMPT"):
        a = run["next_action"]
        if not a["presented"]:
            run = post(c, f"/script-simulations/{run['id']}/delivery", {"action_id": a["action_id"], "delivered": True})
            a = run["next_action"]
        value = a["options"][0] if a["answer_type"] == "ENUM" else VALUES[a["answer_type"]]
        run = post(
            c,
            f"/script-simulations/{run['id']}/answer",
            {"action_id": a["action_id"], "kind": "ANSWER", "value": value},
        )
    return run


def test_plan_start_complete_and_no_operational_side_effects(client: TestClient, user: Account, db: Session) -> None:
    login(client, user)
    before = fingerprint(db)
    kpis = measures(ok(client.get("/api/v1/dashboard/kpis")))
    ilp_high = case_where(db, "(s.facts->>'is_ilp')::boolean AND r.band_code = 'HIGH'", 1)
    plan = ok(client.get("/api/v1/script-simulations/plan", params={"case_id": ilp_high}))
    included = {s["module_code"]: s["included"] for s in plan["sections"]}
    assert included == {"COMMON_SALES_CONDUCT": True, "PROTECTION": False, "ILP": True, "ELEVATED_RISK": True}
    skipped = [q for q in plan["questions"] if not q["applicable"]]
    assert skipped and all(q["skip_reason"] for q in skipped)
    assert len(plan["contacts"]) == 1 and plan["content_approval_status"] == "SYNTHETIC_UNAPPROVED"
    run = post(client, "/script-simulations", {"case_id": ilp_high}, 201)
    assert (
        run["status"] == "IN_PROGRESS"
        and run["contact_role"]
        and run["next_action"]["question_code"] == "Q-REP-DISCLOSED"
    )
    assert run["trace"][0]["event_type"] == "STARTED" and "no customer is contacted" in run["note"]
    done = run_to_end(client, run)
    assert done["status"] == "SEQUENCE_FINISHED" and done["next_action"]["kind"] == "SEQUENCE_FINISHED"
    ended = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    assert ended["status"] == "COMPLETED" and ended["outcome"] == "COMPLETED"
    s = ended["summary"]
    assert (
        not s["mandatory_open"] and not s["mandatory_unresolved"] and len(s["mandatory_completed"]) == 10
    )  # 4 common + 4 ILP + 2 elevated risk
    types = {e["event_type"] for e in ended["trace"]}
    assert {
        "QUESTION_SKIPPED",
        "QUESTION_REQUESTED",
        "DELIVERY_RECORDED",
        "ANSWER_RECEIVED",
        "QUESTION_COMPLETED",
        "SEQUENCE_FINISHED",
        "ENDED",
    } <= types
    # Ended runs are final; pins and events are immutable.
    assert post(client, f"/script-simulations/{run['id']}/end", {"abandon": True}, 409)["code"] == "ALREADY_ENDED"
    for sql in (
        f"UPDATE {SCHEMA}.script_simulation_event SET data = '{{}}' WHERE run_id = :r",
        f"UPDATE {SCHEMA}.script_simulation_run SET outcome = 'INCOMPLETE' WHERE id = :r",
    ):
        with pytest.raises(Exception, match="immutable|final|not allowed|forbid"):
            db.execute(text(sql), {"r": run["id"]})
        db.rollback()
    # Nothing operational changed (attempts, sessions, survey runs, answers, findings, holds, states, scripts, KPIs).
    assert fingerprint(db) == before
    assert measures(ok(client.get("/api/v1/dashboard/kpis"))) == kpis
    # Restart = a new run; the earlier run is kept.
    post(client, "/script-simulations", {"case_id": ilp_high}, 201)
    runs = ok(client.get(f"/api/v1/cases/{ilp_high}/script-simulations"))["items"]
    assert len(runs) == 2 and {r["outcome"] for r in runs} == {"COMPLETED", None}


def test_conditional_modules_incomplete_runs_duplicates_and_contacts(
    client: TestClient, user: Account, db: Session
) -> None:
    login(client, user)
    protection = case_where(
        db, "s.facts->>'product_family' = 'PROTECTION' AND coalesce(r.band_code, 'LOW') <> 'HIGH'", 1
    )
    plan = ok(client.get("/api/v1/script-simulations/plan", params={"case_id": protection}))
    assert {s["module_code"]: s["included"] for s in plan["sections"]}["ILP"] is False
    run = post(client, "/script-simulations", {"case_id": protection}, 201)
    rid, a = run["id"], run["next_action"]
    assert (
        post(
            client,
            f"/script-simulations/{rid}/answer",
            {"action_id": a["action_id"], "kind": "ANSWER", "value": True},
            409,
        )["code"]
        == "NOT_PRESENTED"
    )
    run = post(client, f"/script-simulations/{rid}/delivery", {"action_id": a["action_id"], "delivered": True})
    assert (
        post(
            client,
            f"/script-simulations/{rid}/answer",
            {"action_id": a["action_id"], "kind": "ANSWER", "value": "maybe"},
            422,
        )["code"]
        == "INVALID_ANSWER"
    )
    first = post(
        client, f"/script-simulations/{rid}/answer", {"action_id": a["action_id"], "kind": "ANSWER", "value": True}
    )
    dup = post(
        client, f"/script-simulations/{rid}/answer", {"action_id": a["action_id"], "kind": "ANSWER", "value": True}
    )
    assert dup["replayed"] and len(dup["trace"]) == len(first["trace"])  # a duplicate submission changes nothing
    assert (
        post(client, f"/script-simulations/{rid}/skip", {"action_id": first["next_action"]["action_id"]}, 409)["code"]
        == "MANDATORY_NOT_SKIPPABLE"
    )
    nxt = first["next_action"]
    post(client, f"/script-simulations/{rid}/delivery", {"action_id": nxt["action_id"], "delivered": True})
    rep = post(
        client,
        f"/script-simulations/{rid}/clarification",
        {"action_id": nxt["action_id"], "reason": "Customer asked to repeat"},
    )
    assert rep["next_action"]["kind"] == "REPROMPT" and rep["next_action"]["action_id"].endswith("#2")
    post(
        client, f"/script-simulations/{rid}/delivery", {"action_id": rep["next_action"]["action_id"], "delivered": True}
    )
    out = post(
        client, f"/script-simulations/{rid}/answer", {"action_id": rep["next_action"]["action_id"], "kind": "UNCLEAR"}
    )
    assert next(q for q in out["questions"] if q["code"] == nxt["question_code"])["status"] == "UNRESOLVED"
    ended = post(client, f"/script-simulations/{rid}/end", {"abandon": False, "reason": "Stopped early (test)"})
    assert ended["outcome"] == "INCOMPLETE" and ended["summary"]["mandatory_unresolved"] == [nxt["question_code"]]
    assert ended["summary"]["mandatory_open"]  # not reached: never counted as complete
    # Several eligible contacts and no contact recorded by the assignment: the simulation must be told which one.
    multi = case_where(db, "true", 2)
    assert post(client, "/script-simulations", {"case_id": multi}, 422)["code"] == "CONTACT_REQUIRED"
    contacts = ok(client.get("/api/v1/script-simulations/plan", params={"case_id": multi}))["contacts"]
    chosen = post(
        client, "/script-simulations", {"case_id": multi, "contact_selection_id": contacts[1]["selection_id"]}, 201
    )
    assert chosen["contact_role"] == contacts[1]["role"]


def test_scope_permissions_and_cases_without_a_script(
    client: TestClient, other_client: TestClient, user: Account, db: Session
) -> None:
    login(client, user)
    my = db.execute(
        text(
            f"SELECT c.id FROM {SCHEMA}.callback_case c JOIN {SCHEMA}.script_assignment a "
            "ON a.callback_case_id = c.id WHERE c.market_code = 'MY' LIMIT 1"
        )
    ).scalar()
    unassigned = db.execute(
        text(
            f"SELECT c.id FROM {SCHEMA}.callback_case c WHERE c.market_code = 'SG' AND NOT EXISTS "
            f"(SELECT 1 FROM {SCHEMA}.script_assignment a WHERE a.callback_case_id = c.id) "
            "LIMIT 1"
        )
    ).scalar()
    db.rollback()
    assert client.get("/api/v1/script-simulations/plan", params={"case_id": str(my)}).status_code == 404
    assert post(client, "/script-simulations", {"case_id": str(my)}, 404)["code"] == "NOT_FOUND"
    assert post(client, "/script-simulations", {"case_id": str(unassigned)}, 409)["code"] == "NO_SCRIPT_ASSIGNED"
    listed = ok(client.get("/api/v1/script-simulations/cases"))["items"]
    assert listed and all(not i["case_ref"].startswith("CB-MY") for i in listed)
    admin = make_account(db, "LOCAL_ADMIN", prefix="sadm")
    login(other_client, admin)
    sg = listed[0]["case_id"]
    assert post(other_client, "/script-simulations", {"case_id": sg}, 403)["code"] == "FORBIDDEN"
    checker = make_account(db, "LOCAL_SC_CHECKER_SG", prefix="schk")
    other_client.cookies.clear()
    login(other_client, checker)
    assert post(other_client, "/script-simulations", {"case_id": sg}, 201)["status"] in (
        "IN_PROGRESS",
        "SEQUENCE_FINISHED",
    )
