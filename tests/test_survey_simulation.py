# ruff: noqa: E501, F811
"""SS-03B — the simulation and call-plan API: real HTTP, real PostgreSQL (schema ``call360_test``), no mocks.

A golden fixture is saved under server-issued codes, submitted, approved by a second person and published by a third.
Its PUBLISHED version is then simulated through the five operations, and what the server returns is compared with what
the fixture expects. Simulation only: these tests also prove that nothing operational is read, written or implied."""

from __future__ import annotations

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
from tests.survey_fixtures import load_all
from tests.test_survey_api import ALL as FOUR
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_lib1 import build, publish

FX = {fx["fixture"][:2]: fx for fx in load_all()}
OPERATIONAL = (
    "callback_case", "contact_attempt", "conversation_session", "survey_run", "answer_observation", "finding",
    "media_asset", "transcript_run", "transcript_segment",
)  # fmt: skip


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    """The application with survey definitions, the library and SIMULATION on."""
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "transcription_worker": False,
            }
        )
    )  # fmt: skip
    with_grants(app)
    return app


SIMULATE = frozenset({"survey.simulate"})
ALL = FOUR | SIMULATE


@pytest.fixture()
def trio(_trio: Any) -> Any:
    """Author, checker, publisher — the author also holds `survey.simulate` (the four others never imply it)."""
    author_person = _trio[3][0]
    GRANTS[author_person.principal_id] = ALL
    return _trio


def published(people: Any, prefix: str) -> str:
    sid, _, _ = build(people[0], prefix)
    return publish(people, sid)[1]


def start(c: TestClient, vid: str, facts: dict[str, Any] | None = None) -> dict[str, Any]:
    r = post(c, f"/api/v1/survey-versions/{vid}/simulations", {"facts": facts or {}, "label": "test"})
    assert r.status_code == 201, r.text
    return r.json()


def give(c: TestClient, sim: dict[str, Any], key: str, answer: dict[str, Any]) -> Any:
    return post(
        c,
        f"/api/v1/survey-simulations/{sim['id']}/inputs",
        {"expected_inputs": len(sim["inputs"]), "key": key, "answer": answer},
    )


def play(c: TestClient, vid: str, run: dict[str, Any]) -> dict[str, Any]:
    """Drive a simulation through the API exactly as the fixture's run says: refused answers first, then its own."""
    sim = start(c, vid, run.get("facts") or run.get("profile") or {})
    bad: dict[str, list[dict[str, Any]]] = {}
    for b in run.get("rejected") or []:
        bad.setdefault(b["at"], []).append(b)
    while sim["status"] != "TERMINAL":
        key = sim["run"]["pending"]["key"]
        if bad.get(key):
            answer = bad[key].pop(0)["answer"]
        elif key in run["answers"]:
            answer = run["answers"][key]
        else:
            break
        r = give(c, sim, key, answer)
        assert r.status_code == 200, r.text
        sim = r.json()
    return sim


def existing(db: Session, tables: tuple[str, ...]) -> dict[str, int]:
    out = {}
    for t in tables:
        if db.execute(text("SELECT to_regclass(:t)"), {"t": f"call360_test.{t}"}).scalar_one():
            out[t] = db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one()  # noqa: S608 — fixed names
    return out


@pytest.mark.parametrize("prefix", ["K1", "K3", "K4", "K7", "K8"])
def test_a_published_version_simulated_through_the_api_gives_the_golden_runs(trio: Any, prefix: str) -> None:
    vid = published(trio, prefix)
    for run in FX[prefix]["expected_runs"]:
        sim = play(trio[0], vid, run)
        exp, got = run["expect"], sim["run"]
        assert sim["record_class"] == "SIMULATION" and "not" in sim["note"].lower()
        assert got["asked"] == exp["asked"], run["name"]
        assert got["terminal"] == exp["terminal"]
        assert [{k: m[k] for k in ("instance", "status", "outcome") if k in m} for m in got["modules"]] == exp[
            "modules"
        ]
        assert got["evidence_states"] == exp["evidence_states"]
        assert got["rejections"] == [{"at": b["at"], "error": b["error"]} for b in run.get("rejected") or []]
        assert (got["pending"] or {}).get("key") == exp["pending"]
        assert [d["key"] for d in got["delivered"]] == [d["key"] for d in exp["delivered"]]
        if prefix != "K8":  # K8's one variable was replaced by plain words to make it publishable (default-deny)
            assert [d["text"] for d in got["delivered"]] == [d["text"] for d in exp["delivered"]]
        # reading it again replays the recorded inputs and gives the very same run
        again = trio[0].get(f"/api/v1/survey-simulations/{sim['id']}").json()
        assert again["run_sha256"] == sim["run_sha256"] and again["replay_consistent"] is True and again["run"] == got
        # the same inputs given to a NEW simulation give the same run, fingerprint for fingerprint
        assert play(trio[0], vid, run)["run_sha256"] == sim["run_sha256"]


def test_an_invalid_or_misplaced_input_never_advances_a_simulation(trio: Any, db: Session) -> None:
    c = trio[0]
    vid = published(trio, "K3")
    run = next(r for r in FX["K3"]["expected_runs"] if r.get("rejected"))
    bad = run["rejected"][0]
    sim = start(c, vid)
    while sim["run"]["pending"]["key"] != bad["at"]:
        sim = give(c, sim, sim["run"]["pending"]["key"], run["answers"][sim["run"]["pending"]["key"]]).json()
    before = len(sim["inputs"])
    r = give(c, sim, bad["at"], bad["answer"])
    assert r.status_code == 200
    after = r.json()
    last = after["inputs"][-1]
    assert (last["accepted"], last["rejection_code"]) == (False, bad["error"])  # recorded — as REFUSED
    assert (after["status"], after["run"]["pending"]["key"], after["run"]["pending"]["attempt"]) == (
        "PENDING",
        bad["at"],
        1,
    )
    assert bad["at"] not in after["run"]["asked"] and after["run"]["terminal"] is None

    def count():
        return db.execute(
            text("SELECT count(*) FROM survey_simulation_input WHERE simulation_id = :s"), {"s": sim["id"]}
        ).scalar_one()  # noqa: E731

    assert count() == before + 1
    # against a stale count: refused, nothing recorded
    r = give(c, sim, bad["at"], run["answers"][bad["at"]])
    assert (r.status_code, r.json()["code"]) == (409, "STALE_SIMULATION")
    # for a question that is not current: refused, nothing recorded
    r = give(c, after, "mi-nowhere/n99", {"choice": "YES"})
    assert (r.status_code, r.json()["code"]) == (409, "INPUT_NOT_CURRENT")
    # an answer with a field the contract does not define, or of the wrong shape: refused, nothing recorded
    for wrong in (
        {"number": 3, "confidence": 0.9},
        {"number": {"value": 3}},
        {"number": [3]},
        {"choices": "YES"},
        {"choices": [["YES"]]},
    ):
        r = give(c, after, bad["at"], wrong)
        assert (r.status_code, r.json()["code"]) == (422, "ANSWER_INVALID"), wrong
    assert count() == before + 1
    # the valid answer is then accepted, and once the run has ended nothing more is taken
    sim = give(c, after, bad["at"], run["answers"][bad["at"]]).json()
    while sim["status"] != "TERMINAL":
        key = sim["run"]["pending"]["key"]
        sim = give(c, sim, key, run["answers"][key]).json()
    r = give(c, sim, bad["at"], run["answers"][bad["at"]])
    assert (r.status_code, r.json()["code"]) == (409, "SIMULATION_ENDED")


def test_a_non_answer_fails_closed_as_policy_unresolved(trio: Any) -> None:
    c = trio[0]
    vid = published(trio, "K4")
    run = FX["K4"]["expected_runs"][0]
    sim = start(c, vid)
    while sim["run"]["pending"]["answer_type"] != "ACKNOWLEDGEMENT":
        key = sim["run"]["pending"]["key"]
        sim = give(c, sim, key, run["answers"][key]).json()
    key = sim["run"]["pending"]["key"]
    refused = give(c, sim, key, {"acknowledged": False}).json()
    assert refused["status"] == "POLICY_UNRESOLVED"
    assert refused["run"]["policy_unresolved"] == {
        "key": key,
        "code": "POLICY_UNRESOLVED",
        "reason": "NON_ANSWER_POLICY_UNRESOLVED",
    }
    assert (
        refused["run"]["terminal"] is None and refused["run"]["pending"]["key"] == key
    )  # the same question, still current
    assert not [m for m in refused["run"]["modules"] if m.get("outcome")]  # no completion or escalation was synthesised
    assert not [e for e in refused["run"]["events"] if e["kind"] == "END"]
    assert (refused["inputs"][-1]["accepted"], refused["inputs"][-1]["rejection_code"]) == (
        False,
        "NON_ANSWER_POLICY_UNRESOLVED",
    )
    assert refused["inputs"][-1]["run_status"] == "POLICY_UNRESOLVED"
    accepted = give(c, refused, key, {"acknowledged": True}).json()
    assert key in accepted["run"]["asked"] and accepted["run"]["policy_unresolved"] is None


def test_a_call_plan_is_deterministic_recorded_and_says_nothing_about_calling(trio: Any) -> None:
    c = trio[0]
    vid = published(trio, "K8")
    seen = {}
    for p in FX["K8"]["expected_plans"]:
        r = post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": p["facts"]})
        assert r.status_code == 201, r.text
        one = r.json()
        two = post(
            c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": dict(reversed(list(p["facts"].items())))}
        ).json()
        assert one["id"] != two["id"] and one["fingerprint"] == two["fingerprint"] and one["plan"] == two["plan"]
        assert one["record_class"] == "SIMULATION" and one["fingerprint_verified"] is True
        # which modules are in, out, conditional or halted is exactly what the golden plan says
        assert [{"instance": m["instance"], "status": m["status"]} for m in one["plan"]["modules"]] == p["expect"][
            "modules"
        ]
        assert {i["field"]: i["state"] for i in one["plan"]["inputs"] if i["field"] in p["expect"]["inputs"]} == {
            k: v for k, v in p["expect"]["inputs"].items() if k in {i["field"] for i in one["plan"]["inputs"]}
        }
        assert [i for i in one["plan"]["issues"] if i["code"] == "ELIGIBILITY_UNKNOWN"] == [
            i for i in p["expect"]["issues"] if i["code"] == "ELIGIBILITY_UNKNOWN"
        ]
        read = c.get(f"/api/v1/survey-call-plans/{one['id']}").json()
        assert read["plan"] == one["plan"] and read["facts"] == p["facts"]
        seen[one["fingerprint"]] = p["name"]
        flat = str(one).lower()
        assert "eligible_for_call" not in flat and "may_call" not in flat
    assert len(seen) == len(FX["K8"]["expected_plans"])
    r = post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {"customer.shoe_size": 9}})
    assert (r.status_code, r.json()["code"]) == (422, "FACT_UNKNOWN")
    r = post(c, f"/api/v1/survey-versions/{vid}/simulations", {"facts": {"policy.annual_premium": {"amount": 1}}})
    assert (r.status_code, r.json()["code"]) == (422, "FACTS_INVALID")


def test_simulation_is_denied_without_permission_market_session_or_csrf(
    trio: Any, survey_app: Any, db: Session
) -> None:
    c = trio[0]
    vid = published(trio, "K1")
    sim = start(c, vid)
    plan = post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}).json()
    key = sim["run"]["pending"]["key"]
    body = {"expected_inputs": 0, "key": key, "answer": {"choice": "YES"}}
    calls = [
        ("POST", f"/api/v1/survey-versions/{vid}/simulations", {"facts": {}}),
        ("POST", f"/api/v1/survey-simulations/{sim['id']}/inputs", body),
        ("GET", f"/api/v1/survey-simulations/{sim['id']}", None),
        ("POST", f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}),
        ("GET", f"/api/v1/survey-call-plans/{plan['id']}", None),
    ]
    rows = lambda: existing(db, ("survey_simulation", "survey_simulation_input", "survey_call_plan"))  # noqa: E731
    before = rows()

    def call(x: TestClient, method: str, path: str, payload: Any) -> Any:
        return x.get(path) if method == "GET" else post(x, path, payload)

    plain = _client(survey_app, make_account(db, prefix="plain"))  # signed in, no survey permission
    reader_person = make_account(db, prefix="reader")
    GRANTS[reader_person.principal_id] = FOUR  # read, edit, approve, publish — everything EXCEPT simulate
    reader = _client(survey_app, reader_person)
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)  # every permission, another market
    with TestClient(survey_app, base_url="http://testserver") as anon:
        for method, path, payload in calls:
            assert call(plain, method, path, payload).status_code == 403, path
            # read, edit, approve and publish together do not allow creating or advancing a simulation, or a plan;
            # they do allow READING a simulation or plan of a version in the reader's market
            assert call(reader, method, path, payload).status_code == (200 if method == "GET" else 403), path
            assert call(outsider, method, path, payload).status_code == 404, path  # it does not exist for them
            r = anon.get(path) if method == "GET" else anon.post(path, json=payload)
            assert r.status_code in (401, 403), path
            if method == "POST":
                assert c.post(path, json=payload).status_code == 403, path  # a signed-in author, no CSRF token
    assert rows() == before  # nothing was recorded by any refused call
    db.expire_all()
    denied = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' AND reason = 'missing permission survey.read'"
        )
    ).scalar_one()
    assert denied >= 2  # the two reads
    refused = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' AND reason = 'missing permission survey.simulate'"
        )
    ).scalar_one()
    assert refused >= 6  # three state-changing operations, refused for the plain person and for the reader
    # the permission exists, is described, and NO role holds it by migration
    assert db.execute(text("SELECT count(*) FROM permission WHERE code = 'survey.simulate'")).scalar_one() == 1
    holders = (
        db.execute(
            text(
                "SELECT r.code FROM role_permission rp JOIN role r ON r.id = rp.role_id JOIN permission p ON p.id = rp.permission_id WHERE p.code = 'survey.simulate'"
            )
        )
        .scalars()
        .all()
    )
    assert holders == []
    GRANTS.pop(reader_person.principal_id)
    reader.__exit__(None, None, None)
    for x in (plain, outsider):
        x.__exit__(None, None, None)
    GRANTS.pop(elsewhere.principal_id)
    MARKETS.pop(elsewhere.principal_id)
    # an unknown version; and a version whose documents no longer match its manifest is never executed
    import uuid

    assert post(c, f"/api/v1/survey-versions/{uuid.uuid4()}/simulations", {"facts": {}}).status_code == 404


def test_a_version_that_does_not_match_its_manifest_is_never_executed(
    trio: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = trio[0]
    vid = published(trio, "K1")
    sim = start(c, vid)
    monkeypatch.setattr(
        store, "manifest_problems", lambda _db, _cand: ["ITEM X version 1 does not match the hash the manifest pinned"]
    )
    for r in (
        post(c, f"/api/v1/survey-versions/{vid}/simulations", {"facts": {}}),
        post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}),
        c.get(f"/api/v1/survey-simulations/{sim['id']}"),
        give(c, sim, sim["run"]["pending"]["key"], {"choice": "YES"}),
    ):
        assert (r.status_code, r.json()["code"]) == (409, "MANIFEST_MISMATCH")


def test_simulation_records_are_isolated_append_only_audited_and_never_operational(
    trio: Any, db: Session, engine: Engine
) -> None:
    c = trio[0]
    operational_before = existing(db, OPERATIONAL)
    assert set(operational_before) == set(OPERATIONAL)  # every one of them exists and is compared
    vid = published(trio, "K1")
    sim = play(c, vid, FX["K1"]["expected_runs"][0])
    plan = post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}).json()
    db.expire_all()
    assert existing(db, OPERATIONAL) == operational_before  # nothing operational was written
    # the three tables refer ONLY to the survey definition tables and to each other
    refs = db.execute(
        text(
            "SELECT DISTINCT c.relname, f.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid "
            "JOIN pg_class f ON f.oid = k.confrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE k.contype = 'f' "
            "AND n.nspname = 'call360_test' AND c.relname IN ('survey_simulation', 'survey_simulation_input', 'survey_call_plan')"
        )
    ).all()
    assert {tuple(r) for r in refs} == {
        ("survey_simulation", "survey_version"), ("survey_simulation", "survey_definition"),
        ("survey_simulation_input", "survey_simulation"),
        ("survey_call_plan", "survey_version"), ("survey_call_plan", "survey_definition"),
    }  # fmt: skip
    # … and nothing operational refers to them
    inbound = (
        db.execute(
            text(
                "SELECT DISTINCT c.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class f ON f.oid = k.confrelid "
                "WHERE k.contype = 'f' AND f.relname IN ('survey_simulation', 'survey_simulation_input', 'survey_call_plan') "
                "AND c.relname NOT IN ('survey_simulation', 'survey_simulation_input', 'survey_call_plan')"
            )
        )
        .scalars()
        .all()
    )
    # only the ASG-1 and ASG-2A simulated-selection records (themselves record_class SIMULATION) point at them
    assert set(inbound) <= {
        "survey_assignment_evaluation", "survey_assignment_simulation", "survey_composite_plan_member",
        "survey_coordinated_simulation_step",
        # EVAL-1: the evaluation of a simulated journey and its evidence observations (record_class SIMULATION too)
        "survey_journey_evaluation", "survey_evidence_observation", "survey_obligation_observation",  # EVAL-2A likewise
        "survey_execution_assurance", "survey_execution_assurance_survey",  # EVAL-2B: the assurance of a simulated journey
    }  # fmt: skip
    columns = set(
        db.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = 'call360_test' AND table_name IN ('survey_simulation', 'survey_simulation_input', 'survey_call_plan')"
            )
        ).scalars()
    )
    assert not [
        x
        for x in columns
        if any(
            w in x for w in ("case", "attempt", "session", "recording", "transcript", "finding", "customer", "policy")
        )
    ]
    # every row is of class SIMULATION and can be nothing else; rows cannot be changed or removed
    for table, ident in (("survey_simulation", sim["id"]), ("survey_call_plan", plan["id"])):
        assert (
            db.execute(text(f"SELECT record_class FROM {table} WHERE id = :i"), {"i": ident}).scalar_one()
            == "SIMULATION"
        )  # noqa: S608
        for statement in (
            f"UPDATE {table} SET record_class = 'OPERATIONAL' WHERE id = :i",  # noqa: S608
            f"UPDATE {table} SET facts = '{{}}'::jsonb WHERE id = :i",  # noqa: S608
            f"DELETE FROM {table} WHERE id = :i",  # noqa: S608
        ):
            with engine.connect() as conn, pytest.raises(DBAPIError):
                conn.execute(text(statement), {"i": ident})
    with engine.connect() as conn, pytest.raises(DBAPIError):
        conn.execute(text("DELETE FROM survey_simulation_input WHERE simulation_id = :i"), {"i": sim["id"]})
    with engine.connect() as conn, pytest.raises(DBAPIError):
        conn.execute(
            text(
                "INSERT INTO survey_simulation (id, record_class, survey_version_id, survey_definition_id, content_sha256, manifest_sha256, facts, facts_sha256, created_by) "
                "SELECT gen_random_uuid(), 'OPERATIONAL', survey_version_id, survey_definition_id, content_sha256, manifest_sha256, facts, facts_sha256, created_by FROM survey_simulation WHERE id = :i"
            ),
            {"i": sim["id"]},
        )
    # audited, on the one hash chain, naming the class of record
    events = db.execute(
        text(
            "SELECT action, count(*) FROM audit_event WHERE action LIKE 'SURVEY.SIMULATION%' OR action = 'SURVEY.CALL_PLAN_GENERATED' GROUP BY action"
        )
    ).all()
    got = {a: n for a, n in events}
    assert (
        got["SURVEY.SIMULATION_CREATED"] >= 1
        and got["SURVEY.SIMULATION_INPUT"] >= len(sim["inputs"])
        and got["SURVEY.CALL_PLAN_GENERATED"] >= 1
    )
    assert verify_chain(db).ok


def test_with_the_setting_off_there_is_no_simulation_at_all(settings: Settings, engine: Engine, db: Session) -> None:
    import uuid

    app = create_app(
        settings.model_copy(
            update={"survey_definitions_enabled": True, "survey_library_enabled": True, "transcription_worker": False}
        )
    )
    with_grants(app)
    person = make_account(db, prefix="reader")
    GRANTS[person.principal_id] = ALL
    c = _client(app, person)
    assert post(c, f"/api/v1/survey-versions/{uuid.uuid4()}/simulations", {"facts": {}}).status_code == 404
    assert post(c, f"/api/v1/survey-versions/{uuid.uuid4()}/call-plans", {"facts": {}}).status_code == 404
    assert c.get(f"/api/v1/survey-simulations/{uuid.uuid4()}").status_code == 404
    assert c.get(f"/api/v1/survey-call-plans/{uuid.uuid4()}").status_code == 404
    assert c.get("/api/v1/survey-definitions").status_code == 200  # the rest of Survey Studio is unaffected
    c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id)
    # the default is OFF, and simulation alone (without survey definitions) is not on
    assert Settings.model_fields["survey_simulation_enabled"].default is False
    paths = create_app(
        settings.model_copy(update={"survey_simulation_enabled": True, "transcription_worker": False}),
        with_database=False,
    ).openapi()["paths"]
    assert not [p for p in paths if "survey-simulations" in p or "/simulations" in p or "call-plans" in p]


def test_a_simulation_records_its_execution_contract_and_never_hides_replay_drift(
    trio: Any, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.domain.survey import execution, simulation

    c = trio[0]
    vid = published(trio, "K3")
    run = FX["K3"]["expected_runs"][0]
    fresh = start(c, vid)  # no input yet
    sim = start(c, vid)
    key = sim["run"]["pending"]["key"]
    sim = give(c, sim, key, run["answers"][key]).json()
    for s in (fresh, sim):
        assert (s["engine_contract"], s["current_engine_contract"]) == (execution.CONTRACT, execution.CONTRACT)
        assert s["replay_consistent"] is True and s["drift"] is None and s["status"] == s["run_status"]
    recorded = db.execute(
        text("SELECT engine_contract, initial_run_sha256 FROM survey_simulation WHERE id = :i"), {"i": fresh["id"]}
    ).one()
    assert tuple(recorded) == (execution.CONTRACT, fresh["run_sha256"])  # the run before any input is fingerprinted

    # 1. the engine's RESULT changes for the same inputs (here: it words a rejection differently)
    real = simulation.execute_inputs

    def changed(bundle: Any, facts: Any, inputs: Any) -> Any:
        out = real(bundle, facts, inputs)
        out["trace"] = [*out["trace"], "changed engine"]
        return out

    monkeypatch.setattr(simulation, "execute_inputs", changed)
    for original in (fresh, sim):  # with and without inputs
        now = c.get(f"/api/v1/survey-simulations/{original['id']}").json()
        assert now["status"] == "REPLAY_DRIFT" and now["replay_consistent"] is False
        assert now["run_status"] in ("PENDING", "TERMINAL")  # what the engine says now is still shown, labelled
        d = now["drift"]
        assert d["code"] == "REPLAY_DRIFT" and d["result_differs"] is True
        assert d["recorded_run_sha256"] == original["run_sha256"] != d["recomputed_run_sha256"] == now["run_sha256"]
        # … and nothing more is appended to a history that has moved
        pending = now["run"]["pending"]
        if pending:
            r = give(c, now, pending["key"], run["answers"][pending["key"]])
            assert (r.status_code, r.json()["code"]) == (409, "REPLAY_DRIFT")
    assert (
        db.execute(
            text("SELECT count(*) FROM survey_simulation_input WHERE simulation_id = :i"), {"i": fresh["id"]}
        ).scalar_one()
        == 0
    )
    monkeypatch.setattr(simulation, "execute_inputs", real)
    assert c.get(f"/api/v1/survey-simulations/{sim['id']}").json()["status"] != "REPLAY_DRIFT"

    # 2. the execution CONTRACT changes, even if this run happens to recompute the same
    monkeypatch.setattr(simulation, "CONTRACT", "call360.survey.execution/2")
    now = c.get(f"/api/v1/survey-simulations/{sim['id']}").json()
    assert now["status"] == "REPLAY_DRIFT" and now["drift"]["result_differs"] is False
    assert (now["drift"]["recorded_engine_contract"], now["drift"]["current_engine_contract"]) == (
        "call360.survey.execution/1",
        "call360.survey.execution/2",
    )
    newer = start(c, vid)  # a new simulation is recorded under the new contract and is consistent
    assert newer["engine_contract"] == "call360.survey.execution/2" and newer["replay_consistent"] is True
    monkeypatch.undo()

    # the same for a recorded plan: it is assembled again on reading, and a difference is reported
    plan = post(c, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}).json()
    assert plan["recompute_consistent"] is True and plan["recomputed_fingerprint"] == plan["fingerprint"]
    assert plan["plan_contract"] == plan["current_plan_contract"] == "call360.survey.call-plan/1"
    real_assemble = simulation.assemble
    monkeypatch.setattr(simulation, "assemble", lambda b, f: {**real_assemble(b, f), "fingerprint": "0" * 64})
    again = c.get(f"/api/v1/survey-call-plans/{plan['id']}").json()
    assert (
        again["recompute_consistent"] is False
        and again["fingerprint"] == plan["fingerprint"]
        and again["plan"] == plan["plan"]
    )
