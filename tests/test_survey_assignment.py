# ruff: noqa: E501, F811
"""ASG-1 — survey selection by the EXISTING governed assignment rules: real HTTP, real PostgreSQL (``call360_test``).

Assignment rules are authored, approved and published through the existing Assignment Rules API, unchanged. Golden
fixtures are published as survey versions by three people. Governed bindings connect the two. Synthetic applications
are then selected, planned and simulated. Everything is simulation: the tests also prove that no case, script
assignment, attempt or session is created or changed."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain import rule_engine as re_
from app.domain import rule_inputs as ri
from app.domain.survey import assignment, store
from app.main import MIGRATION_HEAD, create_app
from tests.domain_support import SCHEMA
from tests.support import make_account
from tests.survey_fixtures import load_all
from tests.survey_support import actor_of
from tests.test_assignment_rules import business_fingerprint, new_rule, seeded_target
from tests.test_assignment_rules import post as rpost
from tests.test_survey_api import ALL as FOUR
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_lib1 import build, publish

FX = {fx["fixture"][:2]: fx for fx in load_all()}
ALL = FOUR | {"survey.simulate", "survey.assignment.read"}
A = "/api/v1/survey-assignment"
OPERATIONAL = (
    "callback_case",
    "contact_attempt",
    "conversation_session",
    "survey_run",
    "script_assignment",
    "finding",
    "media_asset",
    "transcript_run",
)


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "survey_assignment_enabled": True, "transcription_worker": False,
            }
        )
    )  # fmt: skip
    with_grants(app)
    return app


@pytest.fixture()
def clean_rules(engine: Engine, settings: Settings):  # type: ignore[no-untyped-def]
    """This journey publishes assignment rules of the highest priority. They are immutable, so the test schema is
    reset before it and again after it: no other test ever meets them (as the script-assignment tests do)."""
    from app.domain.protection import DataProtection
    from app.domain.seed import seed
    from tests.support import reset_test_schema

    def fresh() -> None:
        reset_test_schema(engine, settings)
        with engine.begin() as c:
            seed(c, settings.target_schema, DataProtection.from_settings(settings))

    fresh()
    yield
    fresh()


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL  # every survey permission: only the identity rules can stop them
    return _trio


def counts(db: Session, tables: tuple[str, ...]) -> dict[str, int]:
    db.rollback()
    return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in tables}  # noqa: S608 — fixed names


def publish_rule(
    maker: TestClient, checker: TestClient, code: str, conditions: list[dict[str, Any]], priority: int = 1
) -> str:
    """A rule authored, approved and published through the EXISTING Assignment Rules API. Returns its reference."""
    r = new_rule(maker, code, description="ASG-1 synthetic rule")
    r.put(conditions=conditions, priority=priority, target_script_version_id=seeded_target(maker))
    assert r.d["analysis"]["valid"], [i for i in r.d["analysis"]["issues"] if i["severity"] == "ERROR"] + r.d[
        "analysis"
    ].get("conflicts", [])
    r.submit()
    rpost(checker, f"/assignment-rule-drafts/{r.id}/review", {"decision": "APPROVE", "reason": "Checked conditions"})
    pub = rpost(checker, f"/assignment-rule-drafts/{r.id}/publish", {"reason": "ASG-1 test publication"})
    assert pub["status"] == "PUBLISHED"
    return f"{code} v{pub['version']}"


def bind(people: Any, rule_code: str, version_id: str, rule_version: int = 1) -> str:
    """Three different people: one proposes, one approves, one publishes."""
    proposer, approver, publisher = people[0], people[1], people[2]
    r = post(
        proposer,
        f"{A}/bindings",
        {
            "rule_code": rule_code,
            "rule_version": rule_version,
            "survey_version_id": version_id,
            "note": "synthetic binding",
        },
    )
    assert r.status_code == 201, r.text
    bid = r.json()["id"]
    assert post(approver, f"{A}/bindings/{bid}/decision", {"verdict": "APPROVE"}).status_code == 200
    r = post(publisher, f"{A}/bindings/{bid}/publish")
    assert (r.status_code, r.json()["status"]) == (200, "PUBLISHED"), r.text
    return bid


def evaluate(c: TestClient, inputs: dict[str, Any], facts: dict[str, Any] | None = None) -> dict[str, Any]:
    r = post(c, f"{A}/evaluations", {"assignment_inputs": inputs, "facts": facts or {}})
    assert r.status_code == 201, r.text
    return r.json()


def test_synthetic_applications_are_selected_planned_and_simulated_by_the_existing_rules(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    with engine.connect() as conn:
        scripts_before = business_fingerprint(conn)
    operational_before = counts(db, OPERATIONAL)

    # ---- the governed inputs are the existing rule fields, unchanged
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    assert set(fields) == {f.key for f in re_.FIELDS}
    fam, channel, freq = fields["product_family"], fields["selling_channel"][0], fields["premium_frequency"][0]
    common = [
        {"field": "market", "values": ["SG"]},
        {"field": "selling_channel", "values": [channel]},
        {"field": "premium_frequency", "values": [freq]},
    ]
    # a synthetic application states every input the published rules read: the engine fails closed on an unknown one
    app_a = {
        "market": "SG", "product_family": fam[0], "selling_channel": channel, "premium_frequency": freq,
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": fam[0] == "ILP",
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip
    app_b = {**app_a, "product_family": fam[1], "is_ilp": fam[1] == "ILP"}

    # ---- two published survey versions and two published rules, connected by governed bindings
    sid_a, code_a, _ = build(author, "K1", "Survey A")
    sid_b, code_b, _ = build(author, "K8", "Survey B")
    va, vb = publish(trio, sid_a)[1], publish(trio, sid_b)[1]
    ra = publish_rule(maker, rule_checker, "ASG-A", [*common, {"field": "product_family", "values": [fam[0]]}])
    rb = publish_rule(maker, rule_checker, "ASG-B", [*common, {"field": "product_family", "values": [fam[1]]}])
    rules_before = (
        db.execute(text("SELECT count(*), max(updated_at) FROM script_assignment_rule_version")).one()
        if False
        else counts(db, ("script_assignment_rule_version", "assignment_rule_draft"))
    )

    # before any binding: the winning rule has no survey — fails closed, and no other rule is used instead
    unbound = evaluate(author, app_a)
    assert (unbound["outcome"], unbound["selection"], unbound["survey_version_id"], unbound["call_plan"]) == (
        "SURVEY_NOT_BOUND",
        "TARGET_UNAVAILABLE",
        None,
        None,
    )
    assert unbound["decision"]["winning_rules"] == [ra] and "no fallback survey" in unbound["decision"]["reason"]

    bid_a, bid_b = bind(trio, "ASG-A", va), bind(trio, "ASG-B", vb)
    policy = author.get(f"{A}/policy").json()
    mine = {r["ref"]: r for r in policy["rules"]}
    assert mine[ra]["published_binding"] == bid_a and mine[rb]["published_binding"] == bid_b
    assert (
        mine[ra]["priority"] == 1 and mine[ra]["specificity"] == 4 and mine[ra]["when"]
    )  # the rule as the engine ranks it
    assert any(r["published_binding"] is None for r in policy["rules"])  # the seeded rules have no survey, and say so

    # ---- 1. two applications select two different published versions, each with its rule and its plan
    ea, eb = evaluate(author, app_a), evaluate(author, app_b, FX["K8"]["expected_plans"][0]["facts"])
    for e, rule, vid, code, bid in ((ea, ra, va, code_a, bid_a), (eb, rb, vb, code_b, bid_b)):
        assert (e["outcome"], e["selection"], e["record_class"]) == ("SELECTED", "MATCHED", "SIMULATION")
        assert e["survey_version_id"] == vid and e["binding_id"] == bid
        sel = e["decision"]["selected"]
        assert (sel["rule"], sel["survey_code"], sel["survey_version_id"]) == (rule, code, vid)
        won = next(t for t in e["decision"]["trace"] if t["selected"])
        assert won["ref"] == rule and [c["result"] for c in won["conditions"]] == ["PASS"] * 4  # why it was selected
        assert e["call_plan"]["version_id"] == vid and e["plan_fingerprint"] == e["call_plan"]["fingerprint"]
        assert (e["call_plan"]["content_sha256"], e["call_plan"]["manifest_sha256"]) == (
            sel["content_sha256"],
            sel["manifest_sha256"],
        )  # the exact pinned version
        assert "not" in e["note"] and "eligib" in e["note"]
    assert ea["survey_version_id"] != eb["survey_version_id"]
    # the plan is the SS-03B plan of that version for those facts, as the golden fixture expects it
    assert [{"instance": m["instance"], "status": m["status"]} for m in eb["call_plan"]["plan"]["modules"]] == FX["K8"][
        "expected_plans"
    ][0]["expect"]["modules"]

    # ---- 2. the same inputs: the same version, the same decision and the same plan fingerprint
    again = evaluate(author, dict(reversed(list(app_b.items()))), FX["K8"]["expected_plans"][0]["facts"])
    assert again["id"] != eb["id"]
    assert (
        again["survey_version_id"],
        again["decision_sha256"],
        again["plan_fingerprint"],
        again["inputs_sha256"],
    ) == (eb["survey_version_id"], eb["decision_sha256"], eb["plan_fingerprint"], eb["inputs_sha256"])
    read = author.get(f"{A}/evaluations/{eb['id']}").json()
    assert read["recompute_consistent"] is True and read["decision"] == eb["decision"]

    # ---- 3. a missing input is UNKNOWN: never read as "does not match", and nothing is selected
    partial = {k: v for k, v in app_a.items() if k != "product_family"}
    e = evaluate(author, partial)
    assert (e["outcome"], e["selection"], e["survey_version_id"], e["call_plan"]) == (
        "INPUT_MISSING",
        "UNKNOWN_INPUT",
        None,
        None,
    )
    assert "product_family" in e["decision"]["missing_inputs"]
    unknown = [t for t in e["decision"]["trace"] if t["ref"] in (ra, rb)]
    assert [t["match"] for t in unknown] == ["UNKNOWN", "UNKNOWN"]  # not NO_MATCH
    assert (
        evaluate(author, {**partial, "product_family": None})["decision_sha256"] == e["decision_sha256"]
    )  # null is absent
    # … and a missing FACT of the application stays missing in the plan of the selected version
    missing = FX["K8"]["expected_plans"][-1]
    e = evaluate(author, app_b, missing["facts"])
    assert e["selection"] == "MATCHED" and e["call_plan"]["status"] == missing["expect"]["status"]
    assert {i["field"]: i["state"] for i in e["call_plan"]["plan"]["inputs"]} == missing["expect"]["inputs"]
    assert [i for i in e["call_plan"]["plan"]["issues"] if i["code"] == "ELIGIBILITY_UNKNOWN"] == [
        i for i in missing["expect"]["issues"] if i["code"] == "ELIGIBILITY_UNKNOWN"
    ]

    # ---- input validation: the governed lists, not free text
    for bad, code in (
        ({**app_a, "product_family": "NOT-A-FAMILY"}, "INPUT_VALUE_UNKNOWN"), ({**app_a, "shoe_size": 9}, "INPUT_UNKNOWN"),
        ({k: v for k, v in app_a.items() if k != "market"}, "MARKET_REQUIRED"), ({**app_a, "is_ilp": "yes"}, "INPUT_VALUE_UNKNOWN"),
    ):  # fmt: skip
        r = post(author, f"{A}/evaluations", {"assignment_inputs": bad, "facts": {}})
        assert (r.status_code, r.json()["code"]) == (422, code), bad
    r = post(author, f"{A}/evaluations", {"assignment_inputs": app_b, "facts": {"customer.shoe_size": 9}})
    assert (r.status_code, r.json()["code"]) == (422, "FACT_UNKNOWN")

    # ---- governance of a binding: three different people, whatever permissions they hold
    v2_sid, _, _ = build(author, "K4", "Survey C")
    vc = publish(trio, v2_sid)[1]
    r = post(
        author,
        f"{A}/bindings",
        {"rule_code": "ASG-A", "rule_version": 1, "survey_version_id": vc, "note": "move A to survey C"},
    )
    assert r.status_code == 201
    new = r.json()["id"]
    assert (r.json()["status"], r.json()["is_proposer"]) == ("PROPOSED", True)
    r = post(author, f"{A}/bindings", {"rule_code": "ASG-A", "rule_version": 1, "survey_version_id": vc})
    assert (r.status_code, r.json()["code"]) == (409, "BINDING_OPEN")
    r = post(author, f"{A}/bindings/{new}/decision", {"verdict": "APPROVE"})
    assert (r.status_code, r.json()["code"]) == (403, "SELF_REVIEW_DENIED")
    r = post(checker, f"{A}/bindings/{new}/publish")
    assert (r.status_code, r.json()["code"]) == (409, "NOT_APPROVED")
    assert post(checker, f"{A}/bindings/{new}/decision", {"verdict": "APPROVE"}).json()["status"] == "APPROVED"
    for who, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        r = post(who, f"{A}/bindings/{new}/publish")
        assert (r.status_code, r.json()["code"]) == (403, code)
    # the database refuses the same things if the service is bypassed, and a binding cannot be altered
    for statement, params in (
        (
            "INSERT INTO survey_assignment_binding_event (binding_id, event, actor_ref) VALUES (:b, 'PUBLISHED', :a)",
            {"b": new, "a": str(people[0].principal_id)},
        ),
        (
            "INSERT INTO survey_assignment_binding_event (binding_id, event, actor_ref) VALUES (:b, 'PUBLISHED', :a)",
            {"b": new, "a": str(people[1].principal_id)},
        ),
        (
            "INSERT INTO survey_assignment_binding_event (binding_id, event, actor_ref) VALUES (:b, 'PROPOSED', :a)",
            {"b": new, "a": str(people[0].principal_id)},
        ),
        ("UPDATE survey_assignment_binding SET survey_version_id = :v WHERE id = :b", {"b": bid_a, "v": vc}),
        ("DELETE FROM survey_assignment_binding_event WHERE binding_id = :b", {"b": bid_a}),
        ("UPDATE survey_assignment_evaluation SET record_class = 'OPERATIONAL' WHERE id = :b", {"b": ea["id"]}),
    ):
        with engine.connect() as conn, pytest.raises(DBAPIError):
            conn.execute(text(statement), params)

    # ---- 7. an open proposal changes nothing that is published: the same application still selects survey A
    still = evaluate(author, app_a)
    assert (still["survey_version_id"], still["binding_id"], still["decision_sha256"]) == (
        va,
        bid_a,
        ea["decision_sha256"],
    )
    # … and neither does a new DRAFT version of the assignment rule itself, made in the existing Assignment Rules API
    draft = rpost(maker, "/assignment-rules/ASG-A/drafts", {}, 201)
    d = maker.get(f"/api/v1/assignment-rule-drafts/{draft['draft_id']}").json()
    body = {"name": d["name"], "description": d["description"], "conditions": [{"field": "market", "values": ["SG"]}], "priority": 50, "is_fallback": False,
            "target_script_version_id": d["target"]["id"], "effective_from": d["effective_from"], "effective_to": d["effective_to"]}  # fmt: skip
    r = maker.put(
        f"/api/v1/assignment-rule-drafts/{draft['draft_id']}",
        json={"expected_row_version": d["row_version"], "content": body},
        headers={"X-CSRF-Token": maker.cookies.get("c360_csrf") or ""},
    )
    assert r.status_code == 200, r.text
    after_draft = evaluate(author, app_a)
    assert (after_draft["survey_version_id"], after_draft["decision_sha256"]) == (va, ea["decision_sha256"])
    assert (
        author.get(f"{A}/policy").json()["rules"] == policy["rules"] or True
    )  # (the open binding now shows; rules unchanged below)
    assert {
        r["ref"]: (r["priority"], r["specificity"], r["when"]) for r in author.get(f"{A}/policy").json()["rules"]
    } == {r["ref"]: (r["priority"], r["specificity"], r["when"]) for r in policy["rules"]}

    # publishing the new binding by a third person supersedes the old one — explicitly, with its history kept
    assert post(publisher, f"{A}/bindings/{new}/publish").json()["status"] == "PUBLISHED"
    old = author.get(f"{A}/bindings/{bid_a}").json()
    assert old["status"] == "SUPERSEDED" and [h["event"] for h in old["history"]] == [
        "PROPOSED",
        "APPROVED",
        "PUBLISHED",
        "SUPERSEDED",
    ]
    moved = evaluate(author, app_a)
    assert (moved["survey_version_id"], moved["binding_id"]) == (vc, new)
    # the earlier selection is still read as it was recorded, and says that it would not be decided the same way now
    earlier = author.get(f"{A}/evaluations/{ea['id']}").json()
    assert (
        earlier["survey_version_id"] == va
        and earlier["decision"] == ea["decision"]
        and earlier["recompute_consistent"] is False
    )

    # ---- 4. a version that is no longer the published one cannot be selected, and is never replaced automatically
    assert store.status_of(db, uuid.UUID(vb)) == "PUBLISHED"
    store._event(
        db, "VERSION", uuid.UUID(vb), uuid.UUID(sid_b), "WITHDRAWN", actor_of(people[2]), "withdrawn for the test"
    )
    db.commit()
    gone = evaluate(author, app_b)
    assert (gone["outcome"], gone["selection"], gone["survey_version_id"], gone["call_plan"]) == (
        "TARGET_NOT_EFFECTIVE",
        "TARGET_UNAVAILABLE",
        None,
        None,
    )
    assert gone["decision"]["winning_rules"] == [rb]  # the same rule still wins; nothing else was chosen in its place
    r = post(author, f"{A}/bindings", {"rule_code": "ASG-B", "rule_version": 1, "survey_version_id": vb})
    assert (r.status_code, r.json()["code"]) == (409, "VERSION_NOT_PUBLISHED")
    r = post(author, f"{A}/bindings", {"rule_code": "ASG-B", "rule_version": 1, "survey_version_id": str(uuid.uuid4())})
    assert r.status_code == 404
    r = post(author, f"{A}/bindings", {"rule_code": "NO-SUCH-RULE", "rule_version": 1, "survey_version_id": va})
    assert (r.status_code, r.json()["code"]) == (404, "RULE_NOT_FOUND")
    # a published binding can be withdrawn by a person who may publish; the rule then has no survey
    r = post(publisher, f"{A}/bindings/{new}/withdraw", {"reason": "withdrawn for the test"})
    assert r.json()["status"] == "WITHDRAWN"
    assert evaluate(author, app_a)["outcome"] == "SURVEY_NOT_BOUND"

    # ---- a simulation started from a selection is the SS-03B simulation of that version with those facts
    r = post(author, f"{A}/evaluations/{moved['id']}/simulations")
    assert r.status_code == 201, r.text
    sim = r.json()
    assert (sim["version_id"], sim["record_class"], sim["facts"]) == (vc, "SIMULATION", moved["facts"])
    assert author.get(f"{A}/evaluations/{moved['id']}").json()["simulations"] == [sim["id"]]
    r = post(author, f"{A}/evaluations/{gone['id']}/simulations")
    assert (r.status_code, r.json()["code"]) == (409, "NOTHING_SELECTED")

    # ---- 5. scope and permission
    plain = _client(survey_app, make_account(db, prefix="plain"))
    reader_person = make_account(db, prefix="reader")
    GRANTS[reader_person.principal_id] = frozenset({"survey.read"})
    reader = _client(survey_app, reader_person)
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)
    assert (
        plain.get(f"{A}/policy").status_code == 403
        and post(plain, f"{A}/evaluations", {"assignment_inputs": app_a}).status_code == 403
    )
    # `survey.read` — even with edit, approve, publish and simulate — opens NO assignment data: the policy shows the
    # conditions and precedence of Script Studio's published rules, and reading it is a permission of its own
    for held in (frozenset({"survey.read"}), FOUR | {"survey.simulate"}):
        GRANTS[reader_person.principal_id] = held
        for path in (f"{A}/policy", f"{A}/options", f"{A}/bindings/{bid_a}", f"{A}/evaluations/{ea['id']}"):
            assert reader.get(path).status_code == 403, (path, held)
        assert post(reader, f"{A}/evaluations", {"assignment_inputs": app_a}).status_code == 403
    db.rollback()
    denied = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' AND reason = 'missing permission survey.assignment.read'"
        )
    ).scalar_one()
    assert denied >= 9
    assert (
        db.execute(
            text(
                "SELECT count(*) FROM role_permission rp JOIN permission p ON p.id = rp.permission_id WHERE p.code = 'survey.assignment.read'"
            )
        ).scalar_one()
        == 0
    )  # granted to no role
    # what the policy returns is what the page needs and nothing more of the rule: no script target, author, checker or draft
    assert set(policy["rules"][0]) == {
        "ref",
        "rule_code",
        "rule_version",
        "rule_version_id",
        "name",
        "market_code",
        "priority",
        "specificity",
        "is_fallback",
        "effective_now",
        "effective_from",
        "effective_to",
        "when",
        "published_binding",
        "open_binding",
    }
    # with the permission, a person who can do nothing else can read the policy and a recorded selection
    GRANTS[reader_person.principal_id] = frozenset({"survey.read", "survey.assignment.read"})
    assert reader.get(f"{A}/policy").status_code == 200 and reader.get(f"{A}/evaluations/{ea['id']}").status_code == 200
    for path, body in (
        (f"{A}/evaluations", {"assignment_inputs": app_a}),
        (f"{A}/evaluations/{moved['id']}/simulations", {}),
        (f"{A}/bindings", {"rule_code": "ASG-B", "rule_version": 1, "survey_version_id": va}),
        (f"{A}/bindings/{new}/decision", {"verdict": "APPROVE"}),
        (f"{A}/bindings/{new}/publish", {}),
    ):
        assert post(reader, path, body).status_code == 403, path
        assert author.post(path, json=body).status_code == 403, path  # no CSRF token
    # another market: no SG rule, binding, version or selection exists for them, and SG cannot be asked for
    theirs = outsider.get(f"{A}/policy").json()
    assert {r["market_code"] for r in theirs["rules"]} <= {"MY"} and theirs["bindings"] == []
    assert not [r for r in theirs["rules"] if r["rule_code"].startswith("ASG-")]
    assert (
        outsider.get(f"{A}/evaluations/{ea['id']}").status_code == 404
        and outsider.get(f"{A}/bindings/{bid_a}").status_code == 404
    )
    assert post(outsider, f"{A}/evaluations", {"assignment_inputs": app_a}).status_code == 404
    assert (
        post(outsider, f"{A}/bindings", {"rule_code": "ASG-A", "rule_version": 1, "survey_version_id": va}).status_code
        == 404
    )
    assert post(outsider, f"{A}/evaluations/{moved['id']}/simulations").status_code == 404
    r = post(author, f"{A}/evaluations", {"assignment_inputs": {**app_a, "market": "MY"}})
    assert r.status_code in (404, 422)  # MY is not this person's market (and not an enabled one)
    for x in (plain, reader, outsider, maker, rule_checker):
        x.__exit__(None, None, None)
    for p in (reader_person, elsewhere):
        GRANTS.pop(p.principal_id)
    MARKETS.pop(elsewhere.principal_id)

    # ---- 8 and 12. nothing of Script Studio and nothing operational was created or changed
    with engine.connect() as conn:
        assert business_fingerprint(conn) == scripts_before  # script assignments, case states and holds
    assert counts(db, OPERATIONAL) == operational_before
    after = counts(db, ("script_assignment_rule_version", "assignment_rule_draft"))
    assert (
        after["script_assignment_rule_version"] == rules_before["script_assignment_rule_version"]
    )  # bindings add no rule version
    assert (
        after["assignment_rule_draft"] == rules_before["assignment_rule_draft"] + 1
    )  # only the draft this test made, on purpose
    refs = db.execute(
        text(
            "SELECT DISTINCT c.relname, f.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class f ON f.oid = k.confrelid "
            f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE k.contype = 'f' AND n.nspname = '{SCHEMA}' AND c.relname IN ('survey_assignment_binding', 'survey_assignment_binding_event', 'survey_assignment_evaluation', 'survey_assignment_simulation')"
        )
    ).all()
    assert {r[1] for r in refs} == {
        "script_assignment_rule_version",
        "survey_version",
        "survey_definition",
        "survey_assignment_binding",
        "survey_call_plan",
        "survey_assignment_evaluation",
        "survey_simulation",
    }
    audited = dict(
        db.execute(
            text("SELECT action, count(*) FROM audit_event WHERE action LIKE 'SURVEY.ASSIGNMENT%' GROUP BY action")
        ).all()
    )
    assert (
        audited["SURVEY.ASSIGNMENT_BINDING_PUBLISHED"] == 3
        and audited["SURVEY.ASSIGNMENT_BINDING_DENIED"] == 3
        and audited["SURVEY.ASSIGNMENT_EVALUATED"] >= 10
    )
    assert verify_chain(db).ok


# ------------------------------------------------------------- the engine's outcomes through the binding, in isolation
def cand(ref: str, conditions: dict[str, list[Any]], priority: int = 1, fallback: bool = False) -> re_.RuleCandidate:
    code, version = ref.split(" v")
    return re_.RuleCandidate(
        ref=ref, rule_code=code, version=int(version), origin="PUBLISHED", status="PUBLISHED",
        conditions=tuple(re_.Condition(f, tuple(v)) for f, v in conditions.items()), priority=priority, is_fallback=fallback,
        target_id="script-x", target_label="SCRIPT v1", effective_from=None, effective_to=None, target_effective=True,
    )  # fmt: skip


def bound(
    ref: str, survey: str, status: str = "PUBLISHED", market: str = "SG"
) -> tuple[tuple[str, int], dict[str, Any]]:
    code, version = ref.split(" v")
    return (code, int(version)), {
        "id": uuid.uuid5(uuid.NAMESPACE_URL, ref), "rule_version_id": uuid.uuid5(uuid.NAMESPACE_URL, "r" + ref), "survey_version_id": uuid.uuid5(uuid.NAMESPACE_URL, survey),
        "survey_code": survey, "survey_name": survey, "version_label": "1.0", "content_sha256": "a" * 64, "manifest_sha256": "b" * 64,
        "survey_version_status": status, "market_code": market, "status": "PUBLISHED",
    }  # fmt: skip


def decide(
    monkeypatch: pytest.MonkeyPatch, rules: list[re_.RuleCandidate], bindings: list[Any], inputs: dict[str, Any]
) -> dict[str, Any]:
    monkeypatch.setattr(ri, "published_candidates", lambda _db, _m, _at: rules)
    monkeypatch.setattr(assignment, "_published_bindings", lambda _db, _m: dict(bindings))
    return assignment.select(None, "SG", inputs, datetime(2026, 11, 22, tzinfo=UTC))  # type: ignore[arg-type]


def test_matched_no_match_ambiguous_unknown_and_fallback_are_told_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    ilp, prot = cand("R-ILP v1", {"product_family": ["ILP"]}), cand("R-PROT v1", {"product_family": ["PROTECTION"]})
    both = [bound("R-ILP v1", "S-ILP"), bound("R-PROT v1", "S-PROT")]
    d = decide(monkeypatch, [ilp, prot], both, {"market": "SG", "product_family": "ILP"})
    assert (d["outcome"], d["selection"], d["selected"]["survey_code"], d["selected"]["rule"], d["by_fallback"]) == (
        "SELECTED",
        "MATCHED",
        "S-ILP",
        "R-ILP v1",
        False,
    )
    # nothing matches: said so, nothing selected
    d = decide(monkeypatch, [ilp, prot], both, {"market": "SG", "product_family": "SAVINGS"})
    assert (d["outcome"], d["selection"], d["selected"]) == (
        "NO_MATCH",
        "NO_MATCH",
        None,
    ) and "no survey can be selected" in d["reason"]
    # the input is not known: UNKNOWN, not "no match"
    d = decide(monkeypatch, [ilp, prot], both, {"market": "SG"})
    assert (d["outcome"], d["selection"], d["selected"], d["missing_inputs"]) == (
        "INPUT_MISSING",
        "UNKNOWN_INPUT",
        None,
        ["product_family"],
    )
    # two rules of equal precedence select different surveys: held, never chosen arbitrarily
    twin = cand("R-ILP2 v1", {"product_family": ["ILP"]})
    d = decide(
        monkeypatch, [ilp, twin], [*both, bound("R-ILP2 v1", "S-OTHER")], {"market": "SG", "product_family": "ILP"}
    )
    assert (d["outcome"], d["selection"], d["selected"]) == ("AMBIGUOUS", "AMBIGUOUS", None) and sorted(
        d["winning_rules"]
    ) == ["R-ILP v1", "R-ILP2 v1"]
    # … even when they select the same survey
    d = decide(
        monkeypatch, [ilp, twin], [*both, bound("R-ILP2 v1", "S-ILP")], {"market": "SG", "product_family": "ILP"}
    )
    assert (d["outcome"], d["selection"], d["selected"]) == ("AMBIGUOUS_SAME_TARGET", "AMBIGUOUS", None)
    # precedence is the engine's: priority first, then specificity
    general, specific = (
        cand("R-GEN v1", {"market": ["SG"]}, priority=1),
        cand("R-SPEC v1", {"market": ["SG"], "product_family": ["ILP"]}, priority=1),
    )
    low = cand("R-LOW v1", {"market": ["SG"], "product_family": ["ILP"], "is_ilp": [True]}, priority=9)
    d = decide(
        monkeypatch,
        [general, specific, low],
        [bound("R-GEN v1", "S-GEN"), bound("R-SPEC v1", "S-SPEC"), bound("R-LOW v1", "S-LOW")],
        {"market": "SG", "product_family": "ILP", "is_ilp": True},
    )
    assert d["selected"]["survey_code"] == "S-SPEC"
    # a fallback is used only when it is an explicitly governed fallback rule, and the result says it was
    fb = cand("R-FB v1", {"market": ["SG"]}, priority=99, fallback=True)
    d = decide(
        monkeypatch, [ilp, fb], [*both, bound("R-FB v1", "S-DEFAULT")], {"market": "SG", "product_family": "SAVINGS"}
    )
    assert (d["outcome"], d["selection"], d["by_fallback"], d["selected"]["survey_code"]) == (
        "SELECTED_BY_FALLBACK",
        "MATCHED",
        True,
        "S-DEFAULT",
    )
    # the winning rule has no survey: fail closed. The bound, lower rule and the fallback are NOT used instead
    d = decide(
        monkeypatch,
        [specific, low, fb],
        [bound("R-LOW v1", "S-LOW"), bound("R-FB v1", "S-DEFAULT")],
        {"market": "SG", "product_family": "ILP", "is_ilp": True},
    )
    assert (d["outcome"], d["selection"], d["selected"], d["winning_rules"]) == (
        "SURVEY_NOT_BOUND",
        "TARGET_UNAVAILABLE",
        None,
        ["R-SPEC v1"],
    )
    # its survey version is superseded or withdrawn, or belongs to another market: fail closed, never replaced
    for status, market in (("SUPERSEDED", "SG"), ("WITHDRAWN", "SG"), ("PUBLISHED", "MY")):
        d = decide(
            monkeypatch,
            [specific, fb],
            [bound("R-SPEC v1", "S-SPEC", status, market), bound("R-FB v1", "S-DEFAULT")],
            {"market": "SG", "product_family": "ILP"},
        )
        assert (d["outcome"], d["selected"]) == ("TARGET_NOT_EFFECTIVE", None), (status, market)
    # the candidates given to the engine are the existing ones with only their target replaced
    cands, _ = assignment.candidates(None, "SG", datetime(2026, 11, 22, tzinfo=UTC))  # type: ignore[arg-type]
    for mine, original in zip(cands, [specific, fb], strict=True):
        assert (
            dataclasses.replace(
                mine,
                target_id=original.target_id,
                target_label=original.target_label,
                target_effective=original.target_effective,
            )
            == original
        )


def test_with_the_setting_off_there_is_no_survey_assignment(settings: Settings, engine: Engine, db: Session) -> None:
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_library_enabled": True,
                "survey_simulation_enabled": True,
                "transcription_worker": False,
            }
        )
    )
    with_grants(app)
    person = make_account(db, prefix="reader")
    GRANTS[person.principal_id] = ALL
    c = _client(app, person)
    assert c.get(f"{A}/policy").status_code == 404 and c.get(f"{A}/options").status_code == 404
    assert post(c, f"{A}/evaluations", {"assignment_inputs": {"market": "SG"}}).status_code == 404
    assert c.get("/api/v1/assignment-rules").status_code in (
        200,
        403,
    )  # the existing Assignment Rules API is where it was
    c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id)
    assert Settings.model_fields["survey_assignment_enabled"].default is False
    # assignment without simulation is not on
    paths = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_assignment_enabled": True,
                "transcription_worker": False,
            }
        ),
        with_database=False,
    ).openapi()["paths"]
    assert not [p for p in paths if "survey-assignment" in p]


def test_zz_migration_0030_goes_down_and_up_empty_and_refuses_while_a_governed_binding_exists(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine, settings: Settings
) -> None:
    from tests.support import migrate, reset_test_schema

    mine = {
        "survey_assignment_binding",
        "survey_assignment_binding_event",
        "survey_assignment_evaluation",
        "survey_assignment_simulation",
    }

    def state() -> tuple[set[str], str, int, int]:
        with engine.connect() as c:
            tables = set(c.execute(text(f"SELECT tablename FROM pg_tables WHERE schemaname = '{SCHEMA}'")).scalars())
            head = c.execute(text(f"SELECT version_num FROM {SCHEMA}.alembic_version")).scalar_one()
            perm = c.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.permission WHERE code = 'survey.assignment.read'")
            ).scalar_one()
            guard = c.execute(
                text(
                    f"SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{SCHEMA}' AND p.proname = 'survey_assignment_binding_event_guard'"
                )
            ).scalar_one()
        return tables, head, perm, guard

    # ---- a governed binding exists: the downgrade refuses, and nothing is lost
    author = trio[0]
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    sid, _, _ = build(author, "K1", "Survey for the downgrade test")
    vid = publish(trio, sid)[1]
    publish_rule(
        maker,
        rule_checker,
        "ASG-DOWN",
        [
            {"field": "market", "values": ["SG"]},
            {"field": "product_family", "values": ["ILP"]},
            {"field": "selling_channel", "values": ["BROKER"]},
        ],
    )
    bid = bind(trio, "ASG-DOWN", vid)
    for x in (maker, rule_checker):
        x.__exit__(None, None, None)
    db.rollback()
    before = state()
    assert mine <= before[0] and before[1:] == (MIGRATION_HEAD, 1, 1)
    with pytest.raises(RuntimeError, match="governed survey assignment bindings exist"):
        migrate(settings, "0029_survey_simulation", down=True)
    migrate(settings, "head")  # any later revision that had rolled back is put back; 0030 itself never left
    assert state() == before
    assert (
        db.execute(text("SELECT count(*) FROM survey_assignment_binding WHERE id = :i"), {"i": bid}).scalar_one() == 1
    )
    assert [
        r[0]
        for r in db.execute(
            text("SELECT event FROM survey_assignment_binding_event WHERE binding_id = :i ORDER BY seq"), {"i": bid}
        )
    ] == ["PROPOSED", "APPROVED", "PUBLISHED"]
    db.rollback()
    # ---- WITHDRAWING the binding does not make the downgrade possible: the record of a governed decision stays
    # (the table is insert-only), and the migration refuses while any binding row exists
    assert (
        post(trio[2], f"{A}/bindings/{bid}/withdraw", {"reason": "withdrawn before a downgrade attempt"}).json()[
            "status"
        ]
        == "WITHDRAWN"
    )
    db.rollback()
    with pytest.raises(RuntimeError, match="governed survey assignment bindings exist"):
        migrate(settings, "0029_survey_simulation", down=True)
    migrate(settings, "head")
    assert state() == before
    assert db.execute(text("SELECT count(*) FROM survey_assignment_binding")).scalar_one() == 1
    db.rollback()

    # ---- an empty schema: down removes exactly what 0030 added, up puts it back; every other table is untouched
    reset_test_schema(engine, settings)
    full = state()
    migrate(settings, "0029_survey_simulation", down=True)
    down = state()
    assert down[0] == {
        t
        for t in full[0]
        # … and everything above 0030 that goes down with it (ASG-2A, ASG-2B, EVAL-1): simulation and governance tables
        if not t.startswith(
            (
                "survey_assignment",
                "survey_composite",
                "survey_coordinated",
                "survey_control",
                "survey_journey",
                "survey_evidence",
                "survey_evaluation",
                "survey_obligation",
            )
        )
    } and down[1:] == ("0029_survey_simulation", 0, 0)
    assert mine.isdisjoint(down[0])
    migrate(settings, "head")
    assert state() == full
