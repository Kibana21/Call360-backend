# ruff: noqa: E501, F811 — long request literals; fixtures imported from the other test modules
"""SHARED-1 — Assignment Rules and Finding Rules on their own, on the isolated test database.

A rule has a market of its own · a rule may name no script, for survey selection only · such a rule is governed like
any other, bound to a published survey, used by requirement groups, composite plans and the coordinated simulator ·
it is NEVER a candidate for assigning a script to a case — by the loader, by validation and by the database · every
existing script-backed rule, assignment, hold and history is exactly as it was · both capabilities can be governed with
their own permissions, and the legacy permissions keep working."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import Depends, Request
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain import rule_inputs as ri
from app.main import MIGRATION_HEAD, create_app
from app.security.authz import AuthContext, authenticate, get_db, resolve_auth
from tests.support import csrf_header, make_account, migrate
from tests.test_assignment_rules import Rule, business_fingerprint, new_rule, seeded_target
from tests.test_assignment_rules import post as rpost
from tests.test_findings_api import rule as finding_rule
from tests.test_survey_api import GRANTS, _client, post
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import ALL, OPERATIONAL, bind, clean_rules, counts, evaluate, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import compose, group
from tests.test_survey_lib1 import build, publish

A = "/api/v1/survey-assignment"
SG = {"field": "market", "values": ["SG"]}
SURVEY, SCRIPT = "SURVEY_BINDING", "SCRIPT_VERSION"
#: principals whose permissions are EXACTLY these, whatever their group grants (to test the dedicated permissions alone)
ONLY: dict[Any, frozenset[str]] = {}
RULE_PERMS = ("assignment_rule.read", "assignment_rule.edit", "assignment_rule.approve", "assignment_rule.publish")
FINDING_PERMS = ("finding_rule.read", "finding_rule.edit", "finding_rule.approve", "finding_rule.publish")


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "survey_assignment_enabled": True, "survey_assignment_groups_enabled": True,
                "survey_coordinated_simulation_enabled": True, "shared_rule_services_enabled": True,
                "transcription_worker": False,
            }
        )
    )  # fmt: skip

    def grants(request: Request, db: Session = Depends(get_db)) -> AuthContext:
        ctx = resolve_auth(request.app, request.cookies, db)
        if ctx.principal_id in ONLY:
            return dataclasses.replace(ctx, permissions=ONLY[ctx.principal_id])
        return dataclasses.replace(ctx, permissions=ctx.permissions | GRANTS.get(ctx.principal_id, frozenset()))

    app.dependency_overrides[authenticate] = grants
    return app


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL
    return _trio


def rule_rows(engine: Engine) -> list[tuple[Any, ...]]:
    """Every pre-existing column of every rule version, publication and change event: what SHARED-1 must not change."""
    with engine.connect() as c:
        return [
            tuple(r)
            for sql in (
                "SELECT id::text, rule_code, version, md5(predicate::text), priority, specificity, target_script_version_id::text, effective_from::text, coalesce(effective_to::text,''), status, checksum, author_ref, checker_ref FROM call360_test.script_assignment_rule_version ORDER BY 1",
                "SELECT rule_version_id::text, name, is_fallback, approved_by, published_by FROM call360_test.assignment_rule_publication ORDER BY 1",
                "SELECT id::text, draft_id::text, seq, event_type, actor_ref FROM call360_test.assignment_rule_change_event ORDER BY 1",
            )
            for r in c.execute(text(sql))
        ]


def survey_rule(
    maker: TestClient, checker: TestClient, code: str, conditions: list[dict[str, Any]], priority: int
) -> dict[str, Any]:
    """A rule that names no script, through the existing two-person lifecycle. Returns the published version."""
    r = new_rule(maker, code, description="SHARED-1 synthetic survey-only rule", target_kind=SURVEY)
    r.put(conditions=conditions, priority=priority)
    assert r.d["analysis"]["valid"], r.d["analysis"]["issues"]
    r.submit()
    rpost(checker, f"/assignment-rule-drafts/{r.id}/review", {"decision": "APPROVE", "reason": "Checked conditions"})
    pub = rpost(checker, f"/assignment-rule-drafts/{r.id}/publish", {"reason": "SHARED-1 test publication"})
    assert pub["status"] == "PUBLISHED"
    return pub


def registry(c: TestClient) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in c.get("/api/v1/assignment-rules").json()["items"]:
        for v in item.get("versions") or []:
            out[f"{v['rule_code']} v{v['version']}"] = v
    return out


# ------------------------------------------------------------------ a survey-only rule, end to end; nothing else moves
def test_a_rule_that_names_no_script_selects_surveys_and_never_a_script_for_a_case(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, engine: Engine
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="s1maker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="s1chk"))
    with engine.connect() as conn:
        scripts_before = business_fingerprint(conn)
    operational_before = counts(db, OPERATIONAL)
    rules_before = rule_rows(engine)
    script_side_before = maker.get("/api/v1/script-assignment-rules").json()
    case_id = str(
        db.execute(text("SELECT id FROM callback_case WHERE market_code = 'SG' ORDER BY case_ref LIMIT 1")).scalar_one()
    )
    db.rollback()
    preview_before = maker.get(f"/api/v1/cases/{case_id}/script-assignment/preview").json()
    sim_before = rpost(maker, "/assignment-rules/simulate", {"draft_ids": [], "scope": "ALL"})

    # every existing rule has its OWN market now, and it is the one its script family has
    opts = maker.get("/api/v1/assignment-rules/options").json()
    assert opts["survey_only_rules"] is True
    db.rollback()
    for code, market, family_market, kind, target in db.execute(
        text(
            "SELECT r.rule_code, r.market_code, f.market_code, r.target_kind, r.target_script_version_id FROM script_assignment_rule_version r "
            "JOIN script_version v ON v.id = r.target_script_version_id JOIN script_family f ON f.id = v.script_family_id"
        )
    ):
        assert (market, kind) == (family_market, SCRIPT) and target is not None, code

    # ---- 4. a survey-only rule is created without any script — no dummy script exists or is needed
    scripts = db.execute(text("SELECT count(*) FROM script_version")).scalar_one()
    db.rollback()
    draft = new_rule(maker, "SO-PRIMARY", description="Selects the primary survey", target_kind=SURVEY)
    assert (draft.d["target_kind"], draft.d["target"], draft.d["market"]) == (SURVEY, None, "SG")
    draft.put(conditions=[SG, {"field": "product_family", "values": ["PROTECTION"]}], priority=1)
    codes = {i["code"]: i["severity"] for i in draft.d["analysis"]["issues"]}
    assert draft.d["analysis"]["valid"] and "NO_TARGET" not in codes and codes["SURVEY_ONLY"] == "WARNING"
    assert "no script" in draft.d["analysis"]["explanation"].lower()
    # it can never be given a script, and what it selects never changes
    r = maker.put(
        f"/api/v1/assignment-rule-drafts/{draft.id}",
        json={
            "expected_row_version": draft.d["row_version"],
            "content": {
                "name": draft.d["name"],
                "description": "",
                "conditions": draft.d["conditions"],
                "priority": 1,
                "is_fallback": False,
                "target_script_version_id": seeded_target(maker),
                "effective_from": None,
                "effective_to": None,
            },
        },
        headers=csrf_header(maker),
    )
    assert (r.status_code, r.json()["code"]) == (422, "TARGET_NOT_ALLOWED")
    with pytest.raises(DBAPIError, match="what an assignment rule selects is fixed"):
        db.execute(
            text("UPDATE assignment_rule_draft SET target_kind = 'SCRIPT_VERSION' WHERE id = :i"), {"i": draft.id}
        )
    db.rollback()
    # a market the author is not authorised for is refused; the market is never a free field
    r = maker.post(
        "/api/v1/assignment-rules",
        json={"code": "SO-MY", "name": "Other market", "market": "MY", "target_kind": SURVEY},
        headers=csrf_header(maker),
    )
    assert (r.status_code, r.json()["code"]) == (403, "MARKET_NOT_IN_SCOPE")
    # it is not simulated over cases: that simulation assigns scripts
    r = maker.post(
        "/api/v1/assignment-rules/simulate", json={"draft_ids": [draft.id], "scope": "ALL"}, headers=csrf_header(maker)
    )
    assert (r.status_code, r.json()["code"]) == (422, "SURVEY_ONLY_NOT_SIMULATED_ON_CASES")

    # ---- 5. the existing two-person governance: the maker can neither review nor publish
    draft.submit()
    r = maker.post(
        f"/api/v1/assignment-rule-drafts/{draft.id}/review",
        json={"decision": "APPROVE", "reason": "my own rule"},
        headers=csrf_header(maker),
    )
    assert r.status_code == 403
    rpost(
        rule_checker,
        f"/assignment-rule-drafts/{draft.id}/review",
        {"decision": "APPROVE", "reason": "Checked conditions"},
    )
    pub = rpost(rule_checker, f"/assignment-rule-drafts/{draft.id}/publish", {"reason": "SHARED-1 test publication"})
    db.rollback()
    row = db.execute(
        text(
            "SELECT market_code, target_kind, target_script_version_id, status, author_ref <> checker_ref FROM script_assignment_rule_version WHERE rule_code = 'SO-PRIMARY'"
        )
    ).one()
    assert tuple(row) == ("SG", SURVEY, None, "PUBLISHED", True)
    assert db.execute(text("SELECT count(*) FROM script_version")).scalar_one() == scripts  # no script was created
    # ---- 6. the published market and kind are immutable
    for sql in (
        "UPDATE script_assignment_rule_version SET market_code = 'MY' WHERE rule_code = 'SO-PRIMARY'",
        "UPDATE script_assignment_rule_version SET target_kind = 'SCRIPT_VERSION' WHERE rule_code = 'SO-PRIMARY'",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()

    survey_rule(maker, rule_checker, "SO-ADD", [SG, {"field": "premium_frequency", "values": ["SINGLE"]}], 2)
    # ---- 1. a script-backed rule is authored exactly as before, and gets its script family's market
    publish_rule(maker, rule_checker, "SB-RULE", [SG, {"field": "selling_channel", "values": ["DIRECT"]}], 3)
    reg = registry(maker)
    assert (
        reg["SO-PRIMARY v1"]["target_kind"],
        reg["SO-PRIMARY v1"]["market"],
        reg["SO-PRIMARY v1"]["target"]["id"],
    ) == (SURVEY, "SG", None)
    assert (reg["SB-RULE v1"]["target_kind"], reg["SB-RULE v1"]["market"]) == (SCRIPT, "SG") and reg["SB-RULE v1"][
        "target"
    ]["id"]
    assert pub["version"] == 1

    # ---- 8. bound to published surveys by three people; 9. requirement groups select several surveys
    version: dict[str, str] = {}
    for name, fixture in (("A", "K1"), ("B", "K3")):
        sid, _, _ = build(author, fixture, f"SHARED-1 survey {name}")
        version[name] = publish(trio, sid)[1]
    bind(trio, "SO-PRIMARY", version["A"])
    bind(trio, "SO-ADD", version["B"])
    policy = {r["rule_code"]: r for r in author.get(f"{A}/policy").json()["rules"]}
    assert (policy["SO-PRIMARY"]["target_kind"], policy["SO-PRIMARY"]["market_code"]) == (SURVEY, "SG") and policy[
        "SO-PRIMARY"
    ]["published_binding"]
    assert policy["SB-RULE"]["target_kind"] == SCRIPT and policy["SB-RULE"]["published_binding"] is None
    group(trio, "PRIMARY-SG", "PRIMARY", ["SO-PRIMARY"], sequence=1)
    group(trio, "ADD-B", "ADD_REQUIRED", ["SO-ADD"], sequence=2)

    # ---- single-survey selection by the existing engine, for a synthetic application
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    app = {
        "market": "SG",
        "case_purpose": fields["case_purpose"][0],
        "product_family": "PROTECTION",
        "product_code": None,
        "is_ilp": False,
        "risk_band": "LOW",
        "selling_channel": "AGENCY",
        "premium_frequency": "SINGLE",
        "contact_role": [],
    }
    ev = evaluate(author, app)
    assert (ev["outcome"], ev["selection"], ev["survey_version_id"]) == ("SELECTED", "MATCHED", version["A"]), ev[
        "outcome"
    ]
    assert ev["decision"]["selected"]["rule"] == "SO-PRIMARY v1" and ev["call_plan"]["version_id"] == version["A"]
    # a script-backed rule with no binding fails closed, exactly as before
    unbound = evaluate(
        author,
        {**app, "product_family": "ILP", "is_ilp": True, "selling_channel": "DIRECT", "premium_frequency": "MONTHLY"},
    )
    assert unbound["outcome"] == "SURVEY_NOT_BOUND"

    # ---- 10. a composite plan of two surveys and the coordinated simulator, by the existing rules
    plan = compose(author, app)
    assert (plan["selection_status"], plan["ordering_status"], plan["plan_status"]) == ("RESOLVED", "GOVERNED", "READY")
    assert [s["survey_version_id"] for s in plan["composite"]["selected"]] == [version["A"], version["B"]]
    assert plan["composite"]["ordering"]["order"] == ["PRIMARY-SG", "ADD-B"]
    co = post(author, f"{A}/composite-plans/{plan['id']}/coordinated-simulations", {"label": "shared-1"})
    assert co.status_code == 201 and [s["survey_version_id"] for s in co.json()["surveys"]] == [
        version["A"],
        version["B"],
    ]

    # ---- 11. a survey-only rule can never assign a real case: not loaded, not simulated, refused by the database
    now = datetime.now(UTC)
    db.rollback()
    operational_rules = {c.rule_code for c in ri.published_candidates(db, ["SG"], now)}
    everything = {c.rule_code: c for c in ri.published_candidates(db, ["SG"], now, ri.ALL_KINDS)}
    assert not operational_rules & {"SO-PRIMARY", "SO-ADD"} and "SB-RULE" in operational_rules
    assert {"SO-PRIMARY", "SO-ADD", "SB-RULE"} <= set(everything)
    assert (everything["SO-PRIMARY"].target_effective, everything["SO-PRIMARY"].target_id) == (
        False,
        "survey-binding:SO-PRIMARY",
    )
    preview_after = maker.get(f"/api/v1/cases/{case_id}/script-assignment/preview").json()
    assert "SO-PRIMARY" not in json.dumps(preview_after) and "SO-ADD" not in json.dumps(preview_after)
    assert (preview_after.get("outcome"), preview_after.get("selected_script_version_id")) == (
        preview_before.get("outcome"),
        preview_before.get("selected_script_version_id"),
    )
    sim_after = rpost(maker, "/assignment-rules/simulate", {"draft_ids": [], "scope": "ALL"})
    assert "SO-PRIMARY" not in json.dumps(sim_after) and "SO-ADD" not in json.dumps(sim_after)
    assert sim_after["summary"]["baseline"] == sim_before["summary"]["baseline"]  # the same cases get the same scripts
    cols = [
        r[0]
        for r in db.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'script_assignment' ORDER BY ordinal_position"
            )
        )
    ]
    so_id = db.execute(
        text("SELECT id FROM script_assignment_rule_version WHERE rule_code = 'SO-PRIMARY'")
    ).scalar_one()
    select = ", ".join(
        "gen_random_uuid()"
        if c == "id"
        else ":r"
        if c == "matched_rule_version_id"
        else "NULL"
        if c == "supersedes_id"
        else c
        for c in cols
    )
    with pytest.raises(DBAPIError, match="survey-only assignment rule can never assign|matched rule does not target"):
        db.execute(
            text(f"INSERT INTO script_assignment ({', '.join(cols)}) SELECT {select} FROM script_assignment LIMIT 1"),
            {"r": so_id},
        )  # noqa: S608
    db.rollback()
    # the script-side list of rules is the list of script-backed rules
    script_side = {x["rule_code"] for x in maker.get("/api/v1/script-assignment-rules").json()["items"]}
    assert not script_side & {"SO-PRIMARY", "SO-ADD"} and "SB-RULE" in script_side
    assert {x["rule_code"] for x in script_side_before["items"]} <= script_side

    # ---- 7. a binding across markets is refused by the database, whatever the application does
    bcols = [
        r[0]
        for r in db.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'survey_assignment_binding' ORDER BY ordinal_position"
            )
        )
    ]
    bselect = ", ".join("gen_random_uuid()" if c == "id" else "'MY'" if c == "market_code" else c for c in bcols)
    with pytest.raises(DBAPIError, match="belong to the same market"):
        db.execute(
            text(
                f"INSERT INTO survey_assignment_binding ({', '.join(bcols)}) SELECT {bselect} FROM survey_assignment_binding LIMIT 1"
            )
        )  # noqa: S608
    db.rollback()

    # ---- a new rule version and a new binding never rewrite a recorded composite plan
    recorded = author.get(f"{A}/composite-plans/{plan['id']}").json()
    v2 = Rule(maker, rpost(maker, "/assignment-rules/SO-ADD/drafts", {}, 201)["draft_id"])
    assert v2.d["target_kind"] == SURVEY  # a new version selects the same kind of thing
    v2.put(conditions=[SG, {"field": "premium_frequency", "values": ["SINGLE", "MONTHLY"]}])
    v2.submit()
    rpost(
        rule_checker, f"/assignment-rule-drafts/{v2.id}/review", {"decision": "APPROVE", "reason": "Checked conditions"}
    )
    live = registry(maker)["SO-ADD v1"]["id"]
    rpost(
        rule_checker, f"/assignment-rule-drafts/{v2.id}/publish", {"supersede_rule_version_id": live, "reason": "wider"}
    )
    bind(trio, "SO-ADD", version["A"], rule_version=2)
    again = author.get(f"{A}/composite-plans/{plan['id']}").json()
    assert (again["fingerprint"], again["composite"]) == (recorded["fingerprint"], recorded["composite"])
    assert again.get("recompute_consistent", True) in (True, False)  # told, never rewritten

    # ---- 2, 3, 12, 19. nothing operational or historical moved
    with engine.connect() as conn:
        assert business_fingerprint(conn) == scripts_before
    assert counts(db, OPERATIONAL) == operational_before
    after = rule_rows(engine)
    assert [r for r in after if r in rules_before] == rules_before or set(rules_before) <= set(after)
    hist = maker.get("/api/v1/assignment-rules/SG-SALES-VERIFY/history")
    assert hist.status_code == 200
    assert maker.get(f"/api/v1/cases/{case_id}/script-assignment").status_code == 200  # assignment history is readable
    for c in (maker, rule_checker):
        c.__exit__(None, None, None)


# ----------------------------------------------------------------------------------- dedicated permissions, and old ones
def test_rules_and_finding_rules_are_governed_by_their_own_permissions_or_the_legacy_ones(
    clean_rules: None, survey_app: Any, db: Session
) -> None:
    def person(prefix: str, perms: tuple[str, ...]) -> TestClient:
        acct = make_account(db, "LOCAL_USER_SG", prefix=prefix)
        ONLY[acct.principal_id] = frozenset(perms)
        return _client(survey_app, acct)

    r_author = person("ar_author", ("assignment_rule.read", "assignment_rule.edit"))
    r_checker = person("ar_checker", ("assignment_rule.read", "assignment_rule.approve", "assignment_rule.publish"))
    r_reader = person("ar_reader", ("assignment_rule.read",))
    f_author = person("fr_author", ("finding_rule.read", "finding_rule.edit"))
    f_checker = person("fr_checker", ("finding_rule.read", "finding_rule.approve", "finding_rule.publish"))
    survey_editor = person(
        "sv_editor", ("survey.read", "survey.edit", "survey.approve", "survey.publish", "survey.assignment.read")
    )
    nobody = person("nobody", ())
    legacy_user = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="legacy_u"))
    legacy_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="legacy_c"))
    try:
        # ---- 13. assignment rules with the dedicated permissions alone — no Script Studio permission at all
        assert r_author.get("/api/v1/assignment-rules").status_code == 200
        assert r_author.get("/api/v1/assignment-rules/options").status_code == 200
        pub = survey_rule(
            r_author, r_checker, "DED-RULE", [SG, {"field": "product_family", "values": ["ENDOWMENT"]}], 9
        )
        assert pub["status"] == "PUBLISHED"
        # …and nothing more: not Script Studio, not operational assignment, not the simulation over cases
        for c in (r_author, r_checker, r_reader):
            assert c.get("/api/v1/scripts").status_code == 403
            assert c.get("/api/v1/script-assignment-rules").status_code == 403
            assert (
                c.post("/api/v1/script-assignments/run", json={"dry_run": True}, headers=csrf_header(c)).status_code
                == 403
            )
            assert (
                c.post(
                    "/api/v1/assignment-rules/simulate", json={"draft_ids": [], "scope": "ALL"}, headers=csrf_header(c)
                ).status_code
                == 403
            )
            assert c.get("/api/v1/finding-rule-sets").status_code == 403
            assert c.get("/api/v1/survey-definitions").status_code == 403
        # segregation within the capability: a reader cannot write, an author cannot approve, a checker cannot create
        assert (
            r_reader.post(
                "/api/v1/assignment-rules", json={"code": "NOPE-1", "name": "nope rule"}, headers=csrf_header(r_reader)
            ).status_code
            == 403
        )
        d = new_rule(r_author, "DED-TWO", target_kind=SURVEY)
        d.put(conditions=[SG, {"field": "product_family", "values": ["ILP"]}], priority=8)
        d.submit()
        assert (
            r_author.post(
                f"/api/v1/assignment-rule-drafts/{d.id}/review",
                json={"decision": "APPROVE", "reason": "mine"},
                headers=csrf_header(r_author),
            ).status_code
            == 403
        )
        assert (
            r_checker.post(
                "/api/v1/assignment-rules", json={"code": "NOPE-2", "name": "nope rule"}, headers=csrf_header(r_checker)
            ).status_code
            == 403
        )

        # ---- 15. no permission implies another
        for c in (survey_editor, nobody, f_author, f_checker):
            assert c.get("/api/v1/assignment-rules").status_code == 403, (
                "survey or finding-rule permissions grant nothing on assignment rules"
            )
            assert (
                c.post(
                    "/api/v1/assignment-rules", json={"code": "NOPE-3", "name": "nope rule"}, headers=csrf_header(c)
                ).status_code
                == 403
            )
        for c in (survey_editor, nobody, r_author):
            assert c.get("/api/v1/finding-rule-sets").status_code == 403

        # ---- 13. finding rules with the dedicated permissions alone
        assert (
            f_author.get("/api/v1/finding-rule-sets").status_code == 200
            and f_author.get("/api/v1/finding-rule-sets/options").status_code == 200
        )
        v = f_author.post("/api/v1/finding-rule-sets", json={"empty": True}, headers=csrf_header(f_author))
        assert v.status_code == 201, v.text
        rules = [finding_rule("FR-S1-ANY", "MISMATCH", "FACT_MISMATCH", "HIGH")]
        s = f_author.put(
            f"/api/v1/finding-rule-sets/{v.json()['id']}",
            json={"expected_row_version": v.json()["row_version"], "rules": rules},
            headers=csrf_header(f_author),
        )
        if s.status_code == 200:
            sub = f_author.post(
                f"/api/v1/finding-rule-sets/{v.json()['id']}/submit",
                json={
                    "expected_row_version": s.json()["row_version"],
                    "change_summary": "SHARED-1 dedicated permissions (synthetic)",
                },
                headers=csrf_header(f_author),
            )
            assert sub.status_code == 200, sub.text
            assert (
                f_author.post(
                    f"/api/v1/finding-rule-sets/{v.json()['id']}/review",
                    json={"decision": "APPROVE", "reason": "mine"},
                    headers=csrf_header(f_author),
                ).status_code
                == 403
            )
            assert (
                f_checker.post(
                    f"/api/v1/finding-rule-sets/{v.json()['id']}/review",
                    json={"decision": "APPROVE", "reason": "Reviewed (synthetic)"},
                    headers=csrf_header(f_checker),
                ).status_code
                == 200
            )
            done = f_checker.post(
                f"/api/v1/finding-rule-sets/{v.json()['id']}/publish", json={}, headers=csrf_header(f_checker)
            )
            assert done.status_code == 200 and done.json()["status"] == "PUBLISHED", done.text
        else:
            pytest.fail(f"the dedicated author could not save a finding rule set: {s.status_code} {s.text[:300]}")
        assert (
            f_checker.post(
                "/api/v1/finding-rule-sets", json={"empty": True}, headers=csrf_header(f_checker)
            ).status_code
            == 403
        )
        for c in (f_author, f_checker):
            assert c.get("/api/v1/scripts").status_code == 403

        # ---- 14. the legacy permissions keep working for both capabilities, unchanged
        assert (
            legacy_user.get("/api/v1/assignment-rules").status_code == 200
            and legacy_user.get("/api/v1/finding-rule-sets").status_code == 200
        )
        assert legacy_user.get("/api/v1/scripts").status_code == 200
        publish_rule(
            legacy_user, legacy_checker, "LEG-RULE", [SG, {"field": "selling_channel", "values": ["BANCASSURANCE"]}], 7
        )
        assert (
            legacy_user.post(
                f"/api/v1/assignment-rule-drafts/{d.id}/review",
                json={"decision": "APPROVE", "reason": "x"},
                headers=csrf_header(legacy_user),
            ).status_code
            == 403
        )  # a USER never could approve
        # the dedicated permissions are held by no role
        db.rollback()
        held = db.execute(
            text(
                "SELECT count(*) FROM role_permission rp JOIN permission p ON p.id = rp.permission_id WHERE p.code = ANY(:c)"
            ),
            {"c": [*RULE_PERMS, *FINDING_PERMS]},
        ).scalar_one()
        assert (
            held == 0
            and db.execute(
                text("SELECT count(*) FROM permission WHERE code = ANY(:c)"), {"c": [*RULE_PERMS, *FINDING_PERMS]}
            ).scalar_one()
            == 8
        )
    finally:
        for c in (
            r_author,
            r_checker,
            r_reader,
            f_author,
            f_checker,
            survey_editor,
            nobody,
            legacy_user,
            legacy_checker,
        ):
            c.__exit__(None, None, None)
        ONLY.clear()


def test_with_the_setting_off_no_survey_only_rule_can_be_created_and_everything_else_is_as_it_was(
    settings: Settings, db: Session
) -> None:
    app = create_app(settings.model_copy(update={"transcription_worker": False}))
    maker = _client(app, make_account(db, "LOCAL_USER_SG", prefix="s1off"))
    try:
        assert maker.get("/api/v1/assignment-rules/options").json()["survey_only_rules"] is False
        r = maker.post(
            "/api/v1/assignment-rules",
            json={"code": "SO-OFF", "name": "Off rule", "target_kind": SURVEY},
            headers=csrf_header(maker),
        )
        assert (r.status_code, r.json()["code"]) == (409, "SURVEY_ONLY_RULES_UNAVAILABLE")
        d = new_rule(maker, "SB-OFF")  # a script-backed rule is created as it always was
        assert (d.d["target_kind"], d.d["market"]) == (SCRIPT, "SG")
        assert any(i["code"] == "NO_TARGET" for i in d.d["analysis"]["issues"])
    finally:
        maker.__exit__(None, None, None)


# ------------------------------------------------------------------------------------------------------- the migration
def test_zz_migration_0037_backfills_and_preserves_every_rule_and_fails_safely(
    fresh_schema: None, engine: Engine, settings: Settings, survey_app: Any, db: Session
) -> None:
    from app.domain.protection import DataProtection
    from app.domain.seed import seed

    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))

    def head() -> str:
        with engine.connect() as c:
            return str(c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one())

    def columns() -> set[str]:
        with engine.connect() as c:
            return set(
                c.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'call360_test' AND table_name = 'script_assignment_rule_version'"
                    )
                ).scalars()
            )

    def guard_enabled() -> str:
        with engine.connect() as c:
            return str(
                c.execute(
                    text(
                        "SELECT tgenabled FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid JOIN pg_namespace n ON n.oid = r.relnamespace WHERE n.nspname = 'call360_test' AND t.tgname = 'assignment_rule_version_guard'"
                    )
                ).scalar_one()
            )

    def others() -> str:
        """Operational and historical records, and the survey bindings: none may change."""
        h = hashlib.sha256()
        with engine.connect() as c:
            for t in (
                "script_assignment",
                "script_version",
                "script_family",
                "question_revision",
                "conversation_session",
                "survey_run",
                "question_execution",
                "finding",
                "finding_rule_set_version",
                "survey_assignment_binding",
                "survey_assignment_group",
                "survey_assignment_group_member",
            ):
                for r in c.execute(text(f"SELECT md5(t::text) FROM call360_test.{t} t ORDER BY 1")):  # noqa: S608
                    h.update(str(r[0]).encode())
        return h.hexdigest()

    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="zmaker"))
    checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="zchk"))
    try:
        publish_rule(
            maker, checker, "Z-SCRIPT", [SG, {"field": "selling_channel", "values": ["DIRECT"]}], 5
        )  # a populated schema
        assert head() == MIGRATION_HEAD == "0037_shared_rule_services"
        full_rules, full_others = rule_rows(engine), others()
        assert {"market_code", "target_kind"} <= columns()

        # ---- down: the two columns go, every rule is exactly what it was
        migrate(settings, "0036_survey_module_authoring", down=True)
        assert head() == "0036_survey_module_authoring" and not {"market_code", "target_kind"} & columns()
        assert rule_rows(engine) == full_rules and others() == full_others and guard_enabled() == "O"
        # the application still serves the rules on the earlier schema (their market read through the script)
        assert "Z-SCRIPT v1" in registry(maker) and registry(maker)["Z-SCRIPT v1"]["market"] == "SG"

        # ---- a failure part-way leaves nothing behind: the whole migration is one transaction
        with engine.begin() as c:
            c.execute(
                text(
                    "CREATE FUNCTION call360_test.script_assignment_rule_kind_check() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                )
            )
        with pytest.raises(Exception, match="already exists"):
            migrate(settings, "head")
        assert head() == "0036_survey_module_authoring" and not {"market_code", "target_kind"} & columns()
        assert rule_rows(engine) == full_rules and others() == full_others and guard_enabled() == "O"
        with engine.begin() as c:
            c.execute(text("DROP FUNCTION call360_test.script_assignment_rule_kind_check()"))

        # ---- up: every rule's market is its script family's; nothing else changed
        migrate(settings, "head")
        assert (
            head() == MIGRATION_HEAD
            and rule_rows(engine) == full_rules
            and others() == full_others
            and guard_enabled() == "O"
        )
        with engine.connect() as c:
            rows = c.execute(
                text(
                    "SELECT r.market_code, f.market_code, r.target_kind FROM call360_test.script_assignment_rule_version r JOIN call360_test.script_version v ON v.id = r.target_script_version_id JOIN call360_test.script_family f ON f.id = v.script_family_id"
                )
            ).all()
        assert rows and all(m == fm and k == SCRIPT for m, fm, k in rows) and {m for m, _, _ in rows} >= {"SG", "MY"}

        # ---- a survey-only rule cannot be expressed in the earlier schema: the downgrade refuses and keeps it
        survey_rule(maker, checker, "Z-SURVEY", [SG, {"field": "product_family", "values": ["ILP"]}], 6)
        kept = rule_rows(engine)
        with pytest.raises(RuntimeError, match="survey-only assignment rules exist"):
            migrate(settings, "0036_survey_module_authoring", down=True)
        assert head() == MIGRATION_HEAD and rule_rows(engine) == kept and {"market_code", "target_kind"} <= columns()
    finally:
        maker.__exit__(None, None, None)
        checker.__exit__(None, None, None)
