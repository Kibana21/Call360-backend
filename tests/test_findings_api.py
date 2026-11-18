"""S3-B findings over the API: governed finding rule sets (structured validation, maker-checker, immutable published
versions, superseded history), simulated finding generation from an interactive evaluation (evidence, controls,
severity from configuration, human-assessment routing, no findings for correct answers, idempotent and duplicate-free,
new rule set → new set with the old kept, replay), scenario expected findings in batch runs, authorization, audit,
simulation isolation and idempotent operational persistence on a synthetic fixture (visible to the Review Workbench
queue)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain import finding_rules as fr
from app.domain import simulation_findings as sf
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema
from tests.test_answer_evaluation_api import answer_all, build
from tests.test_script_authoring import ok
from tests.test_script_simulation import case_where, post
from tests.test_simulation_workbench import operational

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # this module publishes scripts and finding rules; reset afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="fchk")


def put(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
    r = c.put(f"/api/v1{path}", json=body, headers=csrf_header(c))
    assert r.status_code == status, r.text
    return dict(r.json())


def rule(
    code: str, trigger: str, category: str, severity: str, scope: str = "ANY_QUESTION", **kw: Any
) -> dict[str, Any]:
    return {
        "rule_code": code,
        "scope": scope,
        "target": kw.pop("target", None),
        "trigger": trigger,
        "category": category,
        "severity": severity,
        "description": f"Synthetic rule {code} (test)",
        "severity_justification": "Synthetic test severity, not an approved threshold",
        "review_required": kw.pop("review_required", True),
        **kw,
    }


def publish_rules(c: TestClient, chk: TestClient, rules: list[dict[str, Any]], summary: str) -> dict[str, Any]:
    v = post(c, "/finding-rule-sets", {"empty": True}, 201)
    v = put(c, f"/finding-rule-sets/{v['id']}", {"expected_row_version": v["row_version"], "rules": rules})
    v = post(
        c, f"/finding-rule-sets/{v['id']}/submit", {"expected_row_version": v["row_version"], "change_summary": summary}
    )
    post(chk, f"/finding-rule-sets/{v['id']}/review", {"decision": "APPROVE", "reason": "Reviewed (synthetic test)"})
    return post(chk, f"/finding-rule-sets/{v['id']}/publish", {})


def count(db: Session, table: str) -> int:
    n = int(db.execute(text(f"SELECT count(*) FROM {SCHEMA}.{table}")).scalar_one())
    db.rollback()
    return n


def test_finding_rules_governance_findings_scenarios_isolation_and_operational_fixture(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, admin: Account, db: Session
) -> None:
    login(client, user)
    login(other_client, checker)
    vid, _, _ = build(client, "FN_RUN")
    case_id = case_where(db, "(s.facts->>'premium_term_years') IS NOT NULL", 1)
    term = int(
        db.execute(
            text(
                f"SELECT s.facts->>'premium_term_years' FROM {SCHEMA}.policy_fact_snapshot s "
                f"JOIN {SCHEMA}.callback_case c "
                f"ON c.sale_event_id = s.sale_event_id WHERE c.id = :c ORDER BY s.captured_at DESC LIMIT 1"
            ),
            {"c": case_id},
        ).scalar_one()
    )
    db.rollback()
    before = operational(db)

    # A wrong run, evaluated.
    run = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    run = answer_all(client, run, {"Q-FN_RUN-TERM": term + 5, "Q-FN_RUN-ADVICE": False, "Q-FN_RUN-NOTES": "Synthetic"})
    run = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    assert run["outcome"] == "COMPLETED"
    ev = post(client, f"/script-simulations/{run['id']}/evaluations", {})
    gen_path = f"/script-simulations/{run['id']}/evaluations/{ev['id']}/findings"

    # No published rule set yet: nothing is assumed.
    r = client.post(f"/api/v1{gen_path}", json={}, headers=csrf_header(client))
    assert r.status_code == 409 and r.json()["code"] == "NO_PUBLISHED_FINDING_RULES"

    # Governance: structured validation, maker-checker, publish.
    v1 = post(client, "/finding-rule-sets", {"empty": True}, 201)
    assert v1["status"] == "DRAFT" and v1["i_am_maker"] is True
    bad = client.put(
        f"/api/v1/finding-rule-sets/{v1['id']}",
        json={
            "expected_row_version": v1["row_version"],
            "rules": [rule("FR-X-BAD", "MISMATCH", "POLICY_DATA_ISSUE", "HIGH")],
        },
        headers=csrf_header(client),
    )
    assert bad.status_code == 422 and "category for a mismatch trigger" in bad.text
    rules = [
        rule("FR-TERM-MISMATCH", "MISMATCH", "FACT_MISMATCH", "HIGH", "QUESTION", target="Q-FN_RUN-TERM"),
        rule("FR-ANY-MANDATORY-MISMATCH", "MISMATCH", "UNCLEAR_UNDERSTANDING", "LOW", mandatory_only=True),
        rule("FR-MANDATORY-UNRESOLVED", "UNRESOLVED", "MISSING_MANDATORY_ANSWER", "MEDIUM", mandatory_only=True),
        rule("FR-FACT-MISSING", "MISSING_EXPECTED_FACT", "POLICY_DATA_ISSUE", "LOW", review_required=False),
        rule("FR-NARRATIVE", "HUMAN_ASSESSMENT_REQUIRED", "NARRATIVE_REVIEW", "MEDIUM"),
    ]
    v1 = put(client, f"/finding-rule-sets/{v1['id']}", {"expected_row_version": v1["row_version"], "rules": rules})
    assert len(v1["rules"]) == 5 and v1["rules"][0]["text"]
    v1 = post(
        client,
        f"/finding-rule-sets/{v1['id']}/submit",
        {"expected_row_version": v1["row_version"], "change_summary": "Synthetic v1"},
    )
    assert (
        client.post(
            f"/api/v1/finding-rule-sets/{v1['id']}/review",
            json={"decision": "APPROVE", "reason": "self"},
            headers=csrf_header(client),
        ).status_code
        == 403
    )  # the maker lacks script.approve
    with pytest.raises(fr.RuleSetError, match="another S&C checker"):  # and the service refuses a maker-reviewer
        fr.review(db, v1["id"], ["SG"], str(user.principal_id), "APPROVE", "self review")
    db.rollback()
    post(other_client, f"/finding-rule-sets/{v1['id']}/review", {"decision": "APPROVE", "reason": "Reviewed (test)"})
    v1 = post(other_client, f"/finding-rule-sets/{v1['id']}/publish", {})
    assert v1["status"] == "PUBLISHED" and [h["action"] for h in v1["history"]][-1] == "PUBLISHED"
    r = client.put(
        f"/api/v1/finding-rule-sets/{v1['id']}",
        json={"expected_row_version": v1["row_version"], "rules": []},
        headers=csrf_header(client),
    )
    assert r.status_code == 409  # published versions are immutable (service) …
    with pytest.raises(DBAPIError):  # … and in the database
        db.execute(
            text(f"UPDATE {SCHEMA}.finding_rule_set_version SET rules = '[]'::jsonb WHERE id = :v"), {"v": v1["id"]}
        )
    db.rollback()

    # Generate findings from the evaluation.
    fs = post(client, gen_path, {})
    assert fs["created"] and fs["finding_set_ref"].startswith("FGS-") and fs["rule_set_status"] == "PUBLISHED"
    by = {f["question_code"]: f for f in fs["findings"]}
    t = by["Q-FN_RUN-TERM"]
    assert (t["category"], t["severity"], t["finding_class"], t["rule"]["rule_code"]) == (
        "FACT_MISMATCH",
        "HIGH",
        "CUSTOMER_DISCREPANCY",
        "FR-TERM-MISMATCH",
    )
    assert t["evidence"]["expected"]["fact_value"] == term and t["evidence"]["evaluation_ref"] == ev["evaluation_ref"]
    assert t["evidence"]["fact_source"]["sha256"] == ev["policy_fact_snapshot_sha256"]
    assert t["evidence"]["content_sha256"] == ev["content_sha256"] and t["question_revision_id"]
    assert t["control_unmapped"] is True  # the test script maps no control: flagged, not hidden
    assert by["Q-FN_RUN-ADVICE"]["rule"]["rule_code"] == "FR-ANY-MANDATORY-MISMATCH"
    assert by["Q-FN_RUN-NOTES"]["finding_class"] == "HUMAN_ASSESSMENT" and by["Q-FN_RUN-NOTES"]["review_required"]
    assert [h["question_code"] for h in fs["human_assessment"]] == ["Q-FN_RUN-NOTES"]
    assert fs["replay"]["matches"] is True and fs["summary"]["findings"] == len(fs["findings"])
    # Idempotent: the same inputs return the same set; no finding is duplicated.
    n_sets, n_rows = count(db, "simulation_finding_set"), count(db, "simulation_finding")
    again = post(client, gen_path, {})
    assert again["id"] == fs["id"] and again["created"] is False
    assert (count(db, "simulation_finding_set"), count(db, "simulation_finding")) == (n_sets, n_rows)

    # A correct run: no discrepancy findings (only the human-assessment item).
    ok_run = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    ok_run = answer_all(client, ok_run, {"Q-FN_RUN-TERM": term, "Q-FN_RUN-NOTES": "Synthetic"})
    freq = next(q for q in ok_run["questions"] if q["code"] == "Q-FN_RUN-FREQ")
    assert freq["status"] == "COMPLETED"
    ok_run = post(client, f"/script-simulations/{ok_run['id']}/end", {"abandon": False})
    ok_ev = post(client, f"/script-simulations/{ok_run['id']}/evaluations", {})
    ok_fs = post(client, f"/script-simulations/{ok_run['id']}/evaluations/{ok_ev['id']}/findings", {})
    discrepancies = [f for f in ok_fs["findings"] if f["finding_class"] != "HUMAN_ASSESSMENT"]
    mismatch_freq = {r["question_code"]: r["result"] for r in ok_ev["results"]}["Q-FN_RUN-FREQ"]
    assert [f["question_code"] for f in discrepancies] == (["Q-FN_RUN-FREQ"] if mismatch_freq == "MISMATCH" else [])

    # v2 changes a severity; v1 is superseded and kept; the old finding set is preserved and a new one is generated.
    v2 = post(client, "/finding-rule-sets", {}, 201)  # a copy of the published rules
    assert len(v2["rules"]) == 5 and v2["diff_vs_published"] == {"added": [], "removed": [], "changed": []}
    changed = [x | ({"severity": "CRITICAL"} if x["rule_code"] == "FR-TERM-MISMATCH" else {}) for x in rules]
    v2 = put(client, f"/finding-rule-sets/{v2['id']}", {"expected_row_version": v2["row_version"], "rules": changed})
    assert v2["diff_vs_published"]["changed"][0]["changes"]["severity"] == {"from": "HIGH", "to": "CRITICAL"}
    # A draft can be tested in simulation (labelled), before publication.
    draft_fs = post(client, gen_path, {"rule_set_version_id": v2["id"]})
    assert draft_fs["rule_set_status"] == "DRAFT" and "draft" in draft_fs["rule_set_label"]
    v2 = post(
        client,
        f"/finding-rule-sets/{v2['id']}/submit",
        {"expected_row_version": v2["row_version"], "change_summary": "Synthetic v2"},
    )
    post(other_client, f"/finding-rule-sets/{v2['id']}/review", {"decision": "APPROVE", "reason": "Reviewed v2 (test)"})
    post(other_client, f"/finding-rule-sets/{v2['id']}/publish", {})
    old = ok(client.get(f"/api/v1/finding-rule-sets/{v1['id']}"))
    assert old["status"] == "SUPERSEDED"
    assert {x["rule_code"]: x["severity"] for x in old["rules"]}["FR-TERM-MISMATCH"] == "HIGH"  # history kept
    fs2 = post(client, gen_path, {})  # published v2 has the same rules as the tested draft: the same set is returned
    assert fs2["id"] == draft_fs["id"] and fs2["created"] is False and fs2["rule_set_current_status"] == "PUBLISHED"
    assert {f["question_code"]: f for f in fs2["findings"]}["Q-FN_RUN-TERM"]["severity"] == "CRITICAL"
    assert (
        ok(client.get(f"/api/v1/script-simulations/{run['id']}/finding-sets/{fs['id']}"))["findings"] == fs["findings"]
    )
    sets = ok(client.get(f"/api/v1{gen_path}"))["items"]
    assert len(sets) == 2  # v1 and v2 — none overwritten, none duplicated

    # Scenario expected findings: batch regression with the published rule set.
    scn = post(
        client,
        "/simulation-scenarios",
        {
            "name": "Wrong term raises a critical fact mismatch",
            "script_version_id": vid,
            "facts": {
                "product_family": "PROTECTION",
                "is_ilp": False,
                "premium_frequency": "MONTHLY",
                "premium_term_years": 10,
                "currency": "SGD",
            },
            "risk_band": "LOW",
            "steps": [{"question": "Q-FN_RUN-TERM", "kind": "ANSWER", "value": 5}],
            "expectations": {
                "outcome": "COMPLETED",
                "basis": "INDEPENDENT",
                "findings": [
                    {"question": "Q-FN_RUN-TERM", "category": "FACT_MISMATCH", "severity": "CRITICAL"},
                    {"question": "Q-FN_RUN-NOTES", "category": "NARRATIVE_REVIEW"},
                ],
            },
        },
        201,
    )
    batch = post(client, "/simulation-runs", {"scenario_ids": [scn["id"]]}, 201)
    assert batch["totals"]["A"]["PASSED"] == 1, batch["results"][0]["failures"]
    actual = batch["results"][0]["actual"]
    assert actual["finding_rule_set"]["status"] == "PUBLISHED" and actual["findings_summary"]["findings"] == 2
    with_v1 = post(
        client, "/simulation-runs", {"scenario_ids": [scn["id"]], "finding_rule_set_version_id": v1["id"]}, 201
    )
    msgs = [f["message"] for f in with_v1["results"][0]["failures"]]
    assert "Expected finding(s) not generated: Q-FN_RUN-TERM fact mismatch (CRITICAL)" in msgs
    assert "Unexpected finding(s): Q-FN_RUN-TERM fact mismatch (HIGH)" in msgs

    # Authorization and audit.
    login(other_client, admin)
    assert other_client.post("/api/v1/finding-rule-sets", json={}, headers=csrf_header(other_client)).status_code == 403
    assert other_client.post(f"/api/v1{gen_path}", json={}, headers=csrf_header(other_client)).status_code == 403
    actions = set(
        db.execute(
            text(
                f"SELECT action FROM {SCHEMA}.audit_event WHERE action LIKE 'FINDING_RULES.%' OR action = "
                "'SIMULATION.FINDINGS_GENERATED'"
            )
        ).scalars()
    )
    db.rollback()
    assert {
        "FINDING_RULES.CREATED",
        "FINDING_RULES.EDITED",
        "FINDING_RULES.SUBMITTED",
        "FINDING_RULES.REVIEWED",
        "FINDING_RULES.PUBLISHED",
        "SIMULATION.FINDINGS_GENERATED",
    } <= actions

    # Simulation isolation: no operational finding, case, hold, attempt or assignment change.
    assert operational(db) == before
    for sql in (
        f"UPDATE {SCHEMA}.simulation_finding SET severity = 'LOW'",
        f"DELETE FROM {SCHEMA}.simulation_finding_set",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()

    # Operational persistence on an explicitly synthetic seeded fixture (no API; no real session evaluated).
    qe_id, ref = db.execute(
        text(
            f"SELECT qe.id, c.case_ref FROM {SCHEMA}.question_execution qe JOIN {SCHEMA}.survey_run sr ON sr.id = "
            f"qe.survey_run_id JOIN {SCHEMA}.conversation_session cs ON cs.id = sr.session_id JOIN "
            f"{SCHEMA}.contact_attempt ca ON ca.id = cs.contact_attempt_id JOIN {SCHEMA}.callback_case c ON "
            f"c.id = ca.callback_case_id WHERE c.is_synthetic AND c.market_code = 'SG' "
            "ORDER BY c.case_ref, qe.position "
            "LIMIT 1"
        )
    ).one()
    with pytest.raises(PermissionError, match="published finding rule set only"):  # draft-rule severity refused
        sf.persist_operational(db, fs2["findings"][0], qe_id, "engine-test")
    db.rollback()
    finding = fs["findings"][0]  # generated with the published v1 rules
    fid, created = sf.persist_operational(db, finding, qe_id, "engine-test")
    again_id, again_created = sf.persist_operational(db, finding, qe_id, "engine-test")
    db.commit()
    assert created and not again_created and again_id == fid
    queue = ok(client.get("/api/v1/review-queue", params={"q": ref, "queue": "ALL"}))
    item = next(i for i in queue["items"] if i["finding_ref"].startswith("FND-ENG-"))
    assert item["category"] == finding["category"] and item["origin"] == "RULE_EVALUATION"
