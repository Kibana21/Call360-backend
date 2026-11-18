"""S3-A answer evaluation over the API: Script Studio rule configuration (structured fields, governed values, validation
of incompatible types / operators / fact mappings), maker-checker publication with immutable published rules and a new
rule revision in the next draft, interactive evaluation of a simulated run against the case's immutable policy fact
snapshot (evidence trace, idempotent re-evaluation, new evaluation for new inputs, replay), scenario evaluation
expectations with expanded synthetic facts, batch regression and version comparison of rules, generated baselines,
authorization, insert-only evidence and no operational change."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema
from tests.test_lifecycle_authoring import add, build_lifecycle, issues
from tests.test_script_authoring import Draft, approve, ok
from tests.test_script_simulation import case_where, post
from tests.test_simulation_workbench import operational

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # this module publishes scripts; reset afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="echk")


def verification(**over: Any) -> dict[str, Any]:
    return {
        "delivery_mode": "CONVERSATIONAL",
        "lifecycle_role": "VERIFICATION",
        "customer_wording": "[Synthetic example, not approved wording] evaluation item",
        **over,
    }


def build(c: TestClient, code: str) -> tuple[str, Draft, str]:
    """A lifecycle draft plus a verification section with S3-A evaluation rules."""
    vid, d = build_lifecycle(c, code)
    core = next(s["section_id"] for s in d.sections() if s["module_code"] == f"{code}_CORE")
    add(
        d,
        core,
        f"Q-{code}-TERM",
        **verification(
            answer_type="NUMERIC",
            expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
            policy_fact_key="premium_term_years",
            evaluation={"operator": "EQ", "unit": "YEARS"},
        ),
    )
    add(
        d,
        core,
        f"Q-{code}-ADVICE",
        **verification(answer_type="YES_NO", expected_answer_policy="EXACT_BOOLEAN", expected_boolean=True),
    )
    add(
        d,
        core,
        f"Q-{code}-FREQ",
        **verification(
            answer_type="ENUM",
            enum_options=["MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"],
            expected_answer_policy="ENUM_MATCH_POLICY_FACT",
            policy_fact_key="premium_frequency",
        ),
    )
    add(
        d,
        core,
        f"Q-{code}-NOTES",
        **verification(answer_type="FREE_TEXT", expected_answer_policy="NARRATIVE_REVIEW", mandatory=False),
    )
    return vid, d, core


def answer_all(c: TestClient, run: dict[str, Any], answers: dict[str, Any]) -> dict[str, Any]:
    """Deliver statements and answer questions: ``answers`` by code, otherwise yes / the first option / text."""
    while run["next_action"]["kind"] in ("ASK", "REPROMPT"):
        a = run["next_action"]
        if not a["presented"]:
            run = post(c, f"/script-simulations/{run['id']}/delivery", {"action_id": a["action_id"], "delivered": True})
            if a["completes_on_delivery"]:
                continue
            a = run["next_action"]
        code = a["question_code"]
        if code in answers:
            kind, value = answers[code] if isinstance(answers[code], tuple) else ("ANSWER", answers[code])
        else:
            kind = "ANSWER"
            t = a["answer_type"]
            value = (
                True
                if t in ("YES_NO", "ACKNOWLEDGEMENT")
                else a["options"][0]
                if t == "ENUM"
                else 10
                if t == "NUMERIC"
                else "Synthetic"
            )
        body = {"action_id": a["action_id"], "kind": kind, **({"value": value} if kind == "ANSWER" else {})}
        run = post(c, f"/script-simulations/{run['id']}/answer", body)
    return run


def evaluations_count(db: Session) -> int:
    n = int(db.execute(text(f"SELECT count(*) FROM {SCHEMA}.simulation_answer_evaluation")).scalar_one())
    db.rollback()
    return n


def test_rule_configuration_validation_in_script_studio(client: TestClient, user: Account) -> None:
    login(client, user)
    vid, d, core = build(client, "EV_CFG")
    cases = [
        (verification(answer_type="YES_NO", expected_answer_policy="NUMERIC_COMPARE"), "numeric question"),
        (
            verification(answer_type="NUMERIC", expected_answer_policy="NUMERIC_COMPARE", evaluation={"unit": "YEARS"}),
            "expected number",
        ),
        (
            verification(
                answer_type="NUMERIC",
                expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
                policy_fact_key="annual_income",
            ),
            "approved policy fact",
        ),
        (
            verification(
                answer_type="NUMERIC",
                expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
                policy_fact_key="premium_amount",
                evaluation={"unit": "SGD", "tolerance": "10"},
            ),
            "reference of its business approval",
        ),
        (
            verification(
                answer_type="ENUM",
                enum_options=["MONTHLY", "WEEKLY"],
                expected_answer_policy="ENUM_MATCH_POLICY_FACT",
                policy_fact_key="premium_frequency",
            ),
            "WEEKLY is not",
        ),
    ]
    for i, (body, message) in enumerate(cases):
        out = add(d, core, f"Q-EV_CFG-BAD{i}", 422, **body)
        assert message in out["message"], (message, out)
    r = client.post(  # unsupported operator: rejected by the governed vocabulary
        f"/api/v1/script-versions/{vid}/sections/{core}/questions",
        json={
            "expected_row_version": d.rv,
            "question_code": "Q-EV_CFG-OP",
            "content": verification(
                intent="Synthetic",
                category="OTHER",
                mandatory=True,
                answer_type="NUMERIC",
                expected_answer_policy="NUMERIC_COMPARE",
                evaluation={"operator": "BETWEEN", "value": 1},
            ),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 422
    add(  # an approved tolerance with its approval reference is stored as structured rule data
        d,
        core,
        "Q-EV_CFG-AMOUNT",
        **verification(
            answer_type="NUMERIC",
            expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
            policy_fact_key="premium_amount",
            evaluation={"unit": "SGD", "tolerance": "0.50", "tolerance_reference": "SYN-TOL-001 (synthetic)"},
        ),
    )
    q = next(x for s in d.sections() for x in s["questions"] if x["question_code"] == "Q-EV_CFG-AMOUNT")
    assert q["expected_value"] == {
        "operator": "EQ",
        "unit": "SGD",
        "tolerance": "0.5",
        "tolerance_reference": "SYN-TOL-001 (synthetic)",
    }
    assert not issues(d).get("ERROR")
    opts = ok(client.get("/api/v1/script-authoring/options"))
    assert "ENUM_MATCH_POLICY_FACT" in opts["expected_answer_policies"]
    assert opts["evaluation"]["facts"]["premium_frequency"]["kind"] == "ENUM"
    assert "No tolerance or threshold is assumed" in opts["evaluation"]["note"]


def test_interactive_evaluation_evidence_replay_isolation_and_history(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, admin: Account, db: Session
) -> None:
    login(client, user)
    vid, d, core = build(client, "EV_RUN")
    case_id = case_where(db, "(s.facts->>'premium_term_years') IS NOT NULL", 1)
    snap_id, sha, facts = db.execute(
        text(
            f"SELECT s.id, s.sha256, s.facts FROM {SCHEMA}.policy_fact_snapshot s JOIN {SCHEMA}.callback_case c "
            f"ON c.sale_event_id = s.sale_event_id WHERE c.id = :c ORDER BY s.captured_at DESC LIMIT 1"
        ),
        {"c": case_id},
    ).one()
    db.rollback()
    term, freq = int(facts["premium_term_years"]), facts["premium_frequency"]
    wrong_freq = next(f for f in ("MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL") if f != freq)
    before, n0 = operational(db), evaluations_count(db)

    # Draft version test: answer the term wrongly (5 vs the policy's term), advice no, frequency wrong.
    run = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    run = answer_all(
        client,
        run,
        {
            "Q-EV_RUN-TERM": term - 5 if term > 5 else term + 5,
            "Q-EV_RUN-ADVICE": False,
            "Q-EV_RUN-FREQ": wrong_freq,
            "Q-EV_RUN-NOTES": "Synthetic narrative answer",
        },
    )
    run = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    assert run["outcome"] == "COMPLETED"  # a completed conversation …
    ev = post(client, f"/script-simulations/{run['id']}/evaluations", {})
    by = {r["question_code"]: r for r in ev["results"]}
    assert ev["created"] and ev["evaluation_ref"].startswith("EVL-")
    assert by["Q-EV_RUN-TERM"]["result"] == "MISMATCH"  # … that still contains mismatches
    assert by["Q-EV_RUN-ADVICE"]["result"] == "MISMATCH" and by["Q-EV_RUN-FREQ"]["result"] == "MISMATCH"
    assert by["Q-EV_RUN-NOTES"]["result"] == "HUMAN_ASSESSMENT_REQUIRED"
    assert by["Q-EV_RUN-OPEN"]["result"] == "NOT_EVALUATED"
    t = by["Q-EV_RUN-TERM"]
    assert t["expected"]["source"] == "POLICY_FACT:premium_term_years" and t["expected"]["fact_value"] == term
    assert f"expected equal to {term} years from policy fact premium_term_years" in t["explanation"]
    assert t["question_revision_id"] and t["revision"] == 1 and t["rule"]["method"] == "NUMERIC_MATCH_POLICY_FACT"
    # Evidence trace: pinned immutable inputs.
    assert ev["policy_fact_snapshot_id"] == str(snap_id) and ev["policy_fact_snapshot_sha256"] == sha
    assert ev["content_source"] == "CONTENT_SNAPSHOT" and ev["mode"] == "VERSION_TEST"
    assert ev["engine_version"].startswith("call360.answer-evaluation/1") and ev["replay"]["matches"] is True
    assert ev["totals"]["MISMATCH"] == 3 and ev["controller_outcome"] == "COMPLETED"
    # Identical inputs: the same evaluation (nothing new is written).
    again = post(client, f"/script-simulations/{run['id']}/evaluations", {})
    assert again["id"] == ev["id"] and again["created"] is False
    assert evaluations_count(db) == n0 + 1

    # A later draft edit never changes the recorded evaluation (exact content snapshot); replay still agrees.
    term_q = next(x for s in d.sections() for x in s["questions"] if x["question_code"] == "Q-EV_RUN-TERM")
    d.put(
        f"/sections/{core}/questions/{term_q['module_question_id']}",
        {
            "content": {
                "intent": "Synthetic lifecycle item for tests",
                "category": "OTHER",
                "mandatory": True,
                **verification(
                    answer_type="NUMERIC",
                    expected_answer_policy="NUMERIC_COMPARE",
                    evaluation={"operator": "GTE", "value": 1, "unit": "YEARS"},
                ),
            },
            "change_reason": "Rule changed after the evaluation (test)",
        },
    )
    got = ok(client.get(f"/api/v1/script-simulations/{run['id']}/evaluations/{ev['id']}"))
    assert got["results"] == ev["results"] and got["replay"]["matches"] is True

    # A run in progress: evaluate, answer more, evaluate again — a new evaluation; the first is kept.
    run2 = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    run2 = answer_all(client, run2, {"Q-EV_RUN-TERM": ("REFUSED", None)})
    first = post(client, f"/script-simulations/{run2['id']}/evaluations", {})
    assert {r["question_code"]: r["result"] for r in first["results"]}["Q-EV_RUN-TERM"] == "UNRESOLVED"
    lst = ok(client.get(f"/api/v1/script-simulations/{run2['id']}/evaluations"))["items"]
    assert len(lst) == 1
    post(client, f"/script-simulations/{run2['id']}/end", {"abandon": False})
    second = post(client, f"/script-simulations/{run2['id']}/evaluations", {})
    assert second["id"] != first["id"] and second["events_evaluated"] > first["events_evaluated"]
    assert len(ok(client.get(f"/api/v1/script-simulations/{run2['id']}/evaluations"))["items"]) == 2

    # Insert-only evidence; immutable fact snapshot.
    for sql in (
        f"UPDATE {SCHEMA}.simulation_answer_evaluation SET totals = '{{}}'::jsonb",
        f"DELETE FROM {SCHEMA}.simulation_answer_evaluation",
        f"UPDATE {SCHEMA}.policy_fact_snapshot SET facts = facts WHERE id = '{snap_id}'",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()

    # Authorization: ADMIN cannot evaluate; reads need case.read + script.read.
    login(other_client, admin)
    r = other_client.post(f"/api/v1/script-simulations/{run['id']}/evaluations", headers=csrf_header(other_client))
    assert r.status_code == 403
    # No operational record changes (no answer observation, rule evaluation, finding, case state or hold).
    assert operational(db) == before


def test_scenario_evaluation_expectations_batch_regression_and_rule_comparison(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, db: Session
) -> None:
    login(client, user)
    vid, d, core = build(client, "EV_SCN")
    facts = {
        "product_family": "PROTECTION",
        "is_ilp": False,
        "premium_frequency": "ANNUAL",
        "premium_term_years": 10,
        "premium_amount": "1200.00",
        "currency": "SGD",
    }

    def scenario(name: str, steps: list[dict[str, Any]], evaluations: dict[str, str], **exp: Any) -> dict[str, Any]:
        return {
            "name": name,
            "script_version_id": vid,
            "facts": facts,
            "risk_band": "LOW",
            "steps": steps,
            "expectations": {"evaluations": evaluations, "basis": "INDEPENDENT", **exp},
        }

    wrong = post(
        client,
        "/simulation-scenarios",
        scenario(
            "Completed with wrong answers",
            [{"question": "Q-EV_SCN-TERM", "kind": "ANSWER", "value": 5}],
            {"Q-EV_SCN-TERM": "MISMATCH", "Q-EV_SCN-ADVICE": "MATCH", "Q-EV_SCN-FREQ": "MISMATCH"},
            outcome="COMPLETED",
        ),
        201,
    )  # default response picks MONTHLY (first option) vs ANNUAL: a mismatch
    right = post(
        client,
        "/simulation-scenarios",
        scenario(
            "Correct answers",
            [
                {"question": "Q-EV_SCN-TERM", "kind": "ANSWER", "value": 10},
                {"question": "Q-EV_SCN-FREQ", "kind": "ANSWER", "value": "ANNUAL"},
            ],
            {"Q-EV_SCN-TERM": "MATCH", "Q-EV_SCN-FREQ": "MATCH", "Q-EV_SCN-NOTES": "HUMAN_ASSESSMENT_REQUIRED"},
        ),
        201,
    )
    missing = post(
        client,
        "/simulation-scenarios",
        scenario(
            "Missing expected fact",
            [{"question": "Q-EV_SCN-TERM", "kind": "ANSWER", "value": 10}],
            {"Q-EV_SCN-TERM": "MISSING_EXPECTED_FACT"},
        )
        | {"facts": {k: v for k, v in facts.items() if k != "premium_term_years"}},
        201,
    )
    assert wrong["content"]["expectations"]["basis"] == "INDEPENDENT"
    bad = client.post(
        "/api/v1/simulation-scenarios",
        json=scenario("Bad facts", [], {"Q-EV_SCN-TERM": "PASS"}) | {"facts": facts | {"currency": "MYR"}},
        headers=csrf_header(client),
    )
    assert bad.status_code == 422, bad.text
    assert "Fact currency: SGD (Singapore-only synthetic data)" in bad.text and "not an evaluation result" in bad.text
    batch = post(client, "/simulation-runs", {"scenario_ids": [wrong["id"], right["id"], missing["id"]]}, 201)
    assert batch["totals"]["A"]["PASSED"] == 3, [r["failures"] for r in batch["results"]]
    res = next(r for r in batch["results"] if r["scenario_id"] == wrong["id"])
    assert (
        res["actual"]["outcome"] == "COMPLETED" and res["actual"]["evaluation_results"]["Q-EV_SCN-TERM"] == "MISMATCH"
    )
    assert res["actual"]["fact_source"]["kind"] == "SCENARIO_FACTS"
    cov = batch["coverage"][0]
    assert {"question": "Q-EV_SCN-TERM", "results": ["MATCH", "MISMATCH", "MISSING_EXPECTED_FACT"]} in cov[
        "evaluation_results_observed"
    ]

    # Publish A (maker-checker), open B with a changed rule; compare: rule change and evaluation diff are explained.
    assert not issues(d).get("ERROR")
    d.post("/submit", {"change_summary": "Evaluation version A"})
    login(other_client, checker)
    for step, body in (("review", approve(other_client, vid)), ("publish", {})):
        ok(other_client.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(other_client)))
    pub = ok(client.get(f"/api/v1/script-versions/{vid}"))
    r = client.put(  # published versions are immutable
        f"/api/v1/script-versions/{vid}/sections/{core}/questions/x",
        json={"expected_row_version": pub["row_version"], "content": {}},
        headers=csrf_header(client),
    )
    assert r.status_code in (404, 409, 422)
    vb = ok(
        client.post(f"/api/v1/scripts/{pub['script_family_id']}/drafts", json={}, headers=csrf_header(client)), 201
    )["script_version_id"]
    d2 = Draft(client, vb)
    sec2 = next(s for s in d2.sections() if s["module_code"] == "EV_SCN_CORE")
    tq = next(x for x in sec2["questions"] if x["question_code"] == "Q-EV_SCN-TERM")
    d2.put(
        f"/sections/{sec2['section_id']}/questions/{tq['module_question_id']}",
        {
            "content": {
                "intent": "Synthetic lifecycle item for tests",
                "category": "OTHER",
                "mandatory": True,
                **verification(
                    answer_type="NUMERIC",
                    expected_answer_policy="NUMERIC_COMPARE",
                    evaluation={"operator": "LTE", "value": 5, "unit": "YEARS"},
                ),
            },
            "change_reason": "Synthetic rule change (test)",
        },
    )
    cmp_ = post(
        client,
        "/simulation-runs",
        {"scenario_ids": [wrong["id"]], "script_version_id": vid, "compare_with_version_id": vb},
        201,
    )
    (c,) = cmp_["comparison"]
    assert c["status_a"] == "PASSED" and c["status_b"] == "FAILED"
    assert c["plan_diff"]["rule_changes"] == [
        {
            "question": "Q-EV_SCN-TERM",
            "from": "Expected: equal to policy fact premium_term_years years",
            "to": "Expected: at most 5 years",
        }
    ]
    assert {"field": "evaluation:Q-EV_SCN-TERM", "a": "MISMATCH", "b": "MATCH"} in c["outcome_diff"]
    b_res = next(r for r in cmp_["results"] if r["side"] == "B")
    assert any("answer evaluation: expected mismatch, got match" in f["message"] for f in b_res["failures"])
    # The historical published revision keeps its rule: A still evaluates against the policy fact.
    a_res = next(r for r in cmp_["results"] if r["side"] == "A")
    a_term = next(x for x in a_res["actual"]["evaluations"] if x["question_code"] == "Q-EV_SCN-TERM")
    assert a_term["method"] == "NUMERIC_MATCH_POLICY_FACT" and a_term["revision"] == 1


def test_recorded_run_expectations_are_a_generated_baseline(client: TestClient, user: Account, db: Session) -> None:
    login(client, user)
    vid, _, _ = build(client, "EV_BASE")
    case_id = case_where(db, "(s.facts->>'premium_term_years') IS NOT NULL", 1)
    run = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    run = answer_all(client, run, {"Q-EV_BASE-ADVICE": False})
    run = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    rec = ok(client.get(f"/api/v1/script-simulations/{run['id']}/as-scenario"))
    assert rec["expectations"]["basis"] == "GENERATED_BASELINE"
    assert rec["expectations"]["evaluations"]["Q-EV_BASE-ADVICE"] == "MISMATCH"
    assert "premium_term_years" in rec["facts"] and rec["facts"]["currency"] == "SGD"
