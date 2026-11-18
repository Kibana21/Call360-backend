"""S2-E simulation workbench over the API: draft version testing without assignments (isolated snapshot), scenario
library (create, revise with versioning and concurrency, copy, archive), single and batch automated runs with explained
failures, invalid and stale scenarios, exact snapshot preservation, coverage, two-version comparison, recording an
interactive run as a scenario, dry runs that write nothing, authorization and no operational change."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema
from tests.test_lifecycle_authoring import add, build_lifecycle, issues, section
from tests.test_script_authoring import Draft, approve, ok
from tests.test_script_simulation import case_where, post

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # this module publishes scripts; reset afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="wchk")


def put(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
    r = c.put(f"/api/v1{path}", json=body, headers=csrf_header(c))
    assert r.status_code == status, r.text
    out: dict[str, Any] = r.json()
    return out


def counts(db: Session) -> dict[str, int]:
    out = {
        t: db.execute(text(f"SELECT count(*) FROM {SCHEMA}.{t}")).scalar_one()
        for t in (
            "simulation_scenario",
            "simulation_scenario_revision",
            "simulation_batch",
            "simulation_result",
            "simulation_content_snapshot",
        )
    }
    db.rollback()
    return out


def operational(db: Session) -> tuple[Any, ...]:
    """Operational records simulations must never touch (script versions change here only by governed authoring)."""
    row = db.execute(
        text(
            f"SELECT (SELECT count(*) FROM {SCHEMA}.script_assignment), "
            f"(SELECT count(*) FROM {SCHEMA}.contact_attempt), "
            f"(SELECT count(*) FROM {SCHEMA}.conversation_session), (SELECT count(*) FROM {SCHEMA}.survey_run), "
            f"(SELECT count(*) FROM {SCHEMA}.finding), (SELECT count(*) FROM {SCHEMA}.rule_evaluation), "
            f"(SELECT string_agg(id::text || released_at::text, ',' ORDER BY id) FROM {SCHEMA}.case_hold), "
            f"(SELECT string_agg(id::text || state || has_blocking_hold::text || row_version::text, ',' ORDER BY id) "
            f"FROM {SCHEMA}.callback_case)"
        )
    ).one()
    db.rollback()
    return tuple(row)


def scenario(vid: str, name: str, steps: list[dict[str, Any]], exp: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": "S2-E test (synthetic)",
        "script_version_id": vid,
        "facts": {"product_family": "PROTECTION", "is_ilp": False},
        "risk_band": "LOW",
        "steps": steps,
        "expectations": exp,
        **kw,
    }


def test_workbench_end_to_end(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, admin: Account, db: Session
) -> None:
    login(client, user)
    vid, d = build_lifecycle(client, "WB_A")  # a DRAFT lifecycle script (opening … closing)
    case_id = case_where(db, "true", 1)
    db.rollback()
    before = operational(db)

    # 1. Interactive draft simulation: VERSION_TEST from a snapshot, never an assignment.
    plan = ok(client.get("/api/v1/script-simulations/plan", params={"case_id": case_id, "script_version_id": vid}))
    assert plan["mode"] == "VERSION_TEST" and plan["version_status"] == "DRAFT"
    assert plan["live_eligibility"]["structurally_eligible"] is True
    run = post(client, "/script-simulations", {"case_id": case_id, "script_version_id": vid}, 201)
    a = run["next_action"]
    run = post(client, f"/script-simulations/{run['id']}/delivery", {"action_id": a["action_id"], "delivered": True})
    a = run["next_action"]
    run = post(client, f"/script-simulations/{run['id']}/delivery", {"action_id": a["action_id"], "delivered": True})
    run = post(
        client,
        f"/script-simulations/{run['id']}/answer",
        {"action_id": a["action_id"], "kind": "ANSWER", "value": False},
    )  # identity: no
    run = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    assert run["outcome"] == "TERMINATED"
    mode, assignment, csha = db.execute(
        text(f"SELECT mode, script_assignment_id, content_sha256 FROM {SCHEMA}.script_simulation_run WHERE id = :r"),
        {"r": run["id"]},
    ).one()
    db.rollback()
    assert (mode, assignment) == ("VERSION_TEST", None) and csha == plan["manifest_sha256"]
    # 2. Save the interactive run as a scenario (round trip): expectations are its actual result.
    recorded = ok(client.get(f"/api/v1/script-simulations/{run['id']}/as-scenario"))
    assert recorded["steps"] == [
        {"question": "Q-WB_A-ID", "kind": "ANSWER", "value": False, "event": None, "note": None}
    ]
    assert recorded["expectations"]["termination_reason"] == "IDENTITY_FAILED"
    s_fail = post(client, "/simulation-scenarios", recorded | {"name": "Identity failure (recorded)"}, 201)
    assert s_fail["scenario_ref"].startswith("SCN-") and s_fail["revision"] == 1

    # 3. More scenarios: normal, consent refused, a wrong expectation, and a strict one.
    normal = post(
        client,
        "/simulation-scenarios",
        scenario(
            vid,
            "Normal closing",
            [],
            {
                "outcome": "COMPLETED",
                "termination_reason": "NONE",
                "mandatory_complete": True,
                "gates": {"identity": "CONFIRMED", "willingness": "AGREED", "recording_consent": "GRANTED"},
            },
        ),
        201,
    )
    refused = post(
        client,
        "/simulation-scenarios",
        scenario(
            vid,
            "Declines to proceed",
            [{"question": "Q-WB_A-PROCEED", "kind": "ANSWER", "value": False}],
            {"outcome": "TERMINATED", "termination_reason": "DECLINED_TO_PROCEED"},
        ),
        201,
    )
    wrong = post(
        client,
        "/simulation-scenarios",
        scenario(
            vid,
            "Wrong expectation",
            [{"question": "Q-WB_A-REC", "kind": "ANSWER", "value": False}],
            {"outcome": "TERMINATED", "gates": {"recording_consent": "GRANTED"}},
        ),
        201,
    )
    bad = client.post(
        "/api/v1/simulation-scenarios",
        json=scenario(vid, "Bad", [{"question": "Q-X", "kind": "EVENT", "event": "NOPE"}], {}),
        headers=csrf_header(client),
    )
    assert bad.status_code == 422 and bad.json()["code"] == "INVALID_SCENARIO"
    preview_before = counts(db)
    dry = post(client, "/simulation-scenarios/preview", scenario(vid, "Dry", [], {"outcome": "COMPLETED"}))
    assert dry["status"] == "PASSED" and counts(db) == preview_before  # a dry run writes nothing

    # 4. Batch run: passed / failed with explanations; snapshot and revision preserved.
    ids = [s_fail["id"], normal["id"], refused["id"], wrong["id"]]
    batch = post(client, "/simulation-runs", {"scenario_ids": ids}, 201)
    by = {r["scenario_name"]: r for r in batch["results"]}
    assert batch["totals"]["A"] == {"PASSED": 3, "FAILED": 1, "ERROR": 0, "INVALID": 0, "STALE": 0, "TOTAL": 4}
    failed = by["Wrong expectation"]
    assert failed["status"] == "FAILED" and {f["check"] for f in failed["failures"]} == {
        "outcome",
        "gate:recording_consent",
    }
    assert "expected granted, got declined" in failed["failures"][1]["message"]
    snap = db.execute(
        text(f"SELECT content FROM {SCHEMA}.simulation_content_snapshot WHERE sha256 = :s"),
        {"s": failed["content_sha256"]},
    ).scalar_one()
    db.rollback()
    assert any(q["question_code"] == "Q-WB_A-REC" for s in snap["sections"] for q in s["questions"])
    cov = batch["coverage"][0]
    assert cov["questions_not_exercised"] == [] and "NORMAL_COMPLETION" in cov["lifecycle_paths_exercised"]
    assert (
        "IDENTITY_FAILED" in cov["lifecycle_paths_exercised"] and "INTERRUPTED" in cov["lifecycle_paths_not_exercised"]
    )

    # 5. Versioning: revise (new revision), stale token refused, copy, archive.
    sc = ok(client.get(f"/api/v1/simulation-scenarios/{wrong['id']}"))
    fixed = put(
        client,
        f"/simulation-scenarios/{wrong['id']}",
        {
            "expected_row_version": sc["row_version"],
            "change_note": "Recording declined continues",
            "content": sc["content"]
            | {"expectations": {"outcome": "COMPLETED", "gates": {"recording_consent": "DECLINED"}}},
        },
    )
    assert fixed["revision"] == 2 and [r["revision"] for r in fixed["revisions"]] == [2, 1]
    stale = client.put(
        f"/api/v1/simulation-scenarios/{wrong['id']}",
        json={"expected_row_version": sc["row_version"], "content": sc["content"]},
        headers=csrf_header(client),
    )
    assert stale.status_code == 409 and stale.json()["code"] == "STALE_SCENARIO"
    r1 = ok(client.get(f"/api/v1/simulation-scenarios/{wrong['id']}", params={"revision": 1}))
    assert r1["content"]["expectations"]["outcome"] == "TERMINATED"  # earlier revision kept
    again = post(client, "/simulation-runs", {"scenario_ids": [wrong["id"]]}, 201)
    assert again["results"][0]["status"] == "PASSED" and again["results"][0]["revision"] == 2
    old = ok(client.get(f"/api/v1/simulation-runs/{batch['id']}"))
    assert next(r for r in old["results"] if r["scenario_id"] == wrong["id"])["revision"] == 1  # history unchanged
    cp = post(client, f"/simulation-scenarios/{normal['id']}/copy", {"name": "Normal closing (copy)"}, 201)
    assert cp["copied_from_ref"] == normal["scenario_ref"]
    arch = post(
        client,
        f"/simulation-scenarios/{cp['id']}/status",
        {"expected_row_version": cp["row_version"], "status": "ARCHIVED"},
    )
    assert arch["status"] == "ARCHIVED"
    blocked = client.put(
        f"/api/v1/simulation-scenarios/{cp['id']}",
        json={"expected_row_version": arch["row_version"], "content": cp["content"]},
        headers=csrf_header(client),
    )
    assert blocked.json()["code"] == "SCENARIO_ARCHIVED"
    assert cp["id"] not in {s["id"] for s in ok(client.get("/api/v1/simulation-scenarios"))["items"]}

    # 6. Draft edits after saving make scenarios stale (still run); a removed question makes one invalid.
    sec_id = next(s["section_id"] for s in d.sections() if s["module_code"] == "WB_A_CORE")
    add(d, sec_id, "Q-WB_A-EXTRA", answer_type="YES_NO", expected_answer_policy="COLLECT_ONLY", mandatory=False)
    after_edit = post(client, "/simulation-runs", {"scenario_ids": [normal["id"]]}, 201)
    res = after_edit["results"][0]
    assert res["status"] == "PASSED" and res["stale"] and "content changed" in res["stale_reasons"][0]
    assert res["content_sha256"] != batch["results"][0]["content_sha256"]  # a new exact snapshot

    # 7. Publish A, open draft B, change it, compare A vs B.
    assert not issues(d).get("ERROR")
    d.post("/submit", {"change_summary": "Workbench version A"})
    login(other_client, checker)
    for step, body in (("review", approve(other_client, vid)), ("publish", {})):
        ok(other_client.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(other_client)))
    fam = ok(client.get(f"/api/v1/script-versions/{vid}"))["script_family_id"]
    vb = ok(client.post(f"/api/v1/scripts/{fam}/drafts", json={}, headers=csrf_header(client)), 201)[
        "script_version_id"
    ]
    db2 = Draft(client, vb)
    core = next(s for s in db2.sections() if s["module_code"] == "WB_A_CORE")
    extra = next(q for q in core["questions"] if q["question_code"] == "Q-WB_A-EXTRA")
    db2.delete(f"/sections/{core['section_id']}/questions/{extra['module_question_id']}")
    rec = section(db2, "WB_B_CONSENT2", "CONSENT")
    add(
        db2,
        rec,
        "Q-WB_B-CLOUD",
        lifecycle_role="CLOUD_PROCESSING_CONSENT",
        answer_type="YES_NO",
        expected_answer_policy="COLLECT_ONLY",
        mandatory=False,
        on_failure="TERMINATE",
    )
    cloud_refused = post(
        client,
        "/simulation-scenarios",
        scenario(
            vb,
            "Cloud refused terminates in B",
            [{"question": "Q-WB_B-CLOUD", "kind": "ANSWER", "value": False}],
            {"outcome": "TERMINATED"},
        ),
        201,
    )
    cmp = post(
        client,
        "/simulation-runs",
        {"scenario_ids": [normal["id"], cloud_refused["id"]], "script_version_id": vid, "compare_with_version_id": vb},
        201,
    )
    assert cmp["kind"] == "COMPARISON" and cmp["version_a"].endswith("v1.0") and cmp["version_b"].endswith("v1.1")
    rows = {c["scenario_name"]: c for c in cmp["comparison"]}
    pd = rows["Normal closing"]["plan_diff"]
    assert pd["only_in_a"] == ["Q-WB_A-EXTRA"] and pd["only_in_b"] == ["Q-WB_B-CLOUD"]
    assert any(x["field"] == "sequence" for x in rows["Normal closing"]["outcome_diff"])
    assert (rows["Cloud refused terminates in B"]["status_a"], rows["Cloud refused terminates in B"]["status_b"]) == (
        "INVALID",
        "PASSED",
    )  # the question does not exist in A
    assert {c["side"] for c in cmp["coverage"]} == {"A", "B"}

    # 8. Authorization: ADMIN cannot write; the checker can run; other markets are invisible.
    login(other_client, admin)
    for path, body in (
        ("/api/v1/simulation-runs", {"scenario_ids": [normal["id"]]}),
        ("/api/v1/simulation-scenarios", scenario(vid, "Admin", [], {})),
    ):
        assert other_client.post(path, json=body, headers=csrf_header(other_client)).status_code == 403
    login(other_client, checker)
    assert post(other_client, "/simulation-runs", {"scenario_ids": [normal["id"]]}, 201)["totals"]["A"]["TOTAL"] == 1
    assert client.get("/api/v1/simulation-scenarios/00000000-0000-0000-0000-000000000000").status_code == 404

    # 9. Nothing operational changed: no assignment, attempt, session, survey run, finding, hold or case change.
    assert operational(db) == before
