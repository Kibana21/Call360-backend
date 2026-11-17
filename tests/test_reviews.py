"""F7 — Review Workbench (API-077) and Voice Studio preflight (API-078): Singapore findings only, with case, policy,
sale, recorded question/answer/rule evidence and controls; awaiting-review queue vs all; search, filters, sorting and
paging; severity kept apart from the SBQ selection band; no review outcome fabricated; voice capability state;
permissions."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from tests.domain_support import SCHEMA
from tests.support import Account, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")
SG_FINDINGS = (
    f"FROM {SCHEMA}.finding f JOIN {SCHEMA}.callback_case c ON c.id = f.callback_case_id WHERE c.market_code = 'SG'"
)


def get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    r = client.get(path, params=params)
    assert r.status_code == 200, (path, r.text)
    return r.json()


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


def test_queue_lists_singapore_findings_with_context_and_evidence(signed_in: TestClient, conn: Connection) -> None:
    every = get(signed_in, "/api/v1/review-queue", queue="ALL", limit=100)
    assert every["markets"] == ["SG"]
    assert every["total"] == conn.execute(text(f"SELECT count(*) {SG_FINDINGS}")).scalar_one()
    awaiting = conn.execute(text(f"SELECT count(*) {SG_FINDINGS} AND f.status IN ('OPEN','UNDER_REVIEW')")).scalar_one()
    assert get(signed_in, "/api/v1/review-queue", limit=100)["total"] == awaiting
    for i in every["items"]:
        assert i["case_ref"].startswith("CB-2026-1") and i["policy_ref"].startswith("POL-SG-")
        assert i["sale_ref"].startswith("SALE-SG-")
        assert i["material"] == (i["severity"] in every["material_severities"])
        assert i["evidence"]["recording"] == "NOT_AVAILABLE" and i["evidence"]["transcript"] == "NOT_AVAILABLE"
        assert i["review_closed_at"] is None and not i["reviewer_assigned"]  # nothing adjudicated in S0
    with_rule = [i for i in every["items"] if i["evidence"]["rule_ref"]]
    assert with_rule and all(i["evidence"]["rule_result"] and i["evidence"]["question_code"] for i in with_rule)
    assert any(i["evidence"]["controls"] for i in every["items"])
    whole = json.dumps(every)
    assert "POL-MY" not in whole and "SALE-MY" not in whole and "CB-2026-2" not in whole


def test_severity_is_separate_from_selection_risk(signed_in: TestClient, conn: Connection) -> None:
    items = get(signed_in, "/api/v1/review-queue", queue="ALL", limit=100)["items"]
    assert {i["severity"] for i in items} <= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert {i["selection_risk_band"] for i in items} <= {"LOW", "MEDIUM", "HIGH", "UNKNOWN", "NOT_ASSESSED"}
    assert any(i["severity"] != i["selection_risk_band"] for i in items)
    assert all("suitability" not in k for i in items for k in i)
    one = items[0]
    case = get(signed_in, f"/api/v1/cases/{one['case_id']}")
    assert one["case_ref"] == case["case_ref"]


def test_filters_search_sort_and_paging(signed_in: TestClient) -> None:
    q = lambda **p: get(signed_in, "/api/v1/review-queue", queue="ALL", limit=100, **p)  # noqa: E731
    every = q()
    crit = q(severity="CRITICAL")
    assert crit["total"] == every["facets"]["severity"].get("CRITICAL", 0) > 0
    assert {i["severity"] for i in q(material=True)["items"]} <= {"HIGH", "CRITICAL"}
    ref = every["items"][3]
    assert [i["finding_ref"] for i in q(q=ref["finding_ref"].lower())["items"]] == [ref["finding_ref"]]
    assert ref["finding_ref"] in [i["finding_ref"] for i in q(q=ref["case_ref"])["items"]]
    ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sev = [ranks[i["severity"]] for i in every["items"]]
    assert sev == sorted(sev)  # default sort: most severe first
    newest = q(sort="-raised_at")["items"]
    assert [i["raised_at"] for i in newest] == sorted((i["raised_at"] for i in newest), reverse=True)
    p1 = get(signed_in, "/api/v1/review-queue", queue="ALL", limit=5, offset=0)
    p2 = get(signed_in, "/api/v1/review-queue", queue="ALL", limit=5, offset=5)
    assert p1["total"] == every["total"] and not {i["id"] for i in p1["items"]} & {i["id"] for i in p2["items"]}
    assert signed_in.get("/api/v1/review-queue", params={"severity": "SEVERE"}).status_code == 422


def test_voice_preflight_reports_the_s1a_state_honestly(signed_in: TestClient) -> None:
    """API-078 after S1-C: a mock-provider test session and consent-gated recording are available (default: not
    recorded); transcript, script control, identity verification and compliance evaluation are not."""
    v = get(signed_in, "/api/v1/voice/preflight")
    assert (v["status"], v["stage"], v["provider"]) == ("AVAILABLE", "S1-A", "MOCK")
    caps = {c["code"]: c["status"] for c in v["capabilities"]}
    assert caps["VOICE_SESSION"] == "AVAILABLE" and caps["RECORDING"] == "AVAILABLE"
    assert v["recording_notice"]["default_decision"] == "DECLINED" and v["recording_notice"]["approved_policy"] is False
    # S1-D: transcripts after a recorded session, by the local model configured in .env.test.
    assert caps["TRANSCRIPT"] == "AVAILABLE" and caps["SCRIPT_CONTROLLER"] == "NOT_AVAILABLE"
    assert (caps["IDENTITY"], caps["COMPLIANCE"]) == ("NOT_PERFORMED", "NOT_EVALUATED")
    assert v["test_message"][-1] == "This test does not verify an insurance transaction."


def test_permissions_and_scope(client: TestClient, db: Session) -> None:
    assert client.get("/api/v1/review-queue").status_code == 401
    assert client.get("/api/v1/voice/preflight").status_code == 401
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    assert client.get("/api/v1/review-queue").status_code == 403
    assert client.get("/api/v1/voice/preflight").status_code == 403
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))
    assert get(client, "/api/v1/review-queue", queue="ALL")["total"] == 0
    assert client.post("/api/v1/review-queue", json={}).status_code in (403, 405)  # no decision route in S0
