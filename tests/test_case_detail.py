"""F3 — Call Detail APIs (API-037…047, API-063): BE-API-01…04 on the twelve golden fixtures, BE-SEC-02 (every object
endpoint: MY / missing id → identical audited 404), historical script pins (T-15), masking and permissions."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from tests.domain_support import SCHEMA
from tests.support import Account, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")


def case_id(conn: Connection, ref: str) -> uuid.UUID:
    return conn.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE case_ref = :r"), {"r": ref}).scalar_one()


def get(client: TestClient, path: str) -> dict[str, Any]:
    r = client.get(path)
    assert r.status_code == 200, (path, r.text)
    return r.json()


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


def detail(client: TestClient, conn: Connection, ref: str) -> dict[str, Any]:
    return get(client, f"/api/v1/cases/{case_id(conn, ref)}")


# ---- golden fixtures -----------------------------------------------------------------------------------------
def test_golden_10482_full_investigation_trail(signed_in: TestClient, conn: Connection) -> None:
    cid = case_id(conn, "CB-2026-10482")
    d = get(signed_in, f"/api/v1/cases/{cid}")
    assert (d["state"], d["outcome"], d["market"], d["risk_band"]) == ("AWAITING_REVIEW", "OPEN", "SG", "HIGH")
    assert d["effective_risk"]["origin"] == "RULE_ASSESSED" and d["effective_risk"]["effective"] is True
    assert {a["origin"] for a in d["risk_assessments"]} == {"SOURCE_ASSIGNED", "RULE_ASSESSED"}
    assert any(f["factor_code"] == "ILP_INDICATOR" for f in d["effective_risk"]["factors"])
    assert (
        d["policy"]["policy_ref"] == "POL-SG-000001"
        and d["policy"]["is_ilp"]
        and d["policy"]["premium_term_years"] == 10
    )
    assert d["sale"]["fsc"]["fsc_ref"].startswith("FSC-") and d["sale"]["selling_channel"]
    assert d["current_script"]["family"] == "SALES_VERIFICATION_SG"
    assert (d["attempts"], d["sessions"], d["open_findings"]) == (3, 1, 1)
    snap = d["fact_snapshots"][0]
    assert snap["facts"]["premium_term_years"] == 10 and len(snap["sha256"]) == 64
    assert "suitability" in snap["facts"]  # investment suitability fact kept separate from SBQ selection risk

    attempts = get(signed_in, f"/api/v1/cases/{cid}/attempts")["items"]
    assert [a["status"] for a in attempts] == ["NO_ANSWER", "BUSY", "CONNECTED"]
    assert [a["session"] is not None for a in attempts] == [False, False, True]
    assert all("•" in a["contact_snapshot"]["masked_value"] for a in attempts)
    assert get(signed_in, f"/api/v1/attempts/{attempts[0]['id']}")["attempt_ref"] == "AT-2026-10482-1"

    link = attempts[2]["session"]
    s = get(signed_in, f"/api/v1/sessions/{link['session_id']}")
    assert s["session_ref"] == "SS-2026-10482" and s["script_pin_matches"] and s["fact_snapshot_pin_matches"]
    assert s["media_status"] and s["risk_assessment"]["band_code"] == "HIGH"
    for kind, msg in (("media", "Recording not available"), ("transcript", "Transcript not available")):
        a = get(signed_in, f"/api/v1/sessions/{link['session_id']}/{kind}")
        assert (a["availability"], a["reason"]) == ("NOT_AVAILABLE", "NO_CAPTURE_BEFORE_S1") and a[
            "message"
        ].startswith(msg)

    run = get(signed_in, f"/api/v1/survey-runs/{link['survey_run_id']}")
    assert run["status"] == "COMPLETED" and run["controls_satisfied"] is False
    term = next(q for q in run["questions"] if q["question_code"] == "Q-PREMIUM-TERM-YEARS")
    assert (
        term["expected_answer_policy"] == "NUMERIC_MATCH_POLICY_FACT"
        and term["policy_fact_key"] == "premium_term_years"
    )
    assert term["rule_result"] == "MISMATCH" and term["control_satisfied"] is False and term["findings"]
    assert term["rule_expected"] != term["rule_observed"]

    findings = get(signed_in, f"/api/v1/cases/{cid}/findings")
    assert [(f["severity"], f["category"], f["question_code"]) for f in findings["items"]] == [
        ("HIGH", "FACT_MISMATCH", "Q-PREMIUM-TERM-YEARS")
    ]
    assert findings["items"][0]["finding_ref"] in term["findings"] and "HIGH" in findings["material_severities"]
    trace = get(signed_in, f"/api/v1/cases/{cid}/script-assignment")["items"][0]
    assert trace["rule_trace"]["resolved_sections"] == ["COMMON_SALES_CONDUCT", "ILP", "ELEVATED_RISK"]
    assert trace["matched_rule"] and trace["input_snapshot"]["risk_band"] == "HIGH"
    timeline = get(signed_in, f"/api/v1/cases/{cid}/timeline")["items"]
    assert [e["event_type"] for e in timeline][:2] == ["CASE_CREATED", "RISK_RECORDED"]
    assert any(e["route"] and "?session=" in e["route"] for e in timeline)


def test_golden_10497_compliant_with_satisfied_controls(signed_in: TestClient, conn: Connection) -> None:
    d = detail(signed_in, conn, "CB-2026-10497")
    assert (d["state"], d["outcome"], d["controls_satisfied"], d["open_findings"]) == (
        "VERIFIED",
        "VERIFIED_COMPLIANT",
        True,
        0,
    )
    assert d["callable"] is False and d["callable_blockers"] == ["CASE_VERIFIED"]
    attempts = get(signed_in, f"/api/v1/cases/{d['case_id']}/attempts")["items"]
    run = get(signed_in, f"/api/v1/survey-runs/{attempts[-1]['session']['survey_run_id']}")
    assert run["controls_satisfied"] is True
    counted = [q for q in run["questions"] if q["control_satisfied"] is not None]
    assert counted and all(q["control_satisfied"] for q in counted) and all(q["mandatory"] for q in counted)
    sections = get(signed_in, f"/api/v1/cases/{d['case_id']}/script-assignment")["items"][0]["rule_trace"]
    assert sections["resolved_sections"] == ["COMMON_SALES_CONDUCT", "PROTECTION"]
    assert get(signed_in, f"/api/v1/cases/{d['case_id']}/findings")["items"] == []


@pytest.mark.parametrize(
    "ref, check",
    [
        (
            "CB-2026-10483",
            lambda d, a: d["attempts"] == 2 and d["sessions"] == 0 and all(x["session"] is None for x in a),
        ),
        ("CB-2026-10490", lambda d, a: "HOLD:AWAITING_SCRIPT_ASSIGNMENT" in d["callable_blockers"]),
        (
            "CB-2026-10491",
            lambda d, a: (
                "NO_ELIGIBLE_CONTACT" in d["callable_blockers"]
                and any(s["ineligibility_reason"] for s in d["contact_selection"])
            ),
        ),
        (
            "CB-2026-10492",
            lambda d, a: (
                "HOLD:RISK_TRIAGE" in d["callable_blockers"]
                and d["risk_band"] is None
                and d["policy"]["is_ilp"]
                and d["risk_assessments"] == []
            ),
        ),
        (
            "CB-2026-10493",
            lambda d, a: (
                (d["state"], d["outcome"], d["closure_reason"])
                == ("CLOSED_UNVERIFIED", "NOT_VERIFIED", "ATTEMPTS_EXHAUSTED")
            ),
        ),
        (
            "CB-2026-10494",
            lambda d, a: (
                d["outcome"] == "CANCELLED"
                and d["sla"]["exempt"]
                and d["sla"]["exemption_rule"] == "SLA-EX-001"
                and d["sla"]["breached"] is None
                and d["cancellation"]["sla_exempt"]
            ),
        ),
        (
            "CB-2026-10495",
            lambda d, a: (
                d["outcome"] == "CANCELLED"
                and not d["sla"]["exempt"]
                and d["cancellation"]["authorization_ref"] is None
            ),
        ),
        (
            "CB-2026-10496",
            lambda d, a: (
                d["outcome"] == "CANCELLED"
                and not d["sla"]["exempt"]
                and d["cancellation"]["recorded_at"] > d["due_at"]
            ),
        ),
        (
            "CB-2026-10498",
            lambda d, a: (
                "HOLD:RISK_TRIAGE" in d["callable_blockers"]
                and d["sla"]["matured"]
                and d["sla"]["breached"] is True
                and any(h["active"] for h in d["holds"])
            ),
        ),
    ],
)
def test_golden_fixtures(signed_in: TestClient, conn: Connection, ref: str, check: Any) -> None:
    d = detail(signed_in, conn, ref)
    a = get(signed_in, f"/api/v1/cases/{d['case_id']}/attempts")["items"]
    assert d["case_ref"] == ref and check(d, a), ref
    holds = get(signed_in, f"/api/v1/cases/{d['case_id']}/holds")["items"]
    assert holds == d["holds"]


def test_historical_script_pin_is_preserved(signed_in: TestClient, conn: Connection) -> None:
    """T-15: a session pinned to the now-SUPERSEDED 1.0 still shows that exact version and matching hash."""
    sid = conn.execute(
        text(
            f"SELECT s.id FROM {SCHEMA}.conversation_session s JOIN {SCHEMA}.script_version v "
            "ON v.id = s.script_version_id "
            f"JOIN {SCHEMA}.contact_attempt a ON a.id = s.contact_attempt_id JOIN {SCHEMA}.callback_case c "
            "ON c.id = a.callback_case_id WHERE v.status = 'SUPERSEDED' AND c.market_code = 'SG' LIMIT 1"
        )
    ).scalar_one()
    s = get(signed_in, f"/api/v1/sessions/{sid}")
    assert (s["script"]["version_label"], s["script"]["status"]) == ("1.0", "SUPERSEDED") and s["script_pin_matches"]
    v = get(signed_in, f"/api/v1/script-versions/{s['script']['script_version_id']}")
    assert v["status"] == "SUPERSEDED" and v["content_approval_status"] == "SYNTHETIC_UNAPPROVED" and v["sections"]
    assert all(q["wording"].startswith("[Synthetic") for sec in v["sections"] for q in sec["questions"])


def test_script_version_detail(signed_in: TestClient, conn: Connection) -> None:
    d = detail(signed_in, conn, "CB-2026-10482")
    v = get(signed_in, f"/api/v1/script-versions/{d['current_script']['script_version_id']}")
    assert v["market"] == "SG" and [s["module_code"] for s in v["sections"]][0] == "COMMON_SALES_CONDUCT"
    assert any(q["controls"] for s in v["sections"] for q in s["questions"])


def test_no_unmasked_personal_data(signed_in: TestClient, conn: Connection) -> None:
    cid = case_id(conn, "CB-2026-10482")
    blob = "".join(
        signed_in.get(p).text
        for p in (f"/api/v1/cases/{cid}", f"/api/v1/cases/{cid}/attempts", f"/api/v1/cases/{cid}/timeline")
    )
    assert "Example Policyholder" not in blob and "@example.invalid" not in blob.replace("•••@example.invalid", "")
    assert "SYN-TEL-SG-1" not in blob and "ciphertext" not in blob and "value_hmac" not in blob


# ---- BE-SEC-02 -----------------------------------------------------------------------------------------------
def test_be_sec_02_malaysian_and_missing_objects_are_identical_audited_404s(
    client: TestClient, admin: Account, conn: Connection
) -> None:
    login(client, admin)  # ADMIN is SG-only too (D-39)
    my = conn.execute(
        text(
            f"SELECT c.id AS c, a.id AS a, s.id AS s, r.id AS r, sv.id AS v FROM {SCHEMA}.callback_case c "
            f"JOIN {SCHEMA}.contact_attempt a ON a.callback_case_id = c.id JOIN {SCHEMA}.conversation_session s "
            f"ON s.contact_attempt_id = a.id JOIN {SCHEMA}.survey_run r ON r.session_id = s.id "
            f"JOIN {SCHEMA}.script_version sv ON sv.id = s.script_version_id WHERE c.market_code = 'MY' LIMIT 1"
        )
    ).one()
    gone = uuid.uuid4()
    paths = {
        "callback_case": [
            f"/api/v1/cases/{{}}{x}"
            for x in ("", "/attempts", "/script-assignment", "/timeline", "/findings", "/holds")
        ],
        "contact_attempt": ["/api/v1/attempts/{}"],
        "conversation_session": ["/api/v1/sessions/{}", "/api/v1/sessions/{}/media", "/api/v1/sessions/{}/transcript"],
        "survey_run": ["/api/v1/survey-runs/{}"],
        "script_version": ["/api/v1/script-versions/{}"],
    }
    ids = {
        "callback_case": my.c,
        "contact_attempt": my.a,
        "conversation_session": my.s,
        "survey_run": my.r,
        "script_version": my.v,
    }
    for entity, templates in paths.items():
        for tpl in templates:
            out_of_scope = client.get(tpl.format(ids[entity]))
            missing = client.get(tpl.format(gone))
            assert out_of_scope.status_code == missing.status_code == 404, tpl
            body = {k: v for k, v in out_of_scope.json().items() if k != "correlation_id"}
            assert body == {k: v for k, v in missing.json().items() if k != "correlation_id"}, tpl
        denied = conn.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'ACCESS.DENIED_OBJECT' "
                "AND entity_type = :t AND entity_id = :i"
            ),
            {"t": entity, "i": str(ids[entity])},
        ).scalar_one()
        assert denied >= len(templates), entity


def test_permissions(client: TestClient, db: Session, conn: Connection) -> None:
    cid = case_id(conn, "CB-2026-10482")
    assert client.get(f"/api/v1/cases/{cid}").status_code == 401
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    assert client.get(f"/api/v1/cases/{cid}").status_code == 403
    assert client.get(f"/api/v1/cases/{cid}/attempts").status_code == 403
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))  # permissions but no market → 404
    assert client.get(f"/api/v1/cases/{cid}").status_code == 404
