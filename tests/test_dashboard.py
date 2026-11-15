"""F1 — Overview APIs (API-030…034): BE-KPI-01 (hand-computed), BE-KPI-03 (scope before aggregation),
BE-KPI-04 (NOT_MEASURED), BE-KPI-06 (SLA-EX-001), D-39 (no MY leakage), permissions."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.domain.kpis import compute_kpis, kpi_10, load_facts, local_range
from app.domain.outcomes import derive_outcomes
from tests.domain_support import SCHEMA
from tests.support import Account, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")
WIDE = {"from": "2026-03-01", "to": "2027-01-01"}  # covers every seeded due date (Apr–Dec 2026)
START, END = date(2026, 3, 1), date(2027, 1, 1)


def kpis(client: TestClient, **params: str) -> dict[str, dict[str, Any]]:
    r = client.get("/api/v1/dashboard/kpis", params=params)
    assert r.status_code == 200, r.text
    return {k["definition_id"]: k for k in r.json()["items"]}


def one(conn: Connection, sql: str, **p: Any) -> Any:
    return conn.execute(text(sql.replace("§", SCHEMA + ".")), p).scalar_one()


def test_be_kpi_01_values_match_independent_sql(client: TestClient, admin: Account, conn: Connection) -> None:
    login(client, admin)
    k = kpis(client, **WIDE)
    s, e = local_range(START, END)
    rng = {"s": s, "e": e}
    sg = "c.market_code = 'SG' AND c.due_at >= :s AND c.due_at < :e"
    den1 = one(conn, f"SELECT count(*) FROM §callback_case c WHERE {sg} AND c.state <> 'CANCELLED'", **rng)
    num1 = one(
        conn,
        f"SELECT count(*) FROM §callback_case c WHERE {sg} AND c.state <> 'CANCELLED' AND EXISTS "
        "(SELECT 1 FROM §contact_attempt a WHERE a.callback_case_id = c.id AND a.status <> 'SCHEDULED')",
        **rng,
    )
    assert (k["KPI-01"]["denominator"], k["KPI-01"]["numerator"]) == (den1, num1)
    att = (
        "FROM §contact_attempt a JOIN §callback_case c ON c.id = a.callback_case_id WHERE c.market_code = 'SG' "
        "AND a.started_at >= :s AND a.started_at < :e AND a.status IN "
        "('NO_ANSWER','BUSY','WRONG_PARTY','FAILED','CONNECTED','IN_SESSION','ENDED')"
    )
    assert k["KPI-02"]["denominator"] == one(conn, f"SELECT count(*) {att}", **rng)
    assert k["KPI-02"]["numerator"] == one(
        conn, f"SELECT count(*) {att} AND a.status IN ('CONNECTED','IN_SESSION','ENDED')", **rng
    )
    runs = (
        "FROM §survey_run r JOIN §conversation_session s2 ON s2.id = r.session_id JOIN §contact_attempt a ON "
        "a.id = s2.contact_attempt_id JOIN §callback_case c ON c.id = a.callback_case_id WHERE c.market_code = 'SG' "
        "AND r.started_at >= :s AND r.started_at < :e AND r.status <> 'NOT_STARTED'"
    )
    assert k["KPI-03"]["denominator"] == one(conn, f"SELECT count(*) {runs}", **rng)
    assert k["KPI-03"]["numerator"] == one(conn, f"SELECT count(*) {runs} AND r.status = 'COMPLETED'", **rng)
    assert k["KPI-18"]["denominator"] == one(conn, f"SELECT count(*) FROM §callback_case c WHERE {sg}", **rng)
    assert k["KPI-18"]["numerator"] == one(
        conn, f"SELECT count(*) FROM §callback_case c WHERE {sg} AND c.state = 'CANCELLED'", **rng
    )
    assert k["OPS-04"]["numerator"] == one(
        conn, "SELECT count(*) FROM §callback_case WHERE market_code = 'SG' AND state = 'AWAITING_REVIEW'"
    )
    sg_outcomes = [o for ref, o in derive_outcomes(conn, SCHEMA, ["SG"]).items()]
    assert k["OPS-01"]["numerator"] == sum(o.category == "OPEN" for o in sg_outcomes)
    counts = k["KPI-15"]["breakdown"]["counts"]
    for cat in ("VERIFIED_COMPLIANT", "VERIFIED_WITH_FINDINGS", "NOT_VERIFIED", "CANCELLED", "OPEN"):
        assert counts[cat] == sum(o.category == cat for o in sg_outcomes), cat
    assert k["KPI-15"]["breakdown"]["guard_count"] == 0
    assert k["KPI-04"]["numerator"] == counts["VERIFIED_COMPLIANT"] + counts["VERIFIED_WITH_FINDINGS"]
    assert k["KPI-04"]["denominator"] == den1
    assert k["KPI-04"]["value"] == round(100 * k["KPI-04"]["numerator"] / den1, 1)


def test_d39_singapore_only_everywhere(client: TestClient, admin: Account, conn: Connection) -> None:
    login(client, admin)
    sg_total = one(conn, "SELECT count(*) FROM §callback_case WHERE market_code = 'SG'")
    assert sg_total == 195 and one(conn, "SELECT count(*) FROM §callback_case") == 250
    k = kpis(client, **WIDE)
    assert k["KPI-15"]["numerator"] == sg_total
    assert all(x["filter_scope"] == {"markets": ["SG"]} for x in k.values())
    my_refs = {
        r[0] for r in conn.execute(text(f"SELECT case_ref FROM {SCHEMA}.callback_case WHERE market_code = 'MY'"))
    }
    att = client.get("/api/v1/dashboard/attention", params={"limit": 20}).json()
    act = client.get("/api/v1/dashboard/activity", params={"limit": 50}).json()
    assert att["items"] and act["items"]
    assert not {i["case_ref"] for i in att["items"]} & my_refs
    assert not {i["case_ref"] for i in act["items"]} & my_refs
    now = datetime.now(UTC).isoformat()
    assert all(i["occurred_at"] <= now for i in act["items"])  # recent = already happened
    risk = client.get("/api/v1/dashboard/risk-distribution").json()
    assert risk["total_open"] == k["OPS-01"]["numerator"]
    assert risk["markets"] == att["markets"] == act["markets"] == ["SG"]


def test_be_kpi_03_scope_is_applied_before_aggregation(conn: Connection) -> None:
    now = datetime.now(UTC)
    sg = {k["definition_id"]: k for k in compute_kpis(load_facts(conn, SCHEMA, ["SG"], now), START, END, frozenset())}
    both = {
        k["definition_id"]: k
        for k in compute_kpis(load_facts(conn, SCHEMA, ["SG", "MY"], now), START, END, frozenset())
    }
    none = {k["definition_id"]: k for k in compute_kpis(load_facts(conn, SCHEMA, [], now), START, END, frozenset())}
    assert (sg["KPI-15"]["numerator"], both["KPI-15"]["numerator"], none["KPI-15"]["numerator"]) == (195, 250, 0)
    assert all(k["value"] in (None, 0.0) for k in none.values())


def test_be_kpi_04_not_measured_never_returns_a_number(client: TestClient, admin: Account) -> None:
    login(client, admin)
    k = kpis(client)
    for kid in ("KPI-08", "KPI-09", "KPI-14", "OPS-06"):
        assert k[kid]["status"] == "NOT_MEASURED" and k[kid]["value"] is None and k[kid]["stage_note"], kid
    assert "Stage S1" in k["KPI-08"]["stage_note"]


def test_be_kpi_06_sla_ex_001_on_seeded_cancellations(conn: Connection) -> None:
    f = load_facts(conn, SCHEMA, ["SG"], datetime.now(UTC))
    s, e = local_range(START, END)
    den, num = kpi_10(f, s, e)
    by_ref = {c.ref: c.id for c in f.cases.values()}
    assert by_ref["CB-2026-10494"] not in den  # valid exemption: excluded from numerator and denominator
    assert by_ref["CB-2026-10495"] in den and by_ref["CB-2026-10495"] in num  # no authorisation
    assert by_ref["CB-2026-10496"] in den and by_ref["CB-2026-10496"] in num  # recorded after due_at
    assert by_ref["CB-2026-10498"] in num  # held past due: the hold does not pause SLA


def test_user_and_admin_see_the_same_sg_numbers(
    client: TestClient, other_client: TestClient, admin: Account, user: Account
) -> None:
    login(client, admin)
    login(other_client, user)
    a = kpis(client, **WIDE)
    u = {k["definition_id"]: k for k in other_client.get("/api/v1/dashboard/kpis", params=WIDE).json()["items"]}
    assert {k: (v["numerator"], v["denominator"]) for k, v in a.items() if k != "KPI-14"} == {
        k: (v["numerator"], v["denominator"]) for k, v in u.items()
    }
    assert "KPI-14" in a and "KPI-14" not in u  # intake KPI is ADMIN-only (intake.read)


def test_principal_without_market_scope_sees_no_business_data(client: TestClient, db: Session) -> None:
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))
    k = kpis(client, **WIDE)
    assert all((v["numerator"] or 0) == 0 and v["value"] in (None, 0.0) for v in k.values())
    assert client.get("/api/v1/dashboard/attention").json()["items"] == []
    assert client.get("/api/v1/dashboard/activity").json()["items"] == []
    assert client.get("/api/v1/dashboard/risk-distribution").json()["total_open"] == 0


def test_permissions_and_validation(client: TestClient, db: Session) -> None:
    assert client.get("/api/v1/dashboard/kpis").status_code == 401
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    for path in ("kpis", "trend", "attention", "activity", "risk-distribution"):
        assert client.get(f"/api/v1/dashboard/{path}").status_code == 403, path


def test_range_trend_and_drilldowns(client: TestClient, admin: Account) -> None:
    login(client, admin)
    bad = client.get("/api/v1/dashboard/kpis", params={"from": "2026-11-15", "to": "2026-11-01"})
    assert bad.status_code == 422 and bad.json()["code"] == "INVALID_RANGE"
    k = kpis(client)
    assert k["KPI-01"]["range"]["to"] > k["KPI-01"]["range"]["from"]
    assert k["KPI-01"]["drilldown"]["numerator"].startswith("/calls?kpi=KPI-01&kpi_set=numerator")
    assert all(v["reporting_version"] == "S0-KPI-2" and v["synthetic_badge"] for v in k.values())
    t = client.get("/api/v1/dashboard/trend", params={"kpi": "KPI-02", "days": 7}).json()
    assert len(t["points"]) == 7 and t["markets"] == ["SG"]
    assert client.get("/api/v1/dashboard/trend", params={"days": 10}).status_code == 422
    assert client.get("/api/v1/dashboard/trend", params={"kpi": "KPI-99"}).status_code == 422
    risk = client.get("/api/v1/dashboard/risk-distribution").json()
    assert [b["band"] for b in risk["items"]] == ["LOW", "MEDIUM", "HIGH", "UNKNOWN", "NOT_ASSESSED"]
    assert "not an automatic misconduct verdict" in risk["note"]
