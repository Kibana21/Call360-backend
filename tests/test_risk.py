"""F5 — SBQ Risk Workbench APIs (API-056…058): BE-API-03 (stored assessments with origin, factors, rule-set version,
input hash, source original value and supersedes chain), source-vs-rule discrepancies, effective and superseded
history, separate populations for assessments and sales, the golden fixture, BE-SEC-02 (MY / missing → identical
audited 404; no MY row, count or facet), separation from suitability and finding severity, paging and permissions."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from tests.domain_support import SCHEMA
from tests.support import Account, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")
SG = (
    f"FROM {SCHEMA}.risk_assessment ra JOIN {SCHEMA}.sale_event s ON s.id = ra.sale_event_id "
    f"JOIN {SCHEMA}.policy p ON p.id = s.policy_id WHERE p.market_code = 'SG'"
)


def get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    r = client.get(path, params=params)
    assert r.status_code == 200, (path, r.text)
    return r.json()


def all_rows(client: TestClient, limit: int = 50, **params: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = None
    while True:
        body = get(client, "/api/v1/risk-assessments", **params, limit=limit, **({"cursor": cursor} if cursor else {}))
        out.extend(body["items"])
        cursor = body["page"]["next_cursor"]
        if cursor is None:
            assert len(out) == body["total"]
            return out


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


def test_register_is_assessment_grain_and_singapore_only(signed_in: TestClient, conn: Connection) -> None:
    rows = all_rows(signed_in)
    assert len(rows) == len({r["id"] for r in rows}) == conn.execute(text(f"SELECT count(*) {SG}")).scalar_one()
    assert all(r["policy_ref"].startswith("POL-SG-") and r["sale_ref"].startswith("SALE-SG-") for r in rows)
    assert {r["origin"] for r in rows} == {"SOURCE_ASSIGNED", "RULE_ASSESSED"}
    rule = [r for r in rows if r["origin"] == "RULE_ASSESSED"]
    assert all(r["rule_set"] and r["input_snapshot_sha256"] for r in rule)  # RISK-003 traceability
    assert all(r["source_original_value"] for r in rows if r["origin"] == "SOURCE_ASSIGNED")
    assert all(r["score"] is None for r in rows)  # no score stored, none computed (C-17, RISK-008)
    blob = json.dumps(rows)
    assert "suitability" not in blob and "risk_tolerance" not in blob and "severity" not in blob


def test_summary_keeps_assessment_and_sale_populations_separate(signed_in: TestClient, conn: Connection) -> None:
    s = get(signed_in, "/api/v1/risk-assessments", band="HIGH")["summary"]  # filters never change the summary
    a, sales = s["assessments"], s["sales"]
    assert a["total"] == conn.execute(text(f"SELECT count(*) {SG}")).scalar_one()
    assert sum(a["by_origin"].values()) == sum(a["by_status"].values()) == sum(a["by_band"].values()) == a["total"]
    n_sales = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.sale_event s JOIN {SCHEMA}.policy p ON p.id = s.policy_id "
            "WHERE p.market_code = 'SG'"
        )
    ).scalar_one()
    assert sales["total"] == n_sales
    assert (
        sum(sales["by_effective_band"].values()) + sales["without_assessment"] + sales["without_final_assessment"]
        == n_sales
    )
    effective = [r for r in all_rows(signed_in, limit=100) if r["effective"]]
    assert len(effective) == sum(sales["by_effective_band"].values())  # exactly one effective assessment per sale
    assert len({r["sale_event_id"] for r in effective}) == len(effective)


def test_source_versus_rule_discrepancies(signed_in: TestClient, conn: Connection) -> None:
    rows = all_rows(signed_in, discrepancy="true")
    expected = conn.execute(
        text(
            f"SELECT DISTINCT s.sale_ref FROM {SCHEMA}.risk_assessment a JOIN {SCHEMA}.risk_assessment b "
            "ON a.sale_event_id = b.sale_event_id AND a.origin = 'SOURCE_ASSIGNED' AND b.origin = 'RULE_ASSESSED' "
            "AND a.status = 'FINAL' AND b.status = 'FINAL' AND a.band_code <> b.band_code "
            f"JOIN {SCHEMA}.sale_event s ON s.id = a.sale_event_id JOIN {SCHEMA}.policy p ON p.id = s.policy_id "
            "WHERE p.market_code = 'SG'"
        )
    ).scalars()
    sales = {r["sale_ref"] for r in rows}
    assert sales == set(expected) and sales
    assert get(signed_in, "/api/v1/risk-assessments")["summary"]["sales"]["source_rule_discrepancies"] == len(sales)
    d = get(signed_in, f"/api/v1/risk-assessments/{rows[0]['id']}")
    cmp = d["comparison"]
    assert cmp["discrepancy"] and cmp["source_band"] != cmp["rule_band"]
    assert {h["origin"] for h in d["history"]} == {"SOURCE_ASSIGNED", "RULE_ASSESSED"}
    eff = next(h for h in d["history"] if h["effective"])
    assert eff["id"] == cmp["effective_id"] and eff["band_code"] == cmp["effective_band"]


def test_superseded_history_and_chain(signed_in: TestClient) -> None:
    sup = all_rows(signed_in, status="SUPERSEDED")
    assert sup and all(not r["effective"] and r["superseded_by"] for r in sup)
    d = get(signed_in, f"/api/v1/risk-assessments/{sup[0]['id']}")
    successor = next(h for h in d["history"] if h["id"] == d["superseded_by"])
    assert successor["supersedes_id"] == d["id"] and successor["status"] == "FINAL"
    assert [h["valid_at"] for h in d["history"]] == sorted(h["valid_at"] for h in d["history"])


def test_golden_10482_rule_assessment_detail(signed_in: TestClient, conn: Connection) -> None:
    rows = all_rows(signed_in, q="CB-2026-10482")
    assert {r["origin"] for r in rows} == {"SOURCE_ASSIGNED", "RULE_ASSESSED"}
    rule = next(r for r in rows if r["origin"] == "RULE_ASSESSED")
    d = get(signed_in, f"/api/v1/risk-assessments/{rule['id']}")
    assert (d["band_code"], d["effective"], d["policy_ref"]) == ("HIGH", True, "POL-SG-000001")
    assert [c["case_ref"] for c in d["cases"]] == ["CB-2026-10482"] and d["cases"][0]["route"].startswith("/cases/")
    ilp = next(f for f in d["factors"] if f["factor_code"] == "ILP_INDICATOR")
    assert ilp["result"] == "MATCHED" and ilp["label"] == "Investment-linked indicator" and ilp["value"] is True
    assert d["rule_set_version"]["code"] == "SYN-SBQ-RULES" and len(d["rule_set_version"]["checksum"]) == 64
    assert d["provenance"]["is_synthetic"] and d["kind"] == "CALLBACK_SELECTION"


@pytest.mark.parametrize("sort", ["-valid_at", "band", "sale_ref", "-origin"])
def test_sort_and_cursor_have_no_gaps_or_duplicates(signed_in: TestClient, sort: str) -> None:
    assert [r["id"] for r in all_rows(signed_in, limit=13, sort=sort)] == [
        r["id"] for r in all_rows(signed_in, limit=100, sort=sort)
    ]


def test_filters_and_facets(signed_in: TestClient) -> None:
    body = get(signed_in, "/api/v1/risk-assessments", factor="ILP_INDICATOR", origin="RULE_ASSESSED", limit=100)
    assert body["total"] and all("ILP_INDICATOR" in r["matched_factors"] for r in body["items"])
    assert body["facets"]["factor"]["ILP_INDICATOR"] == body["total"]
    assert sum(body["facets"]["origin"].values()) >= body["total"]  # origin facet ignores its own selection
    eff = get(signed_in, "/api/v1/risk-assessments", effective="true", band="HIGH", limit=100)
    assert all(r["effective"] and r["band_code"] == "HIGH" for r in eff["items"])
    v2 = get(signed_in, "/api/v1/risk-assessments", rule_set="SYN-SBQ-RULES v2", limit=100)
    assert v2["total"] and all(r["rule_set"] == "SYN-SBQ-RULES v2" for r in v2["items"])
    assert signed_in.get("/api/v1/risk-assessments", params={"sort": "score"}).status_code == 422


def test_factor_vocabulary(signed_in: TestClient) -> None:
    v = get(signed_in, "/api/v1/risk-factors")
    assert v["status"] == "ACTIVE" and {i["code"] for i in v["items"]} >= {"ILP_INDICATOR", "SELLING_CHANNEL"}
    assert {b["code"] for b in v["bands"]} >= {"HIGH", "MEDIUM", "LOW"}


def test_be_sec_02_malaysian_assessments_are_identical_audited_404s(
    client: TestClient, admin: Account, conn: Connection
) -> None:
    login(client, admin)
    my = conn.execute(
        text(SG.replace("'SG'", "'MY'").replace("FROM", "SELECT ra.id, s.sale_ref FROM", 1) + " LIMIT 1")
    ).one()
    out_of_scope, missing = (
        client.get(f"/api/v1/risk-assessments/{my.id}"),
        client.get(f"/api/v1/risk-assessments/{uuid.uuid4()}"),
    )
    assert out_of_scope.status_code == missing.status_code == 404
    assert {k: v for k, v in out_of_scope.json().items() if k != "correlation_id"} == {
        k: v for k, v in missing.json().items() if k != "correlation_id"
    }
    assert (
        conn.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'ACCESS.DENIED_OBJECT' "
                "AND entity_type = 'risk_assessment' AND entity_id = :i"
            ),
            {"i": str(my.id)},
        ).scalar_one()
        >= 1
    )
    for q in (my.sale_ref, "SALE-MY", "POL-MY", "CB-2026-2"):
        body = get(client, "/api/v1/risk-assessments", q=q)
        assert body["total"] == 0 and not any(body["facets"]["origin"].values()), q
    whole = json.dumps(all_rows(client, limit=100))
    assert "POL-MY" not in whole and "SALE-MY" not in whole and "CB-2026-2" not in whole


def test_permissions(client: TestClient, db: Session, conn: Connection) -> None:
    rid = conn.execute(text(f"SELECT ra.id {SG} LIMIT 1")).scalar_one()
    assert client.get("/api/v1/risk-assessments").status_code == 401
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    for path in ("/api/v1/risk-assessments", f"/api/v1/risk-assessments/{rid}", "/api/v1/risk-factors"):
        assert client.get(path).status_code == 403, path
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))  # permissions but no market
    assert client.get(f"/api/v1/risk-assessments/{rid}").status_code == 404
    assert get(client, "/api/v1/risk-assessments")["total"] == 0
