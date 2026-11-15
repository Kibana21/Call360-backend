"""F4 — Policy Explorer and Policy Detail APIs (API-050…055): BE-API-02 (typed policy, sale and party reads with
masking), multi-sale and top-up relationships, historical fact snapshots, record lineage, BE-SEC-02 (MY / missing
policy and sale → identical audited 404; no MY row, count, facet or search match), paging and permissions."""

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


def policy_id(conn: Connection, ref: str) -> uuid.UUID:
    return conn.execute(text(f"SELECT id FROM {SCHEMA}.policy WHERE policy_ref = :r"), {"r": ref}).scalar_one()


def get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    r = client.get(path, params=params)
    assert r.status_code == 200, (path, r.text)
    return r.json()


def all_policies(client: TestClient, limit: int = 40, **params: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = None
    while True:
        body = get(client, "/api/v1/policies", **params, limit=limit, **({"cursor": cursor} if cursor else {}))
        out.extend(body["items"])
        cursor = body["page"]["next_cursor"]
        if cursor is None:
            assert len(out) == body["total"]
            return out


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


# ---- API-050 -------------------------------------------------------------------------------------------------
def test_explorer_lists_every_singapore_policy_once(signed_in: TestClient, conn: Connection) -> None:
    rows = all_policies(signed_in)
    refs = [r["policy_ref"] for r in rows]
    sg = conn.execute(text(f"SELECT count(*) FROM {SCHEMA}.policy WHERE market_code = 'SG'")).scalar_one()
    assert len(refs) == len(set(refs)) == sg and all(r.startswith("POL-SG-") for r in refs)
    row = next(r for r in rows if r["policy_ref"] == "POL-SG-000001")
    assert row["route"] == f"/policies/{row['policy_id']}" and row["is_ilp"] and row["risk_band"] == "HIGH"
    assert row["latest_case_ref"] == "CB-2026-10482" and row["latest_case_outcome"] == "OPEN"
    assert row["fsc_ref"].startswith("FSC-") and row["selling_channel"] and row["script"].startswith("SALES_")
    assert "•" not in row["owner"] and "@" not in str(rows) and "SYN-TEL" not in str(rows)  # names masked, no contacts


@pytest.mark.parametrize("sort", ["-latest_sold_at", "policy_ref", "-premium_amount", "risk_band", "-cases"])
def test_sort_and_cursor_have_no_gaps_or_duplicates(signed_in: TestClient, sort: str) -> None:
    small = all_policies(signed_in, limit=9, sort=sort)
    big = all_policies(signed_in, limit=100, sort=sort)
    assert [r["policy_ref"] for r in small] == [r["policy_ref"] for r in big]


def test_filters_and_disjunctive_facets(signed_in: TestClient, conn: Connection) -> None:
    body = get(signed_in, "/api/v1/policies", multi_sale="true", limit=100)
    multi = conn.execute(
        text(
            f"SELECT p.policy_ref FROM {SCHEMA}.policy p JOIN {SCHEMA}.sale_event s ON s.policy_id = p.id "
            "WHERE p.market_code = 'SG' GROUP BY 1 HAVING count(*) > 1"
        )
    ).scalars()
    assert {r["policy_ref"] for r in body["items"]} == set(multi) and body["total"] > 0
    assert all(r["sales"] > 1 for r in body["items"])
    assert body["facets"]["multi_sale"]["true"] == body["total"]  # own dimension excluded
    assert body["facets"]["multi_sale"]["false"] > 0
    topups = get(signed_in, "/api/v1/policies", sale_type="TOP_UP", limit=100)
    assert topups["total"] and all("TOP_UP" in r["sale_types"] for r in topups["items"])
    ilp = get(signed_in, "/api/v1/policies", ilp="true", band="HIGH", limit=100)
    assert all(r["is_ilp"] and r["risk_band"] == "HIGH" for r in ilp["items"])
    assert sum(get(signed_in, "/api/v1/policies")["facets"]["product_family"].values()) == len(
        all_policies(signed_in, limit=100)
    )
    bad = signed_in.get("/api/v1/policies", params={"outcome": "NOPE"})
    assert bad.status_code == 422 and bad.json()["code"] == "INVALID_FILTER"
    assert signed_in.get("/api/v1/policies", params={"sort": "nope"}).status_code == 422


def test_text_search_by_policy_sale_party_case_and_exact_contact(signed_in: TestClient) -> None:
    for q in ("POL-SG-000001", "pol-sg-000001", "SALE-SG-000001", "CB-2026-10482"):
        assert "POL-SG-000001" in {r["policy_ref"] for r in all_policies(signed_in, q=q)}, q
    phone = "SYN-TEL-SG-100001"  # synthetic, non-dialable; matched only through the protected HMAC token
    assert {r["policy_ref"] for r in all_policies(signed_in, q=phone)} == {"POL-SG-000001"}
    assert get(signed_in, "/api/v1/policies", q=phone[:-1])["total"] == 0


# ---- API-051…055 ---------------------------------------------------------------------------------------------
def test_policy_detail_with_provenance_and_related_cases(signed_in: TestClient, conn: Connection) -> None:
    pid = policy_id(conn, "POL-SG-000001")
    d = get(signed_in, f"/api/v1/policies/{pid}")
    assert (d["policy_ref"], d["market"], d["product_family"], d["is_ilp"]) == ("POL-SG-000001", "SG", "ILP", True)
    assert d["premium_term_years"] == 10 and d["risk_band"] == "HIGH" and (d["sales"], d["top_ups"]) == (1, 0)
    assert d["provenance"]["source_type"] and d["provenance"]["is_synthetic"] is True
    fields = {f["field"]: f for f in d["material_fields"]}
    assert fields["premium_term_years"]["value"] == 10 and fields["premium_amount"]["as_of"]
    assert all(f["source_system"] for f in d["material_fields"])
    assert {(x["source_system"], x["object_type"]) for x in d["external_refs"]} == {("SYN-POLICY-ADMIN", "POLICY")}
    case = d["cases"][0]
    assert (case["case_ref"], case["state"], case["outcome"], case["risk_band"]) == (
        "CB-2026-10482",
        "AWAITING_REVIEW",
        "OPEN",
        "HIGH",
    )
    assert case["route"] == f"/cases/{case['case_id']}" and case["script"]["family"] == "SALES_VERIFICATION_SG"
    assert case["matched_rule"] and case["script_rationale"]["matched"] == case["matched_rule"]


def test_multi_sale_top_up_with_historical_fact_snapshots(signed_in: TestClient, conn: Connection) -> None:
    pid = policy_id(conn, "POL-SG-000017")
    d = get(signed_in, f"/api/v1/policies/{pid}")
    assert (d["sales"], d["top_ups"]) == (2, 1) and len(d["cases"]) == 2
    sales = get(signed_in, f"/api/v1/policies/{pid}/sales")["items"]
    assert [s["sale_event_type"] for s in sales] == ["NEW_BUSINESS", "TOP_UP"]
    assert sales[0]["sold_at"] < sales[1]["sold_at"] and d["latest_sale_id"] == sales[1]["id"]
    assert all(s["fsc"]["fsc_ref"] and s["fact_snapshots"] == 1 and len(s["cases"]) == 1 for s in sales)
    assert {c["case_ref"] for s in sales for c in s["cases"]} == {c["case_ref"] for c in d["cases"]}
    snaps = []
    for s in sales:
        ctx = get(signed_in, f"/api/v1/sales/{s['id']}")
        assert ctx["policy_ref"] == "POL-SG-000017" and ctx["sale"]["sale_ref"] == s["sale_ref"]
        assert ctx["risk_assessments"] and sum(a["effective"] for a in ctx["risk_assessments"]) == 1
        assert [c["case_ref"] for c in ctx["cases"]] == [c["case_ref"] for c in s["cases"]]
        snaps.extend(ctx["fact_snapshots"])
    # each sale keeps its own insert-only snapshot: the top-up's premium does not overwrite the original sale's
    assert [x["facts"]["sale_event_type"] for x in snaps] == ["NEW_BUSINESS", "TOP_UP"]
    assert snaps[0]["facts"]["premium_amount"] != snaps[1]["facts"]["premium_amount"]
    assert snaps[0]["sha256"] != snaps[1]["sha256"] and all("suitability" in x["facts"] for x in snaps)


def test_parties_roles_masked_contacts_and_eligibility(signed_in: TestClient, conn: Connection) -> None:
    pid = policy_id(conn, "POL-SG-000017")
    items = get(signed_in, f"/api/v1/policies/{pid}/parties")["items"]
    by_ref = {p["party_ref"]: p for p in items}
    assert len(items) == len(by_ref) == 2  # one card per party, never duplicated per role (PARTY-001)
    owner = next(p for p in items if any(r["role"] == "OWNER" for r in p["roles"]))
    assert {r["role"] for r in owner["roles"]} >= {"OWNER", "PAYER"} and all(r["current"] for r in owner["roles"])
    assert all("•" in c["masked_value"] for p in items for c in p["contacts"])
    assert all(e["case_ref"].startswith("CB-2026-1") and e["rule_basis"] for p in items for e in p["eligibility"])
    assert any(e["eligible"] for p in items for e in p["eligibility"])
    ended = conn.execute(
        text(
            f"SELECT p.id FROM {SCHEMA}.contact_method cm JOIN {SCHEMA}.policy_party_role pr "
            f"ON pr.party_id = cm.party_id JOIN {SCHEMA}.policy p ON p.id = pr.policy_id "
            "WHERE cm.valid_to IS NOT NULL AND p.market_code = 'SG' LIMIT 1"
        )
    ).scalar_one()
    contacts = [c for p in get(signed_in, f"/api/v1/policies/{ended}/parties")["items"] for c in p["contacts"]]
    assert any(not c["current"] and c["valid_to"] for c in contacts)  # historical contact kept, flagged


def test_history_is_record_lineage_and_the_field_ledger_is_not_available(
    signed_in: TestClient, conn: Connection
) -> None:
    pid = policy_id(conn, "POL-SG-000017")
    h = get(signed_in, f"/api/v1/policies/{pid}/history")
    types = [x["entity_type"] for x in h["lineage"]]
    assert {"policy", "sale_event", "policy_party_role", "policy_fact_snapshot", "risk_assessment"} <= set(types)
    assert types.count("sale_event") == 2 and all(x["provenance"]["source_type"] for x in h["lineage"])
    assert h["field_changes"]["availability"] == "NOT_AVAILABLE"
    assert h["field_changes"]["reason"] == "LEDGER_ARRIVES_CP0_4"


def test_no_unmasked_personal_data(signed_in: TestClient, conn: Connection) -> None:
    pid = policy_id(conn, "POL-SG-000001")
    blob = "".join(signed_in.get(f"/api/v1/policies/{pid}{p}").text for p in ("", "/parties", "/sales", "/history"))
    assert "Example Policyholder" not in blob and "@example.invalid" not in blob.replace("•••@example.invalid", "")
    assert "SYN-TEL-SG-1" not in blob and "ciphertext" not in blob and "value_hmac" not in blob


# ---- BE-SEC-02 -----------------------------------------------------------------------------------------------
def test_be_sec_02_malaysian_policies_and_sales_are_identical_audited_404s(
    client: TestClient, admin: Account, conn: Connection
) -> None:
    login(client, admin)  # ADMIN is SG-only too (D-39)
    my = conn.execute(
        text(
            f"SELECT p.id AS p, p.policy_ref, s.id AS s, s.sale_ref FROM {SCHEMA}.policy p "
            f"JOIN {SCHEMA}.sale_event s ON s.policy_id = p.id WHERE p.market_code = 'MY' LIMIT 1"
        )
    ).one()
    gone = uuid.uuid4()
    paths = {
        "policy": [f"/api/v1/policies/{{}}{x}" for x in ("", "/parties", "/sales", "/history")],
        "sale_event": ["/api/v1/sales/{}"],
    }
    ids = {"policy": my.p, "sale_event": my.s}
    for entity, templates in paths.items():
        for tpl in templates:
            out_of_scope, missing = client.get(tpl.format(ids[entity])), client.get(tpl.format(gone))
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
    # no MY row, count or facet leaks through the explorer, its search or its facets
    for q in (my.policy_ref, my.sale_ref, "POL-MY", "SALE-MY"):
        body = get(client, "/api/v1/policies", q=q)
        assert body["total"] == 0 and not any(body["facets"]["product_family"].values()), q
    whole = json.dumps(get(client, "/api/v1/policies", limit=100))
    assert "POL-MY" not in whole and "SALE-MY" not in whole and "CB-2026-2" not in whole


def test_search_policy_hit_opens_policy_detail(signed_in: TestClient, conn: Connection) -> None:
    hits = get(signed_in, "/api/v1/search", q="POL-SG-000017")["items"]
    policy = next(h for h in hits if h["entity_type"] == "policy")
    assert policy["route"] == f"/policies/{policy_id(conn, 'POL-SG-000017')}"


def test_permissions(client: TestClient, db: Session, conn: Connection) -> None:
    pid = policy_id(conn, "POL-SG-000001")
    assert client.get("/api/v1/policies").status_code == 401
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    for path in ("/api/v1/policies", f"/api/v1/policies/{pid}", f"/api/v1/policies/{pid}/parties"):
        assert client.get(path).status_code == 403, path
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))  # permissions but no market → 404 / empty
    assert client.get(f"/api/v1/policies/{pid}").status_code == 404
    assert get(client, "/api/v1/policies")["total"] == 0
