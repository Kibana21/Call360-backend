"""F6 — Script Studio and Assignment Rules read APIs (API-060…062, API-064…066, with API-063); BE-API-04 (library
filters, version detail, assignment trace) and BE-API-05 (regulatory register and control mappings are distinct):
seeded SG script versions in structural order with manifest SHA, lifecycle status and supersedes chain;
content-condition filters;
rule versions with predicates, targets and the cases they assigned (counts reconcile with ``script_assignment``);
controls and regulatory references limited to Singapore; BE-SEC-02 (MY family → audited 404 identical to missing);
permissions (no role → 403, no market → nothing). Read-only: no write route exists."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.api.scripts import content_tags
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")


def get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    r = client.get(path, params=params)
    assert r.status_code == 200, (path, r.text)
    return r.json()


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


def family_id(conn: Connection, market: str) -> uuid.UUID:
    return conn.execute(
        text(f"SELECT id FROM {SCHEMA}.script_family WHERE code = :c"), {"c": f"SALES_VERIFICATION_{market}"}
    ).scalar_one()


def test_library_lists_singapore_versions_with_structure_and_history(signed_in: TestClient, conn: Connection) -> None:
    # S2-A: authored families may exist beside the seeded one; these checks address the seeded family.
    body = get(signed_in, "/api/v1/scripts", q="SALES_VERIFICATION_SG")
    assert body["markets"] == ["SG"] and {v["market"] for v in body["items"]} == {"SG"}
    expected = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.script_version v JOIN {SCHEMA}.script_family f "
            "ON f.id = v.script_family_id WHERE f.code = 'SALES_VERIFICATION_SG'"
        )
    ).scalar_one()
    assert body["total"] == len(body["items"]) == expected
    by_label = {v["version_label"]: v for v in body["items"]}
    assert by_label["1.1"]["status"] == "PUBLISHED" and by_label["1.2"]["status"] == "DRAFT"
    assert by_label["1.1"]["supersedes_label"] == "1.0"
    for v in body["items"]:
        assert [m["position"] for m in v["modules"]] == sorted(m["position"] for m in v["modules"])
        assert v["questions"] == sum(m["questions"] for m in v["modules"])
        assert v["content_approval_status"] == "SYNTHETIC_UNAPPROVED"
        if v["status"] == "DRAFT":
            assert v["manifest_sha256"] is None
        else:
            assert len(v["manifest_sha256"]) == 64
    for v in body["items"]:
        assigned = conn.execute(
            text(
                f"SELECT count(DISTINCT a.callback_case_id) FROM {SCHEMA}.script_assignment a "
                f"JOIN {SCHEMA}.callback_case c ON c.id = a.callback_case_id "
                "WHERE a.script_version_id = :v AND c.market_code = 'SG'"
            ),
            {"v": v["id"]},
        ).scalar_one()
        assert v["cases_assigned"] == assigned, v["version_label"]
    assert by_label["1.1"]["rules_targeting"] == ["SG-SALES-VERIFY v2"]
    published = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.script_version v JOIN {SCHEMA}.script_family f "
            "ON f.id = v.script_family_id WHERE f.market_code = 'SG' AND v.status = 'PUBLISHED'"
        )
    ).scalar_one()
    assert body["facets"]["status"]["PUBLISHED"] == published and "MY" not in json.dumps(body["facets"])


def test_library_filters(signed_in: TestClient) -> None:
    def labels(**p: Any) -> list[str]:  # the seeded family (S2-A may have added authored families)
        p.setdefault("q", "SALES_VERIFICATION_SG")
        return [v["version_label"] for v in get(signed_in, "/api/v1/scripts", **p)["items"]]

    assert labels(status="PUBLISHED") == ["1.1"]
    assert labels(status=["DRAFT", "WITHDRAWN"]) == ["0.9", "1.2"]
    assert labels(effective_on="2026-03-01") == ["1.0"]
    assert len(labels(product_family="ILP")) == 4 and len(labels(risk_band="HIGH")) == 4
    assert labels(channel="AGENCY") == []  # no seeded module is channel-specific
    assert [x for x in labels(language="en", q="ELEVATED_RISK") if x in labels()] == labels()
    assert labels(market_code="MY") == []  # outside the caller's scope: nothing, not an error
    assert signed_in.get("/api/v1/scripts", params={"status": "LIVE"}).status_code == 422


def test_content_tags_name_conditions_without_evaluating_cases() -> None:
    assert content_tags({"fact": "is_ilp", "equals": True})["product_family"] == {"ILP"}
    assert content_tags({"all": [{"fact": "selling_channel", "equals": "AGENCY"}, {"risk_band_in": ["HIGH"]}]}) == {
        "product_family": set(),
        "risk_band": {"HIGH"},
        "channel": {"AGENCY"},
    }
    assert content_tags(None) == {"product_family": set(), "risk_band": set(), "channel": set()}


def test_family_and_versions(signed_in: TestClient, conn: Connection) -> None:
    fid = family_id(conn, "SG")
    fam = get(signed_in, f"/api/v1/scripts/{fid}")
    assert fam["code"] == "SALES_VERIFICATION_SG" and fam["market"] == "SG"
    versions = get(signed_in, f"/api/v1/scripts/{fid}/versions")
    assert [v["version_label"] for v in versions["items"]] == [v["version_label"] for v in fam["versions"]]
    detail = get(signed_in, f"/api/v1/script-versions/{versions['items'][-1]['id']}")
    for sec in detail["sections"]:
        assert [q["position"] for q in sec["questions"]] == sorted(q["position"] for q in sec["questions"])
    qs = [q for sec in detail["sections"] for q in sec["questions"]]
    assert all(q["expected_answer_policy"] and q["answer_type"] and q["delivery_mode"] for q in qs)
    linked = [c for q in qs for c in q["controls"]]
    assert linked and all(c["issuer"] is None or "SYNTHETIC" in c["issuer"] for c in linked)


def test_be_sec_02_malaysian_family_is_an_audited_404(client: TestClient, admin: Account, conn: Connection) -> None:
    login(client, admin)
    my = family_id(conn, "MY")
    for path in (f"/api/v1/scripts/{my}", f"/api/v1/scripts/{my}/versions"):
        out, missing = client.get(path), client.get(path.replace(str(my), str(uuid.uuid4())))
        assert out.status_code == missing.status_code == 404
        assert {k: v for k, v in out.json().items() if k != "correlation_id"} == {
            k: v for k, v in missing.json().items() if k != "correlation_id"
        }
    denied = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'ACCESS.DENIED_OBJECT' "
            "AND entity_type = 'script_family' AND entity_id = :i"
        ),
        {"i": str(my)},
    ).scalar_one()
    assert denied >= 2
    whole = json.dumps(
        [get(client, p) for p in ("/api/v1/scripts", "/api/v1/script-assignment-rules", "/api/v1/controls")]
        + [get(client, "/api/v1/regulatory-references")]
    )
    assert "_MY" not in whole and '"MY"' not in whole and "MY-SALES" not in whole


def test_assignment_rules_with_targets_and_cases(signed_in: TestClient, conn: Connection) -> None:
    body = get(signed_in, "/api/v1/script-assignment-rules")
    assert {r["market"] for r in body["items"]} == {"SG"}
    assert {(r["rule_code"], r["version"]) for r in body["items"]} == {
        ("SG-PILOT", 1),
        ("SG-SALES-VERIFY", 1),
        ("SG-SALES-VERIFY", 2),
    }
    for r in body["items"]:
        n = conn.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.script_assignment a JOIN {SCHEMA}.callback_case c "
                "ON c.id = a.callback_case_id WHERE a.matched_rule_version_id = :r AND c.market_code = 'SG'"
            ),
            {"r": r["id"]},
        ).scalar_one()
        assert r["cases_assigned"] == n
        assert len(r["recent_cases"]) == min(n, 10)
        assert all(c["case_ref"].startswith("CB-2026-1") for c in r["recent_cases"])
        assert r["predicate"]["all"][0] == {"fact": "market", "equals": "SG"}
        assert r["target"]["family"] == "SALES_VERIFICATION_SG"
    live = next(r for r in body["items"] if r["status"] == "PUBLISHED")
    assert live["target"]["version_label"] == "1.1" and live["cases_assigned"] > 0


def test_controls_and_regulatory_references(signed_in: TestClient) -> None:
    refs = get(signed_in, "/api/v1/regulatory-references")["items"]
    assert [r["market"] for r in refs] == ["SG"] and refs[0]["interpretation_status"] == "NOT_REVIEWED"
    controls = get(signed_in, "/api/v1/controls")["items"]
    assert [c["control_code"] for c in controls] == sorted(c["control_code"] for c in controls)
    assert all(c["content_approval_status"] == "SYNTHETIC_UNAPPROVED" for c in controls)
    links = [q for c in controls for q in c["questions"]]
    assert links and not any(v.startswith("SALES_VERIFICATION_MY") for q in links for v in q["script_versions"])
    assert {q["regulatory_reference_id"] for q in links} - {None} == {r["id"] for r in refs}
    assert set(refs[0]["controls"]) <= {c["control_code"] for c in controls}


def test_permissions_and_read_only(client: TestClient, db: Session, conn: Connection) -> None:
    fid = family_id(conn, "SG")
    paths = (
        "/api/v1/scripts",
        f"/api/v1/scripts/{fid}",
        f"/api/v1/scripts/{fid}/versions",
        "/api/v1/script-assignment-rules",
        "/api/v1/regulatory-references",
        "/api/v1/controls",
    )
    assert all(client.get(p).status_code == 401 for p in paths)
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    assert all(client.get(p).status_code == 403 for p in paths)
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))  # script.read but no market in scope
    assert get(client, "/api/v1/scripts")["total"] == 0
    assert get(client, "/api/v1/script-assignment-rules")["total"] == 0
    assert client.get(f"/api/v1/scripts/{fid}").status_code == 404
    # S2-A: authoring exists, but never outside the caller's markets.
    r = client.post("/api/v1/scripts", json={"code": "S2A_NOMKT", "name": "No market"}, headers=csrf_header(client))
    assert r.status_code == 403 and r.json()["code"] == "MARKET_NOT_IN_SCOPE"
