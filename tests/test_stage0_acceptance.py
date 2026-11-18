"""CP0.6 — integrated Stage 0 acceptance sweeps across every API and the whole schema (complementing the per-slice
tests): BE-SEC-02 for every GET route (no Malaysian row, reference, count or facet in any list, search or facet;
every Malaysian object ID is the same audited 404 as a missing one), BE-DATA integrity (every constraint validated,
reference chains complete, core fixture counts), immutability of historical scripts, assignments and assessments,
manifest digests reproducible, and no secret material in responses or audit events."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

from app.domain.digest import sha256_of
from tests.domain_support import SCHEMA
from tests.support import Account, login

pytestmark = pytest.mark.usefixtures("seeded")
# Business references and markers of Malaysian data (configuration code lists legitimately name the MY code).
MALAYSIA = re.compile(r'POL-MY-|SALE-MY-|CB-2026-2\d{4}|SALES_VERIFICATION_MY|MY-SALES-VERIFY|"market(_code)?": "MY"')
SECRETS = re.compile(
    r"\$argon2|password_hash|refresh_token|csrf_secret|token_hash|BEGIN [A-Z ]*PRIVATE KEY|value_ciphertext"
)
CONFIG_ROUTES = {"/api/v1/admin/code-lists", "/api/v1/admin/feature-flags", "/api/v1/intake/reference"}
UNSCOPED_ROUTES: set[str] = set()  # CP0.6-F1: the operational audit view is market-scoped too
REQUIRED_PARAMS = {"/api/v1/search": {"q": "SG"}, "/api/v1/search/suggest": {"q": "CB-2026"}}
MY_IDS = {
    "case_id": "SELECT id FROM {s}.callback_case WHERE market_code = 'MY' LIMIT 1",
    "policy_id": "SELECT id FROM {s}.policy WHERE market_code = 'MY' LIMIT 1",
    "sale_event_id": "SELECT s.id FROM {s}.sale_event s JOIN {s}.policy p ON p.id = s.policy_id "
    "WHERE p.market_code = 'MY' LIMIT 1",
    "attempt_id": "SELECT a.id FROM {s}.contact_attempt a JOIN {s}.callback_case c ON c.id = a.callback_case_id "
    "WHERE c.market_code = 'MY' LIMIT 1",
    "session_id": "SELECT cs.id FROM {s}.conversation_session cs "
    "JOIN {s}.contact_attempt a ON a.id = cs.contact_attempt_id "
    "JOIN {s}.callback_case c ON c.id = a.callback_case_id WHERE c.market_code = 'MY' LIMIT 1",
    "survey_run_id": "SELECT r.id FROM {s}.survey_run r JOIN {s}.conversation_session cs ON cs.id = r.session_id "
    "JOIN {s}.contact_attempt a ON a.id = cs.contact_attempt_id JOIN {s}.callback_case c ON c.id = a.callback_case_id "
    "WHERE c.market_code = 'MY' LIMIT 1",
    "assessment_id": "SELECT ra.id FROM {s}.risk_assessment ra JOIN {s}.sale_event s ON s.id = ra.sale_event_id "
    "JOIN {s}.policy p ON p.id = s.policy_id WHERE p.market_code = 'MY' LIMIT 1",
    "script_family_id": "SELECT id FROM {s}.script_family WHERE market_code = 'MY' LIMIT 1",
    "script_version_id": "SELECT v.id FROM {s}.script_version v JOIN {s}.script_family f ON f.id = v.script_family_id "
    "WHERE f.market_code = 'MY' LIMIT 1",
}


def _get_routes() -> list[str]:
    from app.main import ROUTERS

    return sorted(
        {r.path for router in ROUTERS for r in router.routes if isinstance(r, APIRoute) and "GET" in r.methods}
    )


@pytest.fixture()
def admin_client(client: TestClient, admin: Account) -> TestClient:
    login(client, admin)
    return client


def test_no_malaysian_data_or_secrets_in_any_list_search_or_facet(admin_client: TestClient, conn: Connection) -> None:
    sg_case = conn.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE market_code = 'SG' LIMIT 1")).scalar_one()
    sg_assigned = conn.execute(
        text(
            f"SELECT c.id FROM {SCHEMA}.callback_case c JOIN {SCHEMA}.script_assignment a ON a.callback_case_id = c.id "
            "WHERE c.market_code = 'SG' LIMIT 1"
        )
    ).scalar_one()
    params_for = {
        **REQUIRED_PARAMS,
        "/api/v1/voice/sessions": {"case_id": str(sg_case)},
        "/api/v1/script-simulations/plan": {"case_id": str(sg_assigned)},  # S2-D: a case with a pinned script
        "/api/v1/simulation-workbench/case-facts": {"case_id": str(sg_case)},  # S2-E: facts of a synthetic case
    }
    lists = [p for p in _get_routes() if "{" not in p and p.startswith("/api/v1/")]
    assert len(lists) >= 30
    for path in lists:
        r = admin_client.get(path, params=params_for.get(path))
        assert r.status_code == 200, (path, r.status_code, r.text[:200])
        body = r.text
        if path not in CONFIG_ROUTES | UNSCOPED_ROUTES:
            assert not MALAYSIA.search(body), (path, MALAYSIA.search(body))
        assert not SECRETS.search(body), (path, SECRETS.search(body))
    for path, params in (
        ("/api/v1/search", {"q": "MY"}),
        ("/api/v1/search", {"q": "POL-MY-000001"}),
        ("/api/v1/search/suggest", {"q": "CB-2026-2"}),
        ("/api/v1/cases", {"q": "CB-2026-20001"}),
        ("/api/v1/policies", {"q": "POL-MY"}),
        ("/api/v1/risk-assessments", {"q": "SALE-MY"}),
        ("/api/v1/review-queue", {"q": "CB-2026-2", "queue": "ALL"}),
        ("/api/v1/scripts", {"market_code": "MY"}),
    ):
        r = admin_client.get(path, params=params)
        assert r.status_code == 200 and not MALAYSIA.search(r.text), (path, params)
        total = r.json().get("total")
        assert total in (None, 0), (path, params, total)


def test_every_malaysian_object_is_an_audited_404_like_a_missing_one(
    admin_client: TestClient, conn: Connection
) -> None:
    ids = {k: conn.execute(text(sql.format(s=SCHEMA))).scalar_one() for k, sql in MY_IDS.items()}
    objects = [p for p in _get_routes() if "{" in p and re.search(r"\{(\w+)\}", p).group(1) in ids]  # type: ignore[union-attr]
    assert len(objects) >= 20
    for path in objects:
        param = re.search(r"\{(\w+)\}", path).group(1)  # type: ignore[union-attr]
        target = path.replace("{track}", "MIC")  # S1-C audio route: second, non-object path parameter
        mine, missing = (
            admin_client.get(target.replace(f"{{{param}}}", str(ids[param]))),
            admin_client.get(target.replace(f"{{{param}}}", str(uuid.uuid4()))),
        )
        # ADMIN lacks recording.read (D-46) and transcript.sensitive.read (D-50): those routes refuse before any
        # lookup, identically for both.
        expected = 403 if path.endswith(("/audio", "/transcript/segments")) else 404
        assert mine.status_code == missing.status_code == expected, (path, mine.status_code, missing.status_code)
        strip = lambda r: {k: v for k, v in r.json().items() if k != "correlation_id"}  # noqa: E731
        assert strip(mine) == strip(missing), path
    denied = conn.execute(
        text(f"SELECT count(DISTINCT entity_id) FROM {SCHEMA}.audit_event WHERE action = 'ACCESS.DENIED_OBJECT'")
    ).scalar_one()
    assert denied >= len(set(ids.values()))


def test_schema_constraints_and_reference_chains(conn: Connection) -> None:
    invalid = conn.execute(
        text(
            "SELECT conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE n.nspname = :s AND NOT c.convalidated"
        ),
        {"s": SCHEMA},
    ).all()
    assert invalid == []
    fks = conn.execute(
        text(
            "SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE n.nspname = :s AND c.contype = 'f'"
        ),
        {"s": SCHEMA},
    ).scalar_one()
    assert fks >= 60
    q = lambda sql: conn.execute(text(sql.format(s=SCHEMA))).scalar_one()  # noqa: E731
    assert q("SELECT count(*) FROM {s}.callback_case") >= 250  # S0 seed size (backend CLAUDE.md)
    assert q("SELECT count(*) FROM {s}.callback_case WHERE market_code = 'SG'") > 0
    # Every case reaches its sale, policy and at least one policy party; every SG sale has a fact snapshot.
    assert (
        q(
            "SELECT count(*) FROM {s}.callback_case c JOIN {s}.sale_event s ON s.id = c.sale_event_id "
            "JOIN {s}.policy p ON p.id = s.policy_id WHERE p.market_code <> c.market_code"
        )
        == 0
    )
    assert (
        q(
            "SELECT count(*) FROM {s}.policy p WHERE NOT EXISTS "
            "(SELECT 1 FROM {s}.policy_party_role r WHERE r.policy_id = p.id AND r.role = 'OWNER')"
        )
        == 0
    )
    assert (
        q(
            "SELECT count(*) FROM {s}.sale_event s WHERE NOT EXISTS "
            "(SELECT 1 FROM {s}.policy_fact_snapshot f WHERE f.sale_event_id = s.id)"
        )
        == 0
    )
    # Assignments pin the exact manifest of their version; sessions pin what they ran.
    assert (
        q(
            "SELECT count(*) FROM {s}.script_assignment a JOIN {s}.script_version v ON v.id = a.script_version_id "
            "WHERE a.script_manifest_sha256 <> v.manifest_sha256"
        )
        == 0
    )
    # Every finding belongs to a case in the same market as its question's survey run.
    assert (
        q(
            "SELECT count(*) FROM {s}.finding f JOIN {s}.question_execution qe ON qe.id = f.question_execution_id "
            "JOIN {s}.survey_run r ON r.id = qe.survey_run_id JOIN {s}.conversation_session cs ON cs.id = r.session_id "
            "JOIN {s}.contact_attempt a ON a.id = cs.contact_attempt_id WHERE a.callback_case_id <> f.callback_case_id"
        )
        == 0
    )


def test_historical_scripts_assignments_and_assessments_are_immutable(conn: Connection) -> None:
    for v in conn.execute(
        text(
            f"SELECT version_label, manifest, manifest_sha256 FROM {SCHEMA}.script_version "
            "WHERE manifest_sha256 IS NOT NULL"
        )
    ):
        assert sha256_of(v.manifest) == v.manifest_sha256, v.version_label  # digests reproduce
    attempts = (
        f"UPDATE {SCHEMA}.script_version SET version_label = version_label || 'x' WHERE status = 'PUBLISHED'",
        f"UPDATE {SCHEMA}.question_revision SET customer_wording = 'changed'",
        f"UPDATE {SCHEMA}.script_assignment SET assigned_by = 'changed'",
        f"DELETE FROM {SCHEMA}.risk_assessment WHERE status = 'FINAL'",
        f"UPDATE {SCHEMA}.risk_assessment SET band_code = 'LOW' WHERE status = 'FINAL'",
        f"UPDATE {SCHEMA}.audit_event SET reason = 'changed'",
    )
    for sql in attempts:
        tx = conn.begin_nested()
        with pytest.raises(DBAPIError):
            conn.execute(text(sql))
        tx.rollback()


def test_audit_chain_and_no_secrets_in_audit(admin_client: TestClient, conn: Connection) -> None:
    from sqlalchemy.orm import Session

    from app.audit.chain import verify_chain

    with Session(conn) as s:
        report = verify_chain(s)
    assert report.ok and report.events > 0
    audit = json.dumps(
        conn.execute(
            text(f"SELECT json_agg(json_build_object('b', before, 'a', after, 'r', reason)) FROM {SCHEMA}.audit_event")
        ).scalar_one()
    )
    assert not SECRETS.search(audit), SECRETS.search(audit)
    assert not re.search(r'"(password|one_time_password|new_password|current_password)": "', audit)


def test_cp06_f1_operational_audit_view_is_singapore_only_and_the_ledger_is_complete(
    admin_client: TestClient, conn: Connection
) -> None:
    """CP0.6-F1 (owner decision): API-021 lists no out-of-scope business event or reference; access-denied events on
    out-of-scope records stay listed with the record ID withheld; the seed manifest is listed without dataset-wide
    totals; the immutable ledger still holds every event and its hash chain verifies."""
    from sqlalchemy.orm import Session

    from app.audit.chain import verify_chain

    my_case = conn.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE market_code = 'MY' LIMIT 1")).scalar_one()
    assert admin_client.get(f"/api/v1/cases/{my_case}").status_code == 404  # writes an ACCESS.DENIED_OBJECT event
    listed: list[dict[str, Any]] = []
    cursor = None
    while True:
        page = admin_client.get(
            "/api/v1/admin/audit-events", params={"limit": 200, **({"cursor": cursor} if cursor else {})}
        )
        assert page.status_code == 200
        listed += page.json()["items"]
        cursor = page.json()["page"]["next_cursor"]
        if not cursor:
            break
    blob = json.dumps(listed)
    assert not MALAYSIA.search(blob), MALAYSIA.search(blob)
    assert str(my_case) not in blob
    denied = [e for e in listed if e["action"] == "ACCESS.DENIED_OBJECT" and e["scope_redacted"]]
    assert denied and all(e["entity_id"] is None and e["entity_type"] for e in denied)  # signal kept, ID withheld
    seed = [e for e in listed if e["action"] == "SEED.MANIFEST"]
    assert seed and all("counts" not in e["after"] and e["after"]["digest"] for e in seed)
    assert any(e["action"].startswith("AUTH.") for e in listed)  # market-neutral events unchanged
    ledger = conn.execute(text(f"SELECT count(*) FROM {SCHEMA}.audit_event")).scalar_one()
    hidden = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE entity_type = 'callback_case' AND action <> "
            "'ACCESS.DENIED_OBJECT' AND entity_id IN (SELECT case_ref FROM " + SCHEMA + ".callback_case "
            "WHERE market_code = 'MY')"
        )
    ).scalar_one()
    assert hidden >= 1 and len(listed) <= ledger - hidden  # the seeded MY hold event exists but is not listed
    with Session(conn) as s:
        assert verify_chain(s).ok
    health = admin_client.get("/api/v1/admin/system-health").json()
    assert health["audit_events"] == ledger  # the integrity check covers the whole ledger


INJECTION = ("' OR 1=1 --", "%", "_", ".*", "\\", "%' UNION SELECT password_hash FROM local_credential --", "(?i).*")


def test_be_sec_04_injection_payloads_in_search_and_filters_are_inert(admin_client: TestClient) -> None:
    """BE-SEC-04: SQL/LIKE/regex payloads are parameterised and bounded — never a 500, never extra rows or secrets."""
    baseline = {
        p: admin_client.get(p, params={"q": "ZZZ-NO-MATCH-0000"}).json().get("total")
        for p in ("/api/v1/cases", "/api/v1/policies", "/api/v1/risk-assessments", "/api/v1/scripts")
    }
    for payload in INJECTION:
        for path, params in (
            ("/api/v1/search", {"q": payload}),
            ("/api/v1/search/suggest", {"q": payload}),
            ("/api/v1/cases", {"q": payload}),
            ("/api/v1/cases", {"state": payload}),
            ("/api/v1/policies", {"q": payload}),
            ("/api/v1/risk-assessments", {"q": payload}),
            ("/api/v1/review-queue", {"q": payload, "queue": "ALL"}),
            ("/api/v1/review-queue", {"category": payload}),
            ("/api/v1/scripts", {"q": payload}),
            ("/api/v1/admin/audit-events", {"action": payload}),
        ):
            r = admin_client.get(path, params=params)
            assert r.status_code in (200, 422), (path, params, r.status_code)
            assert not SECRETS.search(r.text), (path, params)
            if r.status_code == 200 and path in baseline and "q" in params and payload.startswith("'"):
                assert r.json().get("total") == baseline[path], (path, payload)  # no tautology widening
