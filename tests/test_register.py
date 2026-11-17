"""F2 — case register, facets, work queues and search (API-035/036/070/071/076): BE-API-01 (register grain),
BE-KPI-02 (drilldown set equality), BE-SRCH-01…06 and 08, BE-SEC-02 (no MY rows, counts, facets or suggestions),
queue counts equal to the Overview OPS cards, and permissions."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.core.middleware import SearchTermRedaction
from app.domain.kpis import CASE_PREDICATES
from app.domain.register import Row, page, term_hash
from tests.domain_support import SCHEMA
from tests.support import Account, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")
WIDE = {"from": "2026-03-01", "to": "2027-01-01"}


def all_rows(client: TestClient, limit: int = 40, **params: Any) -> list[dict[str, Any]]:
    """Traverse every page of the register; asserts the reported total matches what was paged."""
    out: list[dict[str, Any]] = []
    cursor = None
    total = None
    while True:
        r = client.get("/api/v1/cases", params={**params, "limit": limit, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200, r.text
        body = r.json()
        total = body["total"] if total is None else total
        out.extend(body["items"])
        cursor = body["page"]["next_cursor"]
        if cursor is None:
            break
    assert len(out) == total
    return out


def route_params(route: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(route).query)


def sql_refs(conn: Connection, where: str, **p: Any) -> set[str]:
    sql = f"SELECT DISTINCT c.case_ref FROM {SCHEMA}.callback_case c WHERE c.market_code = 'SG' AND {where}"
    return set(conn.execute(text(sql), p).scalars())


@pytest.fixture()
def signed_in(client: TestClient, user: Account) -> TestClient:
    login(client, user)
    return client


# ---- register ----------------------------------------------------------------------------------------------
def test_be_api_01_register_is_case_grain_and_singapore_only(signed_in: TestClient, conn: Connection) -> None:
    rows = all_rows(signed_in)
    refs = [r["case_ref"] for r in rows]
    assert (
        len(refs)
        == len(set(refs))
        == conn.execute(text(f"SELECT count(*) FROM {SCHEMA}.callback_case WHERE market_code = 'SG'")).scalar_one()
    )
    assert all(r.startswith("CB-2026-1") for r in refs)  # SG refs; MY fixtures are CB-2026-2xxxx
    assert not any(r["policy_ref"].startswith("POL-MY") for r in rows)
    sample = rows[0]
    assert sample["route"] == f"/cases/{sample['case_id']}" and sample["evidence"] == "NOT_AVAILABLE"
    assert "@" not in str(rows) and "SYN-TEL" not in str(rows)  # no contact value, masked or otherwise
    attempts = conn.execute(
        text(
            f"SELECT c.case_ref, count(a.id) FROM {SCHEMA}.callback_case c LEFT JOIN {SCHEMA}.contact_attempt a "
            "ON a.callback_case_id = c.id WHERE c.market_code = 'SG' GROUP BY 1"
        )
    ).all()
    assert {r["case_ref"]: r["attempts"] for r in rows} == dict(attempts)


@pytest.mark.parametrize("sort", ["due_at", "-due_at", "case_ref", "-case_ref", "state", "risk_band", "-attempts"])
def test_be_srch_04_sort_is_deterministic_without_gaps_or_duplicates(signed_in: TestClient, sort: str) -> None:
    small = all_rows(signed_in, limit=7, sort=sort)
    big = all_rows(signed_in, limit=100, sort=sort)
    assert [r["case_ref"] for r in small] == [r["case_ref"] for r in big]
    assert len({r["case_ref"] for r in small}) == len(small)
    if sort.lstrip("-") == "due_at":
        dues = [r["due_at"] for r in small]
        assert dues == sorted(dues, reverse=sort.startswith("-"))


def test_be_srch_04_cursor_is_stable_under_concurrent_inserts(signed_in: TestClient) -> None:
    """Keyset cursor: a row inserted before the cursor position is not returned again and shifts nothing; a
    row inserted after it appears exactly once."""
    from app.domain.kpis import Case

    def row(ref: str, due: datetime) -> Row:
        c = Case(uuid.uuid4(), ref, "READY", due, due, "SEED", None, None, None, None, None, False, True, uuid.uuid4())
        return Row(c, uuid.uuid4(), "POL", "x", "ILP", "ILP", True, None, None)

    base = datetime(2026, 6, 1, tzinfo=UTC)
    rows = [row(f"CB-{i:03d}", base + timedelta(days=i)) for i in range(10)]
    first, cursor = page(rows, "due_at", 4, None)
    assert cursor is not None
    early = row("CB-NEW-EARLY", base - timedelta(days=1))
    late = row("CB-NEW-LATE", base + timedelta(days=50))
    second, cursor2 = page([*rows, early, late], "due_at", 4, cursor)
    third, _ = page([*rows, early, late], "due_at", 4, cursor2)
    seen = [r.case.ref for r in first + second + third]
    assert len(seen) == len(set(seen)) == 11 and "CB-NEW-EARLY" not in seen and seen[-1] == "CB-NEW-LATE"
    assert seen[:10] == [r.case.ref for r in rows]


def test_be_srch_03_filters_match_independent_sql(signed_in: TestClient, conn: Connection) -> None:
    def refs(**params: Any) -> set[str]:
        return {r["case_ref"] for r in all_rows(signed_in, limit=100, **params)}

    assert refs(state=["AWAITING_CALLBACK", "READY"]) == sql_refs(conn, "c.state IN ('AWAITING_CALLBACK','READY')")
    assert refs(product_family="ILP") == sql_refs(
        conn,
        f"EXISTS (SELECT 1 FROM {SCHEMA}.sale_event s JOIN {SCHEMA}.policy p ON p.id = s.policy_id "
        "WHERE s.id = c.sale_event_id AND p.product_family = 'ILP')",
    )
    assert refs(ilp="true") == refs(product_family="ILP")
    assert refs(hold_reason="DATA_CONFLICT") == sql_refs(
        conn,
        f"EXISTS (SELECT 1 FROM {SCHEMA}.case_hold h WHERE h.callback_case_id = c.id "
        "AND h.released_at IS NULL AND h.hold_reason = 'DATA_CONFLICT')",
    )
    assert refs(on_hold="true") == sql_refs(
        conn, f"EXISTS (SELECT 1 FROM {SCHEMA}.case_hold h WHERE h.callback_case_id = c.id AND h.released_at IS NULL)"
    )
    band_sql = (
        f"(SELECT ra.band_code FROM {SCHEMA}.risk_assessment ra WHERE ra.sale_event_id = c.sale_event_id "
        "AND ra.status = 'FINAL' ORDER BY ra.valid_at DESC LIMIT 1)"
    )
    assert refs(band="HIGH") == sql_refs(conn, f"{band_sql} = 'HIGH'")
    assert refs(band="NOT_ASSESSED") == sql_refs(conn, f"{band_sql} IS NULL")
    assert refs(due_from="2026-06-01", due_to="2026-07-01") == sql_refs(
        conn, "c.due_at >= '2026-06-01T00:00:00+08:00' AND c.due_at < '2026-07-01T00:00:00+08:00'"
    )
    combo = refs(state="AWAITING_CALLBACK", band="HIGH", product_family="ILP")
    assert combo == refs(state="AWAITING_CALLBACK") & refs(band="HIGH") & refs(product_family="ILP")
    overdue = all_rows(signed_in, limit=100, overdue="true")
    assert overdue and all(r["overdue"] and r["outcome"] == "OPEN" for r in overdue)


def test_validation_errors(signed_in: TestClient) -> None:
    for params, code in (
        ({"q": "x" * 65}, "QUERY_TOO_LONG"),
        ({"outcome": "NON_COMPLIANT"}, "INVALID_FILTER"),
        ({"queue": "LATER"}, "INVALID_FILTER"),
        ({"due_from": "2026-07-01", "due_to": "2026-06-01"}, "INVALID_FILTER"),
        ({"kpi": "KPI-02", "kpi_set": "numerator", **WIDE}, "INVALID_FILTER"),  # attempt grain: no case drilldown
        ({"kpi": "KPI-04"}, "INVALID_FILTER"),
        ({"sort": "policyholder"}, "INVALID_FILTER"),
        ({"cursor": "not-a-cursor"}, "INVALID_CURSOR"),
    ):
        r = signed_in.get("/api/v1/cases", params=params)
        assert (r.status_code, r.json()["code"]) == (422, code), params
    first = signed_in.get("/api/v1/cases", params={"limit": 5, "sort": "due_at"}).json()
    other = signed_in.get("/api/v1/cases", params={"sort": "case_ref", "cursor": first["page"]["next_cursor"]})
    assert other.json()["code"] == "INVALID_CURSOR"


# ---- dashboard drilldowns and queues -----------------------------------------------------------------------
def test_be_kpi_02_drilldown_set_equality(signed_in: TestClient) -> None:
    k = {x["definition_id"]: x for x in signed_in.get("/api/v1/dashboard/kpis", params=WIDE).json()["items"]}
    checked = 0
    for kid in [*CASE_PREDICATES, "KPI-15"]:
        for kset in ("numerator", "denominator"):
            route = k[kid]["drilldown"][kset]
            assert route is not None, (kid, kset)
            rows = all_rows(signed_in, limit=100, **route_params(route))
            expected = k[kid]["numerator" if kset == "numerator" else "denominator"]
            assert len(rows) == expected, (kid, kset)
            checked += 1
    assert checked == 18
    # Card routes (OPS-01…05, OPS-07) open the register with the identical count.
    for ops in ("OPS-01", "OPS-02", "OPS-03", "OPS-04", "OPS-05", "OPS-07"):
        route = k[ops]["drilldown"]["numerator"]
        assert len(all_rows(signed_in, limit=100, **route_params(route))) == k[ops]["numerator"], ops
    # A drilldown route exists only where the KPI reports that count (no route for an absent denominator).
    for kid, v in k.items():
        for kset in ("numerator", "denominator"):
            if v["drilldown"][kset] is not None:
                assert v[kset] is not None, (kid, kset)


def test_kpi_drilldown_ids_equal_the_predicate_ids(signed_in: TestClient, conn: Connection) -> None:
    from app.domain.kpis import load_facts, local_range
    from app.domain.register import kpi_ids

    f = load_facts(conn, SCHEMA, ["SG"], datetime.now(UTC))
    s, e = local_range(*(datetime.fromisoformat(WIDE[x]).date() for x in ("from", "to")))
    den, num = CASE_PREDICATES["KPI-10"](f, s, e)
    api = {r["case_id"] for r in all_rows(signed_in, limit=100, kpi="KPI-10", kpi_set="numerator", **WIDE)}
    assert api == {str(i) for i in num}
    assert kpi_ids(f, "KPI-10", "denominator", *(datetime.fromisoformat(WIDE[x]).date() for x in ("from", "to"))) == den


def test_work_queue_counts_equal_overview_cards_and_register(signed_in: TestClient) -> None:
    k = {x["definition_id"]: x for x in signed_in.get("/api/v1/dashboard/kpis").json()["items"]}
    q = {x["code"]: x for x in signed_in.get("/api/v1/work-queues").json()["items"]}
    assert list(q) == ["DUE_TODAY", "OVERDUE", "AWAITING_CALLBACK", "ON_HOLD"]
    assert q["DUE_TODAY"]["count"] == k["OPS-02"]["numerator"]
    assert q["OVERDUE"]["count"] == k["OPS-01"]["breakdown"]["overdue"]
    assert q["ON_HOLD"]["count"] == k["OPS-03"]["numerator"]
    assert {r["hold_reason"]: r["count"] for r in q["ON_HOLD"]["by_reason"]} == k["OPS-03"]["breakdown"]["by_reason"]
    for code, entry in q.items():
        rows = all_rows(signed_in, limit=100, **route_params(entry["register_route"]))
        assert len(rows) == entry["count"], code
        assert all(r["outcome"] == "OPEN" for r in rows)
    for reason in q["ON_HOLD"]["by_reason"]:
        rows = all_rows(signed_in, limit=100, **route_params(reason["register_route"]))
        assert len(rows) == reason["count"] and all(reason["hold_reason"] in r["holds"] for r in rows)
    awaiting = all_rows(signed_in, limit=100, queue="AWAITING_CALLBACK")
    assert all(r["state"] == "AWAITING_CALLBACK" for r in awaiting)


def test_facets_are_scoped_and_disjunctive(signed_in: TestClient) -> None:
    body = signed_in.get("/api/v1/cases/facets").json()
    total = body["total"]
    for dim in ("state", "outcome", "band", "product_family", "ilp"):
        assert sum(body["facets"][dim].values()) == total, dim
    filtered = signed_in.get("/api/v1/cases/facets", params={"state": "AWAITING_CALLBACK"}).json()
    assert filtered["facets"]["state"] == body["facets"]["state"]  # own dimension excluded
    assert sum(filtered["facets"]["band"].values()) == filtered["total"] == body["facets"]["state"]["AWAITING_CALLBACK"]
    assert body["markets"] == ["SG"]


# ---- search ------------------------------------------------------------------------------------------------
def golden(conn: Connection) -> dict[str, str]:
    r = conn.execute(
        text(
            f"SELECT c.case_ref, p.policy_ref, a.attempt_ref, s.session_ref FROM {SCHEMA}.callback_case c "
            f"JOIN {SCHEMA}.sale_event se ON se.id = c.sale_event_id JOIN {SCHEMA}.policy p ON p.id = se.policy_id "
            f"JOIN {SCHEMA}.contact_attempt a ON a.callback_case_id = c.id JOIN {SCHEMA}.conversation_session s "
            "ON s.contact_attempt_id = a.id WHERE c.market_code = 'SG' ORDER BY c.case_ref LIMIT 1"
        )
    ).one()
    return {"case": r.case_ref, "policy": r.policy_ref, "attempt": r.attempt_ref, "session": r.session_ref}


def test_be_srch_01_02_06_each_type_findable_ranked_with_typed_routes(signed_in: TestClient, conn: Connection) -> None:
    """BE-SRCH-01, BE-SRCH-02 (exact > prefix > fuzzy with matched field), BE-SRCH-06 (typed routes)."""
    g = golden(conn)
    for etype, ref in g.items():
        body = signed_in.get("/api/v1/search", params={"q": ref.lower()}).json()
        top = body["items"][0]
        assert (top["entity_type"], top["ref"], top["match_kind"]) == (etype, ref, "EXACT"), etype
        assert top["matched_field"] == f"{etype}_ref"
        prefix = {"case": "/cases/", "policy": "/policies/", "attempt": "/cases/", "session": "/cases/"}[etype]
        assert top["route"].startswith(prefix) and top["register_route"] == f"/calls?q={ref}"
        assert len(all_rows(signed_in, q=ref)) >= 1
    kinds = [
        h["match_kind"]
        for h in signed_in.get("/api/v1/search", params={"q": g["case"][:-1], "limit": 50}).json()["items"]
    ]
    assert kinds == sorted(kinds, key=["EXACT", "PREFIX", "FUZZY"].index) and "PREFIX" in kinds
    fuzzy = signed_in.get("/api/v1/search", params={"q": g["case"][3:]}).json()["items"]
    assert any(h["ref"] == g["case"] and h["match_kind"] == "FUZZY" for h in fuzzy)
    typed = signed_in.get("/api/v1/search", params={"q": "CB-2026-1", "types": ["policy"]}).json()
    assert typed["total"] == 0
    sug = signed_in.get("/api/v1/search/suggest", params={"q": "SS-2026"}).json()["items"]
    assert 1 <= len(sug) <= 8 and all(h["entity_type"] == "session" for h in sug)


def test_exact_phone_and_email_lookup_uses_the_protected_token(signed_in: TestClient, conn: Connection) -> None:
    row = conn.execute(
        text(
            f"SELECT p.policy_ref, pa.party_ref FROM {SCHEMA}.policy p JOIN {SCHEMA}.policy_party_role pr "
            f"ON pr.policy_id = p.id AND pr.role = 'OWNER' JOIN {SCHEMA}.party pa ON pa.id = pr.party_id "
            "WHERE p.market_code = 'SG' AND p.policy_ref = 'POL-SG-000001'"
        )
    ).one()
    party_no = int(row.party_ref.split("-")[1])
    phone = f"SYN-TEL-SG-{100000 + party_no:06d}"
    email = f"Example.Policyholder.{party_no:03d}@example.invalid "
    for q, fld in ((phone, "contact_phone"), (email, "contact_email")):
        hits = signed_in.get("/api/v1/search", params={"q": q}).json()["items"]
        assert hits and all(h["matched_field"] == fld and h["match_kind"] == "EXACT" for h in hits)
        assert {r["policy_ref"] for r in all_rows(signed_in, q=q)} == {"POL-SG-000001"}
        assert q.strip().lower() not in str(hits).lower()
    # partial contact values never match (exact token only)
    assert signed_in.get("/api/v1/search", params={"q": phone[:-1]}).json()["total"] == 0


def test_be_srch_05_be_sec_02_no_malaysian_rows_counts_facets_or_suggestions(
    client: TestClient, admin: Account, conn: Connection
) -> None:
    login(client, admin)  # ADMIN is SG-only too (D-39)
    my = conn.execute(
        text(
            f"SELECT c.case_ref, p.policy_ref, a.attempt_ref FROM {SCHEMA}.callback_case c JOIN {SCHEMA}.sale_event s "
            f"ON s.id = c.sale_event_id JOIN {SCHEMA}.policy p ON p.id = s.policy_id JOIN {SCHEMA}.contact_attempt a "
            "ON a.callback_case_id = c.id WHERE c.market_code = 'MY' ORDER BY c.case_ref LIMIT 1"
        )
    ).one()
    my_party = conn.execute(
        text(
            f"SELECT pa.party_ref FROM {SCHEMA}.policy p JOIN {SCHEMA}.policy_party_role pr ON pr.policy_id = p.id "
            f"JOIN {SCHEMA}.party pa ON pa.id = pr.party_id WHERE p.market_code = 'MY' LIMIT 1"
        )
    ).scalar_one()
    my_phone = f"SYN-TEL-MY-{100000 + int(my_party.split('-')[1]):06d}"
    for q in (my.case_ref, my.policy_ref, my.attempt_ref, "POL-MY", "CB-2026-2", my_phone):
        assert client.get("/api/v1/search", params={"q": q}).json()["total"] == 0, q
        assert client.get("/api/v1/search/suggest", params={"q": q}).json()["items"] == [], q
        assert client.get("/api/v1/cases", params={"q": q}).json()["total"] == 0, q
        assert client.get("/api/v1/cases/facets", params={"q": q}).json()["total"] == 0, q
    everything = str(all_rows(client, limit=100)) + str(client.get("/api/v1/cases/facets").json())
    assert "MY" not in client.get("/api/v1/cases/facets").json()["markets"] and "POL-MY" not in everything


def test_principal_without_market_scope_sees_nothing(client: TestClient, db: Session, conn: Connection) -> None:
    login(client, make_account(db, "LOCAL_USER_MY", prefix="nomkt"))
    g = golden(conn)
    assert client.get("/api/v1/cases").json()["total"] == 0
    assert client.get("/api/v1/cases/facets").json()["facets"]["state"] == {}
    assert all(q["count"] == 0 for q in client.get("/api/v1/work-queues").json()["items"])
    assert client.get("/api/v1/search", params={"q": g["case"]}).json()["total"] == 0
    assert client.get("/api/v1/search/suggest", params={"q": g["policy"]}).json()["items"] == []


def test_permissions(client: TestClient, db: Session, admin: Account) -> None:
    paths = ("/api/v1/cases", "/api/v1/cases/facets", "/api/v1/work-queues", "/api/v1/search?q=CB")
    for p in paths:
        assert client.get(p).status_code == 401, p
    account = make_account(db, "LOCAL_USER_SG", prefix="norole")
    db.execute(
        text("UPDATE group_membership SET valid_to = now() WHERE principal_id = :p"), {"p": account.principal_id}
    )
    db.commit()
    login(client, account)
    for p in (*paths, "/api/v1/search/suggest?q=CB"):
        assert client.get(p).status_code == 403, p
    client.cookies.clear()
    login(client, admin)
    assert all(client.get(p).status_code == 200 for p in paths)


def test_be_srch_08_terms_are_logged_and_audited_only_as_hashes(
    signed_in: TestClient, conn: Connection, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "SYN-TEL-SG-100001"
    with caplog.at_level(logging.DEBUG):
        signed_in.get("/api/v1/search", params={"q": secret})
        signed_in.get("/api/v1/search/suggest", params={"q": secret})
        signed_in.get("/api/v1/cases", params={"q": secret})
    # httpx / httpx2 are the test client (httpx2 since S1-D's huggingface-hub dependency), not the server.
    server = [r for r in caplog.records if r.name not in ("httpx", "httpx2")]
    assert server and secret not in str([(r.getMessage(), r.__dict__) for r in server])
    assert any(getattr(r, "q_sha256", None) == term_hash(secret) for r in caplog.records)
    after = conn.execute(
        text(f"SELECT after FROM {SCHEMA}.audit_event WHERE action = 'SEARCH.EXECUTED' ORDER BY seq DESC LIMIT 1")
    ).scalar_one()
    assert after["q_sha256"] == term_hash(secret) and secret not in str(after)
    # the uvicorn access log line has its q= replaced by the digest
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d', None, None)
    rec.args = ("127.0.0.1:1", "GET", f"/api/v1/search?q={secret}&limit=5", "1.1", 200)
    SearchTermRedaction().filter(rec)
    assert secret not in rec.getMessage() and f"q=sha256:{term_hash(secret)}&limit=5" in rec.getMessage()


def test_search_validation(signed_in: TestClient) -> None:
    assert signed_in.get("/api/v1/search", params={"q": "x" * 65}).json()["code"] == "QUERY_TOO_LONG"
    assert signed_in.get("/api/v1/search", params={"q": "  "}).status_code == 422
    assert signed_in.get("/api/v1/search", params={"q": "CB", "types": "transcript"}).json()["code"] == "INVALID_FILTER"
    first = signed_in.get("/api/v1/search", params={"q": "CB-2026-1", "limit": 5}).json()
    assert first["total"] > 5 and first["page"]["next_cursor"]
    again = signed_in.get("/api/v1/search", params={"q": "CB-2026-10", "cursor": first["page"]["next_cursor"]})
    assert again.json()["code"] == "INVALID_CURSOR"
    seen: list[str] = []
    cursor = None
    while True:
        b = signed_in.get(
            "/api/v1/search", params={"q": "CB-2026-1", "limit": 50, **({"cursor": cursor} if cursor else {})}
        ).json()
        seen += [h["ref"] for h in b["items"]]
        cursor = b["page"]["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == first["total"]
