"""S2-B editable assignment rules over HTTP: authoring, copy and versioning, validation (target eligibility, dates,
conflicts), maker-checker lifecycle, explicit supersede, immutability, history and diff, side-effect-free simulation,
permissions and Singapore-only scope. Publishing never changes existing case assignments (S2-C assigns)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.domain.digest import content_digest
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_script_authoring import approve, build_basic, ok

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk")


def post(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
    return ok(c.post(f"/api/v1{path}", json=body, headers=csrf_header(c)), status)


def seeded_target(c: TestClient) -> str:
    opts = ok(c.get("/api/v1/assignment-rules/options"))
    return next(t["id"] for t in opts["targets"] if t["label"] == "SALES_VERIFICATION_SG v1.1")


def publish_script(user_c: TestClient, checker_c: TestClient, code: str) -> str:
    """A second published SG script version to target (built with the S2-A editor)."""
    _, vid, d = build_basic(user_c, code)
    d.post("/submit", {"change_summary": "Target script for rule tests"})
    for step, body in (("review", approve(checker_c, vid)), ("publish", {})):
        ok(checker_c.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(checker_c)))
    return vid


class Rule:
    """A rule draft with its concurrency token."""

    def __init__(self, c: TestClient, draft_id: str) -> None:
        self.c, self.id = c, draft_id
        self.d = self.get()

    def get(self) -> dict[str, Any]:
        self.d = ok(self.c.get(f"/api/v1/assignment-rule-drafts/{self.id}"))
        return self.d

    def put(self, status: int = 200, **content: Any) -> Any:
        body = {
            "name": self.d["name"],
            "description": self.d["description"],
            "conditions": self.d["conditions"],
            "priority": self.d["priority"],
            "is_fallback": self.d["is_fallback"],
            "target_script_version_id": (self.d["target"] or {}).get("id"),
            "effective_from": self.d["effective_from"],
            "effective_to": self.d["effective_to"],
            **content,
        }
        r = self.c.put(
            f"/api/v1/assignment-rule-drafts/{self.id}",
            json={"expected_row_version": self.d["row_version"], "content": body},
            headers=csrf_header(self.c),
        )
        assert r.status_code == status, r.text
        self.get()
        return r.json()

    def submit(self, status: int = 200) -> Any:
        r = self.c.post(
            f"/api/v1/assignment-rule-drafts/{self.id}/submit",
            json={"expected_row_version": self.d["row_version"], "change_summary": "Rule for S2-B tests (synthetic)"},
            headers=csrf_header(self.c),
        )
        assert r.status_code == status, r.text
        self.get()
        return r.json()


def new_rule(c: TestClient, code: str, **kw: Any) -> Rule:
    out = post(c, "/assignment-rules", {"code": code, "name": f"{code} rule", **kw}, 201)
    return Rule(c, out["draft_id"])


ILP_HIGH = [
    {"field": "market", "values": ["SG"]},
    {"field": "is_ilp", "values": [True]},
    {"field": "risk_band", "values": ["HIGH"]},
]


def business_fingerprint(conn: Connection) -> str:
    """Hash of everything simulation and publication must not touch: assignments, case states and holds."""
    h = hashlib.sha256()
    for sql in (
        f"SELECT id, script_version_id, matched_rule_version_id, supersedes_id FROM {SCHEMA}.script_assignment "
        "ORDER BY id",
        f"SELECT id, state, has_blocking_hold, row_version, updated_at FROM {SCHEMA}.callback_case ORDER BY id",
        f"SELECT * FROM {SCHEMA}.case_hold ORDER BY id",
    ):
        for row in conn.execute(text(sql)):
            h.update(repr(tuple(row)).encode())
    conn.rollback()
    return h.hexdigest()


def test_create_configure_simulate_submit_approve_publish(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    login(other_client, checker)
    before = business_fingerprint(conn)
    digest_before = content_digest(conn, SCHEMA)
    conn.rollback()
    opts = ok(client.get("/api/v1/assignment-rules/options"))
    fields = {f["field"]: f for f in opts["fields"]}
    assert set(fields) == {
        "market",
        "case_purpose",
        "product_family",
        "product_code",
        "is_ilp",
        "risk_band",
        "selling_channel",
        "premium_frequency",
        "contact_role",
    }
    assert [v["value"] for v in fields["market"]["values"]] == ["SG"]  # Singapore only (D-39)
    assert "UNASSESSED" in [v["value"] for v in fields["risk_band"]["values"]]
    assert {u["field"] for u in opts["unsupported"]} == {"language"}  # reported, not invented
    target = seeded_target(client)
    r = new_rule(client, "S2B-ILP-HIGH", description="ILP sales with high SBQ risk (synthetic)")
    assert (
        r.d["status"] == "DRAFT"
        and r.d["planned_version"] == 1
        and r.d["conditions"] == [{"field": "market", "values": ["SG"]}]
    )
    # Immediate feedback on unsaved content.
    fb = post(
        client,
        "/assignment-rules/explain",
        {"name": "x" * 5, "conditions": ILP_HIGH, "priority": 5, "target_script_version_id": target},
    )
    assert fb["specificity"] == 3 and fb["explanation"].startswith("Assign SALES_VERIFICATION_SG v1.1 when the market")
    r.put(conditions=ILP_HIGH, priority=5, target_script_version_id=target)
    assert r.d["analysis"]["specificity"] == 3 and r.d["analysis"]["valid"], r.d["analysis"]
    # It overlaps the seeded catch-all rule and wins on priority (INFO, not an error).
    assert {c["kind"] for c in r.d["analysis"]["conflicts"]} == {"OVERLAP"}
    # Simulate: no side effects, deterministic, explained.
    sim = post(client, "/assignment-rules/simulate", {"draft_ids": [r.id]})
    assert sim["side_effects"] == "NONE" and sim["summary"]["cases"] > 0
    ilp_high = [c for c in sim["cases"] if c["inputs"]["is_ilp"] and c["inputs"]["risk_band"] == "HIGH"]
    assert ilp_high and all(c["proposed"]["winning_rules"] == ["S2B-ILP-HIGH v1 (proposed)"] for c in ilp_high)
    others = [c for c in sim["cases"] if c not in ilp_high]
    assert all(
        c["proposed"]["winning_rules"] == ["SG-SALES-VERIFY v2"] for c in others if c["inputs"]["product_family"]
    )
    assert sim["summary"]["changed"] == len(ilp_high)
    one = ilp_high[0]["proposed"]["trace"]
    mine = next(t for t in one if t["ref"].startswith("S2B-ILP-HIGH"))
    assert mine["selected"] and [c["result"] for c in mine["conditions"]] == ["PASS", "PASS", "PASS"]
    seeded = next(t for t in one if t["ref"] == "SG-SALES-VERIFY v2")
    assert seeded["match"] == "MATCH" and not seeded["selected"]
    assert {t["ref"]: t["excluded_reason"] for t in one}["SG-PILOT v1"]  # withdrawn / not effective, with a reason
    assert not any(c["case_ref"].startswith("CB-") and c["inputs"]["market"] != "SG" for c in sim["cases"])
    again = post(client, "/assignment-rules/simulate", {"draft_ids": [r.id], "as_of": sim["as_of"]})
    assert [c["proposed"]["outcome"] for c in again["cases"]] == [c["proposed"]["outcome"] for c in sim["cases"]]
    assert business_fingerprint(conn) == before
    # Submit locks the content.
    sub = r.submit()
    assert sub["status"] == "SUBMITTED_FOR_REVIEW" and len(sub["manifest_sha256"]) == 64
    assert r.put(status=409)["code"] == "RULE_NOT_EDITABLE"
    with pytest.raises(Exception, match="locked once submitted"):
        conn.execute(text(f"UPDATE {SCHEMA}.assignment_rule_draft SET priority = 1 WHERE id = :i"), {"i": r.id})
    conn.rollback()
    # The maker cannot review (no permission); the checker approves and publishes.
    assert (
        client.post(
            f"/api/v1/assignment-rule-drafts/{r.id}/review",
            json={"decision": "APPROVE", "reason": "mine"},
            headers=csrf_header(client),
        ).status_code
        == 403
    )
    post(
        other_client, f"/assignment-rule-drafts/{r.id}/review", {"decision": "APPROVE", "reason": "Checked conditions"}
    )
    pub = post(other_client, f"/assignment-rule-drafts/{r.id}/publish", {"reason": "First publication"})
    assert pub["status"] == "PUBLISHED" and pub["version"] == 1 and pub["superseded"] is None
    reg = ok(client.get("/api/v1/assignment-rules"))
    item = next(i for i in reg["items"] if i["rule_code"] == "S2B-ILP-HIGH")
    live = item["live"]
    assert live["status"] == "PUBLISHED" and live["specificity"] == 3 and live["priority"] == 5
    assert live["authored_in_rule_studio"] and live["cases_assigned"] == 0  # publication assigns nothing (S2-C)
    assert live["checker_ref"] == str(checker.principal_id) and live["author_ref"] == str(user.principal_id)
    # Published rule versions are immutable in the database.
    for sql in (
        f"UPDATE {SCHEMA}.script_assignment_rule_version SET priority = 1 WHERE id = :i",
        f"UPDATE {SCHEMA}.script_assignment_rule_version SET status = 'SUPERSEDED' WHERE id = :i",  # no effective_to
        f"DELETE FROM {SCHEMA}.script_assignment_rule_version WHERE id = :i",
    ):
        with pytest.raises(Exception, match="immutable|never deleted"):
            conn.execute(text(sql), {"i": live["id"]})
        conn.rollback()
    with pytest.raises(Exception, match="immutable"):
        conn.execute(text(f"UPDATE {SCHEMA}.assignment_rule_draft SET name = 'x' WHERE id = :i"), {"i": r.id})
    conn.rollback()
    assert business_fingerprint(conn) == before  # no case reassigned, no state or hold changed
    assert content_digest(conn, SCHEMA) == digest_before
    audit = {
        a
        for (a,) in conn.execute(
            text(
                f"SELECT action FROM {SCHEMA}.audit_event WHERE action LIKE 'RULE.%' AND actor_principal_id = ANY(:p)"
            ),
            {"p": [user.principal_id, checker.principal_id]},
        )
    }
    assert {
        "RULE.DRAFT_CREATED",
        "RULE.CHANGED",
        "RULE.SIMULATED",
        "RULE.SUBMITTED",
        "RULE.APPROVED",
        "RULE.PUBLISHED",
    } <= audit


def test_versioning_copy_supersede_history_and_diff(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    login(other_client, checker)
    target = seeded_target(client)
    r = new_rule(client, "S2B-VERSIONED")
    r.put(
        conditions=[*ILP_HIGH[:2], {"field": "selling_channel", "values": ["AGENCY"]}],
        priority=7,
        target_script_version_id=target,
    )
    r.submit()
    post(other_client, f"/assignment-rule-drafts/{r.id}/review", {"decision": "APPROVE", "reason": "Version 1 checked"})
    v1 = post(other_client, f"/assignment-rule-drafts/{r.id}/publish", {})
    # One open draft per rule; a new version starts from the live version.
    v2 = Rule(client, post(client, "/assignment-rules/S2B-VERSIONED/drafts", {}, 201)["draft_id"])
    assert v2.d["planned_version"] == 2 and v2.d["base_ref"] == "S2B-VERSIONED v1" and v2.d["priority"] == 7
    dup = client.post("/api/v1/assignment-rules/S2B-VERSIONED/drafts", json={}, headers=csrf_header(client))
    assert dup.status_code == 409 and dup.json()["code"] == "OPEN_DRAFT_EXISTS"
    # Optimistic concurrency: a stale token is refused and nothing is overwritten.
    stale = v2.d["row_version"]
    v2.put(conditions=[*ILP_HIGH[:2], {"field": "selling_channel", "values": ["AGENCY", "BROKER"]}], priority=6)
    r_stale = client.put(
        f"/api/v1/assignment-rule-drafts/{v2.id}",
        json={"expected_row_version": stale, "content": {"name": "x" * 4, "conditions": ILP_HIGH[:1], "priority": 1}},
        headers=csrf_header(client),
    )
    assert r_stale.status_code == 409 and r_stale.json()["code"] == "STALE_DRAFT"
    assert v2.get()["priority"] == 6
    diff = ok(
        client.get(
            "/api/v1/assignment-rules/S2B-VERSIONED/diff",
            params={"base": f"version:{v1['rule_version_id']}", "target": f"draft:{v2.id}"},
        )
    )
    assert {c["field"]: c["effect"] for c in diff["conditions"]} == {"selling_channel": "MORE_PERMISSIVE"}
    # The draft starts "on publication" (no date yet); v1 has its publication date.
    assert {f["field"] for f in diff["fields"]} == {"priority", "effective_from"}
    v2.submit()
    post(
        other_client, f"/assignment-rule-drafts/{v2.id}/review", {"decision": "APPROVE", "reason": "Version 2 checked"}
    )
    # Superseding must be confirmed explicitly.
    r_no = other_client.post(
        f"/api/v1/assignment-rule-drafts/{v2.id}/publish", json={}, headers=csrf_header(other_client)
    )
    assert r_no.status_code == 422 and r_no.json()["code"] == "SUPERSEDE_CONFIRMATION_REQUIRED"
    out = post(
        other_client,
        f"/assignment-rule-drafts/{v2.id}/publish",
        {"supersede_rule_version_id": v1["rule_version_id"], "reason": "Broker sales too"},
    )
    assert out["version"] == 2 and out["superseded"] == "v1"
    hist = ok(client.get("/api/v1/assignment-rules/S2B-VERSIONED/history"))
    by_v = {v["version"]: v for v in hist["versions"]}
    assert (
        by_v[1]["status"] == "SUPERSEDED" and by_v[1]["effective_to"] is not None and by_v[2]["status"] == "PUBLISHED"
    )
    assert by_v[1]["priority"] == 7 and by_v[1]["checksum"] != by_v[2]["checksum"]  # v1 content unchanged
    types = [e["event_type"] for e in hist["events"]]
    assert types[:1] == ["DRAFT_CREATED"] and types.count("PUBLISHED") == 2 and "SUPERSEDED" in types
    # Copy an existing rule (the seeded one) into a new rule code.
    seeded = next(i for i in ok(client.get("/api/v1/assignment-rules"))["items"] if i["rule_code"] == "SG-SALES-VERIFY")
    cp = new_rule(client, "S2B-COPY", copy_from_rule_version_id=seeded["live"]["id"])
    assert cp.d["copied_from_ref"] == "SG-SALES-VERIFY v2" and cp.d["conditions"] == seeded["live"]["conditions"]
    assert cp.d["target"]["id"] == seeded["live"]["target"]["id"] and cp.d["priority"] == seeded["live"]["priority"]
    # The copy is an exact overlap with the seeded rule: same priority and specificity, same target → blocked.
    assert {i["code"] for i in cp.d["analysis"]["issues"] if i["severity"] == "ERROR"} == {"CONFLICT_SAME_TARGET_TIE"}
    assert cp.submit(status=422)["code"] == "VALIDATION_FAILED"
    # Historical assignments keep their rule (seeded cases still point at SG-SALES-VERIFY v2).
    seeded_after = next(
        i for i in ok(client.get("/api/v1/assignment-rules"))["items"] if i["rule_code"] == "SG-SALES-VERIFY"
    )
    assert seeded_after["live"]["cases_assigned"] == seeded["live"]["cases_assigned"] > 0


def test_conflicts_target_eligibility_dates_fallback_and_no_match(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    login(other_client, checker)
    target = seeded_target(client)
    other_target = publish_script(client, other_client, "S2B_TGT")
    a = new_rule(client, "S2B-CONF-A")
    a.put(conditions=ILP_HIGH[:2], priority=2, target_script_version_id=target)
    b = new_rule(client, "S2B-CONF-B")
    b.put(conditions=[ILP_HIGH[0], ILP_HIGH[2]], priority=2, target_script_version_id=other_target)
    # Two unpublished drafts that would tie: warned about each other, and ambiguous in a joint simulation.
    assert "OPEN_DRAFT_OVERLAP" in {i["code"] for i in a.get()["analysis"]["issues"]}
    sim = post(client, "/assignment-rules/simulate", {"draft_ids": [a.id, b.id]})
    amb = [c for c in sim["cases"] if c["proposed"]["outcome"] == "AMBIGUOUS"]
    assert amb and all(c["inputs"]["is_ilp"] and c["inputs"]["risk_band"] == "HIGH" for c in amb)
    assert all(c["proposed"]["selected_script_version_id"] is None for c in amb)
    assert {x["kind"] for x in sim["conflicts"]} >= {"AMBIGUOUS"}
    # Publish A; B now conflicts with a live rule and cannot be submitted.
    a.submit()
    post(other_client, f"/assignment-rule-drafts/{a.id}/review", {"decision": "APPROVE", "reason": "Rule A checked"})
    post(other_client, f"/assignment-rule-drafts/{a.id}/publish", {})
    errors = {i["code"] for i in b.get()["analysis"]["issues"] if i["severity"] == "ERROR"}
    assert errors == {"CONFLICT_AMBIGUOUS"}
    assert b.submit(status=422)["code"] == "VALIDATION_FAILED"
    b.put(priority=3)  # a different priority resolves it (A wins where both match)
    assert b.get()["analysis"]["valid"]
    # Target eligibility: superseded/withdrawn/draft targets and past start dates are errors.
    withdrawn = next(
        t for t in ok(client.get("/api/v1/assignment-rules/options"))["targets"] if t["status"] == "WITHDRAWN"
    )
    b.put(target_script_version_id=withdrawn["id"])
    assert "TARGET_NOT_PUBLISHED" in {i["code"] for i in b.d["analysis"]["issues"]}
    b.put(target_script_version_id=other_target, effective_from=(datetime.now(UTC) - timedelta(days=1)).isoformat())
    assert "START_IN_PAST" in {i["code"] for i in b.d["analysis"]["issues"]}
    start = datetime.now(UTC) + timedelta(days=3)
    b.put(effective_from=start.isoformat(), effective_to=(start + timedelta(days=30)).isoformat())
    assert b.d["analysis"]["valid"]
    sim_before = post(client, "/assignment-rules/simulate", {"draft_ids": [b.id]})
    sim_after = post(
        client, "/assignment-rules/simulate", {"draft_ids": [b.id], "as_of": (start + timedelta(days=1)).isoformat()}
    )
    won = lambda s: sum(r["cases_won"] for r in s["rules"] if r["rule_code"] == "S2B-CONF-B")  # noqa: E731
    assert won(sim_before) == 0 and won(sim_after) > 0  # effective only from its start date
    # No match: before any rule was effective, nothing can be selected.
    early = post(client, "/assignment-rules/simulate", {"as_of": "2025-01-01T00:00:00+08:00"})
    assert set(early["summary"]["proposed"]) == {"NO_MATCH"}
    # Fallback: explicit, considered only when no other rule matches.
    fb = new_rule(client, "S2B-FALLBACK")
    fb.put(priority=999, is_fallback=True, target_script_version_id=target)
    warn = {i["code"] for i in fb.d["analysis"]["issues"]}
    assert "FALLBACK" in warn and fb.d["analysis"]["valid"]
    early_fb = post(client, "/assignment-rules/simulate", {"draft_ids": [fb.id], "as_of": "2025-01-01T00:00:00+08:00"})
    assert set(early_fb["summary"]["proposed"]) == {"NO_MATCH"}  # not yet effective then either
    now_fb = post(client, "/assignment-rules/simulate", {"draft_ids": [fb.id]})
    assert "SELECTED_BY_FALLBACK" not in now_fb["summary"]["proposed"]  # other rules match every case now


def test_permissions_abandon_and_scope(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, db: Session, conn: Connection
) -> None:
    login(client, user)
    target = seeded_target(client)
    r = new_rule(client, "S2B-PERM")
    r.put(conditions=ILP_HIGH, priority=4, target_script_version_id=target)
    # ADMIN and the checker cannot author; nobody can create outside their markets.
    admin = make_account(db, "LOCAL_ADMIN", prefix="radm")
    for acct in (admin, checker):
        other_client.cookies.clear()
        login(other_client, acct)
        assert (
            other_client.post(
                "/api/v1/assignment-rules", json={"code": "S2B-NOPE", "name": "nope"}, headers=csrf_header(other_client)
            ).status_code
            == 403
        )
    assert (
        client.post(
            "/api/v1/assignment-rules",
            json={"code": "S2B-MY", "name": "Malaysia", "market": "MY"},
            headers=csrf_header(client),
        ).status_code
        == 403
    )
    # ADMIN cannot approve; a principal with both roles cannot approve their own edit.
    r.submit()
    other_client.cookies.clear()
    login(other_client, admin)
    assert (
        other_client.post(
            f"/api/v1/assignment-rule-drafts/{r.id}/review",
            json={"decision": "APPROVE", "reason": "admin"},
            headers=csrf_header(other_client),
        ).status_code
        == 403
    )
    other_client.cookies.clear()
    login(other_client, checker)
    post(other_client, f"/assignment-rule-drafts/{r.id}/review", {"decision": "REQUEST_CHANGES", "reason": "Narrow it"})
    assert r.get()["status"] == "DRAFT" and r.d["manifest_sha256"] is None
    dual = make_account(db, "LOCAL_USER_SG", prefix="rdual")
    db.execute(
        text(
            f"INSERT INTO {SCHEMA}.group_membership (id, principal_id, group_id, provenance, created_by) "
            f"SELECT :i, :p, id, 'LOCAL', 'SYSTEM:test' FROM {SCHEMA}.app_group WHERE code = 'LOCAL_SC_CHECKER_SG'"
        ),
        {"i": uuid.uuid4(), "p": dual.principal_id},
    )
    db.commit()
    other_client.cookies.clear()
    login(other_client, dual)
    mine = Rule(other_client, r.id)
    mine.put(priority=3)  # dual edits → becomes a maker
    mine.submit()
    denied = other_client.post(
        f"/api/v1/assignment-rule-drafts/{r.id}/review",
        json={"decision": "APPROVE", "reason": "self"},
        headers=csrf_header(other_client),
    )
    assert denied.status_code == 403 and denied.json()["code"] == "SELF_REVIEW_DENIED"
    other_client.cookies.clear()
    login(other_client, checker)
    post(
        other_client, f"/assignment-rule-drafts/{r.id}/review", {"decision": "REQUEST_CHANGES", "reason": "Back again"}
    )
    # Abandon: only a maker, with a reason; frozen afterwards and nothing deleted.
    stranger = make_account(db, "LOCAL_USER_SG", prefix="rstr")
    other_client.cookies.clear()
    login(other_client, stranger)
    rv = r.get()["row_version"]
    assert (
        other_client.post(
            f"/api/v1/assignment-rule-drafts/{r.id}/abandon",
            json={"expected_row_version": rv, "reason": "not mine"},
            headers=csrf_header(other_client),
        ).json()["code"]
        == "NOT_A_MAKER"
    )
    post(client, f"/assignment-rule-drafts/{r.id}/abandon", {"expected_row_version": rv, "reason": "Approach replaced"})
    assert r.get()["status"] == "ABANDONED"
    assert r.put(status=409)["code"] == "RULE_NOT_EDITABLE"
    with pytest.raises(Exception, match="never deleted"):
        conn.execute(text(f"DELETE FROM {SCHEMA}.assignment_rule_draft WHERE id = :i"), {"i": r.id})
    conn.rollback()
    hist = ok(client.get("/api/v1/assignment-rules/S2B-PERM/history"))
    assert hist["events"][-1]["event_type"] == "ABANDONED"
    assert post(client, "/assignment-rules/S2B-PERM/drafts", {}, 404)  # no published version to branch from
    fresh = new_rule(client, "S2B-PERM-2")
    assert fresh.d["status"] == "DRAFT"
    # Unknown fields and executable expressions are refused.
    bad = client.put(
        f"/api/v1/assignment-rule-drafts/{fresh.id}",
        json={
            "expected_row_version": fresh.d["row_version"],
            "content": {"name": "Bad rule", "conditions": [{"field": "language", "values": ["en"]}], "priority": 5},
        },
        headers=csrf_header(client),
    )
    assert bad.status_code == 422 and bad.json()["code"] == "INVALID_CONDITION"
    # Simulation is read-only even at the database level, and limited to Singapore.
    sim = post(client, "/assignment-rules/simulate", {"scope": "UNASSIGNED"})
    assert all(c["existing"] is None for c in sim["cases"])
    my_cases = conn.execute(text(f"SELECT count(*) FROM {SCHEMA}.callback_case WHERE market_code = 'MY'")).scalar_one()
    conn.rollback()
    assert (
        my_cases > 0
        and post(client, "/assignment-rules/simulate", {})["summary"]["cases"]
        == conn.execute(text(f"SELECT count(*) FROM {SCHEMA}.callback_case WHERE market_code = 'SG'")).scalar_one()
    )
