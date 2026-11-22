"""CP0.1B-3 — Administration completion: API-007, 009, 011, 013, 014…020, 026. BE-AUD-04 (groups, memberships and
mappings audited with before/after, history kept), BE-AUTH-06 (admin revoke, password reset, membership and mapping
changes take effect on the next request), one-time passwords (shown once, never audited, must be changed before any
permissioned action), Idempotency-Key on user creation, If-Match on mappings, reserved permissions and non-enabled
markets refused, last-administrator and self-demotion guards, system health, CSRF and USER denial."""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, unique

pytestmark = pytest.mark.usefixtures("seeded")
FRESH_CREDENTIAL = secrets.token_urlsafe(18)  # generated per run (S0_IDENTITY_ACCESS_DESIGN: test credentials)


def ok(r: Any, status: int = 200) -> dict[str, Any]:
    assert r.status_code == status, r.text
    return r.json() if r.content else {}


def group(client: TestClient, code: str) -> dict[str, Any]:
    return next(g for g in ok(client.get("/api/v1/admin/groups"))["items"] if g["code"] == code)


def audit(conn: Connection, action: str, entity_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"SELECT reason, before, after FROM {SCHEMA}.audit_event WHERE action = :a AND entity_id = :e ORDER BY seq"
        ),
        {"a": action, "e": entity_id},
    ).mappings()
    return [dict(r) for r in rows]


@pytest.fixture()
def admin_client(client: TestClient, admin: Account) -> TestClient:
    login(client, admin)
    return client


def test_create_user_one_time_password_and_first_sign_in(
    admin_client: TestClient, other_client: TestClient, conn: Connection
) -> None:
    username = unique("new")
    body = {
        "username": username,
        "display_name": "New Example User",
        "group_code": "LOCAL_USER_SG",
        "reason": "Onboard",
    }
    path, h = "/api/v1/admin/users", csrf_header(admin_client)
    assert admin_client.post(path, json=body, headers=h).status_code == 428
    key = f"k-{uuid.uuid4().hex}"
    r = admin_client.post(path, json=body, headers={**h, "Idempotency-Key": key})
    created = ok(r, 201)
    assert r.headers["cache-control"] == "no-store"
    otp = created["one_time_password"]
    assert otp and len(otp) >= 12 and created["user"]["groups"] == ["LOCAL_USER_SG"]
    replay = ok(admin_client.post(path, json=body, headers={**h, "Idempotency-Key": key}))
    assert replay["replayed"] and replay["one_time_password"] is None
    assert replay["user"]["principal_id"] == created["user"]["principal_id"]
    other = admin_client.post(path, json={**body, "username": unique("x")}, headers={**h, "Idempotency-Key": key})
    assert other.status_code == 409 and other.json()["code"] == "IDEMPOTENCY_KEY_REUSED"
    dup = admin_client.post(path, json=body, headers={**h, "Idempotency-Key": f"k-{uuid.uuid4().hex}"})
    assert dup.status_code == 409 and dup.json()["code"] == "USERNAME_TAKEN"
    pid = created["user"]["principal_id"]
    events = audit(conn, "ADMIN.USER_CREATED", pid)
    assert events[0]["reason"] == "Onboard" and events[0]["after"]["one_time_password"] is True
    assert otp not in json.dumps(conn.execute(text(f"SELECT json_agg(a) FROM {SCHEMA}.audit_event a")).scalar_one())

    # First sign-in: only /me and the own password change work until the one-time password is replaced.
    login(other_client, Account(username, otp, uuid.UUID(pid)))
    assert ok(other_client.get("/api/v1/me"))["password_change_required"] is True
    blocked = other_client.get("/api/v1/cases")
    assert blocked.status_code == 403 and blocked.json()["code"] == "PASSWORD_CHANGE_REQUIRED"
    ph = csrf_header(other_client)
    wrong = other_client.post(
        "/api/v1/me/password", json={"current_password": "nope", "new_password": FRESH_CREDENTIAL}, headers=ph
    )
    assert wrong.status_code == 422 and wrong.json()["code"] == "CURRENT_PASSWORD_INVALID"
    weak = other_client.post("/api/v1/me/password", json={"current_password": otp, "new_password": "short"}, headers=ph)
    assert weak.status_code == 422 and weak.json()["code"] == "PASSWORD_POLICY"
    ok(
        other_client.post(
            "/api/v1/me/password", json={"current_password": otp, "new_password": FRESH_CREDENTIAL}, headers=ph
        ),
        204,
    )
    assert ok(other_client.get("/api/v1/me"))["password_change_required"] is False
    assert other_client.get("/api/v1/cases").status_code == 200
    assert audit(conn, "AUTH.PASSWORD_CHANGED", pid)[0]["after"]["one_time_password_replaced"] is True


def test_password_reset_revokes_sessions(admin_client: TestClient, other_client: TestClient, db: Session) -> None:
    target = make_account(db, "LOCAL_USER_SG", prefix="reset")
    login(other_client, target)
    assert other_client.get("/api/v1/cases").status_code == 200
    h = csrf_header(admin_client)
    r = ok(
        admin_client.post(
            f"/api/v1/admin/users/{target.principal_id}/password-reset", json={"reason": "Lost"}, headers=h
        )
    )
    assert r["one_time_password"] and other_client.get("/api/v1/cases").status_code == 401  # next request
    me = ok(admin_client.get("/api/v1/me"))["principal"]["principal_id"]
    own = admin_client.post(f"/api/v1/admin/users/{me}/password-reset", json={"reason": "x" * 3}, headers=h)
    assert own.status_code == 409 and own.json()["code"] == "OWN_ACCOUNT"
    session = ok(admin_client.get("/api/v1/auth/session"))
    assert {"session_id", "idle_expires_at", "absolute_expires_at"} <= session.keys()


def test_groups_roles_and_membership_changes(
    admin_client: TestClient, other_client: TestClient, db: Session, conn: Connection
) -> None:
    body = ok(admin_client.get("/api/v1/admin/groups"))
    assert body["enabled_markets"] == ["SG"]
    adm = group(admin_client, "LOCAL_ADMIN")
    assert adm["roles"] == ["ADMIN"] and adm["markets"] == ["SG"] and adm["member_count"] >= 1
    assert all(m["valid_to"] is None for m in adm["members"])
    roles = ok(admin_client.get("/api/v1/admin/roles"))
    assert {"admin.groups.manage", "admin.sessions.manage"} <= {
        p["code"] for r in roles["items"] if r["code"] == "ADMIN" for p in r["permissions"]
    }
    reserved = {p["code"] for p in roles["reserved_permissions"]}
    assert "pii.unmasked" in reserved and "review.decide" not in reserved  # S3-C un-reserved review.decide
    assert not {"review.decide", "review.approve"} & {  # never granted to ADMIN (no maker-checker bypass)
        p["code"] for r in roles["items"] if r["code"] == "ADMIN" for p in r["permissions"]
    }

    target = make_account(db, "LOCAL_USER_SG", prefix="member")
    login(other_client, target)
    assert other_client.get("/api/v1/admin/users").status_code == 403
    h = csrf_header(admin_client)
    path = f"/api/v1/admin/groups/{adm['group_id']}/members/{target.principal_id}"
    assert admin_client.put(path, json={}, headers=h).status_code == 422  # reason required
    after = ok(admin_client.put(path, json={"reason": "Temporary admin cover"}, headers=h))
    assert str(target.principal_id) in {m["principal_id"] for m in after["members"]}
    assert other_client.get("/api/v1/admin/users").status_code == 200  # effective on the next request
    ok(admin_client.put(path, json={"reason": "Again"}, headers=h))  # idempotent PUT
    ended = ok(admin_client.request("DELETE", path, json={"reason": "Cover finished"}, headers=h))
    assert str(target.principal_id) in {m["principal_id"] for m in ended["former_members"]}
    assert other_client.get("/api/v1/admin/users").status_code == 403
    entity = f"LOCAL_ADMIN:{target.principal_id}"
    added, removed = audit(conn, "ADMIN.MEMBERSHIP_ADDED", entity), audit(conn, "ADMIN.MEMBERSHIP_ENDED", entity)
    assert len(added) == 1 and added[0]["before"] == {"member": False} and removed[0]["reason"] == "Cover finished"

    me = ok(admin_client.get("/api/v1/me"))["principal"]["principal_id"]
    self_remove = admin_client.request(
        "DELETE", f"/api/v1/admin/groups/{adm['group_id']}/members/{me}", json={"reason": "Leave"}, headers=h
    )
    assert self_remove.status_code == 409 and self_remove.json()["code"] == "LAST_ADMIN_GUARD"
    assert me in {m["principal_id"] for m in group(admin_client, "LOCAL_ADMIN")["members"]}  # rolled back


def test_mappings_replace_with_guards_and_history(
    admin_client: TestClient, other_client: TestClient, db: Session, conn: Connection
) -> None:
    usr = group(admin_client, "LOCAL_USER_SG")
    path, h = f"/api/v1/admin/groups/{usr['group_id']}/mappings", csrf_header(admin_client)
    body = {"roles": ["USER"], "markets": [], "reason": "Pause Singapore access"}
    assert admin_client.put(path, json=body, headers=h).status_code == 428
    stale = admin_client.put(path, json=body, headers={**h, "If-Match": "0000000000000000"})
    assert stale.status_code == 409 and stale.json()["code"] == "CONFLICT_ROW_VERSION"
    v = {**h, "If-Match": usr["mappings_version"]}
    my = admin_client.put(path, json={**body, "markets": ["MY"]}, headers=v)
    assert my.status_code == 422 and my.json()["code"] == "MARKET_NOT_ENABLED"
    bad = admin_client.put(path, json={**body, "roles": ["AUDITOR"]}, headers=v)
    assert bad.status_code == 422 and bad.json()["code"] == "UNKNOWN_ROLE"
    same = admin_client.put(path, json={**body, "markets": ["SG"]}, headers=v)
    assert same.status_code == 422 and same.json()["code"] == "NO_CHANGE"

    member = make_account(db, "LOCAL_USER_SG", prefix="scope")
    login(other_client, member)
    assert ok(other_client.get("/api/v1/cases"))["total"] > 0
    paused = ok(admin_client.put(path, json=body, headers=v))
    assert paused["markets"] == [] and ok(other_client.get("/api/v1/cases"))["total"] == 0  # next request
    restored = ok(
        admin_client.put(
            path,
            json={**body, "markets": ["SG"], "reason": "Restore"},
            headers={**h, "If-Match": paused["mappings_version"]},
        )
    )
    assert restored["markets"] == ["SG"] and ok(other_client.get("/api/v1/cases"))["total"] > 0
    sg_rows = [s for s in restored["scope_history"] if s["market"] == "SG"]
    assert len(sg_rows) >= 2 and sum(s["effective_to"] is None for s in sg_rows) == 1  # history kept, one current
    events = audit(conn, "ADMIN.GROUP_MAPPINGS_REPLACED", usr["group_id"])
    assert events[-2]["before"]["markets"] == ["SG"] and events[-2]["after"]["markets"] == []

    adm = group(admin_client, "LOCAL_ADMIN")
    demote = admin_client.put(
        f"/api/v1/admin/groups/{adm['group_id']}/mappings",
        json={"roles": ["USER"], "markets": ["SG"], "reason": "Demote"},
        headers={**h, "If-Match": adm["mappings_version"]},
    )
    assert demote.status_code == 409 and demote.json()["code"] == "LAST_ADMIN_GUARD"
    assert group(admin_client, "LOCAL_ADMIN")["roles"] == ["ADMIN"]


def test_sessions_list_and_revoke(admin_client: TestClient, other_client: TestClient, user: Account) -> None:
    login(other_client, user)
    sessions = ok(admin_client.get("/api/v1/admin/sessions"))["items"]
    assert sum(s["current"] for s in sessions) == 1
    assert all("token" not in k for s in sessions for k in s)
    theirs = next(s for s in sessions if s["username"] == user.username)
    h = csrf_header(admin_client)
    assert (
        admin_client.post(f"/api/v1/admin/sessions/{theirs['session_id']}/revoke", json={}, headers=h).status_code
        == 422
    )
    ok(
        admin_client.post(
            f"/api/v1/admin/sessions/{theirs['session_id']}/revoke", json={"reason": "Lost laptop"}, headers=h
        ),
        204,
    )
    assert other_client.get("/api/v1/me").status_code == 401
    mine = next(s for s in sessions if s["current"])
    own = admin_client.post(f"/api/v1/admin/sessions/{mine['session_id']}/revoke", json={"reason": "x" * 3}, headers=h)
    assert own.status_code == 409 and own.json()["code"] == "OWN_SESSION"
    gone = admin_client.post(
        f"/api/v1/admin/sessions/{theirs['session_id']}/revoke", json={"reason": "Again"}, headers=h
    )
    assert gone.status_code == 404


def test_system_health(admin_client: TestClient) -> None:
    from pathlib import Path

    body = ok(admin_client.get("/api/v1/admin/system-health"))
    checks = {c["code"]: c["status"] for c in body["checks"]}
    assert checks["DATABASE"] == checks["MIGRATIONS"] == checks["DATA_POLICY"] == checks["AUDIT_CHAIN"] == "OK"
    assert checks["MOCK_UPSTREAM"] == checks["VOICE"] == "NOT_AVAILABLE"
    assert body["migration_head"] == body["expected_migration_head"] == "0028_survey_library"
    assert body["enabled_markets"] == ["SG"] and body["current_stage"] == "S0" and body["audit_chain_head"]
    sha = (Path(__file__).resolve().parents[1] / "contracts" / "generated" / "openapi.sha256").read_text().strip()
    assert body["openapi_sha256"] == sha
    assert body["counts"]["active_admins"] >= 1 and body["counts"]["active_sessions"] >= 1


def test_user_is_denied_and_writes_need_csrf(client: TestClient, user: Account, admin: Account) -> None:
    login(client, user)
    gid, sid = uuid.uuid4(), uuid.uuid4()
    for method, path in (
        ("GET", "/api/v1/admin/groups"),
        ("GET", "/api/v1/admin/roles"),
        ("GET", "/api/v1/admin/sessions"),
        ("GET", "/api/v1/admin/system-health"),
        ("POST", "/api/v1/admin/users"),
        ("POST", f"/api/v1/admin/users/{gid}/password-reset"),
        ("PUT", f"/api/v1/admin/groups/{gid}/members/{sid}"),
        ("PUT", f"/api/v1/admin/groups/{gid}/mappings"),
        ("POST", f"/api/v1/admin/sessions/{sid}/revoke"),
    ):
        r = client.request(method, path, json={"reason": "probe"}, headers=csrf_header(client))
        assert r.status_code == 403, path
    assert ok(client.get("/api/v1/auth/session"))["session_id"]  # own session: any authenticated user
    client.cookies.clear()
    login(client, admin)
    r = client.post(f"/api/v1/admin/sessions/{sid}/revoke", json={"reason": "No CSRF"})
    assert r.status_code == 403 and r.json()["code"] == "CSRF_INVALID"
