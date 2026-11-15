"""BE-AUTH-01…03, 05…10 — login, throttling, refresh rotation/concurrency, logout, CSRF, secrets."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.security.models import AuthSession, GroupMembership, RefreshToken
from tests.support import Account, csrf_header, csrf_token, login


def _refresh(c: TestClient):  # type: ignore[no-untyped-def]
    return c.post("/api/v1/auth/refresh", headers=csrf_header(c))


# ---- BE-AUTH-01 ------------------------------------------------------------------------------
def test_be_auth_01_unauthenticated_is_401(client: TestClient) -> None:
    r = client.get("/api/v1/me")
    assert r.status_code == 401 and r.json()["code"] == "AUTH_REQUIRED"


def test_be_auth_01_login_sets_httponly_cookies_and_new_session(client: TestClient, user: Account) -> None:
    r1 = login(client, user)
    assert r1.status_code == 200, r1.text
    set_cookie = r1.headers.get_list("set-cookie")
    access = next(h for h in set_cookie if h.startswith("c360_at="))
    refresh = next(h for h in set_cookie if h.startswith("c360_rt="))
    csrf = next(h for h in set_cookie if h.startswith("c360_csrf="))
    assert "HttpOnly" in access and "SameSite=lax" in access
    assert "HttpOnly" in refresh and "Path=/api/v1/auth/refresh" in refresh and "SameSite=strict" in refresh
    assert "HttpOnly" not in csrf
    me1 = client.get("/api/v1/me").json()
    assert me1["principal"]["username"] == user.username and me1["roles"] == ["USER"]
    login(client, user)
    me2 = client.get("/api/v1/me").json()
    assert me2["session"]["session_id"] != me1["session"]["session_id"]  # regenerated (fixation defence)


# ---- BE-AUTH-02 / 03 -------------------------------------------------------------------------
def test_be_auth_02_uniform_failures(client: TestClient, user: Account, db: Session) -> None:
    wrong = login(client, user, "Wrong-Password-123")
    unknown = client.post(
        "/api/v1/auth/login",
        json={"username": "nobody-here", "password": "Whatever-12345"},
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    for r in (wrong, unknown):
        assert r.status_code == 401
        body = r.json()
        assert (body["code"], body["message"]) == ("AUTH_INVALID_CREDENTIALS", "Sign-in failed")


def test_be_auth_03_account_backoff_then_correct_password_refused(client: TestClient, user: Account) -> None:
    for _ in range(5):
        assert login(client, user, "Wrong-Password-123").status_code == 401
    r = login(client, user)  # correct password, but the account is in backoff
    assert r.status_code == 401 and r.json()["code"] == "AUTH_INVALID_CREDENTIALS"


def test_be_auth_03_ip_throttle(client: TestClient, user: Account) -> None:
    codes = [login(client, user, "Wrong-Password-123").status_code for _ in range(21)]
    assert codes[-1] == 429


# ---- BE-AUTH-05 / 10 -------------------------------------------------------------------------
def test_be_auth_05_refresh_rotates_and_reuse_revokes(
    client: TestClient, other_client: TestClient, user: Account
) -> None:
    login(client, user)
    old_refresh = client.cookies.get("c360_rt", path="/api/v1/auth/refresh")
    r = _refresh(client)
    assert r.status_code == 200
    new_refresh = client.cookies.get("c360_rt", path="/api/v1/auth/refresh")
    assert new_refresh and new_refresh != old_refresh
    assert client.get("/api/v1/me").status_code == 200
    # Rotate once more, then replay the first token: two generations old => reuse.
    assert _refresh(client).status_code == 200
    other_client.cookies.set("c360_rt", old_refresh, path="/api/v1/auth/refresh")
    other_client.cookies.set("c360_csrf", client.cookies.get("c360_csrf"))
    replay = _refresh(other_client)
    assert replay.status_code == 401 and replay.json()["code"] == "AUTH_REFRESH_INVALID"
    assert client.get("/api/v1/me").json()["code"] == "AUTH_SESSION_INVALID"  # session revoked


def _replay_client(base: TestClient, other: TestClient, token: str) -> TestClient:
    other.cookies.set("c360_rt", token, path="/api/v1/auth/refresh")
    other.cookies.set("c360_csrf", base.cookies.get("c360_csrf"))
    return other


def test_be_auth_10a_benign_duplicate_gets_409_without_tokens(
    client: TestClient, other_client: TestClient, user: Account
) -> None:
    login(client, user)
    previous = client.cookies.get("c360_rt", path="/api/v1/auth/refresh")
    assert _refresh(client).status_code == 200
    dup = _refresh(_replay_client(client, other_client, previous))
    assert dup.status_code == 409 and dup.json()["code"] == "REFRESH_SUPERSEDED"
    assert "set-cookie" not in dup.headers
    assert client.get("/api/v1/me").status_code == 200  # session still usable
    assert _refresh(client).status_code == 200  # and can keep rotating


def test_be_auth_10b_duplicate_after_grace_is_reuse(
    client: TestClient, other_client: TestClient, user: Account, db: Session
) -> None:
    login(client, user)
    previous = client.cookies.get("c360_rt", path="/api/v1/auth/refresh")
    assert _refresh(client).status_code == 200
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.generation == 2, RefreshToken.used_at.is_(None))
        .values(issued_at=datetime.now(UTC) - timedelta(seconds=11))
    )
    db.commit()
    r = _refresh(_replay_client(client, other_client, previous))
    assert r.status_code == 401
    assert client.get("/api/v1/me").json()["code"] == "AUTH_SESSION_INVALID"


def test_be_auth_10d_duplicate_after_logout_is_rejected(
    client: TestClient, other_client: TestClient, user: Account
) -> None:
    login(client, user)
    previous = client.cookies.get("c360_rt", path="/api/v1/auth/refresh")
    assert _refresh(client).status_code == 200
    csrf_before_logout = client.cookies.get("c360_csrf")
    assert client.post("/api/v1/auth/logout", headers=csrf_header(client)).status_code == 204
    other_client.cookies.set("c360_rt", previous, path="/api/v1/auth/refresh")
    other_client.cookies.set("c360_csrf", csrf_before_logout)
    r = other_client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf_before_logout})
    assert r.status_code == 401 and r.json()["code"] == "AUTH_REFRESH_INVALID"


def test_be_auth_10e_simultaneous_redemptions_rotate_once(app, user: Account, db: Session) -> None:  # type: ignore[no-untyped-def]
    from tests.support import ORIGIN

    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        login(c, user)
        token, csrf = c.cookies.get("c360_rt", path="/api/v1/auth/refresh"), c.cookies.get("c360_csrf")
    results: list[int] = []

    def redeem() -> None:
        with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as t:
            t.cookies.set("c360_rt", token, path="/api/v1/auth/refresh")
            t.cookies.set("c360_csrf", csrf)
            results.append(t.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf}).status_code)

    threads = [threading.Thread(target=redeem) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200, 409]


# ---- BE-AUTH-06 -----------------------------------------------------------------------------
def test_be_auth_06_logout_invalidates_session(client: TestClient, user: Account) -> None:
    login(client, user)
    stolen_access = client.cookies.get("c360_at")
    assert client.post("/api/v1/auth/logout", headers=csrf_header(client)).status_code == 204
    client.cookies.set("c360_at", stolen_access)  # even if a copy of the old cookie survives
    assert client.get("/api/v1/me").json()["code"] == "AUTH_SESSION_INVALID"


def test_be_auth_06_membership_removal_takes_effect_next_request(
    client: TestClient, admin: Account, db: Session
) -> None:
    login(client, admin)
    assert client.get("/api/v1/admin/users").status_code == 200
    db.execute(
        update(GroupMembership)
        .where(GroupMembership.principal_id == admin.principal_id)
        .values(valid_to=datetime.now(UTC))
    )
    db.commit()
    assert client.get("/api/v1/admin/users").status_code == 403


def test_be_auth_06_expired_session_rejected(client: TestClient, user: Account, db: Session) -> None:
    login(client, user)
    db.execute(
        update(AuthSession)
        .where(AuthSession.principal_id == user.principal_id)
        .values(idle_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db.commit()
    assert client.get("/api/v1/me").json()["code"] == "AUTH_SESSION_INVALID"


# ---- BE-AUTH-07 -----------------------------------------------------------------------------
def test_be_auth_07_login_requires_csrf(client: TestClient, user: Account) -> None:
    r = client.post("/api/v1/auth/login", json={"username": user.username, "password": user.password})
    assert r.status_code == 403 and r.json()["code"] == "CSRF_INVALID"


def test_be_auth_07_foreign_origin_rejected(client: TestClient, user: Account) -> None:
    token = csrf_token(client)
    r = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": user.password},
        headers={"X-CSRF-Token": token, "Origin": "https://evil.example"},
    )
    assert r.status_code == 403 and r.json()["code"] == "ORIGIN_REJECTED"


def test_be_auth_07_missing_origin_rejected(app, user: Account) -> None:  # type: ignore[no-untyped-def]
    with TestClient(app, base_url="http://testserver") as c:
        token = c.get("/api/v1/auth/csrf").json()["csrf_token"]
        r = c.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": user.password},
            headers={"X-CSRF-Token": token},
        )
        assert r.json()["code"] == "ORIGIN_REJECTED"


def test_be_auth_07_csrf_from_another_session_rejected(
    client: TestClient, other_client: TestClient, admin: Account, user: Account
) -> None:
    login(client, admin)
    login(other_client, user)
    victim_users = client.get("/api/v1/admin/users").json()["items"]
    target = next(u for u in victim_users if u["username"] == user.username)
    foreign = other_client.cookies.get("c360_csrf")
    client.cookies.set("c360_csrf", foreign)
    r = client.patch(
        f"/api/v1/admin/users/{target['principal_id']}",
        json={"status": "DISABLED", "reason": "x" * 5},
        headers={"X-CSRF-Token": foreign, "If-Match": str(target["row_version"])},
    )
    assert r.status_code == 403 and r.json()["code"] == "CSRF_INVALID"


def test_be_auth_07_refresh_requires_csrf(client: TestClient, user: Account) -> None:
    login(client, user)
    assert client.post("/api/v1/auth/refresh").json()["code"] == "CSRF_INVALID"


# ---- BE-AUTH-08 -----------------------------------------------------------------------------
def test_be_auth_08_no_secrets_in_bodies_or_logs(
    client: TestClient, user: Account, caplog: pytest.LogCaptureFixture, db: Session
) -> None:
    caplog.set_level(logging.DEBUG)
    r = login(client, user)
    secrets_ = [
        client.cookies.get("c360_at"),
        client.cookies.get("c360_rt", path="/api/v1/auth/refresh"),
        user.password,
    ]
    bodies = r.text + client.get("/api/v1/me").text
    for s in secrets_:
        assert s and s not in bodies and s not in caplog.text
    audit_dump = " ".join(str(x) for x in db.execute(text("SELECT a.* FROM audit_event a")).all())
    for s in secrets_:
        assert s not in audit_dump
    stored = db.execute(select(RefreshToken.token_hmac)).scalars().all()
    assert secrets_[1] not in stored  # only the HMAC is stored
