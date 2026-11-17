"""BE-SEC-01, 03, 05, 06; BE-IAM-01…03; BE-AUD-03, 04; BE-AUTH-09 — authorization, admin, headers, CLI."""

from __future__ import annotations

import uuid

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.api.deps import AUTHENTICATED_ROUTES, PUBLIC_ROUTES
from app.cli import main as cli_main
from app.core.middleware import UNSAFE_METHODS
from app.core.settings import Settings
from app.security.authz import resolve_grants
from app.security.models import AppGroup, AuditEvent, GroupMembership, IdentityBinding, Permission, Role
from tests.support import Account, csrf_header, login, make_account, reset_test_schema


# ---- BE-SEC-01 route inventory ----------------------------------------------------------------
def _api_routes() -> list[APIRoute]:
    from app.main import ROUTERS

    routes = [r for router in ROUTERS for r in router.routes if isinstance(r, APIRoute)]
    assert routes, "route inventory must not be empty"
    return routes


def test_be_sec_01_every_route_declares_access(app) -> None:  # type: ignore[no-untyped-def]
    problems = []
    for route in _api_routes():
        for method in route.methods:
            key = (method, route.path)
            perms = [getattr(d.call, "required_permission", None) for d in route.dependant.dependencies]
            if key not in PUBLIC_ROUTES and key not in AUTHENTICATED_ROUTES and not any(perms):
                problems.append(f"{key} has no permission")
            if method in UNSAFE_METHODS and not getattr(route.endpoint, "csrf_protected", False):
                problems.append(f"{key} is unsafe without CSRF verification")
    assert not problems, problems


def test_be_sec_01_exact_api_surface(app) -> None:  # type: ignore[no-untyped-def]
    surface = {(m, r.path) for r in _api_routes() for m in r.methods}
    documented = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert surface == documented  # inventory covers every served operation
    assert surface == {
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/api/v1/auth/csrf"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/refresh"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/me"),
        ("GET", "/api/v1/admin/users"),
        ("PATCH", "/api/v1/admin/users/{principal_id}"),
        ("GET", "/api/v1/admin/audit-events"),
        # CP0.1B-1 (API-022…025)
        ("GET", "/api/v1/admin/code-lists"),
        ("POST", "/api/v1/admin/code-lists/{code}/versions"),
        ("GET", "/api/v1/admin/feature-flags"),
        ("PATCH", "/api/v1/admin/feature-flags/{code}"),
        # F1 Overview (API-030…034)
        ("GET", "/api/v1/dashboard/kpis"),
        ("GET", "/api/v1/dashboard/trend"),
        ("GET", "/api/v1/dashboard/attention"),
        ("GET", "/api/v1/dashboard/activity"),
        ("GET", "/api/v1/dashboard/risk-distribution"),
        # F2 Work Queues and search (API-035, 036, 070, 071, 076)
        ("GET", "/api/v1/cases"),
        ("GET", "/api/v1/cases/facets"),
        ("GET", "/api/v1/work-queues"),
        ("GET", "/api/v1/search"),
        ("GET", "/api/v1/search/suggest"),
        # F3 Call Detail (API-037…047, API-063)
        ("GET", "/api/v1/cases/{case_id}"),
        ("GET", "/api/v1/cases/{case_id}/attempts"),
        ("GET", "/api/v1/cases/{case_id}/script-assignment"),
        ("GET", "/api/v1/cases/{case_id}/timeline"),
        ("GET", "/api/v1/cases/{case_id}/findings"),
        ("GET", "/api/v1/cases/{case_id}/holds"),
        ("GET", "/api/v1/attempts/{attempt_id}"),
        ("GET", "/api/v1/sessions/{session_id}"),
        ("GET", "/api/v1/sessions/{session_id}/transcript"),
        ("GET", "/api/v1/sessions/{session_id}/media"),
        ("GET", "/api/v1/survey-runs/{survey_run_id}"),
        ("GET", "/api/v1/script-versions/{script_version_id}"),
        # F4 Policy Explorer and Policy Detail (API-050…055)
        ("GET", "/api/v1/policies"),
        ("GET", "/api/v1/policies/{policy_id}"),
        ("GET", "/api/v1/policies/{policy_id}/parties"),
        ("GET", "/api/v1/policies/{policy_id}/sales"),
        ("GET", "/api/v1/sales/{sale_event_id}"),
        ("GET", "/api/v1/policies/{policy_id}/history"),
        # F5 SBQ Risk Workbench (API-056…058)
        ("GET", "/api/v1/risk-assessments"),
        ("GET", "/api/v1/risk-assessments/{assessment_id}"),
        ("GET", "/api/v1/risk-factors"),
        # F6 Script Studio and Assignment Rules (API-060…062, API-064…066)
        ("GET", "/api/v1/scripts"),
        ("GET", "/api/v1/scripts/{script_family_id}"),
        ("GET", "/api/v1/scripts/{script_family_id}/versions"),
        ("GET", "/api/v1/script-assignment-rules"),
        ("GET", "/api/v1/regulatory-references"),
        ("GET", "/api/v1/controls"),
        # CP0.1B-3 Administration completion (API-007, 009, 011, 013, 014…020, 026)
        ("GET", "/api/v1/auth/session"),
        ("POST", "/api/v1/me/password"),
        ("POST", "/api/v1/admin/users"),
        ("POST", "/api/v1/admin/users/{principal_id}/password-reset"),
        ("GET", "/api/v1/admin/groups"),
        ("PUT", "/api/v1/admin/groups/{group_id}/members/{principal_id}"),
        ("DELETE", "/api/v1/admin/groups/{group_id}/members/{principal_id}"),
        ("GET", "/api/v1/admin/roles"),
        ("PUT", "/api/v1/admin/groups/{group_id}/mappings"),
        ("GET", "/api/v1/admin/sessions"),
        ("POST", "/api/v1/admin/sessions/{session_id}/revoke"),
        ("GET", "/api/v1/admin/system-health"),
        # F7 Review Workbench and Voice Studio (API-077, API-078)
        ("GET", "/api/v1/review-queue"),
        ("GET", "/api/v1/voice/preflight"),
        ("POST", "/api/v1/voice/sessions"),  # S1-A
        ("GET", "/api/v1/voice/sessions"),  # S1-B
        ("GET", "/api/v1/voice/sessions/{session_id}"),
        ("POST", "/api/v1/voice/sessions/{session_id}/resume"),
        ("POST", "/api/v1/voice/sessions/{session_id}/stop"),
        ("POST", "/api/v1/voice/sessions/{session_id}/recording/chunks"),  # S1-C
        ("POST", "/api/v1/voice/sessions/{session_id}/recording/close"),
        ("GET", "/api/v1/sessions/{session_id}/media/{track}/audio"),
        ("GET", "/api/v1/sessions/{session_id}/media/timeline"),  # S1-D
        ("GET", "/api/v1/sessions/{session_id}/transcript/segments"),
        ("POST", "/api/v1/sessions/{session_id}/transcript/retry"),
        # CP0.4a manual intake (API-080, API-082…085)
        ("GET", "/api/v1/intake/sources"),
        ("GET", "/api/v1/intake/reference"),  # API-087 (CP0.4b)
        ("POST", "/api/v1/intake/manual/preview"),
        ("POST", "/api/v1/intake/manual"),
        ("GET", "/api/v1/intake/import-runs"),
        ("GET", "/api/v1/intake/import-runs/{run_id}"),
    }


# ---- ADMIN vs USER ---------------------------------------------------------------------------
def test_user_denied_admin_and_audited(client: TestClient, user: Account, db: Session) -> None:
    login(client, user)
    for path in ("/api/v1/admin/users", "/api/v1/admin/audit-events"):
        r = client.get(path)
        assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
    denied = (
        db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "ACCESS.DENIED_FUNCTION", AuditEvent.actor_principal_id == user.principal_id
            )
        )
        .scalars()
        .all()
    )
    assert len(denied) == 2


def test_admin_lists_users_and_audit(client: TestClient, admin: Account, user: Account) -> None:
    login(client, admin)
    users = client.get("/api/v1/admin/users?limit=200").json()["items"]
    assert {admin.username, user.username} <= {u["username"] for u in users}
    events = client.get("/api/v1/admin/audit-events?action=AUTH.LOGIN").json()["items"]
    assert events and all(e["action"].startswith("AUTH.LOGIN") for e in events)


def test_admin_users_cursor_pagination(client: TestClient, admin: Account, db: Session) -> None:
    for _ in range(3):
        make_account(db)
    login(client, admin)
    seen: list[str] = []
    cursor = None
    while True:
        url = "/api/v1/admin/users?limit=2" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(url).json()
        seen += [u["principal_id"] for u in page["items"]]
        cursor = page["page"]["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) >= 4


# ---- BE-AUD-04 disable/enable with before/after; revocation --------------------------------
def test_be_aud_04_disable_user_revokes_and_audits(
    client: TestClient, other_client: TestClient, admin: Account, user: Account, db: Session
) -> None:
    login(client, admin)
    login(other_client, user)
    assert other_client.get("/api/v1/me").status_code == 200
    target = next(
        u for u in client.get("/api/v1/admin/users?limit=200").json()["items"] if u["username"] == user.username
    )
    r = client.patch(
        f"/api/v1/admin/users/{target['principal_id']}",
        json={"status": "DISABLED", "reason": "Left the team"},
        headers={**csrf_header(client), "If-Match": str(target["row_version"])},
    )
    assert r.status_code == 200 and r.json()["status"] == "DISABLED" and r.json()["active_sessions"] == 0
    assert other_client.get("/api/v1/me").json()["code"] == "AUTH_SESSION_INVALID"
    assert login(other_client, user).status_code == 401  # disabled accounts cannot sign in
    event = db.execute(
        select(AuditEvent).where(
            AuditEvent.action == "ADMIN.USER_DISABLED", AuditEvent.entity_id == target["principal_id"]
        )
    ).scalar_one()
    assert event.before == {"status": "ACTIVE", "display_name": "Test User"}
    assert event.after["status"] == "DISABLED" and event.reason == "Left the team"
    assert event.actor_principal_id == admin.principal_id
    # stale row version is rejected
    stale = client.patch(
        f"/api/v1/admin/users/{target['principal_id']}",
        json={"status": "ACTIVE", "reason": "Back"},
        headers={**csrf_header(client), "If-Match": str(target["row_version"])},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "CONFLICT_ROW_VERSION"
    ok = client.patch(
        f"/api/v1/admin/users/{target['principal_id']}",
        json={"status": "ACTIVE", "reason": "Back"},
        headers={**csrf_header(client), "If-Match": str(r.json()["row_version"])},
    )
    assert ok.status_code == 200 and ok.json()["status"] == "ACTIVE"


def test_admin_cannot_disable_self_or_last_admin(client: TestClient, admin: Account) -> None:
    login(client, admin)
    me = next(u for u in client.get("/api/v1/admin/users?limit=200").json()["items"] if u["username"] == admin.username)
    r = client.patch(
        f"/api/v1/admin/users/{me['principal_id']}",
        json={"status": "DISABLED", "reason": "oops"},
        headers={**csrf_header(client), "If-Match": str(me["row_version"])},
    )
    assert r.status_code == 409 and r.json()["code"] == "LAST_ADMIN_GUARD"


def test_patch_requires_if_match_and_reason(client: TestClient, admin: Account, user: Account) -> None:
    login(client, admin)
    target = next(
        u for u in client.get("/api/v1/admin/users?limit=200").json()["items"] if u["username"] == user.username
    )
    url = f"/api/v1/admin/users/{target['principal_id']}"
    assert (
        client.patch(
            url, json={"status": "DISABLED", "reason": "valid reason"}, headers=csrf_header(client)
        ).status_code
        == 428
    )
    assert (
        client.patch(url, json={"status": "DISABLED"}, headers={**csrf_header(client), "If-Match": "1"}).status_code
        == 422
    )
    missing = client.patch(
        f"/api/v1/admin/users/{uuid.uuid4()}",
        json={"status": "DISABLED", "reason": "x" * 4},
        headers={**csrf_header(client), "If-Match": "1"},
    )
    assert missing.status_code == 404


# ---- BE-SEC-03 strict schemas / mass assignment ------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        {"status": "DISABLED", "reason": "valid reason", "row_version": 99},
        {"status": "DISABLED", "reason": "valid reason", "created_by": "attacker"},
        {"status": "SUPERUSER", "reason": "valid reason"},
        {"display_name": "x" * 500, "reason": "valid reason"},
    ],
)
def test_be_sec_03_unknown_or_invalid_fields_rejected(
    client: TestClient, admin: Account, user: Account, payload: dict[str, object]
) -> None:
    login(client, admin)
    target = next(
        u for u in client.get("/api/v1/admin/users?limit=200").json()["items"] if u["username"] == user.username
    )
    r = client.patch(
        f"/api/v1/admin/users/{target['principal_id']}",
        json=payload,
        headers={**csrf_header(client), "If-Match": str(target["row_version"])},
    )
    assert r.status_code == 422 and r.json()["code"] == "VALIDATION_FAILED"


def test_be_sec_03_login_body_strict(client: TestClient) -> None:
    from tests.support import csrf_token

    r = client.post(
        "/api/v1/auth/login",
        json={"username": "a", "password": "b", "role": "ADMIN"},
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert r.status_code == 422


def test_be_sec_03_injection_in_filters_is_inert(client: TestClient, admin: Account) -> None:
    login(client, admin)
    r = client.get("/api/v1/admin/audit-events", params={"action": "' OR 1=1; DROP TABLE principal; --"})
    assert r.status_code == 200 and r.json()["items"] == []
    assert client.get("/api/v1/admin/users").status_code == 200


# ---- BE-SEC-05 headers / CORS -------------------------------------------------------------------
def test_be_sec_05_security_headers(client: TestClient) -> None:
    r = client.get("/api/v1/me", headers={"Origin": "https://evil.example"})
    for h in (
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-correlation-id",
    ):
        assert h in r.headers
    assert r.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in r.headers
    assert r.json()["correlation_id"] == r.headers["x-correlation-id"]


# ---- BE-SEC-06 rate limits ---------------------------------------------------------------------
def test_be_sec_06_write_rate_limit(client: TestClient, admin: Account, user: Account) -> None:
    login(client, admin)
    target = next(
        u for u in client.get("/api/v1/admin/users?limit=200").json()["items"] if u["username"] == user.username
    )
    codes = [
        client.patch(
            f"/api/v1/admin/users/{target['principal_id']}",
            json={"display_name": "Test User", "reason": "rate test"},
            headers={**csrf_header(client), "If-Match": "0"},
        ).status_code
        for _ in range(31)
    ]
    assert codes[-1] == 429


# ---- BE-IAM-01…03 ------------------------------------------------------------------------------
def test_be_iam_01_principal_separate_from_binding(db: Session, user: Account) -> None:
    binding = db.execute(select(IdentityBinding).where(IdentityBinding.principal_id == user.principal_id)).scalar_one()
    assert binding.subject != str(user.principal_id) and binding.username == user.username
    binding.subject = str(uuid.uuid4())  # provider-side identity change
    db.commit()
    assert db.execute(select(AuditEvent).where(AuditEvent.entity_id == str(user.principal_id))).scalars().first()


def test_be_iam_02_group_role_mapping_and_unmapped_group(db: Session, user: Account, settings: Settings) -> None:
    from datetime import UTC, datetime

    roles, perms = resolve_grants(db, user.principal_id, datetime.now(UTC))
    assert roles == {"USER"} and "admin.users.read" not in perms and "case.read" in perms
    local = db.execute(select(AppGroup.identity_provider_id).where(AppGroup.code == "LOCAL_ADMIN")).scalar_one()
    stray = AppGroup(
        identity_provider_id=local, code=f"UNMAPPED_{uuid.uuid4().hex[:6]}", name="Unmapped", status="ACTIVE"
    )
    db.add(stray)
    db.flush()
    outsider = make_account(db, "LOCAL_USER_MY", prefix="outsider")
    db.execute(text("DELETE FROM group_membership WHERE principal_id = :p"), {"p": outsider.principal_id})
    db.add(GroupMembership(principal_id=outsider.principal_id, group_id=stray.id, provenance="TEST", created_by="t"))
    db.commit()
    assert resolve_grants(db, outsider.principal_id, datetime.now(UTC)) == (frozenset(), frozenset())


def test_be_iam_03_reserved_permissions_never_granted(db: Session) -> None:
    reserved = db.execute(select(Permission).where(Permission.reserved.is_(True))).scalars().all()
    assert {p.code for p in reserved} >= {
        "script.approve",
        "risk.override.approve",
        "evidence.export",
        "pii.unmasked",
    }
    # S1-C (D-46) recording.read and S1-D (D-50) transcript.sensitive.read are activated for USER only; ADMIN keeps
    # the ADR-0004 segregation.
    for code in ("recording.read", "transcript.sensitive.read"):
        assert code not in {p.code for p in reserved}
        holders = db.execute(
            text(
                "SELECT r.code FROM role_permission rp JOIN role r ON r.id = rp.role_id JOIN permission p "
                "ON p.id = rp.permission_id WHERE p.code = :c"
            ),
            {"c": code},
        ).scalars()
        assert sorted(holders) == ["USER"], code
    granted = db.execute(
        text("SELECT count(*) FROM role_permission rp JOIN permission p ON p.id = rp.permission_id WHERE p.reserved")
    ).scalar()
    assert granted == 0
    admin_role = db.execute(select(Role.id).where(Role.code == "ADMIN")).scalar_one()
    with pytest.raises(DBAPIError, match="reserved permission"):
        db.execute(text("INSERT INTO role_permission VALUES (:r, :p)"), {"r": admin_role, "p": reserved[0].id})
    db.rollback()


# ---- BE-AUD-03 security events -------------------------------------------------------------
def test_be_aud_03_security_events_recorded(client: TestClient, user: Account, db: Session) -> None:
    login(client, user, "Wrong-Password-123")
    login(client, user)
    client.post("/api/v1/auth/logout", headers=csrf_header(client))
    actions = set(
        db.execute(select(AuditEvent.action).where(AuditEvent.actor_principal_id == user.principal_id)).scalars()
    )
    assert {"AUTH.LOGIN_FAILED", "AUTH.LOGIN_SUCCEEDED", "AUTH.LOGOUT"} <= actions
    ok = (
        db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "AUTH.LOGIN_SUCCEEDED", AuditEvent.actor_principal_id == user.principal_id
            )
        )
        .scalars()
        .first()
    )
    assert ok is not None and ok.source_ip and ok.correlation_id and ok.session_id


# ---- BE-AUTH-09 bootstrap -------------------------------------------------------------------
def test_be_auth_09_bootstrap_once_and_no_default_credentials(
    engine,
    settings: Settings,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
    db: Session,
) -> None:
    reset_test_schema(engine, settings)  # fresh schema: migrate creates no principals or credentials
    assert db.execute(text("SELECT count(*) FROM principal")).scalar() == 0
    assert db.execute(text("SELECT count(*) FROM local_credential")).scalar() == 0
    db.rollback()
    args = ["--env-file", ".env.test", "bootstrap-admin", "--username", "first.admin", "--display-name", "First Admin"]
    monkeypatch.setenv("CALL360_NEW_PASSWORD", "Bootstrap-Secret-4821")
    assert cli_main(args) == 0
    monkeypatch.setenv("CALL360_NEW_PASSWORD", "Bootstrap-Secret-4822")
    assert cli_main([*args[:3], "--username", "second.admin", "--display-name", "Second"]) == 2
    events = db.execute(select(AuditEvent.action)).scalars().all()
    assert events.count("SECURITY.BOOTSTRAP_ADMIN_CREATED") == 1
    monkeypatch.setenv("CALL360_NEW_PASSWORD", "password1234")
    assert (
        cli_main(
            [
                "--env-file",
                ".env.test",
                "create-local-user",
                "--username",
                "weak.user",
                "--display-name",
                "Weak",
                "--group",
                "LOCAL_USER_SG",
            ]
        )
        == 2
    )  # policy refuses
