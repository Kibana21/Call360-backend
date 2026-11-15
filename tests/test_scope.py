"""F0 — CP0.1B-2 market scope reduced by D-39 (Singapore-only): BE-IAM-02 (scope half), BE-SEC-02 (mechanism)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, select, text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.core.errors import AppError
from app.security.models import AuditEvent
from app.security.scope import ENABLED_MARKETS, NOT_FOUND_MESSAGE, mapping_id, resolve_markets, scoped_case
from tests.domain_support import SCHEMA, rejected
from tests.support import Account, csrf_token, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")


def test_seeded_mappings_are_singapore_only(conn: Connection) -> None:
    rows = conn.execute(
        text(
            f"SELECT g.code, m.market_code FROM {SCHEMA}.group_scope_mapping m "
            f"JOIN {SCHEMA}.app_group g ON g.id = m.group_id ORDER BY g.code"
        )
    ).all()
    assert [tuple(r) for r in rows] == [("LOCAL_ADMIN", "SG"), ("LOCAL_USER_SG", "SG")]
    assert ENABLED_MARKETS == {"SG"}
    events = conn.execute(
        text(
            f"SELECT entity_id, after FROM {SCHEMA}.audit_event WHERE action = 'ADMIN.GROUP_MAPPING_CHANGED' "
            "AND entity_type = 'group_scope_mapping' AND after IS NOT NULL AND after <> 'null'::jsonb"
        )
    ).all()
    assert {e.entity_id for e in events} >= {
        str(mapping_id("LOCAL_ADMIN", "SG")),
        str(mapping_id("LOCAL_USER_SG", "SG")),
    }
    sql = (
        f"INSERT INTO {SCHEMA}.group_scope_mapping (id, group_id, market_code, effective_from, created_by, "
        "change_reason) "
        f"SELECT gen_random_uuid(), id, 'XX', now(), 't', 'r' FROM {SCHEMA}.app_group WHERE code = 'LOCAL_ADMIN'"
    )
    assert rejected(conn, sql) == "23514"  # unknown market code


@pytest.mark.parametrize("group, expected", [("LOCAL_ADMIN", ["SG"]), ("LOCAL_USER_SG", ["SG"]), ("LOCAL_USER_MY", [])])
def test_effective_markets_in_me_and_login(client: TestClient, db: Session, group: str, expected: list[str]) -> None:
    account = make_account(db, group, prefix="scope")
    r = login(client, account)
    assert r.status_code == 200 and r.json()["markets"] == expected
    assert client.get("/api/v1/me").json()["markets"] == expected


def test_enabled_markets_cap_any_mapping(db: Session, admin: Account) -> None:
    """Even if a group were mapped to MY, MY is not enabled in Stage 0 (D-39)."""
    db.execute(
        text(
            "INSERT INTO group_scope_mapping (id, group_id, market_code, effective_from, created_by, change_reason) "
            "SELECT gen_random_uuid(), id, 'MY', now() - interval '1 day', 't', 'pytest' FROM app_group "
            "WHERE code = 'LOCAL_ADMIN'"
        )
    )
    assert resolve_markets(db, admin.principal_id, datetime.now(UTC)) == {"SG"}
    db.rollback()


def _case_id(db: Session, ref: str) -> uuid.UUID:
    return db.execute(text("SELECT id FROM callback_case WHERE case_ref = :r"), {"r": ref}).scalar_one()


def test_be_sec_02_my_and_missing_cases_get_the_same_audited_404(db: Session) -> None:
    actor, meta = Actor(service="pytest"), RequestMeta()
    sg = scoped_case(db, _case_id(db, "CB-2026-10482"), frozenset({"SG"}), actor=actor, meta=meta)
    assert sg["case_ref"] == "CB-2026-10482"
    errors = []
    for target, markets in (
        (_case_id(db, "CB-2026-20001"), frozenset({"SG"})),  # MY record, SG user (ADMIN included)
        (uuid.uuid4(), frozenset({"SG"})),  # does not exist
        (_case_id(db, "CB-2026-10482"), frozenset()),  # no market scope at all
    ):
        with pytest.raises(AppError) as exc:
            scoped_case(db, target, markets, actor=actor, meta=meta)
        errors.append((exc.value.status_code, exc.value.code, str(exc.value)))
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "ACCESS.DENIED_OBJECT", AuditEvent.entity_id == str(target))
        ).scalar_one()
        assert audit.outcome == "DENIED"
    assert errors == [(404, "NOT_FOUND", NOT_FOUND_MESSAGE)] * 3  # indistinguishable: existence never revealed


def test_unauthenticated_and_csrf_context_unchanged(client: TestClient) -> None:
    assert client.get("/api/v1/me").status_code == 401
    assert csrf_token(client)
