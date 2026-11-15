"""BE-DATA-01, BE-DATA-10, BE-DATA-14 — schema build scope, data policy and schema isolation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

from app.core.settings import Settings
from app.db.guards import UnsafeDatabaseTarget, verify_connection
from tests.support import migrate, reset_test_schema

CP01A_TABLES = {
    "identity_provider",
    "principal",
    "identity_binding",
    "local_credential",
    "app_group",
    "group_membership",
    "role",
    "permission",
    "role_permission",
    "group_role_mapping",
    "auth_session",
    "refresh_token_family",
    "refresh_token",
    "login_attempt",
    "audit_event",
}


def _tables(engine: Engine) -> set[str]:
    with engine.connect() as c:
        return set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='call360_test'")).scalars())


def test_be_data_01_head_creates_exactly_cp01a_tables(engine: Engine) -> None:
    assert _tables(engine) == CP01A_TABLES | {"alembic_version"}


def test_be_data_01_downgrade_and_reupgrade(engine: Engine, settings: Settings) -> None:
    migrate(settings, "base", down=True)
    assert _tables(engine) == {"alembic_version"}
    migrate(settings, "head")
    assert _tables(engine) == CP01A_TABLES | {"alembic_version"}


def test_be_data_14_test_role_has_no_rights_on_development_schema(engine: Engine) -> None:
    with engine.connect() as c:
        row = c.execute(
            text(
                "SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole, "
                "has_schema_privilege(current_user,'call360','USAGE'),"
                " has_schema_privilege(current_user,'call360','CREATE'), current_user FROM pg_roles r "
                "WHERE r.rolname = current_user"
            )
        ).one()
        assert tuple(row)[:5] == (False, False, False, False, False)
        assert row[5] == "call360_test_user"
        for stmt in (
            "SELECT count(*) FROM call360.principal",
            "TRUNCATE call360.audit_event",
            "DROP SCHEMA call360 CASCADE",
            "ALTER TABLE call360.principal ADD COLUMN x int",
        ):
            with pytest.raises(ProgrammingError):
                c.execute(text(stmt))
            c.rollback()


def test_be_data_14_guard_rejects_wrong_role(engine: Engine, settings: Settings) -> None:
    wrong = settings.model_copy(update={"expected_db_role": "Call360_db_user_x"})
    with engine.connect() as c, pytest.raises(UnsafeDatabaseTarget):
        verify_connection(c, wrong)


def test_be_data_14_guard_rejects_wrong_database(engine: Engine, settings: Settings) -> None:
    wrong = settings.model_copy(update={"expected_database": "postgres"})
    with engine.connect() as c, pytest.raises(UnsafeDatabaseTarget):
        verify_connection(c, wrong)


def test_be_data_14_reset_refuses_non_test_schema(engine: Engine, settings: Settings) -> None:
    dev_like = settings.model_copy(update={"app_env": "local", "app_db_schema": "call360"})
    with pytest.raises(UnsafeDatabaseTarget):
        reset_test_schema(engine, dev_like)


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"APP_ENV": "test", "TEST_DB_SCHEMA": "call360"}, "requires schema call360_test"),
        ({"APP_ENV": "local", "APP_DB_SCHEMA": "call360_test"}, "reserved for APP_ENV=test"),
        ({"APP_ENV": "local", "APP_DB_SCHEMA": "public"}, "not allowed"),
        (
            {"APP_ENV": "test", "TEST_DB_SCHEMA": "call360_test", "EXPECTED_DB_ROLE": "Call360_db_user"},
            "must not use the application database role",
        ),
        (
            {
                "APP_ENV": "test",
                "TEST_DB_SCHEMA": "call360_test",
                "APP_DATABASE_URL": "postgresql+psycopg://u:p@h/Call360_db",
            },
            "must differ",
        ),
    ],
)
def test_be_data_14_settings_fail_closed(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str], message: str
) -> None:
    base = {
        "EXPECTED_DB_ROLE": "call360_test_user",
        "REFRESH_TOKEN_PEPPER": "x" * 32,
        "CSRF_SECRET": "y" * 32,
        "APP_DATABASE_URL": "postgresql+psycopg://a:b@h/Call360_db",
        "TEST_DATABASE_URL": "postgresql+psycopg://u:p@h/Call360_db",
        "APP_DB_SCHEMA": "call360",
    }
    for k, v in {**base, **overrides}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_be_data_10_data_policy_is_synthetic_only(settings: Settings) -> None:
    assert settings.data_policy == "SYNTHETIC_ONLY"


def test_be_data_10_readiness_ok(client) -> None:  # type: ignore[no-untyped-def]
    assert client.get("/health/ready").json() == {"status": "ok"}
    assert client.get("/health/live").json() == {"status": "ok"}
