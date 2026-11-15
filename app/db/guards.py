"""Fail-closed connection guards (S0_IDENTITY_ACCESS_DESIGN §10, BE-DATA-14).

Called before migrations, at application startup and before any destructive test reset.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

from app.core.settings import Settings


class UnsafeDatabaseTarget(RuntimeError):
    """Raised when the connection is not exactly the configured database, role and schema."""


def verify_connection(conn: Connection, settings: Settings, *, require_schema: bool = True) -> None:
    row = conn.execute(
        text(
            "SELECT current_database() AS db, current_user AS role, "
            "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser, "
            "to_regnamespace(:schema) IS NOT NULL AS schema_exists, "
            "to_regnamespace('call360') IS NOT NULL AS app_schema_exists"
        ),
        {"schema": settings.target_schema},
    ).one()
    if row.db != settings.expected_database:
        raise UnsafeDatabaseTarget(f"connected to database {row.db!r}, expected {settings.expected_database!r}")
    if row.role != settings.expected_db_role:
        raise UnsafeDatabaseTarget(f"connected as role {row.role!r}, expected {settings.expected_db_role!r}")
    if require_schema and not row.schema_exists:
        raise UnsafeDatabaseTarget(f"schema {settings.target_schema!r} does not exist (run make db-setup)")
    if settings.app_env == "test":
        if settings.target_schema != "call360_test":
            raise UnsafeDatabaseTarget("test environment must target call360_test")
        if row.role == settings.app_db_role or row.superuser:
            raise UnsafeDatabaseTarget("tests must use the least-privilege test role, not the app role or a superuser")
        if row.app_schema_exists:
            has_usage = conn.execute(text("SELECT has_schema_privilege(current_user, 'call360', 'USAGE')")).scalar()
            if has_usage:
                raise UnsafeDatabaseTarget("test role must have no privileges on schema call360")
