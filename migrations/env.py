"""Alembic environment. Verifies the connected database, role and schema before any migration
(S0_IDENTITY_ACCESS_DESIGN §10, D-22/D-24) and keeps the version table inside the target schema."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from app.core.settings import load_settings
from app.db.guards import verify_connection

config = context.config
settings = config.attributes.get("settings") or load_settings()
schema = settings.target_schema


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_engine(settings.database_url, connect_args={"options": f"-c search_path={schema}"})
    with engine.connect() as conn:
        _run(conn)
    engine.dispose()


def _run(conn: object) -> None:
    verify_connection(conn, settings)  # type: ignore[arg-type]
    conn.commit()  # end the guard's implicit transaction so Alembic owns the migration transaction
    context.configure(
        connection=conn, version_table_schema=schema, target_metadata=None, transaction_per_migration=True
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("Offline migrations are not supported; connect to the verified target.")
run_migrations_online()
