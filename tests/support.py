"""Test-only helpers. The destructive reset is hard-wired to ``call360_test`` and re-checks guards."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.core.settings import BACKEND_ROOT, Settings
from app.db.guards import UnsafeDatabaseTarget, verify_connection
from app.security.identity import create_local_account

TEST_SCHEMA = "call360_test"
ORIGIN = "http://testserver"


def reset_test_schema(engine: Engine, settings: Settings) -> None:
    """Drop every object in call360_test (never any other schema), then migrate to head."""
    if settings.target_schema != TEST_SCHEMA or settings.app_env != "test":
        raise UnsafeDatabaseTarget("reset is only permitted for the test schema")
    with engine.connect() as conn:
        verify_connection(conn, settings)
        assert conn.execute(text("SELECT current_user")).scalar() == settings.expected_db_role
        tables = conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars().all()
        for t in tables:
            conn.exec_driver_sql(f'DROP TABLE IF EXISTS call360_test."{t}" CASCADE')
        funcs = (
            conn.execute(
                text(
                    "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'call360_test'"
                )
            )
            .scalars()
            .all()
        )
        for f in funcs:
            conn.exec_driver_sql(f"DROP FUNCTION IF EXISTS {f} CASCADE")
        # LIB-1 (migration 0028) is the first revision with a sequence that no table owns: drop those as well
        sequences = (
            conn.execute(text("SELECT sequencename FROM pg_sequences WHERE schemaname = 'call360_test'"))
            .scalars()
            .all()
        )
        for q in sequences:
            conn.exec_driver_sql(f'DROP SEQUENCE IF EXISTS call360_test."{q}" CASCADE')
        conn.commit()
    migrate(settings, "head")


def migrate(settings: Settings, target: str, *, down: bool = False) -> None:
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    cfg.attributes["settings"] = settings
    (command.downgrade if down else command.upgrade)(cfg, target)


def unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


PASSWORD = "Correct-Horse-Battery-9"


@dataclass
class Account:
    username: str
    password: str
    principal_id: uuid.UUID


def make_account(db: Session, group: str = "LOCAL_USER_SG", *, prefix: str = "user") -> Account:
    username = unique(prefix)
    p = create_local_account(
        db,
        username=username,
        display_name=f"Test {prefix.title()}",
        password=PASSWORD,
        group_code=group,
        created_by="SYSTEM:test",
        actor=Actor(service="pytest"),
        meta=RequestMeta(),
    )
    db.commit()
    return Account(username, PASSWORD, p.id)


def csrf_token(client: TestClient) -> str:
    return client.get("/api/v1/auth/csrf").json()["csrf_token"]


def login(client: TestClient, account: Account, password: str | None = None) -> Any:
    token = csrf_token(client)
    return client.post(
        "/api/v1/auth/login",
        json={"username": account.username, "password": password or account.password},
        headers={"X-CSRF-Token": token},
    )


def csrf_header(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("c360_csrf") or ""}


#: APPL-X4a (0040): scenarios, suites and recorded runs. A downgrade below 0040 removes them (only while empty).
SCENARIO_TABLES = (
    "applicability_scenario", "applicability_scenario_dependency", "applicability_suite", "applicability_suite_member",
    "applicability_scenario_event", "applicability_evaluation_run", "applicability_evaluation_result",
)  # fmt: skip
#: APPL-X2 (0038) and APPL-X3 (0039): the applicability tables. A downgrade below 0038 removes them all.
APPLICABILITY_TABLES = frozenset(
    {
        "applicability_asset", "applicability_asset_version", "applicability_asset_dependency", "applicability_event",
        # APPL-X3 (migration 0039): saved applicability policies
        "applicability_policy", "applicability_policy_dependency", "applicability_policy_event",
        # APPL-X4a (migration 0040): scenarios, suites and recorded runs
        *SCENARIO_TABLES,
    }
)  # fmt: skip
