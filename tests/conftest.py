"""Pytest fixtures. Tests run ONLY against schema call360_test as the least-privilege test role
(.env.test). The session aborts before touching the database if any guard fails (BE-DATA-14)."""

from __future__ import annotations

import os

os.environ["CALL360_ENV_FILE"] = ".env.test"

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Connection, Engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.settings import Settings, load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from app.main import create_app  # noqa: E402
from tests.support import ORIGIN, Account, make_account, reset_test_schema  # noqa: E402


@pytest.fixture(scope="session")
def settings() -> Settings:
    s = load_settings(".env.test")
    if s.app_env != "test" or s.target_schema != "call360_test":
        pytest.exit("Refusing to run tests: .env.test is not a test configuration", returncode=3)
    return s


@pytest.fixture(scope="session")
def engine(settings: Settings) -> Iterator[Engine]:
    e = make_engine(settings)
    reset_test_schema(e, settings)  # guarded; touches call360_test only
    yield e
    e.dispose()


@pytest.fixture()
def db(engine: Engine) -> Iterator[Session]:
    with make_session_factory(engine)() as session:
        yield session


@pytest.fixture()
def app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return create_app(settings)


@pytest.fixture()
def client(app) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        yield c


@pytest.fixture()
def other_client(app) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        yield c


@pytest.fixture()
def user(db: Session) -> Account:
    return make_account(db, "LOCAL_USER_SG", prefix="user")


@pytest.fixture()
def admin(db: Session) -> Account:
    return make_account(db, "LOCAL_ADMIN", prefix="admin")


@pytest.fixture()
def fresh_schema(engine: Engine, settings: Settings) -> None:
    """Guarded reset of call360_test to an unseeded head (for migration round-trip tests)."""
    reset_test_schema(engine, settings)


@pytest.fixture()
def conn(engine: Engine) -> Iterator[Connection]:
    """A connection whose work is always rolled back (CP0.2 integrity tests)."""
    with engine.connect() as c:
        tx = c.begin()
        try:
            yield c
        finally:
            tx.rollback()


@pytest.fixture()
def seeded(engine: Engine, settings: Settings) -> Iterator[None]:
    """Ensure S0-SEED-1 is present in call360_test (re-seeds after any test that reset the schema)."""
    from app.domain.protection import DataProtection
    from app.domain.seed import seed

    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))
    yield
