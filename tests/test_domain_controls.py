"""CP0.2 targeted corrections — D-34 key enforcement wherever the domain exists, and the idempotent bootstrap
audit of governed reference data (migration 0007, S0_DATA_MODEL §4.6)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.governed import (
    ACTIVATED,
    AUDIT_ACTOR,
    REASON,
    REFERENCE_DATA_VERSION,
    VALUES,
    _snapshot,
    audit_governed,
    seed_governed,
    version_id,
)
from app.domain.protection import DataProtection, DataProtectionUnavailable, generate_key, protection_for
from app.main import create_app
from tests.domain_support import SCHEMA
from tests.support import ORIGIN, migrate


def _keyless(settings: Settings) -> Settings:
    return settings.model_copy(update={"pii_encryption_key": None, "pii_hmac_key": None})


# ---- D-34: keys are mandatory wherever the CP0.2 domain exists ------------------------------------------------
def test_d34_startup_refuses_a_cp02_schema_without_keys(settings: Settings) -> None:
    app = create_app(_keyless(settings))
    with pytest.raises(DataProtectionUnavailable), TestClient(app, base_url=ORIGIN):
        pass


def test_d34_readiness_fails_when_keys_are_missing(settings: Settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/health/ready").json() == {"status": "ok"}
        app.state.settings = _keyless(settings)
        r = client.get("/health/ready")
        assert r.status_code == 503 and r.json() == {"status": "not_ready"}


def test_d34_seed_and_domain_operations_refuse_without_keys(engine: Engine, settings: Settings) -> None:
    with pytest.raises(DataProtectionUnavailable):
        DataProtection.from_settings(_keyless(settings))
    with engine.connect() as c, pytest.raises(DataProtectionUnavailable):
        protection_for(c, _keyless(settings))
    with engine.connect() as c:
        assert protection_for(c, settings) is not None


def test_d34_pre_cp02_schema_runs_without_keys(fresh_schema: None, engine: Engine, settings: Settings) -> None:
    migrate(settings, "0002_config_foundation", down=True)
    try:
        with engine.connect() as c:
            assert protection_for(c, _keyless(settings)) is None
        app = create_app(_keyless(settings))
        with TestClient(app, base_url=ORIGIN) as client:
            assert client.get("/health/live").json() == {"status": "ok"}
            assert app.state.data_protection is None
    finally:
        migrate(settings, "head")


@pytest.mark.parametrize(
    "keys, message",
    [
        ({"PII_ENCRYPTION_KEY": "K"}, "configured together"),
        ({"PII_ENCRYPTION_KEY": "SAME", "PII_HMAC_KEY": "SAME"}, "must differ"),
        ({"PII_ENCRYPTION_KEY": "c2hvcnQ", "PII_HMAC_KEY": "OTHER"}, "32 bytes"),
    ],
)
def test_d34_settings_validate_keys_whenever_present(
    monkeypatch: pytest.MonkeyPatch, keys: dict[str, str], message: str
) -> None:
    same, other = generate_key(), generate_key()
    base = {
        "APP_ENV": "local",
        "APP_DB_SCHEMA": "call360",
        "EXPECTED_DB_ROLE": "Call360_db_user",
        "REFRESH_TOKEN_PEPPER": "x" * 32,
        "CSRF_SECRET": "y" * 32,
        "APP_DATABASE_URL": "postgresql+psycopg://a:b@h/Call360_db",
    }
    resolved = {k: {"K": same, "SAME": same, "OTHER": other}.get(v, v) for k, v in keys.items()}
    for k, v in {**base, **resolved}.items():
        monkeypatch.setenv(k, v)
    for k in ("PII_ENCRYPTION_KEY", "PII_HMAC_KEY"):
        if k not in resolved:
            monkeypatch.delenv(k, raising=False)
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_d34_local_settings_without_keys_still_load(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {
        "APP_ENV": "local",
        "APP_DB_SCHEMA": "call360",
        "EXPECTED_DB_ROLE": "Call360_db_user",
        "REFRESH_TOKEN_PEPPER": "x" * 32,
        "CSRF_SECRET": "y" * 32,
        "APP_DATABASE_URL": "postgresql+psycopg://a:b@h/Call360_db",
    }.items():
        monkeypatch.setenv(k, v)
    for k in ("PII_ENCRYPTION_KEY", "PII_HMAC_KEY"):
        monkeypatch.delenv(k, raising=False)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.pii_encryption_key is None and isinstance(s.refresh_token_pepper, SecretStr)


# ---- governed reference data: bootstrap audit ------------------------------------------------------------------
def _activation_events(engine: Engine) -> list[dict[str, object]]:
    with engine.connect() as c:
        return [
            dict(r._mapping)
            for r in c.execute(
                text(
                    f"SELECT entity_id, entity_version, actor_snapshot, reason, before, after, outcome FROM "
                    f"{SCHEMA}.audit_event WHERE action = :a ORDER BY seq"
                ),
                {"a": ACTIVATED},
            )
            if r.entity_id in VALUES
        ]


def test_governed_activation_is_audited_once_per_list(fresh_schema: None, engine: Engine) -> None:
    events = _activation_events(engine)
    assert sorted(e["entity_id"] for e in events) == sorted(VALUES)  # type: ignore[type-var]
    for e in events:
        list_code = str(e["entity_id"])
        assert e["entity_version"] == 1 and e["outcome"] == "SUCCEEDED" and e["reason"] == REASON
        assert e["actor_snapshot"] == {"provider": None, "display_name": None, "username": None, "service": AUDIT_ACTOR}
        assert e["before"] is None
        after = e["after"]
        assert isinstance(after, dict)
        assert after["version_id"] == str(version_id(list_code))
        assert after["reference_data_version"] == REFERENCE_DATA_VERSION
        assert after["values"] == _snapshot(list_code)


def test_governed_bootstrap_audit_is_idempotent(engine: Engine) -> None:
    before = len(_activation_events(engine))
    with engine.begin() as c:
        assert audit_governed(c, SCHEMA) == 0
        seed_governed(c, SCHEMA)  # repeated reference-data seeding writes neither values nor audit events
    assert len(_activation_events(engine)) == before
    with Session(engine) as db:
        assert verify_chain(db).ok
