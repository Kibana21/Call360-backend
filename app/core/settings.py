"""Application settings with fail-closed environment and schema validation.

Configuration comes from the env file named by ``CALL360_ENV_FILE`` (default ``.env``).
Development uses APP_* connection settings; automated tests use TEST_* settings from
``.env.test``. See Call360-specs S0_IDENTITY_ACCESS_DESIGN §10 (D-22).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ALLOWED_SCHEMAS = frozenset({"call360", "call360_test"})
BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    app_env: Literal["local", "test"]
    data_policy: Literal["SYNTHETIC_ONLY"] = "SYNTHETIC_ONLY"

    app_database_url: SecretStr | None = None
    app_db_schema: str | None = None
    test_database_url: SecretStr | None = None
    test_db_schema: str | None = None
    expected_database: str = "Call360_db"
    expected_db_role: str
    app_db_role: str = "Call360_db_user"

    jwt_private_key_path: Path = Path(".secrets/jwt_ed25519_private.pem")
    jwt_public_key_path: Path = Path(".secrets/jwt_ed25519_public.pem")
    jwt_issuer: str = "call360-local-api"
    jwt_audience: str = "call360-api"
    refresh_token_pepper: SecretStr
    csrf_secret: SecretStr

    access_token_ttl_seconds: int = 600
    refresh_idle_seconds: int = 1800
    refresh_absolute_seconds: int = 28800
    refresh_reuse_grace_seconds: int = 10

    login_max_failures: int = 5
    login_failure_window_seconds: int = 900
    login_backoff_cap_seconds: int = 1800
    login_ip_per_minute: int = 20
    refresh_per_minute: int = 30
    writes_per_minute: int = 30

    allowed_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    cookie_secure: bool = False

    @model_validator(mode="after")
    def _fail_closed(self) -> Settings:
        url, schema = self.database_url_secret, self.db_schema
        if url is None or schema is None:
            raise ValueError(f"database URL and schema must be configured for APP_ENV={self.app_env}")
        if schema not in ALLOWED_SCHEMAS:
            raise ValueError(f"schema {schema!r} is not allowed")
        if self.app_env == "test" and schema != "call360_test":
            raise ValueError("APP_ENV=test requires schema call360_test")
        if self.app_env != "test" and schema == "call360_test":
            raise ValueError("schema call360_test is reserved for APP_ENV=test")
        if (
            self.app_database_url is not None
            and self.test_database_url is not None
            and self.app_database_url.get_secret_value() == self.test_database_url.get_secret_value()
        ):
            raise ValueError("application and test database URLs must differ")
        if self.app_env == "test" and self.expected_db_role == self.app_db_role:
            raise ValueError("tests must not use the application database role")
        return self

    @property
    def database_url_secret(self) -> SecretStr | None:
        return self.test_database_url if self.app_env == "test" else self.app_database_url

    @property
    def database_url(self) -> str:
        secret = self.database_url_secret
        assert secret is not None
        return secret.get_secret_value()

    @property
    def db_schema(self) -> str | None:
        return self.test_db_schema if self.app_env == "test" else self.app_db_schema

    @property
    def target_schema(self) -> str:
        assert self.db_schema is not None
        return self.db_schema

    def resolve(self, path: Path) -> Path:
        return path if path.is_absolute() else BACKEND_ROOT / path


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    file = Path(env_file or os.environ.get("CALL360_ENV_FILE", ".env"))
    if not file.is_absolute():
        file = BACKEND_ROOT / file
    return Settings(_env_file=file if file.exists() else None)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
