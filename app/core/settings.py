"""Application settings with fail-closed environment and schema validation.

Configuration comes from the env file named by ``CALL360_ENV_FILE`` (default ``.env``).
Development uses APP_* connection settings; automated tests use TEST_* settings from
``.env.test``. See Call360-specs S0_IDENTITY_ACCESS_DESIGN §10 (D-22).
"""

from __future__ import annotations

import os
from decimal import Decimal
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
    # Data-protection keys (S-13, D-34): base64url, 32 bytes each, independent. Always required for tests.
    # Elsewhere they are validated when present and enforced by app.domain.protection.protection_for wherever
    # the CP0.2 domain exists (startup, readiness, seed), so a pre-CP0.2 development schema still runs.
    pii_encryption_key: SecretStr | None = None
    pii_hmac_key: SecretStr | None = None
    # S1-C recording (D-47): a separate base64url 32-byte key for audio objects. Without it recording is NOT_AVAILABLE.
    # Audio objects live outside the database and the repositories; retention is a local development setting only
    # (no approved retention policy, BRD DEC-015).
    recording_encryption_key: SecretStr | None = None
    recording_storage_dir: Path = Path.home() / ".call360" / "recordings"
    recording_retention_hours: int = 168
    recording_chunks_per_minute: int = 150
    # S1-D transcription (D-49, D-51, D-52): local, offline faster-whisper small.en. Without a model directory the
    # transcript is UNAVAILABLE (ENGINE_NOT_CONFIGURED). Model files live outside Git and are verified against the
    # pinned SHA-256 values in app.voice.transcript before use. The indicator thresholds are configurable development
    # values: model probabilities are not calibrated compliance-confidence scores, and nothing is ever certified.
    transcription_model_dir: Path | None = None
    transcription_worker: bool = True
    transcription_threads: int = 4
    # Defaults chosen from the golden dataset (S1.md "S1-D as built"); development indicators, not calibrated scores.
    transcript_low_logprob: float = -0.45
    transcript_reject_logprob: float = -0.8
    transcript_word_prob: float = 0.7
    transcript_no_speech_prob: float = 0.6
    transcript_max_compression: float = 2.4
    transcript_split_pause_s: float = 1.0
    # S1-E.2 GPT-Live adapter (Voice Lab only). DISABLED by default: no connection is possible. LIVE needs the dedicated
    # backend-only key VOICE_LAB_OPENAI_API_KEY (never sent to a browser, logged or returned) and is still gated by the
    # Voice Lab paid switch, a single-use smoke-test authorisation and the PAID budget. The official URL is the only
    # remote host allowed; a loopback URL is accepted only in APP_ENV=test (mocked protocol server).
    voice_lab_gpt_live_mode: Literal["DISABLED", "LIVE"] = "DISABLED"
    voice_lab_openai_api_key: SecretStr | None = None
    voice_lab_gpt_live_url: str = "wss://api.openai.com/v1/live/sessions"
    # The GPT_LIVE_MOCK provider: the same adapter against a local mocked protocol server (loopback only, no key, no
    # money; synthetic metering at the verified GPT-Live rate). Unset: the provider is unavailable.
    voice_lab_gpt_live_mock_url: str | None = None
    voice_lab_close_timeout_s: float = 5.0
    # S1-E.2A Azure OpenAI GPT-Live — the PREFERRED live provider. DISABLED by default. Endpoint = the resource
    # endpoint (https://<resource>.openai.azure.com); deployment = the GPT-Live deployment name (sent as session.model).
    # Auth: API_KEY (local development; header ``api-key``) or ENTRA (Microsoft Entra ID / Managed Identity bearer token
    # via azure-identity, scope below). The price is NOT known to Call360: until VOICE_LAB_AZURE_PRICE_USD_PER_MIN and
    # its source are configured from the owner's verified Azure price, every Azure session is refused (fail closed).
    voice_lab_azure_gpt_live_mode: Literal["DISABLED", "LIVE"] = "DISABLED"
    voice_lab_azure_openai_endpoint: str | None = None
    voice_lab_azure_openai_deployment: str | None = None
    voice_lab_azure_auth: Literal["API_KEY", "ENTRA"] = "API_KEY"
    voice_lab_azure_openai_api_key: SecretStr | None = None
    voice_lab_azure_entra_scope: str = "https://ai.azure.com/.default"  # Foundry managed-identity page; configurable
    voice_lab_azure_managed_identity_client_id: str | None = None
    voice_lab_azure_audio_rate: Literal[16000, 24000] = 24000
    voice_lab_azure_deployment_type: Literal["GLOBAL", "DATA_ZONE"] | None = None
    voice_lab_azure_region: str | None = None
    voice_lab_azure_price_usd_per_min: Decimal | None = None
    voice_lab_azure_price_source: str | None = None
    voice_lab_azure_price_verified_on: str | None = None
    # The mocked protocol server's profile (GPT_LIVE_MOCK): AZURE (default, the preferred provider's URL path, 24 kHz
    # audio and api-key header) or OPENAI.
    voice_lab_gpt_live_mock_profile: Literal["AZURE", "OPENAI"] = "AZURE"
    voice_lab_start_timeout_s: float = 10.0  # connect + session.started; bounded 2–30 s

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
    script_writes_per_minute: int = 240  # S2-A: an author edits many small things in a row

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
        self._check_data_protection_keys()
        return self

    def _check_data_protection_keys(self) -> None:
        keys = (self.pii_encryption_key, self.pii_hmac_key)
        if self.app_env == "test" and None in keys:
            raise ValueError("APP_ENV=test requires PII_ENCRYPTION_KEY and PII_HMAC_KEY (scripts/make_data_keys.py)")
        if (keys[0] is None) != (keys[1] is None):
            raise ValueError("PII_ENCRYPTION_KEY and PII_HMAC_KEY must be configured together")
        if keys[0] is not None and keys[1] is not None:
            from app.domain.protection import decode_key  # local import: protection depends on settings

            enc, mac = decode_key(keys[0].get_secret_value()), decode_key(keys[1].get_secret_value())
            if enc == mac:
                raise ValueError("PII_ENCRYPTION_KEY and PII_HMAC_KEY must differ")
            if self.recording_encryption_key is not None:
                rec = decode_key(self.recording_encryption_key.get_secret_value())
                if rec in (enc, mac):
                    raise ValueError("RECORDING_ENCRYPTION_KEY must differ from the PII keys")
        if self.recording_retention_hours < 1:
            raise ValueError("RECORDING_RETENTION_HOURS must be at least 1")
        if not (-5.0 <= self.transcript_reject_logprob < self.transcript_low_logprob <= 0.0):
            raise ValueError("transcript log-probability thresholds are out of range or out of order")
        if not (0.0 <= self.transcript_word_prob <= 1.0 and 0.2 <= self.transcript_split_pause_s <= 10.0):
            raise ValueError("transcript word or pause thresholds are out of range")
        if not (0.0 <= self.transcript_no_speech_prob <= 1.0 and self.transcript_max_compression > 1.0):
            raise ValueError("transcript rejection thresholds are out of range")
        if not 1 <= self.transcription_threads <= 16:
            raise ValueError("TRANSCRIPTION_THREADS must be between 1 and 16")
        from app.voice.gpt_live import check_urls  # local import: the adapter module imports settings types only

        check_urls(self)

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
