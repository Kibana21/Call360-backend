"""GPT-Live provider endpoints (S1-E.2A): one shared protocol adapter (``app.voice.gpt_live``), several endpoints.

- ``AZURE_OPENAI_GPT_LIVE`` (preferred): ``wss://<resource>.openai.azure.com/openai/v1/live/sessions``; ``api-key``
  header (API_KEY) or ``Authorization: Bearer`` Entra / Managed Identity token (ENTRA); PCM16 24 kHz on the wire
  (documented; 16 kHz configurable); ``session.model`` = the deployment name.
- ``OPENAI_GPT_LIVE``: ``wss://api.openai.com/v1/live/sessions``; ``Authorization: Bearer`` key; PCM16 16 kHz;
  ``session.model`` = ``gpt-live-1``.
- ``GPT_LIVE_MOCK``: the loopback mocked protocol server (Azure or OpenAI profile); no credentials.

Browser audio stays 16 kHz; the adapter resamples at its boundary when the wire rate differs. Only the official
OpenAI host and ``*.openai.azure.com`` are reachable outside tests; in ``APP_ENV=test`` only loopback. Azure Entra
authentication uses ``azure-identity`` when installed (``DefaultAzureCredential`` / ``ManagedIdentityCredential``);
without it the provider is unavailable (fail closed) — the library is not installed in local development.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import numpy as np

AZURE = "AZURE_OPENAI_GPT_LIVE"
OPENAI = "OPENAI_GPT_LIVE"
LEGACY_OPENAI = "GPT_LIVE"  # S1-E.2 code, kept so recorded prompt versions resolve; not offered for new prompts
MOCK = "GPT_LIVE_MOCK"
LIVE_PROVIDERS = (AZURE, OPENAI, LEGACY_OPENAI, MOCK)
AZURE_PATH = "/openai/v1/live/sessions"
OPENAI_URL = "wss://api.openai.com/v1/live/sessions"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class EndpointError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def vendor_of(code: str, settings: Any) -> str:
    if code in (OPENAI, LEGACY_OPENAI):
        return "OPENAI"
    if code == AZURE:
        return "AZURE"
    return str(settings.voice_lab_gpt_live_mock_profile)


def _loopback(url: str) -> bool:
    u = urlparse(url)
    return u.scheme in ("ws", "wss") and (u.hostname or "") in LOOPBACK


def official(url: str, vendor: str) -> bool:
    u = urlparse(url)
    if u.scheme != "wss":
        return False
    if vendor == "AZURE":
        host = u.hostname or ""
        return host.endswith(".openai.azure.com") and host.count(".") >= 3 and u.path.startswith(AZURE_PATH)
    return u.hostname == "api.openai.com" and u.path.startswith("/v1/live/sessions")


def allowed(url: str, *, vendor: str, app_env: str, mock: bool) -> bool:
    """Connection-time guard. Tests (and the mock provider) reach loopback only; otherwise only the vendor's official
    host — never anything else."""
    if mock or app_env == "test":
        return _loopback(url)
    return official(url, vendor)


def azure_url(endpoint: str) -> str:
    """``https://<resource>.openai.azure.com`` (as shown in the Azure portal) → the GPT-Live WebSocket URL."""
    u = urlparse(endpoint.strip())
    if u.scheme in ("ws", "wss") and u.path.startswith(AZURE_PATH):
        return endpoint.strip().rstrip("/")
    scheme = "ws" if u.scheme in ("http", "ws") else "wss"
    return f"{scheme}://{u.netloc}{AZURE_PATH}"


def check(settings: Any) -> None:
    """Startup validation of the Azure configuration (APP_ENV=test may use a loopback endpoint)."""
    ep = settings.voice_lab_azure_openai_endpoint
    if ep:
        url = azure_url(ep)
        if not (official(url, "AZURE") or (settings.app_env == "test" and _loopback(url))):
            raise ValueError("VOICE_LAB_AZURE_OPENAI_ENDPOINT must be https://<resource>.openai.azure.com")
    dep = settings.voice_lab_azure_openai_deployment
    plain = (dep or "").replace("-", "").replace("_", "").replace(".", "")
    if dep is not None and not (1 <= len(dep) <= 64 and plain.isalnum()):
        raise ValueError("VOICE_LAB_AZURE_OPENAI_DEPLOYMENT must be a deployment name (letters, digits, - _ .)")
    price = settings.voice_lab_azure_price_usd_per_min
    if price is not None and not (0 < price <= 10):
        raise ValueError("VOICE_LAB_AZURE_PRICE_USD_PER_MIN must be a positive USD amount per minute (≤ 10)")
    if price is not None and not (settings.voice_lab_azure_price_source and settings.voice_lab_azure_price_verified_on):
        raise ValueError("An Azure price needs VOICE_LAB_AZURE_PRICE_SOURCE and VOICE_LAB_AZURE_PRICE_VERIFIED_ON")


def azure_missing(settings: Any) -> list[str]:
    """Why the Azure provider cannot run on this server (empty = configured)."""
    missing = []
    if settings.voice_lab_azure_gpt_live_mode != "LIVE":
        missing.append("VOICE_LAB_AZURE_GPT_LIVE_MODE is not LIVE")
    if not settings.voice_lab_azure_openai_endpoint:
        missing.append("no Azure OpenAI endpoint")
    if not settings.voice_lab_azure_openai_deployment:
        missing.append("no GPT-Live deployment name")
    if settings.voice_lab_azure_auth == "API_KEY" and settings.voice_lab_azure_openai_api_key is None:
        missing.append("no backend Azure API key")
    if settings.voice_lab_azure_auth == "ENTRA" and not entra_available():
        missing.append("Entra ID authentication needs the azure-identity package, which is not installed")
    return missing


def entra_available() -> bool:
    try:
        import azure.identity  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


def entra_token(settings: Any, credential: Any = None) -> str:
    """A Microsoft Entra ID access token for the data plane (Managed Identity when a client id is configured,
    otherwise DefaultAzureCredential). Never logged or returned."""
    if credential is None:
        if not entra_available():
            raise EndpointError("ENTRA_UNAVAILABLE", "azure-identity is not installed")
        from azure.identity import DefaultAzureCredential, ManagedIdentityCredential

        cid = settings.voice_lab_azure_managed_identity_client_id
        credential = ManagedIdentityCredential(client_id=cid) if cid else DefaultAzureCredential()
    return str(credential.get_token(settings.voice_lab_azure_entra_scope).token)


@dataclass(frozen=True)
class Endpoint:
    vendor: str
    url: str
    headers: dict[str, str]  # secret: never log, return or persist
    wire_rate: int
    model: str
    mock: bool
    attach_base: str

    def describe(self) -> dict[str, Any]:
        """Non-secret description for the trace and the UI."""
        return {
            "vendor": self.vendor,
            "host": urlparse(self.url).hostname,
            "wire_rate": self.wire_rate,
            "model": self.model,
            "auth": sorted(self.headers) or ["none"],
            "mock": self.mock,
        }


def endpoint(code: str, settings: Any, *, model: str, credential: Any = None) -> Endpoint:
    """Resolve the connection for one session. Raises ``EndpointError`` when the provider is not configured."""
    if code == MOCK:
        url = settings.voice_lab_gpt_live_mock_url
        if not url:
            raise EndpointError("PROVIDER_NOT_AVAILABLE", "VOICE_LAB_GPT_LIVE_MOCK_URL is not set")
        azure = settings.voice_lab_gpt_live_mock_profile == "AZURE"
        u = urlparse(url)
        path = AZURE_PATH if azure else "/v1/live/sessions"
        live = f"{u.scheme}://{u.netloc}{path}"
        return Endpoint("AZURE" if azure else "OPENAI", live, {}, 24000 if azure else 16000, model, True, live)
    if code in (OPENAI, LEGACY_OPENAI):
        if settings.voice_lab_gpt_live_mode != "LIVE" or settings.voice_lab_openai_api_key is None:
            raise EndpointError("PROVIDER_NOT_AVAILABLE", "OpenAI GPT-Live is not configured on this server")
        url = settings.voice_lab_gpt_live_url
        key = settings.voice_lab_openai_api_key.get_secret_value()
        return Endpoint("OPENAI", url, {"Authorization": f"Bearer {key}"}, 16000, model, False, url)
    if code == AZURE:
        missing = azure_missing(settings)
        if missing:
            raise EndpointError("PROVIDER_NOT_AVAILABLE", "; ".join(missing))
        url = azure_url(settings.voice_lab_azure_openai_endpoint)
        if settings.voice_lab_azure_auth == "API_KEY":
            headers = {"api-key": settings.voice_lab_azure_openai_api_key.get_secret_value()}
        else:
            headers = {"Authorization": f"Bearer {entra_token(settings, credential)}"}
        return Endpoint(
            "AZURE",
            url,
            headers,
            int(settings.voice_lab_azure_audio_rate),
            settings.voice_lab_azure_openai_deployment,
            False,
            url,
        )
    raise EndpointError("PROVIDER_UNKNOWN", f"{code} is not a GPT-Live provider")


# ---- resampling at the adapter boundary (browser 16 kHz ⇄ wire rate) -------------------------------------------------
def resample(pcm: bytes, src: int, dst: int) -> bytes:
    """PCM16 mono linear-interpolation resampling (adequate for speech; not a broadcast-quality resampler)."""
    if src == dst or not pcm:
        return pcm
    x = np.frombuffer(pcm[: len(pcm) - len(pcm) % 2], dtype="<i2").astype(np.float32)
    n = int(round(len(x) * dst / src))
    if n == 0:
        return b""
    t = np.linspace(0, len(x) - 1, n, dtype=np.float32)
    y = np.interp(t, np.arange(len(x), dtype=np.float32), x)
    return bytes(np.clip(np.round(y), -32768, 32767).astype("<i2").tobytes())
