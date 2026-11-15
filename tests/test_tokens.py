"""BE-AUTH-04 — access-token validation rejects every malformed, expired or substituted token."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.settings import Settings
from app.security.tokens import TokenExpired, TokenInvalid, TokenService


@pytest.fixture()
def svc(settings: Settings) -> TokenService:
    return TokenService(settings)


def _claims(svc: TokenService, **over: object) -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())
    base: dict[str, object] = {
        "iss": svc.settings.jwt_issuer,
        "aud": svc.settings.jwt_audience,
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "jti": "j",
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def _sign(svc: TokenService, claims: dict[str, object], key: object = None, kid: str | None = None) -> str:
    return jwt.encode(claims, key or svc._private, algorithm="EdDSA", headers={"kid": kid or svc.kid})


def test_valid_token_round_trip(svc: TokenService) -> None:
    pid, sid = uuid.uuid4(), uuid.uuid4()
    token, _ = svc.issue_access(pid, sid, datetime.now(UTC))
    claims = svc.decode_access(token)
    assert (claims.principal_id, claims.session_id) == (pid, sid)


def test_expired(svc: TokenService) -> None:
    token, _ = svc.issue_access(uuid.uuid4(), uuid.uuid4(), datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(TokenExpired):
        svc.decode_access(token)


@pytest.mark.parametrize(
    "over",
    [
        {"iss": "someone-else"},
        {"aud": "another-api"},
        {"typ": "refresh"},
        {"sid": None},
        {"jti": None},
        {"nbf": int(datetime.now(UTC).timestamp()) + 3600},
        {"sub": "not-a-uuid"},
    ],
)
def test_rejected_claims(svc: TokenService, over: dict[str, object]) -> None:
    with pytest.raises(TokenInvalid):
        svc.decode_access(_sign(svc, _claims(svc, **over)))


def test_wrong_signing_key(svc: TokenService) -> None:
    with pytest.raises(TokenInvalid):
        svc.decode_access(_sign(svc, _claims(svc), key=Ed25519PrivateKey.generate()))


def test_unknown_kid(svc: TokenService) -> None:
    with pytest.raises(TokenInvalid):
        svc.decode_access(_sign(svc, _claims(svc), kid="ffffffffffffffff"))


def test_alg_none(svc: TokenService) -> None:
    token = jwt.encode(_claims(svc), None, algorithm="none", headers={"kid": svc.kid})
    with pytest.raises(TokenInvalid):
        svc.decode_access(token)


def test_hs256_with_public_key_confusion(svc: TokenService, settings: Settings) -> None:
    pub = Path(settings.resolve(settings.jwt_public_key_path)).read_bytes()
    import base64
    import hashlib
    import hmac
    import json

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": svc.kid}).encode())
    body = b64(json.dumps(_claims(svc)).encode())
    sig = b64(hmac.new(pub, f"{header}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(TokenInvalid):
        svc.decode_access(f"{header}.{body}.{sig}")


def test_tampered_payload(svc: TokenService) -> None:
    token, _ = svc.issue_access(uuid.uuid4(), uuid.uuid4(), datetime.now(UTC))
    h, p, s = token.split(".")
    with pytest.raises(TokenInvalid):
        svc.decode_access(f"{h}.{p[:-2]}AA.{s}")


def test_key_is_ed25519(settings: Settings) -> None:
    key = serialization.load_pem_private_key(settings.resolve(settings.jwt_private_key_path).read_bytes(), None)
    assert isinstance(key, Ed25519PrivateKey)
