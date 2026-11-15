"""EdDSA (Ed25519) access tokens, opaque refresh tokens and their HMAC storage form."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.settings import Settings

ALGORITHM = "EdDSA"


class TokenExpired(Exception):
    pass


class TokenInvalid(Exception):
    pass


@dataclass(frozen=True)
class AccessClaims:
    principal_id: uuid.UUID
    session_id: uuid.UUID
    expires_at: datetime


def generate_keypair(private_path: Path, public_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        private = serialization.load_pem_private_key(
            settings.resolve(settings.jwt_private_key_path).read_bytes(), password=None
        )
        public = serialization.load_pem_public_key(settings.resolve(settings.jwt_public_key_path).read_bytes())
        if not isinstance(private, Ed25519PrivateKey) or not isinstance(public, Ed25519PublicKey):
            raise ValueError("JWT keys must be Ed25519")
        self._private = private
        self._public = public
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.kid = hashlib.sha256(raw).hexdigest()[:16]
        self._pepper = settings.refresh_token_pepper.get_secret_value().encode()

    def issue_access(self, principal_id: uuid.UUID, session_id: uuid.UUID, now: datetime) -> tuple[str, datetime]:
        exp = now + timedelta(seconds=self.settings.access_token_ttl_seconds)
        claims = {
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "sub": str(principal_id),
            "sid": str(session_id),
            "jti": str(uuid.uuid4()),
            "typ": "access",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }
        token = jwt.encode(claims, self._private, algorithm=ALGORITHM, headers={"kid": self.kid, "typ": "JWT"})
        return token, exp

    def decode_access(self, token: str, *, allow_expired: bool = False) -> AccessClaims:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != ALGORITHM or header.get("kid") != self.kid:
                raise TokenInvalid("unexpected algorithm or key id")
            claims = jwt.decode(
                token,
                self._public,
                algorithms=[ALGORITHM],
                audience=self.settings.jwt_audience,
                issuer=self.settings.jwt_issuer,
                options={
                    "require": ["exp", "iat", "nbf", "jti", "sub", "sid", "typ", "iss", "aud"],
                    "verify_exp": not allow_expired,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpired() from exc
        except jwt.PyJWTError as exc:
            raise TokenInvalid(str(exc)) from exc
        if claims.get("typ") != "access":
            raise TokenInvalid("wrong token type")
        try:
            return AccessClaims(
                uuid.UUID(claims["sub"]), uuid.UUID(claims["sid"]), datetime.fromtimestamp(claims["exp"], UTC)
            )
        except (ValueError, KeyError) as exc:
            raise TokenInvalid("malformed claims") from exc

    @staticmethod
    def new_refresh_token() -> str:
        return secrets.token_urlsafe(32)

    def refresh_hmac(self, token: str) -> str:
        return hmac.new(self._pepper, token.encode(), hashlib.sha256).hexdigest()
