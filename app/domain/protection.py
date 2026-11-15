"""Data protection for party names and contact values (S-13, D-34; S0_IDENTITY_ACCESS_DESIGN §10).

- AES-256-GCM with a random 96-bit nonce per value; the associated data binds a ciphertext to its table,
  column and row, so a ciphertext copied to another row fails to decrypt.
- HMAC-SHA-256 exact-match tokens with a separate key, over a normalised value.
- Keys come only from local settings and are never logged, printed or returned. ``key_ids`` exposes a
  derived, non-reversible identifier for evidence (D-33), never key material.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Connection, text

from app.core.settings import Settings

_FORMAT = b"\x01"  # ciphertext layout version: 0x01 || nonce(12) || ciphertext+tag
KEY_BYTES = 32


class DataProtectionUnavailable(RuntimeError):
    """The data-protection keys are not configured for this environment."""


def decode_key(value: str) -> bytes:
    """Decode a base64url key and require exactly 32 bytes."""
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != KEY_BYTES:
        raise ValueError("data-protection keys must be 32 bytes (base64url)")
    return raw


def generate_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).rstrip(b"=").decode()


class DataProtection:
    def __init__(self, encryption_key: bytes, hmac_key: bytes) -> None:
        if len(encryption_key) != KEY_BYTES or len(hmac_key) != KEY_BYTES:
            raise ValueError("data-protection keys must be 32 bytes")
        if hmac.compare_digest(encryption_key, hmac_key):
            raise ValueError("encryption and HMAC keys must differ")
        self._aead = AESGCM(encryption_key)
        self._hmac_key = hmac_key
        self._enc_id = hmac.new(encryption_key, b"call360-key-id", hashlib.sha256).hexdigest()[:12]
        self._mac_id = hmac.new(hmac_key, b"call360-key-id", hashlib.sha256).hexdigest()[:12]

    @classmethod
    def from_settings(cls, settings: Settings) -> DataProtection:
        if settings.pii_encryption_key is None or settings.pii_hmac_key is None:
            raise DataProtectionUnavailable(
                "PII_ENCRYPTION_KEY and PII_HMAC_KEY are not configured (scripts/make_data_keys.py)"
            )
        return cls(
            decode_key(settings.pii_encryption_key.get_secret_value()),
            decode_key(settings.pii_hmac_key.get_secret_value()),
        )

    @property
    def key_ids(self) -> dict[str, str]:
        return {"encryption": self._enc_id, "hmac": self._mac_id}

    def encrypt(self, plaintext: str, *, aad: str) -> bytes:
        nonce = os.urandom(12)
        return _FORMAT + nonce + self._aead.encrypt(nonce, plaintext.encode(), aad.encode())

    def decrypt(self, blob: bytes, *, aad: str) -> str:
        if blob[:1] != _FORMAT:
            raise ValueError("unknown ciphertext format")
        return self._aead.decrypt(blob[1:13], blob[13:], aad.encode()).decode()

    def token(self, channel: str, value: str) -> str:
        message = f"{channel}:{normalise_contact(channel, value)}".encode()
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()


def domain_present(conn: Connection, schema: str) -> bool:
    """True once migration 0003 has created the CP0.2 protected tables in ``schema``."""
    assert schema in {"call360", "call360_test"}, schema
    return bool(conn.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": f"{schema}.party"}).scalar())


def protection_for(conn: Connection, settings: Settings) -> DataProtection | None:
    """D-34 enforcement point for startup, readiness and the seed. Whenever the CP0.2 domain exists in the
    connected schema both keys are mandatory, so protected data is never served or written without them. A
    pre-CP0.2 schema (development at 0002) runs without keys until it is upgraded."""
    if settings.pii_encryption_key is None or settings.pii_hmac_key is None:
        if domain_present(conn, settings.target_schema):
            raise DataProtectionUnavailable(
                "the CP0.2 business domain is present but PII_ENCRYPTION_KEY / PII_HMAC_KEY are not configured"
            )
        return None
    return DataProtection.from_settings(settings)


def aad(table: str, column: str, row_id: object) -> str:
    return f"{table}.{column}:{row_id}"


def normalise_contact(channel: str, value: str) -> str:
    value = value.strip()
    return value.lower() if channel == "EMAIL" else value.upper()


def mask_contact(channel: str, value: str) -> str:
    """``SYN-TEL-SG-004217`` -> ``SYN-TEL-SG-••••17``; ``example.policyholder.012@example.invalid`` ->
    ``e•••@example.invalid``."""
    if channel == "EMAIL":
        local, _, domain = value.partition("@")
        return f"{local[:1]}•••@{domain}"
    head, _, digits = value.rpartition("-")
    return f"{head}-{'•' * max(len(digits) - 2, 0)}{digits[-2:]}"


def mask_name(name: str) -> str:
    """``Example Policyholder 012`` -> ``Example P. 012``: enough to tell synthetic parties apart."""
    parts = name.split()
    if len(parts) < 3:
        return f"{parts[0][:1]}•••" if parts else "•••"
    return f"{parts[0]} {parts[1][:1]}. {' '.join(parts[2:])}"


def matches_any(value: str, patterns: list[str]) -> bool:
    return any(re.fullmatch(p, value) for p in patterns)
