"""Argon2id hashing and the local password policy (S0_IDENTITY_ACCESS_DESIGN §3, S-3 provisional)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
HASH_PARAMS = "argon2id;m=65536;t=3;p=1"
# Precomputed so unknown-user logins cost the same as real ones (T-51).
_DUMMY_HASH = _HASHER.hash("call360-timing-equaliser-not-a-credential")

MIN_LENGTH, MAX_LENGTH = 12, 128
# Small offline blocklist of very common passwords (a full breached-password corpus is a later
# hardening step; recorded as a CP0.1A limitation).
_COMMON = frozenset(
    """password password1 password123 passw0rd 123456789012 1234567890123 qwertyuiopas qwerty123456
    letmein12345 iloveyou1234 welcome12345 admin1234567 administrator changeme1234 abc123456789
    trustno11234 football1234 baseball1234 monkey123456 dragon123456 sunshine1234 princess1234
    call360admin call360user call360password aia123456789 insurance123 password1234 qwertyuiop12
    111111111111 000000000000 123123123123 aaaaaaaaaaaa""".split()
)


class PasswordPolicyError(ValueError):
    pass


def check_policy(password: str, *, username: str, display_name: str) -> None:
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise PasswordPolicyError(f"password must be {MIN_LENGTH}–{MAX_LENGTH} characters")
    lowered = password.lower()
    if lowered in _COMMON:
        raise PasswordPolicyError("password is too common")
    for part in (username.lower(), *display_name.lower().split()):
        if len(part) >= 4 and part in lowered:
            raise PasswordPolicyError("password must not contain the username or display name")


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _HASHER.check_needs_rehash(password_hash)
