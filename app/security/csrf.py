"""Session-bound double-submit CSRF tokens (S0_IDENTITY_ACCESS_DESIGN §4).

token = <nonce>.<HMAC(secret, binding + ":" + nonce)>; binding is ``pre:<nonce cookie>`` before
login and ``sid:<session id>`` afterwards. The header must equal the cookie and verify.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Request

from app.core.errors import AppError

CSRF_COOKIE = "c360_csrf"
CSRF_HEADER = "x-csrf-token"
PRE_SESSION_COOKIE = "c360_pre"


def _sign(secret: str, binding: str, nonce: str) -> str:
    return hmac.new(secret.encode(), f"{binding}:{nonce}".encode(), hashlib.sha256).hexdigest()


def issue(secret: str, binding: str) -> str:
    nonce = secrets.token_urlsafe(18)
    return f"{nonce}.{_sign(secret, binding, nonce)}"


def verify(request: Request, secret: str, binding: str, cookie_name: str = CSRF_COOKIE) -> None:
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(cookie_name)
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise AppError(403, "CSRF_INVALID", "Missing or mismatched CSRF token")
    nonce, _, sig = header.partition(".")
    if not nonce or not sig or not hmac.compare_digest(sig, _sign(secret, binding, nonce)):
        raise AppError(403, "CSRF_INVALID", "CSRF token is not valid for this session")
