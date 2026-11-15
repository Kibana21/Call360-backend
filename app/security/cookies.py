"""Cookie names and attributes (S0_IDENTITY_ACCESS_DESIGN §4; S-5 provisional)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Response

from app.core.settings import Settings
from app.security.csrf import CSRF_COOKIE, PRE_SESSION_COOKIE

REFRESH_PATH = "/api/v1/auth/refresh"


@dataclass(frozen=True)
class CookieNames:
    access: str
    refresh: str
    csrf: str
    pre: str
    secure: bool


def cookie_names(settings: Settings) -> CookieNames:
    if settings.cookie_secure:
        return CookieNames(
            "__Host-c360_at", "__Secure-c360_rt", f"__Host-{CSRF_COOKIE}", f"__Host-{PRE_SESSION_COOKIE}", True
        )
    return CookieNames("c360_at", "c360_rt", CSRF_COOKIE, PRE_SESSION_COOKIE, False)


def _seconds_until(t: datetime) -> int:
    return max(0, int((t - datetime.now(UTC)).total_seconds()))


def set_session_cookies(
    response: Response,
    names: CookieNames,
    *,
    access: str,
    access_expires_at: datetime,
    refresh: str | None,
    csrf: str | None,
    session_expires_at: datetime,
) -> None:
    response.set_cookie(
        names.access,
        access,
        max_age=_seconds_until(access_expires_at),
        path="/",
        httponly=True,
        secure=names.secure,
        samesite="lax",
    )
    if refresh is not None:
        response.set_cookie(
            names.refresh,
            refresh,
            max_age=_seconds_until(session_expires_at),
            path=REFRESH_PATH,
            httponly=True,
            secure=names.secure,
            samesite="strict",
        )
    if csrf is not None:
        response.set_cookie(
            names.csrf,
            csrf,
            max_age=_seconds_until(session_expires_at),
            path="/",
            httponly=False,
            secure=names.secure,
            samesite="strict",
        )


def clear_session_cookies(response: Response, names: CookieNames) -> None:
    response.delete_cookie(names.access, path="/", secure=names.secure, httponly=True, samesite="lax")
    response.delete_cookie(names.refresh, path=REFRESH_PATH, secure=names.secure, httponly=True, samesite="strict")
    response.delete_cookie(names.csrf, path="/", secure=names.secure, samesite="strict")
