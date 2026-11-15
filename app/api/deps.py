"""Shared route helpers: route classification markers used by the route-inventory test (BE-SEC-01)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Routes reachable without an access token (S0_IDENTITY_ACCESS_DESIGN §7.1).
PUBLIC_ROUTES = frozenset(
    {
        ("GET", "/health/live"),
        ("GET", "/health/ready"),
        ("GET", "/api/v1/auth/csrf"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/refresh"),
        ("POST", "/api/v1/auth/logout"),
    }
)
# Routes requiring only an authenticated session (no specific permission).
AUTHENTICATED_ROUTES = frozenset({("GET", "/api/v1/me")})


def csrf_protected[F: Callable[..., Any]](fn: F) -> F:
    """Marks a state-changing endpoint whose handler verifies the session-bound CSRF token."""
    fn.csrf_protected = True  # type: ignore[attr-defined]
    return fn
