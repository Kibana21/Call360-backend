"""Correlation IDs, security headers and Origin enforcement for unsafe methods."""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.errors import error_body

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "microphone=(), camera=(), geolocation=()",
    "X-Frame-Options": "DENY",
}

Next = Callable[[Request], Awaitable[Response]]


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, allowed_origins: list[str], hsts: bool) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.allowed_origins = frozenset(allowed_origins)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: Next) -> Response:
        supplied = request.headers.get("x-correlation-id", "")
        request.state.correlation_id = supplied if _CORRELATION_RE.match(supplied) else str(uuid.uuid4())

        if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/") and not self._origin_ok(request):
            response: Response = JSONResponse(
                error_body(request, "ORIGIN_REJECTED", "Request origin is not allowed"), status_code=403
            )
        else:
            response = await call_next(request)

        response.headers["X-Correlation-ID"] = request.state.correlation_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if self.hsts:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def _origin_ok(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer")
            if referer is None:
                return False
            m = re.match(r"^(https?://[^/]+)", referer)
            origin = m.group(1) if m else None
        return origin in self.allowed_origins
