"""Correlation IDs, security headers and Origin enforcement for unsafe methods."""

from __future__ import annotations

import logging
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


_SEARCH_PATHS = ("/api/v1/search", "/api/v1/cases")
_Q_PARAM = re.compile(r"([?&]q=)[^&]*")


class SearchTermRedaction(logging.Filter):
    """S-14 / BE-SRCH-08: the access log never carries a raw search term; ``q=`` is replaced by its SHA-256."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if (
            isinstance(args, tuple)
            and len(args) >= 3
            and isinstance(args[2], str)
            and args[2].startswith(_SEARCH_PATHS)
        ):
            path = _Q_PARAM.sub(lambda m: m.group(1) + "sha256:" + _q_digest(m.group(0)[len(m.group(1)) :]), args[2])
            record.args = (*args[:2], path, *args[3:])
        return True


def _q_digest(raw: str) -> str:
    from urllib.parse import unquote_plus

    from app.domain.register import term_hash

    return term_hash(unquote_plus(raw))


def install_log_redaction() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, SearchTermRedaction) for f in access.filters):
        access.addFilter(SearchTermRedaction())
