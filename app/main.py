"""FastAPI application factory (CP0.1A)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import (
    admin,
    admin_access,
    admin_config,
    auth,
    case_detail,
    cases,
    dashboard,
    health,
    intake,
    me,
    policies,
    reviews,
    risk,
    scripts,
    search,
    voice,
)
from app.core.errors import install_error_handlers
from app.core.middleware import SecurityMiddleware, install_log_redaction
from app.core.settings import Settings, get_settings
from app.db.guards import verify_connection
from app.db.session import make_engine, make_session_factory
from app.domain.protection import protection_for
from app.security.cookies import cookie_names
from app.security.rate_limit import SlidingWindowLimiter
from app.security.tokens import TokenService


async def _voice_sweeper(app: FastAPI, every_s: float = 15.0) -> None:
    """S1-B: finalise abandoned, interrupted-too-long and orphaned voice sessions."""
    while True:
        await asyncio.sleep(every_s)
        try:
            await asyncio.to_thread(voice.run_sweep, app)
        except Exception:  # noqa: BLE001 — the sweeper must keep running; the next pass retries
            logging.getLogger("call360.voice").exception("voice session sweep failed")


MIGRATION_HEAD = "0012_session_event"
ROUTERS = (
    health.router,
    auth.router,
    me.router,
    admin.router,
    admin_access.router,
    admin_config.router,
    dashboard.router,
    cases.router,
    search.router,
    case_detail.router,
    scripts.router,
    reviews.router,
    voice.router,
    policies.router,
    risk.router,
    intake.router,
)


def create_app(settings: Settings | None = None, *, with_database: bool = True) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if with_database:  # fail closed: refuse to serve against the wrong database, role or schema
            with app.state.engine.connect() as conn:
                verify_connection(conn, settings)
                # D-34: refuse to start on a CP0.2 schema without both data-protection keys.
                app.state.data_protection = protection_for(conn, settings)
            # S1-B: nothing is live after a (re)start, so sessions left open are finalised; then sweep periodically.
            voice.run_sweep(app, startup=True)
            sweeper = asyncio.create_task(_voice_sweeper(app))
        yield
        if with_database:
            sweeper.cancel()
            app.state.engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="Call360 API",
        version="0.1.0",
        description="Call360 Stage 0 API (CP0.1A: authentication, sessions, administration of users and audit).",
    )
    app.state.settings = settings
    app.state.cookies = cookie_names(settings)
    app.state.limiter = SlidingWindowLimiter()
    app.state.expected_migration_head = MIGRATION_HEAD
    if with_database:
        app.state.engine = make_engine(settings)
        app.state.session_factory = make_session_factory(app.state.engine)
        app.state.tokens = TokenService(settings)
    app.add_middleware(SecurityMiddleware, allowed_origins=settings.allowed_origins, hsts=settings.cookie_secure)
    install_error_handlers(app)
    install_log_redaction()
    for router in ROUTERS:
        app.include_router(router)
    return app


def app_factory() -> FastAPI:  # used by `uvicorn --factory app.main:app_factory`
    return create_app()
