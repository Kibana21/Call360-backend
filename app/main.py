"""FastAPI application factory (CP0.1A)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from app.api import (
    admin,
    admin_access,
    admin_config,
    assignment_rules,
    auth,
    case_detail,
    cases,
    dashboard,
    finding_rules,
    health,
    intake,
    me,
    policies,
    review_workbench,
    reviews,
    risk,
    script_assignments,
    script_authoring,
    script_simulations,
    scripts,
    search,
    simulation_workbench,
    survey_definitions,
    voice,
    voice_lab,
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
from app.voice import lab, transcript


async def _voice_sweeper(app: FastAPI, every_s: float = 15.0) -> None:
    """S1-B: finalise abandoned, interrupted-too-long and orphaned voice sessions; S1-C: finalise recordings past their
    upload window and purge audio past local retention."""
    while True:
        await asyncio.sleep(every_s)
        try:
            await asyncio.to_thread(voice.run_sweep, app)
            await asyncio.to_thread(_lab_sweep, app)
        except Exception:  # noqa: BLE001 — the sweeper must keep running; the next pass retries
            logging.getLogger("call360.voice").exception("voice session sweep failed")


def _lab_sweep(app: FastAPI) -> None:
    """S1-E.1: end Voice Lab sessions that were created but never connected (their reservation is released)."""
    with app.state.session_factory() as db, db.begin():
        if db.execute(text("SELECT to_regclass('lab_session')")).scalar() is not None:
            lab.abandon_unconnected(db)  # only CREATED sessions: a connected one is LIVE
            if db.execute(text("SELECT to_regclass('lab_speech_assessment')")).scalar() is not None:
                # S1-E.2: the local retention policy (RECORDING_RETENTION_HOURS, 168 h) applies to lab audio and
                # session transcripts; rows, checksums, metrics and evaluation history are kept.
                lab.purge_expired(db, lab.store_for(app), app.state.settings.recording_retention_hours)


def _lab_recover(app: FastAPI) -> None:
    with app.state.session_factory() as db, db.begin():
        if db.execute(text("SELECT to_regclass('lab_session')")).scalar() is not None:
            lab.recover(db)


async def _transcription_worker(app: FastAPI, every_s: float = 2.0) -> None:
    """S1-D: transcribe finalised recordings outside the request path (one run at a time, idempotent, restartable)."""
    while True:
        await asyncio.sleep(every_s)
        try:
            await asyncio.to_thread(transcript.work, app)
        except Exception:  # noqa: BLE001 — the worker must keep running; leases and retries recover a failed pass
            logging.getLogger("call360.transcript").exception("transcription pass failed")


MIGRATION_HEAD = "0027_survey_definitions"
#: Revision 0027 (SS-03A) only ADDS tables that are used when `survey_definitions_enabled` is on. A schema still at the
#: revision before it therefore serves the whole existing product correctly while that setting is off, and is accepted
#: in that case only. With the setting on, the schema must be at the head.
HEAD_BEFORE_SURVEY_DEFINITIONS = "0026_gpt_live_provider"


def acceptable_migration_heads(settings: Settings) -> tuple[str, ...]:
    if settings.survey_definitions_enabled:
        return (MIGRATION_HEAD,)
    return (MIGRATION_HEAD, HEAD_BEFORE_SURVEY_DEFINITIONS)


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
    script_authoring.router,
    assignment_rules.router,
    script_assignments.router,
    script_simulations.router,
    simulation_workbench.router,
    finding_rules.router,
    review_workbench.router,
    reviews.router,
    voice.router,
    voice_lab.router,
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
            transcript.recover(app)  # nothing is transcribing after a (re)start: expire leases
            _lab_recover(app)  # S1-E.1: nothing is live in the Voice Lab after a (re)start
            worker = asyncio.create_task(_transcription_worker(app)) if settings.transcription_worker else None
        yield
        if with_database:
            sweeper.cancel()
            if worker is not None:
                worker.cancel()
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
    app.state.acceptable_migration_heads = acceptable_migration_heads(settings)
    if with_database:
        app.state.engine = make_engine(settings)
        app.state.session_factory = make_session_factory(app.state.engine)
        app.state.tokens = TokenService(settings)
    app.add_middleware(SecurityMiddleware, allowed_origins=settings.allowed_origins, hsts=settings.cookie_secure)
    install_error_handlers(app)
    install_log_redaction()
    for router in ROUTERS:
        app.include_router(router)
    if settings.survey_definitions_enabled:
        # SS-03A: off by default. With it off the survey routes do not exist and nothing touches the survey_* tables.
        app.include_router(survey_definitions.router)
    return app


def app_factory() -> FastAPI:  # used by `uvicorn --factory app.main:app_factory`
    return create_app()
