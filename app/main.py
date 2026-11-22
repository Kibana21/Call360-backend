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
    survey_assignment_groups,
    survey_assignments,
    survey_control_policies,
    survey_coordinated_simulations,
    survey_definitions,
    survey_evaluations,
    survey_execution_assurance,
    survey_journey_trace,
    survey_simulations,
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


MIGRATION_HEAD = "0035_survey_execution_assurance"
#: Each of the last nine revisions only ADDS objects that are used when its own setting is on. A schema behind the
#: head therefore serves everything that is switched on correctly, and is accepted in exactly that case:
#:   0027 (SS-03A, survey definitions)        — needed when `survey_definitions_enabled` is on;
#:   0028 (LIB-1, server-issued codes)        — needed when `survey_library_enabled` is on;
#:   0029 (SS-03B, simulation and call plans) — needed when `survey_simulation_enabled` is on;
#:   0030 (ASG-1, survey assignment)          — needed when `survey_assignment_enabled` is on;
#:   0031 (ASG-2A, requirement groups)        — needed when `survey_assignment_groups_enabled` is on;
#:   0032 (ASG-2B, coordinated simulation)    — needed when `survey_coordinated_simulation_enabled` is on.
#:   0033 (EVAL-1, control evaluation)        — needed when `survey_evaluation_enabled` is on.
#:   0034 (EVAL-2A, control policies)         — needed when `survey_control_policy_enabled` is on.
#:   0035 (EVAL-2B, execution assurance)      — needed when `survey_execution_assurance_enabled` is on.
#: With a setting on, the schema must hold that setting's revision, or readiness fails closed.
OPTIONAL_REVISIONS = (
    "0035_survey_execution_assurance", "0034_survey_control_policy", "0033_survey_control_evaluation",
    "0032_survey_coordinated_sim",
    "0031_survey_assignment_groups",
    "0030_survey_assignment", "0029_survey_simulation", "0028_survey_library", "0027_survey_definitions",
    "0026_gpt_live_provider",
)  # fmt: skip


def survey_library_on(settings: Settings) -> bool:
    """The library needs the survey definitions it reuses: it is on only when both settings are."""
    return settings.survey_definitions_enabled and settings.survey_library_enabled


def survey_simulation_on(settings: Settings) -> bool:
    """Simulation runs published survey versions: it is on only when the survey definitions are."""
    return settings.survey_definitions_enabled and settings.survey_simulation_enabled


def survey_assignment_on(settings: Settings) -> bool:
    """Selection ends in a call plan and a simulation: it is on only when simulation is."""
    return survey_simulation_on(settings) and settings.survey_assignment_enabled


def survey_assignment_groups_on(settings: Settings) -> bool:
    """Requirement groups arrange the rules that single-survey assignment already reads: on only with it."""
    return survey_assignment_on(settings) and settings.survey_assignment_groups_enabled


def survey_coordinated_simulation_on(settings: Settings) -> bool:
    """A coordinated simulation runs the surveys of a composite plan: on only with requirement groups."""
    return survey_assignment_groups_on(settings) and settings.survey_coordinated_simulation_enabled


def survey_evaluation_on(settings: Settings) -> bool:
    """Journeys are simulations: evaluation is on only when simulation is. (A coordinated journey can only exist when
    coordinated simulation was on; the 0033 schema holds everything it reads.)"""
    return survey_simulation_on(settings) and settings.survey_evaluation_enabled


def survey_control_policy_on(settings: Settings) -> bool:
    """A control policy scopes an evaluation: on only when evaluation is."""
    return survey_evaluation_on(settings) and settings.survey_control_policy_enabled


def survey_execution_assurance_on(settings: Settings) -> bool:
    """Assurance verifies the journeys that are evaluated: on only when evaluation is."""
    return survey_evaluation_on(settings) and settings.survey_execution_assurance_enabled


def acceptable_migration_heads(settings: Settings) -> tuple[str, ...]:
    """The head, and every earlier revision down to the newest one that something switched on needs."""
    needed = (
        0 if survey_execution_assurance_on(settings)
        else 1 if survey_control_policy_on(settings)
        else 2 if survey_evaluation_on(settings)
        else 3 if survey_coordinated_simulation_on(settings)
        else 4 if survey_assignment_groups_on(settings)
        else 5 if survey_assignment_on(settings)
        else 6 if survey_simulation_on(settings)
        else 7 if survey_library_on(settings)
        else 8 if settings.survey_definitions_enabled
        else 9
    )  # fmt: skip
    return OPTIONAL_REVISIONS[: needed + 1]


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
        if survey_library_on(settings):
            # LIB-1: off by default. With it off the library routes do not exist and no code is issued.
            app.include_router(survey_definitions.library_router)
        if survey_simulation_on(settings):
            # SS-03B: off by default. Simulation and call-plan assembly only; no route here can start a call.
            app.include_router(survey_simulations.router)
        if survey_assignment_on(settings):
            # ASG-1: off by default. Synthetic applications only; nothing here assigns a survey to a customer case.
            app.include_router(survey_assignments.router)
        if survey_assignment_groups_on(settings):
            # ASG-2A: off by default. Several surveys for one synthetic application; still assigns nothing.
            app.include_router(survey_assignment_groups.router)
        if survey_coordinated_simulation_on(settings):
            # ASG-2B: off by default. A coordinated SIMULATION; nothing here is or starts a call.
            app.include_router(survey_coordinated_simulations.router)
        if survey_evaluation_on(settings):
            # EVAL-1: off by default. Evaluation of SIMULATIONS; nothing operational is evaluated or written.
            app.include_router(survey_evaluations.router)
        if survey_control_policy_on(settings):
            # EVAL-2A: off by default. Governed control policies, applicability and coverage of SIMULATED journeys.
            app.include_router(survey_control_policies.router)
        if survey_execution_assurance_on(settings):
            # EVAL-2B: off by default. Verifies the RECORDED execution of simulated journeys; executes nothing.
            app.include_router(survey_execution_assurance.router)
            # E2E-1: read-only provenance of one simulated journey across the records above. No table, no write.
            app.include_router(survey_journey_trace.router)
    return app


def app_factory() -> FastAPI:  # used by `uvicorn --factory app.main:app_factory`
    return create_app()
