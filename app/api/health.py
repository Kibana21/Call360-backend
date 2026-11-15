"""Unauthenticated liveness/readiness probes that reveal no internal detail (API-001, API-002)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.schemas import HealthResponse
from app.db.guards import UnsafeDatabaseTarget, verify_connection

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse, operation_id="health_live")
def live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    operation_id="health_ready",
    responses={503: {"model": HealthResponse}},
)
def ready(request: Request) -> HealthResponse | JSONResponse:
    settings = request.app.state.settings
    try:
        with request.app.state.engine.connect() as conn:
            verify_connection(conn, settings)
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        if version != request.app.state.expected_migration_head or settings.data_policy != "SYNTHETIC_ONLY":
            raise UnsafeDatabaseTarget("not at migration head")
    except Exception:
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return HealthResponse(status="ok")
