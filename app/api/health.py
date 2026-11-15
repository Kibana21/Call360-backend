"""Unauthenticated liveness/readiness probes that reveal no internal detail (API-001, API-002)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.schemas import HealthResponse
from app.db.guards import UnsafeDatabaseTarget, verify_connection
from app.domain.catalog import P_TABLES
from app.domain.protection import protection_for

router = APIRouter(tags=["health"])
# Table names come from the fixed CP0.2 catalogue; the connection's search_path is the verified schema.
_EXISTS = "EXISTS (SELECT 1 FROM {} WHERE NOT is_synthetic)"
NON_SYNTHETIC_SQL = "SELECT " + " OR ".join(_EXISTS.format(t) for t in P_TABLES)  # noqa: S608


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
            protection_for(conn, settings)  # D-34: keys present whenever the CP0.2 domain is
            # INV-10 / GOV-001: under SYNTHETIC_ONLY no business row may be non-synthetic (ADR-0008 §6).
            if conn.execute(text(NON_SYNTHETIC_SQL)).scalar():
                raise UnsafeDatabaseTarget("non-synthetic business data present")
    except Exception:
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return HealthResponse(status="ok")
