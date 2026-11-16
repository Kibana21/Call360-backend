"""API-008 — the authenticated principal, roles, permissions and session (also covers API-007's data)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.schemas import EnvironmentInfo, ErrorResponse, MeResponse, PrincipalSummary, SessionInfo
from app.security.authz import AuthContext, authenticate

router = APIRouter(prefix="/api/v1", tags=["me"])


@router.get("/me", response_model=MeResponse, operation_id="me_get", responses={401: {"model": ErrorResponse}})
def get_me(request: Request, auth: AuthContext = Depends(authenticate)) -> MeResponse:
    s = auth.session
    settings = request.app.state.settings
    return MeResponse(
        principal=PrincipalSummary(
            principal_id=auth.principal_id, display_name=auth.display_name, username=auth.username
        ),
        roles=sorted(auth.roles),
        permissions=sorted(auth.permissions),
        markets=sorted(auth.markets),
        session=SessionInfo(
            session_id=s.id,
            created_at=s.created_at,
            idle_expires_at=s.idle_expires_at,
            absolute_expires_at=s.absolute_expires_at,
            access_expires_at=auth.access_expires_at,
        ),
        environment=EnvironmentInfo(app_env=settings.app_env, data_policy=settings.data_policy),
        password_change_required=auth.password_change_required,
    )
