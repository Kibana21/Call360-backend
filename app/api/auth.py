"""Authentication endpoints: API-003…006 (S0_API_CATALOGUE §1)."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    CsrfResponse,
    ErrorResponse,
    LoginRequest,
    LoginResponse,
    PrincipalSummary,
    RefreshResponse,
)
from app.audit.chain import Actor, write_audit
from app.core.errors import AppError, error_body
from app.security import csrf
from app.security.authz import get_db, request_meta, resolve_grants
from app.security.cookies import clear_session_cookies, set_session_cookies
from app.security.scope import resolve_markets
from app.security.service import RefreshSuperseded, login, logout, refresh
from app.security.tokens import TokenExpired, TokenInvalid

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
_ERR: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
}


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/csrf", response_model=CsrfResponse, operation_id="auth_csrf")
def get_csrf(request: Request, response: Response) -> CsrfResponse:
    names = request.app.state.cookies
    pre_nonce = secrets.token_urlsafe(18)
    token = csrf.issue(request.app.state.settings.csrf_secret.get_secret_value(), f"pre:{pre_nonce}")
    response.set_cookie(
        names.pre, pre_nonce, max_age=600, path="/api/v1/auth", httponly=True, secure=names.secure, samesite="strict"
    )
    response.set_cookie(
        names.csrf, token, max_age=600, path="/", httponly=False, secure=names.secure, samesite="strict"
    )
    return CsrfResponse(csrf_token=token)


@router.post("/login", response_model=LoginResponse, operation_id="auth_login", responses=_ERR)
@csrf_protected
def post_login(
    body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)
) -> LoginResponse:
    app = request.app
    settings, names = app.state.settings, app.state.cookies
    ip = _client_ip(request)
    if not app.state.limiter.allow(f"login-ip:{ip}", settings.login_ip_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many sign-in attempts. Try again later.", retryable=True)
    pre_nonce = request.cookies.get(names.pre, "")
    try:
        csrf.verify(request, settings.csrf_secret.get_secret_value(), f"pre:{pre_nonce}", names.csrf)
    except AppError:
        _audit_csrf_rejection(request, "login")
        raise
    issued = login(
        db,
        settings,
        app.state.tokens,
        username=body.username,
        password=body.password,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
        meta=request_meta(request),
    )
    roles, perms = resolve_grants(db, issued.principal.id, issued.session.created_at)
    set_session_cookies(
        response,
        names,
        access=issued.access_token,
        access_expires_at=issued.access_expires_at,
        refresh=issued.refresh_token,
        csrf=csrf.issue(settings.csrf_secret.get_secret_value(), f"sid:{issued.session.id}"),
        session_expires_at=issued.session.absolute_expires_at,
    )
    response.delete_cookie(names.pre, path="/api/v1/auth", secure=names.secure, httponly=True, samesite="strict")
    return LoginResponse(
        principal=PrincipalSummary(
            principal_id=issued.principal.id, display_name=issued.principal.display_name, username=issued.username
        ),
        roles=sorted(roles),
        permissions=sorted(perms),
        markets=sorted(resolve_markets(db, issued.principal.id, issued.session.created_at)),
        session_expires_at=issued.session.absolute_expires_at,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    operation_id="auth_refresh",
    responses={**_ERR, 409: {"model": ErrorResponse}},
)
@csrf_protected
def post_refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> RefreshResponse | JSONResponse:
    app = request.app
    settings, names = app.state.settings, app.state.cookies
    raw = request.cookies.get(names.refresh)
    if not raw:
        raise AppError(401, "AUTH_REFRESH_INVALID", "Refresh token is not valid")
    if not app.state.limiter.allow(f"refresh:{app.state.tokens.refresh_hmac(raw)}", settings.refresh_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many refresh attempts", retryable=True)
    session_id = _session_for_refresh(db, app, raw)
    if session_id is not None:
        csrf.verify(request, settings.csrf_secret.get_secret_value(), f"sid:{session_id}", names.csrf)
    try:
        issued = refresh(db, settings, app.state.tokens, raw_token=raw, meta=request_meta(request))
    except RefreshSuperseded:
        return JSONResponse(
            error_body(request, "REFRESH_SUPERSEDED", "Session already refreshed; retry with current cookies", True),
            status_code=status.HTTP_409_CONFLICT,
        )
    set_session_cookies(
        response,
        names,
        access=issued.access_token,
        access_expires_at=issued.access_expires_at,
        refresh=issued.refresh_token,
        csrf=None,
        session_expires_at=issued.session.absolute_expires_at,
    )
    return RefreshResponse(
        session_expires_at=issued.session.absolute_expires_at, access_expires_at=issued.access_expires_at
    )


def _session_for_refresh(db: Session, app: Any, raw: str) -> uuid.UUID | None:
    from sqlalchemy import select

    from app.security.models import RefreshToken, RefreshTokenFamily

    tokens = app.state.tokens
    return db.execute(
        select(RefreshTokenFamily.session_id)
        .join(RefreshToken, RefreshToken.family_id == RefreshTokenFamily.id)
        .where(RefreshToken.token_hmac == tokens.refresh_hmac(raw))
    ).scalar()


@router.post("/logout", status_code=204, operation_id="auth_logout", responses=_ERR)
@csrf_protected
def post_logout(request: Request, db: Session = Depends(get_db)) -> Response:
    app = request.app
    settings, names = app.state.settings, app.state.cookies
    response = Response(status_code=204)
    token = request.cookies.get(names.access)
    claims = None
    if token:
        try:
            claims = app.state.tokens.decode_access(token, allow_expired=True)
        except (TokenInvalid, TokenExpired):
            claims = None
    if claims is not None:
        csrf.verify(request, settings.csrf_secret.get_secret_value(), f"sid:{claims.session_id}", names.csrf)
        logout(
            db,
            session_id=claims.session_id,
            actor=Actor(claims.principal_id, session_id=claims.session_id),
            meta=request_meta(request),
        )
        db.commit()
    clear_session_cookies(response, names)
    return response


def _audit_csrf_rejection(request: Request, where: str) -> None:
    with request.app.state.session_factory() as db, db.begin():
        write_audit(
            db,
            action="SECURITY.CSRF_REJECTED",
            outcome="DENIED",
            meta=request_meta(request),
            entity_type="route",
            entity_id=where,
        )
