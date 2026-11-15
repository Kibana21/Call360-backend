"""Administration → Configuration APIs: API-022…025 (CP0.1B-1)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Path, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    CodeListList,
    CodeListOut,
    CodeListVersionCreate,
    CodeListVersionOut,
    CodeValueOut,
    ErrorResponse,
    FeatureFlagChangeOut,
    FeatureFlagList,
    FeatureFlagOut,
    FeatureFlagPatch,
)
from app.config.models import CodeList, CodeListVersion, FeatureFlag, FeatureFlagChange
from app.config.service import CURRENT_STAGE, ValueIn, create_version, set_flag, values_of
from app.core.errors import AppError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require
from app.security.models import Principal

router = APIRouter(prefix="/api/v1/admin", tags=["admin-config"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 428, 429)}


def _names(db: Session, ids: set[str]) -> dict[str, str]:
    uuids = []
    for i in ids:
        try:
            uuids.append(uuid.UUID(i))
        except ValueError:
            continue
    if not uuids:
        return {}
    rows = db.execute(select(Principal.id, Principal.display_name).where(Principal.id.in_(uuids))).all()
    return {str(pid): name for pid, name in rows}


def _list_view(db: Session, code_list: CodeList) -> CodeListOut:
    versions = (
        db.execute(
            select(CodeListVersion)
            .where(CodeListVersion.code_list_id == code_list.id)
            .order_by(CodeListVersion.version.desc())
        )
        .scalars()
        .all()
    )
    names = _names(db, {v.created_by for v in versions})
    out = [
        CodeListVersionOut(
            version=v.version,
            status=v.status,
            effective_from=v.effective_from,
            activated_at=v.activated_at,
            superseded_at=v.superseded_at,
            change_reason=v.change_reason,
            created_by=v.created_by,
            created_by_name=names.get(v.created_by),
            values=[
                CodeValueOut(code=c.code, label=c.label, attributes=c.attributes, sort_order=c.sort_order)
                for c in values_of(db, v.id)
            ],
        )
        for v in versions
    ]
    active = next((v.version for v in versions if v.status == "ACTIVE"), None)
    return CodeListOut(
        code=code_list.code,
        name=code_list.name,
        description=code_list.description,
        governed=code_list.governed,
        active_version=active,
        versions=out,
    )


def _flag_view(db: Session, flag: FeatureFlag) -> FeatureFlagOut:
    history = (
        db.execute(
            select(FeatureFlagChange)
            .where(FeatureFlagChange.feature_flag_id == flag.id)
            .order_by(FeatureFlagChange.id.desc())
        )
        .scalars()
        .all()
    )
    names = _names(db, {h.changed_by for h in history} | {flag.updated_by})
    return FeatureFlagOut(
        code=flag.code,
        description=flag.description,
        enabled=flag.enabled,
        stage_gate=flag.stage_gate,
        locked=flag.stage_gate > CURRENT_STAGE,
        row_version=flag.row_version,
        updated_at=flag.updated_at,
        updated_by=names.get(flag.updated_by, flag.updated_by),
        history=[
            FeatureFlagChangeOut(
                old_enabled=h.old_enabled,
                new_enabled=h.new_enabled,
                reason=h.reason,
                changed_by=h.changed_by,
                changed_by_name=names.get(h.changed_by),
                changed_at=h.changed_at,
            )
            for h in history
        ],
    )


def _write_guard(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"writes:{auth.principal_id}", settings.writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many changes; try again shortly", retryable=True)


@router.get("/code-lists", response_model=CodeListList, operation_id="admin_code_lists_list", responses=_ERR)
def list_code_lists(
    db: Session = Depends(get_db), _auth: AuthContext = Depends(require("config.read"))
) -> CodeListList:
    lists = db.execute(select(CodeList).order_by(CodeList.governed, CodeList.name)).scalars().all()
    return CodeListList(items=[_list_view(db, cl) for cl in lists])


@router.post(
    "/code-lists/{code}/versions",
    response_model=CodeListOut,
    operation_id="admin_code_lists_create_version",
    responses=_ERR,
    status_code=201,
)
@csrf_protected
def create_code_list_version(
    body: CodeListVersionCreate,
    request: Request,
    code: str = Path(min_length=1, max_length=64, pattern="^[a-z0-9_]+$"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("config.manage")),
) -> CodeListOut:
    _write_guard(request, auth)
    values = [ValueIn(v.code, v.label.strip(), dict(v.attributes), v.sort_order) for v in body.values]
    code_list = create_version(
        db,
        list_code=code,
        based_on_version=body.based_on_version,
        values=values,
        reason=body.reason.strip(),
        actor=auth.actor,
        meta=request_meta(request),
    )
    return _list_view(db, code_list)


@router.get("/feature-flags", response_model=FeatureFlagList, operation_id="admin_feature_flags_list", responses=_ERR)
def list_feature_flags(
    db: Session = Depends(get_db), _auth: AuthContext = Depends(require("config.read"))
) -> FeatureFlagList:
    flags = db.execute(select(FeatureFlag).order_by(FeatureFlag.stage_gate, FeatureFlag.code)).scalars().all()
    return FeatureFlagList(items=[_flag_view(db, f) for f in flags], current_stage=CURRENT_STAGE)


@router.patch(
    "/feature-flags/{code}", response_model=FeatureFlagOut, operation_id="admin_feature_flags_update", responses=_ERR
)
@csrf_protected
def update_feature_flag(
    body: FeatureFlagPatch,
    request: Request,
    code: str = Path(min_length=1, max_length=64, pattern="^[a-z0-9_.]+$"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("config.manage")),
    if_match: str | None = Header(None, alias="If-Match", max_length=20),
) -> FeatureFlagOut:
    _write_guard(request, auth)
    flag = set_flag(
        db,
        flag_code=code,
        enabled=body.enabled,
        if_match=if_match,
        reason=body.reason.strip(),
        actor=auth.actor,
        meta=request_meta(request),
    )
    return _flag_view(db, flag)
