"""Request/response models. Requests forbid unknown fields (SEC-002)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class ErrorResponse(BaseModel):
    code: str
    message: str
    correlation_id: str | None
    retryable: bool
    details: list[dict[str, Any]] | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "not_ready"]


class CsrfResponse(BaseModel):
    csrf_token: str


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PrincipalSummary(BaseModel):
    principal_id: uuid.UUID
    display_name: str
    username: str | None


class SessionInfo(BaseModel):
    session_id: uuid.UUID
    created_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    access_expires_at: datetime


class EnvironmentInfo(BaseModel):
    app_env: str
    data_policy: str


class MeResponse(BaseModel):
    principal: PrincipalSummary
    roles: list[str]
    permissions: list[str]
    markets: list[str]
    session: SessionInfo
    environment: EnvironmentInfo


class LoginResponse(BaseModel):
    principal: PrincipalSummary
    roles: list[str]
    permissions: list[str]
    markets: list[str]
    session_expires_at: datetime


class RefreshResponse(BaseModel):
    session_expires_at: datetime
    access_expires_at: datetime


class PageInfo(BaseModel):
    next_cursor: str | None
    limit: int
    sort: str


class AdminUser(BaseModel):
    principal_id: uuid.UUID
    username: str | None
    display_name: str
    status: Literal["ACTIVE", "DISABLED"]
    groups: list[str]
    roles: list[str]
    created_at: datetime
    disabled_at: datetime | None
    last_login_at: datetime | None
    active_sessions: int
    row_version: int


class AdminUserList(BaseModel):
    items: list[AdminUser]
    page: PageInfo
    total: None = None


class AdminUserPatch(StrictModel):
    status: Literal["ACTIVE", "DISABLED"] | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=500)


class AuditEventOut(BaseModel):
    event_id: uuid.UUID
    seq: int
    occurred_at: datetime
    action: str
    outcome: str
    actor_principal_id: uuid.UUID | None
    actor_display_name: str | None
    actor_username: str | None
    actor_service: str | None
    session_id: uuid.UUID | None
    correlation_id: str | None
    source_ip: str | None
    entity_type: str | None
    entity_id: str | None
    entity_version: int | None
    reason: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class AuditEventList(BaseModel):
    items: list[AuditEventOut]
    page: PageInfo
    total: None = None


# ---- CP0.1B-1 configuration ------------------------------------------------------------------
AttributeValue = str | int | bool | None


class CodeValueIn(StrictModel):
    code: str = Field(min_length=1, max_length=40)
    label: str = Field(min_length=1, max_length=120)
    attributes: dict[str, AttributeValue] = Field(default_factory=dict, max_length=20)
    sort_order: int = Field(default=0, ge=0, le=100000)


class CodeListVersionCreate(StrictModel):
    based_on_version: int = Field(ge=0)
    values: list[CodeValueIn] = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=500)


class CodeValueOut(BaseModel):
    code: str
    label: str
    attributes: dict[str, Any]
    sort_order: int


class CodeListVersionOut(BaseModel):
    version: int
    status: Literal["DRAFT", "ACTIVE", "SUPERSEDED"]
    effective_from: datetime
    activated_at: datetime | None
    superseded_at: datetime | None
    change_reason: str
    created_by: str
    created_by_name: str | None
    values: list[CodeValueOut]


class CodeListOut(BaseModel):
    code: str
    name: str
    description: str
    governed: bool
    active_version: int | None
    versions: list[CodeListVersionOut]


class CodeListList(BaseModel):
    items: list[CodeListOut]


class FeatureFlagChangeOut(BaseModel):
    old_enabled: bool
    new_enabled: bool
    reason: str
    changed_by: str
    changed_by_name: str | None
    changed_at: datetime


class FeatureFlagOut(BaseModel):
    code: str
    description: str
    enabled: bool
    stage_gate: str
    locked: bool
    row_version: int
    updated_at: datetime
    updated_by: str
    history: list[FeatureFlagChangeOut]


class FeatureFlagList(BaseModel):
    items: list[FeatureFlagOut]
    current_stage: str


class FeatureFlagPatch(StrictModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=500)
