"""CP0.1B-1 configuration tables (S0_DATA_MODEL §4.1, Build = CP0.1B; D-25…D-28)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Identity, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

TS = DateTime(timezone=True)


class CodeList(Base):
    __tablename__ = "code_list"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    governed: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class CodeListVersion(Base):
    __tablename__ = "code_list_version"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_list_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("code_list.id"))
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    effective_from: Mapped[datetime] = mapped_column(TS)
    activated_at: Mapped[datetime | None] = mapped_column(TS)
    superseded_at: Mapped[datetime | None] = mapped_column(TS)
    change_reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class CodeValue(Base):
    __tablename__ = "code_value"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_list_version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("code_list_version.id"))
    code: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(120))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)


class FeatureFlag(Base):
    __tablename__ = "feature_flag"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    stage_gate: Mapped[str] = mapped_column(String(2))
    row_version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    updated_by: Mapped[str] = mapped_column(String(80))


class FeatureFlagChange(Base):
    __tablename__ = "feature_flag_change"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    feature_flag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("feature_flag.id"))
    old_enabled: Mapped[bool] = mapped_column(Boolean)
    new_enabled: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(String(80))
    changed_at: Mapped[datetime] = mapped_column(TS)
