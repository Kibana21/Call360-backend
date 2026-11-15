"""Code-list versioning and feature-flag service (CP0.1B-1; D-25…D-28).

Governance is enforced here and in the database: governed lists cannot be versioned through the API,
the `market` code set is fixed, versions move DRAFT -> ACTIVE -> SUPERSEDED atomically, and stage-locked
flags cannot be enabled before their stage.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.config.models import CodeList, CodeListVersion, CodeValue, FeatureFlag, FeatureFlagChange
from app.core.errors import AppError

CURRENT_STAGE = "S0"  # Stage 0; flags gated to a later stage stay locked (D-27).
FIXED_CODE_SET_LISTS = frozenset({"market"})  # market codes become access scopes in CP0.1B-2 (D-25)
_CODE_RE = re.compile(r"^[A-Z0-9_]{1,40}$")


@dataclass(frozen=True)
class ValueIn:
    code: str
    label: str
    attributes: dict[str, Any]
    sort_order: int


def values_of(db: Session, version_id: uuid.UUID) -> list[CodeValue]:
    """Values of any version, active or historical (historical explainability, ADMIN-004)."""
    return list(
        db.execute(
            select(CodeValue)
            .where(CodeValue.code_list_version_id == version_id)
            .order_by(CodeValue.sort_order, CodeValue.code)
        ).scalars()
    )


def active_values(db: Session, list_code: str) -> list[CodeValue]:
    version = db.execute(
        select(CodeListVersion)
        .join(CodeList, CodeList.id == CodeListVersion.code_list_id)
        .where(CodeList.code == list_code, CodeListVersion.status == "ACTIVE")
    ).scalar()
    return values_of(db, version.id) if version else []


def _snapshot(values: Sequence[CodeValue | ValueIn]) -> list[dict[str, Any]]:
    rows = [{"code": v.code, "label": v.label, "attributes": v.attributes, "sort_order": v.sort_order} for v in values]
    return sorted(rows, key=lambda r: (r["sort_order"], r["code"]))


def create_version(
    db: Session,
    *,
    list_code: str,
    based_on_version: int,
    values: list[ValueIn],
    reason: str,
    actor: Actor,
    meta: RequestMeta,
) -> CodeList:
    code_list = db.execute(select(CodeList).where(CodeList.code == list_code).with_for_update()).scalar()
    if code_list is None:
        raise AppError(404, "NOT_FOUND", "Code list not found")
    if code_list.governed:
        write_audit(
            db,
            action="CONFIG.GOVERNED_CHANGE_DENIED",
            outcome="DENIED",
            actor=actor,
            meta=meta,
            entity_type="code_list",
            entity_id=list_code,
            reason=reason,
        )
        db.commit()
        raise AppError(
            403,
            "GOVERNED_LIST_READ_ONLY",
            "This list is business-governed and read-only until the approval workflow is available",
        )

    active = db.execute(
        select(CodeListVersion)
        .where(CodeListVersion.code_list_id == code_list.id, CodeListVersion.status == "ACTIVE")
        .with_for_update()
    ).scalar()
    if (active.version if active else 0) != based_on_version:
        raise AppError(409, "CONFLICT_STALE_VERSION", "The list changed since you loaded it; reload and retry")
    codes = [v.code for v in values]
    if any(not _CODE_RE.match(c) for c in codes):
        raise AppError(422, "VALIDATION_FAILED", "Codes must be 1–40 characters of A–Z, 0–9 or _")
    if len(set(codes)) != len(codes):
        raise AppError(422, "DUPLICATE_CODE", "Each code may appear only once")
    previous = values_of(db, active.id) if active else []
    if list_code in FIXED_CODE_SET_LISTS and set(codes) != {v.code for v in previous}:
        raise AppError(
            422,
            "CODE_SET_CHANGE_NOT_ALLOWED",
            "Codes in this list are fixed; only labels and display attributes can change",
        )
    if _snapshot(values) == _snapshot(previous):
        raise AppError(422, "NO_CHANGE", "The new version is identical to the active version")

    now = datetime.now(UTC)
    next_version = (
        db.execute(
            select(func.max(CodeListVersion.version)).where(CodeListVersion.code_list_id == code_list.id)
        ).scalar()
        or 0
    ) + 1
    new = CodeListVersion(
        id=uuid.uuid4(),
        code_list_id=code_list.id,
        version=next_version,
        status="DRAFT",
        effective_from=now,
        change_reason=reason,
        created_by=str(actor.principal_id),
    )
    db.add(new)
    db.flush()
    db.add_all(
        [
            CodeValue(
                code_list_version_id=new.id,
                code=v.code,
                label=v.label,
                attributes=v.attributes,
                sort_order=v.sort_order,
            )
            for v in values
        ]
    )
    db.flush()
    if active is not None:  # supersede first: at most one ACTIVE version per list
        active.status, active.superseded_at = "SUPERSEDED", now
        db.flush()
    new.status, new.activated_at = "ACTIVE", now
    db.flush()
    write_audit(
        db,
        action="CONFIG.CODE_LIST_VERSION_ACTIVATED",
        outcome="SUCCEEDED",
        actor=actor,
        meta=meta,
        entity_type="code_list",
        entity_id=list_code,
        entity_version=next_version,
        reason=reason,
        before={"version": active.version if active else None, "values": _snapshot(previous)},
        after={"version": next_version, "values": _snapshot(values)},
    )
    db.commit()
    return code_list


def set_flag(
    db: Session, *, flag_code: str, enabled: bool, if_match: str | None, reason: str, actor: Actor, meta: RequestMeta
) -> FeatureFlag:
    if if_match is None:
        raise AppError(428, "IF_MATCH_REQUIRED", "If-Match header with the row version is required")
    flag = db.execute(select(FeatureFlag).where(FeatureFlag.code == flag_code).with_for_update()).scalar()
    if flag is None:
        raise AppError(404, "NOT_FOUND", "Feature flag not found")
    if if_match.strip('"') != str(flag.row_version):
        raise AppError(409, "CONFLICT_ROW_VERSION", "This flag changed since you loaded it; reload and retry")
    if enabled == flag.enabled:
        raise AppError(422, "NO_CHANGE", "The flag already has this value")
    if enabled and flag.stage_gate > CURRENT_STAGE:
        write_audit(
            db,
            action="CONFIG.FLAG_STAGE_GATED_DENIED",
            outcome="DENIED",
            actor=actor,
            meta=meta,
            entity_type="feature_flag",
            entity_id=flag_code,
            reason=reason,
        )
        db.commit()
        raise AppError(422, "STAGE_GATED", f"This capability is not available before Stage {flag.stage_gate}")
    now = datetime.now(UTC)
    before = {"enabled": flag.enabled}
    flag.enabled, flag.row_version = enabled, flag.row_version + 1
    flag.updated_at, flag.updated_by = now, str(actor.principal_id)
    db.add(
        FeatureFlagChange(
            feature_flag_id=flag.id,
            old_enabled=before["enabled"],
            new_enabled=enabled,
            reason=reason,
            changed_by=str(actor.principal_id),
            changed_at=now,
        )
    )
    write_audit(
        db,
        action="CONFIG.FLAG_CHANGED",
        outcome="SUCCEEDED",
        actor=actor,
        meta=meta,
        entity_type="feature_flag",
        entity_id=flag_code,
        entity_version=flag.row_version,
        reason=reason,
        before=before,
        after={"enabled": enabled},
    )
    db.commit()
    return flag
