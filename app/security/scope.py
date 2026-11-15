"""Market scope (CP0.1B-2, reduced by D-39: Singapore-only Stage 0).

Effective scope = markets mapped to the principal's active groups ∩ ENABLED_MARKETS. In Stage 0 only `SG` is
enabled, so every principal (ADMIN included) sees SG records only; `MY` synthetic fixtures stay in PostgreSQL
and are never exposed. A principal with no effective market sees no business records. Out-of-scope or
missing objects return the same 404 and are audited (ACCESS.DENIED_OBJECT), so existence is never revealed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, and_, or_, select, text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.errors import AppError
from app.security.models import AppGroup, GroupMembership, GroupScopeMapping

ENABLED_MARKETS = frozenset({"SG"})  # D-39. Multi-market enablement is a later, explicit decision.

# Seeded mappings (no administration UI or API in Stage 0). LOCAL_USER_MY maps no market.
SEEDED_MAPPINGS = (("LOCAL_ADMIN", "SG"), ("LOCAL_USER_SG", "SG"))
NOT_FOUND_MESSAGE = "Not found or not available to you"


def resolve_markets(db: Session, principal_id: uuid.UUID, now: datetime) -> frozenset[str]:
    rows = db.execute(
        select(GroupScopeMapping.market_code)
        .select_from(GroupMembership)
        .join(AppGroup, and_(AppGroup.id == GroupMembership.group_id, AppGroup.status == "ACTIVE"))
        .join(GroupScopeMapping, GroupScopeMapping.group_id == AppGroup.id)
        .where(
            GroupMembership.principal_id == principal_id,
            GroupMembership.valid_from <= now,
            or_(GroupMembership.valid_to.is_(None), GroupMembership.valid_to > now),
            GroupScopeMapping.effective_from <= now,
            or_(GroupScopeMapping.effective_to.is_(None), GroupScopeMapping.effective_to > now),
        )
    ).scalars()
    return frozenset(rows) & ENABLED_MARKETS


def not_found(
    db: Session, *, actor: Actor, meta: RequestMeta, entity_type: str, entity_id: str, reason: str
) -> AppError:
    """Audit an object denial and return the uniform 404 (out of scope and missing look identical)."""
    write_audit(
        db,
        action="ACCESS.DENIED_OBJECT",
        outcome="DENIED",
        actor=actor,
        meta=meta,
        entity_type=entity_type,
        entity_id=entity_id[:64],
        reason=reason,
    )
    db.commit()
    return AppError(404, "NOT_FOUND", NOT_FOUND_MESSAGE)


def scoped_case(
    db: Session, case_id: uuid.UUID, markets: frozenset[str], *, actor: Actor, meta: RequestMeta
) -> dict[str, Any]:
    """Fetch one callback case inside the caller's scope or raise the uniform, audited 404."""
    row = (
        db.execute(
            text("SELECT id, case_ref, market_code, state FROM callback_case WHERE id = :i AND market_code = ANY(:m)"),
            {"i": case_id, "m": sorted(markets)},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise not_found(
            db,
            actor=actor,
            meta=meta,
            entity_type="callback_case",
            entity_id=str(case_id),
            reason="out of scope or missing",
        )
    return dict(row)


# ---- seed and bootstrap audit (migration 0008), idempotent like the governed-values bootstrap ---------------
ADDED, REMOVED = "added", "removed"
EFFECTIVE_FROM = datetime(2025, 11, 14, 16, 0, tzinfo=UTC)
NS = uuid.UUID("5d6c0a2e-3b1f-4c9e-9a51-360000000008")
REASON = "D-39 Singapore-only Stage 0: seeded group-to-market scope (no scope administration in S0)"


def mapping_id(group: str, market: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"{group}:{market}")


def _latest(conn: Connection, schema: str, mid: uuid.UUID) -> str | None:
    row = conn.execute(
        text(
            f"SELECT after FROM {schema}.audit_event WHERE action = 'ADMIN.GROUP_MAPPING_CHANGED' "  # noqa: S608
            "AND entity_type = 'group_scope_mapping' AND entity_id = :e ORDER BY seq DESC LIMIT 1"
        ),
        {"e": str(mid)},
    ).first()
    if row is None:
        return None
    return ADDED if isinstance(row.after, dict) else REMOVED


def _audit(conn: Connection, group: str, market: str, change: str) -> None:
    state = {"mapping_id": str(mapping_id(group, market)), "group": group, "market_code": market, "decision": "D-39"}
    write_audit(
        Session(bind=conn),
        action="ADMIN.GROUP_MAPPING_CHANGED",
        outcome="SUCCEEDED",
        actor=Actor(service="migration:0008_market_scope"),
        entity_type="group_scope_mapping",
        entity_id=str(mapping_id(group, market)),
        reason=REASON if change == ADDED else "Migration 0008 downgrade (development only): scope mapping removed",
        before=None if change == ADDED else state,
        after=state if change == ADDED else None,
    )


def seed_scope(conn: Connection, schema: str) -> None:
    assert schema in {"call360", "call360_test"}, schema
    for group, market in SEEDED_MAPPINGS:
        mid = mapping_id(group, market)
        conn.execute(
            text(
                f"INSERT INTO {schema}.group_scope_mapping (id, group_id, market_code, effective_from, created_by, "  # noqa: S608
                f"change_reason) SELECT :i, id, :m, :f, 'SYSTEM:migration-0008', :r FROM {schema}.app_group "
                "WHERE code = :g ON CONFLICT (id) DO NOTHING"
            ),
            {"i": mid, "m": market, "f": EFFECTIVE_FROM, "r": REASON, "g": group},
        )
        if _latest(conn, schema, mid) != ADDED:
            _audit(conn, group, market, ADDED)


def audit_scope_removal(conn: Connection, schema: str) -> None:
    assert schema in {"call360", "call360_test"}, schema
    for group, market in SEEDED_MAPPINGS:
        if _latest(conn, schema, mapping_id(group, market)) == ADDED:
            _audit(conn, group, market, REMOVED)
