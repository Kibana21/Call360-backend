"""CP0.1B-2 market scope, reduced by D-39 (Singapore-only Stage 0): `group_scope_mapping` + seeded mappings.

LOCAL_ADMIN → SG and LOCAL_USER_SG → SG; LOCAL_USER_MY maps no market. Enabled markets are {SG}
(app.security.scope.ENABLED_MARKETS), so MY records are never exposed. Mappings are audited idempotently.

Revision ID: 0008_market_scope
Revises: 0007_governed_values
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.db.ddl import TS, market_trigger, uid
from app.security.scope import audit_scope_removal, seed_scope

revision = "0008_market_scope"
down_revision = "0007_governed_values"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "group_scope_mapping",
        sa.Column("id", uid(), primary_key=True),
        sa.Column("group_id", uid(), sa.ForeignKey(f"{s}.app_group.id"), nullable=False),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("effective_from", TS, nullable=False),
        sa.Column("effective_to", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("change_reason", sa.Text, nullable=False),
        sa.UniqueConstraint("group_id", "market_code", "effective_from", name="uq_group_scope_mapping"),
        sa.CheckConstraint("effective_to IS NULL OR effective_to > effective_from", name="ck_group_scope_interval"),
        schema=s,
    )
    op.execute(market_trigger(s, "group_scope_mapping"))
    seed_scope(op.get_bind(), s)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    audit_scope_removal(op.get_bind(), s)  # append-only history: the removal is audited, never erased
    op.drop_table("group_scope_mapping", schema=s)
