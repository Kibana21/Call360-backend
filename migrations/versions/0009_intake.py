"""CP0.4a intake ledger: `intake_run`, `intake_item`, `field_change` (S0_DATA_MODEL §4.6, Build = CP0.4).

Also adds the deferred foreign key from every provenance (**P**) table's ``intake_item_id`` to ``intake_item``
(app.db.ddl.provenance). All three tables are insert-only (ADR-0005 §3). ``field_change`` is created now and
written by corrections in CP0.4b. Downgrade refuses to run once intake rows exist (history is never erased).

Revision ID: 0009_intake
Revises: 0008_market_scope
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import SOURCE_TYPES, TS, enum_check, fk, forbid_change_trigger, market_trigger, pk, sha256_check, uid
from app.domain.catalog import P_TABLES

revision = "0009_intake"
down_revision = "0008_market_scope"
branch_labels = None
depends_on = None

RUN_STATUS = ("RECEIVED", "VALIDATING", "NORMALIZED", "PREVIEWED", "ACCEPTED", "REJECTED", "QUARANTINED", "RECONCILED")
ITEM_STATUS = ("ACCEPTED", "REJECTED", "QUARANTINED")
COUNTS = ("received", "new", "updated", "unchanged", "rejected", "quarantined")


def _insert_only() -> list[sa.Column[object]]:
    return [
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("correlation_id", sa.String(80)),
    ]


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "intake_run",
        pk(),
        sa.Column("run_ref", sa.String(40), nullable=False, unique=True),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("source_system", sa.String(80), nullable=False),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS),
        sa.Column("requested_by", sa.String(80), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        *(sa.Column(f"{c}_count", sa.Integer, nullable=False, server_default="0") for c in COUNTS),
        # Identifiers and routes of the records the run wrote (no personal data), returned on idempotent replay.
        sa.Column("result", JSONB, nullable=False, server_default="{}"),
        *_insert_only(),
        enum_check("source_type", SOURCE_TYPES, "ck_intake_run_source_type"),
        enum_check("status", RUN_STATUS, "ck_intake_run_status"),
        sha256_check("payload_digest", "intake_run"),
        *(sa.CheckConstraint(f"{c}_count >= 0", name=f"ck_intake_run_{c}_count") for c in COUNTS),
        schema=s,
    )
    op.create_index("ix_intake_run_started", "intake_run", ["started_at"], schema=s)
    op.create_table(
        "intake_item",
        pk(),
        fk("intake_run_id", "intake_run", s),
        sa.Column("source_system", sa.String(80), nullable=False),
        sa.Column("source_event_id", sa.String(160), nullable=False),
        sa.Column("entity_type", sa.String(24), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("errors", JSONB, nullable=False, server_default="[]"),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("raw_payload_ref", sa.String(160)),  # S0: hash only, no raw payload is stored
        *_insert_only(),
        enum_check("entity_type", ("SALE_TRANSACTION",), "ck_intake_item_entity_type"),
        enum_check("status", ITEM_STATUS, "ck_intake_item_status"),
        sha256_check("payload_digest", "intake_item"),
        schema=s,
    )
    # A source event is accepted once (duplicate/replay detection, intake lifecycle step 2).
    op.create_index(
        "ux_intake_item_source_event",
        "intake_item",
        ["source_system", "source_event_id"],
        unique=True,
        schema=s,
        postgresql_where=sa.text("status = 'ACCEPTED'"),
    )
    op.create_table(
        "field_change",
        pk(),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("entity_id", uid(), nullable=False),
        sa.Column("field", sa.String(80), nullable=False),
        sa.Column("old_value_redacted", sa.Text),
        sa.Column("new_value_redacted", sa.Text),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("changed_by", sa.String(80), nullable=False),
        sa.Column("changed_at", TS, nullable=False),
        fk("intake_item_id", "intake_item", s, nullable=True),
        *_insert_only(),
        enum_check("source_type", SOURCE_TYPES, "ck_field_change_source_type"),
        schema=s,
    )
    op.create_index("ix_field_change_entity", "field_change", ["entity_type", "entity_id"], schema=s)
    for table in P_TABLES:
        op.create_foreign_key(
            f"fk_{table}_intake_item",
            table,
            "intake_item",
            ["intake_item_id"],
            ["id"],
            source_schema=s,
            referent_schema=s,
        )
    op.execute(
        "\n".join(
            [
                forbid_change_trigger(s, "intake_run"),
                forbid_change_trigger(s, "intake_item"),
                forbid_change_trigger(s, "field_change"),
                market_trigger(s, "intake_run"),
            ]
        )
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    if op.get_bind().execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {s}.intake_run)")).scalar():  # noqa: S608
        raise RuntimeError("refusing to remove intake history: intake_run holds rows")
    for table in P_TABLES:
        op.drop_constraint(f"fk_{table}_intake_item", table, schema=s, type_="foreignkey")
    for table in ("field_change", "intake_item", "intake_run"):
        op.drop_table(table, schema=s)
