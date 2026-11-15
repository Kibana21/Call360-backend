"""CP0.1B-1 configuration foundation: versioned code lists and feature flags (5 tables, additive).

Revision ID: 0002_config_foundation
Revises: 0001_identity_foundation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.config.seed import seed_config

revision = "0002_config_foundation"
down_revision = "0001_identity_foundation"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    schema = op.get_context().version_table_schema
    assert schema in {"call360", "call360_test"}, schema
    uid = UUID(as_uuid=True)
    op.create_table(
        "code_list",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("governed", sa.Boolean, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        schema=schema,
    )
    op.create_table(
        "code_list_version",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code_list_id", uid, sa.ForeignKey(f"{schema}.code_list.id"), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("effective_from", TS, nullable=False),
        sa.Column("activated_at", TS),
        sa.Column("superseded_at", TS),
        sa.Column("change_reason", sa.Text, nullable=False),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("code_list_id", "version"),
        sa.CheckConstraint("status IN ('DRAFT','ACTIVE','SUPERSEDED')", name="ck_code_list_version_status"),
        sa.CheckConstraint("version >= 1", name="ck_code_list_version_positive"),
        schema=schema,
    )
    op.create_index(
        "ux_code_list_one_active",
        "code_list_version",
        ["code_list_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )
    op.create_table(
        "code_value",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code_list_version_id", uid, sa.ForeignKey(f"{schema}.code_list_version.id"), nullable=False),
        sa.Column("code", sa.String(40), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("attributes", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.UniqueConstraint("code_list_version_id", "code"),
        schema=schema,
    )
    op.create_table(
        "feature_flag",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("stage_gate", sa.String(2), nullable=False),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(80), nullable=False),
        sa.CheckConstraint("stage_gate IN ('S0','S1','S2','S3','S4','S5','S6')", name="ck_feature_flag_stage"),
        # Stage lock (D-27): in Stage 0 only S0-gated flags may be enabled. Each later stage's migration
        # moves this boundary; the API enforces the same rule.
        sa.CheckConstraint("NOT enabled OR stage_gate <= 'S0'", name="ck_feature_flag_stage_lock"),
        schema=schema,
    )
    op.create_table(
        "feature_flag_change",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("feature_flag_id", uid, sa.ForeignKey(f"{schema}.feature_flag.id"), nullable=False),
        sa.Column("old_enabled", sa.Boolean, nullable=False),
        sa.Column("new_enabled", sa.Boolean, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("changed_by", sa.String(80), nullable=False),
        sa.Column("changed_at", TS, nullable=False),
        schema=schema,
    )

    # Lifecycle and immutability (D-28): DRAFT -> ACTIVE -> SUPERSEDED, one-way; content frozen once non-draft.
    op.execute(f"""
        CREATE FUNCTION {schema}.code_list_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'code_list_version % is % and cannot be deleted', OLD.id, OLD.status
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN OLD;
          END IF;
          IF NEW.code_list_id IS DISTINCT FROM OLD.code_list_id OR NEW.version IS DISTINCT FROM OLD.version
             OR NEW.effective_from IS DISTINCT FROM OLD.effective_from
             OR NEW.change_reason IS DISTINCT FROM OLD.change_reason
             OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'code_list_version content is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NOT ((OLD.status = 'DRAFT' AND NEW.status IN ('DRAFT', 'ACTIVE'))
               OR (OLD.status = 'ACTIVE' AND NEW.status = 'SUPERSEDED')) THEN
            RAISE EXCEPTION 'invalid code_list_version transition % -> %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER code_list_version_guard BEFORE UPDATE OR DELETE ON {schema}.code_list_version
          FOR EACH ROW EXECUTE FUNCTION {schema}.code_list_version_guard();

        CREATE FUNCTION {schema}.code_value_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE v_status text;
        BEGIN
          SELECT status INTO v_status FROM {schema}.code_list_version
            WHERE id = CASE WHEN TG_OP = 'INSERT' THEN NEW.code_list_version_id ELSE OLD.code_list_version_id END;
          IF v_status IS DISTINCT FROM 'DRAFT' THEN
            RAISE EXCEPTION 'code_value of a % version is immutable', v_status USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END $$;
        CREATE TRIGGER code_value_guard BEFORE INSERT OR UPDATE OR DELETE ON {schema}.code_value
          FOR EACH ROW EXECUTE FUNCTION {schema}.code_value_guard();

        CREATE FUNCTION {schema}.feature_flag_change_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'feature_flag_change is append-only' USING ERRCODE = 'insufficient_privilege'; END $$;
        CREATE TRIGGER feature_flag_change_append_only BEFORE UPDATE OR DELETE ON {schema}.feature_flag_change
          FOR EACH ROW EXECUTE FUNCTION {schema}.feature_flag_change_append_only();
    """)
    seed_config(op.get_bind(), schema)


def downgrade() -> None:
    schema = op.get_context().version_table_schema
    assert schema in {"call360", "call360_test"}, schema
    for table in ("feature_flag_change", "feature_flag", "code_value", "code_list_version", "code_list"):
        op.drop_table(table, schema=schema)
    for fn in ("code_list_version_guard", "code_value_guard", "feature_flag_change_append_only"):
        op.execute(f"DROP FUNCTION IF EXISTS {schema}.{fn}()")
