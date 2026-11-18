"""S2-E: callback simulation workbench (scenario library, automated runs, coverage, version comparison).

All tables are simulation records, separate from operational evidence (no contact attempt, session, survey run,
finding, hold, case state or KPI input). Permission ``script.simulate`` (USER, SC_CHECKER) covers them.

- ``simulation_scenario``: a named, reusable test scenario (status ACTIVE / ARCHIVED, current revision, optimistic
  concurrency). Only the pointer, status, name and row version change.
- ``simulation_scenario_revision``: insert-only. Each edit is a new revision: the script version tested, the synthetic
  facts and SBQ band (entered or copied from a synthetic case snapshot), ordered steps, expectations, the default
  response policy and the script content checksum at save time (stale detection).
- ``simulation_content_snapshot``: insert-only, content-addressed (SHA-256) copy of exactly the script content a run
  used — a draft's live content is snapshotted, so later draft edits never change a recorded run.
- ``simulation_batch`` / ``simulation_result``: insert-only records of automated runs (single, batch or a two-version
  comparison): scenario revision, script version, content snapshot, plan checksum, status, explained failures, actual
  outcome and the controller events.
- ``script_simulation_run``: interactive runs gain mode VERSION_TEST (any visible draft or published version on a
  synthetic case, from a content snapshot; no script assignment is read or written). TEXT_SIMULATION runs still require
  the case's pinned assignment.

Revision ID: 0021_simulation_workbench
Revises: 0020_conversation_lifecycle
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, sha256_check

revision = "0021_simulation_workbench"
down_revision = "0020_conversation_lifecycle"
branch_labels = None
depends_on = None

RESULT_STATUS = ("PASSED", "FAILED", "ERROR", "INVALID")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "simulation_scenario",
        pk(),
        sa.Column("scenario_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("market_code", sa.String(2), nullable=False),
        fk("script_family_id", "script_family", s),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="ACTIVE"),
        sa.Column("current_revision", sa.Integer, nullable=False, server_default="1"),
        fk("copied_from_id", "simulation_scenario", s, nullable=True),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        enum_check("status", ("ACTIVE", "ARCHIVED"), "ck_simulation_scenario_status"),
        sa.CheckConstraint("is_synthetic", name="ck_simulation_scenario_synthetic"),
        schema=s,
    )
    op.execute(f"""
        CREATE FUNCTION {s}.simulation_scenario_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'scenarios are archived, never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - ARRAY['name', 'status', 'current_revision', 'updated_at', 'row_version'])
             IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['name', 'status', 'current_revision', 'updated_at', 'row_version'])
          THEN
            RAISE EXCEPTION 'scenario identity is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER simulation_scenario_guard BEFORE UPDATE OR DELETE ON {s}.simulation_scenario
          FOR EACH ROW EXECUTE FUNCTION {s}.simulation_scenario_guard();
    """)
    op.create_table(
        "simulation_scenario_revision",
        pk(),
        fk("scenario_id", "simulation_scenario", s),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text),
        fk("script_version_id", "script_version", s),
        sa.Column("script_content_sha256", sa.String(64), nullable=False),
        sa.Column("facts", JSONB, nullable=False),
        sa.Column("risk_band", sa.String(16)),
        fk("source_case_id", "callback_case", s, nullable=True),
        sa.Column("source_snapshot_id", sa.Uuid, nullable=True),
        sa.Column("steps", JSONB, nullable=False),
        sa.Column("expectations", JSONB, nullable=False),
        sa.Column("default_response", sa.String(16), nullable=False),
        sa.Column("change_note", sa.String(300)),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("scenario_id", "revision", name="uq_simulation_scenario_revision"),
        enum_check("default_response", ("AFFIRMATIVE", "STRICT"), "ck_simulation_scenario_revision_default"),
        sha256_check("script_content_sha256", "simulation_scenario_revision"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_scenario_revision"))
    op.create_table(
        "simulation_content_snapshot",
        sa.Column("sha256", sa.String(64), primary_key=True),
        fk("script_version_id", "script_version", s),
        sa.Column("version_status", sa.String(16), nullable=False),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sha256_check("sha256", "simulation_content_snapshot"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_content_snapshot"))
    op.create_table(
        "simulation_batch",
        pk(),
        sa.Column("batch_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("market_code", sa.String(2), nullable=False),
        sa.Column("kind", sa.String(12), nullable=False),
        fk("version_a_id", "script_version", s, nullable=True),
        fk("version_b_id", "script_version", s, nullable=True),
        sa.Column("totals", JSONB, nullable=False),
        sa.Column("started_by", sa.String(80), nullable=False),
        sa.Column("started_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check("kind", ("RUN", "COMPARISON"), "ck_simulation_batch_kind"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_batch"))
    op.create_table(
        "simulation_result",
        pk(),
        fk("batch_id", "simulation_batch", s),
        sa.Column("side", sa.String(1), nullable=False, server_default="A"),
        fk("scenario_id", "simulation_scenario", s),
        fk("scenario_revision_id", "simulation_scenario_revision", s),
        fk("script_version_id", "script_version", s),
        sa.Column(
            "content_sha256", sa.String(64), sa.ForeignKey(f"{s}.simulation_content_snapshot.sha256"), nullable=True
        ),
        sa.Column("plan_sha256", sa.String(64)),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("stale", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("stale_reasons", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("problems", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("failures", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("error", sa.Text),
        sa.Column("actual", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("response_log", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("events", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check("status", RESULT_STATUS, "ck_simulation_result_status"),
        enum_check("side", ("A", "B"), "ck_simulation_result_side"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_result"))
    op.execute(f"CREATE INDEX ix_simulation_result_batch ON {s}.simulation_result (batch_id)")
    op.execute(f"CREATE INDEX ix_simulation_result_scenario ON {s}.simulation_result (scenario_id, created_at)")
    # Interactive version testing (no assignment): widen the run mode and relax the assignment pin for it only.
    op.execute(f"ALTER TABLE {s}.script_simulation_run ALTER COLUMN script_assignment_id DROP NOT NULL")
    op.execute(f"ALTER TABLE {s}.script_simulation_run DROP CONSTRAINT ck_script_simulation_run_mode")
    op.execute(
        f"ALTER TABLE {s}.script_simulation_run ADD CONSTRAINT ck_script_simulation_run_mode "
        "CHECK (mode IN ('TEXT_SIMULATION', 'VERSION_TEST'))"
    )
    op.execute(
        f"ALTER TABLE {s}.script_simulation_run ADD CONSTRAINT ck_script_simulation_run_pin "
        "CHECK (mode = 'VERSION_TEST' OR script_assignment_id IS NOT NULL)"
    )
    op.add_column(
        "script_simulation_run",
        sa.Column(
            "content_sha256", sa.String(64), sa.ForeignKey(f"{s}.simulation_content_snapshot.sha256"), nullable=True
        ),
        schema=s,
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.simulation_scenario) + (SELECT count(*) FROM {s}.simulation_batch) + "
            f"(SELECT count(*) FROM {s}.script_simulation_run WHERE mode = 'VERSION_TEST')"
        )
    ).scalar_one()
    if used:
        raise RuntimeError("workbench scenarios, results or version-test runs exist; downgrade would lose them")
    op.drop_column("script_simulation_run", "content_sha256", schema=s)
    op.execute(f"ALTER TABLE {s}.script_simulation_run DROP CONSTRAINT ck_script_simulation_run_pin")
    op.execute(f"ALTER TABLE {s}.script_simulation_run DROP CONSTRAINT ck_script_simulation_run_mode")
    op.execute(
        f"ALTER TABLE {s}.script_simulation_run ADD CONSTRAINT ck_script_simulation_run_mode "
        "CHECK (mode IN ('TEXT_SIMULATION'))"
    )
    op.execute(f"ALTER TABLE {s}.script_simulation_run ALTER COLUMN script_assignment_id SET NOT NULL")
    for t in ("simulation_result", "simulation_batch", "simulation_content_snapshot", "simulation_scenario_revision"):
        op.drop_table(t, schema=s)
    op.execute(f"DROP TRIGGER simulation_scenario_guard ON {s}.simulation_scenario")
    op.drop_table("simulation_scenario", schema=s)
    op.execute(f"DROP FUNCTION {s}.simulation_scenario_guard()")
