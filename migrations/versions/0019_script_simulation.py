"""S2-D: text simulation of the deterministic question controller.

Simulation records are deliberately separate from operational evidence: no ``contact_attempt``,
``conversation_session``, ``survey_run``, ``question_execution`` or ``answer_observation`` rows are created, so
simulations never affect case outcomes, holds, KPIs or compliance.

- ``script.simulate`` (USER and SC_CHECKER): run a text simulation on a case with a pinned script. ADMIN does not hold it.
- ``script_simulation_run``: one run (pinned script version and manifest checksum, policy fact snapshot, SBQ assessment,
  the callback contact selection and role used, the plan, status and outcome). Status and outcome change; the pins never
  change (trigger).
- ``script_simulation_event``: the insert-only, ordered event log; the run state is the replay of these events.

Revision ID: 0019_script_simulation
Revises: 0018_script_assignment_engine
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, sha256_check

revision = "0019_script_simulation"
down_revision = "0018_script_assignment_engine"
branch_labels = None
depends_on = None

CODE = "script.simulate"
STATUS = ("IN_PROGRESS", "SEQUENCE_FINISHED", "COMPLETED", "INCOMPLETE", "ABANDONED")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES "
        f"('{uuid.uuid5(uuid.NAMESPACE_URL, 'call360:permission:' + CODE)}', '{CODE}', NULL, false, "
        "'Run a text simulation of the question controller on a case with a pinned script (S2-D; no customer contact)')"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT r.id, p.id FROM {s}.role r, "
        f"{s}.permission p WHERE r.code IN ('USER', 'SC_CHECKER') AND p.code = '{CODE}'"
    )
    op.create_table(
        "script_simulation_run",
        pk(),
        sa.Column("sim_ref", sa.String(40), nullable=False, unique=True),
        fk("callback_case_id", "callback_case", s),
        fk("script_assignment_id", "script_assignment", s),
        fk("script_version_id", "script_version", s),
        sa.Column("script_manifest_sha256", sa.String(64), nullable=False),
        fk("policy_fact_snapshot_id", "policy_fact_snapshot", s),
        fk("risk_assessment_id", "risk_assessment", s, nullable=True),
        fk("contact_selection_id", "case_contact_selection", s, nullable=True),
        sa.Column("contact_role", sa.String(40)),
        sa.Column("plan", JSONB, nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("outcome", sa.String(24)),
        sa.Column("mode", sa.String(16), nullable=False, server_default="TEXT_SIMULATION"),
        sa.Column("started_by", sa.String(80), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("ended_at", TS),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        enum_check("status", STATUS, "ck_script_simulation_run_status"),
        enum_check(
            "outcome", ("COMPLETED", "INCOMPLETE", "ABANDONED"), "ck_script_simulation_run_outcome", nullable=True
        ),
        enum_check("mode", ("TEXT_SIMULATION",), "ck_script_simulation_run_mode"),
        sha256_check("script_manifest_sha256", "script_simulation_run"),
        sha256_check("plan_sha256", "script_simulation_run"),
        schema=s,
    )
    op.execute(
        f"CREATE INDEX ix_script_simulation_run_case ON {s}.script_simulation_run (callback_case_id, started_at)"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.script_simulation_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'simulation runs are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - ARRAY['status', 'outcome', 'ended_at', 'row_version'])
             IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'outcome', 'ended_at', 'row_version'])
             OR OLD.outcome IS NOT NULL THEN
            RAISE EXCEPTION 'simulation pins are immutable and an ended run is final' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER script_simulation_run_guard BEFORE UPDATE OR DELETE ON {s}.script_simulation_run
          FOR EACH ROW EXECUTE FUNCTION {s}.script_simulation_run_guard();
    """)
    op.create_table(
        "script_simulation_event",
        pk(),
        fk("run_id", "script_simulation_run", s),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("question_code", sa.String(60)),
        sa.Column("action_id", sa.String(80)),
        sa.Column("data", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("run_id", "seq", name="uq_script_simulation_event_seq"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "script_simulation_event"))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.script_simulation_run")).scalar_one():
        raise RuntimeError("simulation runs exist; downgrade would lose their traces")
    op.drop_table("script_simulation_event", schema=s)
    op.execute(f"DROP TRIGGER script_simulation_run_guard ON {s}.script_simulation_run")
    op.drop_table("script_simulation_run", schema=s)
    op.execute(f"DROP FUNCTION {s}.script_simulation_run_guard()")
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code = '{CODE}')"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{CODE}'")
