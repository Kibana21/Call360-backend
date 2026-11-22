"""ASG-2B — COORDINATED SIMULATION of the surveys of one composite plan. SIMULATION ONLY.

ADDITIVE ONLY: two insert-only tables. No existing table, row, constraint or trigger is changed.

* ``survey_coordinated_simulation``       one coordinated simulation: the composite plan it runs, the fingerprints it
                                          was started from, the governed order. ``record_class`` fixed to SIMULATION.
* ``survey_coordinated_simulation_step``  each individual SS-03B simulation the coordinator STARTED, in order, with
                                          why it was started. The run of each survey is its own ``survey_simulation``
                                          with its own inputs, trace and fingerprint; a step only refers to it.

Nothing is stored that could drift: the state of a coordinated simulation is computed from its steps and from the
replay of each individual simulation. No row here references, or is referenced by, a callback case, contact attempt,
conversation session, operational survey run, script assignment, recording, transcript or finding.

Revision ID: 0032_survey_coordinated_sim
Revises: 0031_survey_assignment_groups
"""

from __future__ import annotations

from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0032_survey_coordinated_sim"
down_revision = "0031_survey_assignment_groups"
branch_labels = None
depends_on = None

TABLES = ("survey_coordinated_simulation_step", "survey_coordinated_simulation")
SHA = "~ '^[0-9a-f]{64}$'"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_coordinated_simulation (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            composite_plan_id uuid NOT NULL REFERENCES {s}.survey_composite_plan (id),
            market_code varchar(40) NOT NULL,
            application_sha256 char(64) NOT NULL CHECK (application_sha256 {SHA}),
            composite_fingerprint char(64) NOT NULL CHECK (composite_fingerprint {SHA}),
            contract varchar(64) NOT NULL,
            governed_order jsonb NOT NULL CHECK (jsonb_typeof(governed_order) = 'array' AND jsonb_array_length(governed_order) >= 1),
            label varchar(160) NOT NULL DEFAULT '',
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_coordinated_simulation_step (
            coordinated_id uuid NOT NULL REFERENCES {s}.survey_coordinated_simulation (id),
            position integer NOT NULL CHECK (position >= 1),
            group_id uuid NOT NULL REFERENCES {s}.survey_assignment_group (id),
            group_code varchar(40) NOT NULL,
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            simulation_id uuid NOT NULL UNIQUE REFERENCES {s}.survey_simulation (id),
            -- why the coordinator started this survey: the first in the governed order, or the one before it COMPLETED
            started_because varchar(32) NOT NULL CHECK (started_because IN ('FIRST_IN_ORDER', 'PREVIOUS_COMPLETED')),
            started_by varchar(80) NOT NULL,
            started_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (coordinated_id, position),
            CHECK ((position = 1) = (started_because = 'FIRST_IN_ORDER'))
        )
        """
    )
    op.execute(
        f"CREATE INDEX survey_coordinated_simulation_plan ON {s}.survey_coordinated_simulation (composite_plan_id, created_at)"
    )
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    # simulation records are not evidence of anything operational, and no governed decision lives here
    for table in TABLES:
        op.drop_table(table, schema=s)
