"""SS-03B — isolated records of survey SIMULATIONS and computed call plans.

ADDITIVE ONLY: three insert-only tables. No existing table, row or reference is changed. Used only when
``survey_simulation_enabled`` is on.

These tables hold SIMULATION records and nothing else. They reference a published survey version and a fact snapshot
that was supplied for the simulation; they have **no foreign key to, and no column naming, any operational record** —
no callback case, contact attempt, conversation session, operational survey run, recording, transcript or finding. A
CHECK constraint fixes ``record_class`` to ``SIMULATION`` on every row, so a simulation can never be stored as, or
mistaken for, operational evidence.

* ``survey_simulation``        one simulation: the version, its manifest and content fingerprints, the immutable facts.
* ``survey_simulation_input``  every input given to it, in order, accepted or refused. Append-only; the run is the
                               deterministic replay of these, so it can always be reproduced exactly.
* ``survey_call_plan``         one computed plan: the version, the facts, the plan document and its fingerprint.

Every simulation records the EXECUTION CONTRACT it was computed under and the fingerprint of its run before any input,
and every input the fingerprint of the run after it. A run is recomputed on reading; if the recomputed fingerprint is
not the recorded one the simulation is reported as DRIFTED and takes no further input. It never silently appears
unchanged.

Permission ``survey.simulate`` is created and granted to NO role: creating and advancing a simulation, and generating a
call plan, need it. ``survey.read`` alone can only read.

Revision ID: 0029_survey_simulation
Revises: 0028_survey_library
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0029_survey_simulation"
down_revision = "0028_survey_library"
branch_labels = None
depends_on = None

TABLES = ("survey_simulation_input", "survey_simulation", "survey_call_plan")
PERMISSION = "survey.simulate"
PERMISSION_TEXT = "Create and advance survey simulations and generate simulated call plans; simulation only (SS-03B)"
SHA = "~ '^[0-9a-f]{64}$'"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_simulation (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            survey_definition_id uuid NOT NULL REFERENCES {s}.survey_definition (id),
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            facts jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
            facts_sha256 char(64) NOT NULL CHECK (facts_sha256 {SHA}),
            engine_contract varchar(64) NOT NULL,
            initial_run_sha256 char(64) NOT NULL CHECK (initial_run_sha256 {SHA}),
            label varchar(160) NOT NULL DEFAULT '',
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_simulation_input (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            simulation_id uuid NOT NULL REFERENCES {s}.survey_simulation (id),
            seq integer NOT NULL CHECK (seq >= 1),
            item_key varchar(200) NOT NULL,
            answer jsonb NOT NULL CHECK (jsonb_typeof(answer) = 'object'),
            accepted boolean NOT NULL,
            rejection_code varchar(64),
            run_status varchar(24) NOT NULL,
            run_sha256 char(64) NOT NULL CHECK (run_sha256 {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (simulation_id, seq),
            CHECK (accepted = (rejection_code IS NULL))
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_call_plan (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            survey_definition_id uuid NOT NULL REFERENCES {s}.survey_definition (id),
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            facts jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
            facts_sha256 char(64) NOT NULL CHECK (facts_sha256 {SHA}),
            plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
            plan_status varchar(16) NOT NULL CHECK (plan_status IN ('READY', 'BLOCKED')),
            plan_contract varchar(64) NOT NULL,
            fingerprint char(64) NOT NULL CHECK (fingerprint {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(f"CREATE INDEX survey_simulation_version ON {s}.survey_simulation (survey_version_id, created_at)")
    op.execute(f"CREATE INDEX survey_call_plan_version ON {s}.survey_call_plan (survey_version_id, created_at)")
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))
    op.get_bind().execute(  # created, and granted to nobody
        sa.text(
            f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES (:i, :c, NULL, false, :d)"
        ),
        {
            "i": uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + PERMISSION),
            "c": PERMISSION,
            "d": PERMISSION_TEXT,
        },
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    # simulation records are not evidence of anything operational: they may be dropped with the tables
    for table in TABLES:
        op.drop_table(table, schema=s)
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN "
        f"(SELECT id FROM {s}.permission WHERE code = '{PERMISSION}')"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{PERMISSION}'")
