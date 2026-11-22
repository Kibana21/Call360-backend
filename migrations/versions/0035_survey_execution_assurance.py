"""EVAL-2B — EXECUTION ASSURANCE of synthetic journeys: whether the recorded execution followed its pinned plan.
SIMULATION ONLY.

PURELY ADDITIVE: two new insert-only tables. No existing table, column, key, index or trigger is changed; no
permission is added (the two evaluation permissions of migration 0033 are used).

* ``survey_execution_assurance``         one assurance run of one synthetic journey — a single-survey simulation or a
                                         coordinated simulation. Pins every input. ``record_class`` fixed to SIMULATION.
* ``survey_execution_assurance_survey``  the verification result of one survey execution of that journey: its status,
                                         every check, every delivery, exclusion, branch and refusal, by reference.

No row here references, or is referenced by, a callback case, contact attempt, conversation session, operational
survey run, recording, transcript, finding or review.

Revision ID: 0035_survey_execution_assurance
Revises: 0034_survey_control_policy
"""

from __future__ import annotations

from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0035_survey_execution_assurance"
down_revision = "0034_survey_control_policy"
branch_labels = None
depends_on = None

TABLES = ("survey_execution_assurance_survey", "survey_execution_assurance")
SHA = "~ '^[0-9a-f]{64}$'"
STATUSES = "('VERIFIED', 'INCOMPLETE', 'DEVIATION_DETECTED', 'INTEGRITY_FAILED', 'NOT_ASSESSABLE')"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_execution_assurance (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            market_code varchar(40) NOT NULL,
            journey_kind varchar(16) NOT NULL CHECK (journey_kind IN ('SINGLE_SURVEY', 'COORDINATED')),
            simulation_id uuid REFERENCES {s}.survey_simulation (id),
            coordinated_id uuid REFERENCES {s}.survey_coordinated_simulation (id),
            -- the control evaluation of the same journey this result is shown beside, when one was named
            evaluation_id uuid REFERENCES {s}.survey_journey_evaluation (id),
            contract varchar(64) NOT NULL,
            pins jsonb NOT NULL CHECK (jsonb_typeof(pins) = 'object'),
            input_sha256 char(64) NOT NULL CHECK (input_sha256 {SHA}),
            status varchar(24) NOT NULL CHECK (status IN {STATUSES}),
            summary jsonb NOT NULL CHECK (jsonb_typeof(summary) = 'object'),
            result_sha256 char(64) NOT NULL CHECK (result_sha256 {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((journey_kind = 'SINGLE_SURVEY' AND simulation_id IS NOT NULL AND coordinated_id IS NULL)
                OR (journey_kind = 'COORDINATED' AND coordinated_id IS NOT NULL AND simulation_id IS NULL))
        )
        """
    )
    op.execute(
        f"CREATE UNIQUE INDEX survey_execution_assurance_single ON {s}.survey_execution_assurance (simulation_id, input_sha256) WHERE simulation_id IS NOT NULL"
    )
    op.execute(
        f"CREATE UNIQUE INDEX survey_execution_assurance_coordinated ON {s}.survey_execution_assurance (coordinated_id, input_sha256) WHERE coordinated_id IS NOT NULL"
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_execution_assurance_survey (
            assurance_id uuid NOT NULL REFERENCES {s}.survey_execution_assurance (id),
            position integer NOT NULL CHECK (position >= 1),
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            simulation_id uuid REFERENCES {s}.survey_simulation (id),
            status varchar(24) NOT NULL CHECK (status IN {STATUSES}),
            detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
            PRIMARY KEY (assurance_id, position)
        )
        """
    )
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    if op.get_bind().exec_driver_sql(f"SELECT count(*) FROM {s}.survey_execution_assurance").scalar():
        # a recorded assurance result is evidence of what was verified, from what: it is not destroyed by a downgrade
        raise RuntimeError("Refusing to downgrade: recorded execution-assurance results exist")
    for table in TABLES:
        op.drop_table(table, schema=s)
