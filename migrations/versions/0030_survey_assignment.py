"""ASG-1 — governed binding of published assignment rules to published survey versions, and SIMULATED selections.

ADDITIVE ONLY: four insert-only tables and one guard function. No existing table, row, constraint or trigger is
changed — in particular nothing of Script Studio: the assignment-rule tables, their triggers and their data are only
REFERENCED (one foreign key from a new table to ``script_assignment_rule_version``).

* ``survey_assignment_binding``        "when this exact published rule version wins, the survey is this exact published
                                       survey version" — pinned by id and by content and manifest fingerprint.
* ``survey_assignment_binding_event``  its lifecycle: PROPOSED → APPROVED | REJECTED | WITHDRAWN → PUBLISHED →
                                       SUPERSEDED | WITHDRAWN. Append-only. The database refuses an approver who is
                                       the proposer, and a publisher who is the proposer or the approver.
* ``survey_assignment_evaluation``     one SIMULATED selection for a synthetic application: the inputs, the complete
                                       decision trace of the existing rule engine, the selected version and the plan.
                                       ``record_class`` is fixed to SIMULATION.
* ``survey_assignment_simulation``     which simulations were started from a selection.

Permission ``survey.assignment.read`` is created and granted to NO role. Reading the assignment policy — which shows
the conditions and precedence of published assignment rules — the bindings and the recorded selections needs it.
``survey.read`` alone does not: a person who may read surveys does not thereby read Script Studio's rules.

None of them references, or is referenced by, a callback case, contact attempt, conversation session, script
assignment, recording, transcript or finding. Nothing here assigns a survey to a customer.

Revision ID: 0030_survey_assignment
Revises: 0029_survey_simulation
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0030_survey_assignment"
down_revision = "0029_survey_simulation"
branch_labels = None
depends_on = None

TABLES = (
    "survey_assignment_simulation", "survey_assignment_evaluation", "survey_assignment_binding_event",
    "survey_assignment_binding",
)  # fmt: skip
SHA = "~ '^[0-9a-f]{64}$'"
PERMISSION = "survey.assignment.read"
PERMISSION_TEXT = "Read the survey assignment policy (published rules as they apply to surveys), bindings and simulated selections (ASG-1)"
EVENTS = "('PROPOSED', 'APPROVED', 'REJECTED', 'WITHDRAWN', 'PUBLISHED', 'SUPERSEDED')"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_binding (
            id uuid PRIMARY KEY,
            rule_version_id uuid NOT NULL REFERENCES {s}.script_assignment_rule_version (id),
            rule_code varchar(40) NOT NULL,
            rule_version integer NOT NULL,
            market_code varchar(40) NOT NULL,
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            survey_definition_id uuid NOT NULL REFERENCES {s}.survey_definition (id),
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            note text NOT NULL DEFAULT '',
            proposed_by varchar(80) NOT NULL,
            proposed_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_binding_event (
            seq bigserial PRIMARY KEY,
            binding_id uuid NOT NULL REFERENCES {s}.survey_assignment_binding (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            occurred_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {s}.survey_assignment_binding_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            last_event text;
            proposer text;
            approver text;
        BEGIN
            SELECT event INTO last_event FROM {s}.survey_assignment_binding_event
             WHERE binding_id = NEW.binding_id ORDER BY seq DESC LIMIT 1;
            SELECT proposed_by INTO proposer FROM {s}.survey_assignment_binding WHERE id = NEW.binding_id;
            SELECT actor_ref INTO approver FROM {s}.survey_assignment_binding_event
             WHERE binding_id = NEW.binding_id AND event = 'APPROVED' ORDER BY seq DESC LIMIT 1;
            IF NOT ((NEW.event = 'PROPOSED' AND last_event IS NULL)
                 OR (NEW.event IN ('APPROVED', 'REJECTED') AND last_event = 'PROPOSED')
                 OR (NEW.event = 'PUBLISHED' AND last_event = 'APPROVED')
                 OR (NEW.event = 'WITHDRAWN' AND last_event IN ('PROPOSED', 'APPROVED', 'PUBLISHED'))
                 OR (NEW.event = 'SUPERSEDED' AND last_event = 'PUBLISHED')) THEN
                RAISE EXCEPTION 'survey assignment binding: % is not allowed after %', NEW.event, coalesce(last_event, 'nothing');
            END IF;
            IF NEW.event = 'PROPOSED' AND NEW.actor_ref <> proposer THEN
                RAISE EXCEPTION 'survey assignment binding: only its proposer records the proposal';
            END IF;
            IF NEW.event IN ('APPROVED', 'REJECTED') AND NEW.actor_ref = proposer THEN
                RAISE EXCEPTION 'survey assignment binding: the proposer cannot decide it';
            END IF;
            IF NEW.event = 'PUBLISHED' AND (NEW.actor_ref = proposer OR NEW.actor_ref = approver) THEN
                RAISE EXCEPTION 'survey assignment binding: the proposer and the approver cannot publish it';
            END IF;
            RETURN NEW;
        END $$
        """
    )
    op.execute(
        f"CREATE TRIGGER survey_assignment_binding_event_guard BEFORE INSERT ON {s}.survey_assignment_binding_event "
        f"FOR EACH ROW EXECUTE FUNCTION {s}.survey_assignment_binding_event_guard()"
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_evaluation (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            market_code varchar(40) NOT NULL,
            assignment_inputs jsonb NOT NULL CHECK (jsonb_typeof(assignment_inputs) = 'object'),
            facts jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
            inputs_sha256 char(64) NOT NULL CHECK (inputs_sha256 {SHA}),
            evaluated_at timestamptz NOT NULL,
            engine varchar(80) NOT NULL,
            outcome varchar(32) NOT NULL,
            selection varchar(24) NOT NULL CHECK (selection IN
                ('MATCHED', 'NO_MATCH', 'AMBIGUOUS', 'UNKNOWN_INPUT', 'TARGET_UNAVAILABLE')),
            decision jsonb NOT NULL CHECK (jsonb_typeof(decision) = 'object'),
            decision_sha256 char(64) NOT NULL CHECK (decision_sha256 {SHA}),
            rule_version_id uuid REFERENCES {s}.script_assignment_rule_version (id),
            binding_id uuid REFERENCES {s}.survey_assignment_binding (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            call_plan_id uuid REFERENCES {s}.survey_call_plan (id),
            plan_fingerprint char(64) CHECK (plan_fingerprint IS NULL OR plan_fingerprint {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            -- a survey version is recorded exactly when the rules selected one
            CHECK ((selection = 'MATCHED') = (survey_version_id IS NOT NULL)),
            CHECK (call_plan_id IS NULL OR survey_version_id IS NOT NULL)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_simulation (
            evaluation_id uuid NOT NULL REFERENCES {s}.survey_assignment_evaluation (id),
            simulation_id uuid NOT NULL REFERENCES {s}.survey_simulation (id),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (evaluation_id, simulation_id)
        )
        """
    )
    op.execute(
        f"CREATE INDEX survey_assignment_binding_rule ON {s}.survey_assignment_binding (rule_code, rule_version)"
    )
    op.execute(
        f"CREATE INDEX survey_assignment_binding_event_b ON {s}.survey_assignment_binding_event (binding_id, seq)"
    )
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
    if op.get_bind().exec_driver_sql(f"SELECT count(*) FROM {s}.survey_assignment_binding").scalar():
        # a governed decision is not thrown away by a schema change
        raise RuntimeError("Refusing to downgrade: governed survey assignment bindings exist")
    for table in TABLES:
        op.drop_table(table, schema=s)
    op.execute(f"DROP FUNCTION {s}.survey_assignment_binding_event_guard()")
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN "
        f"(SELECT id FROM {s}.permission WHERE code = '{PERMISSION}')"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{PERMISSION}'")
