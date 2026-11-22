"""ASG-2A — governed requirement groups and SIMULATED composite plans (one application, several surveys).

ADDITIVE ONLY: five insert-only tables and one guard function. No existing table, row, constraint or trigger is
changed. Nothing of Script Studio is altered: a group member REFERS to a published assignment-rule version.

* ``survey_assignment_group``          a governed, versioned requirement: PRIMARY, ADD_REQUIRED or ALTERNATIVE, with
                                       a stated purpose and an optional governed position in an ordering.
* ``survey_assignment_group_member``   the exact published rule versions that compete to satisfy it.
* ``survey_assignment_group_event``    its lifecycle, as for a binding; the database refuses an approver who is the
                                       proposer and a publisher who is the proposer or the approver.
* ``survey_composite_plan``            one SIMULATED multi-survey selection and plan for a synthetic application.
                                       ``record_class`` is fixed to SIMULATION.
* ``survey_composite_plan_member``     each requirement of it, with the exact survey version, rule version, binding
                                       and individual call plan it refers to.

None references, or is referenced by, a callback case, script assignment, contact attempt, session or finding.

Revision ID: 0031_survey_assignment_groups
Revises: 0030_survey_assignment
"""

from __future__ import annotations

from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0031_survey_assignment_groups"
down_revision = "0030_survey_assignment"
branch_labels = None
depends_on = None

TABLES = (
    "survey_composite_plan_member", "survey_composite_plan", "survey_assignment_group_event",
    "survey_assignment_group_member", "survey_assignment_group",
)  # fmt: skip
SHA = "~ '^[0-9a-f]{64}$'"
EVENTS = "('PROPOSED', 'APPROVED', 'REJECTED', 'WITHDRAWN', 'PUBLISHED', 'SUPERSEDED')"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_group (
            id uuid PRIMARY KEY,
            code varchar(40) NOT NULL CHECK (code ~ '^[A-Z][A-Z0-9_-]{{2,39}}$'),
            version integer NOT NULL CHECK (version >= 1),
            market_code varchar(40) NOT NULL,
            kind varchar(16) NOT NULL CHECK (kind IN ('PRIMARY', 'ADD_REQUIRED', 'ALTERNATIVE')),
            name varchar(160) NOT NULL CHECK (length(btrim(name)) >= 3),
            purpose text NOT NULL CHECK (length(btrim(purpose)) >= 10),
            sequence integer CHECK (sequence IS NULL OR sequence >= 1),
            note text NOT NULL DEFAULT '',
            proposed_by varchar(80) NOT NULL,
            proposed_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (code, version)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_group_member (
            group_id uuid NOT NULL REFERENCES {s}.survey_assignment_group (id),
            rule_version_id uuid NOT NULL REFERENCES {s}.script_assignment_rule_version (id),
            rule_code varchar(40) NOT NULL,
            rule_version integer NOT NULL,
            PRIMARY KEY (group_id, rule_version_id)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_assignment_group_event (
            seq bigserial PRIMARY KEY,
            group_id uuid NOT NULL REFERENCES {s}.survey_assignment_group (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            occurred_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {s}.survey_assignment_group_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            last_event text;
            proposer text;
            approver text;
        BEGIN
            SELECT event INTO last_event FROM {s}.survey_assignment_group_event
             WHERE group_id = NEW.group_id ORDER BY seq DESC LIMIT 1;
            SELECT proposed_by INTO proposer FROM {s}.survey_assignment_group WHERE id = NEW.group_id;
            SELECT actor_ref INTO approver FROM {s}.survey_assignment_group_event
             WHERE group_id = NEW.group_id AND event = 'APPROVED' ORDER BY seq DESC LIMIT 1;
            IF NOT ((NEW.event = 'PROPOSED' AND last_event IS NULL)
                 OR (NEW.event IN ('APPROVED', 'REJECTED') AND last_event = 'PROPOSED')
                 OR (NEW.event = 'PUBLISHED' AND last_event = 'APPROVED')
                 OR (NEW.event = 'WITHDRAWN' AND last_event IN ('PROPOSED', 'APPROVED', 'PUBLISHED'))
                 OR (NEW.event = 'SUPERSEDED' AND last_event = 'PUBLISHED')) THEN
                RAISE EXCEPTION 'survey assignment group: % is not allowed after %', NEW.event, coalesce(last_event, 'nothing');
            END IF;
            IF NEW.event = 'PROPOSED' AND NEW.actor_ref <> proposer THEN
                RAISE EXCEPTION 'survey assignment group: only its proposer records the proposal';
            END IF;
            IF NEW.event IN ('APPROVED', 'REJECTED') AND NEW.actor_ref = proposer THEN
                RAISE EXCEPTION 'survey assignment group: the proposer cannot decide it';
            END IF;
            IF NEW.event = 'PUBLISHED' AND (NEW.actor_ref = proposer OR NEW.actor_ref = approver) THEN
                RAISE EXCEPTION 'survey assignment group: the proposer and the approver cannot publish it';
            END IF;
            RETURN NEW;
        END $$
        """
    )
    op.execute(
        f"CREATE TRIGGER survey_assignment_group_event_guard BEFORE INSERT ON {s}.survey_assignment_group_event "
        f"FOR EACH ROW EXECUTE FUNCTION {s}.survey_assignment_group_event_guard()"
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_composite_plan (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            market_code varchar(40) NOT NULL,
            assignment_inputs jsonb NOT NULL CHECK (jsonb_typeof(assignment_inputs) = 'object'),
            facts jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
            application_sha256 char(64) NOT NULL CHECK (application_sha256 {SHA}),
            evaluated_at timestamptz NOT NULL,
            contract varchar(64) NOT NULL,
            selection_status varchar(32) NOT NULL CHECK (selection_status IN
                ('RESOLVED', 'UNRESOLVED_REQUIREMENT', 'UNRESOLVED_CONFIGURATION')),
            ordering_status varchar(16) NOT NULL CHECK (ordering_status IN ('NOT_APPLICABLE', 'GOVERNED', 'UNRESOLVED')),
            plan_status varchar(32) NOT NULL CHECK (plan_status IN ('READY', 'BLOCKED', 'UNRESOLVED')),
            composite jsonb NOT NULL CHECK (jsonb_typeof(composite) = 'object'),
            fingerprint char(64) NOT NULL CHECK (fingerprint {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            -- a composite is READY or BLOCKED only when what it consists of, and in what order, is settled
            CHECK (plan_status = 'UNRESOLVED'
                   OR (selection_status = 'RESOLVED' AND ordering_status IN ('GOVERNED', 'NOT_APPLICABLE')))
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_composite_plan_member (
            composite_id uuid NOT NULL REFERENCES {s}.survey_composite_plan (id),
            position integer NOT NULL CHECK (position >= 1),
            group_id uuid NOT NULL REFERENCES {s}.survey_assignment_group (id),
            kind varchar(16) NOT NULL,
            state varchar(16) NOT NULL CHECK (state IN ('SELECTED', 'NOT_APPLICABLE', 'UNRESOLVED')),
            outcome varchar(32) NOT NULL,
            rule_version_id uuid REFERENCES {s}.script_assignment_rule_version (id),
            binding_id uuid REFERENCES {s}.survey_assignment_binding (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            call_plan_id uuid REFERENCES {s}.survey_call_plan (id),
            plan_fingerprint char(64) CHECK (plan_fingerprint IS NULL OR plan_fingerprint {SHA}),
            PRIMARY KEY (composite_id, position),
            -- a selected requirement names its exact version, rule, binding and plan; any other names none
            CHECK ((state = 'SELECTED') = (survey_version_id IS NOT NULL AND rule_version_id IS NOT NULL
                   AND binding_id IS NOT NULL AND call_plan_id IS NOT NULL AND plan_fingerprint IS NOT NULL))
        )
        """
    )
    op.execute(f"CREATE INDEX survey_assignment_group_code ON {s}.survey_assignment_group (code, version)")
    op.execute(f"CREATE INDEX survey_assignment_group_event_g ON {s}.survey_assignment_group_event (group_id, seq)")
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    if op.get_bind().exec_driver_sql(f"SELECT count(*) FROM {s}.survey_assignment_group").scalar():
        raise RuntimeError("Refusing to downgrade: governed survey assignment groups exist")
    for table in TABLES:
        op.drop_table(table, schema=s)
    op.execute(f"DROP FUNCTION {s}.survey_assignment_group_event_guard()")
