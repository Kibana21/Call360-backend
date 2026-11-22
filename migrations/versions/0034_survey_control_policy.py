"""EVAL-2A — governed CONTROL POLICIES and policy-scoped evaluation results. SIMULATION ONLY.

PURELY ADDITIVE: six new insert-only tables and one guard function. NO existing table is altered — not the control
register, not any Script Studio or operational table, and not the EVAL-1 result tables: an evaluation recorded
before this revision, or without a policy after it, is stored and read exactly as before, row for row.

* ``survey_control_policy``          one immutable revision of a control policy of one market: its scope, whether its
                                     list of controls is declared complete, and for each control of the register its
                                     purpose, obligations, applicability and required evidence.
* ``survey_control_policy_event``    its lifecycle; proposer, approver and publisher are three people (trigger).
* ``survey_evaluation_policy``       which policy revision a journey evaluation was made under. An evaluation with no
                                     row here was made without a policy (every EVAL-1 evaluation).
* ``survey_obligation_result``       the control instance of a policy-scoped evaluation: one OBLIGATION of one control
                                     — key (evaluation, control, obligation), so two obligations are two results.
* ``survey_obligation_observation``  one evidence observation of such an instance.
* ``survey_obligation_finding``      a finding of the existing finding engine about such an observation.

(An earlier draft of this revision added an ``obligation`` column to the three EVAL-1 result tables and replaced
their keys. It was never applied outside the test schema and was withdrawn: historical evaluation evidence is not
restructured.)

Revision ID: 0034_survey_control_policy
Revises: 0033_survey_control_evaluation
"""

from __future__ import annotations

from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0034_survey_control_policy"
down_revision = "0033_survey_control_evaluation"
branch_labels = None
depends_on = None

TABLES = (
    "survey_obligation_finding", "survey_obligation_observation", "survey_obligation_result", "survey_evaluation_policy",
    "survey_control_policy_event", "survey_control_policy",
)  # fmt: skip
SHA = "~ '^[0-9a-f]{64}$'"
EVENTS = "('PROPOSED', 'APPROVED', 'REJECTED', 'WITHDRAWN', 'PUBLISHED', 'SUPERSEDED')"
OUTCOMES = "('SATISFIED', 'NOT_SATISFIED', 'INSUFFICIENT_EVIDENCE', 'NOT_APPLICABLE', 'UNRESOLVED', 'REQUIRES_REVIEW')"
COVERAGE = (
    "('EVIDENCED', 'EVIDENCE_MISSING', 'NOT_MAPPED', 'APPLICABILITY_UNKNOWN', 'EVIDENCE_CONFLICTING', "
    "'EVALUATION_UNSUPPORTED', 'HUMAN_ASSESSMENT_PENDING', 'INTEGRITY_FAILED', 'NOT_REQUIRED')"
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_control_policy (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            code varchar(40) NOT NULL CHECK (code ~ '^[A-Z][A-Z0-9-]{{2,39}}$'),
            revision integer NOT NULL CHECK (revision >= 1),
            name varchar(160) NOT NULL CHECK (length(btrim(name)) >= 3),
            scope_statement text NOT NULL CHECK (length(btrim(scope_statement)) >= 10),
            scope jsonb,
            completeness varchar(24) NOT NULL CHECK (completeness IN ('DECLARED_COMPLETE', 'PARTIAL')),
            empty_set_is_complete boolean NOT NULL DEFAULT false,
            controls jsonb NOT NULL CHECK (jsonb_typeof(controls) = 'array' AND jsonb_array_length(controls) >= 1),
            owner varchar(160) NOT NULL CHECK (length(btrim(owner)) >= 2),
            source text NOT NULL CHECK (length(btrim(source)) >= 10),
            policy_sha256 char(64) NOT NULL CHECK (policy_sha256 {SHA}),
            proposed_by varchar(80) NOT NULL,
            proposed_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (market_code, code, revision)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_control_policy_event (
            seq bigserial PRIMARY KEY,
            policy_id uuid NOT NULL REFERENCES {s}.survey_control_policy (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            occurred_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {s}.survey_control_policy_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            last_event text;
            proposer text;
            approver text;
        BEGIN
            SELECT event INTO last_event FROM {s}.survey_control_policy_event
             WHERE policy_id = NEW.policy_id ORDER BY seq DESC LIMIT 1;
            SELECT proposed_by INTO proposer FROM {s}.survey_control_policy WHERE id = NEW.policy_id;
            SELECT actor_ref INTO approver FROM {s}.survey_control_policy_event
             WHERE policy_id = NEW.policy_id AND event = 'APPROVED' ORDER BY seq DESC LIMIT 1;
            IF NOT ((NEW.event = 'PROPOSED' AND last_event IS NULL)
                 OR (NEW.event IN ('APPROVED', 'REJECTED') AND last_event = 'PROPOSED')
                 OR (NEW.event = 'PUBLISHED' AND last_event = 'APPROVED')
                 OR (NEW.event = 'WITHDRAWN' AND last_event IN ('PROPOSED', 'APPROVED', 'PUBLISHED'))
                 OR (NEW.event = 'SUPERSEDED' AND last_event = 'PUBLISHED')) THEN
                RAISE EXCEPTION 'survey control policy: % is not allowed after %', NEW.event, coalesce(last_event, 'nothing');
            END IF;
            IF NEW.event = 'PROPOSED' AND NEW.actor_ref <> proposer THEN
                RAISE EXCEPTION 'survey control policy: only its proposer records the proposal';
            END IF;
            IF NEW.event IN ('APPROVED', 'REJECTED') AND NEW.actor_ref = proposer THEN
                RAISE EXCEPTION 'survey control policy: the proposer cannot decide it';
            END IF;
            IF NEW.event = 'PUBLISHED' AND (NEW.actor_ref = proposer OR NEW.actor_ref = approver) THEN
                RAISE EXCEPTION 'survey control policy: the proposer and the approver cannot publish it';
            END IF;
            RETURN NEW;
        END $$
        """
    )
    op.execute(
        f"CREATE TRIGGER survey_control_policy_event_guard BEFORE INSERT ON {s}.survey_control_policy_event "
        f"FOR EACH ROW EXECUTE FUNCTION {s}.survey_control_policy_event_guard()"
    )
    op.execute(f"CREATE INDEX survey_control_policy_event_p ON {s}.survey_control_policy_event (policy_id, seq)")
    op.execute(
        f"""
        CREATE TABLE {s}.survey_evaluation_policy (
            evaluation_id uuid PRIMARY KEY REFERENCES {s}.survey_journey_evaluation (id),
            control_policy_id uuid NOT NULL REFERENCES {s}.survey_control_policy (id),
            policy_sha256 char(64) NOT NULL CHECK (policy_sha256 {SHA})
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_obligation_result (
            evaluation_id uuid NOT NULL REFERENCES {s}.survey_evaluation_policy (evaluation_id),
            control_id uuid NOT NULL REFERENCES {s}.control (id),
            control_code varchar(40) NOT NULL,
            obligation varchar(40) NOT NULL CHECK (length(obligation) >= 1),
            mapping_id uuid REFERENCES {s}.survey_control_mapping (id),
            outcome varchar(24) NOT NULL CHECK (outcome IN {OUTCOMES}),
            applicability varchar(16) NOT NULL CHECK (applicability IN ('APPLICABLE', 'NOT_APPLICABLE', 'UNKNOWN')),
            coverage varchar(32) NOT NULL CHECK (coverage IN {COVERAGE}),
            detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
            PRIMARY KEY (evaluation_id, control_code, obligation)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_obligation_observation (
            evaluation_id uuid NOT NULL,
            seq integer NOT NULL CHECK (seq >= 1),
            control_code varchar(40) NOT NULL,
            obligation varchar(40) NOT NULL,
            requirement varchar(40) NOT NULL,
            simulation_id uuid REFERENCES {s}.survey_simulation (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            placement varchar(200),
            item_code varchar(80) NOT NULL,
            item_version integer NOT NULL,
            evidence_type varchar(16) NOT NULL CHECK (evidence_type IN ('ANSWER', 'DELIVERY')),
            result varchar(32) NOT NULL,
            detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
            PRIMARY KEY (evaluation_id, seq),
            FOREIGN KEY (evaluation_id, control_code, obligation)
                REFERENCES {s}.survey_obligation_result (evaluation_id, control_code, obligation)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_obligation_finding (
            evaluation_id uuid NOT NULL,
            finding_key char(64) NOT NULL CHECK (finding_key {SHA}),
            control_code varchar(40) NOT NULL,
            obligation varchar(40) NOT NULL,
            observation_seq integer NOT NULL,
            rule_set_version_id uuid NOT NULL REFERENCES {s}.finding_rule_set_version (id),
            rule_code varchar(60) NOT NULL,
            category varchar(40) NOT NULL,
            severity varchar(16) NOT NULL,
            finding jsonb NOT NULL CHECK (jsonb_typeof(finding) = 'object'),
            PRIMARY KEY (evaluation_id, finding_key),
            FOREIGN KEY (evaluation_id, observation_seq) REFERENCES {s}.survey_obligation_observation (evaluation_id, seq),
            FOREIGN KEY (evaluation_id, control_code, obligation)
                REFERENCES {s}.survey_obligation_result (evaluation_id, control_code, obligation)
        )
        """
    )
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    bind = op.get_bind()
    if bind.exec_driver_sql(f"SELECT count(*) FROM {s}.survey_control_policy").scalar():
        # a governed decision is not thrown away by a schema change
        raise RuntimeError("Refusing to downgrade: governed control policies exist")
    if bind.exec_driver_sql(f"SELECT count(*) FROM {s}.survey_evaluation_policy").scalar():
        # immutable evaluation evidence is never destroyed by a downgrade
        raise RuntimeError("Refusing to downgrade: evaluations recorded under a control policy exist")
    for table in TABLES:
        op.drop_table(table, schema=s)
    op.execute(f"DROP FUNCTION {s}.survey_control_policy_event_guard()")
