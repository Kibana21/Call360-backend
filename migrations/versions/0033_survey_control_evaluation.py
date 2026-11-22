"""EVAL-1 — governed control mappings and JOURNEY-LEVEL control evaluation of synthetic simulations. SIMULATION ONLY.

ADDITIVE ONLY: six insert-only tables, one guard function, two permissions granted to nobody. No existing table, row,
constraint or trigger is changed. The control register (``control``) and the finding rule sets
(``finding_rule_set_version``) are only REFERRED to.

* ``survey_control_mapping``        one immutable revision of the governed mapping of ONE control of one market: how
                                    its evidence combines, when it applies, and which exact survey items (code and
                                    version) give it evidence under which rule of the existing S3-A rule language.
* ``survey_control_mapping_event``  its lifecycle: PROPOSED → APPROVED | REJECTED | WITHDRAWN → PUBLISHED →
                                    SUPERSEDED | WITHDRAWN. Proposer, approver and publisher are three people; the
                                    trigger enforces it whatever the service does.
* ``survey_journey_evaluation``     one evaluation run of one synthetic journey: a single-survey simulation OR a
                                    coordinated simulation. Pins every input. ``record_class`` fixed to SIMULATION.
* ``survey_control_result``         the atomic grain: one control instance in one evaluation.
* ``survey_evidence_observation``   one placement of one mapped item in one survey execution, as evidence of a control.
* ``survey_evaluation_finding``     a finding of the EXISTING finding engine and rule set, about one observation.

No row here references, or is referenced by, a callback case, contact attempt, conversation session, operational
survey run, script assignment, recording, transcript, operational ``finding`` or review. A new evaluation never
changes an old one.

Revision ID: 0033_survey_control_evaluation
Revises: 0032_survey_coordinated_sim
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0033_survey_control_evaluation"
down_revision = "0032_survey_coordinated_sim"
branch_labels = None
depends_on = None

TABLES = (
    "survey_evaluation_finding", "survey_evidence_observation", "survey_control_result", "survey_journey_evaluation",
    "survey_control_mapping_event", "survey_control_mapping",
)  # fmt: skip
SHA = "~ '^[0-9a-f]{64}$'"
PERMISSIONS = {
    "survey.evaluation.read": "Read governed control mappings and journey-level control evaluations of simulations (EVAL-1)",
    "survey.evaluate": "Evaluate a synthetic simulation journey against governed control mappings (EVAL-1; simulation only)",
}
EVENTS = "('PROPOSED', 'APPROVED', 'REJECTED', 'WITHDRAWN', 'PUBLISHED', 'SUPERSEDED')"
OUTCOMES = "('SATISFIED', 'NOT_SATISFIED', 'INSUFFICIENT_EVIDENCE', 'NOT_APPLICABLE', 'UNRESOLVED', 'REQUIRES_REVIEW')"
PROCESSING = "('COMPLETED', 'INCOMPLETE', 'REQUIRES_REVIEW', 'FAILED_TECHNICALLY')"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"""
        CREATE TABLE {s}.survey_control_mapping (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            control_id uuid NOT NULL REFERENCES {s}.control (id),
            control_code varchar(40) NOT NULL,
            -- the control register has no revisions: the fingerprint of the control row as it was when proposed
            control_sha256 char(64) NOT NULL CHECK (control_sha256 {SHA}),
            revision integer NOT NULL CHECK (revision >= 1),
            combination varchar(24) NOT NULL,
            applicability jsonb,
            entries jsonb NOT NULL CHECK (jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) >= 1),
            source text NOT NULL CHECK (length(btrim(source)) >= 10),
            mapping_sha256 char(64) NOT NULL CHECK (mapping_sha256 {SHA}),
            proposed_by varchar(80) NOT NULL,
            proposed_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (market_code, control_code, revision)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_control_mapping_event (
            seq bigserial PRIMARY KEY,
            mapping_id uuid NOT NULL REFERENCES {s}.survey_control_mapping (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            occurred_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {s}.survey_control_mapping_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            last_event text;
            proposer text;
            approver text;
        BEGIN
            SELECT event INTO last_event FROM {s}.survey_control_mapping_event
             WHERE mapping_id = NEW.mapping_id ORDER BY seq DESC LIMIT 1;
            SELECT proposed_by INTO proposer FROM {s}.survey_control_mapping WHERE id = NEW.mapping_id;
            SELECT actor_ref INTO approver FROM {s}.survey_control_mapping_event
             WHERE mapping_id = NEW.mapping_id AND event = 'APPROVED' ORDER BY seq DESC LIMIT 1;
            IF NOT ((NEW.event = 'PROPOSED' AND last_event IS NULL)
                 OR (NEW.event IN ('APPROVED', 'REJECTED') AND last_event = 'PROPOSED')
                 OR (NEW.event = 'PUBLISHED' AND last_event = 'APPROVED')
                 OR (NEW.event = 'WITHDRAWN' AND last_event IN ('PROPOSED', 'APPROVED', 'PUBLISHED'))
                 OR (NEW.event = 'SUPERSEDED' AND last_event = 'PUBLISHED')) THEN
                RAISE EXCEPTION 'survey control mapping: % is not allowed after %', NEW.event, coalesce(last_event, 'nothing');
            END IF;
            IF NEW.event = 'PROPOSED' AND NEW.actor_ref <> proposer THEN
                RAISE EXCEPTION 'survey control mapping: only its proposer records the proposal';
            END IF;
            IF NEW.event IN ('APPROVED', 'REJECTED') AND NEW.actor_ref = proposer THEN
                RAISE EXCEPTION 'survey control mapping: the proposer cannot decide it';
            END IF;
            IF NEW.event = 'PUBLISHED' AND (NEW.actor_ref = proposer OR NEW.actor_ref = approver) THEN
                RAISE EXCEPTION 'survey control mapping: the proposer and the approver cannot publish it';
            END IF;
            RETURN NEW;
        END $$
        """
    )
    op.execute(
        f"CREATE TRIGGER survey_control_mapping_event_guard BEFORE INSERT ON {s}.survey_control_mapping_event "
        f"FOR EACH ROW EXECUTE FUNCTION {s}.survey_control_mapping_event_guard()"
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_journey_evaluation (
            id uuid PRIMARY KEY,
            record_class varchar(16) NOT NULL DEFAULT 'SIMULATION' CHECK (record_class = 'SIMULATION'),
            market_code varchar(40) NOT NULL,
            journey_kind varchar(16) NOT NULL CHECK (journey_kind IN ('SINGLE_SURVEY', 'COORDINATED')),
            simulation_id uuid REFERENCES {s}.survey_simulation (id),
            coordinated_id uuid REFERENCES {s}.survey_coordinated_simulation (id),
            contract varchar(64) NOT NULL,
            -- everything the result was computed from: evidence fingerprints, mapping revisions, rule set, engines
            pins jsonb NOT NULL CHECK (jsonb_typeof(pins) = 'object'),
            input_sha256 char(64) NOT NULL CHECK (input_sha256 {SHA}),
            processing_status varchar(24) NOT NULL CHECK (processing_status IN {PROCESSING}),
            summary jsonb NOT NULL CHECK (jsonb_typeof(summary) = 'object'),
            result_sha256 char(64) NOT NULL CHECK (result_sha256 {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((journey_kind = 'SINGLE_SURVEY' AND simulation_id IS NOT NULL AND coordinated_id IS NULL)
                OR (journey_kind = 'COORDINATED' AND coordinated_id IS NOT NULL AND simulation_id IS NULL))
        )
        """
    )
    # the same journey evaluated from the same inputs is the same evaluation; a changed input is a new one
    op.execute(
        f"CREATE UNIQUE INDEX survey_journey_evaluation_single ON {s}.survey_journey_evaluation (simulation_id, input_sha256) WHERE simulation_id IS NOT NULL"
    )
    op.execute(
        f"CREATE UNIQUE INDEX survey_journey_evaluation_coordinated ON {s}.survey_journey_evaluation (coordinated_id, input_sha256) WHERE coordinated_id IS NOT NULL"
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_control_result (
            evaluation_id uuid NOT NULL REFERENCES {s}.survey_journey_evaluation (id),
            control_id uuid NOT NULL REFERENCES {s}.control (id),
            control_code varchar(40) NOT NULL,
            mapping_id uuid REFERENCES {s}.survey_control_mapping (id),
            outcome varchar(24) NOT NULL CHECK (outcome IN {OUTCOMES}),
            applicability varchar(16) NOT NULL CHECK (applicability IN ('APPLICABLE', 'NOT_APPLICABLE', 'UNKNOWN', 'NOT_DETERMINED')),
            detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
            PRIMARY KEY (evaluation_id, control_code)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_evidence_observation (
            evaluation_id uuid NOT NULL,
            seq integer NOT NULL CHECK (seq >= 1),
            control_code varchar(40) NOT NULL,
            simulation_id uuid REFERENCES {s}.survey_simulation (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            placement varchar(200),
            item_code varchar(80) NOT NULL,
            item_version integer NOT NULL,
            evidence_type varchar(16) NOT NULL CHECK (evidence_type IN ('ANSWER', 'DELIVERY')),
            result varchar(32) NOT NULL,
            detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object'),
            PRIMARY KEY (evaluation_id, seq),
            FOREIGN KEY (evaluation_id, control_code) REFERENCES {s}.survey_control_result (evaluation_id, control_code)
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE {s}.survey_evaluation_finding (
            evaluation_id uuid NOT NULL,
            finding_key char(64) NOT NULL CHECK (finding_key {SHA}),
            control_code varchar(40) NOT NULL,
            observation_seq integer NOT NULL,
            rule_set_version_id uuid NOT NULL REFERENCES {s}.finding_rule_set_version (id),
            rule_code varchar(60) NOT NULL,
            category varchar(40) NOT NULL,
            severity varchar(16) NOT NULL,
            finding jsonb NOT NULL CHECK (jsonb_typeof(finding) = 'object'),
            PRIMARY KEY (evaluation_id, finding_key),
            FOREIGN KEY (evaluation_id, observation_seq) REFERENCES {s}.survey_evidence_observation (evaluation_id, seq),
            FOREIGN KEY (evaluation_id, control_code) REFERENCES {s}.survey_control_result (evaluation_id, control_code)
        )
        """
    )
    op.execute(f"CREATE INDEX survey_control_mapping_event_m ON {s}.survey_control_mapping_event (mapping_id, seq)")
    for table in TABLES:
        op.execute(forbid_change_trigger(s, table))
    for code, description in PERMISSIONS.items():  # created, and granted to nobody
        op.get_bind().execute(
            sa.text(
                f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES (:i, :c, NULL, false, :d)"
            ),
            {"i": uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + code), "c": code, "d": description},
        )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    if op.get_bind().exec_driver_sql(f"SELECT count(*) FROM {s}.survey_control_mapping").scalar():
        # a governed decision is not thrown away by a schema change
        raise RuntimeError("Refusing to downgrade: governed control mappings exist")
    if op.get_bind().exec_driver_sql(f"SELECT count(*) FROM {s}.survey_journey_evaluation").scalar():
        # a recorded evaluation is historical evidence of what was evaluated, from what: it is not silently destroyed
        raise RuntimeError("Refusing to downgrade: recorded journey evaluations exist")
    for table in TABLES:
        op.drop_table(table, schema=s)
    op.execute(f"DROP FUNCTION {s}.survey_control_mapping_event_guard()")
    for code in PERMISSIONS:
        op.execute(
            f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code = '{code}')"
        )
        op.execute(f"DELETE FROM {s}.permission WHERE code = '{code}'")
