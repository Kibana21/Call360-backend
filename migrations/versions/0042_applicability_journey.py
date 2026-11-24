"""APPL-X5a — coordinated execution of published surveys selected by a published Applicability Policy. Additive only:
five tables, five guards; NO permission.

Nothing existing is altered: no table, column, constraint, trigger or permission of an earlier revision. In
particular the legacy composite-plan, requirement-group, binding and coordinated-simulation tables, and the
evaluation and assurance tables, are not touched and not referenced.

* ``applicability_fact_correspondence`` — an immutable, numbered, SYNTHETIC declaration that an application fact (one
  published applicability variable version) is the same fact as a Survey Studio catalog field. IDENTITY only: no
  expression, no conversion. Insert only. It is not a dependency of any policy.
* ``applicability_selection_plan`` — the IMMUTABLE record of one selection: one exact published policy version, one
  synthetic fact snapshot, the evaluator's complete plan, and a fingerprint of each. ``selection_source`` is always
  ``APPLICABILITY``; ``record_class`` is always ``SYNTHETIC``.
* ``applicability_journey`` — one synthetic journey over one selection plan. What it froze never changes; only its
  status moves, one revision at a time, along the allowed transitions; what it froze at start is written once.
* ``applicability_journey_step`` — one selected survey at its position, at its exact published version, with the
  requirements it fulfils (several, for a declared shared delivery) and — once started — the ONE existing
  single-survey simulation that executes it. Its outcome is written once.
* ``applicability_journey_event`` — the append-only coordination history, with the idempotency key of a submission.

A journey is a SIMULATION over synthetic facts. Nothing here refers to a case, a sale, a customer, a session, a
callback, an assignment rule, a survey binding, a requirement group or a composite plan. Used only when
``applicability_journeys_enabled`` is on.

Revision ID: 0042_applicability_journey
Revises: 0041_applicability_publication
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042_applicability_journey"
down_revision = "0041_applicability_publication"
branch_labels = None
depends_on = None

SHA = "~ '^[0-9a-f]{64}$'"
OUTCOMES = ("SURVEYS_SELECTED", "NO_SURVEY_REQUIRED", "UNRESOLVED", "OUT_OF_SCOPE", "SCOPE_UNRESOLVED")
STATUS = (
    "READY", "RUNNING", "ALL_SURVEYS_COMPLETED", "CROSS_SURVEY_POLICY_UNRESOLVED", "ENDED_INCOMPLETE", "ABANDONED",
    "NO_SURVEY_REQUIRED", "SELECTION_UNRESOLVED", "OUT_OF_SCOPE", "SCOPE_UNRESOLVED",
)  # fmt: skip
EVENTS = (
    "CREATED", "STARTED", "STEP_STARTED", "INPUT_ACCEPTED", "INPUT_REJECTED", "SUBMISSION_REFUSED", "STEP_ENDED",
    "ENDED", "ABANDONED",
)  # fmt: skip
TABLES = (
    "applicability_journey_event",
    "applicability_journey_step",
    "applicability_journey",
    "applicability_selection_plan",
    "applicability_fact_correspondence",
)
FUNCTIONS = (
    "applicability_fact_correspondence_guard",
    "applicability_selection_plan_guard",
    "applicability_journey_guard",
    "applicability_journey_step_guard",
    "applicability_journey_event_guard",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(f"""
        CREATE TABLE {s}.applicability_fact_correspondence (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            code varchar(80) NOT NULL CHECK (code ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{{1,79}}$'),
            version_no integer NOT NULL CHECK (version_no >= 1),
            record_class varchar(16) NOT NULL DEFAULT 'SYNTHETIC' CHECK (record_class = 'SYNTHETIC'),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (market_code, code, version_no)
        );

        CREATE TABLE {s}.applicability_selection_plan (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            record_class varchar(16) NOT NULL DEFAULT 'SYNTHETIC' CHECK (record_class = 'SYNTHETIC'),
            selection_source varchar(16) NOT NULL DEFAULT 'APPLICABILITY' CHECK (selection_source = 'APPLICABILITY'),
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            policy_version_id uuid NOT NULL REFERENCES {s}.applicability_policy_version (id),
            version_no integer NOT NULL CHECK (version_no >= 1),
            version_status varchar(12) NOT NULL CHECK (version_status IN ('PUBLISHED', 'SUPERSEDED')),
            version_sha256 char(64) NOT NULL CHECK (version_sha256 {SHA}),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            facts jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
            facts_sha256 char(64) NOT NULL CHECK (facts_sha256 {SHA}),
            profiles jsonb NOT NULL CHECK (jsonb_typeof(profiles) = 'array'),
            origin jsonb NOT NULL DEFAULT '{{}}'::jsonb CHECK (jsonb_typeof(origin) = 'object'),
            evaluator_contract varchar(64) NOT NULL,
            plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
            plan_sha256 char(64) NOT NULL CHECK (plan_sha256 {SHA}),
            outcome varchar(20) NOT NULL CHECK (outcome IN {OUTCOMES}),
            record_sha256 char(64) NOT NULL CHECK (record_sha256 {SHA}),
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_applicability_selection_plan_version ON {s}.applicability_selection_plan (policy_version_id);

        CREATE TABLE {s}.applicability_journey (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            record_class varchar(16) NOT NULL DEFAULT 'SYNTHETIC' CHECK (record_class = 'SYNTHETIC'),
            selection_source varchar(16) NOT NULL DEFAULT 'APPLICABILITY' CHECK (selection_source = 'APPLICABILITY'),
            selection_plan_id uuid NOT NULL UNIQUE REFERENCES {s}.applicability_selection_plan (id),
            policy_version_id uuid NOT NULL REFERENCES {s}.applicability_policy_version (id),
            label varchar(160) NOT NULL DEFAULT '',
            status varchar(32) NOT NULL CHECK (status IN {STATUS}),
            revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
            correspondence_id uuid REFERENCES {s}.applicability_fact_correspondence (id),
            start_record jsonb,
            start_sha256 char(64) CHECK (start_sha256 {SHA}),
            survey_facts jsonb,
            survey_facts_sha256 char(64) CHECK (survey_facts_sha256 {SHA}),
            end_detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            created_by varchar(80) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_by varchar(80),
            started_at timestamptz,
            ended_at timestamptz,
            -- what a journey froze at start is there exactly when it has started
            CHECK ((start_record IS NULL) = (start_sha256 IS NULL) AND (start_record IS NULL) = (survey_facts IS NULL)
               AND (start_record IS NULL) = (survey_facts_sha256 IS NULL) AND (start_record IS NULL) = (started_at IS NULL)
               AND (start_record IS NULL) = (started_by IS NULL)),
            CHECK (correspondence_id IS NULL OR start_record IS NOT NULL)
        );
        CREATE INDEX ix_applicability_journey_market ON {s}.applicability_journey (market_code, created_at DESC);

        CREATE TABLE {s}.applicability_journey_step (
            id uuid PRIMARY KEY,
            journey_id uuid NOT NULL REFERENCES {s}.applicability_journey (id),
            position integer NOT NULL CHECK (position >= 1),
            survey_definition_id uuid NOT NULL REFERENCES {s}.survey_definition (id),
            survey_version_id uuid NOT NULL REFERENCES {s}.survey_version (id),
            survey_code varchar(80) NOT NULL,
            version_no integer NOT NULL CHECK (version_no >= 1),
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            required_by jsonb NOT NULL CHECK (jsonb_typeof(required_by) = 'array' AND jsonb_array_length(required_by) >= 1),
            obligations integer NOT NULL CHECK (obligations >= 1),
            status varchar(12) NOT NULL DEFAULT 'WAITING' CHECK (status IN ('WAITING', 'RUNNING', 'ENDED')),
            simulation_id uuid UNIQUE REFERENCES {s}.survey_simulation (id),
            outcome varchar(40),
            outcome_detail jsonb,
            started_at timestamptz,
            ended_at timestamptz,
            UNIQUE (journey_id, position),
            -- a survey is executed at most once per journey: a shared delivery is ONE step with several requirements
            UNIQUE (journey_id, survey_definition_id),
            CHECK ((status = 'WAITING') = (simulation_id IS NULL)),
            CHECK ((status = 'ENDED') = (outcome IS NOT NULL) AND (status = 'ENDED') = (ended_at IS NOT NULL))
        );

        CREATE TABLE {s}.applicability_journey_event (
            seq bigserial PRIMARY KEY,
            journey_id uuid NOT NULL REFERENCES {s}.applicability_journey (id),
            event varchar(20) NOT NULL CHECK (event IN {EVENTS}),
            step_position integer,
            actor_ref varchar(80) NOT NULL,
            idempotency_key varchar(80) CHECK (idempotency_key IS NULL OR length(idempotency_key) >= 8),
            request_sha256 char(64) CHECK (request_sha256 {SHA}),
            detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            occurred_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((idempotency_key IS NULL) = (request_sha256 IS NULL))
        );
        CREATE INDEX ix_applicability_journey_event ON {s}.applicability_journey_event (journey_id, seq);
        CREATE UNIQUE INDEX uq_applicability_journey_idempotency ON {s}.applicability_journey_event (journey_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL;
    """)
    op.execute(f"""
        CREATE FUNCTION {s}.applicability_fact_correspondence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'a fact correspondence version is never changed or deleted; save a new version'
            USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_fact_correspondence_guard BEFORE UPDATE OR DELETE
          ON {s}.applicability_fact_correspondence
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_fact_correspondence_guard();

        CREATE FUNCTION {s}.applicability_selection_plan_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'a selection plan is immutable evidence' USING ERRCODE = 'insufficient_privilege';
          END IF;
          -- the plan names a version that exists exactly as recorded: same policy, market, number and fingerprints
          IF NOT EXISTS (SELECT 1 FROM {s}.applicability_policy_version v
               WHERE v.id = NEW.policy_version_id AND v.policy_id = NEW.policy_id AND v.market_code = NEW.market_code
                 AND v.version_no = NEW.version_no AND v.version_sha256 = NEW.version_sha256
                 AND v.document_sha256 = NEW.document_sha256 AND v.manifest_sha256 = NEW.manifest_sha256) THEN
            RAISE EXCEPTION 'a selection plan records a published policy version of its own market, at its fingerprints'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_selection_plan_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_selection_plan
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_selection_plan_guard();

        CREATE FUNCTION {s}.applicability_journey_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE plan record; other text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a journey is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            SELECT market_code, policy_version_id, outcome INTO plan FROM {s}.applicability_selection_plan
              WHERE id = NEW.selection_plan_id;
            IF plan.market_code IS DISTINCT FROM NEW.market_code OR plan.policy_version_id IS DISTINCT FROM NEW.policy_version_id THEN
              RAISE EXCEPTION 'a journey belongs to its selection plan: same market, same policy version'
                USING ERRCODE = 'check_violation';
            END IF;
            -- execution may begin ONLY from a resolved selection that selected surveys
            IF NEW.status IS DISTINCT FROM (CASE plan.outcome WHEN 'SURVEYS_SELECTED' THEN 'READY'
                 WHEN 'NO_SURVEY_REQUIRED' THEN 'NO_SURVEY_REQUIRED' WHEN 'UNRESOLVED' THEN 'SELECTION_UNRESOLVED'
                 WHEN 'OUT_OF_SCOPE' THEN 'OUT_OF_SCOPE' ELSE 'SCOPE_UNRESOLVED' END)
               OR NEW.revision <> 1 OR NEW.start_record IS NOT NULL THEN
              RAISE EXCEPTION 'a journey starts in the state its selection plan allows' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (NEW.id, NEW.market_code, NEW.record_class, NEW.selection_source, NEW.selection_plan_id, NEW.policy_version_id,
              NEW.label, NEW.created_by, NEW.created_at)
             IS DISTINCT FROM
             (OLD.id, OLD.market_code, OLD.record_class, OLD.selection_source, OLD.selection_plan_id, OLD.policy_version_id,
              OLD.label, OLD.created_by, OLD.created_at) THEN
            RAISE EXCEPTION 'what a journey is never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'a journey moves one revision at a time' USING ERRCODE = 'check_violation';
          END IF;
          IF NOT ((OLD.status = 'READY' AND NEW.status IN ('RUNNING', 'ABANDONED'))
               OR (OLD.status = 'RUNNING' AND NEW.status IN ('RUNNING', 'ALL_SURVEYS_COMPLETED',
                     'CROSS_SURVEY_POLICY_UNRESOLVED', 'ENDED_INCOMPLETE', 'ABANDONED'))) THEN
            RAISE EXCEPTION 'a journey cannot go from % to %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          -- what was frozen at start is written exactly once, when the journey starts
          IF OLD.start_record IS NOT NULL OR OLD.status <> 'READY' OR NEW.status <> 'RUNNING' THEN
            IF (NEW.correspondence_id, NEW.start_record, NEW.start_sha256, NEW.survey_facts, NEW.survey_facts_sha256,
                NEW.started_by, NEW.started_at)
               IS DISTINCT FROM
               (OLD.correspondence_id, OLD.start_record, OLD.start_sha256, OLD.survey_facts, OLD.survey_facts_sha256,
                OLD.started_by, OLD.started_at) THEN
              RAISE EXCEPTION 'what a journey froze when it started never changes' USING ERRCODE = 'insufficient_privilege';
            END IF;
          ELSIF NEW.start_record IS NULL THEN
            RAISE EXCEPTION 'a running journey has its start record' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.correspondence_id IS NOT NULL THEN
            SELECT market_code INTO other FROM {s}.applicability_fact_correspondence WHERE id = NEW.correspondence_id;
            IF other IS DISTINCT FROM NEW.market_code THEN
              RAISE EXCEPTION 'a journey uses a fact correspondence of its own market' USING ERRCODE = 'check_violation';
            END IF;
          END IF;
          IF (NEW.status IN ('RUNNING', 'READY')) <> (NEW.ended_at IS NULL) THEN
            RAISE EXCEPTION 'a journey has an end time exactly when it has ended' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_journey_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_journey
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_journey_guard();

        CREATE FUNCTION {s}.applicability_journey_step_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE market text; other text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a journey step is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            SELECT market_code INTO market FROM {s}.applicability_journey WHERE id = NEW.journey_id;
            SELECT d.market_code INTO other FROM {s}.survey_definition d JOIN {s}.survey_version v
              ON v.survey_definition_id = d.id WHERE d.id = NEW.survey_definition_id AND v.id = NEW.survey_version_id
               AND v.version_no = NEW.version_no AND d.artifact_kind = 'SURVEY';
            IF other IS NULL OR other IS DISTINCT FROM market OR NEW.status <> 'WAITING' THEN
              RAISE EXCEPTION 'a step is a version of a survey of the journey''s own market, waiting to start'
                USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (NEW.id, NEW.journey_id, NEW.position, NEW.survey_definition_id, NEW.survey_version_id, NEW.survey_code,
              NEW.version_no, NEW.content_sha256, NEW.manifest_sha256, NEW.required_by, NEW.obligations)
             IS DISTINCT FROM
             (OLD.id, OLD.journey_id, OLD.position, OLD.survey_definition_id, OLD.survey_version_id, OLD.survey_code,
              OLD.version_no, OLD.content_sha256, OLD.manifest_sha256, OLD.required_by, OLD.obligations) THEN
            RAISE EXCEPTION 'what a step is never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status = 'WAITING' AND NEW.status = 'RUNNING' THEN
            -- the ONE simulation of this step: of exactly this survey version, at exactly these fingerprints
            IF NOT EXISTS (SELECT 1 FROM {s}.survey_simulation m WHERE m.id = NEW.simulation_id
                 AND m.survey_version_id = NEW.survey_version_id AND m.content_sha256 = NEW.content_sha256
                 AND m.manifest_sha256 = NEW.manifest_sha256) THEN
              RAISE EXCEPTION 'a step is executed by a simulation of its own pinned survey version'
                USING ERRCODE = 'check_violation';
            END IF;
          ELSIF OLD.status = 'RUNNING' AND NEW.status = 'ENDED' THEN
            IF NEW.simulation_id IS DISTINCT FROM OLD.simulation_id OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
              RAISE EXCEPTION 'the simulation of a step never changes' USING ERRCODE = 'insufficient_privilege';
            END IF;
          ELSE
            RAISE EXCEPTION 'a step cannot go from % to %', OLD.status, NEW.status USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_journey_step_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_journey_step
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_journey_step_guard();

        CREATE FUNCTION {s}.applicability_journey_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'the history of a journey is append-only' USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_journey_event_guard BEFORE UPDATE OR DELETE
          ON {s}.applicability_journey_event
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_journey_event_guard();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    for table in ("applicability_selection_plan", "applicability_fact_correspondence"):
        if conn.execute(sa.text(f"SELECT count(*) FROM {s}.{table}")).scalar_one():
            # a recorded selection, a journey and its history, and a correspondence a journey may have frozen are evidence
            raise RuntimeError(
                "selection plans or fact correspondences exist; downgrade would destroy recorded evidence"
            )
    for table in TABLES:
        op.execute(f"DROP TABLE {s}.{table}")
    for fn in FUNCTIONS:
        op.execute(f"DROP FUNCTION {s}.{fn}()")
