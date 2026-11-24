"""APPL-X4a — persistent synthetic scenarios, regression suites and recorded evaluation runs. Additive only.

Seven tables, six guards; NO permission; nothing existing is altered. Publication of policies is NOT here (APPL-X4b):
there is no policy candidate and no published policy version in these tables.

* ``applicability_scenario`` — one saved SYNTHETIC application: a stable identity (market and code never change) and
  one working draft (``document``: name, description, profiles, typed facts, pins), a monotonic ``draft_revision``,
  and ``snapshot`` — the exact library definitions (variable and profile versions, with fingerprints) that give the
  facts their meaning. ``purpose`` separates a REGRESSION scenario (may gate publication later) from an EXPLORATORY
  one. ``baseline_id`` makes a variant a genuine saved scenario that knows what it varies. There is NO column for a
  customer, an operational policy number, a case or a call session: ``record_class`` is always ``SYNTHETIC``.
* ``applicability_scenario_dependency`` — the snapshot as rows, with FOREIGN KEYS to the library, written in the same
  transaction as the document.
* ``applicability_suite`` — a named, ordered regression dataset FOR ONE POLICY; ``purpose`` PUBLICATION_GATING or
  EXPLORATORY.
* ``applicability_suite_member`` — a scenario in a suite, its position, and the EXPECTED outcome a person stated
  (never derived silently from a result).
* ``applicability_scenario_event`` — the append-only history of scenarios and suites.
* ``applicability_evaluation_run`` / ``applicability_evaluation_result`` — IMMUTABLE evidence: the exact policy
  revision and dependency manifest, the definitions the evaluator read, each scenario exactly as it was, what was
  expected, what the evaluator returned, and the verdict. A run never changes and is never deleted; a new run is a new
  row.

Used only when ``applicability_scenarios_enabled`` is on. No assignment rule, survey binding or requirement group is
read or written, and nothing here refers to a case, a sale, a contact attempt or a session.

Revision ID: 0040_applicability_scenarios
Revises: 0039_applicability_policy
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040_applicability_scenarios"
down_revision = "0039_applicability_policy"
branch_labels = None
depends_on = None

SHA = "~ '^[0-9a-f]{64}$'"
CODE = "~ '^[A-Za-z][A-Za-z0-9_.-]{1,59}$'"
EVENTS = ("CREATED", "DRAFT_SAVED", "ARCHIVED", "RESTORED")
RUN_STATUS = ("PASSED", "FAILED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION")
RESULT = ("PASSED", "FAILED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION", "NO_EXPECTATION")
TABLES = (
    "applicability_evaluation_result",
    "applicability_evaluation_run",
    "applicability_scenario_event",
    "applicability_suite_member",
    "applicability_suite",
    "applicability_scenario_dependency",
    "applicability_scenario",
)
FUNCTIONS = (
    "applicability_scenario_guard",
    "applicability_scenario_dependency_guard",
    "applicability_suite_member_guard",
    "applicability_scenario_event_guard",
    "applicability_evaluation_guard",
    "applicability_evaluation_result_guard",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(f"""
        CREATE TABLE {s}.applicability_scenario (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            code varchar(60) NOT NULL CHECK (code {CODE}),
            record_class varchar(12) NOT NULL DEFAULT 'SYNTHETIC' CHECK (record_class = 'SYNTHETIC'),
            purpose varchar(12) NOT NULL DEFAULT 'REGRESSION' CHECK (purpose IN ('REGRESSION', 'EXPLORATORY')),
            policy_id uuid REFERENCES {s}.applicability_policy (id),
            baseline_id uuid REFERENCES {s}.applicability_scenario (id),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            snapshot_sha256 char(64) NOT NULL CHECK (snapshot_sha256 {SHA}),
            draft_revision integer NOT NULL DEFAULT 1 CHECK (draft_revision >= 1),
            draft_updated_at timestamptz NOT NULL DEFAULT now(),
            draft_updated_by varchar(80) NOT NULL,
            archived_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by varchar(80) NOT NULL,
            CHECK (baseline_id IS DISTINCT FROM id)
        );
        CREATE UNIQUE INDEX uq_applicability_scenario_identity ON {s}.applicability_scenario (market_code, lower(code));
        CREATE INDEX ix_applicability_scenario_policy ON {s}.applicability_scenario (policy_id, draft_updated_at DESC);
        CREATE INDEX ix_applicability_scenario_baseline ON {s}.applicability_scenario (baseline_id);

        CREATE TABLE {s}.applicability_scenario_dependency (
            id bigserial PRIMARY KEY,
            scenario_id uuid NOT NULL REFERENCES {s}.applicability_scenario (id),
            kind varchar(12) NOT NULL CHECK (kind IN ('VARIABLE', 'PROFILE')),
            code varchar(80) NOT NULL,
            asset_id uuid NOT NULL REFERENCES {s}.applicability_asset (id),
            asset_version_id uuid REFERENCES {s}.applicability_asset_version (id),
            draft_revision integer,
            version_no integer,
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) CHECK (manifest_sha256 {SHA}),
            CONSTRAINT ck_applicability_scenario_dependency_shape CHECK (
                (asset_version_id IS NOT NULL AND version_no IS NOT NULL AND draft_revision IS NULL
                   AND manifest_sha256 IS NOT NULL)
                OR (asset_version_id IS NULL AND version_no IS NULL AND draft_revision IS NOT NULL
                   AND manifest_sha256 IS NULL))
        );
        CREATE UNIQUE INDEX uq_applicability_scenario_dependency ON {s}.applicability_scenario_dependency
            (scenario_id, kind, lower(code));
        CREATE INDEX ix_applicability_scenario_dependency_asset ON {s}.applicability_scenario_dependency (asset_id);

        CREATE TABLE {s}.applicability_suite (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            code varchar(60) NOT NULL CHECK (code {CODE}),
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            purpose varchar(20) NOT NULL DEFAULT 'PUBLICATION_GATING'
                CHECK (purpose IN ('PUBLICATION_GATING', 'EXPLORATORY')),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            draft_revision integer NOT NULL DEFAULT 1 CHECK (draft_revision >= 1),
            draft_updated_at timestamptz NOT NULL DEFAULT now(),
            draft_updated_by varchar(80) NOT NULL,
            archived_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by varchar(80) NOT NULL
        );
        CREATE UNIQUE INDEX uq_applicability_suite_identity ON {s}.applicability_suite (market_code, lower(code));
        CREATE INDEX ix_applicability_suite_policy ON {s}.applicability_suite (policy_id);

        CREATE TABLE {s}.applicability_suite_member (
            id bigserial PRIMARY KEY,
            suite_id uuid NOT NULL REFERENCES {s}.applicability_suite (id),
            scenario_id uuid NOT NULL REFERENCES {s}.applicability_scenario (id),
            position integer NOT NULL CHECK (position >= 1),
            expectation jsonb CHECK (expectation IS NULL OR jsonb_typeof(expectation) = 'object'),
            UNIQUE (suite_id, scenario_id),
            UNIQUE (suite_id, position)
        );
        CREATE INDEX ix_applicability_suite_member_scenario ON {s}.applicability_suite_member (scenario_id);

        CREATE TABLE {s}.applicability_scenario_event (
            seq bigserial PRIMARY KEY,
            scenario_id uuid REFERENCES {s}.applicability_scenario (id),
            suite_id uuid REFERENCES {s}.applicability_suite (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            draft_revision integer NOT NULL,
            comment text NOT NULL DEFAULT '',
            detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            occurred_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((scenario_id IS NULL) <> (suite_id IS NULL))
        );
        CREATE INDEX ix_applicability_scenario_event_scenario ON {s}.applicability_scenario_event (scenario_id, seq);
        CREATE INDEX ix_applicability_scenario_event_suite ON {s}.applicability_scenario_event (suite_id, seq);

        CREATE TABLE {s}.applicability_evaluation_run (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            record_class varchar(12) NOT NULL DEFAULT 'SYNTHETIC' CHECK (record_class = 'SYNTHETIC'),
            suite_id uuid NOT NULL REFERENCES {s}.applicability_suite (id),
            suite_revision integer NOT NULL,
            suite_purpose varchar(20) NOT NULL,
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            policy_revision integer NOT NULL,
            policy_document_sha256 char(64) NOT NULL CHECK (policy_document_sha256 {SHA}),
            policy_snapshot_sha256 char(64) NOT NULL CHECK (policy_snapshot_sha256 {SHA}),
            policy_fingerprint char(64) CHECK (policy_fingerprint {SHA}),
            evaluator_contract varchar(80) NOT NULL,
            idempotency_key varchar(80) NOT NULL,
            status varchar(20) NOT NULL CHECK (status IN {RUN_STATUS}),
            scenarios integer NOT NULL CHECK (scenarios >= 0),
            passed integer NOT NULL, failed integer NOT NULL, not_evaluated integer NOT NULL,
            invalid integer NOT NULL, no_expectation integer NOT NULL,
            coverage jsonb NOT NULL CHECK (jsonb_typeof(coverage) = 'object'),
            record jsonb NOT NULL CHECK (jsonb_typeof(record) = 'object'),
            record_sha256 char(64) NOT NULL CHECK (record_sha256 {SHA}),
            run_sha256 char(64) NOT NULL CHECK (run_sha256 {SHA}),
            duration_ms integer NOT NULL DEFAULT 0,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by varchar(80) NOT NULL,
            CHECK (passed + failed + not_evaluated + invalid + no_expectation = scenarios),
            UNIQUE (suite_id, idempotency_key)
        );
        CREATE INDEX ix_applicability_evaluation_run_suite ON {s}.applicability_evaluation_run (suite_id, created_at DESC);
        CREATE INDEX ix_applicability_evaluation_run_policy
            ON {s}.applicability_evaluation_run (policy_id, created_at DESC);

        CREATE TABLE {s}.applicability_evaluation_result (
            run_id uuid NOT NULL REFERENCES {s}.applicability_evaluation_run (id),
            position integer NOT NULL CHECK (position >= 1),
            scenario_id uuid NOT NULL REFERENCES {s}.applicability_scenario (id),
            scenario_code varchar(60) NOT NULL,
            scenario_name text NOT NULL,
            scenario_revision integer NOT NULL,
            scenario_document jsonb NOT NULL,
            scenario_snapshot jsonb NOT NULL,
            scenario_document_sha256 char(64) NOT NULL CHECK (scenario_document_sha256 {SHA}),
            scenario_snapshot_sha256 char(64) NOT NULL CHECK (scenario_snapshot_sha256 {SHA}),
            expectation jsonb,
            outcome varchar(20) NOT NULL CHECK (outcome IN {RESULT}),
            plan jsonb,
            plan_fingerprint char(64) CHECK (plan_fingerprint {SHA}),
            actual jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            differences jsonb NOT NULL DEFAULT '[]'::jsonb,
            diagnostics jsonb NOT NULL DEFAULT '[]'::jsonb,
            PRIMARY KEY (run_id, position)
        );
        CREATE INDEX ix_applicability_evaluation_result_scenario
            ON {s}.applicability_evaluation_result (scenario_id);
    """)
    op.execute(f"""
        CREATE FUNCTION {s}.applicability_scenario_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE other text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a saved scenario or suite is never deleted; it is archived'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.policy_id IS NOT NULL THEN
              SELECT market_code INTO other FROM {s}.applicability_policy WHERE id = NEW.policy_id;
              IF other IS DISTINCT FROM NEW.market_code THEN
                RAISE EXCEPTION 'a scenario or suite belongs to a policy of its own market only'
                  USING ERRCODE = 'check_violation';
              END IF;
            END IF;
            RETURN NEW;
          END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.market_code IS DISTINCT FROM OLD.market_code
             OR NEW.code IS DISTINCT FROM OLD.code OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.policy_id IS DISTINCT FROM OLD.policy_id THEN
            RAISE EXCEPTION 'the market, the code and the policy of a scenario or suite never change'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.draft_revision < OLD.draft_revision THEN
            RAISE EXCEPTION 'a draft revision never goes back' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.document IS DISTINCT FROM OLD.document AND NEW.draft_revision = OLD.draft_revision THEN
            RAISE EXCEPTION 'a changed draft is a new revision' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_scenario_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.applicability_scenario
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_scenario_guard();
        CREATE TRIGGER applicability_suite_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.applicability_suite
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_scenario_guard();

        CREATE FUNCTION {s}.applicability_scenario_dependency_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE market text; other text; kind_ text;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'a dependency row is replaced with its scenario draft, never edited'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT market_code INTO market FROM {s}.applicability_scenario WHERE id = NEW.scenario_id;
          SELECT a.market_code, a.kind INTO other, kind_ FROM {s}.applicability_asset a WHERE a.id = NEW.asset_id;
          IF kind_ <> NEW.kind THEN
            RAISE EXCEPTION 'the library item is not a %', lower(NEW.kind) USING ERRCODE = 'check_violation';
          END IF;
          IF other IS DISTINCT FROM market THEN
            RAISE EXCEPTION 'a scenario refers to library items of its own market only'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.asset_version_id IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM {s}.applicability_asset_version v WHERE v.id = NEW.asset_version_id
                 AND v.asset_id = NEW.asset_id AND v.status IN ('PUBLISHED', 'SUPERSEDED')
                 AND v.version_no = NEW.version_no) THEN
            RAISE EXCEPTION 'a pinned library version is a published version of that item'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_scenario_dependency_guard BEFORE INSERT OR UPDATE
          ON {s}.applicability_scenario_dependency
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_scenario_dependency_guard();

        CREATE FUNCTION {s}.applicability_suite_member_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE a text; b text;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'a suite member is replaced with its suite draft, never edited'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT market_code INTO a FROM {s}.applicability_suite WHERE id = NEW.suite_id;
          SELECT market_code INTO b FROM {s}.applicability_scenario WHERE id = NEW.scenario_id;
          IF a IS DISTINCT FROM b THEN
            RAISE EXCEPTION 'a suite holds scenarios of its own market only' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_suite_member_guard BEFORE INSERT OR UPDATE ON {s}.applicability_suite_member
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_suite_member_guard();

        CREATE FUNCTION {s}.applicability_scenario_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'the history of a scenario or suite is append-only' USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_scenario_event_guard BEFORE UPDATE OR DELETE
          ON {s}.applicability_scenario_event
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_scenario_event_guard();

        CREATE FUNCTION {s}.applicability_evaluation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE a text; b text;
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'a recorded evaluation is immutable evidence: it is never changed or deleted'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT market_code INTO a FROM {s}.applicability_suite WHERE id = NEW.suite_id AND policy_id = NEW.policy_id;
          SELECT market_code INTO b FROM {s}.applicability_policy WHERE id = NEW.policy_id;
          IF a IS NULL OR a IS DISTINCT FROM b OR a IS DISTINCT FROM NEW.market_code THEN
            RAISE EXCEPTION 'a run evaluates a suite against its own policy, inside one market'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_evaluation_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_evaluation_run
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_evaluation_guard();

        CREATE FUNCTION {s}.applicability_evaluation_result_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE want integer; have integer; market text; other text;
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'a recorded evaluation is immutable evidence: it is never changed or deleted'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT r.scenarios, r.market_code INTO want, market
            FROM {s}.applicability_evaluation_run r WHERE r.id = NEW.run_id;
          SELECT count(*) INTO have FROM {s}.applicability_evaluation_result WHERE run_id = NEW.run_id;
          IF have >= want THEN
            RAISE EXCEPTION 'a run holds exactly the results it was recorded with' USING ERRCODE = 'check_violation';
          END IF;
          SELECT market_code INTO other FROM {s}.applicability_scenario WHERE id = NEW.scenario_id;
          IF other IS DISTINCT FROM market THEN
            RAISE EXCEPTION 'a run records scenarios of its own market only' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_evaluation_result_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_evaluation_result
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_evaluation_result_guard();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    for table, what in (
        ("applicability_evaluation_run", "recorded evaluation runs"),
        ("applicability_suite", "regression suites"),
        ("applicability_scenario", "saved scenarios"),
    ):
        if conn.execute(sa.text(f"SELECT count(*) FROM {s}.{table}")).scalar_one():
            # stored scenarios, suites and evidence are not thrown away by a downgrade
            raise RuntimeError(f"{what} exist; downgrade would destroy them and their history")
    for table in TABLES:
        op.execute(f"DROP TABLE {s}.{table}")
    for fn in FUNCTIONS:
        op.execute(f"DROP FUNCTION {s}.{fn}()")
