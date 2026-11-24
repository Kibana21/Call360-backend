"""APPL-X4b — governed publication of Applicability Policies. Additive only: four tables, four guards; NO permission.

Nothing existing is altered: no table, column, constraint, trigger or permission of an earlier revision — in
particular the accepted ``applicability_policy_event`` CHECK list is left as it is (owner ruling D-444: candidates
have an append-only event table of their own).

* ``applicability_policy_candidate`` — an IMMUTABLE submission: the policy document exactly as it was at one saved
  revision, its whole dependency manifest (identities, fingerprints and the definitions themselves), the qualifying
  recorded evaluation run with its fingerprints, coverage and expectation provenance, and one fingerprint over all of
  it. Only the lifecycle may move — SUBMITTED → APPROVED → PUBLISHED, or RETURNED / WITHDRAWN — and each move may only
  write its own actor, time and comment. Three DIFFERENT people: CHECK constraints refuse a checker who is the
  submitter and a publisher who is either.
* ``applicability_policy_candidate_dependency`` — the manifest as rows, with FOREIGN KEYS to the library and to
  Survey Studio. A guard accepts only versions that were genuinely published (PUBLISHED or SUPERSEDED), of the
  candidate's own market.
* ``applicability_policy_candidate_event`` — the append-only history of candidates and published versions.
* ``applicability_policy_version`` — an immutable, numbered published version, written FROM THE CANDIDATE. At most
  one PUBLISHED per policy; an earlier one becomes SUPERSEDED and stays readable and verifiable.

A published version is a governed configuration artefact. Nothing here refers to a case, a sale, a customer, a
session, a callback, an assignment rule, a survey binding or a requirement group. Used only when
``applicability_publication_enabled`` is on.

Revision ID: 0041_applicability_publication
Revises: 0040_applicability_scenarios
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041_applicability_publication"
down_revision = "0040_applicability_scenarios"
branch_labels = None
depends_on = None

SHA = "~ '^[0-9a-f]{64}$'"
STATUS = ("SUBMITTED", "APPROVED", "RETURNED", "WITHDRAWN", "PUBLISHED")
EVENTS = ("SUBMITTED", "APPROVED", "RETURNED", "WITHDRAWN", "PUBLISHED", "SUPERSEDED", "REFUSED")
TABLES = (
    "applicability_policy_version",
    "applicability_policy_candidate_event",
    "applicability_policy_candidate_dependency",
    "applicability_policy_candidate",
)
FUNCTIONS = (
    "applicability_policy_candidate_guard",
    "applicability_policy_candidate_dependency_guard",
    "applicability_policy_candidate_event_guard",
    "applicability_policy_version_guard",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(f"""
        CREATE TABLE {s}.applicability_policy_candidate (
            id uuid PRIMARY KEY,
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            market_code varchar(40) NOT NULL,
            candidate_no integer NOT NULL CHECK (candidate_no >= 1),
            status varchar(12) NOT NULL DEFAULT 'SUBMITTED' CHECK (status IN {STATUS}),
            draft_revision integer NOT NULL CHECK (draft_revision >= 1),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
            evidence_run_id uuid NOT NULL REFERENCES {s}.applicability_evaluation_run (id),
            evidence_run_sha256 char(64) NOT NULL CHECK (evidence_run_sha256 {SHA}),
            candidate_sha256 char(64) NOT NULL CHECK (candidate_sha256 {SHA}),
            submitted_by varchar(80) NOT NULL,
            submitted_at timestamptz NOT NULL DEFAULT now(),
            submission_note text NOT NULL DEFAULT '',
            decided_by varchar(80),
            decided_at timestamptz,
            decision_comment text NOT NULL DEFAULT '',
            published_by varchar(80),
            published_at timestamptz,
            closed_at timestamptz,
            UNIQUE (policy_id, candidate_no),
            -- three DIFFERENT people: nobody decides on, or publishes, what they submitted; nobody publishes what they approved
            CONSTRAINT ck_applicability_candidate_checker CHECK (decided_by IS NULL OR decided_by <> submitted_by),
            CONSTRAINT ck_applicability_candidate_publisher CHECK (
                published_by IS NULL OR (published_by <> submitted_by AND published_by <> decided_by)),
            CONSTRAINT ck_applicability_candidate_shape CHECK (
                (status = 'SUBMITTED' AND decided_by IS NULL AND published_by IS NULL)
                OR (status = 'WITHDRAWN' AND published_by IS NULL AND closed_at IS NOT NULL)
                OR (status IN ('APPROVED', 'RETURNED') AND decided_by IS NOT NULL AND decided_at IS NOT NULL
                    AND published_by IS NULL)
                OR (status = 'PUBLISHED' AND decided_by IS NOT NULL AND published_by IS NOT NULL
                    AND published_at IS NOT NULL))
        );
        -- one candidate at a time is under review for a policy
        CREATE UNIQUE INDEX uq_applicability_candidate_open ON {s}.applicability_policy_candidate (policy_id)
            WHERE status IN ('SUBMITTED', 'APPROVED');
        CREATE INDEX ix_applicability_candidate_policy ON {s}.applicability_policy_candidate (policy_id, candidate_no DESC);

        CREATE TABLE {s}.applicability_policy_candidate_dependency (
            id bigserial PRIMARY KEY,
            candidate_id uuid NOT NULL REFERENCES {s}.applicability_policy_candidate (id),
            kind varchar(12) NOT NULL CHECK (kind IN ('VARIABLE', 'PROFILE', 'CONDITION', 'SURVEY')),
            code varchar(80) NOT NULL,
            asset_id uuid REFERENCES {s}.applicability_asset (id),
            asset_version_id uuid REFERENCES {s}.applicability_asset_version (id),
            survey_definition_id uuid REFERENCES {s}.survey_definition (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            version_no integer NOT NULL,
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            -- a candidate holds PUBLISHED versions only: there is no shape for a draft revision here
            CONSTRAINT ck_applicability_candidate_dependency_shape CHECK (
                (kind = 'SURVEY' AND survey_definition_id IS NOT NULL AND survey_version_id IS NOT NULL
                   AND asset_id IS NULL AND asset_version_id IS NULL)
                OR (kind <> 'SURVEY' AND asset_id IS NOT NULL AND asset_version_id IS NOT NULL
                   AND survey_definition_id IS NULL AND survey_version_id IS NULL))
        );
        CREATE UNIQUE INDEX uq_applicability_candidate_dependency ON {s}.applicability_policy_candidate_dependency
            (candidate_id, kind, lower(code), version_no);
        CREATE INDEX ix_applicability_candidate_dependency_asset
            ON {s}.applicability_policy_candidate_dependency (asset_id);
        CREATE INDEX ix_applicability_candidate_dependency_survey
            ON {s}.applicability_policy_candidate_dependency (survey_definition_id);

        CREATE TABLE {s}.applicability_policy_candidate_event (
            seq bigserial PRIMARY KEY,
            candidate_id uuid NOT NULL REFERENCES {s}.applicability_policy_candidate (id),
            event varchar(12) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_applicability_candidate_event ON {s}.applicability_policy_candidate_event (candidate_id, seq);

        CREATE TABLE {s}.applicability_policy_version (
            id uuid PRIMARY KEY,
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            candidate_id uuid NOT NULL UNIQUE REFERENCES {s}.applicability_policy_candidate (id),
            market_code varchar(40) NOT NULL,
            version_no integer NOT NULL CHECK (version_no >= 1),
            status varchar(12) NOT NULL DEFAULT 'PUBLISHED' CHECK (status IN ('PUBLISHED', 'SUPERSEDED')),
            document jsonb NOT NULL,
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            manifest jsonb NOT NULL,
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            evidence jsonb NOT NULL,
            evidence_run_id uuid NOT NULL REFERENCES {s}.applicability_evaluation_run (id),
            candidate_sha256 char(64) NOT NULL CHECK (candidate_sha256 {SHA}),
            version_sha256 char(64) NOT NULL CHECK (version_sha256 {SHA}),
            published_by varchar(80) NOT NULL,
            published_at timestamptz NOT NULL DEFAULT now(),
            superseded_at timestamptz,
            UNIQUE (policy_id, version_no),
            CHECK ((status = 'PUBLISHED') = (superseded_at IS NULL))
        );
        CREATE UNIQUE INDEX uq_applicability_policy_published ON {s}.applicability_policy_version (policy_id)
            WHERE status = 'PUBLISHED';
    """)
    op.execute(f"""
        CREATE FUNCTION {s}.applicability_policy_candidate_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE other text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a policy candidate is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            SELECT market_code INTO other FROM {s}.applicability_policy WHERE id = NEW.policy_id;
            IF other IS DISTINCT FROM NEW.market_code OR NEW.status <> 'SUBMITTED' THEN
              RAISE EXCEPTION 'a candidate is submitted for a policy of its own market' USING ERRCODE = 'check_violation';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM {s}.applicability_evaluation_run r WHERE r.id = NEW.evidence_run_id
                             AND r.policy_id = NEW.policy_id AND r.run_sha256 = NEW.evidence_run_sha256) THEN
              RAISE EXCEPTION 'the evidence of a candidate is a recorded run of that policy, at that fingerprint'
                USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          -- what was submitted is frozen: the document, the manifest, the evidence, every fingerprint, who and when
          IF (NEW.id, NEW.policy_id, NEW.market_code, NEW.candidate_no, NEW.draft_revision, NEW.document,
              NEW.document_sha256, NEW.manifest, NEW.manifest_sha256, NEW.evidence, NEW.evidence_run_id,
              NEW.evidence_run_sha256, NEW.candidate_sha256, NEW.submitted_by, NEW.submitted_at, NEW.submission_note)
             IS DISTINCT FROM
             (OLD.id, OLD.policy_id, OLD.market_code, OLD.candidate_no, OLD.draft_revision, OLD.document,
              OLD.document_sha256, OLD.manifest, OLD.manifest_sha256, OLD.evidence, OLD.evidence_run_id,
              OLD.evidence_run_sha256, OLD.candidate_sha256, OLD.submitted_by, OLD.submitted_at, OLD.submission_note)
          THEN
            RAISE EXCEPTION 'what a candidate froze at submission never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NOT ((OLD.status = 'SUBMITTED' AND NEW.status IN ('APPROVED', 'RETURNED', 'WITHDRAWN'))
               OR (OLD.status = 'APPROVED' AND NEW.status IN ('PUBLISHED', 'WITHDRAWN'))) THEN
            RAISE EXCEPTION 'a candidate cannot go from % to %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          -- a decision, once recorded, is not rewritten by a later step
          IF OLD.decided_by IS NOT NULL AND (NEW.decided_by, NEW.decided_at, NEW.decision_comment)
             IS DISTINCT FROM (OLD.decided_by, OLD.decided_at, OLD.decision_comment) THEN
            RAISE EXCEPTION 'a recorded decision never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_policy_candidate_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_policy_candidate
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_candidate_guard();

        CREATE FUNCTION {s}.applicability_policy_candidate_dependency_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE market text; other text; kind_ text;
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'the manifest of a candidate never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT market_code INTO market FROM {s}.applicability_policy_candidate WHERE id = NEW.candidate_id;
          IF NEW.kind = 'SURVEY' THEN
            SELECT d.market_code, d.artifact_kind INTO other, kind_ FROM {s}.survey_definition d
              WHERE d.id = NEW.survey_definition_id;
            IF kind_ <> 'SURVEY' OR NOT EXISTS (SELECT 1 FROM {s}.survey_version v
                 WHERE v.id = NEW.survey_version_id AND v.survey_definition_id = NEW.survey_definition_id
                   AND v.version_no = NEW.version_no) THEN
              RAISE EXCEPTION 'a candidate pins a version of a survey' USING ERRCODE = 'check_violation';
            END IF;
          ELSE
            SELECT a.market_code, a.kind INTO other, kind_ FROM {s}.applicability_asset a WHERE a.id = NEW.asset_id;
            IF kind_ <> NEW.kind OR NOT EXISTS (SELECT 1 FROM {s}.applicability_asset_version v
                 WHERE v.id = NEW.asset_version_id AND v.asset_id = NEW.asset_id
                   AND v.status IN ('PUBLISHED', 'SUPERSEDED') AND v.version_no = NEW.version_no
                   AND v.content_sha256 = NEW.content_sha256) THEN
              RAISE EXCEPTION 'a candidate pins library versions that were genuinely published, at their fingerprint'
                USING ERRCODE = 'check_violation';
            END IF;
          END IF;
          IF other IS DISTINCT FROM market THEN
            RAISE EXCEPTION 'a candidate refers to items of its own market only' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_policy_candidate_dependency_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_policy_candidate_dependency
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_candidate_dependency_guard();

        CREATE FUNCTION {s}.applicability_policy_candidate_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'the history of a policy candidate is append-only' USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_policy_candidate_event_guard BEFORE UPDATE OR DELETE
          ON {s}.applicability_policy_candidate_event
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_candidate_event_guard();

        CREATE FUNCTION {s}.applicability_policy_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE c record;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a published policy version is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            -- a version is written FROM its candidate: the same document, manifest, evidence and fingerprints
            SELECT * INTO c FROM {s}.applicability_policy_candidate WHERE id = NEW.candidate_id;
            IF c.policy_id IS DISTINCT FROM NEW.policy_id OR c.status <> 'PUBLISHED'
               OR c.document IS DISTINCT FROM NEW.document OR c.document_sha256 <> NEW.document_sha256
               OR c.manifest IS DISTINCT FROM NEW.manifest OR c.manifest_sha256 <> NEW.manifest_sha256
               OR c.evidence IS DISTINCT FROM NEW.evidence OR c.evidence_run_id <> NEW.evidence_run_id
               OR c.candidate_sha256 <> NEW.candidate_sha256 OR c.published_by IS DISTINCT FROM NEW.published_by
               OR NEW.status <> 'PUBLISHED' THEN
              RAISE EXCEPTION 'a published version is exactly its approved candidate' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF NOT (OLD.status = 'PUBLISHED' AND NEW.status = 'SUPERSEDED' AND NEW.superseded_at IS NOT NULL
                  AND (to_jsonb(NEW) - 'status' - 'superseded_at') = (to_jsonb(OLD) - 'status' - 'superseded_at')) THEN
            RAISE EXCEPTION 'a published version never changes; it can only be superseded'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_policy_version_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_policy_version
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_version_guard();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.applicability_policy_candidate")).scalar_one():
        # a submitted candidate, its decision and any published version are governed history
        raise RuntimeError("policy candidates exist; downgrade would destroy governed history")
    for table in TABLES:
        op.execute(f"DROP TABLE {s}.{table}")
    for fn in FUNCTIONS:
        op.execute(f"DROP FUNCTION {s}.{fn}()")
