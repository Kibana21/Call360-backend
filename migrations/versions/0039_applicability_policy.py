"""APPL-X3 — persistent Applicability Policies (working drafts). Three additive tables, three guards; no permission.

A policy is ONE coherent document — its scope, requirements, conditions, survey-selection actions and delivery order —
that the Card Composer, the Graph and the Matrix all edit. This revision stores that document and the exact
dependencies it was saved against. Publication of policies is NOT here (APPL-X4): there is no candidate, no published
policy version and no approval in these tables.

* ``applicability_policy`` — a stable identity (market and code, which never change) and the one working draft:
  ``document``, a monotonic ``draft_revision`` for optimistic concurrency, and ``snapshot`` — the dependency manifest
  of that draft: the exact library versions (or draft revisions) and published survey versions it was saved against,
  each with its fingerprint. No separate draft table: there is one working draft per policy.
* ``applicability_policy_dependency`` — the same dependencies as rows, written in the same transaction as the document
  and derived from the snapshot, so they cannot diverge from it. Every reference is a FOREIGN KEY: a library item to
  ``applicability_asset``, a published library version to ``applicability_asset_version``, a survey to
  ``survey_definition`` and ``survey_version``. A guard keeps every reference inside the policy's own market and
  refuses a survey "version" that is not a published survey. This is what makes "where is this used" exact and
  indexed.
* ``applicability_policy_event`` — the append-only editing history of a policy. A table of its own, so the accepted
  ``applicability_event`` of 0038 is not altered.

Nothing existing is changed: no table, column, row, trigger or permission of an earlier revision. The existing
permissions are used (``applicability.read`` / ``applicability.edit``, with ``survey.read``). No assignment rule,
survey binding or requirement group is read or written. Used only when ``applicability_policies_enabled`` is on.

Revision ID: 0039_applicability_policy
Revises: 0038_applicability_library
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039_applicability_policy"
down_revision = "0038_applicability_library"
branch_labels = None
depends_on = None

SHA = "~ '^[0-9a-f]{64}$'"
EVENTS = ("CREATED", "DRAFT_SAVED", "ARCHIVED", "RESTORED")
TABLES = ("applicability_policy_event", "applicability_policy_dependency", "applicability_policy")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(f"""
        CREATE TABLE {s}.applicability_policy (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            code varchar(60) NOT NULL CHECK (code ~ '^[A-Za-z][A-Za-z0-9_.-]{{1,59}}$'),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
            document_sha256 char(64) NOT NULL CHECK (document_sha256 {SHA}),
            snapshot_sha256 char(64) NOT NULL CHECK (snapshot_sha256 {SHA}),
            draft_revision integer NOT NULL DEFAULT 1 CHECK (draft_revision >= 1),
            draft_updated_at timestamptz NOT NULL DEFAULT now(),
            draft_updated_by varchar(80) NOT NULL,
            archived_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by varchar(80) NOT NULL
        );
        CREATE UNIQUE INDEX uq_applicability_policy_identity ON {s}.applicability_policy (market_code, lower(code));

        CREATE TABLE {s}.applicability_policy_dependency (
            id bigserial PRIMARY KEY,
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            kind varchar(12) NOT NULL CHECK (kind IN ('VARIABLE', 'PROFILE', 'CONDITION', 'SURVEY')),
            code varchar(80) NOT NULL,
            asset_id uuid REFERENCES {s}.applicability_asset (id),
            asset_version_id uuid REFERENCES {s}.applicability_asset_version (id),
            draft_revision integer,
            survey_definition_id uuid REFERENCES {s}.survey_definition (id),
            survey_version_id uuid REFERENCES {s}.survey_version (id),
            version_no integer,
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) CHECK (manifest_sha256 {SHA}),
            CONSTRAINT ck_applicability_policy_dependency_shape CHECK (
                (kind = 'SURVEY' AND survey_definition_id IS NOT NULL AND survey_version_id IS NOT NULL
                   AND asset_id IS NULL AND asset_version_id IS NULL AND draft_revision IS NULL
                   AND version_no IS NOT NULL AND manifest_sha256 IS NOT NULL)
                OR (kind <> 'SURVEY' AND asset_id IS NOT NULL AND survey_definition_id IS NULL
                   AND survey_version_id IS NULL
                   AND ((asset_version_id IS NOT NULL AND version_no IS NOT NULL AND draft_revision IS NULL
                         AND manifest_sha256 IS NOT NULL)
                     OR (asset_version_id IS NULL AND draft_revision IS NOT NULL AND manifest_sha256 IS NULL)))
            )
        );
        CREATE UNIQUE INDEX uq_applicability_policy_dependency ON {s}.applicability_policy_dependency
            (policy_id, kind, lower(code), coalesce(version_no, -1), coalesce(draft_revision, -1));
        CREATE INDEX ix_applicability_policy_dependency_asset ON {s}.applicability_policy_dependency (asset_id);
        CREATE INDEX ix_applicability_policy_dependency_survey
            ON {s}.applicability_policy_dependency (survey_definition_id);

        CREATE TABLE {s}.applicability_policy_event (
            seq bigserial PRIMARY KEY,
            policy_id uuid NOT NULL REFERENCES {s}.applicability_policy (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            draft_revision integer NOT NULL,
            comment text NOT NULL DEFAULT '',
            detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_applicability_policy_event ON {s}.applicability_policy_event (policy_id, seq);
    """)
    op.execute(f"""
        CREATE FUNCTION {s}.applicability_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'an applicability policy is never deleted; it is archived'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.market_code IS DISTINCT FROM OLD.market_code
             OR NEW.code IS DISTINCT FROM OLD.code OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'the market and the code of an applicability policy never change'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.draft_revision < OLD.draft_revision THEN
            RAISE EXCEPTION 'a draft revision never goes back' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (NEW.document IS DISTINCT FROM OLD.document OR NEW.snapshot IS DISTINCT FROM OLD.snapshot)
             AND NEW.draft_revision = OLD.draft_revision THEN
            RAISE EXCEPTION 'a changed draft is a new revision' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_policy_guard BEFORE UPDATE OR DELETE ON {s}.applicability_policy
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_guard();

        CREATE FUNCTION {s}.applicability_policy_dependency_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE market text; other text; kind_ text;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'a dependency row is replaced with its policy draft, never edited'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT market_code INTO market FROM {s}.applicability_policy WHERE id = NEW.policy_id;
          IF NEW.kind = 'SURVEY' THEN
            SELECT d.market_code, d.artifact_kind INTO other, kind_ FROM {s}.survey_definition d
              WHERE d.id = NEW.survey_definition_id;
            IF kind_ <> 'SURVEY' THEN
              RAISE EXCEPTION 'a policy selects surveys, not standalone modules' USING ERRCODE = 'check_violation';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM {s}.survey_version v WHERE v.id = NEW.survey_version_id
                             AND v.survey_definition_id = NEW.survey_definition_id) THEN
              RAISE EXCEPTION 'that survey version does not belong to that survey' USING ERRCODE = 'check_violation';
            END IF;
          ELSE
            SELECT a.market_code, a.kind INTO other, kind_ FROM {s}.applicability_asset a WHERE a.id = NEW.asset_id;
            IF kind_ <> NEW.kind THEN
              RAISE EXCEPTION 'the library item is not a %', lower(NEW.kind) USING ERRCODE = 'check_violation';
            END IF;
            IF NEW.asset_version_id IS NOT NULL AND NOT EXISTS (
                 SELECT 1 FROM {s}.applicability_asset_version v WHERE v.id = NEW.asset_version_id
                   AND v.asset_id = NEW.asset_id AND v.status IN ('PUBLISHED', 'SUPERSEDED')) THEN
              RAISE EXCEPTION 'a pinned library version is a published version of that item'
                USING ERRCODE = 'check_violation';
            END IF;
          END IF;
          IF other IS DISTINCT FROM market THEN
            RAISE EXCEPTION 'an applicability policy refers to items of its own market only'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_policy_dependency_guard BEFORE INSERT OR UPDATE
          ON {s}.applicability_policy_dependency
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_dependency_guard();

        CREATE FUNCTION {s}.applicability_policy_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'the history of an applicability policy is append-only'
            USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_policy_event_guard BEFORE UPDATE OR DELETE ON {s}.applicability_policy_event
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_policy_event_guard();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.applicability_policy")).scalar_one():
        # a saved policy and its editing history are not thrown away by a downgrade
        raise RuntimeError("applicability policies exist; downgrade would destroy them and their history")
    for table in TABLES:
        op.execute(f"DROP TABLE {s}.{table}")
    for fn in ("applicability_policy_event_guard", "applicability_policy_dependency_guard",
               "applicability_policy_guard"):  # fmt: skip
        op.execute(f"DROP FUNCTION {s}.{fn}()")
