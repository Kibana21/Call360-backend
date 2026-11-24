"""APPL-X2 — the governed Applicability library: variables, application profiles and reusable conditions.

Four additive tables, four guards and four permissions. Nothing existing is altered: no survey, rule, binding, group,
script, case or session table is read or written by this revision, so every historical fingerprint is what it was.

* ``applicability_asset`` — one reusable thing with a stable identity: a market, a kind (``VARIABLE``, ``PROFILE``,
  ``CONDITION``) and a code that never change. It also carries the ONE working draft of that thing (``draft``,
  ``draft_revision``): a draft is mutable working state, saved with an expected revision, so no separate draft table
  is needed. Codes are unique per market and kind whatever their letter case.
* ``applicability_asset_version`` — an immutable CANDIDATE frozen from the draft at submission, which becomes a
  published VERSION. Its document, manifest and fingerprints never change; only its status moves, and only along
  ``SUBMITTED → APPROVED → PUBLISHED → SUPERSEDED`` (or ``RETURNED`` / ``WITHDRAWN``). The table itself refuses a
  decision by the submitter and a publication by the submitter or the approver: three different people.
* ``applicability_asset_dependency`` — the exact published versions a candidate pins (a condition's variables and
  conditions, a profile's variables and profiles, a derived variable's variables). A dependency is always on a version
  that is already published, of ANOTHER asset, of the SAME market — so the graph can hold no cycle and no reference
  across markets, whatever the application does.
* ``applicability_event`` — the append-only lifecycle history of every asset.

The permissions ``applicability.read / edit / approve / publish`` are created and granted to NO role.
Used only when ``applicability_library_enabled`` is on. Applicability policies are not stored here (APPL-X3).

Revision ID: 0038_applicability_library
Revises: 0037_shared_rule_services
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0038_applicability_library"
down_revision = "0037_shared_rule_services"
branch_labels = None
depends_on = None

PERMISSIONS = {
    "applicability.read": "Read the applicability library: variables, application profiles and reusable conditions",
    "applicability.edit": "Create and edit drafts of applicability library items, and submit them for review",
    "applicability.approve": "Approve or return a submitted applicability library item (never one's own)",
    "applicability.publish": "Publish an approved applicability library item (a third person)",
}
SHA = "~ '^[0-9a-f]{64}$'"
EVENTS = (
    "CREATED", "DRAFT_SAVED", "DRAFT_STARTED", "DRAFT_DISCARDED", "SUBMITTED", "APPROVED", "RETURNED", "WITHDRAWN",
    "PUBLISHED", "SUPERSEDED", "DENIED",
)  # fmt: skip
TABLES = (
    "applicability_event", "applicability_asset_dependency", "applicability_asset_version", "applicability_asset",
)  # fmt: skip


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    op.execute(f"""
        CREATE TABLE {s}.applicability_asset (
            id uuid PRIMARY KEY,
            market_code varchar(40) NOT NULL,
            kind varchar(12) NOT NULL CHECK (kind IN ('VARIABLE', 'PROFILE', 'CONDITION')),
            code varchar(60) NOT NULL CHECK (code ~ '^[A-Za-z][A-Za-z0-9_.-]{{1,59}}$'),
            draft jsonb CHECK (draft IS NULL OR jsonb_typeof(draft) = 'object'),
            draft_revision integer NOT NULL DEFAULT 0 CHECK (draft_revision >= 0),
            draft_base_version_no integer,
            draft_updated_at timestamptz,
            draft_updated_by varchar(80),
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by varchar(80) NOT NULL
        );
        CREATE UNIQUE INDEX uq_applicability_asset_identity
            ON {s}.applicability_asset (market_code, kind, lower(code));

        CREATE TABLE {s}.applicability_asset_version (
            id uuid PRIMARY KEY,
            asset_id uuid NOT NULL REFERENCES {s}.applicability_asset (id),
            candidate_no integer NOT NULL CHECK (candidate_no >= 1),
            version_no integer CHECK (version_no >= 1),
            status varchar(12) NOT NULL CHECK (status IN
                ('SUBMITTED', 'APPROVED', 'RETURNED', 'WITHDRAWN', 'PUBLISHED', 'SUPERSEDED')),
            document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
            manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
            content_sha256 char(64) NOT NULL CHECK (content_sha256 {SHA}),
            manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 {SHA}),
            draft_revision integer NOT NULL,
            note text NOT NULL DEFAULT '',
            submitted_by varchar(80) NOT NULL,
            submitted_at timestamptz NOT NULL DEFAULT now(),
            decided_by varchar(80),
            decided_at timestamptz,
            decision_comment text,
            published_by varchar(80),
            published_at timestamptz,
            UNIQUE (asset_id, candidate_no),
            UNIQUE (asset_id, version_no),
            CONSTRAINT ck_applicability_version_not_self_decided
                CHECK (decided_by IS NULL OR decided_by <> submitted_by),
            CONSTRAINT ck_applicability_version_third_publisher
                CHECK (published_by IS NULL OR (published_by <> submitted_by AND published_by <> decided_by)),
            CONSTRAINT ck_applicability_version_numbered_when_published
                CHECK ((status IN ('PUBLISHED', 'SUPERSEDED')) = (version_no IS NOT NULL)),
            CONSTRAINT ck_applicability_version_published_by_three
                CHECK (status NOT IN ('PUBLISHED', 'SUPERSEDED')
                       OR (decided_by IS NOT NULL AND published_by IS NOT NULL AND published_at IS NOT NULL)),
            CONSTRAINT ck_applicability_version_decided
                CHECK (status NOT IN ('APPROVED', 'RETURNED') OR (decided_by IS NOT NULL AND decided_at IS NOT NULL))
        );
        CREATE UNIQUE INDEX uq_applicability_version_one_open
            ON {s}.applicability_asset_version (asset_id) WHERE status IN ('SUBMITTED', 'APPROVED');
        CREATE UNIQUE INDEX uq_applicability_version_one_published
            ON {s}.applicability_asset_version (asset_id) WHERE status = 'PUBLISHED';

        CREATE TABLE {s}.applicability_asset_dependency (
            version_id uuid NOT NULL REFERENCES {s}.applicability_asset_version (id),
            depends_on_version_id uuid NOT NULL REFERENCES {s}.applicability_asset_version (id),
            PRIMARY KEY (version_id, depends_on_version_id)
        );
        CREATE INDEX ix_applicability_dependency_used ON {s}.applicability_asset_dependency (depends_on_version_id);

        CREATE TABLE {s}.applicability_event (
            seq bigserial PRIMARY KEY,
            asset_id uuid NOT NULL REFERENCES {s}.applicability_asset (id),
            version_id uuid REFERENCES {s}.applicability_asset_version (id),
            event varchar(16) NOT NULL CHECK (event IN {EVENTS}),
            actor_ref varchar(80) NOT NULL,
            comment text NOT NULL DEFAULT '',
            detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_applicability_event_asset ON {s}.applicability_event (asset_id, seq);
    """)
    op.execute(f"""
        CREATE FUNCTION {s}.applicability_asset_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'an applicability library item is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.market_code IS DISTINCT FROM OLD.market_code
             OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.code IS DISTINCT FROM OLD.code
             OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'the identity of an applicability library item never changes'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.draft_revision < OLD.draft_revision THEN
            RAISE EXCEPTION 'a draft revision never goes back' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_asset_guard BEFORE UPDATE OR DELETE ON {s}.applicability_asset
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_asset_guard();

        CREATE FUNCTION {s}.applicability_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a submitted or published applicability version is never deleted'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'SUBMITTED' OR NEW.decided_by IS NOT NULL OR NEW.published_by IS NOT NULL THEN
              RAISE EXCEPTION 'an applicability version starts as a submitted candidate'
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
          END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.asset_id IS DISTINCT FROM OLD.asset_id
             OR NEW.candidate_no IS DISTINCT FROM OLD.candidate_no OR NEW.document IS DISTINCT FROM OLD.document
             OR NEW.manifest IS DISTINCT FROM OLD.manifest OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
             OR NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256
             OR NEW.draft_revision IS DISTINCT FROM OLD.draft_revision OR NEW.note IS DISTINCT FROM OLD.note
             OR NEW.submitted_by IS DISTINCT FROM OLD.submitted_by
             OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
            RAISE EXCEPTION 'a submitted applicability version is frozen: its content and manifest never change'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (OLD.decided_by IS NOT NULL AND (NEW.decided_by IS DISTINCT FROM OLD.decided_by
                OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
                OR NEW.decision_comment IS DISTINCT FROM OLD.decision_comment))
             OR (OLD.published_by IS NOT NULL AND (NEW.published_by IS DISTINCT FROM OLD.published_by
                OR NEW.published_at IS DISTINCT FROM OLD.published_at))
             OR (OLD.version_no IS NOT NULL AND NEW.version_no IS DISTINCT FROM OLD.version_no) THEN
            RAISE EXCEPTION 'who decided and who published an applicability version never changes'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NOT ((OLD.status = 'SUBMITTED' AND NEW.status IN ('APPROVED', 'RETURNED', 'WITHDRAWN'))
               OR (OLD.status = 'APPROVED' AND NEW.status IN ('PUBLISHED', 'WITHDRAWN'))
               OR (OLD.status = 'PUBLISHED' AND NEW.status = 'SUPERSEDED')) THEN
            RAISE EXCEPTION 'an applicability version cannot go from % to %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_version_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_asset_version FOR EACH ROW EXECUTE FUNCTION {s}.applicability_version_guard();

        CREATE FUNCTION {s}.applicability_dependency_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE mine record; theirs record;
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'what an applicability version pins never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          SELECT v.status, v.asset_id, a.market_code INTO mine FROM {s}.applicability_asset_version v
            JOIN {s}.applicability_asset a ON a.id = v.asset_id WHERE v.id = NEW.version_id;
          SELECT v.status, v.asset_id, a.market_code INTO theirs FROM {s}.applicability_asset_version v
            JOIN {s}.applicability_asset a ON a.id = v.asset_id WHERE v.id = NEW.depends_on_version_id;
          IF mine.status <> 'SUBMITTED' THEN
            RAISE EXCEPTION 'what a version pins is recorded when it is submitted, never later'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF theirs.status NOT IN ('PUBLISHED', 'SUPERSEDED') THEN
            RAISE EXCEPTION 'an applicability version pins published versions only' USING ERRCODE = 'check_violation';
          END IF;
          IF theirs.market_code <> mine.market_code THEN
            RAISE EXCEPTION 'an applicability version pins items of its own market only'
              USING ERRCODE = 'check_violation';
          END IF;
          IF theirs.asset_id = mine.asset_id THEN
            RAISE EXCEPTION 'an applicability item cannot depend on itself' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER applicability_dependency_guard BEFORE INSERT OR UPDATE OR DELETE
          ON {s}.applicability_asset_dependency FOR EACH ROW EXECUTE FUNCTION {s}.applicability_dependency_guard();

        CREATE FUNCTION {s}.applicability_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'the applicability history is append-only' USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER applicability_event_guard BEFORE UPDATE OR DELETE ON {s}.applicability_event
          FOR EACH ROW EXECUTE FUNCTION {s}.applicability_event_guard();
    """)
    # permissions: created, and granted to nobody
    for code, description in PERMISSIONS.items():
        conn.execute(
            sa.text(
                f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES (:i, :c, NULL, false, :d)"
            ),
            {"i": uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + code), "c": code, "d": description},
        )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.applicability_asset")).scalar_one():
        # governed history (drafts, candidates, published versions, who did what) is not thrown away by a downgrade
        raise RuntimeError("applicability library items exist; downgrade would destroy their governed history")
    codes = ", ".join(f"'{c}'" for c in PERMISSIONS)
    held = conn.execute(
        sa.text(
            f"SELECT count(*) FROM {s}.role_permission rp JOIN {s}.permission p ON p.id = rp.permission_id "
            f"WHERE p.code IN ({codes})"
        )
    ).scalar_one()
    if held:
        raise RuntimeError("a role holds an applicability permission; revoke it deliberately before downgrading")
    op.execute(f"DELETE FROM {s}.permission WHERE code IN ({codes})")
    for table in TABLES:
        op.execute(f"DROP TABLE {s}.{table}")
    for fn in ("applicability_event_guard", "applicability_dependency_guard", "applicability_version_guard",
               "applicability_asset_guard"):  # fmt: skip
        op.execute(f"DROP FUNCTION {s}.{fn}()")
