"""S2-B: editable script-assignment rules (drafts, maker-checker, immutable published versions, change history).

- ``assignment_rule_draft``: the working copy of a rule version (new rule, new version of a rule or a copy). Content
  (name, conditions, priority, fallback flag, target, effective dates) changes only while DRAFT, with an optimistic
  concurrency ``row_version``; submission freezes it with a manifest and SHA-256. Lifecycle DRAFT →
  SUBMITTED_FOR_REVIEW → APPROVED → PUBLISHED, SUBMITTED_FOR_REVIEW → DRAFT (returned), DRAFT → ABANDONED. One open
  draft per rule code. Maker ≠ reviewer is a database check; the service also refuses any maker as publisher.
- Publication inserts the immutable ``script_assignment_rule_version`` row (unchanged S0 table; specificity is
  calculated, D-59) plus an insert-only ``assignment_rule_publication`` row (name, fallback flag, draft, approver,
  publisher). Seeded rule versions have no publication row and are not fallbacks.
- ``script_assignment_rule_version`` stays immutable except for the explicit retirement of a PUBLISHED version
  (→ SUPERSEDED or WITHDRAWN, setting ``effective_to`` once). Nothing else may change and nothing may be deleted.
- ``assignment_rule_change_event``: insert-only history (who, what, why) per rule code.

Permissions reuse the S2-A script governance permissions (D-54): ``script.edit`` (USER) authors, ``script.approve`` /
``script.publish`` (SC_CHECKER) review and publish, ``script.read`` reads and simulates. ADMIN holds none of the
authoring or approval permissions.

Revision ID: 0017_assignment_rule_authoring
Revises: 0016_script_draft_isolation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, provenance, sha256_check

revision = "0017_assignment_rule_authoring"
down_revision = "0016_script_draft_isolation"
branch_labels = None
depends_on = None

DRAFT_STATUS = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED", "PUBLISHED", "ABANDONED")
EVENT_TYPES = (
    "DRAFT_CREATED",
    "CONTENT_CHANGED",
    "VALIDATED",
    "SUBMITTED",
    "CHANGES_REQUESTED",
    "APPROVED",
    "PUBLISHED",
    "SUPERSEDED",
    "ABANDONED",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    op.create_table(
        "assignment_rule_draft",
        pk(),
        sa.Column("rule_code", sa.String(40), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("planned_version", sa.Integer, nullable=False),
        fk("base_rule_version_id", "script_assignment_rule_version", s, nullable=True),
        fk("copied_from_rule_version_id", "script_assignment_rule_version", s, nullable=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("conditions", JSONB, nullable=False),
        sa.Column("priority", sa.SmallInteger, nullable=False),
        sa.Column("is_fallback", sa.Boolean, nullable=False, server_default=sa.false()),
        fk("target_script_version_id", "script_version", s, nullable=True),
        sa.Column("effective_from", TS),
        sa.Column("effective_to", TS),
        sa.Column("validation_status", sa.String(16), nullable=False, server_default="NOT_VALIDATED"),
        sa.Column("manifest", JSONB),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("author_ref", sa.String(80), nullable=False),
        sa.Column("reviewer_ref", sa.String(80)),
        sa.Column("publisher_ref", sa.String(80)),
        fk("published_rule_version_id", "script_assignment_rule_version", s, nullable=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("updated_at", TS),
        sa.Column("updated_by", sa.String(80)),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        *provenance("assignment_rule_draft"),
        enum_check("status", DRAFT_STATUS, "ck_assignment_rule_draft_status"),
        enum_check("validation_status", ("NOT_VALIDATED", "VALID", "INVALID"), "ck_assignment_rule_draft_validation"),
        sa.CheckConstraint("priority BETWEEN 1 AND 999", name="ck_assignment_rule_draft_priority"),
        sa.CheckConstraint(
            "reviewer_ref IS NULL OR reviewer_ref <> author_ref", name="ck_assignment_rule_draft_maker_checker"
        ),
        sa.CheckConstraint(
            "effective_to IS NULL OR effective_from IS NULL OR effective_to > effective_from",
            name="ck_assignment_rule_draft_interval",
        ),
        sha256_check("manifest_sha256", "assignment_rule_draft", nullable=True),
        sa.CheckConstraint(
            "status IN ('DRAFT', 'ABANDONED') OR (manifest IS NOT NULL AND manifest_sha256 IS NOT NULL "
            "AND target_script_version_id IS NOT NULL)",
            name="ck_assignment_rule_draft_frozen",
        ),
        sa.CheckConstraint(
            "status <> 'PUBLISHED' OR published_rule_version_id IS NOT NULL", name="ck_assignment_rule_draft_published"
        ),
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_assignment_rule_draft_open ON {s}.assignment_rule_draft (rule_code) "
        "WHERE status IN ('DRAFT', 'SUBMITTED_FOR_REVIEW', 'APPROVED')"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.assignment_rule_draft_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          meta text[] := ARRAY['status', 'reviewer_ref', 'publisher_ref', 'published_rule_version_id',
                               'validation_status', 'manifest', 'manifest_sha256', 'updated_at', 'updated_by',
                               'row_version'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'assignment rule drafts are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'assignment rule drafts are created as DRAFT' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF OLD.status IN ('PUBLISHED', 'ABANDONED') THEN
            RAISE EXCEPTION 'a % assignment rule draft is immutable', OLD.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'DRAFT' AND (to_jsonb(NEW) - meta) IS DISTINCT FROM (to_jsonb(OLD) - meta) THEN
            RAISE EXCEPTION 'assignment rule content is locked once submitted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'DRAFT' AND OLD.manifest IS DISTINCT FROM NEW.manifest AND NEW.status <> 'DRAFT' THEN
            RAISE EXCEPTION 'a submitted manifest cannot change' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.status IS DISTINCT FROM OLD.status AND (OLD.status, NEW.status) NOT IN (
              ('DRAFT', 'SUBMITTED_FOR_REVIEW'), ('SUBMITTED_FOR_REVIEW', 'DRAFT'),
              ('SUBMITTED_FOR_REVIEW', 'APPROVED'), ('APPROVED', 'PUBLISHED'), ('DRAFT', 'ABANDONED')) THEN
            RAISE EXCEPTION 'invalid assignment rule draft transition % -> %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.status = 'APPROVED' AND NEW.reviewer_ref IS NULL THEN
            RAISE EXCEPTION 'approval needs a reviewer' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER assignment_rule_draft_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.assignment_rule_draft
          FOR EACH ROW EXECUTE FUNCTION {s}.assignment_rule_draft_guard();
    """)

    op.create_table(
        "assignment_rule_change_event",
        pk(),
        fk("draft_id", "assignment_rule_draft", s),
        sa.Column("rule_code", sa.String(40), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("actor_name", sa.String(120), nullable=False),
        sa.Column("reason", sa.Text),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("draft_id", "seq", name="uq_assignment_rule_change_event_seq"),
        enum_check("event_type", EVENT_TYPES, "ck_assignment_rule_change_event_type"),
        schema=s,
    )
    op.execute(f"CREATE INDEX ix_assignment_rule_change_event_code ON {s}.assignment_rule_change_event (rule_code)")
    op.execute(forbid_change_trigger(s, "assignment_rule_change_event"))

    op.create_table(
        "assignment_rule_publication",
        sa.Column(
            "rule_version_id",
            sa.Uuid(),
            sa.ForeignKey(f"{s}.script_assignment_rule_version.id"),
            primary_key=True,
        ),
        fk("draft_id", "assignment_rule_draft", s),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("is_fallback", sa.Boolean, nullable=False),
        sa.Column("approved_by", sa.String(80), nullable=False),
        sa.Column("published_by", sa.String(80), nullable=False),
        sa.Column("published_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "assignment_rule_publication"))

    # Published rule versions: immutable except the explicit retirement of a PUBLISHED version.
    op.execute(f"DROP TRIGGER script_assignment_rule_version_immutable ON {s}.script_assignment_rule_version")
    op.execute(f"""
        CREATE FUNCTION {s}.assignment_rule_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'published assignment rule versions are never deleted'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - ARRAY['status', 'effective_to']) IS DISTINCT FROM
             (to_jsonb(OLD) - ARRAY['status', 'effective_to'])
             OR OLD.status <> 'PUBLISHED' OR NEW.status NOT IN ('SUPERSEDED', 'WITHDRAWN')
             OR (OLD.effective_to IS NOT NULL AND NEW.effective_to IS DISTINCT FROM OLD.effective_to)
             OR NEW.effective_to IS NULL THEN
            RAISE EXCEPTION 'a published assignment rule version is immutable (only explicit retirement is allowed)'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER assignment_rule_version_guard BEFORE UPDATE OR DELETE ON {s}.script_assignment_rule_version
          FOR EACH ROW EXECUTE FUNCTION {s}.assignment_rule_version_guard();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.assignment_rule_draft")).scalar_one():
        raise RuntimeError("assignment rule drafts exist; downgrade would lose authored rules and their history")
    op.execute(f"DROP TRIGGER assignment_rule_version_guard ON {s}.script_assignment_rule_version")
    op.execute(f"DROP FUNCTION {s}.assignment_rule_version_guard()")
    op.execute(forbid_change_trigger(s, "script_assignment_rule_version"))
    op.drop_table("assignment_rule_publication", schema=s)
    op.drop_table("assignment_rule_change_event", schema=s)
    op.execute(f"DROP TRIGGER assignment_rule_draft_guard ON {s}.assignment_rule_draft")
    op.drop_table("assignment_rule_draft", schema=s)
    op.execute(f"DROP FUNCTION {s}.assignment_rule_draft_guard()")
