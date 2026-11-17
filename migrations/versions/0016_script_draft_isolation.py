"""S2-A.1: draft isolation of question and control-link changes, audited Abandon Draft.

Owner refinements on accepting S2-A (2026-11-17):

- ``script_version_control_link``: a draft's control / regulatory-reference links belong to that draft only. They
  are copied from the base version when the draft is created (and from the question's latest published version when
  a question is added), change only while the draft is DRAFT (``script_child_guard``) and are frozen into the
  manifest at submission. The concept-level ``control_mapping`` library (seeded S0 links) is no longer changed by
  authoring, so editing one draft can never change another draft or a seeded version's displayed links.
- ``question_revision_detail``: intent and category are recorded with each new question revision (insert-only)
  instead of being updated on the shared ``question_bank_item``. Seeded revisions have no detail row and keep the
  bank item's values; ``question_revision`` itself is unchanged, so the seed content digest is unchanged.
- ``ABANDONED`` script-version status: DRAFT → ABANDONED only, with a reason, audited and recorded in the change
  history; nothing is deleted and the abandoned content is frozen (sections, module questions, links and the draft's
  own unpublished modules).

Revision ID: 0016_script_draft_isolation
Revises: 0015_script_authoring
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, provenance

revision = "0016_script_draft_isolation"
down_revision = "0015_script_authoring"
branch_labels = None
depends_on = None

VERSION_STATUS = (
    "DRAFT",
    "SUBMITTED_FOR_REVIEW",
    "APPROVED",
    "SCHEDULED",
    "PUBLISHED",
    "SUPERSEDED",
    "WITHDRAWN",
    "ABANDONED",
)
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
OLD_EVENT_TYPES = EVENT_TYPES[:-1]
OLD_VERSION_STATUS = VERSION_STATUS[:-1]
CATEGORIES = (
    "SALES_CONDUCT",
    "PRODUCT_UNDERSTANDING",
    "POLICY_FACT",
    "ELEVATED_RISK",
    "IDENTITY",
    "DISCLOSURE",
    "OTHER",
)


def _guard_sql(s: str, *, abandon: bool) -> str:
    transitions = (
        "('DRAFT', 'SUBMITTED_FOR_REVIEW'), ('SUBMITTED_FOR_REVIEW', 'DRAFT'), "
        "('SUBMITTED_FOR_REVIEW', 'APPROVED'), ('APPROVED', 'SCHEDULED'), ('APPROVED', 'PUBLISHED'), "
        "('APPROVED', 'WITHDRAWN'), ('SCHEDULED', 'PUBLISHED'), ('SCHEDULED', 'WITHDRAWN'), "
        "('PUBLISHED', 'SUPERSEDED'), ('PUBLISHED', 'WITHDRAWN')" + (", ('DRAFT', 'ABANDONED')" if abandon else "")
    )
    leaves_draft = "OLD.status = 'DRAFT' AND NEW.status <> 'ABANDONED'" if abandon else "OLD.status = 'DRAFT'"
    return f"""
        CREATE OR REPLACE FUNCTION {s}.script_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          allowed text[] := ARRAY['status', 'effective_from', 'effective_to', 'published_at', 'reviewer_ref',
                                  'updated_at', 'updated_by', 'row_version'];
          ok boolean;
        BEGIN
          IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'script versions are created as DRAFT' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF TG_OP = 'DELETE' THEN
            IF OLD.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'a % script version cannot be deleted', OLD.status USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.status <> 'DRAFT' THEN
            IF (to_jsonb(NEW) - allowed) IS DISTINCT FROM (to_jsonb(OLD) - allowed)
               OR (OLD.effective_from IS NOT NULL AND NEW.effective_from IS DISTINCT FROM OLD.effective_from)
               OR (OLD.effective_to IS NOT NULL AND NEW.effective_to IS DISTINCT FROM OLD.effective_to)
               OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
               OR (OLD.reviewer_ref IS NOT NULL AND NEW.reviewer_ref IS DISTINCT FROM OLD.reviewer_ref) THEN
              RAISE EXCEPTION 'script_version content is immutable once it leaves DRAFT'
                USING ERRCODE = 'insufficient_privilege';
            END IF;
          END IF;
          IF NEW.status = OLD.status THEN RETURN NEW; END IF;
          ok := (OLD.status, NEW.status) IN ({transitions});
          IF NOT ok THEN
            RAISE EXCEPTION 'invalid script_version transition % -> %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF {leaves_draft} THEN
            IF NEW.manifest IS NULL OR NEW.manifest_sha256 IS NULL OR NEW.validation_status <> 'VALID' THEN
              RAISE EXCEPTION 'a version leaves DRAFT only with a validated manifest and checksum'
                USING ERRCODE = 'check_violation';
            END IF;
          END IF;
          IF NEW.status IN ('PUBLISHED', 'SCHEDULED') AND EXISTS (
              SELECT 1 FROM {s}.script_section sc JOIN {s}.script_module m ON m.id = sc.script_module_id
               WHERE sc.script_version_id = NEW.id AND m.status = 'DRAFT') THEN
            RAISE EXCEPTION 'a version is published only when all its modules are published'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.status = 'APPROVED' AND NEW.reviewer_ref IS NULL THEN
            RAISE EXCEPTION 'approval requires a reviewer distinct from the author' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.status IN ('SUPERSEDED', 'WITHDRAWN') AND OLD.status = 'PUBLISHED' AND NEW.effective_to IS NULL THEN
            RAISE EXCEPTION 'retiring a published version sets effective_to' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
    """


def _module_lock_sql(s: str, frozen: str) -> str:
    return f"""
        CREATE OR REPLACE FUNCTION {s}.script_draft_module_lock() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          v_module uuid;
          v_status text;
        BEGIN
          IF TG_TABLE_NAME = 'script_section' THEN
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            SELECT status INTO v_status FROM {s}.script_module WHERE id = NEW.script_module_id;
            IF v_status = 'DRAFT' AND EXISTS (
                SELECT 1 FROM {s}.script_section x WHERE x.script_module_id = NEW.script_module_id
                   AND x.script_version_id <> NEW.script_version_id) THEN
              RAISE EXCEPTION 'a draft module belongs to one script version' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF TG_TABLE_NAME = 'script_module' THEN
            v_module := CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END;
            IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status
               AND (to_jsonb(NEW) - ARRAY['status', 'updated_at', 'updated_by', 'row_version'])
                   = (to_jsonb(OLD) - ARRAY['status', 'updated_at', 'updated_by', 'row_version']) THEN
              RETURN NEW;  -- publication of the module itself
            END IF;
          ELSE
            v_module := CASE WHEN TG_OP = 'DELETE' THEN OLD.script_module_id ELSE NEW.script_module_id END;
          END IF;
          IF EXISTS (SELECT 1 FROM {s}.script_section sc JOIN {s}.script_version v ON v.id = sc.script_version_id
                      WHERE sc.script_module_id = v_module AND v.status IN ({frozen})
                        AND (SELECT status FROM {s}.script_module WHERE id = v_module) = 'DRAFT') THEN
            RAISE EXCEPTION 'module content is locked while its script version is under review or abandoned'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END $$;
    """


def _replace_check(s: str, table: str, name: str, column: str, values: tuple[str, ...]) -> None:
    op.execute(f"ALTER TABLE {s}.{table} DROP CONSTRAINT {name}")
    allowed = ", ".join(f"'{v}'" for v in values)
    op.execute(f"ALTER TABLE {s}.{table} ADD CONSTRAINT {name} CHECK ({column} IN ({allowed}))")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    # ---- Abandon Draft ------------------------------------------------------------------------------------------
    _replace_check(s, "script_version", "ck_script_version_status", "status", VERSION_STATUS)
    _replace_check(s, "script_change_event", "ck_script_change_event_type", "event_type", EVENT_TYPES)
    op.execute(_guard_sql(s, abandon=True))
    op.execute(_module_lock_sql(s, "'SUBMITTED_FOR_REVIEW', 'APPROVED', 'ABANDONED'"))

    # ---- per-revision intent and category -----------------------------------------------------------------------
    op.create_table(
        "question_revision_detail",
        sa.Column("question_revision_id", sa.Uuid(), sa.ForeignKey(f"{s}.question_revision.id"), primary_key=True),
        sa.Column("intent", sa.String(300), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        enum_check("category", CATEGORIES, "ck_question_revision_detail_category"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "question_revision_detail"))

    # ---- draft-scoped control links -----------------------------------------------------------------------------
    op.create_table(
        "script_version_control_link",
        pk(),
        fk("script_version_id", "script_version", s),
        fk("question_bank_item_id", "question_bank_item", s),
        fk("control_id", "control", s),
        fk("regulatory_reference_id", "regulatory_reference", s, nullable=True),
        sa.Column("rationale", sa.String(500), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("copied_from", sa.String(40), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("updated_at", TS),
        sa.Column("updated_by", sa.String(80)),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        *provenance("script_version_control_link"),
        enum_check("status", ("PROPOSED", "RETIRED"), "ck_script_version_control_link_status"),
        enum_check(
            "copied_from",
            ("BASE_VERSION", "PUBLISHED_QUESTION", "CONCEPT_LIBRARY", "AUTHOR", "MIGRATION_0016"),
            "ck_script_version_control_link_origin",
        ),
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_script_version_control_link ON {s}.script_version_control_link "
        "(script_version_id, question_bank_item_id, control_id, "
        "coalesce(regulatory_reference_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE status <> 'RETIRED'"
    )
    op.execute(
        f"CREATE INDEX ix_script_version_control_link_version ON {s}.script_version_control_link (script_version_id)"
    )
    op.execute(
        f"CREATE TRIGGER script_version_control_link_guard BEFORE INSERT OR UPDATE OR DELETE "
        f"ON {s}.script_version_control_link FOR EACH ROW EXECUTE FUNCTION "
        f"{s}.script_child_guard('script_version', 'script_version_id')"
    )
    # Existing drafts get their own copy of the links they currently show (from the concept-level library).
    conn = op.get_bind()
    conn.execute(
        sa.text(
            f"INSERT INTO {s}.script_version_control_link (id, script_version_id, question_bank_item_id, control_id, "
            "regulatory_reference_id, rationale, status, copied_from, created_by, source_type, source_system, "
            "source_reference, source_observed_at, recorded_at, is_synthetic) "
            "SELECT gen_random_uuid(), x.vid, cm.question_bank_item_id, cm.control_id, cm.regulatory_reference_id, "
            "cm.rationale, 'PROPOSED', 'MIGRATION_0016', 'SYSTEM:migration-0016', 'MANUAL', 'CALL360_SCRIPT_STUDIO', "
            "'migration-0016:draft-control-links', now(), now(), true FROM "
            f"(SELECT DISTINCT v.id AS vid, qr.question_bank_item_id FROM {s}.script_version v "
            f"JOIN {s}.script_section ss ON ss.script_version_id = v.id "
            f"JOIN {s}.module_question mq ON mq.script_module_id = ss.script_module_id "
            f"JOIN {s}.question_revision qr ON qr.id = mq.question_revision_id WHERE v.status = 'DRAFT') x "
            f"JOIN {s}.control_mapping cm ON cm.question_bank_item_id = x.question_bank_item_id "
            "AND cm.status <> 'RETIRED'"
        )
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.script_version WHERE status = 'ABANDONED'")).scalar_one():
        raise RuntimeError("abandoned script versions exist; downgrade would lose their status")
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.question_revision_detail")).scalar_one():
        raise RuntimeError("question revisions with recorded intent/category exist; downgrade would lose them")
    op.drop_table("script_version_control_link", schema=s)
    op.drop_table("question_revision_detail", schema=s)
    op.execute(_module_lock_sql(s, "'SUBMITTED_FOR_REVIEW', 'APPROVED'"))
    op.execute(_guard_sql(s, abandon=False))
    _replace_check(s, "script_change_event", "ck_script_change_event_type", "event_type", OLD_EVENT_TYPES)
    _replace_check(s, "script_version", "ck_script_version_status", "status", OLD_VERSION_STATUS)
