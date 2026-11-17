"""S2-A: editable Script Studio — authoring permissions, S&C checker role, draft locking, change history.

The S0 script model (0005) is reused unchanged in shape; this migration only adjusts lifecycle guards for authoring:

- ``script.edit`` is activated and granted to USER (IDENTITY_AUTHORIZATION_AND_AUDIT §matrix: "Create script draft:
  USER → SCRIPT_EDIT"). ``script.approve`` and ``script.publish`` are activated and granted only to a new role
  ``SC_CHECKER`` (S&C script checker), mapped from the local group ``LOCAL_SC_CHECKER_SG`` (Singapore scope). ADMIN
  holds none of them (ADR-0004 §6). The second-user rule is enforced by the service and by
  ``ck_script_version_maker_checker`` (owner decision D-54, proposed).
- ``script_version_guard``: a version may be submitted and approved while its own new modules are still DRAFT (the
  checker must see content before anything is published); every module must be published before the version
  becomes PUBLISHED or SCHEDULED. All other rules are unchanged (content frozen once the version leaves DRAFT).
- ``script_draft_module_lock``: a DRAFT module belongs to exactly one script version, and its content (name, kind,
  questions) is frozen while that version is SUBMITTED_FOR_REVIEW or APPROVED.
- ``script_change_event``: insert-only change history of script versions (who changed what, why, and the reviewer
  decisions), readable with ``script.read``.

Revision ID: 0015_script_authoring
Revises: 0014_transcript
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, forbid_change_trigger, pk
from app.security.scope import CHECKER_MAPPINGS, audit_scope_removal, seed_scope

revision = "0015_script_authoring"
down_revision = "0014_transcript"
branch_labels = None
depends_on = None

NS = uuid.UUID("6f1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d")
ROLE = "SC_CHECKER"
GROUP = "LOCAL_SC_CHECKER_SG"
CHECKER_PERMISSIONS = (
    "script.approve",
    "script.publish",
    "script.read",
    "dashboard.read",
    "case.read",
    "policy.read",
    "risk.read",
    "search.use",
    "queue.read",
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
)


def _id(kind: str, code: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"0015:{kind}:{code}")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    # ---- permissions, checker role and group ------------------------------------------------------------------
    op.execute(
        f"UPDATE {s}.permission SET reserved = false, description = CASE code "
        "WHEN 'script.edit' THEN 'Create and edit script drafts and submit them for review (S2-A)' "
        "WHEN 'script.approve' THEN 'Approve or return a submitted script version; never your own (S2-A)' "
        "ELSE 'Publish an approved script version; never your own (S2-A)' END "
        "WHERE code IN ('script.edit', 'script.approve', 'script.publish')"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT r.id, p.id FROM {s}.role r, "
        f"{s}.permission p WHERE r.code = 'USER' AND p.code = 'script.edit'"
    )
    conn = op.get_bind()
    conn.execute(
        sa.text(f"INSERT INTO {s}.role (id, code, name) VALUES (:i, :c, 'S&C script checker (synthetic, S2-A)')"),
        {"i": _id("role", ROLE), "c": ROLE},
    )
    conn.execute(
        sa.text(
            f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT :r, id FROM {s}.permission "
            "WHERE code = ANY(:p)"
        ),
        {"r": _id("role", ROLE), "p": list(CHECKER_PERMISSIONS)},
    )
    conn.execute(
        sa.text(
            f"INSERT INTO {s}.app_group (id, identity_provider_id, external_group_id, code, name, status) "
            f"SELECT :i, id, NULL, :c, 'Local S&C script checkers — SG (synthetic)', 'ACTIVE' "
            f"FROM {s}.identity_provider WHERE issuer = 'call360-local'"
        ),
        {"i": _id("group", GROUP), "c": GROUP},
    )
    conn.execute(
        sa.text(
            f"INSERT INTO {s}.group_role_mapping (id, group_id, role_id, approved_by) "
            "VALUES (:i, :g, :r, 'SYSTEM:migration-0015')"
        ),
        {"i": _id("grm", GROUP), "g": _id("group", GROUP), "r": _id("role", ROLE)},
    )
    seed_scope(conn, s, CHECKER_MAPPINGS)

    # ---- change history ---------------------------------------------------------------------------------------
    op.create_table(
        "script_change_event",
        pk(),
        sa.Column("script_version_id", sa.Uuid(), sa.ForeignKey(f"{s}.script_version.id"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("actor_name", sa.String(120), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("script_version_id", "seq", name="uq_script_change_event_seq"),
        enum_check("event_type", EVENT_TYPES, "ck_script_change_event_type"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "script_change_event"))

    # ---- lifecycle guards ---------------------------------------------------------------------------------------
    op.execute(f"""
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
          ok := (OLD.status, NEW.status) IN (
            ('DRAFT', 'SUBMITTED_FOR_REVIEW'), ('SUBMITTED_FOR_REVIEW', 'DRAFT'),
            ('SUBMITTED_FOR_REVIEW', 'APPROVED'), ('APPROVED', 'SCHEDULED'), ('APPROVED', 'PUBLISHED'),
            ('APPROVED', 'WITHDRAWN'), ('SCHEDULED', 'PUBLISHED'), ('SCHEDULED', 'WITHDRAWN'),
            ('PUBLISHED', 'SUPERSEDED'), ('PUBLISHED', 'WITHDRAWN'));
          IF NOT ok THEN
            RAISE EXCEPTION 'invalid script_version transition % -> %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status = 'DRAFT' THEN
            IF NEW.manifest IS NULL OR NEW.manifest_sha256 IS NULL OR NEW.validation_status <> 'VALID' THEN
              RAISE EXCEPTION 'a version leaves DRAFT only with a validated manifest and checksum'
                USING ERRCODE = 'check_violation';
            END IF;
          END IF;
          -- S2-A: modules are published together with their version, after independent approval.
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

        -- A DRAFT module belongs to one version and is frozen while that version is under review or approved.
        CREATE FUNCTION {s}.script_draft_module_lock() RETURNS trigger LANGUAGE plpgsql AS $$
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
                      WHERE sc.script_module_id = v_module AND v.status IN ('SUBMITTED_FOR_REVIEW', 'APPROVED')
                        AND (SELECT status FROM {s}.script_module WHERE id = v_module) = 'DRAFT') THEN
            RAISE EXCEPTION 'module content is locked while its script version is under review'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END $$;
        CREATE TRIGGER script_section_module_lock BEFORE INSERT OR UPDATE ON {s}.script_section
          FOR EACH ROW EXECUTE FUNCTION {s}.script_draft_module_lock();
        CREATE TRIGGER script_module_lock BEFORE UPDATE OR DELETE ON {s}.script_module
          FOR EACH ROW EXECUTE FUNCTION {s}.script_draft_module_lock();
        CREATE TRIGGER module_question_lock BEFORE INSERT OR UPDATE OR DELETE ON {s}.module_question
          FOR EACH ROW EXECUTE FUNCTION {s}.script_draft_module_lock();
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(f"DROP TRIGGER IF EXISTS module_question_lock ON {s}.module_question")
    op.execute(f"DROP TRIGGER IF EXISTS script_module_lock ON {s}.script_module")
    op.execute(f"DROP TRIGGER IF EXISTS script_section_module_lock ON {s}.script_section")
    op.execute(f"DROP FUNCTION IF EXISTS {s}.script_draft_module_lock()")
    op.drop_table("script_change_event", schema=s)
    conn = op.get_bind()
    audit_scope_removal(conn, s, CHECKER_MAPPINGS)
    conn.execute(sa.text(f"DELETE FROM {s}.group_scope_mapping WHERE group_id = :g"), {"g": _id("group", GROUP)})
    conn.execute(sa.text(f"DELETE FROM {s}.group_membership WHERE group_id = :g"), {"g": _id("group", GROUP)})
    conn.execute(sa.text(f"DELETE FROM {s}.group_role_mapping WHERE group_id = :g"), {"g": _id("group", GROUP)})
    conn.execute(sa.text(f"DELETE FROM {s}.app_group WHERE id = :g"), {"g": _id("group", GROUP)})
    conn.execute(sa.text(f"DELETE FROM {s}.role_permission WHERE role_id = :r"), {"r": _id("role", ROLE)})
    conn.execute(sa.text(f"DELETE FROM {s}.role WHERE id = :r"), {"r": _id("role", ROLE)})
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission "
        "WHERE code IN ('script.edit', 'script.approve', 'script.publish'))"
    )
    op.execute(
        f"UPDATE {s}.permission SET reserved = true, description = 'Reserved (S2)' "
        "WHERE code IN ('script.edit', 'script.approve', 'script.publish')"
    )
    op.execute(_S0_GUARD.replace("{s}", s))


# The 0005 definition, restored on downgrade (modules must be published before the version leaves DRAFT).
_S0_GUARD = """
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
  ok := (OLD.status, NEW.status) IN (
    ('DRAFT', 'SUBMITTED_FOR_REVIEW'), ('SUBMITTED_FOR_REVIEW', 'DRAFT'),
    ('SUBMITTED_FOR_REVIEW', 'APPROVED'), ('APPROVED', 'SCHEDULED'), ('APPROVED', 'PUBLISHED'),
    ('APPROVED', 'WITHDRAWN'), ('SCHEDULED', 'PUBLISHED'), ('SCHEDULED', 'WITHDRAWN'),
    ('PUBLISHED', 'SUPERSEDED'), ('PUBLISHED', 'WITHDRAWN'));
  IF NOT ok THEN
    RAISE EXCEPTION 'invalid script_version transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status = 'DRAFT' THEN
    IF NEW.manifest IS NULL OR NEW.manifest_sha256 IS NULL OR NEW.validation_status <> 'VALID' THEN
      RAISE EXCEPTION 'a version leaves DRAFT only with a validated manifest and checksum'
        USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM {s}.script_section sc JOIN {s}.script_module m ON m.id = sc.script_module_id
                WHERE sc.script_version_id = NEW.id AND m.status = 'DRAFT') THEN
      RAISE EXCEPTION 'a version leaves DRAFT only when all its modules are published'
        USING ERRCODE = 'check_violation';
    END IF;
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
