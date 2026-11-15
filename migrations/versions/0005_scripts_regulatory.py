"""CP0.2 scripts, questions, assignment and regulatory references (12 tables; S0_DATA_MODEL §4.4).

Seeded and read-only in S0: there is no authoring, publishing or assignment engine (ADR-0007, ADR-0008 §1).
The lifecycle triggers still enforce ADR-0005 §3 so seeded content obeys the same rules later stages will.

Revision ID: 0005_scripts_regulatory
Revises: 0004_sbq_risk
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import (
    CONTENT_APPROVAL,
    TS,
    enum_check,
    fk,
    forbid_change_trigger,
    market_trigger,
    operational,
    pk,
    provenance,
    sha256_check,
    uid,
)

revision = "0005_scripts_regulatory"
down_revision = "0004_sbq_risk"
branch_labels = None
depends_on = None

VERSION_STATUS = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED", "SCHEDULED", "PUBLISHED", "SUPERSEDED", "WITHDRAWN")
TABLES = (
    "script_family",
    "script_module",
    "script_version",
    "script_section",
    "question_bank_item",
    "question_revision",
    "module_question",
    "script_assignment_rule_version",
    "script_assignment",
    "regulatory_reference",
    "control",
    "control_mapping",
)
FUNCTIONS = (
    "script_version_valid_at(uuid, timestamp with time zone)",
    "script_version_guard()",
    "script_module_guard()",
    "script_child_guard()",
    "assignment_rule_check()",
    "script_assignment_check()",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    op.create_table(
        "script_family",
        pk(),
        sa.Column("code", sa.String(40), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("purpose", sa.String(40), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        *operational(mutable=True),
        *provenance("script_family"),
        schema=s,
    )
    op.create_table(
        "script_module",
        pk(),
        sa.Column("code", sa.String(40), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        *operational(mutable=True),
        *provenance("script_module"),
        sa.UniqueConstraint("code", "revision", name="uq_script_module"),
        enum_check("kind", ("COMMON", "PRODUCT", "RISK", "LANGUAGE"), "ck_script_module_kind"),
        enum_check("status", ("DRAFT", "PUBLISHED", "SUPERSEDED", "WITHDRAWN"), "ck_script_module_status"),
        schema=s,
    )
    op.create_table(
        "script_version",
        pk(),
        fk("script_family_id", "script_family", s),
        sa.Column("version_label", sa.String(16), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("validation_status", sa.String(16), nullable=False),
        sa.Column("language", sa.String(16), nullable=False),
        sa.Column("effective_from", TS),
        sa.Column("effective_to", TS),
        sa.Column("manifest", JSONB),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("author_ref", sa.String(80), nullable=False),
        sa.Column("reviewer_ref", sa.String(80)),
        sa.Column("published_at", TS),
        sa.Column("content_approval_status", sa.String(24), nullable=False),
        fk("supersedes_id", "script_version", s, nullable=True),
        *operational(mutable=True),
        *provenance("script_version"),
        sa.UniqueConstraint("script_family_id", "version_label", name="uq_script_version"),
        enum_check("status", VERSION_STATUS, "ck_script_version_status"),
        enum_check("validation_status", ("NOT_VALIDATED", "VALID", "INVALID"), "ck_script_version_validation"),
        enum_check("content_approval_status", CONTENT_APPROVAL, "ck_script_version_approval"),
        sa.CheckConstraint(
            "reviewer_ref IS NULL OR reviewer_ref <> author_ref", name="ck_script_version_maker_checker"
        ),
        sa.CheckConstraint(
            "status NOT IN ('PUBLISHED', 'SUPERSEDED') OR (published_at IS NOT NULL AND effective_from IS NOT NULL)",
            name="ck_script_version_published",
        ),
        sa.CheckConstraint(
            "effective_to IS NULL OR (effective_from IS NOT NULL AND effective_to >= effective_from)",
            name="ck_script_version_interval",
        ),
        sha256_check("manifest_sha256", "script_version", nullable=True),
        schema=s,
    )
    op.create_table(
        "script_section",
        pk(),
        fk("script_version_id", "script_version", s),
        fk("script_module_id", "script_module", s),
        sa.Column("position", sa.SmallInteger, nullable=False),
        sa.Column("inclusion_condition", JSONB),
        *operational(mutable=True),
        *provenance("script_section"),
        sa.UniqueConstraint("script_version_id", "position", name="uq_script_section_position"),
        schema=s,
    )
    op.create_table(
        "question_bank_item",
        pk(),
        sa.Column("question_code", sa.String(60), nullable=False, unique=True),
        sa.Column("intent", sa.Text, nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        *operational(mutable=True),
        *provenance("question_bank_item"),
        schema=s,
    )
    op.create_table(
        "question_revision",
        pk(),
        fk("question_bank_item_id", "question_bank_item", s),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("language", sa.String(16), nullable=False),
        sa.Column("customer_wording", sa.Text, nullable=False),
        sa.Column("delivery_mode", sa.String(16), nullable=False),
        sa.Column("answer_type", sa.String(16), nullable=False),
        sa.Column("answer_schema", JSONB, nullable=False),
        sa.Column("mandatory", sa.Boolean, nullable=False),
        sa.Column("expected_answer_policy", sa.String(32), nullable=False),
        sa.Column("expected_value", JSONB),
        sa.Column("acceptable_variants", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("policy_fact_key", sa.String(60)),
        sa.Column("unacceptable_outcomes", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("not_applicable_predicate", JSONB),
        sa.Column("evidence_required", sa.Boolean, nullable=False),
        sa.Column("escalation_rule_ref", sa.String(40)),
        sa.Column("max_reprompts", sa.SmallInteger, nullable=False),
        sa.Column("content_approval_status", sa.String(24), nullable=False),
        *operational(mutable=False),
        *provenance("question_revision"),
        sa.UniqueConstraint("question_bank_item_id", "revision", "language", name="uq_question_revision"),
        enum_check("delivery_mode", ("CONVERSATIONAL", "CONTROLLED_TTS", "EXACT_AUDIO"), "ck_question_revision_mode"),
        enum_check(
            "answer_type", ("YES_NO", "NUMERIC", "ENUM", "FREE_TEXT", "ACKNOWLEDGEMENT"), "ck_question_revision_type"
        ),
        enum_check(
            "expected_answer_policy",
            ("EXACT_BOOLEAN", "NUMERIC_MATCH_POLICY_FACT", "ACKNOWLEDGEMENT", "NARRATIVE_REVIEW", "COLLECT_ONLY"),
            "ck_question_revision_policy",
        ),
        enum_check("content_approval_status", CONTENT_APPROVAL, "ck_question_revision_approval"),
        sa.CheckConstraint(
            "(expected_answer_policy = 'NUMERIC_MATCH_POLICY_FACT') = (policy_fact_key IS NOT NULL)",
            name="ck_question_revision_fact_key",
        ),
        sa.CheckConstraint(
            "expected_answer_policy <> 'EXACT_BOOLEAN' OR expected_value IS NOT NULL",
            name="ck_question_revision_expected",
        ),
        schema=s,
    )
    op.create_table(
        "module_question",
        pk(),
        fk("script_module_id", "script_module", s),
        fk("question_revision_id", "question_revision", s),
        sa.Column("position", sa.SmallInteger, nullable=False),
        sa.Column("branch_condition", JSONB),
        *operational(mutable=True),
        *provenance("module_question"),
        sa.UniqueConstraint("script_module_id", "position", name="uq_module_question_position"),
        schema=s,
    )
    op.create_table(
        "script_assignment_rule_version",
        pk(),
        sa.Column("rule_code", sa.String(40), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("predicate", JSONB, nullable=False),
        sa.Column("priority", sa.SmallInteger, nullable=False),
        sa.Column("specificity", sa.SmallInteger, nullable=False),
        fk("target_script_version_id", "script_version", s),
        sa.Column("effective_from", TS, nullable=False),
        sa.Column("effective_to", TS),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("author_ref", sa.String(80), nullable=False),
        sa.Column("checker_ref", sa.String(80), nullable=False),
        *operational(mutable=False),
        *provenance("script_assignment_rule_version"),
        sa.UniqueConstraint("rule_code", "version", name="uq_assignment_rule_version"),
        enum_check("status", ("PUBLISHED", "SUPERSEDED", "WITHDRAWN"), "ck_assignment_rule_status"),
        sa.CheckConstraint("author_ref <> checker_ref", name="ck_assignment_rule_maker_checker"),
        sa.CheckConstraint("effective_to IS NULL OR effective_to > effective_from", name="ck_assignment_rule_interval"),
        sha256_check("checksum", "script_assignment_rule_version"),
        schema=s,
    )
    op.create_table(
        "script_assignment",
        pk(),
        sa.Column("callback_case_id", uid(), nullable=False),  # FK added by 0006 with callback_case
        fk("script_version_id", "script_version", s),
        sa.Column("script_manifest_sha256", sa.String(64), nullable=False),
        fk("risk_assessment_id", "risk_assessment", s, nullable=True),
        fk("policy_fact_snapshot_id", "policy_fact_snapshot", s),
        fk("matched_rule_version_id", "script_assignment_rule_version", s, nullable=True),
        sa.Column("rule_trace", JSONB, nullable=False),
        sa.Column("input_snapshot", JSONB, nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("assigned_at", TS, nullable=False),
        sa.Column("assigned_by", sa.String(80), nullable=False),
        fk("supersedes_id", "script_assignment", s, nullable=True),
        *operational(mutable=False),
        *provenance("script_assignment"),
        enum_check("origin", ("SEED", "ENGINE", "MANUAL_APPROVED"), "ck_script_assignment_origin"),
        sha256_check("script_manifest_sha256", "script_assignment"),
        sha256_check("input_sha256", "script_assignment"),
        schema=s,
    )
    op.create_index("ix_script_assignment_case", "script_assignment", ["callback_case_id"], schema=s)
    op.create_table(
        "regulatory_reference",
        pk(),
        sa.Column("issuer", sa.String(80), nullable=False),
        sa.Column("jurisdiction", sa.String(40), nullable=False),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("document_version", sa.String(40), nullable=False),
        sa.Column("url", sa.String(300)),
        sa.Column("published_on", sa.Date),
        sa.Column("interpretation_status", sa.String(24), nullable=False),
        *operational(mutable=True),
        *provenance("regulatory_reference"),
        enum_check(
            "interpretation_status",
            ("NOT_REVIEWED", "UNDER_REVIEW", "INTERPRETED_APPROVED", "NOT_APPLICABLE"),
            "ck_regulatory_reference_status",
        ),
        schema=s,
    )
    op.create_table(
        "control",
        pk(),
        sa.Column("control_code", sa.String(40), nullable=False, unique=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("owner_role", sa.String(60), nullable=False),
        sa.Column("content_approval_status", sa.String(24), nullable=False),
        *operational(mutable=True),
        *provenance("control"),
        enum_check("content_approval_status", CONTENT_APPROVAL, "ck_control_approval"),
        schema=s,
    )
    op.create_table(
        "control_mapping",
        pk(),
        fk("question_bank_item_id", "question_bank_item", s),
        fk("control_id", "control", s),
        fk("regulatory_reference_id", "regulatory_reference", s, nullable=True),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        *operational(mutable=True),
        *provenance("control_mapping"),
        enum_check("status", ("PROPOSED", "ACTIVE", "RETIRED"), "ck_control_mapping_status"),
        schema=s,
    )

    op.execute(f"""
        -- Historical validity (D-32, INV-09): a version was published and effective at ts, whatever its status now.
        CREATE FUNCTION {s}.script_version_valid_at(p_version uuid, p_ts timestamptz) RETURNS boolean
          LANGUAGE sql STABLE AS $$
          SELECT EXISTS (
            SELECT 1 FROM {s}.script_version v
             WHERE v.id = p_version AND v.status IN ('PUBLISHED', 'SUPERSEDED', 'WITHDRAWN')
               AND v.published_at IS NOT NULL AND v.published_at <= p_ts
               AND v.effective_from IS NOT NULL AND v.effective_from <= p_ts
               AND (v.effective_to IS NULL OR p_ts < v.effective_to))
        $$;

        -- ADR-0007 lifecycle; content frozen once a version leaves DRAFT (ADR-0005 §3, D-32).
        CREATE FUNCTION {s}.script_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
        CREATE TRIGGER script_version_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.script_version
          FOR EACH ROW EXECUTE FUNCTION {s}.script_version_guard();

        CREATE FUNCTION {s}.script_module_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE allowed text[] := ARRAY['status', 'updated_at', 'updated_by', 'row_version'];
        BEGIN
          IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'script modules are created as DRAFT' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF TG_OP = 'DELETE' THEN
            IF OLD.status <> 'DRAFT' THEN
              RAISE EXCEPTION 'a % module cannot be deleted', OLD.status USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.status <> 'DRAFT' AND (to_jsonb(NEW) - allowed) IS DISTINCT FROM (to_jsonb(OLD) - allowed) THEN
            RAISE EXCEPTION 'script_module content is immutable once published' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.status <> OLD.status AND (OLD.status, NEW.status) NOT IN (
              ('DRAFT', 'PUBLISHED'), ('PUBLISHED', 'SUPERSEDED'), ('PUBLISHED', 'WITHDRAWN')) THEN
            RAISE EXCEPTION 'invalid script_module transition % -> %', OLD.status, NEW.status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER script_module_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.script_module
          FOR EACH ROW EXECUTE FUNCTION {s}.script_module_guard();

        -- Sections and module questions change only while their parent is DRAFT.
        -- Arguments: parent table, parent FK column.
        CREATE FUNCTION {s}.script_child_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          v_parent uuid := ((CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END) ->> TG_ARGV[1])::uuid;
          v_status text;
        BEGIN
          EXECUTE format('SELECT status FROM {s}.%I WHERE id = $1', TG_ARGV[0]) INTO v_status USING v_parent;
          IF v_status IS DISTINCT FROM 'DRAFT' THEN
            RAISE EXCEPTION '% of a % % is immutable', TG_TABLE_NAME, v_status, TG_ARGV[0]
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'UPDATE' AND (to_jsonb(OLD) ->> TG_ARGV[1]) IS DISTINCT FROM (to_jsonb(NEW) ->> TG_ARGV[1]) THEN
            RAISE EXCEPTION '% cannot move to another %', TG_TABLE_NAME, TG_ARGV[0]
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END $$;
        CREATE TRIGGER script_section_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.script_section
          FOR EACH ROW EXECUTE FUNCTION {s}.script_child_guard('script_version', 'script_version_id');
        CREATE TRIGGER module_question_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.module_question
          FOR EACH ROW EXECUTE FUNCTION {s}.script_child_guard('script_module', 'script_module_id');

        -- Rules target a version that has left DRAFT.
        CREATE FUNCTION {s}.assignment_rule_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF EXISTS (SELECT 1 FROM {s}.script_version WHERE id = NEW.target_script_version_id AND status = 'DRAFT') THEN
            RAISE EXCEPTION 'an assignment rule cannot target a DRAFT script version' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER assignment_rule_check BEFORE INSERT ON {s}.script_assignment_rule_version
          FOR EACH ROW EXECUTE FUNCTION {s}.assignment_rule_check();

        -- An assignment freezes a version that was published and effective when assigned, with its checksum.
        CREATE FUNCTION {s}.script_assignment_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT {s}.script_version_valid_at(NEW.script_version_id, NEW.assigned_at) THEN
            RAISE EXCEPTION 'script version was not published and effective at assignment time'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM {s}.script_version WHERE id = NEW.script_version_id
                            AND manifest_sha256 = NEW.script_manifest_sha256) THEN
            RAISE EXCEPTION 'assignment manifest checksum does not match the version' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.matched_rule_version_id IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM {s}.script_assignment_rule_version r
               WHERE r.id = NEW.matched_rule_version_id AND r.target_script_version_id = NEW.script_version_id) THEN
            RAISE EXCEPTION 'matched rule does not target the assigned version' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER script_assignment_check BEFORE INSERT ON {s}.script_assignment
          FOR EACH ROW EXECUTE FUNCTION {s}.script_assignment_check();

        {forbid_change_trigger(s, "question_revision")}
        {forbid_change_trigger(s, "script_assignment_rule_version")}
        {forbid_change_trigger(s, "script_assignment")}
        {market_trigger(s, "script_family")}
        {market_trigger(s, "regulatory_reference")}
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    for table in reversed(TABLES):
        op.drop_table(table, schema=s)
    for fn in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {s}.{fn}")
