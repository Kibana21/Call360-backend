"""CP0.2 SBQ callback-selection risk (3 tables; S0_DATA_MODEL §4.3, D-30, D-31).

Risk assessments are persisted records only; no code computes a band or score (ADR-0008 §1, D-4).

Revision ID: 0004_sbq_risk
Revises: 0003_party_policy_sale
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from app.db.ddl import (
    CONTENT_APPROVAL,
    TS,
    code_ref,
    code_ref_trigger,
    enum_check,
    fk,
    forbid_change_trigger,
    operational,
    pk,
    provenance,
    sha256_check,
)

revision = "0004_sbq_risk"
down_revision = "0003_party_policy_sale"
branch_labels = None
depends_on = None

TABLES = ("risk_rule_set_version", "risk_assessment", "risk_factor_result")
FUNCTIONS = ("assert_code_ref", "risk_assessment_guard", "risk_successor_check", "risk_factor_result_guard")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    op.create_table(
        "risk_rule_set_version",
        pk(),
        sa.Column("code", sa.String(40), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("effective_from", TS, nullable=False),
        sa.Column("effective_to", TS),
        sa.Column("rules", JSONB, nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("content_approval_status", sa.String(24), nullable=False),
        sa.Column("author_ref", sa.String(80), nullable=False),
        sa.Column("checker_ref", sa.String(80), nullable=False),
        *operational(mutable=False),
        *provenance("risk_rule_set_version"),
        sa.UniqueConstraint("code", "version", name="uq_risk_rule_set_version"),
        enum_check("status", ("PUBLISHED", "SUPERSEDED", "WITHDRAWN"), "ck_risk_rule_set_status"),
        enum_check("content_approval_status", CONTENT_APPROVAL, "ck_risk_rule_set_approval"),
        sa.CheckConstraint("author_ref <> checker_ref", name="ck_risk_rule_set_maker_checker"),
        sa.CheckConstraint("effective_to IS NULL OR effective_to > effective_from", name="ck_risk_rule_set_interval"),
        sha256_check("checksum", "risk_rule_set_version"),
        schema=s,
    )
    op.create_table(
        "risk_assessment",
        pk(),
        fk("sale_event_id", "sale_event", s),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        *code_ref("risk_assessment", "band_code", "band_list_version_id", s),
        sa.Column("score", sa.Numeric(8, 3)),
        sa.Column("reason_codes", ARRAY(sa.String(40)), nullable=False, server_default="{}"),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("source_original_value", sa.String(80)),
        fk("rule_set_version_id", "risk_rule_set_version", s, nullable=True),
        sa.Column("assessed_at", TS, nullable=False),
        sa.Column("valid_at", TS, nullable=False),
        sa.Column("input_snapshot_sha256", sa.String(64), nullable=False),
        fk("supersedes_id", "risk_assessment", s, nullable=True),
        *operational(mutable=True),
        *provenance("risk_assessment"),
        # Only SBQ callback-selection risk lives here; suitability and finding severity never do (INV-08).
        sa.CheckConstraint("kind = 'CALLBACK_SELECTION'", name="ck_risk_assessment_kind"),
        enum_check("origin", ("SOURCE_ASSIGNED", "RULE_ASSESSED", "MANUAL"), "ck_risk_assessment_origin"),
        enum_check("status", ("PROVISIONAL", "FINAL", "SUPERSEDED"), "ck_risk_assessment_status"),
        sa.CheckConstraint("band_code IS NOT NULL", name="ck_risk_assessment_band_required"),
        sa.CheckConstraint(
            "origin <> 'RULE_ASSESSED' OR rule_set_version_id IS NOT NULL", name="ck_risk_assessment_rule_set"
        ),
        sa.CheckConstraint("score IS NULL OR rule_set_version_id IS NOT NULL", name="ck_risk_assessment_score"),
        sa.UniqueConstraint("supersedes_id", name="uq_risk_assessment_successor"),
        sha256_check("input_snapshot_sha256", "risk_assessment"),
        schema=s,
    )
    op.create_index("ix_risk_assessment_sale", "risk_assessment", ["sale_event_id"], schema=s)
    op.create_table(
        "risk_factor_result",
        pk(),
        fk("assessment_id", "risk_assessment", s),
        *code_ref("risk_factor_result", "factor_code", "factor_list_version_id", s),
        sa.Column("value_type", sa.String(16), nullable=False),
        sa.Column("value", JSONB, nullable=False),
        sa.Column("source", sa.String(80), nullable=False),
        sa.Column("matched_rule_id", sa.String(40)),
        sa.Column("weight", sa.Numeric(8, 3)),
        sa.Column("result", sa.String(16), nullable=False),
        *operational(mutable=False),
        *provenance("risk_factor_result"),
        sa.CheckConstraint("factor_code IS NOT NULL", name="ck_risk_factor_result_factor_required"),
        enum_check("value_type", ("ENUM", "BOOLEAN", "NUMBER", "TEXT"), "ck_risk_factor_result_value_type"),
        enum_check("result", ("MATCHED", "NOT_MATCHED", "NOT_EVALUATED"), "ck_risk_factor_result_result"),
        sa.UniqueConstraint("assessment_id", "factor_code", name="uq_risk_factor_result"),
        schema=s,
    )

    op.execute(f"""
        -- Governed decision code references (S0_DATA_MODEL §2.1, D-30). The composite FK proves the code is
        -- in the referenced version; this trigger proves the version belongs to the expected list and was
        -- ACTIVE when the decision was recorded. Unchanged pairs are never re-validated (history is stable).
        -- Arguments: list code, code column, version column.
        CREATE FUNCTION {s}.assert_code_ref() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          v_code text := to_jsonb(NEW) ->> TG_ARGV[1];
          v_ver  text := to_jsonb(NEW) ->> TG_ARGV[2];
          v_list text;
          v_status text;
        BEGIN
          IF v_code IS NULL AND v_ver IS NULL THEN RETURN NEW; END IF;
          IF TG_OP = 'UPDATE' AND v_code IS NOT DISTINCT FROM (to_jsonb(OLD) ->> TG_ARGV[1])
             AND v_ver IS NOT DISTINCT FROM (to_jsonb(OLD) ->> TG_ARGV[2]) THEN
            RETURN NEW;
          END IF;
          SELECT cl.code, clv.status INTO v_list, v_status
            FROM {s}.code_list_version clv JOIN {s}.code_list cl ON cl.id = clv.code_list_id
           WHERE clv.id = v_ver::uuid;
          IF v_list IS DISTINCT FROM TG_ARGV[0] THEN
            RAISE EXCEPTION '%.% references list %, expected %', TG_TABLE_NAME, TG_ARGV[1], v_list, TG_ARGV[0]
              USING ERRCODE = 'check_violation';
          END IF;
          IF v_status IS DISTINCT FROM 'ACTIVE' THEN
            RAISE EXCEPTION '%.% references a % version of %', TG_TABLE_NAME, TG_ARGV[1], v_status, TG_ARGV[0]
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;

        -- D-31: only the status changes, and only PROVISIONAL -> FINAL, or -> SUPERSEDED once a successor
        -- referencing this row exists. SUPERSEDED is terminal. Assessments are never deleted.
        CREATE FUNCTION {s}.risk_assessment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE frozen text[] := ARRAY['status', 'updated_at', 'updated_by', 'row_version'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'risk_assessment rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.status = 'SUPERSEDED' THEN
              RAISE EXCEPTION 'an assessment cannot be inserted as SUPERSEDED' USING ERRCODE = 'check_violation';
            END IF;
            IF NEW.supersedes_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM {s}.risk_assessment p WHERE p.id = NEW.supersedes_id
                   AND p.sale_event_id = NEW.sale_event_id AND p.status IN ('PROVISIONAL', 'FINAL')) THEN
              RAISE EXCEPTION 'a successor must supersede a current assessment of the same sale'
                USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (to_jsonb(NEW) - frozen) IS DISTINCT FROM (to_jsonb(OLD) - frozen) THEN
            RAISE EXCEPTION 'risk_assessment content is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.status = OLD.status THEN RETURN NEW; END IF;
          IF OLD.status = 'PROVISIONAL' AND NEW.status = 'FINAL' THEN RETURN NEW; END IF;
          IF OLD.status IN ('PROVISIONAL', 'FINAL') AND NEW.status = 'SUPERSEDED' THEN
            IF NOT EXISTS (SELECT 1 FROM {s}.risk_assessment r WHERE r.supersedes_id = OLD.id) THEN
              RAISE EXCEPTION 'supersession requires a successor referencing this assessment'
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'invalid risk_assessment transition % -> %', OLD.status, NEW.status
            USING ERRCODE = 'insufficient_privilege';
        END $$;
        CREATE TRIGGER risk_assessment_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.risk_assessment
          FOR EACH ROW EXECUTE FUNCTION {s}.risk_assessment_guard();

        -- At commit, a successor's predecessor must be SUPERSEDED (supersession is always linked, D-31).
        CREATE FUNCTION {s}.risk_successor_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM {s}.risk_assessment p WHERE p.id = NEW.supersedes_id AND p.status = 'SUPERSEDED') THEN
            RAISE EXCEPTION 'assessment % supersedes % but the predecessor was not marked SUPERSEDED',
              NEW.id, NEW.supersedes_id USING ERRCODE = 'check_violation';
          END IF;
          RETURN NULL;
        END $$;
        CREATE CONSTRAINT TRIGGER risk_successor_check AFTER INSERT ON {s}.risk_assessment
          DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.supersedes_id IS NOT NULL)
          EXECUTE FUNCTION {s}.risk_successor_check();

        -- Factor results are written while the assessment is PROVISIONAL and frozen afterwards.
        CREATE FUNCTION {s}.risk_factor_result_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE v_status text;
        BEGIN
          SELECT status INTO v_status FROM {s}.risk_assessment
           WHERE id = CASE WHEN TG_OP = 'INSERT' THEN NEW.assessment_id ELSE OLD.assessment_id END;
          IF v_status IS DISTINCT FROM 'PROVISIONAL' THEN
            RAISE EXCEPTION 'factor results of a % assessment are immutable', v_status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END $$;
        CREATE TRIGGER risk_factor_result_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.risk_factor_result
          FOR EACH ROW EXECUTE FUNCTION {s}.risk_factor_result_guard();

        {forbid_change_trigger(s, "risk_rule_set_version")}
        {code_ref_trigger(s, "risk_assessment", "band_code", "band_list_version_id", "sbq_risk_band")}
        {code_ref_trigger(s, "risk_factor_result", "factor_code", "factor_list_version_id", "risk_factor")}
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    for table in reversed(TABLES):
        op.drop_table(table, schema=s)
    for fn in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {s}.{fn}()")
