"""S3-B: deterministic compliance findings (governed finding rule sets; simulated findings; operational finding keys).

- ``finding_rule_set_version``: a versioned, governed set of structured finding rules per market (DRAFT →
  SUBMITTED_FOR_REVIEW → APPROVED → PUBLISHED → SUPERSEDED, or ABANDONED). Maker-checker is enforced by the service;
  the guard trigger makes rules immutable outside DRAFT, forbids deletes and only lets a PUBLISHED version become
  SUPERSEDED. One open version and one published version per market.
- ``finding_rule_set_event``: insert-only change history (created, edited, submitted, reviewed, published, abandoned).
- ``simulation_finding_set`` / ``simulation_finding``: insert-only simulated findings generated from an interactive
  run's answer evaluation (rule set version and checksum, engine version, input digest — unique per evaluation, so
  repeated generation returns the same set; each finding's deterministic key is unique, so no duplicates). Simulation
  only: never an operational finding, case state or KPI input.
- ``finding``: the governed category list gains ``POLICY_DATA_ISSUE`` and ``NARRATIVE_REVIEW`` (CHECK only; no row or
  column change, seed digest unchanged) and a partial unique index on ``evidence_refs->>'finding_key'`` makes
  engine-generated operational findings idempotent (verified on synthetic fixtures only; no real session is evaluated).

Revision ID: 0023_compliance_findings
Revises: 0022_answer_evaluation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, sha256_check

revision = "0023_compliance_findings"
down_revision = "0022_answer_evaluation"
branch_labels = None
depends_on = None

STATUSES = ("DRAFT", "SUBMITTED_FOR_REVIEW", "APPROVED", "PUBLISHED", "SUPERSEDED", "ABANDONED")
OLD_CATEGORIES = (
    "FACT_MISMATCH",
    "MISSING_MANDATORY_ANSWER",
    "UNCLEAR_UNDERSTANDING",
    "CONTRADICTORY_ANSWER",
    "DISCLOSURE_CONCERN",
)
NEW_CATEGORIES = (*OLD_CATEGORIES, "POLICY_DATA_ISSUE", "NARRATIVE_REVIEW")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "finding_rule_set_version",
        pk(),
        sa.Column("market_code", sa.String(2), nullable=False),
        sa.Column("version_no", sa.Integer, nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="DRAFT"),
        sa.Column("rules", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("rules_sha256", sa.String(64), nullable=False),
        fk("based_on_id", "finding_rule_set_version", s, nullable=True),
        sa.Column("change_summary", sa.String(500)),
        sa.Column("content_approval_status", sa.String(24), nullable=False, server_default="SYNTHETIC_UNAPPROVED"),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("submitted_by", sa.String(80)),
        sa.Column("submitted_at", TS),
        sa.Column("reviewed_by", sa.String(80)),
        sa.Column("review_reason", sa.String(500)),
        sa.Column("reviewed_at", TS),
        sa.Column("published_by", sa.String(80)),
        sa.Column("published_at", TS),
        sa.Column("superseded_at", TS),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("market_code", "version_no", name="uq_finding_rule_set_version_no"),
        enum_check("status", STATUSES, "ck_finding_rule_set_version_status"),
        enum_check(
            "content_approval_status", ("SYNTHETIC_UNAPPROVED", "APPROVED_BY_SC"), "ck_finding_rule_set_approval"
        ),
        sha256_check("rules_sha256", "finding_rule_set_version"),
        sa.CheckConstraint("is_synthetic", name="ck_finding_rule_set_version_synthetic"),
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_finding_rule_set_published ON {s}.finding_rule_set_version (market_code) "
        "WHERE status = 'PUBLISHED'"
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_finding_rule_set_open ON {s}.finding_rule_set_version (market_code) "
        "WHERE status IN ('DRAFT', 'SUBMITTED_FOR_REVIEW', 'APPROVED')"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.finding_rule_set_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'finding rule set versions are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'DRAFT' AND (NEW.rules IS DISTINCT FROM OLD.rules
              OR NEW.rules_sha256 IS DISTINCT FROM OLD.rules_sha256) THEN
            RAISE EXCEPTION 'finding rules are immutable outside DRAFT' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status IN ('SUPERSEDED', 'ABANDONED') THEN
            RAISE EXCEPTION 'a % finding rule set is final', OLD.status USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status = 'PUBLISHED' AND NOT (NEW.status = 'SUPERSEDED'
              AND (to_jsonb(NEW) - ARRAY['status', 'superseded_at', 'updated_at', 'row_version'])
                  = (to_jsonb(OLD) - ARRAY['status', 'superseded_at', 'updated_at', 'row_version'])) THEN
            RAISE EXCEPTION 'a published finding rule set is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER finding_rule_set_guard BEFORE UPDATE OR DELETE ON {s}.finding_rule_set_version
          FOR EACH ROW EXECUTE FUNCTION {s}.finding_rule_set_guard();
    """)
    op.create_table(
        "finding_rule_set_event",
        pk(),
        fk("rule_set_version_id", "finding_rule_set_version", s),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("reason", sa.String(500)),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "finding_rule_set_event"))
    op.create_table(
        "simulation_finding_set",
        pk(),
        sa.Column("finding_set_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("market_code", sa.String(2), nullable=False),
        fk("evaluation_id", "simulation_answer_evaluation", s),
        fk("rule_set_version_id", "finding_rule_set_version", s),
        sa.Column("rule_set_status", sa.String(24), nullable=False),
        sa.Column("rule_set_sha256", sa.String(64), nullable=False),
        sa.Column("engine_version", sa.String(80), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("findings", JSONB, nullable=False),
        sa.Column("not_converted", JSONB, nullable=False),
        sa.Column("human_assessment", JSONB, nullable=False),
        sa.Column("summary", JSONB, nullable=False),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("evaluation_id", "input_sha256", name="uq_simulation_finding_set_input"),
        sha256_check("rule_set_sha256", "simulation_finding_set"),
        sha256_check("input_sha256", "simulation_finding_set"),
        sa.CheckConstraint("is_synthetic", name="ck_simulation_finding_set_synthetic"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_finding_set"))
    op.create_table(
        "simulation_finding",
        pk(),
        fk("finding_set_id", "simulation_finding_set", s),
        sa.Column("finding_key", sa.String(64), nullable=False, unique=True),
        sa.Column("question_code", sa.String(60), nullable=False),
        sa.Column("finding_class", sa.String(24), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("review_required", sa.Boolean, nullable=False),
        sa.Column("rule_code", sa.String(48), nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check("category", NEW_CATEGORIES, "ck_simulation_finding_category"),
        enum_check("severity", ("LOW", "MEDIUM", "HIGH", "CRITICAL"), "ck_simulation_finding_severity"),
        sha256_check("finding_key", "simulation_finding"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_finding"))
    op.execute(f"ALTER TABLE {s}.finding DROP CONSTRAINT ck_finding_category")
    op.execute(
        f"ALTER TABLE {s}.finding ADD CONSTRAINT ck_finding_category CHECK (category IN ({_in(NEW_CATEGORIES)}))"
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_finding_engine_key ON {s}.finding ((evidence_refs->>'finding_key')) "
        "WHERE evidence_refs ? 'finding_key'"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.finding_rule_set_version) + (SELECT count(*) FROM {s}.finding "
            f"WHERE category IN ('POLICY_DATA_ISSUE', 'NARRATIVE_REVIEW') OR evidence_refs ? 'finding_key')"
        )
    ).scalar_one()
    if used:
        raise RuntimeError("finding rule sets or engine findings exist; downgrade would lose them")
    op.execute(f"DROP INDEX {s}.uq_finding_engine_key")
    op.execute(f"ALTER TABLE {s}.finding DROP CONSTRAINT ck_finding_category")
    op.execute(
        f"ALTER TABLE {s}.finding ADD CONSTRAINT ck_finding_category CHECK (category IN ({_in(OLD_CATEGORIES)}))"
    )
    for t in ("simulation_finding", "simulation_finding_set", "finding_rule_set_event"):
        op.drop_table(t, schema=s)
    op.execute(f"DROP TRIGGER finding_rule_set_guard ON {s}.finding_rule_set_version")
    op.drop_table("finding_rule_set_version", schema=s)
    op.execute(f"DROP FUNCTION {s}.finding_rule_set_guard()")
