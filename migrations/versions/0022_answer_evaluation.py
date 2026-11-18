"""S3-A: deterministic answer evaluation (evaluation methods on question revisions; simulation evaluation evidence).

- ``question_revision``: the expected-answer policy vocabulary gains the S3-A structured methods ``NUMERIC_COMPARE``,
  ``ENUM_MATCH`` and ``ENUM_MATCH_POLICY_FACT``. Only CHECK constraints change (no column is added or altered and no
  row is touched, so seeded content and its digest are unchanged). The structured rule (operator, value, unit,
  tolerance and its approval reference, accepted options) is stored in the existing ``expected_value`` JSON; a fact
  mapping in the existing ``policy_fact_key``.
- ``simulation_answer_evaluation``: insert-only evidence of evaluating an interactive simulation run — the run, the
  exact event prefix evaluated (count and SHA-256), the script version and content checksum (draft content snapshot
  or the published manifest), the immutable policy fact snapshot (id + SHA-256), the engine version, an input digest,
  per-question results with explanations and totals. Re-evaluating identical inputs returns the existing record;
  different inputs create a new one; nothing is overwritten. Simulation records only: no answer observation, rule
  evaluation, finding, verification, case state or KPI input is written.

Revision ID: 0022_answer_evaluation
Revises: 0021_simulation_workbench
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, fk, forbid_change_trigger, pk, sha256_check

revision = "0022_answer_evaluation"
down_revision = "0021_simulation_workbench"
branch_labels = None
depends_on = None

OLD = ("EXACT_BOOLEAN", "NUMERIC_MATCH_POLICY_FACT", "ACKNOWLEDGEMENT", "NARRATIVE_REVIEW", "COLLECT_ONLY")
NEW = (*OLD, "NUMERIC_COMPARE", "ENUM_MATCH", "ENUM_MATCH_POLICY_FACT")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _constraints(s: str, policies: tuple[str, ...], fact: tuple[str, ...], valued: tuple[str, ...]) -> None:
    t = f"{s}.question_revision"
    for c in ("ck_question_revision_policy", "ck_question_revision_fact_key", "ck_question_revision_expected"):
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {c}")
    op.execute(
        f"ALTER TABLE {t} ADD CONSTRAINT ck_question_revision_policy CHECK (expected_answer_policy IN ({_in(policies)}))"
    )
    op.execute(
        f"ALTER TABLE {t} ADD CONSTRAINT ck_question_revision_fact_key CHECK "
        f"((expected_answer_policy IN ({_in(fact)})) = (policy_fact_key IS NOT NULL))"
    )
    op.execute(
        f"ALTER TABLE {t} ADD CONSTRAINT ck_question_revision_expected CHECK "
        f"(expected_answer_policy NOT IN ({_in(valued)}) OR expected_value IS NOT NULL)"
    )


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    _constraints(
        s,
        NEW,
        ("NUMERIC_MATCH_POLICY_FACT", "ENUM_MATCH_POLICY_FACT"),
        ("EXACT_BOOLEAN", "NUMERIC_COMPARE", "ENUM_MATCH"),
    )
    op.create_table(
        "simulation_answer_evaluation",
        pk(),
        sa.Column("evaluation_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("market_code", sa.String(2), nullable=False),
        fk("run_id", "script_simulation_run", s),
        sa.Column("events_evaluated", sa.Integer, nullable=False),
        sa.Column("events_sha256", sa.String(64), nullable=False),
        fk("script_version_id", "script_version", s),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("content_source", sa.String(24), nullable=False),
        fk("policy_fact_snapshot_id", "policy_fact_snapshot", s),
        sa.Column("policy_fact_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("engine_version", sa.String(80), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("controller_status", sa.String(24), nullable=False),
        sa.Column("controller_outcome", sa.String(24)),
        sa.Column("results", JSONB, nullable=False),
        sa.Column("totals", JSONB, nullable=False),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("run_id", "input_sha256", name="uq_simulation_answer_evaluation_input"),
        sa.CheckConstraint("is_synthetic", name="ck_simulation_answer_evaluation_synthetic"),
        sa.CheckConstraint(
            "content_source IN ('PUBLISHED_MANIFEST', 'CONTENT_SNAPSHOT')", name="ck_simulation_answer_evaluation_src"
        ),
        sha256_check("events_sha256", "simulation_answer_evaluation"),
        sha256_check("content_sha256", "simulation_answer_evaluation"),
        sha256_check("policy_fact_snapshot_sha256", "simulation_answer_evaluation"),
        sha256_check("input_sha256", "simulation_answer_evaluation"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "simulation_answer_evaluation"))
    op.execute(
        f"CREATE INDEX ix_simulation_answer_evaluation_run ON {s}.simulation_answer_evaluation (run_id, created_at)"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.simulation_answer_evaluation) + (SELECT count(*) FROM "
            f"{s}.question_revision WHERE expected_answer_policy IN ({_in(NEW[len(OLD) :])}))"
        )
    ).scalar_one()
    if used:
        raise RuntimeError("answer evaluations or S3-A evaluation methods exist; downgrade would lose them")
    op.drop_table("simulation_answer_evaluation", schema=s)
    _constraints(s, OLD, ("NUMERIC_MATCH_POLICY_FACT",), ("EXACT_BOOLEAN",))
