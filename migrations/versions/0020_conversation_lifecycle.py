"""S2-D.1: conversation lifecycle configuration and gate outcomes.

- ``script_module.kind`` gains the lifecycle stages OPENING, IDENTITY, DISCLOSURE, CONSENT and CLOSING (existing kinds
  COMMON / PRODUCT / RISK / LANGUAGE remain the verification stage).
- ``question_revision_detail`` (insert-only, authored revisions only) gains the item's lifecycle role, failure
  behaviour, whether it discloses policy information, and whether a closing statement is delivered on termination.
  Seeded revisions have no detail row and remain verification items; ``question_revision`` itself is unchanged, so the
  seed content digest and every published version are unchanged.
- ``script_simulation_run`` status / outcome gain TERMINATED (a gate or event ended the conversation).

Revision ID: 0020_conversation_lifecycle
Revises: 0019_script_simulation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_conversation_lifecycle"
down_revision = "0019_script_simulation"
branch_labels = None
depends_on = None

OLD_KINDS = ("COMMON", "PRODUCT", "RISK", "LANGUAGE")
KINDS = (*OLD_KINDS, "OPENING", "IDENTITY", "DISCLOSURE", "CONSENT", "CLOSING")
ROLES = (
    "OPENING_STATEMENT",
    "IDENTITY_CHECK",
    "DISCLOSURE",
    "CONSENT_TO_PROCEED",
    "RECORDING_CONSENT",
    "CLOUD_PROCESSING_CONSENT",
    "VERIFICATION",
    "CLOSING_STATEMENT",
)
ON_FAILURE = (
    "TERMINATE",
    "CONTINUE",
    "CONTINUE_FLAGGED",
    "CONTINUE_WITHOUT_RECORDING",
    "CONTINUE_WITHOUT_CLOUD_PROCESSING",
)
OLD_STATUS = ("IN_PROGRESS", "SEQUENCE_FINISHED", "COMPLETED", "INCOMPLETE", "ABANDONED")
OLD_OUTCOME = ("COMPLETED", "INCOMPLETE", "ABANDONED")


def _check(s: str, table: str, name: str, expr: str) -> None:
    op.execute(f"ALTER TABLE {s}.{table} DROP CONSTRAINT {name}")
    op.execute(f"ALTER TABLE {s}.{table} ADD CONSTRAINT {name} CHECK ({expr})")


def _in(col: str, values: tuple[str, ...], nullable: bool = False) -> str:
    expr = f"{col} IN ({', '.join(repr(v) for v in values)})"
    return f"{col} IS NULL OR {expr}" if nullable else expr


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    _check(s, "script_module", "ck_script_module_kind", _in("kind", KINDS))
    op.add_column("question_revision_detail", sa.Column("lifecycle_role", sa.String(32)), schema=s)
    op.add_column("question_revision_detail", sa.Column("on_failure", sa.String(40)), schema=s)
    op.add_column(
        "question_revision_detail",
        sa.Column("discloses_policy_information", sa.Boolean, nullable=False, server_default=sa.false()),
        schema=s,
    )
    op.add_column(
        "question_revision_detail",
        sa.Column("deliver_on_termination", sa.Boolean, nullable=False, server_default=sa.false()),
        schema=s,
    )
    op.execute(
        f"ALTER TABLE {s}.question_revision_detail ADD CONSTRAINT ck_question_revision_detail_role "
        f"CHECK ({_in('lifecycle_role', ROLES, True)})"
    )
    op.execute(
        f"ALTER TABLE {s}.question_revision_detail ADD CONSTRAINT ck_question_revision_detail_on_failure "
        f"CHECK ({_in('on_failure', ON_FAILURE, True)})"
    )
    _check(s, "script_simulation_run", "ck_script_simulation_run_status", _in("status", (*OLD_STATUS, "TERMINATED")))
    _check(
        s,
        "script_simulation_run",
        "ck_script_simulation_run_outcome",
        _in("outcome", (*OLD_OUTCOME, "TERMINATED"), True),
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    for sql, what in (
        (f"SELECT count(*) FROM {s}.script_module WHERE kind NOT IN {OLD_KINDS}", "lifecycle modules"),
        (f"SELECT count(*) FROM {s}.question_revision_detail WHERE lifecycle_role IS NOT NULL", "lifecycle items"),
        (f"SELECT count(*) FROM {s}.script_simulation_run WHERE status = 'TERMINATED'", "terminated simulations"),
    ):
        if conn.execute(sa.text(sql)).scalar_one():
            raise RuntimeError(f"{what} exist; downgrade would lose them")
    _check(s, "script_simulation_run", "ck_script_simulation_run_outcome", _in("outcome", OLD_OUTCOME, True))
    _check(s, "script_simulation_run", "ck_script_simulation_run_status", _in("status", OLD_STATUS))
    op.execute(f"ALTER TABLE {s}.question_revision_detail DROP CONSTRAINT ck_question_revision_detail_on_failure")
    op.execute(f"ALTER TABLE {s}.question_revision_detail DROP CONSTRAINT ck_question_revision_detail_role")
    for col in ("deliver_on_termination", "discloses_policy_information", "on_failure", "lifecycle_role"):
        op.drop_column("question_revision_detail", col, schema=s)
    _check(s, "script_module", "ck_script_module_kind", _in("kind", OLD_KINDS))
