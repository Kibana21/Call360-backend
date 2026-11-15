"""CP0.2 governed code lists, version 1 (reference data only; S0_DATA_MODEL §6.1, D-26, D-36, D-37).

Synthetic development fixtures, not AIA-approved business rules. No tables are created. Each activation is
audited idempotently (CONFIG.CODE_LIST_VERSION_ACTIVATED); a downgrade audits the removal.

Revision ID: 0007_governed_values
Revises: 0006_case_evidence
"""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

from app.domain.catalog import CP02_TABLES
from app.domain.governed import VALUES, audit_governed_removal, seed_governed, version_id

revision = "0007_governed_values"
down_revision = "0006_case_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    seed_governed(op.get_bind(), s)


def downgrade() -> None:
    """Development-only. Removing reference data that business rows reference would orphan history, so
    this refuses unless every CP0.2 table is empty. The CP0.1B-1 guards are suspended only for this delete."""
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    populated = [t for t in CP02_TABLES if conn.execute(text(f"SELECT EXISTS (SELECT 1 FROM {s}.{t})")).scalar()]
    if populated:
        raise RuntimeError(f"refusing to remove governed values while CP0.2 data exists ({', '.join(populated)})")
    ids = [version_id(code) for code in VALUES]
    audit_governed_removal(conn, s)  # append-only history: the removal is audited, never erased
    op.execute(f"ALTER TABLE {s}.code_value DISABLE TRIGGER code_value_guard")
    op.execute(f"ALTER TABLE {s}.code_list_version DISABLE TRIGGER code_list_version_guard")
    conn.execute(text(f"DELETE FROM {s}.code_value WHERE code_list_version_id = ANY(:ids)"), {"ids": ids})
    conn.execute(text(f"DELETE FROM {s}.code_list_version WHERE id = ANY(:ids)"), {"ids": ids})
    op.execute(f"ALTER TABLE {s}.code_list_version ENABLE TRIGGER code_list_version_guard")
    op.execute(f"ALTER TABLE {s}.code_value ENABLE TRIGGER code_value_guard")
