"""LIB-1 — server-issued asset codes for the reusable component library.

ADDITIVE ONLY: one sequence and one insert-only table. No existing table, row, code or reference is changed; every
historical asset code stays exactly as it is. Used only when ``survey_library_enabled`` is on.

* ``survey_code_seq`` — the one source of new code numbers. A sequence never returns a value twice, also across
  concurrent transactions and after a rolled-back one, so a failed operation can never make a code reusable.
* ``survey_issued_code`` — every code the server issued: to which survey, of which kind, by whom, when. The primary key
  is the code, so no code is ever issued twice whatever the allocator does. Insert-only.

Revision ID: 0028_survey_library
Revises: 0027_survey_definitions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.db.ddl import forbid_change_trigger

revision = "0028_survey_library"
down_revision = "0027_survey_definitions"
branch_labels = None
depends_on = None

KINDS = ("MODULE", "ITEM", "CONDITION", "OPTION_SET")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    kinds = ", ".join(f"'{k}'" for k in KINDS)
    op.execute(f"CREATE SEQUENCE {s}.survey_code_seq START WITH 100001 INCREMENT BY 1 NO CYCLE")
    op.execute(
        f"""
        CREATE TABLE {s}.survey_issued_code (
            code varchar(64) PRIMARY KEY,
            kind varchar(16) NOT NULL CHECK (kind IN ({kinds})),
            survey_definition_id uuid NOT NULL REFERENCES {s}.survey_definition (id),
            issued_by varchar(80) NOT NULL,
            issued_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(f"CREATE INDEX survey_issued_code_survey ON {s}.survey_issued_code (survey_definition_id, kind)")
    op.execute(forbid_change_trigger(s, "survey_issued_code"))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.survey_issued_code")).scalar_one():
        # the record of what was issued is what keeps a code from ever being issued again
        raise RuntimeError("server-issued survey codes exist; downgrade would lose the record of them")
    op.drop_table("survey_issued_code", schema=s)
    op.execute(f"DROP SEQUENCE {s}.survey_code_seq")
