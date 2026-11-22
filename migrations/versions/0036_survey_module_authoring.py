"""LIB-2 — a reusable MODULE authored on its own. ONE additive column and three guards; no new table.

Until now every definition in ``survey_definition`` was a survey. A module could only be written inside a survey's
draft and became reusable when that survey was published (owner decision LIB-D-1). LIB-2 lets a module be drafted,
validated, reviewed by three different people and published WITHOUT a survey, and it does so with the governance that
already exists rather than a second copy of it: a standalone module is a definition whose ``artifact_kind`` is
``MODULE``. Its draft, its immutable candidates, its published versions, its lifecycle history, the freezing of what
it pins, the identity rules of the lifecycle trigger and the market rule are the existing tables and triggers,
unchanged.

* ``survey_definition.artifact_kind`` — ``SURVEY`` (the default: every existing row is a survey, exactly as before) or
  ``MODULE``. It never changes after the row is written (trigger).
* A ``MODULE`` definition is an authoring and publication record only. It is not a survey and can never be treated as
  one: the database itself refuses a simulation, a call plan or an assignment binding that names one
  (``survey_module_not_a_survey``), whatever the application does.

Nothing existing is rewritten: no asset, candidate, version, manifest, fingerprint or lifecycle event is touched, so
every historical fingerprint is what it was. Used only when ``survey_module_authoring_enabled`` is on.

Revision ID: 0036_survey_module_authoring
Revises: 0035_survey_execution_assurance
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036_survey_module_authoring"
down_revision = "0035_survey_execution_assurance"
branch_labels = None
depends_on = None

#: tables whose rows stand for a SURVEY that is simulated, planned or assigned
SURVEY_ONLY = ("survey_simulation", "survey_call_plan", "survey_assignment_binding")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"ALTER TABLE {s}.survey_definition ADD COLUMN artifact_kind varchar(8) NOT NULL DEFAULT 'SURVEY' "
        "CONSTRAINT ck_survey_definition_artifact_kind CHECK (artifact_kind IN ('SURVEY', 'MODULE'))"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.survey_definition_kind_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.artifact_kind IS DISTINCT FROM OLD.artifact_kind THEN
            RAISE EXCEPTION 'the kind of a definition never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_definition_kind_guard BEFORE UPDATE ON {s}.survey_definition
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_definition_kind_guard();
        CREATE FUNCTION {s}.survey_module_not_a_survey() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF EXISTS (SELECT 1 FROM {s}.survey_definition d
                     WHERE d.id = NEW.survey_definition_id AND d.artifact_kind <> 'SURVEY') THEN
            RAISE EXCEPTION 'a standalone module is not a survey: it cannot be simulated, planned or assigned as one'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
    """)
    for table in SURVEY_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_survey_only BEFORE INSERT ON {s}.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION {s}.survey_module_not_a_survey()"
        )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(
        sa.text(f"SELECT count(*) FROM {s}.survey_definition WHERE artifact_kind <> 'SURVEY'")
    ).scalar_one():
        # without the column a standalone module would read as a survey, and its governed history would be mislabelled
        raise RuntimeError("standalone modules exist; downgrade would turn them into surveys")
    for table in SURVEY_ONLY:
        op.execute(f"DROP TRIGGER {table}_survey_only ON {s}.{table}")
    op.execute(f"DROP TRIGGER survey_definition_kind_guard ON {s}.survey_definition")
    op.execute(f"DROP FUNCTION {s}.survey_module_not_a_survey()")
    op.execute(f"DROP FUNCTION {s}.survey_definition_kind_guard()")
    op.execute(f"ALTER TABLE {s}.survey_definition DROP COLUMN artifact_kind")
