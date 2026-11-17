"""S2-C: deterministic script assignment — permission and the insert-only attempt ledger.

- ``script.assign`` (USER): apply a deterministic script assignment to an eligible, unassigned case. Not held by ADMIN or
  SC_CHECKER. Previewing needs only ``case.read``.
- ``script_assignment_attempt``: one row per applied evaluation (success or failure) with the full decision trace,
  input snapshot and SHA-256, the selected contact resolution, the resulting ``script_assignment`` (success only), the
  holds released or placed, and the idempotency-key digest (unique) so a retried request replays the stored result.
  Insert-only. The pinned ``script_assignment`` table (S0) is unchanged and stays immutable.

Revision ID: 0018_script_assignment_engine
Revises: 0017_assignment_rule_authoring
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, sha256_check

revision = "0018_script_assignment_engine"
down_revision = "0017_assignment_rule_authoring"
branch_labels = None
depends_on = None

CODE = "script.assign"
OUTCOMES = (
    "SELECTED",
    "SELECTED_BY_FALLBACK",
    "NO_MATCH",
    "AMBIGUOUS",
    "AMBIGUOUS_SAME_TARGET",
    "INPUT_MISSING",
    "TARGET_NOT_EFFECTIVE",
    "CONTACT_UNRESOLVED",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES "
        f"('{uuid.uuid5(uuid.NAMESPACE_URL, 'call360:permission:' + CODE)}', '{CODE}', NULL, false, "
        "'Apply a deterministic script assignment to an eligible unassigned case (S2-C)')"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) "
        f"SELECT r.id, p.id FROM {s}.role r, {s}.permission p WHERE r.code = 'USER' AND p.code = '{CODE}'"
    )
    op.create_table(
        "script_assignment_attempt",
        pk(),
        fk("callback_case_id", "callback_case", s),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("applied", sa.Boolean, nullable=False),
        fk("script_assignment_id", "script_assignment", s, nullable=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("decision", JSONB, nullable=False),
        sa.Column("input_snapshot", JSONB, nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("decision_sha256", sa.String(64), nullable=False),
        sa.Column("holds_released", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("holds_placed", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("idempotency_key_sha256", sa.String(64)),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("evaluated_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check("outcome", OUTCOMES, "ck_script_assignment_attempt_outcome"),
        enum_check("trigger", ("CASE", "BATCH"), "ck_script_assignment_attempt_trigger"),
        sa.CheckConstraint("applied = (script_assignment_id IS NOT NULL)", name="ck_script_assignment_attempt_applied"),
        sha256_check("input_sha256", "script_assignment_attempt"),
        sha256_check("decision_sha256", "script_assignment_attempt"),
        sha256_check("idempotency_key_sha256", "script_assignment_attempt", nullable=True),
        sa.UniqueConstraint("idempotency_key_sha256", name="uq_script_assignment_attempt_key"),
        schema=s,
    )
    op.execute(
        f"CREATE INDEX ix_script_assignment_attempt_case ON {s}.script_assignment_attempt (callback_case_id, created_at)"
    )
    op.execute(forbid_change_trigger(s, "script_assignment_attempt"))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.script_assignment_attempt")).scalar_one():
        raise RuntimeError("script assignment attempts exist; downgrade would lose assignment evidence")
    op.drop_table("script_assignment_attempt", schema=s)
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code = '{CODE}')"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{CODE}'")
