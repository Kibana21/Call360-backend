"""S3-C: human review and case resolution (REV-002/003/004, COMP-009, S3-A5; review_decision designed in S0_DATA_MODEL).

- ``review_decision`` (the S0-designed, S3-deferred table): one immutable reviewer or checker action — finding
  dispositions, answer assessments, case actions (further callback, escalation, return to review), decision proposals
  and checker approvals — with actor, permission used, previous and resulting finding / case status, reason and reason
  code, evidence and readiness snapshot, and a unique idempotency key (a repeated submission returns the original).
- ``review_approval``: maker-checker requests for protected outcomes — final case decisions (VERIFIED,
  CLOSED_UNVERIFIED) and dispositions of material findings (dismiss, resolve). One pending request per case / finding;
  it records the case and finding row versions it was based on (stale when they change) and is decided once by a
  different user holding ``review.approve``.
- Permissions: ``review.decide`` is un-reserved and granted to USER and the S&C checker role; new ``review.approve``
  (checker capability) is granted to the S&C checker role only. ADMIN gets neither (no maker-checker bypass for
  administrators).

Revision ID: 0024_review_resolution
Revises: 0023_compliance_findings
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk

revision = "0024_review_resolution"
down_revision = "0023_compliance_findings"
branch_labels = None
depends_on = None

CHECKER_ROLE = "SC_CHECKER"
APPROVE = "review.approve"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "review_approval",
        pk(),
        sa.Column("approval_ref", sa.String(24), nullable=False, unique=True),
        fk("callback_case_id", "callback_case", s),
        fk("finding_id", "finding", s, nullable=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("proposed_action", sa.String(24), nullable=False),
        sa.Column("proposed_to_status", sa.String(24), nullable=False),
        sa.Column("closure_reason", sa.String(40)),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("readiness", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("case_row_version", sa.Integer, nullable=False),
        sa.Column("finding_row_version", sa.Integer),
        sa.Column("proposed_by", sa.String(80), nullable=False),
        sa.Column("proposed_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("decided_by", sa.String(80)),
        sa.Column("decided_at", TS),
        sa.Column("decision_reason", sa.String(1000)),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        enum_check("kind", ("CASE_DECISION", "FINDING_DISPOSITION"), "ck_review_approval_kind"),
        enum_check(
            "proposed_action", ("VERIFY", "CLOSE_UNVERIFIED", "DISMISS", "RESOLVE"), "ck_review_approval_action"
        ),
        enum_check("status", ("PENDING", "APPROVED", "REJECTED", "STALE", "WITHDRAWN"), "ck_review_approval_status"),
        sa.CheckConstraint(
            "(kind = 'FINDING_DISPOSITION') = (finding_id IS NOT NULL)", name="ck_review_approval_target"
        ),
        sa.CheckConstraint("decided_by IS NULL OR decided_by <> proposed_by", name="ck_review_approval_four_eyes"),
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_review_approval_case_pending ON {s}.review_approval (callback_case_id) "
        "WHERE status = 'PENDING' AND kind = 'CASE_DECISION'"
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_review_approval_finding_pending ON {s}.review_approval (finding_id) "
        "WHERE status = 'PENDING' AND kind = 'FINDING_DISPOSITION'"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.review_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE decided text[] := ARRAY['status', 'decided_by', 'decided_at', 'decision_reason', 'row_version'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'review approvals are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'PENDING' THEN
            RAISE EXCEPTION 'a % review approval is final', OLD.status USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - decided) IS DISTINCT FROM (to_jsonb(OLD) - decided) THEN
            RAISE EXCEPTION 'a review approval request is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER review_approval_guard BEFORE UPDATE OR DELETE ON {s}.review_approval
          FOR EACH ROW EXECUTE FUNCTION {s}.review_approval_guard();
    """)
    op.create_table(
        "review_decision",
        pk(),
        sa.Column("decision_ref", sa.String(24), nullable=False, unique=True),
        fk("callback_case_id", "callback_case", s),
        fk("finding_id", "finding", s, nullable=True),
        fk("question_execution_id", "question_execution", s, nullable=True),
        fk("approval_id", "review_approval", s, nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(24)),
        sa.Column("to_status", sa.String(24)),
        sa.Column("case_state_before", sa.String(24), nullable=False),
        sa.Column("case_state_after", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("reason_code", sa.String(40)),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("actor_permission", sa.String(64), nullable=False),
        sa.Column("checker_ref", sa.String(80)),
        sa.Column("idempotency_key", sa.String(80), nullable=False, unique=True),
        sa.Column("decided_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.CheckConstraint("length(reason) >= 5", name="ck_review_decision_reason"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "review_decision"))
    op.execute(f"CREATE INDEX ix_review_decision_case ON {s}.review_decision (callback_case_id, decided_at)")
    # ---- permissions ---------------------------------------------------------------------------------------------
    op.execute(
        f"UPDATE {s}.permission SET reserved = false, description = 'Review findings and cases: dispositions, "
        "assessments, escalation, further callback and decision proposals (S3-C)' WHERE code = 'review.decide'"
    )
    pid = uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + APPROVE)
    op.execute(
        f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES ('{pid}', '{APPROVE}', NULL, "
        "false, 'Approve or reject protected review outcomes proposed by another user; never your own (S3-C)')"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT r.id, p.id FROM {s}.role r, "
        f"{s}.permission p WHERE (r.code = 'USER' AND p.code = 'review.decide') "
        f"OR (r.code = '{CHECKER_ROLE}' AND p.code IN ('review.decide', '{APPROVE}')) "
        "ON CONFLICT DO NOTHING"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(f"SELECT (SELECT count(*) FROM {s}.review_decision) + (SELECT count(*) FROM {s}.review_approval)")
    ).scalar_one()
    if used:
        raise RuntimeError("review decisions or approvals exist; downgrade would lose them")
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code IN "
        f"('review.decide', '{APPROVE}'))"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{APPROVE}'")
    op.execute(f"UPDATE {s}.permission SET reserved = true, description = 'Reserved (S3)' WHERE code = 'review.decide'")
    op.drop_table("review_decision", schema=s)
    op.execute(f"DROP TRIGGER review_approval_guard ON {s}.review_approval")
    op.drop_table("review_approval", schema=s)
    op.execute(f"DROP FUNCTION {s}.review_approval_guard()")
