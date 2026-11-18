"""S1-E.2: GPT-Live provider adapter (Voice Lab only) — paid sessions become *possible* under strict gates, never
enabled.

- ``lab_paid_authorisation``: a manager's single-use smoke-test permission for one paid session (provider, model,
  voice, maximum duration ≤ 120 s, maximum USD, expiry, reason). It is consumed by exactly one session created by a
  different user; it can be revoked; it expires. One ISSUED permission at a time.
- ``lab_control.paid_enabled`` may now be switched by a manager (still false by default; audited). The CHECK that
  forbade it is replaced; paid *experiments* stay forbidden (``ck_lab_experiment_no_paid`` unchanged).
- ``lab_session``: PAID only with a consumed permission (CHECK, unique — single use); provider session id,
  termination status (NOT_APPLICABLE / NOT_STARTED / CONFIRMED / UNCONFIRMED / RESOLVED), provider-reported usage
  seconds and its source.
- ``lab_reservation``: PAID only for a session.
- Retention (owner decision, S1-E.1 acceptance): ``lab_media`` and ``lab_transcript`` get ``purged_at``; the
  insert-only triggers become purge-only guards (audio objects deleted, transcript text blanked, rows and checksums
  kept). ``lab_transcript.source`` distinguishes the independent local transcript from the provider's own transcript.
- ``lab_speech_assessment`` (insert-only): a person's speech result for a trial or session (human-confirmed result).

Revision ID: 0026_gpt_live_provider
Revises: 0025_voice_lab
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk

revision = "0026_gpt_live_provider"
down_revision = "0025_voice_lab"
branch_labels = None
depends_on = None

USD = sa.Numeric(12, 4)
TERMINATION = ("NOT_APPLICABLE", "NOT_STARTED", "CONFIRMED", "UNCONFIRMED", "RESOLVED")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.drop_constraint("ck_lab_control_paid_disabled", "lab_control", schema=s)
    op.create_table(
        "lab_paid_authorisation",
        pk(),
        sa.Column("authorisation_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("voice", sa.String(80), nullable=False),
        sa.Column("max_sessions", sa.SmallInteger, nullable=False, server_default="1"),
        sa.Column("max_duration_s", sa.Integer, nullable=False),
        sa.Column("max_usd", USD, nullable=False),
        sa.Column("rate_card", JSONB, nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ISSUED"),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("authorised_by", sa.String(80), nullable=False),
        sa.Column("authorised_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("consumed_by", sa.String(80)),
        sa.Column("consumed_at", TS),
        sa.Column("revoked_by", sa.String(80)),
        sa.Column("revoked_at", TS),
        sa.Column("revoke_reason", sa.String(500)),
        enum_check("status", ("ISSUED", "CONSUMED", "REVOKED", "EXPIRED"), "ck_lab_paid_auth_status"),
        sa.CheckConstraint("max_sessions = 1", name="ck_lab_paid_auth_single"),
        sa.CheckConstraint("max_duration_s BETWEEN 10 AND 120", name="ck_lab_paid_auth_duration"),
        sa.CheckConstraint("max_usd > 0 AND max_usd <= 1", name="ck_lab_paid_auth_usd"),
        sa.CheckConstraint("length(reason) >= 5", name="ck_lab_paid_auth_reason"),
        sa.CheckConstraint("consumed_by IS NULL OR consumed_by <> authorised_by", name="ck_lab_paid_auth_four_eyes"),
        sa.CheckConstraint("(status = 'CONSUMED') = (consumed_at IS NOT NULL)", name="ck_lab_paid_auth_consumed"),
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_lab_paid_auth_issued ON {s}.lab_paid_authorisation ((true)) WHERE status = 'ISSUED'"
    )
    op.execute(f"""
        CREATE FUNCTION {s}.lab_paid_auth_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE closing text[] := ARRAY['status', 'consumed_by', 'consumed_at', 'revoked_by', 'revoked_at',
                                        'revoke_reason'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'paid authorisations are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'ISSUED' THEN
            RAISE EXCEPTION 'a % paid authorisation is final', OLD.status USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - closing) IS DISTINCT FROM (to_jsonb(OLD) - closing) THEN
            RAISE EXCEPTION 'a paid authorisation is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER lab_paid_auth_guard BEFORE UPDATE OR DELETE ON {s}.lab_paid_authorisation
          FOR EACH ROW EXECUTE FUNCTION {s}.lab_paid_auth_guard();
    """)
    # ---- sessions and reservations ---------------------------------------------------------------------------------
    op.drop_constraint("ck_lab_session_no_paid", "lab_session", schema=s)
    op.add_column("lab_session", fk("paid_authorisation_id", "lab_paid_authorisation", s, nullable=True), schema=s)
    op.add_column("lab_session", sa.Column("provider_session_id", sa.String(128)), schema=s)
    op.add_column(
        "lab_session",
        sa.Column("termination_status", sa.String(16), nullable=False, server_default="NOT_APPLICABLE"),
        schema=s,
    )
    op.add_column("lab_session", sa.Column("provider_usage_seconds", sa.Numeric(10, 2)), schema=s)
    op.add_column("lab_session", sa.Column("usage_source", sa.String(40)), schema=s)
    op.create_check_constraint(
        "ck_lab_session_termination",
        "lab_session",
        "termination_status IN ('" + "', '".join(TERMINATION) + "')",
        schema=s,
    )
    op.create_check_constraint(
        "ck_lab_session_paid_authorised",
        "lab_session",
        "spend_class <> 'PAID' OR paid_authorisation_id IS NOT NULL",
        schema=s,
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_lab_session_paid_auth ON {s}.lab_session (paid_authorisation_id) "
        "WHERE paid_authorisation_id IS NOT NULL"
    )
    op.drop_constraint("ck_lab_reservation_no_paid", "lab_reservation", schema=s)
    op.create_check_constraint(
        "ck_lab_reservation_paid_session", "lab_reservation", "spend_class <> 'PAID' OR scope = 'SESSION'", schema=s
    )
    # ---- retention: purge-only guards ------------------------------------------------------------------------------
    for t in ("lab_media", "lab_transcript"):
        op.add_column(t, sa.Column("purged_at", TS), schema=s)
        op.add_column(t, sa.Column("purge_reason", sa.String(120)), schema=s)
        op.execute(f"DROP TRIGGER {t}_immutable ON {s}.{t}")
    op.add_column(
        "lab_transcript",
        sa.Column("source", sa.String(24), nullable=False, server_default="INDEPENDENT_ASR"),
        schema=s,
    )
    op.create_check_constraint(
        "ck_lab_transcript_source", "lab_transcript", "source IN ('INDEPENDENT_ASR', 'PROVIDER_TRANSCRIPT')", schema=s
    )
    op.execute(f"""
        CREATE FUNCTION {s}.lab_purge_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE allowed text[] := ARRAY['purged_at', 'purge_reason', 'text', 'words'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION '% rows are never deleted (retention purges content only)', TG_TABLE_NAME
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.purged_at IS NOT NULL OR NEW.purged_at IS NULL THEN
            RAISE EXCEPTION '% rows change only once, by a retention purge', TG_TABLE_NAME
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - allowed) IS DISTINCT FROM (to_jsonb(OLD) - allowed) THEN
            RAISE EXCEPTION 'a retention purge changes only content columns' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_TABLE_NAME = 'lab_transcript'
             AND (to_jsonb(NEW)->>'text' <> '' OR to_jsonb(NEW)->'words' <> '[]'::jsonb) THEN
            RAISE EXCEPTION 'a purged transcript keeps no text' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER lab_media_purge_guard BEFORE UPDATE OR DELETE ON {s}.lab_media
          FOR EACH ROW EXECUTE FUNCTION {s}.lab_purge_guard();
        CREATE TRIGGER lab_transcript_purge_guard BEFORE UPDATE OR DELETE ON {s}.lab_transcript
          FOR EACH ROW EXECUTE FUNCTION {s}.lab_purge_guard();
    """)
    # ---- human speech assessment -----------------------------------------------------------------------------------
    op.create_table(
        "lab_speech_assessment",
        pk(),
        fk("trial_id", "lab_trial", s, nullable=True),
        fk("session_id", "lab_session", s, nullable=True),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("notes", sa.String(1000), nullable=False),
        sa.Column("listened", sa.Boolean, nullable=False),
        sa.Column("assessed_by", sa.String(80), nullable=False),
        sa.Column("assessed_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check(
            "result",
            ("CONFIRMED_AS_EXPECTED", "CONFIRMED_DEVIATION", "INCONCLUSIVE"),
            "ck_lab_speech_assessment_result",
        ),
        sa.CheckConstraint("(trial_id IS NULL) <> (session_id IS NULL)", name="ck_lab_speech_assessment_target"),
        sa.CheckConstraint("length(notes) >= 5", name="ck_lab_speech_assessment_notes"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "lab_speech_assessment"))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.lab_paid_authorisation) + (SELECT count(*) FROM "
            f"{s}.lab_speech_assessment) + (SELECT count(*) FROM {s}.lab_session WHERE spend_class = 'PAID') + "
            f"(SELECT count(*) FROM {s}.lab_media WHERE purged_at IS NOT NULL) + "
            f"(SELECT count(*) FROM {s}.lab_transcript WHERE purged_at IS NOT NULL OR source <> 'INDEPENDENT_ASR')"
        )
    ).scalar_one()
    if used:
        raise RuntimeError("S1-E.2 records exist; downgrade would lose them")
    op.drop_table("lab_speech_assessment", schema=s)
    for t in ("lab_media", "lab_transcript"):
        op.execute(f"DROP TRIGGER {t}_purge_guard ON {s}.{t}")
        op.drop_column(t, "purge_reason", schema=s)
        op.drop_column(t, "purged_at", schema=s)
        op.execute(forbid_change_trigger(s, t))
    op.execute(f"DROP FUNCTION {s}.lab_purge_guard()")
    op.drop_constraint("ck_lab_transcript_source", "lab_transcript", schema=s)
    op.drop_column("lab_transcript", "source", schema=s)
    op.drop_constraint("ck_lab_reservation_paid_session", "lab_reservation", schema=s)
    op.create_check_constraint("ck_lab_reservation_no_paid", "lab_reservation", "spend_class <> 'PAID'", schema=s)
    op.execute(f"DROP INDEX {s}.uq_lab_session_paid_auth")
    for c in ("ck_lab_session_paid_authorised", "ck_lab_session_termination"):
        op.drop_constraint(c, "lab_session", schema=s)
    for c in (
        "usage_source",
        "provider_usage_seconds",
        "termination_status",
        "provider_session_id",
        "paid_authorisation_id",
    ):
        op.drop_column("lab_session", c, schema=s)
    op.create_check_constraint("ck_lab_session_no_paid", "lab_session", "spend_class <> 'PAID'", schema=s)
    op.execute(f"DROP TRIGGER lab_paid_auth_guard ON {s}.lab_paid_authorisation")
    op.drop_table("lab_paid_authorisation", schema=s)
    op.execute(f"DROP FUNCTION {s}.lab_paid_auth_guard()")
    op.execute(f"UPDATE {s}.lab_control SET paid_enabled = false")
    op.create_check_constraint("ck_lab_control_paid_disabled", "lab_control", "NOT paid_enabled", schema=s)
