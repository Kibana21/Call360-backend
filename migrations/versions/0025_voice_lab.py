"""S1-E.1: Voice Lab foundation — experimental voice records isolated from operational records, with budget controls.

Every table is prefixed ``lab_`` and has no foreign key to any operational table (case, attempt, conversation, finding,
review). Nothing here is a contact attempt or a conversation session, so KPIs, queues and Call Detail never see it.

- ``lab_control`` (one row): emergency kill switch; paid providers, automatic retries and scheduled experiments are
  disabled by CHECK constraints (enabling paid access needs a later, separately authorised migration).
- ``lab_budget``: per spend class (``SIMULATED`` — synthetic metered mock, no money; ``PAID`` — real providers) the
  overall, daily and per-experiment limits, maximum concurrent sessions, interactive maximum and idle timeout.
- ``lab_config_change``: insert-only history of control and budget changes (before / after, actor, reason).
- ``lab_reservation``: budget reservations made before a session or experiment starts, reconciled with the measured
  cost or released; amounts are immutable once written.
- ``lab_prompt`` / ``lab_prompt_version`` (insert-only): editable system prompt, per-turn instructions and provider /
  model / voice configuration, versioned.
- ``lab_session`` (+ insert-only ``lab_session_event`` trace, ``lab_media``, ``lab_transcript``): playground and
  experiment sessions with timings, costs, server-side recording references and independent transcripts.
- ``lab_dataset`` / ``lab_test_case`` / insert-only ``lab_test_case_revision``: golden test cases.
- ``lab_experiment`` / insert-only ``lab_trial``: repeatable experiment configuration, authorisation and results.
- Permissions: ``voicelab.use`` (USER, S&C checker) and ``voicelab.manage`` (ADMIN: budgets, kill switch, spend
  authorisation — never for one's own experiment).

Revision ID: 0025_voice_lab
Revises: 0024_review_resolution
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, pk, sha256_check

revision = "0025_voice_lab"
down_revision = "0024_review_resolution"
branch_labels = None
depends_on = None

USD = sa.Numeric(12, 4)
CLASSES = ("SIMULATED", "PAID")
SPEND = ("NONE", "SIMULATED", "PAID")
TABLES = (  # drop order (dependents first)
    "lab_trial",
    "lab_transcript",
    "lab_media",
    "lab_session_event",
    "lab_reservation",
    "lab_session",
    "lab_experiment",
    "lab_test_case_revision",
    "lab_test_case",
    "lab_dataset",
    "lab_prompt_version",
    "lab_prompt",
    "lab_config_change",
    "lab_budget",
    "lab_control",
)
INSERT_ONLY = (
    "lab_config_change",
    "lab_prompt_version",
    "lab_session_event",
    "lab_media",
    "lab_transcript",
    "lab_test_case_revision",
    "lab_trial",
)
PERMISSIONS = {
    "voicelab.use": "Voice Lab: playground, golden datasets, experiments and results (S1-E.1; synthetic only)",
    "voicelab.manage": "Voice Lab: budgets, kill switch and spend authorisation of experiments created by other users (S1-E.1)",
}


def _common() -> list[sa.Column[object]]:
    return [
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    # ---- controls and budgets --------------------------------------------------------------------------------------
    op.create_table(
        "lab_control",
        sa.Column("id", sa.SmallInteger, primary_key=True),
        sa.Column("kill_switch", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("kill_reason", sa.String(500)),
        sa.Column("paid_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("retries_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("scheduling_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("updated_by", sa.String(80)),
        sa.Column("updated_at", TS),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.CheckConstraint("id = 1", name="ck_lab_control_singleton"),
        sa.CheckConstraint("NOT paid_enabled", name="ck_lab_control_paid_disabled"),
        sa.CheckConstraint("NOT retries_enabled", name="ck_lab_control_no_retries"),
        sa.CheckConstraint("NOT scheduling_enabled", name="ck_lab_control_no_schedules"),
        schema=s,
    )
    op.execute(f"INSERT INTO {s}.lab_control (id) VALUES (1)")
    op.create_table(
        "lab_budget",
        sa.Column("spend_class", sa.String(16), primary_key=True),
        sa.Column("overall_usd", USD, nullable=False),
        sa.Column("daily_usd", USD, nullable=False),
        sa.Column("per_experiment_usd", USD, nullable=False),
        sa.Column("max_concurrent_sessions", sa.SmallInteger, nullable=False),
        sa.Column("interactive_max_s", sa.Integer, nullable=False),
        sa.Column("idle_timeout_s", sa.Integer, nullable=False),
        sa.Column("basis", sa.String(300), nullable=False),
        sa.Column("updated_by", sa.String(80)),
        sa.Column("updated_at", TS),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        enum_check("spend_class", CLASSES, "ck_lab_budget_class"),
        sa.CheckConstraint(
            "per_experiment_usd > 0 AND per_experiment_usd <= daily_usd AND daily_usd <= overall_usd",
            name="ck_lab_budget_order",
        ),
        sa.CheckConstraint("max_concurrent_sessions BETWEEN 1 AND 4", name="ck_lab_budget_concurrency"),
        sa.CheckConstraint("interactive_max_s BETWEEN 5 AND 300", name="ck_lab_budget_interactive"),
        sa.CheckConstraint("idle_timeout_s BETWEEN 2 AND 60", name="ck_lab_budget_idle"),
        schema=s,
    )
    basis = "Owner-proposed initial configuration (S1-E.1), not authorisation to spend"
    for cls in CLASSES:
        op.execute(
            f"INSERT INTO {s}.lab_budget (spend_class, overall_usd, daily_usd, per_experiment_usd, "
            f"max_concurrent_sessions, interactive_max_s, idle_timeout_s, basis) VALUES ('{cls}', 10, 2, 1, 1, 300, 15, "
            f"'{basis}')"
        )
    op.create_table(
        "lab_config_change",
        pk(),
        sa.Column("target", sa.String(32), nullable=False),
        sa.Column("before", JSONB, nullable=False),
        sa.Column("after", JSONB, nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        *_common(),
        sa.CheckConstraint("length(reason) >= 5", name="ck_lab_config_change_reason"),
        schema=s,
    )
    # ---- prompts ---------------------------------------------------------------------------------------------------
    op.create_table(
        "lab_prompt",
        pk(),
        sa.Column("prompt_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        *_common(),
        schema=s,
    )
    op.create_table(
        "lab_prompt_version",
        pk(),
        fk("prompt_id", "lab_prompt", s),
        sa.Column("version_no", sa.Integer, nullable=False),
        sa.Column("system_prompt", sa.Text, nullable=False),
        sa.Column("turn_instructions", JSONB, nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("voice", sa.String(80), nullable=False),
        sa.Column("parameters", JSONB, nullable=False),
        sa.Column("change_note", sa.String(500), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        *_common(),
        sa.UniqueConstraint("prompt_id", "version_no", name="uq_lab_prompt_version"),
        sha256_check("sha256", "lab_prompt_version"),
        sa.CheckConstraint("length(system_prompt) <= 20000", name="ck_lab_prompt_version_size"),
        schema=s,
    )
    # ---- datasets --------------------------------------------------------------------------------------------------
    op.create_table(
        "lab_dataset",
        pk(),
        sa.Column("dataset_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        *_common(),
        schema=s,
    )
    op.create_table(
        "lab_test_case",
        pk(),
        fk("dataset_id", "lab_dataset", s),
        sa.Column("case_ref", sa.String(24), nullable=False, unique=True),
        *_common(),
        schema=s,
    )
    op.create_table(
        "lab_test_case_revision",
        pk(),
        fk("test_case_id", "lab_test_case", s),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("system_prompt", sa.Text, nullable=False),
        sa.Column("test_instruction", sa.String(2000), nullable=False),
        sa.Column("expected_statement", sa.String(2000), nullable=False),
        sa.Column("customer_response", sa.String(2000), nullable=False),
        sa.Column("expected_answer", JSONB, nullable=False),
        sa.Column("expected_behaviour", sa.String(2000), nullable=False),
        sa.Column("criteria", JSONB, nullable=False),
        sa.Column("mock_output", sa.String(2000)),
        sa.Column("audio_object_key", sa.String(120)),
        sa.Column("audio_sha256", sa.String(64)),
        sa.Column("audio_samples", sa.Integer),
        sa.Column("source", JSONB, nullable=False),
        sa.Column("retired", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("change_note", sa.String(500), nullable=False),
        *_common(),
        sa.UniqueConstraint("test_case_id", "revision", name="uq_lab_test_case_revision"),
        sha256_check("audio_sha256", "lab_test_case_revision", nullable=True),
        sa.CheckConstraint(
            "(audio_object_key IS NULL) = (audio_sha256 IS NULL) AND (audio_object_key IS NULL) = (audio_samples IS NULL)",
            name="ck_lab_test_case_revision_audio",
        ),
        schema=s,
    )
    # ---- experiments -----------------------------------------------------------------------------------------------
    op.create_table(
        "lab_experiment",
        pk(),
        sa.Column("experiment_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("name", sa.String(160), nullable=False),
        fk("dataset_id", "lab_dataset", s),
        fk("prompt_version_id", "lab_prompt_version", s),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("voice", sa.String(80), nullable=False),
        sa.Column("spend_class", sa.String(16), nullable=False),
        sa.Column("case_revision_ids", JSONB, nullable=False),
        sa.Column("repetitions", sa.SmallInteger, nullable=False),
        sa.Column("max_duration_s", sa.Integer, nullable=False),
        sa.Column("max_spend_usd", USD, nullable=False),
        sa.Column("estimated_max_usd", USD, nullable=False),
        sa.Column("rate_card", JSONB, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("authorised_by", sa.String(80)),
        sa.Column("authorised_at", TS),
        sa.Column("authorisation_reason", sa.String(500)),
        sa.Column("authorised_usd", USD),
        sa.Column("started_at", TS),
        sa.Column("finished_at", TS),
        sa.Column("actual_usd", USD),
        sa.Column("summary", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("end_reason", sa.String(40)),
        *_common(),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        enum_check("spend_class", SPEND, "ck_lab_experiment_class"),
        enum_check(
            "status",
            ("AWAITING_AUTHORISATION", "READY", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"),
            "ck_lab_experiment_status",
        ),
        sa.CheckConstraint("repetitions BETWEEN 1 AND 5", name="ck_lab_experiment_repetitions"),
        sa.CheckConstraint("max_duration_s BETWEEN 5 AND 120", name="ck_lab_experiment_duration"),
        sa.CheckConstraint("estimated_max_usd <= max_spend_usd", name="ck_lab_experiment_within_limit"),
        sa.CheckConstraint("authorised_by IS NULL OR authorised_by <> created_by", name="ck_lab_experiment_four_eyes"),
        sa.CheckConstraint("spend_class <> 'PAID'", name="ck_lab_experiment_no_paid"),
        schema=s,
    )
    # ---- sessions --------------------------------------------------------------------------------------------------
    op.create_table(
        "lab_session",
        pk(),
        sa.Column("session_ref", sa.String(24), nullable=False, unique=True),
        sa.Column("mode", sa.String(16), nullable=False),
        fk("prompt_version_id", "lab_prompt_version", s, nullable=True),
        fk("experiment_id", "lab_experiment", s, nullable=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("voice", sa.String(80), nullable=False),
        sa.Column("spend_class", sa.String(16), nullable=False),
        sa.Column("rate_card", JSONB, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("record", sa.Boolean, nullable=False),
        sa.Column("max_duration_s", sa.Integer, nullable=False),
        sa.Column("idle_timeout_s", sa.Integer, nullable=False),
        sa.Column("estimated_max_usd", USD, nullable=False),
        sa.Column("reconciled_usd", USD),
        sa.Column("started_at", TS),
        sa.Column("ended_at", TS),
        sa.Column("end_reason", sa.String(40)),
        sa.Column("metrics", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("transcript_status", sa.String(16), nullable=False, server_default="NOT_REQUESTED"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        *_common(),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        enum_check("mode", ("INTERACTIVE", "EXPERIMENT"), "ck_lab_session_mode"),
        enum_check("spend_class", SPEND, "ck_lab_session_class"),
        enum_check("status", ("CREATED", "LIVE", "ENDED", "FAILED"), "ck_lab_session_status"),
        enum_check(
            "transcript_status",
            ("NOT_REQUESTED", "PENDING", "COMPLETED", "FAILED", "NOT_AVAILABLE"),
            "ck_lab_session_transcript",
        ),
        sa.CheckConstraint("spend_class <> 'PAID'", name="ck_lab_session_no_paid"),
        sa.CheckConstraint("is_synthetic", name="ck_lab_session_synthetic"),
        schema=s,
    )
    op.create_table(
        "lab_reservation",
        pk(),
        sa.Column("spend_class", sa.String(16), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        fk("session_id", "lab_session", s, nullable=True),
        fk("experiment_id", "lab_experiment", s, nullable=True),
        sa.Column("reserved_usd", USD, nullable=False),
        sa.Column("actual_usd", USD),
        sa.Column("status", sa.String(16), nullable=False, server_default="HELD"),
        sa.Column("basis", JSONB, nullable=False),
        sa.Column("closed_at", TS),
        *_common(),
        enum_check("spend_class", CLASSES, "ck_lab_reservation_class"),
        enum_check("scope", ("SESSION", "EXPERIMENT"), "ck_lab_reservation_scope"),
        enum_check("status", ("HELD", "RECONCILED", "RELEASED"), "ck_lab_reservation_status"),
        sa.CheckConstraint("(scope = 'SESSION') = (session_id IS NOT NULL)", name="ck_lab_reservation_target"),
        sa.CheckConstraint("(scope = 'EXPERIMENT') = (experiment_id IS NOT NULL)", name="ck_lab_reservation_target2"),
        sa.CheckConstraint(
            "reserved_usd >= 0 AND (actual_usd IS NULL OR actual_usd >= 0)", name="ck_lab_reservation_usd"
        ),
        sa.CheckConstraint("spend_class <> 'PAID'", name="ck_lab_reservation_no_paid"),
        schema=s,
    )
    op.execute(f"""
        CREATE FUNCTION {s}.lab_reservation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE closing text[] := ARRAY['status', 'actual_usd', 'closed_at'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'budget reservations are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status <> 'HELD' THEN
            RAISE EXCEPTION 'a % reservation is final', OLD.status USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - closing) IS DISTINCT FROM (to_jsonb(OLD) - closing) THEN
            RAISE EXCEPTION 'a reservation amount is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER lab_reservation_guard BEFORE UPDATE OR DELETE ON {s}.lab_reservation
          FOR EACH ROW EXECUTE FUNCTION {s}.lab_reservation_guard();
    """)
    op.execute(
        f"CREATE UNIQUE INDEX uq_lab_reservation_session ON {s}.lab_reservation (session_id) WHERE session_id IS NOT NULL"
    )
    op.execute(
        f"CREATE UNIQUE INDEX uq_lab_reservation_experiment ON {s}.lab_reservation (experiment_id) "
        "WHERE experiment_id IS NOT NULL"
    )
    op.create_table(
        "lab_session_event",
        pk(),
        fk("session_id", "lab_session", s),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("offset_ms", sa.Integer, nullable=False),
        sa.Column("details", JSONB, nullable=False),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("session_id", "seq", name="uq_lab_session_event_seq"),
        enum_check("source", ("SERVER", "PROVIDER", "CLIENT", "BUDGET"), "ck_lab_session_event_source"),
        schema=s,
    )
    op.create_table(
        "lab_media",
        pk(),
        fk("session_id", "lab_session", s),
        sa.Column("track", sa.String(24), nullable=False),
        sa.Column("object_key", sa.String(120), nullable=False, unique=True),
        sa.Column("samples", sa.Integer, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("basis", sa.String(300), nullable=False),
        *_common(),
        sa.UniqueConstraint("session_id", "track", name="uq_lab_media_track"),
        enum_check("track", ("MIC", "PROVIDER_PLAYBACK"), "ck_lab_media_track"),
        sha256_check("sha256", "lab_media"),
        schema=s,
    )
    op.create_table(
        "lab_transcript",
        pk(),
        fk("session_id", "lab_session", s, nullable=True),
        fk("test_case_revision_id", "lab_test_case_revision", s, nullable=True),
        sa.Column("track", sa.String(24), nullable=False),
        sa.Column("engine", sa.String(120), nullable=False),
        sa.Column("model_sha256", sa.String(64), nullable=False),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("words", JSONB, nullable=False),
        sa.Column("audio_sha256", sa.String(64), nullable=False),
        *_common(),
        sa.CheckConstraint("(session_id IS NULL) <> (test_case_revision_id IS NULL)", name="ck_lab_transcript_target"),
        schema=s,
    )
    op.create_table(
        "lab_trial",
        pk(),
        fk("experiment_id", "lab_experiment", s),
        fk("test_case_revision_id", "lab_test_case_revision", s),
        fk("session_id", "lab_session", s, nullable=True),
        sa.Column("repetition", sa.SmallInteger, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verdict", sa.String(24), nullable=False),
        sa.Column("provider_text", sa.Text),
        sa.Column("heard_text", sa.Text),
        sa.Column("extracted_answer", JSONB),
        sa.Column("metrics", JSONB, nullable=False),
        sa.Column("checks", JSONB, nullable=False),
        sa.Column("failure", sa.String(300)),
        sa.Column("cost_usd", USD, nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS, nullable=False),
        *_common(),
        sa.UniqueConstraint("experiment_id", "test_case_revision_id", "repetition", name="uq_lab_trial"),
        enum_check("status", ("COMPLETED", "FAILED", "CANCELLED"), "ck_lab_trial_status"),
        enum_check("verdict", ("PASS", "FAIL", "NEEDS_HUMAN_REVIEW", "NOT_EVALUATED"), "ck_lab_trial_verdict"),
        schema=s,
    )
    for t in INSERT_ONLY:
        op.execute(forbid_change_trigger(s, t))
    op.execute(f"CREATE INDEX ix_lab_session_created ON {s}.lab_session (created_at DESC)")
    op.execute(f"CREATE INDEX ix_lab_reservation_class ON {s}.lab_reservation (spend_class, status, created_at)")
    # ---- permissions -----------------------------------------------------------------------------------------------
    for code, desc in PERMISSIONS.items():
        pid = uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + code)
        op.execute(
            f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES ('{pid}', '{code}', NULL, "
            f"false, '{desc}')"
        )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT r.id, p.id FROM {s}.role r, "
        f"{s}.permission p WHERE (r.code IN ('USER', 'SC_CHECKER') AND p.code = 'voicelab.use') "
        "OR (r.code = 'ADMIN' AND p.code = 'voicelab.manage') ON CONFLICT DO NOTHING"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    used = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.lab_session) + (SELECT count(*) FROM {s}.lab_prompt) "
            f"+ (SELECT count(*) FROM {s}.lab_dataset) + (SELECT count(*) FROM {s}.lab_config_change)"
        )
    ).scalar_one()
    if used:
        raise RuntimeError("Voice Lab records exist; downgrade would lose them")
    codes = ", ".join(f"'{c}'" for c in PERMISSIONS)
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code IN ({codes}))"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code IN ({codes})")
    op.execute(f"DROP TRIGGER lab_reservation_guard ON {s}.lab_reservation")
    for t in TABLES:
        op.drop_table(t, schema=s)
    op.execute(f"DROP FUNCTION {s}.lab_reservation_guard()")
