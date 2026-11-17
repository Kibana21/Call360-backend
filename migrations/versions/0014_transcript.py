"""S1-D: machine transcripts of recorded tracks — ``transcript_run``, ``transcript_segment``, ledger events, access.

- ``transcript_run``: one transcription of one stored track (``media_asset``) by one pinned engine/model/config.
  Provenance (engine, versions, model revision and SHA-256, configuration, input content checksum, triggering
  ledger event) never changes; a run is ``PENDING → PROCESSING → DONE | FAILED`` (``PROCESSING`` may return to
  ``PENDING`` when its lease expires); DONE and FAILED are terminal. A retry is a new revision. Rows are never deleted.
- ``transcript_segment`` (canonical, deferred from S0 — D-19): insert-only metadata of each recognised or
  unrecognised stretch: recording segment and sample range on the shared 16 kHz clock, speaker from the track,
  engine metrics and the SHA-256 of its text. **Text is not stored in the database**: it lives in one encrypted
  object per run in the recording store and is deleted with the audio at retention expiry.
- ``session_event`` gains TRANSCRIPT_STARTED, TRANSCRIPT_COMPLETED, TRANSCRIPT_FAILED, TRANSCRIPT_PURGED.
- ``transcript.sensitive.read`` (reserved since 0001) is activated and granted to USER only (owner decision D-50).

Revision ID: 0014_transcript
Revises: 0013_recording
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from app.db.ddl import TS, enum_check, forbid_change_trigger, pk, sha256_check

revision = "0014_transcript"
down_revision = "0013_recording"
branch_labels = None
depends_on = None

PRIOR_EVENT_TYPES = (
    "SESSION_REQUESTED",
    "CONNECTED",
    "RESUMED",
    "PROVIDER_RESPONSE_STARTED",
    "PROVIDER_RESPONSE_COMPLETED",
    "BARGE_IN",
    "USER_TURN_ENDED",
    "MIC_MUTED",
    "MIC_UNMUTED",
    "CLIENT_NOTICE",
    "DISCONNECTED",
    "STOP_REQUESTED",
    "ENDED",
    "ABANDONED",
    "FAILED",
    "RECORDING_CONSENT_GRANTED",
    "RECORDING_CONSENT_DECLINED",
    "RECORDING_STARTED",
    "RECORDING_TRACK_CLOSED",
    "RECORDING_FINALIZED",
    "RECORDING_PURGED",
)
TRANSCRIPT_EVENT_TYPES = ("TRANSCRIPT_STARTED", "TRANSCRIPT_COMPLETED", "TRANSCRIPT_FAILED", "TRANSCRIPT_PURGED")
TRACKS = ("MIC", "PROVIDER_PLAYBACK")
RUN_STATUS = ("PENDING", "PROCESSING", "DONE", "FAILED")
SPEAKERS = ("CALLER_MIC", "MOCK_PROVIDER")
KINDS = ("SPEECH", "UNRECOGNIZED")
CONFIDENCE = ("NORMAL", "LOW")
PERMISSION = "transcript.sensitive.read"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "transcript_run",
        pk(),
        sa.Column("run_ref", sa.String(48), nullable=False, unique=True),
        sa.Column("contact_attempt_id", sa.Uuid(), sa.ForeignKey(f"{s}.contact_attempt.id"), nullable=False),
        sa.Column("conversation_session_id", sa.Uuid(), sa.ForeignKey(f"{s}.conversation_session.id"), nullable=False),
        sa.Column("media_asset_id", sa.Uuid(), sa.ForeignKey(f"{s}.media_asset.id"), nullable=False),
        sa.Column("track", sa.String(20), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("language", sa.String(8), nullable=False),
        sa.Column("engine", sa.String(32), nullable=False),
        sa.Column("engine_version", sa.String(64), nullable=False),
        sa.Column("model_id", sa.String(96), nullable=False),
        sa.Column("model_revision", sa.String(64), nullable=False),
        sa.Column("model_sha256", sa.String(64), nullable=False),
        sa.Column("config", JSONB, nullable=False),
        sa.Column("config_sha256", sa.String(64), nullable=False),
        sa.Column("input_content_sha256", sa.String(64), nullable=False),
        sa.Column("input_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("source_event_seq", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_until", TS),
        sa.Column("error_code", sa.String(48)),
        sa.Column("requested_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("requested_by", sa.String(80), nullable=False),
        sa.Column("started_at", TS),
        sa.Column("finished_at", TS),
        sa.Column("metrics", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("storage_backend", sa.String(24), nullable=False),
        sa.Column("key_id", sa.String(24), nullable=False),
        sa.Column("object_key", sa.String(120)),
        sa.Column("text_sha256", sa.String(64)),
        sa.Column("purged_at", TS),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("updated_at", TS),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("media_asset_id", "revision", name="uq_transcript_run_revision"),
        enum_check("track", TRACKS, "ck_transcript_run_track"),
        enum_check("status", RUN_STATUS, "ck_transcript_run_status"),
        sa.CheckConstraint("language = 'en'", name="ck_transcript_run_language"),  # D-51
        sa.CheckConstraint("revision >= 1 AND attempts >= 0", name="ck_transcript_run_counts"),
        sha256_check("model_sha256", "transcript_run"),
        sha256_check("config_sha256", "transcript_run"),
        sha256_check("input_content_sha256", "transcript_run"),
        sha256_check("input_manifest_sha256", "transcript_run"),
        sha256_check("text_sha256", "transcript_run", nullable=True),
        sa.CheckConstraint(
            "status <> 'DONE' OR (object_key IS NOT NULL AND text_sha256 IS NOT NULL AND finished_at IS NOT NULL)",
            name="ck_transcript_run_done",
        ),
        sa.CheckConstraint("status <> 'FAILED' OR error_code IS NOT NULL", name="ck_transcript_run_failed"),
        sa.CheckConstraint(
            r"object_key IS NULL OR object_key ~ '^[0-9a-f-]{36}/(MIC|PROVIDER_PLAYBACK)/transcript-r[0-9]{3}\.c360$'",
            name="ck_transcript_run_object_key",
        ),
        schema=s,
    )
    op.create_table(
        "transcript_segment",
        pk(),
        sa.Column("transcript_run_id", sa.Uuid(), sa.ForeignKey(f"{s}.transcript_run.id"), nullable=False),
        sa.Column("contact_attempt_id", sa.Uuid(), sa.ForeignKey(f"{s}.contact_attempt.id"), nullable=False),
        sa.Column("track", sa.String(20), nullable=False),
        sa.Column("speaker", sa.String(16), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("rec_segment", sa.Integer(), nullable=False),
        sa.Column("start_sample", sa.BigInteger(), nullable=False),
        sa.Column("end_sample", sa.BigInteger(), nullable=False),
        sa.Column("time_alignment", sa.String(12), nullable=False, server_default="APPROXIMATE"),
        sa.Column("avg_logprob", sa.Float(), nullable=False),
        sa.Column("no_speech_prob", sa.Float(), nullable=False),
        sa.Column("compression_ratio", sa.Float(), nullable=False),
        sa.Column("word_count", sa.Integer(), nullable=False),
        sa.Column("uncertain_words", sa.Integer(), nullable=False),
        sa.Column("min_word_prob", sa.Float()),
        sa.Column("flags", ARRAY(sa.String(32)), nullable=False, server_default="{}"),
        sa.Column("text_sha256", sa.String(64)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("transcript_run_id", "ordinal", name="uq_transcript_segment_ordinal"),
        enum_check("track", TRACKS, "ck_transcript_segment_track"),
        enum_check("speaker", SPEAKERS, "ck_transcript_segment_speaker"),
        enum_check("kind", KINDS, "ck_transcript_segment_kind"),
        enum_check("confidence", CONFIDENCE, "ck_transcript_segment_confidence"),
        sa.CheckConstraint(
            "(track = 'MIC' AND speaker = 'CALLER_MIC') OR (track = 'PROVIDER_PLAYBACK' AND speaker = 'MOCK_PROVIDER')",
            name="ck_transcript_segment_speaker_track",
        ),
        sa.CheckConstraint(
            "rec_segment >= 1 AND start_sample >= 0 AND end_sample >= start_sample", name="ck_transcript_segment_time"
        ),
        # Unrecognised stretches never carry text: the engine output was rejected, not shown.
        sa.CheckConstraint(
            "(kind = 'SPEECH' AND text_sha256 IS NOT NULL) OR (kind = 'UNRECOGNIZED' AND text_sha256 IS NULL "
            "AND word_count = 0)",
            name="ck_transcript_segment_text",
        ),
        sha256_check("text_sha256", "transcript_segment", nullable=True),
        schema=s,
    )
    op.create_index("ix_transcript_segment_attempt", "transcript_segment", ["contact_attempt_id"], schema=s)
    op.create_index("ix_transcript_run_status", "transcript_run", ["status"], schema=s)
    op.execute(forbid_change_trigger(s, "transcript_segment"))
    op.execute(
        f"""
        CREATE FUNCTION {s}.transcript_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          fixed text[] := ARRAY['id', 'run_ref', 'contact_attempt_id', 'conversation_session_id', 'media_asset_id',
                                'track', 'revision', 'language', 'engine', 'engine_version', 'model_id',
                                'model_revision', 'model_sha256', 'config', 'config_sha256', 'input_content_sha256',
                                'input_manifest_sha256', 'source_event_seq', 'requested_at', 'requested_by',
                                'storage_backend', 'key_id', 'is_synthetic'];
          p text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'transcript_run rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          FOREACH p IN ARRAY fixed LOOP
            IF (to_jsonb(NEW) -> p) IS DISTINCT FROM (to_jsonb(OLD) -> p) THEN
              RAISE EXCEPTION 'transcript_run % is immutable', p USING ERRCODE = 'insufficient_privilege';
            END IF;
          END LOOP;
          IF OLD.text_sha256 IS NOT NULL AND NEW.text_sha256 IS DISTINCT FROM OLD.text_sha256 THEN
            RAISE EXCEPTION 'transcript_run text checksum is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.object_key IS NOT NULL AND NEW.object_key IS DISTINCT FROM OLD.object_key THEN
            RAISE EXCEPTION 'transcript_run object key is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status IN ('DONE', 'FAILED') AND (NEW.status <> OLD.status OR NEW.metrics <> OLD.metrics
             OR NEW.error_code IS DISTINCT FROM OLD.error_code) THEN
            RAISE EXCEPTION 'a finished transcript_run is final' USING ERRCODE = 'check_violation';
          END IF;
          IF OLD.purged_at IS NOT NULL AND NEW.purged_at IS DISTINCT FROM OLD.purged_at THEN
            RAISE EXCEPTION 'a purged transcript_run stays purged' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER transcript_run_guard BEFORE UPDATE OR DELETE ON {s}.transcript_run
          FOR EACH ROW EXECUTE FUNCTION {s}.transcript_run_guard();
        """
    )
    op.drop_constraint("ck_session_event_type", "session_event", schema=s, type_="check")
    op.create_check_constraint(
        "ck_session_event_type",
        "session_event",
        "event_type IN (" + ", ".join(f"'{v}'" for v in PRIOR_EVENT_TYPES + TRANSCRIPT_EVENT_TYPES) + ")",
        schema=s,
    )
    op.execute(
        f"UPDATE {s}.permission SET reserved = false, description = "
        "'Read machine transcript text of recorded sessions (S1-D; audited)' "
        f"WHERE code = '{PERMISSION}'"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) SELECT r.id, p.id FROM {s}.role r, "
        f"{s}.permission p WHERE r.code = 'USER' AND p.code = '{PERMISSION}'"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission "
        f"WHERE code = '{PERMISSION}')"
    )
    op.execute(
        f"UPDATE {s}.permission SET reserved = true, description = 'Reserved (S1/S3)' WHERE code = '{PERMISSION}'"
    )
    op.drop_constraint("ck_session_event_type", "session_event", schema=s, type_="check")
    op.create_check_constraint(
        "ck_session_event_type",
        "session_event",
        "event_type IN (" + ", ".join(f"'{v}'" for v in PRIOR_EVENT_TYPES) + ")",
        schema=s,
    )
    op.drop_table("transcript_segment", schema=s)
    op.execute(f"DROP TRIGGER IF EXISTS transcript_run_guard ON {s}.transcript_run")
    op.drop_table("transcript_run", schema=s)
    op.execute(f"DROP FUNCTION IF EXISTS {s}.transcript_run_guard()")
