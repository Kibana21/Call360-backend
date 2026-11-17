"""S1-C: consent-gated recording — ``media_asset``, ``media_chunk``, recording ledger events, ``recording.read``.

- ``media_asset`` (S0_DATA_MODEL §4.5, deferred to S1): one stored track of one browser voice session (``MIC`` or
  ``PROVIDER_PLAYBACK``). Lifecycle columns (``media_status`` vocabulary, coverage, counts, gaps, retention) change;
  identity, codec and consent never change; the content and manifest checksums are immutable once set; rows are
  never deleted (expiry purges the audio objects, not the metadata).
- ``media_chunk``: insert-only manifest of every stored chunk (segment, sequence, start sample, sample count, bytes,
  SHA-256 of the plaintext, server-generated object key). Audio itself lives outside the database (EVD-001).
- ``session_event`` gains the recording event types (consent, start, track close, finalisation, purge).
- ``recording.read`` (reserved since 0001) is activated for S1 and granted to USER only; ADMIN keeps the ADR-0004
  segregation (owner decision D-46, pending acceptance).

Revision ID: 0013_recording
Revises: 0012_session_event
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, forbid_change_trigger, pk, record_origin, sha256_check

revision = "0013_recording"
down_revision = "0012_session_event"
branch_labels = None
depends_on = None

OLD_EVENT_TYPES = (
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
)
RECORDING_EVENT_TYPES = (
    "RECORDING_CONSENT_GRANTED",
    "RECORDING_CONSENT_DECLINED",
    "RECORDING_STARTED",
    "RECORDING_TRACK_CLOSED",
    "RECORDING_FINALIZED",
    "RECORDING_PURGED",
)
TRACKS = ("MIC", "PROVIDER_PLAYBACK")
MEDIA_STATUS = ("CAPTURE_PENDING", "CAPTURING", "UPLOADING", "AVAILABLE", "FAILED", "REDACTED", "PURGED", "HELD")
COVERAGE = ("PENDING", "COMPLETE", "PARTIAL", "NONE")
PERMISSION = "recording.read"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "media_asset",
        pk(),
        sa.Column("asset_ref", sa.String(40), nullable=False, unique=True),
        sa.Column("contact_attempt_id", sa.Uuid(), sa.ForeignKey(f"{s}.contact_attempt.id"), nullable=False),
        sa.Column("conversation_session_id", sa.Uuid(), sa.ForeignKey(f"{s}.conversation_session.id"), nullable=False),
        sa.Column("track", sa.String(20), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("codec", sa.String(32), nullable=False),
        sa.Column("sample_rate", sa.Integer(), nullable=False),
        sa.Column("channels", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("coverage", sa.String(10), nullable=False),
        sa.Column("consent_event_seq", sa.Integer(), nullable=False),
        sa.Column("consent_notice_version", sa.String(24), nullable=False),
        sa.Column("consent_notice_sha256", sa.String(64), nullable=False),
        sa.Column("storage_backend", sa.String(24), nullable=False),
        sa.Column("key_id", sa.String(24), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("capture_ended_at", TS),
        sa.Column("finalized_at", TS),
        sa.Column("chunks_stored", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("samples_stored", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_stored", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("close_manifests", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("gaps", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("content_sha256", sa.String(64)),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("retention_until", TS),
        sa.Column("purged_at", TS),
        sa.Column("purge_reason", sa.String(40)),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        *record_origin("media_asset"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("updated_at", TS),
        sa.Column("updated_by", sa.String(80)),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("contact_attempt_id", "track", name="uq_media_asset_track"),
        enum_check("track", TRACKS, "ck_media_asset_track"),
        enum_check("status", MEDIA_STATUS, "ck_media_asset_status"),
        enum_check("coverage", COVERAGE, "ck_media_asset_coverage"),
        sa.CheckConstraint("source = 'BROWSER_CAPTURE'", name="ck_media_asset_source"),
        sa.CheckConstraint("codec = 'audio/L16' AND sample_rate = 16000 AND channels = 1", name="ck_media_asset_codec"),
        sha256_check("consent_notice_sha256", "media_asset"),
        sha256_check("content_sha256", "media_asset", nullable=True),
        sha256_check("manifest_sha256", "media_asset", nullable=True),
        sa.CheckConstraint(
            "status NOT IN ('AVAILABLE', 'FAILED', 'PURGED') OR finalized_at IS NOT NULL", name="ck_media_asset_final"
        ),
        sa.CheckConstraint("status <> 'PURGED' OR purged_at IS NOT NULL", name="ck_media_asset_purged"),
        schema=s,
    )
    op.create_table(
        "media_chunk",
        pk(),
        sa.Column("media_asset_id", sa.Uuid(), sa.ForeignKey(f"{s}.media_asset.id"), nullable=False),
        sa.Column("segment", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("start_sample", sa.BigInteger(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("object_key", sa.String(120), nullable=False, unique=True),
        sa.Column("client_captured_at", TS),
        sa.Column("received_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.UniqueConstraint("media_asset_id", "segment", "seq", name="uq_media_chunk_seq"),
        sa.CheckConstraint("segment >= 1 AND seq >= 1 AND start_sample >= 0", name="ck_media_chunk_position"),
        sa.CheckConstraint("sample_count > 0 AND byte_size = sample_count * 2", name="ck_media_chunk_size"),
        sha256_check("sha256", "media_chunk"),
        sa.CheckConstraint(
            r"object_key ~ '^[0-9a-f-]{36}/(MIC|PROVIDER_PLAYBACK)/[0-9]{3}-[0-9]{6}\.c360$'",
            name="ck_media_chunk_object_key",
        ),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "media_chunk"))
    op.execute(
        f"""
        CREATE FUNCTION {s}.media_asset_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          fixed text[] := ARRAY['id', 'asset_ref', 'contact_attempt_id', 'conversation_session_id', 'track', 'source',
                                'codec', 'sample_rate', 'channels', 'consent_event_seq', 'consent_notice_version',
                                'consent_notice_sha256', 'storage_backend', 'key_id', 'started_at', 'is_synthetic',
                                'record_origin', 'created_at', 'created_by'];
          p text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'media_asset rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          FOREACH p IN ARRAY fixed LOOP
            IF (to_jsonb(NEW) -> p) IS DISTINCT FROM (to_jsonb(OLD) -> p) THEN
              RAISE EXCEPTION 'media_asset % is immutable', p USING ERRCODE = 'insufficient_privilege';
            END IF;
          END LOOP;
          IF OLD.content_sha256 IS NOT NULL AND NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 THEN
            RAISE EXCEPTION 'media_asset content checksum is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.manifest_sha256 IS NOT NULL AND NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256 THEN
            RAISE EXCEPTION 'media_asset manifest checksum is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.status = 'PURGED' AND NEW.status <> 'PURGED' THEN
            RAISE EXCEPTION 'a purged media_asset stays purged' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER media_asset_guard BEFORE UPDATE OR DELETE ON {s}.media_asset
          FOR EACH ROW EXECUTE FUNCTION {s}.media_asset_guard();
        """
    )
    op.drop_constraint("ck_session_event_type", "session_event", schema=s, type_="check")
    op.create_check_constraint(
        "ck_session_event_type",
        "session_event",
        "event_type IN (" + ", ".join(f"'{v}'" for v in OLD_EVENT_TYPES + RECORDING_EVENT_TYPES) + ")",
        schema=s,
    )
    op.execute(
        f"UPDATE {s}.permission SET reserved = false, description = "
        "'Retrieve recorded session audio (S1-C; audited)' "
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
        "event_type IN (" + ", ".join(f"'{v}'" for v in OLD_EVENT_TYPES) + ")",
        schema=s,
    )
    op.drop_table("media_chunk", schema=s)
    op.execute(f"DROP TRIGGER IF EXISTS media_asset_guard ON {s}.media_asset")
    op.drop_table("media_asset", schema=s)
    op.execute(f"DROP FUNCTION IF EXISTS {s}.media_asset_guard()")
