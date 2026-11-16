"""S1-B: ``session_event`` — the ordered, idempotent voice-session event ledger (EVD-002, VOICE-006).

One row per event of a browser voice attempt (and its conversation session once connected): server-assigned ``seq``
per attempt, ``source`` (SERVER, CLIENT, SYSTEM), an optional client event ID that de-duplicates retries and
reconnects, the client's sequence and timestamp (``out_of_order`` when it arrives late), and metadata-only ``details``.
Never audio, transcript text or microphone content. Insert-only (ADR-0005). Lifecycle state itself stays on the
existing ``contact_attempt`` and ``conversation_session`` rows.

Revision ID: 0012_session_event
Revises: 0011_voice_session_permission
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, forbid_change_trigger, pk

revision = "0012_session_event"
down_revision = "0011_voice_session_permission"
branch_labels = None
depends_on = None

EVENT_TYPES = (
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
SOURCES = ("SERVER", "CLIENT", "SYSTEM")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.create_table(
        "session_event",
        pk(),
        sa.Column("contact_attempt_id", sa.Uuid(), sa.ForeignKey(f"{s}.contact_attempt.id"), nullable=False),
        sa.Column("conversation_session_id", sa.Uuid(), sa.ForeignKey(f"{s}.conversation_session.id")),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("client_event_id", sa.String(64)),
        sa.Column("client_seq", sa.Integer()),
        sa.Column("client_occurred_at", TS),
        sa.Column("out_of_order", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("correlation_id", sa.String(80)),
        sa.UniqueConstraint("contact_attempt_id", "seq", name="uq_session_event_seq"),
        enum_check("event_type", EVENT_TYPES, "ck_session_event_type"),
        enum_check("source", SOURCES, "ck_session_event_source"),
        sa.CheckConstraint("seq >= 1", name="ck_session_event_seq"),
        sa.CheckConstraint("client_event_id IS NULL OR source = 'CLIENT'", name="ck_session_event_client_id"),
        schema=s,
    )
    op.create_index(
        "ux_session_event_client_event",
        "session_event",
        ["contact_attempt_id", "client_event_id"],
        unique=True,
        schema=s,
        postgresql_where=sa.text("client_event_id IS NOT NULL"),
    )
    op.execute(forbid_change_trigger(s, "session_event"))


def downgrade() -> None:
    s = op.get_context().version_table_schema
    op.drop_table("session_event", schema=s)
