"""S1-A: permission ``voice.session.start`` (start a local browser voice session on a callable case).

Granted to the existing ADMIN and USER roles; no new role. It is not a reserved permission. Voice sessions in S1-A
are held in memory and audited (``VOICE.SESSION_*``); session persistence arrives in S1-B.

Revision ID: 0011_voice_session_permission
Revises: 0010_password_change_required
"""

from __future__ import annotations

import uuid

from alembic import op

revision = "0011_voice_session_permission"
down_revision = "0010_password_change_required"
branch_labels = None
depends_on = None

CODE = "voice.session.start"


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.execute(
        f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES "
        f"('{uuid.uuid5(uuid.NAMESPACE_URL, 'call360:permission:' + CODE)}', '{CODE}', NULL, false, "
        "'Start a local browser voice session on a callable case (S1)')"
    )
    op.execute(
        f"INSERT INTO {s}.role_permission (role_id, permission_id) "
        f"SELECT r.id, p.id FROM {s}.role r, {s}.permission p WHERE r.code IN ('ADMIN', 'USER') AND p.code = '{CODE}'"
    )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code = '{CODE}')"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code = '{CODE}'")
