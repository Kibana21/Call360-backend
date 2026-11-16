"""CP0.1B-3: ``local_credential.must_change_password`` (S0_IDENTITY_ACCESS_DESIGN §3, "one-time password the user
must change at first sign-in").

Set when an administrator creates a local user (API-011) or resets a password (API-013); cleared when the user sets
their own password (API-009). While it is set, the account may sign in, read ``/me`` and change its password, and
every permission-protected endpoint returns ``403 PASSWORD_CHANGE_REQUIRED``. Existing credentials are unaffected.

Revision ID: 0010_password_change_required
Revises: 0009_intake
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_password_change_required"
down_revision = "0009_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "local_credential",
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("local_credential", "must_change_password")
