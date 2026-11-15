"""CP0.1A identity, session, access and audit foundation (15 tables; S0_DATA_MODEL §4.1, Build = CP0.1A).

Also seeds the access model (not accounts): the LOCAL identity provider, roles ADMIN/USER,
the permission catalogue (S0_IDENTITY_ACCESS_DESIGN §6), local groups and group→role mappings.

Revision ID: 0001_identity_foundation
Revises:
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001_identity_foundation"
down_revision = None
branch_labels = None
depends_on = None

NS = uuid.UUID("5d6c0a2e-3b1f-4c9e-9a51-360000000001")
TS = sa.DateTime(timezone=True)

ROLES = {"ADMIN": "Administrator", "USER": "Operations user"}
# (code, alias, reserved, description)
PERMISSIONS = [
    ("dashboard.read", None, False, "View Overview KPIs"),
    ("case.read", None, False, "View cases, attempts, sessions and findings"),
    ("policy.read", None, False, "View policies and sale events"),
    ("party.read", None, False, "View masked party and contact data"),
    ("risk.read", None, False, "View SBQ risk assessments"),
    ("script.read", None, False, "View Script Studio and regulatory references"),
    ("search.use", None, False, "Use global search"),
    ("saved_view.manage_own", None, False, "Manage own saved views"),
    ("queue.read", None, False, "View work queues and review lists"),
    ("voice.preflight.read", None, False, "View Voice Studio preflight"),
    ("intake.read", None, False, "View intake sources and runs"),
    ("intake.mock.sync", None, False, "Run mock upstream imports"),
    ("intake.manual.submit", None, False, "Submit manual intake and corrections"),
    ("admin.users.read", None, False, "View users, bindings and memberships"),
    ("admin.users.manage", "USER_ADMIN", False, "Create, enable or disable users; reset passwords"),
    ("admin.groups.manage", "USER_ADMIN", False, "Manage memberships and group mappings"),
    ("admin.sessions.manage", None, False, "View and revoke sessions"),
    ("audit.read", None, False, "Search audit events"),
    ("config.read", None, False, "View code lists and feature flags"),
    ("config.manage", None, False, "Change non-governed configuration"),
    ("system.health.read", None, False, "View system health detail"),
    ("script.edit", "SCRIPT_EDIT", True, "Reserved (S2)"),
    ("script.approve", "SCRIPT_APPROVE", True, "Reserved (S2)"),
    ("script.publish", "SCRIPT_APPROVE", True, "Reserved (S2)"),
    ("risk.override.request", "RISK_OVERRIDE", True, "Reserved (S2)"),
    ("risk.override.approve", "RISK_OVERRIDE", True, "Reserved (S2)"),
    ("recording.read", "RECORDING_READ", True, "Reserved (S1/S3)"),
    ("transcript.sensitive.read", "RECORDING_READ", True, "Reserved (S1/S3)"),
    ("review.decide", None, True, "Reserved (S3)"),
    ("evidence.export", "EVIDENCE_EXPORT", True, "Reserved (S3/S4)"),
    ("pii.unmasked", None, True, "Reserved (S5); granted to nobody in S0"),
]
USER_PERMISSIONS = {
    "dashboard.read",
    "case.read",
    "policy.read",
    "party.read",
    "risk.read",
    "script.read",
    "search.use",
    "saved_view.manage_own",
    "queue.read",
    "voice.preflight.read",
}
GROUPS = [
    ("LOCAL_ADMIN", "Local administrators", "ADMIN"),
    ("LOCAL_USER_SG", "Local users — SG (synthetic)", "USER"),
    ("LOCAL_USER_MY", "Local users — MY (synthetic)", "USER"),
]


def _id(kind: str, code: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"{kind}:{code}")


def upgrade() -> None:
    schema = op.get_context().version_table_schema
    assert schema in {"call360", "call360_test"}, schema
    uid = UUID(as_uuid=True)

    op.create_table(
        "identity_provider",
        sa.Column("id", uid, primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("issuer", sa.String(200), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('LOCAL','OIDC_ENTRA','OIDC_OKTA')", name="ck_identity_provider_kind"),
        schema=schema,
    )
    op.create_table(
        "principal",
        sa.Column("id", uid, primary_key=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("disabled_at", TS),
        sa.Column("disabled_by", sa.String(80)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(80), nullable=False),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.CheckConstraint("status IN ('ACTIVE','DISABLED')", name="ck_principal_status"),
        schema=schema,
    )
    op.create_table(
        "identity_binding",
        sa.Column("id", uid, primary_key=True),
        sa.Column("principal_id", uid, sa.ForeignKey(f"{schema}.principal.id"), nullable=False),
        sa.Column("identity_provider_id", uid, sa.ForeignKey(f"{schema}.identity_provider.id"), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("username", sa.String(64), unique=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("identity_provider_id", "subject"),
        schema=schema,
    )
    op.create_table(
        "local_credential",
        sa.Column("id", uid, primary_key=True),
        sa.Column("principal_id", uid, sa.ForeignKey(f"{schema}.principal.id"), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("hash_params", sa.String(64), nullable=False),
        sa.Column("password_changed_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("failed_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        schema=schema,
    )
    op.create_table(
        "app_group",
        sa.Column("id", uid, primary_key=True),
        sa.Column("identity_provider_id", uid, sa.ForeignKey(f"{schema}.identity_provider.id"), nullable=False),
        sa.Column("external_group_id", sa.String(200)),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        schema=schema,
    )
    op.create_table(
        "group_membership",
        sa.Column("id", uid, primary_key=True),
        sa.Column("principal_id", uid, sa.ForeignKey(f"{schema}.principal.id"), nullable=False),
        sa.Column("group_id", uid, sa.ForeignKey(f"{schema}.app_group.id"), nullable=False),
        sa.Column("valid_from", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("valid_to", TS),
        sa.Column("provenance", sa.String(40), nullable=False),
        sa.Column("created_by", sa.String(80), nullable=False),
        schema=schema,
    )
    op.create_table(
        "role",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code", sa.String(32), nullable=False, unique=True),
        sa.Column("name", sa.String(80), nullable=False),
        schema=schema,
    )
    op.create_table(
        "permission",
        sa.Column("id", uid, primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("alias", sa.String(64)),
        sa.Column("reserved", sa.Boolean, nullable=False),
        sa.Column("description", sa.String(200), nullable=False),
        schema=schema,
    )
    op.create_table(
        "role_permission",
        sa.Column("role_id", uid, sa.ForeignKey(f"{schema}.role.id"), primary_key=True),
        sa.Column("permission_id", uid, sa.ForeignKey(f"{schema}.permission.id"), primary_key=True),
        schema=schema,
    )
    op.create_table(
        "group_role_mapping",
        sa.Column("id", uid, primary_key=True),
        sa.Column("group_id", uid, sa.ForeignKey(f"{schema}.app_group.id"), nullable=False),
        sa.Column("role_id", uid, sa.ForeignKey(f"{schema}.role.id"), nullable=False),
        sa.Column("effective_from", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("effective_to", TS),
        sa.Column("approved_by", sa.String(80), nullable=False),
        schema=schema,
    )
    op.create_table(
        "auth_session",
        sa.Column("id", uid, primary_key=True),
        sa.Column("principal_id", uid, sa.ForeignKey(f"{schema}.principal.id"), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_seen_at", TS, nullable=False),
        sa.Column("idle_expires_at", TS, nullable=False),
        sa.Column("absolute_expires_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
        sa.Column("revoked_reason", sa.String(64)),
        sa.Column("user_agent_hash", sa.String(64)),
        sa.Column("ip", sa.String(64)),
        schema=schema,
    )
    op.create_index("ix_auth_session_principal", "auth_session", ["principal_id"], schema=schema)
    op.create_table(
        "refresh_token_family",
        sa.Column("id", uid, primary_key=True),
        sa.Column("session_id", uid, sa.ForeignKey(f"{schema}.auth_session.id"), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
        sa.Column("revoked_reason", sa.String(64)),
        schema=schema,
    )
    op.create_table(
        "refresh_token",
        sa.Column("id", uid, primary_key=True),
        sa.Column("family_id", uid, sa.ForeignKey(f"{schema}.refresh_token_family.id"), nullable=False),
        sa.Column("generation", sa.Integer, nullable=False),
        sa.Column("token_hmac", sa.String(64), nullable=False, unique=True),
        sa.Column("issued_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
        sa.Column("reuse_detected_at", TS),
        sa.UniqueConstraint("family_id", "generation"),
        schema=schema,
    )
    op.create_table(
        "login_attempt",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("username_hash", sa.String(64), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        schema=schema,
    )
    op.create_index("ix_login_attempt_user_time", "login_attempt", ["username_hash", "occurred_at"], schema=schema)
    op.create_table(
        "audit_event",
        sa.Column("id", uid, primary_key=True),
        sa.Column("seq", sa.BigInteger, sa.Identity(), nullable=False, unique=True),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("actor_principal_id", uid),
        sa.Column("actor_snapshot", JSONB),
        sa.Column("session_id", uid),
        sa.Column("request_id", sa.String(64)),
        sa.Column("correlation_id", sa.String(64)),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(64)),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("entity_version", sa.Integer),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(500)),
        sa.Column("before", JSONB),
        sa.Column("after", JSONB),
        sa.Column("prev_hash", sa.String(64)),
        sa.Column("row_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("outcome IN ('SUCCEEDED','DENIED','FAILED')", name="ck_audit_outcome"),
        schema=schema,
    )
    op.create_index("ix_audit_event_action", "audit_event", ["action"], schema=schema)

    # Append-only audit (ADR-0005 §1): reject UPDATE, DELETE and TRUNCATE.
    op.execute(f"""
        CREATE FUNCTION {schema}.audit_event_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'audit_event is append-only' USING ERRCODE = 'insufficient_privilege'; END $$;
        CREATE TRIGGER audit_event_no_update_delete BEFORE UPDATE OR DELETE ON {schema}.audit_event
            FOR EACH ROW EXECUTE FUNCTION {schema}.audit_event_append_only();
        CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON {schema}.audit_event
            FOR EACH STATEMENT EXECUTE FUNCTION {schema}.audit_event_append_only();
    """)
    # Reserved permissions can never be granted in S0 (ADMIN-003, BE-IAM-03).
    op.execute(f"""
        CREATE FUNCTION {schema}.role_permission_no_reserved() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF (SELECT reserved FROM {schema}.permission WHERE id = NEW.permission_id) THEN
            RAISE EXCEPTION 'reserved permission cannot be granted in Stage 0' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER role_permission_no_reserved BEFORE INSERT OR UPDATE ON {schema}.role_permission
            FOR EACH ROW EXECUTE FUNCTION {schema}.role_permission_no_reserved();
    """)

    # Access-model seed (no accounts, no credentials).
    def t(name: str, *cols: str) -> sa.TableClause:
        return sa.table(name, *(sa.column(c) for c in cols), schema=schema)

    local_id = _id("idp", "call360-local")
    op.bulk_insert(
        t("identity_provider", "id", "kind", "issuer", "status"),
        [{"id": local_id, "kind": "LOCAL", "issuer": "call360-local", "status": "ACTIVE"}],
    )
    op.bulk_insert(
        t("role", "id", "code", "name"), [{"id": _id("role", c), "code": c, "name": n} for c, n in ROLES.items()]
    )
    op.bulk_insert(
        t("permission", "id", "code", "alias", "reserved", "description"),
        [{"id": _id("perm", c), "code": c, "alias": a, "reserved": r, "description": d} for c, a, r, d in PERMISSIONS],
    )
    grants = [{"role_id": _id("role", "ADMIN"), "permission_id": _id("perm", c)} for c, _, r, _ in PERMISSIONS if not r]
    grants += [{"role_id": _id("role", "USER"), "permission_id": _id("perm", c)} for c in sorted(USER_PERMISSIONS)]
    op.bulk_insert(t("role_permission", "role_id", "permission_id"), grants)
    op.bulk_insert(
        t("app_group", "id", "identity_provider_id", "external_group_id", "code", "name", "status"),
        [
            {
                "id": _id("group", c),
                "identity_provider_id": local_id,
                "external_group_id": None,
                "code": c,
                "name": n,
                "status": "ACTIVE",
            }
            for c, n, _ in GROUPS
        ],
    )
    op.bulk_insert(
        t("group_role_mapping", "id", "group_id", "role_id", "approved_by"),
        [
            {
                "id": _id("grm", c),
                "group_id": _id("group", c),
                "role_id": _id("role", role),
                "approved_by": "SYSTEM:migration-0001",
            }
            for c, _, role in GROUPS
        ],
    )


def downgrade() -> None:
    schema = op.get_context().version_table_schema
    assert schema in {"call360", "call360_test"}, schema
    for table in (
        "audit_event",
        "login_attempt",
        "refresh_token",
        "refresh_token_family",
        "auth_session",
        "group_role_mapping",
        "role_permission",
        "permission",
        "role",
        "group_membership",
        "app_group",
        "local_credential",
        "identity_binding",
        "principal",
        "identity_provider",
    ):
        op.drop_table(table, schema=schema)
    op.execute(f"DROP FUNCTION IF EXISTS {schema}.audit_event_append_only()")
    op.execute(f"DROP FUNCTION IF EXISTS {schema}.role_permission_no_reserved()")
