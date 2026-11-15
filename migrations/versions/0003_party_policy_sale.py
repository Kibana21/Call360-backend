"""CP0.2 party, policy and sale (8 tables; S0_DATA_MODEL §4.2, §4.6, D-29).

Revision ID: 0003_party_policy_sale
Revises: 0002_config_foundation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import (
    TS,
    enum_check,
    fk,
    forbid_change_trigger,
    market_trigger,
    operational,
    pk,
    provenance,
    sha256_check,
)

revision = "0003_party_policy_sale"
down_revision = "0002_config_foundation"
branch_labels = None
depends_on = None

PARTY_ROLES = ("OWNER", "INSURED", "PAYER", "PROPOSER", "BENEFICIARY", "AUTHORIZED_CONTACT")
SELLING_CHANNELS = ("AGENCY", "BANCASSURANCE", "BROKER", "DIRECT")
TABLES = (
    "party",
    "contact_method",
    "policy",
    "policy_party_role",
    "fsc_representative",
    "sale_event",
    "policy_fact_snapshot",
    "external_reference",
)
FUNCTIONS = ("forbid_change", "assert_market_code", "contact_method_guard", "sale_event_guard", "fact_snapshot_check")


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    op.create_table(
        "party",
        pk(),
        sa.Column("party_ref", sa.String(40), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("display_alias", sa.String(80), nullable=False),
        sa.Column("name_ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("masked_name", sa.String(120), nullable=False),
        sa.Column("date_of_birth_year", sa.SmallInteger),
        sa.Column("personal_data_class", sa.String(40), nullable=False),
        *operational(mutable=True),
        *provenance("party"),
        enum_check("kind", ("PERSON", "ORGANIZATION"), "ck_party_kind"),
        schema=s,
    )
    op.create_table(
        "contact_method",
        pk(),
        fk("party_id", "party", s),
        sa.Column("channel", sa.String(8), nullable=False),
        sa.Column("value_ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("value_hmac", sa.String(64), nullable=False),
        sa.Column("masked_value", sa.String(120), nullable=False),
        sa.Column("is_verified", sa.Boolean, nullable=False),
        sa.Column("preference_rank", sa.SmallInteger, nullable=False),
        sa.Column("language", sa.String(16), nullable=False),
        sa.Column("timezone", sa.String(40), nullable=False),
        sa.Column("consent_status", sa.String(16), nullable=False),
        sa.Column("suppressed", sa.Boolean, nullable=False),
        sa.Column("valid_from", TS, nullable=False),
        sa.Column("valid_to", TS),
        *operational(mutable=True),
        *provenance("contact_method"),
        enum_check("channel", ("PHONE", "EMAIL"), "ck_contact_method_channel"),
        enum_check("consent_status", ("GRANTED", "WITHDRAWN", "UNKNOWN"), "ck_contact_method_consent"),
        sa.CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="ck_contact_method_interval"),
        sha256_check("value_hmac", "contact_method"),
        schema=s,
    )
    op.create_index("ix_contact_method_hmac", "contact_method", ["value_hmac"], schema=s)
    op.create_index("ix_contact_method_party", "contact_method", ["party_id"], schema=s)
    op.create_table(
        "policy",
        pk(),
        sa.Column("policy_ref", sa.String(40), nullable=False, unique=True),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("product_code", sa.String(40), nullable=False),
        sa.Column("product_family", sa.String(40), nullable=False),
        sa.Column("product_subtype", sa.String(40), nullable=False),
        sa.Column("is_ilp", sa.Boolean, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("premium_amount", sa.Numeric(14, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("premium_frequency", sa.String(12), nullable=False),
        sa.Column("premium_term_years", sa.SmallInteger),
        sa.Column("sum_assured", sa.Numeric(16, 2)),
        sa.Column("sum_assured_currency", sa.String(3)),
        sa.Column("effective_from", TS, nullable=False),
        sa.Column("effective_to", TS),
        *operational(mutable=True),
        *provenance("policy"),
        enum_check(
            "status", ("PROPOSAL", "IN_FORCE", "FREE_LOOK_CANCELLED", "LAPSED", "TERMINATED"), "ck_policy_status"
        ),
        enum_check(
            "premium_frequency", ("SINGLE", "MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"), "ck_policy_frequency"
        ),
        sa.CheckConstraint("premium_amount >= 0", name="ck_policy_premium"),
        sa.CheckConstraint("premium_term_years IS NULL OR premium_term_years > 0", name="ck_policy_term"),
        sa.CheckConstraint("effective_to IS NULL OR effective_to > effective_from", name="ck_policy_interval"),
        schema=s,
    )
    op.create_table(
        "policy_party_role",
        pk(),
        fk("policy_id", "policy", s),
        fk("party_id", "party", s),
        sa.Column("role", sa.String(24), nullable=False),
        sa.Column("valid_from", TS, nullable=False),
        sa.Column("valid_to", TS),
        sa.Column("authorization_ref", sa.String(80)),
        sa.Column("authorization_valid_from", TS),
        sa.Column("authorization_valid_to", TS),
        *operational(mutable=True),
        *provenance("policy_party_role"),
        enum_check("role", PARTY_ROLES, "ck_policy_party_role_role"),
        sa.UniqueConstraint("policy_id", "party_id", "role", "valid_from", name="uq_policy_party_role"),
        sa.CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="ck_policy_party_role_interval"),
        # Authorisation evidence is all-or-nothing (D-36); a role alone never establishes authority.
        sa.CheckConstraint(
            "(authorization_ref IS NULL) = (authorization_valid_from IS NULL) "
            "AND (authorization_ref IS NOT NULL OR authorization_valid_to IS NULL) "
            "AND (authorization_valid_to IS NULL OR authorization_valid_to > authorization_valid_from)",
            name="ck_policy_party_role_authorization",
        ),
        schema=s,
    )
    op.create_index("ix_policy_party_role_party", "policy_party_role", ["party_id"], schema=s)
    op.create_table(
        "fsc_representative",
        pk(),
        sa.Column("fsc_ref", sa.String(40), nullable=False, unique=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        *operational(mutable=True),
        *provenance("fsc_representative"),
        enum_check("channel", SELLING_CHANNELS, "ck_fsc_channel"),
        enum_check("status", ("ACTIVE", "INACTIVE"), "ck_fsc_status"),
        schema=s,
    )
    op.create_table(
        "sale_event",
        pk(),
        sa.Column("sale_ref", sa.String(40), nullable=False, unique=True),
        fk("policy_id", "policy", s),
        sa.Column("sale_event_type", sa.String(16), nullable=False),
        sa.Column("sold_at", TS, nullable=False),
        fk("fsc_id", "fsc_representative", s),
        sa.Column("selling_channel", sa.String(16), nullable=False),
        sa.Column("selling_location", sa.String(80), nullable=False),
        sa.Column("campaign_code", sa.String(40)),
        sa.Column("proposal_ref", sa.String(40), nullable=False),
        sa.Column("product_snapshot", JSONB, nullable=False),
        sa.Column("premium_amount", sa.Numeric(14, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        *operational(mutable=True),
        *provenance("sale_event"),
        enum_check(
            "sale_event_type", ("NEW_BUSINESS", "REPLACEMENT", "TOP_UP", "OTHER_APPROVED"), "ck_sale_event_type"
        ),
        enum_check("selling_channel", SELLING_CHANNELS, "ck_sale_event_channel"),
        sa.UniqueConstraint("source_system", "source_reference", name="uq_sale_event_source"),
        schema=s,
    )
    op.create_index("ix_sale_event_policy", "sale_event", ["policy_id"], schema=s)
    op.create_table(
        "policy_fact_snapshot",
        pk(),
        fk("policy_id", "policy", s),
        fk("sale_event_id", "sale_event", s),
        sa.Column("captured_at", TS, nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("facts", JSONB, nullable=False),
        sa.Column("field_provenance", JSONB, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        *operational(mutable=False),
        *provenance("policy_fact_snapshot"),
        sha256_check("sha256", "policy_fact_snapshot"),
        schema=s,
    )
    op.create_table(
        "external_reference",
        pk(),
        sa.Column("source_system", sa.String(80), nullable=False),
        sa.Column("object_type", sa.String(24), nullable=False),
        sa.Column("external_id", sa.String(80), nullable=False),
        sa.Column("entity_id", sa.Uuid, nullable=False),
        *operational(mutable=False),
        enum_check(
            "object_type",
            ("PARTY", "POLICY", "SALE_EVENT", "CONTACT_METHOD", "FSC_REPRESENTATIVE"),
            "ck_external_reference_type",
        ),
        sa.UniqueConstraint("source_system", "object_type", "external_id", name="uq_external_reference"),
        schema=s,
    )

    op.execute(f"""
        -- Write-once rows (ADR-0005 §3): any UPDATE or DELETE is rejected.
        CREATE FUNCTION {s}.forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '% is immutable (% rejected)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
        END $$;

        -- Market scope is a stable code validated against the fixed market code set (D-25, D-30).
        CREATE FUNCTION {s}.assert_market_code() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM {s}.code_value cv
              JOIN {s}.code_list_version clv ON clv.id = cv.code_list_version_id
              JOIN {s}.code_list cl ON cl.id = clv.code_list_id
             WHERE cl.code = 'market' AND cv.code = NEW.market_code) THEN
            RAISE EXCEPTION 'unknown market code %', NEW.market_code USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;

        -- A contact change inserts a new row; the old row may only be closed once (PARTY-003, INV-05).
        CREATE FUNCTION {s}.contact_method_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'contact_method rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (to_jsonb(NEW) - ARRAY['valid_to', 'updated_at', 'updated_by', 'row_version'])
             IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['valid_to', 'updated_at', 'updated_by', 'row_version'])
             OR (OLD.valid_to IS NOT NULL AND NEW.valid_to IS DISTINCT FROM OLD.valid_to) THEN
            RAISE EXCEPTION 'contact_method is versioned: insert a new row and close the old one'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER contact_method_guard BEFORE UPDATE OR DELETE ON {s}.contact_method
          FOR EACH ROW EXECUTE FUNCTION {s}.contact_method_guard();

        -- Sale context and FSC are frozen at sale (POL-003); sale events are never deleted.
        CREATE FUNCTION {s}.sale_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'sale_event rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF (NEW.policy_id, NEW.sale_event_type, NEW.sold_at, NEW.fsc_id, NEW.selling_channel, NEW.selling_location,
              NEW.campaign_code, NEW.product_snapshot, NEW.source_system, NEW.source_reference)
             IS DISTINCT FROM
             (OLD.policy_id, OLD.sale_event_type, OLD.sold_at, OLD.fsc_id, OLD.selling_channel, OLD.selling_location,
              OLD.campaign_code, OLD.product_snapshot, OLD.source_system, OLD.source_reference) THEN
            RAISE EXCEPTION 'sale context is frozen at sale' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER sale_event_guard BEFORE UPDATE OR DELETE ON {s}.sale_event
          FOR EACH ROW EXECUTE FUNCTION {s}.sale_event_guard();

        -- A fact snapshot belongs to one sale of its policy.
        CREATE FUNCTION {s}.fact_snapshot_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM {s}.sale_event WHERE id = NEW.sale_event_id AND policy_id = NEW.policy_id) THEN
            RAISE EXCEPTION 'fact snapshot sale event does not belong to its policy' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER policy_fact_snapshot_check BEFORE INSERT ON {s}.policy_fact_snapshot
          FOR EACH ROW EXECUTE FUNCTION {s}.fact_snapshot_check();

        {forbid_change_trigger(s, "policy_fact_snapshot")}
        {forbid_change_trigger(s, "external_reference")}
        {market_trigger(s, "policy")}
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    for table in reversed(TABLES):
        op.drop_table(table, schema=s)
    for fn in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {s}.{fn}()")
