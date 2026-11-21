"""SS-03A: survey definition foundation — additive tables for governed survey definitions.

ADDITIVE ONLY. No existing table, row, constraint, trigger, permission grant or role is altered or removed, and no
foreign key points at a script table. With the server setting ``survey_definitions_enabled`` off (the default) nothing
in the product reads or writes these tables.

- ``survey_definition``: identity of a survey.
- ``survey_draft``: the one mutable working copy per survey; ``revision`` is the optimistic-concurrency token.
- ``survey_asset_version``: option set, item, wording, condition and module versions. DRAFT rows may change; a FROZEN
  row can never be changed or deleted (trigger).
- ``survey_candidate``: an immutable submission — content, manifest and their SHA-256 (insert-only).
- ``survey_version``: an immutable published version, made from one approved candidate (insert-only).
- ``survey_lifecycle_event``: APPEND-ONLY history of decisions on candidates and versions. Status is derived from it;
  no candidate or version row is ever updated. A trigger enforces legal transitions and the identity rules
  independently of permissions: the approver is not a maker; the publisher is not the submitter, a maker or the approver.
- ``survey_wording_approval``: append-only approval evidence naming the exact wording version and candidate (D-178).
- ``survey_asset_usage``: a DERIVED index of which candidate or version pins which asset version; rebuildable.
- ``survey_catalog_entry``: governed catalogs (fields, outcomes, response obligations). Every entry is synthetic and
  the CHECK constraint admits no approval state other than SYNTHETIC_UNAPPROVED. ``speakable`` is false on every field:
  no customer field is authorised for speech (D-181). The outcome class NON_ANSWER_EXCEPTION is admitted by the schema
  and has no entry (D-180).

Permissions ``survey.read``, ``survey.edit``, ``survey.approve``, ``survey.publish`` are created and granted to NO role:
no production or development role receives them from this migration (D-182).

Revision ID: 0027_survey_definitions
Revises: 0026_gpt_live_provider
"""

from __future__ import annotations

import json
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.db.ddl import TS, enum_check, fk, forbid_change_trigger, market_trigger, pk, sha256_check, uid

revision = "0027_survey_definitions"
down_revision = "0026_gpt_live_provider"
branch_labels = None
depends_on = None

NS = uuid.UUID("5c0a3f6e-27a0-4b53-9d0e-0027000000aa")
PERMISSIONS = {
    "survey.read": "Read survey definitions, candidates, versions and the survey library (SS-03A)",
    "survey.edit": "Create surveys, change drafts and submit candidates (SS-03A)",
    "survey.approve": "Approve or reject a submitted survey candidate; never one you made (SS-03A)",
    "survey.publish": "Publish an approved survey candidate; never one you made or approved (SS-03A)",
}
ASSET_KINDS = ("OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE")
EVENTS = ("SUBMITTED", "APPROVED", "REJECTED", "WITHDRAWN", "SUPERSEDED", "PUBLISHED", "SCHEDULED")
OUTCOME_CLASSES = ("NORMAL_COMPLETION", "EXCEPTION", "ESCALATION", "REVIEW_HALT", "NON_ANSWER_EXCEPTION")
TABLES = (
    "survey_definition",
    "survey_draft",
    "survey_asset_version",
    "survey_candidate",
    "survey_version",
    "survey_lifecycle_event",
    "survey_wording_approval",
    "survey_asset_usage",
    "survey_catalog_entry",
)

# Synthetic catalog content. NOT approved business policy: illustrative entries so that definitions can be validated.
FIELDS = {
    "policy.product_family": {"type": "ENUM", "values": ["PROTECTION", "ILP", "ENDOWMENT"], "label": "Product family"},
    "policy.annual_premium": {"type": "MONEY", "unit": "SGD", "scale": 2, "label": "Annual premium"},
    "policy.sum_assured": {"type": "MONEY", "unit": "SGD", "scale": 2, "label": "Sum assured"},
    "policy.is_replacement": {"type": "BOOLEAN", "label": "Replaces an existing policy"},
    "customer.age_years": {"type": "INTEGER", "unit": "years", "scale": 0, "label": "Customer age"},
    "sale.channel": {"type": "ENUM", "values": ["AGENCY", "BANCASSURANCE", "DIRECT"], "label": "Selling channel"},
    "policy.plan_name": {"type": "TEXT", "label": "Plan name"},
    "policy.term_years": {"type": "INTEGER", "unit": "years", "scale": 0, "label": "Policy term"},
}
OUTCOMES = {
    "COMPLETED": ("NORMAL_COMPLETION", "Completed"),
    "CLARIFICATION_REQUIRED": ("EXCEPTION", "Clarification required"),
    "ESCALATE": ("ESCALATION", "Escalate"),
    "CUSTOMER_DECLINED": ("EXCEPTION", "Customer declined"),
    "UNABLE_TO_VERIFY": ("EXCEPTION", "Unable to verify"),
    "REVIEW_REQUIRED": ("REVIEW_HALT", "Review required"),
}
OBLIGATIONS = {
    "MANDATORY": "Mandatory (synthetic placeholder)",
    "NOT_MANDATORY": "Not mandatory (synthetic placeholder)",
}


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()

    for code, description in PERMISSIONS.items():  # created, and granted to nobody
        conn.execute(
            sa.text(
                f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES (:i, :c, NULL, false, :d)"
            ),
            {"i": uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + code), "c": code, "d": description},
        )

    op.create_table(
        "survey_definition",
        pk(),
        sa.Column("code", sa.String(60), nullable=False, unique=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("purpose", sa.Text, nullable=False, server_default=""),
        sa.Column("market_code", sa.String(8), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.CheckConstraint("code ~ '^[A-Z][A-Z0-9_-]{2,59}$'", name="ck_survey_definition_code"),
        schema=s,
    )
    op.execute(market_trigger(s, "survey_definition"))

    op.create_table(
        "survey_draft",
        pk(),
        sa.Column(
            "survey_definition_id", uid(), sa.ForeignKey(f"{s}.survey_definition.id"), nullable=False, unique=True
        ),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("makers", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(80), nullable=False),
        sa.CheckConstraint("revision >= 0", name="ck_survey_draft_revision"),
        schema=s,
    )
    # the revision only ever moves forward by one: a lost update cannot be written even by mistake
    op.execute(f"""
        CREATE FUNCTION {s}.survey_draft_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'a survey draft is never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.survey_definition_id IS DISTINCT FROM OLD.survey_definition_id OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'a draft revision advances by exactly one' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_draft_guard BEFORE UPDATE OR DELETE ON {s}.survey_draft
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_draft_guard();
    """)

    op.create_table(
        "survey_asset_version",
        pk(),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("state", sa.String(8), nullable=False, server_default="DRAFT"),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        fk("owner_definition_id", "survey_definition", s, nullable=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("frozen_at", TS),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("kind", "code", "version", name="uq_survey_asset_version"),
        enum_check("kind", ASSET_KINDS, "ck_survey_asset_version_kind"),
        enum_check("state", ("DRAFT", "FROZEN"), "ck_survey_asset_version_state"),
        sa.CheckConstraint("version >= 1", name="ck_survey_asset_version_version"),
        sa.CheckConstraint("(state = 'FROZEN') = (frozen_at IS NOT NULL)", name="ck_survey_asset_version_frozen_at"),
        sha256_check("sha256", "survey_asset_version"),
        schema=s,
    )
    op.execute(f"""
        CREATE FUNCTION {s}.survey_asset_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.state = 'FROZEN' THEN
            RAISE EXCEPTION 'a frozen asset version is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'DELETE' THEN
            RETURN OLD;
          END IF;
          IF (NEW.kind, NEW.code, NEW.version) IS DISTINCT FROM (OLD.kind, OLD.code, OLD.version) THEN
            RAISE EXCEPTION 'the identity of an asset version never changes' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.state = 'FROZEN' AND (NEW.content IS DISTINCT FROM OLD.content OR NEW.sha256 IS DISTINCT FROM OLD.sha256) THEN
            RAISE EXCEPTION 'freezing does not change content' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_asset_version_guard BEFORE UPDATE OR DELETE ON {s}.survey_asset_version
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_asset_version_guard();
    """)

    op.create_table(
        "survey_candidate",
        pk(),
        fk("survey_definition_id", "survey_definition", s),
        sa.Column("n", sa.Integer, nullable=False),
        sa.Column("draft_revision", sa.Integer, nullable=False),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("manifest", JSONB, nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("makers", JSONB, nullable=False),
        sa.Column("note", sa.Text, nullable=False, server_default=""),
        sa.Column("acknowledgements", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("submitted_by", sa.String(80), nullable=False),
        sa.Column("submitted_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("survey_definition_id", "n", name="uq_survey_candidate_n"),
        sa.CheckConstraint("n >= 1", name="ck_survey_candidate_n"),
        sha256_check("content_sha256", "survey_candidate"),
        sha256_check("manifest_sha256", "survey_candidate"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "survey_candidate"))

    op.create_table(
        "survey_version",
        pk(),
        fk("survey_definition_id", "survey_definition", s),
        sa.Column("version_no", sa.Integer, nullable=False),
        sa.Column("label", sa.String(20), nullable=False),
        sa.Column("candidate_id", uid(), sa.ForeignKey(f"{s}.survey_candidate.id"), nullable=False, unique=True),
        sa.Column("effective_from", TS),  # recorded only: nothing takes effect on a date in SS-03A
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("survey_definition_id", "version_no", name="uq_survey_version_no"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "survey_version"))

    op.create_table(
        "survey_lifecycle_event",
        pk(),
        sa.Column("seq", sa.BigInteger, sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("subject_type", sa.String(12), nullable=False),
        sa.Column("subject_id", uid(), nullable=False),
        fk("survey_definition_id", "survey_definition", s),
        sa.Column("event", sa.String(12), nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("reason", sa.Text),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        enum_check("subject_type", ("CANDIDATE", "VERSION"), "ck_survey_lifecycle_event_subject"),
        enum_check("event", EVENTS, "ck_survey_lifecycle_event_event"),
        schema=s,
    )
    op.execute(f"CREATE INDEX ix_survey_lifecycle_event_subject ON {s}.survey_lifecycle_event (subject_id, seq)")
    op.execute(forbid_change_trigger(s, "survey_lifecycle_event"))
    # Legal transitions and identity rules, enforced by the database whatever the caller's permissions.
    op.execute(f"""
        CREATE FUNCTION {s}.survey_lifecycle_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          last_event text;
          cand {s}.survey_candidate%ROWTYPE;
          approver text;
        BEGIN
          SELECT e.event INTO last_event FROM {s}.survey_lifecycle_event e
            WHERE e.subject_id = NEW.subject_id ORDER BY e.seq DESC LIMIT 1;
          IF NEW.subject_type = 'CANDIDATE' THEN
            SELECT * INTO cand FROM {s}.survey_candidate c WHERE c.id = NEW.subject_id;
            IF NOT FOUND OR cand.survey_definition_id <> NEW.survey_definition_id THEN
              RAISE EXCEPTION 'lifecycle event for an unknown candidate' USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NOT (
                 (NEW.event = 'SUBMITTED' AND last_event IS NULL)
              OR (NEW.event IN ('APPROVED', 'REJECTED') AND last_event = 'SUBMITTED')
              OR (NEW.event IN ('WITHDRAWN', 'SUPERSEDED') AND last_event IN ('SUBMITTED', 'APPROVED'))
              OR (NEW.event = 'PUBLISHED' AND last_event = 'APPROVED')) THEN
              RAISE EXCEPTION 'illegal candidate transition % after %', NEW.event, coalesce(last_event, 'nothing')
                USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NEW.event = 'SUBMITTED' AND NEW.actor_ref <> cand.submitted_by THEN
              RAISE EXCEPTION 'a candidate is submitted by its submitter' USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NEW.event IN ('APPROVED', 'REJECTED', 'PUBLISHED')
               AND (NEW.actor_ref = cand.submitted_by OR cand.makers ? NEW.actor_ref) THEN
              RAISE EXCEPTION 'a maker of a candidate cannot decide or publish it' USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NEW.event = 'PUBLISHED' THEN
              SELECT e.actor_ref INTO approver FROM {s}.survey_lifecycle_event e
                WHERE e.subject_id = NEW.subject_id AND e.event = 'APPROVED' ORDER BY e.seq DESC LIMIT 1;
              IF approver = NEW.actor_ref THEN
                RAISE EXCEPTION 'the approver of a candidate cannot publish it' USING ERRCODE = 'insufficient_privilege';
              END IF;
            END IF;
          ELSE
            IF NOT EXISTS (SELECT 1 FROM {s}.survey_version v WHERE v.id = NEW.subject_id
                           AND v.survey_definition_id = NEW.survey_definition_id) THEN
              RAISE EXCEPTION 'lifecycle event for an unknown version' USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF NOT (
                 (NEW.event IN ('PUBLISHED', 'SCHEDULED') AND last_event IS NULL)
              OR (NEW.event = 'PUBLISHED' AND last_event = 'SCHEDULED')
              OR (NEW.event IN ('SUPERSEDED', 'WITHDRAWN') AND last_event IN ('PUBLISHED', 'SCHEDULED'))) THEN
              RAISE EXCEPTION 'illegal version transition % after %', NEW.event, coalesce(last_event, 'nothing')
                USING ERRCODE = 'insufficient_privilege';
            END IF;
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_lifecycle_event_guard BEFORE INSERT ON {s}.survey_lifecycle_event
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_lifecycle_event_guard();
    """)
    # a version exists only for a candidate whose history says APPROVED
    op.execute(f"""
        CREATE FUNCTION {s}.survey_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE last_event text;
        BEGIN
          SELECT e.event INTO last_event FROM {s}.survey_lifecycle_event e
            WHERE e.subject_id = NEW.candidate_id ORDER BY e.seq DESC LIMIT 1;
          IF last_event IS DISTINCT FROM 'APPROVED' THEN
            RAISE EXCEPTION 'a version is made only from an approved candidate' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM {s}.survey_candidate c WHERE c.id = NEW.candidate_id
                         AND c.survey_definition_id = NEW.survey_definition_id) THEN
            RAISE EXCEPTION 'the candidate belongs to another survey' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_version_guard BEFORE INSERT ON {s}.survey_version
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_version_guard();
    """)

    op.create_table(
        "survey_wording_approval",
        pk(),
        sa.Column("item_code", sa.String(80), nullable=False),
        sa.Column("language", sa.String(8), nullable=False),
        sa.Column("wording_version", sa.Integer, nullable=False),
        sa.Column("wording_sha256", sa.String(64), nullable=False),
        fk("candidate_id", "survey_candidate", s),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("occurred_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "candidate_id", "item_code", "language", "wording_version", name="uq_survey_wording_approval"
        ),
        sha256_check("wording_sha256", "survey_wording_approval"),
        schema=s,
    )
    op.execute(forbid_change_trigger(s, "survey_wording_approval"))

    op.create_table(
        "survey_asset_usage",
        sa.Column("subject_type", sa.String(12), nullable=False),
        sa.Column("subject_id", uid(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.PrimaryKeyConstraint("subject_id", "kind", "code", "version", name="pk_survey_asset_usage"),
        enum_check("subject_type", ("CANDIDATE", "VERSION"), "ck_survey_asset_usage_subject"),
        schema=s,
    )
    op.execute(f"CREATE INDEX ix_survey_asset_usage_asset ON {s}.survey_asset_usage (kind, code, version)")

    op.create_table(
        "survey_catalog_entry",
        pk(),
        sa.Column("catalog", sa.String(24), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("attributes", JSONB, nullable=False),
        sa.Column("approval", sa.String(24), nullable=False, server_default="SYNTHETIC_UNAPPROVED"),
        sa.Column("is_synthetic", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.UniqueConstraint("catalog", "code", name="uq_survey_catalog_entry"),
        enum_check("catalog", ("FIELD", "OUTCOME", "RESPONSE_OBLIGATION"), "ck_survey_catalog_entry_catalog"),
        # nothing in these catalogs is approved for operational use; no other state can be stored (D-183)
        sa.CheckConstraint(
            "approval = 'SYNTHETIC_UNAPPROVED' AND is_synthetic", name="ck_survey_catalog_entry_unapproved"
        ),
        sa.CheckConstraint(
            "catalog <> 'OUTCOME' OR coalesce(attributes->>'class', '') IN ("
            + ", ".join(f"'{c}'" for c in OUTCOME_CLASSES)
            + ")",
            name="ck_survey_catalog_entry_outcome_class",
        ),
        # default-deny: a field is speakable only when explicitly set, and this migration sets it for none (D-181)
        sa.CheckConstraint(
            "catalog <> 'FIELD' OR coalesce(jsonb_typeof(attributes->'speakable'), '') = 'boolean'",
            name="ck_survey_catalog_entry_speakable",
        ),
        schema=s,
    )

    def entry(catalog: str, code: str, attributes: dict[str, object]) -> None:
        conn.execute(
            sa.text(
                f"INSERT INTO {s}.survey_catalog_entry (id, catalog, code, attributes, created_by) "
                "VALUES (:i, :cat, :c, CAST(:a AS jsonb), 'SYSTEM:migration-0027')"
            ),
            {"i": uuid.uuid5(NS, f"{catalog}:{code}"), "cat": catalog, "c": code, "a": json.dumps(attributes)},
        )

    for code, attrs in FIELDS.items():
        entry("FIELD", code, {**attrs, "speakable": False})
    for code, (cls, label) in OUTCOMES.items():
        entry("OUTCOME", code, {"class": cls, "label": label})
    for code, label in OBLIGATIONS.items():
        entry("RESPONSE_OBLIGATION", code, {"label": label})


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    if conn.execute(sa.text(f"SELECT count(*) FROM {s}.survey_definition")).scalar_one():
        raise RuntimeError("survey definitions exist; downgrade would lose them and their approval history")
    for table in reversed(TABLES):
        op.drop_table(table, schema=s)
    for fn in (
        "survey_version_guard",
        "survey_lifecycle_event_guard",
        "survey_asset_version_guard",
        "survey_draft_guard",
    ):
        op.execute(f"DROP FUNCTION {s}.{fn}()")
    codes = ", ".join(f"'{c}'" for c in PERMISSIONS)
    op.execute(
        f"DELETE FROM {s}.role_permission WHERE permission_id IN (SELECT id FROM {s}.permission WHERE code IN ({codes}))"
    )
    op.execute(f"DELETE FROM {s}.permission WHERE code IN ({codes})")
