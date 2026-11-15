"""CP0.2 callback cases, holds, contacts, attempts, sessions and evidence (11 tables; S0_DATA_MODEL §4.5).

S0 evidence is seeded (record_origin = SYNTHETIC_SEED, ADR-0008 §4). The triggers enforce the grain and
history rules every later producer must obey: session pins (ADR-0005 §4, D-32), holds (ADR-0008 §2),
contact eligibility (D-36) and write-once evidence (ADR-0005 §3).

Revision ID: 0006_case_evidence
Revises: 0005_scripts_regulatory
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from app.db.ddl import (
    TS,
    code_ref,
    code_ref_trigger,
    enum_check,
    fk,
    forbid_change_trigger,
    market_trigger,
    operational,
    pk,
    provenance,
    record_origin,
    sha256_check,
    uid,
)

revision = "0006_case_evidence"
down_revision = "0005_scripts_regulatory"
branch_labels = None
depends_on = None

CASE_STATES = (
    "CREATED",
    "VALIDATED",
    "READY",
    "IN_PROGRESS",
    "AWAITING_CALLBACK",
    "AWAITING_REVIEW",
    "ESCALATED",
    "VERIFIED",
    "CLOSED_UNVERIFIED",
    "CANCELLED",
)
ATTEMPT_STATUS = (
    "SCHEDULED",
    "INITIATED",
    "CONNECTING",
    "NO_ANSWER",
    "BUSY",
    "WRONG_PARTY",
    "FAILED",
    "CONNECTED",
    "IN_SESSION",
    "ENDED",
)
SESSION_STATES = (
    "CREATED",
    "CONSENT_PENDING",
    "IDENTITY_PENDING",
    "SURVEY_ACTIVE",
    "PAUSED",
    "INTERRUPTED",
    "ESCALATING",
    "COMPLETED",
    "ABORTED",
    "FINALIZING",
    "FINALIZED",
)
MEDIA_STATUS = (
    "NOT_REQUIRED",
    "CAPTURE_PENDING",
    "CAPTURING",
    "UPLOADING",
    "AVAILABLE",
    "FAILED",
    "REDACTED",
    "PURGED",
    "HELD",
)
TRANSCRIPT_STATUS = ("PENDING", "PARTIAL", "FINALIZED", "QUALITY_FLAGGED", "CORRECTED_BY_ADDENDUM", "UNAVAILABLE")
TRANSPORTS = ("SYNTHETIC", "BROWSER", "GENESYS")
RUN_STATUS = ("NOT_STARTED", "IN_PROGRESS", "PAUSED", "COMPLETED", "INCOMPLETE", "ABORTED")
ANSWER_STATES = ("YES", "NO", "UNKNOWN", "UNCLEAR", "REFUSED", "NOT_ASKED", "NOT_APPLICABLE")
TABLES = (
    "callback_case",
    "case_hold",
    "case_contact_selection",
    "contact_attempt",
    "conversation_session",
    "survey_run",
    "question_execution",
    "answer_observation",
    "rule_evaluation",
    "finding",
    "case_event",
)
FUNCTIONS = (
    "callback_case_guard",
    "case_hold_guard",
    "case_hold_sync",
    "contact_selection_check",
    "contact_attempt_guard",
    "conversation_session_guard",
    "survey_run_guard",
    "question_execution_guard",
    "answer_observation_check",
    "finding_guard",
    "script_assignment_case_check",
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s

    op.create_table(
        "callback_case",
        pk(),
        sa.Column("case_ref", sa.String(40), nullable=False, unique=True),
        fk("sale_event_id", "sale_event", s),
        sa.Column("obligation_type", sa.String(24), nullable=False),
        sa.Column("source_request_ref", sa.String(80), nullable=False),
        sa.Column("market_code", sa.String(40), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        *code_ref("callback_case", "closure_reason", "closure_reason_list_version_id", s),
        sa.Column("priority", sa.SmallInteger, nullable=False),
        fk("owner_principal_id", "principal", s, nullable=True),
        sa.Column("due_at", TS, nullable=False),
        sa.Column("verified_at", TS),
        sa.Column("closed_at", TS),
        *code_ref("callback_case", "cancellation_reason", "cancellation_reason_list_version_id", s),
        sa.Column("cancelled_recorded_at", TS),
        sa.Column("cancellation_authorized_by", sa.String(80)),
        sa.Column("cancellation_authorization_ref", sa.String(80)),
        sa.Column("has_blocking_hold", sa.Boolean, nullable=False, server_default=sa.false()),
        *operational(mutable=True),
        *provenance("callback_case"),
        enum_check("obligation_type", ("SALE_VERIFICATION",), "ck_callback_case_obligation"),
        enum_check("state", CASE_STATES, "ck_callback_case_state"),
        sa.UniqueConstraint(
            "sale_event_id", "obligation_type", "source_request_ref", name="uq_callback_case_obligation"
        ),
        sa.CheckConstraint("priority BETWEEN 1 AND 5", name="ck_callback_case_priority"),
        # ADR-0008 §2 / INV-06: a blocking hold prevents READY and IN_PROGRESS.
        sa.CheckConstraint(
            "NOT (has_blocking_hold AND state IN ('READY', 'IN_PROGRESS'))", name="ck_callback_case_blocking_hold"
        ),
        # Cancellation fields exist only on CANCELLED cases (S0_KPI_DEFINITIONS SLA-EX-001).
        sa.CheckConstraint(
            "state = 'CANCELLED' OR (cancellation_reason IS NULL AND cancelled_recorded_at IS NULL "
            "AND cancellation_authorized_by IS NULL AND cancellation_authorization_ref IS NULL)",
            name="ck_callback_case_cancellation_only_when_cancelled",
        ),
        sa.CheckConstraint(
            "state <> 'CANCELLED' OR (cancellation_reason IS NOT NULL AND cancelled_recorded_at IS NOT NULL)",
            name="ck_callback_case_cancellation_recorded",
        ),
        sa.CheckConstraint(
            "(cancellation_authorized_by IS NULL) = (cancellation_authorization_ref IS NULL)",
            name="ck_callback_case_cancellation_authorization",
        ),
        sa.CheckConstraint(
            "(state = 'CLOSED_UNVERIFIED') = (closure_reason IS NOT NULL)", name="ck_callback_case_closure_reason"
        ),
        sa.CheckConstraint("state <> 'CLOSED_UNVERIFIED' OR closed_at IS NOT NULL", name="ck_callback_case_closed_at"),
        sa.CheckConstraint("(state = 'VERIFIED') = (verified_at IS NOT NULL)", name="ck_callback_case_verified_at"),
        schema=s,
    )
    op.create_index("ix_callback_case_due", "callback_case", ["due_at"], schema=s)
    op.create_table(
        "case_hold",
        pk(),
        fk("callback_case_id", "callback_case", s),
        *code_ref("case_hold", "hold_reason", "hold_reason_list_version_id", s),
        sa.Column("is_blocking", sa.Boolean, nullable=False),
        sa.Column("placed_at", TS, nullable=False),
        sa.Column("placed_by", sa.String(80), nullable=False),
        sa.Column("placed_reason", sa.Text, nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("released_at", TS),
        sa.Column("released_by", sa.String(80)),
        sa.Column("release_reason", sa.Text),
        *operational(mutable=True),
        sa.CheckConstraint("hold_reason IS NOT NULL", name="ck_case_hold_reason_required"),
        enum_check("source", ("SEED", "INTAKE", "SYSTEM", "MANUAL"), "ck_case_hold_source"),
        sa.CheckConstraint(
            "num_nonnulls(released_at, released_by, release_reason) IN (0, 3)", name="ck_case_hold_release"
        ),
        sa.CheckConstraint("released_at IS NULL OR released_at >= placed_at", name="ck_case_hold_interval"),
        schema=s,
    )
    op.create_index(
        "ux_case_hold_active",
        "case_hold",
        ["callback_case_id", "hold_reason"],
        unique=True,
        schema=s,
        postgresql_where=sa.text("released_at IS NULL"),
    )
    op.create_table(
        "case_contact_selection",
        pk(),
        fk("callback_case_id", "callback_case", s),
        fk("party_id", "party", s),
        fk("policy_party_role_id", "policy_party_role", s),
        fk("contact_method_id", "contact_method", s, nullable=True),
        sa.Column("eligible", sa.Boolean, nullable=False),
        sa.Column("ineligibility_reason", sa.String(32)),
        *code_ref("case_contact_selection", "rule_basis", "rule_basis_list_version_id", s),
        sa.Column("decided_at", TS, nullable=False),
        sa.Column("decided_by", sa.String(80), nullable=False),
        fk("supersedes_id", "case_contact_selection", s, nullable=True),
        *operational(mutable=False),
        *provenance("case_contact_selection"),
        sa.CheckConstraint("rule_basis IS NOT NULL", name="ck_case_contact_selection_basis_required"),
        enum_check(
            "ineligibility_reason",
            (
                "ROLE_NOT_CALLABLE",
                "AUTHORIZATION_NOT_EVIDENCED",
                "CONTACT_SUPPRESSED",
                "CONSENT_NOT_GRANTED",
                "NO_CONTACT_METHOD",
            ),
            "ck_case_contact_selection_reason",
            nullable=True,
        ),
        sa.CheckConstraint("eligible = (ineligibility_reason IS NULL)", name="ck_case_contact_selection_reason_pair"),
        schema=s,
    )
    op.create_table(
        "contact_attempt",
        pk(),
        sa.Column("attempt_ref", sa.String(40), nullable=False, unique=True),
        fk("callback_case_id", "callback_case", s),
        sa.Column("sequence", sa.SmallInteger, nullable=False),
        sa.Column("transport", sa.String(16), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        fk("contacted_party_id", "party", s, nullable=True),
        fk("contact_method_id", "contact_method", s, nullable=True),
        sa.Column("contact_snapshot", JSONB, nullable=False),
        sa.Column("scheduled_at", TS, nullable=False),
        sa.Column("started_at", TS),
        sa.Column("ended_at", TS),
        sa.Column("failure_reason", sa.String(80)),
        *operational(mutable=True),
        *provenance("contact_attempt"),
        *record_origin("contact_attempt"),
        sa.UniqueConstraint("callback_case_id", "sequence", name="uq_contact_attempt_sequence"),
        sa.CheckConstraint("sequence >= 1", name="ck_contact_attempt_sequence"),
        enum_check("transport", TRANSPORTS, "ck_contact_attempt_transport"),
        enum_check("direction", ("OUTBOUND", "INBOUND"), "ck_contact_attempt_direction"),
        enum_check("status", ATTEMPT_STATUS, "ck_contact_attempt_status"),
        # Seeded transport is never presented as browser or Genesys, and only seeds use it (ADR-0008 §4).
        sa.CheckConstraint(
            "transport <> 'SYNTHETIC' OR record_origin = 'SYNTHETIC_SEED'", name="ck_contact_attempt_synthetic"
        ),
        schema=s,
    )
    op.create_table(
        "conversation_session",
        pk(),
        sa.Column("session_ref", sa.String(40), nullable=False, unique=True),
        fk("contact_attempt_id", "contact_attempt", s),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("transport", sa.String(16), nullable=False),
        sa.Column("external_session_ref", sa.String(80)),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("ended_at", TS),
        fk("script_version_id", "script_version", s),
        sa.Column("script_manifest_sha256", sa.String(64), nullable=False),
        fk("risk_assessment_id", "risk_assessment", s),
        sa.Column("risk_snapshot_sha256", sa.String(64), nullable=False),
        fk("policy_fact_snapshot_id", "policy_fact_snapshot", s),
        sa.Column("policy_fact_snapshot_sha256", sa.String(64), nullable=False),
        fk("contacted_party_id", "party", s),
        sa.Column("contact_method_snapshot", JSONB, nullable=False),
        sa.Column("media_status", sa.String(16), nullable=False),
        sa.Column("transcript_status", sa.String(24), nullable=False),
        *operational(mutable=True),
        *provenance("conversation_session"),
        *record_origin("conversation_session"),
        enum_check("state", SESSION_STATES, "ck_conversation_session_state"),
        enum_check("transport", TRANSPORTS, "ck_conversation_session_transport"),
        enum_check("media_status", MEDIA_STATUS, "ck_conversation_session_media"),
        enum_check("transcript_status", TRANSCRIPT_STATUS, "ck_conversation_session_transcript"),
        sa.CheckConstraint(
            "transport <> 'SYNTHETIC' OR record_origin = 'SYNTHETIC_SEED'", name="ck_conversation_session_synthetic"
        ),
        sa.CheckConstraint("ended_at IS NULL OR ended_at >= started_at", name="ck_conversation_session_interval"),
        sha256_check("script_manifest_sha256", "conversation_session"),
        sha256_check("risk_snapshot_sha256", "conversation_session"),
        sha256_check("policy_fact_snapshot_sha256", "conversation_session"),
        schema=s,
    )
    op.create_table(
        "survey_run",
        pk(),
        fk("session_id", "conversation_session", s),
        fk("script_version_id", "script_version", s),
        sa.Column("script_manifest_sha256", sa.String(64), nullable=False),
        fk("policy_fact_snapshot_id", "policy_fact_snapshot", s),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("completed_at", TS),
        *operational(mutable=True),
        *provenance("survey_run"),
        *record_origin("survey_run"),
        enum_check("status", RUN_STATUS, "ck_survey_run_status"),
        sha256_check("script_manifest_sha256", "survey_run"),
        schema=s,
    )
    op.create_index(  # grain constraint 3: at most one active run per session
        "ux_survey_run_active",
        "survey_run",
        ["session_id"],
        unique=True,
        schema=s,
        postgresql_where=sa.text("status IN ('NOT_STARTED', 'IN_PROGRESS', 'PAUSED')"),
    )
    op.create_table(
        "question_execution",
        pk(),
        fk("survey_run_id", "survey_run", s),
        fk("question_revision_id", "question_revision", s),
        sa.Column("position", sa.SmallInteger, nullable=False),
        sa.Column("delivery_status", sa.String(16), nullable=False),
        sa.Column("retries", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("skip_reason", sa.String(80)),
        sa.Column("event_range", JSONB),
        *operational(mutable=True),
        *provenance("question_execution"),
        *record_origin("question_execution"),
        sa.UniqueConstraint("survey_run_id", "position", name="uq_question_execution_position"),
        enum_check(
            "delivery_status", ("DELIVERED", "REPROMPTED", "SKIPPED", "NOT_DELIVERED"), "ck_question_execution_delivery"
        ),
        schema=s,
    )
    op.create_table(
        "answer_observation",
        pk(),
        fk("question_execution_id", "question_execution", s),
        sa.Column("answer_state", sa.String(16), nullable=False),
        sa.Column("typed_value", JSONB),
        sa.Column("verbatim_text_redacted", sa.Text),
        sa.Column("transcript_segment_ids", ARRAY(uid()), nullable=False, server_default="{}"),
        sa.Column("extraction_engine", sa.String(40), nullable=False),
        sa.Column("extraction_version", sa.String(40), nullable=False),
        fk("supersedes_id", "answer_observation", s, nullable=True),
        *operational(mutable=False),
        *provenance("answer_observation"),
        *record_origin("answer_observation"),
        enum_check("answer_state", ANSWER_STATES, "ck_answer_observation_state"),
        # Stage lock: transcripts do not exist before S1 (D-19); S1's migration lifts this check.
        sa.CheckConstraint("cardinality(transcript_segment_ids) = 0", name="ck_answer_observation_no_transcript_s0"),
        schema=s,
    )
    op.create_table(
        "rule_evaluation",
        pk(),
        fk("question_execution_id", "question_execution", s),
        sa.Column("rule_ref", sa.String(60), nullable=False),
        sa.Column("rule_version", sa.String(40), nullable=False),
        sa.Column("expected", JSONB, nullable=False),
        sa.Column("observed", JSONB, nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("evaluated_at", TS, nullable=False),
        *operational(mutable=False),
        *provenance("rule_evaluation"),
        *record_origin("rule_evaluation"),
        enum_check("result", ("MATCH", "MISMATCH", "INDETERMINATE", "NOT_EVALUATED"), "ck_rule_evaluation_result"),
        schema=s,
    )
    op.create_table(
        "finding",
        pk(),
        sa.Column("finding_ref", sa.String(40), nullable=False, unique=True),
        fk("callback_case_id", "callback_case", s),
        fk("question_execution_id", "question_execution", s, nullable=True),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("evidence_refs", JSONB, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("raised_at", TS, nullable=False),
        sa.Column("review_assigned_at", TS),
        sa.Column("review_closed_at", TS),
        fk("assigned_reviewer_id", "principal", s, nullable=True),
        *operational(mutable=True),
        *provenance("finding"),
        *record_origin("finding"),
        enum_check(
            "category",
            (
                "FACT_MISMATCH",
                "MISSING_MANDATORY_ANSWER",
                "UNCLEAR_UNDERSTANDING",
                "CONTRADICTORY_ANSWER",
                "DISCLOSURE_CONCERN",
            ),
            "ck_finding_category",
        ),
        # Compliance finding severity: its own enum, never a risk band (RISK-001, INV-08).
        enum_check("severity", ("LOW", "MEDIUM", "HIGH", "CRITICAL"), "ck_finding_severity"),
        enum_check("status", ("OPEN", "UNDER_REVIEW", "CONFIRMED", "DISMISSED", "CLOSED"), "ck_finding_status"),
        enum_check("origin", ("RULE_EVALUATION", "NARRATIVE_FLAG", "REVIEWER"), "ck_finding_origin"),
        schema=s,
    )
    op.create_table(
        "case_event",
        pk(),
        fk("callback_case_id", "callback_case", s),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("actor_ref", sa.String(80), nullable=False),
        sa.Column("related_entity_type", sa.String(40)),
        sa.Column("related_entity_id", uid()),
        sa.Column("summary", sa.Text, nullable=False),
        *operational(mutable=False),
        schema=s,
    )
    op.create_index("ix_case_event_case", "case_event", ["callback_case_id", "occurred_at"], schema=s)
    op.create_foreign_key(
        "fk_script_assignment_case",
        "script_assignment",
        "callback_case",
        ["callback_case_id"],
        ["id"],
        source_schema=s,
        referent_schema=s,
    )

    op.execute(f"""
        -- Case identity is fixed; has_blocking_hold is always derived from active holds (ADR-0008 §2);
        -- cancellation, verification and closure facts are recorded once; terminal states are final.
        CREATE FUNCTION {s}.callback_case_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'callback_case rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            NEW.has_blocking_hold := false;
            IF NOT EXISTS (SELECT 1 FROM {s}.sale_event se JOIN {s}.policy p ON p.id = se.policy_id
                            WHERE se.id = NEW.sale_event_id AND p.market_code = NEW.market_code) THEN
              RAISE EXCEPTION 'case market must equal its policy market' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          NEW.has_blocking_hold := EXISTS (SELECT 1 FROM {s}.case_hold h
                                            WHERE h.callback_case_id = NEW.id AND h.is_blocking AND h.released_at IS NULL);
          IF (NEW.case_ref, NEW.sale_event_id, NEW.obligation_type, NEW.source_request_ref, NEW.market_code)
             IS DISTINCT FROM (OLD.case_ref, OLD.sale_event_id, OLD.obligation_type, OLD.source_request_ref, OLD.market_code)
             OR (OLD.cancelled_recorded_at IS NOT NULL AND NEW.cancelled_recorded_at IS DISTINCT FROM OLD.cancelled_recorded_at)
             OR (OLD.cancellation_reason IS NOT NULL AND (NEW.cancellation_reason, NEW.cancellation_reason_list_version_id,
                 NEW.cancellation_authorized_by, NEW.cancellation_authorization_ref) IS DISTINCT FROM
                 (OLD.cancellation_reason, OLD.cancellation_reason_list_version_id,
                  OLD.cancellation_authorized_by, OLD.cancellation_authorization_ref))
             OR (OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at)
             OR (OLD.closed_at IS NOT NULL AND NEW.closed_at IS DISTINCT FROM OLD.closed_at) THEN
            RAISE EXCEPTION 'recorded callback_case facts are immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF OLD.state IN ('VERIFIED', 'CLOSED_UNVERIFIED', 'CANCELLED') AND NEW.state <> OLD.state THEN
            RAISE EXCEPTION 'a % case is terminal', OLD.state USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER callback_case_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.callback_case
          FOR EACH ROW EXECUTE FUNCTION {s}.callback_case_guard();

        -- A hold placement is recorded once and released once; is_blocking comes from the pinned list value.
        CREATE FUNCTION {s}.case_hold_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE release text[] := ARRAY['released_at', 'released_by', 'release_reason',
                                        'updated_at', 'updated_by', 'row_version'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'case_hold rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.released_at IS NOT NULL THEN
              RAISE EXCEPTION 'a hold is placed unreleased' USING ERRCODE = 'check_violation';
            END IF;
            SELECT (cv.attributes ->> 'blocking')::boolean INTO NEW.is_blocking FROM {s}.code_value cv
             WHERE cv.code_list_version_id = NEW.hold_reason_list_version_id AND cv.code = NEW.hold_reason;
            IF NEW.is_blocking IS NULL THEN
              RAISE EXCEPTION 'hold reason % has no blocking attribute', NEW.hold_reason USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (to_jsonb(NEW) - release) IS DISTINCT FROM (to_jsonb(OLD) - release) OR OLD.released_at IS NOT NULL THEN
            RAISE EXCEPTION 'a hold may only be released, once' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER case_hold_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.case_hold
          FOR EACH ROW EXECUTE FUNCTION {s}.case_hold_guard();

        -- Recompute the case flag in the same statement; the case CHECK then rejects a blocking hold on a
        -- READY or IN_PROGRESS case (INV-06).
        CREATE FUNCTION {s}.case_hold_sync() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          UPDATE {s}.callback_case SET has_blocking_hold = has_blocking_hold WHERE id = NEW.callback_case_id;
          RETURN NULL;
        END $$;
        CREATE TRIGGER case_hold_sync AFTER INSERT OR UPDATE ON {s}.case_hold
          FOR EACH ROW EXECUTE FUNCTION {s}.case_hold_sync();

        -- D-36 / INV-14: eligibility is recorded only when its conditions hold at decided_at. A callable role
        -- is a candidate only; AUTHORIZED_CONTACT additionally needs valid authorisation evidence.
        CREATE FUNCTION {s}.contact_selection_check() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          r {s}.policy_party_role%ROWTYPE;
          m {s}.contact_method%ROWTYPE;
          attrs jsonb;
        BEGIN
          SELECT * INTO r FROM {s}.policy_party_role WHERE id = NEW.policy_party_role_id;
          IF r.party_id <> NEW.party_id OR r.role <> NEW.rule_basis OR NOT EXISTS (
              SELECT 1 FROM {s}.callback_case c JOIN {s}.sale_event se ON se.id = c.sale_event_id
               WHERE c.id = NEW.callback_case_id AND se.policy_id = r.policy_id) THEN
            RAISE EXCEPTION 'selection must name a role of this party on the case policy' USING ERRCODE = 'check_violation';
          END IF;
          IF NEW.contact_method_id IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM {s}.contact_method WHERE id = NEW.contact_method_id AND party_id = NEW.party_id) THEN
            RAISE EXCEPTION 'contact method belongs to another party' USING ERRCODE = 'check_violation';
          END IF;
          IF NOT NEW.eligible THEN RETURN NEW; END IF;
          SELECT cv.attributes INTO attrs FROM {s}.code_value cv
           WHERE cv.code_list_version_id = NEW.rule_basis_list_version_id AND cv.code = NEW.rule_basis;
          IF coalesce((attrs ->> 'callable')::boolean, false) IS NOT TRUE THEN
            RAISE EXCEPTION 'role % is not callable', NEW.rule_basis USING ERRCODE = 'check_violation';
          END IF;
          IF r.valid_from > NEW.decided_at OR (r.valid_to IS NOT NULL AND r.valid_to <= NEW.decided_at) THEN
            RAISE EXCEPTION 'role is not valid at decided_at' USING ERRCODE = 'check_violation';
          END IF;
          IF coalesce((attrs ->> 'requires_authorization_evidence')::boolean, true) AND (
              r.authorization_ref IS NULL OR r.authorization_valid_from > NEW.decided_at
              OR (r.authorization_valid_to IS NOT NULL AND r.authorization_valid_to <= NEW.decided_at)) THEN
            RAISE EXCEPTION 'eligibility requires valid authorisation evidence' USING ERRCODE = 'check_violation';
          END IF;
          SELECT * INTO m FROM {s}.contact_method WHERE id = NEW.contact_method_id;
          IF m.id IS NULL OR m.suppressed OR m.consent_status <> 'GRANTED' OR m.valid_from > NEW.decided_at
             OR (m.valid_to IS NOT NULL AND m.valid_to <= NEW.decided_at) THEN
            RAISE EXCEPTION 'eligibility requires a valid, unsuppressed, consented contact method'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER contact_selection_check BEFORE INSERT ON {s}.case_contact_selection
          FOR EACH ROW EXECUTE FUNCTION {s}.contact_selection_check();

        -- Attempt identity and contact snapshot are frozen (INV-05); an attempt with a session stays connected
        -- (INV-03); the contacted party is a party of the case policy.
        CREATE FUNCTION {s}.contact_attempt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'contact_attempt rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.contacted_party_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM {s}.callback_case c JOIN {s}.sale_event se ON se.id = c.sale_event_id
                  JOIN {s}.policy_party_role r ON r.policy_id = se.policy_id
                 WHERE c.id = NEW.callback_case_id AND r.party_id = NEW.contacted_party_id) THEN
              RAISE EXCEPTION 'contacted party is not a party of the case policy' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (NEW.attempt_ref, NEW.callback_case_id, NEW.sequence, NEW.transport, NEW.direction, NEW.contacted_party_id,
              NEW.contact_method_id, NEW.contact_snapshot, NEW.record_origin, NEW.scheduled_at)
             IS DISTINCT FROM
             (OLD.attempt_ref, OLD.callback_case_id, OLD.sequence, OLD.transport, OLD.direction, OLD.contacted_party_id,
              OLD.contact_method_id, OLD.contact_snapshot, OLD.record_origin, OLD.scheduled_at) THEN
            RAISE EXCEPTION 'contact_attempt identity and contact snapshot are immutable'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NEW.status NOT IN ('CONNECTED', 'IN_SESSION', 'ENDED')
             AND EXISTS (SELECT 1 FROM {s}.conversation_session WHERE contact_attempt_id = NEW.id) THEN
            RAISE EXCEPTION 'an attempt with a session must remain connected' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER contact_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.contact_attempt
          FOR EACH ROW EXECUTE FUNCTION {s}.contact_attempt_guard();

        -- Session pins (ADR-0005 §4, D-6, D-32): validated at insert, immutable afterwards.
        CREATE FUNCTION {s}.conversation_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          a {s}.contact_attempt%ROWTYPE;
          v_sale uuid;
          pins text[] := ARRAY['session_ref', 'contact_attempt_id', 'transport', 'started_at', 'script_version_id',
                               'script_manifest_sha256', 'risk_assessment_id', 'risk_snapshot_sha256',
                               'policy_fact_snapshot_id', 'policy_fact_snapshot_sha256', 'contacted_party_id',
                               'contact_method_snapshot', 'record_origin'];
          p text;
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'conversation_session rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'UPDATE' THEN
            FOREACH p IN ARRAY pins LOOP
              IF (to_jsonb(NEW) -> p) IS DISTINCT FROM (to_jsonb(OLD) -> p) THEN
                RAISE EXCEPTION 'session pin % is immutable', p USING ERRCODE = 'insufficient_privilege';
              END IF;
            END LOOP;
            RETURN NEW;
          END IF;
          SELECT * INTO a FROM {s}.contact_attempt WHERE id = NEW.contact_attempt_id;
          IF a.status NOT IN ('CONNECTED', 'IN_SESSION', 'ENDED') THEN
            RAISE EXCEPTION 'only a connected attempt has a session (INV-03)' USING ERRCODE = 'check_violation';
          END IF;
          IF a.contacted_party_id IS DISTINCT FROM NEW.contacted_party_id THEN
            RAISE EXCEPTION 'session party must be the attempt contacted party' USING ERRCODE = 'check_violation';
          END IF;
          SELECT c.sale_event_id INTO v_sale FROM {s}.callback_case c WHERE c.id = a.callback_case_id;
          IF NOT {s}.script_version_valid_at(NEW.script_version_id, NEW.started_at) THEN
            RAISE EXCEPTION 'pinned script version was not published and effective at session start (INV-09)'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM {s}.script_version WHERE id = NEW.script_version_id
                            AND manifest_sha256 = NEW.script_manifest_sha256) THEN
            RAISE EXCEPTION 'pinned manifest checksum mismatch' USING ERRCODE = 'check_violation';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM {s}.risk_assessment WHERE id = NEW.risk_assessment_id AND sale_event_id = v_sale
                            AND status <> 'PROVISIONAL' AND input_snapshot_sha256 = NEW.risk_snapshot_sha256) THEN
            RAISE EXCEPTION 'pinned risk assessment must be a decided assessment of the case sale with its hash'
              USING ERRCODE = 'check_violation';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM {s}.policy_fact_snapshot WHERE id = NEW.policy_fact_snapshot_id
                            AND sale_event_id = v_sale AND sha256 = NEW.policy_fact_snapshot_sha256) THEN
            RAISE EXCEPTION 'pinned fact snapshot must belong to the case sale with its hash'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER conversation_session_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.conversation_session
          FOR EACH ROW EXECUTE FUNCTION {s}.conversation_session_guard();

        -- In S0 the run pin equals the session pin (ADR-0005 §4); run pins are immutable; finished runs are final.
        CREATE FUNCTION {s}.survey_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'survey_run rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NOT EXISTS (SELECT 1 FROM {s}.conversation_session cs WHERE cs.id = NEW.session_id
                              AND cs.script_version_id = NEW.script_version_id
                              AND cs.script_manifest_sha256 = NEW.script_manifest_sha256
                              AND cs.policy_fact_snapshot_id = NEW.policy_fact_snapshot_id) THEN
              RAISE EXCEPTION 'survey run pins must equal its session pins' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
          END IF;
          IF (NEW.session_id, NEW.script_version_id, NEW.script_manifest_sha256, NEW.policy_fact_snapshot_id,
              NEW.started_at, NEW.record_origin)
             IS DISTINCT FROM (OLD.session_id, OLD.script_version_id, OLD.script_manifest_sha256,
              OLD.policy_fact_snapshot_id, OLD.started_at, OLD.record_origin)
             OR (OLD.status IN ('COMPLETED', 'INCOMPLETE', 'ABORTED') AND (NEW.status, NEW.completed_at)
                 IS DISTINCT FROM (OLD.status, OLD.completed_at)) THEN
            RAISE EXCEPTION 'survey run pins and final outcomes are immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_run_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.survey_run
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_run_guard();

        -- Executions change only while their run is active, and only for questions in the frozen manifest.
        CREATE FUNCTION {s}.question_execution_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          v_run uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.survey_run_id ELSE NEW.survey_run_id END;
          v_status text;
          v_manifest jsonb;
        BEGIN
          SELECT r.status, v.manifest INTO v_status, v_manifest FROM {s}.survey_run r
            JOIN {s}.script_version v ON v.id = r.script_version_id WHERE r.id = v_run;
          IF v_status NOT IN ('NOT_STARTED', 'IN_PROGRESS', 'PAUSED') THEN
            RAISE EXCEPTION 'question executions of a % run are immutable', v_status
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
          IF TG_OP = 'UPDATE' AND (NEW.survey_run_id, NEW.question_revision_id, NEW.record_origin)
             IS DISTINCT FROM (OLD.survey_run_id, OLD.question_revision_id, OLD.record_origin) THEN
            RAISE EXCEPTION 'question execution identity is immutable' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF NOT coalesce(v_manifest -> 'question_revision_ids' ? NEW.question_revision_id::text, false) THEN
            RAISE EXCEPTION 'question revision is not in the pinned script manifest' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER question_execution_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.question_execution
          FOR EACH ROW EXECUTE FUNCTION {s}.question_execution_guard();

        -- A superseding observation refers to the same execution (attributable addenda, ADR-0005).
        CREATE FUNCTION {s}.answer_observation_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.supersedes_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM {s}.answer_observation
               WHERE id = NEW.supersedes_id AND question_execution_id = NEW.question_execution_id) THEN
            RAISE EXCEPTION 'a superseding observation must refer to the same execution' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER answer_observation_check BEFORE INSERT ON {s}.answer_observation
          FOR EACH ROW EXECUTE FUNCTION {s}.answer_observation_check();

        -- A finding's evidence comes from this case; only status and review fields change; never deleted.
        CREATE FUNCTION {s}.finding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE mutable text[] := ARRAY['status', 'review_assigned_at', 'review_closed_at', 'assigned_reviewer_id',
                                        'updated_at', 'updated_by', 'row_version'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'finding rows are never deleted' USING ERRCODE = 'insufficient_privilege';
          END IF;
          IF TG_OP = 'UPDATE' THEN
            IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
              RAISE EXCEPTION 'finding evidence is immutable' USING ERRCODE = 'insufficient_privilege';
            END IF;
            RETURN NEW;
          END IF;
          IF NEW.question_execution_id IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM {s}.question_execution qe JOIN {s}.survey_run r ON r.id = qe.survey_run_id
                JOIN {s}.conversation_session cs ON cs.id = r.session_id
                JOIN {s}.contact_attempt a ON a.id = cs.contact_attempt_id
               WHERE qe.id = NEW.question_execution_id AND a.callback_case_id = NEW.callback_case_id) THEN
            RAISE EXCEPTION 'finding evidence must come from the same case' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER finding_guard BEFORE INSERT OR UPDATE OR DELETE ON {s}.finding
          FOR EACH ROW EXECUTE FUNCTION {s}.finding_guard();

        -- An assignment's risk and fact snapshot belong to the case sale.
        CREATE FUNCTION {s}.script_assignment_case_check() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE v_sale uuid;
        BEGIN
          SELECT sale_event_id INTO v_sale FROM {s}.callback_case WHERE id = NEW.callback_case_id;
          IF NOT EXISTS (SELECT 1 FROM {s}.policy_fact_snapshot WHERE id = NEW.policy_fact_snapshot_id
                            AND sale_event_id = v_sale)
             OR (NEW.risk_assessment_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM {s}.risk_assessment
                  WHERE id = NEW.risk_assessment_id AND sale_event_id = v_sale AND status <> 'PROVISIONAL')) THEN
            RAISE EXCEPTION 'assignment inputs must belong to the case sale' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER script_assignment_case_check BEFORE INSERT ON {s}.script_assignment
          FOR EACH ROW EXECUTE FUNCTION {s}.script_assignment_case_check();

        {forbid_change_trigger(s, "case_contact_selection")}
        {forbid_change_trigger(s, "answer_observation")}
        {forbid_change_trigger(s, "rule_evaluation")}
        {forbid_change_trigger(s, "case_event")}
        {market_trigger(s, "callback_case")}
        {code_ref_trigger(s, "callback_case", "closure_reason", "closure_reason_list_version_id", "case_closure_reason")}
        {code_ref_trigger(s, "callback_case", "cancellation_reason", "cancellation_reason_list_version_id", "case_cancellation_reason")}
        {code_ref_trigger(s, "case_hold", "hold_reason", "hold_reason_list_version_id", "case_hold_reason")}
        {code_ref_trigger(s, "case_contact_selection", "rule_basis", "rule_basis_list_version_id", "callable_party_roles")}
    """)


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    op.drop_constraint("fk_script_assignment_case", "script_assignment", schema=s, type_="foreignkey")
    op.execute(f"DROP TRIGGER IF EXISTS script_assignment_case_check ON {s}.script_assignment")
    for table in reversed(TABLES):
        op.drop_table(table, schema=s)
    for fn in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {s}.{fn}()")
