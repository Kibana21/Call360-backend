"""CP0.2 table catalogue (S0_DATA_MODEL §4.2–§4.6, D-29). The migrations are the DDL source of truth;
this module only names the tables and their column-flag classes for the seed, digest, readiness and tests."""

from __future__ import annotations

# Migration assignment (S0_DATA_MODEL §4.6). Order is creation order and digest order.
MIGRATION_TABLES: dict[str, tuple[str, ...]] = {
    "0003_party_policy_sale": (
        "party",
        "contact_method",
        "policy",
        "policy_party_role",
        "fsc_representative",
        "sale_event",
        "policy_fact_snapshot",
        "external_reference",
    ),
    "0004_sbq_risk": ("risk_rule_set_version", "risk_assessment", "risk_factor_result"),
    "0005_scripts_regulatory": (
        "script_family",
        "script_module",
        "script_version",
        "script_section",
        "question_bank_item",
        "question_revision",
        "module_question",
        "script_assignment_rule_version",
        "script_assignment",
        "regulatory_reference",
        "control",
        "control_mapping",
    ),
    "0006_case_evidence": (
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
    ),
    "0007_governed_values": (),
}
CP02_TABLES: tuple[str, ...] = tuple(t for tables in MIGRATION_TABLES.values() for t in tables)
# Tables created by later revisions that are not CP0.2 business tables (S0_DATA_MODEL §4.6, D-39).
LATER_MIGRATION_TABLES: dict[str, tuple[str, ...]] = {
    "0008_market_scope": ("group_scope_mapping",),
    "0009_intake": ("intake_run", "intake_item", "field_change"),  # CP0.4a intake ledger (Build = CP0.4)
    "0012_session_event": ("session_event",),  # S1-B voice-session event ledger (EVD-002)
    "0013_recording": ("media_asset", "media_chunk"),  # S1-C recording manifest (EVD-001, EVD-003)
    "0014_transcript": ("transcript_run", "transcript_segment"),  # S1-D machine transcripts (VOICE-009, EVD-004)
    "0015_script_authoring": ("script_change_event",),  # S2-A script change history (SUR-006, SCR-014, SCR-015)
    # S2-A.1 draft isolation: per-revision intent/category and draft-scoped control links
    "0016_script_draft_isolation": ("question_revision_detail", "script_version_control_link"),
    # S2-B editable assignment rules (SCR-011): drafts, change history, publication records
    "0017_assignment_rule_authoring": (
        "assignment_rule_draft",
        "assignment_rule_change_event",
        "assignment_rule_publication",
    ),
    "0018_script_assignment_engine": ("script_assignment_attempt",),  # S2-C assignment evidence (SCR-004/011)
    "0019_script_simulation": ("script_simulation_run", "script_simulation_event"),  # S2-D text simulation (SUR-008)
    "0020_conversation_lifecycle": (),  # S2-D.1: widened kinds, lifecycle columns on question_revision_detail
    "0021_simulation_workbench": (  # S2-E workbench: scenarios, snapshots, automated results (SUR-010)
        "simulation_scenario",
        "simulation_scenario_revision",
        "simulation_content_snapshot",
        "simulation_batch",
        "simulation_result",
    ),
    # S3-A deterministic answer evaluation of simulation runs (COMP-003/006); widened evaluation methods
    "0022_answer_evaluation": ("simulation_answer_evaluation",),
    # S3-B governed finding rule sets and simulated findings (COMP-008); finding categories widened
    "0023_compliance_findings": (
        "finding_rule_set_version",
        "finding_rule_set_event",
        "simulation_finding_set",
        "simulation_finding",
    ),
    # S3-C human review and case resolution: the S0-designed review_decision ledger and maker-checker approvals
    "0024_review_resolution": ("review_approval", "review_decision"),
    "0026_gpt_live_provider": ("lab_paid_authorisation", "lab_speech_assessment"),
    "0025_voice_lab": (
        "lab_control",
        "lab_budget",
        "lab_config_change",
        "lab_prompt",
        "lab_prompt_version",
        "lab_dataset",
        "lab_test_case",
        "lab_test_case_revision",
        "lab_experiment",
        "lab_session",
        "lab_reservation",
        "lab_session_event",
        "lab_media",
        "lab_transcript",
        "lab_trial",
    ),
}
DEFERRED_TABLES = frozenset({"risk_override"})  # media_asset: S1-C; transcript_segment: S1-D; review_decision: S3-C

# Flag P: provenance + is_synthetic (INV-07, INV-10). Flag E: record_origin.
P_TABLES: tuple[str, ...] = tuple(t for t in CP02_TABLES if t not in {"external_reference", "case_hold", "case_event"})
E_TABLES: tuple[str, ...] = (
    "contact_attempt",
    "conversation_session",
    "survey_run",
    "question_execution",
    "answer_observation",
    "rule_evaluation",
    "finding",
)
# Insert-only tables (flag I): UPDATE and DELETE are always rejected.
INSERT_ONLY_TABLES: tuple[str, ...] = (
    "policy_fact_snapshot",
    "external_reference",
    "risk_rule_set_version",
    "question_revision",
    "script_assignment_rule_version",
    "script_assignment",
    "case_contact_selection",
    "answer_observation",
    "rule_evaluation",
    "case_event",
)
PROVENANCE_COLUMNS = ("source_type", "source_system", "source_reference", "recorded_at", "is_synthetic")
# Excluded from the seed content digest (D-33): randomised ciphertext and operational metadata (§2).
DIGEST_EXCLUDED_COLUMNS = ("created_at", "updated_at", "row_version", "correlation_id")
CIPHERTEXT_SUFFIX = "_ciphertext"

GOVERNED_LISTS = (
    "sbq_risk_band",
    "risk_factor",
    "case_hold_reason",
    "case_closure_reason",
    "case_cancellation_reason",
    "finding_materiality_policy",
    "kpi_sla_exemption_rule",
    "callable_party_roles",
    "synthetic_contact_ranges",
)
# Governed decision columns (S0_DATA_MODEL §2.1): table -> (code column, version column, list).
CODE_REFS: tuple[tuple[str, str, str, str], ...] = (
    ("risk_assessment", "band_code", "band_list_version_id", "sbq_risk_band"),
    ("risk_factor_result", "factor_code", "factor_list_version_id", "risk_factor"),
    ("case_hold", "hold_reason", "hold_reason_list_version_id", "case_hold_reason"),
    ("callback_case", "closure_reason", "closure_reason_list_version_id", "case_closure_reason"),
    ("callback_case", "cancellation_reason", "cancellation_reason_list_version_id", "case_cancellation_reason"),
    ("case_contact_selection", "rule_basis", "rule_basis_list_version_id", "callable_party_roles"),
)
MARKET_SCOPED_TABLES = ("policy", "callback_case", "script_family", "regulatory_reference")
