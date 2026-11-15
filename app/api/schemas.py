"""Request/response models. Requests forbid unknown fields (SEC-002)."""

from __future__ import annotations

import uuid
from datetime import date as Date
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class ErrorResponse(BaseModel):
    code: str
    message: str
    correlation_id: str | None
    retryable: bool
    details: list[dict[str, Any]] | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "not_ready"]


class CsrfResponse(BaseModel):
    csrf_token: str


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PrincipalSummary(BaseModel):
    principal_id: uuid.UUID
    display_name: str
    username: str | None


class SessionInfo(BaseModel):
    session_id: uuid.UUID
    created_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    access_expires_at: datetime


class EnvironmentInfo(BaseModel):
    app_env: str
    data_policy: str


class MeResponse(BaseModel):
    principal: PrincipalSummary
    roles: list[str]
    permissions: list[str]
    markets: list[str]
    session: SessionInfo
    environment: EnvironmentInfo


class LoginResponse(BaseModel):
    principal: PrincipalSummary
    roles: list[str]
    permissions: list[str]
    markets: list[str]
    session_expires_at: datetime


class RefreshResponse(BaseModel):
    session_expires_at: datetime
    access_expires_at: datetime


class PageInfo(BaseModel):
    next_cursor: str | None
    limit: int
    sort: str


class AdminUser(BaseModel):
    principal_id: uuid.UUID
    username: str | None
    display_name: str
    status: Literal["ACTIVE", "DISABLED"]
    groups: list[str]
    roles: list[str]
    created_at: datetime
    disabled_at: datetime | None
    last_login_at: datetime | None
    active_sessions: int
    row_version: int


class AdminUserList(BaseModel):
    items: list[AdminUser]
    page: PageInfo
    total: None = None


class AdminUserPatch(StrictModel):
    status: Literal["ACTIVE", "DISABLED"] | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=500)


class AuditEventOut(BaseModel):
    event_id: uuid.UUID
    seq: int
    occurred_at: datetime
    action: str
    outcome: str
    actor_principal_id: uuid.UUID | None
    actor_display_name: str | None
    actor_username: str | None
    actor_service: str | None
    session_id: uuid.UUID | None
    correlation_id: str | None
    source_ip: str | None
    entity_type: str | None
    entity_id: str | None
    entity_version: int | None
    reason: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class AuditEventList(BaseModel):
    items: list[AuditEventOut]
    page: PageInfo
    total: None = None


# ---- CP0.1B-1 configuration ------------------------------------------------------------------
AttributeValue = str | int | bool | None


class CodeValueIn(StrictModel):
    code: str = Field(min_length=1, max_length=40)
    label: str = Field(min_length=1, max_length=120)
    attributes: dict[str, AttributeValue] = Field(default_factory=dict, max_length=20)
    sort_order: int = Field(default=0, ge=0, le=100000)


class CodeListVersionCreate(StrictModel):
    based_on_version: int = Field(ge=0)
    values: list[CodeValueIn] = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=500)


class CodeValueOut(BaseModel):
    code: str
    label: str
    attributes: dict[str, Any]
    sort_order: int


class CodeListVersionOut(BaseModel):
    version: int
    status: Literal["DRAFT", "ACTIVE", "SUPERSEDED"]
    effective_from: datetime
    activated_at: datetime | None
    superseded_at: datetime | None
    change_reason: str
    created_by: str
    created_by_name: str | None
    values: list[CodeValueOut]


class CodeListOut(BaseModel):
    code: str
    name: str
    description: str
    governed: bool
    active_version: int | None
    versions: list[CodeListVersionOut]


class CodeListList(BaseModel):
    items: list[CodeListOut]


class FeatureFlagChangeOut(BaseModel):
    old_enabled: bool
    new_enabled: bool
    reason: str
    changed_by: str
    changed_by_name: str | None
    changed_at: datetime


class FeatureFlagOut(BaseModel):
    code: str
    description: str
    enabled: bool
    stage_gate: str
    locked: bool
    row_version: int
    updated_at: datetime
    updated_by: str
    history: list[FeatureFlagChangeOut]


class FeatureFlagList(BaseModel):
    items: list[FeatureFlagOut]
    current_stage: str


class FeatureFlagPatch(StrictModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=500)


# ---- Overview / Dashboard (API-030…034; S0_KPI_DEFINITIONS) ----------------------------------------------
class KpiRange(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: Date = Field(alias="from")
    to: Date


class KpiDrilldown(BaseModel):
    numerator: str | None
    denominator: str | None


class KpiOut(BaseModel):
    definition_id: str
    label: str
    grain: str
    numerator: int | None
    denominator: int | None
    value: float | None
    unit: Literal["percent", "count", "hours"]
    status: Literal["MEASURED", "NOT_MEASURED"]
    stage_note: str | None
    cohort_basis: str
    range: KpiRange
    time_zone: str
    filter_scope: dict[str, list[str]]
    dedup_rule: str
    eligibility_rule: str
    exclusions: dict[str, Any]
    exemptions_applied: list[dict[str, Any]]
    materiality_policy_version: int | None
    reopen_handling: str
    data_as_of: datetime
    reporting_version: str
    synthetic_badge: bool
    drilldown: KpiDrilldown
    breakdown: dict[str, Any]


class KpiList(BaseModel):
    items: list[KpiOut]
    range: KpiRange
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool


class TrendPoint(BaseModel):
    date: Date
    numerator: int
    denominator: int
    value: float | None


class KpiTrend(BaseModel):
    definition_id: str
    label: str
    days: int
    time_zone: str
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool
    points: list[TrendPoint]


class AttentionReason(BaseModel):
    code: str
    label: str


class AttentionItem(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    policy_ref: str
    policyholder: str  # masked by the server; never unmasked in S0
    state: str
    due_at: datetime
    risk_band: str | None
    holds: list[str]
    reasons: list[AttentionReason]
    priority: int
    route: str


class AttentionList(BaseModel):
    items: list[AttentionItem]
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool


class ActivityItem(BaseModel):
    event_id: uuid.UUID
    occurred_at: datetime
    event_type: str
    summary: str
    case_id: uuid.UUID
    case_ref: str
    related_entity_type: str | None


class ActivityList(BaseModel):
    items: list[ActivityItem]
    markets: list[str]
    synthetic_badge: bool


class RiskBucket(BaseModel):
    band: str
    label: str
    count: int
    share: float | None
    drilldown: str


class RiskDistribution(BaseModel):
    items: list[RiskBucket]
    total_open: int
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool
    note: str


# ---- F2: case register, work queues and search (API-035/036/070/071/076) -----------------------------------
class CaseRow(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    policy_id: uuid.UUID
    policy_ref: str
    policyholder: str  # masked by the server
    product_family: str
    product_subtype: str
    is_ilp: bool
    risk_band: str  # effective SBQ band or NOT_ASSESSED (sale-selection risk, not a finding severity)
    state: str
    outcome: str
    holds: list[str]
    blocking_hold: bool
    overdue: bool
    due_at: datetime
    attempts: int
    latest_attempt_status: str | None
    sessions: int
    script: str | None
    evidence: str  # recordings and transcripts do not exist before Stage S1
    is_synthetic: bool
    route: str  # Call Detail (/cases/:caseId), delivered in F3


class CaseList(BaseModel):
    items: list[CaseRow]
    total: int
    page: PageInfo
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool


class CaseFacets(BaseModel):
    total: int
    facets: dict[str, dict[str, int]]
    markets: list[str]
    data_as_of: datetime


class HoldReasonCount(BaseModel):
    hold_reason: str
    count: int
    blocking: int
    register_route: str


class WorkQueue(BaseModel):
    code: Literal["DUE_TODAY", "OVERDUE", "AWAITING_CALLBACK", "ON_HOLD"]
    label: str
    count: int
    rule: str
    route: str
    register_route: str
    by_reason: list[HoldReasonCount]


class WorkQueueList(BaseModel):
    items: list[WorkQueue]
    markets: list[str]
    data_as_of: datetime
    time_zone: str
    synthetic_badge: bool


class SearchHit(BaseModel):
    entity_type: Literal["case", "policy", "attempt", "session"]
    id: uuid.UUID
    ref: str
    masked_display: str
    matched_field: str
    match_kind: Literal["EXACT", "PREFIX", "FUZZY"]
    route: str  # typed detail route (Call Detail F3, Policy Detail F4)
    register_route: str  # Call Explorer filtered to this record (available now)


class SearchResults(BaseModel):
    items: list[SearchHit]
    total: int
    counts: dict[str, int]
    page: PageInfo
    markets: list[str]


class SearchSuggestions(BaseModel):
    items: list[SearchHit]
    markets: list[str]


# ---- F3: Call Detail (API-037…047, API-063). JSON columns (facts, traces, snapshots) are passed through as
# stored; every person-related value is the server-masked form. ------------------------------------------------
class Sla(BaseModel):
    due_at: datetime
    matured: bool  # due_at has passed
    breached: bool | None  # None while not matured or when exempt
    exempt: bool
    exemption_rule: str | None
    note: str


class HoldOut(BaseModel):
    id: uuid.UUID
    hold_reason: str
    is_blocking: bool
    placed_at: datetime
    placed_by: str
    placed_reason: str | None
    source: str
    released_at: datetime | None
    released_by: str | None
    release_reason: str | None
    active: bool


class HoldList(BaseModel):
    items: list[HoldOut]


class FscOut(BaseModel):
    fsc_ref: str
    display_name: str
    channel: str | None
    status: str | None


class SaleOut(BaseModel):
    id: uuid.UUID
    sale_ref: str
    sale_event_type: str
    sold_at: datetime
    selling_channel: str | None
    selling_location: str | None
    campaign_code: str | None
    proposal_ref: str | None
    premium_amount: float | None
    currency: str | None
    product_snapshot: dict[str, Any]
    fsc: FscOut | None
    source_type: str
    source_system: str | None
    recorded_at: datetime | None


class PolicyOut(BaseModel):
    id: uuid.UUID
    policy_ref: str
    product_code: str
    product_family: str
    product_subtype: str
    is_ilp: bool
    status: str
    premium_amount: float | None
    currency: str | None
    premium_frequency: str | None
    premium_term_years: int | None
    sum_assured: float | None
    sum_assured_currency: str | None
    effective_from: datetime | None
    effective_to: datetime | None
    source_type: str
    source_system: str | None


class PartyRoleOut(BaseModel):
    party_ref: str
    masked_name: str
    kind: str
    roles: list[str]
    authorization_ref: str | None


class ContactSelectionOut(BaseModel):
    party_ref: str
    masked_name: str
    role: str
    channel: str | None
    masked_contact: str | None
    eligible: bool
    ineligibility_reason: str | None
    rule_basis: str
    decided_at: datetime
    decided_by: str


class RiskFactorOut(BaseModel):
    factor_code: str
    value_type: str
    value: Any
    source: str | None
    matched_rule_id: str | None
    result: str


class RiskAssessmentOut(BaseModel):
    id: uuid.UUID
    kind: str
    origin: str
    status: str
    band_code: str | None
    score: float | None
    reason_codes: list[str]
    explanation: str | None
    source_original_value: str | None
    rule_set: str | None
    assessed_at: datetime | None
    valid_at: datetime
    input_snapshot_sha256: str | None
    effective: bool
    factors: list[RiskFactorOut]
    supersedes_id: uuid.UUID | None = None


class FactSnapshotOut(BaseModel):
    id: uuid.UUID
    captured_at: datetime
    schema_version: str
    sha256: str
    facts: dict[str, Any]
    field_provenance: dict[str, Any]


class ScriptPin(BaseModel):
    script_version_id: uuid.UUID
    family: str
    version_label: str
    status: str
    manifest_sha256: str
    content_approval_status: str


class CaseDetail(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    market: str
    obligation_type: str
    source_request_ref: str | None
    state: str
    outcome: str
    controls_satisfied: bool
    open_findings: int
    priority: int | None
    owner: str | None
    due_at: datetime
    verified_at: datetime | None
    closed_at: datetime | None
    closure_reason: str | None
    cancellation: dict[str, Any] | None
    sla: Sla
    holds: list[HoldOut]
    callable: bool
    callable_blockers: list[str]
    risk_band: str | None
    effective_risk: RiskAssessmentOut | None
    risk_assessments: list[RiskAssessmentOut]
    policy: PolicyOut
    sale: SaleOut
    parties: list[PartyRoleOut]
    contact_selection: list[ContactSelectionOut]
    fact_snapshots: list[FactSnapshotOut]
    current_script: ScriptPin | None
    attempts: int
    sessions: int
    source_type: str
    is_synthetic: bool
    data_as_of: datetime


class SessionLink(BaseModel):
    session_id: uuid.UUID
    session_ref: str
    state: str
    survey_run_id: uuid.UUID | None
    survey_run_status: str | None


class AttemptOut(BaseModel):
    id: uuid.UUID
    attempt_ref: str
    case_id: uuid.UUID
    sequence: int
    transport: str
    direction: str
    status: str
    contact_snapshot: dict[str, Any]
    contacted_party: str | None
    scheduled_at: datetime | None
    started_at: datetime | None
    ended_at: datetime | None
    failure_reason: str | None
    record_origin: str
    session: SessionLink | None


class AttemptList(BaseModel):
    items: list[AttemptOut]


class ScriptAssignmentOut(BaseModel):
    id: uuid.UUID
    script: ScriptPin
    script_manifest_sha256: str
    matched_rule: str | None
    rule_trace: dict[str, Any]
    input_snapshot: dict[str, Any]
    input_sha256: str
    risk_assessment_id: uuid.UUID | None
    policy_fact_snapshot_id: uuid.UUID | None
    origin: str
    assigned_at: datetime
    assigned_by: str
    superseded: bool


class ScriptAssignmentList(BaseModel):
    items: list[ScriptAssignmentOut]


class TimelineItem(BaseModel):
    id: uuid.UUID
    event_type: str
    occurred_at: datetime
    actor_ref: str
    related_entity_type: str | None
    related_entity_id: uuid.UUID | None
    summary: str
    route: str | None


class Timeline(BaseModel):
    items: list[TimelineItem]


class FindingOut(BaseModel):
    id: uuid.UUID
    finding_ref: str
    category: str
    severity: str
    status: str
    origin: str
    record_origin: str
    evidence_refs: dict[str, Any]
    question_execution_id: uuid.UUID | None
    question_code: str | None
    survey_run_id: uuid.UUID | None
    raised_at: datetime
    review_assigned_at: datetime | None
    review_closed_at: datetime | None


class FindingList(BaseModel):
    items: list[FindingOut]
    material_severities: list[str]


class SessionDetail(BaseModel):
    id: uuid.UUID
    session_ref: str
    case_id: uuid.UUID
    case_ref: str
    attempt_id: uuid.UUID
    attempt_ref: str
    state: str
    transport: str
    started_at: datetime | None
    ended_at: datetime | None
    script: ScriptPin
    script_manifest_sha256: str
    script_pin_matches: bool  # the pinned SHA equals the version's stored manifest SHA
    risk_assessment: RiskAssessmentOut | None
    risk_snapshot_sha256: str | None
    fact_snapshot: FactSnapshotOut | None
    fact_snapshot_pin_matches: bool
    contacted_party: str | None
    contact_method_snapshot: dict[str, Any]
    media_status: str
    transcript_status: str
    record_origin: str
    survey_run_ids: list[uuid.UUID]


class Availability(BaseModel):
    session_id: uuid.UUID
    availability: Literal["NOT_AVAILABLE"]
    reason: Literal["NO_CAPTURE_BEFORE_S1"]
    message: str


class QuestionResult(BaseModel):
    question_execution_id: uuid.UUID
    position: int
    question_code: str
    intent: str | None
    wording: str
    revision: int
    delivery_mode: str
    answer_type: str
    mandatory: bool
    expected_answer_policy: str
    expected_value: Any
    policy_fact_key: str | None
    delivery_status: str
    retries: int
    skip_reason: str | None
    event_range: dict[str, Any] | None
    answer_state: str | None
    typed_value: Any
    verbatim_text_redacted: str | None
    extraction_engine: str | None
    rule_ref: str | None
    rule_expected: Any
    rule_observed: Any
    rule_result: str | None
    control_satisfied: bool | None  # existing §1.1 test for mandatory questions; None when not mandatory
    findings: list[str]
    record_origin: str


class SurveyRunDetail(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    session_ref: str
    case_id: uuid.UUID
    case_ref: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    script: ScriptPin
    script_manifest_sha256: str
    policy_fact_snapshot_id: uuid.UUID
    controls_satisfied: bool
    questions: list[QuestionResult]
    record_origin: str


class ScriptQuestionOut(BaseModel):
    position: int
    question_code: str
    intent: str | None
    wording: str
    revision: int
    delivery_mode: str
    answer_type: str
    mandatory: bool
    expected_answer_policy: str
    expected_value: Any
    acceptable_variants: Any
    unacceptable_outcomes: Any
    policy_fact_key: str | None
    not_applicable_predicate: Any
    branch_condition: Any
    controls: list[dict[str, Any]]
    content_approval_status: str


class ScriptSectionOut(BaseModel):
    position: int
    module_code: str
    module_name: str
    module_kind: str
    inclusion_condition: Any
    questions: list[ScriptQuestionOut]


class ScriptVersionDetail(BaseModel):
    id: uuid.UUID
    family: str
    family_name: str
    market: str
    version_label: str
    status: str
    validation_status: str | None
    language: str
    effective_from: datetime | None
    effective_to: datetime | None
    manifest_sha256: str
    author_ref: str | None
    reviewer_ref: str | None
    published_at: datetime | None
    content_approval_status: str
    sections: list[ScriptSectionOut]


# ---- F4: Policy Explorer and Policy Detail (API-050…055) --------------------------------------------------------
class Provenance(BaseModel):
    source_type: str
    source_system: str | None
    source_reference: str | None
    source_observed_at: datetime | None
    recorded_at: datetime | None
    mapping_version: str | None
    intake_item_id: uuid.UUID | None
    is_synthetic: bool


class ExternalRefOut(BaseModel):
    source_system: str
    object_type: str
    external_id: str


class PolicyRow(BaseModel):
    policy_id: uuid.UUID
    policy_ref: str
    owner: str  # masked by the server; joint owners joined
    insured: str  # masked by the server
    product_code: str
    product_family: str
    product_subtype: str
    is_ilp: bool
    premium_amount: float | None
    currency: str | None
    premium_frequency: str | None
    sales: int
    sale_types: list[str]
    latest_sale_ref: str | None
    latest_sold_at: datetime | None
    selling_channel: str | None  # latest sale event
    selling_location: str | None
    fsc_ref: str | None
    fsc_name: str | None
    risk_band: str  # effective SBQ band of the latest sale, or NOT_ASSESSED (selection risk, not a finding severity)
    script: str | None  # script pinned on the latest callback case
    cases: int
    latest_case_id: uuid.UUID | None
    latest_case_ref: str | None
    latest_case_state: str | None
    latest_case_outcome: str | None
    is_synthetic: bool
    route: str  # Policy Detail


class PolicyList(BaseModel):
    items: list[PolicyRow]
    total: int
    page: PageInfo
    facets: dict[str, dict[str, int]]
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool


class MaterialField(BaseModel):
    field: str
    value: Any
    source_system: str | None
    source_reference: str | None
    as_of: datetime | None  # source_observed_at, else recorded_at


class PolicyCaseSummary(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    sale_event_id: uuid.UUID
    sale_ref: str
    sale_event_type: str
    state: str
    outcome: str
    controls_satisfied: bool | None
    open_findings: int
    risk_band: str
    due_at: datetime
    verified_at: datetime | None
    closed_at: datetime | None
    script: ScriptPin | None
    matched_rule: str | None
    assignment_origin: str | None
    script_rationale: dict[str, Any]
    route: str  # Call Detail


class PolicyDetail(PolicyOut):
    market: str
    provenance: Provenance
    material_fields: list[MaterialField]
    external_refs: list[ExternalRefOut]
    owners: list[str]
    insured: list[str]
    sales: int
    top_ups: int
    latest_sale_id: uuid.UUID | None
    risk_band: str
    cases: list[PolicyCaseSummary]
    data_as_of: datetime


class RoleEdge(BaseModel):
    role: str
    valid_from: datetime
    valid_to: datetime | None
    current: bool
    authorization_ref: str | None
    authorization_valid_from: datetime | None
    authorization_valid_to: datetime | None
    source_system: str | None


class ContactCard(BaseModel):
    channel: str
    masked_value: str
    is_verified: bool
    preference_rank: int | None
    language: str | None
    timezone: str | None
    consent_status: str
    suppressed: bool
    valid_from: datetime
    valid_to: datetime | None
    current: bool
    source_system: str | None
    source_observed_at: datetime | None


class EligibilityOut(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    role: str
    channel: str | None
    masked_contact: str | None
    eligible: bool
    ineligibility_reason: str | None
    rule_basis: str
    decided_at: datetime
    decided_by: str
    superseded: bool


class PartyCard(BaseModel):
    party_ref: str
    kind: str
    masked_name: str
    personal_data_class: str
    roles: list[RoleEdge]
    contacts: list[ContactCard]
    eligibility: list[EligibilityOut]
    provenance: Provenance


class PartyList(BaseModel):
    policy_id: uuid.UUID
    policy_ref: str
    items: list[PartyCard]


class SaleSummary(SaleOut):
    source_reference: str | None
    source_observed_at: datetime | None
    risk_band: str
    fact_snapshots: int
    cases: list[PolicyCaseSummary]


class SaleList(BaseModel):
    policy_id: uuid.UUID
    policy_ref: str
    items: list[SaleSummary]


class SaleContext(BaseModel):
    sale: SaleOut
    policy_id: uuid.UUID
    policy_ref: str
    provenance: Provenance
    external_refs: list[ExternalRefOut]
    fact_snapshots: list[FactSnapshotOut]
    risk_assessments: list[RiskAssessmentOut]
    cases: list[PolicyCaseSummary]


class LineageItem(BaseModel):
    entity_type: str
    entity_ref: str
    label: str
    provenance: Provenance
    external_refs: list[ExternalRefOut]


class FieldChangeAvailability(BaseModel):
    availability: Literal["NOT_AVAILABLE"]
    reason: Literal["LEDGER_ARRIVES_CP0_4"]
    message: str


class PolicyHistory(BaseModel):
    policy_id: uuid.UUID
    policy_ref: str
    lineage: list[LineageItem]
    field_changes: FieldChangeAvailability
