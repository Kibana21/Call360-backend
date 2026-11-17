"""Request/response models. Requests forbid unknown fields (SEC-002)."""

from __future__ import annotations

import uuid
from datetime import date as Date
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


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
    password_change_required: bool = False  # CP0.1B-3: a one-time password must be replaced first


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


# ---- CP0.1B-3 Administration completion (API-007, 009, 011, 013, 014…020, 026) -------------------------------
class SessionStatus(BaseModel):
    session_id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime


class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class AdminUserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    group_code: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=500)


class Reason(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


class OneTimePassword(BaseModel):
    """Returned once to the administrator; never stored in plain text, logged or audited."""

    user: AdminUser
    one_time_password: str | None
    replayed: bool = False
    note: str


class GroupMember(BaseModel):
    principal_id: uuid.UUID
    username: str | None
    display_name: str
    status: str
    valid_from: datetime
    valid_to: datetime | None
    provenance: str
    created_by: str


class GroupRoleOut(BaseModel):
    role: str
    effective_from: datetime
    effective_to: datetime | None
    approved_by: str


class GroupScopeOut(BaseModel):
    market: str
    effective_from: datetime
    effective_to: datetime | None
    created_by: str
    change_reason: str


class AdminGroup(BaseModel):
    group_id: uuid.UUID
    code: str
    name: str
    status: str
    provider: str
    member_count: int
    roles: list[str]  # current role mappings
    markets: list[str]  # current scope mappings
    mappings_version: str  # If-Match value for API-018
    members: list[GroupMember]  # current members
    former_members: list[GroupMember]
    role_history: list[GroupRoleOut]
    scope_history: list[GroupScopeOut]


class AdminGroupList(BaseModel):
    items: list[AdminGroup]
    enabled_markets: list[str]


class GroupMappingsUpdate(StrictModel):
    roles: list[str] = Field(max_length=10)
    markets: list[str] = Field(max_length=10)
    reason: str = Field(min_length=3, max_length=500)


class RolePermissionOut(BaseModel):
    code: str
    alias: str | None
    reserved: bool
    description: str


class AdminRole(BaseModel):
    code: str
    name: str
    permissions: list[RolePermissionOut]


class AdminRoleList(BaseModel):
    items: list[AdminRole]
    reserved_permissions: list[RolePermissionOut]


class AdminSessionOut(BaseModel):
    session_id: uuid.UUID
    principal_id: uuid.UUID
    username: str | None
    display_name: str
    created_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    ip: str | None
    current: bool


class AdminSessionList(BaseModel):
    items: list[AdminSessionOut]


class HealthCheck(BaseModel):
    code: str
    label: str
    status: Literal["OK", "WARN", "FAIL", "NOT_AVAILABLE"]
    detail: str


class SystemHealth(BaseModel):
    checked_at: datetime
    app_env: str
    data_policy: str
    current_stage: str
    migration_head: str | None
    expected_migration_head: str
    enabled_markets: list[str]
    openapi_sha256: str
    audit_chain_head: str | None
    audit_events: int
    checks: list[HealthCheck]
    counts: dict[str, int]


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
    scope_redacted: bool = False  # CP0.6-F1: out-of-scope record ID or dataset-wide totals withheld


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
    script_family_id: uuid.UUID
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
    # D-48 (derived, no schema change): a Call360 browser test session (transport BROWSER, origin CALL360_RUNTIME,
    # mock provider in S1) is a TEST_SESSION, not a customer CONTACT_ATTEMPT.
    attempt_kind: Literal["CONTACT_ATTEMPT", "TEST_SESSION"]
    media_status: str | None  # the session's BRD §3.3 media status, when a session exists
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


TranscriptStatusT = Literal["PENDING", "PROCESSING", "COMPLETE", "PARTIAL", "FAILED", "UNAVAILABLE"]
TrackT = Literal["MIC", "PROVIDER_PLAYBACK"]


class TranscriptRun(BaseModel):
    """One transcription of one stored track with its full provenance (D-49). Immutable once DONE or FAILED."""

    run_ref: str
    track: TrackT
    revision: int
    status: Literal["PENDING", "PROCESSING", "DONE", "FAILED"]
    attempts: int
    error_code: str | None
    language: Literal["en"]
    engine: str
    engine_version: str
    model_id: str
    model_revision: str
    model_sha256: str
    config: dict[str, Any]
    config_sha256: str
    input_content_sha256: str
    text_sha256: str | None
    source_event_seq: int
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    metrics: dict[str, Any]
    purged_at: datetime | None


class TranscriptTrack(BaseModel):
    track: TrackT
    speaker: Literal["CALLER_MIC", "MOCK_PROVIDER"]
    speaker_label: str
    run: TranscriptRun | None
    revisions: int
    speech_segments: int
    unrecognized_segments: int
    low_confidence_segments: int
    uncertain_words: int


class SessionTranscript(BaseModel):
    """API-045 from S1-D: transcript status, provenance and counts (no text) for any reader of the case. ``status``
    maps to the approved ``conversation_session.transcript_status``: PENDING/PROCESSING → PENDING, COMPLETE →
    FINALIZED (QUALITY_FLAGGED when uncertain speech is present), PARTIAL → PARTIAL, FAILED/UNAVAILABLE →
    UNAVAILABLE. COMPLETE means every stored track was processed over complete recording coverage; it never means
    correct, reviewed or certified (``review_status`` is always NOT_REVIEWED in S1)."""

    session_id: uuid.UUID
    availability: Literal["AVAILABLE", "RESTRICTED", "PENDING", "FAILED", "NOT_AVAILABLE"]
    status: TranscriptStatusT
    reason: str
    message: str
    session_transcript_status: str
    review_status: Literal["NOT_REVIEWED"]
    uncertain: bool
    language: Literal["en"]
    recording_status: str
    can_read_text: bool
    can_retry: bool
    tracks: list[TranscriptTrack]


class TranscriptWord(BaseModel):
    text: str
    timeline_start_ms: int
    timeline_end_ms: int
    probability: float
    uncertain: bool


class TranscriptSegmentOut(BaseModel):
    """One recognised (SPEECH) or rejected (UNRECOGNIZED, never with text) stretch of one track. Times are on the
    session recording timeline; ``wav_offset_ms`` is the position in that track's evidence WAV."""

    track: TrackT
    speaker: Literal["CALLER_MIC", "MOCK_PROVIDER"]
    speaker_label: str
    run_ref: str
    ordinal: int
    kind: Literal["SPEECH", "UNRECOGNIZED"]
    confidence: Literal["NORMAL", "LOW"]
    rec_segment: int
    start_sample: int
    end_sample: int
    timeline_start_ms: int
    timeline_end_ms: int
    wav_offset_ms: int | None
    time_alignment: str
    avg_logprob: float
    no_speech_prob: float
    word_count: int
    uncertain_words: int
    text: str | None
    text_available: bool
    words: list[TranscriptWord]
    flags: list[str]


class TimelineSpan(BaseModel):
    segment: int
    seq: int
    start_sample: int
    sample_count: int
    timeline_start: int
    wav_offset: int


class TimelineGap(BaseModel):
    type: str
    segment: int
    seqs: list[int]
    timeline_start: int
    timeline_end: int
    estimated: bool
    reason: str | None


class TimelineTrack(BaseModel):
    asset_ref: str
    media_status: str
    coverage: str
    content_sha256: str | None
    stored_samples: int
    spans: list[TimelineSpan]
    gaps: list[TimelineGap]


class TimelineSegment(BaseModel):
    segment: int
    timeline_start: int
    length: int
    started_at: datetime


class RecordingTimeline(BaseModel):
    """Recording time ↔ playback mapping for both tracks (samples at ``sample_rate``). The evidence WAV holds stored
    chunks only; gaps are timeline spans, never filled audio."""

    session_id: uuid.UUID
    sample_rate: int
    total_samples: int
    segments: list[TimelineSegment]
    tracks: dict[str, TimelineTrack]


class TranscriptProblem(BaseModel):
    track: str
    code: str


class TranscriptSegments(BaseModel):
    session_id: uuid.UUID
    status: TranscriptStatusT
    review_status: Literal["NOT_REVIEWED"]
    segments: list[TranscriptSegmentOut]
    problems: list[TranscriptProblem]
    timeline: RecordingTimeline


class TranscriptRetryOut(BaseModel):
    session_id: uuid.UUID
    queued_tracks: list[TrackT]
    status: TranscriptStatusT


class SessionMedia(BaseModel):
    """API-046 from S1-C: the session's recording evidence. ``availability`` is the derived evidence vocabulary
    (EXT-002): AVAILABLE (audio stored and you may retrieve it), RESTRICTED (stored, but your role lacks
    ``recording.read``), NOT_AVAILABLE (not recorded, purged or no capture), FAILED (consent granted, nothing
    stored)."""

    session_id: uuid.UUID
    availability: Literal["AVAILABLE", "RESTRICTED", "NOT_AVAILABLE", "FAILED"]
    reason: str
    message: str
    media_status: str
    recording: RecordingSummary
    can_retrieve_audio: bool


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
    script_family_id: uuid.UUID
    family: str
    family_name: str
    market: str
    version_label: str
    status: str
    validation_status: str | None
    language: str
    effective_from: datetime | None
    effective_to: datetime | None
    manifest_sha256: str | None  # a draft has no frozen manifest yet
    author_ref: str | None
    reviewer_ref: str | None
    published_at: datetime | None
    content_approval_status: str
    sections: list[ScriptSectionOut]


# ---- F6: Script Studio and Assignment Rules (API-060…062, API-064…066; read-only) ------------------------------
class ScriptModuleSummary(BaseModel):
    position: int
    module_code: str
    module_name: str
    module_kind: str
    module_revision: int
    inclusion_condition: Any
    questions: int


class ScriptVersionSummary(BaseModel):
    id: uuid.UUID
    script_family_id: uuid.UUID
    family: str
    family_name: str
    market: str
    purpose: str
    version_label: str
    status: str
    validation_status: str | None
    language: str
    effective_from: datetime | None
    effective_to: datetime | None
    published_at: datetime | None
    manifest_sha256: str | None  # a draft has no frozen manifest yet
    content_approval_status: str
    author_ref: str | None
    reviewer_ref: str | None
    supersedes_id: uuid.UUID | None
    supersedes_label: str | None
    modules: list[ScriptModuleSummary]
    questions: int
    mandatory_questions: int
    cases_assigned: int
    rules_targeting: list[str]


class ScriptLibrary(BaseModel):
    items: list[ScriptVersionSummary]
    total: int
    facets: dict[str, dict[str, int]]
    markets: list[str]


class ScriptFamilyDetail(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    market: str
    purpose: str
    description: str | None
    versions: list[ScriptVersionSummary]


class ScriptVersionList(BaseModel):
    script_family_id: uuid.UUID
    family: str
    items: list[ScriptVersionSummary]


class RuleCaseRef(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    assigned_at: datetime


class AssignmentRuleOut(BaseModel):
    id: uuid.UUID
    rule_code: str
    version: int
    status: str
    predicate: Any
    priority: int
    specificity: int
    effective_from: datetime | None
    effective_to: datetime | None
    checksum: str | None
    author_ref: str | None
    checker_ref: str | None
    market: str
    target: ScriptPin
    target_family_id: uuid.UUID
    cases_assigned: int
    recent_cases: list[RuleCaseRef]


class AssignmentRuleList(BaseModel):
    items: list[AssignmentRuleOut]
    total: int


class RegulatoryReferenceOut(BaseModel):
    id: uuid.UUID
    issuer: str
    jurisdiction: str
    market: str | None
    title: str
    document_version: str | None
    url: str | None
    published_on: Date | None
    interpretation_status: str
    controls: list[str]


class RegulatoryReferenceList(BaseModel):
    items: list[RegulatoryReferenceOut]


class ControlQuestionLink(BaseModel):
    question_code: str
    intent: str | None
    rationale: str | None
    mapping_status: str
    regulatory_reference_id: uuid.UUID | None
    regulatory_reference_title: str | None
    script_versions: list[str]  # "FAMILY vLABEL" of in-scope versions that include the question


class ControlOut(BaseModel):
    id: uuid.UUID
    control_code: str
    name: str
    owner_role: str | None
    content_approval_status: str
    questions: list[ControlQuestionLink]


class ControlList(BaseModel):
    items: list[ControlOut]


# ---- F7: Review Workbench (API-077) and Voice Studio preflight (API-078); read-only ---------------------------
class ReviewEvidence(BaseModel):
    """What the finding points at, as recorded. Absent media is stated, never implied."""

    question_code: str | None
    question_wording: str | None
    controls: list[str]
    answer_state: str | None
    typed_value: Any
    verbatim_redacted: str | None
    rule_ref: str | None
    rule_version: str | None
    rule_expected: Any
    rule_observed: Any
    rule_result: str | None
    transcript: str
    recording: str
    label: str | None


class ReviewItem(BaseModel):
    id: uuid.UUID
    finding_ref: str
    category: str
    severity: str  # compliance finding severity: not SBQ selection risk, not investment suitability
    material: bool
    status: str
    origin: str
    record_origin: str
    raised_at: datetime
    review_assigned_at: datetime | None
    review_closed_at: datetime | None
    reviewer_assigned: bool
    case_id: uuid.UUID
    case_ref: str
    case_state: str
    policy_id: uuid.UUID
    policy_ref: str
    sale_event_id: uuid.UUID
    sale_ref: str
    selection_risk_band: str  # the case's effective SBQ callback-selection band (context only)
    evidence: ReviewEvidence


class ReviewQueue(BaseModel):
    items: list[ReviewItem]
    total: int
    limit: int
    offset: int
    facets: dict[str, dict[str, int]]
    material_severities: list[str]
    markets: list[str]


class VoiceCapability(BaseModel):
    code: str
    label: str
    status: Literal["AVAILABLE", "NOT_AVAILABLE", "DISABLED", "NOT_PERFORMED", "NOT_EVALUATED"]
    reason: str
    stage: str


class VoiceCaseOption(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    state: str


class RecordingNotice(BaseModel):
    """S1-C test-only recording notice (D-45). Not approved AIA/MAS consent wording."""

    version: str
    text: str
    sha256: str
    default_decision: Literal["DECLINED"] = "DECLINED"
    retention_hours: int  # local development setting, not a retention policy
    approved_policy: Literal[False] = False


class VoicePreflight(BaseModel):
    status: Literal["AVAILABLE", "NOT_AVAILABLE"]
    reason: str
    stage: str
    provider: str | None
    capabilities: list[VoiceCapability]
    data_policy: str
    test_message: list[str]
    callable_cases: list[VoiceCaseOption]  # a few callable Singapore cases, for starting a test session
    recording_notice: RecordingNotice | None  # None when recording is not configured or not permitted


class VoiceSessionCreate(StrictModel):
    case_id: uuid.UUID
    # S1-C (VOICE-007, D-45): explicit recording decision; omitted means DECLINED (default no recording). GRANTED must
    # name the notice version shown to the operator. Microphone permission is never taken as consent.
    recording_consent: Literal["GRANTED", "DECLINED"] | None = None
    consent_notice_version: str | None = Field(default=None, max_length=24)


class VoiceContact(BaseModel):
    party_ref: str
    masked_name: str
    role: str
    channel: str | None
    masked_contact: str | None


class VoiceSessionOut(BaseModel):
    """A short-lived, case-bound test session (S1-A; persisted from S1-B). ``session_id`` is the persisted browser
    contact attempt. The credential is single-use and expires quickly; it is sent as the first WebSocket message,
    never in a URL."""

    session_id: uuid.UUID
    attempt_ref: str
    resumed: bool = False
    credential: str
    credential_expires_at: datetime
    stream_path: str
    case_id: uuid.UUID
    case_ref: str
    provider: str
    script: ScriptPin
    contact: VoiceContact
    identity_verification: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    compliance_outcome: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    recording_consent: Literal["GRANTED", "DECLINED"]
    transcript: Literal["NOT_AVAILABLE"] = "NOT_AVAILABLE"
    attempt_kind: Literal["TEST_SESSION"] = "TEST_SESSION"
    test_message: list[str]
    sample_rate: int
    frame_ms: int
    max_duration_s: int


class VoiceSessionEvent(BaseModel):
    seq: int
    event_type: str
    source: str
    occurred_at: datetime
    client_seq: int | None
    out_of_order: bool
    details: dict[str, Any]  # metadata only: never audio, transcript text or microphone content


RecordingStatus = Literal["NOT_RECORDED", "RECORDING", "COMPLETE", "PARTIAL", "FAILED", "PURGED"]


class RecordingGap(BaseModel):
    type: str  # MISSING, UPLOAD_FAILED, DISCONTINUITY, SESSION_INTERRUPTED, END_NOT_CONFIRMED, CAPTURE_INTERRUPTED…
    segment: int
    seq: int | None = None
    samples: int | None = None
    reason: str | None = None


class RecordingTrack(BaseModel):
    """One recorded track's manifest metadata (EVD-003). Never an object key or storage path."""

    track: Literal["MIC", "PROVIDER_PLAYBACK"]
    asset_ref: str
    media_status: str  # BRD §3.3 media vocabulary
    coverage: Literal["PENDING", "COMPLETE", "PARTIAL", "NONE"]
    codec: str
    started_at: datetime
    capture_ended_at: datetime | None
    finalized_at: datetime | None
    chunks_stored: int
    duration_ms: int
    bytes_stored: int
    gaps: list[RecordingGap]
    content_sha256: str | None
    manifest_sha256: str | None
    retention_until: datetime | None
    purged_at: datetime | None


class RecordingSummary(BaseModel):
    status: RecordingStatus
    consent: Literal["GRANTED", "DECLINED", "NOT_ASKED"]
    consent_at: datetime | None
    notice_version: str | None
    tracks: list[RecordingTrack]


class RecordingChunkIn(StrictModel):
    track: Literal["MIC", "PROVIDER_PLAYBACK"]
    segment: int = Field(ge=1, le=999)
    seq: int = Field(ge=1, le=10_000)
    start_sample: int = Field(ge=0)
    sample_count: int = Field(ge=1, le=32_000)
    sha256: str = Field(min_length=64, max_length=64)
    data_b64: str = Field(max_length=86_000)  # ≤ 2 s of 16 kHz PCM16 mono, base64
    captured_at: datetime | None = None


class RecordingChunkAck(BaseModel):
    stored: bool
    duplicate: bool


class RecordingCloseTrack(StrictModel):
    track: Literal["MIC", "PROVIDER_PLAYBACK"]
    segment: int = Field(ge=1, le=999)
    chunks: int = Field(ge=0, le=10_000)
    failed: list[int] = Field(default_factory=list, max_length=10_000)
    reason: Literal["STOPPED", "MIC_DEVICE_LOST", "CONNECTION_LOST", "PAGE_CLOSED", "UPLOAD_FAILED", "CAPTURE_ERROR"]


class RecordingCloseIn(StrictModel):
    tracks: list[RecordingCloseTrack] = Field(min_length=1, max_length=8)


class VoiceSessionStatus(BaseModel):
    session_id: uuid.UUID  # the browser contact attempt
    attempt_ref: str
    session_ref: str | None
    case_id: uuid.UUID
    case_ref: str
    status: Literal[
        "PENDING_CONNECTION", "NOT_CONNECTED", "CREATED", "INTERRUPTED", "FINALIZING", "FINALIZED", "ABORTED"
    ]
    started_at: datetime | None
    ended_at: datetime | None
    end_reason: str | None
    responses: int
    interruptions: int
    events_total: int
    started_by: str
    yours: bool
    can_resume: bool
    identity_verification: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    compliance_outcome: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    attempt_kind: Literal["TEST_SESSION"] = "TEST_SESSION"  # D-48: a mock audio test, not a customer contact
    recording: RecordingSummary
    events: list[VoiceSessionEvent] = Field(default_factory=list)


class VoiceSessionList(BaseModel):
    items: list[VoiceSessionStatus]


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


# ---- F5: SBQ Risk Workbench (API-056…058) ----------------------------------------------------------------------
class CaseLink(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    route: str


class RiskRow(BaseModel):
    id: uuid.UUID
    sale_event_id: uuid.UUID
    sale_ref: str
    sale_event_type: str
    sold_at: datetime
    policy_id: uuid.UUID
    policy_ref: str
    product_family: str
    is_ilp: bool
    channel: str | None
    fsc_ref: str | None
    origin: str  # SOURCE_ASSIGNED | RULE_ASSESSED | MANUAL
    status: str  # FINAL | SUPERSEDED | other stored statuses
    band_code: str | None  # SBQ callback-selection band; never a finding severity or a suitability fact
    score: float | None  # only when stored (C-17)
    reason_codes: list[str]
    source_original_value: str | None
    rule_set: str | None
    assessed_at: datetime | None
    valid_at: datetime
    input_snapshot_sha256: str | None
    matched_factors: list[str]
    effective: bool  # latest FINAL assessment of the sale
    supersedes_id: uuid.UUID | None
    superseded_by: uuid.UUID | None
    discrepancy: bool  # the sale's latest FINAL source-assigned and rule-assessed bands differ
    cases: list[CaseLink]
    is_synthetic: bool
    route: str  # Risk Workbench drawer


class RiskPopulationAssessments(BaseModel):
    total: int
    by_origin: dict[str, int]
    by_status: dict[str, int]
    by_band: dict[str, int]
    superseded: int


class RiskPopulationSales(BaseModel):
    total: int
    by_effective_band: dict[str, int]
    without_assessment: int
    without_final_assessment: int
    source_rule_discrepancies: int


class RiskSummary(BaseModel):
    assessments: RiskPopulationAssessments  # grain: one stored assessment
    sales: RiskPopulationSales  # grain: one sale event (its effective assessment)


class RiskList(BaseModel):
    items: list[RiskRow]
    total: int
    page: PageInfo
    facets: dict[str, dict[str, int]]
    summary: RiskSummary  # whole Singapore population, independent of the filters
    markets: list[str]
    data_as_of: datetime
    synthetic_badge: bool


class RiskFactorDetail(BaseModel):
    factor_code: str | None
    label: str | None
    value_type: str
    value: Any
    source: str
    matched_rule_id: str | None
    weight: float | None
    result: str


class RuleSetOut(BaseModel):
    code: str
    version: int
    status: str
    effective_from: datetime
    effective_to: datetime | None
    checksum: str
    content_approval_status: str


class RiskComparison(BaseModel):
    source_band: str | None
    rule_band: str | None
    effective_band: str | None
    effective_id: uuid.UUID | None
    discrepancy: bool


class RiskAssessmentDetail(RiskRow):
    kind: str
    explanation: str | None
    factors: list[RiskFactorDetail]
    rule_set_version: RuleSetOut | None
    provenance: Provenance
    history: list[RiskRow]  # every stored assessment of the same sale, oldest first
    comparison: RiskComparison


class FactorVocabularyItem(BaseModel):
    code: str
    label: str
    attributes: dict[str, Any]


class RiskFactorVocabulary(BaseModel):
    list_code: str
    version: int
    status: str
    items: list[FactorVocabularyItem]
    bands: list[FactorVocabularyItem]


# ---- CP0.4a manual intake (API-080, API-082…085) ----------------------------------------------------------------
PartyRole = Literal["OWNER", "INSURED", "PAYER", "PROPOSER", "BENEFICIARY", "AUTHORIZED_CONTACT"]
SellingChannel = Literal["AGENCY", "BANCASSURANCE", "BROKER", "DIRECT"]


class IntakeContact(StrictModel):
    channel: Literal["PHONE", "EMAIL"]
    value: str = Field(min_length=3, max_length=120, description="Synthetic identifier only (synthetic_contact_ranges)")
    consent_status: Literal["GRANTED", "WITHDRAWN", "UNKNOWN"]
    suppressed: bool = False
    preference_rank: int = Field(1, ge=1, le=9)
    is_verified: bool = False
    language: str = Field("en", pattern=r"^[a-z]{2}(-[A-Z]{2})?$")


class IntakeAuthorization(StrictModel):
    reference: str = Field(min_length=1, max_length=80)
    valid_from: AwareDatetime
    valid_to: AwareDatetime | None = None


class IntakeParty(StrictModel):
    """Either an existing synthetic party (``party_ref``) or a new one (``kind`` + ``name``). Parties are never
    matched on name or contact value."""

    party_ref: str | None = Field(None, pattern=r"^PTY-[0-9]{6}$")
    source_party_id: str | None = Field(None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
    kind: Literal["PERSON", "ORGANIZATION"] | None = None
    name: str | None = Field(None, min_length=1, max_length=120)
    date_of_birth_year: int | None = Field(None, ge=1900, le=2100)
    roles: list[PartyRole] = Field(min_length=1, max_length=6)
    authorization: IntakeAuthorization | None = None
    contacts: list[IntakeContact] = Field(default_factory=list, max_length=6)


class IntakePolicy(StrictModel):
    policy_ref: str = Field(pattern=r"^POL-[A-Z]{2}-[0-9]{6}$")
    market_code: str = Field(pattern=r"^[A-Z]{2}$")
    product_code: str = Field(min_length=1, max_length=40)
    product_family: str = Field(min_length=1, max_length=40)
    product_subtype: str = Field(min_length=1, max_length=40)
    status: Literal["PROPOSAL", "IN_FORCE", "FREE_LOOK_CANCELLED", "LAPSED", "TERMINATED"]
    premium_amount: Decimal = Field(gt=0, max_digits=14, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    premium_frequency: Literal["SINGLE", "MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"]
    premium_term_years: int | None = Field(None, ge=1, le=99)
    sum_assured: Decimal | None = Field(None, gt=0, max_digits=16, decimal_places=2)
    sum_assured_currency: str | None = Field(None, pattern=r"^[A-Z]{3}$")
    effective_from: AwareDatetime


class IntakeSale(StrictModel):
    sale_ref: str = Field(pattern=r"^SALE-[A-Z]{2}-[0-9]{6}$")
    sale_event_type: Literal["NEW_BUSINESS", "REPLACEMENT", "TOP_UP", "OTHER_APPROVED"]
    sold_at: AwareDatetime
    fsc_ref: str = Field(pattern=r"^FSC-[0-9]{4}$")
    selling_channel: SellingChannel
    selling_location: str = Field(min_length=1, max_length=80)
    campaign_code: str | None = Field(None, min_length=1, max_length=40)
    proposal_ref: str = Field(min_length=1, max_length=40)
    premium_amount: Decimal = Field(gt=0, max_digits=14, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    premium_amount_band: str | None = Field(None, pattern=r"^[A-Z0-9_]{1,40}$", description="Source-supplied label")


class IntakeSourceRisk(StrictModel):
    """SBQ callback-selection risk exactly as the source assigned it. Call360 calculates no band or score."""

    band_code: str = Field(min_length=1, max_length=40)
    source_original_value: str = Field(min_length=1, max_length=80)
    status: Literal["PROVISIONAL", "FINAL"]
    assessed_at: AwareDatetime
    reason_codes: list[str] = Field(default_factory=list, max_length=10)


class IntakeCallbackRequest(StrictModel):
    """The verification obligation as the source requested it: due date and priority are source-provided."""

    source_request_ref: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
    due_at: AwareDatetime
    priority: int = Field(ge=1, le=5)


class IntakeTransaction(StrictModel):
    is_synthetic: bool
    source_system: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{1,79}$")
    source_event_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
    source_observed_at: AwareDatetime | None = None
    reason: str = Field(min_length=3, max_length=500)
    policy: IntakePolicy
    sale: IntakeSale
    parties: list[IntakeParty] = Field(default_factory=list, max_length=10)
    source_risk: IntakeSourceRisk | None = None
    callback_request: IntakeCallbackRequest


class IntakePolicyOut(BaseModel):
    outcome: Literal["NEW", "REUSED"]
    policy_ref: str
    policy_id: uuid.UUID | None


class IntakePartyOut(BaseModel):
    outcome: Literal["NEW", "EXISTING"]
    party_ref: str | None
    party_id: uuid.UUID | None
    masked_name: str
    roles: list[str]
    contacts: list[str]  # masked values only


class IntakeEligibilityOut(BaseModel):
    party_ref: str | None
    masked_name: str
    role: str
    eligible: bool
    ineligibility_reason: str | None
    contact_masked: str | None


class IntakeHoldOut(BaseModel):
    reason: str
    label: str
    blocking: bool


class IntakeRiskOut(BaseModel):
    origin: Literal["SOURCE_ASSIGNED"]
    band_code: str
    status: str
    source_original_value: str
    assessment_id: uuid.UUID | None


class IntakeCaseOut(BaseModel):
    case_id: uuid.UUID | None
    case_ref: str | None
    state: str
    obligation_type: str
    source_request_ref: str
    due_at: datetime
    priority: int
    callable: bool


class IntakeOutcome(BaseModel):
    mode: Literal["PREVIEW", "COMMITTED"]
    replayed: bool = False
    run_id: uuid.UUID | None = None
    run_ref: str | None = None
    payload_digest: str
    source_system: str
    source_event_id: str
    policy: IntakePolicyOut
    sale_ref: str
    sale_event_id: uuid.UUID | None
    parties: list[IntakePartyOut]
    eligibility: list[IntakeEligibilityOut]
    risk: IntakeRiskOut | None
    risk_note: str | None
    case: IntakeCaseOut
    holds: list[IntakeHoldOut]
    script_routing: Literal["NOT_EVALUATED_IN_S0"] = "NOT_EVALUATED_IN_S0"
    compliance_outcome: Literal["NOT_EVALUATED_IN_S0"] = "NOT_EVALUATED_IN_S0"
    routes: dict[str, str] = Field(default_factory=dict)


class IntakeSource(BaseModel):
    source_type: Literal["MANUAL", "MOCK_API", "BULK", "INTERNAL_API"]
    available: bool
    note: str


class IntakeSourceList(BaseModel):
    items: list[IntakeSource]
    data_policy: str


class IntakeCounts(BaseModel):
    received: int
    new: int
    updated: int
    unchanged: int
    rejected: int
    quarantined: int


class IntakeRunRow(BaseModel):
    id: uuid.UUID
    run_ref: str
    source_type: str
    source_system: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    requested_by: str
    counts: IntakeCounts
    payload_digest: str


class IntakeRunList(BaseModel):
    items: list[IntakeRunRow]
    total: int


class IntakeItemOut(BaseModel):
    id: uuid.UUID
    source_system: str
    source_event_id: str
    entity_type: str
    status: str
    errors: list[dict[str, Any]]
    payload_digest: str


class IntakeRunDetail(IntakeRunRow):
    items: list[IntakeItemOut]
    result: dict[str, Any]


# ---- CP0.4b reference data for the Manual Intake screen (API-087) --------------------------------------------
class IntakeProductOption(BaseModel):
    product_code: str
    product_family: str
    product_subtype: str


class IntakeFscOption(BaseModel):
    fsc_ref: str
    display_name: str
    channel: str


class IntakeBandOption(BaseModel):
    code: str
    label: str


class IntakeContactFormat(BaseModel):
    channel: str
    code: str
    label: str
    pattern: str
    example: str


class IntakeReference(BaseModel):
    """Values the intake API accepts, read from the same sources the validator uses (no new rules)."""

    market_code: str
    currency: str
    data_policy: str
    source_system_prefix: str
    reserved_source_systems: list[str]
    products: list[IntakeProductOption]
    fscs: list[IntakeFscOption]
    risk_bands: list[IntakeBandOption]
    risk_band_list_version: str
    contact_formats: list[IntakeContactFormat]
    enums: dict[str, list[str]]
    priority_min: int
    priority_max: int
