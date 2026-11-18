"""Voice Lab API (S1-E.1): playground sessions, prompt versions, golden datasets, mock experiments, results, session
history, budgets and the kill switch.

Permissions: ``voicelab.use`` (USER, S&C checker) for the lab; ``voicelab.manage`` (ADMIN) for budgets, the kill switch
and spend authorisation of another user's metered experiment. Reads accept either. Writes are CSRF-protected,
rate-limited and audited (``LAB.*``). Every cost decision is made by ``app.voice.lab_cost`` on the server: paid
providers are refused, metered work reserves its estimated maximum first, and nothing runs while the kill switch is
engaged. Opening the lab connects to nothing; only Start (the mock) opens a local WebSocket.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import secrets
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import ErrorResponse
from app.api.voice import CREDENTIAL_TTL, MAX_FRAME_BYTES, SessionRegistry, VoiceSession
from app.audit.chain import RequestMeta, write_audit
from app.core.errors import AppError
from app.security import csrf
from app.security.authz import AuthContext, authenticate, get_db, request_meta, require, resolve_auth
from app.voice import gpt_live, lab
from app.voice import lab_cost as lc
from app.voice import live_providers as lp
from app.voice.media import _wav_header
from app.voice.mock import MockVoiceProvider
from app.voice.provider import FRAME_MS, SAMPLE_RATE, Inbound, SessionStats

router = APIRouter(prefix="/api/v1", tags=["voice-lab"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
log = logging.getLogger("call360.voicelab")
USE, MANAGE = "voicelab.use", "voicelab.manage"
AUTH_TIMEOUT_S = 5
NOTE = (
    "Voice Lab: synthetic experiments only — never real customers, policies or calls. Records are isolated from "
    "operational cases, KPIs and compliance. Paid providers are disabled; the mock provider costs nothing; the metered "
    "mock uses synthetic rates and spends no money."
)


class _M(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- schemas -----------------------------------------------------------------------------------------------------
class LabProviderOut(_M):
    code: str
    label: str
    spend_class: str
    available: bool
    reason: str
    models: list[str]
    voices: list[str]
    rate_card: dict[str, Any]
    network: bool
    vendor: str | None = None
    preferred: bool = False
    hidden: bool = False


class LabUsage(_M):
    overall: Decimal
    daily: Decimal
    held: Decimal
    reconciled: Decimal
    active: int
    reservations: int


class LabBudgetOut(_M):
    spend_class: str
    overall_usd: Decimal
    daily_usd: Decimal
    per_experiment_usd: Decimal
    max_concurrent_sessions: int
    interactive_max_s: int
    idle_timeout_s: int
    basis: str
    updated_by: str | None
    updated_at: datetime | None
    row_version: int
    usage: LabUsage | None = None


class LabControlOut(_M):
    kill_switch: bool
    kill_reason: str | None
    paid_enabled: bool
    retries_enabled: bool
    scheduling_enabled: bool
    updated_by: str | None
    updated_at: datetime | None
    row_version: int


class LabPaidSpend(_M):
    paid_reservations: int
    paid_usd: Decimal
    paid_sessions: int
    paid_experiments: int


class LabConfigChange(_M):
    target: str
    before: dict[str, Any]
    after: dict[str, Any]
    reason: str
    created_by: str
    created_at: datetime


class LabPaidAuthorisationOut(_M):
    id: uuid.UUID
    authorisation_ref: str
    provider: str
    model: str
    voice: str
    max_sessions: int
    max_duration_s: int
    max_usd: Decimal
    rate_card: dict[str, Any]
    reason: str
    status: str
    expires_at: datetime
    authorised_by: str
    authorised_at: datetime
    consumed_by: str | None
    consumed_at: datetime | None
    consumed_session_ref: str | None
    revoked_by: str | None
    revoked_at: datetime | None
    revoke_reason: str | None


class LabGptLiveConfig(_M):
    mode: str
    api_key_configured: bool
    endpoint_host: str
    mock_endpoint_configured: bool
    mock_profile: str
    close_timeout_s: float
    protocol_notes: str


class LabAzureConfig(_M):
    mode: str
    endpoint_host: str | None
    deployment: str | None
    auth: str
    credential_configured: bool
    entra_available: bool
    entra_scope: str
    audio_rate: int
    deployment_type: str | None
    region: str | None
    price_usd_per_min: Decimal | None
    price_source: str | None
    price_verified_on: str | None
    missing: list[str]


class LabSettingsOut(_M):
    control: LabControlOut
    budgets: list[LabBudgetOut]
    providers: list[LabProviderOut]
    paid_spend: LabPaidSpend
    history: list[LabConfigChange]
    authorisations: list[LabPaidAuthorisationOut]
    gpt_live: LabGptLiveConfig
    azure: LabAzureConfig
    retention_hours: int
    recording_available: bool
    transcription_available: bool
    mock_message: list[str]
    can_manage: bool
    note: str


class LabBudgetIn(BaseModel):
    expected_row_version: int
    overall_usd: Decimal = Field(gt=0, le=1000)
    daily_usd: Decimal = Field(gt=0, le=1000)
    per_experiment_usd: Decimal = Field(gt=0, le=1000)
    max_concurrent_sessions: int = Field(ge=1, le=4)
    interactive_max_s: int = Field(ge=5, le=300)
    idle_timeout_s: int = Field(ge=2, le=60)
    reason: str = Field(min_length=5, max_length=500)


class LabKillSwitchIn(BaseModel):
    engaged: bool
    reason: str = Field(min_length=5, max_length=500)


class LabPromptIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    system_prompt: str = Field(min_length=1, max_length=20000)
    turn_instructions: list[str] = Field(default_factory=list, max_length=20)
    provider: str = Field(max_length=32)
    model: str = Field(min_length=1, max_length=80)
    voice: str = Field(min_length=1, max_length=80)
    parameters: dict[str, Any] = Field(default_factory=dict)
    change_note: str | None = Field(None, max_length=500)
    expected_version: int | None = None


class LabPromptVersionOut(_M):
    id: uuid.UUID
    version_no: int
    system_prompt: str
    turn_instructions: list[str]
    provider: str
    model: str
    voice: str
    parameters: dict[str, Any]
    change_note: str
    sha256: str
    created_by: str
    created_at: datetime


class LabPromptOut(_M):
    id: uuid.UUID
    prompt_ref: str
    name: str
    created_by: str
    created_at: datetime
    versions: list[LabPromptVersionOut]


class LabPromptList(_M):
    items: list[LabPromptOut]


class LabDatasetIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field("", max_length=1000)


class LabCaseIn(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field("", max_length=1000)
    system_prompt: str = Field("", max_length=20000)
    test_instruction: str = Field("", max_length=2000)
    expected_statement: str = Field(min_length=1, max_length=2000)
    customer_response: str = Field("", max_length=2000)
    expected_answer: dict[str, str | int] = Field(default_factory=dict)
    expected_behaviour: str = Field("", max_length=2000)
    criteria: dict[str, Any] = Field(default_factory=dict)
    mock_output: str | None = Field(None, max_length=2000)
    audio_wav_b64: str | None = Field(None, max_length=1_400_000)
    keep_audio: bool = True
    retired: bool = False
    change_note: str | None = Field(None, max_length=500)
    expected_revision: int | None = None


class LabCaseOut(_M):
    id: uuid.UUID
    test_case_id: uuid.UUID
    case_ref: str
    revision: int
    revisions: int | None = None
    name: str
    description: str
    system_prompt: str
    test_instruction: str
    expected_statement: str
    customer_response: str
    expected_answer: dict[str, Any]
    expected_behaviour: str
    criteria: dict[str, Any]
    mock_output: str | None
    audio_sha256: str | None
    audio_samples: int | None
    source: dict[str, Any]
    retired: bool
    change_note: str
    created_by: str
    created_at: datetime


class LabCaseHistory(_M):
    items: list[LabCaseOut]


class LabDatasetOut(_M):
    id: uuid.UUID
    dataset_ref: str
    name: str
    description: str
    created_by: str
    created_at: datetime
    cases: list[LabCaseOut]


class LabDatasetList(_M):
    items: list[LabDatasetOut]


class LabImportIn(BaseModel):
    script_version_id: uuid.UUID
    question_codes: list[str] | None = Field(None, max_length=100)


class LabScriptSource(_M):
    id: uuid.UUID
    family: str
    version_label: str
    status: str
    questions: int


class LabScriptSourceList(_M):
    items: list[LabScriptSource]


class LabSessionIn(BaseModel):
    prompt_version_id: uuid.UUID
    record: bool = False


class LabSessionEvent(_M):
    seq: int
    event_type: str
    source: str
    offset_ms: int
    details: dict[str, Any]
    occurred_at: datetime


class LabMedia(_M):
    track: str
    samples: int
    sha256: str
    basis: str
    purged_at: datetime | None = None


class LabTranscriptOut(_M):
    track: str
    engine: str
    text: str
    words: list[dict[str, Any]]
    created_at: datetime
    source: str = "INDEPENDENT_ASR"
    purged_at: datetime | None = None


class LabSessionOut(_M):
    id: uuid.UUID
    session_ref: str
    mode: str
    prompt_ref: str | None
    prompt_name: str | None
    prompt_version_no: int | None
    experiment_ref: str | None
    provider: str
    model: str
    voice: str
    spend_class: str
    rate_card: dict[str, Any]
    status: str
    record: bool
    max_duration_s: int
    idle_timeout_s: int
    estimated_max_usd: Decimal
    reconciled_usd: Decimal | None
    reservation_status: str | None
    reserved_usd: Decimal | None
    started_at: datetime | None
    ended_at: datetime | None
    end_reason: str | None
    metrics: dict[str, Any]
    transcript_status: str
    termination_status: str
    provider_session_id: str | None
    provider_usage_seconds: Decimal | None
    usage_source: str | None
    authorisation_ref: str | None
    created_by: str
    created_at: datetime
    media: list[LabMedia]
    transcripts: list[LabTranscriptOut]
    events: list[LabSessionEvent]


class LabSessionStart(LabSessionOut):
    credential: str
    stream_path: str
    sample_rate: int
    recording_consent: Literal["DECLINED"] = "DECLINED"  # the lab records on the server (``record``), not the browser


class LabSessionList(_M):
    items: list[LabSessionOut]


class LabExperimentIn(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    dataset_id: uuid.UUID
    prompt_version_id: uuid.UUID
    case_revision_ids: list[uuid.UUID] | None = Field(None, max_length=50)
    repetitions: int = Field(1, ge=1, le=5)
    max_duration_s: int = Field(30, ge=5, le=120)
    max_spend_usd: Decimal = Field(ge=0, le=1000)


class LabAuthoriseIn(BaseModel):
    confirm_usd: Decimal
    reason: str = Field(min_length=5, max_length=500)


class LabTrialOut(_M):
    id: uuid.UUID
    case_ref: str
    case_name: str
    case_revision: int
    test_case_revision_id: uuid.UUID
    repetition: int
    status: str
    verdict: str
    session_ref: str | None
    expected_statement: str
    expected_behaviour: str
    has_audio: bool
    provider_text: str | None
    heard_text: str | None
    extracted_answer: dict[str, Any] | None
    metrics: dict[str, Any]
    checks: list[dict[str, Any]]
    failure: str | None
    cost_usd: Decimal
    started_at: datetime
    finished_at: datetime
    speech_result: str | None = None
    assessments: list[dict[str, Any]] = []


class LabExperimentOut(_M):
    id: uuid.UUID
    experiment_ref: str
    name: str
    dataset_id: uuid.UUID
    dataset_ref: str
    dataset_name: str
    prompt_ref: str
    prompt_version_no: int
    prompt_version_id: uuid.UUID
    provider: str
    model: str
    voice: str
    spend_class: str
    case_revision_ids: list[str]
    repetitions: int
    max_duration_s: int
    max_spend_usd: Decimal
    estimated_max_usd: Decimal
    rate_card: dict[str, Any]
    status: str
    authorised_by: str | None
    authorised_at: datetime | None
    authorisation_reason: str | None
    authorised_usd: Decimal | None
    reservation_status: str | None
    reserved_usd: Decimal | None
    started_at: datetime | None
    finished_at: datetime | None
    actual_usd: Decimal | None
    summary: dict[str, Any]
    end_reason: str | None
    created_by: str
    created_at: datetime
    trials: list[LabTrialOut]


class LabExperimentList(_M):
    items: list[LabExperimentOut]


class LabPaidSwitchIn(BaseModel):
    enabled: bool
    reason: str = Field(min_length=5, max_length=500)


class LabPaidAuthorisationIn(BaseModel):
    provider: Literal["AZURE_OPENAI_GPT_LIVE", "OPENAI_GPT_LIVE"] = "AZURE_OPENAI_GPT_LIVE"
    model: str = Field(min_length=1, max_length=80)  # Azure: the deployment name; OpenAI: gpt-live-1
    voice: str = Field("marin", max_length=80)
    max_duration_s: int = Field(120, ge=10, le=120)
    expires_in_h: int = Field(24, ge=1, le=72)
    reason: str = Field(min_length=5, max_length=500)


class LabRevokeIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class LabResolveUsageIn(BaseModel):
    usage_seconds: float = Field(ge=0, le=86400)
    source: Literal["PROVIDER_USAGE_DASHBOARD", "PROVIDER_SUPPORT_CONFIRMATION"]
    reason: str = Field(min_length=5, max_length=500)


class LabAssessmentIn(BaseModel):
    result: Literal["CONFIRMED_AS_EXPECTED", "CONFIRMED_DEVIATION", "INCONCLUSIVE"]
    notes: str = Field(min_length=5, max_length=1000)
    listened: bool


# ---- helpers -----------------------------------------------------------------------------------------------------
def _reader(request: Request, auth: AuthContext = Depends(authenticate)) -> AuthContext:
    if auth.password_change_required:
        raise AppError(403, "PASSWORD_CHANGE_REQUIRED", "Set your own password before continuing")
    if USE not in auth.permissions and MANAGE not in auth.permissions:
        with request.app.state.session_factory() as db, db.begin():
            write_audit(
                db,
                action="ACCESS.DENIED_FUNCTION",
                outcome="DENIED",
                actor=auth.actor,
                meta=request_meta(request),
                entity_type="route",
                entity_id=request.url.path[:64],
            )
        raise AppError(403, "FORBIDDEN", "You do not have permission for this action")
    return auth


_reader.required_permission = f"{USE} | {MANAGE}"  # type: ignore[attr-defined]  # BE-SEC-01 route inventory


def _guard(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(f"voicelab:{auth.principal_id}", settings.script_writes_per_minute):
        raise AppError(429, "RATE_LIMITED", "Too many Voice Lab changes; try again shortly", retryable=True)


def _err(exc: lab.LabError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=[{"message": d} for d in exc.details] or None)


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    entity: str | None,
    *,
    outcome: str = "SUCCEEDED",
    reason: str | None = None,
    **after: Any,
) -> None:
    write_audit(
        db,
        action=f"LAB.{action}"[:64],
        outcome=outcome,
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="voice_lab",
        entity_id=entity,
        after=json.loads(json.dumps(after, default=str)),
        reason=reason,
    )


def _refused(request: Request, auth: AuthContext, action: str, exc: lab.LabError, **after: Any) -> AppError:
    with request.app.state.session_factory() as db, db.begin():
        _audit(db, request, auth, action, None, outcome="DENIED", code=exc.code, reasons=exc.details, **after)
    return _err(exc)


def _recording_ok(app: Any) -> bool:
    return lab.store_for(app) is not None


def registry(app: Any) -> SessionRegistry:
    """Lab credentials and live connections (the S1-A registry; ``case_id`` carries the lab session id — a lab session
    belongs to no case)."""
    if not hasattr(app.state, "lab_sessions"):
        app.state.lab_sessions = SessionRegistry()
    reg: SessionRegistry = app.state.lab_sessions
    return reg


def stop_live(app: Any) -> int:
    reg = registry(app)
    return sum(reg.signal_stop(k) for k in list(reg.live))


# ---- settings, budgets, kill switch ------------------------------------------------------------------------------
@router.get("/voice-lab/settings", response_model=LabSettingsOut, operation_id="voicelab_settings", responses=_ERR)
def get_settings(
    request: Request, auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)
) -> LabSettingsOut:
    st = request.app.state.settings
    s = lab.lab_settings(db, st)
    db.commit()  # expired authorisations are marked EXPIRED
    return LabSettingsOut(
        **s,
        gpt_live=LabGptLiveConfig(
            mode=st.voice_lab_gpt_live_mode,
            api_key_configured=st.voice_lab_openai_api_key is not None,
            endpoint_host=urlparse(st.voice_lab_gpt_live_url).hostname or "",
            mock_endpoint_configured=bool(st.voice_lab_gpt_live_mock_url),
            mock_profile=st.voice_lab_gpt_live_mock_profile,
            close_timeout_s=st.voice_lab_close_timeout_s,
            protocol_notes="Call360-specs/docs/integrations/GPT_LIVE_PROTOCOL_NOTES.md",
        ),
        retention_hours=st.recording_retention_hours,
        azure=LabAzureConfig(
            mode=st.voice_lab_azure_gpt_live_mode,
            endpoint_host=urlparse(lp.azure_url(st.voice_lab_azure_openai_endpoint)).hostname
            if st.voice_lab_azure_openai_endpoint
            else None,
            deployment=st.voice_lab_azure_openai_deployment,
            auth=st.voice_lab_azure_auth,
            credential_configured=st.voice_lab_azure_openai_api_key is not None
            if st.voice_lab_azure_auth == "API_KEY"
            else lp.entra_available(),
            entra_available=lp.entra_available(),
            entra_scope=st.voice_lab_azure_entra_scope,
            audio_rate=st.voice_lab_azure_audio_rate,
            deployment_type=st.voice_lab_azure_deployment_type,
            region=st.voice_lab_azure_region,
            price_usd_per_min=st.voice_lab_azure_price_usd_per_min,
            price_source=st.voice_lab_azure_price_source,
            price_verified_on=st.voice_lab_azure_price_verified_on,
            missing=lp.azure_missing(st)
            + ([] if st.voice_lab_azure_price_usd_per_min is not None else ["no verified Azure price"]),
        ),
        recording_available=_recording_ok(request.app),
        transcription_available=request.app.state.settings.transcription_model_dir is not None,
        mock_message=lab.mock_message(),
        can_manage=MANAGE in auth.permissions,
        note=NOTE,
    )


@router.put(
    "/voice-lab/budgets/{spend_class}",
    response_model=LabBudgetOut,
    operation_id="voicelab_budget_update",
    responses=_ERR,
)
@csrf_protected
def update_budget(
    spend_class: Literal["SIMULATED", "PAID"],
    body: LabBudgetIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabBudgetOut:
    _guard(request, auth)
    try:
        b = lab.update_budget(db, str(auth.principal_id), spend_class, body.model_dump(), body.reason)
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "BUDGET_UPDATED",
        spend_class,
        reason=body.reason,
        **body.model_dump(exclude={"reason", "expected_row_version"}),
    )
    db.commit()
    return LabBudgetOut(**b)


@router.post(
    "/voice-lab/kill-switch", response_model=LabControlOut, operation_id="voicelab_kill_switch", responses=_ERR
)
@csrf_protected
def kill_switch(
    body: LabKillSwitchIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabControlOut:
    """Engage: refuse every new session and experiment, stop live sessions now and running experiments before their
    next trial. Release: allow new work again (both audited with a reason)."""
    _guard(request, auth)
    c = lab.set_kill_switch(db, str(auth.principal_id), body.engaged, body.reason)
    _audit(
        db, request, auth, "KILL_SWITCH_ENGAGED" if body.engaged else "KILL_SWITCH_RELEASED", None, reason=body.reason
    )
    db.commit()
    if body.engaged:
        stopped = stop_live(request.app)
        log.warning("voice lab kill switch engaged; %d live session(s) stopped", stopped)
    return LabControlOut(**c)


# ---- prompts -----------------------------------------------------------------------------------------------------
@router.get("/voice-lab/prompts", response_model=LabPromptList, operation_id="voicelab_prompts", responses=_ERR)
def list_prompts(auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)) -> LabPromptList:
    return LabPromptList(items=[LabPromptOut(**p) for p in lab.prompts(db)])


@router.post(
    "/voice-lab/prompts",
    response_model=LabPromptOut,
    status_code=201,
    operation_id="voicelab_prompt_create",
    responses=_ERR,
)
@csrf_protected
def create_prompt(
    body: LabPromptIn, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabPromptOut:
    _guard(request, auth)
    try:
        p = lab.save_prompt(db, str(auth.principal_id), body.model_dump())
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "PROMPT_CREATED", p["prompt_ref"], version=1, sha256=p["latest"]["sha256"])
    db.commit()
    return LabPromptOut(**p)


@router.post(
    "/voice-lab/prompts/{prompt_id}/versions",
    response_model=LabPromptOut,
    operation_id="voicelab_prompt_version",
    responses=_ERR,
)
@csrf_protected
def new_prompt_version(
    prompt_id: uuid.UUID,
    body: LabPromptIn,
    request: Request,
    auth: AuthContext = Depends(require(USE)),
    db: Session = Depends(get_db),
) -> LabPromptOut:
    _guard(request, auth)
    try:
        p = lab.save_prompt(db, str(auth.principal_id), body.model_dump(), prompt_id)
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "PROMPT_VERSIONED",
        p["prompt_ref"],
        version=p["latest"]["version_no"],
        sha256=p["latest"]["sha256"],
    )
    db.commit()
    return LabPromptOut(**p)


# ---- datasets ----------------------------------------------------------------------------------------------------
@router.get("/voice-lab/datasets", response_model=LabDatasetList, operation_id="voicelab_datasets", responses=_ERR)
def list_datasets(auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)) -> LabDatasetList:
    return LabDatasetList(items=[LabDatasetOut(**d) for d in lab.datasets(db)])


@router.post(
    "/voice-lab/datasets",
    response_model=LabDatasetOut,
    status_code=201,
    operation_id="voicelab_dataset_create",
    responses=_ERR,
)
@csrf_protected
def create_dataset(
    body: LabDatasetIn, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabDatasetOut:
    _guard(request, auth)
    d = lab.create_dataset(db, str(auth.principal_id), body.name, body.description)
    _audit(db, request, auth, "DATASET_CREATED", d["dataset_ref"])
    db.commit()
    return LabDatasetOut(**d)


@router.post(
    "/voice-lab/datasets/{dataset_id}/cases",
    response_model=LabCaseOut,
    status_code=201,
    operation_id="voicelab_case_create",
    responses=_ERR,
)
@csrf_protected
def create_case(
    dataset_id: uuid.UUID,
    body: LabCaseIn,
    request: Request,
    auth: AuthContext = Depends(require(USE)),
    db: Session = Depends(get_db),
) -> LabCaseOut:
    _guard(request, auth)
    try:
        c = lab.save_case(db, lab.store_for(request.app), str(auth.principal_id), dataset_id, body.model_dump())
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "TEST_CASE_CREATED", c["case_ref"], revision=1, audio=c["audio_sha256"])
    db.commit()
    return LabCaseOut(**c)


@router.post(
    "/voice-lab/datasets/{dataset_id}/cases/{test_case_id}/revisions",
    response_model=LabCaseOut,
    operation_id="voicelab_case_revise",
    responses=_ERR,
)
@csrf_protected
def revise_case(
    dataset_id: uuid.UUID,
    test_case_id: uuid.UUID,
    body: LabCaseIn,
    request: Request,
    auth: AuthContext = Depends(require(USE)),
    db: Session = Depends(get_db),
) -> LabCaseOut:
    _guard(request, auth)
    try:
        c = lab.save_case(
            db, lab.store_for(request.app), str(auth.principal_id), dataset_id, body.model_dump(), test_case_id
        )
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "TEST_CASE_REVISED", c["case_ref"], revision=c["revision"])
    db.commit()
    return LabCaseOut(**c)


@router.get(
    "/voice-lab/test-cases/{test_case_id}/revisions",
    response_model=LabCaseHistory,
    operation_id="voicelab_case_history",
    responses=_ERR,
)
def case_history(
    test_case_id: uuid.UUID, auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)
) -> LabCaseHistory:
    items = lab.case_history(db, test_case_id)
    if not items:
        raise AppError(404, "NOT_FOUND", "Test case not found")
    return LabCaseHistory(items=[LabCaseOut(**r) for r in items])


@router.get(
    "/voice-lab/script-sources",
    response_model=LabScriptSourceList,
    operation_id="voicelab_script_sources",
    responses=_ERR,
)
def script_sources(auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)) -> LabScriptSourceList:
    """Script Studio versions whose synthetic questions and statements can be imported (read-only)."""
    rows = db.execute(
        text(
            "SELECT v.id, f.code AS family, v.version_label, v.status, (SELECT count(*) FROM script_section ss JOIN "
            "module_question mq ON mq.script_module_id = ss.script_module_id WHERE ss.script_version_id = v.id) AS "
            "questions FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
            "WHERE f.market_code = ANY(:m) ORDER BY f.code, v.version_label DESC LIMIT 200"
        ),
        {"m": sorted(auth.markets)},
    ).mappings()
    return LabScriptSourceList(items=[LabScriptSource(**r) for r in rows if r["questions"]])


@router.post(
    "/voice-lab/datasets/{dataset_id}/import-script",
    response_model=LabCaseHistory,
    operation_id="voicelab_import_script",
    responses=_ERR,
)
@csrf_protected
def import_script(
    dataset_id: uuid.UUID,
    body: LabImportIn,
    request: Request,
    auth: AuthContext = Depends(require(USE)),
    db: Session = Depends(get_db),
) -> LabCaseHistory:
    _guard(request, auth)
    market = db.execute(
        text(
            "SELECT f.market_code FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
            "WHERE v.id = :v"
        ),
        {"v": body.script_version_id},
    ).scalar()
    if market not in auth.markets:
        raise AppError(404, "NOT_FOUND", "Script version not found")
    try:
        out = lab.import_from_script(
            db, str(auth.principal_id), dataset_id, body.script_version_id, body.question_codes
        )
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "SCRIPT_IMPORTED",
        str(dataset_id),
        script_version=str(body.script_version_id),
        cases=[c["case_ref"] for c in out],
    )
    db.commit()
    return LabCaseHistory(items=[LabCaseOut(**c) for c in out])


def _wav(pcm: bytes | None) -> Response:
    if pcm is None:
        raise AppError(404, "AUDIO_NOT_AVAILABLE", "No audio is available")
    return Response(_wav_header(len(pcm)) + pcm, media_type="audio/wav", headers={"Cache-Control": "no-store"})


@router.get(
    "/voice-lab/test-case-revisions/{revision_id}/audio",
    operation_id="voicelab_case_audio",
    response_class=Response,
    responses={200: {"content": {"audio/wav": {}}}, **_ERR},
)
def case_audio(
    revision_id: uuid.UUID, request: Request, auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)
) -> Response:
    try:
        return _wav(lab.fixture_audio(db, lab.store_for(request.app), revision_id))
    except lab.LabError as exc:
        raise _err(exc) from exc


# ---- sessions ----------------------------------------------------------------------------------------------------
@router.post(
    "/voice-lab/sessions",
    response_model=LabSessionStart,
    status_code=201,
    operation_id="voicelab_session_create",
    responses=_ERR,
)
@csrf_protected
def create_session(
    body: LabSessionIn, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabSessionStart:
    """Create a playground session after every cost control passes; returns a single-use 60 s credential for the
    local WebSocket. Paid providers, unknown costs, exhausted budgets, concurrency and the kill switch are refused."""
    _guard(request, auth)
    try:
        s = lab.create_session(
            db,
            str(auth.principal_id),
            body.prompt_version_id,
            record=body.record,
            recording_available=_recording_ok(request.app),
            settings=request.app.state.settings,
        )
    except lab.LabError as exc:
        db.rollback()
        raise _refused(request, auth, "SESSION_REFUSED", exc, prompt_version=str(body.prompt_version_id)) from exc
    _audit(
        db,
        request,
        auth,
        "SESSION_CREATED",
        s["session_ref"],
        provider=s["provider"],
        estimated_max_usd=s["estimated_max_usd"],
        record=body.record,
    )
    db.commit()
    credential = secrets.token_urlsafe(32)
    import hashlib

    registry(request.app).add(
        VoiceSession(
            attempt_id=s["id"],
            case_id=s["id"],
            case_ref=s["session_ref"],
            principal_id=auth.principal_id,
            credential_hash=hashlib.sha256(credential.encode()).hexdigest(),
            credential_expires_at=datetime.now(UTC) + CREDENTIAL_TTL,
        )
    )
    return LabSessionStart(
        **s, credential=credential, stream_path=f"/api/v1/voice-lab/sessions/{s['id']}/stream", sample_rate=SAMPLE_RATE
    )


@router.get("/voice-lab/sessions", response_model=LabSessionList, operation_id="voicelab_sessions", responses=_ERR)
def list_sessions(auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)) -> LabSessionList:
    return LabSessionList(items=[LabSessionOut(**s) for s in lab.sessions(db)])


@router.get(
    "/voice-lab/sessions/{session_id}", response_model=LabSessionOut, operation_id="voicelab_session", responses=_ERR
)
def get_session(
    session_id: uuid.UUID, auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)
) -> LabSessionOut:
    try:
        return LabSessionOut(**lab.session(db, session_id))
    except lab.LabError as exc:
        raise _err(exc) from exc


@router.post(
    "/voice-lab/sessions/{session_id}/stop",
    response_model=LabSessionOut,
    operation_id="voicelab_session_stop",
    responses=_ERR,
)
@csrf_protected
def stop_session(
    session_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabSessionOut:
    """Idempotent: stops a live connection, or ends a session that never connected (releasing its reservation)."""
    _guard(request, auth)
    try:
        s = lab.session(db, session_id, events=False)
    except lab.LabError as exc:
        raise _err(exc) from exc
    if s["created_by"] != str(auth.principal_id):
        raise AppError(403, "FORBIDDEN", "Only the session's owner can stop it")
    if not registry(request.app).signal_stop(session_id) and s["status"] == "CREATED":
        lab.finish_session(db, session_id, reason="STOPPED_BEFORE_CONNECT", metrics={})
        db.commit()
    return LabSessionOut(**lab.session(db, session_id))


@router.get(
    "/voice-lab/sessions/{session_id}/audio/{track}",
    operation_id="voicelab_session_audio",
    response_class=Response,
    responses={200: {"content": {"audio/wav": {}}}, **_ERR},
)
def session_audio(
    session_id: uuid.UUID,
    track: Literal["MIC", "PROVIDER_PLAYBACK"],
    request: Request,
    auth: AuthContext = Depends(_reader),
    db: Session = Depends(get_db),
) -> Response:
    return _wav(lab.audio(db, lab.store_for(request.app), session_id, track))


# ---- experiments -------------------------------------------------------------------------------------------------
@router.post(
    "/voice-lab/experiments",
    response_model=LabExperimentOut,
    status_code=201,
    operation_id="voicelab_experiment_create",
    responses=_ERR,
)
@csrf_protected
def create_experiment(
    body: LabExperimentIn, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabExperimentOut:
    """Configure an experiment; the estimated maximum cost is computed and fixed now. Metered experiments wait for
    explicit spend authorisation by another user; free (mock) experiments are ready to run."""
    _guard(request, auth)
    try:
        e = lab.create_experiment(db, str(auth.principal_id), body.model_dump())
    except lab.LabError as exc:
        db.rollback()
        raise _refused(request, auth, "EXPERIMENT_REFUSED", exc, name=body.name) from exc
    _audit(
        db,
        request,
        auth,
        "EXPERIMENT_CREATED",
        e["experiment_ref"],
        estimated_max_usd=e["estimated_max_usd"],
        status=e["status"],
    )
    db.commit()
    return LabExperimentOut(**e)


@router.get(
    "/voice-lab/experiments", response_model=LabExperimentList, operation_id="voicelab_experiments", responses=_ERR
)
def list_experiments(auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)) -> LabExperimentList:
    return LabExperimentList(items=[LabExperimentOut(**e) for e in lab.experiments(db)])


@router.get(
    "/voice-lab/experiments/{experiment_id}",
    response_model=LabExperimentOut,
    operation_id="voicelab_experiment",
    responses=_ERR,
)
def get_experiment(
    experiment_id: uuid.UUID, auth: AuthContext = Depends(_reader), db: Session = Depends(get_db)
) -> LabExperimentOut:
    try:
        return LabExperimentOut(**lab.experiment(db, experiment_id))
    except lab.LabError as exc:
        raise _err(exc) from exc


@router.post(
    "/voice-lab/experiments/{experiment_id}/authorise",
    response_model=LabExperimentOut,
    operation_id="voicelab_experiment_authorise",
    responses=_ERR,
)
@csrf_protected
def authorise_experiment(
    experiment_id: uuid.UUID,
    body: LabAuthoriseIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabExperimentOut:
    """Explicit spend authorisation of a metered experiment: a different user confirms the exact estimated maximum."""
    _guard(request, auth)
    try:
        e = lab.authorise(db, str(auth.principal_id), experiment_id, body.reason, body.confirm_usd)
    except lab.LabError as exc:
        db.rollback()
        raise _refused(request, auth, "AUTHORISATION_REFUSED", exc, experiment=str(experiment_id)) from exc
    _audit(
        db,
        request,
        auth,
        "EXPERIMENT_AUTHORISED",
        e["experiment_ref"],
        authorised_usd=e["authorised_usd"],
        reason=body.reason,
    )
    db.commit()
    return LabExperimentOut(**e)


@router.post(
    "/voice-lab/experiments/{experiment_id}/run",
    response_model=LabExperimentOut,
    operation_id="voicelab_experiment_run",
    responses=_ERR,
)
@csrf_protected
def run_experiment(
    experiment_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require(USE)), db: Session = Depends(get_db)
) -> LabExperimentOut:
    """Reserve the estimated maximum and run every trial once in the background (never retried or scheduled)."""
    _guard(request, auth)
    try:
        e = lab.start_experiment(db, str(auth.principal_id), experiment_id)
    except lab.LabError as exc:
        db.rollback()
        raise _refused(request, auth, "EXPERIMENT_RUN_REFUSED", exc, experiment=str(experiment_id)) from exc
    _audit(db, request, auth, "EXPERIMENT_STARTED", e["experiment_ref"], reserved_usd=e["reserved_usd"])
    db.commit()
    lab.start_background(request.app, experiment_id)
    db.expire_all()
    return LabExperimentOut(**lab.experiment(db, experiment_id))


# ---- WebSocket ---------------------------------------------------------------------------------------------------
class _LabChannel:
    """The S1-A channel contract for the lab: idle timeout, kill switch / stop, server-side recording, latency
    measurement and the provider event trace (insert-only ``lab_session_event``)."""

    def __init__(
        self,
        ws: WebSocket,
        app: Any,
        sid: uuid.UUID,
        stop: asyncio.Event,
        idle_s: int,
        instructions: list[str],
        recorder: lab.LabRecorder | None,
    ) -> None:
        self.ws, self.app, self.sid, self.stop, self.idle_s = ws, app, sid, stop, idle_s
        self.instructions, self.recorder = instructions, recorder
        self.lock = asyncio.Lock()
        self.t0 = time.monotonic()
        self.last_activity = self.t0
        self.arrivals: collections.deque[float] = collections.deque(maxlen=8)
        self.first_audio_ms: int | None = None
        self.barge_latencies: list[int] = []
        self.frames_out = 0
        self.agent_speaking = False
        self.provider_kind = "MOCK"

    def _ms(self, t: float | None = None) -> int:
        return int(((t or time.monotonic()) - self.t0) * 1000)

    def _persist(self, event_type: str, source: str, details: dict[str, Any]) -> None:
        with self.app.state.session_factory() as db, db.begin():
            lab.append_event(db, self.sid, event_type, source=source, offset_ms=self._ms(), details=details)

    async def trace(self, event_type: str, source: str = "PROVIDER", **details: Any) -> None:
        await asyncio.to_thread(self._persist, event_type, source, details)

    async def receive(self) -> Inbound | None:
        while True:
            idle_left = self.idle_s - (time.monotonic() - self.last_activity)
            if idle_left <= 0 and not self.agent_speaking:
                return Inbound(event={"type": "session.stop", "reason": "IDLE_TIMEOUT"})
            recv = asyncio.ensure_future(self.ws.receive())
            stopper = asyncio.ensure_future(self.stop.wait())
            done, _ = await asyncio.wait(
                {recv, stopper}, timeout=max(0.5, idle_left), return_when=asyncio.FIRST_COMPLETED
            )
            if stopper in done:
                recv.cancel()
                return Inbound(event={"type": "session.stop", "reason": self.stop_reason()})
            stopper.cancel()
            if recv not in done:
                recv.cancel()
                continue  # re-check the idle window
            msg = recv.result()
            if msg.get("type") == "websocket.disconnect":
                return None
            if msg.get("bytes") is not None:
                data: bytes = msg["bytes"]
                if len(data) > MAX_FRAME_BYTES or len(data) % 2:
                    continue
                self.arrivals.append(time.monotonic())
                if self.recorder is not None:
                    self.recorder.on_mic(data)
                return Inbound(audio=data)
            try:
                event = json.loads(msg.get("text") or "{}")
            except ValueError:
                continue
            kind = event.get("type") if isinstance(event, dict) else None
            if kind == "session.stop":
                await self.trace("STOP_REQUESTED", "CLIENT")
                return Inbound(event={"type": "session.stop", "reason": "STOPPED_BY_USER"})
            if kind == "input.mute":
                await self.trace("MIC_MUTED" if event.get("muted") else "MIC_UNMUTED", "CLIENT")
                return Inbound(event={"type": "input.mute", "muted": bool(event.get("muted"))})
            if kind == "lab.instruction" and isinstance(event.get("text"), str) and event["text"].strip():
                await self.trace("PLAYGROUND_INSTRUCTION", "CLIENT", chars=len(event["text"]))
                return Inbound(event={"type": "lab.instruction", "text": event["text"][:1500]})

    def stop_reason(self) -> str:
        with self.app.state.session_factory() as db:
            return "KILL_SWITCH" if lc.control(db)["kill_switch"] else "STOPPED_BY_USER"

    async def send_audio(self, response: int, pcm: bytes) -> None:
        if self.first_audio_ms is None:
            self.first_audio_ms = self._ms()
            await self.trace("FIRST_AUDIO", first_audio_ms=self.first_audio_ms)
        self.frames_out += 1
        self.last_activity = time.monotonic()
        if self.recorder is not None:
            self.recorder.on_provider(pcm)
        async with self.lock:
            await self.ws.send_bytes(response.to_bytes(4, "little") + pcm)

    async def send_event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "response.started":
            self.agent_speaking = True
            n = int(event.get("response") or 0)
            instr = self.instructions[n - 1] if 0 < n <= len(self.instructions) else None
            await self.trace(
                "RESPONSE_STARTED",
                response=n,
                turn_instruction=instr,
                note=None
                if self.provider_kind == "GPT"
                else "The mock provider does not interpret prompts or instructions",
            )
        elif kind == "playback.clear":
            self.agent_speaking = False
            onset = self.arrivals[-5] if len(self.arrivals) >= 5 else (self.arrivals[0] if self.arrivals else None)
            latency = int((time.monotonic() - onset) * 1000) if onset else None
            if latency is not None:
                self.barge_latencies.append(latency)
            await self.trace(
                "BARGE_IN",
                response=event.get("response"),
                interruption_latency_ms=latency,
                basis="server: first frame of the speech onset → playback cleared",
            )
        elif kind == "response.done":
            self.agent_speaking = False
            self.last_activity = time.monotonic()
            await self.trace("RESPONSE_DONE", response=event.get("response"), completed=bool(event.get("completed")))
        elif kind in ("input.speech_started", "input.speech_stopped"):
            self.last_activity = time.monotonic()
            await self.trace("SPEECH_STARTED" if kind == "input.speech_started" else "SPEECH_STOPPED", "SERVER")
        async with self.lock:
            await self.ws.send_text(json.dumps(event))


@router.websocket("/voice-lab/sessions/{session_id}/stream")
async def lab_stream(websocket: WebSocket, session_id: uuid.UUID) -> None:
    app = websocket.app
    if websocket.headers.get("origin") not in set(app.state.settings.allowed_origins):
        await websocket.close(code=4403)
        return
    try:
        with app.state.session_factory() as db:
            auth = resolve_auth(app, websocket.cookies, db)
    except AppError:
        await websocket.close(code=4401)
        return
    if USE not in auth.permissions or auth.password_change_required:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    try:
        first = await asyncio.wait_for(websocket.receive_json(), timeout=AUTH_TIMEOUT_S)
    except (TimeoutError, ValueError, WebSocketDisconnect, RuntimeError):
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=4401)
        return
    credential = first.get("credential") if isinstance(first, dict) and first.get("type") == "session.auth" else None
    reg = registry(app)
    live = reg.claim(session_id, auth.principal_id, str(credential or ""))
    if live is None:
        await websocket.send_text(json.dumps({"type": "error", "code": "SESSION_CREDENTIAL_INVALID"}))
        await websocket.close(code=4401)
        return
    assert live.stop is not None

    def _connect() -> tuple[dict[str, Any], dict[str, Any], bool]:
        with app.state.session_factory() as db, db.begin():
            if lc.control(db)["kill_switch"]:
                raise lab.LabError(409, "KILL_SWITCH", "The Voice Lab emergency stop is engaged")
            s = lab.mark_live(db, session_id)
            pv = lab.prompt_version(db, s["prompt_version_id"])
            lab.append_event(
                db,
                session_id,
                "PROMPT_APPLIED",
                source="PROVIDER",
                details={
                    "prompt_sha256": pv["sha256"],
                    "system_prompt_chars": len(pv["system_prompt"]),
                    "turn_instructions": len(pv["turn_instructions"]),
                    "note": "Sent in session.start (GPT-Live)"
                    if s["provider"] in lab.GPT_PROVIDERS
                    else "The mock provider does not interpret prompts; it speaks the fixed synthetic test message",
                },
            )
            return s, pv, s["record"] and lab.store_for(app) is not None

    try:
        s, pv, record = await asyncio.to_thread(_connect)
    except lab.LabError as exc:
        reg.release(session_id)
        await websocket.send_text(json.dumps({"type": "error", "code": exc.code}))
        await websocket.close(code=4409)
        with app.state.session_factory() as db, db.begin():
            lab.finish_session(db, session_id, reason=exc.code, metrics={}, status="FAILED")
        return
    recorder = lab.LabRecorder() if record else None
    channel = _LabChannel(
        websocket, app, session_id, live.stop, s["idle_timeout_s"], list(pv["turn_instructions"]), recorder
    )
    stats = SessionStats()
    channel.provider_kind = "GPT" if s["provider"] in lab.GPT_PROVIDERS else "MOCK"
    gpt: gpt_live.GptLiveProvider | None = None
    provider: Any
    if s["provider"] in lab.GPT_PROVIDERS:
        gpt = await gpt_live_provider(app, s, pv)
        provider = gpt
        await channel.trace("PROVIDER_ENDPOINT", "SERVER", **gpt.endpoint_info)
    else:
        provider = MockVoiceProvider()
    try:
        await channel.send_event(
            {
                "type": "session.ready",
                "session_id": str(session_id),
                "provider": s["provider"],
                "sample_rate": SAMPLE_RATE,
                "frame_ms": FRAME_MS,
                "max_duration_s": s["max_duration_s"],
                "idle_timeout_s": s["idle_timeout_s"],
                "recording": {"state": "SERVER_RECORDING" if record else "NOT_RECORDED"},
                "resumed": False,
            }
        )
        # The GPT-Live adapter enforces the duration itself (and then closes the provider session); this outer timer
        # is a backstop that also covers the bounded close.
        backstop = s["max_duration_s"] + (app.state.settings.voice_lab_close_timeout_s + 15 if gpt else 0)
        try:
            await asyncio.wait_for(provider.run(channel, stats), timeout=backstop)
        except TimeoutError:
            stats.end_reason = "MAX_DURATION"
    except (WebSocketDisconnect, RuntimeError):
        stats.end_reason = "DISCONNECTED"
    finally:
        # Settling runs in its own task: when the browser vanishes, Starlette cancels this handler (and keeps
        # cancelling every await here), but the provider close, the reservation and the evidence must still be
        # completed.

        async def settle() -> None:
            reg.release(session_id)
            # The provider close may still be in progress (e.g. the browser vanished): wait for it, bounded.
            if gpt is not None:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(gpt.finished(), timeout=app.state.settings.voice_lab_close_timeout_s + 5)
            metrics = {
                "duration_ms": channel._ms(),
                "first_audio_ms": channel.first_audio_ms,
                "interruption_latency_ms": channel.barge_latencies,
                "interruptions": stats.barge_ins,
                "responses": stats.responses,
                "completed_responses": stats.completed_responses,
                "user_turns": stats.user_turns,
                "input_audio_s": round(stats.frames_in * FRAME_MS / 1000, 3),
                "output_audio_s": round(channel.frames_out * FRAME_MS / 1000, 3),
                "timing_basis": "server-measured; excludes network and browser buffering",
            }
            reason = stats.end_reason if stats.end_reason != "UNKNOWN" else "DISCONNECTED"
            outcome: dict[str, Any] | None = None
            if gpt is not None:
                o = gpt.outcome
                outcome = {
                    "termination": o.termination,
                    "usage_seconds": o.usage_seconds,
                    "usage_confirmed": o.usage_confirmed,
                    "provider_session_id": o.provider_session_id,
                    "input_transcript": o.input_transcript,
                    "output_transcript": o.output_transcript,
                }
                metrics |= {
                    "delegations": o.delegations,
                    "instructions_sent": o.instructions_sent,
                    "provider_errors": len(o.errors),
                    "invalid_provider_events": o.invalid_events,
                    "provider_close_reason": o.close_reason,
                    "provider_usage_seconds": o.usage_seconds,
                    "usage_confirmed": o.usage_confirmed,
                }

            def _close() -> None:
                rs = lab.store_for(app)
                with app.state.session_factory() as db, db.begin():
                    if recorder is not None and rs is not None:
                        lab.save_recording(db, rs, session_id, recorder, str(auth.principal_id))
                    lab.finish_session(db, session_id, reason=reason, metrics=metrics, provider_outcome=outcome)
                    if outcome is not None:
                        lab.save_provider_transcripts(
                            db, session_id, outcome, "gpt-live-1 provider transcript (not independent)"
                        )
                    write_audit(
                        db,
                        action="LAB.SESSION_ENDED",
                        outcome="SUCCEEDED",
                        actor=auth.actor,
                        meta=RequestMeta(),
                        entity_type="voice_lab",
                        entity_id=s["session_ref"],
                        after={"reason": reason, **{k: v for k, v in metrics.items() if k != "timing_basis"}},
                    )

            await asyncio.to_thread(_close)
            with contextlib.suppress(Exception):
                await websocket.send_text(json.dumps({"type": "session.ended", "reason": reason, "state": "ENDED"}))
                await websocket.close(code=1000)
            if record and not getattr(app.state, "voicelab_inline", False):  # tests transcribe explicitly
                asyncio.get_running_loop().run_in_executor(None, _transcribe_safely, app, session_id)

        task = asyncio.get_running_loop().create_task(settle())
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.shield(task)


def _transcribe_safely(app: Any, session_id: uuid.UUID) -> None:
    try:
        lab.transcribe_session(app, session_id)
    except Exception:  # noqa: BLE001
        log.exception("lab transcription failed")


# ---- GPT-Live adapter (S1-E.2) -------------------------------------------------------------------------------------
async def guarded_connect(
    app: Any, url: str, headers: dict[str, str], *, mock: bool, vendor: str
) -> gpt_live.Connection:
    """The only way the adapter reaches the network: the URL is re-checked for the provider's vendor here, every
    attempt is logged (host only) and tests substitute ``app.state.gpt_live_connect``."""
    st = app.state.settings
    if not gpt_live.allowed_url(url, app_env=st.app_env, mock=mock, vendor=vendor):
        raise gpt_live.GptLiveError("refused: URL not allowed")
    attempts = getattr(app.state, "gpt_live_connect_log", None)
    if attempts is None:
        attempts = app.state.gpt_live_connect_log = []
    attempts.append(urlparse(url).hostname or "")
    connect = getattr(app.state, "gpt_live_connect", None) or gpt_live.default_connect
    conn: gpt_live.Connection = await connect(url, headers)
    return conn


async def resolve_endpoint(app: Any, code: str, model: str) -> lp.Endpoint:
    """Endpoint and credentials for one connection (an Entra token request runs off the event loop)."""
    credential = getattr(app.state, "azure_credential", None)  # tests inject a fake credential
    return await asyncio.to_thread(lp.endpoint, code, app.state.settings, model=model, credential=credential)


async def gpt_live_provider(app: Any, s: dict[str, Any], pv: dict[str, Any]) -> gpt_live.GptLiveProvider:
    st = app.state.settings
    try:
        ep: lp.Endpoint | None = await resolve_endpoint(app, s["provider"], s["model"])
    except lp.EndpointError as exc:
        log.warning("GPT-Live endpoint unavailable for %s: %s", s["session_ref"], exc.code)
        ep = None

    async def connect(u: str, h: dict[str, str]) -> gpt_live.Connection:
        if ep is None:
            raise gpt_live.GptLiveError("endpoint not configured")
        return await guarded_connect(app, u, h, mock=ep.mock, vendor=ep.vendor)

    cfg = gpt_live.LiveConfig(
        url=ep.url if ep else "",
        headers=ep.headers if ep else {},
        model=ep.model if ep else s["model"],
        voice=s["voice"],
        instructions=pv["system_prompt"],
        turn_instructions=list(pv["turn_instructions"]),
        max_duration_s=float(s["max_duration_s"]),
        close_timeout_s=st.voice_lab_close_timeout_s,
        start_timeout_s=st.voice_lab_start_timeout_s,
        wire_rate=ep.wire_rate if ep else 16000,
        store=None if ep and ep.vendor == "AZURE" else False,
    )
    provider = gpt_live.GptLiveProvider(cfg, connect=connect, label=s["provider"])
    provider.endpoint_info = ep.describe() if ep else {"error": "endpoint not configured"}  # non-secret
    return provider


@router.post(
    "/voice-lab/paid-switch", response_model=LabControlOut, operation_id="voicelab_paid_switch", responses=_ERR
)
@csrf_protected
def paid_switch(
    body: LabPaidSwitchIn, request: Request, auth: AuthContext = Depends(require(MANAGE)), db: Session = Depends(get_db)
) -> LabControlOut:
    """The manager's paid-provider switch (off by default). Switching it on starts nothing: a paid session still needs
    the server configuration, a single-use smoke-test authorisation and another user to start it."""
    _guard(request, auth)
    c = lab.set_paid_switch(db, str(auth.principal_id), body.enabled, body.reason)
    _audit(db, request, auth, "PAID_SWITCH_ON" if body.enabled else "PAID_SWITCH_OFF", None, reason=body.reason)
    db.commit()
    return LabControlOut(**c)


@router.post(
    "/voice-lab/paid-authorisations",
    response_model=LabPaidAuthorisationOut,
    status_code=201,
    operation_id="voicelab_paid_authorisation_issue",
    responses=_ERR,
)
@csrf_protected
def issue_paid_authorisation(
    body: LabPaidAuthorisationIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabPaidAuthorisationOut:
    """Issue ONE single-use smoke-test permission (≤ 120 s, its own USD maximum, expiry). Not an execution."""
    _guard(request, auth)
    try:
        a = lab.issue_authorisation(
            db,
            str(auth.principal_id),
            provider_code=body.provider,
            model=body.model,
            voice=body.voice,
            max_duration_s=body.max_duration_s,
            reason=body.reason,
            expires_in_h=body.expires_in_h,
            settings=request.app.state.settings,
        )
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "PAID_AUTHORISATION_ISSUED",
        a["authorisation_ref"],
        max_usd=a["max_usd"],
        max_duration_s=a["max_duration_s"],
        reason=body.reason,
    )
    db.commit()
    return LabPaidAuthorisationOut(**a)


@router.post(
    "/voice-lab/paid-authorisations/{authorisation_id}/revoke",
    response_model=LabPaidAuthorisationOut,
    operation_id="voicelab_paid_authorisation_revoke",
    responses=_ERR,
)
@csrf_protected
def revoke_paid_authorisation(
    authorisation_id: uuid.UUID,
    body: LabRevokeIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabPaidAuthorisationOut:
    _guard(request, auth)
    try:
        a = lab.revoke_authorisation(db, str(auth.principal_id), authorisation_id, body.reason)
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "PAID_AUTHORISATION_REVOKED", a["authorisation_ref"], reason=body.reason)
    db.commit()
    return LabPaidAuthorisationOut(**a)


@router.post(
    "/voice-lab/sessions/{session_id}/resolve-usage",
    response_model=LabSessionOut,
    operation_id="voicelab_session_resolve_usage",
    responses=_ERR,
)
@csrf_protected
def resolve_usage(
    session_id: uuid.UUID,
    body: LabResolveUsageIn,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabSessionOut:
    """Settle an UNCONFIRMED GPT-Live session with the provider-reported usage (the reservation stays held until
    then)."""
    _guard(request, auth)
    try:
        out = lab.resolve_usage(
            db,
            str(auth.principal_id),
            session_id,
            usage_seconds=body.usage_seconds,
            source=body.source,
            reason=body.reason,
        )
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(
        db,
        request,
        auth,
        "USAGE_RESOLVED",
        out["session_ref"],
        usage_seconds=body.usage_seconds,
        source=body.source,
        reason=body.reason,
    )
    db.commit()
    return LabSessionOut(**out)


@router.post(
    "/voice-lab/sessions/{session_id}/provider-close",
    response_model=LabSessionOut,
    operation_id="voicelab_session_provider_close",
    responses=_ERR,
)
@csrf_protected
async def provider_close(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require(MANAGE)),
    db: Session = Depends(get_db),
) -> LabSessionOut:
    """A manager's explicit close of an orphaned GPT-Live session over the documented sideband (``…/attach`` →
    ``session.close`` → ``session.closed``). On confirmation the reservation is reconciled from the reported usage;
    otherwise nothing changes."""
    _guard(request, auth)
    s = await asyncio.to_thread(lab.session, db, session_id, events=False)
    if s["provider"] not in lab.GPT_PROVIDERS or s["termination_status"] != "UNCONFIRMED":
        raise AppError(409, "NOT_UNCONFIRMED", "Only a GPT-Live session with unconfirmed termination can be closed")
    if not s["provider_session_id"]:
        raise AppError(409, "NO_PROVIDER_SESSION_ID", "The provider session id is unknown; confirm usage manually")
    st = request.app.state.settings
    try:
        ep = await resolve_endpoint(request.app, s["provider"], s["model"])
    except lp.EndpointError as exc:
        raise AppError(409, "PROVIDER_NOT_AVAILABLE", exc.message) from exc

    async def connect(u: str, h: dict[str, str]) -> gpt_live.Connection:
        return await guarded_connect(request.app, u, h, mock=ep.mock, vendor=ep.vendor)

    ok, seconds, why = await gpt_live.close_orphan(
        ep.attach_base, ep.headers, s["provider_session_id"], timeout_s=st.voice_lab_close_timeout_s, connect=connect
    )

    def _settle() -> dict[str, Any]:
        with request.app.state.session_factory() as db2, db2.begin():
            if ok and seconds is not None:
                out = lab.resolve_usage(
                    db2,
                    str(auth.principal_id),
                    session_id,
                    usage_seconds=seconds,
                    source="SIDEBAND_SESSION_CLOSED",
                    reason=f"Sideband close confirmed ({why})",
                )
            else:
                lab.append_event(
                    db2,
                    session_id,
                    "SIDEBAND_CLOSE_UNCONFIRMED",
                    source="BUDGET",
                    details={"result": "no session.closed received; reservation retained"},
                )
                out = lab.session(db2, session_id)
            _audit(db2, request, auth, "PROVIDER_CLOSE", s["session_ref"], confirmed=ok, usage_seconds=seconds)
            return out

    return LabSessionOut(**await asyncio.to_thread(_settle))


@router.post(
    "/voice-lab/trials/{trial_id}/assessments",
    response_model=LabTrialOut,
    operation_id="voicelab_trial_assess",
    responses=_ERR,
)
@csrf_protected
def assess_trial(
    trial_id: uuid.UUID,
    body: LabAssessmentIn,
    request: Request,
    auth: AuthContext = Depends(require(USE)),
    db: Session = Depends(get_db),
) -> LabTrialOut:
    """A person's speech result after listening (human-confirmed result; insert-only)."""
    _guard(request, auth)
    try:
        lab.assess_trial(db, str(auth.principal_id), trial_id, body.result, body.notes, body.listened)
    except lab.LabError as exc:
        db.rollback()
        raise _err(exc) from exc
    _audit(db, request, auth, "SPEECH_ASSESSED", str(trial_id), result=body.result)
    db.commit()
    eid = db.execute(text("SELECT experiment_id FROM lab_trial WHERE id = :t"), {"t": trial_id}).scalar_one()
    t = next(x for x in lab.experiment(db, eid)["trials"] if str(x["id"]) == str(trial_id))
    return LabTrialOut(**t)
