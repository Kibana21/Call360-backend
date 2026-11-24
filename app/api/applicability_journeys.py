# ruff: noqa: E501 — field descriptions are kept one per line
"""APPL-X5a — synthetic journeys over published Applicability Policy versions. Sixteen operations under
``/api/v1/applicability``.

The selection of surveys is the accepted evaluator's, on one exact PUBLISHED policy version. The execution of each
selected survey is the accepted single-survey simulation's. This router adds the coordination between them and the
voice-neutral runtime: ``turn`` (what is asked next), ``answers`` (propose one answer to exactly that turn), the
journey ``state`` and ``verify``. The server decides order, eligibility, branching, replacement and completion; a
client — a browser now, a voice adapter later — reads a turn and proposes an answer.

Registered ONLY when ``applicability_journeys_enabled`` (with publication and survey simulation) is on; off by
default; needs migration 0042. Permissions — no new one: ``applicability.read`` and ``survey.read`` on every
operation; ``survey.simulate`` as well to create, start, answer or abandon a journey; ``applicability.edit`` to save a
fact correspondence. Market-scoped. Writes are CSRF-protected, rate-limited and audited.

Everything here is a SIMULATION over SYNTHETIC facts. Nothing selects a survey for a real case, plans a callback or
starts a session; nothing reads or writes an assignment rule, a binding, a requirement group or a composite plan.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import ErrorResponse
from app.core.errors import AppError
from app.domain.survey.applicability import journeys as jr
from app.domain.survey.store import SurveyError
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/applicability", tags=["applicability-journeys"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
READ, EDIT, SURVEYS, SIMULATE = "applicability.read", "applicability.edit", "survey.read", "survey.simulate"
JourneyStatus = Literal[
    "READY", "RUNNING", "ALL_SURVEYS_COMPLETED", "CROSS_SURVEY_POLICY_UNRESOLVED", "ENDED_INCOMPLETE", "ABANDONED",
    "NO_SURVEY_REQUIRED", "SELECTION_UNRESOLVED", "OUT_OF_SCOPE", "SCOPE_UNRESOLVED",
]  # fmt: skip
SelectionOutcome = Literal["SURVEYS_SELECTED", "NO_SURVEY_REQUIRED", "UNRESOLVED", "OUT_OF_SCOPE", "SCOPE_UNRESOLVED"]


class JourneyPolicyVersion(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    policy_code: str
    policy_name: str | None
    market_code: str
    version_no: int
    status: Literal["PUBLISHED", "SUPERSEDED"]
    published_at: datetime
    version_sha256: str


class JourneyPolicyVersionPage(BaseModel):
    items: list[JourneyPolicyVersion]


class JourneyVariable(BaseModel):
    code: str
    name: str | None = None
    type: str | None = None
    values: list[dict[str, Any]] | None = None
    currency: str | None = None
    min: float | None = None
    max: float | None = None
    description: str | None = None
    category: str | None = None
    version: int | None = None
    derived: bool


class JourneyOptions(BaseModel):
    policy_id: uuid.UUID
    policy_code: str
    policy_name: str
    policy_version_id: uuid.UUID
    version_no: int
    version_status: Literal["PUBLISHED", "SUPERSEDED"]
    published_at: datetime
    current_version_id: uuid.UUID | None
    current_version_no: int | None
    version_sha256: str
    document_sha256: str
    manifest_sha256: str
    profiles: list[str]
    variables: list[JourneyVariable] = Field(
        description="The application facts this version reads, from its own frozen definitions."
    )
    requirements: list[dict[str, Any]]


class JourneySelection(BaseModel):
    record_class: Literal["SYNTHETIC"]
    selection_source: Literal["APPLICABILITY"]
    note: str
    evaluator_contract: str
    policy_id: uuid.UUID
    policy_code: str
    policy_name: str
    policy_version_id: uuid.UUID
    version_no: int
    version_status: Literal["PUBLISHED", "SUPERSEDED"]
    current_version_id: uuid.UUID | None
    current_version_no: int | None
    version_sha256: str
    document_sha256: str
    manifest_sha256: str
    facts: dict[str, Any]
    facts_sha256: str
    outcome: SelectionOutcome
    plan: dict[str, Any] = Field(
        description="The evaluator's complete plan: selected, pending, excluded, needs, requirements with their traces."
    )
    plan_sha256: str


class JourneySelectIn(BaseModel):
    policy_version_id: uuid.UUID = Field(
        description="One exact published policy version. Never a draft; never chosen for the person."
    )
    facts: dict[str, Any] = Field(
        description="Synthetic application facts by variable code. null = not known; absent = not provided."
    )


class JourneyCreateIn(JourneySelectIn):
    label: str = Field(default="", max_length=160)
    origin_scenario_id: uuid.UUID | None = Field(
        default=None, description="A saved synthetic scenario the facts were copied from, by value."
    )
    confirm_superseded: bool = Field(
        default=False, description="Required, explicitly, to run against a superseded version."
    )


class JourneyTurnPrompt(BaseModel):
    text: str | None = Field(description="The approved wording, rendered by the engine. Never rewritten by a client.")
    followup: bool | None = Field(default=None, description="Whether this is a follow-up question.")
    delivery_mode: str | None
    exact_wording_required: bool


class JourneyTurnExpects(BaseModel):
    answer_type: str
    options: list[dict[str, Any]]
    selection: dict[str, Any] | None
    number_rule: dict[str, Any] | None
    text_rule: dict[str, Any] | None


class JourneyTurn(BaseModel):
    contract: str
    journey_id: uuid.UUID
    step: int
    steps: int | None
    survey: dict[str, Any] = Field(description="The exact published survey version being executed.")
    item_key: str = Field(description="The identity of this turn. A submission names it.")
    item: dict[str, Any] | None
    attempt: int
    module: dict[str, Any]
    question_no: int
    prompt: JourneyTurnPrompt
    expects: JourneyTurnExpects
    allowed_non_answers: list[Literal["NOT_ACKNOWLEDGED", "EMPTY_TEXT", "NONE_SELECTED"]]
    policy_unresolved: dict[str, Any] | None
    expected_inputs: int = Field(
        description="The concurrency token: how many inputs the journey holds. A submission names it."
    )
    turn_token: int


class JourneyState(BaseModel):
    id: uuid.UUID
    contract: str
    record_class: Literal["SYNTHETIC"]
    selection_source: Literal["APPLICABILITY"]
    note: str
    market_code: str
    label: str
    status: JourneyStatus
    condition: Literal["REPLAY_DRIFT", "POLICY_UNRESOLVED"] | None
    revision: int
    expected_inputs: int
    created_by: str
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    end_detail: dict[str, Any]
    selection: dict[str, Any]
    start: dict[str, Any] | None = Field(
        description="What was frozen at start: the correspondence used, each survey fact and where it came from."
    )
    start_sha256: str | None
    survey_facts: dict[str, Any] | None
    survey_facts_sha256: str | None
    steps: list[dict[str, Any]]
    current_step: int | None
    turn: JourneyTurn | None
    progress: dict[str, int]
    requirements: list[dict[str, Any]]
    events: list[dict[str, Any]]


class JourneyNext(BaseModel):
    kind: Literal["TURN", "END"]
    turn: JourneyTurn | None
    end: dict[str, Any] | None
    status: JourneyStatus
    condition: Literal["REPLAY_DRIFT", "POLICY_UNRESOLVED"] | None


class JourneySummary(BaseModel):
    id: uuid.UUID
    label: str
    status: JourneyStatus
    revision: int
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    created_by: str
    created_by_name: str | None
    policy_code: str
    policy_name: str | None
    version_no: int
    version_status: str
    outcome: SelectionOutcome
    surveys: int
    surveys_completed: int


class JourneyPage(BaseModel):
    items: list[JourneySummary]
    total: int
    limit: int
    offset: int


class JourneySurveyFactsIn(BaseModel):
    correspondence_id: uuid.UUID | None = Field(
        default=None, description="A fact correspondence version the person CHOSE. None is applied by default."
    )
    survey_facts: dict[str, Any] = Field(
        default_factory=dict,
        description="Survey facts typed by the person, by catalog field. null = explicitly not known.",
    )


class JourneySurveyFacts(BaseModel):
    correspondence: dict[str, Any] | None
    entries: list[dict[str, Any]]
    fields: list[dict[str, Any]]
    missing: list[dict[str, Any]]
    conflicts: list[dict[str, Any]]
    survey_facts: dict[str, Any]
    survey_facts_sha256: str
    ready: bool


class JourneyStartIn(JourneySurveyFactsIn):
    expected_revision: int = Field(ge=1)


class JourneyInteraction(BaseModel):
    """What a voice adapter may attach later. PROPOSED interaction evidence: recorded, never an accepted fact."""

    transcript_ref: str | None = Field(default=None, max_length=200)
    recognition_confidence: float | None = Field(default=None, ge=0, le=1)
    proposed_answer: dict[str, Any] | None = None
    clarification_required: bool | None = None
    delivery_evidence_ref: str | None = Field(default=None, max_length=200)


class JourneyAnswerIn(BaseModel):
    item_key: str = Field(max_length=240, description="The turn being answered, exactly as the runtime gave it.")
    expected_inputs: int = Field(ge=0, description="The concurrency token of that turn.")
    answer: dict[str, Any] = Field(
        default_factory=dict,
        description="choice | choices | text | other_text | number | acknowledged — or {non_answer: kind}.",
    )
    idempotency_key: str = Field(min_length=8, max_length=80)
    interaction: JourneyInteraction | None = None


class JourneyAnswerOut(BaseModel):
    result: Literal["ACCEPTED", "REJECTED"]
    code: str | None = Field(description="The machine-readable reason of a rejection.")
    replayed: bool = Field(description="True when this is the stored result of an earlier identical submission.")
    recorded_seq: int | None
    state: JourneyState


class JourneyAbandonIn(BaseModel):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)


class JourneyVerification(BaseModel):
    journey_id: uuid.UUID
    verified: bool
    status: JourneyStatus
    checks: list[dict[str, Any]]
    failed: list[str]
    selection_plan_sha256: str
    start_sha256: str | None
    inputs: int
    note: str


class FactCorrespondence(BaseModel):
    id: uuid.UUID
    market_code: str
    code: str
    version_no: int
    record_class: Literal["SYNTHETIC"]
    name: str | None
    description: str
    entries: list[dict[str, Any]]
    document_sha256: str
    created_by: str
    created_by_name: str | None
    created_at: datetime
    note: str


class FactCorrespondencePage(BaseModel):
    items: list[FactCorrespondence]


class FactCorrespondenceIn(BaseModel):
    market_code: str = Field(max_length=40)
    code: str = Field(min_length=2, max_length=80)
    document: dict[str, Any] = Field(
        description="{name, description, entries: [{source: {version_id}, target: {field}, rule: 'IDENTITY'}]}"
    )


class FactCorrespondenceCatalog(BaseModel):
    variables: list[dict[str, Any]]
    fields: list[dict[str, Any]]
    rules: list[str]


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext, *, answering: bool = False) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    key, limit = (
        (f"applicability-journey-input:{auth.principal_id}", settings.survey_simulation_inputs_per_minute)
        if answering
        else (f"applicability-journey:{auth.principal_id}", settings.survey_writes_per_minute)
    )
    if not request.app.state.limiter.allow(key, limit):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _try(work: Any) -> Any:
    try:
        return work()
    except SurveyError as exc:
        raise _err(exc) from exc


def _act(db: Session, work: Any, *, refused: Any = None) -> Any:
    """One transaction, or nothing. A refused submission is then recorded in a transaction of its own."""
    try:
        out = work()
        db.commit()
        return out
    except SurveyError as exc:
        db.rollback()
        if refused is not None and exc.status == 409:
            refused(exc)
            db.commit()
        raise _err(exc) from exc


R = Depends(require(READ))
S = Depends(require(SURVEYS))
E = Depends(require(EDIT))
X = Depends(require(SIMULATE))
DB = Depends(get_db)


@router.get(
    "/journey-policy-versions",
    response_model=JourneyPolicyVersionPage,
    responses=_ERR,
    operation_id="applicability_journey_policy_versions",
    summary="Every published policy version a synthetic journey may be made against",
)
def applicability_journey_policy_versions(
    auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyPolicyVersionPage:
    return JourneyPolicyVersionPage.model_validate(_try(lambda: jr.published_versions(db, _markets(auth))))


@router.get(
    "/journey-policy-versions/{version_id}",
    response_model=JourneyOptions,
    responses=_ERR,
    operation_id="applicability_journey_policy_version",
    summary="One published policy version and the application facts it reads",
)
def applicability_journey_policy_version(
    version_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyOptions:
    return JourneyOptions.model_validate(_try(lambda: jr.options(db, _markets(auth), version_id)))


@router.post(
    "/journeys/selection-preview",
    response_model=JourneySelection,
    responses=_ERR,
    operation_id="applicability_journey_selection_preview",
    summary="What a published version selects for these synthetic facts; records nothing",
)
@csrf_protected
def applicability_journey_selection_preview(
    body: JourneySelectIn, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneySelection:
    _write(request, auth, answering=True)
    return JourneySelection.model_validate(
        _try(lambda: jr.preview(db, _markets(auth), body.policy_version_id, body.facts))
    )


@router.post(
    "/journeys",
    response_model=JourneyState,
    status_code=201,
    responses=_ERR,
    operation_id="applicability_journey_create",
    summary="Record the selection plan, immutably, and the synthetic journey over it",
)
@csrf_protected
def applicability_journey_create(
    body: JourneyCreateIn,
    request: Request,
    auth: AuthContext = X,
    _r: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> JourneyState:
    _write(request, auth)
    origin = {"scenario_id": str(body.origin_scenario_id)} if body.origin_scenario_id else None
    jid = _act(
        db,
        lambda: jr.create(
            db,
            _markets(auth),
            body.policy_version_id,
            body.facts,
            body.label,
            origin,
            body.confirm_superseded,
            auth.actor,
            request_meta(request),
        ),
    )
    return JourneyState.model_validate(_try(lambda: jr.state(db, _markets(auth), jid)))


@router.get(
    "/journeys",
    response_model=JourneyPage,
    responses=_ERR,
    operation_id="applicability_journey_list",
    summary="Synthetic journeys, newest first",
)
def applicability_journey_list(
    limit: int = 50, offset: int = 0, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyPage:
    return JourneyPage.model_validate(_try(lambda: jr.listing(db, _markets(auth), limit=limit, offset=offset)))


@router.get(
    "/journeys/{journey_id}",
    response_model=JourneyState,
    responses=_ERR,
    operation_id="applicability_journey_state",
    summary="The journey as it stands, replayed from what is recorded",
)
def applicability_journey_state(
    journey_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyState:
    return JourneyState.model_validate(_try(lambda: jr.state(db, _markets(auth), journey_id)))


@router.post(
    "/journeys/{journey_id}/survey-facts",
    response_model=JourneySurveyFacts,
    responses=_ERR,
    operation_id="applicability_journey_survey_facts",
    summary="Which survey facts the journey would run with, and where each comes from; records nothing",
)
@csrf_protected
def applicability_journey_survey_facts(
    journey_id: uuid.UUID,
    body: JourneySurveyFactsIn,
    request: Request,
    auth: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> JourneySurveyFacts:
    _write(request, auth, answering=True)
    return JourneySurveyFacts.model_validate(
        _try(lambda: jr.resolve_survey_facts(db, _markets(auth), journey_id, body.correspondence_id, body.survey_facts))
    )


@router.post(
    "/journeys/{journey_id}/start",
    response_model=JourneyState,
    responses=_ERR,
    operation_id="applicability_journey_start",
    summary="Freeze the survey facts and begin the first selected survey",
)
@csrf_protected
def applicability_journey_start(
    journey_id: uuid.UUID,
    body: JourneyStartIn,
    request: Request,
    auth: AuthContext = X,
    _r: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> JourneyState:
    _write(request, auth)
    return JourneyState.model_validate(
        _act(
            db,
            lambda: jr.start(
                db,
                _markets(auth),
                journey_id,
                body.expected_revision,
                body.correspondence_id,
                body.survey_facts,
                auth.actor,
                request_meta(request),
            ),
        )
    )


@router.get(
    "/journeys/{journey_id}/turn",
    response_model=JourneyNext,
    responses=_ERR,
    operation_id="applicability_journey_turn",
    summary="next: the one question the journey is waiting for, or how it ended",
)
def applicability_journey_turn(
    journey_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyNext:
    return JourneyNext.model_validate(_try(lambda: jr.turn(db, _markets(auth), journey_id)))


@router.post(
    "/journeys/{journey_id}/answers",
    response_model=JourneyAnswerOut,
    responses=_ERR,
    operation_id="applicability_journey_submit",
    summary="submit: propose one answer to exactly the current turn; retry-safe",
)
@csrf_protected
def applicability_journey_submit(
    journey_id: uuid.UUID,
    body: JourneyAnswerIn,
    request: Request,
    auth: AuthContext = X,
    _r: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> JourneyAnswerOut:
    _write(request, auth, answering=True)
    actor, markets = auth.actor, _markets(auth)
    interaction = body.interaction.model_dump(exclude_none=True) if body.interaction else None
    out = _act(
        db,
        lambda: jr.submit(
            db,
            markets,
            journey_id,
            body.item_key,
            body.expected_inputs,
            body.answer,
            body.idempotency_key,
            interaction,
            actor,
            request_meta(request),
        ),
        refused=lambda exc: jr.record_refusal(
            db, markets, journey_id, body.item_key, body.expected_inputs, exc.code, exc.message, actor
        ),
    )
    return JourneyAnswerOut.model_validate(out)


@router.post(
    "/journeys/{journey_id}/verify",
    response_model=JourneyVerification,
    responses=_ERR,
    operation_id="applicability_journey_verify",
    summary="Reproduce the journey from its own records; records nothing",
)
@csrf_protected
def applicability_journey_verify(
    journey_id: uuid.UUID, request: Request, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> JourneyVerification:
    _write(request, auth, answering=True)
    return JourneyVerification.model_validate(_try(lambda: jr.verify(db, _markets(auth), journey_id)))


@router.post(
    "/journeys/{journey_id}/abandon",
    response_model=JourneyState,
    responses=_ERR,
    operation_id="applicability_journey_abandon",
    summary="End an open journey, with a reason; everything recorded stays",
)
@csrf_protected
def applicability_journey_abandon(
    journey_id: uuid.UUID,
    body: JourneyAbandonIn,
    request: Request,
    auth: AuthContext = X,
    _r: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> JourneyState:
    _write(request, auth)
    return JourneyState.model_validate(
        _act(
            db,
            lambda: jr.abandon(
                db, _markets(auth), journey_id, body.expected_revision, body.reason, auth.actor, request_meta(request)
            ),
        )
    )


@router.get(
    "/fact-correspondences",
    response_model=FactCorrespondencePage,
    responses=_ERR,
    operation_id="applicability_fact_correspondence_list",
    summary="Synthetic fact correspondences, every version",
)
def applicability_fact_correspondence_list(
    auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> FactCorrespondencePage:
    return FactCorrespondencePage.model_validate(_try(lambda: jr.correspondences(db, _markets(auth))))


@router.get(
    "/fact-correspondences/catalog",
    response_model=FactCorrespondenceCatalog,
    responses=_ERR,
    operation_id="applicability_fact_correspondence_catalog",
    summary="What a correspondence may connect: published application facts and survey catalog fields",
)
def applicability_fact_correspondence_catalog(
    market_code: str, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> FactCorrespondenceCatalog:
    return FactCorrespondenceCatalog.model_validate(_try(lambda: jr.catalog(db, _markets(auth), market_code)))


@router.get(
    "/fact-correspondences/{correspondence_id}",
    response_model=FactCorrespondence,
    responses=_ERR,
    operation_id="applicability_fact_correspondence_get",
    summary="One immutable version of a fact correspondence",
)
def applicability_fact_correspondence_get(
    correspondence_id: uuid.UUID, auth: AuthContext = R, _s: AuthContext = S, db: Session = DB
) -> FactCorrespondence:
    return FactCorrespondence.model_validate(_try(lambda: jr.correspondence(db, _markets(auth), correspondence_id)))


@router.post(
    "/fact-correspondences",
    response_model=FactCorrespondence,
    status_code=201,
    responses=_ERR,
    operation_id="applicability_fact_correspondence_save",
    summary="Save a NEW immutable version of a synthetic fact correspondence",
)
@csrf_protected
def applicability_fact_correspondence_save(
    body: FactCorrespondenceIn,
    request: Request,
    auth: AuthContext = E,
    _r: AuthContext = R,
    _s: AuthContext = S,
    db: Session = DB,
) -> FactCorrespondence:
    _write(request, auth)
    cid = _act(
        db,
        lambda: jr.save_correspondence(
            db, _markets(auth), body.market_code, body.code, body.document, auth.actor, request_meta(request)
        ),
    )
    return FactCorrespondence.model_validate(_try(lambda: jr.correspondence(db, _markets(auth), cid)))
