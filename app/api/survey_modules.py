"""LIB-2 — reusable modules authored on their own: four operations under ``/api/v1``.

A standalone module is a definition of kind MODULE (migration 0036). It is created here, without a survey, and from
then on it is edited, validated, submitted, reviewed and published through the SAME operations as a survey, addressed
by the module's id — its draft documents and atomic save, the code issuer, validation, submission, candidates, the
decision, publication and history (``/survey-definitions/{id}/…``, ``/survey-candidates/{id}/…``). There is one
governance, not two: the three-person rule, immutable candidates, frozen pinned versions and the market rule are the
existing ones. Once published, the module is in the existing component library like any other.

What is refused: a standalone module is never a survey. It is not in the list of surveys, and it cannot be simulated,
given a call plan, bound to an assignment rule, coordinated or evaluated — by the application and by the database.

The test operation runs ONE module in a fixed frame with the authoritative Python engine and records nothing.

Registered only when ``survey_module_authoring_enabled`` (and the library) is on. Permissions are the existing ones:
``survey.read`` to see, ``survey.edit`` to create, ``survey.simulate`` to run the engine. No permission is added.
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
from app.domain.survey import module_test, store
from app.security import csrf
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1", tags=["survey-modules"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 429)}
MARKET = "SG"  # Singapore-only synthetic development (D-39)
NOTE = (
    "Synthetic content, unapproved for operational use. A standalone module is not a survey: it cannot be simulated, "
    "planned or assigned as one, and publishing it makes nothing eligible for a call."
)
READ, EDIT, APPROVE, PUBLISH, SIMULATE = (
    "survey.read", "survey.edit", "survey.approve", "survey.publish", "survey.simulate",
)  # fmt: skip


class SurveyModuleCreateIn(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=2000)


class SurveyModuleCandidate(BaseModel):
    id: uuid.UUID
    n: int
    status: Literal["IN_REVIEW", "APPROVED"]
    revision: int = Field(description="The module revision this candidate would publish.")
    submitted_at: datetime
    submitted_by_you: bool
    your_action: Literal["DECIDE", "PUBLISH"] | None = Field(
        description="What the identity rules AND the reader's permissions allow the reader to do with it now."
    )
    waiting_for: Literal["A_REVIEWER", "A_PUBLISHER"] = Field(
        description="Whose step is next, whoever the reader is: a reviewer while in review, a publisher once approved."
    )


class SurveyModuleRevision(BaseModel):
    revision: int
    version_id: uuid.UUID
    version_label: str
    status: str
    published_at: datetime


class SurveyModuleOut(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    description: str
    market_code: str
    draft_revision: int = Field(description="The save counter of the working draft (the optimistic-concurrency token).")
    saved_at: datetime
    saved_by_you: bool
    working_revision: int = Field(description="The module revision the working draft holds.")
    working_state: Literal["DRAFT", "FROZEN"] = Field(
        description="DRAFT: it can still be changed. FROZEN: it was submitted; a change is a new revision."
    )
    unpublished_changes: bool = Field(description="The working revision is not a published one.")
    facts: dict[str, Any]
    open_candidate: SurveyModuleCandidate | None
    published: list[SurveyModuleRevision]
    latest_published_revision: int | None
    note: str = NOTE


class SurveyModuleList(BaseModel):
    items: list[SurveyModuleOut]
    note: str = NOTE


class SurveyModuleTestInput(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    answer: dict[str, Any] = Field(default_factory=dict)


class SurveyModuleTestIn(BaseModel):
    module_id: uuid.UUID | None = Field(
        default=None, description="A standalone module: its working draft is tested, or `revision` of it."
    )
    code: str | None = Field(default=None, max_length=80, description="Otherwise a PUBLISHED module, by code…")
    revision: int | None = Field(default=None, ge=1, description="…and revision.")
    facts: dict[str, Any] = Field(default_factory=dict)
    inputs: list[SurveyModuleTestInput] = Field(default_factory=list, max_length=module_test.MAX_INPUTS)


class SurveyModuleTestOut(BaseModel):
    record_class: Literal["MODULE_TEST"]
    note: str
    module: dict[str, Any]
    engine_contract: str
    frame: dict[str, Any] = Field(description="The fixed one-module content the engine was given. Not a survey.")
    manifest: list[dict[str, Any]] = Field(description="Every exact version the test ran on.")
    requires: dict[str, Any]
    fields: dict[str, Any] = Field(description="The catalog definition of each fact the module's conditions read.")
    findings: list[dict[str, Any]]
    testable: bool = Field(description="False when the module has a blocker: it is then not executed at all.")
    facts: dict[str, Any]
    facts_sha256: str | None
    inputs: list[dict[str, Any]]
    status: Literal["PENDING", "POLICY_UNRESOLVED", "TERMINAL", "NOT_TESTABLE"]
    run: dict[str, Any] | None
    run_sha256: str | None = Field(description="The fingerprint of the run: the same inputs always give the same one.")


def _markets(auth: AuthContext) -> list[str]:
    return sorted(auth.markets)


def _err(exc: store.SurveyError) -> AppError:
    return AppError(exc.status, exc.code, exc.message, details=exc.details)


def _write(request: Request, auth: AuthContext, bucket: str = "survey-writes") -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    limit = (
        settings.survey_writes_per_minute if bucket == "survey-writes" else settings.survey_simulation_inputs_per_minute
    )
    if not request.app.state.limiter.allow(f"{bucket}:{auth.principal_id}", limit):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _revision_of(content: Any) -> int:
    return int(content["sequence"][0]["module"]["revision"])


def _out(db: Session, row: dict[str, Any], auth: AuthContext) -> SurveyModuleOut:
    mid, who = row["id"], str(auth.principal_id)
    d = store.draft(db, mid)
    working = _revision_of(d["content"])
    doc = store._doc(db, "MODULE", row["code"], working)  # noqa: SLF001 — the module's own working revision
    assert doc is not None, "a standalone module always holds its working revision"
    published: list[SurveyModuleRevision] = []
    for v in store.versions_of(db, mid):
        full = store.version(db, v["id"], [row["market_code"]], store.ARTIFACT_KINDS)
        published.append(
            SurveyModuleRevision(
                revision=_revision_of(full["content"]), version_id=v["id"], version_label=v["label"],
                status=store.status_of(db, v["id"]) or "UNKNOWN", published_at=v["created_at"],
            )
        )  # fmt: skip
    live = [p.revision for p in published if p.status in store.PUBLISHED_VERSION_EVENTS]
    open_c: SurveyModuleCandidate | None = None
    for c in reversed(store.candidates_of(db, mid)):
        status = store.status_of(db, c["id"])
        if status not in store.OPEN_CANDIDATE:
            continue
        cand = store.candidate(db, c["id"], [row["market_code"]])
        allowed = store.restrictions(db, cand, auth.actor)
        # the same two conditions the operations enforce: the identity rule, and the permission
        action: Literal["DECIDE", "PUBLISH"] | None = (
            "DECIDE" if allowed["can_decide"] and APPROVE in auth.permissions
            else "PUBLISH" if allowed["can_publish"] and PUBLISH in auth.permissions
            else None
        )  # fmt: skip
        open_c = SurveyModuleCandidate(
            id=c["id"], n=c["n"], status=status, revision=_revision_of(cand["content"]),
            submitted_at=c["submitted_at"], submitted_by_you=c["submitted_by"] == who, your_action=action,
            waiting_for="A_REVIEWER" if status == "IN_REVIEW" else "A_PUBLISHER",
        )  # fmt: skip
        break
    return SurveyModuleOut(
        id=mid, code=row["code"], name=row["name"], description=row["purpose"], market_code=row["market_code"],
        draft_revision=d["revision"], saved_at=d["updated_at"], saved_by_you=d["updated_by"] == who,
        working_revision=working, working_state=doc["state"], unpublished_changes=working not in live,
        facts=store._summary(db, "MODULE", doc["content"])["facts"],  # noqa: SLF001
        open_candidate=open_c, published=published, latest_published_revision=max(live) if live else None,
    )  # fmt: skip


@router.post(
    "/survey-modules", response_model=SurveyModuleOut, status_code=201, operation_id="survey_module_create",
    responses=_ERR,
)  # fmt: skip
@csrf_protected
def survey_module_create(
    body: SurveyModuleCreateIn, request: Request, auth: AuthContext = Depends(require(EDIT)),
    db: Session = Depends(get_db),
) -> SurveyModuleOut:  # fmt: skip
    """Create a reusable module on its own: its permanent, server-issued code and an empty first draft revision. No
    survey is created."""
    _write(request, auth)
    if MARKET not in auth.markets:
        raise AppError(403, "MARKET_NOT_IN_SCOPE", "Not available in your markets")
    try:
        mid = store.create_module(
            db, name=body.name, description=body.description, market=MARKET, actor=auth.actor,
            meta=request_meta(request),
        )  # fmt: skip
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.commit()
    return _out(db, store.module(db, mid, _markets(auth)), auth)


@router.get("/survey-modules", response_model=SurveyModuleList, operation_id="survey_module_list", responses=_ERR)
def survey_module_list(auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)) -> SurveyModuleList:
    """The standalone modules of the reader's markets — drafts included, which the published library never shows —
    with where each stands and what, if anything, the reader may do next."""
    return SurveyModuleList(items=[_out(db, r, auth) for r in store.surveys(db, _markets(auth), "MODULE")])


@router.get(
    "/survey-modules/{module_id}", response_model=SurveyModuleOut, operation_id="survey_module_get", responses=_ERR
)
def survey_module_get(
    module_id: uuid.UUID, auth: AuthContext = Depends(require(READ)), db: Session = Depends(get_db)
) -> SurveyModuleOut:
    try:
        return _out(db, store.module(db, module_id, _markets(auth)), auth)
    except store.SurveyError as exc:
        raise _err(exc) from exc


@router.post(
    "/survey-module-tests", response_model=SurveyModuleTestOut, operation_id="survey_module_test", responses=_ERR
)
@csrf_protected
def survey_module_test(
    body: SurveyModuleTestIn, request: Request, auth: AuthContext = Depends(require(SIMULATE)),
    db: Session = Depends(get_db),
) -> SurveyModuleTestOut:  # fmt: skip
    """Run ONE module with the Python engine, in a fixed one-module frame, for synthetic facts and an ordered list of
    answers. Nothing is stored: the run is the replay of exactly the inputs given, so the same request gives the same
    run and the same fingerprint. A module with a blocker is reported as not testable and is not executed."""
    _write(request, auth, "survey-sim")
    if READ not in auth.permissions:
        raise AppError(403, "FORBIDDEN", "You do not have permission to read survey definitions")
    try:
        out = module_test.run(
            db, _markets(auth), module_id=body.module_id, code=body.code, revision=body.revision, facts=body.facts,
            inputs=[i.model_dump() for i in body.inputs],
        )  # fmt: skip
    except store.SurveyError as exc:
        db.rollback()
        raise _err(exc) from exc
    db.rollback()  # nothing was written, and nothing is
    return SurveyModuleTestOut(**out)
