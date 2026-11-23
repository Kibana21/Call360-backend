"""APPL-X1 — Survey Applicability, PROTOTYPE: four stateless operations under ``/api/v1``.

Each takes the documents it works on in the request — a workspace of variables, profiles and saved conditions, one
applicability policy, synthetic scenarios — runs the pure Python evaluator (``app.domain.survey.applicability``) and
returns the result. **Nothing is read from the database and nothing is written**: no table exists for this capability
yet, and none is touched. The same request always gives the same response and the same fingerprints.

This is the one evaluator: the authoring preview, the Condition Lab, Scenario Studio, the generated matrix and the
draft-versus-published comparison all call it, so no screen computes applicability on its own. It does not use and
does not write assignment rules, survey bindings or requirement groups.

Registered only when ``survey_applicability_prototype_enabled`` is on (off by default). Permission: the existing
``survey.read``. A selection plan is a synthetic result: it assigns nothing and gives no permission to call anyone.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.deps import csrf_protected
from app.api.schemas import ErrorResponse
from app.core.errors import AppError
from app.domain.survey.applicability import CONTRACT, ApplicabilityError, analysis, evaluator
from app.domain.survey.applicability.logic import Evaluation, Workspace, needs, variables_of
from app.security import csrf
from app.security.authz import AuthContext, require

router = APIRouter(prefix="/api/v1/survey-applicability/prototype", tags=["survey-applicability"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 422, 429)}
READ = "survey.read"
NOTE = (
    "Prototype (APPL-X1). Synthetic content; nothing is stored. A selection plan is not an assignment and gives no "
    "permission to call anyone."
)
MAX_SCENARIOS = 300
MAX_DEFINITIONS = 600


class SurveyApplicabilityScenarioIn(BaseModel):
    id: str = Field(max_length=80)
    facts: dict[str, Any] = Field(default_factory=dict)
    profiles: list[str] | None = None


class SurveyApplicabilityEvaluateIn(BaseModel):
    workspace: dict[str, Any]
    policy: dict[str, Any]
    scenarios: list[SurveyApplicabilityScenarioIn] = Field(max_length=MAX_SCENARIOS)
    compare_with: dict[str, Any] | None = Field(
        default=None, description="A second policy (for example the published one) to compare every result against."
    )


class SurveyApplicabilityConditionTestIn(BaseModel):
    workspace: dict[str, Any]
    expr: dict[str, Any]
    facts: dict[str, Any] = Field(default_factory=dict)
    profiles: list[str] | None = None


class SurveyApplicabilityAnalyseIn(BaseModel):
    workspace: dict[str, Any]
    policy: dict[str, Any] | None = None


class SurveyApplicabilityGenerateIn(BaseModel):
    workspace: dict[str, Any]
    policy: dict[str, Any]
    limit: int = Field(default=40, ge=1, le=analysis.MAX_SCENARIOS)


class SurveyApplicabilityOut(BaseModel):
    """A result of the applicability evaluator: ``result`` is the evaluator's own document."""

    contract: str
    note: str
    result: dict[str, Any]


def _guard(request: Request, auth: AuthContext) -> None:
    settings = request.app.state.settings
    csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    if not request.app.state.limiter.allow(
        f"survey-sim:{auth.principal_id}", settings.survey_simulation_inputs_per_minute
    ):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly", retryable=True)


def _workspace(raw: dict[str, Any]) -> Workspace:
    count = sum(len(raw.get(k) or []) for k in ("variables", "profiles", "conditions"))
    if count > MAX_DEFINITIONS:
        raise AppError(422, "TOO_LARGE", f"A request holds at most {MAX_DEFINITIONS} definitions")
    try:
        return Workspace(raw)
    except (AttributeError, TypeError) as exc:
        raise AppError(422, "INVALID_DOCUMENT", "The workspace is not a valid document") from exc


def _out(result: dict[str, Any]) -> SurveyApplicabilityOut:
    return SurveyApplicabilityOut(contract=CONTRACT, note=NOTE, result=result)


def _problem(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, ApplicabilityError):
        return {"status": "ERROR", "error": {"code": exc.code, "message": exc.message, "at": exc.at}}
    return {"status": "ERROR", "error": {"code": "INVALID_DOCUMENT", "message": "The document is not well formed"}}


_BAD = (ApplicabilityError, AttributeError, KeyError, TypeError, ValueError)


@router.post(
    "/evaluate", response_model=SurveyApplicabilityOut, operation_id="survey_applicability_evaluate", responses=_ERR
)
@csrf_protected
def survey_applicability_evaluate(
    body: SurveyApplicabilityEvaluateIn, request: Request, auth: AuthContext = Depends(require(READ))
) -> SurveyApplicabilityOut:
    """One policy applied to each scenario: the selection plan with its trace, and — when a second policy is given —
    what changes for each scenario and which requirements are the reason."""
    _guard(request, auth)
    ws = _workspace(body.workspace)
    results = []
    for s in body.scenarios:
        row: dict[str, Any] = {"scenario": s.id}
        try:
            row["plan"] = evaluator.evaluate(ws, body.policy, s.facts, s.profiles)
        except _BAD as exc:
            row["plan"] = _problem(exc)
        if body.compare_with is not None:
            try:
                row["before"] = evaluator.evaluate(ws, body.compare_with, s.facts, s.profiles)
                if row["plan"].get("status") != "ERROR":
                    row["comparison"] = evaluator.compare(row["before"], row["plan"])
            except _BAD as exc:
                row["before"] = _problem(exc)
        results.append(row)
    try:
        fingerprint = evaluator.fingerprint(ws, body.policy)
    except _BAD:
        fingerprint = None
    return _out({"policy_fingerprint": fingerprint, "results": results})


@router.post(
    "/condition-test",
    response_model=SurveyApplicabilityOut,
    operation_id="survey_applicability_condition_test",
    responses=_ERR,
)
@csrf_protected
def survey_applicability_condition_test(
    body: SurveyApplicabilityConditionTestIn, request: Request, auth: AuthContext = Depends(require(READ))
) -> SurveyApplicabilityOut:
    """One expression against one set of facts: TRUE, FALSE or UNKNOWN, with the full trace and what is missing."""
    _guard(request, auth)
    ws = _workspace(body.workspace)
    problems: list[dict[str, Any]] = []
    try:
        analysis.check_expr(ws, body.expr, {"kind": "expression"}, problems)
        if any(p["severity"] == "BLOCKER" for p in problems):
            return _out({"status": "INVALID", "diagnostics": problems})
        ev = Evaluation(ws, body.facts, body.profiles or None)
        trace = ev.expr(dict(body.expr), "")
        used = [ev.fact(c) for c in variables_of(ws, body.expr)]
        analysis.check_reach(ws, body.expr, {"kind": "expression"}, problems)
    except _BAD as exc:
        return _out({**_problem(exc), "diagnostics": problems})
    return _out({"status": "OK", "result": trace["result"], "trace": trace, "needs": needs(trace), "facts": used,
                 "diagnostics": problems})  # fmt: skip


@router.post(
    "/analyse", response_model=SurveyApplicabilityOut, operation_id="survey_applicability_analyse", responses=_ERR
)
@csrf_protected
def survey_applicability_analyse(
    body: SurveyApplicabilityAnalyseIn, request: Request, auth: AuthContext = Depends(require(READ))
) -> SurveyApplicabilityOut:
    """Every diagnostic of a workspace and, when given, of one policy. A BLOCKER would stop submission."""
    _guard(request, auth)
    ws = _workspace(body.workspace)
    try:
        found = analysis.analyse(ws, body.policy)
        fingerprint = evaluator.fingerprint(ws, body.policy) if body.policy else None
        variables = evaluator.policy_variables(ws, body.policy) if body.policy else []
    except _BAD as exc:
        return _out({**_problem(exc), "diagnostics": []})
    blockers = sum(1 for d in found if d["severity"] == "BLOCKER")
    return _out({"status": "BLOCKED" if blockers else "OK", "blockers": blockers, "diagnostics": found,
                 "policy_fingerprint": fingerprint, "policy_variables": variables})  # fmt: skip


@router.post(
    "/scenarios", response_model=SurveyApplicabilityOut, operation_id="survey_applicability_scenarios", responses=_ERR
)
@csrf_protected
def survey_applicability_scenarios(
    body: SurveyApplicabilityGenerateIn, request: Request, auth: AuthContext = Depends(require(READ))
) -> SurveyApplicabilityOut:
    """Generated synthetic applications — one for each distinct result the policy can give — and a statement of what
    was and was not covered. It never claims a coverage it did not compute."""
    _guard(request, auth)
    ws = _workspace(body.workspace)
    try:
        return _out({"status": "OK", **analysis.generate(ws, body.policy, body.limit)})
    except _BAD as exc:
        return _out({**_problem(exc), "scenarios": [], "coverage": {"checked": False}})
