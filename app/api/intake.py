"""Data Intake APIs for CP0.4a: API-080, API-082…085 (manual intake; mock upstream and corrections are CP0.4b).

- ``POST /intake/manual/preview`` (API-084) validates and plans one synthetic transaction and **persists nothing
  except an audit event**.
- ``POST /intake/manual`` (API-085) requires ``Idempotency-Key``: the same key and payload replays the stored
  outcome (200, ``replayed``); the same key with a different payload is ``409 IDEMPOTENCY_KEY_REUSED``. An accepted
  transaction is written in one database transaction; every rejection is rolled back and audited.
- Writes need ``intake.manual.submit`` (ADMIN) and the session CSRF token; reads need ``intake.read`` (ADMIN).
  Runs are scoped by ``market_code`` (D-39). Audit events carry the payload digest, references and error codes,
  never submitted personal data.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.admin_config import _write_guard
from app.api.deps import csrf_protected
from app.api.schemas import (
    ErrorResponse,
    IntakeCounts,
    IntakeItemOut,
    IntakeOutcome,
    IntakeRunDetail,
    IntakeRunList,
    IntakeRunRow,
    IntakeSource,
    IntakeSourceList,
    IntakeTransaction,
)
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain.intake import INTAKE_LOCK_KEY, commit, describe, now_utc, payload_digest, plan
from app.security.authz import AuthContext, get_db, request_meta, require
from app.security.scope import not_found

router = APIRouter(prefix="/api/v1/intake", tags=["intake"])
_ERR: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorResponse} for code in (401, 403, 404, 409, 422, 428, 429, 503)
}
_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
log = logging.getLogger("call360.intake")
COUNTS = ("received", "new", "updated", "unchanged", "rejected", "quarantined")


def _audit(
    db: Session,
    request: Request,
    auth: AuthContext,
    action: str,
    outcome: str,
    body: IntakeTransaction,
    digest: str,
    **after: Any,
) -> None:
    write_audit(
        db,
        action=action,
        outcome=outcome,
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="intake_transaction",
        entity_id=body.source_event_id[:64],
        reason=body.reason if outcome == "SUCCEEDED" else None,
        after={"source_system": body.source_system, "payload_digest": digest, **after},
    )


def _rejected(
    db: Session, request: Request, auth: AuthContext, body: IntakeTransaction, digest: str, exc: AppError
) -> None:
    """Record a rejection in its own transaction after the business transaction was rolled back."""
    db.rollback()
    issues = [{"loc": d.get("loc"), "code": d.get("code")} for d in exc.details or []]
    _audit(
        db,
        request,
        auth,
        "INTAKE.REJECTED",
        "FAILED" if exc.status_code >= 500 else "DENIED",
        body,
        digest,
        code=exc.code,
        status=exc.status_code,
        issues=issues,
    )
    db.commit()


@router.get("/sources", response_model=IntakeSourceList, operation_id="intake_sources", responses=_ERR)
def sources(request: Request, _auth: AuthContext = Depends(require("intake.read"))) -> IntakeSourceList:
    return IntakeSourceList(
        data_policy=request.app.state.settings.data_policy,
        items=[
            IntakeSource(source_type="MANUAL", available=True, note="Manual synthetic transaction intake (API)"),
            IntakeSource(source_type="MOCK_API", available=False, note="Mock upstream import arrives in CP0.4b"),
            IntakeSource(source_type="BULK", available=False, note="Not available in Stage 0 (S4)"),
            IntakeSource(source_type="INTERNAL_API", available=False, note="Not available in Stage 0 (S4+)"),
        ],
    )


@router.post("/manual/preview", response_model=IntakeOutcome, operation_id="intake_manual_preview", responses=_ERR)
@csrf_protected
def preview(
    body: IntakeTransaction,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("intake.manual.submit")),
) -> IntakeOutcome:
    _write_guard(request, auth)
    digest = payload_digest(body)
    try:
        p = plan(db, body, auth.markets, now_utc())
    except AppError as exc:
        _rejected(db, request, auth, body, digest, exc)
        raise
    db.rollback()  # nothing from planning is kept
    _audit(db, request, auth, "INTAKE.PREVIEWED", "SUCCEEDED", body, digest, holds=p.holds)
    db.commit()
    return IntakeOutcome(**describe(p))


@router.post(
    "/manual", response_model=IntakeOutcome, status_code=201, operation_id="intake_manual_submit", responses=_ERR
)
@csrf_protected
def submit(
    body: IntakeTransaction,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("intake.manual.submit")),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=128),
) -> IntakeOutcome:
    _write_guard(request, auth)
    if idempotency_key is None or not _KEY.fullmatch(idempotency_key):
        raise AppError(
            428, "IDEMPOTENCY_KEY_REQUIRED", "Send an Idempotency-Key header (8–128 characters: A-Z a-z 0-9 . _ : -)"
        )
    digest = payload_digest(body)
    try:
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": INTAKE_LOCK_KEY})
        run = (
            db.execute(
                text("SELECT run_ref, payload_digest, result FROM intake_run WHERE idempotency_key = :k"),
                {"k": idempotency_key},
            )
            .mappings()
            .first()
        )
        if run is not None:
            if run["payload_digest"] != digest:
                raise AppError(
                    409, "IDEMPOTENCY_KEY_REUSED", "This Idempotency-Key was used for a different transaction"
                )
            _audit(db, request, auth, "INTAKE.REPLAYED", "SUCCEEDED", body, digest, run_ref=run["run_ref"])
            db.commit()
            response.status_code = 200
            return IntakeOutcome(**{**run["result"], "replayed": True})
        p = plan(db, body, auth.markets, now_utc())
        result = commit(
            db,
            request.app.state.settings.target_schema,
            p,
            actor=auth.actor,
            meta=request_meta(request),
            idempotency_key=idempotency_key,
            dp=request.app.state.data_protection,
        )
        _audit(
            db,
            request,
            auth,
            "INTAKE.COMMITTED",
            "SUCCEEDED",
            body,
            digest,
            run_ref=result["run_ref"],
            policy_ref=result["policy"]["policy_ref"],
            policy_outcome=result["policy"]["outcome"],
            sale_ref=result["sale_ref"],
            case_ref=result["case"]["case_ref"],
            holds=p.holds,
        )
        db.commit()
    except AppError as exc:
        _rejected(db, request, auth, body, digest, exc)
        raise
    log.info("intake committed run=%s case=%s", result["run_ref"], result["case"]["case_ref"])
    return IntakeOutcome(**result)


def _run_row(r: Any, names: dict[str, str]) -> dict[str, Any]:
    return {
        "id": r["id"],
        "run_ref": r["run_ref"],
        "source_type": r["source_type"],
        "source_system": r["source_system"],
        "status": r["status"],
        "started_at": r["started_at"],
        "finished_at": r["finished_at"],
        "requested_by": names.get(r["requested_by"], r["requested_by"]),
        "counts": IntakeCounts(**{c: r[f"{c}_count"] for c in COUNTS}),
        "payload_digest": r["payload_digest"],
    }


def _names(db: Session, ids: set[str]) -> dict[str, str]:
    valid = [i for i in ids if _is_uuid(i)]
    if not valid:
        return {}
    rows = db.execute(
        text("SELECT CAST(id AS text) AS id, display_name FROM principal WHERE CAST(id AS text) = ANY(:i)"),
        {"i": valid},
    ).all()
    return {r.id: r.display_name for r in rows}


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


@router.get("/import-runs", response_model=IntakeRunList, operation_id="intake_runs_list", responses=_ERR)
def runs(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("intake.read")),
    limit: int = Query(50, ge=1, le=200),
) -> IntakeRunList:
    m = {"m": sorted(auth.markets)}
    rows = (
        db.execute(
            text("SELECT * FROM intake_run WHERE market_code = ANY(:m) ORDER BY started_at DESC, id LIMIT :l"),
            {**m, "l": limit},
        )
        .mappings()
        .all()
    )
    total = db.execute(text("SELECT count(*) FROM intake_run WHERE market_code = ANY(:m)"), m).scalar_one()
    names = _names(db, {r["requested_by"] for r in rows})
    return IntakeRunList(items=[IntakeRunRow(**_run_row(r, names)) for r in rows], total=total)


@router.get("/import-runs/{run_id}", response_model=IntakeRunDetail, operation_id="intake_runs_get", responses=_ERR)
def run_detail(
    run_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require("intake.read")),
) -> IntakeRunDetail:
    r = (
        db.execute(
            text("SELECT * FROM intake_run WHERE id = :i AND market_code = ANY(:m)"),
            {"i": run_id, "m": sorted(auth.markets)},
        )
        .mappings()
        .first()
    )
    if r is None:
        raise not_found(
            db,
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="intake_run",
            entity_id=str(run_id),
            reason="out of scope or missing",
        )
    items = (
        db.execute(
            text(
                "SELECT id, source_system, source_event_id, entity_type, status, errors, payload_digest "
                "FROM intake_item WHERE intake_run_id = :i ORDER BY created_at, id"
            ),
            {"i": run_id},
        )
        .mappings()
        .all()
    )
    return IntakeRunDetail(
        **_run_row(r, _names(db, {r["requested_by"]})),
        items=[IntakeItemOut(**dict(i)) for i in items],
        result=dict(r["result"]),
    )
