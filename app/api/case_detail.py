"""Call Detail read APIs (F3: API-037…047, API-063). Read-only, `case.read` (API-063: `script.read`).

Every object is fetched through its callback case (or, for a script version, its family) with the caller's markets
in the WHERE clause (D-39: SG only). A missing or out-of-scope id returns the same audited 404 (BE-SEC-02). Outcome,
SLA and control satisfaction reuse ``app.domain.kpis`` / ``app.domain.outcomes``; nothing here adds a business rule.
Personal data leaves the server only in its stored masked form; ciphertext columns are never selected.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import csrf_protected
from app.api.schemas import (
    AttemptList,
    AttemptOut,
    CaseDetail,
    ContactSelectionOut,
    ErrorResponse,
    FactSnapshotOut,
    FindingList,
    FindingOut,
    FscOut,
    HoldList,
    HoldOut,
    PartyRoleOut,
    PolicyOut,
    QuestionResult,
    RecordingSummary,
    RecordingTimeline,
    RiskAssessmentOut,
    RiskFactorOut,
    SaleOut,
    ScriptAssignmentList,
    ScriptAssignmentOut,
    ScriptPin,
    ScriptQuestionOut,
    ScriptSectionOut,
    ScriptVersionDetail,
    SessionDetail,
    SessionLink,
    SessionMedia,
    SessionTranscript,
    Sla,
    SurveyRunDetail,
    Timeline,
    TimelineItem,
    TranscriptRetryOut,
    TranscriptSegments,
)
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain.kpis import breached, is_test_attempt, load_facts, sla_exempt
from app.domain.outcomes import applicable_mandatory, controls_satisfied, derive_outcomes, question_satisfied
from app.security.authz import AuthContext, get_db, request_meta, require
from app.security.scope import not_found
from app.voice import media, transcript

router = APIRouter(prefix="/api/v1", tags=["call-detail"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 404, 422, 429)}
TERMINAL_STATES = {"VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED"}
UNAVAILABLE = {  # S0_SCREEN_SPEC "Call Detail"
    "media": "Recording not available — no audio is captured before Stage S1",
    "transcript": "Transcript not available — transcripts are captured from Stage S1",
}
ENTITY_ROUTES = {
    "contact_attempt": "/cases/{case}?attempt={id}",
    "conversation_session": "/cases/{case}?session={id}",
    "finding": "/cases/{case}?finding={id}",
}


# ---- scoped lookups ------------------------------------------------------------------------------------------
def _schema(db: Session) -> str:
    return str(db.connection().execute(text("SELECT current_schema()")).scalar_one())


def _one(db: Session, sql: str, **params: Any) -> dict[str, Any] | None:
    row = db.execute(text(sql), params).mappings().first()
    return dict(row) if row else None


def _deny(db: Session, request: Request, auth: AuthContext, entity_type: str, entity_id: uuid.UUID) -> Exception:
    return not_found(
        db,
        actor=auth.actor,
        meta=request_meta(request),
        entity_type=entity_type,
        entity_id=str(entity_id),
        reason="out of scope or missing",
    )


def _case(db: Session, request: Request, auth: AuthContext, case_id: uuid.UUID) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT c.*, s.policy_id FROM callback_case c JOIN sale_event s ON s.id = c.sale_event_id "
        "WHERE c.id = :i AND c.market_code = ANY(:m)",
        i=case_id,
        m=sorted(auth.markets),
    )
    if row is None:
        raise _deny(db, request, auth, "callback_case", case_id)
    return row


def _pin(db: Session, version_id: uuid.UUID) -> ScriptPin:
    r = _one(
        db,
        "SELECT v.id, v.script_family_id, f.code, v.version_label, v.status, v.manifest_sha256, "
        "v.content_approval_status "
        "FROM script_version v JOIN script_family f ON f.id = v.script_family_id WHERE v.id = :i",
        i=version_id,
    )
    assert r is not None
    return ScriptPin(
        script_version_id=r["id"],
        script_family_id=r["script_family_id"],
        family=r["code"],
        version_label=r["version_label"],
        status=r["status"],
        manifest_sha256=r["manifest_sha256"],
        content_approval_status=r["content_approval_status"],
    )


def _assessments(db: Session, sale_event_id: uuid.UUID, effective_id: uuid.UUID | None) -> list[RiskAssessmentOut]:
    factors: dict[uuid.UUID, list[RiskFactorOut]] = {}
    for f in db.execute(
        text(
            "SELECT fr.assessment_id, fr.factor_code, fr.value_type, fr.value, fr.source, fr.matched_rule_id, "
            "fr.result FROM risk_factor_result fr JOIN risk_assessment ra ON ra.id = fr.assessment_id "
            "WHERE ra.sale_event_id = :s ORDER BY fr.factor_code"
        ),
        {"s": sale_event_id},
    ).mappings():
        factors.setdefault(f["assessment_id"], []).append(
            RiskFactorOut(**{k: f[k] for k in RiskFactorOut.model_fields})
        )
    out = []
    for r in db.execute(
        text(
            "SELECT ra.*, rs.code || ' v' || rs.version AS rule_set FROM risk_assessment ra "
            "LEFT JOIN risk_rule_set_version rs ON rs.id = ra.rule_set_version_id "
            "WHERE ra.sale_event_id = :s ORDER BY ra.valid_at DESC, ra.id"
        ),
        {"s": sale_event_id},
    ).mappings():
        out.append(
            RiskAssessmentOut(
                id=r["id"],
                kind=r["kind"],
                origin=r["origin"],
                status=r["status"],
                band_code=r["band_code"],
                score=float(r["score"]) if r["score"] is not None else None,
                reason_codes=list(r["reason_codes"] or []),
                explanation=r["explanation"],
                source_original_value=r["source_original_value"],
                rule_set=r["rule_set"],
                assessed_at=r["assessed_at"],
                valid_at=r["valid_at"],
                input_snapshot_sha256=r["input_snapshot_sha256"],
                effective=r["id"] == effective_id,
                factors=factors.get(r["id"], []),
                supersedes_id=r["supersedes_id"],
            )
        )
    return out


def _snapshot(row: dict[str, Any]) -> FactSnapshotOut:
    return FactSnapshotOut(**{k: row[k] for k in FactSnapshotOut.model_fields})


def call_blockers(holds: list[HoldOut], has_eligible_contact: bool, state: str) -> list[str]:
    """The Call Detail pre-check (F3), shared with the S1-A voice session: active blocking holds, no eligible
    contact, or a terminal case state. An empty list means the case may be called."""
    blockers = [f"HOLD:{h.hold_reason}" for h in holds if h.active and h.is_blocking]
    if not has_eligible_contact:
        blockers.append("NO_ELIGIBLE_CONTACT")
    if state in TERMINAL_STATES:
        blockers.append(f"CASE_{state}")
    return blockers


def _holds(db: Session, case_id: uuid.UUID) -> list[HoldOut]:
    return [
        HoldOut(**{k: r[k] for k in HoldOut.model_fields if k != "active"}, active=r["released_at"] is None)
        for r in db.execute(
            text("SELECT * FROM case_hold WHERE callback_case_id = :c ORDER BY placed_at, id"), {"c": case_id}
        ).mappings()
    ]


def _num(v: Any) -> float | None:
    return float(v) if v is not None else None


# ---- API-037 ---------------------------------------------------------------------------------------------------
@router.get("/cases/{case_id}", response_model=CaseDetail, operation_id="case_detail", responses=_ERR)
def case_detail(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> CaseDetail:
    c = _case(db, request, auth, case_id)
    conn = db.connection()
    schema = _schema(db)
    markets = sorted(auth.markets)
    f = load_facts(conn, schema, markets, datetime.now(UTC))
    fc = f.cases[case_id]
    outcome = derive_outcomes(conn, schema, markets)[c["case_ref"]]
    exempt = sla_exempt(f, fc)
    matured = fc.due_at < f.now
    sla = Sla(
        due_at=fc.due_at,
        matured=matured,
        breached=breached(fc) if matured and not exempt else None,
        exempt=exempt,
        exemption_rule="SLA-EX-001" if exempt else None,
        note="Timeliness of the callback verification only; not a compliance outcome and not a verdict on the sale",
    )
    holds = _holds(db, case_id)
    selection = [
        ContactSelectionOut(**r)
        for r in db.execute(
            text(
                "SELECT pa.party_ref, pa.masked_name, ppr.role, cm.channel, cm.masked_value AS masked_contact, "
                "s.eligible, s.ineligibility_reason, s.rule_basis, s.decided_at, s.decided_by "
                "FROM case_contact_selection s JOIN party pa ON pa.id = s.party_id "
                "JOIN policy_party_role ppr ON ppr.id = s.policy_party_role_id "
                "LEFT JOIN contact_method cm ON cm.id = s.contact_method_id "
                "WHERE s.callback_case_id = :c AND NOT EXISTS "
                "(SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = s.id) "
                "ORDER BY s.eligible DESC, pa.party_ref, ppr.role"
            ),
            {"c": case_id},
        ).mappings()
    ]
    blockers = call_blockers(holds, any(s.eligible for s in selection), c["state"])
    pol = _one(db, "SELECT * FROM policy WHERE id = :p AND market_code = ANY(:m)", p=c["policy_id"], m=markets)
    sale = _one(
        db,
        "SELECT s.*, f.fsc_ref, f.display_name AS fsc_name, f.channel AS fsc_channel, f.status AS fsc_status "
        "FROM sale_event s LEFT JOIN fsc_representative f ON f.id = s.fsc_id WHERE s.id = :s",
        s=c["sale_event_id"],
    )
    assert pol is not None and sale is not None
    parties: dict[str, PartyRoleOut] = {}
    for r in db.execute(
        text(
            "SELECT pa.party_ref, pa.masked_name, pa.kind, r.role, r.authorization_ref FROM policy_party_role r "
            "JOIN party pa ON pa.id = r.party_id WHERE r.policy_id = :p AND r.valid_to IS NULL "
            "ORDER BY pa.party_ref, r.role"
        ),
        {"p": c["policy_id"]},
    ).mappings():
        p = parties.setdefault(
            r["party_ref"],
            PartyRoleOut(
                party_ref=r["party_ref"], masked_name=r["masked_name"], kind=r["kind"], roles=[], authorization_ref=None
            ),
        )
        p.roles.append(r["role"])
        p.authorization_ref = p.authorization_ref or r["authorization_ref"]
    effective = _one(
        db,
        "SELECT id FROM risk_assessment WHERE sale_event_id = :s AND status = 'FINAL' ORDER BY valid_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    assessments = _assessments(db, c["sale_event_id"], effective["id"] if effective else None)
    snapshots = [
        _snapshot(dict(r))
        for r in db.execute(
            text("SELECT * FROM policy_fact_snapshot WHERE sale_event_id = :s ORDER BY captured_at"),
            {"s": c["sale_event_id"]},
        ).mappings()
    ]
    current = _one(
        db,
        "SELECT script_version_id FROM script_assignment WHERE callback_case_id = :c ORDER BY assigned_at DESC LIMIT 1",
        c=case_id,
    )
    owner = (
        _one(db, "SELECT display_name FROM principal WHERE id = :p", p=c["owner_principal_id"])
        if c["owner_principal_id"]
        else None
    )
    cancellation = None
    if c["state"] == "CANCELLED":
        cancellation = {
            "reason": c["cancellation_reason"],
            "recorded_at": c["cancelled_recorded_at"],
            "authorized_by": c["cancellation_authorized_by"],
            "authorization_ref": c["cancellation_authorization_ref"],
            "sla_exempt": exempt,
        }
    return CaseDetail(
        case_id=case_id,
        case_ref=c["case_ref"],
        market=c["market_code"],
        obligation_type=c["obligation_type"],
        source_request_ref=c["source_request_ref"],
        state=c["state"],
        outcome=outcome.category,
        controls_satisfied=outcome.controls_satisfied,
        open_findings=outcome.open_findings,
        priority=c["priority"],
        owner=owner["display_name"] if owner else None,
        due_at=c["due_at"],
        verified_at=c["verified_at"],
        closed_at=c["closed_at"],
        closure_reason=c["closure_reason"],
        cancellation=cancellation,
        sla=sla,
        holds=holds,
        callable=not blockers,
        callable_blockers=blockers,
        risk_band=fc.band,
        effective_risk=next((a for a in assessments if a.effective), None),
        risk_assessments=assessments,
        policy=PolicyOut(
            **{k: pol[k] for k in PolicyOut.model_fields if k not in {"premium_amount", "sum_assured"}},
            premium_amount=_num(pol["premium_amount"]),
            sum_assured=_num(pol["sum_assured"]),
        ),
        sale=SaleOut(
            **{k: sale[k] for k in SaleOut.model_fields if k not in {"premium_amount", "fsc"}},
            premium_amount=_num(sale["premium_amount"]),
            fsc=FscOut(
                fsc_ref=sale["fsc_ref"],
                display_name=sale["fsc_name"],
                channel=sale["fsc_channel"],
                status=sale["fsc_status"],
            )
            if sale["fsc_ref"]
            else None,
        ),
        parties=list(parties.values()),
        contact_selection=selection,
        fact_snapshots=snapshots,
        current_script=_pin(db, current["script_version_id"]) if current else None,
        attempts=len(fc.attempts),
        sessions=int(
            db.execute(
                text(
                    "SELECT count(*) FROM conversation_session s JOIN contact_attempt a ON a.id = s.contact_attempt_id "
                    "WHERE a.callback_case_id = :c"
                ),
                {"c": case_id},
            ).scalar_one()
        ),
        source_type=c["source_type"],
        is_synthetic=c["is_synthetic"],
        data_as_of=f.now,
    )


# ---- API-038, API-043 ------------------------------------------------------------------------------------------
_ATTEMPT_SQL = (
    "SELECT a.*, pa.masked_name AS contacted_party, s.id AS session_id, s.session_ref, s.state AS session_state, "
    "s.media_status, "
    "(SELECT r.id FROM survey_run r WHERE r.session_id = s.id ORDER BY r.started_at DESC LIMIT 1) AS run_id, "
    "(SELECT r.status FROM survey_run r WHERE r.session_id = s.id ORDER BY r.started_at DESC LIMIT 1) AS run_status "
    "FROM contact_attempt a JOIN callback_case c ON c.id = a.callback_case_id "
    "LEFT JOIN party pa ON pa.id = a.contacted_party_id LEFT JOIN conversation_session s "
    "ON s.contact_attempt_id = a.id WHERE c.market_code = ANY(:m) "
)


def attempt_kind(transport: str, record_origin: str) -> Literal["CONTACT_ATTEMPT", "TEST_SESSION"]:
    """D-48: every S1 browser session created by Call360 is a synthetic mock-provider test, not a customer contact."""
    return "TEST_SESSION" if is_test_attempt(transport, record_origin) else "CONTACT_ATTEMPT"


def _attempt(r: dict[str, Any]) -> AttemptOut:
    return AttemptOut(
        **{k: r[k] for k in AttemptOut.model_fields if k not in {"case_id", "session", "attempt_kind"}},
        case_id=r["callback_case_id"],
        attempt_kind=attempt_kind(r["transport"], r["record_origin"]),
        session=SessionLink(
            session_id=r["session_id"],
            session_ref=r["session_ref"],
            state=r["session_state"],
            survey_run_id=r["run_id"],
            survey_run_status=r["run_status"],
        )
        if r["session_id"]
        else None,
    )


@router.get("/cases/{case_id}/attempts", response_model=AttemptList, operation_id="case_attempts", responses=_ERR)
def case_attempts(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> AttemptList:
    _case(db, request, auth, case_id)
    rows = db.execute(
        text(_ATTEMPT_SQL + "AND a.callback_case_id = :c ORDER BY a.sequence"),
        {"c": case_id, "m": sorted(auth.markets)},
    ).mappings()
    return AttemptList(items=[_attempt(dict(r)) for r in rows])


@router.get("/attempts/{attempt_id}", response_model=AttemptOut, operation_id="attempt_detail", responses=_ERR)
def attempt_detail(
    attempt_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> AttemptOut:
    r = _one(db, _ATTEMPT_SQL + "AND a.id = :a", a=attempt_id, m=sorted(auth.markets))
    if r is None:
        raise _deny(db, request, auth, "contact_attempt", attempt_id)
    return _attempt(r)


# ---- API-039 ---------------------------------------------------------------------------------------------------
@router.get(
    "/cases/{case_id}/script-assignment",
    response_model=ScriptAssignmentList,
    operation_id="case_script_assignment",
    responses=_ERR,
)
def case_script_assignment(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> ScriptAssignmentList:
    _case(db, request, auth, case_id)
    rows = db.execute(
        text(
            "SELECT a.*, rv.rule_code || ' v' || rv.version AS matched_rule, "
            "EXISTS (SELECT 1 FROM script_assignment x WHERE x.supersedes_id = a.id) AS superseded "
            "FROM script_assignment a LEFT JOIN script_assignment_rule_version rv ON rv.id = a.matched_rule_version_id "
            "WHERE a.callback_case_id = :c ORDER BY a.assigned_at DESC"
        ),
        {"c": case_id},
    ).mappings()
    return ScriptAssignmentList(
        items=[
            ScriptAssignmentOut(
                **{k: r[k] for k in ScriptAssignmentOut.model_fields if k != "script"},
                script=_pin(db, r["script_version_id"]),
            )
            for r in rows
        ]
    )


# ---- API-040, API-041, API-042 ---------------------------------------------------------------------------------
@router.get("/cases/{case_id}/timeline", response_model=Timeline, operation_id="case_timeline", responses=_ERR)
def case_timeline(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> Timeline:
    _case(db, request, auth, case_id)
    rows = db.execute(  # creation first among simultaneous events
        text(
            "SELECT * FROM case_event WHERE callback_case_id = :c "
            "ORDER BY occurred_at, (event_type = 'CASE_CREATED') DESC, id"
        ),
        {"c": case_id},
    ).mappings()
    items = []
    for r in rows:
        tpl = ENTITY_ROUTES.get(r["related_entity_type"] or "")
        route = tpl.format(case=case_id, id=r["related_entity_id"]) if tpl and r["related_entity_id"] else None
        items.append(TimelineItem(**{k: r[k] for k in TimelineItem.model_fields if k != "route"}, route=route))
    return Timeline(items=items)


@router.get("/cases/{case_id}/findings", response_model=FindingList, operation_id="case_findings", responses=_ERR)
def case_findings(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> FindingList:
    _case(db, request, auth, case_id)
    rows = db.execute(
        text(
            "SELECT f.*, qe.survey_run_id, qbi.question_code FROM finding f "
            "LEFT JOIN question_execution qe ON qe.id = f.question_execution_id "
            "LEFT JOIN question_revision qr ON qr.id = qe.question_revision_id "
            "LEFT JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id "
            "WHERE f.callback_case_id = :c ORDER BY f.raised_at, f.finding_ref"
        ),
        {"c": case_id},
    ).mappings()
    material = db.execute(
        text(
            "SELECT cv.code FROM code_value cv JOIN code_list_version v ON v.id = cv.code_list_version_id "
            "AND v.status = 'ACTIVE' JOIN code_list l ON l.id = v.code_list_id "
            "WHERE l.code = 'finding_materiality_policy' AND (cv.attributes->>'material')::boolean ORDER BY cv.code"
        )
    ).scalars()
    return FindingList(
        items=[FindingOut(**{k: r[k] for k in FindingOut.model_fields}) for r in rows],
        material_severities=list(material),
    )


@router.get("/cases/{case_id}/holds", response_model=HoldList, operation_id="case_holds", responses=_ERR)
def case_holds(
    case_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> HoldList:
    _case(db, request, auth, case_id)
    return HoldList(items=_holds(db, case_id))


# ---- API-044…046 -----------------------------------------------------------------------------------------------
def _session(db: Session, request: Request, auth: AuthContext, session_id: uuid.UUID) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT s.*, a.attempt_ref, a.callback_case_id AS case_id, c.case_ref, c.sale_event_id, "
        "pa.masked_name AS contacted_party FROM conversation_session s JOIN contact_attempt a "
        "ON a.id = s.contact_attempt_id JOIN callback_case c ON c.id = a.callback_case_id "
        "LEFT JOIN party pa ON pa.id = s.contacted_party_id WHERE s.id = :s AND c.market_code = ANY(:m)",
        s=session_id,
        m=sorted(auth.markets),
    )
    if r is None:
        raise _deny(db, request, auth, "conversation_session", session_id)
    return r


@router.get("/sessions/{session_id}", response_model=SessionDetail, operation_id="session_detail", responses=_ERR)
def session_detail(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SessionDetail:
    s = _session(db, request, auth, session_id)
    pin = _pin(db, s["script_version_id"])
    snap = _one(db, "SELECT * FROM policy_fact_snapshot WHERE id = :i", i=s["policy_fact_snapshot_id"])
    risk = next((a for a in _assessments(db, s["sale_event_id"], None) if a.id == s["risk_assessment_id"]), None)
    runs = db.execute(
        text("SELECT id FROM survey_run WHERE session_id = :s ORDER BY started_at"), {"s": session_id}
    ).scalars()
    return SessionDetail(
        id=s["id"],
        session_ref=s["session_ref"],
        case_id=s["case_id"],
        case_ref=s["case_ref"],
        attempt_id=s["contact_attempt_id"],
        attempt_ref=s["attempt_ref"],
        state=s["state"],
        transport=s["transport"],
        started_at=s["started_at"],
        ended_at=s["ended_at"],
        script=pin,
        script_manifest_sha256=s["script_manifest_sha256"],
        script_pin_matches=s["script_manifest_sha256"] == pin.manifest_sha256,
        risk_assessment=risk,
        risk_snapshot_sha256=s["risk_snapshot_sha256"],
        fact_snapshot=_snapshot(snap) if snap else None,
        fact_snapshot_pin_matches=bool(snap and snap["sha256"] == s["policy_fact_snapshot_sha256"]),
        contacted_party=s["contacted_party"],
        contact_method_snapshot=s["contact_method_snapshot"] or {},
        media_status=s["media_status"],
        transcript_status=s["transcript_status"],
        record_origin=s["record_origin"],
        survey_run_ids=list(runs),
    )


TRANSCRIPT_MESSAGES = {
    "CONSENT_DECLINED": "No transcript — recording consent was declined",
    "NOT_RECORDED": "No transcript — the session was not recorded",
    "RECORDING_IN_PROGRESS": "Transcript waits until the recording is finalised",
    "NO_AUDIO_STORED": "No transcript — no audio was stored",
    "PURGED": "Transcript text removed with the audio at local retention expiry",
    "ENGINE_NOT_CONFIGURED": "Transcription is not configured on this server",
    "QUEUED": "Transcription queued",
    "TRANSCRIBING": "Transcribing on this server (local model)",
    "TRACK_FAILED": "One track could not be transcribed",
    "RECORDING_GAPS": "Transcribed; the recording has gaps, which are never transcribed or filled in",
    "UNCERTAIN_SPEECH": "Transcribed; some speech is uncertain or was not recognised",
    "PROCESSED": "Transcribed",
}


def _transcript_view(
    request: Request, auth: AuthContext, s: dict[str, Any], session_id: uuid.UUID, db: Session
) -> SessionTranscript:
    configured = request.app.state.settings.transcription_model_dir is not None
    o = transcript.overview(db, s["contact_attempt_id"], engine_configured=configured)
    may_read = "transcript.sensitive.read" in auth.permissions
    status, reason = o["status"], o["reason"]
    if s["record_origin"] != "CALL360_RUNTIME":  # seeded S0 sessions never had capture
        reason, message = "NO_CAPTURE_BEFORE_S1", UNAVAILABLE["transcript"]
    else:
        message = TRANSCRIPT_MESSAGES.get(reason, f"Transcription failed ({reason})")
        message += " — machine transcript, not reviewed or certified" if status in ("COMPLETE", "PARTIAL") else ""
    has_text = status in ("COMPLETE", "PARTIAL")
    availability = (
        ("AVAILABLE" if may_read else "RESTRICTED")
        if has_text
        else {"PENDING": "PENDING", "PROCESSING": "PENDING", "FAILED": "FAILED"}.get(status, "NOT_AVAILABLE")
    )
    if has_text and not may_read:
        message += "; your role cannot read transcript text"
    failed = any(t["run"] and t["run"]["status"] == "FAILED" for t in o["tracks"])
    return SessionTranscript(
        session_id=session_id,
        availability=availability,
        status=status,
        reason=reason,
        message=message,
        session_transcript_status=s["transcript_status"],
        review_status="NOT_REVIEWED",
        uncertain=o["uncertain"],
        language="en",
        recording_status=o["recording_status"],
        can_read_text=has_text and may_read,
        can_retry=failed and may_read and configured,
        tracks=o["tracks"],
    )


@router.get(
    "/sessions/{session_id}/transcript",
    response_model=SessionTranscript,
    operation_id="session_transcript",
    responses=_ERR,
)
def session_transcript(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SessionTranscript:
    """API-045 (S1-D): transcript status, provenance and counts for any reader of the case — never text."""
    s = _session(db, request, auth, session_id)
    return _transcript_view(request, auth, s, session_id, db)


@router.get(
    "/sessions/{session_id}/transcript/segments",
    response_model=TranscriptSegments,
    operation_id="session_transcript_segments",
    responses=_ERR,
)
def session_transcript_segments(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("transcript.sensitive.read")),
    db: Session = Depends(get_db),
) -> TranscriptSegments:
    """Machine transcript text with speaker, timeline and evidence-WAV times, uncertainty and provenance (D-50).
    Every read is audited; text never appears in logs, events or error messages."""
    s = _session(db, request, auth, session_id)
    view = _transcript_view(request, auth, s, session_id, db)
    out = transcript.segments(db, media.store_for(request.app), s["contact_attempt_id"])
    write_audit(
        db,
        action="TRANSCRIPT.ACCESSED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="conversation_session",
        entity_id=str(session_id),
        after={
            "case_ref": s["case_ref"],
            "status": view.status,
            "segments": len(out["segments"]),
            "runs": [t.run.run_ref for t in view.tracks if t.run],
            "text_sha256": [t.run.text_sha256 for t in view.tracks if t.run and t.run.text_sha256],
        },
    )
    db.commit()
    return TranscriptSegments(
        session_id=session_id,
        status=view.status,
        review_status="NOT_REVIEWED",
        segments=out["segments"],
        problems=out["problems"],
        timeline=RecordingTimeline(session_id=session_id, **out["timeline"]),
    )


@router.post(
    "/sessions/{session_id}/transcript/retry",
    response_model=TranscriptRetryOut,
    operation_id="session_transcript_retry",
    responses=_ERR,
)
@csrf_protected
def session_transcript_retry(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("transcript.sensitive.read")),
    db: Session = Depends(get_db),
) -> TranscriptRetryOut:
    """Queue a new transcription revision for each track whose latest run FAILED. Idempotent: tracks that are
    queued, processing or done are left alone. The failed revision stays as it is."""
    from app.security import csrf as _csrf

    settings = request.app.state.settings
    _csrf.verify(
        request, settings.csrf_secret.get_secret_value(), f"sid:{auth.session_id}", request.app.state.cookies.csrf
    )
    s = _session(db, request, auth, session_id)
    try:
        engine = transcript.engine_for(request.app)
        queued = transcript.retry(
            db, engine, media.store_for(request.app), settings, s["contact_attempt_id"], actor=str(auth.principal_id)
        )
    except transcript.TranscriptError as exc:
        raise AppError(409, exc.code, exc.message) from exc
    write_audit(
        db,
        action="TRANSCRIPT.RETRY_REQUESTED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="conversation_session",
        entity_id=str(session_id),
        after={"case_ref": s["case_ref"], "queued_tracks": queued},
    )
    db.commit()
    view = _transcript_view(request, auth, _session(db, request, auth, session_id), session_id, db)
    return TranscriptRetryOut(session_id=session_id, queued_tracks=queued, status=view.status)


@router.get(
    "/sessions/{session_id}/media/timeline",
    response_model=RecordingTimeline,
    operation_id="session_media_timeline",
    responses=_ERR,
)
def session_media_timeline(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> RecordingTimeline:
    """Recording time ↔ evidence-WAV mapping for both tracks, with gaps as spans (metadata only, no audio)."""
    s = _session(db, request, auth, session_id)
    return RecordingTimeline(session_id=session_id, **transcript.timeline(db, s["contact_attempt_id"]))


@router.get("/sessions/{session_id}/media", response_model=SessionMedia, operation_id="session_media", responses=_ERR)
def session_media(
    session_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SessionMedia:
    """API-046 (S1-C): recording evidence metadata for any reader of the case; audio needs ``recording.read``."""
    s = _session(db, request, auth, session_id)
    rec = media.summary(db, s["contact_attempt_id"])
    may_read = "recording.read" in auth.permissions
    stored = any(t["media_status"] == "AVAILABLE" for t in rec["tracks"])
    if stored:
        availability, reason = ("AVAILABLE", "RECORDED") if may_read else ("RESTRICTED", "RECORDING_READ_REQUIRED")
        message = (
            "Recording stored"
            + (" with gaps — see the manifest" if rec["status"] == "PARTIAL" else "")
            + ("" if may_read else "; your role cannot retrieve recorded audio")
        )
    elif rec["status"] == "FAILED":
        availability, reason, message = "FAILED", "CAPTURE_FAILED", "Recording consented but no audio was stored"
    elif rec["status"] == "RECORDING":
        availability, reason, message = "NOT_AVAILABLE", "IN_PROGRESS", "Recording in progress or finishing upload"
    elif rec["status"] == "PURGED":
        availability, reason, message = "NOT_AVAILABLE", "PURGED", "Audio removed at local retention expiry"
    elif s["record_origin"] == "CALL360_RUNTIME":
        availability, reason = "NOT_AVAILABLE", "NOT_RECORDED"
        message = "Not recorded — recording consent was declined" if rec["consent"] == "DECLINED" else "Not recorded"
    else:
        availability, reason, message = "NOT_AVAILABLE", "NO_CAPTURE_BEFORE_S1", UNAVAILABLE["media"]
    return SessionMedia(
        session_id=session_id,
        availability=availability,
        reason=reason,
        message=message,
        media_status=s["media_status"],
        recording=RecordingSummary(**rec),
        can_retrieve_audio=stored and may_read,
    )


@router.get(
    "/sessions/{session_id}/media/{track}/audio",
    operation_id="session_media_audio",
    responses={**_ERR, 200: {"content": {"audio/wav": {}}, "description": "WAV of the stored chunks, in order"}},
    response_class=StreamingResponse,
)
def session_media_audio(
    session_id: uuid.UUID,
    track: Literal["MIC", "PROVIDER_PLAYBACK"],
    request: Request,
    purpose: Literal["DOWNLOAD", "PLAYBACK"] = "DOWNLOAD",
    auth: AuthContext = Depends(require("recording.read")),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Audited retrieval of one recorded track (D-46). The WAV holds the stored chunks in order; gaps are listed in the
    manifest and never filled. ``X-Call360-Content-SHA256`` equals the stored content checksum."""
    s = _session(db, request, auth, session_id)
    rs = media.store_for(request.app)
    try:
        out = media.audio_stream(db, rs, s["contact_attempt_id"], track) if rs is not None else None
    except media.RecordingError as exc:  # stored audio no longer matches its checksum: refuse, and record that
        write_audit(
            db,
            action="RECORDING.ACCESS_DENIED",
            outcome="DENIED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="conversation_session",
            entity_id=str(session_id),
            after={"track": track, "reason": exc.code},
        )
        db.commit()
        raise AppError(exc.status, exc.code, exc.message) from exc
    if out is None:
        write_audit(
            db,
            action="RECORDING.ACCESS_DENIED",
            outcome="DENIED",
            actor=auth.actor,
            meta=request_meta(request),
            entity_type="conversation_session",
            entity_id=str(session_id),
            after={"track": track, "reason": "no stored audio"},
        )
        db.commit()
        raise AppError(404, "RECORDING_NOT_AVAILABLE", "No stored audio for this track")
    asset, body = out
    write_audit(
        db,
        action="RECORDING.ACCESSED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="conversation_session",
        entity_id=str(session_id),
        after={
            "track": track,
            "asset_ref": asset["asset_ref"],
            "coverage": asset["coverage"],
            "content_sha256": asset["content_sha256"],
            "case_ref": s["case_ref"],
            "purpose": purpose,
        },
    )
    db.commit()
    return StreamingResponse(
        body,
        media_type="audio/wav",
        headers={
            "Content-Disposition": f"{'inline' if purpose == 'PLAYBACK' else 'attachment'}; "
            f'filename="{asset["asset_ref"]}.wav"',
            "X-Call360-Content-SHA256": asset["content_sha256"],
            "X-Call360-Manifest-SHA256": asset["manifest_sha256"],
            "X-Call360-Coverage": asset["coverage"],
            "Cache-Control": "no-store",
        },
    )


# ---- API-047 ---------------------------------------------------------------------------------------------------
@router.get(
    "/survey-runs/{survey_run_id}", response_model=SurveyRunDetail, operation_id="survey_run_detail", responses=_ERR
)
def survey_run_detail(
    survey_run_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("case.read")),
    db: Session = Depends(get_db),
) -> SurveyRunDetail:
    r = _one(
        db,
        "SELECT r.*, s.session_ref, s.risk_assessment_id, a.callback_case_id AS case_id, c.case_ref "
        "FROM survey_run r JOIN conversation_session s ON s.id = r.session_id JOIN contact_attempt a "
        "ON a.id = s.contact_attempt_id JOIN callback_case c ON c.id = a.callback_case_id "
        "WHERE r.id = :r AND c.market_code = ANY(:m)",
        r=survey_run_id,
        m=sorted(auth.markets),
    )
    if r is None:
        raise _deny(db, request, auth, "survey_run", survey_run_id)
    ctx = _one(
        db,
        "SELECT v.manifest, pfs.facts, ra.band_code FROM script_version v, policy_fact_snapshot pfs, "
        "risk_assessment ra WHERE v.id = :v AND pfs.id = :p AND ra.id = :ra",
        v=r["script_version_id"],
        p=r["policy_fact_snapshot_id"],
        ra=r["risk_assessment_id"],
    )
    applicable = (
        {q["question_revision_id"] for q in applicable_mandatory(ctx["manifest"], ctx["facts"], ctx["band_code"])}
        if ctx
        else set()
    )
    findings: dict[uuid.UUID, list[str]] = {}
    for fr in db.execute(
        text(
            "SELECT f.question_execution_id, f.finding_ref FROM finding f JOIN question_execution qe "
            "ON qe.id = f.question_execution_id WHERE qe.survey_run_id = :r ORDER BY f.finding_ref"
        ),
        {"r": survey_run_id},
    ):
        findings.setdefault(fr.question_execution_id, []).append(fr.finding_ref)
    questions = []
    for q in db.execute(
        text(
            "SELECT qe.id, qe.position, qe.delivery_status, qe.retries, qe.skip_reason, qe.event_range, "
            "qe.record_origin, qe.question_revision_id, qbi.question_code, qbi.intent, qr.customer_wording, "
            "qr.revision, qr.delivery_mode, qr.answer_type, qr.mandatory, qr.expected_answer_policy, "
            "qr.expected_value, qr.policy_fact_key, ao.answer_state, ao.typed_value, ao.verbatim_text_redacted, "
            "ao.extraction_engine, re.rule_ref, re.expected AS rule_expected, re.observed AS rule_observed, "
            "re.result AS rule_result FROM question_execution qe "
            "JOIN question_revision qr ON qr.id = qe.question_revision_id "
            "JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id "
            "LEFT JOIN LATERAL (SELECT * FROM answer_observation ao WHERE ao.question_execution_id = qe.id "
            "  AND NOT EXISTS (SELECT 1 FROM answer_observation x WHERE x.supersedes_id = ao.id) "
            "  ORDER BY ao.created_at DESC LIMIT 1) ao ON true "
            "LEFT JOIN LATERAL (SELECT * FROM rule_evaluation re WHERE re.question_execution_id = qe.id "
            "  ORDER BY re.evaluated_at DESC LIMIT 1) re ON true "
            "WHERE qe.survey_run_id = :r ORDER BY qe.position"
        ),
        {"r": survey_run_id},
    ).mappings():
        counted = str(q["question_revision_id"]) in applicable
        questions.append(
            QuestionResult(
                question_execution_id=q["id"],
                wording=q["customer_wording"],
                control_satisfied=question_satisfied(q["expected_answer_policy"], q["answer_state"], q["rule_result"])
                if counted
                else None,
                findings=findings.get(q["id"], []),
                **{
                    k: q[k]
                    for k in QuestionResult.model_fields
                    if k not in {"question_execution_id", "wording", "control_satisfied", "findings"}
                },
            )
        )
    return SurveyRunDetail(
        id=r["id"],
        session_id=r["session_id"],
        session_ref=r["session_ref"],
        case_id=r["case_id"],
        case_ref=r["case_ref"],
        status=r["status"],
        started_at=r["started_at"],
        completed_at=r["completed_at"],
        script=_pin(db, r["script_version_id"]),
        script_manifest_sha256=r["script_manifest_sha256"],
        policy_fact_snapshot_id=r["policy_fact_snapshot_id"],
        controls_satisfied=controls_satisfied(db.connection(), _schema(db), survey_run_id),
        questions=questions,
        record_origin=r["record_origin"],
    )


# ---- API-063 ---------------------------------------------------------------------------------------------------
@router.get(
    "/script-versions/{script_version_id}",
    response_model=ScriptVersionDetail,
    operation_id="script_version_detail",
    responses=_ERR,
)
def script_version_detail(
    script_version_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(require("script.read")),
    db: Session = Depends(get_db),
) -> ScriptVersionDetail:
    v = _one(
        db,
        "SELECT v.*, f.code AS family, f.name AS family_name, f.market_code FROM script_version v "
        "JOIN script_family f ON f.id = v.script_family_id WHERE v.id = :v AND f.market_code = ANY(:m)",
        v=script_version_id,
        m=sorted(auth.markets),
    )
    if v is None:
        raise _deny(db, request, auth, "script_version", script_version_id)
    controls: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for cm in db.execute(
        text(
            "SELECT cm.question_bank_item_id, ct.control_code, ct.name, ct.owner_role, cm.rationale, cm.status, "
            "rr.issuer, rr.title, rr.document_version, rr.interpretation_status FROM control_mapping cm "
            "JOIN control ct ON ct.id = cm.control_id LEFT JOIN regulatory_reference rr "
            "ON rr.id = cm.regulatory_reference_id AND rr.market_code = ANY(:m) ORDER BY ct.control_code"
        ),
        {"m": sorted(auth.markets)},  # F6: regulatory references only from the caller's markets (D-39)
    ).mappings():
        controls.setdefault(cm["question_bank_item_id"], []).append(
            {k: cm[k] for k in cm.keys() if k != "question_bank_item_id"}
        )
    sections = []
    for sec in db.execute(
        text(
            "SELECT ss.position, ss.inclusion_condition, m.id AS module_id, m.code, m.name, m.kind "
            "FROM script_section ss JOIN script_module m ON m.id = ss.script_module_id "
            "WHERE ss.script_version_id = :v ORDER BY ss.position"
        ),
        {"v": script_version_id},
    ).mappings():
        qs = []
        for q in db.execute(
            text(
                "SELECT mq.position, mq.branch_condition, qbi.id AS item_id, qbi.question_code, qbi.intent, qr.* "
                "FROM module_question mq JOIN question_revision qr ON qr.id = mq.question_revision_id "
                "JOIN question_bank_item qbi ON qbi.id = qr.question_bank_item_id "
                "WHERE mq.script_module_id = :m ORDER BY mq.position"
            ),
            {"m": sec["module_id"]},
        ).mappings():
            qs.append(
                ScriptQuestionOut(
                    wording=q["customer_wording"],
                    controls=controls.get(q["item_id"], []),
                    **{k: q[k] for k in ScriptQuestionOut.model_fields if k not in {"wording", "controls"}},
                )
            )
        sections.append(
            ScriptSectionOut(
                position=sec["position"],
                module_code=sec["code"],
                module_name=sec["name"],
                module_kind=sec["kind"],
                inclusion_condition=sec["inclusion_condition"],
                questions=qs,
            )
        )
    return ScriptVersionDetail(
        **{k: v[k] for k in ScriptVersionDetail.model_fields if k not in {"market", "sections"}},
        market=v["market_code"],
        sections=sections,
    )
