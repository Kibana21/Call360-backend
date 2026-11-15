"""Migration 0006 integrity — holds (INV-06, BE-DATA-09), cancellation rules, contact eligibility (INV-14,
D-36), attempts and sessions (INV-03, INV-05, INV-09), runs, evidence and findings (ADR-0005 §3)."""

from __future__ import annotations

import uuid

from sqlalchemy import Connection, text

from tests.domain_support import (
    CANCELLATIONS,
    NOW,
    ROLES,
    SCHEMA,
    Chain,
    days,
    ensure_active,
    ins,
    make_contact,
    make_module,
    make_party,
    make_question,
    make_version,
    rejected,
    scalar,
)

IMMUTABLE, CHECK, UNIQUE = "42501", "23514", "23505"
CASE = f"UPDATE {SCHEMA}.callback_case SET "


def _blocking(conn: Connection, case: uuid.UUID) -> bool:
    return bool(scalar(conn, f"SELECT has_blocking_hold FROM {SCHEMA}.callback_case WHERE id=:i", i=case))


# ---- holds (ADR-0008 §2, INV-06) -------------------------------------------------------------------------
def test_be_data_09_blocking_hold_prevents_ready_and_release_allows_it(conn: Connection) -> None:
    c = Chain(conn)
    hold = c.hold("RISK_TRIAGE")  # is_blocking passed as false; derived from the list value
    assert scalar(conn, f"SELECT is_blocking FROM {SCHEMA}.case_hold WHERE id=:i", i=hold) is True
    assert _blocking(conn, c.case)
    for state in ("READY", "IN_PROGRESS"):
        assert rejected(conn, CASE + f"state = '{state}' WHERE id = :i", {"i": c.case}) == CHECK
    conn.execute(text(CASE + "has_blocking_hold = false WHERE id = :i"), {"i": c.case})
    assert _blocking(conn, c.case)  # derived, cannot be cleared by hand
    conn.execute(
        text(
            f"UPDATE {SCHEMA}.case_hold SET released_at = :t, released_by = 'pytest', release_reason = 'ok' WHERE id=:i"
        ),
        {"t": NOW, "i": hold},
    )
    assert not _blocking(conn, c.case)
    conn.execute(text(CASE + "state = 'READY' WHERE id = :i"), {"i": c.case})


def test_be_data_09_blocking_hold_cannot_be_placed_on_a_ready_case(conn: Connection) -> None:
    c = Chain(conn, state="READY")
    c.hold("OPERATOR_HOLD")  # non-blocking: allowed
    assert not _blocking(conn, c.case)
    sp = conn.begin_nested()
    try:
        c.hold("NO_ELIGIBLE_CONTACT")
        raise AssertionError("blocking hold placed on READY case")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == CHECK


def test_hold_records_are_placed_once_released_once_and_never_deleted(conn: Connection) -> None:
    c = Chain(conn)
    hold = c.hold("DATA_CONFLICT")
    hold_sql = f"UPDATE {SCHEMA}.case_hold SET "
    assert rejected(conn, hold_sql + "placed_reason = 'x' WHERE id = :i", {"i": hold}) == IMMUTABLE
    assert rejected(conn, hold_sql + "released_at = now() WHERE id = :i", {"i": hold}) == CHECK  # all three fields
    conn.execute(
        text(hold_sql + "released_at = now(), released_by = 'p', release_reason = 'r' WHERE id = :i"), {"i": hold}
    )
    sql = hold_sql + "released_at = now(), released_by = 'q', release_reason = 's' WHERE id = :i"
    assert rejected(conn, sql, {"i": hold}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.case_hold WHERE id = :i", {"i": hold}) == IMMUTABLE
    c.hold("DATA_CONFLICT")  # a new placement after release is allowed
    sp = conn.begin_nested()
    try:
        c.hold("DATA_CONFLICT")
        raise AssertionError("duplicate active hold")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == UNIQUE


# ---- cancellation and terminal states ---------------------------------------------------------------------
def test_cancellation_fields_only_on_cancelled_and_recorded_once(conn: Connection) -> None:
    c = Chain(conn)
    cv = ensure_active(conn, "case_cancellation_reason", CANCELLATIONS)
    params = {"r": "POLICY_NOT_TAKEN_UP", "v": cv, "i": c.case}
    sql = CASE + "cancellation_reason = :r, cancellation_reason_list_version_id = :v, cancelled_recorded_at = now() "
    assert rejected(conn, sql + "WHERE id = :i", params) == CHECK  # state is not CANCELLED
    assert rejected(conn, CASE + "state = 'CANCELLED' WHERE id = :i", {"i": c.case}) == CHECK  # no reason recorded
    auth = ", cancellation_authorized_by = 'pytest' "
    assert rejected(conn, sql + auth + ", state = 'CANCELLED' WHERE id = :i", params) == CHECK  # auth needs a ref
    conn.execute(text(sql + ", state = 'CANCELLED' WHERE id = :i"), params)
    assert rejected(conn, CASE + "cancelled_recorded_at = now() - interval '1 day' WHERE id = :i", params) == IMMUTABLE
    assert (
        rejected(
            conn, CASE + "cancellation_authorized_by = 'x', cancellation_authorization_ref = 'y' WHERE id = :i", params
        )
        == IMMUTABLE
    )
    assert rejected(conn, CASE + "state = 'READY' WHERE id = :i", {"i": c.case}) == IMMUTABLE  # terminal


def test_closure_and_verification_facts(conn: Connection) -> None:
    c = Chain(conn)
    assert rejected(conn, CASE + "state = 'CLOSED_UNVERIFIED', closed_at = now() WHERE id = :i", {"i": c.case}) == CHECK
    assert rejected(conn, CASE + "state = 'VERIFIED' WHERE id = :i", {"i": c.case}) == CHECK
    conn.execute(text(CASE + "state = 'VERIFIED', verified_at = now() WHERE id = :i"), {"i": c.case})
    assert rejected(conn, CASE + "verified_at = now() + interval '1 hour' WHERE id = :i", {"i": c.case}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.callback_case WHERE id = :i", {"i": c.case}) == IMMUTABLE


def test_case_market_must_match_policy_and_identity_is_fixed(conn: Connection) -> None:
    c = Chain(conn, market="SG")
    assert rejected(conn, CASE + "case_ref = 'CB-NEW' WHERE id = :i", {"i": c.case}) == IMMUTABLE
    sql = (
        f"INSERT INTO {SCHEMA}.callback_case (id, case_ref, sale_event_id, obligation_type, source_request_ref, "
        "market_code, state, priority, due_at, created_by, source_type, source_system, source_reference, recorded_at, "
        "is_synthetic) VALUES (gen_random_uuid(), 'CB-MKT', :s, 'SALE_VERIFICATION', 'OTHER', 'MY', 'CREATED', 3, "
        "now(), 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, sql, {"s": c.sale}) == CHECK


# ---- contact eligibility (D-36, INV-14) ---------------------------------------------------------------------
def _select(
    conn: Connection,
    c: Chain,
    role_id: uuid.UUID,
    party: uuid.UUID,
    contact: uuid.UUID | None,
    role: str,
    eligible: bool,
    reason: str | None = None,
) -> str | None:
    rv = ensure_active(conn, "callable_party_roles", ROLES)
    sp = conn.begin_nested()
    try:
        ins(
            conn,
            "case_contact_selection",
            callback_case_id=c.case,
            party_id=party,
            policy_party_role_id=role_id,
            contact_method_id=contact,
            eligible=eligible,
            ineligibility_reason=reason,
            rule_basis=role,
            rule_basis_list_version_id=rv,
            decided_at=NOW - days(1),
            decided_by="SYSTEM:pytest",
        )
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        return str(getattr(getattr(exc, "orig", None), "sqlstate", None))
    sp.commit()
    return None


def test_inv_14_owner_with_valid_contact_is_eligible(conn: Connection) -> None:
    c = Chain(conn)
    assert _select(conn, c, c.role, c.party, c.contact, "OWNER", True) is None


def test_inv_14_authorized_contact_needs_authorisation_evidence(conn: Connection) -> None:
    c = Chain(conn)
    party = make_party(conn)
    contact = make_contact(conn, party)
    bare = ins(
        conn,
        "policy_party_role",
        policy_id=c.policy,
        party_id=party,
        role="AUTHORIZED_CONTACT",
        valid_from=NOW - days(100),
    )
    assert _select(conn, c, bare, party, contact, "AUTHORIZED_CONTACT", True) == CHECK
    assert _select(conn, c, bare, party, contact, "AUTHORIZED_CONTACT", False, "AUTHORIZATION_NOT_EVIDENCED") is None
    expired = ins(
        conn,
        "policy_party_role",
        policy_id=c.policy,
        party_id=party,
        role="AUTHORIZED_CONTACT",
        valid_from=NOW - days(90),
        authorization_ref="AUTH-OLD",
        authorization_valid_from=NOW - days(90),
        authorization_valid_to=NOW - days(30),
    )
    assert _select(conn, c, expired, party, contact, "AUTHORIZED_CONTACT", True) == CHECK
    evidenced = ins(
        conn,
        "policy_party_role",
        policy_id=c.policy,
        party_id=party,
        role="AUTHORIZED_CONTACT",
        valid_from=NOW - days(80),
        authorization_ref="AUTH-1",
        authorization_valid_from=NOW - days(80),
    )
    assert _select(conn, c, evidenced, party, contact, "AUTHORIZED_CONTACT", True) is None


def test_inv_14_non_callable_role_suppressed_or_unconsented_contact_is_ineligible(conn: Connection) -> None:
    c = Chain(conn)
    insured = ins(
        conn, "policy_party_role", policy_id=c.policy, party_id=c.party, role="INSURED", valid_from=NOW - days(200)
    )
    assert _select(conn, c, insured, c.party, c.contact, "INSURED", True) == CHECK
    suppressed = make_contact(conn, c.party, suppressed=True, preference_rank=2)
    assert _select(conn, c, c.role, c.party, suppressed, "OWNER", True) == CHECK
    assert _select(conn, c, c.role, c.party, suppressed, "OWNER", False, "CONTACT_SUPPRESSED") is None
    unconsented = make_contact(conn, c.party, consent_status="UNKNOWN", preference_rank=3)
    assert _select(conn, c, c.role, c.party, unconsented, "OWNER", True) == CHECK
    assert _select(conn, c, c.role, c.party, None, "OWNER", True) == CHECK
    assert _select(conn, c, c.role, c.party, c.contact, "OWNER", True, "ROLE_NOT_CALLABLE") == CHECK  # reason pair
    assert _select(conn, c, c.role, c.party, c.contact, "INSURED", False, "ROLE_NOT_CALLABLE") == CHECK  # basis != role


# ---- attempts and sessions (INV-03, INV-05, INV-09) ---------------------------------------------------------
def test_be_data_08_attempt_snapshot_is_immutable(conn: Connection) -> None:
    c = Chain(conn)
    a = c.attempt("NO_ANSWER")
    att = f"UPDATE {SCHEMA}.contact_attempt SET "
    assert rejected(conn, att + "contact_snapshot = '{}' WHERE id = :i", {"i": a}) == IMMUTABLE
    assert rejected(conn, att + "contact_method_id = NULL WHERE id = :i", {"i": a}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.contact_attempt WHERE id = :i", {"i": a}) == IMMUTABLE
    conn.execute(text(att + "status = 'BUSY' WHERE id = :i"), {"i": a})  # disposition may progress


def test_attempt_rules(conn: Connection) -> None:
    c = Chain(conn)
    c.attempt("NO_ANSWER", seq=1)
    sp = conn.begin_nested()
    try:
        c.attempt("BUSY", seq=1)
        raise AssertionError("duplicate sequence")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == UNIQUE
    for over in ({"record_origin": "CALL360_RUNTIME"}, {"contacted_party_id": make_party(conn)}):
        sp = conn.begin_nested()
        try:
            c.attempt("NO_ANSWER", seq=5, **over)
            raise AssertionError(f"accepted {over}")
        except Exception as exc:  # noqa: BLE001
            sp.rollback()
            assert getattr(getattr(exc, "orig", None), "sqlstate", None) == CHECK


def _session_state(conn: Connection, c: Chain, attempt: uuid.UUID, **over: object) -> str | None:
    sp = conn.begin_nested()
    try:
        c.session(attempt, **over)
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        return str(getattr(getattr(exc, "orig", None), "sqlstate", None))
    sp.rollback()
    return None


def test_inv_03_only_connected_attempts_have_sessions(conn: Connection) -> None:
    c = Chain(conn)
    assert _session_state(conn, c, c.attempt("NO_ANSWER", seq=1)) == CHECK
    connected = c.attempt("CONNECTED", seq=2)
    c.session(connected)
    sql = f"UPDATE {SCHEMA}.contact_attempt SET status = 'NO_ANSWER' WHERE id = :i"
    assert rejected(conn, sql, {"i": connected}) == CHECK
    conn.execute(text(f"UPDATE {SCHEMA}.contact_attempt SET status = 'ENDED' WHERE id = :i"), {"i": connected})


def test_inv_09_session_pins_validated_against_history(conn: Connection) -> None:
    c = Chain(conn)
    a = c.attempt()
    assert _session_state(conn, c, a) is None
    module = make_module(conn, [c.question])
    old = make_version(
        conn,
        [module],
        published_at=NOW - days(300),
        effective_to=NOW - days(100),
        final="SUPERSEDED",
        questions=[c.question],
    )
    old_sha = scalar(conn, f"SELECT manifest_sha256 FROM {SCHEMA}.script_version WHERE id=:i", i=old)
    # Valid when the session started, SUPERSEDED now: accepted (T-15).
    assert (
        _session_state(conn, c, a, script_version_id=old, script_manifest_sha256=old_sha, started_at=NOW - days(150))
        is None
    )
    # After the version's effective interval ended: rejected.
    assert (
        _session_state(conn, c, a, script_version_id=old, script_manifest_sha256=old_sha, started_at=NOW - days(50))
        == CHECK
    )
    draft = make_version(conn, [module], final="DRAFT")
    assert _session_state(conn, c, a, script_version_id=draft, script_manifest_sha256=old_sha) == CHECK
    assert _session_state(conn, c, a, script_manifest_sha256="0" * 64) == CHECK
    assert _session_state(conn, c, a, risk_snapshot_sha256="0" * 64) == CHECK
    assert _session_state(conn, c, a, policy_fact_snapshot_sha256="0" * 64) == CHECK
    other = Chain(conn)
    assert _session_state(conn, c, a, risk_assessment_id=other.risk, risk_snapshot_sha256=other.risk_sha) == CHECK
    assert _session_state(conn, c, a, contacted_party_id=other.party) == CHECK


def test_inv_04_session_pins_are_immutable(conn: Connection) -> None:
    c = Chain(conn)
    s = c.session(c.attempt())
    ses = f"UPDATE {SCHEMA}.conversation_session SET "
    for col, val in [
        ("script_version_id", "gen_random_uuid()"),
        ("risk_snapshot_sha256", "repeat('e', 64)"),
        ("contact_method_snapshot", "'{}'"),
        ("started_at", "now()"),
    ]:
        assert rejected(conn, ses + f"{col} = {val} WHERE id = :i", {"i": s}) == IMMUTABLE
    conn.execute(text(ses + "state = 'FINALIZED' WHERE id = :i"), {"i": s})
    assert rejected(conn, f"DELETE FROM {SCHEMA}.conversation_session WHERE id = :i", {"i": s}) == IMMUTABLE


# ---- runs, executions and evidence ---------------------------------------------------------------------------
def test_survey_run_pins_equal_session_and_one_active_run(conn: Connection) -> None:
    c = Chain(conn)
    s = c.session(c.attempt())
    run = c.run(s)
    sp = conn.begin_nested()
    try:
        c.run(s)
        raise AssertionError("second active run")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == UNIQUE
    other = Chain(conn)
    sql = (
        f"INSERT INTO {SCHEMA}.survey_run (id, session_id, script_version_id, script_manifest_sha256, "
        "policy_fact_snapshot_id, status, started_at, record_origin, created_by, source_type, source_system, "
        "source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), :s, :v, :h, :p, 'COMPLETED', now(), "
        "'SYNTHETIC_SEED', 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, sql, {"s": s, "v": other.version, "h": other.version_sha, "p": c.snapshot}) == CHECK
    qe = ins(
        conn,
        "question_execution",
        survey_run_id=run,
        question_revision_id=c.question,
        position=1,
        delivery_status="DELIVERED",
        record_origin="SYNTHETIC_SEED",
    )
    foreign = make_question(conn)
    ex_sql = (
        f"INSERT INTO {SCHEMA}.question_execution (id, survey_run_id, question_revision_id, position, delivery_status, "
        "record_origin, created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) VALUES "
        "(gen_random_uuid(), :r, :q, 2, 'DELIVERED', 'SYNTHETIC_SEED', 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, ex_sql, {"r": run, "q": foreign}) == CHECK  # not in the pinned manifest
    conn.execute(text(f"UPDATE {SCHEMA}.survey_run SET status='COMPLETED', completed_at=now() WHERE id=:i"), {"i": run})
    qe_sql = f"UPDATE {SCHEMA}.question_execution SET retries = 3 WHERE id = :i"
    assert rejected(conn, qe_sql, {"i": qe}) == IMMUTABLE  # run finished
    run_sql = f"UPDATE {SCHEMA}.survey_run SET status = 'ABORTED' WHERE id = :i"
    assert rejected(conn, run_sql, {"i": run}) == IMMUTABLE


def test_answers_rule_evaluations_and_findings_are_evidence(conn: Connection) -> None:
    c = Chain(conn)
    run = c.run(c.session(c.attempt()))
    qe = ins(
        conn,
        "question_execution",
        survey_run_id=run,
        question_revision_id=c.question,
        position=1,
        delivery_status="DELIVERED",
        record_origin="SYNTHETIC_SEED",
    )
    obs = ins(
        conn,
        "answer_observation",
        question_execution_id=qe,
        answer_state="YES",
        typed_value={"value": True},
        extraction_engine="SYNTHETIC_SEED",
        extraction_version="S0-SEED-1",
        record_origin="SYNTHETIC_SEED",
    )
    ev = ins(
        conn,
        "rule_evaluation",
        question_execution_id=qe,
        rule_ref="R",
        rule_version="1",
        expected={"value": True},
        observed={"value": True},
        result="MATCH",
        evaluated_at=NOW,
        record_origin="SYNTHETIC_SEED",
    )
    for table, row in (("answer_observation", obs), ("rule_evaluation", ev)):
        assert rejected(conn, f"UPDATE {SCHEMA}.{table} SET created_by = 'x' WHERE id = :i", {"i": row}) == IMMUTABLE
        assert rejected(conn, f"DELETE FROM {SCHEMA}.{table} WHERE id = :i", {"i": row}) == IMMUTABLE
    obs_sql = (
        f"INSERT INTO {SCHEMA}.answer_observation (id, question_execution_id, answer_state, transcript_segment_ids, "
        "extraction_engine, extraction_version, record_origin, created_by, source_type, source_system, "
        "source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), :q, 'YES', ARRAY[gen_random_uuid()], "
        "'e', '1', 'SYNTHETIC_SEED', 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, obs_sql, {"q": qe}) == CHECK  # no transcripts before S1
    finding = ins(
        conn,
        "finding",
        finding_ref=f"F-{uuid.uuid4().hex[:8]}",
        callback_case_id=c.case,
        question_execution_id=qe,
        category="FACT_MISMATCH",
        severity="HIGH",
        status="OPEN",
        evidence_refs={"rule_evaluation_ids": [str(ev)]},
        origin="RULE_EVALUATION",
        raised_at=NOW,
        record_origin="SYNTHETIC_SEED",
    )
    f_sql = f"UPDATE {SCHEMA}.finding SET "
    assert rejected(conn, f_sql + "severity = 'LOW' WHERE id = :i", {"i": finding}) == IMMUTABLE
    conn.execute(text(f_sql + "status = 'UNDER_REVIEW' WHERE id = :i"), {"i": finding})
    assert rejected(conn, f"DELETE FROM {SCHEMA}.finding WHERE id = :i", {"i": finding}) == IMMUTABLE
    other = Chain(conn)
    sql = (
        f"INSERT INTO {SCHEMA}.finding (id, finding_ref, callback_case_id, question_execution_id, category, severity, "
        "status, evidence_refs, origin, raised_at, record_origin, created_by, source_type, source_system, "
        "source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), 'F-OTHER', :c, :q, 'FACT_MISMATCH', "
        "'HIGH', 'OPEN', '{}', 'RULE_EVALUATION', now(), 'SYNTHETIC_SEED', 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, sql, {"c": other.case, "q": qe}) == CHECK
    assert rejected(conn, sql.replace("'HIGH'", "'SEVERE'"), {"c": c.case, "q": None}) == CHECK  # severity enum


def test_script_assignment_freezes_a_valid_version_of_the_case_sale(conn: Connection) -> None:
    c = Chain(conn)
    base = {
        "callback_case_id": c.case,
        "script_version_id": c.version,
        "script_manifest_sha256": c.version_sha,
        "risk_assessment_id": c.risk,
        "policy_fact_snapshot_id": c.snapshot,
        "rule_trace": {"matched": None},
        "input_snapshot": {},
        "input_sha256": "a" * 64,
        "origin": "SEED",
        "assigned_at": NOW - days(30),
        "assigned_by": "SYSTEM:seed",
    }
    sid = ins(conn, "script_assignment", **base)
    assert rejected(conn, f"UPDATE {SCHEMA}.script_assignment SET origin='ENGINE' WHERE id=:i", {"i": sid}) == IMMUTABLE
    other = Chain(conn)
    for over in (
        {"script_manifest_sha256": "0" * 64},
        {"assigned_at": NOW - days(400)},
        {"risk_assessment_id": other.risk},
        {"policy_fact_snapshot_id": other.snapshot},
        {"script_version_id": make_version(conn, [c.module], final="DRAFT")},
    ):
        sp = conn.begin_nested()
        try:
            ins(conn, "script_assignment", **{**base, **over})
            raise AssertionError(f"accepted {over}")
        except Exception as exc:  # noqa: BLE001
            sp.rollback()
            assert getattr(getattr(exc, "orig", None), "sqlstate", None) == CHECK, over


def test_case_events_are_immutable(conn: Connection) -> None:
    c = Chain(conn)
    ev = ins(
        conn,
        "case_event",
        p=False,
        callback_case_id=c.case,
        event_type="CASE_CREATED",
        occurred_at=NOW,
        actor_ref="SYSTEM:pytest",
        summary="created",
    )
    assert rejected(conn, f"UPDATE {SCHEMA}.case_event SET summary='x' WHERE id=:i", {"i": ev}) == IMMUTABLE
