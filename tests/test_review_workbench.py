"""S3-C human review and case resolution over the API, on explicitly synthetic operational fixtures: review dossier,
finding dispositions with mandatory reasons, protected (material) dispositions and final decisions under maker-checker,
escalation (REV-003 reason) and further callback, premature verification blocked (open findings, unresolved mandatory
questions, unconverted discrepancies, missing identity evidence, no conversation), invalid transitions, concurrency
(stale row versions and stale proposals), duplicate submissions, unauthorised and out-of-market access, history
preservation and simulation isolation."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain import review as rv
from app.domain import review_fixtures as rf
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema
from tests.test_answer_evaluation_api import build
from tests.test_findings_api import publish_rules, rule
from tests.test_script_authoring import approve, ok

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # this module records fixtures and decisions; reset afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk")


def key() -> str:
    return f"test-{uuid.uuid4()}"


def dossier(c: TestClient, case_id: Any) -> dict[str, Any]:
    return ok(c.get(f"/api/v1/review/cases/{case_id}"))


def act(c: TestClient, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
    r = c.post(f"/api/v1{path}", json={"idempotency_key": key(), **body}, headers=csrf_header(c))
    assert r.status_code == status, r.text
    return dict(r.json())


def pin(db: Session, vid: str, manifest_sha: str, exclude: list[str]) -> tuple[str, str]:
    """Test setup: pin the published lifecycle script to an open seeded case (supersede its assignment)."""
    row = db.execute(
        text(
            f"SELECT c.id, c.case_ref, a.id AS aid FROM {SCHEMA}.callback_case c JOIN {SCHEMA}.script_assignment a "
            f"ON a.callback_case_id = c.id WHERE c.market_code = 'SG' AND c.state IN ('VALIDATED', 'READY') "
            f"AND NOT c.has_blocking_hold AND NOT EXISTS (SELECT 1 FROM {SCHEMA}.script_assignment x WHERE "
            f"x.supersedes_id = a.id) AND NOT (c.case_ref = ANY(:ex)) AND EXISTS (SELECT 1 FROM "
            f"{SCHEMA}.case_contact_selection s WHERE s.callback_case_id = c.id AND s.eligible) AND EXISTS (SELECT 1 "
            f"FROM {SCHEMA}.policy_fact_snapshot f JOIN {SCHEMA}.sale_event se ON se.id = f.sale_event_id WHERE "
            f"se.id = c.sale_event_id AND f.facts->>'premium_term_years' IS NOT NULL) ORDER BY c.case_ref LIMIT 1"
        ),
        {"ex": exclude},
    ).one()
    db.execute(
        text(
            f"INSERT INTO {SCHEMA}.script_assignment (id, callback_case_id, script_version_id, "
            "script_manifest_sha256, policy_fact_snapshot_id, risk_assessment_id, rule_trace, input_snapshot, "
            "input_sha256, origin, assigned_at, assigned_by, created_by, source_type, source_system, "
            "source_reference, recorded_at, is_synthetic, supersedes_id) SELECT :i, callback_case_id, :v, :sha, "
            "policy_fact_snapshot_id, risk_assessment_id, rule_trace, input_snapshot, input_sha256, "
            "'MANUAL_APPROVED', now(), 'SYSTEM:pytest', 'SYSTEM:pytest', source_type, 'PYTEST', "
            f"'review-test', now(), true, id FROM {SCHEMA}.script_assignment WHERE id = :old"
        ),
        {"i": uuid.uuid4(), "v": vid, "sha": manifest_sha, "old": row.aid},
    )
    db.commit()
    return str(row.id), row.case_ref


def counts(db: Session, *tables: str) -> tuple[int, ...]:
    out = tuple(int(db.execute(text(f"SELECT count(*) FROM {SCHEMA}.{t}")).scalar_one()) for t in tables)
    db.rollback()
    return out


SIM = ("script_simulation_run", "simulation_answer_evaluation", "simulation_finding_set", "simulation_finding")


def test_fixture_builder_refuses_unsafe_targets(db: Session) -> None:
    terminal = db.execute(
        text(f"SELECT case_ref FROM {SCHEMA}.callback_case WHERE state = 'CLOSED_UNVERIFIED' LIMIT 1")
    ).scalar_one()
    with pytest.raises(rf.FixtureError, match="needs an open case|fixtures need an open case"):
        rf.build(db, terminal, {})
    db.rollback()
    with pytest.raises(rf.FixtureError, match="not found"):
        rf.build(db, "CB-0000-00000", {})
    db.rollback()


def test_review_workflow_on_synthetic_fixtures(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, admin: Account, db: Session
) -> None:
    login(client, user)
    login(other_client, checker)
    # Published lifecycle + evaluation script and published finding rules (maker-checker).
    vid, d, _ = build(client, "RV_FX")
    d.post("/submit", {"change_summary": "Review fixture script"})
    for step, body in (("review", approve(other_client, vid)), ("publish", {})):
        ok(other_client.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(other_client)))
    sha = ok(client.get(f"/api/v1/script-versions/{vid}"))["manifest_sha256"]
    publish_rules(
        client,
        other_client,
        [
            rule("FR-RV-TERM", "MISMATCH", "FACT_MISMATCH", "HIGH", "QUESTION", target="Q-RV_FX-TERM"),
            rule("FR-RV-UNRESOLVED", "UNRESOLVED", "MISSING_MANDATORY_ANSWER", "MEDIUM", mandatory_only=True),
            rule("FR-RV-NARRATIVE", "HUMAN_ASSESSMENT_REQUIRED", "NARRATIVE_REVIEW", "MEDIUM"),
        ],
        "Review test rules",
    )
    sim_before = counts(db, *SIM)

    # ---- Case A: a successful resolution --------------------------------------------------------------------
    good_id, good_ref = pin(db, vid, sha, [])
    fx = rf.build(db, good_ref, {"Q-RV_FX-NOTES": "Synthetic narrative answer"})
    db.commit()
    assert fx["state"] == "AWAITING_REVIEW" and fx["evaluations"]["MISMATCH"] == 0
    a = dossier(client, good_id)
    assert a["conversation"]["transport"] == "SYNTHETIC" and a["conversation"]["record_origin"] == "SYNTHETIC_SEED"
    assert a["attempts"][-1]["fixture"] is True and a["attempts"][-1]["is_browser_voice"] is False
    term = next(q for q in a["questions"] if q["code"] == "Q-RV_FX-TERM")
    assert term["evaluation_result"] == "MATCH" and term["expected"]["source"] == "POLICY_FACT:premium_term_years"
    (narr,) = a["findings"]  # the narrative answer needs a person (human assessment finding)
    assert narr["finding_class"] == "HUMAN_ASSESSMENT" and narr["severity_justification"].startswith("Synthetic")
    assert narr["rule"]["rule_code"] == "FR-RV-NARRATIVE" and not narr["material"]
    assert a["media"][0]["available"] is False and "No recording exists" in a["media"][0]["detail"]  # explicit
    checks = {c["code"]: c for c in a["readiness"]["checks"]}
    assert checks["IDENTITY_GATE"]["ok"] and checks["LIFECYCLE_GATES"]["ok"] and checks["MANDATORY_ANSWERED"]["ok"]
    assert checks["RECORDING_CONSENT"]["ok"] and "recorded —" in checks["RECORDING_CONSENT"]["detail"]
    assert "not identity assurance" in checks["IDENTITY_GATE"]["label"]
    assert not checks["FINDINGS_DISPOSITIONED"]["ok"] and not a["readiness"]["ready"]
    # Premature verification is blocked, with every reason.
    r = client.post(
        f"/api/v1/review/cases/{good_id}/decisions",
        json={
            "decision": "VERIFY",
            "reason": "Everything matched",
            "expected_row_version": a["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "NOT_READY_TO_VERIFY"
    assert any("No outstanding findings" in x["message"] for x in r.json()["details"])
    # Dispositions need a reason; a non-material dismissal is direct.
    bad = client.post(
        f"/api/v1/review/findings/{narr['id']}/actions",
        json={"action": "DISMISS", "reason": "", "expected_row_version": narr["row_version"], "idempotency_key": key()},
        headers=csrf_header(client),
    )
    assert bad.status_code == 422 and bad.json()["code"] == "REASON_REQUIRED"
    k = key()
    body = {
        "action": "DISMISS",
        "reason": "Narrative reviewed: consistent with the product summary (synthetic)",
        "expected_row_version": narr["row_version"],
        "idempotency_key": k,
    }
    first = ok(client.post(f"/api/v1/review/findings/{narr['id']}/actions", json=body, headers=csrf_header(client)))
    assert first["to_status"] == "DISMISSED" and not first["replayed"]
    again = ok(client.post(f"/api/v1/review/findings/{narr['id']}/actions", json=body, headers=csrf_header(client)))
    assert again["replayed"] and again["decision_ref"] == first["decision_ref"]  # duplicate submission
    a = dossier(client, good_id)
    assert a["readiness"]["ready"], a["readiness"]
    # Maker-checker: the proposer cannot approve; ADMIN cannot decide or approve.
    prop = act(
        client,
        f"/review/cases/{good_id}/decisions",
        {
            "decision": "VERIFY",
            "reason": "All checks pass; narrative assessed",
            "expected_row_version": a["case"]["row_version"],
        },
    )
    assert prop["approval_id"] and prop["case_state_after"] == "AWAITING_REVIEW"
    r = client.post(
        f"/api/v1/review/approvals/{prop['approval_id']}/decide",
        json={"decision": "APPROVE", "reason": "self", "idempotency_key": key()},
        headers=csrf_header(client),
    )
    assert r.status_code == 403  # USER lacks review.approve
    pending = ok(other_client.get("/api/v1/review/approvals"))["items"]
    assert any(p["id"] == prop["approval_id"] and p["proposed_action"] == "VERIFY" for p in pending)
    # The pending request itself blocks a new proposal, but is excluded when the checker decides it; another pending
    # request (simulated here with a second id) would still block.
    case_row = dict(
        db.execute(text(f"SELECT * FROM {SCHEMA}.callback_case WHERE id = :i"), {"i": good_id}).mappings().one()
    )
    assert not {c["code"]: c for c in rv.readiness(db, case_row)["checks"]}["NO_PENDING_APPROVAL"]["ok"]
    mine = {c["code"]: c for c in rv.readiness(db, case_row, exclude_approval_id=prop["approval_id"])["checks"]}
    assert mine["NO_PENDING_APPROVAL"]["ok"] and mine["NO_PENDING_APPROVAL"]["label"] == "No other pending approval"
    other = {c["code"]: c for c in rv.readiness(db, case_row, exclude_approval_id=uuid.uuid4())["checks"]}
    assert not other["NO_PENDING_APPROVAL"]["ok"]
    done = act(
        other_client,
        f"/review/approvals/{prop['approval_id']}/decide",
        {"decision": "APPROVE", "reason": "Checked readiness and evidence (synthetic)"},
    )
    assert done["case_state_after"] == "VERIFIED"
    a = dossier(client, good_id)
    assert a["case"]["state"] == "VERIFIED" and a["case"]["verified_at"]
    hist = [h["action"] for h in a["history"]]
    assert hist == ["DISMISS", "PROPOSE_VERIFY", "APPROVE_VERIFY"]
    # Terminal: nothing more changes.
    r = client.post(
        f"/api/v1/review/cases/{good_id}/actions",
        json={
            "action": "ESCALATE",
            "reason": "Late complaint received",
            "reason_code": "COMPLAINT",
            "expected_row_version": a["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "INVALID_TRANSITION"

    # ---- Case B: discrepancies, escalation, further callback, material approval, unverified closure ---------
    bad_id, bad_ref = pin(db, vid, sha, [good_ref])
    term_fact, freq_fact = db.execute(
        text(
            f"SELECT f.facts->>'premium_term_years', f.facts->>'premium_frequency' FROM {SCHEMA}.policy_fact_snapshot "
            f"f JOIN {SCHEMA}.callback_case c ON c.sale_event_id = f.sale_event_id WHERE c.id = :c "
            "ORDER BY f.captured_at DESC LIMIT 1"
        ),
        {"c": bad_id},
    ).one()
    db.rollback()
    wrong_freq = next(x for x in ("MONTHLY", "QUARTERLY", "ANNUAL") if x != freq_fact)
    rf.build(db, bad_ref, {"Q-RV_FX-TERM": int(term_fact) + 5, "Q-RV_FX-ADVICE": "REFUSED", "Q-RV_FX-FREQ": wrong_freq})
    db.commit()
    b = dossier(client, bad_id)
    by = {f["question_code"]: f for f in b["findings"]}
    assert by["Q-RV_FX-TERM"]["material"] and by["Q-RV_FX-TERM"]["finding_class"] == "CUSTOMER_DISCREPANCY"
    assert by["Q-RV_FX-ADVICE"]["finding_class"] == "MISSING_EVIDENCE"
    checks = {c["code"]: c for c in b["readiness"]["checks"]}
    assert not checks["MANDATORY_ANSWERED"]["ok"] and "Q-RV_FX-ADVICE" in checks["MANDATORY_ANSWERED"]["detail"]
    freq = next(q for q in b["questions"] if q["code"] == "Q-RV_FX-FREQ")
    assert freq["evaluation_result"] == "MISMATCH"  # an unconverted discrepancy: no rule covers frequency
    assert "Q-RV_FX-FREQ (mismatch, no finding)" in checks["DISCREPANCIES_DISPOSITIONED"]["detail"]
    # Escalation needs a REV-003 reason code.
    r = client.post(
        f"/api/v1/review/cases/{bad_id}/actions",
        json={
            "action": "ESCALATE",
            "reason": "Possible mis-selling",
            "expected_row_version": b["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 422 and r.json()["code"] == "ESCALATION_REASON_REQUIRED"
    esc = act(
        client,
        f"/review/cases/{bad_id}/actions",
        {
            "action": "ESCALATE",
            "reason": "Premium term misunderstood; possible mis-selling",
            "reason_code": "MIS_SELLING_CONCERN",
            "expected_row_version": b["case"]["row_version"],
        },
    )
    assert esc["case_state_after"] == "ESCALATED"
    # Stale: the old row version is refused.
    r = client.post(
        f"/api/v1/review/cases/{bad_id}/actions",
        json={
            "action": "RETURN_TO_REVIEW",
            "reason": "Investigation concluded",
            "expected_row_version": b["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "STALE_CASE"
    b = dossier(client, bad_id)
    assert b["readiness"]["checks"][0]["ok"] is False  # VERIFY needs AWAITING_REVIEW
    cb = act(
        client,
        f"/review/cases/{bad_id}/actions",
        {
            "action": "REQUEST_CALLBACK",
            "reason": "Call the customer again to re-confirm the term",
            "expected_row_version": b["case"]["row_version"],
        },
    )
    assert cb["case_state_after"] == "AWAITING_CALLBACK"
    b = dossier(client, bad_id)
    act(
        client,
        f"/review/cases/{bad_id}/actions",
        {
            "action": "RETURN_TO_REVIEW",
            "reason": "Callback outcome recorded for review",
            "expected_row_version": b["case"]["row_version"],
        },
    )
    b = dossier(client, bad_id)
    t = {f["question_code"]: f for f in b["findings"]}["Q-RV_FX-TERM"]
    # Invalid finding transition: resolve before confirming.
    r = client.post(
        f"/api/v1/review/findings/{t['id']}/actions",
        json={
            "action": "RESOLVE",
            "reason": "done",
            "expected_row_version": t["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code in (409, 422) and r.json()["code"] in ("INVALID_TRANSITION", "REASON_REQUIRED")
    conf = act(
        client,
        f"/review/findings/{t['id']}/actions",
        {
            "action": "CONFIRM",
            "reason": "The customer stated a different term than the policy",
            "expected_row_version": t["row_version"],
        },
    )
    assert conf["to_status"] == "CONFIRMED"
    info = act(
        client,
        f"/review/findings/{t['id']}/actions",
        {
            "action": "REQUEST_INFORMATION",
            "reason": "Ask sales for the illustration given to the customer",
            "expected_row_version": t["row_version"] + 1,
        },
    )
    assert info["to_status"] == "CONFIRMED"
    res = act(
        client,
        f"/review/findings/{t['id']}/actions",
        {
            "action": "RESOLVE",
            "reason": "Customer re-informed of the correct term (synthetic)",
            "expected_row_version": t["row_version"] + 1,
        },
    )
    assert res["action"] == "PROPOSE_RESOLVE" and res["to_status"] == "CONFIRMED"  # material: needs a checker
    # Stale proposal: the finding changes behind the proposal → refused and marked STALE.
    db.execute(text(f"UPDATE {SCHEMA}.finding SET row_version = row_version + 1 WHERE id = :f"), {"f": t["id"]})
    db.commit()
    r = other_client.post(
        f"/api/v1/review/approvals/{res['approval_id']}/decide",
        json={"decision": "APPROVE", "reason": "Approve the resolution", "idempotency_key": key()},
        headers=csrf_header(other_client),
    )
    assert r.status_code == 409 and r.json()["code"] == "STALE_PROPOSAL"
    t = {f["question_code"]: f for f in dossier(client, bad_id)["findings"]}["Q-RV_FX-TERM"]
    res = act(
        client,
        f"/review/findings/{t['id']}/actions",
        {
            "action": "RESOLVE",
            "reason": "Customer re-informed of the correct term (synthetic)",
            "expected_row_version": t["row_version"],
        },
    )
    ok_res = act(
        other_client,
        f"/review/approvals/{res['approval_id']}/decide",
        {"decision": "APPROVE", "reason": "Resolution evidence checked (synthetic)"},
    )
    assert ok_res["to_status"] == "CLOSED"
    # Still not verifiable: the mandatory question is unresolved (missing evidence is never success).
    b = dossier(client, bad_id)
    r = client.post(
        f"/api/v1/review/cases/{bad_id}/decisions",
        json={
            "decision": "VERIFY",
            "reason": "Findings handled",
            "expected_row_version": b["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and any("Q-RV_FX-ADVICE" in x["message"] for x in r.json()["details"])
    # Close unverified (governed reason) through maker-checker; the checker rejects first, then approves.
    r = client.post(
        f"/api/v1/review/cases/{bad_id}/decisions",
        json={
            "decision": "CLOSE_UNVERIFIED",
            "reason": "Unresolved",
            "expected_row_version": b["case"]["row_version"],
            "idempotency_key": key(),
        },
        headers=csrf_header(client),
    )
    assert r.status_code == 422 and r.json()["code"] == "CLOSURE_REASON_REQUIRED"
    p1 = act(
        client,
        f"/review/cases/{bad_id}/decisions",
        {
            "decision": "CLOSE_UNVERIFIED",
            "reason": "Mandatory answer refused; cannot verify",
            "closure_reason": "UNABLE_TO_VERIFY",
            "expected_row_version": b["case"]["row_version"],
        },
    )
    act(
        other_client,
        f"/review/approvals/{p1['approval_id']}/decide",
        {"decision": "REJECT", "reason": "Use the unresolved-exception reason"},
    )
    p2 = act(
        client,
        f"/review/cases/{bad_id}/decisions",
        {
            "decision": "CLOSE_UNVERIFIED",
            "reason": "Mandatory answer refused; unresolved exception",
            "closure_reason": "UNRESOLVED_MATERIAL_EXCEPTION",
            "expected_row_version": b["case"]["row_version"],
        },
    )
    act(
        other_client,
        f"/review/approvals/{p2['approval_id']}/decide",
        {"decision": "APPROVE", "reason": "Closure reason and evidence checked"},
    )
    b = dossier(client, bad_id)
    assert b["case"]["state"] == "CLOSED_UNVERIFIED" and b["case"]["closure_reason"] == "UNRESOLVED_MATERIAL_EXCEPTION"
    actions = [h["action"] for h in b["history"]]
    assert actions[:3] == ["ESCALATE", "REQUEST_CALLBACK", "RETURN_TO_REVIEW"]
    assert {"APPROVAL_STALE", "REJECT_PROPOSAL", "APPROVE_CLOSE_UNVERIFIED", "APPROVE_RESOLVE"} <= set(actions)
    # Original finding evidence is unchanged; history is insert-only.
    orig = db.execute(
        text(f"SELECT category, severity, evidence_refs FROM {SCHEMA}.finding WHERE id = :f"), {"f": t["id"]}
    ).one()
    db.rollback()
    assert orig.severity == "HIGH" and orig.evidence_refs["rule"]["rule_code"] == "FR-RV-TERM"
    for sql in (
        f"UPDATE {SCHEMA}.review_decision SET reason = 'x'",
        f"DELETE FROM {SCHEMA}.review_decision",
        f"UPDATE {SCHEMA}.finding SET severity = 'LOW' WHERE id = '{t['id']}'",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()

    # ---- Seeded S0 case (no identity gate) and a case without any conversation ---------------------------------
    seeded = db.execute(text(f"SELECT id FROM {SCHEMA}.callback_case WHERE case_ref = 'CB-2026-10482'")).scalar_one()
    no_conv = db.execute(
        text(
            f"SELECT c.id FROM {SCHEMA}.callback_case c WHERE c.state = 'VALIDATED' AND NOT EXISTS (SELECT 1 FROM "
            f"{SCHEMA}.contact_attempt a WHERE a.callback_case_id = c.id) ORDER BY c.case_ref LIMIT 1"
        )
    ).scalar_one()
    db.rollback()
    s = dossier(client, seeded)
    sc = {c["code"]: c for c in s["readiness"]["checks"]}
    assert not sc["IDENTITY_GATE"]["ok"] and "no identity check" in sc["IDENTITY_GATE"]["detail"]
    assert s["findings"][0]["severity_justification"].startswith("Not recorded")
    n = dossier(client, no_conv)
    assert [c["code"] for c in n["readiness"]["checks"] if not c["ok"]][-1] == "CONVERSATION_COMPLETED"

    # ---- Authorisation, market scope, isolation -----------------------------------------------------------------
    login(other_client, admin)
    assert (
        other_client.post(
            f"/api/v1/review/cases/{seeded}/actions",
            json={
                "action": "ESCALATE",
                "reason": "x" * 10,
                "reason_code": "COMPLAINT",
                "expected_row_version": 1,
                "idempotency_key": key(),
            },
            headers=csrf_header(other_client),
        ).status_code
        == 403
    )
    my_user = make_account(db, "LOCAL_USER_MY", prefix="rvmy")
    login(other_client, my_user)
    assert other_client.get(f"/api/v1/review/cases/{seeded}").status_code in (403, 404)
    assert counts(db, *SIM) == sim_before  # review never touches simulation records
    audits = set(db.execute(text(f"SELECT action FROM {SCHEMA}.audit_event WHERE action LIKE 'REVIEW.%'")).scalars())
    db.rollback()
    assert {"REVIEW.DISMISS", "REVIEW.ESCALATE", "REVIEW.APPROVE_VERIFY", "REVIEW.VERIFY_BLOCKED"} <= audits
