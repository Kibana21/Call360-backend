"""S2-D.1 Script Studio lifecycle configuration and its simulation over the API: lifecycle sections and item roles,
system-enforced gates that configuration cannot relax, lifecycle validation, maker-checker publication of a new
synthetic version (published content immutable, seeded scripts unchanged), and the published lifecycle running in the
text simulator: normal closing, identity failure, declining to proceed — with no operational change."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.digest import content_digest
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema
from tests.test_script_authoring import Draft, approve, new_family, ok
from tests.test_script_simulation import case_where, fingerprint, post

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture(scope="module", autouse=True)
def restore(engine: Engine, settings: Settings) -> Iterator[None]:
    yield  # this module pins a script to a seeded case directly; reset afterwards
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="lchk")


def content(**over: Any) -> dict[str, Any]:
    base = {
        "intent": "Synthetic lifecycle item for tests",
        "category": "OTHER",
        "customer_wording": "[Synthetic example, not approved wording] lifecycle item",
        "delivery_mode": "CONTROLLED_TTS",
        "answer_type": "ACKNOWLEDGEMENT",
        "mandatory": True,
        "expected_answer_policy": "COLLECT_ONLY",
    }
    return base | over


def add(d: Draft, section_id: str, code: str, status: int = 200, **over: Any) -> dict[str, Any]:
    return d.post(f"/sections/{section_id}/questions", {"question_code": code, "content": content(**over)}, status)


def section(d: Draft, code: str, kind: str) -> str:
    d.post("/sections", {"module_code": code, "module_name": f"{kind.title()} (synthetic)", "module_kind": kind})
    return str(next(s["section_id"] for s in d.sections() if s["module_code"] == code))


def issues(d: Draft) -> dict[str, list[str]]:
    out = ok(d.c.post(f"/api/v1/script-versions/{d.vid}/validate", headers=csrf_header(d.c)))
    d.rv = ok(d.c.get(f"/api/v1/script-versions/{d.vid}"))["row_version"]
    by: dict[str, list[str]] = {}
    for i in out["issues"]:
        by.setdefault(i["severity"], []).append(i["code"])
    return by


def build_lifecycle(c: TestClient, code: str) -> tuple[str, Draft]:
    _, vid = new_family(c, code)
    d = Draft(c, vid)
    core = section(d, f"{code}_CORE", "COMMON")
    add(d, core, f"Q-{code}-SUMMARY", discloses_policy_information=True)
    assert "IDENTITY_GATE_REQUIRED" in issues(d).get("ERROR", [])  # policy information needs an identity gate
    opening = section(d, f"{code}_OPEN", "OPENING")
    add(d, opening, f"Q-{code}-OPEN", lifecycle_role="OPENING_STATEMENT")
    ident = section(d, f"{code}_ID", "IDENTITY")
    add(d, ident, f"Q-{code}-ID", lifecycle_role="IDENTITY_CHECK", answer_type="YES_NO")
    disc = section(d, f"{code}_DISC", "DISCLOSURE")
    add(d, disc, f"Q-{code}-DISC", lifecycle_role="DISCLOSURE")
    consent = section(d, f"{code}_CONSENT", "CONSENT")
    add(d, consent, f"Q-{code}-PROCEED", lifecycle_role="CONSENT_TO_PROCEED", answer_type="YES_NO")
    add(d, consent, f"Q-{code}-REC", lifecycle_role="RECORDING_CONSENT", answer_type="YES_NO")
    close = section(d, f"{code}_CLOSE", "CLOSING")
    add(d, close, f"Q-{code}-CLOSE", lifecycle_role="CLOSING_STATEMENT", deliver_on_termination=True)
    return vid, d


def test_configuration_cannot_relax_system_gates_and_validation_explains_the_lifecycle(
    client: TestClient, user: Account
) -> None:
    login(client, user)
    _, vid = new_family(client, "LC_RULES")
    d = Draft(client, vid)
    ident = section(d, "LC_RULES_ID", "IDENTITY")
    for over, text_ in (
        (
            {"lifecycle_role": "IDENTITY_CHECK", "answer_type": "FREE_TEXT", "expected_answer_policy": "COLLECT_ONLY"},
            "must be yes no",
        ),
        ({"lifecycle_role": "IDENTITY_CHECK", "answer_type": "YES_NO", "on_failure": "CONTINUE"}, "system-enforced"),
        (
            {"lifecycle_role": "CONSENT_TO_PROCEED", "answer_type": "YES_NO", "on_failure": "CONTINUE"},
            "system-enforced",
        ),
        ({"lifecycle_role": "DISCLOSURE", "on_failure": "CONTINUE_FLAGGED"}, "must terminate"),
        ({"lifecycle_role": "OPENING_STATEMENT", "discloses_policy_information": True}, "must not disclose"),
        (
            {"lifecycle_role": "VERIFICATION", "answer_type": "YES_NO", "deliver_on_termination": True},
            "Only a closing statement",
        ),
    ):
        r = add(d, ident, "Q-LC-RULES-X", status=422, **over)
        assert r["code"] == "INVALID_QUESTION" and text_ in r["message"], (over, r)
    add(d, ident, "Q-LC-RULES-WRONG", lifecycle_role="CONSENT_TO_PROCEED", answer_type="YES_NO")
    found = issues(d)
    assert "ROLE_STAGE_MISMATCH" in found["ERROR"] and "LIFECYCLE_INCOMPLETE" in found["WARNING"]
    options = ok(client.get("/api/v1/script-authoring/options"))["lifecycle"]
    roles = {r["role"]: r for r in options["roles"]}
    assert roles["IDENTITY_CHECK"]["on_failure"] == ["TERMINATE"] and roles["RECORDING_CONSENT"]["on_failure"] == [
        "CONTINUE_WITHOUT_RECORDING",
        "TERMINATE",
    ]
    assert options["stages"] == ["OPENING", "IDENTITY", "DISCLOSURE", "CONSENT", "VERIFICATION", "CLOSING"]
    assert options["assumptions"]


def test_lifecycle_version_publishes_immutably_and_runs_in_the_simulator(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, db: Session
) -> None:
    login(client, user)
    digest = content_digest(db.connection(), SCHEMA)
    seeded = db.execute(
        text(f"SELECT id, manifest_sha256 FROM {SCHEMA}.script_version WHERE status = 'PUBLISHED' ORDER BY id")
    ).all()
    db.rollback()
    vid, d = build_lifecycle(client, "LC_DEMO")
    assert not issues(d).get("ERROR")
    d.post("/submit", {"change_summary": "Synthetic lifecycle script for S2-D.1 tests"})
    login(other_client, checker)
    for step, body in (("review", approve(other_client, vid)), ("publish", {})):
        ok(other_client.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(other_client)))
    detail = ok(client.get(f"/api/v1/script-versions/{vid}"))
    roles = {q["question_code"]: q["lifecycle_role"] for s in detail["sections"] for q in s["questions"]}
    assert roles["Q-LC_DEMO-ID"] == "IDENTITY_CHECK" and roles["Q-LC_DEMO-SUMMARY"] == "VERIFICATION"
    manifest = db.execute(text(f"SELECT manifest FROM {SCHEMA}.script_version WHERE id = :v"), {"v": vid}).scalar_one()
    db.rollback()
    frozen = {q["question_code"]: q for s in manifest["sections"] for q in s["questions"]}
    assert frozen["Q-LC_DEMO-SUMMARY"]["discloses_policy_information"] is True
    with pytest.raises(Exception, match="immutable|not allowed|forbid"):
        db.execute(
            text(
                f"UPDATE {SCHEMA}.question_revision_detail SET lifecycle_role = 'VERIFICATION' WHERE "
                "lifecycle_role = 'IDENTITY_CHECK'"
            )
        )
    db.rollback()
    assert (
        db.execute(
            text(
                f"SELECT id, manifest_sha256 FROM {SCHEMA}.script_version WHERE status = 'PUBLISHED' "
                "AND id <> :v ORDER BY id"
            ),
            {"v": vid},
        ).all()
        == seeded
    )  # earlier scripts unchanged
    db.rollback()
    assert content_digest(db.connection(), SCHEMA) == digest
    db.rollback()
    # Test setup: pin the lifecycle script to a seeded single-contact case by superseding its assignment.
    case_id = case_where(db, "true", 1)
    old = db.execute(
        text(
            f"SELECT a.id FROM {SCHEMA}.script_assignment a WHERE a.callback_case_id = :c AND NOT EXISTS "
            f"(SELECT 1 FROM {SCHEMA}.script_assignment x WHERE x.supersedes_id = a.id)"
        ),
        {"c": case_id},
    ).scalar_one()
    db.execute(
        text(
            f"INSERT INTO {SCHEMA}.script_assignment (id, callback_case_id, script_version_id, "
            "script_manifest_sha256, policy_fact_snapshot_id, risk_assessment_id, rule_trace, input_snapshot, "
            "input_sha256, origin, assigned_at, assigned_by, created_by, source_type, source_system, "
            "source_reference, recorded_at, is_synthetic, supersedes_id) SELECT :i, callback_case_id, :v, :sha, "
            "policy_fact_snapshot_id, risk_assessment_id, rule_trace, input_snapshot, input_sha256, "
            "'MANUAL_APPROVED', now(), 'SYSTEM:pytest', 'SYSTEM:pytest', source_type, 'PYTEST', "
            f"'lifecycle-test', now(), true, id FROM {SCHEMA}.script_assignment WHERE id = :old"
        ),
        {"i": uuid.uuid4(), "v": vid, "sha": detail["manifest_sha256"], "old": old},
    )
    db.commit()
    before = fingerprint(db)
    contacts = ok(client.get("/api/v1/script-simulations/plan", params={"case_id": str(case_id)}))
    assert contacts["identity_gate_configured"] and contacts["questions"][0]["stage"] == "OPENING"
    contact = contacts["contacts"][0]["selection_id"] if len(contacts["contacts"]) > 1 else None

    def start() -> dict[str, Any]:
        return post(client, "/script-simulations", {"case_id": str(case_id), "contact_selection_id": contact}, 201)

    def step(run: dict[str, Any], answer: Any = True) -> dict[str, Any]:
        a = run["next_action"]
        run = post(
            client, f"/script-simulations/{run['id']}/delivery", {"action_id": a["action_id"], "delivered": True}
        )
        if a["completes_on_delivery"]:
            return run
        return post(
            client,
            f"/script-simulations/{run['id']}/answer",
            {"action_id": a["action_id"], "kind": "ANSWER", "value": answer},
        )

    run = start()
    assert run["lifecycle"]["stage"] == "OPENING" and run["lifecycle"]["gates"]["identity"] == "PENDING"
    while run["next_action"]["kind"] in ("ASK", "REPROMPT"):
        run = step(run)
    run = post(client, f"/script-simulations/{run['id']}/end", {"abandon": False})
    assert run["outcome"] == "COMPLETED" and run["lifecycle"]["gates"] == {
        "identity": "CONFIRMED",
        "willingness": "AGREED",
        "recording_consent": "GRANTED",
        "cloud_processing": "NOT_ASKED",
    }
    failed = step(step(start()), False)  # opening delivered, identity answered no
    assert failed["lifecycle"]["gates"]["identity"] == "FAILED"
    assert failed["lifecycle"]["termination"]["reason"] == "IDENTITY_FAILED"
    assert failed["next_action"]["role"] == "CLOSING_STATEMENT"
    assert not any(
        e["question_code"] == "Q-LC_DEMO-SUMMARY" and e["event_type"] == "QUESTION_REQUESTED" for e in failed["trace"]
    )  # no policy information before identity
    failed = post(client, f"/script-simulations/{step(failed)['id']}/end", {"abandon": False})
    assert failed["status"] == "TERMINATED" and failed["outcome"] == "TERMINATED"
    declined = start()
    for _ in range(3):  # opening, identity, disclosure
        declined = step(declined)
    declined = step(declined, False)  # does not want to proceed
    assert declined["lifecycle"]["gates"]["willingness"] == "DECLINED"
    assert declined["lifecycle"]["termination"]["reason"] == "DECLINED_TO_PROCEED"
    wrong = post(client, f"/script-simulations/{start()['id']}/event", {"kind": "WRONG_PERSON"})
    assert wrong["lifecycle"]["gates"]["identity"] == "WRONG_PERSON"
    assert fingerprint(db) == before  # simulations change no operational record
