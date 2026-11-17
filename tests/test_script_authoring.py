"""S2-A editable Script Studio: authoring, validation, maker-checker lifecycle, immutability and history.

Covers SUR-002/003/005/006/007 and SCR-007/008/012/013/014/015 for the S2-A scope: create a family, add/edit/delete/
reorder sections, modules and questions in a draft, configure question semantics and controls, validate, diff,
submit → approve/request changes → publish by a different S&C checker, immutable published content and checksums.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.domain.digest import content_digest, sha256_of
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="checker")


def both_roles(db: Session) -> Account:
    """A principal in the USER and the S&C checker groups: holds script.edit and script.approve/publish."""
    a = make_account(db, "LOCAL_USER_SG", prefix="dual")
    db.execute(
        text(
            f"INSERT INTO {SCHEMA}.group_membership (id, principal_id, group_id, provenance, created_by) "
            f"SELECT :i, :p, id, 'LOCAL', 'SYSTEM:test' FROM {SCHEMA}.app_group WHERE code = 'LOCAL_SC_CHECKER_SG'"
        ),
        {"i": uuid.uuid4(), "p": a.principal_id},
    )
    db.commit()
    return a


def ok(r: Any, status: int = 200) -> dict[str, Any]:
    assert r.status_code == status, r.text
    return dict(r.json())


def detail(c: TestClient, vid: str) -> dict[str, Any]:
    return ok(c.get(f"/api/v1/script-versions/{vid}"))


def approve(c: TestClient, vid: str, reason: str = "Reviewed (test)") -> dict[str, Any]:
    """Approve as the checker, acknowledging the flagged mandatory questions without a mapped control (S2-A.1)."""
    return {
        "decision": "APPROVE",
        "reason": reason,
        "acknowledged_unmapped_mandatory": detail(c, vid)["unmapped_mandatory"],
    }


class Draft:
    """Small client for one draft: keeps the optimistic-concurrency token current."""

    def __init__(self, c: TestClient, vid: str) -> None:
        self.c, self.vid = c, vid
        self.rv = detail(c, vid)["row_version"]

    def post(self, path: str, body: dict[str, Any], status: int = 200) -> dict[str, Any]:
        r = self.c.post(
            f"/api/v1/script-versions/{self.vid}{path}",
            json={"expected_row_version": self.rv, **body},
            headers=csrf_header(self.c),
        )
        out = ok(r, status)
        self.rv = out.get("row_version", self.rv)
        return out

    def put(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.c.put(
            f"/api/v1/script-versions/{self.vid}{path}",
            json={"expected_row_version": self.rv, **body},
            headers=csrf_header(self.c),
        )
        out = ok(r)
        self.rv = out["row_version"]
        return out

    def delete(self, path: str) -> dict[str, Any]:
        r = self.c.delete(
            f"/api/v1/script-versions/{self.vid}{path}",
            params={"expected_row_version": self.rv},
            headers=csrf_header(self.c),
        )
        out = ok(r)
        self.rv = out["row_version"]
        return out

    def sections(self) -> list[dict[str, Any]]:
        return list(detail(self.c, self.vid)["sections"])


def q(code: str, **over: Any) -> dict[str, Any]:
    content = {
        "intent": "Customer confirms the representative explained the plan",
        "category": "SALES_CONDUCT",
        "customer_wording": "Did the representative explain how the plan works?",
        "delivery_mode": "CONVERSATIONAL",
        "answer_type": "YES_NO",
        "mandatory": True,
        "expected_answer_policy": "EXACT_BOOLEAN",
        "expected_boolean": True,
        **over,
    }
    return {"question_code": code, "content": content}


def new_family(c: TestClient, code: str) -> tuple[str, str]:
    out = ok(
        c.post(
            "/api/v1/scripts",
            json={"code": code, "name": "Test verification script", "description": "S2-A test family (synthetic)"},
            headers=csrf_header(c),
        ),
        201,
    )
    return out["script_family_id"], out["script_version_id"]


def build_basic(c: TestClient, code: str) -> tuple[str, str, Draft]:
    fid, vid = new_family(c, code)
    d = Draft(c, vid)
    d.post("/sections", {"module_code": f"{code}_CORE", "module_name": "Core questions", "module_kind": "COMMON"})
    sec = d.sections()[0]["section_id"]
    d.post(f"/sections/{sec}/questions", q(f"Q-{code}-EXPLAINED"))
    d.post(
        f"/sections/{sec}/questions",
        q(
            f"Q-{code}-TERM",
            intent="Customer states the premium term",
            category="POLICY_FACT",
            customer_wording="For how many years will you pay premiums?",
            answer_type="NUMERIC",
            expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
            policy_fact_key="premium_term_years",
            expected_boolean=None,
        ),
    )
    return fid, vid, d


# ---- the full lifecycle -----------------------------------------------------------------------------------------
def test_create_edit_submit_approve_publish_by_a_different_checker(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    seed_before = content_digest(conn, SCHEMA)
    fid, vid, d = build_basic(client, "S2A_LIFE")
    sec = d.sections()[0]
    # Enum question with a not-applicable condition, a reused published module with an inclusion condition.
    d.post(
        f"/sections/{sec['section_id']}/questions",
        q(
            "Q-S2A_LIFE-FREQ",
            intent="Customer states the premium frequency",
            category="POLICY_FACT",
            customer_wording="How often will you pay premiums?",
            answer_type="ENUM",
            enum_options=["MONTHLY", "ANNUAL"],
            mandatory=False,
            expected_answer_policy="COLLECT_ONLY",
            expected_boolean=None,
            not_applicable_predicate={"fact": "premium_frequency", "equals": "SINGLE"},
        ),
    )
    opts = ok(client.get("/api/v1/script-authoring/options"))
    ilp = next(m for m in opts["published_modules"] if m["code"] == "ILP")
    d.post("/sections", {"module_id": ilp["id"], "inclusion_condition": {"fact": "is_ilp", "equals": True}})
    # Reorder questions and sections; edit one question (a new revision); remove one.
    secs = d.sections()
    core = secs[0]
    order = [x["module_question_id"] for x in reversed(core["questions"])]
    d.post(f"/sections/{core['section_id']}/questions/reorder", {"order": order})
    assert [x["question_code"] for x in d.sections()[0]["questions"]][0] == "Q-S2A_LIFE-FREQ"
    d.post("/sections/reorder", {"order": [secs[1]["section_id"], secs[0]["section_id"]]})
    assert [s["module_code"] for s in d.sections()] == ["ILP", "S2A_LIFE_CORE"]
    core = d.sections()[1]
    explained = next(x for x in core["questions"] if x["question_code"] == "Q-S2A_LIFE-EXPLAINED")
    d.put(
        f"/sections/{core['section_id']}/questions/{explained['module_question_id']}",
        {
            "content": {**q("x")["content"], "customer_wording": "Did the representative explain how this plan works?"},
            "change_reason": "Clearer wording",
        },
    )
    revised = next(x for x in d.sections()[1]["questions"] if x["question_code"] == "Q-S2A_LIFE-EXPLAINED")
    assert revised["revision"] == 2 and revised["wording"].endswith("how this plan works?")
    freq = next(x for x in d.sections()[1]["questions"] if x["question_code"] == "Q-S2A_LIFE-FREQ")
    d.delete(f"/sections/{core['section_id']}/questions/{freq['module_question_id']}")
    # Link a control and the Singapore regulatory reference.
    ctl = ok(client.get("/api/v1/controls"))["items"][0]
    ref = ok(client.get("/api/v1/regulatory-references"))["items"][0]
    d.put(
        "/questions/Q-S2A_LIFE-EXPLAINED/controls",
        {
            "links": [
                {
                    "control_id": ctl["id"],
                    "regulatory_reference_id": ref["id"],
                    "rationale": "Explains the plan (synthetic)",
                }
            ]
        },
    )
    # Validate (warnings only), then submit with a change summary.
    v = ok(client.post(f"/api/v1/script-versions/{vid}/validate", headers=csrf_header(client)))
    assert v["validation_status"] == "VALID"
    assert {i["code"] for i in v["issues"]} >= {"NO_CONTROL"}  # the numeric question has no control: a warning
    sub = d.post("/submit", {"change_summary": "First version of the test verification script"})
    assert sub["status"] == "SUBMITTED_FOR_REVIEW" and len(sub["manifest_sha256"]) == 64
    # Submitted content is locked: the API refuses and so does the database.
    stale = client.post(
        f"/api/v1/script-versions/{vid}/sections",
        json={
            "expected_row_version": d.rv + 1,
            "module_code": "LATE_ADD",
            "module_name": "Late",
            "module_kind": "RISK",
        },
        headers=csrf_header(client),
    )
    assert stale.status_code == 409 and stale.json()["code"] == "VERSION_NOT_EDITABLE"
    core_module = d.sections()[1]["module_id"]
    with pytest.raises(Exception, match="locked while its script version is under review"):
        conn.execute(text(f"DELETE FROM {SCHEMA}.module_question WHERE script_module_id = :m"), {"m": core_module})
    conn.rollback()
    # The maker cannot review (no script.approve); a different S&C checker approves and publishes.
    assert (
        client.post(
            f"/api/v1/script-versions/{vid}/review",
            json={"decision": "APPROVE", "reason": "mine"},
            headers=csrf_header(client),
        ).status_code
        == 403
    )
    login(other_client, checker)
    diff = ok(other_client.get(f"/api/v1/script-versions/{vid}/diff"))
    assert diff["base"] is None and diff["summary"]["ADDED"] == 6  # 2 core + 4 reused ILP questions
    # S2-A.1: mandatory questions without a mapped control are flagged and must be acknowledged one by one.
    flagged = detail(other_client, vid)["unmapped_mandatory"]
    assert flagged == ["Q-S2A_LIFE-TERM"]
    r = other_client.post(
        f"/api/v1/script-versions/{vid}/review",
        json={"decision": "APPROVE", "reason": "Structure and expectations reviewed"},
        headers=csrf_header(other_client),
    )
    assert r.status_code == 422 and r.json()["code"] == "UNMAPPED_MANDATORY_NOT_ACKNOWLEDGED"
    ok(
        other_client.post(
            f"/api/v1/script-versions/{vid}/review",
            json=approve(other_client, vid, "Structure and expectations reviewed"),
            headers=csrf_header(other_client),
        )
    )
    pub = ok(
        other_client.post(
            f"/api/v1/script-versions/{vid}/publish",
            json={"reason": "Initial publication"},
            headers=csrf_header(other_client),
        )
    )
    assert pub["status"] == "PUBLISHED" and pub["manifest_sha256"] == sub["manifest_sha256"]
    # Published: immutable, checksum reproducible, controls frozen in the manifest, modules published.
    pd = detail(other_client, vid)
    assert (pd["status"], pd["reviewer_ref"], pd["author_ref"]) == (
        "PUBLISHED",
        str(checker.principal_id),
        str(user.principal_id),
    )
    assert pd["controls_source"] == "MANIFEST" and all(s["module_status"] == "PUBLISHED" for s in pd["sections"])
    row = conn.execute(
        text(f"SELECT manifest, manifest_sha256 FROM {SCHEMA}.script_version WHERE id = :v"), {"v": vid}
    ).one()
    assert sha256_of(row.manifest) == row.manifest_sha256
    explained = next(x for s in pd["sections"] for x in s["questions"] if x["question_code"] == "Q-S2A_LIFE-EXPLAINED")
    assert explained["controls"][0]["control_code"] == ctl["control_code"] and explained["controls"][0]["title"]
    with pytest.raises(Exception, match="immutable"):
        conn.execute(text(f"UPDATE {SCHEMA}.script_version SET language = 'zh' WHERE id = :v"), {"v": vid})
    conn.rollback()
    with pytest.raises(Exception, match="immutable"):
        conn.execute(text(f"DELETE FROM {SCHEMA}.module_question WHERE script_module_id = :m"), {"m": core_module})
    conn.rollback()
    # History: every step with its actor and reason; the library lists the new family beside the seeded scripts.
    hist = ok(other_client.get(f"/api/v1/script-versions/{vid}/history"))
    kinds = [e["event_type"] for e in hist["events"]]
    assert kinds[0] == "DRAFT_CREATED" and kinds[-3:] == ["SUBMITTED", "APPROVED", "PUBLISHED"]
    assert hist["makers"] == [str(user.principal_id)]
    lib = ok(other_client.get("/api/v1/scripts"))["items"]
    assert {(x["family"], x["version_label"], x["status"]) for x in lib} >= {
        ("S2A_LIFE", "1.0", "PUBLISHED"),
        ("SALES_VERIFICATION_SG", "1.1", "PUBLISHED"),
        ("SALES_VERIFICATION_SG", "1.0", "SUPERSEDED"),
    }
    audit = (
        conn.execute(text(f"SELECT action FROM {SCHEMA}.audit_event WHERE entity_id = :v ORDER BY seq"), {"v": vid})
        .scalars()
        .all()
    )
    assert {"SCRIPT.SUBMITTED", "SCRIPT.APPROVED", "SCRIPT.PUBLISHED"} <= set(audit)
    # Seeded synthetic content was not changed by authoring.
    assert content_digest(conn, SCHEMA) == seed_before


# ---- maker-checker -----------------------------------------------------------------------------------------------
def test_a_checker_who_authored_or_edited_cannot_approve_or_publish(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, db: Session, conn: Connection
) -> None:
    dual = both_roles(db)
    login(client, dual)
    _, vid, d = build_basic(client, "S2A_SELF")
    d.post("/submit", {"change_summary": "Self-approval attempt (test)"})
    r = client.post(
        f"/api/v1/script-versions/{vid}/review",
        json={"decision": "APPROVE", "reason": "own work"},
        headers=csrf_header(client),
    )
    assert r.status_code == 403 and r.json()["code"] == "SELF_REVIEW_DENIED"
    denied = (
        conn.execute(
            text(f"SELECT outcome FROM {SCHEMA}.audit_event WHERE action = 'SCRIPT.REVIEW_DENIED' AND entity_id = :v"),
            {"v": vid},
        )
        .scalars()
        .all()
    )
    assert denied == ["DENIED"]
    # An editor who is also a checker is a maker too.
    login(other_client, user)
    _, vid2, d2 = build_basic(other_client, "S2A_EDIT")
    client.cookies.clear()
    login(client, dual)
    d2.c = client
    sec = d2.sections()[0]["section_id"]
    d2.post(f"/sections/{sec}/questions", q("Q-S2A_EDIT-EXTRA"))
    d2.post("/submit", {"change_summary": "Edited by a dual-role principal"})
    r = client.post(
        f"/api/v1/script-versions/{vid2}/review",
        json={"decision": "APPROVE", "reason": "edited it"},
        headers=csrf_header(client),
    )
    assert r.status_code == 403
    login(other_client, checker)
    ok(
        other_client.post(
            f"/api/v1/script-versions/{vid2}/review",
            json=approve(other_client, vid2),
            headers=csrf_header(other_client),
        )
    )
    # ADMIN holds no script authoring or approval permission (ADR-0004).
    other_client.cookies.clear()
    admin = make_account(db, "LOCAL_ADMIN", prefix="adm")
    login(other_client, admin)
    assert (
        other_client.post(
            "/api/v1/scripts", json={"code": "S2A_ADMIN", "name": "No"}, headers=csrf_header(other_client)
        ).status_code
        == 403
    )
    assert (
        other_client.post(
            f"/api/v1/script-versions/{vid2}/publish", json={}, headers=csrf_header(other_client)
        ).status_code
        == 403
    )
    assert ok(other_client.get(f"/api/v1/script-versions/{vid2}"))["status"] == "APPROVED"  # can still read


def test_request_changes_returns_the_draft_and_resubmission_needs_a_new_review(
    client: TestClient, other_client: TestClient, user: Account, checker: Account
) -> None:
    login(client, user)
    _, vid, d = build_basic(client, "S2A_BACK")
    d.post("/submit", {"change_summary": "Please review the first cut"})
    login(other_client, checker)
    out = ok(
        other_client.post(
            f"/api/v1/script-versions/{vid}/review",
            json={"decision": "REQUEST_CHANGES", "reason": "Add the ILP module"},
            headers=csrf_header(other_client),
        )
    )
    assert out["status"] == "DRAFT"
    d.rv = detail(client, vid)["row_version"]
    opts = ok(client.get("/api/v1/script-authoring/options"))
    ilp = next(m for m in opts["published_modules"] if m["code"] == "ILP")
    d.post("/sections", {"module_id": ilp["id"], "inclusion_condition": {"fact": "is_ilp", "equals": True}})
    d.post("/submit", {"change_summary": "ILP module added as requested"})
    assert (
        other_client.post(f"/api/v1/script-versions/{vid}/publish", json={}, headers=csrf_header(other_client)).json()[
            "code"
        ]
        == "NOT_APPROVED"
    )
    hist = [e["event_type"] for e in ok(client.get(f"/api/v1/script-versions/{vid}/history"))["events"]]
    assert hist.count("SUBMITTED") == 2 and "CHANGES_REQUESTED" in hist


# ---- new versions of a published script: copy-on-write, diff, supersede ------------------------------------------
def test_new_version_copies_on_write_diffs_and_supersedes_without_changing_history(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    fid, v1, d = build_basic(client, "S2A_NEXT")
    d.post("/submit", {"change_summary": "Version 1 of the test script"})
    login(other_client, checker)
    for step, body in (("review", approve(other_client, v1)), ("publish", {})):
        ok(other_client.post(f"/api/v1/script-versions/{v1}/{step}", json=body, headers=csrf_header(other_client)))
    v1_before = detail(client, v1)
    # Only one open version per family.
    out = ok(client.post(f"/api/v1/scripts/{fid}/drafts", json={}, headers=csrf_header(client)), 201)
    assert out["version_label"] == "1.1"
    again = client.post(f"/api/v1/scripts/{fid}/drafts", json={}, headers=csrf_header(client))
    assert again.status_code == 409 and again.json()["code"] == "OPEN_VERSION_EXISTS"
    d2 = Draft(client, out["script_version_id"])
    sec = d2.sections()[0]
    assert sec["module_status"] == "PUBLISHED"  # the draft starts from v1.0's published module
    term = next(x for x in sec["questions"] if x["question_code"] == "Q-S2A_NEXT-TERM")
    d2.put(
        f"/sections/{sec['section_id']}/questions/{term['module_question_id']}",
        {
            "content": {
                **q(
                    "x",
                    intent="Customer states the premium term",
                    category="POLICY_FACT",
                    customer_wording="How many years will you pay premiums for?",
                    answer_type="NUMERIC",
                    expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
                    policy_fact_key="premium_term_years",
                    expected_boolean=None,
                )["content"]
            },
            "change_reason": "Plainer wording",
        },
    )
    sec = d2.sections()[0]
    assert (sec["module_status"], sec["module_revision"]) == ("DRAFT", 2)  # copy-on-write module revision
    d2.post(f"/sections/{sec['section_id']}/questions", {"question_code": "Q-REP-DISCLOSED"})  # reuse from the bank
    diff = ok(client.get(f"/api/v1/script-versions/{d2.vid}/diff"))
    changes = {x["question_code"]: x["change"] for x in diff["questions"]}
    assert changes["Q-S2A_NEXT-TERM"] == "REWORDED" and changes["Q-REP-DISCLOSED"] == "ADDED"
    assert changes["Q-S2A_NEXT-EXPLAINED"] == "UNCHANGED"
    assert detail(client, v1) == v1_before  # the published version is untouched
    d2.post("/submit", {"change_summary": "Plainer premium-term wording; representative disclosure added"})
    for step, body in (
        ("review", approve(other_client, d2.vid)),
        ("publish", {"supersede_version_id": v1, "reason": "Replaces v1.0"}),
    ):
        out = ok(
            other_client.post(f"/api/v1/script-versions/{d2.vid}/{step}", json=body, headers=csrf_header(other_client))
        )
    assert out["superseded"] == "1.0"
    v1_after = detail(client, v1)
    assert v1_after["status"] == "SUPERSEDED" and v1_after["effective_to"] is not None
    assert v1_after["sections"] == v1_before["sections"] and v1_after["manifest_sha256"] == v1_before["manifest_sha256"]
    revs = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.question_revision r JOIN {SCHEMA}.question_bank_item i "
            "ON i.id = r.question_bank_item_id WHERE i.question_code = 'Q-S2A_NEXT-TERM'"
        )
    ).scalar_one()
    assert revs == 2  # the old revision remains for v1.0 and its history


# ---- validation and input rules ----------------------------------------------------------------------------------
def test_validation_blocks_submission_and_inputs_use_only_approved_vocabularies(
    client: TestClient, user: Account
) -> None:
    login(client, user)
    _, vid = new_family(client, "S2A_VALID")
    d = Draft(client, vid)
    r = client.post(
        f"/api/v1/script-versions/{vid}/submit",
        json={"expected_row_version": d.rv, "change_summary": "Nothing in it yet"},
        headers=csrf_header(client),
    )
    assert r.status_code == 422 and r.json()["code"] == "VALIDATION_FAILED"
    assert {x["code"] for x in r.json()["details"] if x["severity"] == "ERROR"} == {"NO_SECTIONS"}
    assert detail(client, vid)["validation_status"] == "INVALID"
    d.post("/sections", {"module_code": "S2A_VALID_CORE", "module_name": "Core", "module_kind": "COMMON"})
    sec = d.sections()[0]["section_id"]
    bad_condition = client.post(
        f"/api/v1/script-versions/{vid}/sections",
        json={
            "expected_row_version": d.rv,
            "module_code": "S2A_VALID_X",
            "module_name": "X",
            "module_kind": "RISK",
            "inclusion_condition": {"fact": "customer_age", "equals": 70},
        },
        headers=csrf_header(client),
    )
    assert bad_condition.status_code == 422 and bad_condition.json()["code"] == "INVALID_CONDITION"
    bad_q = client.post(
        f"/api/v1/script-versions/{vid}/sections/{sec}/questions",
        json={"expected_row_version": d.rv, **q("Q-S2A-VALID-1", expected_boolean=None)},
        headers=csrf_header(client),
    )
    assert bad_q.status_code == 422 and "expected answer" in bad_q.json()["message"]
    bad_fact = client.post(
        f"/api/v1/script-versions/{vid}/sections/{sec}/questions",
        json={
            "expected_row_version": d.rv,
            **q(
                "Q-S2A-VALID-2",
                answer_type="NUMERIC",
                expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
                policy_fact_key="annual_income",
                expected_boolean=None,
            ),
        },
        headers=csrf_header(client),
    )
    assert bad_fact.status_code == 422 and "approved policy fact" in bad_fact.json()["message"]
    r = client.post(
        f"/api/v1/script-versions/{vid}/submit",
        json={"expected_row_version": d.rv, "change_summary": "Empty section"},
        headers=csrf_header(client),
    )
    assert {x["code"] for x in r.json()["details"] if x["severity"] == "ERROR"} == {"EMPTY_SECTION"}
    # Optimistic concurrency: a stale token is refused and nothing changes.
    stale = client.post(
        f"/api/v1/script-versions/{vid}/sections/{sec}/questions",
        json={"expected_row_version": d.rv - 1, **q("Q-S2A-VALID-3")},
        headers=csrf_header(client),
    )
    assert stale.status_code == 409 and stale.json()["code"] == "STALE_DRAFT"
    assert (
        client.post(
            f"/api/v1/script-versions/{vid}/sections/{sec}/questions",
            json={"expected_row_version": d.rv, **q("Q-S2A-VALID-3")},
        ).status_code
        == 403
    )  # CSRF


def test_scope_and_permissions(client: TestClient, user: Account, db: Session) -> None:
    login(client, user)
    _, vid, _ = build_basic(client, "S2A_SCOPE")
    client.cookies.clear()
    outsider = make_account(db, "LOCAL_USER_MY", prefix="outsider")
    login(client, outsider)
    assert client.get(f"/api/v1/script-versions/{vid}").status_code == 404
    assert client.post(f"/api/v1/script-versions/{vid}/validate", headers=csrf_header(client)).status_code == 404
    assert (
        client.post(
            "/api/v1/scripts", json={"code": "S2A_MY", "name": "Malaysia", "market": "MY"}, headers=csrf_header(client)
        ).status_code
        == 403
    )
