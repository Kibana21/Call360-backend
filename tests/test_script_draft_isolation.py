"""S2-A.1 owner refinements: draft-isolated question and control-link changes, published-only reuse from the question
bank, preserved revision history and the audited Abandon Draft action."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.domain.digest import content_digest
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account
from tests.test_script_authoring import Draft, approve, build_basic, detail, ok, q

pytestmark = pytest.mark.usefixtures("seeded")


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="checker")


def controls_of(c: TestClient, vid: str, code: str) -> list[str]:
    for sec in detail(c, vid)["sections"]:
        for x in sec["questions"]:
            if x["question_code"] == code:
                return sorted(ctl["control_code"] for ctl in x["controls"])
    raise AssertionError(code)


def publish(c: TestClient, vid: str) -> None:
    for step, body in (("review", approve(c, vid)), ("publish", {})):
        ok(c.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(c)))


def seeded_published(conn: Connection) -> str:
    return str(
        conn.execute(
            text(
                f"SELECT v.id FROM {SCHEMA}.script_version v JOIN {SCHEMA}.script_family f "
                "ON f.id = v.script_family_id WHERE f.code = 'SALES_VERIFICATION_SG' AND v.status = 'PUBLISHED'"
            )
        ).scalar_one()
    )


def test_control_link_and_question_changes_stay_inside_their_draft(
    client: TestClient, other_client: TestClient, user: Account, checker: Account, conn: Connection
) -> None:
    login(client, user)
    seeded = seeded_published(conn)
    seeded_before = detail(client, seeded)
    library_before = conn.execute(text(f"SELECT count(*), max(updated_at) FROM {SCHEMA}.control_mapping")).one()
    digest_before = content_digest(conn, SCHEMA)
    conn.rollback()
    controls = ok(client.get("/api/v1/script-authoring/options"))["controls"]
    # Two drafts of different families both reuse the seeded question Q-REP-DISCLOSED from the question bank.
    _, va, a = build_basic(client, "ISO_A")
    _, vb, b = build_basic(client, "ISO_B")
    for d in (a, b):
        d.post(f"/sections/{d.sections()[0]['section_id']}/questions", {"question_code": "Q-REP-DISCLOSED"})
    shared = controls_of(client, va, "Q-REP-DISCLOSED")
    assert shared and shared == controls_of(client, vb, "Q-REP-DISCLOSED")  # each draft copied the published links
    assert detail(client, va)["controls_source"] == "DRAFT"
    # Draft A replaces the links; draft B, the seeded version and the concept library are untouched.
    a.put("/questions/Q-REP-DISCLOSED/controls", {"links": [{"control_id": controls[-1]["id"], "rationale": "Only A"}]})
    assert controls_of(client, va, "Q-REP-DISCLOSED") == [controls[-1]["code"]]
    assert controls_of(client, vb, "Q-REP-DISCLOSED") == shared
    assert detail(client, seeded) == seeded_before
    assert conn.execute(text(f"SELECT count(*), max(updated_at) FROM {SCHEMA}.control_mapping")).one() == library_before
    # Draft A rewords and recategorises the shared question: a new revision for A only.
    sec_a = a.sections()[0]
    mq = next(x for x in sec_a["questions"] if x["question_code"] == "Q-REP-DISCLOSED")
    item_before = conn.execute(
        text(f"SELECT intent, category, row_version FROM {SCHEMA}.question_bank_item WHERE question_code = :c"),
        {"c": "Q-REP-DISCLOSED"},
    ).one()
    conn.rollback()
    a.put(
        f"/sections/{sec_a['section_id']}/questions/{mq['module_question_id']}",
        {
            "content": q(
                "x",
                intent="Customer confirms the representative disclosed the relationship (draft A)",
                category="DISCLOSURE",
                customer_wording="Did the representative tell you they act for the insurer?",
            )["content"],
            "change_reason": "Draft A wording",
        },
    )
    rev_a = next(x for x in a.sections()[0]["questions"] if x["question_code"] == "Q-REP-DISCLOSED")
    rev_b = next(x for x in b.sections()[0]["questions"] if x["question_code"] == "Q-REP-DISCLOSED")
    assert rev_a["category"] == "DISCLOSURE" and rev_a["revision"] > rev_b["revision"]
    assert rev_b["intent"] == item_before.intent and rev_b["category"] == item_before.category
    item_after = conn.execute(
        text(f"SELECT intent, category, row_version FROM {SCHEMA}.question_bank_item WHERE question_code = :c"),
        {"c": "Q-REP-DISCLOSED"},
    ).one()
    assert item_after == item_before  # the shared bank item is never changed by a draft
    # Draft A's unpublished revision is not what the bank offers others: B reuses the latest published revision.
    bank = {x["question_code"]: x for x in ok(client.get("/api/v1/question-bank"))["items"]}
    assert bank["Q-REP-DISCLOSED"]["latest_revision"] == rev_b["revision"] and bank["Q-REP-DISCLOSED"]["reusable"]
    # A question that exists only in draft A cannot be reused by B until it is published.
    assert bank["Q-ISO_A-EXPLAINED"]["reusable"] is False
    r = client.post(
        f"/api/v1/script-versions/{vb}/sections/{b.sections()[0]['section_id']}/questions",
        json={"expected_row_version": b.rv, "question_code": "Q-ISO_A-EXPLAINED"},
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "QUESTION_NOT_PUBLISHED"
    # Publishing A freezes A's links; B still shows its own.
    a.post("/submit", {"change_summary": "Isolation test version A"})
    login(other_client, checker)
    publish(other_client, va)
    pub_a = detail(client, va)
    assert pub_a["controls_source"] == "MANIFEST" and controls_of(client, va, "Q-REP-DISCLOSED") == [
        controls[-1]["code"]
    ]
    assert controls_of(client, vb, "Q-REP-DISCLOSED") == shared
    bank = {x["question_code"]: x for x in ok(client.get("/api/v1/question-bank"))["items"]}
    assert bank["Q-ISO_A-EXPLAINED"]["reusable"] is True
    # Historical revisions are preserved: every revision of the question still exists, and the seed is unchanged.
    revs = conn.execute(
        text(
            f"SELECT count(*) FROM {SCHEMA}.question_revision qr JOIN {SCHEMA}.question_bank_item i "
            "ON i.id = qr.question_bank_item_id WHERE i.question_code = 'Q-REP-DISCLOSED'"
        )
    ).scalar_one()
    assert revs >= 2
    assert content_digest(conn, SCHEMA) == digest_before


def test_abandon_draft_is_audited_frozen_and_deletes_nothing(
    client: TestClient, other_client: TestClient, user: Account, db: Session, conn: Connection
) -> None:
    login(client, user)
    fid, vid, d = build_basic(client, "ISO_ABANDON")
    sections_before = d.sections()
    stranger = make_account(db, "LOCAL_USER_SG", prefix="other")
    login(other_client, stranger)
    r = other_client.post(
        f"/api/v1/script-versions/{vid}/abandon",
        json={"expected_row_version": d.rv, "reason": "Not mine to abandon"},
        headers=csrf_header(other_client),
    )
    assert r.status_code == 403 and r.json()["code"] == "NOT_A_MAKER"
    r = client.post(
        f"/api/v1/script-versions/{vid}/abandon",
        json={"expected_row_version": d.rv - 1, "reason": "Stale token"},
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "STALE_DRAFT"
    r = client.post(
        f"/api/v1/script-versions/{vid}/abandon",
        json={"expected_row_version": d.rv, "reason": "x"},
        headers=csrf_header(client),
    )
    assert r.status_code == 422
    out = ok(
        client.post(
            f"/api/v1/script-versions/{vid}/abandon",
            json={"expected_row_version": d.rv, "reason": "Superseded by a different approach (test)"},
            headers=csrf_header(client),
        )
    )
    assert out["status"] == "ABANDONED"
    after = detail(client, vid)
    assert after["status"] == "ABANDONED" and after["sections"] == sections_before  # nothing deleted
    events = ok(client.get(f"/api/v1/script-versions/{vid}/history"))["events"]
    assert events[-1]["event_type"] == "ABANDONED" and "different approach" in events[-1]["reason"]
    audit = conn.execute(
        text(f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'SCRIPT.DRAFT_ABANDONED' AND entity_id = :v"),
        {"v": vid},
    ).scalar_one()
    assert audit == 1
    # Frozen: the API refuses changes and the database refuses them too.
    r = client.post(
        f"/api/v1/script-versions/{vid}/sections/{sections_before[0]['section_id']}/questions",
        json={"expected_row_version": after["row_version"], **q("Q-ISO_ABANDON-LATE")},
        headers=csrf_header(client),
    )
    assert r.status_code == 409 and r.json()["code"] == "VERSION_NOT_EDITABLE"
    with pytest.raises(Exception, match="immutable|locked"):
        conn.execute(text(f"DELETE FROM {SCHEMA}.script_section WHERE script_version_id = :v"), {"v": vid})
    conn.rollback()
    with pytest.raises(Exception, match="invalid script_version transition"):
        conn.execute(text(f"UPDATE {SCHEMA}.script_version SET status = 'DRAFT' WHERE id = :v"), {"v": vid})
    conn.rollback()
    # The family can start again; the abandoned version stays in its history.
    new = ok(client.post(f"/api/v1/scripts/{fid}/drafts", json={}, headers=csrf_header(client)), 201)
    assert new["version_label"] == "1.1"
    labels = {v["version_label"]: v["status"] for v in ok(client.get(f"/api/v1/scripts/{fid}/versions"))["items"]}
    assert labels == {"1.0": "ABANDONED", "1.1": "DRAFT"}
    Draft(client, new["script_version_id"])  # the new draft is editable
