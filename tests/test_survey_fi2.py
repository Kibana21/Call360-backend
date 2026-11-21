# ruff: noqa: E501, F811 — long request literals; fixtures imported from test_survey_api
"""FI-2 — what real review and publication need from the server, on the isolated test database:

* server-governed WARNINGS with stable codes, each acknowledged with a reason that is stored in the immutable candidate
  beside the content fingerprint it was given for (owner decision FI2-D-1);
* ``GET /survey-candidates/{id}/documents`` — what a reviewer inspects, and what the identity rules allow the reader;
* ``GET /survey-definitions/{id}/history`` — every candidate and version, with derived status.

The identity rules themselves are those of SS-03A (tests/test_survey_store.py, tests/test_survey_api.py)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain.survey.canonical import sha256_hex
from scripts.e2e_forge_candidate import forge
from tests.support import make_account
from tests.survey_support import new_code
from tests.test_survey_api import ALL, GRANTS, MARKETS, _client, make_survey, post, submit, survey_app, trio  # noqa: F401
from tests.test_survey_fi1 import save, state

WARNING = "SYNTHETIC_WORDING_UNAPPROVED"


def candidates(c: TestClient, sid: str, acks: list[dict[str, Any]], note: str = "") -> Any:
    return post(c, f"/api/v1/survey-definitions/{sid}/candidates", {"note": note, "acknowledgements": acks})


def docs(c: TestClient, cid: str) -> Any:
    r = c.get(f"/api/v1/survey-candidates/{cid}/documents")
    assert r.status_code == 200, r.text
    return r.json()


def frozen_rows(db: Session, sid: str) -> list[tuple[Any, ...]]:
    db.rollback()
    return [
        tuple(r)
        for r in db.execute(
            text(
                "SELECT kind, code, version, state, sha256 FROM survey_asset_version WHERE owner_definition_id = :s ORDER BY 1, 2, 3"
            ),
            {"s": sid},
        )
    ]


# ------------------------------------------------------------------------------- server-governed warnings (FI2-D-1)
def test_the_server_raises_its_governed_warning_with_a_stable_code_and_only_where_there_is_wording(trio: Any) -> None:
    author = trio[0]
    sid, code = make_survey(author, "K7")
    v = post(author, f"/api/v1/survey-definitions/{sid}/draft/validate").json()
    assert v["blockers"] == 0
    (w,) = v["findings"]
    assert (w["code"], w["severity"], w["at"]) == (WARNING, "WARNING", code)
    assert "synthetic" in w["message"] and "not Compliance approval" in w["message"]
    # an empty survey has no wording, so there is nothing to warn about
    r = post(author, "/api/v1/survey-definitions", {"code": new_code(), "name": "Empty survey", "purpose": ""})
    assert [
        f["code"]
        for f in post(author, f"/api/v1/survey-definitions/{r.json()['id']}/draft/validate").json()["findings"]
    ] == ["SURVEY_EMPTY"]


def test_a_draft_cannot_be_submitted_until_every_governed_warning_is_acknowledged_with_a_reason(
    trio: Any, db: Session
) -> None:
    author = trio[0]
    sid, code = make_survey(author, "K7")
    before = state(db, sid), frozen_rows(db, sid)

    r = candidates(author, sid, [])
    assert (r.status_code, r.json()["code"]) == (422, "ACKNOWLEDGEMENT_REQUIRED")
    assert [(d["code"], d["at"]) for d in r.json()["details"]] == [(WARNING, code)]
    for bad_reason in ("", "ok", "         x", "r" * 501):
        r = candidates(author, sid, [{"code": WARNING, "at": code, "reason": bad_reason}])
        assert (r.status_code, r.json()["code"]) == (422, "ACKNOWLEDGEMENT_REQUIRED"), bad_reason
    r = candidates(
        author,
        sid,
        [
            {"code": WARNING, "at": code, "reason": "A good reason."},
            {"code": "INVENTED_WARNING", "at": code, "reason": "Not a server warning."},
        ],
    )
    assert (r.status_code, r.json()["code"]) == (422, "ACKNOWLEDGEMENT_UNKNOWN")
    r = candidates(author, sid, [{"code": WARNING, "at": "S-SOMETHING-ELSE", "reason": "For another place."}])
    assert (r.status_code, r.json()["code"]) == (422, "ACKNOWLEDGEMENT_UNKNOWN")
    r = candidates(author, sid, [{"code": WARNING, "at": code}])
    assert (r.status_code, r.json()["code"]) == (422, "ACKNOWLEDGEMENT_INVALID")
    assert (state(db, sid), frozen_rows(db, sid)) == before  # a refused submission freezes nothing and creates nothing
    assert (
        db.execute(
            text("SELECT count(*) FROM survey_candidate WHERE survey_definition_id = :s"), {"s": sid}
        ).scalar_one()
        == 0
    )

    reason = "Synthetic wording for a development walkthrough; not for operational use."
    r = candidates(author, sid, [{"code": WARNING, "at": code, "reason": f"  {reason}  "}], "please review")
    assert r.status_code == 201, r.text
    d = docs(author, r.json()["id"])
    (ack,) = d["acknowledgements"]
    # recorded in the immutable candidate, against the fingerprint of exactly this content, with who and why
    assert (ack["code"], ack["at"], ack["reason"]) == (WARNING, code, reason)
    assert ack["content_sha256"] == d["content_sha256"] == sha256_hex(d["content"])
    assert ack["acknowledged_by"] == d["submitted_by"]["ref"] and ack["acknowledged_by_name"]
    assert "synthetic" in ack["message"]
    stored = db.execute(
        text("SELECT acknowledgements FROM survey_candidate WHERE id = :c"), {"c": d["id"]}
    ).scalar_one()
    assert stored == d["acknowledgements"]
    audit = db.execute(
        text("SELECT after FROM audit_event WHERE action = 'SURVEY.SUBMITTED' AND entity_id = :c"), {"c": d["id"]}
    ).scalar_one()
    assert audit["acknowledged"] == [WARNING]


# ---------------------------------------------------------------------------------------- what a reviewer is shown
def test_a_reviewer_sees_every_pinned_document_its_hash_the_makers_and_what_they_may_do(trio: Any, db: Session) -> None:
    author, checker, publisher, _ = trio
    sid, code = make_survey(author, "K7")
    cid = submit(author, sid, "please review").json()["id"]
    rows_before = frozen_rows(db, sid)

    d = docs(checker, cid)
    assert (d["n"], d["status"], d["survey_code"], d["note"]) == (1, "IN_REVIEW", code, "please review")
    assert d["manifest_intact"] is True and d["manifest_problems"] == []
    assert len(d["assets"]) == 9 and {a["kind"] for a in d["assets"]} == {"OPTION_SET", "ITEM", "WORDING", "MODULE"}
    for a in d["assets"]:  # the full frozen document, and its hash is the one the manifest pins
        assert a["intact"] is True and sha256_hex(a["document"]) == a["sha256"]
    assert d["content_sha256"] == sha256_hex(d["content"])
    assert [m["name"] for m in d["makers"]] and d["submitted_by"]["name"] and d["approver"] is None
    assert (d["validation"]["blockers"], d["validation"]["warnings"]) == (0, 1)
    assert [h["event"] for h in d["history"]] == ["SUBMITTED"]
    assert (d["version_id"], d["version_label"]) == (None, None)

    # the identity rules, shown per reader — every one of these people holds ALL FOUR permissions
    who = lambda c: docs(c, cid)["restrictions"]  # noqa: E731
    assert (who(author)["is_maker"], who(author)["can_decide"], who(author)["decide_reason"]) == (
        True,
        False,
        "SELF_REVIEW_DENIED",
    )
    assert (who(author)["can_withdraw"], who(checker)["can_withdraw"], who(checker)["withdraw_reason"]) == (
        True,
        False,
        "NOT_SUBMITTER",
    )
    assert (who(checker)["can_decide"], who(checker)["decide_reason"]) == (True, None)
    assert (who(publisher)["can_publish"], who(publisher)["publish_reason"]) == (False, "NOT_APPROVED")

    assert (
        post(
            checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE", "comment": "reads correctly"}
        ).status_code
        == 200
    )
    d = docs(publisher, cid)
    assert (d["status"], d["approver"]["name"] is not None) == ("APPROVED", True)
    assert (who(author)["can_publish"], who(author)["publish_reason"]) == (False, "SELF_PUBLISH_DENIED")
    assert (who(checker)["is_approver"], who(checker)["can_publish"], who(checker)["publish_reason"]) == (
        True,
        False,
        "APPROVER_PUBLISH_DENIED",
    )
    assert (who(publisher)["can_publish"], who(checker)["can_decide"], who(checker)["decide_reason"]) == (
        True,
        False,
        "NOT_IN_REVIEW",
    )
    # what is shown is what is enforced
    assert post(author, f"/api/v1/survey-candidates/{cid}/publish").json()["code"] == "SELF_PUBLISH_DENIED"
    assert post(checker, f"/api/v1/survey-candidates/{cid}/publish").json()["code"] == "APPROVER_PUBLISH_DENIED"
    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish")
    assert r.status_code == 201
    d = docs(author, cid)
    assert (d["status"], d["version_label"], d["version_id"]) == ("PUBLISHED", "1.0", r.json()["id"])
    assert [h["event"] for h in d["history"]] == ["SUBMITTED", "APPROVED", "PUBLISHED"]
    assert frozen_rows(db, sid) == rows_before  # reading, approving and publishing changed no document


def test_reading_candidate_documents_and_history_needs_read_and_the_market(
    trio: Any, survey_app: Any, db: Session
) -> None:
    author = trio[0]
    sid, _ = make_survey(author, "K1")
    cid = submit(author, sid).json()["id"]
    plain = _client(survey_app, make_account(db, prefix="plain"))
    assert plain.get(f"/api/v1/survey-candidates/{cid}/documents").status_code == 403
    assert plain.get(f"/api/v1/survey-definitions/{sid}/history").status_code == 403
    other = make_account(db, prefix="elsewhere")
    GRANTS[other.principal_id] = ALL
    MARKETS[other.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, other)
    assert outsider.get(f"/api/v1/survey-candidates/{cid}/documents").status_code == 404
    assert outsider.get(f"/api/v1/survey-definitions/{sid}/history").status_code == 404
    with TestClient(survey_app, base_url="http://testserver") as anon:
        assert anon.get(f"/api/v1/survey-candidates/{cid}/documents").status_code == 401
    for c in (plain, outsider):
        c.__exit__(None, None, None)
    GRANTS.pop(other.principal_id)
    MARKETS.pop(other.principal_id)


# ------------------------------------------------------------- immutability across later edits; no inherited approval
def test_later_edits_change_neither_the_candidate_nor_the_version_and_a_new_candidate_is_not_approved(
    trio: Any, db: Session
) -> None:
    author, checker, publisher, _ = trio
    sid, code = make_survey(author, "K7")
    c1 = submit(author, sid, "first").json()["id"]
    assert post(checker, f"/api/v1/survey-candidates/{c1}/decision", {"verdict": "APPROVE"}).status_code == 200
    v1 = post(publisher, f"/api/v1/survey-candidates/{c1}/publish").json()["id"]
    c1_before, v1_before = docs(author, c1), author.get(f"/api/v1/survey-versions/{v1}/content").json()

    # the author goes on editing the working draft: a NEW version of one wording, pinned by a new module revision
    draft = author.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    wording = next(a for a in draft["assets"] if a["kind"] == "WORDING")
    module = next(
        a
        for a in draft["assets"]
        if a["kind"] == "MODULE"
        and any(n.get("item", {}).get("code") == wording["code"] for n in a["document"]["nodes"])
    )
    new_wording = {
        **wording["document"],
        "wording_version": wording["version"] + 1,
        "text": "A reworded question for the next revision?",
    }
    new_module = {
        **module["document"],
        "revision": module["version"] + 1,
        "nodes": [
            {**n, "item": {**n["item"], "wording_version": wording["version"] + 1}}
            if n.get("item", {}).get("code") == wording["code"]
            else n
            for n in module["document"]["nodes"]
        ],
    }
    content = {
        **draft["content"],
        "sequence": [
            {**i, "module": {**i["module"], "revision": module["version"] + 1}}
            if i["module"]["code"] == module["code"]
            else i
            for i in draft["content"]["sequence"]
        ],
    }
    r = save(
        author,
        sid,
        draft["revision"],
        [
            {"op": "PUT_ASSET", "kind": "WORDING", "document": new_wording},
            {"op": "PUT_ASSET", "kind": "MODULE", "document": new_module},
            {"op": "SET_CONTENT", "content": content},
        ],
    )
    assert r.status_code == 200, r.text
    # changing a FROZEN version directly is refused: the candidate's documents cannot be reached through the draft
    r = save(
        author,
        sid,
        draft["revision"] + 1,
        [
            {
                "op": "PUT_ASSET",
                "kind": "WORDING",
                "document": {**wording["document"], "text": "Changing the published wording itself"},
            }
        ],
    )
    assert (r.status_code, r.json()["code"]) == (409, "ASSET_FROZEN")

    assert docs(author, c1) == c1_before  # C-1: content, every document, hashes, status, history — unchanged
    assert author.get(f"/api/v1/survey-versions/{v1}/content").json() == v1_before  # Version 1.0: unchanged
    h = author.get(f"/api/v1/survey-definitions/{sid}/history").json()
    assert h["draft_content_sha256"] != c1_before["content_sha256"]  # the draft has moved on; the candidate has not

    # the changed draft is a NEW candidate, in review: it does not inherit C-1's approval
    c2 = submit(author, sid, "second").json()["id"]
    d2 = docs(publisher, c2)
    assert (d2["n"], d2["status"], d2["approver"], d2["version_id"]) == (2, "IN_REVIEW", None, None)
    assert d2["content_sha256"] != c1_before["content_sha256"] and d2["manifest_sha256"] != c1_before["manifest_sha256"]
    assert d2["acknowledgements"][0]["content_sha256"] == d2["content_sha256"]  # acknowledged afresh, for this content
    r = post(publisher, f"/api/v1/survey-candidates/{c2}/publish")
    assert (r.status_code, r.json()["code"]) == (409, "NOT_APPROVED")
    assert docs(author, c1)["status"] == "PUBLISHED"

    h = author.get(f"/api/v1/survey-definitions/{sid}/history").json()
    assert [(c["n"], c["status"], c["last_event"]) for c in h["candidates"]] == [
        (1, "PUBLISHED", "PUBLISHED"),
        (2, "IN_REVIEW", "SUBMITTED"),
    ]
    assert [(v["label"], v["status"], v["candidate_n"]) for v in h["versions"]] == [("1.0", "PUBLISHED", 1)]
    assert h["candidates"][0]["submitted_by"] and h["versions"][0]["published_by"] and h["candidates"][0]["makers"] == 1
    assert (h["code"], h["draft_revision"]) == (code, draft["revision"] + 1)

    # C-2 approved and published by the other two people: version 2.0; version 1.0 is superseded, and still unchanged
    assert post(checker, f"/api/v1/survey-candidates/{c2}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert post(publisher, f"/api/v1/survey-candidates/{c2}/publish").status_code == 201
    h = author.get(f"/api/v1/survey-definitions/{sid}/history").json()
    assert [(v["label"], v["status"]) for v in h["versions"]] == [("1.0", "SUPERSEDED"), ("2.0", "PUBLISHED")]
    assert author.get(f"/api/v1/survey-versions/{v1}/content").json() == v1_before


def test_a_tampered_candidate_is_shown_as_such_and_can_be_neither_approved_nor_published(
    trio: Any, db: Session
) -> None:
    author, checker, publisher, _ = trio
    sid, code = make_survey(author, "K1")
    good = submit(author, sid).json()["id"]
    fid = str(forge(db, code))
    db.commit()
    d = docs(checker, fid)
    assert d["status"] == "IN_REVIEW" and d["manifest_intact"] is False and d["manifest_problems"]
    assert [a["intact"] for a in d["assets"]].count(False) == 1  # exactly the pinned hash that was changed
    r = post(checker, f"/api/v1/survey-candidates/{fid}/decision", {"verdict": "APPROVE"})
    assert (r.status_code, r.json()["code"]) == (409, "MANIFEST_MISMATCH")
    assert docs(checker, fid)["status"] == "IN_REVIEW"  # not approved
    assert post(publisher, f"/api/v1/survey-candidates/{fid}/publish").json()["code"] == "NOT_APPROVED"
    denied = db.execute(
        text("SELECT count(*) FROM audit_event WHERE action = 'SURVEY.MANIFEST_MISMATCH' AND entity_id = :c"),
        {"c": fid},
    ).scalar_one()
    assert denied == 1
    assert docs(checker, good)["manifest_intact"] is True  # the untouched candidate still verifies
