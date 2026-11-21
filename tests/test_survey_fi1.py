# ruff: noqa: E501, E731, F811, S603 — long request literals; fixtures imported from test_survey_api; one fixed local command
"""FI-1 — the two additive backend operations a real Save needs, on the isolated test database:

* ``GET  /survey-definitions/{id}/draft/documents`` — everything needed to open a draft, with the server's hashes;
* ``POST /survey-definitions/{id}/draft/save`` — one Save: every operation as ONE revision, or none of them.

and the optional ``authoring`` field of MODULE and CONDITION documents. Permissions are granted per person exactly as in
``test_survey_api`` (no role holds a survey permission)."""

from __future__ import annotations

import copy
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.documents import check_document
from app.domain.survey.validator import validate
from tests.support import make_account
from tests.survey_support import fixture_bundle, namespaced, new_code, operations_for
from tests.test_survey_api import ALL, GRANTS, MARKETS, _client, make_survey, post, survey_app, trio  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


def new_survey(c: TestClient) -> tuple[str, str]:
    code = new_code()
    r = post(c, "/api/v1/survey-definitions", {"code": code, "name": f"Test {code}", "purpose": "synthetic"})
    assert r.status_code == 201, r.text
    return r.json()["id"], code


def ops_of(prefix: str, code: str) -> list[dict[str, Any]]:
    return operations_for(namespaced(fixture_bundle(prefix), "-" + code[2:]), code)


def state(db: Session, sid: str) -> tuple[Any, ...]:
    """The draft row, every asset of the survey and the count of its audit events: what a failed save must not change."""
    db.rollback()
    d = db.execute(
        text(
            "SELECT revision, content, updated_at, updated_by, makers FROM survey_draft WHERE survey_definition_id = :s"
        ),
        {"s": sid},
    ).one()
    assets = db.execute(
        text(
            "SELECT kind, code, version, state, sha256 FROM survey_asset_version WHERE owner_definition_id = :s ORDER BY 1, 2, 3"
        ),
        {"s": sid},
    ).all()
    audits = db.execute(
        text("SELECT count(*) FROM audit_event WHERE entity_id = :s AND outcome = 'SUCCEEDED'"), {"s": sid}
    ).scalar_one()
    name = db.execute(text("SELECT name, purpose FROM survey_definition WHERE id = :s"), {"s": sid}).one()
    return tuple(d), [tuple(a) for a in assets], audits, tuple(name)


def save(c: TestClient, sid: str, revision: int, operations: list[dict[str, Any]]) -> Any:
    return post(
        c, f"/api/v1/survey-definitions/{sid}/draft/save", {"expected_revision": revision, "operations": operations}
    )


# ----------------------------------------------------------------------------------------------------- one atomic save
def test_a_whole_survey_is_saved_as_one_revision_and_read_back_with_the_servers_hashes(trio: Any, db: Session) -> None:
    author = trio[0]
    sid, code = new_survey(author)
    ops = ops_of("K7", code)
    r = save(author, sid, 0, ops)
    assert r.status_code == 200, r.text
    saved = r.json()
    assert (saved["revision"], saved["code"], len(saved["assets"])) == (1, code, 9)  # ten operations, ONE revision
    assert {a["state"] for a in saved["assets"]} == {"DRAFT"} and all(a["owned"] for a in saved["assets"])
    # the response is the complete saved draft, and every hash is the server's own canonical hash of that document
    sent = {(o["kind"], sha256_hex(o["document"])) for o in ops if o["op"] == "PUT_ASSET"}
    assert {(a["kind"], a["sha256"]) for a in saved["assets"]} == sent
    assert all(a["sha256"] == sha256_hex(a["document"]) for a in saved["assets"])
    assert saved["content"] == ops[-1]["content"] and saved["content_sha256"] == sha256_hex(saved["content"])
    assert saved["updated_by"] and saved["catalogs"]["fields"] and saved["catalogs"]["outcomes"]
    assert all(f["speakable"] is False for f in saved["catalogs"]["fields"].values())  # still default-deny
    # reading it again gives exactly the same thing (a reload shows what was saved)
    again = author.get(f"/api/v1/survey-definitions/{sid}/draft/documents")
    assert again.status_code == 200 and again.json() == saved
    # one audit event for the save, not ten; the chain verifies
    rows = db.execute(text("SELECT action, after FROM audit_event WHERE entity_id = :s ORDER BY seq"), {"s": sid}).all()
    assert [a for a, _ in rows] == ["SURVEY.CREATED", "SURVEY.DRAFT_SAVED"]
    assert (rows[1][1]["operations"], rows[1][1]["revision"], rows[1][1]["by_operation"]) == (
        10,
        1,
        {"PUT_ASSET": 9, "SET_CONTENT": 1},
    )
    assert verify_chain(db).ok
    # server validation of the saved draft: valid
    assert post(author, f"/api/v1/survey-definitions/{sid}/draft/validate").json()["blockers"] == 0


def test_a_batch_save_gives_the_same_documents_as_the_same_operations_one_at_a_time(trio: Any) -> None:
    author = trio[0]
    one_by_one, code_a = make_survey(author, "K8")  # one operation at a time: one revision each
    batch, code_b = new_survey(author)
    assert save(author, batch, 0, ops_of("K8", code_b)).status_code == 200

    def shape(sid: str, code: str) -> Any:
        d = author.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
        strip = lambda v: v.replace("-" + code[2:], "").replace(code, "S") if isinstance(v, str) else v  # noqa: E731
        walk = lambda v: (
            {strip(k): walk(x) for k, x in v.items()}
            if isinstance(v, dict)
            else [walk(x) for x in v]
            if isinstance(v, list)
            else strip(v)
        )  # noqa: E731
        return walk(d["content"]), sorted((a["kind"], str(walk(a["document"]))) for a in d["assets"])

    assert shape(one_by_one, code_a) == shape(batch, code_b)
    assert author.get(f"/api/v1/survey-definitions/{one_by_one}/draft").json()["revision"] == len(ops_of("K8", code_a))
    assert author.get(f"/api/v1/survey-definitions/{batch}/draft").json()["revision"] == 1


def test_a_save_that_fails_part_way_changes_nothing_at_all(trio: Any, db: Session) -> None:
    author = trio[0]
    sid, code = new_survey(author)
    ops = ops_of("K7", code)
    assert save(author, sid, 0, ops[:4]).status_code == 200  # a first, good save: revision 1
    before = state(db, sid)

    # five good operations, then a malformed document, then more good ones
    bad = copy.deepcopy(ops)
    bad[6]["document"]["schema"] = "call360.survey.module/9"
    r = save(author, sid, 1, bad)
    assert (r.status_code, r.json()["code"]) == (422, "DOCUMENT_INVALID")
    assert r.json()["details"][0]["operation_index"] == 6  # the error names the operation that was refused
    assert state(db, sid) == before  # draft row, every asset, the audit trail and the name: all exactly as they were

    # a rename and good documents, then a removal of something that does not exist: the rename is rolled back too
    r = save(
        author,
        sid,
        1,
        [
            {"op": "SET_DETAILS", "name": "Renamed and then refused", "purpose": "x"},
            *ops[4:6],
            {"op": "REMOVE_ASSET", "kind": "ITEM", "code": "NO-SUCH", "version": 1},
        ],
    )
    assert (r.status_code, r.json()["code"], r.json()["details"][0]["operation_index"]) == (404, "NOT_FOUND", 3)
    assert state(db, sid) == before

    # an unknown operation in the last position
    r = save(author, sid, 1, [*ops[4:], {"op": "PUBLISH_NOW"}])
    assert (r.status_code, r.json()["code"]) == (422, "OPERATION_INVALID")
    assert state(db, sid) == before

    # the same good operations, complete: one more revision
    r = save(author, sid, 1, ops[4:])
    assert r.status_code == 200 and r.json()["revision"] == 2 and len(r.json()["assets"]) == 9


def test_a_save_cannot_change_a_frozen_version_and_is_refused_whole(trio: Any, db: Session) -> None:
    author, checker = trio[0], trio[1]
    sid, code = make_survey(author, "K1")
    cid = post(author, f"/api/v1/survey-definitions/{sid}/candidates").json()["id"]  # freezes what the draft pins
    assert post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    docs = author.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    assert {a["state"] for a in docs["assets"]} == {"FROZEN"}
    wording = next(a for a in docs["assets"] if a["kind"] == "WORDING")
    before = state(db, sid)
    newer = {**wording["document"], "wording_version": wording["version"] + 1, "text": "A new version of the wording."}
    changed = {**wording["document"], "text": "The same version, changed."}
    r = save(
        author,
        sid,
        docs["revision"],
        [
            {"op": "PUT_ASSET", "kind": "WORDING", "document": newer},
            {"op": "PUT_ASSET", "kind": "WORDING", "document": changed},
        ],
    )
    assert (r.status_code, r.json()["code"], r.json()["details"][0]["operation_index"]) == (409, "ASSET_FROZEN", 1)
    assert state(db, sid) == before  # the new version of the first operation was not kept either
    r = save(author, sid, docs["revision"], [{"op": "PUT_ASSET", "kind": "WORDING", "document": newer}])
    assert r.status_code == 200
    states = {
        (a["kind"], a["version"]): a["state"]
        for a in r.json()["assets"]
        if a["code"] == wording["code"] and a["kind"] == "WORDING"
    }
    assert states == {("WORDING", wording["version"]): "FROZEN", ("WORDING", wording["version"] + 1): "DRAFT"}


def test_a_stale_save_is_refused_and_two_sessions_never_overwrite_each_other_silently(
    trio: Any, survey_app: Any, db: Session
) -> None:
    first = trio[0]
    second_person = make_account(db, prefix="second")
    GRANTS[second_person.principal_id] = frozenset({"survey.read", "survey.edit"})
    second = _client(survey_app, second_person)
    sid, code = new_survey(first)
    ops = ops_of("K1", code)
    assert save(first, sid, 0, ops).status_code == 200
    a = first.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    b = second.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    assert a["revision"] == b["revision"] == 1

    item = next(x for x in a["assets"] if x["kind"] == "ITEM")
    assert (
        save(
            first,
            sid,
            1,
            [
                {
                    "op": "PUT_ASSET",
                    "kind": "ITEM",
                    "document": {**item["document"], "intent": "changed by the first session"},
                }
            ],
        ).status_code
        == 200
    )
    before = state(db, sid)
    r = save(
        second,
        sid,
        1,
        [
            {
                "op": "PUT_ASSET",
                "kind": "ITEM",
                "document": {**item["document"], "intent": "changed by the second session"},
            }
        ],
    )
    assert (r.status_code, r.json()["code"]) == (409, "STALE_DRAFT")
    assert r.json()["details"][0] == {"current_revision": 2, "expected_revision": 1}
    assert state(db, sid) == before
    # the second session reads the newer draft, and then saves deliberately on top of it
    newer = second.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    assert (
        newer["revision"],
        next(x for x in newer["assets"] if x["kind"] == "ITEM" and x["code"] == item["code"])["document"]["intent"],
    ) == (2, "changed by the first session")
    r = save(
        second,
        sid,
        2,
        [
            {
                "op": "PUT_ASSET",
                "kind": "ITEM",
                "document": {**item["document"], "intent": "changed by the second session"},
            }
        ],
    )
    assert r.status_code == 200 and r.json()["revision"] == 3
    makers = db.execute(
        text("SELECT jsonb_array_length(makers) FROM survey_draft WHERE survey_definition_id = :s"), {"s": sid}
    ).scalar_one()
    assert makers == 2  # both are makers of the draft: neither may approve or publish a candidate of it
    second.__exit__(None, None, None)
    GRANTS.pop(second_person.principal_id)


def test_repeating_a_save_whose_reply_was_lost_cannot_apply_it_twice(trio: Any) -> None:
    author = trio[0]
    sid, code = new_survey(author)
    ops = ops_of("K1", code)
    first = save(author, sid, 0, ops)
    assert first.status_code == 200
    # the client never saw that reply and sends the same save again: refused as stale, and the draft is as first saved
    again = save(author, sid, 0, ops)
    assert (again.status_code, again.json()["code"]) == (409, "STALE_DRAFT")
    now = author.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()
    assert (
        now == first.json()
    )  # so a client can tell "already saved" by reading the draft: revision 1, identical documents


def test_save_limits_and_details(trio: Any, db: Session) -> None:
    author = trio[0]
    sid, code = new_survey(author)
    assert save(author, sid, 0, []).status_code == 422
    one = {"op": "SET_DETAILS", "name": "A name", "purpose": ""}
    assert save(author, sid, 0, [one] * 501).status_code == 422
    assert state(db, sid)[0][0] == 0
    r = save(author, sid, 0, [{"op": "SET_DETAILS", "name": "  Renamed survey  ", "purpose": "A stated purpose."}])
    assert r.status_code == 200 and (r.json()["name"], r.json()["purpose"], r.json()["revision"]) == (
        "Renamed survey",
        "A stated purpose.",
        1,
    )
    assert author.get(f"/api/v1/survey-definitions/{sid}").json()["name"] == "Renamed survey"
    for bad in (
        {"op": "SET_DETAILS", "name": "ab"},
        {"op": "SET_DETAILS", "name": "x" * 161},
        {"op": "SET_DETAILS", "name": "Fine name", "purpose": "p" * 2001},
        {"op": "SET_DETAILS"},
    ):
        r = save(author, sid, 1, [bad])
        assert (r.status_code, r.json()["code"]) == (422, "OPERATION_INVALID"), bad
    assert state(db, sid)[3] == ("Renamed survey", "A stated purpose.")


# ------------------------------------------------------------------------------------------------------- authorisation
def test_reading_documents_needs_read_saving_needs_edit_and_both_are_market_scoped(
    trio: Any, survey_app: Any, db: Session
) -> None:
    author = trio[0]
    sid, code = new_survey(author)
    ops = ops_of("K1", code)
    assert save(author, sid, 0, ops).status_code == 200
    before = state(db, sid)

    with TestClient(survey_app, base_url="http://testserver", headers={"Origin": "http://testserver"}) as anon:
        assert anon.get(f"/api/v1/survey-definitions/{sid}/draft/documents").status_code == 401
        assert (
            anon.post(
                f"/api/v1/survey-definitions/{sid}/draft/save", json={"expected_revision": 1, "operations": ops}
            ).status_code
            == 401
        )

    reader_person = make_account(db, prefix="reader")
    GRANTS[reader_person.principal_id] = frozenset({"survey.read"})
    reader = _client(survey_app, reader_person)
    assert reader.get(f"/api/v1/survey-definitions/{sid}/draft/documents").status_code == 200
    r = save(reader, sid, 1, ops)
    assert (r.status_code, r.json()["code"]) == (403, "FORBIDDEN")

    plain = _client(survey_app, make_account(db, prefix="plain"))  # an ordinary USER: no survey permission at all
    assert plain.get(f"/api/v1/survey-definitions/{sid}/draft/documents").status_code == 403
    assert save(plain, sid, 1, ops).status_code == 403

    # an editor without the CSRF token
    r = author.post(f"/api/v1/survey-definitions/{sid}/draft/save", json={"expected_revision": 1, "operations": ops})
    assert r.status_code == 403 and r.json()["code"].startswith("CSRF")

    outsider_person = make_account(db, prefix="outsider")  # every permission, another market
    GRANTS[outsider_person.principal_id] = ALL
    MARKETS[outsider_person.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, outsider_person)
    assert outsider.get(f"/api/v1/survey-definitions/{sid}/draft/documents").status_code == 404
    r = save(outsider, sid, 1, ops)
    assert (r.status_code, r.json()["code"]) == (404, "NOT_FOUND")
    assert outsider.get(f"/api/v1/survey-definitions/{uuid.uuid4()}/draft/documents").status_code == 404

    assert state(db, sid) == before
    for c in (reader, plain, outsider):
        c.__exit__(None, None, None)
    for p in (reader_person, outsider_person):
        GRANTS.pop(p.principal_id, None)
        MARKETS.pop(p.principal_id, None)


def test_another_surveys_draft_asset_cannot_be_taken_by_a_save(trio: Any, db: Session) -> None:
    author = trio[0]
    mine, code_a = new_survey(author)
    theirs, code_b = new_survey(author)
    ops = ops_of("K1", code_a)
    assert save(author, mine, 0, ops).status_code == 200
    before = state(db, theirs)
    r = save(author, theirs, 0, [ops[0]])
    assert (r.status_code, r.json()["code"]) == (409, "ASSET_OWNED_ELSEWHERE")
    assert state(db, theirs) == before
    assert code_b


# ------------------------------------------------------------------------------------------------- the authoring field
def test_authoring_notes_are_part_of_the_document_and_change_no_rule() -> None:
    b = fixture_bundle("K8")
    module = dict(next(iter(b.modules.values())))
    condition = dict(next(iter(b.conditions.values())))
    with_notes = {**module, "authoring": {"intent": "Why this module exists", "default_entry": {"mode": "ALWAYS"}}}
    cond_notes = {**condition, "authoring": {"param_labels": {"threshold": "Premium threshold"}, "shared": False}}
    assert check_document("MODULE", with_notes) == [] and check_document("CONDITION", cond_notes) == []
    assert sha256_hex(with_notes) != sha256_hex(module)  # it IS part of the document and of its hash
    # a document without the field is exactly as before; other unknown fields are still refused
    assert check_document("MODULE", module) == []
    item = dict(next(iter(b.items.values())))
    assert check_document("ITEM", {**item, "authoring": {"wording_version": 2}}) == []
    wording = dict(next(iter(b.wordings.values())))
    assert [p.code for p in check_document("WORDING", {**wording, "authoring": {}})] == ["DOCUMENT_FIELD_UNKNOWN"]
    assert [p.code for p in check_document("MODULE", {**module, "authoring": "text"})] == ["DOCUMENT_FIELD_INVALID"]
    assert [p.code for p in check_document("MODULE", {**module, "notes": {}})] == ["DOCUMENT_FIELD_UNKNOWN"]

    # no rule reads it: the findings of the survey are identical with and without the notes
    def findings(mods: Any, conds: Any) -> list[tuple[str, str]]:
        from app.domain.survey.documents import Bundle

        nb = Bundle.build(
            fields=b.fields,
            outcomes=b.outcomes,
            option_sets=b.option_sets.values(),
            items=b.items.values(),
            wordings=b.wordings.values(),
            conditions=conds,
            modules=mods,
            survey=b.survey,
        )
        return [(f.code, f.at) for f in validate(nb)]

    plain = findings(b.modules.values(), b.conditions.values())
    noted = findings(
        [{**dict(m), "authoring": {"intent": "x"}} for m in b.modules.values()],
        [{**dict(c), "authoring": {"shared": False}} for c in b.conditions.values()],
    )
    assert plain == noted


# ------------------------------------------------------------------------------------------- the exported documents
def test_the_exported_canonical_fixture_documents_are_current() -> None:
    """The frontend proves its Workspace <-> document mapping on these 27 files; they must be exactly what the backend's
    own translation and canonical hash produce today."""
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "export_survey_fixture_documents.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )  # noqa: S603
    assert r.returncode == 0, r.stdout + r.stderr
    assert "27 files" in r.stdout
