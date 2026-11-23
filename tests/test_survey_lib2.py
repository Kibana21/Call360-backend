# ruff: noqa: E501, F811 — long request literals; fixtures imported from the other survey test modules
"""LIB-2 — a reusable module authored, tested, reviewed and published ON ITS OWN, on the isolated test database.

No survey is created to author it · its draft holds exactly the fixed one-module frame · it is tested by the Python
engine and nothing is recorded · it is published by three different people through the existing governance · it is
then in the existing library and pinned by exact revision · a newer revision changes no survey · it is never a survey:
not listed as one, not simulated, planned or assigned as one — by the application and by the database."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.main import MIGRATION_HEAD, create_app
from tests.support import make_account, migrate
from tests.survey_support import fixture_bundle, operations_for
from tests.test_survey_api import ALL, GRANTS, MARKETS, _client, post, submit, with_grants
from tests.test_survey_fi1 import save
from tests.test_survey_lib1 import build, draft, empty_survey, issue, lib
from tests.test_survey_lib1 import publish as publish_survey

M = "/api/v1/survey-modules"
T = "/api/v1/survey-module-tests"
EVERYTHING = ALL | {"survey.simulate"}
OPERATIONAL = (
    "callback_case",
    "contact_attempt",
    "conversation_session",
    "finding",
    "survey_simulation",
    "survey_call_plan",
)


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True,
                "survey_module_authoring_enabled": True, "transcription_worker": False,
            }
        )
    )  # fmt: skip
    with_grants(app)
    return app


@pytest.fixture()
def trio(survey_app: Any, db: Session):  # type: ignore[no-untyped-def]
    people = tuple(make_account(db, prefix=p) for p in ("mauthor", "mchecker", "mpublisher"))
    for p in people:
        GRANTS[p.principal_id] = EVERYTHING
    clients = tuple(_client(survey_app, p) for p in people)
    yield clients[0], clients[1], clients[2], people
    for c in clients:
        c.__exit__(None, None, None)
    for p in people:
        GRANTS.pop(p.principal_id, None)


def counts(db: Session, tables: tuple[str, ...]) -> dict[str, int]:
    db.rollback()
    return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in tables}  # noqa: S608 — fixed names


def create(c: TestClient, name: str = "Suitability check", description: str = "Checks understanding") -> dict[str, Any]:
    r = post(c, M, {"name": name, "description": description})
    assert r.status_code == 201, r.text
    return r.json()


def frame(code: str, doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "call360.survey.content/1", "code": code,
        "sequence": [{"instance": "module", "module": {"code": code, "revision": doc["revision"]}, "routes": {o: {"survey_outcome": o} for o in doc["outcomes"]}}],
    }  # fmt: skip


def fill(c: TestClient, m: dict[str, Any], prefix: str, revision: int = 1) -> dict[str, Any]:
    """Put the ONE module of a golden fixture into a standalone module: the module takes the standalone module's own
    code, everything it places takes a code the server issues to it. Returns the saved module document."""
    b = fixture_bundle(prefix)
    assert len(b.modules) == 1
    old_module = next(iter(b.modules))[0]
    old = {
        "OPTION_SET": [k[0] for k in b.option_sets],
        "ITEM": sorted({k[0] for k in b.items}),
        "CONDITION": sorted({k[0] for k in b.conditions}),
    }
    got = issue(c, m["id"], **{k: len(v) for k, v in old.items()})
    renames = {o: n for k in old for o, n in zip(old[k], got.get(k, []), strict=True)} | {old_module: m["code"]}
    ops_text = json.dumps([o for o in operations_for(b, m["code"]) if o["op"] == "PUT_ASSET"])
    for o, n in renames.items():
        ops_text = ops_text.replace(json.dumps(o), json.dumps(n))
    ops = json.loads(ops_text)
    for op in ops:
        if op["kind"] == "WORDING":
            op["document"]["text"] = re.sub(r"\{\{[^}]*\}\}", "the stated amount", op["document"]["text"])
            op["document"]["delivery_mode"] = "CONTROLLED_TTS"  # the only publishable delivery of plain text (TS-4)
        if op["kind"] == "MODULE":
            op["document"] |= {"revision": revision, "name": m["name"]}
    doc = next(o["document"] for o in ops if o["kind"] == "MODULE")
    d = draft(c, m["id"])
    r = save(c, m["id"], d["revision"], [*ops, {"op": "SET_CONTENT", "content": frame(m["code"], doc)}])
    assert r.status_code == 200, r.text
    return doc


def publish(people: Any, mid: str, note: str = "") -> tuple[str, str]:
    return publish_survey(people, mid, note)


def run_test(c: TestClient, **body: Any) -> Any:
    return post(c, T, body)


def place(c: TestClient, sid: str, code: str, revision: int, outcomes: list[str], instance: str = "mi-reused") -> Any:
    d = draft(c, sid)
    inst = {
        "instance": instance,
        "module": {"code": code, "revision": revision},
        "routes": {o: "@CONTINUE" if o == "COMPLETED" else {"survey_outcome": o} for o in outcomes},
    }
    return save(
        c,
        sid,
        d["revision"],
        [{"op": "SET_CONTENT", "content": {**d["content"], "sequence": [*d["content"]["sequence"], inst]}}],
    )


# ------------------------------------------------------------------------------------------------- 1 · no survey needed
def test_a_module_is_created_without_a_survey_and_is_never_listed_as_one(trio: Any, db: Session) -> None:
    author = trio[0]
    surveys_before = author.get("/api/v1/survey-definitions").json()["items"]
    workspace_before = author.get("/api/v1/survey-definitions/workspace").json()["inventory"]["surveys"]["total"]
    m = create(author, "Standalone suitability", "Checks the customer understood")
    assert re.fullmatch(r"M-\d+", m["code"]) and (m["working_revision"], m["working_state"], m["draft_revision"]) == (
        1,
        "DRAFT",
        0,
    )
    assert (
        m["unpublished_changes"]
        and m["published"] == []
        and m["open_candidate"] is None
        and m["latest_published_revision"] is None
    )
    assert (m["name"], m["description"], m["saved_by_you"]) == (
        "Standalone suitability",
        "Checks the customer understood",
        True,
    )
    # no survey came into being: the list of surveys and the workspace's count are exactly what they were
    assert author.get("/api/v1/survey-definitions").json()["items"] == surveys_before
    assert (
        author.get("/api/v1/survey-definitions/workspace").json()["inventory"]["surveys"]["total"] == workspace_before
    )
    db.rollback()
    row = db.execute(text("SELECT artifact_kind, code FROM survey_definition WHERE id = :i"), {"i": m["id"]}).one()
    assert tuple(row) == ("MODULE", m["code"])
    assert (
        db.execute(text("SELECT kind FROM survey_issued_code WHERE code = :c"), {"c": m["code"]}).scalar_one()
        == "MODULE"
    )
    # its draft is the existing draft-documents read, by the module's id: one empty revision in the fixed frame
    d = draft(author, m["id"])
    doc = next(a for a in d["assets"] if a["kind"] == "MODULE")
    assert (doc["code"], doc["version"], doc["state"], doc["owned"]) == (m["code"], 1, "DRAFT", True)
    assert d["content"] == frame(m["code"], doc["document"]) and doc["document"]["nodes"] == []
    assert (
        m["id"] in {x["id"] for x in author.get(M).json()["items"]}
        and author.get(f"{M}/{m['id']}").json()["code"] == m["code"]
    )
    assert (
        db.execute(
            text("SELECT count(*) FROM audit_event WHERE action = 'SURVEY.MODULE_CREATED' AND entity_id = :i"),
            {"i": m["id"]},
        ).scalar_one()
        == 1
    )
    # a survey is not a module
    sid, _ = empty_survey(author)
    assert author.get(f"{M}/{sid}").status_code == 404
    assert post(author, M, {"name": "ab"}).status_code == 422


# ------------------------------------------------------------------------- 2–6 · contents, the frame, save and reopen
def test_questions_branches_and_conditions_are_saved_and_the_frame_cannot_be_bent(trio: Any, db: Session) -> None:
    author = trio[0]
    m = create(author, "Multi-select follow-ups")
    doc = fill(author, m, "F4")  # yes/no and multi-select, ordered follow-ups, three different endings
    got = author.get(f"{M}/{m['id']}").json()
    assert (
        got["facts"]["questions"] == 4
        and got["facts"]["branching"] is True
        and set(got["facts"]["outcomes"]) == set(doc["outcomes"])
    )
    assert got["draft_revision"] == 1 and got["name"] == "Multi-select follow-ups"
    # reopened: exactly what was saved, with the server's hashes
    d = draft(author, m["id"])
    assert next(a["document"] for a in d["assets"] if a["kind"] == "MODULE") == doc
    assert post(author, f"/api/v1/survey-definitions/{m['id']}/draft/validate").json()["blockers"] == 0

    single = create(author, "Single choice routes")
    fill(author, single, "F3")  # single choice with a different next question per answer
    cond = create(author, "Condition inside")
    cdoc = fill(author, cond, "G5")  # a reusable condition deciding a branch
    assert (
        any(n["type"] == "DECISION" for n in cdoc["nodes"])
        and author.get(f"{M}/{cond['id']}").json()["facts"]["decisions"] == 1
    )

    # the frame holds exactly one revision of the module's own module, and nothing an author chose
    d = draft(author, m["id"])
    good = d["content"]
    inst = good["sequence"][0]
    other = draft(author, single["id"])["content"]["sequence"][0]
    for bad in (
        {**good, "sequence": []},
        {**good, "sequence": [inst, {**inst, "instance": "again"}]},
        {**good, "sequence": [{**inst, "routes": {**inst["routes"], "COMPLETED": "@CONTINUE"}}]},
        {**good, "sequence": [{**inst, "module": other["module"]}]},  # another standalone module's draft
        {**good, "sequence": [{**inst, "if_skipped_in_sequence": "@CONTINUE"}]},
    ):
        r = save(author, m["id"], d["revision"], [{"op": "SET_CONTENT", "content": bad}])
        assert r.status_code == 422 and r.json()["code"] in ("MODULE_FRAME_INVALID", "REFERENCE_NOT_PUBLISHED"), r.text
    assert draft(author, m["id"])["revision"] == d["revision"]  # nothing was saved

    # renaming the module in its document renames the module
    renamed = {**doc, "name": "Renamed module", "authoring": {"intent": "A new description"}}
    assert (
        save(author, m["id"], d["revision"], [{"op": "PUT_ASSET", "kind": "MODULE", "document": renamed}]).status_code
        == 200
    )
    got = author.get(f"{M}/{m['id']}").json()
    assert (got["name"], got["description"]) == ("Renamed module", "A new description")
    # a stale save is refused, as for a survey
    assert (
        save(author, m["id"], d["revision"], [{"op": "PUT_ASSET", "kind": "MODULE", "document": doc}]).status_code
        == 409
    )


# ------------------------------------------------------------------------------------ 7–8 · the Python engine, no record
def test_a_draft_module_is_tested_by_the_engine_and_nothing_is_recorded(trio: Any, db: Session) -> None:
    author = trio[0]
    m = create(author, "Tested module")
    empty = run_test(author, module_id=m["id"]).json()
    assert (empty["testable"], empty["status"], empty["run"]) == (False, "NOT_TESTABLE", None) and empty["findings"]
    fill(author, m, "F3")
    before = counts(db, (*OPERATIONAL, "survey_candidate", "survey_version", "audit_event", "survey_definition"))

    start = run_test(author, module_id=m["id"]).json()
    assert start["record_class"] == "MODULE_TEST" and start["testable"] and start["status"] == "PENDING"
    assert (start["module"]["source"], start["module"]["state"], start["module"]["published"]) == (
        "WORKING_DRAFT",
        "DRAFT",
        False,
    )
    first = start["run"]["pending"]
    assert first["answer_type"] == "SINGLE_SELECT" and first["text"] and len(first["options"]) >= 2
    assert {e["kind"] for e in start["manifest"]} >= {"MODULE", "ITEM", "WORDING", "OPTION_SET"}

    # two different answers lead to two different next questions
    nexts = {}
    for o in first["options"]:
        r = run_test(author, module_id=m["id"], inputs=[{"key": first["key"], "answer": {"choice": o["code"]}}]).json()
        assert r["inputs"][0]["accepted"] is True
        nexts[o["code"]] = (r["run"]["pending"] or {}).get("key") or r["run"]["terminal"]["survey_outcome"]
    assert len(set(nexts.values())) > 1, nexts

    # an invalid response is refused with a stable code, and the same question stays current
    bad = run_test(
        author, module_id=m["id"], inputs=[{"key": first["key"], "answer": {"choice": "NOT-AN-OPTION"}}]
    ).json()
    assert (
        bad["inputs"][0]["accepted"] is False
        and bad["inputs"][0]["rejection_code"]
        and bad["run"]["pending"]["key"] == first["key"]
    )
    assert bad["run"]["rejections"]

    # to the end, then the same inputs again: the same run, the same fingerprint
    inputs: list[dict[str, Any]] = []
    r = start
    while r["status"] == "PENDING" and len(inputs) < 20:
        p = r["run"]["pending"]
        answer = {"choice": p["options"][0]["code"]} if p["options"] else {"text": "synthetic"}
        inputs.append({"key": p["key"], "answer": answer})
        r = run_test(author, module_id=m["id"], inputs=inputs).json()
    assert r["status"] == "TERMINAL" and r["run"]["terminal"]["survey_outcome"] in r["frame"]["sequence"][0]["routes"]
    again = run_test(author, module_id=m["id"], inputs=inputs).json()
    assert again["run_sha256"] == r["run_sha256"] and again["run"] == r["run"]
    # an answer for a question that is not current is refused
    assert run_test(author, module_id=m["id"], inputs=[{"key": "module/nope", "answer": {}}]).status_code == 409
    assert run_test(author, module_id=m["id"], facts={"no.such.field": 1}).status_code == 422
    assert (
        counts(db, tuple(before)) == before
    )  # not a row anywhere: no simulation, no plan, no audit, nothing operational

    # running the engine is its own permission, as for a simulation
    reader = make_account(db, prefix="mreader")
    GRANTS[reader.principal_id] = frozenset({"survey.read", "survey.edit"})
    c = _client(trio[0].app, reader)
    assert run_test(c, module_id=m["id"]).status_code == 403
    c.__exit__(None, None, None)
    GRANTS.pop(reader.principal_id, None)


def test_a_condition_reads_synthetic_facts_in_a_module_test(trio: Any) -> None:
    author = trio[0]
    m = create(author, "Condition module")
    fill(author, m, "G5")
    r = run_test(author, module_id=m["id"]).json()
    assert r["testable"], r["findings"]
    assert isinstance(r["requires"]["fields"], list) and set(r["fields"]) == set(r["requires"]["fields"])


# ------------------------------------------------------------------------ 9–10 · three people, and who is refused
def test_a_module_is_published_by_three_different_people_and_nobody_else(trio: Any, db: Session) -> None:
    author, checker, publisher, people = trio
    m = create(author, "Governed module")
    assert submit(author, m["id"]).status_code == 422  # an empty module cannot be submitted
    fill(author, m, "F4")
    r = submit(author, m["id"], "first revision")
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    mine = author.get(f"{M}/{m['id']}").json()
    assert (mine["working_state"], mine["open_candidate"]["status"], mine["open_candidate"]["revision"]) == (
        "FROZEN",
        "IN_REVIEW",
        1,
    )
    # whose step it is, for each person: the author waits; the checker is asked to decide
    assert (
        mine["open_candidate"]["submitted_by_you"],
        mine["open_candidate"]["your_action"],
        mine["open_candidate"]["waiting_for"],
    ) == (True, None, "A_REVIEWER")
    assert checker.get(f"{M}/{m['id']}").json()["open_candidate"]["your_action"] == "DECIDE"
    # the maker can neither approve nor publish what they made
    r = post(author, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"})
    assert r.status_code == 403 and r.json()["code"] == "SELF_REVIEW_DENIED"
    assert post(publisher, f"/api/v1/survey-candidates/{cid}/publish").status_code == 409  # not approved yet
    assert post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    after = {c: c.get(f"{M}/{m['id']}").json()["open_candidate"] for c in (author, checker, publisher)}
    assert [after[c]["your_action"] for c in (author, checker, publisher)] == [None, None, "PUBLISH"]
    assert {a["waiting_for"] for a in after.values()} == {"A_PUBLISHER"}
    for who, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        r = post(who, f"/api/v1/survey-candidates/{cid}/publish")
        assert r.status_code == 403 and r.json()["code"] == code
    # a permission is needed as well: someone who made nothing, without `survey.publish`, is refused
    outsider = make_account(db, prefix="moutsider")
    GRANTS[outsider.principal_id] = frozenset({"survey.read"})
    c = _client(author.app, outsider)
    assert post(c, f"/api/v1/survey-candidates/{cid}/publish").status_code == 403
    assert post(c, M, {"name": "Not allowed"}).status_code == 403
    c.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id, None)
    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish")
    assert r.status_code == 201, r.text
    vid = r.json()["id"]
    done = author.get(f"{M}/{m['id']}").json()
    assert (
        done["open_candidate"] is None
        and done["unpublished_changes"] is False
        and done["latest_published_revision"] == 1
    )
    assert [(p["revision"], p["version_label"], p["status"]) for p in done["published"]] == [(1, "1.0", "PUBLISHED")]
    # the governance record is the existing one: history, version, immutable candidate
    h = author.get(f"/api/v1/survey-definitions/{m['id']}/history").json()
    assert [c["status"] for c in h["candidates"]] == ["PUBLISHED"] and [v["label"] for v in h["versions"]] == ["1.0"]
    assert author.get(f"/api/v1/survey-versions/{vid}").json()["status"] == "PUBLISHED"
    db.rollback()
    actors = db.execute(
        text("SELECT event, actor_ref FROM survey_lifecycle_event WHERE subject_id = :c ORDER BY seq"), {"c": cid}
    ).all()
    assert [e for e, _ in actors] == ["SUBMITTED", "APPROVED", "PUBLISHED"] and len({a for _, a in actors}) == 3
    # published is frozen: the revision cannot be changed in place
    d = draft(author, m["id"])
    doc = next(a for a in d["assets"] if a["kind"] == "MODULE")
    assert doc["state"] == "FROZEN"
    r = save(
        author,
        m["id"],
        d["revision"],
        [{"op": "PUT_ASSET", "kind": "MODULE", "document": {**doc["document"], "name": "Changed in place"}}],
    )
    assert r.status_code == 409 and r.json()["code"] == "ASSET_FROZEN"


# ---------------------------------------------------- 11–16 · in the library, reused, pinned, superseded without effect
def test_a_published_module_is_reused_by_two_surveys_and_a_newer_revision_changes_neither(
    trio: Any, db: Session
) -> None:
    author, checker, publisher, people = trio
    m = create(author, "Reusable module")
    doc = fill(author, m, "F4")
    assert m["code"] not in {c["code"] for c in lib(author, "MODULE")}  # a draft is not in the library
    assert author.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").status_code == 404
    publish(trio, m["id"])

    card = next(c for c in lib(author, "MODULE") if c["code"] == m["code"])
    assert (card["version"], card["is_latest"], card["title"]) == (1, True, "Reusable module")
    assert card["origin"] == {
        "definition_id": m["id"],
        "code": m["code"],
        "name": "Reusable module",
        "artifact_kind": "MODULE",
    }
    assert [(s["artifact_kind"], s["version_label"]) for s in card["published_in"]] == [("MODULE", "1.0")]
    assert card["used_by"] == {"surveys": 0, "versions": 0}  # its own publication is not a survey that uses it
    detail = author.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").json()
    assert (
        detail["document"] == doc
        and detail["missing_dependencies"] == []
        and detail["origin"]["artifact_kind"] == "MODULE"
    )
    # what it places is in the library too, each owned by the module
    placed = {n["item"]["code"] for n in doc["nodes"] if n.get("item")}
    assert placed <= {c["code"] for c in lib(author, "ITEM")}

    # two different surveys pin the exact published revision
    pins = {}
    for name in ("Consumer one", "Consumer two"):
        sid, code = empty_survey(author, name)
        r = place(author, sid, m["code"], 1, doc["outcomes"])
        assert r.status_code == 200, r.text
        _, vid = publish_survey(trio, sid)
        v = author.get(f"/api/v1/survey-versions/{vid}/content").json()
        entry = next(e for e in v["manifest"] if e["kind"] == "MODULE")
        assert (entry["code"], entry["version"], entry["sha256"]) == (m["code"], 1, detail["sha256"])
        pins[sid] = (vid, v["content_sha256"], v["manifest_sha256"])
    card = next(c for c in lib(author, "MODULE") if c["code"] == m["code"])
    assert card["used_by"] == {"surveys": 2, "versions": 2}
    # a published survey that pins it is simulated by the existing simulator
    any_vid = next(iter(pins.values()))[0]
    r = post(author, f"/api/v1/survey-versions/{any_vid}/simulations", {"facts": {}, "label": "reuse"})
    assert r.status_code == 201 and r.json()["run"]["pending"]["instance"] == "mi-reused"

    # a newer revision of the module, through the same three people
    two = {**copy.deepcopy(doc), "revision": 2, "name": "Reusable module (second)"}
    d = draft(author, m["id"])
    r = save(
        author,
        m["id"],
        d["revision"],
        [
            {"op": "PUT_ASSET", "kind": "MODULE", "document": two},
            {"op": "SET_CONTENT", "content": frame(m["code"], two)},
        ],
    )
    assert r.status_code == 200, r.text
    assert author.get(f"{M}/{m['id']}").json()["unpublished_changes"] is True
    publish(trio, m["id"], "second revision")
    after = author.get(f"{M}/{m['id']}").json()
    assert [(p["revision"], p["status"]) for p in after["published"]] == [
        (1, "SUPERSEDED"),
        (2, "PUBLISHED"),
    ] and after["latest_published_revision"] == 2
    # neither survey changed: the same version, the same content and manifest fingerprints, still revision 1
    for sid, (vid, content_sha, manifest_sha) in pins.items():
        v = author.get(f"/api/v1/survey-versions/{vid}/content").json()
        assert (v["content_sha256"], v["manifest_sha256"]) == (content_sha, manifest_sha)
        assert next(e for e in v["manifest"] if e["kind"] == "MODULE")["version"] == 1
        assert draft(author, sid)["content"]["sequence"][0]["module"]["revision"] == 1
        info = [
            f
            for f in post(author, f"/api/v1/survey-definitions/{sid}/draft/validate").json()["findings"]
            if f["code"] == "NEWER_REVISION_PUBLISHED"
        ]
        assert info and all(f["severity"] == "INFO" for f in info)  # told, never upgraded, never blocked
    # both revisions stay in the library, each exactly as published
    revs = {c["version"]: c for c in lib(author, "MODULE") if c["code"] == m["code"]}
    assert set(revs) == {1, 2} and revs[2]["is_latest"] and not revs[1]["is_latest"]
    old = author.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").json()
    assert (
        old["document"] == doc
        and old["sha256"] == detail["sha256"]
        and [r["version"] for r in old["revisions"]] == [1, 2]
    )
    # and either published revision can still be tested on its own
    for rev in (1, 2):
        r = run_test(author, code=m["code"], revision=rev).json()
        assert r["testable"] and (r["module"]["source"], r["module"]["revision"]) == ("PUBLISHED_REVISION", rev)


# ----------------------------------------------------------------------------- 17 · markets and permissions
def test_a_module_of_another_market_does_not_exist_for_the_reader(trio: Any, db: Session) -> None:
    author = trio[0]
    m = create(author, "Singapore module")
    fill(author, m, "F3")
    publish(trio, m["id"])
    elsewhere = make_account(db, prefix="melsewhere")
    GRANTS[elsewhere.principal_id] = EVERYTHING
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    c = _client(author.app, elsewhere)
    try:
        assert c.get(M).json()["items"] == [] and c.get(f"{M}/{m['id']}").status_code == 404
        assert c.get(f"/api/v1/survey-definitions/{m['id']}/draft/documents").status_code == 404
        assert (
            run_test(c, module_id=m["id"]).status_code == 404
            and run_test(c, code=m["code"], revision=1).status_code == 404
        )
        assert m["code"] not in {x["code"] for x in lib(c, "MODULE")}
        assert (
            post(c, M, {"name": "Elsewhere module"}).status_code == 403
        )  # creation is for the market it is created in
    finally:
        c.__exit__(None, None, None)
        GRANTS.pop(elsewhere.principal_id, None)
        MARKETS.pop(elsewhere.principal_id, None)
    stranger = make_account(db, prefix="mstranger")
    c = _client(author.app, stranger)
    assert c.get(M).status_code == 403 and c.get(f"{M}/{m['id']}").status_code == 403
    c.__exit__(None, None, None)


# ------------------------------------------------------------- 18 · modules written inside a survey are as they were
def test_modules_written_inside_a_survey_are_unchanged_and_can_be_tested_too(trio: Any) -> None:
    author = trio[0]
    sid, s_code, renames = build(author, "K7", "Survey with its own modules")
    publish_survey(trio, sid)
    mine = [c for c in lib(author, "MODULE") if c["code"] in renames.values()]
    assert len(mine) == 2 and all(
        c["origin"]["artifact_kind"] == "SURVEY" and c["origin"]["code"] == s_code for c in mine
    )
    assert all(
        [s["artifact_kind"] for s in c["published_in"]] == ["SURVEY"] and c["used_by"] == {"surveys": 1, "versions": 1}
        for c in mine
    )
    assert not {x["code"] for x in author.get(M).json()["items"]} & set(renames.values())  # not standalone modules
    r = run_test(author, code=mine[0]["code"], revision=1).json()
    assert r["testable"] and r["module"]["source"] == "PUBLISHED_REVISION" and r["status"] in ("PENDING", "TERMINAL")
    # a standalone module cannot add a revision to a survey's module, nor the reverse
    m = create(author, "Other lineage")
    d = draft(author, m["id"])
    foreign = author.get(f"/api/v1/survey-components/MODULE/{mine[0]['code']}/1").json()["document"]
    r = save(
        author, m["id"], d["revision"], [{"op": "PUT_ASSET", "kind": "MODULE", "document": {**foreign, "revision": 2}}]
    )
    assert r.status_code == 409 and r.json()["code"] == "CODE_OWNED_ELSEWHERE"


# -------------------------------------------------- 19 · never a survey: nothing operational, by application and database
def test_a_standalone_module_is_never_simulated_planned_or_assigned_as_a_survey(trio: Any, db: Session) -> None:
    author = trio[0]
    before = counts(db, OPERATIONAL)
    m = create(author, "Not a survey")
    fill(author, m, "F3")
    _, vid = publish(trio, m["id"])
    assert post(author, f"/api/v1/survey-versions/{vid}/simulations", {"facts": {}, "label": "x"}).status_code == 404
    assert post(author, f"/api/v1/survey-versions/{vid}/call-plans", {"facts": {}}).status_code == 404
    assert counts(db, OPERATIONAL) == before
    # and the database refuses it whatever the application does
    row = db.execute(
        text(
            "SELECT c.content_sha256, c.manifest_sha256 FROM survey_version v JOIN survey_candidate c ON c.id = v.candidate_id WHERE v.id = :v"
        ),
        {"v": vid},
    ).one()
    with pytest.raises(DBAPIError, match="a standalone module is not a survey"):
        db.execute(
            text(
                "INSERT INTO survey_simulation (id, survey_version_id, survey_definition_id, content_sha256, manifest_sha256, facts, "
                "facts_sha256, engine_contract, initial_run_sha256, label, created_by) VALUES (gen_random_uuid(), :v, :d, :c, :m, "
                "'{}'::jsonb, :c, 'x', :c, 'x', 'test')"
            ),
            {"v": vid, "d": m["id"], "c": row[0], "m": row[1]},
        )
    db.rollback()
    with pytest.raises(DBAPIError, match="the kind of a definition never changes"):
        db.execute(text("UPDATE survey_definition SET artifact_kind = 'SURVEY' WHERE id = :i"), {"i": m["id"]})
    db.rollback()


# ------------------------------------------------------------------------------------------- the setting and migration
def test_with_the_setting_off_no_module_route_exists(settings: Settings, db: Session) -> None:
    app = with_grants(
        create_app(
            settings.model_copy(
                update={
                    "survey_definitions_enabled": True,
                    "survey_library_enabled": True,
                    "transcription_worker": False,
                }
            )
        )
    )
    person = make_account(db, prefix="moff")
    GRANTS[person.principal_id] = EVERYTHING
    c = _client(app, person)
    try:
        assert (
            c.get(M).status_code == 404
            and post(c, M, {"name": "Off module"}).status_code == 404
            and post(c, T, {}).status_code == 404
        )
        assert c.get("/api/v1/survey-definitions").status_code == 200
    finally:
        c.__exit__(None, None, None)
        GRANTS.pop(person.principal_id, None)
    # the module setting alone is not on: it needs the library
    alone = create_app(
        settings.model_copy(
            update={
                "survey_definitions_enabled": True,
                "survey_module_authoring_enabled": True,
                "transcription_worker": False,
            }
        )
    )
    assert not [r for r in alone.routes if getattr(r, "path", "").startswith(M)]


def test_zz_migration_0036_keeps_every_fingerprint_and_refuses_to_lose_a_standalone_module(
    fresh_schema: None, engine: Engine, settings: Settings, survey_app: Any, db: Session
) -> None:
    """On a POPULATED schema: down and up again changes no governed row; with a standalone module the downgrade is
    refused and nothing is lost."""
    people = tuple(make_account(db, prefix=p) for p in ("zauthor", "zchecker", "zpublisher"))
    for p in people:
        GRANTS[p.principal_id] = EVERYTHING
    clients = tuple(_client(survey_app, p) for p in people)
    try:
        sid, _, _ = build(clients[0], "K8", "Populated before the migration")
        publish_survey(clients, sid)

        def governed() -> list[tuple[Any, ...]]:
            with engine.connect() as c:
                return [
                    tuple(r)
                    for sql in (
                        "SELECT kind, code, version, state, sha256, md5(content::text) FROM call360_test.survey_asset_version ORDER BY 1,2,3",
                        "SELECT id::text, content_sha256, manifest_sha256, md5(manifest::text) FROM call360_test.survey_candidate ORDER BY 1",
                        "SELECT id::text, version_no, label, candidate_id::text FROM call360_test.survey_version ORDER BY 1",
                        "SELECT seq, event, actor_ref, subject_id::text FROM call360_test.survey_lifecycle_event ORDER BY 1",
                        "SELECT id::text, code, name, market_code FROM call360_test.survey_definition ORDER BY 1",
                    )
                    for r in c.execute(text(sql))
                ]

        def head() -> str:
            with engine.connect() as c:
                return str(c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one())

        before = governed()
        assert head() == MIGRATION_HEAD
        migrate(settings, "0035_survey_execution_assurance", down=True)
        assert head() == "0035_survey_execution_assurance" and governed() == before
        # on the earlier schema every definition reads as a survey, and the survey API works as before
        assert sid in {x["id"] for x in clients[0].get("/api/v1/survey-definitions").json()["items"]}
        assert lib(clients[0], "MODULE")
        migrate(settings, "head")
        assert head() == MIGRATION_HEAD and governed() == before
        with engine.connect() as c:
            assert set(
                c.execute(text("SELECT DISTINCT artifact_kind FROM call360_test.survey_definition")).scalars()
            ) == {"SURVEY"}
        m = create(clients[0], "Kept by the downgrade")
        fill(clients[0], m, "F3")
        publish(clients, m["id"])
        kept = governed()
        with pytest.raises(RuntimeError, match="standalone modules exist"):
            migrate(settings, "0035_survey_execution_assurance", down=True)
        # 0037 (SHARED-1, no survey-only rule here) rolled back first; 0036 then refused and kept the module
        assert head() == "0036_survey_module_authoring" and governed() == kept
        migrate(settings, "head")
        assert head() == MIGRATION_HEAD and governed() == kept
    finally:
        for c in clients:
            c.__exit__(None, None, None)
        for p in people:
            GRANTS.pop(p.principal_id, None)
