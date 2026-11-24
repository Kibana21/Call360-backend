# ruff: noqa: E501, E731, F811 — long request literals; small lambdas; fixtures imported from test_survey_api
"""LIB-1 — the reusable component library, on the isolated test database, with BOTH settings on.

Discovery only of what a PUBLISHED version pins (LIB-D-1) · pinning an exact immutable revision across surveys ·
newer revisions are information only (LIB-D-5) · copy-on-write under a code of the survey's own · server-issued codes,
concurrency-safe (LIB-D-3) · makers are not inherited (LIB-D-4) · a draft can never reference another survey's
unpublished asset, whatever client asks.

Every survey here is built the way the editor builds one with the library on: under codes the server issued."""

from __future__ import annotations

import copy
import json
import re
import threading
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.settings import Settings
from app.domain.survey import store
from app.main import MIGRATION_HEAD, acceptable_migration_heads, create_app
from tests.support import APPLICABILITY_TABLES, make_account, migrate
from tests.survey_support import MARKETS as SG
from tests.survey_support import actor_of, fixture_bundle, new_code, operations_for
from tests.test_survey_api import ALL, GRANTS, MARKETS, _client, post, submit, trio, with_grants  # noqa: F401
from tests.test_survey_fi1 import save, state

KIND_OF_OP = {"OPTION_SET": "OPTION_SET", "ITEM": "ITEM", "CONDITION": "CONDITION", "MODULE": "MODULE"}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    """The application with the survey definitions AND the library on."""
    app = create_app(
        settings.model_copy(
            update={"survey_definitions_enabled": True, "survey_library_enabled": True, "transcription_worker": False}
        )
    )
    with_grants(app)
    return app


def issue(c: TestClient, sid: str, **counts: int) -> dict[str, list[str]]:
    r = post(
        c,
        f"/api/v1/survey-definitions/{sid}/codes",
        {"requests": [{"kind": k, "count": n} for k, n in counts.items() if n]},
    )
    assert r.status_code == 201, r.text
    out: dict[str, list[str]] = {}
    for x in r.json()["codes"]:
        out.setdefault(x["kind"], []).append(x["code"])
    return out


def build(c: TestClient, prefix: str, name: str = "") -> tuple[str, str, dict[str, str]]:
    """A survey holding a golden fixture, saved in ONE save, under SERVER-ISSUED codes. Returns id, survey code and the
    map from the fixture's codes to the issued ones."""
    code = new_code()
    r = post(
        c, "/api/v1/survey-definitions", {"code": code, "name": name or f"Library test {code}", "purpose": "synthetic"}
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    b = fixture_bundle(prefix)
    old = {
        "OPTION_SET": [k[0] for k in b.option_sets],
        "ITEM": sorted({k[0] for k in b.items}),
        "CONDITION": sorted({k[0] for k in b.conditions}),
        "MODULE": sorted({k[0] for k in b.modules}),
    }
    got = issue(c, sid, **{k: len(v) for k, v in old.items()})
    renames = {o: n for k in old for o, n in zip(old[k], got.get(k, []), strict=True)}
    ops_text = json.dumps(operations_for(b, code))
    for o, n in renames.items():  # a code is always a whole JSON string
        ops_text = ops_text.replace(json.dumps(o), json.dumps(n))
    ops = json.loads(ops_text)
    for op in ops:
        # K8 is the only clean fixture with conditions, apart from one wording that speaks a customer field — which no
        # field is allowlisted for (default-deny), so it could not be published. The variable is replaced by plain words.
        if op.get("kind") == "WORDING":
            op["document"]["text"] = re.sub(r"\{\{[^}]*\}\}", "the stated amount", op["document"]["text"])
    r = save(c, sid, 0, ops)
    assert r.status_code == 200, r.text
    return sid, code, renames


def publish(people: Any, sid: str, note: str = "") -> tuple[str, str]:
    """Author submits, checker approves, publisher publishes. Returns candidate id and version id."""
    author, checker, publisher = people[0], people[1], people[2]
    r = submit(author, sid, note)
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish")
    assert r.status_code == 201, r.text
    return cid, r.json()["id"]


def lib(c: TestClient, kind: str, q: str = "") -> list[dict[str, Any]]:
    r = c.get("/api/v1/survey-components", params={"kind": kind, "q": q})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def draft(c: TestClient, sid: str) -> dict[str, Any]:
    return c.get(f"/api/v1/survey-definitions/{sid}/draft/documents").json()


def asset(d: dict[str, Any], kind: str, code: str | None = None) -> dict[str, Any]:
    return next(a for a in d["assets"] if a["kind"] == kind and (code is None or a["code"] == code))


def empty_survey(c: TestClient, name: str = "") -> tuple[str, str]:
    code = new_code()
    r = post(
        c, "/api/v1/survey-definitions", {"code": code, "name": name or f"Consumer {code}", "purpose": "synthetic"}
    )
    return r.json()["id"], code


@pytest.fixture()
def second(survey_app: Any, db: Session) -> Any:
    """Another author, who made nothing of survey A."""
    person = make_account(db, prefix="second")
    GRANTS[person.principal_id] = frozenset({"survey.read", "survey.edit"})
    c = _client(survey_app, person)
    yield c, person
    c.__exit__(None, None, None)
    GRANTS.pop(person.principal_id, None)


# ------------------------------------------------------------------------------------------------ discovery (LIB-D-1)
def test_only_what_a_published_version_pins_is_in_the_library(trio: Any) -> None:
    author = trio[0]
    a_sid, a_code, a_map = build(author, "K8", "Source survey A")
    drafted, _, d_map = build(author, "K1", "Never submitted")
    in_review, _, r_map = build(author, "K7", "Submitted, not published")
    assert submit(author, in_review).status_code == 201
    rejected, _, x_map = build(author, "K3", "Sent back")
    cid = submit(author, rejected).json()["id"]
    assert (
        post(trio[1], f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "REJECT", "comment": "no"}).status_code
        == 200
    )

    def codes(kind: str) -> set[str]:
        return {c["code"] for c in lib(author, kind)}

    mine = set(a_map.values()) | set(d_map.values()) | set(r_map.values()) | set(x_map.values())
    assert (
        not (codes("MODULE") | codes("ITEM") | codes("CONDITION") | codes("OPTION_SET")) & mine
    )  # nothing published yet

    publish(trio, a_sid)
    for kind in ("MODULE", "ITEM", "CONDITION", "OPTION_SET"):
        got = codes(kind) & mine
        assert got and got <= set(a_map.values()), kind  # A's components, and nobody else's
    m = next(c for c in lib(author, "MODULE") if c["code"] in a_map.values())
    assert (m["version"], m["is_latest"], m["latest_published_version"], m["wording_version"]) == (1, True, 1, None)
    assert [
        (s["survey_code"], s["survey_name"], s["version_label"], s["version_status"]) for s in m["published_in"]
    ] == [(a_code, "Source survey A", "1.0", "PUBLISHED")]
    assert m["used_by"] == {"surveys": 1, "versions": 1}
    assert m["title"] and m["category"] == "COMMON" and m["facts"]["outcomes"]
    q = next(c for c in lib(author, "ITEM") if c["code"] in a_map.values())
    assert (
        q["wording_version"] == 1
        and q["title"]
        and q["facts"]["answer_type"]
        and q["facts"]["delivery_mode"] == "CONTROLLED_TTS"
    )
    cond = next(c for c in lib(author, "CONDITION") if c["code"] in a_map.values())
    assert cond["facts"]["fields"] and isinstance(cond["facts"]["params"], dict)
    # search: by title, by the publishing survey's name, and nothing for nonsense
    assert m["code"] in {c["code"] for c in lib(author, "MODULE", m["title"][:6].lower())}
    assert m["code"] in {c["code"] for c in lib(author, "MODULE", "source survey")}
    assert lib(author, "MODULE", "zzzz-no-such-thing") == []
    assert author.get("/api/v1/survey-components", params={"kind": "WORDING"}).status_code == 422


def test_a_component_is_previewed_complete_or_not_at_all(trio: Any) -> None:
    author = trio[0]
    a_sid, _, a_map = build(author, "K8")
    unpublished, _, u_map = build(author, "K7")
    publish(trio, a_sid)
    m = next(c for c in lib(author, "MODULE") if c["code"] in a_map.values())
    d = author.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").json()
    assert d["document"]["code"] == m["code"] and d["sha256"] == m["sha256"] and d["missing_dependencies"] == []
    kinds = {x["kind"] for x in d["dependencies"]}
    assert {"ITEM", "WORDING"} <= kinds
    placed = [n["item"] for n in d["document"]["nodes"] if n.get("item")]
    have = {(x["kind"], x["code"], x["version"]) for x in d["dependencies"]}
    for ref in placed:  # every question the module places comes with its item and the exact wording it pins
        assert ("ITEM", ref["code"], ref["version"]) in have and (
            "WORDING",
            ref["code"],
            ref["wording_version"],
        ) in have
    assert [r["version"] for r in d["revisions"]] == [1] and d["derived_from"] is None
    q = next(c for c in lib(author, "ITEM") if c["code"] in a_map.values() and c["facts"]["option_set"])
    qd = author.get(
        f"/api/v1/survey-components/ITEM/{q['code']}/{q['version']}", params={"wording_version": q["wording_version"]}
    ).json()
    assert {x["kind"] for x in qd["dependencies"]} == {"WORDING", "OPTION_SET"}
    assert (
        author.get(
            f"/api/v1/survey-components/ITEM/{q['code']}/{q['version']}", params={"wording_version": 99}
        ).status_code
        == 404
    )
    # an unpublished component does not exist in the library, even by its exact address
    um = next(v for k, v in u_map.items() if k.startswith("M-"))
    assert author.get(f"/api/v1/survey-components/MODULE/{um}/1").status_code == 404
    assert author.get("/api/v1/survey-components/MODULE/M-NO-SUCH/1").status_code == 404


# ------------------------------------------------------------------------- pinning across surveys; makers (LIB-D-4)
def pin_module(c: TestClient, consumer: str, source: dict[str, Any], instance: str = "mi-shared") -> Any:
    """Survey B's content pins the first module instance of the source survey exactly as published."""
    inst = source["content"]["sequence"][0]
    d = draft(c, consumer)
    content = {
        **d["content"],
        "sequence": [
            *d["content"]["sequence"],
            {
                "instance": instance,
                "module": inst["module"],
                "routes": {k: {"survey_outcome": k} if k != "COMPLETED" else "@CONTINUE" for k in inst["routes"]},
            },
        ],
    }
    return save(c, consumer, d["revision"], [{"op": "SET_CONTENT", "content": content}])


def test_another_survey_pins_the_exact_published_revision_and_inherits_no_maker(
    trio: Any, second: Any, db: Session
) -> None:
    author, checker, publisher, people = trio
    other, other_person = second
    a_sid, _, _ = build(author, "K7", "Source survey A")
    a_cid, _ = publish(trio, a_sid)
    a = draft(author, a_sid)
    a_module = asset(a, "MODULE", a["content"]["sequence"][0]["module"]["code"])
    a_rows = [
        tuple(r)
        for r in db.execute(
            text(
                "SELECT kind, code, version, state, sha256 FROM survey_asset_version WHERE owner_definition_id = :s ORDER BY 1,2,3"
            ),
            {"s": a_sid},
        )
    ]

    b_sid, _ = empty_survey(other, "Consumer survey B")
    r = pin_module(other, b_sid, a)
    assert r.status_code == 200, r.text
    b = r.json()
    pinned = asset(b, "MODULE", a_module["code"])
    # the SAME immutable revision: same code, same version, same server fingerprint; pinned, not copied, not owned
    assert (pinned["version"], pinned["sha256"], pinned["state"], pinned["owned"]) == (
        a_module["version"],
        a_module["sha256"],
        "FROZEN",
        False,
    )
    assert all(
        not x["owned"] and x["state"] == "FROZEN" for x in b["assets"]
    )  # its questions, wording and answers came with it
    assert {(x["kind"], x["code"], x["version"], x["sha256"]) for x in b["assets"]} <= {
        (x["kind"], x["code"], x["version"], x["sha256"]) for x in a["assets"]
    }
    assert post(other, f"/api/v1/survey-definitions/{b_sid}/draft/validate").json()["blockers"] == 0
    # changing the shared revision from B is impossible: neither in place, nor by adding a revision to A's code
    changed = {**pinned["document"], "name": "Changed from survey B"}
    assert (
        save(other, b_sid, b["revision"], [{"op": "PUT_ASSET", "kind": "MODULE", "document": changed}]).json()["code"]
        == "ASSET_FROZEN"
    )
    r = save(
        other,
        b_sid,
        b["revision"],
        [{"op": "PUT_ASSET", "kind": "MODULE", "document": {**changed, "revision": pinned["version"] + 1}}],
    )
    assert (r.status_code, r.json()["code"]) == (409, "CODE_OWNED_ELSEWHERE")

    b_cid = submit(other, b_sid, "reuses A's module").json()["id"]
    bc = other.get(f"/api/v1/survey-candidates/{b_cid}/documents").json()
    ac = author.get(f"/api/v1/survey-candidates/{a_cid}/documents").json()
    # makers: the person who placed the published module — and nobody who made survey A
    assert [m["ref"] for m in bc["makers"]] == [str(other_person.principal_id)]
    assert not {m["ref"] for m in bc["makers"]} & {m["ref"] for m in ac["makers"]}
    assert bc["manifest_intact"] is True
    b_entry = next(x for x in bc["assets"] if x["kind"] == "MODULE")
    a_entry = next(x for x in ac["assets"] if x["kind"] == "MODULE" and x["code"] == a_module["code"])
    assert (b_entry["code"], b_entry["version"], b_entry["sha256"]) == (
        a_entry["code"],
        a_entry["version"],
        a_entry["sha256"],
    )  # both surveys reference the same source revision
    # A's author is NOT a maker of B, so (holding the permission) may review it; B's own author may not
    assert other.get(f"/api/v1/survey-candidates/{b_cid}/documents").json()["restrictions"]["is_maker"] is True
    assert author.get(f"/api/v1/survey-candidates/{b_cid}/documents").json()["restrictions"]["can_decide"] is True
    assert post(checker, f"/api/v1/survey-candidates/{b_cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert post(publisher, f"/api/v1/survey-candidates/{b_cid}/publish").status_code == 201
    # usage, from the derived index: two surveys, two published versions pin this exact revision
    m = next(c for c in lib(author, "MODULE") if c["code"] == a_module["code"])
    assert m["used_by"] == {"surveys": 2, "versions": 2} and len(m["published_in"]) == 2
    index = db.execute(
        text(
            "SELECT count(*) FROM survey_asset_usage WHERE kind = 'MODULE' AND code = :c AND version = :v AND subject_type = 'VERSION'"
        ),
        {"c": a_module["code"], "v": a_module["version"]},
    ).scalar_one()
    assert index == 2
    # and nothing of survey A was touched by any of it
    db.rollback()
    assert [
        tuple(r)
        for r in db.execute(
            text(
                "SELECT kind, code, version, state, sha256 FROM survey_asset_version WHERE owner_definition_id = :s ORDER BY 1,2,3"
            ),
            {"s": a_sid},
        )
    ] == a_rows
    assert people


# ----------------------------------------------------------------------------- newer revisions are information only
def test_a_newer_published_revision_changes_nothing_for_the_consumer(trio: Any, second: Any) -> None:
    author, checker, publisher, _ = trio
    other, _ = second
    a_sid, _, _ = build(author, "K7")
    publish(trio, a_sid)
    a = draft(author, a_sid)
    b_sid, _ = empty_survey(other)
    assert pin_module(other, b_sid, a).status_code == 200
    waiting = submit(other, b_sid, "submitted before A's new revision").json()["id"]
    b_before = draft(other, b_sid)
    cand_before = other.get(f"/api/v1/survey-candidates/{waiting}/documents").json()

    # survey A publishes revision 2 of the module (a reworded question)
    module = asset(a, "MODULE", a["content"]["sequence"][0]["module"]["code"])
    wording = next(
        x
        for x in a["assets"]
        if x["kind"] == "WORDING"
        and any(n.get("item", {}).get("code") == x["code"] for n in module["document"]["nodes"])
    )
    w2 = {**wording["document"], "wording_version": 2, "text": "The reworded question of revision two?"}
    m2 = {
        **module["document"],
        "revision": 2,
        "nodes": [
            {**n, "item": {**n["item"], "wording_version": 2}}
            if n.get("item", {}).get("code") == wording["code"]
            else n
            for n in module["document"]["nodes"]
        ],
    }
    content = {
        **a["content"],
        "sequence": [
            {**i, "module": {**i["module"], "revision": 2}} if i["module"]["code"] == module["code"] else i
            for i in a["content"]["sequence"]
        ],
    }
    assert (
        save(
            author,
            a_sid,
            a["revision"],
            [
                {"op": "PUT_ASSET", "kind": "WORDING", "document": w2},
                {"op": "PUT_ASSET", "kind": "MODULE", "document": m2},
                {"op": "SET_CONTENT", "content": content},
            ],
        ).status_code
        == 200
    )
    publish(trio, a_sid, "revision two")

    # the library knows; survey B is exactly as it was — draft, candidate, pin
    rows = {c["version"]: c for c in lib(other, "MODULE") if c["code"] == module["code"]}
    assert (rows[1]["is_latest"], rows[1]["latest_published_version"], rows[2]["is_latest"]) == (False, 2, True)
    assert [
        r["version"] for r in other.get(f"/api/v1/survey-components/MODULE/{module['code']}/1").json()["revisions"]
    ] == [1, 2]
    assert draft(other, b_sid) == b_before
    now = other.get(f"/api/v1/survey-candidates/{waiting}/documents").json()
    assert (now["content"], now["assets"], now["manifest_intact"], now["status"]) == (
        cand_before["content"],
        cand_before["assets"],
        True,
        "IN_REVIEW",
    )
    # information only: not a blocker, not a warning to acknowledge
    v = post(other, f"/api/v1/survey-definitions/{b_sid}/draft/validate").json()
    info = [f for f in v["findings"] if f["code"] == "NEWER_REVISION_PUBLISHED"]
    assert (
        v["blockers"] == 0
        and len(info) == 1
        and info[0]["severity"] == "INFO"
        and info[0]["at"] == f"MODULE:{module['code']}@1"
    )
    assert (now["validation"]["blockers"], now["validation"]["warnings"]) == (0, 1)  # the candidate is not invalidated
    # and the candidate submitted before the new revision is still approved and published, on revision 1
    assert post(checker, f"/api/v1/survey-candidates/{waiting}/decision", {"verdict": "APPROVE"}).status_code == 200
    vid = post(publisher, f"/api/v1/survey-candidates/{waiting}/publish").json()["id"]
    pinned = next(
        e for e in other.get(f"/api/v1/survey-versions/{vid}/content").json()["manifest"] if e["kind"] == "MODULE"
    )
    assert (pinned["code"], pinned["version"]) == (module["code"], 1)


# -------------------------------------------------------------------------- copy-on-write, and who owns an identity
def test_a_local_copy_gets_its_own_server_issued_identity_and_leaves_the_source_alone(
    trio: Any, second: Any, db: Session
) -> None:
    author = trio[0]
    other, other_person = second
    a_sid, _, _ = build(author, "K7")
    publish(trio, a_sid)
    a = draft(author, a_sid)
    source = asset(a, "MODULE", a["content"]["sequence"][0]["module"]["code"])
    b_sid, _ = empty_survey(other)
    assert pin_module(other, b_sid, a).status_code == 200
    b = draft(other, b_sid)

    mine = issue(other, b_sid, MODULE=1)["MODULE"][0]
    assert mine != source["code"] and mine.startswith("M-") and mine[2:].isdigit()
    local = {
        **copy.deepcopy(source["document"]),
        "code": mine,
        "revision": 1,
        "name": "My edited copy",
        "authoring": {
            "derived_from": {"code": source["code"], "version": source["version"], "sha256": source["sha256"]}
        },
    }
    content = {
        **b["content"],
        "sequence": [{**i, "module": {"code": mine, "revision": 1}} for i in b["content"]["sequence"]],
    }
    r = save(
        other,
        b_sid,
        b["revision"],
        [{"op": "PUT_ASSET", "kind": "MODULE", "document": local}, {"op": "SET_CONTENT", "content": content}],
    )
    assert r.status_code == 200, r.text
    made = asset(r.json(), "MODULE", mine)
    assert (made["state"], made["owned"], made["document"]["authoring"]["derived_from"]["code"]) == (
        "DRAFT",
        True,
        source["code"],
    )
    # it still pins A's published questions; the source module is untouched and still frozen
    assert all(not x["owned"] for x in r.json()["assets"] if x["kind"] != "MODULE")
    again = asset(draft(author, a_sid), "MODULE", source["code"])
    assert (again["sha256"], again["state"], again["document"]) == (source["sha256"], "FROZEN", source["document"])
    # the copy is editable; and whoever edits it is its maker — nobody from survey A
    assert (
        save(
            other,
            b_sid,
            r.json()["revision"],
            [{"op": "PUT_ASSET", "kind": "MODULE", "document": {**local, "name": "Edited again"}}],
        ).status_code
        == 200
    )
    cid = submit(other, b_sid).json()["id"]
    assert [m["ref"] for m in other.get(f"/api/v1/survey-candidates/{cid}/documents").json()["makers"]] == [
        str(other_person.principal_id)
    ]
    issued = db.execute(
        text("SELECT kind, CAST(survey_definition_id AS text) FROM survey_issued_code WHERE code = :c"), {"c": mine}
    ).one()
    assert tuple(issued) == ("MODULE", b_sid)


def test_a_new_identity_must_be_one_the_server_issued_to_that_survey_for_that_kind(
    trio: Any, second: Any, db: Session
) -> None:
    author = trio[0]
    other, _ = second
    a_sid, _, a_map = build(author, "K7")
    a = draft(author, a_sid)
    module = asset(a, "MODULE")
    b_sid, _ = empty_survey(other)
    theirs = issue(author, a_sid, MODULE=1)["MODULE"][0]  # issued — to ANOTHER survey
    as_item = issue(other, b_sid, ITEM=1)["ITEM"][0]  # issued to this survey — for another KIND
    before = state(db, b_sid)
    doc = lambda code: {**module["document"], "code": code, "revision": 1}

    r = save(other, b_sid, 0, [{"op": "PUT_ASSET", "kind": "MODULE", "document": doc("M-INVENTED-BY-A-CLIENT")}])
    assert (r.status_code, r.json()["code"]) == (422, "CODE_NOT_ISSUED")
    assert (
        save(other, b_sid, 0, [{"op": "PUT_ASSET", "kind": "MODULE", "document": doc(theirs)}]).json()["code"]
        == "CODE_NOT_ISSUED"
    )
    assert (
        save(other, b_sid, 0, [{"op": "PUT_ASSET", "kind": "MODULE", "document": doc(as_item)}]).json()["code"]
        == "CODE_NOT_ISSUED"
    )
    r = post(
        other,
        f"/api/v1/survey-definitions/{b_sid}/draft/operations",
        {
            "expected_revision": 0,
            "operation": {"op": "PUT_ASSET", "kind": "MODULE", "document": doc("M-ALSO-INVENTED")},
        },
    )
    assert r.json()["code"] == "CODE_NOT_ISSUED"  # the single-operation endpoint is no way round
    assert state(db, b_sid) == before
    ok = issue(other, b_sid, MODULE=1, STATEMENT=1, CONDITION=1, OPTION_SET=1)
    assert (
        ok["STATEMENT"][0].startswith("S-")
        and ok["CONDITION"][0].startswith("C-")
        and ok["OPTION_SET"][0].startswith("OS-")
    )
    assert (
        save(other, b_sid, 0, [{"op": "PUT_ASSET", "kind": "MODULE", "document": doc(ok["MODULE"][0])}]).status_code
        == 200
    )
    # historical codes are untouched: A's existing assets keep theirs and A can still add versions to its own
    wording = asset(a, "WORDING")
    assert (
        save(
            author,
            a_sid,
            a["revision"],
            [
                {
                    "op": "PUT_ASSET",
                    "kind": "WORDING",
                    "document": {**wording["document"], "wording_version": 2, "text": "A second wording."},
                }
            ],
        ).status_code
        == 200
    )
    assert a_map


def test_a_draft_cannot_acquire_a_reference_to_another_surveys_unpublished_asset(
    trio: Any, second: Any, db: Session
) -> None:
    author, checker, _, _ = trio
    other, _ = second
    drafted, _, _ = build(author, "K7", "Only a draft")
    in_review, _, _ = build(author, "K1", "In review")
    assert submit(author, in_review).status_code == 201
    rejected, _, _ = build(author, "K3", "Rejected")
    cid = submit(author, rejected).json()["id"]
    assert (
        post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "REJECT", "comment": "no"}).status_code
        == 200
    )
    b_sid, _ = empty_survey(other)
    codes = issue(other, b_sid, MODULE=1)
    before = state(db, b_sid)
    for source_sid, why in (
        (drafted, "a draft"),
        (in_review, "frozen in a candidate, never published"),
        (rejected, "rejected"),
    ):
        r = pin_module(other, b_sid, draft(author, source_sid))
        assert (r.status_code, r.json()["code"]) == (422, "REFERENCE_NOT_PUBLISHED"), why
        assert "MODULE" in {d["kind"] for d in r.json()["details"]}, why
        single = post(
            other,
            f"/api/v1/survey-definitions/{b_sid}/draft/operations",
            {
                "expected_revision": 0,
                "operation": {
                    "op": "SET_CONTENT",
                    "content": {
                        **draft(other, b_sid)["content"],
                        "sequence": [
                            {
                                "instance": "mi-x",
                                "module": draft(author, source_sid)["content"]["sequence"][0]["module"],
                                "routes": {},
                            }
                        ],
                    },
                },
            },
        )
        assert single.json()["code"] == "REFERENCE_NOT_PUBLISHED", why
    # a module of B's own that places another survey's unpublished QUESTION is caught the same way
    foreign_item = asset(draft(author, drafted), "ITEM")
    mod = {
        "schema": "call360.survey.module/1",
        "code": codes["MODULE"][0],
        "revision": 1,
        "name": "Mine",
        "outcomes": ["COMPLETED"],
        "entry": "n1",
        "nodes": [
            {
                "node": "n1",
                "type": "QUESTION",
                "item": {"code": foreign_item["code"], "version": 1, "wording_version": 1},
                "routing": {"mode": "ALL_TO_NEXT"},
            }
        ],
        "edges": [{"edge": "e1", "from": "n1", "on": "ANY", "to": {"outcome": "COMPLETED"}}],
    }
    r = save(
        other,
        b_sid,
        0,
        [
            {"op": "PUT_ASSET", "kind": "MODULE", "document": mod},
            {
                "op": "SET_CONTENT",
                "content": {
                    **draft(other, b_sid)["content"],
                    "sequence": [
                        {
                            "instance": "mi-mine",
                            "module": {"code": mod["code"], "revision": 1},
                            "routes": {"COMPLETED": "@CONTINUE"},
                        }
                    ],
                },
            },
        ],
    )
    assert (r.status_code, r.json()["code"]) == (422, "REFERENCE_NOT_PUBLISHED")
    assert {d["kind"] for d in r.json()["details"]} >= {"ITEM"}
    assert state(db, b_sid) == before  # nothing was kept, not even B's own new module


# ------------------------------------------------------------------- LIB-1B: questions, conditions, option sets alone
def test_published_questions_conditions_and_option_sets_are_reused_independently(trio: Any, second: Any) -> None:
    author = trio[0]
    other, _ = second
    a_sid, _, a_map = build(author, "K8", "Source with conditions")
    publish(trio, a_sid)
    a = draft(author, a_sid)
    b_sid, _ = empty_survey(other)
    q = next(c for c in lib(other, "ITEM") if c["code"] in a_map.values() and c["facts"]["answer_type"] == "YES_NO")
    cond = next(c for c in lib(other, "CONDITION") if c["code"] in a_map.values())
    yes_no = next(c for c in lib(other, "OPTION_SET") if c["code"] in a_map.values())
    binding_of = next(
        i["eligibility"]
        for i in a["content"]["sequence"]
        if i.get("eligibility", {}).get("condition", {}).get("code") == cond["code"]
    )

    codes = issue(other, b_sid, MODULE=1, ITEM=1)
    own_item = {
        "schema": "call360.survey.item/1",
        "code": codes["ITEM"][0],
        "version": 1,
        "answer_type": "YES_NO",
        "intent": "A question of B's own, with A's published answers",
        "option_set": {"code": yes_no["code"], "version": yes_no["version"]},
    }
    own_wording = {
        "schema": "call360.survey.wording/1",
        "item": own_item["code"],
        "language": "en",
        "wording_version": 1,
        "text": "Is this your own question?",
        "delivery_mode": "CONTROLLED_TTS",
    }
    module = {
        "schema": "call360.survey.module/1",
        "code": codes["MODULE"][0],
        "revision": 1,
        "name": "B's own module",
        "outcomes": ["COMPLETED"],
        "entry": "n1",
        "nodes": [
            # a published question of survey A, placed on its own in B's module, with the wording it was published with
            {
                "node": "n1",
                "type": "QUESTION",
                "item": {"code": q["code"], "version": q["version"], "wording_version": q["wording_version"]},
                "routing": {"mode": "ALL_TO_NEXT"},
            },
            {
                "node": "n2",
                "type": "QUESTION",
                "item": {"code": own_item["code"], "version": 1, "wording_version": 1},
                "routing": {"mode": "ALL_TO_NEXT"},
            },
        ],
        "edges": [
            {"edge": "e1", "from": "n1", "on": "ANY", "to": {"node": "n2"}},
            {"edge": "e2", "from": "n2", "on": "ANY", "to": {"outcome": "COMPLETED"}},
        ],
    }
    instance = {
        "instance": "mi-own",
        "module": {"code": module["code"], "revision": 1},
        "routes": {"COMPLETED": "@CONTINUE"},
        # a published condition of survey A decides whether B's module runs, with B's own parameter values
        "eligibility": {
            "condition": {"code": cond["code"], "version": cond["version"]},
            "params": dict(binding_of["params"]),
            "unknown_policy": "SKIP_WITH_REASON",
        },
    }
    ops = [
        {"op": "PUT_ASSET", "kind": "ITEM", "document": own_item},
        {"op": "PUT_ASSET", "kind": "WORDING", "document": own_wording},
        {"op": "PUT_ASSET", "kind": "MODULE", "document": module},
    ]
    d = draft(other, b_sid)
    r = save(
        other, b_sid, d["revision"], [*ops, {"op": "SET_CONTENT", "content": {**d["content"], "sequence": [instance]}}]
    )
    assert r.status_code == 200, r.text
    owned = {(x["kind"], x["code"]): x["owned"] for x in r.json()["assets"]}
    assert (
        owned[("ITEM", q["code"])] is False
        and owned[("CONDITION", cond["code"])] is False
        and owned[("OPTION_SET", yes_no["code"])] is False
    )
    assert owned[("ITEM", own_item["code"])] is True and owned[("MODULE", module["code"])] is True
    v = post(other, f"/api/v1/survey-definitions/{b_sid}/draft/validate").json()
    assert v["blockers"] == 0, v["findings"]
    assert submit(other, b_sid).status_code == 201

    # a binding that leaves a declared parameter out is refused by the server, by a stable code — never guessed
    if binding_of["params"]:
        name = next(iter(binding_of["params"]))
        broken = {
            **instance,
            "eligibility": {
                **instance["eligibility"],
                "params": {k: v for k, v in binding_of["params"].items() if k != name},
            },
        }
        d = draft(other, b_sid)
        assert (
            save(
                other, b_sid, d["revision"], [{"op": "SET_CONTENT", "content": {**d["content"], "sequence": [broken]}}]
            ).status_code
            == 200
        )  # a draft may be incomplete …
        v = post(other, f"/api/v1/survey-definitions/{b_sid}/draft/validate").json()
        assert "CONDITION_PARAM_MISSING" in {
            f["code"] for f in v["findings"] if f["severity"] == "BLOCKER"
        }  # … but it is blocked
        assert submit(other, b_sid).json()["code"] == "VALIDATION_BLOCKED"
    # an option set is never changed by its user: a change needs a version or a copy under a code of B's own
    os_doc = asset(a, "OPTION_SET", yes_no["code"])["document"]
    d = draft(other, b_sid)
    assert (
        save(
            other,
            b_sid,
            d["revision"],
            [{"op": "PUT_ASSET", "kind": "OPTION_SET", "document": {**os_doc, "options": os_doc["options"][:1]}}],
        ).json()["code"]
        == "ASSET_FROZEN"
    )
    assert (
        save(
            other,
            b_sid,
            d["revision"],
            [{"op": "PUT_ASSET", "kind": "OPTION_SET", "document": {**os_doc, "version": os_doc["version"] + 1}}],
        ).json()["code"]
        == "CODE_OWNED_ELSEWHERE"
    )
    copy_code = issue(other, b_sid, OPTION_SET=1)["OPTION_SET"][0]
    derived = {
        **os_doc,
        "code": copy_code,
        "version": 1,
        "authoring": {"derived_from": {"code": os_doc["code"], "version": os_doc["version"]}},
    }
    assert (
        save(other, b_sid, d["revision"], [{"op": "PUT_ASSET", "kind": "OPTION_SET", "document": derived}]).status_code
        == 200
    )
    assert asset(draft(author, a_sid), "OPTION_SET", yes_no["code"])["document"] == os_doc


# ------------------------------------------------------------------------------------------- server-issued identities
def test_concurrent_requests_never_receive_the_same_code(trio: Any, engine: Engine, db: Session) -> None:
    author, _, _, people = trio
    sid, _ = empty_survey(author)
    factory = sessionmaker(bind=engine)
    got: list[str] = []
    errors: list[BaseException] = []
    gate = threading.Barrier(8)

    def worker(n: int) -> None:
        try:
            with factory() as s:
                s.execute(text("SET search_path TO call360_test"))
                gate.wait()
                codes = store.issue_codes(
                    s,
                    uuid.UUID(sid),
                    SG,
                    [{"kind": "ITEM", "count": 6}, {"kind": "MODULE", "count": 2}],
                    actor_of(people[0]),
                )
                if n % 4 == 3:
                    s.rollback()  # a failed operation: its numbers are gone for good, never handed out again
                    return
                s.commit()
                got.extend(c["code"] for c in codes)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(got) == 6 * 8 and len(set(got)) == len(got)  # six committed requests of eight codes: all different
    db.rollback()
    recorded = set(
        db.execute(text("SELECT code FROM survey_issued_code WHERE survey_definition_id = :s"), {"s": sid}).scalars()
    )
    assert recorded == set(got)  # the rolled-back requests recorded nothing
    later = issue(author, sid, ITEM=3)["ITEM"]
    numbers = lambda cs: {int(c.split("-")[-1]) for c in cs}
    assert min(numbers(later)) > max(numbers(got))  # and their numbers are not reused afterwards
    # a code some asset already carries is never issued: put one in the sequence's path
    nxt = db.execute(text("SELECT last_value FROM survey_code_seq")).scalar_one() + 1
    db.execute(
        text(
            "INSERT INTO survey_asset_version (id, kind, code, version, state, content, sha256, owner_definition_id, created_by) VALUES (:i, 'ITEM', :c, 1, 'DRAFT', CAST('{}' AS jsonb), :h, :s, 'test')"
        ),
        {"i": uuid.uuid4(), "c": f"Q-{nxt}", "h": "0" * 64, "s": sid},
    )
    db.commit()
    assert issue(author, sid, ITEM=1)["ITEM"] == [f"Q-{nxt + 1}"]
    with pytest.raises(Exception, match="immutable|rejected"):  # the record of an issued code cannot be altered
        db.execute(text("DELETE FROM survey_issued_code WHERE code = :c"), {"c": got[0]})
    db.rollback()


def test_code_requests_are_validated_and_scoped(trio: Any, survey_app: Any, db: Session) -> None:
    author = trio[0]
    sid, _ = empty_survey(author)
    for bad in (
        {"requests": []},
        {"requests": [{"kind": "WORDING", "count": 1}]},
        {"requests": [{"kind": "ITEM", "count": 0}]},
        {"requests": [{"kind": "ITEM", "count": 61}]},
    ):
        assert post(author, f"/api/v1/survey-definitions/{sid}/codes", bad).status_code == 422
    r = author.post(f"/api/v1/survey-definitions/{sid}/codes", json={"requests": [{"kind": "ITEM", "count": 1}]})
    assert r.status_code == 403 and r.json()["code"].startswith("CSRF")
    reader_person = make_account(db, prefix="reader")
    GRANTS[reader_person.principal_id] = frozenset({"survey.read"})
    reader = _client(survey_app, reader_person)
    assert (
        post(
            reader, f"/api/v1/survey-definitions/{sid}/codes", {"requests": [{"kind": "ITEM", "count": 1}]}
        ).status_code
        == 403
    )
    assert (
        reader.get("/api/v1/survey-components", params={"kind": "MODULE"}).status_code == 200
    )  # reading the library needs read
    reader.__exit__(None, None, None)
    GRANTS.pop(reader_person.principal_id)


# ----------------------------------------------------------------------------------------------- scope and the setting
def test_the_library_is_scoped_to_permission_and_market(trio: Any, survey_app: Any, db: Session) -> None:
    author = trio[0]
    a_sid, _, a_map = build(author, "K7")
    publish(trio, a_sid)
    m = next(c for c in lib(author, "MODULE") if c["code"] in a_map.values())
    plain = _client(survey_app, make_account(db, prefix="plain"))
    assert plain.get("/api/v1/survey-components", params={"kind": "MODULE"}).status_code == 403
    assert plain.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").status_code == 403
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)
    assert lib(outsider, "MODULE") == [] and lib(outsider, "ITEM") == []  # another market: the library is empty
    assert outsider.get(f"/api/v1/survey-components/MODULE/{m['code']}/1").status_code == 404
    assert (
        post(
            outsider, f"/api/v1/survey-definitions/{a_sid}/codes", {"requests": [{"kind": "ITEM", "count": 1}]}
        ).status_code
        == 404
    )
    with TestClient(survey_app, base_url="http://testserver") as anon:
        assert anon.get("/api/v1/survey-components", params={"kind": "MODULE"}).status_code == 401
    for c in (plain, outsider):
        c.__exit__(None, None, None)
    GRANTS.pop(elsewhere.principal_id)
    MARKETS.pop(elsewhere.principal_id)


def test_with_the_library_setting_off_its_routes_do_not_exist_and_the_reference_rule_still_holds(
    settings: Settings, db: Session
) -> None:
    assert settings.survey_library_enabled is False  # the default
    app = create_app(settings.model_copy(update={"survey_definitions_enabled": True, "transcription_worker": False}))
    with_grants(app)
    person, foreign = make_account(db, prefix="off"), make_account(db, prefix="offb")
    GRANTS[person.principal_id] = GRANTS[foreign.principal_id] = ALL
    c, f = _client(app, person), _client(app, foreign)
    sid, _ = empty_survey(c)
    assert c.get("/api/v1/survey-components", params={"kind": "MODULE"}).status_code == 404
    assert (
        post(c, f"/api/v1/survey-definitions/{sid}/codes", {"requests": [{"kind": "ITEM", "count": 1}]}).status_code
        == 404
    )
    assert not [p for p in c.get("/openapi.json").json()["paths"] if "survey-components" in p or p.endswith("/codes")]
    # without the library, an editor's own codes are accepted as before (nothing is issued) …
    their_sid, their_code = empty_survey(f)
    assert save(f, their_sid, 0, operations_for(fixture_bundle("K1"), their_code)).status_code == 200
    # … and a reference to another survey's unpublished asset is refused all the same
    r = pin_module(c, sid, draft(f, their_sid))
    assert (r.status_code, r.json()["code"]) == (422, "REFERENCE_NOT_PUBLISHED")
    for x in (c, f):
        x.__exit__(None, None, None)
    for p in (person, foreign):
        GRANTS.pop(p.principal_id)


def test_each_setting_demands_its_own_migration_and_no_more(settings: Settings) -> None:
    on = lambda **k: settings.model_copy(update=k)
    h39, h38, h37, h36, h35, h34, h33, h32, h31, h30, h29, h28, h27, h26 = (
        "0039_applicability_policy",
        "0038_applicability_library",
        "0037_shared_rule_services",
        "0036_survey_module_authoring",
        "0035_survey_execution_assurance",
        "0034_survey_control_policy",
        "0033_survey_control_evaluation",
        "0032_survey_coordinated_sim",
        "0031_survey_assignment_groups",
        "0030_survey_assignment",
        "0029_survey_simulation",
        "0028_survey_library",
        "0027_survey_definitions",
        "0026_gpt_live_provider",
    )
    full = (h39, h38, h37, h36, h35, h34, h33, h32, h31, h30, h29, h28, h27, h26)
    assert MIGRATION_HEAD == h39
    # APPL-X3: saved policies need 0039, and are on only with the library
    assert (
        acceptable_migration_heads(on(applicability_library_enabled=True, applicability_policies_enabled=True))
        == full[:1]
    )
    assert acceptable_migration_heads(on(applicability_policies_enabled=True)) == full
    # APPL-X2: the applicability library needs 0038, whatever else is on; with it off everything is one further
    assert acceptable_migration_heads(on(applicability_library_enabled=True)) == full[:2]
    # SHARED-1: rules on their own need 0037, whatever else is on; with it off everything is one revision further
    assert acceptable_migration_heads(on(shared_rule_services_enabled=True)) == full[:3]
    # LIB-2: standalone modules need 0036, and are on only with the library; with them off everything below is as it
    # was, one revision further from the head
    lib_ = on(survey_definitions_enabled=True, survey_library_enabled=True)
    assert acceptable_migration_heads(lib_.model_copy(update={"survey_module_authoring_enabled": True})) == full[:4]
    assert (
        acceptable_migration_heads(on(survey_definitions_enabled=True, survey_module_authoring_enabled=True))
        == full[:13]
    )
    assert acceptable_migration_heads(lib_) == full[:12]
    ev_ = on(survey_definitions_enabled=True, survey_simulation_enabled=True, survey_evaluation_enabled=True)
    # EVAL-2B: execution assurance needs 0035, and is on only with evaluation
    assert acceptable_migration_heads(ev_.model_copy(update={"survey_execution_assurance_enabled": True})) == full[:5]
    assert (
        acceptable_migration_heads(
            on(survey_definitions_enabled=True, survey_simulation_enabled=True, survey_execution_assurance_enabled=True)
        )
        == full[:11]
    )
    # EVAL-2A: control policies need 0034, and are on only with evaluation
    assert acceptable_migration_heads(ev_.model_copy(update={"survey_control_policy_enabled": True})) == full[:6]
    assert acceptable_migration_heads(ev_) == full[:7]  # EVAL-1: evaluation needs 0033, and is on only with simulation
    sim_ = on(survey_definitions_enabled=True, survey_simulation_enabled=True)
    assert acceptable_migration_heads(sim_.model_copy(update={"survey_control_policy_enabled": True})) == full[:11]
    assert acceptable_migration_heads(on(survey_definitions_enabled=True, survey_evaluation_enabled=True)) == full[:13]
    assert acceptable_migration_heads(on(survey_evaluation_enabled=True)) == full
    assert acceptable_migration_heads(on()) == full
    assert acceptable_migration_heads(on(survey_definitions_enabled=True)) == full[:13]
    assert acceptable_migration_heads(on(survey_definitions_enabled=True, survey_library_enabled=True)) == full[:12]
    assert acceptable_migration_heads(on(survey_library_enabled=True)) == full  # the library alone is not on
    # SS-03B: simulation needs 0029, whatever else is on; alone (without survey definitions) it is not on
    both = on(survey_definitions_enabled=True, survey_simulation_enabled=True)
    assert acceptable_migration_heads(both) == full[:11]
    assert acceptable_migration_heads(both.model_copy(update={"survey_library_enabled": True})) == full[:11]
    assert acceptable_migration_heads(on(survey_simulation_enabled=True)) == full
    # ASG-1: assignment needs 0030, and is on only with simulation
    asg = both.model_copy(update={"survey_assignment_enabled": True})
    assert acceptable_migration_heads(asg) == full[:10]
    assert acceptable_migration_heads(on(survey_definitions_enabled=True, survey_assignment_enabled=True)) == full[:13]
    # ASG-2A: requirement groups need 0031, and are on only with assignment
    groups = asg.model_copy(update={"survey_assignment_groups_enabled": True})
    assert acceptable_migration_heads(groups) == full[:9]
    assert acceptable_migration_heads(both.model_copy(update={"survey_assignment_groups_enabled": True})) == full[:11]
    # ASG-2B: coordinated simulation needs 0032, and is on only with requirement groups
    assert (
        acceptable_migration_heads(groups.model_copy(update={"survey_coordinated_simulation_enabled": True}))
        == full[:8]
    )
    assert (
        acceptable_migration_heads(asg.model_copy(update={"survey_coordinated_simulation_enabled": True})) == full[:10]
    )


def test_zz_migration_0028_downgrades_and_upgrades_and_refuses_to_lose_issued_codes(
    fresh_schema: None, engine: Engine, settings: Settings, db: Session
) -> None:
    def objects() -> tuple[bool, bool, str]:
        with engine.connect() as c:
            t = c.execute(text("SELECT to_regclass('call360_test.survey_issued_code') IS NOT NULL")).scalar_one()
            q = c.execute(
                text(
                    "SELECT count(*) FROM pg_sequences WHERE schemaname = 'call360_test' AND sequencename = 'survey_code_seq'"
                )
            ).scalar_one()
            return (
                bool(t),
                bool(q),
                c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one(),
            )

    with engine.connect() as c:
        tables = set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())
    assert objects() == (True, True, MIGRATION_HEAD)
    migrate(settings, "0027_survey_definitions", down=True)
    assert objects() == (False, False, "0027_survey_definitions")
    with engine.connect() as c:  # additive: every other table is exactly as it was
        assert set(
            c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars()
        ) == tables - APPLICABILITY_TABLES - {
            "survey_issued_code", "survey_simulation", "survey_simulation_input", "survey_call_plan",
            "survey_assignment_binding", "survey_assignment_binding_event", "survey_assignment_evaluation",
            "survey_assignment_simulation",
            "survey_assignment_group", "survey_assignment_group_member", "survey_assignment_group_event",
            "survey_composite_plan", "survey_composite_plan_member",
            "survey_coordinated_simulation",
            "survey_coordinated_simulation_step",
            "survey_control_mapping", "survey_control_mapping_event", "survey_journey_evaluation",
            "survey_control_result", "survey_evidence_observation", "survey_evaluation_finding",
            "survey_control_policy", "survey_control_policy_event", "survey_evaluation_policy", "survey_obligation_result", "survey_obligation_observation", "survey_obligation_finding", "survey_execution_assurance", "survey_execution_assurance_survey",
        }  # fmt: skip
    migrate(settings, "head")
    assert objects() == (True, True, MIGRATION_HEAD)
    person = make_account(db, prefix="issuer")
    sid = store.create_survey(
        db, code=new_code(), name="Holds an issued code", purpose="", market="SG", actor=actor_of(person)
    )
    store.issue_codes(db, sid, SG, [{"kind": "ITEM", "count": 1}], actor_of(person))
    db.commit()
    with pytest.raises(RuntimeError, match="server-issued survey codes exist"):
        migrate(settings, "0027_survey_definitions", down=True)
    # 0030 and 0029 (no governed binding, simulation records only) rolled back first; 0028 then refused and kept every issued code
    assert objects() == (True, True, "0028_survey_library")
    migrate(settings, "head")
    assert objects() == (True, True, MIGRATION_HEAD)


# -------------------------------------------- the LIB-1 security correction: the legacy library list (SS-03A endpoint)
def legacy(c: TestClient, kind: str) -> Any:
    return c.get(f"/api/v1/survey-library/{kind}")


def test_the_legacy_library_list_shows_only_published_reusable_versions_in_the_readers_market(
    trio: Any, survey_app: Any, db: Session
) -> None:
    """``GET /survey-library/{kind}`` used to list EVERY frozen version by code and fingerprint. It now applies the same
    rule as the component library, by direct API calls, for every kind."""
    author, checker, _, _ = trio
    published_sid, _, pub = build(author, "K8", "Published source")
    drafted, _, d_map = build(author, "K1", "Only a draft")
    in_review, _, r_map = build(author, "K7", "Frozen in a candidate, never published")
    assert submit(author, in_review).status_code == 201
    rejected, _, x_map = build(author, "K3", "Rejected")
    cid = submit(author, rejected).json()["id"]
    assert (
        post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "REJECT", "comment": "no"}).status_code
        == 200
    )
    withdrawn, _, w_map = build(author, "K4", "Withdrawn")
    wid = submit(author, withdrawn).json()["id"]
    assert post(author, f"/api/v1/survey-candidates/{wid}/withdraw", {"reason": "changed my mind"}).status_code == 200
    hidden = set(d_map.values()) | set(r_map.values()) | set(x_map.values()) | set(w_map.values())
    kinds = ("OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE")

    # the frozen-but-unpublished versions exist in the database …
    frozen = set(db.execute(text("SELECT code FROM survey_asset_version WHERE state = 'FROZEN'")).scalars())
    assert frozen & set(r_map.values()) and frozen & set(x_map.values()) and frozen & set(w_map.values())
    # … and before anything is published, the legacy list shows none of these surveys' assets, of any kind
    everything = hidden | set(pub.values())
    for kind in kinds:
        r = legacy(author, kind)
        assert r.status_code == 200
        assert not {i["code"] for i in r.json()["items"]} & everything, kind

    publish(trio, published_sid)
    seen: set[str] = set()
    for kind in kinds:
        items = legacy(author, kind).json()["items"]
        codes = {i["code"] for i in items}
        assert not codes & hidden, kind  # never a draft, an unpublished, a rejected or a withdrawn candidate's asset
        mine = [i for i in items if i["code"] in pub.values()]
        assert mine, kind
        for i in mine:  # what it does list is exactly what is published, with the stored fingerprint and honest counts
            assert (i["versions"], i["candidates"]) == (1, 1) and len(i["sha256"]) == 64
        seen |= {i["code"] for i in mine}
    assert seen == set(pub.values())  # every published component of the source, and nothing else of these surveys
    # the legacy list and the component library agree on what is reusable
    for kind in ("OPTION_SET", "ITEM", "CONDITION", "MODULE"):
        legacy_keys = {
            (i["code"], i["version"]) for i in legacy(author, kind).json()["items"] if i["code"] in everything
        }
        library_keys = {(c["code"], c["version"]) for c in lib(author, kind) if c["code"] in everything}
        assert legacy_keys == library_keys, kind

    # market: a person with every permission in another market gets an empty list; no permission, no session: refused
    elsewhere = make_account(db, prefix="elsewhere")
    GRANTS[elsewhere.principal_id] = ALL
    MARKETS[elsewhere.principal_id] = frozenset({"MY"})
    outsider = _client(survey_app, elsewhere)
    plain = _client(survey_app, make_account(db, prefix="plain"))
    for kind in kinds:
        assert legacy(outsider, kind).json()["items"] == [], kind
        assert legacy(plain, kind).status_code == 403, kind
    with TestClient(survey_app, base_url="http://testserver") as anon:
        assert legacy(anon, "MODULE").status_code == 401
    assert legacy(author, "PROMPT").status_code == 422
    for c in (outsider, plain):
        c.__exit__(None, None, None)
    GRANTS.pop(elsewhere.principal_id)
    MARKETS.pop(elsewhere.principal_id)


def test_the_legacy_library_rule_holds_with_the_library_setting_off(settings: Settings, db: Session) -> None:
    app = with_grants(
        create_app(settings.model_copy(update={"survey_definitions_enabled": True, "transcription_worker": False}))
    )
    people = [make_account(db, prefix=p) for p in ("la", "lc", "lp")]
    for p in people:
        GRANTS[p.principal_id] = ALL
    author, checker, publisher = (_client(app, p) for p in people)
    assert author.get("/api/v1/survey-components", params={"kind": "MODULE"}).status_code == 404  # the library is off
    sid, code = empty_survey(author)
    assert save(author, sid, 0, operations_for(fixture_bundle("K7"), code)).status_code == 200
    cid = submit(author, sid).json()["id"]
    own = {a["code"] for a in draft(author, sid)["assets"]}
    for kind in ("OPTION_SET", "ITEM", "WORDING", "MODULE"):  # frozen in a candidate, not published: not listed
        assert not {i["code"] for i in legacy(author, kind).json()["items"]} & own, kind
    assert post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    for kind in ("OPTION_SET", "ITEM", "WORDING", "MODULE"):  # approved is still not published
        assert not {i["code"] for i in legacy(author, kind).json()["items"]} & own, kind
    assert post(publisher, f"/api/v1/survey-candidates/{cid}/publish").status_code == 201
    listed = set()
    for kind in ("OPTION_SET", "ITEM", "WORDING", "MODULE"):
        listed |= {i["code"] for i in legacy(author, kind).json()["items"]} & own
    assert listed == own  # published: now listed, all of it
    for c in (author, checker, publisher):
        c.__exit__(None, None, None)
    for p in people:
        GRANTS.pop(p.principal_id)
