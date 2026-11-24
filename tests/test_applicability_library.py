# ruff: noqa: E501 — long request literals
"""APPL-X2 — the governed Applicability library, on the isolated test database.

Variables, application profiles and reusable conditions are PERSISTED: a draft survives a reload and is saved with an
expected revision · a submission freezes an immutable candidate that pins the exact published versions it reads ·
publication needs three different people, refused by the service AND by the table · a published version never
changes, whatever is published after it · a market sees only its own library · every step is in the history and the
audit trail · the same evaluator answers, now from the persisted library · and the migration is additive, reversible
while empty, atomic when it fails, and refuses to destroy governed history."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.survey.canonical import sha256_hex
from app.main import MIGRATION_HEAD, acceptable_migration_heads, create_app
from tests.support import ORIGIN, make_account, migrate
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_applicability import S, picked, policy, req

A = "/api/v1/applicability"
P = "/api/v1/survey-applicability/prototype"
READ, EDIT, APPROVE, PUBLISH = (
    "applicability.read",
    "applicability.edit",
    "applicability.approve",
    "applicability.publish",
)
ALL4 = frozenset({READ, EDIT, APPROVE, PUBLISH})
T = "call360_test"

BOOL = {
    "name": "NFTF applies",
    "description": "Illustrative.",
    "category": "Sale",
    "type": "BOOLEAN",
    "source": {"status": "UNMAPPED", "note": "no source has been defined"},
}
FAMILY = {
    "name": "Product family",
    "category": "Product",
    "type": "ENUM",
    "values": [{"value": "ILP", "label": "Investment-linked"}, {"value": "PROTECTION", "label": "Protection"}],
    "source": {"status": "PROPOSED", "system": "Policy", "field": "product_family"},
}
PREMIUM = {
    "name": "Annual premium",
    "category": "Premium",
    "type": "MONEY",
    "currency": "SGD",
    "min": 0,
    "source": {"status": "PROPOSED", "system": "Policy", "field": "annual_premium"},
}


def check(variable: str, operator: str = "is_true", **more: Any) -> dict[str, Any]:
    return {"op": "test", "variable": variable, "operator": operator, **more}


def ref(code: str, version: int = 1) -> dict[str, Any]:
    return {"op": "ref", "condition": code, "version": version}


@pytest.fixture()
def lib_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(
            settings.model_copy(
                update={
                    "applicability_library_enabled": True, "survey_definitions_enabled": True,
                    "survey_applicability_prototype_enabled": True, "transcription_worker": False,
                }
            )
        )
    )  # fmt: skip


@pytest.fixture(autouse=True)
def empty_library(engine: Engine) -> None:
    """Every test starts with an empty applicability library (TEST schema only; nothing else is touched)."""
    with engine.begin() as c:
        if c.execute(text(f"SELECT to_regclass('{T}.applicability_asset')")).scalar_one() is not None:
            c.execute(
                text(
                    f"TRUNCATE {T}.applicability_event, {T}.applicability_asset_dependency, {T}.applicability_asset_version, {T}.applicability_asset CASCADE"
                )
            )


@pytest.fixture()
def people(lib_app: Any, db: Session) -> Iterator[dict[str, TestClient]]:
    """LEAST privilege: an author who may only draft and submit, a checker who may only decide, a publisher who may
    only publish, a reader — and one person holding all four, whom only the identity rules can stop."""
    grants = {
        "author": {READ, EDIT, "survey.read"}, "second": {READ, EDIT}, "checker": {READ, APPROVE},
        "publisher": {READ, PUBLISH}, "reader": {READ}, "everything": set(ALL4), "nobody": {"survey.read", "script.read"},
    }  # fmt: skip
    accounts = {k: make_account(db, prefix=f"ap{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    clients = {k: _client(lib_app, a) for k, a in accounts.items()}
    yield clients
    for c in clients.values():
        c.__exit__(None, None, None)
    for a in accounts.values():
        GRANTS.pop(a.principal_id, None)
        MARKETS.pop(a.principal_id, None)


def make(c: TestClient, kind: str, code: str, doc: dict[str, Any], market: str = "SG") -> Any:
    return post(c, f"{A}/assets", {"market_code": market, "kind": kind, "code": code, "document": doc})


def created(c: TestClient, kind: str, code: str, doc: dict[str, Any]) -> dict[str, Any]:
    r = make(c, kind, code, doc)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def get(c: TestClient, asset_id: str) -> dict[str, Any]:
    r = c.get(f"{A}/assets/{asset_id}")
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def through(p: dict[str, TestClient], asset_id: str, note: str = "") -> dict[str, Any]:
    """Submit, approve and publish with three different people. Returns the item afterwards."""
    a = get(p["author"], asset_id)
    r = post(p["author"], f"{A}/assets/{asset_id}/submit", {"expected_revision": a["draft"]["revision"], "note": note})
    assert r.status_code == 200, r.text
    cid = r.json()["candidate"]["id"]
    r = post(p["checker"], f"{A}/candidates/{cid}/decision", {"verdict": "APPROVE"})
    assert r.status_code == 200, r.text
    r = post(p["publisher"], f"{A}/candidates/{cid}/publish")
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def published(p: dict[str, TestClient], kind: str, code: str, doc: dict[str, Any]) -> dict[str, Any]:
    return through(p, created(p["author"], kind, code, doc)["id"])


def revise(p: dict[str, TestClient], asset_id: str, doc: dict[str, Any]) -> dict[str, Any]:
    """A new draft from the published version, changed, and published as the next version."""
    r = post(p["author"], f"{A}/assets/{asset_id}/draft", {})
    assert r.status_code == 200, r.text
    r = p["author"].put(
        f"{A}/assets/{asset_id}/draft",
        json={"expected_revision": r.json()["draft"]["revision"], "document": doc},
        headers=_csrf(p["author"]),
    )
    assert r.status_code == 200, r.text
    return through(p, asset_id)


def _csrf(c: TestClient) -> dict[str, str]:
    from tests.support import csrf_header

    return csrf_header(c)


def put(c: TestClient, asset_id: str, revision: int, doc: dict[str, Any]) -> Any:
    return c.put(
        f"{A}/assets/{asset_id}/draft", json={"expected_revision": revision, "document": doc}, headers=_csrf(c)
    )


def codes(r: Any) -> set[str]:
    body = r.json() if hasattr(r, "json") else r
    return {d["code"] for d in (body.get("details") or body.get("diagnostics") or [])}


# ------------------------------------------------------------------------------------------- registration, permissions
def test_the_library_is_off_by_default_and_adds_exactly_fourteen_operations(settings: Settings, lib_app: Any) -> None:
    assert settings.applicability_library_enabled is False
    off = create_app(settings.model_copy(update={"transcription_worker": False}))
    assert not [r for r in off.routes if getattr(r, "path", "").startswith(A)]

    def routes(a: Any) -> set[tuple[str, str]]:
        return {(m.upper(), path) for path, ops in a.openapi()["paths"].items() for m in ops if path.startswith(A)}

    assert not routes(off)
    mine = sorted(routes(lib_app))
    assert len(mine) == 14, mine
    # with the library on, the schema must hold 0038; with it off, a schema still at 0037 serves everything else
    assert acceptable_migration_heads(settings.model_copy(update={"applicability_library_enabled": True})) == (
        MIGRATION_HEAD,
        "0038_applicability_library",
    )
    assert "0037_shared_rule_services" in acceptable_migration_heads(
        settings.model_copy(update={"shared_rule_services_enabled": True})
    )


def test_the_four_permissions_exist_and_no_role_holds_one(db: Session) -> None:
    found = set(db.execute(text("SELECT code FROM permission WHERE code LIKE 'applicability.%'")).scalars())
    assert found == set(ALL4)
    held = db.execute(
        text(
            "SELECT count(*) FROM role_permission rp JOIN permission p ON p.id = rp.permission_id WHERE p.code LIKE 'applicability.%'"
        )
    ).scalar_one()
    assert held == 0  # no standing role gained anything: ADMIN, USER and every survey role hold none of them


def test_each_operation_needs_its_own_permission_and_survey_permissions_open_nothing(
    people: dict[str, TestClient], lib_app: Any, db: Session
) -> None:
    p = people
    with TestClient(lib_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as anonymous:
        assert anonymous.get(f"{A}/assets").status_code == 401
    for group in ("LOCAL_USER_SG", "LOCAL_SC_CHECKER_SG", "LOCAL_ADMIN"):
        with _client(lib_app, make_account(db, group, prefix="applain")) as c:
            assert c.get(f"{A}/assets").status_code == 403, group
    assert p["nobody"].get(f"{A}/assets").status_code == 403  # survey.read and script.read give nothing here
    assert p["reader"].get(f"{A}/assets").status_code == 200
    assert make(p["reader"], "VARIABLE", "nftf", BOOL).status_code == 403
    assert make(p["checker"], "VARIABLE", "nftf", BOOL).status_code == 403
    a = created(p["author"], "VARIABLE", "nftf", BOOL)
    # a write without the CSRF token is refused
    r = p["author"].put(f"{A}/assets/{a['id']}/draft", json={"expected_revision": 1, "document": BOOL})
    assert r.status_code == 403 and r.json()["code"].startswith("CSRF")
    assert put(p["checker"], a["id"], 1, BOOL).status_code == 403
    cid = post(p["author"], f"{A}/assets/{a['id']}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
    for who in ("author", "publisher", "reader"):  # none of them may decide
        assert post(p[who], f"{A}/candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 403, who
    assert post(p["checker"], f"{A}/candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    for who in ("author", "checker", "reader"):  # none of them may publish
        assert post(p[who], f"{A}/candidates/{cid}/publish").status_code == 403, who
    assert post(p["publisher"], f"{A}/candidates/{cid}/publish").status_code == 200


# ------------------------------------------------------------------------------------------------ drafts, concurrency
def test_a_draft_is_persisted_reloaded_and_never_silently_overwritten(people: dict[str, TestClient]) -> None:
    p = people
    a = created(
        p["author"],
        "VARIABLE",
        "product_family",
        {**FAMILY, "anything_else": "dropped", "version": 99, "status": "PUBLISHED"},
    )
    assert (a["state"], a["draft"]["revision"], a["published"], a["candidate"]) == ("DRAFT", 1, None, None)
    assert (
        "anything_else" not in a["draft"]["document"] and "version" not in a["draft"]["document"]
    )  # only its own fields are stored
    assert a["draft"]["document"]["source"] == {"status": "PROPOSED", "system": "Policy", "field": "product_family"}
    # it is there for another person, and after a reload
    again = get(p["second"], a["id"])
    assert again["draft"]["document"] == a["draft"]["document"] and again["draft"]["updated_by"] == "Test Apauthor"
    listed = {x["code"]: x for x in p["reader"].get(f"{A}/assets?kind=VARIABLE").json()["items"]}
    assert listed["product_family"]["state"] == "DRAFT"
    # two people open revision 1; the second to save is refused and nothing is lost
    first = put(p["author"], a["id"], 1, {**FAMILY, "description": "Saved by the author"})
    assert first.status_code == 200 and first.json()["draft"]["revision"] == 2
    stale = put(p["second"], a["id"], 1, {**FAMILY, "description": "Would overwrite"})
    assert stale.status_code == 409 and stale.json()["code"] == "STALE_REVISION"
    assert stale.json()["details"][0] == {"current_revision": 2, "updated_by": "Test Apauthor"}
    assert get(p["reader"], a["id"])["draft"]["document"]["description"] == "Saved by the author"
    assert put(p["second"], a["id"], 2, {**FAMILY, "description": "On the current revision"}).status_code == 200
    # the same identity cannot be created twice, whatever its letter case; the same code is free for another kind
    dup = make(p["author"], "VARIABLE", "Product_Family", FAMILY)
    assert dup.status_code == 409 and dup.json()["code"] == "CODE_TAKEN"
    assert make(p["author"], "PROFILE", "product_family", {"name": "A profile", "sections": []}).status_code == 201
    for bad in ("1abc", "a", "has space", "x" * 61):
        assert make(p["author"], "VARIABLE", bad, BOOL).status_code == 422, bad
    assert make(p["author"], "VARIABLE", "noname", {"type": "BOOLEAN"}).json()["code"] == "NAME_REQUIRED"
    # discarding needs the current revision too; a discarded first draft leaves nothing in the list
    b = created(p["author"], "VARIABLE", "mistake", BOOL)
    assert post(p["author"], f"{A}/assets/{b['id']}/draft/discard", {"expected_revision": 7}).status_code == 409
    gone = post(p["author"], f"{A}/assets/{b['id']}/draft/discard", {"expected_revision": 1})
    assert gone.status_code == 200 and gone.json()["state"] == "EMPTY"
    assert "mistake" not in {x["code"] for x in p["reader"].get(f"{A}/assets").json()["items"]}
    assert [e["event"] for e in gone.json()["events"]] == ["CREATED", "DRAFT_DISCARDED"]


def test_variables_are_type_checked_and_source_mapping_is_kept_as_stated(people: dict[str, TestClient]) -> None:
    p = people

    def blockers(doc: dict[str, Any], code: str) -> set[str]:
        a = created(p["author"], "VARIABLE", code, doc)
        assert post(p["author"], f"{A}/assets/{a['id']}/submit", {"expected_revision": 1}).status_code == 422
        return {d["code"] for d in a["diagnostics"] if d["severity"] == "BLOCKER"}

    assert blockers({"name": "No type"}, "v_none") == {"UNKNOWN_TYPE"}
    assert blockers({"name": "Enum without values", "type": "ENUM"}, "v_enum") == {"NO_VALUES"}
    assert blockers({"name": "Money without currency", "type": "MONEY"}, "v_money") == {"NO_CURRENCY"}
    assert blockers(
        {
            "name": "Duplicate values",
            "type": "MULTI_ENUM",
            "values": [{"value": "A", "label": "A"}, {"value": "A", "label": "Again"}],
        },
        "v_dup",
    ) == {"INVALID_VALUES"}
    assert blockers({"name": "Odd source", "type": "BOOLEAN", "source": {"status": "CERTAIN"}}, "v_src") == {
        "UNKNOWN_SOURCE_STATUS"
    }
    family = published(p, "VARIABLE", "product_family", FAMILY)
    assert family["published"]["version_no"] == 1 and family["state"] == "PUBLISHED"
    # a derived variable is a yes/no value worked out from published variables, and says so as its source
    assert blockers(
        {
            "name": "Derived number",
            "type": "NUMBER",
            "derived": {"expr": check("product_family", "equals", value="ILP")},
        },
        "v_dnum",
    ) == {"DERIVED_TYPE"}
    assert blockers(
        {"name": "Derived from nothing", "type": "BOOLEAN", "derived": {"expr": check("missing")}}, "v_dmiss"
    ) == {"UNKNOWN_REFERENCE"}
    assert blockers(
        {"name": "Derived from itself", "type": "BOOLEAN", "derived": {"expr": check("v_self")}}, "v_self"
    ) >= {"DEPENDENCY_CYCLE"}
    is_ilp = published(
        p,
        "VARIABLE",
        "is_ilp",
        {
            "name": "Is ILP",
            "type": "BOOLEAN",
            "derived": {"expr": check("product_family", "equals", value="ILP")},
            "source": {"status": "MAPPED", "system": "ignored"},
        },
    )
    assert is_ilp["published"]["document"]["source"] == {"status": "DERIVED", "system": "ignored"}
    assert [(x["kind"], x["code"], x["version_no"]) for x in is_ilp["published"]["pins"]] == [
        ("VARIABLE", "product_family", 1)
    ]
    # NFTF: nothing is invented — the item says its source is not mapped, and that is what is stored and published
    nftf = published(p, "VARIABLE", "nftf", BOOL)
    assert nftf["published"]["document"]["source"] == {"status": "UNMAPPED", "note": "no source has been defined"}
    money = published(p, "VARIABLE", "annual_premium", PREMIUM)
    assert (money["published"]["document"]["currency"], money["published"]["document"]["min"]) == ("SGD", 0)
    # typed comparison, checked by the evaluator's own analysis: a yes/no test on money is a blocker
    wrong = created(
        p["author"], "CONDITION", "wrong_type", {"name": "Wrong operator", "expr": check("annual_premium", "is_true")}
    )
    assert any(d["severity"] == "BLOCKER" for d in wrong["diagnostics"])
    assert (
        published(
            p,
            "CONDITION",
            "high_premium",
            {"name": "High premium", "expr": check("annual_premium", "gte", value=50000)},
        )["state"]
        == "PUBLISHED"
    )


# ------------------------------------------------------------------------------------------------------ governance
def test_publication_needs_three_different_people_whatever_they_hold(
    people: dict[str, TestClient], db: Session
) -> None:
    p = people
    every = p["everything"]  # holds all four permissions
    a = created(every, "VARIABLE", "nftf", BOOL)
    r = post(every, f"{A}/assets/{a['id']}/submit", {"expected_revision": 1, "note": "first version"})
    assert r.status_code == 200 and r.json()["state"] == "IN_REVIEW"
    cand = r.json()["candidate"]
    assert (cand["status"], cand["is_submitter"], cand["note"], cand["content_sha256"]) == (
        "SUBMITTED",
        True,
        "first version",
        sha256_hex(a["draft"]["document"]),
    )
    # while it is in review the draft is locked for everyone
    assert r.json()["draft"]["locked"] is True
    locked = put(p["second"], a["id"], 1, BOOL)
    assert locked.status_code == 409 and locked.json()["code"] == "CANDIDATE_OPEN"
    # the submitter cannot decide their own candidate — although they hold the permission
    own = post(every, f"{A}/candidates/{cand['id']}/decision", {"verdict": "APPROVE"})
    assert own.status_code == 403 and own.json()["code"] == "SELF_REVIEW_DENIED"
    # nor publish it before a decision
    assert post(p["publisher"], f"{A}/candidates/{cand['id']}/publish").json()["code"] == "NOT_APPROVED"
    # a return needs a reason, unlocks the draft, and the author resubmits a NEW candidate
    assert (
        post(p["checker"], f"{A}/candidates/{cand['id']}/decision", {"verdict": "RETURN", "comment": "short"}).json()[
            "code"
        ]
        == "COMMENT_REQUIRED"
    )
    back = post(
        p["checker"],
        f"{A}/candidates/{cand['id']}/decision",
        {"verdict": "RETURN", "comment": "Please describe where this comes from."},
    )
    assert back.status_code == 200 and (back.json()["state"], back.json()["draft"]["locked"]) == ("RETURNED", False)
    assert back.json()["returned"]["decision_comment"] == "Please describe where this comes from."
    assert (
        post(p["checker"], f"{A}/candidates/{cand['id']}/decision", {"verdict": "APPROVE"}).json()["code"]
        == "NOT_SUBMITTED"
    )
    assert put(every, a["id"], 1, {**BOOL, "description": "Illustrative; no source is defined."}).status_code == 200
    second = post(every, f"{A}/assets/{a['id']}/submit", {"expected_revision": 2}).json()["candidate"]
    assert second["candidate_no"] == 2 and second["id"] != cand["id"]
    ok = post(p["checker"], f"{A}/candidates/{second['id']}/decision", {"verdict": "APPROVE", "comment": "Fine."})
    assert ok.status_code == 200 and ok.json()["state"] == "APPROVED"
    # neither the submitter nor the approver can publish — although the submitter holds the permission
    mine = post(every, f"{A}/candidates/{second['id']}/publish")
    assert mine.status_code == 403 and mine.json()["code"] == "SELF_PUBLISH_DENIED"
    GRANTS_checker = next(k for k, v in GRANTS.items() if v == frozenset({READ, APPROVE}))
    GRANTS[GRANTS_checker] = ALL4  # give the approver the permission to publish: the identity rule still stops them
    theirs = post(p["checker"], f"{A}/candidates/{second['id']}/publish")
    assert theirs.status_code == 403 and theirs.json()["code"] == "APPROVER_PUBLISH_DENIED"
    done = post(p["publisher"], f"{A}/candidates/{second['id']}/publish")
    assert done.status_code == 200, done.text
    out = done.json()
    assert (
        out["state"],
        out["draft"],
        out["candidate"],
        out["published"]["version_no"],
        out["published_versions"],
    ) == ("PUBLISHED", None, None, 1, 1)
    v = out["published"]
    assert len({v["submitted_by"], v["decided_by"], v["published_by"]}) == 3
    assert post(p["publisher"], f"{A}/candidates/{second['id']}/publish").json()["code"] == "NOT_APPROVED"  # once
    # the whole story is in the history, including the refusals, and in the audit trail
    assert [e["event"] for e in out["events"]] == [
        "CREATED", "SUBMITTED", "DENIED", "RETURNED", "DRAFT_SAVED", "SUBMITTED", "APPROVED", "DENIED", "DENIED", "PUBLISHED",
    ]  # fmt: skip
    assert [e["detail"].get("rule") for e in out["events"] if e["event"] == "DENIED"] == [
        "SELF_REVIEW_DENIED",
        "SELF_PUBLISH_DENIED",
        "APPROVER_PUBLISH_DENIED",
    ]
    assert out["events"][-1]["actor"] == "Test Appublisher" and out["events"][3]["comment"].startswith(
        "Please describe"
    )
    audit = db.execute(
        text(
            "SELECT action, outcome FROM audit_event WHERE entity_type = 'applicability_asset' AND entity_id = :i ORDER BY occurred_at, id"
        ),
        {"i": a["id"]},
    ).all()
    assert sorted({x[0] for x in audit}) == [
        "APPLICABILITY.APPROVED",
        "APPLICABILITY.ASSET_CREATED",
        "APPLICABILITY.DENIED",
        "APPLICABILITY.DRAFT_SAVED",
        "APPLICABILITY.PUBLISHED",
        "APPLICABILITY.RETURNED",
        "APPLICABILITY.SUBMITTED",
    ]
    assert sum(1 for x in audit if x[1] == "DENIED") == 3
    # withdrawing: only by the submitter, and it unlocks the draft
    b = created(p["author"], "VARIABLE", "replacement", {**BOOL, "name": "Replacement applies"})
    cid = post(p["author"], f"{A}/assets/{b['id']}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
    assert post(p["second"], f"{A}/candidates/{cid}/withdraw", {"reason": "not mine"}).json()["code"] == "NOT_SUBMITTER"
    w = post(p["author"], f"{A}/candidates/{cid}/withdraw", {"reason": "Submitted too early."})
    assert w.status_code == 200 and (w.json()["state"], w.json()["draft"]["locked"]) == ("DRAFT", False)


def test_a_published_version_is_immutable_and_history_is_preserved(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    premium = published(p, "VARIABLE", "annual_premium", PREMIUM)
    high = published(
        p,
        "CONDITION",
        "high_premium",
        {
            "name": "High premium",
            "description": "Synthetic threshold.",
            "expr": check("annual_premium", "gte", value=20000),
        },
    )
    v1 = high["published"]
    assert [(x["code"], x["version_no"], x["content_sha256"]) for x in v1["pins"]] == [
        ("annual_premium", 1, premium["published"]["content_sha256"])
    ]
    # there is no draft after publication; submitting or saving one is refused until a new draft is started
    assert (
        put(
            p["author"],
            high["id"],
            high["draft_revision"],
            {"name": "x y", "expr": check("annual_premium", "gte", value=1)},
        ).json()["code"]
        == "NO_DRAFT"
    )
    started = post(p["author"], f"{A}/assets/{high['id']}/draft", {})
    assert started.status_code == 200 and started.json()["draft"]["base_version_no"] == 1
    assert started.json()["draft"]["document"] == v1["document"] and started.json()["state"] == "DRAFT"
    assert post(p["author"], f"{A}/assets/{high['id']}/draft", {}).json()["code"] == "DRAFT_EXISTS"
    # an unchanged draft is not a new version
    same = post(
        p["author"], f"{A}/assets/{high['id']}/submit", {"expected_revision": started.json()["draft"]["revision"]}
    )
    assert same.status_code == 409 and same.json()["code"] == "NOTHING_CHANGED"
    assert (
        put(
            p["author"],
            high["id"],
            started.json()["draft"]["revision"],
            {**v1["document"], "expr": check("annual_premium", "gte", value=50000)},
        ).status_code
        == 200
    )
    # the variable moves on to version 2 BEFORE the condition is resubmitted: the new candidate pins what is current
    premium2 = revise(p, premium["id"], {**PREMIUM, "description": "The premium for one year."})
    assert premium2["published"]["version_no"] == 2 and premium2["published_versions"] == 2
    out = through(p, high["id"])
    v2 = out["published"]
    assert (v2["version_no"], [x["version_no"] for x in v2["pins"]]) == (2, [2])
    # version 1 is exactly what it was — same content, same manifest, same pin on the variable's version 1 — and readable
    old = next(v for v in out["versions"] if v["version_no"] == 1)
    assert old["status"] == "SUPERSEDED"
    for key in (
        "document",
        "pins",
        "content_sha256",
        "manifest_sha256",
        "submitted_by",
        "decided_by",
        "published_by",
        "published_at",
    ):
        assert old[key] == v1[key], key
    assert p["reader"].get(f"{A}/versions/{v1['id']}").json()["document"]["expr"]["value"] == 20000
    assert [
        (e["event"], e["detail"].get("version")) for e in out["events"] if e["event"] in ("PUBLISHED", "SUPERSEDED")
    ] == [("PUBLISHED", 1), ("SUPERSEDED", None), ("PUBLISHED", 2)]
    # the variable's published version 1 says something newer exists — nothing was re-pinned for it
    assert get(p["reader"], premium["id"])["used_by"] == [
        {
            "kind": "CONDITION",
            "code": "high_premium",
            "name": "High premium",
            "state": "EARLIER_VERSION",
            "version_no": 1,
            "pinned_version": 1,
        },
        {
            "kind": "CONDITION",
            "code": "high_premium",
            "name": "High premium",
            "state": "PUBLISHED",
            "version_no": 2,
            "pinned_version": 2,
        },
    ]
    # the TABLE refuses what the service never tries
    refused = (
        f"UPDATE {T}.applicability_asset_version SET document = '{{}}'::jsonb WHERE id = '{v1['id']}'",
        f"UPDATE {T}.applicability_asset_version SET manifest = '{{}}'::jsonb WHERE id = '{v2['id']}'",
        f"UPDATE {T}.applicability_asset_version SET published_by = 'someone' WHERE id = '{v2['id']}'",
        f"UPDATE {T}.applicability_asset_version SET status = 'SUBMITTED' WHERE id = '{v2['id']}'",
        f"UPDATE {T}.applicability_asset_version SET status = 'PUBLISHED' WHERE id = '{v1['id']}'",
        f"DELETE FROM {T}.applicability_asset_version WHERE id = '{v1['id']}'",
        f"DELETE FROM {T}.applicability_asset_dependency WHERE version_id = '{v1['id']}'",
        f"UPDATE {T}.applicability_asset SET code = 'renamed' WHERE id = '{high['id']}'",
        f"UPDATE {T}.applicability_asset SET market_code = 'MY' WHERE id = '{high['id']}'",
        f"DELETE FROM {T}.applicability_asset WHERE id = '{high['id']}'",
        f"UPDATE {T}.applicability_event SET comment = 'rewritten' WHERE asset_id = '{high['id']}'",
        f"DELETE FROM {T}.applicability_event WHERE asset_id = '{high['id']}'",
    )
    for sql in refused:
        with engine.connect() as c, pytest.raises(DBAPIError):
            c.execute(text(sql))
    # three people, by the table itself: a candidate decided by its submitter, or published by either, cannot be stored
    with engine.connect() as c:
        who = c.execute(
            text(f"SELECT submitted_by, decided_by FROM {T}.applicability_asset_version WHERE id = '{v2['id']}'")
        ).one()
        cid = created(p["author"], "VARIABLE", "db_guard", BOOL)["id"]
        cand = post(p["author"], f"{A}/assets/{cid}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
    for sql in (
        f"UPDATE {T}.applicability_asset_version SET status = 'APPROVED', decided_by = submitted_by, decided_at = now() WHERE id = '{cand}'",
        f"UPDATE {T}.applicability_asset_version SET status = 'PUBLISHED', version_no = 1, published_by = 'x', published_at = now() WHERE id = '{cand}'",
    ):
        with engine.connect() as c, pytest.raises(DBAPIError):
            c.execute(text(sql))
    with engine.begin() as c:
        c.execute(
            text(
                f"UPDATE {T}.applicability_asset_version SET status = 'APPROVED', decided_by = 'checker-x', decided_at = now() WHERE id = '{cand}'"
            )
        )
    for publisher in ("'checker-x'", "submitted_by"):
        with engine.connect() as c, pytest.raises(DBAPIError, match="third_publisher"):
            c.execute(
                text(
                    f"UPDATE {T}.applicability_asset_version SET status = 'PUBLISHED', version_no = 1, published_at = now(), published_by = {publisher} WHERE id = '{cand}'"
                )
            )
    assert who[0] != who[1]


def test_no_surprising_dependency_upgrade_between_review_and_submission(people: dict[str, TestClient]) -> None:
    """Owner ruling A4: the submitter states the exact versions reviewed; if a newer one was published meanwhile the
    submission is refused, nothing is frozen, and the reviewer of the candidate sees exactly what it pins."""
    p = people
    premium = published(p, "VARIABLE", "annual_premium", PREMIUM)
    high = created(
        p["author"],
        "CONDITION",
        "high_premium",
        {"name": "High premium", "expr": check("annual_premium", "gte", value=50000)},
    )
    seen = post(p["author"], f"{A}/assets/{high['id']}/validate", {}).json()
    assert [(x["kind"], x["code"], x["version_no"]) for x in seen["pins"]] == [("VARIABLE", "annual_premium", 1)]
    assert seen["pins"][0]["content_sha256"] == premium["published"]["content_sha256"]  # shown with its fingerprint
    ack = [{k: x[k] for k in ("kind", "code", "version_no")} for x in seen["pins"]]
    # meanwhile the variable gets a version 2
    revise(p, premium["id"], {**PREMIUM, "min": 100})
    refused = post(p["author"], f"{A}/assets/{high['id']}/submit", {"expected_revision": 1, "pins": ack})
    assert refused.status_code == 409 and refused.json()["code"] == "PINS_CHANGED"
    detail = refused.json()["details"][0]
    assert [x["version_no"] for x in detail["would_pin"]] == [2] and detail["reviewed"] == [
        "variable annual_premium v1"
    ]
    after = get(p["author"], high["id"])
    assert (after["state"], after["candidate"], after["draft"]["revision"]) == ("DRAFT", None, 1)  # nothing was frozen
    # reviewed again, now exactly what would be frozen: accepted, and the checker sees the same pins before deciding
    again = post(p["author"], f"{A}/assets/{high['id']}/validate", {}).json()["pins"]
    ok = post(
        p["author"],
        f"{A}/assets/{high['id']}/submit",
        {"expected_revision": 1, "pins": [{k: x[k] for k in ("kind", "code", "version_no")} for x in again]},
    )
    assert ok.status_code == 200
    for_review = get(p["checker"], high["id"])["candidate"]
    assert [(x["code"], x["version_no"], x["content_sha256"]) for x in for_review["pins"]] == [
        (x["code"], x["version_no"], x["content_sha256"]) for x in again
    ]
    assert for_review["pins"][0]["version_no"] == 2 and len(for_review["content_sha256"]) == 64
    # an item with no dependency acknowledges an empty list; a wrong list is refused the same way
    solo = created(p["author"], "VARIABLE", "nftf", BOOL)
    assert (
        post(p["author"], f"{A}/assets/{solo['id']}/submit", {"expected_revision": 1, "pins": ack}).json()["code"]
        == "PINS_CHANGED"
    )
    assert post(p["author"], f"{A}/assets/{solo['id']}/submit", {"expected_revision": 1, "pins": []}).status_code == 200


def test_fingerprints_are_deterministic(people: dict[str, TestClient]) -> None:
    p = people
    one = published(p, "VARIABLE", "nftf", BOOL)["published"]
    two = published(p, "VARIABLE", "nftf_again", json.loads(json.dumps(dict(reversed(list(BOOL.items()))))))[
        "published"
    ]
    assert one["content_sha256"] == two["content_sha256"] == sha256_hex(one["document"])  # key order does not matter
    assert one["manifest_sha256"] != two["manifest_sha256"]  # the manifest also names the item
    manifest = {
        "contract": "call360.applicability-asset/1",
        "evaluator": "call360.survey-applicability/0",
        "market": "SG",
        "kind": "VARIABLE",
        "code": "nftf",
        "content_sha256": one["content_sha256"],
        "pins": [],
    }
    assert one["manifest_sha256"] == sha256_hex(manifest)


# ---------------------------------------------------------------------------------------------- profiles, conditions
def test_profiles_compose_pin_and_never_copy_a_variable(people: dict[str, TestClient], db: Session) -> None:
    p = people
    family, nftf = published(p, "VARIABLE", "product_family", FAMILY), published(p, "VARIABLE", "nftf", BOOL)
    common = {
        "name": "Common insurance application",
        "description": "What every application carries.",
        "sections": [{"name": "Product", "variables": ["product_family"]}],
        "required": ["product_family"],
    }
    # a profile cannot be published on a draft variable, an unknown one, an unknown or unpublished parent, or itself
    draft_var = created(p["author"], "VARIABLE", "replacement", {**BOOL, "name": "Replacement applies"})
    bad = created(
        p["author"],
        "PROFILE",
        "bad",
        {
            "name": "Bad profile",
            "extends": ["nowhere", "bad"],
            "sections": [{"name": "S", "variables": ["replacement", "ghost"]}],
            "required": ["nftf"],
        },
    )
    found = {(d["code"], d["at"].get("reference")) for d in bad["diagnostics"] if d["severity"] == "BLOCKER"}
    assert {
        ("UNKNOWN_REFERENCE", "nowhere"),
        ("DEPENDENCY_CYCLE", "bad"),
        ("UNPUBLISHED_DEPENDENCY", "replacement"),
        ("UNKNOWN_REFERENCE", "ghost"),
    } <= found
    refused = post(p["author"], f"{A}/assets/{bad['id']}/submit", {"expected_revision": 1})
    assert (
        refused.status_code == 422
        and refused.json()["code"] == "NOT_VALID"
        and "UNPUBLISHED_DEPENDENCY" in codes(refused)
    )
    missing = created(
        p["author"],
        "PROFILE",
        "required_missing",
        {"name": "Requires what it lacks", "sections": [], "required": ["nftf"]},
    )
    assert "REQUIRED_NOT_INCLUDED" in {d["code"] for d in missing["diagnostics"]}
    base = published(p, "PROFILE", "common", common)
    assert [(x["kind"], x["code"], x["version_no"]) for x in base["published"]["pins"]] == [
        ("VARIABLE", "product_family", 1)
    ]
    assert "values" not in json.dumps(
        base["published"]["document"]
    )  # it refers to the variable; it holds no copy of it
    ilp = published(
        p,
        "PROFILE",
        "ilp_extension",
        {
            "name": "ILP extension",
            "extends": ["common"],
            "sections": [{"name": "Sale", "variables": ["nftf"]}],
            "constraints": {"product_family": {"allowed": ["ILP"]}},
        },
    )
    assert [(x["kind"], x["code"]) for x in ilp["published"]["pins"]] == [
        ("PROFILE", "common"),
        ("VARIABLE", "nftf"),
        ("VARIABLE", "product_family"),
    ]
    protection = published(
        p,
        "PROFILE",
        "protection_extension",
        {
            "name": "Protection extension",
            "extends": ["common"],
            "sections": [],
            "constraints": {"product_family": {"allowed": ["PROTECTION"]}},
        },
    )
    # composing two profiles that cannot both hold is a blocker, found by the evaluator's analysis
    both = created(
        p["author"],
        "PROFILE",
        "both",
        {"name": "Both extensions", "extends": ["ilp_extension", "protection_extension"], "sections": []},
    )
    assert "PROFILE_CONFLICT" in {d["code"] for d in both["diagnostics"] if d["severity"] == "BLOCKER"}
    # the composed workspace gives the evaluator the inherited variables; a draft is absent from the published view
    ws = p["reader"].get(f"{A}/workspace?view=published").json()
    assert {x["code"] for x in ws["profiles"]} == {"common", "ilp_extension", "protection_extension"}
    assert {x["code"] for x in ws["variables"]} == {"product_family", "nftf"}
    authoring = p["reader"].get(f"{A}/workspace").json()
    assert {x["code"]: x["status"] for x in authoring["variables"]}["replacement"] == "DRAFT"
    assert {x["code"] for x in authoring["profiles"]} >= {"bad", "both"}
    # a NEW version of the shared variable changes no published profile: same rows, same pins, same fingerprints
    before = db.execute(
        text(
            "SELECT id::text, md5(document::text), md5(manifest::text), content_sha256, manifest_sha256 FROM applicability_asset_version WHERE status = 'PUBLISHED' ORDER BY 1"
        )
    ).all()
    revise(p, family["id"], {**FAMILY, "values": [*FAMILY["values"], {"value": "SAVINGS", "label": "Savings"}]})
    db.rollback()
    after = db.execute(
        text(
            "SELECT id::text, md5(document::text), md5(manifest::text), content_sha256, manifest_sha256 FROM applicability_asset_version WHERE status IN ('PUBLISHED', 'SUPERSEDED') ORDER BY 1"
        )
    ).all()
    assert set(before) <= set(after)
    again = get(p["reader"], base["id"])
    assert (
        again["published"]["pins"] == base["published"]["pins"]
        and again["published"]["manifest_sha256"] == base["published"]["manifest_sha256"]
    )
    assert again["newer_pins"] == [
        {**base["published"]["pins"][0], "current_version_no": 2}
    ]  # it says so; it does not move
    # where the variable is used: the published profiles that pin it and the drafts that name it
    uses = {(u["kind"], u["code"], u["state"], u["pinned_version"]) for u in get(p["reader"], nftf["id"])["used_by"]}
    assert uses == {
        ("PROFILE", "ilp_extension", "PUBLISHED", 1),
        ("PROFILE", "bad", "DRAFT", None),
        ("PROFILE", "required_missing", "DRAFT", None),
    }
    assert draft_var["state"] == "DRAFT" and protection["state"] == "PUBLISHED"


def test_conditions_nest_refer_to_exact_versions_and_are_answered_by_the_server(people: dict[str, TestClient]) -> None:
    p = people
    for code, doc in (("product_family", FAMILY), ("nftf", BOOL), ("annual_premium", PREMIUM)):
        published(p, "VARIABLE", code, doc)
    ilp = published(
        p, "CONDITION", "is_ilp", {"name": "Is ILP", "expr": check("product_family", "equals", value="ILP")}
    )
    published(p, "CONDITION", "nftf_applies", {"name": "NFTF applies", "expr": check("nftf")})
    # AND, OR, NOT, nested groups and references to named conditions at an exact version
    nested = {
        "op": "all",
        "args": [
            ref("is_ilp"),
            {
                "op": "any",
                "args": [{"op": "not", "arg": ref("nftf_applies")}, check("annual_premium", "gte", value=50000)],
            },
        ],
    }
    combo = published(p, "CONDITION", "ilp_special", {"name": "ILP, and not NFTF or a high premium", "expr": nested})
    assert [(x["kind"], x["code"], x["version_no"]) for x in combo["published"]["pins"]] == [
        ("CONDITION", "is_ilp", 1),
        ("CONDITION", "nftf_applies", 1),
        ("VARIABLE", "annual_premium", 1),
    ]

    def answer(expr: dict[str, Any], facts: dict[str, Any], view: str = "published") -> Any:
        r = post(p["reader"], f"{A}/test", {"market_code": "SG", "expr": expr, "facts": facts, "view": view})
        assert r.status_code == 200, r.text
        return r.json()

    assert answer(ref("ilp_special"), {"product_family": "ILP", "nftf": False})["result"] == "TRUE"
    assert (
        answer(ref("ilp_special"), {"product_family": "ILP", "nftf": True, "annual_premium": 100})["result"] == "FALSE"
    )
    assert (
        answer(ref("ilp_special"), {"product_family": "PROTECTION"})["result"] == "FALSE"
    )  # decided although NFTF is not known
    unknown = answer(ref("ilp_special"), {"product_family": "ILP", "nftf": True})
    assert unknown["result"] == "UNKNOWN" and unknown["facts"]["annual_premium"]["state"] == "NOT_PROVIDED"
    assert (
        unknown["trace"]["op"] == "ref" and unknown["trace"]["children"][0]["op"] == "all"
    )  # the full trace comes back
    # only registered variables are read: an arbitrary request field is never a fact
    stray = answer(ref("is_ilp"), {"product_family": "ILP", "is_admin": True, "anything": "else"})
    assert stray["result"] == "TRUE" and set(stray["facts"]) == {"product_family"}
    assert answer(ref("is_ilp"), {"product_family": "NOT-A-VALUE"})["facts"]["product_family"]["state"] == "INVALID"
    # references that cannot be pinned are refused: no version, a version that was never published, an unpublished
    # condition, itself — and a circle between two drafts
    for expr, want in (
        ({"op": "ref", "condition": "is_ilp"}, "UNKNOWN_CONDITION_VERSION"),
        (ref("is_ilp", 7), "UNKNOWN_CONDITION_VERSION"),
        (ref("ghost"), "UNKNOWN_REFERENCE"),
        (check("ghost_variable"), "UNKNOWN_REFERENCE"),
    ):
        a = created(
            p["author"],
            "CONDITION",
            f"bad_{len(expr)}_{want[:9].lower()}_{abs(hash(json.dumps(expr))) % 9999}",
            {"name": "Cannot be pinned", "expr": expr},
        )
        assert want in {d["code"] for d in a["diagnostics"] if d["severity"] == "BLOCKER"}, (expr, a["diagnostics"])
        assert post(p["author"], f"{A}/assets/{a['id']}/submit", {"expected_revision": 1}).status_code == 422
    one = created(p["author"], "CONDITION", "loop_a", {"name": "Loop A", "expr": ref("loop_b")})
    two = created(p["author"], "CONDITION", "loop_b", {"name": "Loop B", "expr": ref("loop_a")})
    assert {d["code"] for d in get(p["author"], one["id"])["diagnostics"]} >= {"UNPUBLISHED_DEPENDENCY"}
    for a in (one, two):
        assert post(p["author"], f"{A}/assets/{a['id']}/submit", {"expected_revision": 1}).status_code == 422
    selfish = created(p["author"], "CONDITION", "selfish", {"name": "Refers to itself", "expr": ref("selfish")})
    assert "DEPENDENCY_CYCLE" in {d["code"] for d in selfish["diagnostics"]}
    # an unsaved edit can be checked and tested live without saving anything
    checked = post(
        p["author"], f"{A}/assets/{selfish['id']}/validate", {"document": {"name": "Fixed", "expr": ref("is_ilp")}}
    )
    assert (
        checked.status_code == 200
        and checked.json()["can_submit"] is True
        and [x["code"] for x in checked.json()["pins"]] == ["is_ilp"]
    )
    assert get(p["author"], selfish["id"])["draft"]["document"]["name"] == "Refers to itself"
    # a draft condition is tested in the authoring view and does not exist in the published one
    assert answer(ref("loop_a"), {}, "authoring")["error"]["code"] in (
        "CONDITION_CYCLE",
        "UNKNOWN_CONDITION_VERSION",
        "REF_CYCLE",
    )
    assert answer(ref("selfish"), {})["error"]["code"] == "UNKNOWN_CONDITION"
    # version 2 of a condition: a reference to version 1 keeps meaning version 1
    v2 = revise(p, ilp["id"], {"name": "Is ILP", "expr": check("product_family", "in", values=["ILP", "PROTECTION"])})
    assert v2["published"]["version_no"] == 2
    assert answer(ref("is_ilp", 1), {"product_family": "PROTECTION"})["result"] == "FALSE"
    assert answer(ref("is_ilp", 2), {"product_family": "PROTECTION"})["result"] == "TRUE"
    assert answer(ref("ilp_special"), {"product_family": "PROTECTION"})["result"] == "FALSE"  # it pinned version 1
    uses = {(u["code"], u["state"], u["pinned_version"]) for u in v2["used_by"]}
    assert ("ilp_special", "PUBLISHED", 1) in uses and ("selfish", "DRAFT", None) not in uses


def test_a_published_version_is_reused_exactly_by_a_prototype_policy_and_outside_profile_facts_are_read(
    people: dict[str, TestClient],
) -> None:
    p = people
    for code, doc in (
        ("product_family", FAMILY),
        ("nftf", BOOL),
        (
            "channel",
            {
                "name": "Sales channel",
                "type": "ENUM",
                "values": [{"value": "AGENCY", "label": "Agency"}],
                "source": {"status": "PROPOSED"},
            },
        ),
    ):
        published(p, "VARIABLE", code, doc)
    ilp = published(p, "CONDITION", "ilp", {"name": "Is ILP", "expr": check("product_family", "equals", value="ILP")})
    published(p, "CONDITION", "nftf", {"name": "NFTF applies", "expr": check("nftf")})
    published(
        p,
        "PROFILE",
        "common",
        {"name": "Common application", "sections": [{"name": "Core", "variables": ["product_family", "channel"]}]},
    )
    revise(p, ilp["id"], {"name": "Is ILP", "expr": check("product_family", "in", values=["ILP", "PROTECTION"])})
    ws = p["author"].get(f"{A}/workspace?view=published").json()
    body_ws = {k: ws[k] for k in ("variables", "profiles", "conditions")}
    pol = policy(
        req("a", ref("ilp", 1), "A"), req("b", ref("nftf", 1), "B"), req("c", ref("ilp", 2), "C"), profiles=["common"]
    )

    def plan(facts: dict[str, Any], **more: Any) -> dict[str, Any]:
        r = post(
            p["author"],
            f"{P}/evaluate",
            {
                "workspace": body_ws,
                "policy": pol,
                "scenarios": [{"id": "s", "facts": facts, "profiles": ["common"], **more}],
            },
        )
        assert r.status_code == 200, r.text
        return r.json()["result"]["results"][0]["plan"]  # type: ignore[no-any-return]

    # version 1 and version 2 of the same condition, side by side, each exactly as published
    out = plan({"product_family": "PROTECTION", "nftf": True})
    assert picked(out) == ["B", "C"] and out["status"] == "RESOLVED"
    # NFTF is not in the profile 'common': the fact that was GIVEN is read, and marked as coming from outside it
    assert (out["facts"]["nftf"]["state"], out["facts"]["nftf"]["outside_profiles"]) == ("KNOWN", True)
    assert "outside_profiles" not in out["facts"]["product_family"]
    # a registered variable the policy does not read is not evaluated; an unregistered field is never a fact
    assert "channel" not in out["facts"]
    stray = plan({"product_family": "ILP", "nftf": False, "channel": "AGENCY", "is_vip": True, "__proto__": 1})
    assert set(stray["facts"]) == {"product_family", "nftf"} and picked(stray) == ["A", "C"]
    # a type-invalid value from outside the profile is INVALID, never a silent yes or no
    assert plan({"product_family": "ILP", "nftf": "yes please"})["facts"]["nftf"]["state"] == "INVALID"
    assert [S("A")["code"], S("C")["code"]] == [e["survey"]["code"] for e in stray["selected"]]


# ---------------------------------------------------------------------------------------------------------- markets
def test_a_market_sees_and_references_only_its_own_library(
    people: dict[str, TestClient], db: Session, engine: Engine
) -> None:
    p = people
    theirs = make_account(db, prefix="apmy")
    GRANTS[theirs.principal_id], MARKETS[theirs.principal_id] = ALL4, frozenset({"MY"})
    sg_only = published(p, "VARIABLE", "nftf", BOOL)
    try:
        with _client(p["author"].app, theirs) as my:
            # the other market's author cannot create in SG, and SG's author cannot create in MY
            assert make(my, "VARIABLE", "x_var", BOOL, "SG").json()["code"] == "MARKET_NOT_IN_SCOPE"
            assert make(p["author"], "VARIABLE", "x_var", BOOL, "MY").json()["code"] == "MARKET_NOT_IN_SCOPE"
            mine = created_in(my, "VARIABLE", "my_only", {**BOOL, "name": "Only in MY"}, "MY")
            # the same code is a different item in another market
            assert created_in(my, "VARIABLE", "nftf", BOOL, "MY")["id"] != sg_only["id"]
            assert {x["code"] for x in my.get(f"{A}/assets").json()["items"]} == {"my_only", "nftf"}
            assert "my_only" not in {x["code"] for x in p["reader"].get(f"{A}/assets").json()["items"]}
            # another market's item does not exist: read, save, submit, validate, decide, version — all 404
            assert p["reader"].get(f"{A}/assets/{mine['id']}").status_code == 404
            assert put(p["author"], mine["id"], 1, BOOL).status_code == 404
            assert post(p["author"], f"{A}/assets/{mine['id']}/submit", {"expected_revision": 1}).status_code == 404
            assert my.get(f"{A}/assets/{sg_only['id']}").status_code == 404
            assert my.get(f"{A}/versions/{sg_only['published']['id']}").status_code == 404
            assert my.get(f"{A}/workspace?market_code=SG").status_code == 403
            assert post(my, f"{A}/test", {"market_code": "SG", "expr": check("nftf"), "facts": {}}).status_code == 403
            assert {x["code"] for x in my.get(f"{A}/workspace").json()["variables"]} == {"my_only", "nftf"}
            # an SG condition cannot read a variable that exists only in MY: for SG it does not exist
            cross = created(
                p["author"], "CONDITION", "cross", {"name": "Reads another market", "expr": check("my_only")}
            )
            assert [(d["code"], d["at"]["reference"]) for d in cross["diagnostics"] if d["severity"] == "BLOCKER"][
                0
            ] == ("UNKNOWN_REFERENCE", "my_only")
            assert post(p["author"], f"{A}/assets/{cross['id']}/submit", {"expected_revision": 1}).status_code == 422
            # and the TABLE refuses a pin across markets, on a version that is not published, or on itself
            ok = created(p["author"], "CONDITION", "sg_cond", {"name": "SG condition", "expr": check("nftf")})
            cand = post(p["author"], f"{A}/assets/{ok['id']}/submit", {"expected_revision": 1}).json()["candidate"][
                "id"
            ]
            my_cand = post(my, f"{A}/assets/{mine['id']}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
            other = created(p["author"], "VARIABLE", "pending", {**BOOL, "name": "Still in review"})
            pending = post(p["author"], f"{A}/assets/{other['id']}/submit", {"expected_revision": 1}).json()[
                "candidate"
            ]["id"]
            for target, why in (
                (my_cand, "published versions only"),
                (pending, "published versions only"),
                (cand, "published versions only"),
            ):
                with engine.connect() as c, pytest.raises(DBAPIError, match=why):
                    c.execute(text(f"INSERT INTO {T}.applicability_asset_dependency VALUES ('{cand}', '{target}')"))
    finally:
        GRANTS.pop(theirs.principal_id, None)
        MARKETS.pop(theirs.principal_id, None)


def created_in(c: TestClient, kind: str, code: str, doc: dict[str, Any], market: str) -> dict[str, Any]:
    r = make(c, kind, code, doc, market)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def test_the_table_refuses_a_pin_across_markets_even_on_a_published_version(
    people: dict[str, TestClient], db: Session, engine: Engine
) -> None:
    p = people
    three = [make_account(db, prefix=f"apmy{i}") for i in range(3)]
    for a in three:
        GRANTS[a.principal_id], MARKETS[a.principal_id] = ALL4, frozenset({"MY"})
    try:
        clients = [_client(p["author"].app, a) for a in three]
        mine = created_in(clients[0], "VARIABLE", "my_var", BOOL, "MY")
        cid = post(clients[0], f"{A}/assets/{mine['id']}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
        assert post(clients[1], f"{A}/candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
        assert post(clients[2], f"{A}/candidates/{cid}/publish").status_code == 200
        published(p, "VARIABLE", "nftf", BOOL)
        ok = created(p["author"], "CONDITION", "sg_cond", {"name": "SG condition", "expr": check("nftf")})
        cand = post(p["author"], f"{A}/assets/{ok['id']}/submit", {"expected_revision": 1}).json()["candidate"]["id"]
        with engine.connect() as c, pytest.raises(DBAPIError, match="its own market only"):
            c.execute(text(f"INSERT INTO {T}.applicability_asset_dependency VALUES ('{cand}', '{cid}')"))
        for c_ in clients:
            c_.__exit__(None, None, None)
    finally:
        for a in three:
            GRANTS.pop(a.principal_id, None)
            MARKETS.pop(a.principal_id, None)


# ------------------------------------------------------------------------------------------- the showcase library
def test_the_showcase_library_is_published_through_the_governed_api_and_is_idempotent(
    people: dict[str, TestClient], db: Session
) -> None:
    from scripts import appl_library_setup as setup

    p = people

    def rows() -> list[int]:
        db.rollback()
        return [
            db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one()
            for t in (
                "applicability_asset",
                "applicability_asset_version",
                "applicability_asset_dependency",
                "applicability_event",
            )
        ]

    missing = setup.run(p["author"], p["checker"], p["publisher"], verify_only=True)
    assert missing["ok"] is False and missing["summary"] == {"MISSING": 26} and rows() == [0, 0, 0, 0]
    first = setup.run(p["author"], p["checker"], p["publisher"])
    assert first["ok"] is True and first["summary"] == {"PUBLISHED": 26}, setup.render(first)
    by = {(i["kind"], i["code"]): i for i in first["items"]}
    assert len({first["people"][r] for r in ("author", "checker", "publisher")}) == 3
    for i in first["items"]:
        assert len({i["submitted_by"], i["approved_by"], i["published_by"]}) == 3, i["code"]
    assert by[("CONDITION", "high_premium")]["version_no"] == 2  # its earlier version was published first, and kept
    assert by[("VARIABLE", "is_ilp")]["pins"] == ["variable product_family v1"]
    assert by[("CONDITION", "ilp_with_nftf")]["pins"] == ["condition is_ilp v1", "condition nftf_applies v1"]
    assert "profile common v1" in by[("PROFILE", "new_business")]["pins"]
    # nothing is invented: NFTF and the riders say their source is not mapped
    ws = p["reader"].get(f"{A}/workspace?view=published").json()
    source = {v["code"]: v["source"]["status"] for v in ws["variables"]}
    assert (source["nftf"], source["selected_riders"], source["is_ilp"]) == ("UNMAPPED", "UNMAPPED", "DERIVED")
    assert (len(ws["variables"]), len(ws["profiles"]), len(ws["conditions"])) == (12, 7, 7)
    assert [h["version"] for h in next(c for c in ws["conditions"] if c["code"] == "high_premium")["history"]] == [1]
    # the showcase conditions answer from the persisted library
    r = post(
        p["reader"],
        f"{A}/test",
        {
            "market_code": "SG",
            "view": "published",
            "expr": ref("ilp_with_nftf"),
            "facts": {"product_family": "ILP", "nftf": True},
        },
    )
    assert r.json()["result"] == "TRUE"
    had = rows()
    assert had[0] == 26 and had[1] == 27
    again = setup.run(p["author"], p["checker"], p["publisher"])
    assert again["ok"] is True and again["summary"] == {"REUSED": 26} and rows() == had  # a second run writes nothing
    assert [(i["code"], i["content_sha256"]) for i in again["items"]] == [
        (i["code"], i["content_sha256"]) for i in first["items"]
    ]
    assert setup.run(p["author"], p["checker"], p["publisher"], verify_only=True)["ok"] is True and rows() == had
    # something that is not the showcase under one of its codes is reported and left alone
    nftf = by[("VARIABLE", "nftf")]["asset_id"]
    assert post(p["author"], f"{A}/assets/{nftf}/draft", {}).status_code == 200
    conflict = setup.run(p["author"], p["checker"], p["publisher"])
    assert conflict["ok"] is False and conflict["summary"] == {"CONFLICT": 1, "REUSED": 25}
    assert get(p["author"], nftf)["state"] == "DRAFT"  # untouched
    assert "assword" not in setup.render(first) + json.dumps(first)


# -------------------------------------------------------------------------------------------------------- migration
def _head(engine: Engine) -> str:
    with engine.connect() as c:
        return str(c.execute(text(f"SELECT version_num FROM {T}.alembic_version")).scalar_one())


def _objects(engine: Engine) -> tuple[list[str], list[str], list[str]]:
    with engine.connect() as c:
        tables = sorted(
            c.execute(
                text(
                    f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_name LIKE 'applicability%' AND table_name NOT LIKE 'applicability_policy%'"
                )
            ).scalars()
        )
        functions = sorted(
            c.execute(
                text(
                    f"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{T}' AND p.proname LIKE 'applicability%' AND p.proname NOT LIKE 'applicability_policy%'"
                )
            ).scalars()
        )
        perms = sorted(c.execute(text(f"SELECT code FROM {T}.permission WHERE code LIKE 'applicability.%'")).scalars())
    return tables, functions, perms


def _everything_else(engine: Engine) -> dict[str, tuple[int, str]]:
    """Row count and content digest of every table that is NOT part of the applicability library."""
    out: dict[str, tuple[int, str]] = {}
    with engine.connect() as c:
        names = c.execute(
            text(
                f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_type = 'BASE TABLE' AND table_name NOT LIKE 'applicability%' AND table_name NOT IN ('alembic_version', 'permission')"
            )
        ).scalars()
        for name in sorted(names):
            row = c.execute(
                text(
                    f"SELECT count(*), coalesce(md5(string_agg(md5(t::text), '' ORDER BY md5(t::text))), '') FROM {T}.\"{name}\" t"
                )
            ).one()  # noqa: S608 — names from the catalogue
            out[name] = (row[0], row[1])
    return out


def test_zz_migration_0038_is_additive_reversible_while_empty_atomic_and_keeps_governed_history(
    fresh_schema: None, engine: Engine, settings: Settings, lib_app: Any, db: Session
) -> None:
    """On a POPULATED schema (the seeded reference data, accounts, audit trail and a published survey library)."""
    from tests.test_survey_lib1 import build
    from tests.test_survey_lib1 import publish as publish_survey

    survey_people = tuple(make_account(db, prefix=p) for p in ("zxauthor", "zxchecker", "zxpublisher"))
    for a in survey_people:
        GRANTS[a.principal_id] = frozenset({"survey.read", "survey.edit", "survey.approve", "survey.publish"})
    survey_app = with_grants(
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
    sc = tuple(_client(survey_app, a) for a in survey_people)
    try:
        sid, _, _ = build(sc[0], "K8", "Published before the applicability migration")
        publish_survey(sc, sid)
    finally:
        for c in sc:
            c.__exit__(None, None, None)
    assert _head(engine) == MIGRATION_HEAD
    full = _objects(engine)
    assert full == (
        ["applicability_asset", "applicability_asset_dependency", "applicability_asset_version", "applicability_event"],
        [
            "applicability_asset_guard",
            "applicability_dependency_guard",
            "applicability_event_guard",
            "applicability_version_guard",
        ],
        sorted(ALL4),
    )
    before = _everything_else(engine)
    assert before["survey_version"][0] >= 1 and before["audit_event"][0] > 0
    # 1. downgrade while empty removes exactly what the upgrade added, and touches nothing else
    migrate(settings, "0037_shared_rule_services", down=True)
    assert _head(engine) == "0037_shared_rule_services" and _objects(engine) == ([], [], [])
    assert _everything_else(engine) == before
    # 2. a forced failure half-way: a permission row that collides makes the LAST step fail, after every table,
    #    index, function and trigger was created — and all of it is rolled back
    with engine.begin() as c:
        c.execute(
            text(
                f"INSERT INTO {T}.permission (id, code, alias, reserved, description) VALUES (gen_random_uuid(), 'applicability.publish', NULL, false, 'collides')"
            )
        )
    with pytest.raises(DBAPIError):
        migrate(settings, "head")
    assert _head(engine) == "0037_shared_rule_services"
    assert _objects(engine) == ([], [], ["applicability.publish"])  # nothing of the migration is left behind
    with engine.begin() as c:
        c.execute(text(f"DELETE FROM {T}.permission WHERE code = 'applicability.publish'"))
    assert _everything_else(engine) == before
    # 3. upgrade again: the same objects, and every other table is byte-identical
    migrate(settings, "head")
    assert _head(engine) == MIGRATION_HEAD and _objects(engine) == full and _everything_else(engine) == before
    # 3b. a role that was deliberately given one of the permissions stops the downgrade until it is revoked
    with engine.begin() as c:
        role = c.execute(text(f"SELECT id FROM {T}.role ORDER BY code LIMIT 1")).scalar_one()
        perm = c.execute(text(f"SELECT id FROM {T}.permission WHERE code = 'applicability.read'")).scalar_one()
        c.execute(
            text(f"INSERT INTO {T}.role_permission (role_id, permission_id) VALUES (:r, :p)"), {"r": role, "p": perm}
        )
    with pytest.raises(RuntimeError, match="a role holds an applicability permission"):
        migrate(settings, "0037_shared_rule_services", down=True)
    assert (
        _head(engine) == "0038_applicability_library" and _objects(engine) == full
    )  # 0039 (no saved policy) rolled back first
    migrate(settings, "head")
    with engine.begin() as c:
        c.execute(
            text(f"DELETE FROM {T}.role_permission WHERE role_id = :r AND permission_id = :p"), {"r": role, "p": perm}
        )
    assert _everything_else(engine) == before
    # 4. with governed content the downgrade is refused and nothing is lost
    grants = {"author": {READ, EDIT}, "checker": {READ, APPROVE}, "publisher": {READ, PUBLISH}}
    accounts = {k: make_account(db, prefix=f"zap{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    clients = {k: _client(lib_app, a) for k, a in accounts.items()}
    try:
        kept = published(clients, "VARIABLE", "nftf", BOOL)

        def governed() -> list[tuple[Any, ...]]:
            with engine.connect() as c:
                return [tuple(r) for sql in (
                    f"SELECT id::text, code, kind, market_code, draft_revision FROM {T}.applicability_asset ORDER BY 1",
                    f"SELECT id::text, status, version_no, content_sha256, manifest_sha256, submitted_by, decided_by, published_by FROM {T}.applicability_asset_version ORDER BY 1",
                    f"SELECT seq, event, actor_ref FROM {T}.applicability_event ORDER BY 1",
                ) for r in c.execute(text(sql))]  # fmt: skip

        rows = governed()
        with pytest.raises(RuntimeError, match="applicability library items exist"):
            migrate(settings, "0037_shared_rule_services", down=True)
        assert (
            _head(engine) == "0038_applicability_library" and governed() == rows
        )  # 0039 rolled back first; 0038 refused
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD and governed() == rows
        assert get(clients["author"], kept["id"])["published"]["version_no"] == 1
    finally:
        for c in clients.values():
            c.__exit__(None, None, None)
        for a in (*accounts.values(), *survey_people):
            GRANTS.pop(a.principal_id, None)
