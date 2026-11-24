# ruff: noqa: E501, F811 — long request literals; fixtures imported from the library test module
"""APPL-X3 — persistent Applicability Policies, on the isolated test database.

A policy is saved in PostgreSQL and reopened in a later session exactly as it was · it records the exact dependencies
it was saved against and never moves to a newer one by itself · adopting a newer version is a deliberate, reversible
edit · a draft dependency is allowed, is reported, and a change to it is noticed, not silently evaluated · a stale
save is refused · every reference is validated and constrained by the database · a market sees only its own · the
saved evaluation is the existing Python evaluator's, byte for byte · and the migration is additive, reversible while
empty, atomic when it fails and refuses to destroy saved policies."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.survey.applicability import evaluator as E
from app.domain.survey.applicability import policies as pol
from app.domain.survey.applicability.logic import Workspace
from app.domain.survey.canonical import sha256_hex
from app.main import MIGRATION_HEAD, acceptable_migration_heads, create_app
from tests.support import ORIGIN, csrf_header, make_account, migrate
from tests.test_applicability_library import BOOL, FAMILY, A, check, created, published, ref, revise
from tests.test_applicability_library import put as put_asset
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_lib1 import build
from tests.test_survey_lib1 import publish as publish_survey

P = f"{A}/policies"
T = "call360_test"
LIB = {"applicability.read", "applicability.edit", "applicability.approve", "applicability.publish"}
SURVEY = {"survey.read", "survey.edit", "survey.approve", "survey.publish"}
TABLES = ("applicability_policy", "applicability_policy_dependency", "applicability_policy_event")


@pytest.fixture()
def x3_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(
            settings.model_copy(
                update={
                    "applicability_library_enabled": True, "applicability_policies_enabled": True,
                    "survey_definitions_enabled": True, "survey_library_enabled": True,
                    "survey_applicability_prototype_enabled": True, "transcription_worker": False,
                }
            )
        )
    )  # fmt: skip


@pytest.fixture(autouse=True)
def empty(engine: Engine) -> None:
    """Every test starts with no policy and an empty library (TEST schema only)."""
    with engine.begin() as c:
        if c.execute(text(f"SELECT to_regclass('{T}.applicability_policy')")).scalar_one() is not None:
            c.execute(
                text(
                    f"TRUNCATE {T}.applicability_policy_event, {T}.applicability_policy_dependency, {T}.applicability_policy"
                )
            )
        if c.execute(text(f"SELECT to_regclass('{T}.applicability_asset')")).scalar_one() is not None:
            c.execute(
                text(
                    f"TRUNCATE {T}.applicability_event, {T}.applicability_asset_dependency, {T}.applicability_asset_version, {T}.applicability_asset CASCADE"
                )
            )


@pytest.fixture()
def people(x3_app: Any, db: Session) -> Iterator[dict[str, TestClient]]:
    """The three library people (each also reads surveys), a second policy author, a survey trio, and people who lack
    one of the two things a policy operation needs."""
    grants = {
        "author": {"applicability.read", "applicability.edit", "survey.read"}, "second": {"applicability.read", "applicability.edit", "survey.read"},
        "checker": {"applicability.read", "applicability.approve", "survey.read"}, "publisher": {"applicability.read", "applicability.publish", "survey.read"},
        "reader": {"applicability.read", "survey.read"}, "no_survey": {"applicability.read", "applicability.edit"}, "survey_only": set(SURVEY),
        "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY),
    }  # fmt: skip
    accounts = {k: make_account(db, prefix=f"x3{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    clients = {k: _client(x3_app, a) for k, a in accounts.items()}
    clients["_accounts"] = accounts  # type: ignore[assignment]
    yield clients
    for k, c in clients.items():
        if k != "_accounts":
            c.__exit__(None, None, None)
    for a in accounts.values():
        GRANTS.pop(a.principal_id, None)
        MARKETS.pop(a.principal_id, None)


def survey(p: dict[str, TestClient], letter: str) -> dict[str, Any]:
    """A REAL published Survey Studio version, as a policy refers to it."""
    sid, code, _ = build(p["s1"], "K8", f"Policy test survey {letter}")
    publish_survey((p["s1"], p["s2"], p["s3"]), sid)
    row = next(x for x in p["s1"].get("/api/v1/survey-definitions").json()["items"] if x["id"] == sid)
    v = p["s1"].get(f"/api/v1/survey-versions/{row['latest_version_id']}").json()
    return {"code": code, "name": f"Survey {letter}", "version": v["version_no"], "label": v["label"], "version_id": v["id"],
            "definition_id": sid, "fingerprint": v["content_sha256"], "manifest": v["manifest_sha256"], "market": "SG"}  # fmt: skip


def library(p: dict[str, TestClient]) -> None:
    published(p, "VARIABLE", "product_family", FAMILY)
    published(p, "VARIABLE", "nftf", BOOL)
    published(p, "CONDITION", "ilp", {"name": "Is ILP", "expr": check("product_family", "equals", value="ILP")})
    published(p, "CONDITION", "nftf_applies", {"name": "NFTF applies", "expr": check("nftf")})
    published(
        p,
        "PROFILE",
        "common",
        {"name": "Common application", "sections": [{"name": "Core", "variables": ["product_family"]}]},
    )


def req(rid: str, when: Any, *surveys: dict[str, Any], replaces: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "id": rid,
        "name": f"Requirement {rid}",
        "when": when,
        "action": {"kind": "INCLUDE", "surveys": list(surveys)},
        "replaces": list(replaces),
    }


def document(*reqs: dict[str, Any], **more: Any) -> dict[str, Any]:
    order = [s["code"] for r in reqs for s in r["action"]["surveys"]]
    return {"name": "ILP and NFTF", "description": "synthetic", "profiles": ["common"], "scope": None, "shared_deliveries": [],
            "requirements": list(reqs), "order": list(dict.fromkeys(order)), **more}  # fmt: skip


def make(c: TestClient, code: str, doc: dict[str, Any], market: str = "SG", origin: str = "BLANK") -> Any:
    return post(c, P, {"market_code": market, "code": code, "document": doc, "origin": origin})


def made(c: TestClient, code: str, doc: dict[str, Any]) -> dict[str, Any]:
    r = make(c, code, doc)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def save(c: TestClient, pid: str, revision: int, doc: dict[str, Any]) -> Any:
    return c.put(f"{P}/{pid}/draft", json={"expected_revision": revision, "document": doc}, headers=csrf_header(c))


def read(c: TestClient, pid: str) -> dict[str, Any]:
    r = c.get(f"{P}/{pid}")
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def evaluate(c: TestClient, pid: str, **facts: dict[str, Any]) -> dict[str, Any]:
    r = post(c, f"{P}/{pid}/evaluate", {"scenarios": [{"id": k, "facts": v} for k, v in facts.items()]})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def picked(run: dict[str, Any], scenario: str) -> list[str]:
    return [
        e["survey"]["name"][-1]
        for e in next(x for x in run["results"] if x["scenario"] == scenario)["plan"]["selected"]
    ]


def deps(policy: dict[str, Any]) -> dict[tuple[str, str], Any]:
    return {
        (e["kind"], e["code"]): e.get("version_no") if e["state"] == "PUBLISHED" else f"draft r{e['draft_revision']}"
        for e in policy["snapshot"]["dependencies"]
    }


FACTS = {"ilp_only": {"product_family": "ILP", "nftf": False}, "nftf_only": {"product_family": "PROTECTION", "nftf": True},
         "both": {"product_family": "ILP", "nftf": True}, "neither": {"product_family": "PROTECTION", "nftf": False}, "unknown_nftf": {"product_family": "ILP"}}  # fmt: skip


def rows(db: Session) -> list[Any]:
    db.rollback()
    return [
        db.execute(
            text(f"SELECT count(*), coalesce(md5(string_agg(md5(t::text), '' ORDER BY md5(t::text))), '') FROM {t} t")
        ).one()
        for t in TABLES
    ]


# ------------------------------------------------------------------------------------------------------ registration
def test_policies_are_off_by_default_need_the_library_and_add_ten_operations(
    settings: Settings, x3_app: Any, people: dict[str, TestClient]
) -> None:
    def routes(a: Any) -> set[tuple[str, str]]:
        return {(m.upper(), path) for path, ops in a.openapi()["paths"].items() for m in ops if path.startswith(P)}

    assert settings.applicability_policies_enabled is False
    assert not routes(create_app(settings.model_copy(update={"transcription_worker": False})))
    alone = create_app(
        settings.model_copy(update={"applicability_policies_enabled": True, "transcription_worker": False})
    )
    assert not routes(alone)  # without the library there is nothing for a policy to read
    assert len(routes(x3_app)) == 10, sorted(routes(x3_app))
    on = settings.model_copy(update={"applicability_library_enabled": True, "applicability_policies_enabled": True})
    assert MIGRATION_HEAD == "0039_applicability_policy" and acceptable_migration_heads(on) == (MIGRATION_HEAD,)
    assert "0038_applicability_library" in acceptable_migration_heads(
        settings.model_copy(update={"applicability_library_enabled": True})
    )
    # no new permission: a policy operation needs the applicability permission AND the read-only survey one
    p = people
    with TestClient(x3_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as anonymous:
        assert anonymous.get(P).status_code == 401
    assert p["survey_only"].get(P).status_code == 403 and p["no_survey"].get(P).status_code == 403
    assert p["reader"].get(P).status_code == 200
    doc = document()
    for who in ("reader", "checker", "publisher", "no_survey", "survey_only"):  # only an editor who also reads surveys
        assert make(p[who], "NOPE", {**doc, "profiles": []}).status_code == 403, who
    r = p["author"].post(P, json={"market_code": "SG", "code": "NO-TOKEN", "document": {**doc, "profiles": []}})
    assert r.status_code == 403 and r.json()["code"].startswith("CSRF")


# ------------------------------------------------------------------------------------- Journey A: saved and reopened
def test_a_policy_is_saved_reopened_in_a_new_session_and_keeps_its_history(
    people: dict[str, TestClient], x3_app: Any, db: Session
) -> None:
    p = people
    library(p)
    a = survey(p, "A")
    for bad in ("1abc", "x", "has space"):
        assert make(p["author"], bad, document()).status_code == 422
    assert make(p["author"], "NONAME", {**document(), "name": " "}).json()["code"] == "NAME_REQUIRED"
    first = made(
        p["author"],
        "ILP-NFTF",
        document(req("r1", ref("ilp"), a), scope=check("product_family", "in", values=["ILP", "PROTECTION"])),
    )
    assert (first["state"], first["draft_revision"], first["code"], first["market_code"]) == (
        "DRAFT",
        1,
        "ILP-NFTF",
        "SG",
    )
    assert make(p["second"], "ilp-nftf", document()).json()["code"] == "CODE_TAKEN"  # market-scoped, whatever the case
    # everything is there for another person, and for the same person in a NEW session (the browser was closed)
    with _client(x3_app, p["_accounts"]["author"]) as later:  # type: ignore[index]
        again = read(later, first["id"])
        assert again["document"] == first["document"] and again["snapshot"] == first["snapshot"]
        assert [x["code"] for x in later.get(P).json()["items"]] == ["ILP-NFTF"]
    doc = again["document"]
    assert doc["requirements"][0]["action"]["surveys"][0] == a and doc["scope"]["values"] == ["ILP", "PROTECTION"]
    # the dependencies it reads were pinned by the server and are part of the document
    assert doc["pins"] == [
        {"kind": "PROFILE", "code": "common", "version": 1},
        {"kind": "VARIABLE", "code": "product_family", "version": 1},
    ]
    assert deps(again) == {
        ("CONDITION", "ilp"): 1,
        ("PROFILE", "common"): 1,
        ("VARIABLE", "product_family"): 1,
        ("SURVEY", a["code"]): 1,
    }
    assert again["snapshot_sha256"] == sha256_hex(again["snapshot"]) and again["document_sha256"] == sha256_hex(doc)
    survey_dep = next(e for e in again["snapshot"]["dependencies"] if e["kind"] == "SURVEY")
    assert (
        survey_dep["version_id"],
        survey_dep["content_sha256"],
        survey_dep["manifest_sha256"],
        survey_dep["definition_id"],
    ) == (a["version_id"], a["fingerprint"], a["manifest"], a["definition_id"])
    # edited and saved again: a new revision; an identical save is not one
    doc2 = {**doc, "description": "Edited in a later session (synthetic)."}
    saved = save(p["second"], first["id"], 1, doc2)
    assert (
        saved.status_code == 200
        and saved.json()["draft_revision"] == 2
        and saved.json()["updated_by"] == "Test X3Second"
    )
    assert save(p["second"], first["id"], 2, doc2).json()["code"] == "NOTHING_CHANGED"
    hist = read(p["reader"], first["id"])["events"]
    assert [(e["event"], e["draft_revision"], e["actor"]) for e in hist] == [
        ("CREATED", 1, "Test X3Author"),
        ("DRAFT_SAVED", 2, "Test X3Second"),
    ]
    assert (
        hist[0]["detail"]["origin"] == "BLANK"
        and hist[1]["detail"]["document_sha256"] == saved.json()["document_sha256"]
    )
    audit = (
        db.execute(
            text(
                "SELECT action FROM audit_event WHERE entity_type = 'applicability_policy' AND entity_id = :i ORDER BY occurred_at, id"
            ),
            {"i": first["id"]},
        )
        .scalars()
        .all()
    )
    assert audit == ["APPLICABILITY.POLICY_CREATED", "APPLICABILITY.POLICY_SAVED"]
    assert pol.consistent(db, uuid.UUID(first["id"]))  # the dependency rows ARE the stored snapshot
    # a read for the document only does not run the inspection; everything else is the same
    light = p["reader"].get(f"{P}/{first['id']}?inspection=false").json()
    assert (
        light["inspection"] is None
        and light["document"] == saved.json()["document"]
        and light["snapshot"] == saved.json()["snapshot"]
    )
    # archived with a reason, out of the gallery, restorable, never deleted
    assert (
        post(p["author"], f"{P}/{first['id']}/archive", {"expected_revision": 2, "reason": "no"}).json()["code"]
        == "COMMENT_REQUIRED"
    )
    assert (
        post(
            p["author"], f"{P}/{first['id']}/archive", {"expected_revision": 1, "reason": "Created by mistake."}
        ).json()["code"]
        == "STALE_REVISION"
    )
    gone = post(p["author"], f"{P}/{first['id']}/archive", {"expected_revision": 2, "reason": "Created by mistake."})
    assert gone.status_code == 200 and gone.json()["state"] == "ARCHIVED" and p["reader"].get(P).json()["items"] == []
    assert [x["code"] for x in p["reader"].get(f"{P}?archived=true").json()["items"]] == ["ILP-NFTF"]
    assert save(p["author"], first["id"], 2, document()).json()["code"] == "ARCHIVED"
    back = post(p["author"], f"{P}/{first['id']}/restore", {"expected_revision": 2})
    assert back.json()["state"] == "DRAFT" and back.json()["document"] == saved.json()["document"]


# ----------------------------------------------------------------- Journeys B and C: deterministic saved evaluation
def test_the_saved_policy_gives_the_evaluators_own_result_every_time(
    people: dict[str, TestClient], db: Session
) -> None:
    p = people
    library(p)
    a, b, c = survey(p, "A"), survey(p, "B"), survey(p, "C")
    both = {"op": "all", "args": [ref("ilp"), ref("nftf_applies")]}
    additive = made(
        p["author"],
        "ADDITIVE",
        document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b), req("r3", both, c)),
    )
    run = evaluate(p["reader"], additive["id"], **FACTS)
    assert (run["source"], run["status"], run["draft_revision"]) == ("SAVED", "OK", 1)
    assert {k: picked(run, k) for k in FACTS} == {
        "ilp_only": ["A"],
        "nftf_only": ["B"],
        "both": ["A", "B", "C"],
        "neither": [],
        "unknown_nftf": ["A"],
    }
    unknown = next(x for x in run["results"] if x["scenario"] == "unknown_nftf")["plan"]
    assert unknown["status"] == "UNRESOLVED" and [e["survey"]["name"][-1] for e in unknown["pending"]] == ["B", "C"]
    # exact published survey versions and fingerprints, straight from Survey Studio
    chosen = next(x for x in run["results"] if x["scenario"] == "both")["plan"]["selected"]
    assert [(e["survey"]["version_id"], e["survey"]["fingerprint"]) for e in chosen] == [
        (s["version_id"], s["fingerprint"]) for s in (a, b, c)
    ]
    # the same saved revision and the same facts: the same bytes, the same fingerprints — now, and in a later read
    again = evaluate(p["author"], additive["id"], **FACTS)
    assert (
        again == run
        and run["snapshot_sha256"] == additive["snapshot_sha256"]
        and run["document_sha256"] == additive["document_sha256"]
    )
    assert (
        run["policy_fingerprint"] == additive["inspection"]["policy_fingerprint"]
        and len(run["policy_fingerprint"]) == 64
    )
    # STOP CONDITION check: the persisted path and the existing evaluator agree exactly
    row = pol.policy_row(db, uuid.UUID(additive["id"]), ["SG"])
    ws = Workspace(additive["inspection"]["workspace"])
    edoc = pol.evaluator_document(row, row["document"])
    for name, facts in FACTS.items():
        assert next(x for x in run["results"] if x["scenario"] == name)["plan"] == E.evaluate(ws, edoc, facts, None), (
            name
        )
    assert run["policy_fingerprint"] == E.fingerprint(ws, edoc)
    # Journey C: C explicitly replaces A and B — saved, reread, evaluated
    doc = copy.deepcopy(additive["document"])
    doc["requirements"][2]["replaces"] = ["r1", "r2"]
    replaced = save(p["author"], additive["id"], 1, doc).json()
    assert replaced["draft_revision"] == 2 and read(p["reader"], additive["id"])["document"]["requirements"][2][
        "replaces"
    ] == ["r1", "r2"]
    run2 = evaluate(p["reader"], additive["id"], **FACTS)
    assert {k: picked(run2, k) for k in FACTS} == {
        "ilp_only": ["A"],
        "nftf_only": ["B"],
        "both": ["C"],
        "neither": [],
        "unknown_nftf": [],  # A may be replaced: it waits with B and C until NFTF is known
    }
    assert run2["policy_fingerprint"] != run["policy_fingerprint"] and run2["snapshot_sha256"] == run["snapshot_sha256"]
    # an unsaved what-if says so, and can be compared with what is saved
    back = copy.deepcopy(doc)
    back["requirements"][2]["replaces"] = []
    pre = post(
        p["reader"],
        f"{P}/{additive['id']}/preview",
        {"document": back, "scenarios": [{"id": "both", "facts": FACTS["both"]}], "compare_with_saved": True},
    ).json()
    assert (pre["source"], pre["document_sha256"], picked(pre, "both")) == ("PREVIEW", None, ["A", "B", "C"])
    assert pre["results"][0]["comparison"]["changed"] is True and picked(
        {"results": [{"scenario": "both", "plan": pre["results"][0]["before"]}]}, "both"
    ) == ["C"]
    assert read(p["reader"], additive["id"])["draft_revision"] == 2  # a preview saves nothing


# ------------------------------------------------------------------------ Journey D: pins never move by themselves
def test_a_newer_version_is_never_adopted_silently_and_adoption_is_reversible(
    people: dict[str, TestClient], db: Session
) -> None:
    p = people
    library(p)
    a = survey(p, "A")
    made_ = made(p["author"], "PINS", document(req("r1", ref("ilp"), a)))
    before = evaluate(p["reader"], made_["id"], prot={"product_family": "PROTECTION"})
    assert picked(before, "prot") == []
    # version 2 of the CONDITION and version 2 of the VARIABLE it reads are published
    ilp = next(x for x in p["author"].get(f"{A}/assets?kind=CONDITION").json()["items"] if x["code"] == "ilp")
    fam = next(x for x in p["author"].get(f"{A}/assets?kind=VARIABLE").json()["items"] if x["code"] == "product_family")
    revise(p, fam["id"], {**FAMILY, "values": [*FAMILY["values"], {"value": "SAVINGS", "label": "Savings"}]})
    revise(p, ilp["id"], {"name": "Is ILP", "expr": check("product_family", "in", values=["ILP", "PROTECTION"])})
    # reopened: exactly what was saved — the same document, the same manifest, the same result, the same fingerprints
    again = read(p["reader"], made_["id"])
    assert again["document"] == made_["document"] and again["snapshot"] == made_["snapshot"]
    assert deps(again)[("CONDITION", "ilp")] == 1 and deps(again)[("VARIABLE", "product_family")] == 1
    assert evaluate(p["reader"], made_["id"], prot={"product_family": "PROTECTION"}) == before
    assert again["inspection"]["workspace"]["variables"][0]["values"] == [
        {"value": "ILP", "label": "Investment-linked"},
        {"value": "PROTECTION", "label": "Protection"},
    ]
    # … and the newer versions are offered, tied to the requirement they concern
    newer = {
        (d["at"]["kind"], d["at"]["code"]): d
        for d in again["inspection"]["diagnostics"]
        if d["code"] == "NEWER_VERSION"
    }
    assert set(newer) == {("condition", "ilp"), ("variable", "product_family")} and newer[("condition", "ilp")]["at"][
        "requirements"
    ] == ["r1"]
    assert "Nothing changes until you adopt it" in newer[("condition", "ilp")]["message"]
    dep = {(e["kind"], e["code"]): e for e in again["inspection"]["dependencies"]}
    assert (
        dep[("CONDITION", "ilp")]["newer_version_no"] == 2
        and dep[("VARIABLE", "product_family")]["newer_version_no"] == 2
    )
    # deliberate adoption of the condition's version 2: the reference in the document changes, and so does the manifest
    adopted = copy.deepcopy(again["document"])
    adopted["requirements"][0]["when"] = ref("ilp", 2)
    two = save(p["author"], made_["id"], 1, adopted).json()
    assert (
        deps(two)[("CONDITION", "ilp")] == 2 and deps(two)[("VARIABLE", "product_family")] == 1
    )  # the variable was not adopted with it
    assert two["snapshot_sha256"] != made_["snapshot_sha256"]
    assert two["events"][-1]["detail"]["pinned"] == ["condition ilp v2"] and two["events"][-1]["detail"][
        "released"
    ] == ["condition ilp v1"]
    assert picked(evaluate(p["reader"], made_["id"], prot={"product_family": "PROTECTION"}), "prot") == [
        "A"
    ]  # version 2's meaning
    # the condition's version 2 was published reading the variable's version 2; the policy still reads version 1, and is told
    assert any(
        d["code"] == "PIN_DIFFERS" and d["at"]["variable"] == "product_family" for d in two["inspection"]["diagnostics"]
    )
    # adoption of the variable is a change of its pin; then undone: the previous pins are restored exactly
    var2 = copy.deepcopy(two["document"])
    next(x for x in var2["pins"] if x["code"] == "product_family")["version"] = 2
    three = save(p["author"], made_["id"], 2, var2).json()
    assert deps(three)[("VARIABLE", "product_family")] == 2 and not [
        d for d in three["inspection"]["diagnostics"] if d["code"] in ("NEWER_VERSION", "PIN_DIFFERS")
    ]
    undone = save(p["author"], made_["id"], 3, again["document"]).json()
    assert (
        undone["snapshot"] == made_["snapshot"]
        and undone["document"] == made_["document"]
        and undone["draft_revision"] == 4
    )
    assert (
        evaluate(p["reader"], made_["id"], prot={"product_family": "PROTECTION"})["policy_fingerprint"]
        == before["policy_fingerprint"]
    )
    assert pol.consistent(db, uuid.UUID(made_["id"]))
    # where used, from the dependency rows: exact, and by version
    use = p["reader"].get(f"{P}/usage?kind=CONDITION&code=ilp").json()["items"]
    assert [(u["policy_code"], u["version_no"]) for u in use] == [("PINS", 1)]
    assert [(u["kind"], u["version_no"]) for u in p["reader"].get(f"{P}/usage?code={a['code']}").json()["items"]] == [
        ("SURVEY", 1)
    ]


# -------------------------------------------------------------------------------- Journey E: a draft dependency
def test_a_draft_dependency_is_allowed_reported_and_a_change_to_it_is_noticed(people: dict[str, TestClient]) -> None:
    p = people
    library(p)
    a = survey(p, "A")
    draft = created(
        p["author"], "CONDITION", "premium_case", {"name": "Premium case", "expr": check("nftf")}
    )  # NOT published
    made_ = made(p["author"], "DRAFT-DEP", document(req("r1", ref("premium_case", 1), a)))
    assert {"kind": "CONDITION", "code": "premium_case", "draft_revision": 1} in made_["document"]["pins"]
    assert deps(made_)[("CONDITION", "premium_case")] == "draft r1"
    ins = read(p["reader"], made_["id"])["inspection"]  # reloaded
    warn = next(d for d in ins["diagnostics"] if d["code"] == "UNPUBLISHED_DEPENDENCY")
    assert warn["at"] == {"kind": "condition", "code": "premium_case", "requirements": ["r1"]}
    assert (ins["unpublished"], ins["ready_for_publication"], ins["can_evaluate"]) == (1, False, True)
    assert ins["readiness"] == "Not ready for publication: it reads 1 unpublished library item."
    assert picked(evaluate(p["reader"], made_["id"], yes={"nftf": True}), "yes") == [
        "A"
    ]  # a draft can be designed with
    # the condition's draft changes: the policy notices, and does NOT evaluate as though nothing had changed
    assert (
        put_asset(
            p["author"], draft["id"], 1, {"name": "Premium case", "expr": {"op": "not", "arg": check("nftf")}}
        ).status_code
        == 200
    )
    stale = evaluate(p["reader"], made_["id"], yes={"nftf": True})
    assert (stale["status"], stale["results"], stale["policy_fingerprint"]) == ("DEPENDENCY_STALE", [], None)
    assert (
        "was changed after this policy was saved against its draft revision 1: it is now at draft revision 2"
        in stale["reasons"][0]["message"]
    )
    ins = read(p["reader"], made_["id"])["inspection"]
    assert (ins["stale"], ins["can_evaluate"], ins["ready_for_publication"]) == (
        1,
        False,
        False,
    ) and "1 dependency has changed since it was saved" in ins["readiness"]
    assert read(p["reader"], made_["id"])["snapshot"] == made_["snapshot"]  # the saved policy itself did not move
    pre = post(
        p["reader"],
        f"{P}/{made_['id']}/preview",
        {"document": made_["document"], "scenarios": [{"id": "yes", "facts": {"nftf": True}}]},
    ).json()
    assert pre["status"] == "DEPENDENCY_STALE"  # not as a what-if either
    # reconciled deliberately: the pin is moved to the revision that was looked at; the result is the new meaning
    accepted = copy.deepcopy(made_["document"])
    next(x for x in accepted["pins"] if x["code"] == "premium_case")["draft_revision"] = 2
    two = save(p["author"], made_["id"], 1, accepted).json()
    assert deps(two)[("CONDITION", "premium_case")] == "draft r2" and two["inspection"]["stale"] == 0
    assert picked(evaluate(p["reader"], made_["id"], yes={"nftf": True}), "yes") == []
    # a pin on a draft revision that never existed is refused
    wrong = copy.deepcopy(accepted)
    next(x for x in wrong["pins"] if x["code"] == "premium_case")["draft_revision"] = 77
    refused = save(p["author"], made_["id"], 2, wrong)
    assert refused.status_code == 422 and refused.json()["code"] == "INVALID_DEPENDENCY_PIN"
    # the draft is then PUBLISHED as version 1: the policy pinned a draft, and is told — it is not silently re-read
    from tests.test_applicability_library import through

    through(p, draft["id"])
    after = read(p["reader"], made_["id"])
    assert (
        after["inspection"]["stale"] == 1
        and evaluate(p["reader"], made_["id"], yes={"nftf": True})["status"] == "DEPENDENCY_STALE"
    )
    assert (
        "version 1 is published"
        in next(d for d in after["inspection"]["diagnostics"] if d["code"] == "STALE_DEPENDENCY")["message"]
    )
    onto = copy.deepcopy(accepted)
    onto["pins"] = [x for x in onto["pins"] if x["code"] != "premium_case"]  # adopt the published version 1
    three = save(p["author"], made_["id"], 2, onto).json()
    assert deps(three)[("CONDITION", "premium_case")] == 1 and three["inspection"]["ready_for_publication"] is True
    assert three["inspection"]["readiness"].startswith(
        "No blocker was found. Publication of policies is not available yet"
    )


# --------------------------------------------------------------------------------------- Journey F: concurrency
def test_a_stale_save_is_refused_and_nothing_is_overwritten(people: dict[str, TestClient], db: Session) -> None:
    p = people
    library(p)
    a = survey(p, "A")
    made_ = made(p["author"], "TWO-EDITORS", document(req("r1", ref("ilp"), a)))
    mine, theirs = copy.deepcopy(made_["document"]), copy.deepcopy(made_["document"])
    mine["description"], theirs["description"] = "From the first session.", "From the second session."
    assert save(p["second"], made_["id"], 1, theirs).status_code == 200
    had = rows(db)
    late = save(p["author"], made_["id"], 1, mine)
    assert late.status_code == 409 and late.json()["code"] == "STALE_REVISION"
    assert late.json()["details"] == [{"current_revision": 2, "updated_by": "Test X3Second"}]
    assert rows(db) == had and read(p["reader"], made_["id"])["document"]["description"] == "From the second session."
    # the first person keeps their own text and, deliberately, saves it as the next revision
    assert save(p["author"], made_["id"], 2, mine).json()["draft_revision"] == 3
    assert [e["actor"] for e in read(p["reader"], made_["id"])["events"]] == [
        "Test X3Author",
        "Test X3Second",
        "Test X3Author",
    ]


# ------------------------------------------------------------------------------------------ Journey H: security
def test_references_are_validated_markets_are_isolated_and_the_tables_refuse_the_rest(
    people: dict[str, TestClient], x3_app: Any, db: Session, engine: Engine
) -> None:
    p = people
    library(p)
    a = survey(p, "A")
    good = document(req("r1", ref("ilp"), a))
    made_ = made(p["author"], "SECURE", good)
    had = rows(db)
    lib_before = db.execute(
        text("SELECT md5(string_agg(md5(t::text), '' ORDER BY id)) FROM applicability_asset_version t")
    ).scalar_one()
    survey_before = db.execute(
        text("SELECT md5(string_agg(md5(t::text), '' ORDER BY id)) FROM survey_version t")
    ).scalar_one()

    def refused(change: Any, code: str) -> None:
        doc = copy.deepcopy(good)
        change(doc)
        r = save(p["author"], made_["id"], 1, doc)
        assert r.status_code == 422 and r.json()["code"] == code, r.text
        assert make(p["author"], f"X{uuid.uuid4().hex[:6]}", doc).status_code == 422

    s0 = lambda d: d["requirements"][0]["action"]["surveys"][0]  # noqa: E731
    # an invalid survey version: one that does not exist, a wrong fingerprint, a wrong number, a wrong code, a module
    refused(lambda d: s0(d).update(version_id=str(uuid.uuid4())), "INVALID_SURVEY_REFERENCE")
    refused(lambda d: s0(d).update(fingerprint="0" * 64), "INVALID_SURVEY_REFERENCE")
    refused(lambda d: s0(d).update(manifest="f" * 64), "INVALID_SURVEY_REFERENCE")
    refused(lambda d: s0(d).update(version=7), "INVALID_SURVEY_REFERENCE")
    refused(lambda d: s0(d).update(code="S-SOMETHING-ELSE"), "INVALID_SURVEY_REFERENCE")
    # an invalid dependency pin: a variable version or a condition version that was never published; an unknown item
    refused(
        lambda d: d.update(pins=[{"kind": "VARIABLE", "code": "product_family", "version": 9}]),
        "INVALID_DEPENDENCY_PIN",
    )
    refused(lambda d: d["requirements"][0].update(when=ref("ilp", 9)), "INVALID_DEPENDENCY_PIN")
    refused(lambda d: d["requirements"][0].update(when={"op": "ref", "condition": "ilp"}), "INVALID_DEPENDENCY_PIN")
    ghost = save(p["author"], made_["id"], 1, {**good, "requirements": [req("r1", check("no_such_variable"), a)]})
    assert ghost.status_code == 200 and "UNKNOWN_REFERENCE" in {
        d["code"] for d in ghost.json()["inspection"]["diagnostics"]
    }  # a draft may be incomplete; it is reported
    assert save(p["author"], made_["id"], 2, good).status_code == 200
    had = rows(db)
    # ---- markets: another market's policy does not exist; its library and its surveys cannot be referenced
    other = make_account(db, prefix="x3my")
    GRANTS[other.principal_id], MARKETS[other.principal_id] = (
        frozenset({"applicability.read", "applicability.edit", "survey.read"}),
        frozenset({"MY"}),
    )
    try:
        with _client(x3_app, other) as my:
            assert make(my, "MINE", {**document(), "profiles": []}, "SG").json()["code"] == "MARKET_NOT_IN_SCOPE"
            assert (
                make(p["author"], "THEIRS", {**document(), "profiles": []}, "MY").json()["code"]
                == "MARKET_NOT_IN_SCOPE"
            )
            mine = make(my, "MINE", {**document(), "profiles": []}, "MY")
            assert mine.status_code == 201 and my.get(P).json()["items"][0]["code"] == "MINE"
            assert [x["code"] for x in p["reader"].get(P).json()["items"]] == ["SECURE"]
            for call in (lambda c, i: c.get(f"{P}/{i}"), lambda c, i: save(c, i, 1, good), lambda c, i: post(c, f"{P}/{i}/evaluate", {"scenarios": []}),
                         lambda c, i: post(c, f"{P}/{i}/preview", {"document": good, "scenarios": []}), lambda c, i: post(c, f"{P}/{i}/inspect", {}),
                         lambda c, i: post(c, f"{P}/{i}/archive", {"expected_revision": 1, "reason": "not my market at all"})):  # fmt: skip
                assert (
                    call(my, made_["id"]).status_code == 404 and call(p["author"], mine.json()["id"]).status_code == 404
                )
            assert my.get(f"{P}/usage?code=ilp").json()["items"] == []  # nothing about SG's policies is disclosed
            # SG's library and SG's survey are not usable from MY: they do not exist there
            theirs = save(my, mine.json()["id"], 1, {**document(req("r1", ref("ilp"), a)), "profiles": []})
            assert theirs.status_code == 422 and {d["code"] for d in theirs.json()["details"]} == {
                "INVALID_SURVEY_REFERENCE"
            }
            unknown = save(my, mine.json()["id"], 1, {**document(req("r1", check("nftf"))), "profiles": []})
            assert unknown.status_code == 200 and [
                d["message"] for d in unknown.json()["inspection"]["diagnostics"] if d["code"] == "UNKNOWN_REFERENCE"
            ] == ["The variable 'nftf' does not exist in market MY"]
            my_id = mine.json()["id"]
    finally:
        GRANTS.pop(other.principal_id, None)
        MARKETS.pop(other.principal_id, None)
    assert rows(db)[0][0] == had[0][0] + 1  # only MY's own policy was added; SG's rows are untouched by every refusal
    # ---- published library versions and Survey Studio versions are exactly as they were
    db.rollback()
    assert (
        db.execute(
            text("SELECT md5(string_agg(md5(t::text), '' ORDER BY id)) FROM applicability_asset_version t")
        ).scalar_one()
        == lib_before
    )
    assert (
        db.execute(text("SELECT md5(string_agg(md5(t::text), '' ORDER BY id)) FROM survey_version t")).scalar_one()
        == survey_before
    )
    # ---- the TABLES refuse what the service never tries
    dep = db.execute(
        text(
            "SELECT asset_id::text, asset_version_id::text FROM applicability_policy_dependency WHERE policy_id = :p AND kind = 'CONDITION'"
        ),
        {"p": made_["id"]},
    ).one()
    sdep = db.execute(
        text(
            "SELECT survey_definition_id::text, survey_version_id::text FROM applicability_policy_dependency WHERE policy_id = :p AND kind = 'SURVEY'"
        ),
        {"p": made_["id"]},
    ).one()
    h = "0" * 64
    for sql, why in (
        (f"UPDATE {T}.applicability_policy SET code = 'RENAMED' WHERE id = '{made_['id']}'", "never change"),
        (f"UPDATE {T}.applicability_policy SET market_code = 'MY' WHERE id = '{made_['id']}'", "never change"),
        (f"UPDATE {T}.applicability_policy SET draft_revision = 1 WHERE id = '{made_['id']}'", "never goes back"),
        (
            f"UPDATE {T}.applicability_policy SET document = '{{\"name\": \"x\"}}'::jsonb WHERE id = '{made_['id']}'",
            "new revision",
        ),
        (f"DELETE FROM {T}.applicability_policy WHERE id = '{made_['id']}'", "never deleted"),
        (
            f"UPDATE {T}.applicability_policy_event SET comment = 'rewritten' WHERE policy_id = '{made_['id']}'",
            "append-only",
        ),
        (f"DELETE FROM {T}.applicability_policy_event WHERE policy_id = '{made_['id']}'", "append-only"),
        (
            f"UPDATE {T}.applicability_policy_dependency SET version_no = 2 WHERE policy_id = '{made_['id']}'",
            "never edited",
        ),
        # a reference that names nothing: refused by the foreign keys
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, asset_id, asset_version_id, version_no, content_sha256, manifest_sha256) VALUES ('{made_['id']}', 'VARIABLE', 'ghost', '{uuid.uuid4()}', '{uuid.uuid4()}', 1, '{h}', '{h}')",
            "foreign key|published version of that item|does not belong to that survey",
        ),
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, survey_definition_id, survey_version_id, version_no, content_sha256, manifest_sha256) VALUES ('{made_['id']}', 'SURVEY', 'ghost', '{sdep[0]}', '{uuid.uuid4()}', 1, '{h}', '{h}')",
            "foreign key|published version of that item|does not belong to that survey",
        ),
        # a reference of the wrong kind, of another market, or shaped like neither a version nor a draft
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, asset_id, asset_version_id, version_no, content_sha256, manifest_sha256) VALUES ('{made_['id']}', 'VARIABLE', 'ilp', '{dep[0]}', '{dep[1]}', 1, '{h}', '{h}')",
            "is not a variable",
        ),
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, asset_id, asset_version_id, version_no, content_sha256, manifest_sha256) VALUES ('{my_id}', 'CONDITION', 'ilp', '{dep[0]}', '{dep[1]}', 1, '{h}', '{h}')",
            "its own market only",
        ),
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, survey_definition_id, survey_version_id, version_no, content_sha256, manifest_sha256) VALUES ('{my_id}', 'SURVEY', 'x', '{sdep[0]}', '{sdep[1]}', 1, '{h}', '{h}')",
            "its own market only",
        ),
        (
            f"INSERT INTO {T}.applicability_policy_dependency (policy_id, kind, code, asset_id, content_sha256) VALUES ('{made_['id']}', 'CONDITION', 'ilp', '{dep[0]}', '{h}')",
            "dependency_shape",
        ),
    ):
        with engine.connect() as c, pytest.raises(DBAPIError, match=why):
            c.execute(text(sql))
    assert pol.consistent(db, uuid.UUID(made_["id"]))


def test_the_document_and_its_dependency_rows_are_written_together_or_not_at_all(
    people: dict[str, TestClient], db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = people
    library(p)
    a, b = survey(p, "A"), survey(p, "B")
    made_ = made(p["author"], "ATOMIC", document(req("r1", ref("ilp"), a)))
    had = rows(db)
    real = pol._write_dependencies  # noqa: SLF001

    def fails(dbx: Any, pid: Any, snapshot: Any) -> None:
        real(dbx, pid, snapshot)
        raise pol.SurveyError(500, "FORCED", "a failure after the document and the rows were written")

    monkeypatch.setattr(pol, "_write_dependencies", fails)
    r = save(p["author"], made_["id"], 1, document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b)))
    assert r.status_code == 500 and r.json()["code"] == "FORCED"
    monkeypatch.undo()
    assert (
        rows(db) == had and read(p["reader"], made_["id"])["draft_revision"] == 1
    )  # document, rows and history: none of it
    assert pol.consistent(db, uuid.UUID(made_["id"]))
    two = save(
        p["author"], made_["id"], 1, document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b))
    ).json()
    assert pol.consistent(db, uuid.UUID(made_["id"])) and len(two["snapshot"]["dependencies"]) == 7
    n = db.execute(
        text("SELECT count(*) FROM applicability_policy_dependency WHERE policy_id = :p"), {"p": made_["id"]}
    ).scalar_one()
    assert n == 7


# -------------------------------------------------------------------------------------------------------- migration
def _head(engine: Engine) -> str:
    with engine.connect() as c:
        return str(c.execute(text(f"SELECT version_num FROM {T}.alembic_version")).scalar_one())


def _objects(engine: Engine) -> tuple[list[str], list[str]]:
    with engine.connect() as c:
        tables = sorted(
            c.execute(
                text(
                    f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_name LIKE 'applicability_policy%'"
                )
            ).scalars()
        )
        functions = sorted(
            c.execute(
                text(
                    f"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{T}' AND p.proname LIKE 'applicability_policy%'"
                )
            ).scalars()
        )
    return tables, functions


def _everything_else(engine: Engine) -> dict[str, tuple[int, str]]:
    out: dict[str, tuple[int, str]] = {}
    with engine.connect() as c:
        names = c.execute(
            text(
                f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_type = 'BASE TABLE' AND table_name NOT LIKE 'applicability_policy%' AND table_name <> 'alembic_version'"
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


def test_zz_migration_0039_is_additive_reversible_while_empty_atomic_and_keeps_saved_policies(
    fresh_schema: None, engine: Engine, settings: Settings, x3_app: Any, db: Session
) -> None:
    """On a POPULATED schema: seeded data, accounts, a published survey and a published applicability library."""
    grants = {"author": {"applicability.read", "applicability.edit", "survey.read"}, "checker": {"applicability.read", "applicability.approve"},
              "publisher": {"applicability.read", "applicability.publish"}, "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY)}  # fmt: skip
    accounts = {k: make_account(db, prefix=f"zx3{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    p = {k: _client(x3_app, a) for k, a in accounts.items()}
    try:
        library(p)
        a = survey(p, "A")
        assert _head(engine) == MIGRATION_HEAD
        full = _objects(engine)
        assert full == (
            list(reversed(TABLES)) and sorted(TABLES),
            ["applicability_policy_dependency_guard", "applicability_policy_event_guard", "applicability_policy_guard"],
        )
        before = _everything_else(engine)
        assert (
            before["applicability_asset_version"][0] == 5
            and before["survey_version"][0] == 1
            and before["permission"][0] > 0
        )
        # 1. downgrade while empty removes exactly the three tables and three guards; nothing else changes — no permission either
        migrate(settings, "0038_applicability_library", down=True)
        assert (
            _head(engine) == "0038_applicability_library"
            and _objects(engine) == ([], [])
            and _everything_else(engine) == before
        )
        # 2. a forced failure at the LAST statement, after every table, index and the other guards were created: all rolled back
        with engine.begin() as c:
            c.execute(
                text(
                    f"CREATE FUNCTION {T}.applicability_policy_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                )
            )
        with pytest.raises(DBAPIError, match="already exists"):
            migrate(settings, "head")
        assert _head(engine) == "0038_applicability_library" and _objects(engine) == (
            [],
            ["applicability_policy_event_guard"],
        )
        with engine.begin() as c:
            c.execute(text(f"DROP FUNCTION {T}.applicability_policy_event_guard()"))
        assert _everything_else(engine) == before
        # 3. upgrade again: identical objects; every other table byte-identical — the library and Survey Studio included
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD and _objects(engine) == full and _everything_else(engine) == before
        # 4. with a saved policy the downgrade is refused and nothing is lost
        kept = made(p["author"], "KEPT", document(req("r1", ref("ilp"), a)))
        with pytest.raises(RuntimeError, match="applicability policies exist"):
            migrate(settings, "0038_applicability_library", down=True)
        assert _head(engine) == MIGRATION_HEAD and read(p["author"], kept["id"])["document"] == kept["document"]
        assert pol.consistent(db, uuid.UUID(kept["id"]))
        after = _everything_else(engine)
        assert {k for k in before if before[k] != after[k]} <= {
            "audit_event"
        }  # saving a policy writes its own tables and the audit trail only
    finally:
        for c in p.values():
            c.__exit__(None, None, None)
        for a_ in accounts.values():
            GRANTS.pop(a_.principal_id, None)
