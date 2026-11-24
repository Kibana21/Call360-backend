# ruff: noqa: E501, F811 — long request literals; fixtures imported from the library test module
"""APPL-X4a — saved synthetic scenarios, regression suites and immutable recorded evaluation runs, on the isolated
test database.

A scenario is saved and reopened exactly as it was, with the exact definitions it was saved against · a newer
published version never moves it; adopting one is deliberate · a variant is a real saved scenario · a suite holds
EXPECTED outcomes that a person confirmed, never derived by the server · a run records the exact policy revision,
every scenario and every result, immutably, and can be re-evaluated from the record alone · failure is explained and
never repaired silently · inability to evaluate is never a pass · markets, permissions and CSRF are enforced · nothing
operational is written · and the migration is additive, reversible while empty, atomic and refuses to destroy evidence.
"""

from __future__ import annotations

import copy
import time
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
from app.domain.survey.applicability import scenarios as sc
from app.domain.survey.applicability.logic import Workspace
from app.domain.survey.canonical import sha256_hex
from app.main import MIGRATION_HEAD, acceptable_migration_heads, create_app
from tests.support import ORIGIN, csrf_header, make_account, migrate
from tests.test_applicability_library import BOOL, FAMILY, A, check, created, get, published, ref, revise
from tests.test_applicability_library import put as put_asset
from tests.test_applicability_policies import P as POLICIES
from tests.test_applicability_policies import document, made, req, survey
from tests.test_applicability_policies import read as read_policy
from tests.test_applicability_policies import save as save_policy
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants

S, U, R = f"{A}/scenarios", f"{A}/suites", f"{A}/runs"
T = "call360_test"
SURVEY = {"survey.read", "survey.edit", "survey.approve", "survey.publish"}
TABLES = (
    "applicability_evaluation_result", "applicability_evaluation_run", "applicability_scenario", "applicability_scenario_dependency",
    "applicability_scenario_event", "applicability_suite", "applicability_suite_member",
)  # fmt: skip
FUNCTIONS = [
    "applicability_evaluation_guard", "applicability_evaluation_result_guard", "applicability_scenario_dependency_guard",
    "applicability_scenario_event_guard", "applicability_scenario_guard", "applicability_suite_member_guard",
]  # fmt: skip
COMMON = {"name": "Common application", "sections": [{"name": "Core", "variables": ["product_family", "nftf"]}]}


@pytest.fixture()
def x4_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(
            settings.model_copy(
                update={
                    "applicability_library_enabled": True, "applicability_policies_enabled": True, "applicability_scenarios_enabled": True,
                    "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_applicability_prototype_enabled": True,
                    "transcription_worker": False, "survey_writes_per_minute": 100_000, "survey_simulation_inputs_per_minute": 100_000,
                }
            )
        )
    )  # fmt: skip


@pytest.fixture(autouse=True)
def empty(engine: Engine) -> None:
    """Every test starts with no scenario, suite, run or policy and an empty library (TEST schema only)."""
    with engine.begin() as c:
        for table in ("applicability_policy", "applicability_asset"):
            if c.execute(text(f"SELECT to_regclass('{T}.{table}')")).scalar_one() is not None:
                c.execute(text(f"TRUNCATE {T}.{table} CASCADE"))


@pytest.fixture()
def people(x4_app: Any, db: Session) -> Iterator[dict[str, TestClient]]:
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {
        "author": edit, "second": edit, "checker": {"applicability.read", "applicability.approve", "survey.read"},
        "publisher": {"applicability.read", "applicability.publish", "survey.read"}, "reader": {"applicability.read", "survey.read"},
        "no_survey": {"applicability.read", "applicability.edit"}, "survey_only": set(SURVEY), "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY),
    }  # fmt: skip
    accounts = {k: make_account(db, prefix=f"x4{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    clients = {k: _client(x4_app, a) for k, a in accounts.items()}
    yield clients
    for c in clients.values():
        c.__exit__(None, None, None)
    for a in accounts.values():
        GRANTS.pop(a.principal_id, None)
        MARKETS.pop(a.principal_id, None)


def world(p: dict[str, TestClient]) -> dict[str, Any]:
    """A published library, three REAL published surveys and a saved policy: ILP → A, NFTF → B, both → C replacing A and B."""
    published(p, "VARIABLE", "product_family", FAMILY)
    published(p, "VARIABLE", "nftf", BOOL)
    published(p, "CONDITION", "ilp", {"name": "Is ILP", "expr": check("product_family", "equals", value="ILP")})
    published(p, "CONDITION", "nftf_applies", {"name": "NFTF applies", "expr": check("nftf")})
    profile = published(p, "PROFILE", "common", COMMON)
    a, b, c = (survey(p, x) for x in "ABC")
    both = {"op": "all", "args": [ref("ilp"), ref("nftf_applies")]}
    additive = document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b), req("r3", both, c))
    policy = made(p["author"], "ILP-NFTF", additive)
    return {"a": a, "b": b, "c": c, "policy": policy, "profile": profile, "additive": additive,
            "replacing": document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b), req("r3", both, c, replaces=("r1", "r2")))}  # fmt: skip


def scenario(c: TestClient, code: str, facts: dict[str, Any], *, name: str | None = None, profiles: tuple[str, ...] = ("common",), market: str = "SG", **more: Any) -> Any:  # fmt: skip
    return post(c, S, {"market_code": market, "code": code, "document": {"name": name or f"Scenario {code}", "description": "synthetic", "profiles": list(profiles), "facts": facts}, **more})  # fmt: skip


def saved(c: TestClient, code: str, facts: dict[str, Any], **more: Any) -> dict[str, Any]:
    r = scenario(c, code, facts, **more)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def put(c: TestClient, path: str, body: dict[str, Any]) -> Any:
    return c.put(path, json=body, headers=csrf_header(c))


def expect(status: str, *surveys: dict[str, Any], pending: tuple[str, ...] = (), **more: Any) -> dict[str, Any]:
    return {"status": status, "selected": [{"code": s["code"], "version": s["version"], "name": s["name"]} for s in surveys], "pending": list(pending), "confirmed": True, **more}  # fmt: skip


def suite(c: TestClient, code: str, policy_id: str, members: list[tuple[dict[str, Any], dict[str, Any] | None]], purpose: str = "PUBLICATION_GATING") -> dict[str, Any]:  # fmt: skip
    r = post(c, U, {"market_code": "SG", "code": code, "policy_id": policy_id, "document": {"name": f"Suite {code}"}, "purpose": purpose,
                    "members": [{"scenario_id": s["id"], "expectation": e} for s, e in members]})  # fmt: skip
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def run(c: TestClient, suite_id: str, key: str | None = None) -> dict[str, Any]:
    r = post(c, f"{U}/{suite_id}/runs", {"idempotency_key": key or f"run-{uuid.uuid4()}"})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def outcomes(run_: dict[str, Any]) -> dict[str, str]:
    return {x["scenario_code"]: x["outcome"] for x in run_["results"]}


def five(p: dict[str, TestClient], w: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "ilp": saved(p["author"], "ILP-ONLY", {"product_family": "ILP", "nftf": False}),
        "nftf": saved(p["author"], "NFTF-ONLY", {"product_family": "PROTECTION", "nftf": True}),
        "both": saved(p["author"], "BOTH", {"product_family": "ILP", "nftf": True}),
        "neither": saved(p["author"], "NEITHER", {"product_family": "PROTECTION", "nftf": False}),
        "unknown": saved(p["author"], "NFTF-UNKNOWN", {"product_family": "ILP", "nftf": None}),
    }


def everything_else(engine: Engine) -> dict[str, tuple[int, str]]:
    """Row count and content digest of every table that is NOT one of this checkpoint's own."""
    out: dict[str, tuple[int, str]] = {}
    with engine.connect() as c:
        names = c.execute(
            text(
                f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_type = 'BASE TABLE' AND table_name <> 'alembic_version'"
            )
        ).scalars()
        for name in sorted(n for n in names if n not in TABLES):
            row = c.execute(
                text(
                    f"SELECT count(*), coalesce(md5(string_agg(md5(t::text), '' ORDER BY md5(t::text))), '') FROM {T}.\"{name}\" t"
                )
            ).one()  # noqa: S608
            out[name] = (row[0], row[1])
    return out


# ------------------------------------------------------------------------------------------------------- the gate
def test_off_by_default_and_twenty_two_operations_with_no_new_permission(settings: Settings, x4_app: Any, people: dict[str, TestClient], engine: Engine) -> None:  # fmt: skip
    def routes(app: Any) -> set[tuple[str, str]]:
        return {(m.upper(), path) for path, ops in app.openapi()["paths"].items() for m in ops if any(path.startswith(f"{A}/{x}") for x in ("scenarios", "suites", "runs"))}  # fmt: skip

    assert settings.applicability_scenarios_enabled is False
    off = settings.model_copy(update={"transcription_worker": False})
    assert not routes(create_app(off))
    # scenarios are evaluated against saved policies: without policies there is nothing to add
    assert not routes(
        create_app(
            off.model_copy(update={"applicability_library_enabled": True, "applicability_scenarios_enabled": True})
        )
    )
    assert len(routes(x4_app)) == 22, sorted(routes(x4_app))
    on = settings.model_copy(
        update={
            "applicability_library_enabled": True,
            "applicability_policies_enabled": True,
            "applicability_scenarios_enabled": True,
        }
    )
    assert MIGRATION_HEAD == "0040_applicability_scenarios" and acceptable_migration_heads(on) == (MIGRATION_HEAD,)
    # with scenarios off, a schema still at 0039 serves saved policies correctly
    assert acceptable_migration_heads(on.model_copy(update={"applicability_scenarios_enabled": False})) == (
        MIGRATION_HEAD,
        "0039_applicability_policy",
    )
    with engine.connect() as c:
        assert (
            c.execute(text(f"SELECT count(*) FROM {T}.permission WHERE code LIKE 'applicability.%'")).scalar_one() == 4
        )  # none added
    with TestClient(x4_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as anonymous:
        assert [anonymous.get(x).status_code for x in (S, U, R)] == [401, 401, 401]
    p = people
    for path in (S, U, R):
        assert p["reader"].get(path).status_code == 200
        assert p["no_survey"].get(path).status_code == 403  # survey.read is an explicit dependency
        assert p["survey_only"].get(path).status_code == 403


# ------------------------------------------------------------------------------------------------------ scenarios
def test_a_scenario_is_saved_and_reopened_exactly_with_its_exact_dependencies(people: dict[str, TestClient], db: Session, engine: Engine) -> None:  # fmt: skip
    p = people
    w = world(p)
    s = saved(p["author"], "ILP-ONLY", {"product_family": "ILP", "nftf": False}, policy_id=w["policy"]["id"])
    assert (
        s["record_class"] == "SYNTHETIC"
        and s["purpose"] == "REGRESSION"
        and s["draft_revision"] == 1
        and s["facts"] == 2
    )
    # the document carries the pins the server resolved: every variable a fact is given for, and the profile
    assert s["document"]["pins"] == [{"kind": "PROFILE", "code": "common", "version": 1}, {"kind": "VARIABLE", "code": "nftf", "version": 1}, {"kind": "VARIABLE", "code": "product_family", "version": 1}]  # fmt: skip
    deps = {(e["kind"], e["code"]): e for e in s["snapshot"]["dependencies"]}
    assert set(deps) == {("PROFILE", "common"), ("VARIABLE", "nftf"), ("VARIABLE", "product_family")}
    for e in deps.values():  # identity, version and BOTH fingerprints of each published dependency
        assert e["state"] == "PUBLISHED" and {
            "asset_id",
            "version_id",
            "version_no",
            "content_sha256",
            "manifest_sha256",
        } <= set(e)
    assert (
        s["inspection"]["reproducible"] is True
        and s["snapshot_sha256"] == sha256_hex(s["snapshot"])
        and s["document_sha256"] == sha256_hex(s["document"])
    )
    # the rows ARE the snapshot, with foreign keys to the library
    with engine.connect() as c:
        rows = c.execute(text(f"SELECT d.kind, d.code, d.version_no, d.content_sha256, v.status FROM {T}.applicability_scenario_dependency d JOIN {T}.applicability_asset_version v ON v.id = d.asset_version_id WHERE d.scenario_id = :s ORDER BY 1, 2"), {"s": s["id"]}).all()  # fmt: skip
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == sorted(
        (e["kind"], e["code"], e["version_no"], e["content_sha256"]) for e in deps.values()
    )
    # a later session, another person: byte-identical document, snapshot and fingerprints
    again = p["reader"].get(f"{S}/{s['id']}").json()
    assert (again["document"], again["snapshot"], again["scenario_fingerprint"]) == (
        s["document"],
        s["snapshot"],
        s["scenario_fingerprint"],
    )
    assert [e["event"] for e in again["events"]] == ["CREATED"] and again["events"][0]["actor"].startswith(
        "Test X4Author"
    )
    # explicit UNKNOWN (null) and NOT PROVIDED (absent) are different, stored states
    u = saved(p["author"], "UNKNOWN", {"product_family": "ILP", "nftf": None})
    n = saved(p["author"], "NOT-GIVEN", {"product_family": "ILP"})
    assert u["document"]["facts"] == {"nftf": None, "product_family": "ILP"} and u["unknown_facts"] == 1
    assert n["document"]["facts"] == {"product_family": "ILP"} and ("VARIABLE", "nftf") not in {
        (e["kind"], e["code"]) for e in n["snapshot"]["dependencies"]
    }
    # ---- a NEWER published version never moves a saved scenario; adopting it is a deliberate edit
    revise(p, w["profile"]["id"], {**COMMON, "name": "Common application (revised)"})
    family = next(
        x for x in p["author"].get(f"{A}/assets?kind=VARIABLE").json()["items"] if x["code"] == "product_family"
    )
    revise(p, family["id"], {**FAMILY, "values": [*FAMILY["values"], {"value": "HEALTH", "label": "Health"}]})
    kept = p["author"].get(f"{S}/{s['id']}").json()
    assert (kept["snapshot"], kept["scenario_fingerprint"], kept["draft_revision"]) == (
        s["snapshot"],
        s["scenario_fingerprint"],
        1,
    )
    newer = {(e["kind"], e["code"]): e.get("newer_version_no") for e in kept["inspection"]["dependencies"]}
    assert newer == {("PROFILE", "common"): 2, ("VARIABLE", "product_family"): 2, ("VARIABLE", "nftf"): None}
    assert {d["code"] for d in kept["inspection"]["diagnostics"]} == {"NEWER_VERSION"}
    adopted = copy.deepcopy(kept["document"])
    next(x for x in adopted["pins"] if x["code"] == "common")["version"] = 2
    r = put(
        p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 1, "document": adopted, "note": "adopt profile v2"}
    )
    assert (
        r.status_code == 200 and r.json()["draft_revision"] == 2 and r.json()["snapshot_sha256"] != s["snapshot_sha256"]
    )
    assert next(e for e in r.json()["snapshot"]["dependencies"] if e["code"] == "common")["version_no"] == 2
    assert (
        next(e for e in r.json()["snapshot"]["dependencies"] if e["code"] == "product_family")["version_no"] == 1
    )  # not adopted, not moved
    # … and undoing the adoption is the same kind of edit: the earlier snapshot fingerprint comes back exactly
    back = put(p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 2, "document": kept["document"]})
    assert (
        back.status_code == 200
        and back.json()["snapshot_sha256"] == s["snapshot_sha256"]
        and back.json()["draft_revision"] == 3
    )
    # an invalid pin, a stale revision and an unchanged save are refused; nothing is written
    bad = copy.deepcopy(kept["document"])
    bad["pins"][0]["version"] = 9
    assert (
        put(p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 3, "document": bad}).json()["code"]
        == "INVALID_DEPENDENCY_PIN"
    )
    assert (
        put(p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 1, "document": adopted}).json()["code"]
        == "STALE_REVISION"
    )
    assert (
        put(p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 3, "document": kept["document"]}).json()["code"]
        == "NOTHING_CHANGED"
    )
    assert scenario(p["author"], "GHOST", {"no_such_variable": True}).json()["code"] == "UNKNOWN_REFERENCE"
    assert scenario(p["author"], "ilp-only", {}).json()["code"] == "CODE_TAKEN"
    assert p["author"].get(f"{S}/{s['id']}").json()["draft_revision"] == 3


def test_variants_purposes_listing_and_synthetic_only(people: dict[str, TestClient]) -> None:
    p = people
    w = world(p)
    base = saved(
        p["author"], "BOTH", {"product_family": "ILP", "nftf": True}, name="ILP + NFTF", policy_id=w["policy"]["id"]
    )
    v1 = saved(
        p["author"],
        "BOTH-ILP-ONLY",
        {"product_family": "ILP", "nftf": False},
        name="ILP only",
        baseline_id=base["id"],
        policy_id=w["policy"]["id"],
        origin=f"VARIANT:{base['code']}",
    )
    v2 = saved(
        p["author"],
        "BOTH-NFTF-UNKNOWN",
        {"product_family": "ILP", "nftf": None},
        name="NFTF unknown",
        baseline_id=base["id"],
        purpose="EXPLORATORY",
    )
    # a variant is a genuine saved scenario that knows its baseline
    assert v1["baseline"]["code"] == "BOTH" and v1["baseline"]["facts"] == {"nftf": True, "product_family": "ILP"}
    assert {x["code"] for x in p["author"].get(f"{S}/{base['id']}").json()["variant_list"]} == {
        "BOTH-ILP-ONLY",
        "BOTH-NFTF-UNKNOWN",
    }
    cmp_ = post(
        p["reader"], f"{S}/compare", {"policy_id": w["policy"]["id"], "before_id": base["id"], "after_id": v1["id"]}
    ).json()
    assert cmp_["facts_changed"] == [
        {"variable": "nftf", "before": True, "after": False, "before_given": True, "after_given": True}
    ]
    assert sorted(cmp_["comparison"]["removed"]) == ["Survey B", "Survey C"] and cmp_["comparison"]["added"] == []
    assert {b["requirement"] for b in cmp_["comparison"]["because"]} == {"r2", "r3"}
    # listing: paged, filtered, searched; nothing is evaluated to list
    page = p["reader"].get(f"{S}?limit=2").json()
    assert (
        page["total"] == 3
        and len(page["items"]) == 2
        and p["reader"].get(f"{S}?limit=2&offset=2").json()["items"][0]["code"]
        not in {x["code"] for x in page["items"]}
    )
    assert [x["code"] for x in p["reader"].get(f"{S}?q=unknown").json()["items"]] == ["BOTH-NFTF-UNKNOWN"]
    assert {x["code"] for x in p["reader"].get(f"{S}?baseline_id={base['id']}").json()["items"]} == {
        "BOTH-ILP-ONLY",
        "BOTH-NFTF-UNKNOWN",
    }
    assert [x["code"] for x in p["reader"].get(f"{S}?purpose=EXPLORATORY").json()["items"]] == ["BOTH-NFTF-UNKNOWN"]
    assert {x["code"] for x in p["reader"].get(f"{S}?policy_id={w['policy']['id']}").json()["items"]} == {
        "BOTH",
        "BOTH-ILP-ONLY",
    }
    assert next(x for x in p["reader"].get(S).json()["items"] if x["code"] == "BOTH")["variants"] == 2
    # ---- a publication-gating suite holds regression scenarios only; an exploratory suite may hold either
    r = post(
        p["author"],
        U,
        {
            "market_code": "SG",
            "code": "GATE",
            "policy_id": w["policy"]["id"],
            "document": {"name": "Gate"},
            "members": [{"scenario_id": v2["id"]}],
        },
    )
    assert r.status_code == 409 and r.json()["code"] == "EXPLORATORY_IN_GATING_SUITE"
    gate = suite(p["author"], "GATE", w["policy"]["id"], [(base, None), (v1, None)])
    suite(p["author"], "EXPLORE", w["policy"]["id"], [(v2, None), (base, None)], purpose="EXPLORATORY")
    r = put(
        p["author"],
        f"{S}/{base['id']}/draft",
        {"expected_revision": 1, "document": base["document"], "purpose": "EXPLORATORY"},
    )
    assert r.status_code == 409 and r.json()["code"] == "IN_GATING_SUITE"
    assert (
        post(
            p["author"], f"{S}/{base['id']}/archive", {"expected_revision": 1, "reason": "no longer needed here"}
        ).json()["code"]
        == "IN_SUITE"
    )
    assert p["author"].get(f"{S}/{base['id']}").json()["suite_list"] == [{"id": mock, "code": c, "name": n, "purpose": pu} for mock, c, n, pu in [(p["author"].get(U).json()["items"][0]["id"], "EXPLORE", "Suite EXPLORE", "EXPLORATORY"), (gate["id"], "GATE", "Suite GATE", "PUBLICATION_GATING")]]  # fmt: skip
    # ---- archive and restore: never deleted; a reason is required
    lone = saved(p["author"], "LONE", {"nftf": True})
    assert (
        post(p["author"], f"{S}/{lone['id']}/archive", {"expected_revision": 1, "reason": "short"}).json()["code"]
        == "COMMENT_REQUIRED"
    )
    assert (
        post(
            p["author"], f"{S}/{lone['id']}/archive", {"expected_revision": 1, "reason": "made by mistake, not needed"}
        ).json()["state"]
        == "ARCHIVED"
    )
    assert "LONE" not in {x["code"] for x in p["reader"].get(S).json()["items"]} and [
        x["code"] for x in p["reader"].get(f"{S}?archived=true").json()["items"]
    ] == ["LONE"]
    assert (
        put(
            p["author"],
            f"{S}/{lone['id']}/draft",
            {"expected_revision": 1, "document": {**lone["document"], "name": "x2"}},
        ).json()["code"]
        == "ARCHIVED"
    )
    back = post(p["author"], f"{S}/{lone['id']}/restore", {"expected_revision": 1}).json()
    assert back["state"] == "DRAFT" and [e["event"] for e in back["events"]] == ["CREATED", "ARCHIVED", "RESTORED"]
    # ---- synthetic only: nothing that looks like a real person or contract is accepted, in any text field
    for name, facts in (
        ("Mrs Tan S1234567D", {}),
        ("Call tan.ah.kow@example.com", {}),
        ("Policy P12345670", {}),
        ("Phone 91234567", {}),
    ):
        assert scenario(p["author"], "REAL", facts, name=name).json()["code"] == "LOOKS_LIKE_REAL_DATA", name
    assert (
        post(
            p["author"],
            S,
            {
                "market_code": "SG",
                "code": "REAL",
                "document": {"name": "ok name", "description": "see S7654321Z", "facts": {}},
            },
        ).json()["code"]
        == "LOOKS_LIKE_REAL_DATA"
    )
    assert "REAL" not in {x["code"] for x in p["reader"].get(S).json()["items"]}
    # the document has no field for a customer, an operational policy, a case or a session: anything else is dropped
    extra = post(
        p["author"],
        S,
        {
            "market_code": "SG",
            "code": "EXTRA",
            "document": {
                "name": "Extra fields",
                "facts": {},
                "customer_id": "C-1",
                "case_id": "X",
                "session_id": "Y",
                "policy_number": "Z",
            },
        },
    ).json()
    assert sorted(extra["document"]) == ["description", "facts", "name", "pins", "profiles"]


def test_evaluation_is_the_python_evaluators_and_says_exactly_what_it_evaluated(people: dict[str, TestClient]) -> None:
    p = people
    w = world(p)
    pid = w["policy"]["id"]
    s = five(p, w)

    def ask(*items: dict[str, Any], **more: Any) -> dict[str, Any]:
        r = post(p["reader"], f"{S}/evaluate", {"policy_id": pid, "scenarios": list(items), **more})
        assert r.status_code == 200, r.text
        return r.json()  # type: ignore[no-any-return]

    out = ask(*({"scenario_id": x["id"]} for x in s.values()))
    assert out["policy_source"] == "SAVED" and out["status"] == "OK" and out["policy_revision"] == 1
    got = {
        r["scenario_code"]: (
            r["plan"]["status"],
            [e["survey"]["name"][-1] for e in r["plan"]["selected"]],
            [e["survey"]["name"][-1] for e in r["plan"]["pending"]],
        )
        for r in out["results"]
    }
    assert got == {"ILP-ONLY": ("RESOLVED", ["A"], []), "NFTF-ONLY": ("RESOLVED", ["B"], []), "BOTH": ("RESOLVED", ["A", "B", "C"], []),
                   "NEITHER": ("RESOLVED", [], []), "NFTF-UNKNOWN": ("UNRESOLVED", ["A"], ["B", "C"])}  # fmt: skip
    assert all(
        r["mode"] == "SAVED_SCENARIO" and r["reproducible"] and r["state"] == "EVALUATED" for r in out["results"]
    )
    # ---- the plan IS the evaluator's: the same workspace, document and facts through the evaluator directly, byte for byte
    insp = read_policy(p["reader"], pid)["inspection"]
    ws = Workspace({k: [x for x in v if not x.get("scenario_context")] for k, v in insp["workspace"].items()})
    edoc = {
        **{k: v for k, v in w["policy"]["document"].items() if k != "pins"},
        "code": "ILP-NFTF",
        "market": "SG",
        "version": 1,
        "status": "DRAFT",
    }
    for r in out["results"]:
        doc = next(x for x in s.values() if x["code"] == r["scenario_code"])["document"]
        assert E.evaluate(ws, edoc, doc["facts"], doc["profiles"]) == r["plan"]
    # ---- three-valued semantics: not known, not provided and invalid are three different states, none of them "false"
    odd = ask({"ref": "unknown", "document": {"name": "nftf not known", "facts": {"product_family": "ILP", "nftf": None}}},
              {"ref": "absent", "document": {"name": "nftf not given", "facts": {"product_family": "ILP"}}},
              {"ref": "invalid", "document": {"name": "nftf invalid", "facts": {"product_family": "ILP", "nftf": "maybe"}}},
              {"ref": "bad-enum", "document": {"name": "family invalid", "facts": {"product_family": "PETS", "nftf": True}}})  # fmt: skip
    by = {r["ref"]: r for r in odd["results"]}
    assert {k: v["plan"]["facts"]["nftf"]["state"] for k, v in by.items() if k != "bad-enum"} == {
        "unknown": "UNKNOWN",
        "absent": "NOT_PROVIDED",
        "invalid": "INVALID",
    }
    assert all(
        by[k]["plan"]["status"] == "UNRESOLVED" and [n["variable"] for n in by[k]["plan"]["needs"]] == ["nftf"]
        for k in ("unknown", "absent", "invalid")
    )
    assert (
        by["bad-enum"]["plan"]["facts"]["product_family"]["state"] == "INVALID"
        and by["bad-enum"]["plan"]["status"] == "UNRESOLVED"
    )
    assert "FACT_INVALID" in {d["code"] for d in by["invalid"]["diagnostics"]}
    # an unsaved scenario is EXPLORATORY and discloses exactly which definitions were resolved for it
    assert all(
        r["mode"] == "EXPLORATORY" and r["reproducible"] is False and r["scenario_id"] is None for r in odd["results"]
    )
    assert {(e["kind"], e["code"], e["version_no"]) for e in by["unknown"]["resolved"]} == {
        ("VARIABLE", "nftf", 1),
        ("VARIABLE", "product_family", 1),
    }
    assert (
        all(len(e["content_sha256"]) == 64 for e in by["unknown"]["resolved"])
        and len(by["unknown"]["scenario_fingerprint"]) == 64
    )
    # an unsaved edit of the POLICY is a preview and is marked as one
    preview = ask({"scenario_id": s["both"]["id"]}, policy_document=w["replacing"])
    assert (
        preview["policy_source"] == "PREVIEW"
        and preview["policy_document_sha256"] is None
        and preview["results"][0]["reproducible"] is False
    )
    assert [e["survey"]["name"][-1] for e in preview["results"][0]["plan"]["selected"]] == ["C"]
    # too many at once is refused with a pointer to suites; nothing is stored by any of this
    assert (
        post(
            p["reader"],
            f"{S}/evaluate",
            {"policy_id": pid, "scenarios": [{"document": {"name": "xx", "facts": {}}}] * 61},
        ).status_code
        == 422
    )
    assert p["reader"].get(R).json()["total"] == 0


# ---------------------------------------------------------------------------------------------- suites and runs
def test_suite_expectations_are_stated_by_a_person_and_a_run_passes_fails_and_explains(people: dict[str, TestClient], engine: Engine) -> None:  # fmt: skip
    p = people
    w = world(p)
    a, b, c = w["a"], w["b"], w["c"]
    s = five(p, w)
    # an expectation must be confirmed by the person; the server never invents one
    r = post(p["author"], U, {"market_code": "SG", "code": "SHOW", "policy_id": w["policy"]["id"], "document": {"name": "Showcase"},
                              "members": [{"scenario_id": s["ilp"]["id"], "expectation": {"status": "RESOLVED", "selected": [{"code": a["code"]}]}}]})  # fmt: skip
    assert r.status_code == 422 and r.json()["code"] == "EXPECTATION_NOT_CONFIRMED"
    assert post(p["author"], U, {"market_code": "SG", "code": "SHOW", "policy_id": w["policy"]["id"], "document": {"name": "Showcase"},
                                 "members": [{"scenario_id": s["ilp"]["id"], "expectation": {"status": "FINE", "confirmed": True}}]}).json()["code"] == "INVALID_EXPECTATION"  # fmt: skip
    u = suite(p["author"], "SHOW", w["policy"]["id"], [
        (s["ilp"], expect("RESOLVED", a)), (s["nftf"], expect("RESOLVED", b)), (s["both"], expect("RESOLVED", a, b, c)), (s["neither"], expect("RESOLVED")),
        (s["unknown"], expect("UNRESOLVED", a, pending=(b["code"], c["code"]), needs=["nftf"])),
    ])  # fmt: skip
    assert u["members"] == 5 and u["with_expectation"] == 5 and u["diagnostics"] == [] and u["last_run"] is None
    assert [m["code"] for m in u["member_list"]] == ["ILP-ONLY", "NFTF-ONLY", "BOTH", "NEITHER", "NFTF-UNKNOWN"]
    assert all(
        m["expectation"]["source"] == "AUTHORED" and m["expectation"]["reviewed_at_revision"] == 1
        for m in u["member_list"]
    )
    first = run(p["author"], u["id"], "key-first-run")
    assert (
        first["status"] == "PASSED"
        and (first["scenarios"], first["passed"], first["failed"]) == (5, 5, 0)
        and first["replayed"] is False
    )
    assert set(outcomes(first).values()) == {"PASSED"}  # a deliberately expected UNRESOLVED result is a legitimate pass
    assert first["record_class"] == "SYNTHETIC" and first["policy_revision"] == 1 and first["suite_revision"] == 1
    # the same key returns the SAME recorded run; nothing is recorded twice
    again = run(p["author"], u["id"], "key-first-run")
    assert (
        again["id"] == first["id"]
        and again["replayed"] is True
        and p["reader"].get(f"{R}?suite_id={u['id']}").json()["total"] == 1
    )
    # ---- an intentionally wrong expectation FAILS and says exactly how
    members = [{"scenario_id": m["scenario_id"], "expectation": m["expectation"]} for m in u["member_list"]]
    wrong = copy.deepcopy(members)
    wrong[0]["expectation"] = expect("RESOLVED", b)  # ILP only is expected to select B: wrong on purpose
    u2 = put(
        p["author"],
        f"{U}/{u['id']}/draft",
        {
            "expected_revision": 1,
            "document": {"name": "Suite SHOW"},
            "purpose": "PUBLICATION_GATING",
            "members": wrong,
            "note": "a deliberately wrong expectation",
        },
    ).json()
    assert u2["draft_revision"] == 2
    failed = run(p["author"], u["id"])
    assert (
        failed["status"] == "FAILED"
        and (failed["passed"], failed["failed"]) == (4, 1)
        and outcomes(failed)["ILP-ONLY"] == "FAILED"
    )
    diffs = failed["results"][0]["differences"]
    assert [(d["kind"], d["survey"]) for d in diffs] == [
        ("SURVEY_MISSING", b["code"]),
        ("SURVEY_UNEXPECTED", a["code"]),
    ]
    assert diffs[0]["text"] == "Expected 'Survey B' to be selected; it is not selected" and diffs[0][
        "requirements"
    ] == ["r2"]
    assert diffs[1]["text"] == "'Survey A' is selected and was not expected" and diffs[1]["requirements"] == ["r1"]
    assert failed["results"][0]["actual"] == {
        "status": "RESOLVED",
        "selected": [{"code": a["code"], "version": a["version"], "name": "Survey A"}],
        "pending": [],
    }
    # the failing run changed NOTHING in the suite: the wrong expectation is still the wrong expectation
    still = p["author"].get(f"{U}/{u['id']}").json()
    assert (
        still["draft_revision"] == 2
        and still["member_list"][0]["expectation"]["selected"][0]["code"] == b["code"]
        and still["last_run"]["status"] == "FAILED"
    )
    assert p["reader"].get(f"{R}/{failed['id']}?outcome=FAILED").json()["results_total"] == 1
    # the person corrects it explicitly; a new run passes; the earlier runs are untouched
    fixed = put(
        p["author"],
        f"{U}/{u['id']}/draft",
        {
            "expected_revision": 2,
            "document": {"name": "Suite SHOW"},
            "purpose": "PUBLICATION_GATING",
            "members": members,
        },
    ).json()
    assert fixed["draft_revision"] == 3 and fixed["events"][-1]["detail"]["expectations_changed"] == [s["ilp"]["id"]]
    third = run(p["author"], u["id"])
    assert third["status"] == "PASSED" and p["reader"].get(f"{R}/{failed['id']}").json()["status"] == "FAILED"
    assert [x["status"] for x in p["reader"].get(f"{R}?suite_id={u['id']}").json()["items"]] == [
        "PASSED",
        "FAILED",
        "PASSED",
    ]
    # ---- "use the current result" is the client's proposal; when stated it is recorded as such, and still needs confirming
    proposed = copy.deepcopy(members)
    proposed[1]["expectation"] = {**expect("RESOLVED", b), "source": "PROPOSED_FROM_RESULT"}
    done = put(
        p["author"],
        f"{U}/{u['id']}/draft",
        {
            "expected_revision": 3,
            "document": {"name": "Suite SHOW"},
            "purpose": "PUBLICATION_GATING",
            "members": proposed,
        },
    ).json()
    assert done["member_list"][1]["expectation"]["source"] == "PROPOSED_FROM_RESULT" and done["events"][-1]["detail"][
        "proposed_from_result"
    ] == [s["nftf"]["id"]]
    # ---- a member without an expectation can neither pass nor fail; the run says the definition is invalid
    lax = suite(p["author"], "LAX", w["policy"]["id"], [(s["ilp"], expect("RESOLVED", a)), (s["both"], None)])
    assert [d["code"] for d in lax["diagnostics"]] == ["NO_EXPECTATION"]
    undefined = run(p["author"], lax["id"])
    assert (
        undefined["status"] == "INVALID_DEFINITION"
        and outcomes(undefined) == {"ILP-ONLY": "PASSED", "BOTH": "NO_EXPECTATION"}
        and undefined["no_expectation"] == 1
    )
    empty = suite(p["author"], "EMPTY", w["policy"]["id"], [])
    assert (
        post(p["author"], f"{U}/{empty['id']}/runs", {"idempotency_key": "empty-suite-run"}).json()["code"]
        == "EMPTY_SUITE"
    )
    # ---- when the scenario changes after its expectation was reviewed, the suite says so
    put(
        p["author"],
        f"{S}/{s['ilp']['id']}/draft",
        {"expected_revision": 1, "document": {**s["ilp"]["document"], "description": "changed"}},
    )
    moved = p["author"].get(f"{U}/{u['id']}").json()
    assert moved["member_list"][0]["scenario_changed"] is True and [d["code"] for d in moved["diagnostics"]] == [
        "SCENARIO_CHANGED"
    ]
    # ---- the database itself refuses to change or delete evidence, or to add a result to a recorded run
    with engine.connect() as cx:
        for sql in (f"UPDATE {T}.applicability_evaluation_run SET status = 'PASSED' WHERE id = '{failed['id']}'", f"DELETE FROM {T}.applicability_evaluation_run WHERE id = '{failed['id']}'",
                    f"UPDATE {T}.applicability_evaluation_result SET outcome = 'PASSED' WHERE run_id = '{failed['id']}'", f"DELETE FROM {T}.applicability_evaluation_result WHERE run_id = '{failed['id']}'",
                    f"INSERT INTO {T}.applicability_evaluation_result (run_id, position, scenario_id, scenario_code, scenario_name, scenario_revision, scenario_document, scenario_snapshot, scenario_document_sha256, scenario_snapshot_sha256, outcome) "
                    f"SELECT run_id, 99, scenario_id, scenario_code, scenario_name, scenario_revision, scenario_document, scenario_snapshot, scenario_document_sha256, scenario_snapshot_sha256, 'PASSED' FROM {T}.applicability_evaluation_result WHERE run_id = '{failed['id']}' AND position = 1",
                    f"DELETE FROM {T}.applicability_scenario WHERE id = '{s['ilp']['id']}'", f"DELETE FROM {T}.applicability_suite WHERE id = '{u['id']}'",
                    f"UPDATE {T}.applicability_scenario_event SET comment = 'x'", f"UPDATE {T}.applicability_scenario SET code = 'OTHER' WHERE id = '{s['ilp']['id']}'"):  # fmt: skip
            tx = cx.begin()
            with pytest.raises(DBAPIError):
                cx.execute(text(sql))
            tx.rollback()
    # there is no operation that changes or deletes a run
    for method in ("put", "patch", "delete"):
        assert getattr(p["author"], method)(f"{R}/{failed['id']}", headers=csrf_header(p["author"])).status_code == 405


def test_a_recorded_run_never_changes_and_reproduces_from_its_own_record(people: dict[str, TestClient]) -> None:
    p = people
    w = world(p)
    a, b, c = w["a"], w["b"], w["c"]
    s = five(p, w)
    u = suite(
        p["author"],
        "HIST",
        w["policy"]["id"],
        [
            (s["ilp"], expect("RESOLVED", a)),
            (s["both"], expect("RESOLVED", a, b, c)),
            (s["unknown"], expect("UNRESOLVED", a, pending=(b["code"], c["code"]))),
        ],
    )
    first = run(p["author"], u["id"])
    assert first["status"] == "PASSED"
    full = [p["reader"].get(f"{R}/{first['id']}/results/{i}").json() for i in (1, 2, 3)]
    assert (
        full[1]["scenario_document"] == s["both"]["document"]
        and full[1]["scenario_snapshot"] == s["both"]["snapshot"]
        and full[1]["reproducible"] is True
    )
    assert [e["survey"]["name"][-1] for e in full[1]["plan"]["selected"]] == ["A", "B", "C"] and full[1]["plan"][
        "fingerprint"
    ] == full[1]["plan_fingerprint"]
    assert first["suite"]["members"][1] == {
        "position": 2,
        "scenario_id": s["both"]["id"],
        "code": "BOTH",
        "revision": 1,
        "expectation": u["member_list"][1]["expectation"],
    }
    # ---- then everything around it changes: the policy (C now replaces A and B), a scenario, a condition version, a variable version
    assert save_policy(p["author"], w["policy"]["id"], 1, w["replacing"]).status_code == 200
    put(
        p["author"],
        f"{S}/{s['both']['id']}/draft",
        {
            "expected_revision": 1,
            "document": {**s["both"]["document"], "facts": {"product_family": "PROTECTION", "nftf": True}},
        },
    )
    ilp = next(x for x in p["author"].get(f"{A}/assets?kind=CONDITION").json()["items"] if x["code"] == "ilp")
    revise(p, ilp["id"], {"name": "Is ILP", "expr": check("product_family", "in", values=["ILP", "PROTECTION"])})
    nftf = next(x for x in p["author"].get(f"{A}/assets?kind=VARIABLE").json()["items"] if x["code"] == "nftf")
    revise(p, nftf["id"], {**BOOL, "name": "NFTF applies (revised)"})
    # the recorded run reads EXACTLY as before: head, fingerprints, every result, every plan
    later = p["reader"].get(f"{R}/{first['id']}").json()
    for k in (
        "status",
        "run_sha256",
        "record_sha256",
        "policy_revision",
        "policy_document_sha256",
        "policy_snapshot_sha256",
        "policy_fingerprint",
        "suite",
        "coverage",
        "results",
    ):
        assert later[k] == first[k], k
    assert [p["reader"].get(f"{R}/{first['id']}/results/{i}").json() for i in (1, 2, 3)] == full
    # … and re-evaluating it from the RECORD ALONE (the library is not read) gives the same plans and verdicts
    proof = post(p["reader"], f"{R}/{first['id']}/verify").json()
    assert proof == {"run_id": first["id"], "record_intact": True, "run_fingerprint_intact": True, "results_checked": 3, "results_reproduced": 3, "mismatched_positions": [],
                     "reproduced": True, "note": "Re-evaluated from the stored record only; the library was not read."}  # fmt: skip
    # ---- what would happen NOW, without recording anything: the run's own scenarios against the current saved draft
    now = post(p["reader"], f"{R}/{first['id']}/against-current").json()
    assert (
        now["kind"] == "RUN_TO_CURRENT_DRAFT"
        and now["policy_changed"] is True
        and now["after"]["recorded"] is False
        and now["after"]["policy_revision"] == 2
    )
    row = next(x for x in now["scenarios"] if x["scenario_name"] == "Scenario BOTH")
    assert (row["outcome_before"], row["outcome_after"]) == ("PASSED", "FAILED") and sorted(
        row["comparison"]["removed"]
    ) == ["Survey A", "Survey B"]
    assert {x["requirement"] for x in row["comparison"]["because"]} == {"r1", "r2"} and row[
        "facts_changed"
    ] == []  # the RECORDED scenario is used, not its later edit
    assert p["reader"].get(f"{R}?suite_id={u['id']}").json()["total"] == 1  # nothing was recorded by looking
    # ---- a NEW run is a new record with a new outcome; the first is not overwritten
    second = run(p["author"], u["id"])
    assert (
        second["id"] != first["id"]
        and second["policy_revision"] == 2
        and second["status"] == "FAILED"
        and second["run_sha256"] != first["run_sha256"]
    )
    # with the replacement, an unknown NFTF leaves Survey A pending too: that expectation now fails as well — honestly
    assert outcomes(second) == {"ILP-ONLY": "PASSED", "BOTH": "FAILED", "NFTF-UNKNOWN": "FAILED"}
    assert p["reader"].get(f"{R}/{first['id']}").json()["run_sha256"] == first["run_sha256"]
    cmp_ = post(p["reader"], f"{R}/compare", {"before_run_id": first["id"], "after_run_id": second["id"]}).json()
    assert (
        cmp_["kind"] == "RUN_TO_RUN"
        and cmp_["policy_changed"]
        and cmp_["same_policy"]
        and (cmp_["changed"], cmp_["unchanged"]) == (2, 1)
    )
    both = next(x for x in cmp_["scenarios"] if x["scenario_name"] == "Scenario BOTH")
    assert both["facts_changed"] == [
        {
            "variable": "product_family",
            "before": "ILP",
            "after": "PROTECTION",
            "before_given": True,
            "after_given": True,
        }
    ]
    assert (
        sorted(both["comparison"]["removed"]) == ["Survey A", "Survey C"]
        and both["comparison"]["added"] == []
        and (both["outcome_before"], both["outcome_after"]) == ("PASSED", "FAILED")
    )
    # the policy still pins condition "ilp" v1 and variable "nftf" v1: neither republication moved it, so no dependency changed
    assert cmp_["dependency_changes"] == []
    assert post(p["reader"], f"{R}/{second['id']}/verify").json()["reproduced"] is True


def test_what_cannot_be_evaluated_never_passes(people: dict[str, TestClient]) -> None:
    p = people
    w = world(p)
    a = w["a"]
    # ---- a scenario on a DRAFT profile: allowed, reported as not reproducible; when the draft moves it is refused, not re-read
    draft = created(
        p["author"],
        "PROFILE",
        "draft_profile",
        {"name": "Draft profile", "sections": [{"name": "Core", "variables": ["product_family"]}]},
    )
    s = saved(p["author"], "ON-DRAFT", {"product_family": "ILP", "nftf": False}, profiles=("draft_profile",))
    assert (
        s["unpublished"] == 1
        and s["inspection"]["reproducible"] is False
        and "UNPUBLISHED_DEPENDENCY" in {d["code"] for d in s["inspection"]["diagnostics"]}
    )
    assert {"kind": "PROFILE", "code": "draft_profile", "draft_revision": 1} in s["document"]["pins"]
    u = suite(p["author"], "DRAFTY", w["policy"]["id"], [(s, expect("RESOLVED", a))])
    assert run(p["author"], u["id"])["status"] == "PASSED"
    assert (
        put_asset(
            p["author"],
            draft["id"],
            1,
            {"name": "Draft profile", "sections": [{"name": "Core", "variables": ["nftf"]}]},
        ).status_code
        == 200
    )
    moved = p["author"].get(f"{S}/{s['id']}").json()
    assert (
        moved["inspection"]["stale"] == 1 and moved["snapshot"] == s["snapshot"]
    )  # the saved scenario is preserved as it was
    stale = next(d for d in moved["inspection"]["diagnostics"] if d["code"] == "STALE_DEPENDENCY")
    assert "draft revision 1" in stale["message"] and "now at draft revision 2" in stale["message"]
    ev = post(
        p["reader"], f"{S}/evaluate", {"policy_id": w["policy"]["id"], "scenarios": [{"scenario_id": s["id"]}]}
    ).json()["results"][0]
    assert ev["state"] == "COULD_NOT_EVALUATE" and ev["plan"] is None and ev["reproducible"] is False
    blocked = run(p["author"], u["id"])
    assert (
        blocked["status"] == "COULD_NOT_EVALUATE"
        and (blocked["passed"], blocked["not_evaluated"]) == (0, 1)
        and "cannot be reproduced" in blocked["results"][0]["reason"]
    )
    # the author reconciles deliberately: accept the current draft revision
    doc = copy.deepcopy(moved["document"])
    next(x for x in doc["pins"] if x["code"] == "draft_profile")["draft_revision"] = 2
    assert (
        put(p["author"], f"{S}/{s['id']}/draft", {"expected_revision": 1, "document": doc}).json()["inspection"][
            "stale"
        ]
        == 0
    )
    assert run(p["author"], u["id"])["status"] == "PASSED"
    # ---- a profile at another version than the policy's: an exploratory suite reads the scenario's and says so; a gating suite demands reconciliation
    old = saved(p["author"], "OLD-PROFILE", {"product_family": "ILP", "nftf": False})
    revise(p, w["profile"]["id"], {**COMMON, "name": "Common application v2"})
    pol_ = read_policy(p["author"], w["policy"]["id"])
    doc2 = copy.deepcopy(pol_["document"])
    next(x for x in doc2["pins"] if x["code"] == "common")["version"] = 2
    assert save_policy(p["author"], w["policy"]["id"], pol_["draft_revision"], doc2).status_code == 200
    loose = suite(p["author"], "LOOSE", w["policy"]["id"], [(old, expect("RESOLVED", a))], purpose="EXPLORATORY")
    strict = suite(p["author"], "STRICT", w["policy"]["id"], [(old, expect("RESOLVED", a))])
    ok = run(p["author"], loose["id"])
    assert ok["status"] == "PASSED" and "PROFILE_VERSION_DIFFERS" in {
        d["code"] for d in p["reader"].get(f"{R}/{ok['id']}/results/1").json()["diagnostics"]
    }
    no = run(p["author"], strict["id"])
    assert (
        no["status"] == "INVALID_DEFINITION" and no["invalid"] == 1 and "Reconcile them" in no["results"][0]["reason"]
    )
    # ---- a policy whose own pinned draft has moved cannot be run: recorded as could-not-evaluate, never as passed
    cond = created(p["author"], "CONDITION", "draft_cond", {"name": "Draft condition", "expr": check("nftf")})
    pol_ = read_policy(p["author"], w["policy"]["id"])
    doc3 = copy.deepcopy(pol_["document"])
    doc3["requirements"].append(req("r9", ref("draft_cond"), w["b"]))
    assert save_policy(p["author"], w["policy"]["id"], pol_["draft_revision"], doc3).status_code == 200
    assert (
        put_asset(
            p["author"], cond["id"], 1, {"name": "Draft condition", "expr": {"op": "not", "arg": check("nftf")}}
        ).status_code
        == 200
    )
    dead = run(p["author"], loose["id"])
    assert (
        dead["status"] == "COULD_NOT_EVALUATE"
        and dead["policy_status"] == "DEPENDENCY_STALE"
        and dead["passed"] == 0
        and dead["policy_reasons"][0]["code"] == "STALE_DEPENDENCY"
    )
    assert post(p["reader"], f"{R}/{dead['id']}/verify").json()["results_checked"] == 0


def test_coverage_is_reported_honestly_and_never_claims_to_be_exhaustive(people: dict[str, TestClient]) -> None:
    p = people
    w = world(p)
    a, b, c = w["a"], w["b"], w["c"]
    save_policy(p["author"], w["policy"]["id"], 1, w["replacing"])
    s = five(p, w)
    # one scenario only: partial, with named gaps a person can act on
    thin = suite(p["author"], "THIN", w["policy"]["id"], [(s["ilp"], expect("RESOLVED", a))])
    cov = run(p["author"], thin["id"])["coverage"]
    assert (
        cov["exhaustive"] is False
        and cov["label"].startswith("Partial coverage.")
        and "does not prove every possible application" in cov["label"]
    )
    assert cov["meaningful_for_publication"] is False and cov["why_not_meaningful"] == "4 requirement-level gaps remain"
    assert {(g["code"], g["requirement"]) for g in cov["gaps"] if not g["code"].startswith("CONDITION_")} == {
        ("NEVER_DOES_NOT_APPLY", "r1"), ("NEVER_APPLIES", "r2"), ("NEVER_APPLIES", "r3"), ("REPLACEMENT_NOT_EXERCISED", "r3")}  # fmt: skip
    assert "In 'Requirement r2', “NFTF applies is yes” is never true" in {g["text"] for g in cov["gaps"]}
    # only unresolved outcomes: every test passes, and it still cannot count towards publication
    only = suite(
        p["author"],
        "ONLY-UNKNOWN",
        w["policy"]["id"],
        [(s["unknown"], expect("UNRESOLVED", pending=(a["code"], b["code"], c["code"])))],
    )
    r = run(p["author"], only["id"])
    assert (
        r["status"] == "PASSED"
        and r["coverage"]["only_unresolved"] is True
        and r["coverage"]["meaningful_for_publication"] is False
        and r["coverage"]["why_not_meaningful"] == "every result is unresolved"
    )
    # the five scenarios: every requirement applies and does not apply, the replacement is exercised
    full = suite(p["author"], "FULL", w["policy"]["id"], [
        (s["ilp"], expect("RESOLVED", a)), (s["nftf"], expect("RESOLVED", b)), (s["both"], expect("RESOLVED", c, replaced=["r1", "r2"])), (s["neither"], expect("RESOLVED")),
        (s["unknown"], expect("UNRESOLVED", pending=(a["code"], b["code"], c["code"]), needs=["nftf"])),
    ])  # fmt: skip
    r = run(p["author"], full["id"])
    cov = r["coverage"]
    assert (
        r["status"] == "PASSED"
        and cov["essential_gaps"] == 0
        and cov["meaningful_for_publication"] is True
        and cov["exhaustive"] is False
    )
    assert (cov["resolved_positive_passing"], cov["negative_passing"], cov["unresolved"]) == (3, 3, 1)
    r3 = next(x for x in cov["requirements"] if x["id"] == "r3")
    assert (r3["applies"], r3["does_not_apply"], r3["unknown"], r3["replaced_them"]) == (1, 3, 1, 1)
    # the remaining gaps are condition-level and are still listed, not hidden: e.g. "Is ILP" was never 'not known'
    assert cov["condition_gaps"] > 0 and all(g["code"].startswith("CONDITION_NOT_") for g in cov["gaps"])
    # the same scenarios in an EXPLORATORY suite never count towards publication, whatever they cover
    members = [
        (s[k], m["expectation"])
        for k, m in zip(("ilp", "nftf", "both", "neither", "unknown"), full["member_list"], strict=True)
    ]
    loose = run(
        p["author"], suite(p["author"], "FULL-EXPLORE", w["policy"]["id"], members, purpose="EXPLORATORY")["id"]
    )
    assert (
        loose["status"] == "PASSED"
        and loose["coverage"]["meaningful_for_publication"] is False
        and loose["coverage"]["why_not_meaningful"] == "the suite is exploratory"
    )
    # a failing suite is not meaningful either: a wrong expectation does not count as a passing positive case
    bad = suite(
        p["author"], "BAD", w["policy"]["id"], [(s["ilp"], expect("RESOLVED", b)), (s["neither"], expect("RESOLVED"))]
    )
    r = run(p["author"], bad["id"])
    assert (
        r["status"] == "FAILED"
        and r["coverage"]["resolved_positive_passing"] == 0
        and r["coverage"]["meaningful_for_publication"] is False
        and r["coverage"]["why_not_meaningful"] == "the run did not pass"
    )


def test_markets_permissions_csrf_and_limits(
    people: dict[str, TestClient], x4_app: Any, db: Session, engine: Engine
) -> None:
    p = people
    w = world(p)
    a = w["a"]
    s = saved(p["author"], "MINE", {"product_family": "ILP", "nftf": False})
    u = suite(p["author"], "MINE", w["policy"]["id"], [(s, expect("RESOLVED", a))])
    r = run(p["author"], u["id"])
    before = everything_else(engine)
    # ---- read-only people read, evaluate and compare; they cannot create, save, archive or record a run
    assert (
        p["reader"].get(f"{S}/{s['id']}").status_code == 200
        and post(
            p["reader"], f"{S}/evaluate", {"policy_id": w["policy"]["id"], "scenarios": [{"scenario_id": s["id"]}]}
        ).status_code
        == 200
    )
    for who in ("reader", "checker", "publisher"):
        assert scenario(p[who], "NOPE", {}).status_code == 403
        assert (
            put(p[who], f"{S}/{s['id']}/draft", {"expected_revision": 1, "document": s["document"]}).status_code == 403
        )
        assert (
            post(
                p[who], f"{S}/{s['id']}/archive", {"expected_revision": 1, "reason": "not allowed to do this"}
            ).status_code
            == 403
        )
        assert (
            post(
                p[who],
                U,
                {"market_code": "SG", "code": "NOPE", "policy_id": w["policy"]["id"], "document": {"name": "No"}},
            ).status_code
            == 403
        )
        assert (
            put(
                p[who],
                f"{U}/{u['id']}/draft",
                {"expected_revision": 1, "document": {"name": "No"}, "purpose": "EXPLORATORY", "members": []},
            ).status_code
            == 403
        )
        assert post(p[who], f"{U}/{u['id']}/runs", {"idempotency_key": "not-allowed-run"}).status_code == 403
    for who in ("no_survey", "survey_only"):
        assert p[who].get(f"{S}/{s['id']}").status_code == 403 and p[who].get(f"{R}/{r['id']}").status_code == 403
    # ---- every write and every computation needs the CSRF token
    for path, body in ((S, {"market_code": "SG", "code": "NOCSRF", "document": {"name": "No token", "facts": {}}}), (f"{S}/evaluate", {"policy_id": w["policy"]["id"], "scenarios": []}),
                       (f"{U}/{u['id']}/runs", {"idempotency_key": "no-csrf-token"}), (f"{R}/{r['id']}/verify", {})):  # fmt: skip
        assert p["author"].post(path, json=body).status_code == 403
        assert p["author"].post(path, json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert (
        p["author"].put(f"{S}/{s['id']}/draft", json={"expected_revision": 1, "document": s["document"]}).status_code
        == 403
    )
    # ---- another market: its scenarios, suites and runs do not exist; nothing crosses
    other = make_account(db, prefix="x4my")
    GRANTS[other.principal_id], MARKETS[other.principal_id] = (
        frozenset({"applicability.read", "applicability.edit", "survey.read"}),
        frozenset({"MY"}),
    )
    try:
        with _client(x4_app, other) as my:
            assert (
                scenario(my, "THEIRS", {}, market="SG").json()["code"] == "MARKET_NOT_IN_SCOPE"
                and scenario(p["author"], "OURS", {}, market="MY").json()["code"] == "MARKET_NOT_IN_SCOPE"
            )
            mine = scenario(my, "MY-ONE", {}, profiles=(), market="MY")
            assert mine.status_code == 201 and [x["code"] for x in my.get(S).json()["items"]] == ["MY-ONE"]
            assert (
                "MY-ONE" not in {x["code"] for x in p["reader"].get(S).json()["items"]}
                and my.get(U).json()["total"] == 0
                and my.get(R).json()["total"] == 0
            )
            for call in (lambda c_: c_.get(f"{S}/{s['id']}"), lambda c_: c_.get(f"{U}/{u['id']}"), lambda c_: c_.get(f"{R}/{r['id']}"), lambda c_: c_.get(f"{R}/{r['id']}/results/1"),
                         lambda c_: put(c_, f"{S}/{s['id']}/draft", {"expected_revision": 1, "document": s["document"]}), lambda c_: post(c_, f"{U}/{u['id']}/runs", {"idempotency_key": "cross-market"}),
                         lambda c_: post(c_, f"{R}/{r['id']}/verify"), lambda c_: post(c_, f"{R}/{r['id']}/against-current"), lambda c_: post(c_, f"{R}/compare", {"before_run_id": r["id"], "after_run_id": r["id"]}),
                         lambda c_: post(c_, f"{S}/evaluate", {"policy_id": w["policy"]["id"], "scenarios": []})):  # fmt: skip
                assert call(my).status_code == 404
            # a MY scenario cannot be evaluated against, or put in a suite of, an SG policy — nor reached at all by an SG person
            assert (
                post(
                    p["author"],
                    f"{S}/evaluate",
                    {"policy_id": w["policy"]["id"], "scenarios": [{"scenario_id": mine.json()["id"]}]},
                ).status_code
                == 404
            )
            assert (
                post(
                    p["author"],
                    U,
                    {
                        "market_code": "SG",
                        "code": "MIX",
                        "policy_id": w["policy"]["id"],
                        "document": {"name": "Mixed"},
                        "members": [{"scenario_id": mine.json()["id"]}],
                    },
                ).status_code
                == 404
            )
            assert (
                post(
                    my,
                    U,
                    {"market_code": "MY", "code": "MIX", "policy_id": w["policy"]["id"], "document": {"name": "Mixed"}},
                ).status_code
                == 404
            )
            # an SG variable does not exist in MY: a MY scenario cannot name it
            assert (
                scenario(my, "BORROW", {"nftf": True}, profiles=(), market="MY").json()["code"] == "UNKNOWN_REFERENCE"
            )
        # the database refuses a cross-market member even if the service were bypassed
        with engine.connect() as cx:
            tx = cx.begin()
            with pytest.raises(DBAPIError, match="own market"):
                cx.execute(
                    text(
                        f"INSERT INTO {T}.applicability_suite_member (suite_id, scenario_id, position) VALUES ('{u['id']}', '{mine.json()['id']}', 9)"
                    )
                )
            tx.rollback()
    finally:
        GRANTS.pop(other.principal_id, None)
        MARKETS.pop(other.principal_id, None)
    # ---- limits: an oversized suite, a stale revision, a bad key
    many = [{"scenario_id": str(uuid.uuid4())} for _ in range(201)]
    assert (
        post(
            p["author"],
            U,
            {
                "market_code": "SG",
                "code": "HUGE",
                "policy_id": w["policy"]["id"],
                "document": {"name": "Huge"},
                "members": many,
            },
        ).status_code
        == 422
    )
    assert (
        put(
            p["author"],
            f"{U}/{u['id']}/draft",
            {"expected_revision": 9, "document": {"name": "x2"}, "purpose": "EXPLORATORY", "members": []},
        ).json()["code"]
        == "STALE_REVISION"
    )
    assert post(p["author"], f"{U}/{u['id']}/runs", {"idempotency_key": "has spaces!"}).status_code == 422
    assert (
        post(
            p["author"],
            S,
            {
                "market_code": "SG",
                "code": "BIG",
                "document": {"name": "Too many facts", "facts": {f"f{i}": True for i in range(401)}},
            },
        ).json()["code"]
        == "INVALID_DOCUMENT"
    )
    # ---- nothing operational was written by any of it: only the audit trail and access records differ
    after = everything_else(engine)
    # … the audit trail, and the access records of the one extra account this test created and signed in
    access = {"audit_event", "principal", "local_credential", "identity_binding", "group_membership", "auth_session", "refresh_token", "refresh_token_family", "login_attempt"}  # fmt: skip
    assert {k for k in before if before[k] != after[k]} <= access


def test_a_whole_flow_writes_only_its_own_tables_and_the_audit_trail(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    w = world(p)
    before = everything_else(engine)
    s = five(p, w)
    u = suite(
        p["author"],
        "FLOW",
        w["policy"]["id"],
        [(s["ilp"], expect("RESOLVED", w["a"])), (s["neither"], expect("RESOLVED"))],
    )
    r = run(p["author"], u["id"])
    post(p["reader"], f"{R}/{r['id']}/verify")
    post(p["reader"], f"{R}/{r['id']}/against-current")
    after = everything_else(engine)
    changed = {k for k in before if before[k] != after[k]}
    assert changed == {"audit_event"}, (
        changed
    )  # no case, sale, session, assignment rule, binding, group, survey or library row
    with engine.connect() as c:
        actions = dict(
            c.execute(
                text(
                    f"SELECT action, count(*) FROM {T}.audit_event WHERE action LIKE 'APPLICABILITY.S%' AND entity_id = ANY(:ids) GROUP BY 1"
                ),
                {"ids": [x["id"] for x in s.values()] + [u["id"], r["id"]]},
            ).all()
        )  # type: ignore[arg-type]
        assert actions == {
            "APPLICABILITY.SCENARIO_CREATED": 5,
            "APPLICABILITY.SUITE_CREATED": 1,
            "APPLICABILITY.SUITE_RUN_RECORDED": 1,
        }
        who = (
            c.execute(
                text(
                    f"SELECT DISTINCT actor_snapshot->>'username' FROM {T}.audit_event WHERE action = 'APPLICABILITY.SUITE_RUN_RECORDED' AND entity_id = '{r['id']}'"
                )
            )
            .scalars()
            .all()
        )
        assert len(who) == 1 and str(who[0]).startswith("x4author")  # the real signed-in identity


def test_scale_a_hundred_requirements_and_two_hundred_scenarios_stay_bounded_and_paged(
    people: dict[str, TestClient],
) -> None:
    p = people
    w = world(p)
    a, b = w["a"], w["b"]
    reqs = [req(f"r{i}", ref("ilp") if i % 2 else ref("nftf_applies"), a if i % 2 else b) for i in range(1, 101)]
    # one delivery of each survey satisfies all the requirements that name it: stated explicitly, as the evaluator requires
    shared = [
        {"survey": x["code"], "requirements": [r["id"] for r in reqs if r["action"]["surveys"][0]["code"] == x["code"]]}
        for x in (a, b)
    ]
    big = made(p["author"], "BIG", document(*reqs, shared_deliveries=shared))
    timings = {}
    for n in (10, 50, 200):
        rows = []
        for i in range(n):
            facts = {"product_family": "ILP" if i % 2 else "PROTECTION", "nftf": [True, False, None][i % 3]}
            sx = saved(p["author"], f"N{n}-{i}", facts)
            sel = [x for x, on in ((a, facts["product_family"] == "ILP"), (b, facts["nftf"] is True)) if on]
            rows.append(
                (
                    sx,
                    expect(
                        "UNRESOLVED" if facts["nftf"] is None else "RESOLVED",
                        *sel,
                        pending=(b["code"],) if facts["nftf"] is None else (),
                    ),
                )
            )
        u = suite(p["author"], f"SCALE-{n}", big["id"], rows)
        t0 = time.monotonic()
        r = run(p["author"], u["id"])
        timings[n] = (round(time.monotonic() - t0, 2), r["duration_ms"])
        assert r["status"] == "PASSED" and r["scenarios"] == n and r["passed"] == n, (
            n,
            r["status"],
            [(x["scenario_code"], x["differences"], x["actual"]) for x in r["results"] if x["outcome"] != "PASSED"][:2],
        )
        assert len(r["results"]) == min(n, 50) and r["results_total"] == n  # a run never arrives in one answer
        if n == 200:
            page = p["reader"].get(f"{R}/{r['id']}?limit=100&offset=100").json()
            assert len(page["results"]) == 100 and page["results"][0]["position"] == 101
            assert len(p["reader"].get(f"{R}/{r['id']}/results/200").json()["plan"]["requirements"]) == 100
            cov = r["coverage"]
            assert len(cov["requirements"]) == 100 and cov["essential_gaps"] == 0 and cov["exhaustive"] is False
            assert post(p["reader"], f"{R}/{r['id']}/verify").json()["reproduced"] is True
    print("\nAPPL-X4a scale (wall seconds, recorded evaluation ms) for 100 requirements:", timings)
    assert timings[200][0] < 60  # bounded: a suite is at most 200 scenarios
    assert (
        p["reader"].get(f"{S}?limit=100").json()["total"] == 260
        and len(p["reader"].get(f"{S}?limit=500").json()["items"]) == 100
    )  # a page is at most 100


# ------------------------------------------------------------------------------------------------------ migration
def _head(engine: Engine) -> str:
    with engine.connect() as c:
        return str(c.execute(text(f"SELECT version_num FROM {T}.alembic_version")).scalar_one())


def _objects(engine: Engine) -> tuple[list[str], list[str]]:
    with engine.connect() as c:
        tables = sorted(
            c.execute(
                text(
                    f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{T}' AND table_name = ANY(:t)"
                ),
                {"t": list(TABLES)},
            ).scalars()
        )
        functions = sorted(
            c.execute(
                text(
                    f"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{T}' AND p.proname = ANY(:f)"
                ),
                {"f": FUNCTIONS},
            ).scalars()
        )
    return tables, functions


def test_zz_migration_0040_is_additive_reversible_while_empty_atomic_and_keeps_evidence(fresh_schema: None, engine: Engine, settings: Settings, x4_app: Any, db: Session) -> None:  # fmt: skip
    """On a POPULATED schema: accounts, a published library, published surveys and a saved policy."""
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {
        "author": edit,
        "checker": {"applicability.read", "applicability.approve"},
        "publisher": {"applicability.read", "applicability.publish"},
        "s1": set(SURVEY),
        "s2": set(SURVEY),
        "s3": set(SURVEY),
    }
    accounts = {k: make_account(db, prefix=f"zx4{k}") for k in grants}
    for k, a_ in accounts.items():
        GRANTS[a_.principal_id] = frozenset(grants[k])
    p = {k: _client(x4_app, a_) for k, a_ in accounts.items()}
    try:
        w = world(p)
        assert _head(engine) == MIGRATION_HEAD == "0040_applicability_scenarios"
        full = _objects(engine)
        assert full == (sorted(TABLES), FUNCTIONS)
        before = everything_else(engine)
        assert (
            before["applicability_policy"][0] == 1
            and before["applicability_asset_version"][0] == 5
            and before["survey_version"][0] == 3
            and before["permission"][0] > 0
        )
        with engine.connect() as c:
            fks = c.execute(
                text(
                    "SELECT count(*) FROM pg_constraint con JOIN pg_class cl ON cl.oid = con.conrelid JOIN pg_namespace n ON n.oid = cl.relnamespace WHERE con.contype = 'f' AND n.nspname = :s AND cl.relname = ANY(:t) AND con.convalidated"
                ),
                {"s": T, "t": list(TABLES)},
            ).scalar_one()
            assert fks == 14  # every reference is a validated foreign key
        # 1. downgrade while empty removes exactly the seven tables and six guards; nothing else changes; no permission
        migrate(settings, "0039_applicability_policy", down=True)
        assert (
            _head(engine) == "0039_applicability_policy"
            and _objects(engine) == ([], [])
            and everything_else(engine) == before
        )
        # 2. a forced failure at the LAST statement, after every table, index and other guard was created: all rolled back
        with engine.begin() as c:
            c.execute(
                text(
                    f"CREATE FUNCTION {T}.applicability_evaluation_result_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                )
            )
        with pytest.raises(DBAPIError, match="already exists"):
            migrate(settings, "head")
        assert _head(engine) == "0039_applicability_policy" and _objects(engine) == (
            [],
            ["applicability_evaluation_result_guard"],
        )
        with engine.begin() as c:
            c.execute(text(f"DROP FUNCTION {T}.applicability_evaluation_result_guard()"))
        assert everything_else(engine) == before
        # 3. upgrade again: identical objects; every other table byte-identical — policies, library and Survey Studio included
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD and _objects(engine) == full and everything_else(engine) == before
        # 4. a saved scenario alone already refuses the downgrade; so does a suite; so does recorded evidence
        s = saved(p["author"], "KEPT", {"product_family": "ILP", "nftf": False})
        with pytest.raises(RuntimeError, match="saved scenarios exist"):
            migrate(settings, "0039_applicability_policy", down=True)
        u = suite(p["author"], "KEPT", w["policy"]["id"], [(s, expect("RESOLVED", w["a"]))])
        r = run(p["author"], u["id"])
        with pytest.raises(RuntimeError, match="recorded evaluation runs exist"):
            migrate(settings, "0039_applicability_policy", down=True)
        assert (
            _head(engine) == MIGRATION_HEAD
            and p["author"].get(f"{R}/{r['id']}").json()["run_sha256"] == r["run_sha256"]
        )
        assert (
            p["author"].get(f"{S}/{s['id']}").json()["document"] == s["document"]
            and post(p["author"], f"{R}/{r['id']}/verify").json()["reproduced"] is True
        )
        after = everything_else(engine)
        assert {k for k in before if before[k] != after[k]} <= {"audit_event"}
        # the audit chain is still consistent after all of it
        from app.audit.chain import verify_chain

        assert verify_chain(db).ok
    finally:
        for c_ in p.values():
            c_.__exit__(None, None, None)
        for a_ in accounts.values():
            GRANTS.pop(a_.principal_id, None)
        with (
            engine.begin() as c
        ):  # leave the shared test schema without this test's evidence, so later modules can migrate
            c.execute(text(f"TRUNCATE {T}.applicability_policy CASCADE"))


_ = (POLICIES, get, sc)
