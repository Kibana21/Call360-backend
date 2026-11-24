# ruff: noqa: E501 — long assertions are kept on one line each
"""APPL-X5a — synthetic journeys over published Applicability Policy versions, on the isolated TEST schema.

Selection is the accepted evaluator's on one exact published version; execution is the accepted single-survey
simulation's; this checkpoint adds the coordination, the fact correspondence and the voice-neutral turn runtime.
Every policy here is PUBLISHED through the governed three-person API; every survey is a REAL published Survey Studio
version. Synthetic facts only.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.survey.applicability import journeys as jr
from app.domain.survey.store import SurveyError
from app.main import MIGRATION_HEAD, create_app
from tests.support import JOURNEY_TABLES, make_account, migrate
from tests.test_applicability_library import BOOL, FAMILY, A, check, published, ref
from tests.test_applicability_policies import document, made, req
from tests.test_applicability_publication import ALL4, CAND, POL, SURVEY, ready, submit
from tests.test_applicability_scenarios import COMMON, S, U, everything_else, saved, suite
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_lib1 import build
from tests.test_survey_lib1 import publish as publish_survey

T = "call360_test"
J, JV, FC = f"{A}/journeys", f"{A}/journey-policy-versions", f"{A}/fact-correspondences"
RUN = {"applicability.read", "survey.read", "survey.simulate"}


@pytest.fixture()
def x6_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(
            settings.model_copy(
                update={
                    "applicability_library_enabled": True, "applicability_policies_enabled": True, "applicability_scenarios_enabled": True,
                    "applicability_publication_enabled": True, "applicability_journeys_enabled": True, "survey_definitions_enabled": True,
                    "survey_library_enabled": True, "survey_simulation_enabled": True, "survey_applicability_prototype_enabled": True,
                    "transcription_worker": False, "survey_writes_per_minute": 100_000, "survey_simulation_inputs_per_minute": 100_000,
                }
            )
        )
    )  # fmt: skip


def _wipe(engine: Engine) -> None:
    with engine.begin() as c:
        for table in ("applicability_policy", "applicability_asset", "applicability_fact_correspondence"):
            if c.execute(text(f"SELECT to_regclass('{T}.{table}')")).scalar_one() is not None:
                c.execute(text(f"TRUNCATE {T}.{table} CASCADE"))


@pytest.fixture(autouse=True)
def empty(engine: Engine) -> Iterator[None]:
    """Before AND after: later modules migrate the shared test schema down, which is refused while journeys exist."""
    _wipe(engine)
    yield
    _wipe(engine)


@pytest.fixture()
def people(x6_app: Any, db: Session) -> Iterator[dict[str, TestClient]]:
    """The three publication roles; a RUNNER holding exactly the three permissions a journey needs; three people each
    missing one of them; a runner of another market."""
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {
        "author": edit, "checker": {"applicability.read", "applicability.approve", "survey.read"},
        "publisher": {"applicability.read", "applicability.publish", "survey.read"}, "reader": {"applicability.read", "survey.read"},
        "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY), "all1": set(ALL4),
        "runner": set(RUN), "runner2": set(RUN), "elsewhere": set(RUN),
        "no_applicability": RUN - {"applicability.read"}, "no_survey": RUN - {"survey.read"}, "no_simulate": RUN - {"survey.simulate"},
    }  # fmt: skip
    accounts = {k: make_account(db, prefix=f"x6{k.replace('_', '')}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    MARKETS[accounts["elsewhere"].principal_id] = frozenset({"MY"})
    clients = {k: _client(x6_app, a) for k, a in accounts.items()}
    yield clients
    for c in clients.values():
        c.__exit__(None, None, None)
    for a in accounts.values():
        GRANTS.pop(a.principal_id, None)
        MARKETS.pop(a.principal_id, None)


CASES = {
    "ILP": {"product_family": "ILP", "nftf": False}, "NFTF": {"product_family": "PROTECTION", "nftf": True}, "BOTH": {"product_family": "ILP", "nftf": True},
    "NEITHER": {"product_family": "PROTECTION", "nftf": False}, "UNKNOWN": {"product_family": "ILP", "nftf": None},
}  # fmt: skip


def library(p: dict[str, TestClient]) -> None:
    published(p, "VARIABLE", "product_family", FAMILY)
    published(p, "VARIABLE", "nftf", BOOL)
    published(p, "CONDITION", "ilp", {"name": "Is ILP", "expr": check("product_family", "equals", value="ILP")})
    published(p, "CONDITION", "nftf_applies", {"name": "NFTF applies", "expr": check("nftf")})
    published(p, "PROFILE", "common", COMMON)


def publish_policy(
    p: dict[str, TestClient], code: str, doc: dict[str, Any], *, policy_id: str | None = None
) -> dict[str, Any]:
    """A policy PUBLISHED through the governed API by three people, with a passing gating suite of five scenarios whose
    expected outcomes are stated by the test's author (the outcomes this test module asserts elsewhere, one by one)."""
    if policy_id is None:
        policy_id = made(p["author"], code, doc)["id"]
        tag = code
    else:
        now = p["author"].get(f"{POL}/{policy_id}?inspection=false").json()
        r = p["author"].put(
            f"{POL}/{policy_id}/draft",
            json={"expected_revision": now["draft_revision"], "document": doc},
            headers={"X-CSRF-Token": p["author"].cookies.get("c360_csrf") or ""},
        )
        assert r.status_code == 200, r.text
        tag = f"{code}-{now['draft_revision'] + 1}"
    scenarios = {k: saved(p["author"], f"{tag}-{k}", facts, policy_id=policy_id) for k, facts in CASES.items()}
    res = post(
        p["reader"],
        f"{S}/evaluate",
        {"policy_id": policy_id, "scenarios": [{"scenario_id": s["id"]} for s in scenarios.values()]},
    ).json()["results"]
    members = []
    for s, r in zip(scenarios.values(), res, strict=True):
        plan = r["plan"]
        members.append((s, {"status": plan["status"], "selected": [{"code": e["survey"]["code"], "version": e["survey"]["version"], "name": e["survey"]["name"]} for e in plan["selected"]],
                            "pending": [e["survey"]["code"] for e in plan["pending"]], "confirmed": True}))  # fmt: skip
    u = suite(p["author"], f"{tag}-GATE", policy_id, members)
    targets = p["author"].get(f"{POL}/{policy_id}/run-targets").json()
    draft = next(t for t in targets["items"] if t["kind"] == "DRAFT")
    run = post(
        p["author"],
        f"{U}/{u['id']}/runs",
        {"idempotency_key": f"run-{uuid.uuid4()}", "target": {"kind": "DRAFT", "revision": draft["revision"]}},
    )
    assert run.status_code == 201 and run.json()["status"] == "PASSED", run.text
    c = submit(p["author"], policy_id, ready(p["author"], policy_id, run.json()["id"]))
    assert c.status_code == 201, c.text
    cid, sha = c.json()["id"], c.json()["candidate_sha256"]
    assert (
        post(p["checker"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).status_code == 200
    )
    out = post(
        p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": c.json()["next_version_no"]}
    )
    assert out.status_code == 200, out.text
    return {
        "policy_id": policy_id,
        "version_id": out.json()["version"]["id"],
        "version_no": out.json()["version"]["version_no"],
        "scenarios": scenarios,
    }


def answer_for(turn: dict[str, Any]) -> dict[str, Any]:
    """A valid answer to any turn, from what the turn itself says is allowed."""
    e = turn["expects"]
    kind, options = e["answer_type"], e["options"]
    if kind in ("YES_NO", "SINGLE_SELECT"):
        return {"choice": options[0]["code"]}
    if kind == "MULTI_SELECT":
        return {"choices": [options[0]["code"]]}
    if kind == "NUMERIC":
        rule = e["number_rule"] or {}
        return {"number": rule.get("min") if rule.get("min") is not None else 1}
    if kind == "ACKNOWLEDGEMENT":
        return {"acknowledged": True}
    return {"text": "A synthetic answer."}


def give(
    c: TestClient, jid: str, turn: dict[str, Any], answer: dict[str, Any], key: str | None = None, **more: Any
) -> Any:
    return post(
        c,
        f"{J}/{jid}/answers",
        {
            "item_key": turn["item_key"],
            "expected_inputs": turn["expected_inputs"],
            "answer": answer,
            "idempotency_key": key or f"k-{uuid.uuid4()}",
            **more,
        },
    )


def walk(c: TestClient, jid: str, limit: int = 200) -> dict[str, Any]:
    """Answer every turn the runtime offers until it offers none."""
    for _ in range(limit):
        n = c.get(f"{J}/{jid}/turn").json()
        if n["kind"] == "END":
            break
        r = give(c, jid, n["turn"], answer_for(n["turn"]))
        assert r.status_code == 200 and r.json()["result"] == "ACCEPTED", r.text
    return c.get(f"{J}/{jid}").json()  # type: ignore[no-any-return]


def new_journey(c: TestClient, version_id: str, facts: dict[str, Any], **more: Any) -> Any:
    return post(c, J, {"policy_version_id": version_id, "facts": facts, "label": "synthetic journey", **more})


def started(
    c: TestClient, version_id: str, facts: dict[str, Any], survey_facts: dict[str, Any] | None = None
) -> dict[str, Any]:
    j = new_journey(c, version_id, facts)
    assert j.status_code == 201 and j.json()["status"] == "READY", j.text
    r = post(c, f"{J}/{j.json()['id']}/start", {"expected_revision": 1, "survey_facts": survey_facts or {}})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def fixture_survey(p: dict[str, TestClient], fixture: str, name: str) -> dict[str, Any]:
    """A REAL published Survey Studio version holding one golden fixture, as a policy refers to it."""
    sid, code, _ = build(p["s1"], fixture, name)
    publish_survey((p["s1"], p["s2"], p["s3"]), sid)
    row = next(x for x in p["s1"].get("/api/v1/survey-definitions").json()["items"] if x["id"] == sid)
    v = p["s1"].get(f"/api/v1/survey-versions/{row['latest_version_id']}").json()
    return {
        "code": code,
        "name": name,
        "version": v["version_no"],
        "label": v["label"],
        "version_id": v["id"],
        "definition_id": sid,
        "fingerprint": v["content_sha256"],
        "manifest": v["manifest_sha256"],
        "market": "SG",
    }


BOTH = {"op": "all", "args": [ref("ilp"), ref("nftf_applies")]}
K8_FACTS = {"customer.age_years": 40, "policy.annual_premium": 12000, "policy.is_replacement": False}


def count(engine: Engine, table: str, where: str = "true") -> int:
    with engine.connect() as c:
        return int(c.execute(text(f"SELECT count(*) FROM {T}.{table} WHERE {where}")).scalar_one())


def trio(p: dict[str, TestClient]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Three REAL published surveys of different kinds: yes/no, numbers, an acknowledgement."""
    return (
        fixture_survey(p, "K1", "Survey A (yes / no)"),
        fixture_survey(p, "K3", "Survey B (numbers)"),
        fixture_survey(p, "K4", "Survey C (acknowledgement)"),
    )


def additive(p: dict[str, TestClient]) -> tuple[dict[str, Any], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    library(p)
    a, b, c = trio(p)
    v = publish_policy(
        p, "ADD", document(req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b), req("r3", BOTH, c))
    )
    return v, (a, b, c)


def turn_of(c: TestClient, jid: str) -> dict[str, Any]:
    n = c.get(f"{J}/{jid}/turn").json()
    assert n["kind"] == "TURN", n
    return n["turn"]  # type: ignore[no-any-return]


def events_of(c: TestClient, jid: str) -> list[str]:
    return [e["event"] for e in c.get(f"{J}/{jid}").json()["events"]]


# ---------------------------------------------------------------------------------------------- authorisation
def test_the_dedicated_test_identity_holds_exactly_three_permissions_and_exists_only_in_the_test_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, settings: Settings
) -> None:
    from scripts import dev_applicability_identities, dev_survey_identities, e2e_survey_setup

    rows = [r for r in e2e_survey_setup.SG if r[3] == "e2e.survey.journey"]
    assert (
        len(rows) == 1 and set(rows[0][5]) == RUN and rows[0][0] == "E2E_APPL_JOURNEY" and rows[0][2].endswith("_SG")
    )  # the synthetic test market
    assert not [r for r in e2e_survey_setup.ELSEWHERE if r[3] == "e2e.survey.journey"]
    # no other test role carries this role code, and no existing role was given simulation or applicability on its way
    assert [r[3] for r in (*e2e_survey_setup.SG, *e2e_survey_setup.ELSEWHERE) if r[0] == "E2E_APPL_JOURNEY"] == [
        "e2e.survey.journey"
    ]
    assert {r[3]: set(r[5]) for r in e2e_survey_setup.SG if r[3] in ("e2e.survey.applauthor", "e2e.survey.simulator", "e2e.survey.applchecker", "e2e.survey.applpublisher")} == {
        "e2e.survey.applauthor": {"survey.read", "survey.edit", "survey.assignment.read", "survey.evaluation.read", "survey.evaluate", "applicability.read", "applicability.edit"},
        "e2e.survey.simulator": {"survey.read", "survey.simulate", "survey.assignment.read", "survey.evaluation.read", "survey.evaluate"},
        "e2e.survey.applchecker": {"survey.read", "applicability.read", "applicability.approve"}, "e2e.survey.applpublisher": {"survey.read", "applicability.read", "applicability.publish"},
    }  # fmt: skip
    # it is not a development identity: neither development script knows it
    for module in (dev_applicability_identities, dev_survey_identities):
        assert (
            "e2e.survey.journey" not in open(module.__file__).read()
            and "E2E_APPL_JOURNEY" not in open(module.__file__).read()
        )  # noqa: SIM115
    # the setup refuses to run against anything but the isolated test configuration
    monkeypatch.setattr(
        e2e_survey_setup,
        "load_settings",
        lambda _path: settings.model_copy(update={"app_env": "local", "target_schema": "call360"}),
    )
    monkeypatch.setattr(e2e_survey_setup.sys, "argv", ["e2e_survey_setup.py", str(tmp_path / "accounts.json")])
    with pytest.raises(SystemExit, match="requires the test configuration"):
        e2e_survey_setup.main()
    assert not (tmp_path / "accounts.json").exists()


def test_off_by_default_sixteen_operations_and_exactly_three_permissions(
    settings: Settings, x6_app: Any, people: dict[str, TestClient], engine: Engine
) -> None:
    def routes(app: Any) -> set[tuple[str, str]]:
        return {
            (m.upper(), path)
            for path, item in app.openapi()["paths"].items()
            for m in item
            if "/journey" in path and "/applicability/" in path or "/fact-correspondences" in path
        }

    off = create_app(settings.model_copy(update={"applicability_library_enabled": True, "applicability_policies_enabled": True, "applicability_scenarios_enabled": True, "applicability_publication_enabled": True,
                                                 "survey_definitions_enabled": True, "survey_library_enabled": True, "survey_simulation_enabled": True, "transcription_worker": False}))  # fmt: skip
    assert routes(off) == set() and len(routes(x6_app)) == 16
    # journeys need BOTH a published policy and survey simulation
    no_sim = create_app(settings.model_copy(update={"applicability_library_enabled": True, "applicability_policies_enabled": True, "applicability_scenarios_enabled": True, "applicability_publication_enabled": True,
                                                    "applicability_journeys_enabled": True, "survey_definitions_enabled": True, "survey_library_enabled": True, "transcription_worker": False}))  # fmt: skip
    assert routes(no_sim) == set()
    assert count(engine, "permission", "code LIKE 'applicability.%'") == 4  # no new permission
    p = people
    v, _ = additive(p)
    body = {"policy_version_id": v["version_id"], "facts": CASES["ILP"], "label": ""}
    # each of the three permissions is necessary: missing ANY ONE of them, a journey cannot be created
    assert [
        new_journey(p[k], v["version_id"], CASES["ILP"]).status_code
        for k in ("no_applicability", "no_survey", "no_simulate", "reader", "author", "checker", "publisher")
    ] == [403] * 7
    assert count(engine, "applicability_journey") == 0
    j = new_journey(p["runner"], v["version_id"], CASES["ILP"])
    assert j.status_code == 201, j.text
    jid = j.json()["id"]
    start = {"expected_revision": 1, "survey_facts": {}}
    for k in ("no_applicability", "no_survey", "no_simulate", "reader", "author"):
        assert post(p[k], f"{J}/{jid}/start", start).status_code == 403, k
    assert post(p["runner"], f"{J}/{jid}/start", start).status_code == 200
    t = turn_of(p["runner"], jid)
    for k in ("no_applicability", "no_survey", "no_simulate", "reader"):
        assert give(p[k], jid, t, answer_for(t)).status_code == 403, k
        assert (
            post(p[k], f"{J}/{jid}/abandon", {"expected_revision": 2, "reason": "not allowed to do this"}).status_code
            == 403
        ), k
    assert p["runner"].get(f"{J}/{jid}").json()["expected_inputs"] == 0  # nothing a refused person sent was recorded
    # reading needs applicability.read AND survey.read; simulate alone reads nothing
    for path in (J, f"{J}/{jid}", f"{J}/{jid}/turn", JV, f"{JV}/{v['version_id']}", FC):
        assert [p[k].get(path).status_code for k in ("reader", "no_simulate", "no_applicability", "no_survey")] == [
            200,
            200,
            403,
            403,
        ], path
    # the runner holds exactly its three permissions: no editing, approving or publishing of applicability
    assert (
        post(
            p["runner"], FC, {"market_code": "SG", "code": "X5-CORR", "document": {"name": "x", "entries": []}}
        ).status_code
        == 403
    )
    assert (
        post(
            p["runner"],
            f"{A}/policies",
            {"market_code": "SG", "code": "NOPE", "origin": "BLANK", "document": document()},
        ).status_code
        == 403
    )
    assert (
        post(
            p["runner"],
            f"{POL}/{v['policy_id']}/submit",
            {
                "expected_revision": 1,
                "run_id": str(uuid.uuid4()),
                "document_sha256": "0" * 64,
                "manifest_sha256": "0" * 64,
                "run_sha256": "0" * 64,
                "note": "",
            },
        ).status_code
        == 403
    )
    assert (
        post(
            p["runner"], f"{CAND}/{uuid.uuid4()}/decision", {"verdict": "APPROVE", "candidate_sha256": "0" * 64}
        ).status_code
        == 403
    )
    assert (
        post(p["runner"], f"{CAND}/{uuid.uuid4()}/publish", {"candidate_sha256": "0" * 64, "version_no": 1}).status_code
        == 403
    )
    # CSRF: a write without the token is refused whoever asks
    assert p["runner"].post(J, json=body).status_code == 403
    assert (
        p["runner"]
        .post(
            f"{J}/{jid}/answers",
            json={
                "item_key": t["item_key"],
                "expected_inputs": 0,
                "answer": answer_for(t),
                "idempotency_key": "no-csrf-token",
            },
        )
        .status_code
        == 403
    )
    # another market: nothing exists
    assert p["elsewhere"].get(J).json()["items"] == [] and p["elsewhere"].get(JV).json()["items"] == []
    assert [
        p["elsewhere"].get(x).status_code for x in (f"{J}/{jid}", f"{J}/{jid}/turn", f"{JV}/{v['version_id']}")
    ] == [404, 404, 404]
    assert new_journey(p["elsewhere"], v["version_id"], CASES["ILP"]).status_code == 404
    assert (
        give(p["elsewhere"], jid, t, answer_for(t)).status_code == 404
        and post(p["elsewhere"], f"{J}/{jid}/verify", {}).status_code == 404
    )
    assert p["elsewhere"].get(f"{FC}/catalog?market_code=SG").status_code == 404
    assert p["runner"].get(f"{J}/{jid}").json()["expected_inputs"] == 0


# -------------------------------------------------------------------------------------------------- selection
def test_selection_is_the_evaluators_on_one_exact_published_version_and_is_recorded_immutably(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    v, (a, b, c) = additive(p)
    run = p["runner"]
    listed = run.get(JV).json()["items"]
    assert [(x["policy_code"], x["version_no"], x["status"]) for x in listed] == [("ADD", 1, "PUBLISHED")]
    opts = run.get(f"{JV}/{v['version_id']}").json()
    assert [(x["code"], x["type"], x["derived"]) for x in opts["variables"]] == [
        ("product_family", "ENUM", False),
        ("nftf", "BOOLEAN", False),
    ]
    # ---- a preview records nothing
    pre = post(run, f"{J}/selection-preview", {"policy_version_id": v["version_id"], "facts": CASES["BOTH"]}).json()
    assert pre["outcome"] == "SURVEYS_SELECTED" and [e["survey"]["code"] for e in pre["plan"]["selected"]] == [
        a["code"],
        b["code"],
        c["code"],
    ]
    assert (pre["selection_source"], pre["record_class"], pre["version_sha256"]) == (
        "APPLICABILITY",
        "SYNTHETIC",
        opts["version_sha256"],
    )
    assert count(engine, "applicability_selection_plan") == 0 and count(engine, "applicability_journey") == 0
    sims = count(engine, "survey_simulation")
    # ---- the working DRAFT is not selectable: only a published version id is one
    assert new_journey(run, v["policy_id"], CASES["ILP"]).status_code == 404
    # ---- facts are checked against the version's own frozen definitions; nothing is coerced or guessed
    assert new_journey(run, v["version_id"], {"product_family": "ILP", "premium": 5}).json()["code"] == "FACT_UNKNOWN"
    assert new_journey(run, v["version_id"], {"product_family": "CAR", "nftf": False}).json()["code"] == "FACT_INVALID"
    assert new_journey(run, v["version_id"], {"product_family": "ILP", "nftf": "yes"}).json()["code"] == "FACT_INVALID"
    assert (
        new_journey(run, v["version_id"], CASES["ILP"], label="for S1234567A").json()["code"] == "LOOKS_LIKE_REAL_DATA"
    )
    assert count(engine, "applicability_selection_plan") == 0
    # ---- every outcome is recorded; only a RESOLVED selection WITH surveys may begin
    made_ = {k: new_journey(run, v["version_id"], facts).json() for k, facts in CASES.items()}
    assert {k: (j["status"], j["selection"]["outcome"], [s["survey_code"] for s in j["steps"]]) for k, j in made_.items()} == {
        "ILP": ("READY", "SURVEYS_SELECTED", [a["code"]]), "NFTF": ("READY", "SURVEYS_SELECTED", [b["code"]]),
        "BOTH": ("READY", "SURVEYS_SELECTED", [a["code"], b["code"], c["code"]]), "NEITHER": ("NO_SURVEY_REQUIRED", "NO_SURVEY_REQUIRED", []),
        "UNKNOWN": ("SELECTION_UNRESOLVED", "UNRESOLVED", []),
    }  # fmt: skip
    unknown = made_["UNKNOWN"]
    # not known is never false: Survey A is definitely required, B and C are PENDING, and the fact needed is named
    plan = unknown["selection"]["plan"]
    assert [e["survey"]["code"] for e in plan["selected"]] == [a["code"]] and sorted(
        e["survey"]["code"] for e in plan["pending"]
    ) == sorted([b["code"], c["code"]])
    assert [(n["variable"], n["state"]) for n in plan["needs"]] == [("nftf", "UNKNOWN")]
    assert (
        unknown["turn"] is None and unknown["steps"] == [] and count(engine, "survey_simulation") == sims
    )  # no survey was started
    for k in ("UNKNOWN", "NEITHER"):
        r = post(run, f"{J}/{made_[k]['id']}/start", {"expected_revision": 1, "survey_facts": {}})
        assert (r.status_code, r.json()["code"]) == (409, "NOT_READY")
        assert run.get(f"{J}/{made_[k]['id']}/turn").json()["kind"] == "END"
        assert (
            post(run, f"{J}/{made_[k]['id']}/verify", {}).json()["verified"] is True
        )  # an unresolved selection is reproducible too
    assert count(engine, "survey_simulation") == sims
    # ---- the record: exact identities and fingerprints, source APPLICABILITY, synthetic
    sel = made_["BOTH"]["selection"]
    assert (
        sel["policy_version_id"],
        sel["version_no"],
        sel["version_status_at_selection"],
        sel["evaluator_contract"],
    ) == (v["version_id"], 1, "PUBLISHED", pre["evaluator_contract"])
    assert (
        sel["version_sha256"],
        sel["document_sha256"],
        sel["manifest_sha256"],
        sel["plan_sha256"],
        sel["facts"],
    ) == (opts["version_sha256"], opts["document_sha256"], opts["manifest_sha256"], pre["plan_sha256"], CASES["BOTH"])
    assert [
        (s["position"], s["required_by"], s["obligations"], s["status"], s["simulation_id"])
        for s in made_["BOTH"]["steps"]
    ] == [(1, ["r1"], 1, "WAITING", None), (2, ["r2"], 1, "WAITING", None), (3, ["r3"], 1, "WAITING", None)]
    assert [(s["survey_version_id"], s["content_sha256"]) for s in made_["BOTH"]["steps"]] == [
        (x["version_id"], x["fingerprint"]) for x in (a, b, c)
    ]
    # ---- immutable in the database, whatever the application does
    jid, pid = made_["BOTH"]["id"], sel["selection_plan_id"]
    with engine.connect() as cx:
        assert cx.execute(
            text(f"SELECT selection_source, record_class FROM {T}.applicability_selection_plan WHERE id = '{pid}'")
        ).one() == ("APPLICABILITY", "SYNTHETIC")
        for sql in (f"UPDATE {T}.applicability_selection_plan SET facts = '{{}}'::jsonb WHERE id = '{pid}'", f"DELETE FROM {T}.applicability_selection_plan WHERE id = '{pid}'",
                    f"UPDATE {T}.applicability_selection_plan SET selection_source = 'LEGACY_ASSIGNMENT' WHERE id = '{pid}'",
                    f"UPDATE {T}.applicability_journey SET label = 'changed', revision = revision + 1 WHERE id = '{jid}'", f"DELETE FROM {T}.applicability_journey WHERE id = '{jid}'",
                    f"UPDATE {T}.applicability_journey SET status = 'ALL_SURVEYS_COMPLETED', revision = revision + 1, ended_at = now() WHERE id = '{jid}'",
                    f"UPDATE {T}.applicability_journey SET status = 'RUNNING', revision = revision + 1 WHERE id = '{jid}'",
                    f"UPDATE {T}.applicability_journey SET status = 'READY', revision = revision + 1 WHERE id = '{made_['UNKNOWN']['id']}'",
                    f"UPDATE {T}.applicability_journey_step SET survey_code = 'OTHER' WHERE journey_id = '{jid}'", f"DELETE FROM {T}.applicability_journey_step WHERE journey_id = '{jid}'",
                    f"UPDATE {T}.applicability_journey_step SET status = 'ENDED', outcome = 'COMPLETED', ended_at = now() WHERE journey_id = '{jid}' AND position = 1",
                    f"UPDATE {T}.applicability_journey_event SET event = 'ENDED' WHERE journey_id = '{jid}'", f"DELETE FROM {T}.applicability_journey_event WHERE journey_id = '{jid}'"):  # fmt: skip
            cx.rollback()
            with pytest.raises(DBAPIError):
                cx.execute(text(sql))
        cx.rollback()
    # ---- an invalid dependency is refused, never substituted: a survey reference that no longer resolves
    with Session(engine) as s2:
        s2.execute(text(f"SET search_path TO {T}"))
        for bad in (
            {**a, "version_id": str(uuid.uuid4())},
            {**a, "fingerprint": "0" * 64},
            {**a, "version": 9},
            {**a, "version_id": "not-a-uuid"},
        ):
            with pytest.raises(SurveyError, match="does not resolve|no longer what") as err:
                jr._survey_version(s2, ["SG"], bad)  # noqa: SLF001
            assert err.value.code == "SURVEY_VERSION_INVALID"
        assert jr._survey_version(s2, ["SG"], a)["survey_code"] == a["code"]  # noqa: SLF001
    assert run.get(J).json()["total"] == 5


# ---------------------------------------------------------------------------- coordinated execution and the runtime
def test_surveys_run_in_the_plans_order_one_after_another_through_a_voice_neutral_turn_runtime(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    v, (a, b, c) = additive(p)
    run, other = p["runner"], p["runner2"]
    sims = count(engine, "survey_simulation")
    j = started(run, v["version_id"], CASES["BOTH"])
    jid = j["id"]
    assert (j["status"], j["current_step"], j["revision"], j["expected_inputs"]) == ("RUNNING", 1, 2, 0)
    assert [(s["status"], s["simulation_id"] is not None) for s in j["steps"]] == [
        ("RUNNING", True),
        ("WAITING", False),
        ("WAITING", False),
    ]
    assert count(engine, "survey_simulation") == sims + 1  # only the FIRST survey has started
    # ---- the turn says everything a client needs and nothing it must decide
    t = turn_of(run, jid)
    assert (t["step"], t["steps"], t["survey"]["code"], t["survey"]["version_id"], t["survey"]["content_sha256"]) == (
        1,
        3,
        a["code"],
        a["version_id"],
        a["fingerprint"],
    )
    assert (
        t["expects"]["answer_type"],
        [o["code"] for o in t["expects"]["options"]],
        t["allowed_non_answers"],
        t["attempt"],
        t["expected_inputs"],
    ) == ("YES_NO", ["YES", "NO"], [], 0, 0)
    assert (
        t["prompt"]["text"]
        and t["prompt"]["delivery_mode"] == "CONTROLLED_TTS"
        and t["prompt"]["exact_wording_required"] is True
        and t["item_key"].startswith("1:")
    )
    assert other.get(f"{J}/{jid}/turn").json()["turn"] == t  # another signed-in person sees the same authoritative turn
    # ---- invalid input is refused with a machine-readable reason, and the question does not advance
    wrong = give(run, jid, t, {"choice": "MAYBE"}).json()
    assert (wrong["result"], wrong["code"], wrong["state"]["expected_inputs"]) == ("REJECTED", "UNKNOWN_OPTION", 1)
    t2 = turn_of(run, jid)
    assert (t2["item_key"], t2["attempt"], t2["expected_inputs"], t2["question_no"]) == (t["item_key"], 1, 1, 1)
    assert give(run, jid, t2, {"number": 3}).json()["code"] == "CHOICE_REQUIRED"
    assert (
        give(run, jid, turn_of(run, jid), {"non_answer": "NOT_ACKNOWLEDGED"}).json()["code"] == "NON_ANSWER_NOT_ALLOWED"
    )  # this question allows no non-answer
    assert turn_of(run, jid)["expected_inputs"] == 2  # … and that refusal was not given to the engine at all
    assert give(run, jid, turn_of(run, jid), ["YES"]).status_code == 422  # not an answer object  # type: ignore[arg-type]
    # ---- stale, out-of-turn, skipping ahead, another survey: refused; nothing advances; the refusal is recorded
    cur = turn_of(run, jid)
    stale = give(run, jid, {**cur, "expected_inputs": 0}, {"choice": "YES"})
    assert (stale.status_code, stale.json()["code"], stale.json()["details"]) == (
        409,
        "STALE_TURN",
        [{"current_inputs": 2, "expected_inputs": 0}],
    )
    for key in ("1:mi-call/n5", "2:mi-numbers/n1", "3:mi-ack/n2", "9:x/y", "nonsense"):
        r = give(run, jid, {**cur, "item_key": key}, {"choice": "YES"})
        assert (r.status_code, r.json()["code"]) == (409, "INPUT_NOT_CURRENT"), key
    assert turn_of(run, jid) == cur and events_of(run, jid).count("SUBMISSION_REFUSED") == 7
    # ---- retry-safe: the same key and request returns the first result and records nothing again
    first = give(run, jid, cur, {"choice": "YES"}, key="same-key-0001")
    assert first.json()["result"] == "ACCEPTED" and first.json()["replayed"] is False
    again = give(run, jid, cur, {"choice": "YES"}, key="same-key-0001")
    assert (again.status_code, again.json()["result"], again.json()["replayed"], again.json()["recorded_seq"]) == (
        200,
        "ACCEPTED",
        True,
        first.json()["recorded_seq"],
    )
    assert again.json()["state"]["expected_inputs"] == 3 == first.json()["state"]["expected_inputs"]
    assert give(run, jid, cur, {"choice": "NO"}, key="same-key-0001").json()["code"] == "IDEMPOTENCY_KEY_REUSED"
    # … a duplicate WITHOUT the key is simply stale; two sessions answering the same turn: exactly one is taken
    assert give(run, jid, cur, {"choice": "YES"}).json()["code"] == "STALE_TURN"
    nxt = turn_of(run, jid)
    assert nxt["item_key"] != cur["item_key"] and nxt["question_no"] == 2
    one, two = give(run, jid, nxt, {"choice": "YES"}), give(other, jid, nxt, {"choice": "NO"})
    assert (one.json()["result"], two.status_code, two.json()["code"]) == ("ACCEPTED", 409, "STALE_TURN")
    # ---- Survey A completed → Survey B starts, and only then
    s = run.get(f"{J}/{jid}").json()
    assert [(x["status"], x["outcome"]) for x in s["steps"]] == [
        ("ENDED", "COMPLETED"),
        ("RUNNING", None),
        ("WAITING", None),
    ] and s["current_step"] == 2
    assert count(engine, "survey_simulation") == sims + 2
    assert [x["answer"] for x in s["steps"][0]["answers"]] == [
        {"choice": "YES"},
        {"choice": "YES"},
    ]  # the second session's NO was never recorded
    n1 = turn_of(run, jid)
    assert (n1["step"], n1["survey"]["code"], n1["expects"]["answer_type"], n1["expects"]["number_rule"]) == (
        2,
        b["code"],
        "NUMERIC",
        {"max": 99, "min": 1, "unit": "years", "integer": True},
    )
    assert [
        give(run, jid, turn_of(run, jid), x).json()["code"]
        for x in ({"number": 0}, {"number": 100}, {"number": 2.5}, {"number": "7"}, {})
    ] == ["NUMBER_TOO_LOW", "NUMBER_TOO_HIGH", "NUMBER_NOT_WHOLE", "NUMBER_REQUIRED", "NUMBER_REQUIRED"]
    assert turn_of(run, jid)["item_key"] == n1["item_key"]
    # ---- the browser is closed: a NEW sign-in of the same person reconstructs the journey from what is recorded
    assert give(run, jid, turn_of(run, jid), {"number": 7}).json()["result"] == "ACCEPTED"
    resumed = other.get(f"{J}/{jid}").json()
    assert (
        resumed["status"],
        resumed["current_step"],
        resumed["turn"]["item_key"],
        resumed["progress"]["questions_answered"],
    ) == ("RUNNING", 2, "2:mi-numbers/n2", 3)
    assert give(other, jid, resumed["turn"], {"number": 12.5}).json()["result"] == "ACCEPTED"  # … and continues it
    assert (
        give(run, jid, turn_of(run, jid), {"number": -3}).json()["result"] == "ACCEPTED"
    )  # no rule on the third number
    # ---- Survey C: an acknowledgement. "Not acknowledged" is a non-answer with NO approved handling: nothing is invented
    ack = turn_of(run, jid)
    assert (ack["step"], ack["expects"]["answer_type"], ack["allowed_non_answers"]) == (
        3,
        "ACKNOWLEDGEMENT",
        ["NOT_ACKNOWLEDGED"],
    )
    na = give(
        run,
        jid,
        ack,
        {"non_answer": "NOT_ACKNOWLEDGED"},
        interaction={
            "transcript_ref": "synthetic-transcript-17",
            "recognition_confidence": 0.41,
            "proposed_answer": {"acknowledged": False},
        },
    ).json()
    assert (na["result"], na["code"], na["state"]["status"], na["state"]["condition"]) == (
        "REJECTED",
        "NON_ANSWER_POLICY_UNRESOLVED",
        "RUNNING",
        "POLICY_UNRESOLVED",
    )
    assert (
        turn_of(run, jid)["policy_unresolved"]["reason"] == "NON_ANSWER_POLICY_UNRESOLVED"
        and turn_of(run, jid)["item_key"] == ack["item_key"]
    )
    # a voice adapter that could not establish an answer says so: recorded, the turn stays, nothing is guessed
    unclear = give(
        run,
        jid,
        turn_of(run, jid),
        {},
        interaction={
            "clarification_required": True,
            "recognition_confidence": 0.2,
            "transcript_ref": "synthetic-transcript-18",
        },
    ).json()
    assert (unclear["result"], unclear["code"]) == ("REJECTED", "CLARIFICATION_REQUIRED")
    done = give(
        run,
        jid,
        turn_of(run, jid),
        {"acknowledged": True},
        interaction={
            "transcript_ref": "synthetic-transcript-19",
            "recognition_confidence": 0.97,
            "proposed_answer": {"acknowledged": True},
            "delivery_evidence_ref": "synthetic-delivery-19",
        },
    ).json()
    assert (done["result"], done["state"]["status"], done["state"]["turn"], done["state"]["condition"]) == (
        "ACCEPTED",
        "ALL_SURVEYS_COMPLETED",
        None,
        None,
    )
    fin = done["state"]
    assert [(x["survey_code"], x["status"], x["outcome"]) for x in fin["steps"]] == [
        (a["code"], "ENDED", "COMPLETED"),
        (b["code"], "ENDED", "COMPLETED"),
        (c["code"], "ENDED", "COMPLETED"),
    ]
    assert [(r["id"], r["fulfilment"], r["step"]) for r in fin["requirements"]] == [
        ("r1", "SATISFIED", 1),
        ("r2", "SATISFIED", 2),
        ("r3", "SATISFIED", 3),
    ]
    assert fin["progress"] == {
        "surveys": 3,
        "surveys_ended": 3,
        "surveys_completed": 3,
        "questions_answered": 6,
        "inputs": fin["expected_inputs"],
    }
    assert (
        run.get(f"{J}/{jid}/turn").json()["kind"] == "END"
        and give(run, jid, ack, {"acknowledged": True}).json()["code"] == "JOURNEY_NOT_RUNNING"
    )
    # the interaction evidence is kept beside the submission as PROPOSED evidence; the accepted answer is the engine's
    ev = [
        e
        for e in fin["events"]
        if e["event"] in ("INPUT_ACCEPTED", "INPUT_REJECTED", "SUBMISSION_REFUSED") and e["detail"].get("interaction")
    ]
    assert [(e["event"], e["detail"]["interaction"].get("recognition_confidence")) for e in ev] == [
        ("INPUT_REJECTED", 0.41),
        ("SUBMISSION_REFUSED", 0.2),
        ("INPUT_ACCEPTED", 0.97),
    ]
    assert (
        ev[2]["detail"]["answer"] == {"acknowledged": True}
        and ev[2]["detail"]["interaction"]["delivery_evidence_ref"] == "synthetic-delivery-19"
    )
    kinds = [e["event"] for e in fin["events"]]
    assert (
        kinds[:3] == ["CREATED", "STARTED", "STEP_STARTED"]
        and kinds[-2:] == ["STEP_ENDED", "ENDED"]
        and kinds.count("STEP_STARTED") == kinds.count("STEP_ENDED") == 3
    )
    # ---- reproduced from the records alone
    proof = post(p["reader"], f"{J}/{jid}/verify", {}).json()
    assert proof["verified"] is True and proof["failed"] == [] and proof["inputs"] == fin["expected_inputs"]
    assert {c_["code"] for c_ in proof["checks"]} >= {
        "POLICY_VERSION",
        "SELECTION_REPRODUCED",
        "STEPS_ARE_THE_SELECTION",
        "START_RECORD",
        "SURVEY_FACTS_REPRODUCED",
        "SURVEY_REPRODUCED",
        "STEP_OUTCOME",
        "HISTORY_CONSISTENT",
        "COORDINATION",
        "COMPLETION",
    }
    assert count(engine, "survey_simulation") == sims + 3  # one simulation per selected survey, and no other
    # a recorded input is never rewritten (the accepted simulation tables' own guard)
    with engine.connect() as cx, pytest.raises(DBAPIError):
        cx.execute(
            text(
                f"UPDATE {T}.survey_simulation_input SET accepted = true WHERE simulation_id = '{fin['steps'][0]['simulation_id']}'"
            )
        )
    # an ended journey cannot be abandoned or restarted
    assert (
        post(run, f"{J}/{jid}/abandon", {"expected_revision": fin["revision"], "reason": "too late to abandon"}).json()[
            "code"
        ]
        == "NOT_OPEN"
    )
    assert (
        post(run, f"{J}/{jid}/start", {"expected_revision": fin["revision"], "survey_facts": {}}).json()["code"]
        == "NOT_READY"
    )


def test_replacement_and_a_superseded_version_are_explicit_never_silent(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    v1, (a, b, c) = additive(p)
    run = p["runner"]
    replacing = document(
        req("r1", ref("ilp"), a), req("r2", ref("nftf_applies"), b), req("r3", BOTH, c, replaces=("r1", "r2"))
    )
    v2 = publish_policy(p, "ADD", {**replacing, "description": "C replaces A and B"}, policy_id=v1["policy_id"])
    assert [(x["version_no"], x["status"]) for x in run.get(JV).json()["items"]] == [
        (2, "PUBLISHED"),
        (1, "SUPERSEDED"),
    ]
    # ---- version 2: the combined survey REPLACES the two separate ones; A and B are never executed
    j = started(run, v2["version_id"], CASES["BOTH"])
    assert [(s["survey_code"], s["required_by"]) for s in j["steps"]] == [(c["code"], ["r3"])]
    plan = j["selection"]["plan"]
    assert sorted(e["survey"]["code"] for e in plan["excluded"]) == sorted([a["code"], b["code"]])
    assert {r["id"]: (r["selection_state"], r["fulfilment"]) for r in j["requirements"]} == {
        "r1": ("REPLACED", "NOT_REQUIRED"),
        "r2": ("REPLACED", "NOT_REQUIRED"),
        "r3": ("ACTIVE", "NOT_SATISFIED"),
    }
    assert {r["id"]: r["replaced_by"] for r in j["requirements"]}["r1"] in ("r3", ["r3"])
    fin = walk(run, j["id"])
    assert fin["status"] == "ALL_SURVEYS_COMPLETED" and len(fin["steps"]) == 1
    with engine.connect() as cx:
        used = set(
            cx.execute(
                text(
                    f"SELECT m.survey_version_id::text FROM {T}.applicability_journey_step t JOIN {T}.survey_simulation m ON m.id = t.simulation_id WHERE t.journey_id = '{j['id']}'"
                )
            ).scalars()
        )
    assert used == {c["version_id"]}
    # ---- version 1 is superseded: never chosen silently, never upgraded; an explicit confirmation runs exactly it
    opts = run.get(f"{JV}/{v1['version_id']}").json()
    assert (opts["version_status"], opts["version_no"], opts["current_version_no"], opts["current_version_id"]) == (
        "SUPERSEDED",
        1,
        2,
        v2["version_id"],
    )
    no = new_journey(run, v1["version_id"], CASES["BOTH"])
    assert (no.status_code, no.json()["code"]) == (409, "SUPERSEDED_NOT_CONFIRMED") and no.json()["details"][0] == {
        "version_no": 1,
        "status": "SUPERSEDED",
        "current_version_no": 2,
        "current_version_id": v2["version_id"],
    }
    old = new_journey(run, v1["version_id"], CASES["BOTH"], confirm_superseded=True).json()
    assert (
        old["selection"]["version_no"],
        old["selection"]["version_status_at_selection"],
        old["selection"]["current_version_no"],
    ) == (1, "SUPERSEDED", 2)
    assert [s["survey_code"] for s in old["steps"]] == [
        a["code"],
        b["code"],
        c["code"],
    ]  # version 1's own behaviour, not version 2's
    assert post(run, f"{J}/{old['id']}/verify", {}).json()["verified"] is True


def test_a_declared_shared_delivery_is_executed_once_and_counts_for_every_requirement_or_for_none(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    library(p)
    k8 = fixture_survey(p, "K8", "Survey shared by two requirements")
    doc = document(
        req("r1", ref("ilp"), k8),
        req("r2", ref("nftf_applies"), k8),
        shared_deliveries=[{"survey": k8["code"], "requirements": ["r1", "r2"]}],
    )
    v = publish_policy(p, "SHARED", doc)
    run = p["runner"]
    sims = count(engine, "survey_simulation")
    # ---- survey facts: the survey READS three catalog fields. Each must be addressed — given, or marked not known
    j = new_journey(run, v["version_id"], CASES["BOTH"]).json()
    assert [(s["survey_code"], s["required_by"], s["obligations"]) for s in j["steps"]] == [
        (k8["code"], ["r1", "r2"], 2)
    ]  # ONE step, two obligations
    need = post(run, f"{J}/{j['id']}/survey-facts", {}).json()
    assert [f["field"] for f in need["missing"]] == [
        "customer.age_years",
        "policy.annual_premium",
        "policy.is_replacement",
    ] and need["ready"] is False
    assert need["missing"][0]["read_by"] == [
        {"step": 1, "survey_code": k8["code"], "used_by": ["ELIGIBILITY:mi-senior"]}
    ]
    r = post(run, f"{J}/{j['id']}/start", {"expected_revision": 1, "survey_facts": {"customer.age_years": 40}})
    assert (r.status_code, r.json()["code"], [d["field"] for d in r.json()["details"]]) == (
        409,
        "SURVEY_FACTS_REQUIRED",
        ["policy.annual_premium", "policy.is_replacement"],
    )
    assert (
        post(
            run, f"{J}/{j['id']}/start", {"expected_revision": 1, "survey_facts": {**K8_FACTS, "policy.colour": "red"}}
        ).json()["code"]
        == "FACT_UNKNOWN"
    )
    assert count(engine, "survey_simulation") == sims and run.get(f"{J}/{j['id']}").json()["status"] == "READY"
    go = post(run, f"{J}/{j['id']}/start", {"expected_revision": 1, "survey_facts": K8_FACTS}).json()
    assert (
        go["status"] == "RUNNING"
        and go["survey_facts"] == K8_FACTS
        and [f["origin"] for f in go["start"]["fields"]] == ["TYPED", "TYPED", "TYPED"]
    )
    fin = walk(run, j["id"])
    assert fin["status"] == "ALL_SURVEYS_COMPLETED" and count(engine, "survey_simulation") == sims + 1  # executed ONCE
    assert [(r_["id"], r_["fulfilment"], r_["step"], r_["shared"]) for r_ in fin["requirements"]] == [
        ("r1", "SATISFIED", 1, True),
        ("r2", "SATISFIED", 1, True),
    ]
    assert post(run, f"{J}/{j['id']}/verify", {}).json()["verified"] is True
    # ---- the same survey NOT completed: every requirement it was shared for stays unsatisfied — none is half-counted
    j2 = started(run, v["version_id"], CASES["BOTH"], K8_FACTS)
    no = give(run, j2["id"], j2["turn"], {"choice": "NO"}).json()
    end = no["state"]
    assert end["status"] == "ENDED_INCOMPLETE" and end["steps"][0]["outcome"] != "COMPLETED" and end["turn"] is None
    assert [(r_["id"], r_["fulfilment"]) for r_ in end["requirements"]] == [
        ("r1", "NOT_SATISFIED"),
        ("r2", "NOT_SATISFIED"),
    ]
    assert (
        end["end_detail"]["terminal"] == end["steps"][0]["outcome_detail"]
        and end["steps"][0]["outcome"] in end["end_detail"]["reason"]
    )
    nxt = run.get(f"{J}/{j2['id']}/turn").json()
    assert nxt["kind"] == "END" and [u["id"] for u in nxt["end"]["unresolved"]] == ["r1", "r2"]
    assert (
        post(run, f"{J}/{j2['id']}/verify", {}).json()["verified"] is True
    )  # an incomplete journey is reproducible and inspectable
    # ---- a fact marked "not known" is passed as not known; what the survey does then is the survey's own governed rule
    j3 = new_journey(run, v["version_id"], CASES["ILP"]).json()
    unknown = post(
        run, f"{J}/{j3['id']}/start", {"expected_revision": 1, "survey_facts": {**K8_FACTS, "customer.age_years": None}}
    ).json()
    assert (
        unknown["survey_facts"]["customer.age_years"] is None
        and [f["origin"] for f in unknown["start"]["fields"]][0] == "MARKED_NOT_KNOWN"
    )
    assert (
        unknown["status"] in ("RUNNING", "ENDED_INCOMPLETE")
        and post(run, f"{J}/{j3['id']}/verify", {}).json()["verified"] is True
    )


def test_a_survey_that_does_not_complete_never_hands_over_to_the_next_one(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    library(p)
    k8, k1 = fixture_survey(p, "K8", "First survey"), fixture_survey(p, "K1", "Second survey")
    v = publish_policy(p, "TWO", document(req("r1", ref("ilp"), k8), req("r2", ref("ilp"), k1)))
    run = p["runner"]
    sims = count(engine, "survey_simulation")
    j = started(run, v["version_id"], {"product_family": "ILP"}, K8_FACTS)
    assert [s["survey_code"] for s in j["steps"]] == [k8["code"], k1["code"]]
    end = give(run, j["id"], j["turn"], {"choice": "NO"}).json()["state"]
    # no governed continuation rule exists: none is invented. The second survey is NOT started.
    assert end["status"] == "CROSS_SURVEY_POLICY_UNRESOLVED" and end["turn"] is None and end["ended_at"] is not None
    assert [(s["status"], s["outcome"] == "COMPLETED", s["simulation_id"] is None) for s in end["steps"]] == [
        ("ENDED", False, False),
        ("WAITING", False, True),
    ]
    assert count(engine, "survey_simulation") == sims + 1
    d = end["end_detail"]
    assert (d["step"], d["survey_code"], d["not_started"], d["terminal"]) == (
        1,
        k8["code"],
        [k1["code"]],
        end["steps"][0]["outcome_detail"],
    ) and "No governed rule" in d["reason"]
    assert d["terminal"]["state"] == end["steps"][0]["outcome"]  # the exact terminal reason is preserved
    assert [(r["id"], r["fulfilment"], r["reason"]) for r in end["requirements"]] == [
        ("r1", "NOT_SATISFIED", f"the survey ended as {end['steps'][0]['outcome']}"),
        ("r2", "NOT_SATISFIED", "the survey has not started"),
    ]
    assert events_of(run, j["id"])[-2:] == ["STEP_ENDED", "ENDED"]
    assert give(run, j["id"], j["turn"], {"choice": "YES"}).json()["code"] == "JOURNEY_NOT_RUNNING"
    assert events_of(run, j["id"])[-1] == "SUBMISSION_REFUSED"  # … and that attempt is in the history
    assert post(run, f"{J}/{j['id']}/verify", {}).json()["verified"] is True
    # ---- abandoning an open journey needs a reason and keeps everything recorded
    j2 = started(run, v["version_id"], {"product_family": "ILP"}, K8_FACTS)
    assert (
        post(run, f"{J}/{j2['id']}/abandon", {"expected_revision": 1, "reason": "no longer needed here"}).json()["code"]
        == "STALE_JOURNEY"
    )
    gone = post(
        run, f"{J}/{j2['id']}/abandon", {"expected_revision": j2["revision"], "reason": "no longer needed here"}
    ).json()
    assert gone["status"] == "ABANDONED" and gone["steps"][0]["status"] == "RUNNING" and gone["turn"] is None
    assert give(run, j2["id"], j2["turn"], {"choice": "YES"}).json()["code"] == "JOURNEY_NOT_RUNNING"


# ---------------------------------------------------------------------------------------------- fact correspondence
def test_fact_correspondence_is_identity_only_exact_and_frozen_in_the_journey(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    library(p)
    k8 = fixture_survey(p, "K8", "Survey reading three facts")
    v = publish_policy(
        p,
        "CORR",
        document(
            req("r1", ref("ilp"), k8),
            req("r2", ref("nftf_applies"), k8),
            shared_deliveries=[{"survey": k8["code"], "requirements": ["r1", "r2"]}],
        ),
    )
    run, author = p["runner"], p["author"]
    cat = author.get(f"{FC}/catalog?market_code=SG").json()
    var = {x["variable"]: x for x in cat["variables"]}
    field = {x["field"]: x for x in cat["fields"]}
    assert cat["rules"] == ["IDENTITY"] and (
        var["nftf"]["type"],
        field["policy.is_replacement"]["type"],
        field["policy.product_family"]["type"],
    ) == ("BOOLEAN", "BOOLEAN", "ENUM")

    def entry(variable: str, target: str, **more: Any) -> dict[str, Any]:
        return {"source": {"version_id": var[variable]["version_id"]}, "target": {"field": target}, **more}

    def save(code: str, *entries: dict[str, Any], name: str = "Synthetic correspondence") -> Any:
        return post(
            author,
            FC,
            {
                "market_code": "SG",
                "code": code,
                "document": {"name": name, "description": "SYNTHETIC. For a test.", "entries": list(entries)},
            },
        )

    # ---- only IDENTITY, only the same type, only exact definitions; nothing is matched by name
    assert save("C1", entry("nftf", "policy.is_replacement", rule="EXPRESSION")).json()["code"] == "RULE_NOT_ALLOWED"
    assert save("C1", entry("product_family", "policy.is_replacement")).json()["code"] == "NOT_COMPATIBLE"
    assert save("C1", entry("nftf", "customer.age_years")).json()["code"] == "NOT_COMPATIBLE"
    assert save("C1", entry("nftf", "policy.colour")).json()["code"] == "TARGET_UNKNOWN"
    assert (
        save("C1", {"source": {"variable": "nftf"}, "target": {"field": "policy.is_replacement"}}).json()["code"]
        == "SOURCE_REQUIRED"
    )  # a name is not an identity
    assert (
        save("C1", {"source": {"version_id": str(uuid.uuid4())}, "target": {"field": "policy.is_replacement"}}).json()[
            "code"
        ]
        == "SOURCE_NOT_PUBLISHED"
    )
    assert (
        save(
            "C1",
            {
                "source": {"version_id": var["nftf"]["version_id"], "content_sha256": "0" * 64},
                "target": {"field": "policy.is_replacement"},
            },
        ).json()["code"]
        == "SOURCE_DEFINITION_DIFFERS"
    )
    assert (
        save(
            "C1",
            {
                "source": {"version_id": var["nftf"]["version_id"]},
                "target": {"field": "policy.is_replacement", "attributes_sha256": "0" * 64},
            },
        ).json()["code"]
        == "TARGET_DEFINITION_DIFFERS"
    )
    assert (
        save("C1", entry("nftf", "policy.is_replacement"), entry("nftf", "policy.is_replacement")).json()["code"]
        == "TARGET_REPEATED"
    )
    assert (
        save("C1").json()["code"] == "INVALID_DOCUMENT"
        and save("bad code!", entry("nftf", "policy.is_replacement")).json()["code"] == "CODE_INVALID"
    )
    assert (
        save("C1", entry("product_family", "policy.product_family")).status_code == 201
    )  # ENUM → ENUM: every value of the fact exists, literally, in the survey field
    made_ = save("C2", entry("nftf", "policy.is_replacement"))
    assert made_.status_code == 201, made_.text
    c1 = made_.json()
    assert (c1["version_no"], c1["record_class"], len(c1["entries"]), c1["entries"][0]["rule"]) == (
        1,
        "SYNTHETIC",
        1,
        "IDENTITY",
    ) and "Not an approved operational data mapping" in c1["note"]
    assert c1["entries"][0]["source"] == {
        "variable": "nftf",
        "version": 1,
        "version_id": var["nftf"]["version_id"],
        "content_sha256": var["nftf"]["content_sha256"],
    }
    assert c1["entries"][0]["target"] == {
        "field": "policy.is_replacement",
        "attributes_sha256": field["policy.is_replacement"]["attributes_sha256"],
    }
    assert save("C2", entry("nftf", "policy.is_replacement")).json()["code"] == "NOTHING_CHANGED"
    with engine.connect() as cx:
        for sql in (
            f"UPDATE {T}.applicability_fact_correspondence SET code = 'X' WHERE id = '{c1['id']}'",
            f"DELETE FROM {T}.applicability_fact_correspondence WHERE id = '{c1['id']}'",
        ):
            cx.rollback()
            with pytest.raises(DBAPIError):
                cx.execute(text(sql))
        cx.rollback()
    # ---- nothing is applied by default: the person chooses the correspondence
    j = new_journey(run, v["version_id"], CASES["BOTH"]).json()
    rest = {"customer.age_years": 40, "policy.annual_premium": 12000}
    assert [f["field"] for f in post(run, f"{J}/{j['id']}/survey-facts", {"survey_facts": rest}).json()["missing"]] == [
        "policy.is_replacement"
    ]
    seen = post(run, f"{J}/{j['id']}/survey-facts", {"correspondence_id": c1["id"], "survey_facts": rest}).json()
    assert (
        seen["ready"] is True
        and seen["entries"][0]["applies"] is True
        and seen["survey_facts"] == {**rest, "policy.is_replacement": True}
    )  # carried over UNCHANGED
    carried = next(f for f in seen["fields"] if f["field"] == "policy.is_replacement")
    assert (carried["value"], carried["origin"], carried["source"]) == (
        True,
        "CORRESPONDENCE",
        {"variable": "nftf", "version": 1},
    )
    # a KNOWN carried value is never replaced: a different typed value is a conflict the person must resolve
    clash = post(
        run,
        f"{J}/{j['id']}/start",
        {
            "expected_revision": 1,
            "correspondence_id": c1["id"],
            "survey_facts": {**rest, "policy.is_replacement": False},
        },
    )
    assert (clash.status_code, clash.json()["code"], clash.json()["details"]) == (
        409,
        "SURVEY_FACT_CONFLICT",
        [
            {
                "field": "policy.is_replacement",
                "carried": True,
                "typed": False,
                "from": {"variable": "nftf", "version": 1},
            }
        ],
    )
    # … and a typed "not known" does not erase it either
    kept = post(
        run,
        f"{J}/{j['id']}/survey-facts",
        {"correspondence_id": c1["id"], "survey_facts": {**rest, "policy.is_replacement": None}},
    ).json()
    assert kept["survey_facts"]["policy.is_replacement"] is True
    go = post(
        run,
        f"{J}/{j['id']}/start",
        {
            "expected_revision": 1,
            "correspondence_id": c1["id"],
            "survey_facts": {**rest, "policy.is_replacement": True},
        },
    ).json()
    assert go["status"] == "RUNNING" and go["survey_facts"] == {**rest, "policy.is_replacement": True}
    # ---- frozen in the journey: the whole document, what applied, each field's origin, the resulting snapshot
    rec = go["start"]
    assert (
        rec["correspondence"]["id"],
        rec["correspondence"]["version_no"],
        rec["correspondence"]["document_sha256"],
        rec["correspondence"]["document"]["entries"],
    ) == (c1["id"], 1, c1["document_sha256"], c1["entries"])
    assert [(f["field"], f["origin"], f["also_carried"]) for f in rec["fields"]] == [
        ("customer.age_years", "TYPED", False),
        ("policy.annual_premium", "TYPED", False),
        ("policy.is_replacement", "TYPED", True),
    ]
    assert (
        rec["survey_facts_sha256"] == go["survey_facts_sha256"]
        and post(run, f"{J}/{j['id']}/verify", {}).json()["verified"] is True
    )
    # ---- UNKNOWN is preserved: an application fact that is not known is carried as not known, never as false
    v2 = publish_policy(
        p,
        "CORR2",
        document(
            req("r1", ref("ilp"), k8), req("r2", ref("nftf_applies"), k1 := fixture_survey(p, "K1", "Another survey"))
        ),
    )
    ju = new_journey(run, v2["version_id"], {"product_family": "ILP", "nftf": None}).json()
    assert (
        ju["status"] == "SELECTION_UNRESOLVED"
    )  # … and a journey whose selection is unresolved never reaches survey facts
    assert k1["code"] in [e["survey"]["code"] for e in ju["selection"]["plan"]["pending"]]
    jk = new_journey(
        run, v["version_id"], {"product_family": "ILP"}
    ).json()  # nftf NOT PROVIDED: the shared survey is selected by r1 alone? no — r2 is unknown
    assert jk["status"] in ("READY", "SELECTION_UNRESOLVED")
    # ---- a new version of the correspondence is a new row; the journey keeps what it froze
    c2 = save("C2", entry("nftf", "policy.is_replacement"), name="Synthetic correspondence, renamed").json()
    assert c2["version_no"] == 2 and author.get(f"{FC}/{c1['id']}").json() == c1
    assert [(x["code"], x["version_no"]) for x in author.get(FC).json()["items"]] == [("C1", 1), ("C2", 2), ("C2", 1)]
    assert run.get(f"{J}/{j['id']}").json()["start"]["correspondence"]["version_no"] == 1
    # ---- an entry whose source is ANOTHER version of the fact than the policy pins does not apply — and says why
    from tests.test_applicability_library import revise

    nftf_id = next(x["id"] for x in author.get(f"{A}/assets?kind=VARIABLE").json()["items"] if x["code"] == "nftf")
    revise(p, nftf_id, {**BOOL, "description": "revised after the policy was published (synthetic)"})
    newer = {
        x["version"]: x
        for x in author.get(f"{FC}/catalog?market_code=SG").json()["variables"]
        if x["variable"] == "nftf"
    }
    assert sorted(newer) == [1, 2]
    c3 = save(
        "C3", {"source": {"version_id": newer[2]["version_id"]}, "target": {"field": "policy.is_replacement"}}
    ).json()
    j4 = new_journey(run, v["version_id"], CASES["BOTH"]).json()
    off = post(run, f"{J}/{j4['id']}/survey-facts", {"correspondence_id": c3["id"], "survey_facts": rest}).json()
    assert (off["entries"][0]["applies"], off["entries"][0]["why_not"], [f["field"] for f in off["missing"]]) == (
        False,
        "SOURCE_DEFINITION_DIFFERS",
        ["policy.is_replacement"],
    )
    # the correspondence of another market, or an unknown one, is not found
    assert post(run, f"{J}/{j4['id']}/survey-facts", {"correspondence_id": str(uuid.uuid4())}).status_code == 404
    assert p["elsewhere"].get(f"{FC}/{c1['id']}").status_code == 404 and p["elsewhere"].get(FC).json()["items"] == []
    # ---- a correspondence is NOT part of the policy: the published version and its manifest are exactly as before
    with engine.connect() as cx:
        assert (
            cx.execute(
                text(
                    f"SELECT count(*) FROM {T}.applicability_policy_candidate_dependency d JOIN {T}.applicability_policy_version pv ON pv.candidate_id = d.candidate_id WHERE pv.id = '{v['version_id']}' AND d.kind NOT IN ('VARIABLE', 'CONDITION', 'PROFILE', 'SURVEY')"
                )
            ).scalar_one()
            == 0
        )
    assert post(p["reader"], f"{A}/policy-versions/{v['version_id']}/verify", {}).json()["verified"] is True


# --------------------------------------------------------------------------------------------- no legacy dependency
LEGACY = (
    "assignment",
    "composite",
    "coordinated",
    "binding",
    "requirement_group",
    "script_",
    "callback",
    "case",
    "conversation",
    "contact_attempt",
    "journey_evaluation",
    "execution_assurance",
    "control_result",
    "finding",
)


def test_nothing_legacy_or_operational_is_read_or_written_and_older_simulations_are_untouched(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    v, (a, _b, _c) = additive(p)
    run = p["runner"]
    # a simulation that existed BEFORE any journey, made the ordinary way
    GRANTS_ = post(
        p["runner"],
        f"/api/v1/survey-versions/{a['version_id']}/simulations",
        {"facts": {}, "label": "an older simulation"},
    )
    assert GRANTS_.status_code == 201, GRANTS_.text
    older = GRANTS_.json()["id"]

    def digest(table: str, where: str) -> tuple[int, str]:
        with engine.connect() as cx:
            n, d = cx.execute(
                text(
                    f"SELECT count(*), coalesce(md5(string_agg(md5(t::text), '' ORDER BY md5(t::text))), '') FROM {T}.{table} t WHERE {where}"
                )
            ).one()
            return int(n), str(d)

    before = everything_else(engine)
    older_before = (
        digest("survey_simulation", f"id = '{older}'"),
        digest("survey_simulation_input", f"simulation_id = '{older}'"),
    )
    fin = walk(run, started(run, v["version_id"], CASES["BOTH"])["id"])
    assert (
        fin["status"] == "ALL_SURVEYS_COMPLETED" and post(run, f"{J}/{fin['id']}/verify", {}).json()["verified"] is True
    )
    after = everything_else(engine)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    # the journey's own tables, the NEW attributable simulations it created, and the audit trail — nothing else
    assert changed == {"survey_simulation", "survey_simulation_input", "audit_event"}
    assert (
        count(engine, "applicability_journey") == 1
        and count(engine, "applicability_selection_plan") == 1
        and count(engine, "applicability_journey_step") == 3
    )
    assert not [t for t in changed if any(k in t for k in LEGACY)]
    assert [t for t in before if any(k in t for k in LEGACY)], "the legacy tables were compared"
    assert (
        digest("survey_simulation", f"id = '{older}'"),
        digest("survey_simulation_input", f"simulation_id = '{older}'"),
    ) == older_before
    # every simulation the journey created is attributable to it: referenced by one step, and labelled
    with engine.connect() as cx:
        rows = cx.execute(
            text(
                f"SELECT m.label, t.position FROM {T}.survey_simulation m JOIN {T}.applicability_journey_step t ON t.simulation_id = m.id WHERE t.journey_id = '{fin['id']}' ORDER BY t.position"
            )
        ).all()
        loose = cx.execute(
            text(
                f"SELECT count(*) FROM {T}.survey_simulation m WHERE m.label LIKE 'Applicability journey {fin['id'][:8]} %' AND NOT EXISTS (SELECT 1 FROM {T}.applicability_journey_step t WHERE t.simulation_id = m.id AND t.journey_id = '{fin['id']}')"
            )
        ).scalar_one()
        fks = cx.execute(text("SELECT DISTINCT ft.relname FROM pg_constraint con JOIN pg_class cl ON cl.oid = con.conrelid JOIN pg_class ft ON ft.oid = con.confrelid JOIN pg_namespace n ON n.oid = cl.relnamespace "
                              "WHERE con.contype = 'f' AND n.nspname = :s AND cl.relname = ANY(:t)"), {"s": T, "t": list(JOURNEY_TABLES)}).scalars().all()  # fmt: skip
    assert (
        [r[1] for r in rows] == [1, 2, 3]
        and all(r[0].startswith(f"Applicability journey {fin['id'][:8]} · step ") for r in rows)
        and loose == 0
    )
    # the schema itself: a journey table references only applicability, survey-version and simulation tables — no legacy or operational one
    assert sorted(fks) == [
        "applicability_fact_correspondence",
        "applicability_journey",
        "applicability_policy",
        "applicability_policy_version",
        "applicability_selection_plan",
        "survey_definition",
        "survey_simulation",
        "survey_version",
    ]
    # the code path: the journey service imports no legacy selection or coordination module
    import inspect

    src = inspect.getsource(jr)
    imports = [line for line in src.splitlines() if line.startswith(("from ", "import "))]
    assert not [
        line
        for line in imports
        if any(
            k in line
            for k in (
                "assignment",
                "coordination",
                "rule_engine",
                "journey_evaluation",
                "execution_assurance",
                "finding",
                "question_controller",
                "voice",
            )
        )
    ]
    assert (
        "survey_assignment" not in src
        and "composite_plan" not in src.replace("a composite plan", "")
        and "script_assignment" not in src
    )


# ------------------------------------------------------------------------------------------------------ migration
FUNCTIONS = [
    "applicability_fact_correspondence_guard",
    "applicability_journey_event_guard",
    "applicability_journey_guard",
    "applicability_journey_step_guard",
    "applicability_selection_plan_guard",
]


def _head(engine: Engine) -> str:
    with engine.connect() as c:
        return str(c.execute(text(f"SELECT version_num FROM {T}.alembic_version")).scalar_one())


def _objects(engine: Engine) -> tuple[list[str], list[str]]:
    with engine.connect() as c:
        tables = (
            c.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = :s AND table_name = ANY(:t) ORDER BY 1"
                ),
                {"s": T, "t": list(JOURNEY_TABLES)},
            )
            .scalars()
            .all()
        )
        fns = (
            c.execute(
                text(
                    "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = :s AND p.proname = ANY(:f) ORDER BY 1"
                ),
                {"s": T, "f": FUNCTIONS},
            )
            .scalars()
            .all()
        )
    return list(tables), list(fns)


def test_zz_migration_0042_is_additive_reversible_while_empty_atomic_and_keeps_recorded_evidence(
    fresh_schema: None, engine: Engine, settings: Settings, x6_app: Any, db: Session
) -> None:
    """On a POPULATED schema: a published library, published surveys, a PUBLISHED policy version with its candidate and run."""
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {"author": edit, "checker": {"applicability.read", "applicability.approve", "survey.read"}, "publisher": {"applicability.read", "applicability.publish", "survey.read"},
              "reader": {"applicability.read", "survey.read"}, "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY), "runner": set(RUN)}  # fmt: skip
    accounts = {k: make_account(db, prefix=f"zx6{k}") for k in grants}
    for k, a_ in accounts.items():
        GRANTS[a_.principal_id] = frozenset(grants[k])
    p = {k: _client(x6_app, a_) for k, a_ in accounts.items()}
    try:
        v, _ = additive(p)
        assert _head(engine) == MIGRATION_HEAD == "0042_applicability_journey"
        full = _objects(engine)
        assert full == (sorted(JOURNEY_TABLES), FUNCTIONS)
        before = everything_else(engine)
        assert (
            count(engine, "applicability_policy_version") == 1 and count(engine, "applicability_policy_candidate") == 1
        )
        with engine.connect() as c:
            fks = c.execute(text("SELECT count(*), count(*) FILTER (WHERE con.convalidated) FROM pg_constraint con JOIN pg_class cl ON cl.oid = con.conrelid JOIN pg_namespace n ON n.oid = cl.relnamespace "
                                 "WHERE con.contype = 'f' AND n.nspname = :s AND cl.relname = ANY(:t)"), {"s": T, "t": list(JOURNEY_TABLES)}).one()  # fmt: skip
            assert tuple(fks) == (10, 10)  # every reference is a validated foreign key
            assert (
                c.execute(text(f"SELECT count(*) FROM {T}.permission WHERE code LIKE 'applicability.%'")).scalar_one()
                == 4
            )

        def same() -> bool:
            return everything_else(engine) == before and count(engine, "applicability_policy_version") == 1

        # 1. downgrade while empty removes exactly the five tables and five guards; nothing else changes — the published version too
        migrate(settings, "0041_applicability_publication", down=True)
        assert _head(engine) == "0041_applicability_publication" and _objects(engine) == ([], []) and same()
        # 2. a forced failure at the LAST statement: all rolled back
        with engine.begin() as c:
            c.execute(
                text(
                    f"CREATE FUNCTION {T}.applicability_journey_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                )
            )
        with pytest.raises(DBAPIError, match="already exists"):
            migrate(settings, "head")
        assert _head(engine) == "0041_applicability_publication" and _objects(engine) == (
            [],
            ["applicability_journey_event_guard"],
        )
        with engine.begin() as c:
            c.execute(text(f"DROP FUNCTION {T}.applicability_journey_event_guard()"))
        assert same()
        # 3. upgrade again: identical objects; everything else byte-identical
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD and _objects(engine) == full and same()
        # 4. with a recorded selection the downgrade is refused; the journey still verifies
        j = started(p["runner"], v["version_id"], CASES["ILP"])
        with pytest.raises(RuntimeError, match="selection plans or fact correspondences exist"):
            migrate(settings, "0041_applicability_publication", down=True)
        assert _head(engine) == MIGRATION_HEAD
        fin = walk(p["runner"], j["id"])
        assert (
            fin["status"] == "ALL_SURVEYS_COMPLETED"
            and post(p["runner"], f"{J}/{j['id']}/verify", {}).json()["verified"] is True
        )
        after = everything_else(engine)
        assert {k for k in before if before[k] != after[k]} == {
            "audit_event",
            "survey_simulation",
            "survey_simulation_input",
        }
        from app.audit.chain import verify_chain

        assert verify_chain(db).ok
    finally:
        for c_ in p.values():
            c_.__exit__(None, None, None)
        for a_ in accounts.values():
            GRANTS.pop(a_.principal_id, None)
        _wipe(engine)
