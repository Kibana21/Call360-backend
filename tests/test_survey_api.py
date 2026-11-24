# ruff: noqa: E501 — long request literals are kept on one line each
"""SS-03A.3 — the survey definition API, on the isolated test database.

No role holds a ``survey.*`` permission (owner decision D-182), so these tests grant them PER PERSON at the
authentication dependency, on top of that person's real session, cookies and CSRF token. Everything after that —
``require(permission)``, market scope, the identity rules, the database guards — is the real code."""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import Depends, Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.main import MIGRATION_HEAD, create_app
from app.security.authz import AuthContext, authenticate, get_db, resolve_auth
from tests.support import ORIGIN, Account, csrf_header, login, make_account
from tests.survey_support import fixture_bundle, namespaced, new_code, operations_for

ALL = frozenset({"survey.read", "survey.edit", "survey.approve", "survey.publish"})
GRANTS: dict[uuid.UUID, frozenset[str]] = {}
#: people placed OUTSIDE the survey's market for a test (every seeded local group is scoped to SG)
MARKETS: dict[uuid.UUID, frozenset[str]] = {}
PREFIXES = (
    "/api/v1/survey-definitions",
    "/api/v1/survey-candidates",
    "/api/v1/survey-versions",
    "/api/v1/survey-library",
    "/api/v1/survey-conditions",
    "/api/v1/survey-components",  # LIB-1
    "/api/v1/survey-simulations",  # SS-03B
    "/api/v1/survey-call-plans",  # SS-03B
    "/api/v1/survey-assignment",  # ASG-1
    "/api/v1/survey-evaluation",  # EVAL-1
    "/api/v1/survey-module",  # LIB-2: standalone modules and the one-module test
    "/api/v1/survey-applicability",  # APPL-X1: the stateless applicability prototype
)


def is_survey_path(path: str) -> bool:
    return path.startswith(PREFIXES)


#: The permissions matrix of SS-03A: every operation, the one permission it needs, and whether it changes state.
MATRIX = {
    ("POST", "/api/v1/survey-definitions"): "survey.edit",
    ("GET", "/api/v1/survey-definitions/workspace"): "survey.read",  # UX-HOME-1: read-only summary
    ("GET", "/api/v1/survey-definitions"): "survey.read",
    ("GET", "/api/v1/survey-definitions/{survey_id}"): "survey.read",
    ("GET", "/api/v1/survey-definitions/{survey_id}/draft"): "survey.read",
    ("POST", "/api/v1/survey-definitions/{survey_id}/draft/operations"): "survey.edit",
    ("POST", "/api/v1/survey-definitions/{survey_id}/draft/validate"): "survey.edit",
    ("GET", "/api/v1/survey-definitions/{survey_id}/draft/documents"): "survey.read",  # FI-1
    ("POST", "/api/v1/survey-definitions/{survey_id}/draft/save"): "survey.edit",  # FI-1
    ("GET", "/api/v1/survey-definitions/{survey_id}/history"): "survey.read",  # FI-2
    ("GET", "/api/v1/survey-candidates/{candidate_id}/documents"): "survey.read",  # FI-2
    ("POST", "/api/v1/survey-definitions/{survey_id}/candidates"): "survey.edit",
    ("GET", "/api/v1/survey-candidates/{candidate_id}"): "survey.read",
    ("POST", "/api/v1/survey-candidates/{candidate_id}/decision"): "survey.approve",
    ("POST", "/api/v1/survey-candidates/{candidate_id}/withdraw"): "survey.edit",
    ("POST", "/api/v1/survey-candidates/{candidate_id}/publish"): "survey.publish",
    ("GET", "/api/v1/survey-versions/{version_id}"): "survey.read",
    ("GET", "/api/v1/survey-versions/{version_id}/content"): "survey.read",
    ("GET", "/api/v1/survey-library/{kind}"): "survey.read",
    ("POST", "/api/v1/survey-conditions/evaluate"): "survey.read",
}


def with_grants(app: Any) -> Any:
    """Install the per-person test grants on an application (used by every survey API test module)."""

    def with_test_grants(request: Request, db: Session = Depends(get_db)) -> AuthContext:
        ctx = resolve_auth(request.app, request.cookies, db)
        return dataclasses.replace(
            ctx,
            permissions=ctx.permissions | GRANTS.get(ctx.principal_id, frozenset()),
            markets=MARKETS.get(ctx.principal_id, ctx.markets),
        )

    app.dependency_overrides[authenticate] = with_test_grants
    return app


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(settings.model_copy(update={"survey_definitions_enabled": True, "transcription_worker": False}))
    )


def _client(app: Any, account: Account) -> TestClient:
    c = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    c.__enter__()
    assert login(c, account).status_code == 200
    return c


@pytest.fixture()
def trio(
    survey_app: Any, db: Session
) -> Iterator[tuple[TestClient, TestClient, TestClient, tuple[Account, Account, Account]]]:
    """Author, checker and publisher — each given ALL FOUR permissions, so that only the identity rules can stop them."""
    people = (
        make_account(db, prefix="author"),
        make_account(db, prefix="checker"),
        make_account(db, prefix="publisher"),
    )
    for p in people:
        GRANTS[p.principal_id] = ALL
    clients = tuple(_client(survey_app, p) for p in people)
    yield clients[0], clients[1], clients[2], people
    for c in clients:
        c.__exit__(None, None, None)
    for p in people:
        GRANTS.pop(p.principal_id, None)


def post(c: TestClient, path: str, body: dict[str, Any] | None = None) -> Any:
    return c.post(path, json=body or {}, headers=csrf_header(c))


def submit(c: TestClient, sid: str, note: str = "") -> Any:
    """Submit the saved draft, acknowledging every server-governed warning with a reason (FI-2)."""
    findings = post(c, f"/api/v1/survey-definitions/{sid}/draft/validate").json().get("findings", [])
    acks = [
        {"code": f["code"], "at": f["at"], "reason": "Synthetic test content; acknowledged."}
        for f in findings
        if f["severity"] == "WARNING"
    ]
    return post(c, f"/api/v1/survey-definitions/{sid}/candidates", {"note": note, "acknowledgements": acks})


def make_survey(c: TestClient, prefix: str = "K1") -> tuple[str, str]:
    code = new_code()
    r = post(c, "/api/v1/survey-definitions", {"code": code, "name": f"Test {code}", "purpose": "synthetic"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    for op in operations_for(namespaced(fixture_bundle(prefix), "-" + code[2:]), code):
        rev = c.get(f"/api/v1/survey-definitions/{sid}/draft").json()["revision"]
        r = post(c, f"/api/v1/survey-definitions/{sid}/draft/operations", {"expected_revision": rev, "operation": op})
        assert r.status_code == 200, r.text
    return sid, code


# ---------------------------------------------------------------- the setting: off by default, and then nothing exists
def test_with_the_setting_off_no_survey_route_exists_and_the_product_is_unchanged(
    client: TestClient, user: Account, settings: Settings
) -> None:
    assert settings.survey_definitions_enabled is False  # the default, and the test configuration
    assert login(client, user).status_code == 200
    for (method, path), _ in MATRIX.items():
        url = (
            path.replace("{survey_id}", str(uuid.uuid4()))
            .replace("{candidate_id}", str(uuid.uuid4()))
            .replace("{version_id}", str(uuid.uuid4()))
            .replace("{kind}", "ITEM")
        )
        r = client.get(url) if method == "GET" else client.post(url, json={}, headers=csrf_header(client))
        assert r.status_code == 404, (method, path)
    assert not [p for p in client.get("/openapi.json").json()["paths"] if is_survey_path(p)]
    assert client.get("/health/ready").status_code == 200


def test_enabling_the_setting_adds_exactly_seventeen_operations_and_changes_no_other_route(
    survey_app: Any, app: Any
) -> None:
    def routes(a: Any) -> set[tuple[str, str]]:
        return {(m.upper(), p) for p, ops in a.openapi()["paths"].items() for m in ops}

    added = routes(survey_app) - routes(app)
    assert added == set(MATRIX) and len(added) == 20  # fifteen of SS-03A, two of FI-1, two of FI-2, one of UX-HOME-1
    assert routes(app) <= routes(survey_app)  # every existing route is still there
    # nothing that speaks, dials or runs a call is among them: no live-call workflow is enabled by this setting
    assert not [p for _, p in added if any(w in p for w in ("voice", "call", "session", "run", "plan", "assign"))]
    assert not [
        p for _, p in added if p == "/api/v1/surveys" or p.startswith("/api/v1/surveys/")
    ]  # the retired legacy name stays retired


def test_every_operation_requires_its_one_permission_and_every_write_is_csrf_protected() -> None:
    from app.api.survey_definitions import router

    seen = set()
    for r in router.routes:
        assert isinstance(r, APIRoute)
        (method,) = r.methods - {"HEAD"}
        seen.add((method, r.path))
        perms = [p for d in r.dependant.dependencies if (p := getattr(d.call, "required_permission", None))]
        assert perms == [MATRIX[(method, r.path)]], r.path  # exactly one permission, and it is the one in the matrix
        assert getattr(r.endpoint, "csrf_protected", False) is (method == "POST"), r.path
    assert seen == set(MATRIX)


# ------------------------------------------------------------------------------------- authentication and permissions
def test_without_a_session_every_operation_is_refused(survey_app: Any) -> None:
    with TestClient(survey_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        for method, path in MATRIX:
            url = (
                path.replace("{survey_id}", str(uuid.uuid4()))
                .replace("{candidate_id}", str(uuid.uuid4()))
                .replace("{version_id}", str(uuid.uuid4()))
                .replace("{kind}", "ITEM")
            )
            r = c.get(url) if method == "GET" else c.post(url, json={})
            assert r.status_code == 401, (method, path)


def test_an_ordinary_user_holds_no_survey_permission_and_is_refused_everywhere(survey_app: Any, db: Session) -> None:
    """No role is granted a survey permission by the migration: USER, SC_CHECKER and ADMIN all get 403."""
    for group in ("LOCAL_USER_SG", "LOCAL_SC_CHECKER_SG", "LOCAL_ADMIN"):
        c = _client(survey_app, make_account(db, group, prefix="plain"))
        for method, path in MATRIX:
            url = (
                path.replace("{survey_id}", str(uuid.uuid4()))
                .replace("{candidate_id}", str(uuid.uuid4()))
                .replace("{version_id}", str(uuid.uuid4()))
                .replace("{kind}", "ITEM")
            )
            r = c.get(url) if method == "GET" else c.post(url, json={}, headers=csrf_header(c))
            assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN", (group, method, path, r.text)
        c.__exit__(None, None, None)
    denied = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' AND outcome = 'DENIED' AND reason LIKE 'missing permission survey.%'"
        )
    ).scalar_one()
    assert denied >= 45


def test_each_permission_opens_only_its_own_operations(survey_app: Any, db: Session) -> None:
    for held in sorted(ALL):
        person = make_account(db, prefix="one")
        GRANTS[person.principal_id] = frozenset({held})
        c = _client(survey_app, person)
        for (method, path), needed in MATRIX.items():
            url = (
                path.replace("{survey_id}", str(uuid.uuid4()))
                .replace("{candidate_id}", str(uuid.uuid4()))
                .replace("{version_id}", str(uuid.uuid4()))
                .replace("{kind}", "ITEM")
            )
            r = c.get(url) if method == "GET" else c.post(url, json={}, headers=csrf_header(c))
            if needed == held:
                assert r.status_code != 403, (
                    held,
                    method,
                    path,
                )  # past the permission check (then 404 / 422 as it should)
            else:
                assert r.status_code == 403, (held, method, path)
        c.__exit__(None, None, None)
        GRANTS.pop(person.principal_id)


def test_a_write_without_the_csrf_token_is_refused(trio: Any) -> None:
    author = trio[0]
    r = author.post("/api/v1/survey-definitions", json={"code": new_code(), "name": "No token", "purpose": ""})
    assert r.status_code == 403 and r.json()["code"].startswith("CSRF")


# -------------------------------------------------------------------------------------------- the journey through HTTP
def test_draft_candidate_approval_and_publication_through_the_api(trio: Any, db: Session) -> None:
    author, checker, publisher, people = trio
    sid, code = make_survey(author, "K7")
    draft = author.get(f"/api/v1/survey-definitions/{sid}/draft").json()
    assert draft["revision"] == 10 and {a["state"] for a in draft["assets"]} == {"DRAFT"} and len(draft["assets"]) == 9
    v = post(author, f"/api/v1/survey-definitions/{sid}/draft/validate").json()
    # no blocker; one server-governed warning, which must be acknowledged at submission (FI-2)
    assert (v["blockers"], [f["code"] for f in v["findings"]]) == (0, ["SYNTHETIC_WORDING_UNAPPROVED"])

    r = submit(author, sid, "please review")
    assert r.status_code == 201, r.text
    cand = r.json()
    cid = cand["id"]
    assert (cand["n"], cand["status"], cand["manifest_intact"], len(cand["manifest"])) == (1, "IN_REVIEW", True, 9)
    assert [h["event"] for h in cand["history"]] == ["SUBMITTED"]
    assert {a["state"] for a in author.get(f"/api/v1/survey-definitions/{sid}/draft").json()["assets"]} == {"FROZEN"}

    # the author holds survey.approve and survey.publish as well — and still cannot decide or publish their own candidate
    r = post(author, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"})
    assert (r.status_code, r.json()["code"]) == (403, "SELF_REVIEW_DENIED")
    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish")
    assert (r.status_code, r.json()["code"]) == (409, "NOT_APPROVED")
    r = post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE", "comment": "reads correctly"})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    r = post(author, f"/api/v1/survey-candidates/{cid}/publish")
    assert (r.status_code, r.json()["code"]) == (403, "SELF_PUBLISH_DENIED")
    r = post(checker, f"/api/v1/survey-candidates/{cid}/publish")
    assert (r.status_code, r.json()["code"]) == (403, "APPROVER_PUBLISH_DENIED")
    r = post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "REJECT", "comment": "too late"})
    assert (r.status_code, r.json()["code"]) == (409, "ALREADY_DECIDED")

    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish", {"effective_from": "2030-01-01T00:00:00Z"})
    assert r.status_code == 201, r.text
    version = r.json()
    assert (version["version_no"], version["label"], version["status"]) == (1, "1.0", "PUBLISHED")
    assert version["effective_from"].startswith("2030-01-01")  # recorded only; nothing is scheduled to happen
    assert "not eligible" in version["note"] or "eligible for a live call" in version["note"]
    content = publisher.get(f"/api/v1/survey-versions/{version['id']}/content").json()
    assert content["content"]["code"] == code and content["manifest_sha256"] == cand["manifest_sha256"]
    assert publisher.get(f"/api/v1/survey-candidates/{cid}").json()["status"] == "PUBLISHED"
    summary = author.get(f"/api/v1/survey-definitions/{sid}").json()
    assert (summary["latest_version_label"], summary["open_candidate_id"]) == ("1.0", None)
    assert sid in [s["id"] for s in author.get("/api/v1/survey-definitions").json()["items"]]
    lib = author.get("/api/v1/survey-library/WORDING").json()["items"]
    assert sum(1 for i in lib if i["code"].endswith(code[2:]) and i["versions"] == 1) == 3
    # the wording rows were never marked: approval is separate, append-only evidence naming this candidate
    approvals = db.execute(
        text("SELECT count(*), count(DISTINCT actor_ref) FROM survey_wording_approval WHERE candidate_id = :c"),
        {"c": cid},
    ).one()
    assert tuple(approvals) == (3, 1)


def test_a_stale_draft_revision_is_rejected_and_nothing_changes(trio: Any) -> None:
    author = trio[0]
    sid, _ = make_survey(author, "K1")
    before = author.get(f"/api/v1/survey-definitions/{sid}/draft").json()
    op = {"op": "SET_CONTENT", "content": {**before["content"], "sequence": []}}
    r = post(
        author,
        f"/api/v1/survey-definitions/{sid}/draft/operations",
        {"expected_revision": before["revision"] - 1, "operation": op},
    )
    assert (r.status_code, r.json()["code"]) == (409, "STALE_DRAFT")
    assert author.get(f"/api/v1/survey-definitions/{sid}/draft").json() == before
    r = post(
        author,
        f"/api/v1/survey-definitions/{sid}/draft/operations",
        {"expected_revision": before["revision"], "operation": op},
    )
    assert r.status_code == 200 and r.json()["revision"] == before["revision"] + 1


def test_blockers_and_malformed_requests_have_explicit_codes(trio: Any) -> None:
    author = trio[0]
    sid, _ = make_survey(author, "K5")  # wording with variables, and no field is allowlisted for speech
    v = post(author, f"/api/v1/survey-definitions/{sid}/draft/validate").json()
    assert v["blockers"] == 5
    assert {f["code"] for f in v["findings"] if f["severity"] == "BLOCKER"} == {"VARIABLE_NOT_PERMITTED"}
    assert [f["code"] for f in v["findings"] if f["severity"] == "WARNING"] == ["SYNTHETIC_WORDING_UNAPPROVED"]
    r = submit(author, sid)
    assert (r.status_code, r.json()["code"]) == (422, "VALIDATION_BLOCKED")
    assert {d["code"] for d in r.json()["details"]} == {"VARIABLE_NOT_PERMITTED"}
    rev = author.get(f"/api/v1/survey-definitions/{sid}/draft").json()["revision"]
    bad = {
        "op": "PUT_ASSET",
        "kind": "ITEM",
        "document": {"schema": "call360.survey.item/9", "code": "Q", "version": 1},
    }
    r = post(author, f"/api/v1/survey-definitions/{sid}/draft/operations", {"expected_revision": rev, "operation": bad})
    assert (r.status_code, r.json()["code"]) == (422, "DOCUMENT_INVALID")
    assert post(author, "/api/v1/survey-definitions", {"code": "lower", "name": "x"}).status_code == 422
    dup = author.get(f"/api/v1/survey-definitions/{sid}").json()["code"]
    r = post(author, "/api/v1/survey-definitions", {"code": dup, "name": "Again", "purpose": ""})
    assert (r.status_code, r.json()["code"]) == (409, "SURVEY_CODE_TAKEN")
    assert author.get(f"/api/v1/survey-definitions/{uuid.uuid4()}").status_code == 404
    assert author.get("/api/v1/survey-library/PROMPT").status_code == 422


def test_a_survey_is_invisible_outside_its_market(trio: Any, survey_app: Any, db: Session) -> None:
    author = trio[0]
    sid, _ = make_survey(author, "K1")
    outsider = make_account(db, prefix="noscope")  # holds every survey permission here, but is scoped to another market
    GRANTS[outsider.principal_id] = ALL
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    c = _client(survey_app, outsider)
    assert c.get(f"/api/v1/survey-definitions/{sid}").status_code == 404
    assert c.get(f"/api/v1/survey-definitions/{sid}/draft").status_code == 404
    assert c.get("/api/v1/survey-definitions").json()["items"] == []
    r = post(c, "/api/v1/survey-definitions", {"code": new_code(), "name": "Out of scope", "purpose": ""})
    assert (r.status_code, r.json()["code"]) == (403, "MARKET_NOT_IN_SCOPE")
    c.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)


def test_condition_evaluation_is_three_valued_and_stores_nothing(trio: Any, db: Session) -> None:
    author = trio[0]
    cond = {
        "params": {"t": {"type": "MONEY", "unit": "SGD"}},
        "ast": {"op": "GTE", "left": {"field": "policy.annual_premium"}, "right": {"param": "t"}},
    }
    rows = db.execute(text("SELECT count(*) FROM survey_asset_version")).scalar_one()

    def ask(facts: dict[str, Any]) -> Any:
        return post(
            author, "/api/v1/survey-conditions/evaluate", {"condition": cond, "params": {"t": 12000}, "facts": facts}
        )

    assert ask({"policy.annual_premium": 12000}).json()["result"] == "TRUE"
    assert ask({"policy.annual_premium": 11999.99}).json()["result"] == "FALSE"
    missing = ask({}).json()
    assert missing["result"] == "UNKNOWN" and missing["explanation"]["reads"][0] == {
        "kind": "field",
        "name": "policy.annual_premium",
        "value": None,
    }
    bad = post(
        author,
        "/api/v1/survey-conditions/evaluate",
        {"condition": {**cond, "ast": {"op": "GTE", "left": {"field": "no.such"}, "right": {"param": "t"}}}},
    )
    assert (bad.status_code, bad.json()["code"]) == (422, "CONDITION_INVALID")
    assert db.execute(text("SELECT count(*) FROM survey_asset_version")).scalar_one() == rows


# ------------------------------------------------------------------------------------------------------- the contract
def test_the_published_contract_gains_the_seventeen_operations_and_loses_nothing() -> None:
    root = Path(__file__).resolve().parents[1]
    spec = json.loads((root / "contracts" / "generated" / "openapi.json").read_text())
    ops = {
        (m.upper(), p)
        for p, item in spec["paths"].items()
        for m in item
        if m in ("get", "post", "put", "patch", "delete")
    }
    assert set(MATRIX) <= ops
    # 19 with the survey setting; 3 more with the library's; 5 more with simulation's (SS-03B)
    # … and 10 more with assignment's (ASG-1)
    # … and 7 more with requirement groups' (ASG-2A)
    # … and 3 more with coordinated simulation's (ASG-2B)
    # … and 10 more with evaluation's (EVAL-1)
    # … and 10 more with control policies' (EVAL-2A)
    # … and 3 more with execution assurance's (EVAL-2B)
    # … and 1 read-only journey trace (E2E-1)
    # … and 1 read-only workspace summary (UX-HOME-1)
    # … and 4 of standalone modules (LIB-2): create, list, read, and the one-module test
    # … and 4 stateless operations of the applicability prototype (APPL-X1)
    assert len([o for o in ops if is_survey_path(o[1])]) == 80
    # … and, outside the survey paths, the 14 operations of the governed applicability library (APPL-X2)
    # … and the 10 of saved applicability policies (APPL-X3), under the same prefix
    # … and the 22 of saved scenarios, regression suites and recorded runs (APPL-X4a)
    assert len([o for o in ops if o[1].startswith("/api/v1/applicability/")]) == 14 + 10 + 22
    assert len(ops) == 199 + 80 + 14 + 10 + 22  # the 199 operations of the accepted contract, and these
    assert not [p for p in spec["paths"] if p == "/api/v1/surveys" or p.startswith("/api/v1/surveys/")]
    # purely additive: a name collision would make the generator rename an EXISTING schema with a module prefix
    schemas = spec["components"]["schemas"]
    assert not [k for k in schemas if "__" in k]
    survey_schemas = [k for k in schemas if k.startswith("Survey") and k not in ("SurveyRunDetail",)]
    # 22 of SS-03A, 4 of FI-1, 9 of FI-2, 11 of LIB-1, 6 of SS-03B
    # … and 10 of ASG-1
    # … and 8 of ASG-2A
    # … and 2 of ASG-2B
    # … and 13 of EVAL-1
    # … and 15 of EVAL-2A
    # … and 4 of EVAL-2B
    # … and 2 of E2E-1
    # … and 1 of UX-HOME-1
    # … and 9 of LIB-2 (eight of the module operations, and where a library component was written)
    # … and 6 of APPL-X1 (five request bodies and one response of the stateless applicability prototype)
    # … and, under their own name, those of the applicability library (APPL-X2):
    # … 21 of APPL-X2 and 1 for the reviewed pins a submitter acknowledges (owner ruling A4)
    # … and 15 of saved applicability policies (APPL-X3)
    # … and 35 of saved scenarios, suites and recorded runs (APPL-X4a)
    assert len([k for k in schemas if k.startswith("Applicability")]) == 22 + 15 + 35
    assert len(survey_schemas) == 122 and len(schemas) == 405 + 122 + 22 + 15 + 35
    assert MIGRATION_HEAD == "0040_applicability_scenarios"
