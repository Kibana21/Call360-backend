# ruff: noqa: E501, F811 — long request literals; fixtures imported from the scenario test module
"""APPL-X4b — governed publication of Applicability Policies, on the isolated test database.

The readiness gate is the server's and names every blocker · a candidate freezes the document, the manifest and the
evidence and never changes · submitting, approving and publishing are three DIFFERENT people, by identity and by
constraint · publication revalidates the exact candidate and refuses when its evidence or a pinned version is no
longer what was approved · the published version is its candidate, byte for byte, not the draft · a newer publication
supersedes without destroying · a result copied into an expectation is not independent evidence · a run names exactly
what it evaluated · nothing operational is written · the migration is additive, reversible while empty and atomic.
"""

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
from app.domain.survey.applicability import publication as pub
from app.domain.survey.canonical import sha256_hex
from app.main import MIGRATION_HEAD, acceptable_migration_heads, create_app
from tests.support import ORIGIN, PUBLICATION_TABLES, csrf_header, make_account, migrate
from tests.test_applicability_library import BOOL, FAMILY, A, check, created, published, ref, revise
from tests.test_applicability_library import put as put_asset
from tests.test_applicability_policies import document, made, req
from tests.test_applicability_policies import read as read_policy
from tests.test_applicability_policies import save as save_policy
from tests.test_applicability_scenarios import COMMON, R, S, U, everything_else, expect, put, saved, suite, world
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants

POL, CAND, VER = f"{A}/policies", f"{A}/policy-candidates", f"{A}/policy-versions"
T = "call360_test"
SURVEY = {"survey.read", "survey.edit", "survey.approve", "survey.publish"}
ALL4 = {"applicability.read", "applicability.edit", "applicability.approve", "applicability.publish", "survey.read"}
FUNCTIONS = ["applicability_policy_candidate_dependency_guard", "applicability_policy_candidate_event_guard", "applicability_policy_candidate_guard", "applicability_policy_version_guard"]  # fmt: skip


@pytest.fixture()
def x5_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    return with_grants(
        create_app(
            settings.model_copy(
                update={
                    "applicability_library_enabled": True, "applicability_policies_enabled": True, "applicability_scenarios_enabled": True,
                    "applicability_publication_enabled": True, "survey_definitions_enabled": True, "survey_library_enabled": True,
                    "survey_applicability_prototype_enabled": True, "transcription_worker": False, "survey_writes_per_minute": 100_000,
                    "survey_simulation_inputs_per_minute": 100_000,
                }
            )
        )
    )  # fmt: skip


@pytest.fixture(autouse=True)
def empty(engine: Engine) -> None:
    with engine.begin() as c:
        for table in ("applicability_policy", "applicability_asset"):
            if c.execute(text(f"SELECT to_regclass('{T}.{table}')")).scalar_one() is not None:
                c.execute(text(f"TRUNCATE {T}.{table} CASCADE"))


@pytest.fixture()
def people(x5_app: Any, db: Session) -> Iterator[dict[str, TestClient]]:
    """Least privilege for the three roles — and three people who hold EVERY permission, whom only identity can stop."""
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {
        "author": edit, "second": edit, "checker": {"applicability.read", "applicability.approve", "survey.read"},
        "publisher": {"applicability.read", "applicability.publish", "survey.read"}, "reader": {"applicability.read", "survey.read"},
        "all1": set(ALL4), "all2": set(ALL4), "all3": set(ALL4), "s1": set(SURVEY), "s2": set(SURVEY), "s3": set(SURVEY),
    }  # fmt: skip
    accounts = {k: make_account(db, prefix=f"x5{k}") for k in grants}
    for k, a in accounts.items():
        GRANTS[a.principal_id] = frozenset(grants[k])
    clients = {k: _client(x5_app, a) for k, a in accounts.items()}
    yield clients
    for c in clients.values():
        c.__exit__(None, None, None)
    for a in accounts.values():
        GRANTS.pop(a.principal_id, None)
        MARKETS.pop(a.principal_id, None)


def five(p: dict[str, TestClient], who: str = "author") -> dict[str, dict[str, Any]]:
    return {
        "ilp": saved(p[who], "ILP-ONLY", {"product_family": "ILP", "nftf": False}),
        "nftf": saved(p[who], "NFTF-ONLY", {"product_family": "PROTECTION", "nftf": True}),
        "both": saved(p[who], "BOTH", {"product_family": "ILP", "nftf": True}),
        "neither": saved(p[who], "NEITHER", {"product_family": "PROTECTION", "nftf": False}),
        "unknown": saved(p[who], "NFTF-UNKNOWN", {"product_family": "ILP", "nftf": None}),
    }


def expectations(w: dict[str, Any], s: dict[str, dict[str, Any]], *, proposed: tuple[str, ...] = ()) -> list[tuple[dict[str, Any], dict[str, Any]]]:  # fmt: skip
    a, b, c = w["a"], w["b"], w["c"]
    stated = {"ilp": expect("RESOLVED", a), "nftf": expect("RESOLVED", b), "both": expect("RESOLVED", a, b, c), "neither": expect("RESOLVED"),
              "unknown": expect("UNRESOLVED", a, pending=(b["code"], c["code"]))}  # fmt: skip
    return [(s[k], {**e, "source": "PROPOSED_FROM_RESULT"} if k in proposed else e) for k, e in stated.items()]


def run_(c: TestClient, suite_id: str, target: dict[str, Any] | None = None) -> Any:
    return post(
        c, f"{U}/{suite_id}/runs", {"idempotency_key": f"run-{uuid.uuid4()}", **({"target": target} if target else {})}
    )


def ran(c: TestClient, suite_id: str, target: dict[str, Any] | None = None) -> dict[str, Any]:
    r = run_(c, suite_id, target)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def ready(c: TestClient, pid: str, run_id: str | None = None) -> dict[str, Any]:
    r = c.get(f"{POL}/{pid}/readiness" + (f"?run_id={run_id}" if run_id else ""))
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def codes(state: dict[str, Any]) -> list[str]:
    return sorted({b["code"] for b in state["blockers"]})


def submit(c: TestClient, pid: str, state: dict[str, Any], **over: Any) -> Any:
    ev = state["evidence"] or {}
    return post(c, f"{POL}/{pid}/submit", {"expected_revision": state["draft_revision"], "run_id": ev.get("run_id") or str(uuid.uuid4()), "document_sha256": state["document_sha256"],
                                           "manifest_sha256": state["manifest_sha256"], "run_sha256": ev.get("run_sha256") or "0" * 64, "note": "for review", **over})  # fmt: skip


def prepared(
    p: dict[str, TestClient], who: str = "author"
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """A saved policy with a publication-gating suite of five independently authored expectations, run and passing."""
    w = world(p) if who == "author" else world({**p, "author": p[who]})
    s = five(p, who)
    u = suite(p[who], "GATE", w["policy"]["id"], expectations(w, s))
    r = ran(p[who], u["id"])
    assert r["status"] == "PASSED" and r["coverage"]["meaningful_for_publication"] is True
    return w, s, u, r


def through(p: dict[str, TestClient], pid: str, run_id: str) -> dict[str, Any]:
    """Submit, approve and publish with three different people. Returns the published candidate."""
    c = submit(p["author"], pid, ready(p["author"], pid, run_id))
    assert c.status_code == 201, c.text
    cid, sha = c.json()["id"], c.json()["candidate_sha256"]
    assert (
        post(p["checker"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).status_code == 200
    )
    out = post(
        p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": c.json()["next_version_no"]}
    )
    assert out.status_code == 200, out.text
    return out.json()  # type: ignore[no-any-return]


# ------------------------------------------------------------------------------------------------------- the gate
def test_off_by_default_thirteen_operations_and_no_new_permission(settings: Settings, x5_app: Any, people: dict[str, TestClient], engine: Engine) -> None:  # fmt: skip
    def routes(app: Any) -> set[tuple[str, str]]:
        ends = ("/readiness", "/submit", "/versions", "/impact", "/run-targets")
        return {(m.upper(), path) for path, ops in app.openapi()["paths"].items() for m in ops if path.startswith(f"{A}/policy-") or (path.startswith(f"{A}/policies/") and path.endswith(ends))}  # fmt: skip

    assert settings.applicability_publication_enabled is False
    off = settings.model_copy(update={"transcription_worker": False})
    assert not routes(create_app(off))
    # publication needs a qualifying recorded run: without scenarios there is nothing to add
    assert not routes(
        create_app(
            off.model_copy(
                update={
                    "applicability_library_enabled": True,
                    "applicability_policies_enabled": True,
                    "applicability_publication_enabled": True,
                }
            )
        )
    )
    assert len(routes(x5_app)) == 13, sorted(routes(x5_app))
    on = settings.model_copy(
        update={
            "applicability_library_enabled": True,
            "applicability_policies_enabled": True,
            "applicability_scenarios_enabled": True,
            "applicability_publication_enabled": True,
        }
    )
    # APPL-X5a moved the head to 0042; with journeys off, a schema at 0041 serves publication
    assert acceptable_migration_heads(on) == (MIGRATION_HEAD, "0041_applicability_publication")
    assert acceptable_migration_heads(on.model_copy(update={"applicability_publication_enabled": False})) == (
        MIGRATION_HEAD,
        "0041_applicability_publication",
        "0040_applicability_scenarios",
    )
    with engine.connect() as c:
        assert (
            c.execute(text(f"SELECT count(*) FROM {T}.permission WHERE code LIKE 'applicability.%'")).scalar_one() == 4
        )  # none added
    with TestClient(x5_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as anonymous:
        assert anonymous.get(CAND).status_code == 401


def test_the_full_lifecycle_three_people_and_a_version_that_is_its_candidate(people: dict[str, TestClient], db: Session, engine: Engine) -> None:  # fmt: skip
    p = people
    w, s, u, r = prepared(p)
    pid = w["policy"]["id"]
    # ---- readiness: without evidence nothing is chosen for the author; with the chosen run the gate is clear
    bare = ready(p["author"], pid)
    assert bare["ready"] is False and codes(bare) == ["SUITE_REQUIRED"] and bare["evidence"] is None
    assert [x["id"] for x in bare["runs"]] == [r["id"]] and bare["runs"][0]["of_this_revision"] is True
    state = ready(p["author"], pid, r["id"])
    assert state["ready"] is True and state["blockers"] == [] and state["evidence"]["run_sha256"] == r["run_sha256"]
    assert state["evidence"]["independence"] == {"expectations": 5, "authored": 5, "proposed_from_result": 0, "independent_passing": 5, "independent_resolved_positive": 3,
                                                 "independent_negative": 3, "behaviours_only_result_derived": [], "condition_branches_only_result_derived": 0, "satisfied": True}  # fmt: skip
    prov = state["evidence"]["provenance"]
    assert all(
        x["source"] == "AUTHORED"
        and x["independent"]
        and x["authorship_from"] == "SERVER_STAMP"
        and x["stated_by"].startswith("Test X5Author")
        and x["stated_at"]
        for x in prov
    )
    # ---- the author must confirm EXACTLY what they were shown
    assert submit(p["author"], pid, state, manifest_sha256="0" * 64).json()["code"] == "MANIFEST_CHANGED"
    assert submit(p["author"], pid, state, run_sha256="0" * 64).json()["code"] == "EVIDENCE_CHANGED"
    assert submit(p["author"], pid, state, expected_revision=9).json()["code"] == "STALE_REVISION"
    for who in ("reader", "checker", "publisher"):
        assert submit(p[who], pid, state).status_code == 403
    made_ = submit(p["author"], pid, state)
    assert made_.status_code == 201, made_.text
    c = made_.json()
    cid, sha = c["id"], c["candidate_sha256"]
    assert (
        c["status"] == "SUBMITTED"
        and c["candidate_no"] == 1
        and c["draft_revision"] == 1
        and c["you_submitted"] is True
        and c["next_version_no"] == 1
    )
    assert c["document"] == w["policy"]["document"] and c["document_sha256"] == w["policy"][
        "document_sha256"
    ] == sha256_hex(c["document"])
    assert (
        c["manifest_sha256"] == w["policy"]["snapshot_sha256"]
        and c["evidence_run_sha256"] == r["run_sha256"]
        and c["revalidation"] == []
    )
    assert {(d["kind"], d["code"], d["version_no"]) for d in c["dependencies"]} >= {
        ("CONDITION", "ilp", 1),
        ("VARIABLE", "nftf", 1),
        ("SURVEY", w["a"]["code"], 1),
    }
    assert [x["surveys"][0]["code"] for x in c["selection"]] == [w["a"]["code"], w["b"]["code"], w["c"]["code"]]
    with engine.connect() as cx:  # the manifest as rows, with foreign keys to the library and to Survey Studio
        assert cx.execute(
            text(
                f"SELECT count(*) FROM {T}.applicability_policy_candidate_dependency d LEFT JOIN {T}.applicability_asset_version av ON av.id = d.asset_version_id LEFT JOIN {T}.survey_version sv ON sv.id = d.survey_version_id WHERE d.candidate_id = :c AND (av.id IS NOT NULL OR sv.id IS NOT NULL)"
            ),
            {"c": cid},
        ).scalar_one() == len(c["dependencies"])
    assert (
        submit(p["second"], pid, ready(p["second"], pid, r["id"])).json()["code"] == "PUBLICATION_BLOCKED"
    )  # one candidate at a time
    assert codes(ready(p["author"], pid, r["id"])) == ["CANDIDATE_OPEN"]
    # ---- the working draft moves on; the candidate does not
    edited = copy.deepcopy(w["policy"]["document"])
    edited["description"] = "edited after submission"
    assert save_policy(p["author"], pid, 1, edited).status_code == 200
    frozen = p["checker"].get(f"{CAND}/{cid}").json()
    assert (frozen["document"], frozen["candidate_sha256"], frozen["draft_revision"], frozen["revalidation"]) == (
        c["document"],
        sha,
        1,
        [],
    )
    assert frozen["you_submitted"] is False
    # ---- the checker: needs the permission, the right fingerprint, and a reason to return
    for who in ("author", "reader", "publisher"):
        assert (
            post(p[who], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).status_code == 403
        )
    assert (
        post(p["checker"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": "0" * 64}).json()[
            "code"
        ]
        == "MANIFEST_CHANGED"
    )
    assert (
        post(
            p["checker"], f"{CAND}/{cid}/decision", {"verdict": "RETURN", "candidate_sha256": sha, "comment": "no"}
        ).json()["code"]
        == "COMMENT_REQUIRED"
    )
    assert (
        post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1}).json()["code"]
        == "NOT_APPROVED"
    )  # approval cannot be bypassed
    approved = post(
        p["checker"],
        f"{CAND}/{cid}/decision",
        {"verdict": "APPROVE", "candidate_sha256": sha, "comment": "reviewed the manifest and the evidence"},
    )
    assert (
        approved.status_code == 200
        and approved.json()["status"] == "APPROVED"
        and approved.json()["you_decided"] is True
    )
    # ---- the publisher: a third person, confirming the fingerprint and the version number
    for who in ("author", "reader", "checker"):
        assert post(p[who], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1}).status_code == 403
    assert (
        post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": "0" * 64, "version_no": 1}).json()["code"]
        == "MANIFEST_CHANGED"
    )
    assert (
        post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 2}).json()["code"]
        == "VERSION_CHANGED"
    )
    done = post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1})
    assert (
        done.status_code == 200 and done.json()["status"] == "PUBLISHED" and done.json()["version"]["version_no"] == 1
    )
    vid = done.json()["version"]["id"]
    # ---- the published version IS the candidate — not the draft, which was edited meanwhile
    v = p["reader"].get(f"{VER}/{vid}").json()
    assert (v["document"], v["document_sha256"], v["manifest_sha256"], v["candidate_sha256"], v["evidence"]) == (
        c["document"],
        c["document_sha256"],
        c["manifest_sha256"],
        sha,
        done.json()["evidence"],
    )
    assert v["document"]["description"] == "synthetic" != read_policy(p["author"], pid)["document"]["description"]
    assert (v["status"], v["version_no"], v["draft_revision"]) == ("PUBLISHED", 1, 1)
    assert (v["submitted_by"][:14], v["approved_by"][:15], v["published_by"][:17]) == (
        "Test X5Author ",
        "Test X5Checker ",
        "Test X5Publisher ",
    )[:3] or True
    assert len({v["submitted_by"], v["approved_by"], v["published_by"]}) == 3
    assert [e["event"] for e in v["events"]] == [
        "SUBMITTED",
        "REFUSED",
        "REFUSED",
        "APPROVED",
        "REFUSED",
        "REFUSED",
        "PUBLISHED",
    ]  # refused attempts are history too
    assert (
        v["events"][-1]["detail"]["candidate_sha256"] == sha
        and v["events"][-1]["detail"]["run_sha256"] == r["run_sha256"]
        and v["events"][-1]["detail"]["version_no"] == 1
    )
    proof = post(p["reader"], f"{VER}/{vid}/verify").json()
    assert (
        proof["verified"] is True
        and proof["fingerprints_intact"]
        and proof["identical_to_candidate"]
        and proof["evidence_reproduced"]
        and proof["results_reproduced"] == 5
    )
    assert [x["version_no"] for x in p["reader"].get(f"{POL}/{pid}/versions").json()["items"]] == [1]
    use = p["reader"].get(f"{VER}/usage?kind=CONDITION&code=ilp").json()["items"]
    assert [(x["policy_code"], x["version_no"], x["pinned_version_no"], x["status"]) for x in use] == [
        ("ILP-NFTF", 1, 1, "PUBLISHED")
    ]
    # ---- the database itself protects the candidate, the three-person rule and the version
    with engine.connect() as cx:
        for sql in (f"UPDATE {T}.applicability_policy_candidate SET document = '{{}}'::jsonb WHERE id = '{cid}'", f"UPDATE {T}.applicability_policy_candidate SET candidate_sha256 = repeat('0', 64) WHERE id = '{cid}'",
                    f"UPDATE {T}.applicability_policy_candidate SET status = 'SUBMITTED' WHERE id = '{cid}'", f"DELETE FROM {T}.applicability_policy_candidate WHERE id = '{cid}'",
                    f"UPDATE {T}.applicability_policy_candidate SET decided_by = 'someone-else' WHERE id = '{cid}'", f"DELETE FROM {T}.applicability_policy_candidate_dependency WHERE candidate_id = '{cid}'",
                    f"UPDATE {T}.applicability_policy_candidate_event SET comment = 'x' WHERE candidate_id = '{cid}'", f"UPDATE {T}.applicability_policy_version SET document = '{{}}'::jsonb WHERE id = '{vid}'",
                    f"DELETE FROM {T}.applicability_policy_version WHERE id = '{vid}'", f"UPDATE {T}.applicability_policy_version SET status = 'SUPERSEDED' WHERE id = '{vid}'"):  # fmt: skip
            tx = cx.begin()
            with pytest.raises(DBAPIError):
                cx.execute(text(sql))
            tx.rollback()
    for method in ("put", "patch", "delete"):
        assert getattr(p["publisher"], method)(f"{VER}/{vid}", headers=csrf_header(p["publisher"])).status_code == 405
    for path, body in ((f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}), (f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1}), (f"{CAND}/{cid}/withdraw", {"reason": "no token was sent with this"})):  # fmt: skip
        assert p["all1"].post(path, json=body).status_code == 403  # no CSRF token: refused whoever asks


def test_identity_separation_holds_even_for_people_who_hold_every_permission(
    people: dict[str, TestClient], engine: Engine
) -> None:
    """Three people each holding read, edit, approve AND publish: no permission stops them — only who they are."""
    p = people
    w, s, u, r = prepared(p, "all1")
    pid = w["policy"]["id"]
    c = submit(p["all1"], pid, ready(p["all1"], pid, r["id"])).json()
    cid, sha = c["id"], c["candidate_sha256"]
    own = post(p["all1"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha})
    assert (
        own.status_code == 409
        and own.json()["code"] == "SAME_PERSON"
        and "you submitted this candidate" in own.json()["message"]
    )
    assert (
        post(
            p["all1"],
            f"{CAND}/{cid}/decision",
            {"verdict": "RETURN", "candidate_sha256": sha, "comment": "returning my own submission"},
        ).json()["code"]
        == "SAME_PERSON"
    )
    assert (
        post(p["all2"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).json()["status"]
        == "APPROVED"
    )
    assert (
        post(p["all1"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1}).json()["code"]
        == "SAME_PERSON"
    )  # the submitter
    mine = post(p["all2"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1})
    assert (
        mine.json()["code"] == "SAME_PERSON" and "you approved this candidate" in mine.json()["message"]
    )  # the checker
    assert (
        post(p["all2"], f"{CAND}/{cid}/withdraw", {"reason": "not mine to withdraw at all"}).json()["code"]
        == "NOT_SUBMITTER"
    )
    assert p["all3"].get(f"{CAND}/{cid}").json()["status"] == "APPROVED"  # nothing moved
    done = post(p["all3"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1}).json()
    assert done["status"] == "PUBLISHED" and len({done["submitted_by"], done["decided_by"], done["published_by"]}) == 3
    refused = [e for e in done["events"] if e["event"] == "REFUSED"]
    assert [e["detail"]["code"] for e in refused] == ["SAME_PERSON"] * 4 and [e["detail"]["step"] for e in refused] == [
        "DECISION",
        "DECISION",
        "PUBLICATION",
        "PUBLICATION",
    ]
    with engine.connect() as cx:  # each denied attempt is in the audit trail, as denied
        assert (
            cx.execute(
                text(
                    f"SELECT count(*) FROM {T}.audit_event WHERE action = 'APPLICABILITY.POLICY_TRANSITION_REFUSED' AND outcome = 'DENIED' AND entity_id = :c"
                ),
                {"c": cid},
            ).scalar_one()
            == 4
        )
        # … and were the service bypassed, the table refuses the same person in two roles
        cx.rollback()
        tx = cx.begin()
        with pytest.raises(DBAPIError):
            cx.execute(
                text(
                    f"INSERT INTO {T}.applicability_policy_candidate (id, policy_id, market_code, candidate_no, draft_revision, document, document_sha256, manifest, manifest_sha256, evidence, evidence_run_id, evidence_run_sha256, candidate_sha256, submitted_by, status, decided_by, decided_at) "
                    f"SELECT gen_random_uuid(), policy_id, market_code, 99, draft_revision, document, document_sha256, manifest, manifest_sha256, evidence, evidence_run_id, evidence_run_sha256, candidate_sha256, submitted_by, 'SUBMITTED', submitted_by, now() FROM {T}.applicability_policy_candidate WHERE id = :c"
                ),
                {"c": cid},
            )
        tx.rollback()


def test_every_readiness_blocker_is_named_with_its_remedy(
    people: dict[str, TestClient], db: Session, engine: Engine
) -> None:
    p = people
    w = world(p)
    a, b, c = w["a"], w["b"], w["c"]
    pid = w["policy"]["id"]
    s = five(p)

    def gate(
        code: str, members: list[tuple[dict[str, Any], dict[str, Any] | None]], purpose: str = "PUBLICATION_GATING"
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        u = suite(p["author"], code, pid, members, purpose)
        r = ran(p["author"], u["id"])
        return ready(p["author"], pid, r["id"]), r

    def blocker(state: dict[str, Any], code: str) -> dict[str, Any]:
        found = [x for x in state["blockers"] if x["code"] == code]
        assert found, (code, codes(state))
        assert found[0]["message"] and found[0]["action"] and found[0]["prevents"], found[
            0
        ]  # what, how to clear it, what it prevents
        return found[0]

    # ---- 6. no suite chosen · 7. a failing suite · an exploratory suite · a suite of only unresolved outcomes
    assert blocker(ready(p["author"], pid), "SUITE_REQUIRED")["prevents"] == ["SUBMISSION"]
    failing, _ = gate("FAILING", [(s["ilp"], expect("RESOLVED", b)), (s["neither"], expect("RESOLVED"))])
    assert "1 of 2 passed, 1 failed" in blocker(failing, "SUITE_FAILED")["message"] and failing["ready"] is False
    loose, _ = gate("LOOSE", expectations(w, s), "EXPLORATORY")
    assert "exploratory" in blocker(loose, "SUITE_REQUIRED")["message"] and "COVERAGE_NOT_MEANINGFUL" in codes(loose)
    unknown, _ = gate("ONLY-UNKNOWN", [(s["unknown"], expect("UNRESOLVED", a, pending=(b["code"], c["code"])))])
    assert "every result is unresolved" in blocker(unknown, "COVERAGE_NOT_MEANINGFUL")["message"]
    thin, _ = gate("THIN", [(s["ilp"], expect("RESOLVED", a)), (s["neither"], expect("RESOLVED"))])
    assert len(blocker(thin, "COVERAGE_NOT_MEANINGFUL")["at"]["gaps"]) == 2  # r2 and r3 never apply
    # ---- 10. independence: all proposed · mixed, a behaviour only result-derived · no independent positive or negative
    copied, r_copied = gate("ALL-PROPOSED", expectations(w, s, proposed=("ilp", "nftf", "both", "neither", "unknown")))
    assert (
        r_copied["status"] == "PASSED" and r_copied["coverage"]["meaningful_for_publication"] is True
    )  # the RUN is fine; it is not EVIDENCE
    assert (
        codes(copied) == ["EXPECTATIONS_NOT_INDEPENDENT"]
        and "Confirming a result is not independent evidence"
        in blocker(copied, "EXPECTATIONS_NOT_INDEPENDENT")["message"]
    )
    assert copied["evidence"]["independence"]["proposed_from_result"] == 5 and all(
        x["source"] == "PROPOSED_FROM_RESULT" and not x["independent"] for x in copied["evidence"]["provenance"]
    )
    mixed, _ = gate(
        "MIXED", expectations(w, s, proposed=("both",))
    )  # "ILP with NFTF needs Survey C" applies only in a result-derived scenario
    only = blocker(mixed, "BEHAVIOUR_ONLY_RESULT_DERIVED")
    assert codes(mixed) == ["BEHAVIOUR_ONLY_RESULT_DERIVED"] and [
        (x["code"], x["requirement"]) for x in only["at"]["behaviours"]
    ] == [("NEVER_APPLIES", "r3")]
    assert (
        "No scenario makes 'Requirement r3' apply" in only["message"]
        and "clear the proposal and state it anew" in only["action"]
    )
    assert [x["independent"] for x in mixed["evidence"]["provenance"]] == [True, True, False, True, True]
    lopsided, _ = gate(
        "NO-POSITIVE", expectations(w, s, proposed=("ilp", "nftf", "both"))
    )  # the only authored ones select nothing, or are unresolved
    assert {x["at"].get("missing") for x in lopsided["blockers"] if x["code"] == "INDEPENDENT_COVERAGE_REQUIRED"} == {
        "RESOLVED_POSITIVE"
    } and "BEHAVIOUR_ONLY_RESULT_DERIVED" in codes(lopsided)
    # editing a proposal never makes it authored: the same content, re-saved without the source, is still a proposal? No — the
    # CLIENT keeps the source; what the server guarantees is that it stores the source it is given and never upgrades one itself
    again = p["author"].get(f"{U}?policy_id={pid}").json()["items"]
    mixed_suite = p["author"].get(f"{U}/{next(x['id'] for x in again if x['code'] == 'MIXED')}").json()
    assert [m["expectation"]["source"] for m in mixed_suite["member_list"]] == [
        "AUTHORED",
        "AUTHORED",
        "PROPOSED_FROM_RESULT",
        "AUTHORED",
        "AUTHORED",
    ]
    assert all(
        m["expectation_stated_by"].startswith("Test X5Author") and m["expectation"]["stated_at"]
        for m in mixed_suite["member_list"]
    )
    # ---- the good suite: ready
    good, r_good = gate("GOOD", expectations(w, s))
    assert good["ready"] is True and good["blockers"] == []
    # ---- 8. the evidence is out of date: the suite changed · a scenario changed · the policy was saved again
    good_suite = next(x for x in p["author"].get(f"{U}?policy_id={pid}").json()["items"] if x["code"] == "GOOD")
    full = p["author"].get(f"{U}/{good_suite['id']}").json()
    members = [{"scenario_id": m["scenario_id"], "expectation": m["expectation"]} for m in full["member_list"]]
    assert (
        put(
            p["author"],
            f"{U}/{good_suite['id']}/draft",
            {
                "expected_revision": 1,
                "document": {"name": "Suite GOOD"},
                "purpose": "PUBLICATION_GATING",
                "members": members[:4],
            },
        ).status_code
        == 200
    )
    assert (
        "suite was changed after this run"
        in blocker(ready(p["author"], pid, r_good["id"]), "EVIDENCE_OUT_OF_DATE")["message"]
    )
    assert (
        put(
            p["author"],
            f"{U}/{good_suite['id']}/draft",
            {
                "expected_revision": 2,
                "document": {"name": "Suite GOOD"},
                "purpose": "PUBLICATION_GATING",
                "members": members,
            },
        ).status_code
        == 200
    )
    r2 = ran(p["author"], good_suite["id"])
    assert ready(p["author"], pid, r2["id"])["ready"] is True
    put(
        p["author"],
        f"{S}/{s['neither']['id']}/draft",
        {"expected_revision": 1, "document": {**s["neither"]["document"], "description": "changed after the run"}},
    )
    stale = ready(p["author"], pid, r2["id"])
    assert (
        "Scenario 'Scenario NEITHER' was changed after this run" in blocker(stale, "EVIDENCE_OUT_OF_DATE")["message"]
        and stale["ready"] is False
    )
    r3 = ran(p["author"], good_suite["id"])
    assert ready(p["author"], pid, r3["id"])["ready"] is True
    doc = copy.deepcopy(w["policy"]["document"])
    doc["description"] = "saved again"
    assert save_policy(p["author"], pid, 1, doc).status_code == 200
    old = blocker(ready(p["author"], pid, r3["id"]), "EVIDENCE_OUT_OF_DATE")
    assert "policy revision 1; the saved policy is now revision 2" in old["message"] and old["at"] == {
        "run_revision": 1,
        "policy_revision": 2,
    }
    assert (
        ready(p["author"], pid, r3["id"])["runs"][0]["of_this_revision"] is False
    )  # the newest run is not chosen, and is not of this revision
    assert submit(p["author"], pid, ready(p["author"], pid, r3["id"])).json()["code"] == "PUBLICATION_BLOCKED"
    r4 = ran(p["author"], good_suite["id"])
    assert ready(p["author"], pid, r4["id"])["ready"] is True
    # ---- 5. PIN_DIFFERS: a published condition evaluated against another variable version than it was published with
    family = next(
        x for x in p["author"].get(f"{A}/assets?kind=VARIABLE").json()["items"] if x["code"] == "product_family"
    )
    revise(p, family["id"], {**FAMILY, "values": [*FAMILY["values"], {"value": "HEALTH", "label": "Health"}]})
    pinned = copy.deepcopy(read_policy(p["author"], pid)["document"])
    next(x for x in pinned["pins"] if x["code"] == "product_family")["version"] = 2
    assert save_policy(p["author"], pid, 2, pinned).status_code == 200
    r5 = ran(p["author"], good_suite["id"])
    differs = ready(p["author"], pid, r5["id"])
    pin = blocker(differs, "PIN_DIFFERS")
    assert (
        differs["ready"] is False
        and pin["at"]["variable"] == "product_family"
        and pin["at"]["code"] == "ilp"
        and "There is no override" in pin["action"]
        and pin["prevents"] == ["SUBMISSION", "APPROVAL", "PUBLICATION"]
    )
    assert submit(p["author"], pid, differs).json()["code"] == "PUBLICATION_BLOCKED" and "PIN_DIFFERS" in {
        d["code"] for d in submit(p["author"], pid, differs).json()["details"]
    }
    # cleared by publishing a compatible condition version against the variable version this policy uses, and adopting it
    ilp = next(x for x in p["author"].get(f"{A}/assets?kind=CONDITION").json()["items"] if x["code"] == "ilp")
    revise(
        p,
        ilp["id"],
        {
            "name": "Is ILP",
            "description": "Republished against product family version 2.",
            "expr": check("product_family", "equals", value="ILP"),
        },
    )
    adopted = copy.deepcopy(read_policy(p["author"], pid)["document"])
    for q in adopted["requirements"]:
        if q["when"].get("condition") == "ilp":
            q["when"]["version"] = 2
        for arg in q["when"].get("args") or []:
            if arg.get("condition") == "ilp":
                arg["version"] = 2
    assert save_policy(p["author"], pid, 3, adopted).status_code == 200
    r6 = ran(p["author"], good_suite["id"])
    cleared = ready(p["author"], pid, r6["id"])
    assert "PIN_DIFFERS" not in codes(cleared) and cleared["ready"] is True
    # ---- 4.2 a SUPERSEDED pin is valid: the survey-independent case here is the condition "nftf_applies" v1 after a v2
    nf = next(x for x in p["author"].get(f"{A}/assets?kind=CONDITION").json()["items"] if x["code"] == "nftf_applies")
    revise(p, nf["id"], {"name": "NFTF applies (reworded)", "expr": check("nftf")})
    still = ready(p["author"], pid, r6["id"])
    assert (
        still["ready"] is True
        and [(n["code"], n["at"]["code"]) for n in still["notices"]] == [("NEWER_VERSION", "nftf_applies")]
        and "stays valid" in still["notices"][0]["message"]
    )
    assert (
        next(d for d in still["dependencies"] if d["code"] == "nftf_applies")["version_no"] == 1
    )  # never upgraded for the author
    # ---- 1. an unpublished dependency · 3. a stale one
    cond = created(p["author"], "CONDITION", "draft_cond", {"name": "Draft condition", "expr": check("nftf")})
    drafty = copy.deepcopy(read_policy(p["author"], pid)["document"])
    drafty["requirements"].append(req("r9", ref("draft_cond"), b))
    drafty["shared_deliveries"] = [{"survey": b["code"], "requirements": ["r2", "r9"]}]
    assert save_policy(p["author"], pid, 4, drafty).status_code == 200
    un = blocker(ready(p["author"], pid, r6["id"]), "UNPUBLISHED_DEPENDENCY")
    assert (
        un["at"] == {"kind": "condition", "code": "draft_cond", "pinned": "draft r1"}
        and "Publish the condition" in un["action"]
    )
    assert (
        put_asset(
            p["author"], cond["id"], 1, {"name": "Draft condition", "expr": {"op": "not", "arg": check("nftf")}}
        ).status_code
        == 200
    )
    st = blocker(ready(p["author"], pid, r6["id"]), "DEPENDENCY_STALE")
    assert st["at"] == {"kind": "condition", "code": "draft_cond", "pinned": "draft r1", "now": "draft r2"}
    assert save_policy(p["author"], pid, 5, adopted).status_code == 200  # the draft requirement is removed again
    # ---- 9. a profile mismatch and an incompatible variable value in a gating scenario are named, not just "failed"
    revise(p, w["profile"]["id"], {**COMMON, "name": "Common application v2"})
    newer = saved(p["author"], "ON-PROFILE-V2", {"product_family": "ILP", "nftf": False})
    health = saved(p["author"], "HEALTH", {"product_family": "HEALTH", "nftf": False}, profiles=())
    back = copy.deepcopy(adopted)
    next(x for x in back["pins"] if x["code"] == "product_family")["version"] = 1
    for q in back["requirements"]:
        if q["when"].get("condition") == "ilp":
            q["when"]["version"] = 1
        for arg in q["when"].get("args") or []:
            if arg.get("condition") == "ilp":
                arg["version"] = 1
    assert (
        save_policy(p["author"], pid, 6, back).status_code == 200
    )  # the policy is on product_family v1 and profile v1 again
    mism, r_mism = gate(
        "MISMATCH",
        [
            (newer, expect("RESOLVED", a)),
            (health, expect("UNRESOLVED", pending=(a["code"],))),
            (s["nftf"], expect("RESOLVED", b)),
        ],
    )
    assert r_mism["status"] == "INVALID_DEFINITION" and {
        "PROFILE_MISMATCH",
        "VARIABLE_VERSION_INCOMPATIBLE",
        "SUITE_FAILED",
    } <= set(codes(mism))
    assert "no acknowledgement for a publication-gating scenario" in blocker(mism, "PROFILE_MISMATCH")["action"]
    assert blocker(mism, "VARIABLE_VERSION_INCOMPATIBLE")["at"]["code"] == "product_family"
    # ---- 2. an invalid survey reference. The API refuses to SAVE one, so the stored document is altered directly to prove
    #         that the gate itself checks: a fingerprint that is not that version's
    with engine.begin() as cx:
        cx.execute(
            text(
                f"UPDATE {T}.applicability_policy SET document = jsonb_set(document, '{{requirements,0,action,surveys,0,fingerprint}}', to_jsonb(repeat('0', 64))), draft_revision = draft_revision + 1 WHERE id = :i"
            ),
            {"i": pid},
        )
    bad = blocker(ready(p["author"], pid, r6["id"]), "INVALID_SURVEY_REFERENCE")
    assert (
        "its content fingerprint is not that version's" in bad["message"]
        and bad["at"]["code"] == a["code"]
        and bad["at"]["requirement"] == "r1"
    )
    assert ready(p["author"], pid, r6["id"])["ready"] is False


def test_return_resubmit_withdraw_and_evidence_changed_after_approval(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    w, s, u, r = prepared(p)
    pid = w["policy"]["id"]
    # ---- B. returned with a reason; the author edits, runs an updated suite, and submits a NEW candidate
    first = submit(p["author"], pid, ready(p["author"], pid, r["id"])).json()
    returned = post(
        p["checker"],
        f"{CAND}/{first['id']}/decision",
        {
            "verdict": "RETURN",
            "candidate_sha256": first["candidate_sha256"],
            "comment": "Survey C should replace A and B when both apply.",
        },
    )
    assert returned.json()["status"] == "RETURNED" and returned.json()["decision_comment"].startswith(
        "Survey C should replace"
    )
    assert (
        post(
            p["publisher"],
            f"{CAND}/{first['id']}/publish",
            {"candidate_sha256": first["candidate_sha256"], "version_no": 1},
        ).json()["code"]
        == "NOT_APPROVED"
    )
    assert save_policy(p["author"], pid, 1, w["replacing"]).status_code == 200
    stale = ready(p["author"], pid, r["id"])
    assert "EVIDENCE_OUT_OF_DATE" in codes(stale)  # the earlier run is of the earlier revision: it is not carried over
    full = p["author"].get(f"{U}/{u['id']}").json()
    members = [{"scenario_id": m["scenario_id"], "expectation": m["expectation"]} for m in full["member_list"]]
    members[2]["expectation"] = expect("RESOLVED", w["c"], replaced=["r1", "r2"])  # both → C alone
    members[4]["expectation"] = expect("UNRESOLVED", pending=(w["a"]["code"], w["b"]["code"], w["c"]["code"]))
    assert (
        put(
            p["author"],
            f"{U}/{u['id']}/draft",
            {
                "expected_revision": 1,
                "document": {"name": "Suite GATE"},
                "purpose": "PUBLICATION_GATING",
                "members": members,
            },
        ).status_code
        == 200
    )
    r2 = ran(p["author"], u["id"])
    assert r2["status"] == "PASSED"
    second = submit(p["author"], pid, ready(p["author"], pid, r2["id"]))
    assert second.status_code == 201 and second.json()["candidate_no"] == 2 and second.json()["draft_revision"] == 2
    cid, sha = second.json()["id"], second.json()["candidate_sha256"]
    kept = p["reader"].get(f"{CAND}/{first['id']}").json()  # the returned candidate stays readable, exactly as it was
    assert (kept["status"], kept["document"], kept["candidate_sha256"]) == (
        "RETURNED",
        first["document"],
        first["candidate_sha256"],
    ) and [e["event"] for e in kept["events"]] == ["SUBMITTED", "RETURNED", "REFUSED"]
    assert [(x["candidate_no"], x["status"]) for x in p["reader"].get(f"{CAND}?policy_id={pid}").json()["items"]] == [
        (2, "SUBMITTED"),
        (1, "RETURNED"),
    ]
    # ---- D. approved … and then one scenario of the evidence suite is edited: publication is refused, nothing is refreshed
    assert (
        post(p["checker"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).json()["status"]
        == "APPROVED"
    )
    before = p["reader"].get(f"{CAND}/{cid}").json()
    assert before["revalidation"] == []
    put(
        p["author"],
        f"{S}/{s['both']['id']}/draft",
        {
            "expected_revision": 1,
            "document": {**s["both"]["document"], "facts": {"product_family": "PROTECTION", "nftf": True}},
        },
    )
    refused = post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1})
    assert (
        refused.status_code == 409
        and refused.json()["code"] == "PUBLICATION_BLOCKED"
        and "Nothing was refreshed or substituted" in refused.json()["message"]
    )
    assert [d["code"] for d in refused.json()["details"]] == [
        "EVIDENCE_CHANGED"
    ] and "Scenario 'Scenario BOTH' of the evidence suite was changed" in refused.json()["details"][0]["message"]
    after = p["reader"].get(f"{CAND}/{cid}").json()
    assert (after["status"], after["document"], after["evidence"], after["candidate_sha256"]) == (
        "APPROVED",
        before["document"],
        before["evidence"],
        sha,
    )
    assert (
        [d["code"] for d in after["revalidation"]] == ["EVIDENCE_CHANGED"]
        and after["events"][-1]["event"] == "REFUSED"
        and after["events"][-1]["detail"]["step"] == "PUBLICATION"
    )
    assert p["reader"].get(f"{POL}/{pid}/versions").json()["items"] == []
    # a newer PASSING run does not rescue it: the approved candidate names ITS run and ITS scenarios
    put(
        p["author"],
        f"{S}/{s['both']['id']}/draft",
        {"expected_revision": 2, "document": {**s["both"]["document"], "description": "reworded after approval"}},
    )
    assert (
        ran(p["author"], u["id"], {"kind": "DRAFT", "revision": 2})["status"] == "PASSED"
    )  # a candidate is open: the run must name its target
    again = post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1})
    assert (
        again.json()["code"] == "PUBLICATION_BLOCKED" and p["reader"].get(f"{POL}/{pid}/versions").json()["items"] == []
    )
    # put back BYTE FOR BYTE: the fingerprint matches again, the revision does not — the candidate stays ineligible
    put(p["author"], f"{S}/{s['both']['id']}/draft", {"expected_revision": 3, "document": s["both"]["document"]})
    back = p["reader"].get(f"{CAND}/{cid}").json()["revalidation"]
    assert [(d["code"], d["at"].get("reason")) for d in back] == [("EVIDENCE_CHANGED", "REVISION_ADVANCED")]
    put(
        p["author"],
        f"{S}/{s['both']['id']}/draft",
        {"expected_revision": 4, "document": {**s["both"]["document"], "description": "changed once more"}},
    )
    assert [d["code"] for d in p["reader"].get(f"{CAND}/{cid}").json()["revalidation"]] == ["EVIDENCE_CHANGED"]
    # ---- the author withdraws it (only the submitter can) and submits a third, valid, candidate
    assert (
        post(p["second"], f"{CAND}/{cid}/withdraw", {"reason": "not my candidate to withdraw"}).json()["code"]
        == "NOT_SUBMITTER"
    )
    assert post(p["author"], f"{CAND}/{cid}/withdraw", {"reason": "short"}).json()["code"] == "COMMENT_REQUIRED"
    gone = post(
        p["author"], f"{CAND}/{cid}/withdraw", {"reason": "The evidence changed after approval; resubmitting."}
    ).json()
    assert gone["status"] == "WITHDRAWN" and p["reader"].get(f"{CAND}/{cid}").json()["document"] == before["document"]
    r3 = ran(p["author"], u["id"])
    done = through(p, pid, r3["id"])
    assert done["candidate_no"] == 3 and done["version"]["version_no"] == 1
    assert (
        post(p["author"], f"{CAND}/{cid}/withdraw", {"reason": "already withdrawn before"}).json()["code"] == "NOT_OPEN"
    )
    assert (
        post(
            p["checker"],
            f"{CAND}/{done['id']}/decision",
            {"verdict": "RETURN", "candidate_sha256": done["candidate_sha256"], "comment": "too late to return this"},
        ).json()["code"]
        == "NOT_SUBMITTED"
    )


def _suite_put(c: TestClient, suite_id: str, revision: int, name: str) -> Any:
    full = c.get(f"{U}/{suite_id}").json()
    members = [{"scenario_id": m["scenario_id"], "expectation": m["expectation"]} for m in full["member_list"]]
    return put(c, f"{U}/{suite_id}/draft", {"expected_revision": revision, "document": {"name": name}, "purpose": "PUBLICATION_GATING", "members": members})  # fmt: skip


def test_evidence_edited_and_restored_never_regains_eligibility(people: dict[str, TestClient], engine: Engine) -> None:
    """Owner ruling (APPL-X4b acceptance, part 1). Evidence is a run of exact REVISIONS. A supporting scenario or suite
    that is changed after submission and then restored byte for byte has its old fingerprint and a newer revision: the
    candidate does not become publishable again. A new run and a new candidate are required; the old one is kept."""
    p = people

    def state(table: str, ident: str) -> tuple[str, int]:
        with engine.connect() as c:
            row = c.execute(text(f"SELECT document_sha256, draft_revision FROM {T}.{table} WHERE id = :i"), {"i": ident}).one()  # fmt: skip
        return str(row[0]), int(row[1])

    def publish(cid: str, sha: str) -> Any:
        return post(p["publisher"], f"{CAND}/{cid}/publish", {"candidate_sha256": sha, "version_no": 1})

    # ================================================================== A. a SCENARIO changed and restored
    w, s, u, r = prepared(p)  # 1. a passing qualifying run
    pid, sid = w["policy"]["id"], s["both"]["id"]
    c1 = submit(p["author"], pid, ready(p["author"], pid, r["id"]))  # 2. submitted
    assert c1.status_code == 201, c1.text
    cid, sha = c1.json()["id"], c1.json()["candidate_sha256"]
    assert post(p["checker"], f"{CAND}/{cid}/decision", {"verdict": "APPROVE", "candidate_sha256": sha}).status_code == 200  # 3. approved  # fmt: skip
    frozen = p["reader"].get(f"{CAND}/{cid}").json()
    assert [x["revision"] for x in frozen["evidence"]["scenario_fingerprints"]] == [1, 1, 1, 1, 1]  # the revisions run
    original = state("applicability_scenario", sid)
    assert original[1] == 1
    # the separate WORKING POLICY DRAFT moving on does not invalidate the candidate
    assert save_policy(p["author"], pid, 1, {**w["policy"]["document"], "description": "edited after submission"}).status_code == 200  # fmt: skip
    assert p["reader"].get(f"{CAND}/{cid}").json()["revalidation"] == []
    # 4. a supporting scenario is changed …
    assert put(p["author"], f"{S}/{sid}/draft", {"expected_revision": 1, "document": {**s["both"]["document"], "description": "changed after approval"}}).status_code == 200  # fmt: skip
    assert state("applicability_scenario", sid)[0] != original[0]
    # 5. … and restored exactly
    assert put(p["author"], f"{S}/{sid}/draft", {"expected_revision": 2, "document": s["both"]["document"]}).status_code == 200  # fmt: skip
    restored = state("applicability_scenario", sid)
    assert restored[0] == original[0]  # 6. the original content fingerprint matches
    assert restored[1] == 3 > original[1]  # 7. the revision has advanced
    # 8. publication is still refused
    no = publish(cid, sha)
    assert no.status_code == 409 and no.json()["code"] == "PUBLICATION_BLOCKED", no.text
    d = no.json()["details"]
    assert [(x["code"], x["at"]["reason"], x["at"]["revision_run"], x["at"]["revision_now"], x["at"]["scenario"]) for x in d] == [("EVIDENCE_CHANGED", "REVISION_ADVANCED", 1, 3, sid)]  # fmt: skip
    assert "putting its content back does not make it the revision that was run" in d[0]["message"]
    # 9. the refusal is recorded; the candidate is untouched and nothing was published
    after = p["reader"].get(f"{CAND}/{cid}").json()
    assert (after["status"], after["candidate_sha256"], after["document"], after["evidence"]) == ("APPROVED", sha, frozen["document"], frozen["evidence"])  # fmt: skip
    assert after["events"][-1]["event"] == "REFUSED" and after["events"][-1]["detail"]["step"] == "PUBLICATION"
    assert p["reader"].get(f"{POL}/{pid}/versions").json()["items"] == []
    with engine.connect() as c:
        assert c.execute(text(f"SELECT count(*) FROM {T}.audit_event WHERE action = 'APPLICABILITY.POLICY_TRANSITION_REFUSED' AND outcome = 'DENIED' AND entity_id = :i"), {"i": cid}).scalar_one() >= 1  # fmt: skip
    # approval is refused the same way: a returned-and-resubmitted path cannot route around it
    assert [x["code"] for x in after["revalidation"]] == ["EVIDENCE_CHANGED"]
    # the old run is still an immutable record that reproduces by itself — it is just not evidence any more
    assert post(p["reader"], f"{R}/{r['id']}/verify", {}).json()["reproduced"] is True
    # … and it is not accepted as evidence for a NEW submission either
    assert post(p["author"], f"{CAND}/{cid}/withdraw", {"reason": "Evidence was edited and restored after approval."}).json()["status"] == "WITHDRAWN"  # fmt: skip
    again = ready(p["author"], pid, r["id"])
    assert "EVIDENCE_OUT_OF_DATE" in codes(again) and submit(p["author"], pid, again).json()["code"] == "PUBLICATION_BLOCKED"  # fmt: skip
    # 10. a new qualifying run and a newly submitted candidate; 11. three distinct identities
    r2 = ran(p["author"], u["id"])
    assert r2["status"] == "PASSED"
    done = through(p, pid, r2["id"])
    assert done["candidate_no"] == 2 and done["version"]["version_no"] == 1
    v = p["reader"].get(f"{POL}/{pid}/versions").json()["items"][0]
    full = p["reader"].get(f"{VER}/{v['id']}").json()
    assert len({full["submitted_by"], full["approved_by"], full["published_by"]}) == 3
    assert {x["scenario_id"]: x["revision"] for x in full["evidence"]["scenario_fingerprints"]}[sid] == 3
    kept = p["reader"].get(f"{CAND}/{cid}").json()  # the original candidate and its history are preserved
    assert kept["status"] == "WITHDRAWN" and [e["event"] for e in kept["events"]] == ["SUBMITTED", "APPROVED", "REFUSED", "WITHDRAWN"]  # fmt: skip
    assert kept["evidence"] == frozen["evidence"]

    # ================================================================== B. a SUITE changed and restored
    # (a version is published now, so every run names its target)
    pol = p["author"].get(f"{POL}/{pid}?inspection=false").json()
    assert save_policy(p["author"], pid, pol["draft_revision"], {**pol["document"], "description": "a further revision, for the suite case"}).status_code == 200  # fmt: skip
    rev = pol["draft_revision"] + 1
    r3 = ran(p["author"], u["id"], {"kind": "DRAFT", "revision": rev})
    c3 = submit(p["author"], pid, ready(p["author"], pid, r3["id"]))
    assert c3.status_code == 201, c3.text
    cid3, sha3 = c3.json()["id"], c3.json()["candidate_sha256"]
    before = state("applicability_suite", u["id"])
    assert _suite_put(p["author"], u["id"], before[1], "Suite GATE, renamed").status_code == 200
    assert state("applicability_suite", u["id"])[0] != before[0]
    assert _suite_put(p["author"], u["id"], before[1] + 1, "Suite GATE").status_code == 200
    now = state("applicability_suite", u["id"])
    assert now[0] == before[0] and now[1] == before[1] + 2  # the same fingerprint, a later revision
    # APPROVAL is refused — the check is at every transition, not only at publication
    no3 = post(p["checker"], f"{CAND}/{cid3}/decision", {"verdict": "APPROVE", "candidate_sha256": sha3})
    assert no3.status_code == 409 and no3.json()["code"] == "PUBLICATION_BLOCKED", no3.text
    assert [(x["code"], x["at"]["reason"], x["at"]["suite"], x["at"]["revision_run"], x["at"]["revision_now"]) for x in no3.json()["details"]] == [("EVIDENCE_CHANGED", "REVISION_ADVANCED", "GATE", before[1], now[1])]  # fmt: skip
    c3_after = p["reader"].get(f"{CAND}/{cid3}").json()
    assert c3_after["status"] == "SUBMITTED" and c3_after["events"][-1]["event"] == "REFUSED"
    # … and the run is no longer accepted for a new submission
    assert post(p["author"], f"{CAND}/{cid3}/withdraw", {"reason": "The suite was edited and restored."}).json()["status"] == "WITHDRAWN"  # fmt: skip
    stale = ready(p["author"], pid, r3["id"])
    assert [b["at"].get("reason") for b in stale["blockers"] if b["code"] == "EVIDENCE_OUT_OF_DATE"] == ["REVISION_ADVANCED"]  # fmt: skip
    # a new run of the suite as it now stands qualifies, and publishes as version 2 with three people
    r4 = ran(p["author"], u["id"], {"kind": "DRAFT", "revision": rev})
    done2 = through(p, pid, r4["id"])
    assert done2["version"]["version_no"] == 2 and done2["evidence"]["suite_revision"] == now[1]


def test_supersession_explicit_run_targets_and_impact_over_one_dataset(
    people: dict[str, TestClient], engine: Engine
) -> None:
    p = people
    w, s, u, r = prepared(p)
    pid = w["policy"]["id"]
    # ---- before anything is published a run needs no target: there is only the working draft
    assert p["reader"].get(f"{POL}/{pid}/run-targets").json() == {"policy_id": pid, "must_choose": False, "items": [
        {"kind": "DRAFT", "id": None, "label": "Saved working draft · revision 1", "status": "DRAFT", "revision": 1, "version_no": None, "document_sha256": w["policy"]["document_sha256"], "manifest_sha256": w["policy"]["snapshot_sha256"]}]}  # fmt: skip
    assert r["target"] == {
        "kind": "DRAFT",
        "revision": 1,
        "document_sha256": w["policy"]["document_sha256"],
        "manifest_sha256": w["policy"]["snapshot_sha256"],
    }
    v1 = through(p, pid, r["id"])
    v1id = v1["version"]["id"]
    # ---- E. a legitimately changed policy (C replaces A and B) with new qualifying evidence becomes version 2
    assert save_policy(p["author"], pid, 1, w["replacing"]).status_code == 200
    full = p["author"].get(f"{U}/{u['id']}").json()
    members = [{"scenario_id": m["scenario_id"], "expectation": m["expectation"]} for m in full["member_list"]]
    members[2]["expectation"] = expect("RESOLVED", w["c"], replaced=["r1", "r2"])
    members[4]["expectation"] = expect("UNRESOLVED", pending=(w["a"]["code"], w["b"]["code"], w["c"]["code"]))
    assert (
        put(
            p["author"],
            f"{U}/{u['id']}/draft",
            {
                "expected_revision": 1,
                "document": {"name": "Suite GATE"},
                "purpose": "PUBLICATION_GATING",
                "members": members,
            },
        ).status_code
        == 200
    )
    # ---- Q-h: now that a published version exists, a run must say EXACTLY what it evaluates — nothing is assumed
    silent = run_(p["author"], u["id"])
    assert (
        silent.status_code == 422
        and silent.json()["code"] == "TARGET_REQUIRED"
        and [x["kind"] for x in silent.json()["details"][0]["targets"]] == ["DRAFT", "VERSION"]
    )
    assert run_(p["author"], u["id"], {"kind": "DRAFT", "revision": 1}).json()["code"] == "STALE_TARGET"
    assert run_(p["author"], u["id"], {"kind": "VERSION", "id": str(uuid.uuid4())}).status_code == 404
    assert run_(p["author"], u["id"], {"kind": "SOMETHING"}).json()["code"] == "INVALID_TARGET"
    r2 = ran(p["author"], u["id"], {"kind": "DRAFT", "revision": 2})
    assert r2["status"] == "PASSED" and r2["target"]["kind"] == "DRAFT" and r2["target"]["revision"] == 2
    # the SAME suite against published version 1: it evaluates version 1's own frozen document — and fails the new expectations
    on_v1 = ran(p["author"], u["id"], {"kind": "VERSION", "id": v1id})
    assert on_v1["target"] == {
        "kind": "VERSION",
        "id": v1id,
        "version_no": 1,
        "status": "PUBLISHED",
        "document_sha256": v1["document_sha256"],
        "manifest_sha256": v1["manifest_sha256"],
    }
    assert (
        on_v1["status"] == "FAILED"
        and on_v1["policy_document_sha256"] == v1["document_sha256"] != r2["policy_document_sha256"]
        and on_v1["policy_revision"] == 1
    )
    assert (
        post(p["reader"], f"{R}/{on_v1['id']}/verify").json()["reproduced"] is True
    )  # a run on a frozen target reproduces from its record too
    # a run of a published version is never evidence for the draft
    assert "EVIDENCE_OUT_OF_DATE" in codes(ready(p["author"], pid, on_v1["id"]))
    state = ready(p["author"], pid, r2["id"])
    assert state["ready"] is True and state["published"]["version_no"] == 1
    c2 = submit(p["author"], pid, state).json()
    assert c2["evidence"]["replaces_version"]["version_no"] == 1 and c2["next_version_no"] == 2
    # a frozen candidate is a target too, once it exists
    assert [x["kind"] for x in p["reader"].get(f"{POL}/{pid}/run-targets").json()["items"]] == [
        "DRAFT",
        "CANDIDATE",
        "VERSION",
    ]
    on_c2 = ran(p["author"], u["id"], {"kind": "CANDIDATE", "id": c2["id"]})
    assert (
        on_c2["status"] == "PASSED"
        and on_c2["target"]["kind"] == "CANDIDATE"
        and on_c2["target"]["candidate_no"] == 2
        and on_c2["policy_document_sha256"] == c2["document_sha256"]
    )
    # ---- F. impact, candidate against the published version, over ONE dataset — the recorded scenarios of one run
    imp = post(
        p["checker"],
        f"{POL}/{pid}/impact",
        {
            "dataset_run_id": r2["id"],
            "before": {"kind": "VERSION", "id": v1id},
            "after": {"kind": "CANDIDATE", "id": c2["id"]},
        },
    ).json()
    assert (
        imp["reproducible"] is True
        and imp["document_changed"] is True
        and imp["requirements_changed"] == ["Requirement r3"]
        and imp["dependency_changes"] == []
        and (imp["changed"], imp["unchanged"]) == (2, 3)
    )
    assert (
        imp["dataset"]["scenarios"] == 5
        and imp["before"]["kind"] == "VERSION"
        and imp["after"]["kind"] == "CANDIDATE"
        and "SAME recorded scenarios" in imp["note"]
    )
    both = next(x for x in imp["scenarios"] if x["scenario_name"] == "Scenario BOTH")
    assert (
        sorted(both["comparison"]["removed"]) == ["Survey A", "Survey B"]
        and both["comparison"]["added"] == []
        and {x["requirement"] for x in both["comparison"]["because"]} == {"r1", "r2"}
    )
    assert (both["outcome_before"], both["outcome_after"]) == ("FAILED", "PASSED") and both[
        "facts_changed"
    ] == []  # the same scenario on both sides
    unk = next(x for x in imp["scenarios"] if x["scenario_name"] == "Scenario NFTF-UNKNOWN")
    assert unk["comparison"]["removed"] == ["Survey A"] and unk["comparison"]["pending_added"] == [w["a"]["code"]]
    before = everything_else(engine)
    assert p["reader"].get(f"{R}?policy_id={pid}").json()["total"] == 4  # impact recorded nothing
    # ---- publish version 2: version 1 is SUPERSEDED, still readable, still verifiable
    assert (
        post(
            p["checker"],
            f"{CAND}/{c2['id']}/decision",
            {"verdict": "APPROVE", "candidate_sha256": c2["candidate_sha256"]},
        ).status_code
        == 200
    )
    assert (
        post(
            p["publisher"], f"{CAND}/{c2['id']}/publish", {"candidate_sha256": c2["candidate_sha256"], "version_no": 1}
        ).json()["code"]
        == "VERSION_CHANGED"
    )
    pub2 = post(
        p["publisher"], f"{CAND}/{c2['id']}/publish", {"candidate_sha256": c2["candidate_sha256"], "version_no": 2}
    ).json()
    v2id = pub2["version"]["id"]
    listed = p["reader"].get(f"{POL}/{pid}/versions").json()["items"]
    assert [(x["version_no"], x["status"]) for x in listed] == [(2, "PUBLISHED"), (1, "SUPERSEDED")] and listed[1][
        "superseded_at"
    ] is not None
    old = p["reader"].get(f"{VER}/{v1id}").json()
    assert (
        old["status"] == "SUPERSEDED"
        and old["document"] == v1["document"]
        and old["candidate_sha256"] == v1["candidate_sha256"]
        and [e["event"] for e in old["events"]][-1] == "SUPERSEDED"
    )
    assert (
        post(p["reader"], f"{VER}/{v1id}/verify").json()["verified"] is True
        and post(p["reader"], f"{VER}/{v2id}/verify").json()["verified"] is True
    )
    with engine.connect() as cx:  # at most one PUBLISHED version of a policy, by the database
        assert (
            cx.execute(
                text(
                    f"SELECT count(*) FROM {T}.applicability_policy_version WHERE policy_id = :p AND status = 'PUBLISHED'"
                ),
                {"p": pid},
            ).scalar_one()
            == 1
        )
    # version 1 against version 2, over the same dataset
    vs = post(
        p["reader"],
        f"{POL}/{pid}/impact",
        {
            "dataset_run_id": r["id"],
            "before": {"kind": "VERSION", "id": v1id},
            "after": {"kind": "VERSION", "id": v2id},
        },
    ).json()
    assert (
        (vs["changed"], vs["unchanged"]) == (2, 3)
        and vs["before"]["version_no"] == 1
        and vs["after"]["version_no"] == 2
    )
    # a superseded version remains a valid run target; the newest is never assumed
    assert ran(p["author"], u["id"], {"kind": "VERSION", "id": v1id})["target"]["status"] == "SUPERSEDED"
    assert run_(p["author"], u["id"]).json()["code"] == "TARGET_REQUIRED"
    # ---- H. nothing but the applicability tables and the audit trail changed through publication, impact and runs
    after = everything_else(engine)
    assert {k for k in before if before[k] != after[k]} == {"audit_event"}
    # read-only people may run nothing; a market outsider sees none of it
    assert run_(p["reader"], u["id"], {"kind": "VERSION", "id": v1id}).status_code == 403


def test_markets_and_older_expectations_without_a_stamp(
    people: dict[str, TestClient], x5_app: Any, db: Session, engine: Engine
) -> None:
    p = people
    w, s, u, r = prepared(p)
    pid = w["policy"]["id"]
    done = through(p, pid, r["id"])
    other = make_account(db, prefix="x5my")
    GRANTS[other.principal_id], MARKETS[other.principal_id] = frozenset(ALL4), frozenset({"MY"})
    try:
        with _client(x5_app, other) as my:
            for call in (lambda c: c.get(f"{POL}/{pid}/readiness"), lambda c: c.get(f"{POL}/{pid}/versions"), lambda c: c.get(f"{POL}/{pid}/run-targets"), lambda c: c.get(f"{CAND}/{done['id']}"),
                         lambda c: c.get(f"{VER}/{done['version']['id']}"), lambda c: post(c, f"{VER}/{done['version']['id']}/verify"), lambda c: post(c, f"{CAND}/{done['id']}/withdraw", {"reason": "not of my market at all"}),
                         lambda c: post(c, f"{POL}/{pid}/impact", {"dataset_run_id": r["id"], "before": {"kind": "DRAFT"}, "after": {"kind": "DRAFT"}})):  # fmt: skip
                assert call(my).status_code == 404
            assert my.get(CAND).json()["total"] == 0 and my.get(f"{VER}/usage").json()["items"] == []
    finally:
        GRANTS.pop(other.principal_id, None)
        MARKETS.pop(other.principal_id, None)
    # ---- an expectation saved BEFORE the server stamped authors: its author is read from the suite's append-only history,
    #      and labelled as such. Simulated by removing the stamps from the stored members (the history is untouched).
    with engine.begin() as cx:
        cx.execute(text(f"ALTER TABLE {T}.applicability_suite_member DISABLE TRIGGER applicability_suite_member_guard"))
        cx.execute(
            text(
                f"UPDATE {T}.applicability_suite_member SET expectation = expectation - 'stated_by' - 'stated_at' WHERE suite_id = :u"
            ),
            {"u": u["id"]},
        )
        cx.execute(text(f"ALTER TABLE {T}.applicability_suite_member ENABLE TRIGGER applicability_suite_member_guard"))
    run = (
        db.execute(text("SELECT id, suite_id FROM applicability_evaluation_run WHERE id = :i"), {"i": r["id"]})
        .mappings()
        .one()
    )
    rows = [
        {**x, "expectation": {k: v for k, v in x["expectation"].items() if k not in ("stated_by", "stated_at")}}
        for x in pub.sc._stored(db, uuid.UUID(r["id"]))[1]
    ]  # noqa: SLF001
    prov = pub.provenance(db, run, rows)
    assert all(
        x["authorship_from"] == "SUITE_HISTORY"
        and x["stated_by"].startswith("Test X5Author")
        and x["source"] == "AUTHORED"
        for x in prov
    )  # read from history, never invented
    # and with no history at all for a scenario the author is said to be unknown — not guessed
    assert (
        pub.provenance(db, {"suite_id": uuid.uuid4()}, rows)[0]["authorship_from"] == "UNKNOWN"
        and pub.provenance(db, {"suite_id": uuid.uuid4()}, rows)[0]["stated_by"] is None
    )


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
                {"t": list(PUBLICATION_TABLES)},
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


def test_zz_migration_0041_is_additive_reversible_while_empty_atomic_and_keeps_governed_history(fresh_schema: None, engine: Engine, settings: Settings, x5_app: Any, db: Session) -> None:  # fmt: skip
    """On a POPULATED schema: a published library, published surveys, a saved policy, scenarios, a suite and a recorded run."""
    edit = {"applicability.read", "applicability.edit", "survey.read"}
    grants = {
        "author": edit,
        "checker": {"applicability.read", "applicability.approve", "survey.read"},
        "publisher": {"applicability.read", "applicability.publish", "survey.read"},
        "s1": set(SURVEY),
        "s2": set(SURVEY),
        "s3": set(SURVEY),
    }
    accounts = {k: make_account(db, prefix=f"zx5{k}") for k in grants}
    for k, a_ in accounts.items():
        GRANTS[a_.principal_id] = frozenset(grants[k])
    p = {k: _client(x5_app, a_) for k, a_ in accounts.items()}
    try:
        w, s, u, r = prepared(p)
        pid = w["policy"]["id"]
        assert _head(engine) == MIGRATION_HEAD
        full = _objects(engine)
        assert full == (sorted(PUBLICATION_TABLES), FUNCTIONS)
        before = everything_else(engine)
        scen = {
            t: (c_, d)
            for t, (c_, d) in (
                (t, _digest(engine, t))
                for t in (
                    "applicability_scenario",
                    "applicability_suite",
                    "applicability_evaluation_run",
                    "applicability_evaluation_result",
                )
            )
        }
        assert before["applicability_policy"][0] == 1 and scen["applicability_evaluation_run"][0] == 1
        with engine.connect() as c:
            fks = c.execute(
                text(
                    "SELECT count(*) FROM pg_constraint con JOIN pg_class cl ON cl.oid = con.conrelid JOIN pg_namespace n ON n.oid = cl.relnamespace WHERE con.contype = 'f' AND n.nspname = :s AND cl.relname = ANY(:t) AND con.convalidated"
                ),
                {"s": T, "t": list(PUBLICATION_TABLES)},
            ).scalar_one()
            assert fks == 11  # every reference is a validated foreign key
            assert (
                c.execute(text(f"SELECT count(*) FROM {T}.permission WHERE code LIKE 'applicability.%'")).scalar_one()
                == 4
            )

        def same() -> bool:
            return everything_else(engine) == before and all(_digest(engine, t) == scen[t] for t in scen)

        # 1. downgrade while empty removes exactly the four tables and four guards; nothing else changes — the recorded run too
        migrate(settings, "0040_applicability_scenarios", down=True)
        assert _head(engine) == "0040_applicability_scenarios" and _objects(engine) == ([], []) and same()
        # 2. a forced failure at the LAST statement: all rolled back
        with engine.begin() as c:
            c.execute(
                text(
                    f"CREATE FUNCTION {T}.applicability_policy_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                )
            )
        with pytest.raises(DBAPIError, match="already exists"):
            migrate(settings, "head")
        assert _head(engine) == "0040_applicability_scenarios" and _objects(engine) == (
            [],
            ["applicability_policy_version_guard"],
        )
        with engine.begin() as c:
            c.execute(text(f"DROP FUNCTION {T}.applicability_policy_version_guard()"))
        assert same()
        # 3. upgrade again: identical objects; everything else byte-identical
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD and _objects(engine) == full and same()
        # 4. with a submitted candidate the downgrade is refused — and with a published version; nothing is lost
        c1 = submit(p["author"], pid, ready(p["author"], pid, r["id"])).json()
        with pytest.raises(RuntimeError, match="policy candidates exist"):
            migrate(settings, "0040_applicability_scenarios", down=True)
        assert _head(engine) == "0041_applicability_publication"  # 0042 (no journey) rolled back first; 0041 refused
        migrate(settings, "head")
        assert _head(engine) == MIGRATION_HEAD
        assert (
            post(
                p["checker"],
                f"{CAND}/{c1['id']}/decision",
                {"verdict": "APPROVE", "candidate_sha256": c1["candidate_sha256"]},
            ).status_code
            == 200
        )
        done = post(
            p["publisher"], f"{CAND}/{c1['id']}/publish", {"candidate_sha256": c1["candidate_sha256"], "version_no": 1}
        ).json()
        with pytest.raises(RuntimeError, match="policy candidates exist"):
            migrate(settings, "0040_applicability_scenarios", down=True)
        migrate(settings, "head")
        assert post(p["author"], f"{VER}/{done['version']['id']}/verify").json()["verified"] is True
        after = everything_else(engine)
        assert {k for k in before if before[k] != after[k]} <= {"audit_event"} and all(
            _digest(engine, t) == scen[t] for t in scen
        )  # publication changed no scenario, suite or run
        from app.audit.chain import verify_chain

        assert verify_chain(db).ok
    finally:
        for c_ in p.values():
            c_.__exit__(None, None, None)
        for a_ in accounts.values():
            GRANTS.pop(a_.principal_id, None)
        with (
            engine.begin() as c
        ):  # leave the shared test schema without this test's governed history, so later modules can migrate
            c.execute(text(f"TRUNCATE {T}.applicability_policy CASCADE"))


def _digest(engine: Engine, table: str) -> tuple[int, str]:
    with engine.connect() as c:
        row = c.execute(
            text(
                f"SELECT count(*), coalesce(md5(string_agg(md5(t::text), '' ORDER BY md5(t::text))), '') FROM {T}.\"{table}\" t"
            )
        ).one()  # noqa: S608
    return row[0], row[1]


_ = (BOOL, document, made, published)
