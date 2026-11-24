# ruff: noqa: E501 — long request literals and assertions are kept on one line each
"""The Applicability Showcase (scripts/appl_showcase_setup.py), run against the in-process application on the isolated
TEST schema. Synthetic demonstration content only.

The three people hold what the DEVELOPMENT identities hold — the author reads, edits and simulates; the checker reads
and approves; the publisher reads and publishes — so the script is shown to need nothing more. Where a test tries
something the identity rules forbid, the person is given every permission for that one attempt, so that only the rule
can refuse them."""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.main import create_app
from scripts import appl_showcase_setup as showcase
from tests.support import ORIGIN, PASSWORD, Account, make_account
from tests.test_survey_api import ALL, GRANTS, _client, post, with_grants

HEX64 = re.compile(r"[0-9a-f]{64}")
ROLES = {
    "author": frozenset({"survey.read", "survey.edit", "survey.simulate"}),
    "checker": frozenset({"survey.read", "survey.approve"}),
    "publisher": frozenset({"survey.read", "survey.publish"}),
}
SURVEY_TABLES = (
    "survey_definition", "survey_draft", "survey_asset_version", "survey_candidate", "survey_version",
    "survey_lifecycle_event", "survey_asset_usage", "survey_issued_code", "survey_simulation", "survey_call_plan",
    "audit_event",
)  # fmt: skip
UNTOUCHED = (
    "callback_case", "script_assignment", "survey_assignment_binding", "survey_assignment_group",
    "script_assignment_rule_version",
)  # fmt: skip
CODES = (
    "S-APPL-DEMO-ILP", "S-APPL-DEMO-NFTF", "S-APPL-DEMO-COMBINED", "S-APPL-DEMO-REPLACEMENT", "S-APPL-DEMO-RIDER",
)  # fmt: skip

W_YES = {"mi-welcome/n2": {"choice": "YES"}}
#: per survey: (label, answers by question instance, expected ending, a question only this path asks or None)
PATHS: dict[str, list[tuple[str, dict[str, dict[str, Any]], str, str | None]]] = {
    "S-APPL-DEMO-ILP": [
        (
            "explained",
            {
                **W_YES,
                "mi-ilp-understanding/n1": {"text": "synthetic answer"},
                "mi-ilp-understanding/n2": {"choice": "YES"},
            },
            "COMPLETED",
            None,
        ),
        (
            "explain again",
            {
                **W_YES,
                "mi-ilp-understanding/n1": {"text": "synthetic answer"},
                "mi-ilp-understanding/n2": {"choice": "NO"},
                "mi-ilp-understanding/n3": {"choice": "CHARGES"},
            },
            "COMPLETED",
            "mi-ilp-understanding/n3",
        ),
        (
            "does not remember",
            {"mi-welcome/n2": {"choice": "NO"}, "mi-welcome/n3": {"text": "synthetic answer"}},
            "CLARIFICATION_REQUIRED",
            "mi-welcome/n3",
        ),
    ],
    "S-APPL-DEMO-NFTF": [
        (
            "video",
            {
                **W_YES,
                "mi-nftf-additional/n1": {"choice": "VIDEO"},
                "mi-nftf-additional/n2": {"choice": "YES"},
                "mi-nftf-additional/n3": {"choices": ["SUMMARY", "APPLICATION_COPY"]},
            },
            "COMPLETED",
            "mi-nftf-additional/n2",
        ),
        (
            "phone, nothing received",
            {
                **W_YES,
                "mi-nftf-additional/n1": {"choice": "PHONE"},
                "mi-nftf-additional/n3": {"choices": ["NOTHING"]},
                "mi-nftf-additional/n4": {"text": "synthetic answer"},
            },
            "CLARIFICATION_REQUIRED",
            "mi-nftf-additional/n4",
        ),
    ],
    "S-APPL-DEMO-COMBINED": [
        (
            "video used",
            {
                **W_YES,
                "mi-combined-ilp/n1": {"choice": "SAVING"},
                "mi-combined-nftf/n1": {"choices": ["VIDEO", "PHONE"]},
                "mi-combined-nftf/n2": {"choice": "YES"},
            },
            "COMPLETED",
            "mi-combined-nftf/n2",
        ),
        (
            "no video",
            {**W_YES, "mi-combined-ilp/n1": {"choice": "FAMILY"}, "mi-combined-nftf/n1": {"choices": ["PHONE"]}},
            "COMPLETED",
            None,
        ),
        (
            "not sure: the NFTF part is skipped",
            {**W_YES, "mi-combined-ilp/n1": {"choice": "NOT_SURE"}, "mi-combined-ilp/n2": {"text": "synthetic answer"}},
            "COMPLETED",
            "mi-combined-ilp/n2",
        ),
    ],
    "S-APPL-DEMO-REPLACEMENT": [
        ("not a replacement", {**W_YES, "mi-replacement/n1": {"choice": "NO"}}, "COMPLETED", None),
        (
            "a replacement",
            {
                **W_YES,
                "mi-replacement/n1": {"choice": "YES"},
                "mi-replacement/n2": {"choices": ["DIFFERENCES", "COSTS"]},
                "mi-replacement/n3": {"text": "synthetic answer"},
            },
            "COMPLETED",
            "mi-replacement/n3",
        ),
    ],
    "S-APPL-DEMO-RIDER": [
        ("no extra cover", {**W_YES, "mi-rider/n1": {"choice": "NO"}}, "COMPLETED", None),
        (
            "asked for it",
            {**W_YES, "mi-rider/n1": {"choice": "YES"}, "mi-rider/n2": {"choice": "MYSELF"}},
            "COMPLETED",
            "mi-rider/n2",
        ),
        (
            "does not remember",
            {
                **W_YES,
                "mi-rider/n1": {"choice": "YES"},
                "mi-rider/n2": {"choice": "DO_NOT_REMEMBER"},
                "mi-rider/n3": {"text": "synthetic answer"},
            },
            "CLARIFICATION_REQUIRED",
            "mi-rider/n3",
        ),
    ],
}


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


def people_of(db: Session, tag: str) -> dict[str, Account]:
    people = {role: make_account(db, prefix=f"{tag}{role}") for role in ROLES}
    for role, person in people.items():
        GRANTS[person.principal_id] = ROLES[role]
    return people


@pytest.fixture()
def trio(survey_app: Any, db: Session) -> Iterator[tuple[dict[str, TestClient], dict[str, Account]]]:
    people = people_of(db, "show")
    clients = {role: _client(survey_app, person) for role, person in people.items()}
    yield clients, people
    for c in clients.values():
        c.__exit__(None, None, None)
    for person in people.values():
        GRANTS.pop(person.principal_id, None)


def counts(db: Session, tables: tuple[str, ...]) -> dict[str, int]:
    db.rollback()
    return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in tables}


def go(clients: dict[str, TestClient], **kw: Any) -> dict[str, Any]:
    return showcase.run(clients["author"], clients["checker"], clients["publisher"], **kw)


def simulate(c: TestClient, version_id: str, answers: dict[str, dict[str, Any]], label: str) -> dict[str, Any]:
    r = post(c, f"/api/v1/survey-versions/{version_id}/simulations", {"facts": {}, "label": label})
    assert r.status_code == 201, r.text
    s = r.json()
    while s["status"] == "PENDING":
        key = s["run"]["pending"]["key"]
        assert key in answers, f"{label}: no answer was planned for {key}"
        r = post(
            c,
            f"/api/v1/survey-simulations/{s['id']}/inputs",
            {"expected_inputs": len(s["inputs"]), "key": key, "answer": answers[key]},
        )
        assert r.status_code == 200, r.text
        s = r.json()
        assert s["inputs"][-1]["accepted"] is True, s["inputs"][-1]
    return s


# ------------------------------------------------------------------------------------------------- 1 · nothing yet
def test_verify_only_creates_nothing_and_reports_what_is_missing(trio: Any, db: Session) -> None:
    clients, _ = trio
    before = counts(db, SURVEY_TABLES)
    report = go(clients, verify_only=True)
    assert report["ok"] is False and report["mode"] == "VERIFY_ONLY"
    assert [i["state"] for i in (report["module"], *report["surveys"])] == ["MISSING"] * 6
    assert counts(db, SURVEY_TABLES) == before


# -------------------------------------------------------------------- 2 · created, governed, idempotent, simulated
def test_the_showcase_is_published_by_three_people_and_a_second_run_changes_nothing(trio: Any, db: Session) -> None:
    clients, people = trio
    author = clients["author"]
    untouched = counts(db, UNTOUCHED)
    refused: list[tuple[str, str, int, str]] = []

    def attempt(stage: str, who: str, path: str, body: dict[str, Any] | None, everything: bool) -> None:
        person = people[who]
        if everything:  # every permission: only the identity rule can refuse now
            GRANTS[person.principal_id] = ALL
        try:
            r = post(clients[who], path, body)
        finally:
            GRANTS[person.principal_id] = ROLES[who]
        refused.append((stage, who, r.status_code, r.json()["code"]))

    def hook(stage: str, info: dict[str, Any]) -> None:
        cid = info["candidate_id"]
        if stage == "SUBMITTED":  # the author may not approve their own candidate — with or without the permission
            attempt(stage, "author", f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}, False)
            attempt(stage, "author", f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}, True)
        else:  # neither a maker nor the approver may publish
            attempt(stage, "author", f"/api/v1/survey-candidates/{cid}/publish", None, True)
            attempt(stage, "checker", f"/api/v1/survey-candidates/{cid}/publish", None, False)
            attempt(stage, "checker", f"/api/v1/survey-candidates/{cid}/publish", None, True)

    first = go(clients, hook=hook)
    items = [first["module"], *first["surveys"]]
    assert first["ok"] is True, [(i["key"], i["state"], i.get("detail")) for i in items]
    assert [i["state"] for i in items] == ["CREATED_AND_PUBLISHED"] * 6
    assert tuple(s["code"] for s in first["surveys"]) == CODES == showcase.SURVEY_CODES

    # every forbidden attempt was refused: by permission as the development identities stand, by identity otherwise
    assert len(refused) == 6 * 5 and {r[2] for r in refused} == {403}
    assert {(s, w, c) for s, w, _, c in refused} >= {
        ("SUBMITTED", "author", "SELF_REVIEW_DENIED"),
        ("APPROVED", "author", "SELF_PUBLISH_DENIED"),
        ("APPROVED", "checker", "APPROVER_PUBLISH_DENIED"),
    }
    assert sum(c == "SELF_REVIEW_DENIED" for *_, c in refused) == 6
    assert sum(c == "SELF_PUBLISH_DENIED" for *_, c in refused) == 6
    assert sum(c == "APPROVER_PUBLISH_DENIED" for *_, c in refused) == 6

    # three different people acted, on every item — in the report and in the database's own record
    names = {role: person.username for role, person in people.items()}
    assert first["people"] == names and len(set(names.values())) == 3
    db.rollback()
    for i in items:
        assert (i["authored_by"], i["approved_by"], i["published_by"]) == (
            names["author"],
            names["checker"],
            names["publisher"],
        )
        events = db.execute(
            text("SELECT event, actor_ref FROM survey_lifecycle_event WHERE subject_id = :c ORDER BY seq"),
            {"c": i["candidate_id"]},
        ).all()
        assert [e for e, _ in events] == ["SUBMITTED", "APPROVED", "PUBLISHED"]
        assert [a for _, a in events] == [str(people[r].principal_id) for r in ("author", "checker", "publisher")]

    # published, fingerprinted, and exactly the definition in the script
    shared, blueprints = showcase.blueprints()
    for i, blueprint in zip(items, (shared, *blueprints), strict=True):
        assert (i["version_status"], i["version_label"], i["version_no"], i["manifest_intact"]) == (
            "PUBLISHED",
            "1.0",
            1,
            True,
        )
        assert HEX64.fullmatch(i["content_sha256"]) and HEX64.fullmatch(i["manifest_sha256"])
        assert i["blueprint_sha256"] == showcase.intended_sha256(blueprint, shared)
        v = author.get(f"/api/v1/survey-versions/{i['version_id']}").json()
        assert (v["status"], v["content_sha256"], v["manifest_sha256"]) == (
            "PUBLISHED",
            i["content_sha256"],
            i["manifest_sha256"],
        )
        again = author.get(f"/api/v1/survey-versions/{i['version_id']}/content").json()
        assert (again["content_sha256"], again["manifest_sha256"]) == (i["content_sha256"], i["manifest_sha256"])
    assert len({i["content_sha256"] for i in items}) == 6

    # each survey is listed by the normal listing; the module is a module, never a survey
    listed = {s["code"]: s for s in author.get("/api/v1/survey-definitions").json()["items"]}
    for s in first["surveys"]:
        row = listed[s["code"]]
        assert (row["id"], row["latest_version_id"], row["latest_version_label"], row["open_candidate_id"]) == (
            s["definition_id"],
            s["version_id"],
            "1.0",
            None,
        )
        assert row["name"] == s["name"] and row["purpose"].startswith(
            "SYNTHETIC DEMONSTRATION — NOT APPROVED FOR CUSTOMER CALLS."
        )
        assert row["market_code"] == "SG"
    module = first["module"]
    assert module["code"] not in listed and re.fullmatch(r"M-\d+", module["code"])
    card = next(m for m in author.get("/api/v1/survey-modules").json()["items"] if m["id"] == module["definition_id"])
    assert (card["name"], card["latest_published_revision"], card["unpublished_changes"]) == (
        showcase.MODULE_NAME,
        1,
        False,
    )
    assert card["description"].startswith("SYNTHETIC DEMONSTRATION — NOT APPROVED FOR CUSTOMER CALLS.")

    # the reusable module is pinned at the SAME published revision by every survey
    library = author.get(f"/api/v1/survey-components/MODULE/{module['code']}/1").json()
    assert library["used_by"] == {"surveys": 5, "versions": 5}
    pinned = 0
    for s in first["surveys"]:
        content = author.get(f"/api/v1/survey-versions/{s['version_id']}/content").json()
        entry = next(e for e in content["manifest"] if e["kind"] == "MODULE" and e["code"] == module["code"])
        assert (entry["version"], entry["sha256"]) == (1, library["sha256"])
        assert content["content"]["sequence"][0] == {
            "instance": "mi-welcome", "module": {"code": module["code"], "revision": 1},
            "routes": {"COMPLETED": "@CONTINUE", "CLARIFICATION_REQUIRED": {"survey_outcome": "CLARIFICATION_REQUIRED"}},
        }  # fmt: skip
        pinned += 1
    assert pinned >= 2 and first["reuse"]["module"] == module["code"]
    assert sorted(p["survey"] for p in first["reuse"]["pinned_by"]) == sorted(CODES)

    # the content: synthetic, labelled, with every answer type and at least one branch per survey
    answer_types: set[str] = set()
    for s in first["surveys"]:
        steps = [st for m in s["structure"] for st in m["steps"]]
        questions = [st for st in steps if st["type"] == "QUESTION"]
        assert 3 <= len(questions) <= 6, (s["code"], len(questions))
        assert all("synthetic demonstration" in st["text"] for st in steps if st["type"] != "DECISION")
        assert all(st["delivery_mode"] == "CONTROLLED_TTS" for st in steps if st["type"] != "DECISION")
        assert any(len({b.split(" -> ")[1] for b in st["branches"]}) > 1 for st in steps), s["code"]
        answer_types |= {st["answer_type"] for st in questions}
        assert [m["instance"] for m in s["structure"]][0] == "mi-welcome" and s["structure"][-1][
            "instance"
        ] == "mi-closing"
    assert answer_types == {"YES_NO", "SINGLE_SELECT", "MULTI_SELECT", "FREE_TEXT"}

    # a second run, and a verification, change nothing at all
    before = counts(db, SURVEY_TABLES)
    second = go(clients)
    verified = go(clients, verify_only=True)
    assert counts(db, SURVEY_TABLES) == before
    for report in (second, verified):
        again_items = [report["module"], *report["surveys"]]
        assert report["ok"] is True and [i["state"] for i in again_items] == ["ALREADY_PUBLISHED_REUSED"] * 6
        for a, b in zip(items, again_items, strict=True):
            for k in (
                "definition_id",
                "code",
                "version_id",
                "candidate_id",
                "content_sha256",
                "manifest_sha256",
                "blueprint_sha256",
                "authored_by",
                "approved_by",
                "published_by",
                "structure",
            ):
                assert a[k] == b[k], (a["key"], k)
    assert "ALREADY_PUBLISHED_REUSED" in showcase.render(second) and "RESULT: OK" in showcase.render(second)

    # every survey runs to its end along different answer paths, which take different branches
    for s in first["surveys"]:
        seen: set[tuple[str, ...]] = set()
        for label, answers, ending, only_here in PATHS[s["code"]]:
            sim = simulate(author, s["version_id"], answers, f"showcase test · {label}")
            assert (sim["record_class"], sim["status"]) == ("SIMULATION", "TERMINAL"), (s["code"], label)
            assert sim["run"]["terminal"]["survey_outcome"] == ending, (s["code"], label, sim["run"]["terminal"])
            assert sorted(sim["run"]["asked"]) == sorted(answers), (s["code"], label)
            if only_here:
                others = [a for other, a, _, _ in PATHS[s["code"]] if other != label]
                assert only_here in sim["run"]["asked"] and any(only_here not in a for a in others)
            seen.add(tuple(sim["run"]["edges"]))
        assert len(seen) == len(PATHS[s["code"]]) >= 2, s["code"]
    # the route between modules: one ending of the ILP part skips the NFTF part and still reaches the closing
    combined = next(s for s in first["surveys"] if s["code"] == "S-APPL-DEMO-COMBINED")
    label, answers, _, _ = PATHS["S-APPL-DEMO-COMBINED"][2]
    skipped = {
        m["instance"]: m["status"] for m in simulate(author, combined["version_id"], answers, label)["run"]["modules"]
    }
    assert skipped["mi-combined-nftf"] == "SKIPPED_BY_ROUTE" and skipped["mi-closing"] == "ACTIVATED"

    # nothing operational, and no assignment of any kind, came into being
    assert counts(db, UNTOUCHED) == untouched


# ------------------------------------------------------------------------------- 3 · what is never done silently
def test_an_unfinished_run_is_continued_and_anything_else_is_left_alone(
    trio: Any, survey_app: Any, db: Session
) -> None:
    clients, people = trio
    author = clients["author"]
    report = go(clients)  # the showcase itself: created here, or reused when the test above made it
    assert report["ok"] is True
    shared, blueprints = showcase.blueprints()
    ids = {role: showcase.whoami(c) for role, c in clients.items()}
    run = showcase._Run(
        clients["author"], clients["checker"], clients["publisher"], ids, False, None, shared, report["module"]["code"]
    )  # noqa: SLF001

    def variant(code: str, **changes: Any) -> showcase.Blueprint:
        base = blueprints[4]  # the rider survey, under a code of this test's own
        return dataclasses.replace(base, code=code, content={**base.content, "code": code}, **changes)

    def ensure(blueprint: showcase.Blueprint, verify_only: bool = False) -> dict[str, Any]:
        return showcase._ensure(dataclasses.replace(run, verify_only=verify_only), blueprint, None)  # noqa: SLF001

    # interrupted after the survey was created: continued
    a = variant("S-APPL-TEST-EMPTY")
    made = post(author, "/api/v1/survey-definitions", {"code": a.code, "name": a.name, "purpose": a.purpose}).json()
    assert ensure(a, verify_only=True)["state"] == "NOT_PUBLISHED"
    done = ensure(a)
    assert (done["state"], done["definition_id"], done["version_label"]) == (
        "CONTINUED_AND_PUBLISHED",
        made["id"],
        "1.0",
    )

    # interrupted after the author submitted: continued from the review, by the other two people
    b = variant("S-APPL-TEST-REVIEW")
    row = showcase._create(run, b)  # noqa: SLF001
    showcase._fill(run, b, row)  # noqa: SLF001
    saved = ensure(b, verify_only=True)
    assert (saved["state"], saved["detail"]) == ("NOT_PUBLISHED", "exists but is not published (SAVED_DRAFT)")
    cid = showcase._submit(run, row)  # noqa: SLF001
    done = ensure(b)
    assert (done["state"], done["candidate_id"], done["approved_by"], done["published_by"]) == (
        "CONTINUED_AND_PUBLISHED", cid, people["checker"].username, people["publisher"].username,
    )  # fmt: skip
    assert ensure(b)["state"] == "ALREADY_PUBLISHED_REUSED"

    # the same code published with OTHER details or content: reported, never overwritten, no new version
    before = counts(db, SURVEY_TABLES)
    for changed in (
        variant("S-APPL-TEST-REVIEW", name="Another name for the same survey (synthetic)"),
        dataclasses.replace(
            blueprints[3], code="S-APPL-TEST-REVIEW", content={**blueprints[3].content, "code": "S-APPL-TEST-REVIEW"}
        ),
    ):
        got = ensure(changed)
        assert got["state"] == "CONFLICT" and "differs from the showcase definition" in got["detail"], got
        assert got["version_id"] == done["version_id"]
    assert counts(db, SURVEY_TABLES) == before

    # a draft another person started under one of the codes: left exactly as it is
    other = make_account(db, prefix="showother")
    GRANTS[other.principal_id] = frozenset({"survey.read", "survey.edit"})
    c = _client(survey_app, other)
    try:
        d = variant("S-APPL-TEST-OTHER")
        assert (
            post(c, "/api/v1/survey-definitions", {"code": d.code, "name": d.name, "purpose": d.purpose}).status_code
            == 201
        )
        before = counts(db, SURVEY_TABLES)
        got = ensure(d)
        assert got["state"] == "CONFLICT" and "someone other than the author" in got["detail"]
        assert counts(db, SURVEY_TABLES) == before
    finally:
        c.__exit__(None, None, None)
        GRANTS.pop(other.principal_id, None)

    # one person cannot play two parts
    with pytest.raises(showcase.ShowcaseError, match="three different people"):
        showcase.run(clients["author"], clients["author"], clients["publisher"])


# ------------------------------------------------------------------------------------------------------ 4 · the CLI
class _Kept(TestClient):
    """The command closes its clients; the test owns the application's lifespan."""

    def close(self) -> None:
        return None


def test_the_command_signs_in_from_either_accounts_shape_and_never_prints_a_password(
    survey_app: Any, db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    people = people_of(db, "cli")
    opened: list[_Kept] = []

    def make_client(base_url: str, origin: str) -> _Kept:
        c = _Kept(survey_app, base_url=base_url, headers={"Origin": origin})
        c.__enter__()
        opened.append(c)
        return c

    monkeypatch.setattr(showcase, "make_client", make_client)
    accounts = tmp_path / "accounts.json"
    accounts.write_text(
        json.dumps(
            {
                people["author"].username: PASSWORD,  # the development file: username -> password
                "survey_checker": {"username": people["checker"].username, "password": PASSWORD, "display_name": "x"},
                "survey_publisher": {"username": people["publisher"].username, "password": PASSWORD},
                "wrong": {"username": people["publisher"].username, "password": "not-the-password"},
            }
        )
    )
    report_path = tmp_path / "report.json"
    base = [
        "--base-url",
        ORIGIN,
        "--origin",
        ORIGIN,
        "--accounts",
        str(accounts),
        "--author",
        people["author"].username,
        "--checker",
        "survey_checker",
    ]
    try:
        assert showcase.main([*base, "--publisher", "survey_publisher", "--report", str(report_path)]) == 0
        report = json.loads(report_path.read_text())
        assert report["ok"] is True and [s["code"] for s in report["surveys"]] == list(CODES)
        assert all(HEX64.fullmatch(i["content_sha256"]) for i in (report["module"], *report["surveys"]))
        governed = tuple(t for t in SURVEY_TABLES if t != "audit_event")  # the three sign-ins are audited, rightly
        before = counts(db, governed)
        assert showcase.main([*base, "--publisher", "survey_publisher", "--verify-only"]) == 0
        assert counts(db, governed) == before
        assert showcase.main([*base, "--publisher", "wrong"]) == 2  # a failed sign-in: no report, no password
        assert showcase.main([*base, "--publisher", "nobody"]) == 2
    finally:
        for c in opened:
            c.__exit__(None, None, None)
        for person in people.values():
            GRANTS.pop(person.principal_id, None)
    out = capsys.readouterr()
    assert (
        "RESULT: OK" in out.out
        and "could not sign in the publisher" in out.err
        and "no entry named 'nobody'" in out.err
    )
    assert PASSWORD not in out.out + out.err + report_path.read_text() and "not-the-password" not in out.out + out.err
