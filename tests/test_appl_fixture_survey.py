# ruff: noqa: E501 — long assertions are kept on one line each
"""The two-version TEST FIXTURE survey (scripts/appl_fixture_survey.py), run against the in-process application on the
isolated TEST schema. Synthetic content only. The three people hold what the development identities hold."""

from __future__ import annotations

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
from scripts import appl_fixture_survey as fixture
from scripts import appl_showcase_setup as showcase
from tests.support import ORIGIN, PASSWORD, Account, make_account
from tests.test_survey_api import GRANTS, _client, with_grants

HEX64 = re.compile(r"[0-9a-f]{64}")
ROLES = {
    "author": frozenset({"survey.read", "survey.edit"}),
    "checker": frozenset({"survey.read", "survey.approve"}),
    "publisher": frozenset({"survey.read", "survey.publish"}),
}
TABLES = (
    "survey_definition", "survey_draft", "survey_asset_version", "survey_candidate", "survey_version",
    "survey_lifecycle_event", "survey_asset_usage", "survey_issued_code", "audit_event",
)  # fmt: skip


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(
        settings.model_copy(
            update={"survey_definitions_enabled": True, "survey_library_enabled": True, "transcription_worker": False}
        )
    )
    with_grants(app)
    return app


@pytest.fixture()
def trio(survey_app: Any, db: Session) -> Iterator[tuple[dict[str, TestClient], dict[str, Account]]]:
    people = {role: make_account(db, prefix=f"adopt{role}") for role in ROLES}
    for role, person in people.items():
        GRANTS[person.principal_id] = ROLES[role]
    clients = {role: _client(survey_app, person) for role, person in people.items()}
    yield clients, people
    for c in clients.values():
        c.__exit__(None, None, None)
    for person in people.values():
        GRANTS.pop(person.principal_id, None)


def counts(db: Session, tables: tuple[str, ...] = TABLES) -> dict[str, int]:
    db.rollback()
    return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in tables}


def go(clients: dict[str, TestClient], version: int) -> dict[str, Any]:
    return fixture.run(clients["author"], clients["checker"], clients["publisher"], version)


def listed(c: TestClient) -> dict[str, Any]:
    return next(s for s in c.get("/api/v1/survey-definitions").json()["items"] if s["code"] == fixture.CODE)


class _Kept(TestClient):
    def close(self) -> None:
        return None


def test_two_successive_versions_are_published_and_the_first_stays_as_it_was(
    trio: Any,
    survey_app: Any,
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    clients, people = trio
    author = clients["author"]
    names = {role: p.username for role, p in people.items()}

    # version 2 before version 1: refused, and nothing is created
    before = counts(db)
    early = go(clients, 2)
    assert (early["ok"], early["state"]) == (False, "VERSION_1_NOT_PUBLISHED") and "run --version 1 first" in early[
        "detail"
    ]
    assert counts(db) == before

    # ---- version 1
    one = go(clients, 1)
    assert (one["ok"], one["state"], len(one["versions"])) == (True, "CREATED_AND_PUBLISHED", 1), one
    v1 = one["versions"][0]
    assert (v1["version_no"], v1["version_label"], v1["version_status"]) == (1, "1.0", "PUBLISHED")
    row1 = listed(author)
    assert (row1["latest_version_id"], row1["latest_version_label"], row1["open_candidate_id"]) == (
        v1["version_id"],
        "1.0",
        None,
    )
    assert row1["name"] == fixture.NAME and row1["purpose"].startswith(
        "SYNTHETIC TEST FIXTURE — NOT APPROVED FOR CUSTOMER CALLS."
    )
    before = counts(db)
    again = go(clients, 1)
    assert (again["state"], again["versions"]) == ("ALREADY_PUBLISHED_UNCHANGED", one["versions"]) and counts(
        db
    ) == before
    v1_get = author.get(f"/api/v1/survey-versions/{v1['version_id']}").json()
    v1_content = author.get(f"/api/v1/survey-versions/{v1['version_id']}/content").json()
    v1_docs = author.get(f"/api/v1/survey-candidates/{v1['candidate_id']}/documents").json()

    # ---- version 2
    two = go(clients, 2)
    assert (two["ok"], two["state"], len(two["versions"])) == (True, "CREATED_AND_PUBLISHED", 2), two
    old, v2 = two["versions"]
    assert (v2["version_no"], v2["version_label"], v2["version_status"]) == (2, "2.0", "PUBLISHED")
    row2 = listed(author)
    assert row2["id"] == row1["id"] and row2["latest_version_id"] == v2["version_id"] != v1["version_id"]
    assert (row2["latest_version_label"], row2["open_candidate_id"], row2["open_candidate_status"]) == (
        "2.0",
        None,
        None,
    )
    assert {k for k in row1 if row1[k] != row2[k]} == {"latest_version_id", "latest_version_label", "draft_revision"}

    # version 1: still readable, exactly as it was — only its status says it is no longer the current one
    assert (old["version_id"], old["version_status"]) == (v1["version_id"], "SUPERSEDED")
    after = author.get(f"/api/v1/survey-versions/{v1['version_id']}").json()
    assert after["status"] == "SUPERSEDED" and v1_get["status"] == "PUBLISHED"
    assert {k for k in after if after[k] != v1_get[k]} == {"status", "history"}
    assert [h["event"] for h in after["history"]] == ["PUBLISHED", "SUPERSEDED"]
    assert (after["content_sha256"], after["manifest_sha256"], after["label"], after["version_no"]) == (
        v1["content_sha256"],
        v1["manifest_sha256"],
        "1.0",
        1,
    )
    assert author.get(f"/api/v1/survey-versions/{v1['version_id']}/content").json() == v1_content
    docs_after = author.get(f"/api/v1/survey-candidates/{v1['candidate_id']}/documents").json()
    assert (docs_after["status"], v1_docs["status"]) == ("PUBLISHED", "PUBLISHED")  # the CANDIDATE keeps PUBLISHED
    assert (docs_after["content"], docs_after["assets"], docs_after["manifest_intact"]) == (
        v1_docs["content"],
        v1_docs["assets"],
        True,
    )

    # both versions' documents are readable, and they differ by exactly the one change
    v2_docs = author.get(f"/api/v1/survey-candidates/{v2['candidate_id']}/documents").json()
    assert (
        v2_docs["manifest_intact"] is True
        and v2_docs["version_label"] == "2.0"
        and docs_after["version_label"] == "1.0"
    )
    for v in (old, v2):
        assert HEX64.fullmatch(v["content_sha256"]) and HEX64.fullmatch(v["manifest_sha256"])
    assert v2["content_sha256"] != old["content_sha256"] and v2["manifest_sha256"] != old["manifest_sha256"]
    module_code = v1_docs["content"]["sequence"][0]["module"]["code"]
    assert v1_docs["content"]["sequence"][0]["module"] == {"code": module_code, "revision": 1}
    assert v2_docs["content"]["sequence"][0]["module"] == {
        "code": module_code,
        "revision": 2,
    }  # the same module, a new revision
    questions = lambda d: [s for m in d["structure"] for s in m["steps"]]  # noqa: E731
    assert [s["answer_type"] for s in questions(old)] == ["YES_NO", "SINGLE_SELECT"]
    assert [s["answer_type"] for s in questions(v2)] == ["YES_NO", "SINGLE_SELECT", "FREE_TEXT"]
    assert [s["item"] for s in questions(v2)][:2] == [s["item"] for s in questions(old)]
    assert all("synthetic test fixture" in s["text"] for s in questions(v2))
    keys = lambda d: {(a["kind"], a["code"], a["version"]): a["sha256"] for a in d["assets"]}  # noqa: E731
    shared_assets = set(keys(v1_docs)) & set(keys(v2_docs))
    assert len(shared_assets) == 6 and all(
        keys(v1_docs)[k] == keys(v2_docs)[k] for k in shared_assets
    )  # what did not change is the SAME frozen version
    assert sorted(k[0] for k in set(keys(v2_docs)) - shared_assets) == ["ITEM", "MODULE", "WORDING"]

    # three different people acted, on both versions
    db.rollback()
    for v in (old, v2):
        assert (v["authored_by"], v["approved_by"], v["published_by"]) == (
            names["author"],
            names["checker"],
            names["publisher"],
        )
        events = db.execute(
            text("SELECT event, actor_ref FROM survey_lifecycle_event WHERE subject_id = :c ORDER BY seq"),
            {"c": v["candidate_id"]},
        ).all()
        assert [e for e, _ in events] == ["SUBMITTED", "APPROVED", "PUBLISHED"]
        assert [a for _, a in events] == [str(people[r].principal_id) for r in ("author", "checker", "publisher")]
    history = author.get(f"/api/v1/survey-definitions/{row2['id']}/history").json()
    assert [(v["version_no"], v["label"], v["status"]) for v in history["versions"]] == [
        (1, "1.0", "SUPERSEDED"),
        (2, "2.0", "PUBLISHED"),
    ]
    assert [c["status"] for c in history["candidates"]] == ["PUBLISHED", "PUBLISHED"]

    # running either step again changes no row
    before = counts(db)
    for version in (2, 1, 2):
        again = go(clients, version)
        assert (again["ok"], again["state"], again["versions"]) == (
            True,
            "ALREADY_PUBLISHED_UNCHANGED",
            two["versions"],
        )
    assert counts(db) == before

    # the command: the same result, and no password in what it prints (its sign-ins are audited, rightly)
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
                names["author"]: PASSWORD,
                "c": {"username": names["checker"], "password": PASSWORD},
                "p": {"username": names["publisher"], "password": PASSWORD},
            }
        )
    )
    base = [
        "--base-url",
        ORIGIN,
        "--origin",
        ORIGIN,
        "--accounts",
        str(accounts),
        "--author",
        names["author"],
        "--checker",
        "c",
        "--publisher",
        "p",
    ]
    governed = tuple(t for t in TABLES if t != "audit_event")
    before = counts(db, governed)
    try:
        assert fixture.main([*base, "--version", "2"]) == 0 and fixture.main([*base, "--version", "1"]) == 0
        with pytest.raises(SystemExit):
            fixture.main(base)  # --version is required
    finally:
        for c in opened:
            c.__exit__(None, None, None)
    assert counts(db, governed) == before
    out = capsys.readouterr().out
    assert PASSWORD not in out and fixture.CODE in out and "RESULT: OK" in out
    for v in (old, v2):
        assert all(str(v[k]) in out for k in ("version_id", "version_label", "content_sha256", "manifest_sha256"))
    assert "status SUPERSEDED" in out and "status PUBLISHED" in out
