# ruff: noqa: E501, F811
"""UX-HOME-1 — the workspace summary: one READ-ONLY operation. It counts and lists the records as they stand, in the
reader's markets; what "awaits you" obeys the same identity rules and permissions the operations enforce; and it
changes nothing. Real HTTP, real PostgreSQL (``call360_test``)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.support import make_account
from tests.test_survey_api import GRANTS, MARKETS, _client, post, submit
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_lib1 import build, draft, empty_survey, pin_module, publish, survey_app, trio  # noqa: F401

W = "/api/v1/survey-definitions/workspace"
TABLES = (
    "survey_definition",
    "survey_draft",
    "survey_candidate",
    "survey_version",
    "survey_lifecycle_event",
    "audit_event",
)


def rows(db: Session) -> dict[str, int]:
    db.rollback()
    return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() for t in TABLES}  # noqa: S608 — fixed names


def test_the_workspace_counts_what_exists_and_says_what_awaits_each_person(
    trio: Any, survey_app: Any, db: Session
) -> None:
    author, checker, publisher, people = trio
    before = author.get(W).json()
    base = before["inventory"]["surveys"]["total"]

    # ---- two surveys; the second pins the first's published module, so that module is reused
    a_sid, a_code, _ = build(author, "K3", "Workspace source")
    publish(trio, a_sid)
    b_sid, b_code = empty_survey(author, "Workspace consumer")
    assert pin_module(author, b_sid, draft(author, a_sid)).status_code == 200
    cand = submit(author, b_sid, "for the workspace test").json()

    w = author.get(W).json()
    inv = w["inventory"]
    assert (inv["surveys"]["total"], inv["surveys"]["in_review"]) == (
        base + 2,
        before["inventory"]["surveys"]["in_review"] + 1,
    )
    assert inv["surveys"]["with_a_published_version"] + inv["surveys"]["never_published"] == inv["surveys"]["total"]
    listed = author.get("/api/v1/survey-definitions").json()["items"]
    assert inv["surveys"]["total"] == len(listed)  # the same surveys the list shows
    for kind in ("MODULE", "ITEM", "CONDITION", "OPTION_SET"):
        items = author.get("/api/v1/survey-components", params={"kind": kind}).json()["items"]
        assert inv["components"][kind]["components"] == len({i["code"] for i in items}), kind  # the library's own count
        assert inv["components"][kind]["pinned_by_more_than_one_survey"] == len(
            {i["code"] for i in items if i["used_by"]["surveys"] > 1}
        )
    assert (
        inv["components"]["ITEM"]["questions"] + inv["components"]["ITEM"]["statements"]
        == inv["components"]["ITEM"]["components"]
    )
    # recency is the records' own time, newest first
    assert w["recent_drafts"][0]["survey_code"] == b_code and w["recent_drafts"][0]["saved_by_you"] is True
    assert [d["saved_at"] for d in w["recent_drafts"]] == sorted(
        (d["saved_at"] for d in w["recent_drafts"]), reverse=True
    )
    assert w["recent_published"][0]["survey_code"] == a_code and w["recent_published"][0]["version_label"] == "1.0"

    # ---- IN REVIEW: it awaits the checker; the author is told who it waits for; the publisher has nothing yet
    def mine(c: Any) -> list[tuple[str, str]]:
        return [(x["survey_code"], x["action"]) for x in c.get(W).json()["awaiting_you"] if x["survey_code"] == b_code]

    assert mine(author) == [] and mine(publisher) == [(b_code, "DECIDE")]  # anyone but the author may review …
    assert mine(checker) == [(b_code, "DECIDE")]
    assert [
        (x["survey_code"], x["waiting_for"])
        for x in author.get(W).json()["waiting_on_others"]
        if x["survey_code"] == b_code
    ] == [(b_code, "A_REVIEWER")]
    # … but only with the permission the operation needs: the same person without it is told nothing awaits them
    GRANTS[people[1].principal_id] = GRANTS[people[1].principal_id] - {"survey.approve"}
    assert mine(checker) == []
    GRANTS[people[1].principal_id] = GRANTS[people[1].principal_id] | {"survey.approve"}

    # ---- APPROVED: it awaits a publisher who is neither the author nor the approver
    assert post(checker, f"/api/v1/survey-candidates/{cand['id']}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert (mine(author), mine(checker), mine(publisher)) == ([], [], [(b_code, "PUBLISH")])
    assert author.get(W).json()["waiting_on_others"][-1]["waiting_for"] == "A_PUBLISHER"
    assert author.get(W).json()["inventory"]["surveys"]["approved_awaiting_publication"] >= 1

    # ---- PUBLISHED: nothing awaits anyone; the module is now reused, and listed as such
    assert post(publisher, f"/api/v1/survey-candidates/{cand['id']}/publish").status_code == 201
    after = author.get(W).json()
    assert (mine(author), mine(checker), mine(publisher)) == ([], [], [])
    reused = {m["code"]: m["used_by"]["surveys"] for m in after["reused_modules"]}
    module = draft(author, a_sid)["content"]["sequence"][0]["module"]["code"]
    assert reused.get(module) == 2 and all(n > 1 for n in reused.values())  # only what really is pinned by several
    assert after["inventory"]["components"]["MODULE"]["pinned_by_more_than_one_survey"] >= 1

    # ---- it is a read: nothing is written, not even an audit event
    counted = rows(db)
    for c in (author, checker, publisher):
        assert c.get(W).status_code == 200
    assert rows(db) == counted

    # ---- another market sees none of it; without survey.read there is no workspace
    outsider = make_account(db, prefix="wsmy")
    GRANTS[outsider.principal_id] = frozenset({"survey.read", "survey.approve", "survey.publish"})
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    oc = _client(survey_app, outsider)
    other = oc.get(W).json()
    assert (
        other["markets"],
        other["inventory"]["surveys"]["total"],
        other["recent_drafts"],
        other["recent_published"],
        other["awaiting_you"],
        other["reused_modules"],
    ) == (["MY"], 0, [], [], [], [])
    assert all(v["components"] == 0 for v in other["inventory"]["components"].values())
    oc.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)
    nobody = make_account(db, prefix="wsnone")
    GRANTS[nobody.principal_id] = frozenset()
    nc = _client(survey_app, nobody)
    assert nc.get(W).status_code == 403
    nc.__exit__(None, None, None)
    GRANTS.pop(nobody.principal_id)
