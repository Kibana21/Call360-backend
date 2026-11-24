# ruff: noqa: E501 — document literals are kept one per line
"""A TEST FIXTURE survey published in two successive versions, for a browser test of deliberately adopting a newer
published survey version. Through the Survey Studio HTTP API ONLY, by three different signed-in people.

EVERYTHING HERE IS A SYNTHETIC TEST FIXTURE: not approved wording, not a call script, eligible for no customer call.

    uv run python scripts/appl_fixture_survey.py --base-url URL --origin ORIGIN --accounts PATH \
        --author KEY --checker KEY --publisher KEY --version {1,2}

``--version 1`` creates survey ``S-APPL-TEST-ADOPT`` (one module, a yes/no and a single-choice question) and publishes
it as version 1 (label 1.0). If version 1 — or a later one — is already published, nothing is changed.

``--version 2`` makes ONE visible change through the normal authoring operations — a third, free-text question, which
is a new revision of the survey's module (a published revision is frozen and is never changed) — and has it submitted
by the author, approved by the checker and published by the publisher as version 2 (label 2.0). Version 1 stays
readable exactly as it was; the server marks it SUPERSEDED. If version 2 is already published nothing is changed; if
version 1 is not published yet the command fails and says so.

Anything found that is not what this script would have made (other content under the code, another person's draft or
candidate) is reported and left alone, with a non-zero exit. Nothing is deleted. A password is never printed.
The accounts file and the sign-in are those of ``scripts/appl_showcase_setup.py``, whose helpers this script uses.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import appl_showcase_setup as showcase  # noqa: E402

CODE = "S-APPL-TEST-ADOPT"
NAME = "Applicability test fixture · adopt a newer version (synthetic)"
BANNER = "SYNTHETIC TEST FIXTURE — NOT APPROVED FOR CUSTOMER CALLS."
PURPOSE = f"{BANNER} One survey in two successive published versions, for a browser test of adopting a newer version."
Q = " (synthetic test fixture question)"
MODULE = "@M:adopt.main"
INSTANCE = "mi-adopt"
NEW_ITEM = "@Q:adopt.comment"
OK_STATES = ("CREATED_AND_PUBLISHED", "CONTINUED_AND_PUBLISHED", "ALREADY_PUBLISHED_UNCHANGED")

Doc = dict[str, Any]
_done: Doc = {"outcome": "COMPLETED"}


def _blueprint(version: int) -> showcase.Blueprint:
    """The survey as version 1, or as version 2: the same two questions, and in version 2 a third one — so the module
    is revision 2 under the SAME code, and the content pins that revision."""
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", showcase._yes_no("@OS:adopt.yes_no")),  # noqa: SLF001
        (
            "OPTION_SET",
            showcase._option_set(  # noqa: SLF001
                "@OS:adopt.times", [("MORNING", "In the morning"), ("AFTERNOON", "In the afternoon"), ("EVENING", "In the evening")]
            ),
        ),
        ("ITEM", showcase._item("@Q:adopt.heard", "YES_NO", "Whether the person can hear the fixture clearly", option_set={"code": "@OS:adopt.yes_no", "version": 1})),  # noqa: SLF001
        ("ITEM", showcase._item("@Q:adopt.time", "SINGLE_SELECT", "Which time of day the person prefers", option_set={"code": "@OS:adopt.times", "version": 1})),  # noqa: SLF001
        ("WORDING", showcase._wording("@Q:adopt.heard", "Can you hear this test fixture clearly?" + Q)),  # noqa: SLF001
        ("WORDING", showcase._wording("@Q:adopt.time", "Which time of day do you prefer for a test?" + Q)),  # noqa: SLF001
    ]  # fmt: skip
    nodes = [showcase._node("n1", "@Q:adopt.heard"), showcase._node("n2", "@Q:adopt.time")]  # noqa: SLF001
    routes: list[tuple[str, str, Doc]] = [("n1", "ANY", {"node": "n2"})]
    if version == 1:
        routes.append(("n2", "ANY", _done))
    else:
        assets += [
            ("ITEM", showcase._item(NEW_ITEM, "FREE_TEXT", "Anything the person wants to add (added in version 2)", text_rule=dict(showcase.TEXT_RULE))),  # noqa: SLF001
            ("WORDING", showcase._wording(NEW_ITEM, "Is there anything you would like to add? This question is new in version 2." + Q)),  # noqa: SLF001
        ]  # fmt: skip
        nodes.append(showcase._node("n3", NEW_ITEM))  # noqa: SLF001
        routes += [("n2", "ANY", {"node": "n3"}), ("n3", "AFTER_CAPTURE", _done)]
    module = showcase._module(  # noqa: SLF001
        MODULE,
        "Adoption fixture questions (synthetic)",
        f"{BANNER} Two questions in version 1; a third is added in version 2.",
        ("COMPLETED",),
        nodes,
        showcase._edges(*routes),  # noqa: SLF001
    )
    module["revision"] = version
    assets.append(("MODULE", module))
    content = {
        "schema": "call360.survey.content/1",
        "code": CODE,
        "sequence": [
            {
                "instance": INSTANCE,
                "module": {"code": MODULE, "revision": version},
                "routes": {"COMPLETED": "@CONTINUE"},
            }
        ],
    }
    return showcase.Blueprint(f"ADOPT-V{version}", "SURVEY", CODE, NAME, PURPOSE, tuple(assets), content)


def _intended(version: int) -> str:
    b = _blueprint(version)
    return showcase.blueprint_sha256(b.content, showcase.index_of(b.assets))


def _fingerprint(documents: Mapping[str, Any]) -> str:
    """Of a draft-documents or candidate-documents response: independent of the codes the server issued."""
    return showcase.blueprint_sha256(documents["content"], showcase.index_of_api(documents["assets"]))


def _versions(run: showcase._Run, definition_id: str) -> list[Doc]:
    """Every published version of the survey, oldest first, read back from the server."""
    hist = showcase.api_get(run.author, f"/survey-definitions/{definition_id}/history")
    out = []
    for v in hist["versions"]:
        record = showcase._published_record(run, v["id"], v["candidate_id"], _blueprint(1))  # noqa: SLF001
        record.pop("_content")
        out.append(record)
    return out


def _result(run: showcase._Run, state: str, detail: str, definition_id: str | None) -> Doc:
    return {
        "fixture": NAME, "banner": BANNER, "code": CODE, "definition_id": definition_id, "state": state,
        "detail": detail, "ok": state in OK_STATES,
        "people": {role: who.username for role, who in run.people.items()},
        "versions": _versions(run, definition_id) if definition_id else [],
    }  # fmt: skip


def _second_version(run: showcase._Run, row: Mapping[str, Any], hist: Mapping[str, Any]) -> tuple[str, str]:
    """From version 1 published and nothing else, to version 2 published. Returns (state, detail); anything that is not
    this script's own unfinished work is a conflict and is not touched."""
    sid, author = row["id"], run.people["author"]
    two = _blueprint(2)
    wanted = _intended(2)
    first = hist["versions"][0]
    open_ones = [c for c in hist["candidates"] if c["status"] in showcase.OPEN_CANDIDATE]
    closed = [
        c for c in hist["candidates"] if c["id"] != first["candidate_id"] and c["status"] not in showcase.OPEN_CANDIDATE
    ]
    if closed:
        listed = ", ".join(f"candidate {c['n']} {c['status']}" for c in closed)
        return "CONFLICT", f"version 2 is not published and the survey has other candidates ({listed})"
    state = "CREATED_AND_PUBLISHED"
    if open_ones:
        cand = showcase.api_get(run.author, f"/survey-candidates/{open_ones[-1]['id']}/documents")
        if _fingerprint(cand) != wanted or cand["submitted_by"]["ref"] != author.principal_id:
            return "CONFLICT", f"candidate {cand['n']} is {cand['status']} and is not this fixture's version 2"
        candidate_id, status, state = str(cand["id"]), str(cand["status"]), "CONTINUED_AND_PUBLISHED"
    else:
        draft = showcase.api_get(run.author, f"/survey-definitions/{sid}/draft/documents")
        if draft["content_sha256"] == first["content_sha256"]:  # the draft is still exactly version 1: make the change
            one = _blueprint(1)
            position_of, _ = showcase.walk(one.content, showcase.index_of(one.assets))  # logical code → position
            actual_at = {
                p: c for c, p in showcase.walk(draft["content"], showcase.index_of_api(draft["assets"]))[0].items()
            }
            names = {logical: actual_at[position] for logical, position in position_of.items()}
            issued = showcase.api_post(
                run.author, f"/survey-definitions/{sid}/codes", {"requests": [{"kind": "ITEM", "count": 1}]}
            )
            names[NEW_ITEM] = issued["codes"][0]["code"]
            added = [
                (k, d)
                for k, d in two.assets
                if (k == "MODULE") or (k in ("ITEM", "WORDING") and NEW_ITEM in (d.get("code"), d.get("item")))
            ]
            operations: list[Doc] = [
                {"op": "PUT_ASSET", "kind": k, "document": showcase._replace(copy.deepcopy(d), names)}  # noqa: SLF001
                for k, d in sorted(added, key=lambda a: showcase.PUT_ORDER.index(a[0]))
            ]
            operations.append({"op": "SET_CONTENT", "content": showcase._replace(copy.deepcopy(two.content), names)})  # noqa: SLF001
            draft = showcase.api_post(
                run.author,
                f"/survey-definitions/{sid}/draft/save",
                {"expected_revision": draft["revision"], "operations": operations},
            )
            if _fingerprint(draft) != wanted:
                raise showcase.ShowcaseError("the saved draft is not this fixture's version 2; nothing was submitted")
        elif _fingerprint(draft) == wanted and draft.get("updated_by") == author.display_name:
            state = "CONTINUED_AND_PUBLISHED"
        else:
            return (
                "CONFLICT",
                f"the working draft (revision {draft['revision']}) is neither version 1 nor this fixture's version 2",
            )
        candidate_id, status = showcase._submit(run, row), "IN_REVIEW"  # noqa: SLF001
    showcase._govern(run, two, row, candidate_id, status)  # noqa: SLF001
    return state, "version 2 published; version 1 is unchanged and superseded"


def run(author: httpx.Client, checker: httpx.Client, publisher: httpx.Client, version: int) -> Doc:
    """Bring the fixture survey to published version 1 or 2 with three SIGNED-IN clients. ``result["ok"]`` is true only
    when that version is published as defined here."""
    if version not in (1, 2):
        raise showcase.ShowcaseError("the fixture has versions 1 and 2")
    people = {
        "author": showcase.whoami(author),
        "checker": showcase.whoami(checker),
        "publisher": showcase.whoami(publisher),
    }
    if len({p.principal_id for p in people.values()}) != 3:
        raise showcase.ShowcaseError("the author, the checker and the publisher must be three different people")
    state = showcase._Run(author, checker, publisher, people, False, None, showcase.blueprints()[0])  # noqa: SLF001
    try:
        rows = [s for s in showcase.api_get(author, "/survey-definitions")["items"] if s["code"] == CODE]
        row = rows[0] if rows else None
        hist = (
            showcase.api_get(author, f"/survey-definitions/{row['id']}/history")
            if row
            else {"versions": [], "candidates": []}
        )
        published = hist["versions"]
        if not published:
            if version == 2:
                return _result(
                    state,
                    "VERSION_1_NOT_PUBLISHED",
                    "version 1 is not published yet: run --version 1 first",
                    row["id"] if row else None,
                )
            made = showcase._ensure(state, _blueprint(1), None)  # noqa: SLF001 — create, or continue this script's own unfinished run
            return _result(state, made["state"], made.get("detail", ""), made.get("definition_id"))
        assert row is not None
        fingerprints = []
        for v in published[:2]:
            fingerprints.append(
                _fingerprint(showcase.api_get(author, f"/survey-candidates/{v['candidate_id']}/documents"))
            )
        if fingerprints[0] != _intended(1) or (row["name"], row["purpose"]) != (NAME, PURPOSE):
            return _result(
                state,
                "CONFLICT",
                "the survey with this code is not this fixture (version 1 differs); nothing was changed",
                row["id"],
            )
        if len(published) >= 2 and fingerprints[1] != _intended(2):
            return _result(
                state,
                "CONFLICT",
                "version 2 exists and is not this fixture's version 2; nothing was changed",
                row["id"],
            )
        if len(published) >= version:
            return _result(
                state,
                "ALREADY_PUBLISHED_UNCHANGED",
                f"version {version} is already published ({len(published)} version(s) exist); nothing was changed",
                row["id"],
            )
        outcome, detail = _second_version(state, row, hist)
        return _result(state, outcome, detail, row["id"])
    except (showcase.ApiError, showcase.ShowcaseError) as exc:
        return _result(state, "FAILED", str(exc), None) | {"versions": []}


def render(result: Mapping[str, Any]) -> str:
    lines = [
        f"{result['fixture']}",
        result["banner"],
        f"[{result['state']}] {result['code']} — {result['detail']}",
        f"    definition id {result['definition_id']}",
    ]
    for v in result["versions"]:
        lines += [
            f"    version_no {v['version_no']}  label {v['version_label']}  status {v['version_status']}  id {v['version_id']}",
            f"        content sha256   {v['content_sha256']}",
            f"        manifest sha256  {v['manifest_sha256']}",
            f"        authored by {v['authored_by']} · approved by {v['approved_by']} · published by {v['published_by']}",
        ]
    lines.append("RESULT: " + ("OK" if result["ok"] else "NOT OK — see above"))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--accounts", required=True, type=Path, help="JSON file of names to passwords or to objects")
    parser.add_argument("--author", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--version", required=True, type=int, choices=(1, 2))
    args = parser.parse_args(argv)
    clients: list[httpx.Client] = []
    try:
        accounts = json.loads(args.accounts.read_text())
        if not isinstance(accounts, dict):
            raise showcase.ShowcaseError("the accounts file is not a JSON object")
        for role in ("author", "checker", "publisher"):
            username, password = showcase.credentials(accounts, getattr(args, role))
            client = showcase.make_client(args.base_url, args.origin)
            clients.append(client)
            try:
                showcase.sign_in(client, username, password)
            except showcase.ApiError as exc:
                raise showcase.ShowcaseError(
                    f"could not sign in the {role} ({username}): {exc.status} {exc.code}"
                ) from None
        result = run(clients[0], clients[1], clients[2], args.version)
    except (showcase.ShowcaseError, showcase.ApiError, OSError, ValueError, httpx.HTTPError) as exc:
        print(f"appl_fixture_survey: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        for client in clients:
            client.close()
    print(render(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
