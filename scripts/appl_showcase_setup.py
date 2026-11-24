"""Applicability Showcase — Synthetic Demo: one reusable module and five small surveys, created and published through
the Survey Studio HTTP API ONLY, by three different signed-in people (author, checker, publisher).

EVERYTHING HERE IS SYNTHETIC DEMONSTRATION CONTENT. It is not approved wording, not a call script, and nothing it
creates is eligible for a customer call. No regulatory, consent or suitability wording is written here, and "NFTF" is an
illustrative label that this script does not define.

    uv run python scripts/appl_showcase_setup.py --base-url URL --origin ORIGIN --accounts PATH \
        --author KEY --checker KEY --publisher KEY [--verify-only] [--report PATH]

``--accounts`` is a JSON file mapping a name either to a password (``{"dev.survey.author": "<password>"}`` — the name is
the username) or to an object (``{"survey_author": {"username": ..., "password": ...}}``). A password is never printed.

What it does, for the module and then for each survey:

* looks up what already exists (a survey by its code; the module by its exact name, since a module's code is issued by
  the server) and compares it with what this script would create. Asset codes are issued by the server and differ from
  one database to the next, so the comparison is a fingerprint of the documents with every issued code replaced by its
  position in the structure (``blueprint_sha256``): equal fingerprints mean equal content.
* already published with equal content → reported as reused, nothing is changed;
* missing → created, saved in one atomic save under server-issued codes, validated, submitted by the author (the
  server's warning that all wording is synthetic is acknowledged with a reason), approved by the checker and published
  by the publisher;
* an unfinished item of the author's own with equal content (an interrupted earlier run) → continued from where it is;
* anything else (different content, another person's draft, a rejected candidate, a withdrawn version) → reported
  exactly as found and NOT touched; the exit status is then non-zero.

Nothing is ever deleted, no published version is changed, and no new version of an existing survey is published.
``--verify-only`` makes no change at all and exits non-zero unless everything is published as defined here.

The work is done by ``run(author, checker, publisher)``, which takes three signed-in ``httpx.Client``-compatible clients
(FastAPI's TestClient is one), so it can be exercised in-process; ``main`` only builds real clients and signs in.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

API = "/api/v1"
BANNER = "SYNTHETIC DEMONSTRATION — NOT APPROVED FOR CUSTOMER CALLS."
COLLECTION = "Applicability Showcase — Synthetic Demo"
ACK_REASON = "Synthetic demonstration content for the Applicability Showcase; not approved for customer calls."
SUBMIT_NOTE = "Applicability Showcase — synthetic demonstration content, created by scripts/appl_showcase_setup.py."
APPROVE_COMMENT = "Applicability Showcase — synthetic demonstration content; reviewed as a demonstration only."
Q = " (synthetic demonstration question)"
S = " (synthetic demonstration statement)"

OK_STATES = ("CREATED_AND_PUBLISHED", "CONTINUED_AND_PUBLISHED", "ALREADY_PUBLISHED_REUSED")
OPEN_CANDIDATE = ("IN_REVIEW", "APPROVED")
#: logical code prefix → the kind asked of the code issuer (a STATEMENT is an ITEM whose code starts with S)
ISSUE_KIND = {"@OS:": "OPTION_SET", "@Q:": "ITEM", "@S:": "STATEMENT", "@C:": "CONDITION", "@M:": "MODULE"}
PUT_ORDER = ("OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE")

Doc = dict[str, Any]
Hook = Callable[[str, dict[str, Any]], None]


# ------------------------------------------------------------------------------------------------------------ the API
class ApiError(Exception):
    """A refused request: the HTTP status and the server's stable error code. Never carries a credential."""

    def __init__(self, method: str, path: str, status: int, code: str, message: str) -> None:
        super().__init__(f"{method} {path} -> {status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class ShowcaseError(Exception):
    """The run cannot continue for one item; the message says exactly why."""


def _fail(method: str, path: str, r: httpx.Response) -> ApiError:
    try:
        body = r.json()
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    return ApiError(method, path, r.status_code, str(body.get("code") or "ERROR"), str(body.get("message") or "")[:300])


def _csrf(client: httpx.Client) -> str:
    for cookie in client.cookies.jar:
        if cookie.name.endswith("c360_csrf"):  # "__Host-c360_csrf" where cookies are secure
            return cookie.value or ""
    return ""


def api_get(client: httpx.Client, path: str) -> Any:
    r = client.get(API + path)
    if r.status_code != 200:
        raise _fail("GET", path, r)
    return r.json()


def api_post(client: httpx.Client, path: str, body: Mapping[str, Any] | None = None) -> Any:
    r = client.post(API + path, json=dict(body or {}), headers={"X-CSRF-Token": _csrf(client)})
    if r.status_code not in (200, 201):
        raise _fail("POST", path, r)
    return r.json()


@dataclass(frozen=True)
class Identity:
    principal_id: str
    username: str
    display_name: str
    permissions: frozenset[str]
    markets: frozenset[str]


def sign_in(client: httpx.Client, username: str, password: str) -> None:
    """The two requests the portal makes: a pre-session CSRF token, then the login that sets the session cookies."""
    r = client.get(API + "/auth/csrf")
    if r.status_code != 200:
        raise _fail("GET", "/auth/csrf", r)
    r = client.post(
        API + "/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": str(r.json()["csrf_token"])},
    )
    if r.status_code != 200:
        raise _fail("POST", "/auth/login", r)


def whoami(client: httpx.Client) -> Identity:
    me = api_get(client, "/me")
    p = me["principal"]
    return Identity(
        principal_id=str(p["principal_id"]),
        username=str(p.get("username") or p["display_name"]),
        display_name=str(p["display_name"]),
        permissions=frozenset(me.get("permissions") or []),
        markets=frozenset(me.get("markets") or []),
    )


# ----------------------------------------------------------------------------------------------------- the documents
def _option_set(code: str, options: Sequence[tuple[str, str] | tuple[str, str, bool]]) -> Doc:
    return {
        "schema": "call360.survey.option-set/1",
        "code": code,
        "version": 1,
        "options": [{"code": o[0], "label": o[1], **({"exclusive": True} if len(o) > 2 else {})} for o in options],
    }


def _item(code: str, answer_type: str, intent: str, **extra: Any) -> Doc:
    return {
        "schema": "call360.survey.item/1",
        "code": code,
        "version": 1,
        "answer_type": answer_type,
        "intent": intent,
        **extra,
    }


def _wording(item: str, text: str) -> Doc:
    # CONTROLLED_TTS: the only delivery mode of plain text that can be published (TS-4). No variable is used.
    return {
        "schema": "call360.survey.wording/1",
        "item": item,
        "language": "en",
        "wording_version": 1,
        "text": text,
        "delivery_mode": "CONTROLLED_TTS",
    }


def _node(node: str, item: str, mode: str = "ALL_TO_NEXT", *, statement: bool = False, **routing: Any) -> Doc:
    return {
        "node": node,
        "type": "STATEMENT" if statement else "QUESTION",
        "item": {"code": item, "version": 1, "wording_version": 1},
        "routing": {"mode": mode, **routing},
    }


def _edges(*routes: tuple[str, str, Doc]) -> list[Doc]:
    return [{"edge": f"e{i}", "from": frm, "on": on, "to": to} for i, (frm, on, to) in enumerate(routes, start=1)]


def _module(code: str, name: str, intent: str, outcomes: Sequence[str], nodes: list[Doc], edges: list[Doc]) -> Doc:
    return {
        "schema": "call360.survey.module/1",
        "code": code,
        "revision": 1,
        "name": name,
        "outcomes": list(outcomes),
        "entry": nodes[0]["node"],
        "nodes": nodes,
        "edges": edges,
        "authoring": {"intent": intent},
    }


def _yes_no(code: str) -> Doc:
    return _option_set(code, [("YES", "Yes"), ("NO", "No")])


TEXT_RULE = {"required": True, "min_length": 1, "max_length": 500}
DONE: Doc = {"outcome": "COMPLETED"}
CLARIFY: Doc = {"outcome": "CLARIFICATION_REQUIRED"}


def _to(node: str) -> Doc:
    return {"node": node}


@dataclass(frozen=True)
class Blueprint:
    """What one item of the showcase is: its documents, under LOGICAL codes (``@Q:…``) that the server's issued codes
    replace when it is created."""

    key: str
    kind: str  # MODULE (a standalone reusable module) or SURVEY
    code: str | None  # a survey's code; a module's code is issued by the server
    name: str
    purpose: str
    assets: tuple[tuple[str, Doc], ...]  # (kind, document) this item OWNS
    content: Doc  # a survey's content; for the module, its fixed one-module frame
    pins_shared: tuple[str, ...] = field(default=())  # instances that place the shared module


SHARED = "@M:shared.welcome"
MODULE_NAME = "Showcase welcome and understanding check (synthetic)"
MODULE_PURPOSE = (
    f"{BANNER} A reusable opening for the {COLLECTION}: a synthetic opening statement and one check that the person "
    "remembers the conversation being discussed, with a follow-up when they do not."
)


def _shared_module() -> Blueprint:
    module = _module(
        SHARED,
        MODULE_NAME,
        MODULE_PURPOSE,
        ("COMPLETED", "CLARIFICATION_REQUIRED"),
        [
            _node("n1", "@S:shared.opening", statement=True),
            _node("n2", "@Q:shared.recall", "PER_CHOICE"),
            _node("n3", "@Q:shared.recall_detail"),
        ],
        _edges(
            ("n1", "AFTER_CAPTURE", _to("n2")),
            ("n2", "YES", DONE),
            ("n2", "NO", _to("n3")),
            ("n3", "AFTER_CAPTURE", CLARIFY),
        ),
    )
    assets: tuple[tuple[str, Doc], ...] = (
        ("OPTION_SET", _yes_no("@OS:shared.yes_no")),
        (
            "ITEM",
            _item("@S:shared.opening", "STATEMENT", "Opens the synthetic demonstration", statement_role="OPENING"),
        ),
        (
            "ITEM",
            _item(
                "@Q:shared.recall",
                "YES_NO",
                "Whether the person remembers discussing a plan",
                option_set={"code": "@OS:shared.yes_no", "version": 1},
            ),
        ),
        (
            "ITEM",
            _item(
                "@Q:shared.recall_detail",
                "FREE_TEXT",
                "What the person remembers of the conversation",
                text_rule=dict(TEXT_RULE),
            ),
        ),
        (
            "WORDING",
            _wording(
                "@S:shared.opening",
                "Hello. This is a synthetic demonstration script and not a real customer call." + S,
            ),
        ),
        ("WORDING", _wording("@Q:shared.recall", "Do you remember recently discussing a plan with an adviser?" + Q)),
        (
            "WORDING",
            _wording("@Q:shared.recall_detail", "In your own words, what do you remember about that conversation?" + Q),
        ),
        ("MODULE", module),
    )
    frame = {
        "schema": "call360.survey.content/1",
        "code": SHARED,
        "sequence": [
            {
                "instance": "module",
                "module": {"code": SHARED, "revision": 1},
                "routes": {o: {"survey_outcome": o} for o in module["outcomes"]},
            }
        ],
    }
    return Blueprint("MODULE", "MODULE", None, MODULE_NAME, MODULE_PURPOSE, assets, frame)


def _closing(tag: str) -> tuple[tuple[str, Doc], ...]:
    """Each survey's own closing module: one closing statement."""
    return (
        (
            "ITEM",
            _item(f"@S:{tag}.closing", "STATEMENT", "Closes the synthetic demonstration", statement_role="CLOSING"),
        ),
        ("WORDING", _wording(f"@S:{tag}.closing", "That is the end of this demonstration. Thank you." + S)),
        (
            "MODULE",
            _module(
                f"@M:{tag}.closing",
                "Showcase closing (synthetic)",
                f"{BANNER} Closes the demonstration.",
                ("COMPLETED",),
                [_node("n1", f"@S:{tag}.closing", statement=True)],
                _edges(("n1", "AFTER_CAPTURE", DONE)),
            ),
        ),
    )


def _survey(
    key: str, code: str, name: str, about: str, assets: Sequence[tuple[str, Doc]], middle: Sequence[Doc]
) -> Blueprint:
    """A survey: the shared welcome, its own module(s), its own closing."""
    tag = key.lower()
    welcome = {
        "instance": "mi-welcome",
        "module": {"code": SHARED, "revision": 1},
        "routes": {"COMPLETED": "@CONTINUE", "CLARIFICATION_REQUIRED": {"survey_outcome": "CLARIFICATION_REQUIRED"}},
    }
    closing = {
        "instance": "mi-closing",
        "module": {"code": f"@M:{tag}.closing", "revision": 1},
        "routes": {"COMPLETED": "@CONTINUE"},
    }
    content = {"schema": "call360.survey.content/1", "code": code, "sequence": [welcome, *middle, closing]}
    return Blueprint(
        key, "SURVEY", code, name, f"{BANNER} {about}", (*assets, *_closing(tag)), content, ("mi-welcome",)
    )


def _placed(instance: str, module: str, clarification: Any = None) -> Doc:
    routes: Doc = {"COMPLETED": "@CONTINUE"}
    if clarification is not None:
        routes["CLARIFICATION_REQUIRED"] = clarification
    return {"instance": instance, "module": {"code": module, "revision": 1}, "routes": routes}


END_CLARIFY: Doc = {"survey_outcome": "CLARIFICATION_REQUIRED"}


def _ilp() -> Blueprint:
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", _yes_no("@OS:ilp.yes_no")),
        (
            "OPTION_SET",
            _option_set(
                "@OS:ilp.parts",
                [
                    ("CHARGES", "The charges"),
                    ("FUND_CHOICES", "The fund choices"),
                    ("DURATION", "How long the plan runs"),
                    ("SOMETHING_ELSE", "Something else"),
                ],
            ),
        ),
        ("ITEM", _item("@Q:ilp.purpose", "FREE_TEXT", "What the person understands the plan to be for",
                       text_rule=dict(TEXT_RULE))),
        ("ITEM", _item("@Q:ilp.explained", "YES_NO", "Whether the main features were explained clearly",
                       option_set={"code": "@OS:ilp.yes_no", "version": 1})),
        ("ITEM", _item("@Q:ilp.explain_again", "SINGLE_SELECT", "Which part the person would like explained again",
                       option_set={"code": "@OS:ilp.parts", "version": 1})),
        ("WORDING", _wording("@Q:ilp.purpose", "In your own words, what do you understand this plan to be for?" + Q)),
        ("WORDING", _wording("@Q:ilp.explained",
                             "Were the main features of the plan explained to you in a way you could follow?" + Q)),
        ("WORDING", _wording("@Q:ilp.explain_again", "Which part would you most like to have explained again?" + Q)),
        (
            "MODULE",
            _module(
                "@M:ilp.understanding",
                "ILP product understanding (synthetic)",
                f"{BANNER} Asks what the person understands the plan to be for; a follow-up is asked only when the "
                "features were not clearly explained.",
                ("COMPLETED",),
                [
                    _node("n1", "@Q:ilp.purpose"),
                    _node("n2", "@Q:ilp.explained", "PER_CHOICE"),
                    _node("n3", "@Q:ilp.explain_again"),
                ],
                _edges(
                    ("n1", "AFTER_CAPTURE", _to("n2")),
                    ("n2", "YES", DONE),
                    ("n2", "NO", _to("n3")),
                    ("n3", "ANY", DONE),
                ),
            ),
        ),
    ]  # fmt: skip
    return _survey(
        "ILP",
        "S-APPL-DEMO-ILP",
        "Applicability Showcase · A · ILP product understanding (synthetic demo)",
        "Demonstrates free text, yes/no and single choice: a follow-up question is reached only by the answer No.",
        assets,
        [_placed("mi-ilp-understanding", "@M:ilp.understanding")],
    )


def _nftf() -> Blueprint:
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", _yes_no("@OS:nftf.yes_no")),
        (
            "OPTION_SET",
            _option_set(
                "@OS:nftf.ways",
                [
                    ("VIDEO", "By video call"),
                    ("PHONE", "By phone call"),
                    ("MESSAGES", "By messages or email"),
                    ("ANOTHER_WAY", "Another way"),
                ],
            ),
        ),
        (
            "OPTION_SET",
            _option_set(
                "@OS:nftf.received",
                [
                    ("SUMMARY", "A summary of the plan"),
                    ("APPLICATION_COPY", "A copy of the application"),
                    ("NOTHING", "None of these", True),
                ],
            ),
        ),
        ("ITEM", _item("@Q:nftf.way", "SINGLE_SELECT", "How the plan was mainly discussed",
                       option_set={"code": "@OS:nftf.ways", "version": 1})),
        ("ITEM", _item("@Q:nftf.video_clear", "YES_NO", "Whether the video call could be seen and heard clearly",
                       option_set={"code": "@OS:nftf.yes_no", "version": 1})),
        ("ITEM", _item("@Q:nftf.received", "MULTI_SELECT", "What the person received after the discussion",
                       option_set={"code": "@OS:nftf.received", "version": 1}, selection={"min": 1, "max": 2})),
        ("ITEM", _item("@Q:nftf.expected", "FREE_TEXT", "What the person was expecting to receive",
                       text_rule=dict(TEXT_RULE))),
        ("WORDING", _wording("@Q:nftf.way", "How was the plan mainly discussed with you?" + Q)),
        ("WORDING", _wording("@Q:nftf.video_clear",
                             "Could you see and hear the adviser clearly during the video call?" + Q)),
        ("WORDING", _wording("@Q:nftf.received",
                             "Which of these did you receive after the discussion? You may choose more than one." + Q)),
        ("WORDING", _wording("@Q:nftf.expected", "Please describe what you were expecting to receive." + Q)),
        (
            "MODULE",
            _module(
                "@M:nftf.additional",
                "NFTF additional questions (synthetic)",
                f"{BANNER} NFTF is an illustrative label only. One question is asked only after the answer "
                "'By video call'; a free-text follow-up is asked only when nothing was received.",
                ("COMPLETED", "CLARIFICATION_REQUIRED"),
                [
                    _node("n1", "@Q:nftf.way", "PER_CHOICE"),
                    _node("n2", "@Q:nftf.video_clear"),
                    _node(
                        "n3",
                        "@Q:nftf.received",
                        "ORDERED_RULES",
                        rules=[{"rule": "r1", "when": {"kind": "ANY", "options": ["NOTHING"]}, "to": _to("n4")}],
                        fallback=DONE,
                    ),
                    _node("n4", "@Q:nftf.expected"),
                ],
                _edges(
                    ("n1", "VIDEO", _to("n2")),
                    ("n1", "PHONE", _to("n3")),
                    ("n1", "MESSAGES", _to("n3")),
                    ("n1", "ANOTHER_WAY", _to("n3")),
                    ("n2", "ANY", _to("n3")),
                    ("n4", "AFTER_CAPTURE", CLARIFY),
                ),
            ),
        ),
    ]  # fmt: skip
    return _survey(
        "NFTF",
        "S-APPL-DEMO-NFTF",
        "Applicability Showcase · B · NFTF additional questions (synthetic demo)",
        "NFTF is an illustrative label only. Demonstrates single choice with a different next question per answer, "
        "and a multi-select whose answers decide whether a free-text follow-up is asked.",
        assets,
        [_placed("mi-nftf-additional", "@M:nftf.additional", END_CLARIFY)],
    )


def _combined() -> Blueprint:
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", _yes_no("@OS:combined.yes_no")),
        (
            "OPTION_SET",
            _option_set(
                "@OS:combined.reasons",
                [
                    ("SAVING", "Saving for the future"),
                    ("FAMILY", "Looking after my family"),
                    ("MIX", "A mix of both"),
                    ("NOT_SURE", "I am not sure"),
                ],
            ),
        ),
        (
            "OPTION_SET",
            _option_set(
                "@OS:combined.ways",
                [("VIDEO", "Video call"), ("PHONE", "Phone call"), ("MESSAGES", "Messages or email")],
            ),
        ),
        ("ITEM", _item("@Q:combined.reason", "SINGLE_SELECT", "Why the person chose the plan",
                       option_set={"code": "@OS:combined.reasons", "version": 1})),
        ("ITEM", _item("@Q:combined.purpose", "FREE_TEXT", "What the person understands the plan to be for",
                       text_rule=dict(TEXT_RULE))),
        ("ITEM", _item("@Q:combined.ways", "MULTI_SELECT", "Which ways were used to discuss the plan",
                       option_set={"code": "@OS:combined.ways", "version": 1}, selection={"min": 1, "max": 3})),
        ("ITEM", _item("@Q:combined.video_clear", "YES_NO", "Whether the video call could be seen and heard clearly",
                       option_set={"code": "@OS:combined.yes_no", "version": 1})),
        ("WORDING", _wording("@Q:combined.reason", "Which of these best describes why you chose this plan?" + Q)),
        ("WORDING", _wording("@Q:combined.purpose",
                             "In your own words, what do you understand this plan to be for?" + Q)),
        ("WORDING", _wording("@Q:combined.ways",
                             "Which of these were used when the plan was discussed with you? "
                             "You may choose more than one." + Q)),
        ("WORDING", _wording("@Q:combined.video_clear",
                             "Could you see and hear the adviser clearly during the video call?" + Q)),
        (
            "CONDITION",
            {
                "schema": "call360.survey.condition/1",
                "code": "@C:combined.video_used",
                "version": 1,
                "name": "A video call was one of the ways used (synthetic)",
                "ast": {"op": "INCLUDES_ANY", "left": {"input": "ways"}, "right": {"literal": ["VIDEO"]}},
                "params": {},
                "inputs": {"ways": {"answer_type": "MULTI_SELECT", "item": {"code": "@Q:combined.ways", "version": 1}}},
            },
        ),
        (
            "MODULE",
            _module(
                "@M:combined.ilp",
                "Combined · ILP part (synthetic)",
                f"{BANNER} A single choice; the answer 'I am not sure' leads to a free-text follow-up and a "
                "different ending of the module.",
                ("COMPLETED", "CLARIFICATION_REQUIRED"),
                [_node("n1", "@Q:combined.reason", "PER_CHOICE"), _node("n2", "@Q:combined.purpose")],
                _edges(
                    ("n1", "SAVING", DONE),
                    ("n1", "FAMILY", DONE),
                    ("n1", "MIX", DONE),
                    ("n1", "NOT_SURE", _to("n2")),
                    ("n2", "AFTER_CAPTURE", CLARIFY),
                ),
            ),
        ),
        (
            "MODULE",
            _module(
                "@M:combined.nftf",
                "Combined · NFTF part (synthetic)",
                f"{BANNER} NFTF is an illustrative label only. A multi-select, then a decision that reads it: the "
                "last question is asked only when a video call was chosen.",
                ("COMPLETED",),
                [
                    _node("n1", "@Q:combined.ways"),
                    {
                        "node": "d1",
                        "type": "DECISION",
                        "binding": {
                            "condition": {"code": "@C:combined.video_used", "version": 1},
                            "params": {},
                            "inputs": {"ways": {"node": "n1"}},
                            "unknown_policy": "BLOCK",
                        },
                    },
                    _node("n2", "@Q:combined.video_clear"),
                ],
                _edges(
                    ("n1", "ANY", _to("d1")),
                    ("d1", "MATCH", _to("n2")),
                    ("d1", "NO_MATCH", DONE),
                    ("n2", "ANY", DONE),
                ),
            ),
        ),
    ]  # fmt: skip
    return _survey(
        "COMBINED",
        "S-APPL-DEMO-COMBINED",
        "Applicability Showcase · C · Combined ILP + NFTF (synthetic demo)",
        "NFTF is an illustrative label only. Demonstrates a route BETWEEN modules (one ending of the ILP part skips "
        "the NFTF part and goes to the closing) and a decision that reads a multi-select answer.",
        assets,
        [
            _placed("mi-combined-ilp", "@M:combined.ilp", {"instance": "mi-closing"}),
            _placed("mi-combined-nftf", "@M:combined.nftf"),
        ],
    )


def _replacement() -> Blueprint:
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", _yes_no("@OS:replacement.yes_no")),
        (
            "OPTION_SET",
            _option_set(
                "@OS:replacement.topics",
                [
                    ("DIFFERENCES", "The differences between the two plans"),
                    ("COSTS", "Any costs of changing"),
                    ("NEITHER", "Neither of these", True),
                ],
            ),
        ),
        ("ITEM", _item("@Q:replacement.replaced", "YES_NO", "Whether this plan took the place of an earlier plan",
                       option_set={"code": "@OS:replacement.yes_no", "version": 1})),
        ("ITEM", _item("@Q:replacement.topics", "MULTI_SELECT", "What was talked through before deciding",
                       option_set={"code": "@OS:replacement.topics", "version": 1}, selection={"min": 1, "max": 2})),
        ("ITEM", _item("@Q:replacement.reason", "FREE_TEXT", "Why the person decided to change plans",
                       text_rule=dict(TEXT_RULE))),
        ("WORDING", _wording("@Q:replacement.replaced",
                             "Did this plan take the place of a plan you already had?" + Q)),
        ("WORDING", _wording("@Q:replacement.topics",
                             "Which of these were talked through with you before you decided? "
                             "You may choose more than one." + Q)),
        ("WORDING", _wording("@Q:replacement.reason", "In your own words, why did you decide to change plans?" + Q)),
        (
            "MODULE",
            _module(
                "@M:replacement.scenario",
                "Replacement scenario (synthetic)",
                f"{BANNER} Two further questions are asked only when the answer to the first is Yes.",
                ("COMPLETED",),
                [
                    _node("n1", "@Q:replacement.replaced", "PER_CHOICE"),
                    _node("n2", "@Q:replacement.topics"),
                    _node("n3", "@Q:replacement.reason"),
                ],
                _edges(
                    ("n1", "YES", _to("n2")),
                    ("n1", "NO", DONE),
                    ("n2", "ANY", _to("n3")),
                    ("n3", "AFTER_CAPTURE", DONE),
                ),
            ),
        ),
    ]  # fmt: skip
    return _survey(
        "REPLACEMENT",
        "S-APPL-DEMO-REPLACEMENT",
        "Applicability Showcase · D · Replacement scenario (synthetic demo)",
        "Demonstrates yes/no, multi-select and free text: two follow-up questions are reached only by the answer Yes.",
        assets,
        [_placed("mi-replacement", "@M:replacement.scenario")],
    )


def _rider() -> Blueprint:
    assets: list[tuple[str, Doc]] = [
        ("OPTION_SET", _yes_no("@OS:rider.yes_no")),
        (
            "OPTION_SET",
            _option_set(
                "@OS:rider.who",
                [
                    ("MYSELF", "I asked for it"),
                    ("ADVISER", "The adviser suggested it"),
                    ("DO_NOT_REMEMBER", "I do not remember"),
                ],
            ),
        ),
        ("ITEM", _item("@Q:rider.added", "YES_NO", "Whether any optional extra cover was added",
                       option_set={"code": "@OS:rider.yes_no", "version": 1})),
        ("ITEM", _item("@Q:rider.who", "SINGLE_SELECT", "Who suggested adding the extra cover",
                       option_set={"code": "@OS:rider.who", "version": 1})),
        ("ITEM", _item("@Q:rider.remember", "FREE_TEXT", "What the person remembers about the extra cover",
                       text_rule=dict(TEXT_RULE))),
        ("WORDING", _wording("@Q:rider.added", "Did you add any optional extra cover to your plan?" + Q)),
        ("WORDING", _wording("@Q:rider.who", "Who suggested adding the extra cover?" + Q)),
        ("WORDING", _wording("@Q:rider.remember", "Please tell us what you remember about the extra cover." + Q)),
        (
            "MODULE",
            _module(
                "@M:rider.scenario",
                "Rider scenario (synthetic)",
                f"{BANNER} A second question is asked only after Yes; a free-text follow-up only after "
                "'I do not remember'.",
                ("COMPLETED", "CLARIFICATION_REQUIRED"),
                [
                    _node("n1", "@Q:rider.added", "PER_CHOICE"),
                    _node("n2", "@Q:rider.who", "PER_CHOICE"),
                    _node("n3", "@Q:rider.remember"),
                ],
                _edges(
                    ("n1", "YES", _to("n2")),
                    ("n1", "NO", DONE),
                    ("n2", "MYSELF", DONE),
                    ("n2", "ADVISER", DONE),
                    ("n2", "DO_NOT_REMEMBER", _to("n3")),
                    ("n3", "AFTER_CAPTURE", CLARIFY),
                ),
            ),
        ),
    ]  # fmt: skip
    return _survey(
        "RIDER",
        "S-APPL-DEMO-RIDER",
        "Applicability Showcase · E · Rider scenario (synthetic demo)",
        "Demonstrates yes/no, single choice and free text: nested follow-ups, each reached by one answer only.",
        assets,
        [_placed("mi-rider", "@M:rider.scenario", END_CLARIFY)],
    )


def blueprints() -> tuple[Blueprint, tuple[Blueprint, ...]]:
    """The reusable module, and the five surveys in the order they are created."""
    return _shared_module(), (_ilp(), _nftf(), _combined(), _replacement(), _rider())


SURVEY_CODES = tuple(b.code for b in blueprints()[1])


# --------------------------------------------------------------------------------------------------- fingerprints
DocIndex = dict[tuple[str, Any, Any], Doc]


def asset_key(kind: str, doc: Mapping[str, Any]) -> tuple[str, str, int]:
    if kind == "WORDING":
        return kind, str(doc["item"]), int(doc["wording_version"])
    if kind == "MODULE":
        return kind, str(doc["code"]), int(doc["revision"])
    return kind, str(doc["code"]), int(doc["version"])


def index_of(assets: Sequence[tuple[str, Doc]]) -> DocIndex:
    return {asset_key(kind, doc): doc for kind, doc in assets}


def index_of_api(assets: Sequence[Mapping[str, Any]]) -> DocIndex:
    """The ``assets`` of a draft-documents or candidate-documents response, by (kind, code, version)."""
    return {
        (str(a["kind"]), str(a["code"]), int(a["version"])): dict(a["document"])
        for a in assets
        if isinstance(a.get("document"), dict)
    }


def _replace(value: Any, names: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return names.get(value, value)
    if isinstance(value, list):
        return [_replace(v, names) for v in value]
    if isinstance(value, dict):
        return {k: _replace(v, names) for k, v in value.items()}
    return value


def walk(content: Mapping[str, Any], docs: DocIndex) -> tuple[dict[str, str], list[tuple[str, str, int]]]:
    """Every asset a content pins, in the order the structure reaches it, and a position-name for every asset code
    (``<M1>``, ``<Q2>`` …). Two contents that differ only in the codes the server issued get the same names."""
    names: dict[str, str] = {}
    counters: dict[str, int] = {}
    order: list[tuple[str, str, int]] = []

    def name(prefix: str, code: Any) -> None:
        if isinstance(code, str) and code not in names:
            counters[prefix] = counters.get(prefix, 0) + 1
            names[code] = f"<{prefix}{counters[prefix]}>"

    def take(kind: str, code: Any, version: Any) -> Doc | None:
        if not isinstance(code, str) or not isinstance(version, int):
            return None
        if (kind, code, version) not in order:
            order.append((kind, code, version))
        return docs.get((kind, code, version))

    def condition(binding: Any) -> None:
        ref = (binding or {}).get("condition") or {}
        name("C", ref.get("code"))
        take("CONDITION", ref.get("code"), ref.get("version"))

    for inst in content.get("sequence") or []:
        condition(inst.get("eligibility"))
        ref = inst.get("module") or {}
        name("M", ref.get("code"))
        module = take("MODULE", ref.get("code"), ref.get("revision"))
        for node in (module or {}).get("nodes") or []:
            if node.get("type") == "DECISION":
                condition(node.get("binding"))
                continue
            placed = node.get("item") or {}
            name("Q", placed.get("code"))
            item = take("ITEM", placed.get("code"), placed.get("version"))
            take("WORDING", placed.get("code"), placed.get("wording_version"))
            options = (item or {}).get("option_set") or {}
            if options:
                name("OS", options.get("code"))
                take("OPTION_SET", options.get("code"), options.get("version"))
    return names, order


def blueprint_sha256(content: Mapping[str, Any], docs: DocIndex) -> str:
    """A fingerprint of a content and everything it pins that does NOT depend on the codes the server issued."""
    names, order = walk(content, docs)
    canonical = {
        "content": _replace(dict(content), names),
        "assets": [
            {"kind": kind, "version": version, "document": _replace(docs.get((kind, code, version)), names)}
            for kind, code, version in order
        ],
    }
    text = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def intended_sha256(blueprint: Blueprint, shared: Blueprint) -> str:
    docs = index_of(blueprint.assets)
    if blueprint.pins_shared:
        docs |= index_of(shared.assets)
    return blueprint_sha256(blueprint.content, docs)


def logical_codes(blueprint: Blueprint) -> dict[str, list[str]]:
    """The codes this item needs from the issuer, per kind, in a fixed order. The standalone module's own code was
    issued when the module was created."""
    wanted: dict[str, list[str]] = {}
    for kind, doc in blueprint.assets:
        if kind == "WORDING":
            continue
        code = str(doc["code"])
        if blueprint.kind == "MODULE" and code == SHARED:
            continue
        issue_kind = next(v for prefix, v in ISSUE_KIND.items() if code.startswith(prefix))
        wanted.setdefault(issue_kind, []).append(code)
    return wanted


# -------------------------------------------------------------------------------------------- describing a structure
def _target(to: Any) -> str:
    if not isinstance(to, dict):
        return str(to)
    if "node" in to:
        return f"go to {to['node']}"
    if "outcome" in to:
        return f"module ends {to['outcome']}"
    return json.dumps(to, sort_keys=True)


def _survey_target(to: Any) -> str:
    if to == "@CONTINUE":
        return "continue to the next module"
    if isinstance(to, dict) and "instance" in to:
        return f"jump to module {to['instance']}"
    if isinstance(to, dict) and "survey_outcome" in to:
        return f"survey ends {to['survey_outcome']}"
    return json.dumps(to, sort_keys=True)


def describe(content: Mapping[str, Any], docs: DocIndex, shared_code: str | None) -> list[Doc]:
    """Modules → steps with their answer type → where each answer leads. Read from the documents themselves."""
    out: list[Doc] = []
    for inst in content.get("sequence") or []:
        ref = inst["module"]
        module = docs.get(("MODULE", ref["code"], ref["revision"])) or {}
        steps: list[Doc] = []
        for node in module.get("nodes") or []:
            edges = [e for e in module.get("edges") or [] if e.get("from") == node["node"]]
            branches = [f"{e['on']} -> {_target(e['to'])}" for e in edges]
            if node.get("type") == "DECISION":
                cond = (node.get("binding") or {}).get("condition") or {}
                cdoc = docs.get(("CONDITION", cond.get("code"), cond.get("version"))) or {}
                steps.append(
                    {
                        "node": node["node"], "type": "DECISION", "condition": cond.get("code"),
                        "condition_name": cdoc.get("name"), "branches": branches,
                    }
                )  # fmt: skip
                continue
            placed = node["item"]
            item = docs.get(("ITEM", placed["code"], placed["version"])) or {}
            wording = docs.get(("WORDING", placed["code"], placed["wording_version"])) or {}
            oref = item.get("option_set") or {}
            options = (docs.get(("OPTION_SET", oref.get("code"), oref.get("version"))) or {}).get("options") or []
            routing = node.get("routing") or {}
            for rule in routing.get("rules") or []:
                when = rule.get("when") or {}
                branches.append(f"{when.get('kind')} of {when.get('options')} -> {_target(rule.get('to'))}")
            if routing.get("fallback"):
                branches.append(f"otherwise -> {_target(routing['fallback'])}")
            steps.append(
                {
                    "node": node["node"], "type": node["type"], "item": placed["code"],
                    "answer_type": item.get("answer_type"), "text": wording.get("text"),
                    "delivery_mode": wording.get("delivery_mode"),
                    "options": [{"code": o["code"], "label": o.get("label", "")} for o in options],
                    "routing_mode": routing.get("mode"), "branches": branches,
                }
            )  # fmt: skip
        out.append(
            {
                "instance": inst["instance"], "module": ref["code"], "revision": ref["revision"],
                "name": module.get("name"), "reused_module": ref["code"] == shared_code,
                "outcomes": list(module.get("outcomes") or []),
                "routes": {o: _survey_target(t) for o, t in (inst.get("routes") or {}).items()},
                "steps": steps,
            }
        )  # fmt: skip
    return out


# ------------------------------------------------------------------------------------------------------------ the run
@dataclass
class _Run:
    author: httpx.Client
    checker: httpx.Client
    publisher: httpx.Client
    people: dict[str, Identity]  # role → identity
    verify_only: bool
    hook: Hook | None
    shared: Blueprint
    shared_code: str | None = None  # the standalone module's actual code, once it is known to be published as defined

    def username_of(self, ref: Any, name: Any) -> str | None:
        if ref is None:
            return None
        for who in self.people.values():
            if who.principal_id == str(ref):
                return who.username
        return f"{name or 'unknown'} ({ref})"


def _event_actor(run: _Run, history: Sequence[Mapping[str, Any]], event: str) -> str | None:
    hit = next((h for h in reversed(history) if h.get("event") == event), None)
    return run.username_of(hit.get("actor_ref"), hit.get("actor_name")) if hit else None


def _published_record(run: _Run, version_id: str, candidate_id: str, blueprint: Blueprint) -> Doc:
    """What the report says of a published version — read back from the server, never assumed."""
    version = api_get(run.author, f"/survey-versions/{version_id}")
    cand = api_get(run.author, f"/survey-candidates/{candidate_id}/documents")
    docs = index_of_api(cand["assets"])
    history = [*cand.get("history", []), *version.get("history", [])]
    return {
        "version_id": version["id"],
        "version_label": version["label"],
        "version_no": version["version_no"],
        "version_status": version["status"],
        "candidate_id": cand["id"],
        "content_sha256": version["content_sha256"],
        "manifest_sha256": version["manifest_sha256"],
        "manifest_intact": cand.get("manifest_intact"),
        "blueprint_sha256": blueprint_sha256(cand["content"], docs),
        "authored_by": run.username_of(cand["submitted_by"]["ref"], cand["submitted_by"].get("name")),
        "approved_by": _event_actor(run, history, "APPROVED"),
        "published_by": _event_actor(run, history, "PUBLISHED"),
        "structure": describe(cand["content"], docs, run.shared_code),
        "_content": cand["content"],
    }


def _pin_problem(run: _Run, blueprint: Blueprint, content: Mapping[str, Any]) -> str | None:
    """A survey of the showcase reuses THE published module — not a look-alike under another code."""
    if not blueprint.pins_shared or run.shared_code is None:
        return None
    for inst in content.get("sequence") or []:
        if inst.get("instance") in blueprint.pins_shared and inst.get("module") != {
            "code": run.shared_code,
            "revision": 1,
        }:
            return f"{inst.get('instance')} pins {inst.get('module')}, not the showcase module {run.shared_code} rev 1"
    return None


def _find(run: _Run, blueprint: Blueprint) -> tuple[list[Doc], str | None]:
    """What exists for this item: the survey with its code, or every standalone module with its exact name."""
    if blueprint.kind == "SURVEY":
        rows = [s for s in api_get(run.author, "/survey-definitions")["items"] if s["code"] == blueprint.code]
        return [{"id": r["id"], "code": r["code"], "name": r["name"], "purpose": r["purpose"]} for r in rows], None
    rows = [m for m in api_get(run.author, "/survey-modules")["items"] if m["name"] == blueprint.name]
    return [{"id": r["id"], "code": r["code"], "name": r["name"], "purpose": r["description"]} for r in rows], None


def _assess(run: _Run, blueprint: Blueprint, row: Doc) -> Doc:
    """Where an existing item stands against the definition here. Reads only."""
    wanted = intended_sha256(blueprint, run.shared)
    hist = api_get(run.author, f"/survey-definitions/{row['id']}/history")
    versions, candidates = hist["versions"], hist["candidates"]
    details_differ = (row["name"], row["purpose"]) != (blueprint.name, blueprint.purpose)
    base: Doc = {"definition_id": row["id"], "code": row["code"]}
    if versions:
        latest = versions[-1]
        record = _published_record(run, latest["id"], latest["candidate_id"], blueprint)
        content = record.pop("_content")
        problems = []
        if latest["status"] != "PUBLISHED":
            problems.append(f"its latest version {latest['label']} is {latest['status']}, not PUBLISHED")
        if record["blueprint_sha256"] != wanted:
            problems.append(f"the content of its latest version {latest['label']} differs from the showcase definition")
        if details_differ:
            problems.append("its name or description differs from the showcase definition")
        pin = _pin_problem(run, blueprint, content)
        if pin:
            problems.append(pin)
        notes = []
        if len(versions) > 1:
            notes.append(f"{len(versions)} versions exist; the latest is reported")
        if any(c["status"] in OPEN_CANDIDATE for c in candidates):
            notes.append("a newer candidate is open; it was not touched")
        if hist["draft_content_sha256"] != latest["content_sha256"]:
            notes.append("its working draft differs from the published version; it was not touched")
        state = "CONFLICT" if problems else "ALREADY_PUBLISHED_REUSED"
        detail = "; ".join(problems) if problems else "already published, reused; nothing was changed"
        return {**base, **record, "state": state, "detail": detail, "notes": notes}
    open_ones = [c for c in candidates if c["status"] in OPEN_CANDIDATE]
    if open_ones:
        cand = api_get(run.author, f"/survey-candidates/{open_ones[-1]['id']}/documents")
        same = blueprint_sha256(cand["content"], index_of_api(cand["assets"])) == wanted and not details_differ
        mine = cand["submitted_by"]["ref"] == run.people["author"].principal_id
        pin = _pin_problem(run, blueprint, cand["content"])
        if same and mine and not pin:
            return {**base, "state": "RESUMABLE", "resume": cand["status"], "candidate_id": cand["id"]}
        why = pin or ("its content differs from the showcase definition" if not same else "another person submitted it")
        return {
            **base, "state": "CONFLICT", "candidate_id": cand["id"],
            "detail": f"not published: candidate {cand['n']} is {cand['status']} and {why}",
        }  # fmt: skip
    if candidates:
        statuses = ", ".join(f"candidate {c['n']} {c['status']}" for c in candidates)
        return {**base, "state": "CONFLICT", "detail": f"not published, and it has earlier candidates ({statuses})"}
    draft = api_get(run.author, f"/survey-definitions/{row['id']}/draft/documents")
    base["draft_revision"] = draft["revision"]
    if draft.get("updated_by") != run.people["author"].display_name:
        return {
            **base, "state": "CONFLICT",
            "detail": f"draft only (revision {draft['revision']}), last saved by someone other than the author",
        }  # fmt: skip
    docs = index_of_api(draft["assets"])
    if blueprint.kind == "SURVEY":
        empty = draft["revision"] == 0 and not draft["content"].get("sequence") and not details_differ
    else:
        own = docs.get(("MODULE", row["code"], 1)) or {}
        empty = draft["revision"] == 0 and own.get("nodes") == [] and not details_differ
    if empty:
        return {**base, "state": "RESUMABLE", "resume": "EMPTY_DRAFT"}
    if blueprint_sha256(draft["content"], docs) == wanted and not details_differ:
        pin = _pin_problem(run, blueprint, draft["content"])
        if not pin:
            return {**base, "state": "RESUMABLE", "resume": "SAVED_DRAFT"}
    return {
        **base, "state": "CONFLICT",
        "detail": f"draft only (revision {draft['revision']}) and its content differs from the showcase definition",
    }  # fmt: skip


def _create(run: _Run, blueprint: Blueprint) -> Doc:
    if blueprint.kind == "SURVEY":
        made = api_post(
            run.author,
            "/survey-definitions",
            {"code": blueprint.code, "name": blueprint.name, "purpose": blueprint.purpose},
        )
    else:
        made = api_post(run.author, "/survey-modules", {"name": blueprint.name, "description": blueprint.purpose})
    return {"id": made["id"], "code": made["code"]}


def _fill(run: _Run, blueprint: Blueprint, row: Mapping[str, Any]) -> None:
    """Issue the codes, then ONE atomic save of every document and the content."""
    wanted = logical_codes(blueprint)
    issued = api_post(
        run.author,
        f"/survey-definitions/{row['id']}/codes",
        {"requests": [{"kind": kind, "count": len(codes)} for kind, codes in wanted.items()]},
    )["codes"]
    names: dict[str, str] = {}
    for kind, codes in wanted.items():
        got = [c["code"] for c in issued if c["kind"] == kind]
        if len(got) != len(codes):
            raise ShowcaseError(f"the server issued {len(got)} {kind} codes where {len(codes)} were asked for")
        names |= dict(zip(codes, got, strict=True))
    if blueprint.kind == "MODULE":
        names[SHARED] = str(row["code"])
    elif run.shared_code is not None:
        names[SHARED] = run.shared_code
    assets = sorted(blueprint.assets, key=lambda a: PUT_ORDER.index(a[0]))  # stable: the given order within a kind
    operations: list[Doc] = [
        {"op": "PUT_ASSET", "kind": kind, "document": _replace(copy.deepcopy(doc), names)} for kind, doc in assets
    ]
    operations.append({"op": "SET_CONTENT", "content": _replace(copy.deepcopy(blueprint.content), names)})
    revision = api_get(run.author, f"/survey-definitions/{row['id']}/draft/documents")["revision"]
    saved = api_post(
        run.author,
        f"/survey-definitions/{row['id']}/draft/save",
        {"expected_revision": revision, "operations": operations},
    )
    if blueprint_sha256(saved["content"], index_of_api(saved["assets"])) != intended_sha256(blueprint, run.shared):
        raise ShowcaseError("the saved draft is not the showcase definition; nothing was submitted")


def _submit(run: _Run, row: Mapping[str, Any]) -> str:
    found = api_post(run.author, f"/survey-definitions/{row['id']}/draft/validate")
    blockers = [f for f in found["findings"] if f["severity"] == "BLOCKER"]
    if blockers:
        listed = ", ".join(f"{f['code']} at {f['at']}" for f in blockers)
        raise ShowcaseError(f"the server found {len(blockers)} blocker(s): {listed}")
    # the server's own warning that all wording is synthetic and unapproved: acknowledged, with a reason, as it asks
    acks = [
        {"code": f["code"], "at": f["at"], "reason": ACK_REASON}
        for f in found["findings"]
        if f["severity"] == "WARNING"
    ]
    made = api_post(
        run.author, f"/survey-definitions/{row['id']}/candidates", {"note": SUBMIT_NOTE, "acknowledgements": acks}
    )
    return str(made["id"])


def _govern(run: _Run, blueprint: Blueprint, row: Mapping[str, Any], candidate_id: str, status: str) -> str:
    """The checker approves, then the publisher publishes. The author does neither."""
    info = {"key": blueprint.key, "definition_id": str(row["id"]), "candidate_id": candidate_id}
    if status == "IN_REVIEW":
        if run.hook:
            run.hook("SUBMITTED", info)
        api_post(
            run.checker,
            f"/survey-candidates/{candidate_id}/decision",
            {"verdict": "APPROVE", "comment": APPROVE_COMMENT},
        )
    if run.hook:
        run.hook("APPROVED", info)
    return str(api_post(run.publisher, f"/survey-candidates/{candidate_id}/publish")["id"])


def _ensure(run: _Run, blueprint: Blueprint, blocked: str | None) -> Doc:
    """One item, from wherever it stands to published — or the exact reason it was left alone."""
    out: Doc = {"key": blueprint.key, "kind": blueprint.kind, "code": blueprint.code, "name": blueprint.name}
    try:
        rows, _ = _find(run, blueprint)
        assessed = [_assess(run, blueprint, r) for r in rows]
        if len(assessed) > 1:
            reusable = [a for a in assessed if a["state"] == "ALREADY_PUBLISHED_REUSED"]
            if not reusable:
                codes = ", ".join(a["code"] for a in assessed)
                return {
                    **out, "state": "CONFLICT",
                    "detail": f"{len(assessed)} standalone modules carry this name ({codes}) and none is published "
                    "as defined here; nothing was changed",
                }  # fmt: skip
            assessed = reusable[:1]
        found = assessed[0] if assessed else None
        if found and found["state"] in ("ALREADY_PUBLISHED_REUSED", "CONFLICT"):
            return {**out, **found}
        if run.verify_only:
            if found:
                return {
                    **out,
                    **found,
                    "state": "NOT_PUBLISHED",
                    "detail": f"exists but is not published ({found['resume']})",
                }
            return {**out, "state": "MISSING", "detail": "does not exist"}
        if blocked:
            return {**out, **(found or {}), "state": "BLOCKED", "detail": blocked}
        if found is None:
            row = _create(run, blueprint)
            resume, state = "EMPTY_DRAFT", "CREATED_AND_PUBLISHED"
        else:
            row = {"id": found["definition_id"], "code": found["code"]}
            resume, state = found["resume"], "CONTINUED_AND_PUBLISHED"
        out |= {"definition_id": row["id"], "code": row["code"]}
        if resume == "EMPTY_DRAFT":
            _fill(run, blueprint, row)
            resume = "SAVED_DRAFT"
        if resume == "SAVED_DRAFT":
            candidate_id, resume = _submit(run, row), "IN_REVIEW"
        else:
            candidate_id = str((found or {})["candidate_id"])
        out["candidate_id"] = candidate_id
        version_id = _govern(run, blueprint, row, candidate_id, resume)
        record = _published_record(run, version_id, candidate_id, blueprint)
        record.pop("_content")
        if record["blueprint_sha256"] != intended_sha256(blueprint, run.shared):
            return {**out, **record, "state": "FAILED", "detail": "what was published is not the showcase definition"}
        detail = (
            "created and published" if state == "CREATED_AND_PUBLISHED" else "an unfinished earlier run was continued"
        )
        return {**out, **record, "state": state, "detail": detail, "notes": []}
    except ApiError as exc:
        if exc.code == "SURVEY_CODE_TAKEN":
            return {
                **out, "state": "CONFLICT",
                "detail": "this survey code is already taken by a survey the author cannot see (another market?)",
            }  # fmt: skip
        return {**out, "state": "FAILED", "detail": str(exc)}
    except ShowcaseError as exc:
        return {**out, "state": "FAILED", "detail": str(exc)}


def run(
    author: httpx.Client,
    checker: httpx.Client,
    publisher: httpx.Client,
    *,
    verify_only: bool = False,
    hook: Hook | None = None,
) -> Doc:
    """Create and publish the showcase (or, with ``verify_only``, only check it) with three SIGNED-IN clients. Returns
    the report; ``report["ok"]`` is true only when the module and all five surveys are published as defined here."""
    people = {"author": whoami(author), "checker": whoami(checker), "publisher": whoami(publisher)}
    if len({p.principal_id for p in people.values()}) != 3:
        raise ShowcaseError("the author, the checker and the publisher must be three different people")
    shared, surveys = blueprints()
    state = _Run(author, checker, publisher, people, verify_only, hook, shared)
    module = _ensure(state, shared, None)
    if module["state"] in OK_STATES:
        state.shared_code = str(module["code"])
    blocked = None if module["state"] in OK_STATES else "the reusable module is not published as defined here"
    items = [module] + [_ensure(state, s, blocked) for s in surveys]
    pins = [
        {"survey": i["code"], "instance": m["instance"], "module": m["module"], "revision": m["revision"]}
        for i in items[1:]
        for m in i.get("structure") or []
        if m.get("reused_module")
    ]
    return {
        "collection": COLLECTION,
        "banner": BANNER,
        "mode": "VERIFY_ONLY" if verify_only else "SETUP",
        "ok": all(i["state"] in OK_STATES for i in items),
        "people": {role: who.username for role, who in people.items()},
        "module": module,
        "surveys": items[1:],
        "reuse": {"module": state.shared_code, "revision": 1 if state.shared_code else None, "pinned_by": pins},
    }


# --------------------------------------------------------------------------------------------------------- the report
def render(report: Mapping[str, Any]) -> str:
    lines = [
        f"{report['collection']} — {report['mode']}",
        report["banner"],
        "People: " + ", ".join(f"{role} = {name}" for role, name in report["people"].items()),
        "",
    ]
    for item in [report["module"], *report["surveys"]]:
        lines.append(f"[{item['state']}] {item['kind']} {item.get('code') or '(no code yet)'} — {item['name']}")
        lines.append(f"    {item.get('detail', '')}")
        for note in item.get("notes") or []:
            lines.append(f"    note: {note}")
        if item.get("version_id"):
            lines += [
                f"    definition id      {item.get('definition_id')}",
                f"    published version  {item['version_id']}  (label {item['version_label']}, "
                f"number {item['version_no']}, {item['version_status']})",
                f"    content sha256     {item['content_sha256']}",
                f"    manifest sha256    {item['manifest_sha256']}",
                f"    blueprint sha256   {item['blueprint_sha256']}  (independent of server-issued codes)",
                f"    authored by {item['authored_by']} · approved by {item['approved_by']} · "
                f"published by {item['published_by']}",
            ]
        for module in item.get("structure") or []:
            reused = "  [the reusable module, pinned by exact revision]" if module["reused_module"] else ""
            lines.append(f"    module {module['instance']}: {module['module']} rev {module['revision']} — "
                         f"{module['name']}{reused}")  # fmt: skip
            for step in module["steps"]:
                if step["type"] == "DECISION":
                    lines.append(f"      {step['node']} DECISION on {step['condition']} — {step['condition_name']}")
                else:
                    lines.append(f"      {step['node']} {step['answer_type']} {step['item']}: {step['text']}")
                    if step["options"]:
                        lines.append("          answers: " + " | ".join(o["label"] for o in step["options"]))
                for branch in step["branches"]:
                    lines.append(f"          {branch}")
            for outcome, target in module["routes"].items():
                lines.append(f"      when the module ends {outcome}: {target}")
        lines.append("")
    reuse = report["reuse"]
    if reuse["module"]:
        users = ", ".join(str(p["survey"]) for p in reuse["pinned_by"]) or "no survey"
        lines.append(f"Reusable module {reuse['module']} revision {reuse['revision']} is pinned by: {users}")
    lines.append("RESULT: " + ("OK — everything is published as defined" if report["ok"] else "NOT OK — see above"))
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------------------ the CLI
def credentials(accounts: Mapping[str, Any], key: str) -> tuple[str, str]:
    """``(username, password)`` for a key of the accounts file, in either of its two shapes."""
    if key not in accounts:
        raise ShowcaseError(f"the accounts file has no entry named {key!r}")
    entry = accounts[key]
    if isinstance(entry, str):
        return key, entry
    if isinstance(entry, dict) and isinstance(entry.get("password"), str):
        return str(entry.get("username") or key), entry["password"]
    raise ShowcaseError(f"the accounts entry {key!r} is neither a password nor an object with a password")


def make_client(base_url: str, origin: str) -> httpx.Client:
    return httpx.Client(base_url=base_url, headers={"Origin": origin}, timeout=60.0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", required=True, help="where the API is served, e.g. http://127.0.0.1:8000")
    parser.add_argument("--origin", required=True, help="the Origin header the API expects (the portal's origin)")
    parser.add_argument("--accounts", required=True, type=Path, help="JSON file of names to passwords or to objects")
    parser.add_argument("--author", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--verify-only", action="store_true", help="change nothing; non-zero unless all is published")
    parser.add_argument("--report", type=Path, help="also write the report as JSON to this path")
    args = parser.parse_args(argv)

    clients: list[httpx.Client] = []
    try:
        accounts = json.loads(args.accounts.read_text())
        if not isinstance(accounts, dict):
            raise ShowcaseError("the accounts file is not a JSON object")
        for role in ("author", "checker", "publisher"):
            username, password = credentials(accounts, getattr(args, role))
            client = make_client(args.base_url, args.origin)
            clients.append(client)
            try:
                sign_in(client, username, password)
            except ApiError as exc:
                raise ShowcaseError(f"could not sign in the {role} ({username}): {exc.status} {exc.code}") from None
        report = run(clients[0], clients[1], clients[2], verify_only=args.verify_only)
    except (ShowcaseError, ApiError, OSError, ValueError, httpx.HTTPError) as exc:
        print(f"appl_showcase_setup: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        for client in clients:
            client.close()
    print(render(report))
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
