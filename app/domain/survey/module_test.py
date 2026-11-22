"""LIB-2 — testing ONE module on its own, with the authoritative Python engine.

The engine executes a survey content. A module on its own has none, so it is given the fixed frame of
``store.module_frame``: the module, once, always entered, every ending of the module ending the run as itself. The
frame is built here for the test and is not a survey: no definition, candidate, version, simulation or call plan is
created, and nothing at all is written — not the facts, not the answers, not the run. The test is the deterministic
replay of the inputs it was given through ``execution.execute_inputs``; giving the same inputs again gives the same
run and the same fingerprint, which is what "replay" means here.

A test is not approval of anything. A module that tests well is not thereby validated for publication, reviewed, or
eligible for any call. Nothing here reads or writes a callback case, contact attempt, conversation session, finding or
disposition.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.domain.survey import simulation, store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import fields_of
from app.domain.survey.documents import manifest_of
from app.domain.survey.execution import CONTRACT, execute_inputs
from app.domain.survey.store import SurveyError

RECORD_CLASS = "MODULE_TEST"
NOTE = (
    "MODULE TEST ONLY. Synthetic facts and unapproved wording, run in a fixed one-module frame; nothing is recorded. "
    "Not validation for publication, not approval, not operational evidence and not eligibility for any call."
)
MAX_INPUTS = 200


def _subject(
    db: Session, markets: Sequence[str], module_id: uuid.UUID | None, code: str | None, revision: int | None
) -> tuple[dict[str, Any], dict[str, Any], uuid.UUID | None]:
    """The frame content to execute and what is being tested. Either a standalone module's own revision (its working
    draft by default — a draft CAN be tested, by a person who may open it), or any PUBLISHED module of the reader's
    markets, however it was authored."""
    if module_id is not None:
        row = store.module(db, module_id, markets)
        content = store.draft(db, module_id)["content"]
        pinned = int(content["sequence"][0]["module"]["revision"])
        wanted = pinned if revision is None else revision
        doc = store._doc(db, "MODULE", row["code"], wanted)  # noqa: SLF001
        if doc is None or doc["owner_definition_id"] != module_id:
            raise SurveyError(404, "NOT_FOUND", "This module has no such revision")
        source = "WORKING_DRAFT" if doc["state"] == "DRAFT" else "FROZEN_REVISION"
        owner: uuid.UUID | None = module_id
    else:
        if not code or not revision:
            raise SurveyError(422, "OPERATION_INVALID", "Name a standalone module, or a published module and revision")
        if (("MODULE", code, revision)) not in store.published_index(db, markets):
            # not published in the reader's markets: it does not exist for them
            raise SurveyError(404, "NOT_FOUND", "No such published module")
        doc = store._doc(db, "MODULE", code, revision)  # noqa: SLF001
        if doc is None:
            raise SurveyError(404, "NOT_FOUND", "No such published module")
        source, owner = "PUBLISHED_REVISION", None
    frame = store.module_frame(str(doc["code"]), doc["content"])
    subject = {
        "code": doc["code"], "revision": doc["version"], "name": str(doc["content"].get("name") or doc["code"]),
        "sha256": doc["sha256"], "state": doc["state"], "source": source,
        "published": ("MODULE", doc["code"], doc["version"]) in store.published_index(db, markets),
    }  # fmt: skip
    return frame, subject, owner


def run(
    db: Session, markets: Sequence[str], *, module_id: uuid.UUID | None, code: str | None, revision: int | None,
    facts: Any, inputs: Any,
) -> dict[str, Any]:  # fmt: skip
    frame, subject, owner = _subject(db, markets, module_id, code, revision)
    # the same validation a submission gets; a module with a blocker is not executed (the engine is never asked to
    # guess at a module that is not well formed)
    findings = store.findings_of(db, frame, owner)
    blockers = [f for f in findings if f["severity"] == "BLOCKER"]
    bundle = store.load_bundle(db, frame)
    needs: set[str] = set()
    for cond in bundle.conditions.values():
        needs |= set(fields_of(cond.get("ast") or {}))
    base = {
        "record_class": RECORD_CLASS, "note": NOTE, "module": subject, "engine_contract": CONTRACT,
        "frame": frame, "manifest": manifest_of(bundle),
        "requires": {"fields": sorted(needs)},
        "fields": {k: dict(v) for k, v in sorted(bundle.fields.items()) if k in needs},
        "findings": [{k: f[k] for k in ("code", "at", "severity", "message")} for f in findings],
    }  # fmt: skip
    if blockers:
        return base | {
            "testable": False, "facts": {}, "facts_sha256": None, "inputs": [], "status": "NOT_TESTABLE", "run": None,
            "run_sha256": None,
        }  # fmt: skip
    clean = simulation.check_facts(bundle, facts)
    if not isinstance(inputs, list) or len(inputs) > MAX_INPUTS:
        raise SurveyError(422, "OPERATION_INVALID", f"A test holds at most {MAX_INPUTS} inputs")
    given: list[dict[str, Any]] = []
    for i in inputs:
        if not isinstance(i, Mapping) or not isinstance(i.get("key"), str):
            raise SurveyError(422, "ANSWER_INVALID", "An input names the question it answers")
        given.append({"key": i["key"], "answer": simulation.check_answer(i.get("answer"))})
    replayed = json.loads(json.dumps(clean))
    out: list[dict[str, Any]] = []
    result = execute_inputs(bundle, replayed, [])
    for n, g in enumerate(given, start=1):
        if result["status"] == "TERMINAL" or (result["pending"] or {}).get("key") != g["key"]:
            # an input for a question that is not current, or after the end: refused, and nothing after it is applied
            raise SurveyError(
                409, "INPUT_NOT_CURRENT", "That is not the question the test is waiting for",
                [{"index": n - 1, "current": (result["pending"] or {}).get("key"), "given": g["key"]}],
            )  # fmt: skip
        result = execute_inputs(bundle, replayed, given[:n])
        accepted = g["key"] in result["asked"]
        code_ = next(
            (e["code"] for e in reversed(result["events"]) if e["kind"] == "REJECT" and e["key"] == g["key"]), None
        )
        out.append(
            {
                "seq": n, "key": g["key"], "answer": g["answer"], "accepted": accepted,
                "rejection_code": None if accepted else (code_ or "REJECTED"), "run_status": result["status"],
            }
        )  # fmt: skip
    fingerprint = sha256_hex(json.loads(json.dumps(result, default=str)))
    return base | {
        "testable": True, "facts": clean, "facts_sha256": sha256_hex(clean), "inputs": out,
        "status": result["status"], "run": result, "run_sha256": fingerprint,
    }  # fmt: skip
