# ruff: noqa: E501 — records are kept one per line
"""EVAL-2B — execution assurance of a SYNTHETIC journey. Pure: no database, clock, randomness or model.

This is NOT an execution engine and it executes nothing. The authoritative SS-03B engine already records, for every
run, a trace of what it did: module entries with their conditions, statements said, questions asked, answers,
refusals, routes, decisions and the ending. This module VERIFIES such a recorded trace against the documents the
simulation pinned — the published survey version, its modules, items and wordings — and against the recorded inputs.

It answers one question per check, and none of them is about controls:

  did the recorded simulation still recompute to its record?              INTEGRITY
  is the trace itself whole?                                              TRACE_WELL_FORMED
  was everything delivered a part of the pinned version, once?            DELIVERIES_EXPECTED
  was every delivery the exact pinned wording?                            WORDING_EXACT
  was every accepted answer valid, and every invalid one refused?         ANSWERS_AND_REJECTIONS
  does every branch follow an edge of the pinned module, on evidence?     BRANCHING
  were modules entered in the pinned order, and nothing owed left out?    MODULE_SEQUENCE
  did the survey end the way its recorded routes say?                     TERMINATION

and, for a coordinated journey, whether the surveys run are the governed selection in the governed order.

Kept apart, always: survey completion, control satisfaction, evidence coverage, execution fidelity, and operational
call eligibility. A question the published survey logic left out is a VALID EXCLUSION, not a deviation; whether a
control then lacks evidence is a coverage matter (EVAL-2A). A simulation proves nothing about what a person heard.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.domain.survey.canonical import sha256_hex
from app.domain.survey.documents import Bundle
from app.domain.survey.execution import CONTRACT as EXECUTION_CONTRACT
from app.domain.survey.execution import validate_answer
from app.domain.survey.wording import render

CONTRACT = "call360.survey.execution-assurance/1"
STATUSES = ("VERIFIED", "INCOMPLETE", "DEVIATION_DETECTED", "INTEGRITY_FAILED", "NOT_ASSESSABLE")
SURVEY_CHECKS = (
    "INTEGRITY", "TRACE_WELL_FORMED", "DELIVERIES_EXPECTED", "WORDING_EXACT", "ANSWERS_AND_REJECTIONS", "BRANCHING",
    "MODULE_SEQUENCE", "TERMINATION",
)  # fmt: skip
JOURNEY_CHECKS = ("SELECTION_RECORDED", "GOVERNED_ORDER", "NO_BYPASS", "OWN_EVIDENCE", "NO_DEDUPLICATION")
QUESTION = {
    "INTEGRITY": "Does the recorded simulation still recompute to its recorded fingerprints?",
    "TRACE_WELL_FORMED": "Is the recorded trace whole: every event once, in order, nothing after the end?",
    "DELIVERIES_EXPECTED": "Was everything delivered a part of the pinned survey version, and delivered once?",
    "WORDING_EXACT": "Was every statement and question delivered in its exact pinned wording?",
    "ANSWERS_AND_REJECTIONS": "Was every accepted answer valid, and every invalid answer refused and recorded?",
    "BRANCHING": "Does every branch follow an edge of the pinned module, on recorded evidence?",
    "MODULE_SEQUENCE": "Were modules entered in the pinned order, and was nothing that was owed left out?",
    "TERMINATION": "Did the survey end the way its recorded routes say?",
    "SELECTION_RECORDED": "Are the surveys of this journey the recorded governed selection?",
    "GOVERNED_ORDER": "Were the surveys started in the governed order?",
    "NO_BYPASS": "Was every survey started only after the one before it reached COMPLETED?",
    "OWN_EVIDENCE": "Does each survey have its own execution evidence?",
    "NO_DEDUPLICATION": "Is every selected requirement still present, with none merged or dropped?",
}
ELIGIBILITY = {
    "status": "NOT_ESTABLISHED",
    "note": "Operational call eligibility is not established by any execution-assurance result, including VERIFIED.",
}
NOTE = (
    "EXECUTION ASSURANCE OF A SIMULATION. It verifies the recorded trace of a synthetic journey against the survey "
    "versions it pinned. VERIFIED means the supported technical checks passed for that recording. It is not a "
    "compliance outcome, it says nothing of whether controls are satisfied or covered, it does not show that a person "
    "heard any wording, and it establishes nothing about a real call."
)
#: why a placement of the pinned version has no delivery in the recording, and whether that is as the survey says
EXCLUSION = {
    "SKIPPED_FALSE": (
        "VALID_CONDITIONAL_EXCLUSION",
        "The module's published entry condition is false for this application",
    ),
    "SKIPPED_UNKNOWN": (
        "EXCLUDED_INFORMATION_MISSING",
        "The module's entry condition could not be decided and its published policy is to skip",
    ),
    "HALTED_MISSING_INFORMATION": (
        "EXCLUDED_INFORMATION_MISSING",
        "The survey halted here: information the entry condition needs is missing",
    ),
    "SKIPPED_PRIOR_OUTCOME": (
        "VALID_ROUTING_EXCLUSION",
        "The module is entered only after an outcome that did not occur",
    ),
    "SKIPPED_BY_ROUTE": ("VALID_ROUTING_EXCLUSION", "A published survey route passed over this module"),
}


def _finding(code: str, text: str, **evidence: Any) -> dict[str, Any]:
    return {"code": code, "text": text, "evidence": {k: v for k, v in evidence.items() if v is not None}}


def _check(
    name: str,
    findings: Sequence[Mapping[str, Any]],
    *,
    examined: int,
    incomplete: str | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    status = "FAILED" if findings else "INCOMPLETE" if incomplete else "PASSED"
    return {
        "check": name,
        "question": QUESTION[name],
        "status": status,
        "examined": examined,
        "findings": list(findings),
        "incomplete_because": incomplete,
        "notes": list(notes),
    }


def placements_of(bundle: Bundle) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for inst in bundle.survey.get("sequence") or []:
        m = bundle.module_of(inst)
        for n in (m or {}).get("nodes", []):
            if n.get("type") == "DECISION" or not n.get("item"):
                continue
            item, wording = bundle.item_of(n), bundle.wording_of(n)
            out[f"{inst['instance']}/{n['node']}"] = {
                "instance": inst["instance"],
                "node": n["node"],
                "ref": dict(n["item"]),
                "item": item,
                "wording": wording,
            }
    return out


def verify_survey(
    bundle: Bundle, facts: Mapping[str, Any], run: Mapping[str, Any], recorded: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify ONE recorded run. ``recorded``: inputs[{key, answer, accepted, rejection_code}], replay_consistent,
    steps_consistent (None when not computed), engine_contract, drift."""
    events = list(run["events"])
    places = placements_of(bundle)
    seq = [i["instance"] for i in bundle.survey.get("sequence") or []]
    modules = {i["instance"]: bundle.module_of(i) or {} for i in bundle.survey.get("sequence") or []}
    status_of = {m["instance"]: m["status"] for m in run["modules"]}
    terminal = run.get("terminal")
    checks: list[dict[str, Any]] = []

    # ---- INTEGRITY
    f: list[dict[str, Any]] = []
    if not recorded.get("replay_consistent", False):
        f.append(
            _finding(
                "REPLAY_DRIFT",
                "The simulation no longer recomputes to its recorded result",
                drift=recorded.get("drift"),
            )
        )
    if recorded.get("steps_consistent") is False:
        f.append(
            _finding(
                "STEP_FINGERPRINT_DIFFERS",
                "The run after one of the recorded inputs does not recompute to the fingerprint recorded with that input",
                steps=recorded.get("step_mismatches"),
            )
        )
    checks.append(_check("INTEGRITY", f, examined=1 + len(recorded.get("inputs") or [])))
    integrity_failed = bool(f)

    # ---- TRACE_WELL_FORMED
    f = []
    ats = [e.get("at") for e in events]
    if ats != list(range(len(events))):
        seen: set[Any] = set()
        dup = sorted({a for a in ats if a in seen or seen.add(a)}, key=str)  # type: ignore[func-returns-value]
        missing = sorted(
            set(range(max([a for a in ats if isinstance(a, int)], default=-1) + 1))
            - {a for a in ats if isinstance(a, int)}
        )
        if dup:
            f.append(_finding("DUPLICATE_EVENT", "An execution event is recorded more than once", events=dup))
        if missing:
            f.append(_finding("MISSING_EVENT", "The trace has a gap: an execution event is missing", events=missing))
        if not dup and not missing:
            f.append(_finding("EVENTS_OUT_OF_ORDER", "The execution events are not in their recorded order"))
    ends = [e for e in events if e["kind"] == "END"]
    if len(ends) > 1:
        f.append(
            _finding(
                "DUPLICATE_EVENT", "The survey's ending is recorded more than once", events=[e["at"] for e in ends]
            )
        )
    if ends and events[-1]["kind"] != "END":
        f.append(
            _finding(
                "EVENT_AFTER_END",
                "Something is recorded after the survey ended",
                events=[e["at"] for e in events[events.index(ends[0]) + 1 :]],
            )
        )
    checks.append(_check("TRACE_WELL_FORMED", f, examined=len(events)))

    # ---- DELIVERIES_EXPECTED and WORDING_EXACT
    f, fw = [], []
    deliveries: list[dict[str, Any]] = []
    said = [e for e in events if e["kind"] in ("ASK", "SAY")]
    counted: dict[str, int] = {}
    for e in said:
        key = e.get("key")
        counted[key] = counted.get(key, 0) + 1
        p = places.get(key)
        line: dict[str, Any] = {
            "placement": key,
            "event": e["at"],
            "kind": "STATEMENT" if e["kind"] == "SAY" else "QUESTION",
            "item": e.get("item"),
            "recorded_text": e.get("text"),
            "wording": "NOT_CHECKED",
        }
        deliveries.append(line)
        if p is None:
            f.append(
                _finding(
                    "UNEXPECTED_DELIVERY",
                    f"{key} was delivered, and the pinned survey version has no such placement",
                    placement=key,
                    event=e["at"],
                )
            )
            line["wording"] = "UNEXPECTED"
            continue
        if e.get("item") != p["ref"]:
            f.append(
                _finding(
                    "DELIVERY_ITEM_DIFFERS",
                    f"{key} was delivered as another item or revision than the pinned version places there",
                    placement=key,
                    event=e["at"],
                    pinned=p["ref"],
                    recorded=e.get("item"),
                )
            )
        wording = p["wording"]
        if wording is None:
            fw.append(
                _finding(
                    "WORDING_NOT_PINNED", f"The pinned version holds no wording for {key}", placement=key, event=e["at"]
                )
            )
            line["wording"] = "NOT_PINNED"
            continue
        pinned_text = render(str(wording.get("text") or "").strip(), bundle.fields, facts)["text"]
        line |= {
            "wording_version": p["ref"].get("wording_version"), "wording_sha256": sha256_hex({"item": p["ref"]["code"], "wording_version": p["ref"].get("wording_version"), "text": wording.get("text")}),
            "delivery_mode": wording.get("delivery_mode"), "expected_text": pinned_text,
        }  # fmt: skip
        if pinned_text is None or e.get("text") != pinned_text:
            fw.append(
                _finding(
                    "WORDING_ALTERED",
                    f"{key} was not delivered in its exact pinned wording",
                    placement=key,
                    event=e["at"],
                    expected=pinned_text,
                    recorded=e.get("text"),
                )
            )
            line["wording"] = "ALTERED"
        elif e["kind"] == "SAY" and e.get("delivery_mode") not in (None, wording.get("delivery_mode")):
            fw.append(
                _finding(
                    "DELIVERY_MODE_DIFFERS",
                    f"{key} was delivered in another mode than its pinned wording allows",
                    placement=key,
                    event=e["at"],
                    pinned=wording.get("delivery_mode"),
                    recorded=e.get("delivery_mode"),
                )
            )
            line["wording"] = "MODE_DIFFERS"
        else:
            line["wording"] = "EXACT"
    for key, n in counted.items():
        if n > 1:
            f.append(
                _finding(
                    "DUPLICATE_DELIVERY",
                    f"{key} was delivered {n} times; a placement is delivered at most once",
                    placement=key,
                    events=[e["at"] for e in said if e.get("key") == key],
                )
            )
    # the run's own list of what was delivered, against its events: a delivery that is in one and not the other
    listed = [d["key"] for d in run.get("delivered", [])]
    answered_keys = {e["key"] for e in events if e["kind"] == "ANSWER"}
    owed = [e["key"] for e in said if e["kind"] == "SAY" or e["key"] in answered_keys]
    for key in sorted(set(owed) - set(listed)):
        f.append(
            _finding(
                "MISSING_RECORDED_DELIVERY",
                f"{key} appears in the trace as delivered, and the record of deliveries does not have it",
                placement=key,
            )
        )
    for key in sorted(set(listed) - {e["key"] for e in said}):
        f.append(
            _finding(
                "DELIVERY_WITHOUT_EVENT",
                f"The record of deliveries has {key}, and the trace has no event that delivered it",
                placement=key,
            )
        )
    for d in run.get("delivered", []):
        ev = next((e for e in said if e.get("key") == d["key"]), None)
        if ev is not None and d.get("text") != ev.get("text"):
            fw.append(
                _finding(
                    "WORDING_ALTERED",
                    f"The recorded delivery of {d['key']} does not carry the wording its trace event carries",
                    placement=d["key"],
                    event=ev["at"],
                    expected=ev.get("text"),
                    recorded=d.get("text"),
                )
            )
    checks.append(_check("DELIVERIES_EXPECTED", f, examined=len(said)))
    checks.append(
        _check(
            "WORDING_EXACT",
            fw,
            examined=len(said),
            notes=["Compared with the pinned wording as text. A simulation does not show that a person heard it."],
        )
    )

    # ---- ANSWERS_AND_REJECTIONS
    f = []
    rejections: list[dict[str, Any]] = []
    asked_at: dict[str, int] = {}
    for e in events:
        if e["kind"] == "ASK":
            asked_at.setdefault(e["key"], e["at"])
        elif e["kind"] in ("ANSWER", "REJECT"):
            p = places.get(e.get("key"))
            if e["key"] not in asked_at:
                f.append(
                    _finding(
                        "ANSWER_WITHOUT_QUESTION",
                        f"An answer to {e['key']} is recorded, and the question was not asked before it",
                        placement=e["key"],
                        event=e["at"],
                    )
                )
            if p is None or p["item"] is None:
                continue
            code = validate_answer(p["item"], bundle.options_of(p["item"]), e.get("answer") or {})
            if e["kind"] == "ANSWER" and code is not None:
                f.append(
                    _finding(
                        "INVALID_ANSWER_ACCEPTED",
                        f"The answer recorded as accepted at {e['key']} is one the survey's own validation refuses ({code})",
                        placement=e["key"],
                        event=e["at"],
                        rejection=code,
                    )
                )
            if e["kind"] == "REJECT":
                rejections.append(
                    {"placement": e["key"], "event": e["at"], "code": e.get("code"), "answer": e.get("answer")}
                )
                if code != e.get("code"):
                    f.append(
                        _finding(
                            "REJECTION_CODE_DIFFERS",
                            f"The refusal recorded at {e['key']} ({e.get('code')}) is not what the survey's own validation gives ({code})",
                            placement=e["key"],
                            event=e["at"],
                        )
                    )
    counts: dict[str, int] = {}
    for e in events:
        if e["kind"] == "ANSWER":
            counts[e["key"]] = counts.get(e["key"], 0) + 1
    for key, n in counts.items():
        if n > 1:
            f.append(
                _finding(
                    "DUPLICATE_ANSWER", f"{key} has {n} accepted answers; a question is answered once", placement=key
                )
            )
    inputs = list(recorded.get("inputs") or [])
    refused_inputs = [(i["key"], i.get("rejection_code")) for i in inputs if not i["accepted"]]
    refused_events = [(r["placement"], r["code"]) for r in rejections]
    if sorted(map(str, refused_inputs)) != sorted(map(str, refused_events)):
        f.append(
            _finding(
                "REJECTION_NOT_RECORDED",
                "The inputs recorded as refused and the refusals in the trace are not the same",
                inputs=[list(x) for x in refused_inputs],
                trace=[list(x) for x in refused_events],
            )
        )
    accepted_inputs = [(i["key"], sha256_hex(i["answer"])) for i in inputs if i["accepted"]]
    accepted_events = [(e["key"], sha256_hex(e.get("answer") or {})) for e in events if e["kind"] == "ANSWER"]
    if accepted_inputs != accepted_events:
        f.append(
            _finding(
                "ANSWER_NOT_AS_RECORDED",
                "The inputs recorded as accepted and the answers in the trace are not the same, in the same order",
                inputs=[x[0] for x in accepted_inputs],
                trace=[x[0] for x in accepted_events],
            )
        )
    checks.append(_check("ANSWERS_AND_REJECTIONS", f, examined=len(inputs)))

    # ---- BRANCHING
    f = []
    branches: list[dict[str, Any]] = []
    omitted: dict[str, int] = {}
    notes: list[str] = []
    for inst in seq:
        m = modules[inst]
        edges = {x["edge"]: x for x in m.get("edges", [])}
        nodes = {n["node"] for n in m.get("nodes", [])}
        mine = [
            e
            for e in events
            if e.get("instance") == inst
            and e["kind"] in ("ASK", "SAY", "ANSWER", "ROUTE", "DECISION", "QUEUE", "MODULE_END")
        ]
        if not mine:
            continue
        queued = any(e["kind"] == "QUEUE" for e in mine)
        if queued:
            notes.append(
                f"{inst}: follow-up questions were queued from a multiple-choice answer; the order of a queue is checked against the recorded queue, not against single edges"
            )
        expected: str | None = m.get("entry")
        evidence_for: set[str] = set()
        for e in mine:
            if e["kind"] in ("ASK", "SAY", "DECISION"):
                if not queued and expected is not None and e["node"] != expected and e["kind"] != "DECISION":
                    f.append(
                        _finding(
                            "TRANSITION_UNEXPLAINED",
                            f"{inst}/{e['node']} was delivered, and the recorded route led to {inst}/{expected}",
                            placement=e.get("key"),
                            event=e["at"],
                            expected=f"{inst}/{expected}",
                        )
                    )
                if not queued and expected is None and e["kind"] != "DECISION":
                    f.append(
                        _finding(
                            "TRANSITION_UNEXPLAINED",
                            f"{inst}/{e['node']} was delivered after the module's recorded route had already left it",
                            placement=e.get("key"),
                            event=e["at"],
                        )
                    )
                if e["kind"] == "SAY":
                    evidence_for.add(e["node"])
            if e["kind"] == "ANSWER":
                evidence_for.add(e["node"])
            if e["kind"] in ("ROUTE", "DECISION"):
                to = e.get("to") or {}
                line = {
                    "instance": inst,
                    "node": e["node"],
                    "event": e["at"],
                    "kind": e["kind"],
                    "via": e.get("via"),
                    "edge": e.get("edge"),
                    "to": to,
                    "explanation": e.get("explanation"),
                    "condition": e.get("condition"),
                }
                branches.append(line)
                edge = edges.get(e.get("edge")) if e.get("edge") else None
                if e.get("edge") and edge is None:
                    f.append(
                        _finding(
                            "ROUTE_NOT_IN_VERSION",
                            f"The route recorded at {inst}/{e['node']} uses edge {e['edge']}, which the pinned module does not have",
                            event=e["at"],
                        )
                    )
                elif edge is not None:
                    on_ok = edge["on"] == e.get("via") or (
                        e["kind"] == "ROUTE" and not e.get("specific") and edge["on"] == "ANY"
                    )
                    if edge["from"] != e["node"] or edge["to"] != to or not on_ok:
                        f.append(
                            _finding(
                                "ROUTE_DIFFERS_FROM_VERSION",
                                f"The route recorded at {inst}/{e['node']} is not the pinned module's edge {e['edge']}",
                                event=e["at"],
                                pinned=edge,
                                recorded={"via": e.get("via"), "to": to},
                            )
                        )
                if to.get("node") and to["node"] not in nodes:
                    f.append(
                        _finding(
                            "ROUTE_NOT_IN_VERSION",
                            f"The route recorded at {inst}/{e['node']} leads to {to['node']}, which the pinned module does not have",
                            event=e["at"],
                        )
                    )
                if e["kind"] == "ROUTE" and e["node"] not in evidence_for:
                    f.append(
                        _finding(
                            "ROUTE_WITHOUT_EVIDENCE",
                            f"A branch is recorded at {inst}/{e['node']} with no recorded answer or delivery to decide it",
                            event=e["at"],
                        )
                    )
                if (
                    e["kind"] == "ROUTE"
                    and edge is not None
                    and e.get("specific")
                    and edge["on"] not in ("AFTER_CAPTURE", "ANY")
                ):
                    ans = next(
                        (x.get("answer") or {} for x in mine if x["kind"] == "ANSWER" and x["node"] == e["node"]), {}
                    )
                    chosen = [ans["choice"]] if ans.get("choice") is not None else list(ans.get("choices") or [])
                    if chosen and edge["on"] not in chosen:
                        f.append(
                            _finding(
                                "ROUTE_NOT_SUPPORTED_BY_ANSWER",
                                f"The branch recorded at {inst}/{e['node']} is for the answer {edge['on']}, and the recorded answer is {', '.join(map(str, chosen))}",
                                event=e["at"],
                            )
                        )
                expected = to.get("node") if "node" in to else None
                if "node" not in to:
                    expected = None
                    owed_node = None
                else:
                    owed_node = to["node"]
                omitted.pop(inst, None)
                if owed_node is not None:
                    omitted[inst] = e["at"]
            if e["kind"] in ("ASK", "SAY", "DECISION") and not queued:
                omitted.pop(inst, None)
        # a recorded route led to a node, the module is over, and that node was never delivered: an omission
        if not queued and inst in omitted and status_of.get(inst) == "ACTIVATED":
            target = next(e for e in mine if e["at"] == omitted[inst])["to"]["node"]
            f.append(
                _finding(
                    "EXECUTION_OMISSION",
                    f"A recorded route led to {inst}/{target}; the module ended and it was never delivered",
                    placement=f"{inst}/{target}",
                    event=omitted[inst],
                )
            )
    checks.append(
        _check(
            "BRANCHING",
            f,
            examined=len(branches),
            notes=notes
            + ["A decision's recorded condition result is shown as recorded; conditions are not evaluated again here."],
        )
    )
    omission_keys = {x["evidence"].get("placement") for x in f if x["code"] == "EXECUTION_OMISSION"}

    # ---- MODULE_SEQUENCE, and why each undelivered placement has no delivery
    f = []
    entries = [e for e in events if e["kind"] == "ENTRY"]
    order = [seq.index(e["instance"]) if e["instance"] in seq else -1 for e in entries]
    if -1 in order:
        f.append(
            _finding(
                "MODULE_NOT_IN_VERSION",
                "A module was entered that the pinned survey version does not have",
                events=[e["at"] for e, o in zip(entries, order, strict=True) if o == -1],
            )
        )
    if order != sorted(order) or len(set(order)) != len(order):
        f.append(
            _finding(
                "MODULE_ORDER_DIFFERS",
                "Modules were not entered in the pinned sequence, or one was entered twice",
                order=[e["instance"] for e in entries],
            )
        )
    entered = {e["instance"]: e for e in entries}
    passed_over = {s: e["at"] for e in events if e["kind"] == "SURVEY_ROUTE" for s in (e.get("skipped") or [])}
    disposed = {e["instance"]: e["at"] for e in events if e["kind"] == "DISPOSITION"}
    # a recorded survey route or disposition that leads to a later module passes over every module in between
    jumps = [
        (seq.index(e["instance"]), seq.index(e["to"]["instance"]))
        for e in events
        if e["kind"] in ("SURVEY_ROUTE", "DISPOSITION")
        and isinstance(e.get("to"), Mapping)
        and e["to"].get("instance") in seq
        and e.get("instance") in seq
    ]
    for inst in seq:
        st = status_of.get(inst, "NOT_REACHED")
        if (
            st
            in (
                "ACTIVATED",
                "RUNNING",
                "SKIPPED_FALSE",
                "SKIPPED_UNKNOWN",
                "SKIPPED_PRIOR_OUTCOME",
                "HALTED_MISSING_INFORMATION",
            )
            and inst not in entered
        ):
            f.append(
                _finding(
                    "MODULE_STATUS_UNSUPPORTED",
                    f"{inst} is recorded as {st.lower().replace('_', ' ')}, and the trace has no entry event for it",
                    instance=inst,
                )
            )
        if st == "SKIPPED_BY_ROUTE" and inst not in passed_over and not any(a < seq.index(inst) < b for a, b in jumps):
            f.append(
                _finding(
                    "MODULE_STATUS_UNSUPPORTED",
                    f"{inst} is recorded as passed over by a route, and no recorded survey route passes over it",
                    instance=inst,
                )
            )
        if st == "ACTIVATED" and not any(e["kind"] == "MODULE_END" and e["instance"] == inst for e in events):
            f.append(
                _finding(
                    "MISSING_TRANSITION",
                    f"{inst} is recorded as completed, and the trace has no event that ends it",
                    instance=inst,
                )
            )
        if (
            inst in entered
            and entered[inst].get("status") not in (None, st)
            and not (
                st == "RUNNING" and entered[inst].get("status") == "ACTIVATED"
            )  # still running: entered, not yet ended
        ):
            f.append(
                _finding(
                    "MODULE_STATUS_UNSUPPORTED",
                    f"{inst} is recorded as {st}, and its entry event says {entered[inst].get('status')}",
                    instance=inst,
                    event=entered[inst]["at"],
                )
            )
    exclusions: list[dict[str, Any]] = []
    delivered_keys = {e["key"] for e in said}
    pending_key = (run.get("pending") or {}).get("key")
    for key, p in places.items():
        if key in delivered_keys:
            continue
        inst = p["instance"]
        st = status_of.get(inst, "NOT_REACHED")
        if key in omission_keys:
            cls, why, ev = "OMISSION", "A recorded route led here and it was never delivered", None
        elif st in EXCLUSION:
            cls, why = EXCLUSION[st]
            ev = entered.get(inst, {}).get("at", disposed.get(inst, passed_over.get(inst)))
        elif st == "ACTIVATED":
            cls, why, ev = (
                "NOT_ON_PATH_TAKEN",
                "The recorded answers led along another published branch of this module",
                next((b["event"] for b in branches if b["instance"] == inst), None),
            )
        elif terminal is not None:
            cls, why, ev = (
                "SURVEY_ENDED_BEFORE",
                f"The survey ended ({terminal.get('state')}) before this was reached",
                ends[0]["at"] if ends else None,
            )
        else:
            cls, why, ev = (
                ("AWAITING_ANSWER", "This question is the one waiting for an answer", None)
                if key == pending_key
                else ("NOT_YET_REACHED", "The simulation has not reached this yet", None)
            )
        exclusions.append(
            {"placement": key, "item": p["ref"], "class": cls, "why": why, "event": ev, "module_status": st}
        )
    checks.append(_check("MODULE_SEQUENCE", f, examined=len(seq)))

    # ---- TERMINATION
    f = []
    ending: dict[str, Any] | None = None
    if terminal is None:
        if ends:
            f.append(
                _finding(
                    "UNEXPECTED_TERMINATION",
                    "The trace records an ending, and the run is not recorded as ended",
                    event=ends[0]["at"],
                )
            )
        checks.append(
            _check(
                "TERMINATION",
                f,
                examined=0,
                incomplete="The simulation has not ended: a question is waiting, or a non-answer is unresolved",
            )
        )
    else:
        state = terminal.get("state")
        ending = {
            "state": state,
            "survey_outcome": terminal.get("survey_outcome"),
            "reason": terminal.get("reason"),
            "completed": state == "COMPLETED",
        }
        if not ends:
            f.append(_finding("MISSING_EVENT", "The run is recorded as ended, and the trace has no ending event"))
        elif ends[0].get("status") != state:
            f.append(
                _finding(
                    "UNEXPECTED_TERMINATION",
                    f"The run is recorded as {state}, and the trace's ending event says {ends[0].get('status')}",
                    event=ends[0]["at"],
                )
            )
        left = [i for i in seq if status_of.get(i, "NOT_REACHED") in ("NOT_REACHED", "RUNNING")]
        if state == "COMPLETED" and left:
            f.append(
                _finding(
                    "UNEXPECTED_TERMINATION",
                    f"The survey is recorded as completed, and {', '.join(left)} was never reached",
                    instances=left,
                )
            )
        if state == "ENDED_WITH_OUTCOME":
            outcome = terminal.get("survey_outcome")
            routed = [
                e
                for e in events
                if e["kind"] in ("SURVEY_ROUTE", "DISPOSITION")
                and isinstance(e.get("to"), Mapping)
                and e["to"].get("survey_outcome") == outcome
            ]
            if not routed:
                f.append(
                    _finding(
                        "UNEXPECTED_TERMINATION",
                        f"The survey ended with outcome {outcome}, and no recorded survey route leads to it",
                        event=ends[0]["at"] if ends else None,
                    )
                )
            else:
                ending["routed_by_event"] = routed[-1]["at"]
        checks.append(_check("TERMINATION", f, examined=1))

    failed = [c for c in checks if c["status"] == "FAILED"]
    if integrity_failed:
        status = "INTEGRITY_FAILED"
    elif failed:
        status = "DEVIATION_DETECTED"
    elif terminal is None:
        status = "INCOMPLETE"
    else:
        status = "VERIFIED"
    for d in deliveries:
        # a question that was asked and is still waiting: delivered, not answered — neither an exclusion nor an omission
        d["awaiting_answer"] = d["placement"] == pending_key and terminal is None
    by_class: dict[str, int] = {}
    for x in exclusions:
        by_class[x["class"]] = by_class.get(x["class"], 0) + 1
    return {
        "status": status, "checks": checks, "deliveries": deliveries, "exclusions": exclusions, "branches": branches, "rejections": rejections,
        "ending": ending, "pending": pending_key,
        "counts": {
            "placements": len(places), "delivered": len(delivered_keys & set(places)), "wording_exact": sum(1 for d in deliveries if d["wording"] == "EXACT"),
            "answers": sum(1 for e in events if e["kind"] == "ANSWER"), "refused_inputs": len(rejections), "branches": len(branches), "events": len(events),
            "findings": sum(len(c["findings"]) for c in checks), "not_delivered": by_class,
        },
    }  # fmt: skip


def not_assessable(reason_code: str, text: str) -> dict[str, Any]:
    return {
        "status": "NOT_ASSESSABLE", "checks": [], "deliveries": [], "exclusions": [], "branches": [], "rejections": [], "ending": None, "pending": None,
        "counts": {"placements": 0, "delivered": 0, "wording_exact": 0, "answers": 0, "refused_inputs": 0, "branches": 0, "events": 0, "findings": 0, "not_delivered": {}},
        "not_assessable": {"code": reason_code, "text": text},
    }  # fmt: skip


def not_started() -> dict[str, Any]:
    out = not_assessable("NOT_STARTED", "This survey was not started, so there is no execution to verify")
    return out | {"status": "INCOMPLETE"}


def verify_coordination(journey: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The journey-level checks of a coordinated simulation, from ASG-2B's own records. ``journey``: selected[] (the
    composite's governed selection, in order: group, survey_version_id), composite_intact, surveys[] (position,
    group, survey_version_id, state, simulation_id), steps[] (position, group_code, survey_version_id, simulation_id,
    started_because), status."""
    selected, surveys, steps = (
        list(journey["selected"]),
        list(journey["surveys"]),
        sorted(journey["steps"], key=lambda s: s["position"]),
    )
    checks = []
    f: list[dict[str, Any]] = []
    if not journey["composite_intact"]:
        f.append(
            _finding(
                "COMPOSITE_NOT_INTACT", "The composite plan this journey was started from is no longer the recorded one"
            )
        )
    want = [(s["group"], str(s["survey_version_id"])) for s in selected]
    got = [(s["group"], str(s["survey_version_id"])) for s in surveys]
    if want != got:
        f.append(
            _finding(
                "SELECTION_DIFFERS",
                "The surveys of the journey are not the recorded governed selection",
                selected=[list(x) for x in want],
                journey=[list(x) for x in got],
            )
        )
    checks.append(_check("SELECTION_RECORDED", f, examined=len(selected)))

    f = []
    for n, step in enumerate(steps, start=1):
        if step["position"] != n:
            f.append(
                _finding(
                    "ORDER_DIFFERS",
                    f"The surveys were not started one after another from the first: a start is recorded at position {step['position']} where {n} was due",
                    position=step["position"],
                )
            )
            break
        if n <= len(want) and (step["group_code"], str(step["survey_version_id"])) != want[n - 1]:
            f.append(
                _finding(
                    "ORDER_DIFFERS",
                    f"Position {n} of the governed order is {want[n - 1][0]}, and {step['group_code']} was started there",
                    position=n,
                    governed=want[n - 1][0],
                    started=step["group_code"],
                )
            )
        if n > len(want):
            f.append(
                _finding(
                    "ORDER_DIFFERS",
                    f"A survey was started at position {n}, and the governed selection has {len(want)} surveys",
                    position=n,
                )
            )
    checks.append(_check("GOVERNED_ORDER", f, examined=len(steps)))

    f = []
    state_at = {s["position"]: s["state"] for s in surveys}
    for step in steps:
        n = step["position"]
        if n == 1:
            if step["started_because"] != "FIRST_IN_ORDER":
                f.append(
                    _finding(
                        "START_REASON_DIFFERS",
                        "The first survey is not recorded as started first in the order",
                        position=1,
                    )
                )
            continue
        if step["started_because"] != "PREVIOUS_COMPLETED" or state_at.get(n - 1) != "COMPLETED":
            f.append(
                _finding(
                    "SURVEY_BYPASSED",
                    f"Survey {n} was started although survey {n - 1} did not reach COMPLETED ({str(state_at.get(n - 1)).lower()}): an unresolved survey was passed over",
                    position=n,
                    previous_state=state_at.get(n - 1),
                )
            )
    checks.append(_check("NO_BYPASS", f, examined=len(steps)))

    f = []
    sims = [str(s["simulation_id"]) for s in steps]
    if len(set(sims)) != len(sims):
        f.append(
            _finding(
                "EVIDENCE_SHARED",
                "Two surveys of the journey refer to the same simulation: each survey must have its own execution evidence",
                simulations=sims,
            )
        )
    for s in surveys:
        step = next((x for x in steps if x["position"] == s["position"]), None)
        if (step is None) != (s.get("simulation_id") is None) or (
            step is not None and str(step["simulation_id"]) != str(s["simulation_id"])
        ):
            f.append(
                _finding(
                    "EVIDENCE_REFERENCE_DIFFERS",
                    f"Survey {s['position']} does not refer to the simulation recorded when it was started",
                    position=s["position"],
                )
            )
    checks.append(_check("OWN_EVIDENCE", f, examined=len(steps)))

    f = []
    if len(surveys) != len(selected):
        f.append(
            _finding(
                "REQUIREMENT_MISSING",
                f"The governed selection has {len(selected)} requirements and the journey has {len(surveys)}: a requirement disappeared or was merged",
                selected=len(selected),
                journey=len(surveys),
            )
        )
    versions = [str(s["survey_version_id"]) for s in selected]
    if len(set(versions)) != len(versions):
        f.append(
            _finding(
                "DUPLICATE_REQUIREMENT_UNRESOLVED",
                "The same survey version is required more than once. Whether it is then run once or more is undecided, so this journey should not have been started",
            )
        )
    checks.append(_check("NO_DEDUPLICATION", f, examined=len(selected)))
    return checks


def assure_journey(journey: Mapping[str, Any], surveys: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The assurance result of one journey. ``surveys``: each a survey reference (position, survey_code, …, state,
    simulation_id, run_sha256, engine_contract) with ``result`` = its ``verify_survey`` result. Deterministic."""
    journey_checks = verify_coordination(journey) if journey["kind"] == "COORDINATED" else []
    lines = []
    for s in surveys:
        r = s["result"]
        lines.append({k: v for k, v in s.items() if k != "result"} | r)
    statuses = [x["status"] for x in lines]
    journey_failed = [c for c in journey_checks if c["status"] == "FAILED"]
    integrity = "INTEGRITY_FAILED" in statuses or any(
        f["code"] == "COMPOSITE_NOT_INTACT" for c in journey_checks for f in c["findings"]
    )
    if integrity:
        status = "INTEGRITY_FAILED"
    elif "DEVIATION_DETECTED" in statuses or journey_failed:
        status = "DEVIATION_DETECTED"
    elif "NOT_ASSESSABLE" in statuses:
        status = "NOT_ASSESSABLE"
    elif "INCOMPLETE" in statuses:
        status = "INCOMPLETE"
    else:
        status = "VERIFIED"
    findings = [
        {"scope": f"survey {x['position']}", "survey_code": x["survey_code"], "simulation_id": x.get("simulation_id"), "check": c["check"]} | f
        for x in lines for c in x["checks"] for f in c["findings"]
    ] + [{"scope": "journey", "check": c["check"]} | f for c in journey_checks for f in c["findings"]]  # fmt: skip
    result: dict[str, Any] = {
        "contract": CONTRACT, "execution_contract": EXECUTION_CONTRACT,
        "journey": {"kind": journey["kind"], "id": str(journey["id"]), "status": journey["status"], "complete": bool(journey["complete"])},
        "status": status, "surveys": lines, "journey_checks": journey_checks, "findings": findings,
        "summary": {
            "surveys": len(lines), "by_status": {s: statuses.count(s) for s in STATUSES}, "findings": len(findings),
            "deliveries": sum(x["counts"]["delivered"] for x in lines), "wording_exact": sum(x["counts"]["wording_exact"] for x in lines),
            "refused_inputs": sum(x["counts"]["refused_inputs"] for x in lines),
            "surveys_completed": sum(1 for x in lines if (x.get("ending") or {}).get("completed")),
            "surveys_ended_without_completed": sum(1 for x in lines if x.get("ending") and not x["ending"]["completed"]),
        },
        "operational_call_eligibility": ELIGIBILITY, "note": NOTE,
    }  # fmt: skip
    return result | {"result_sha256": sha256_hex(result)}
