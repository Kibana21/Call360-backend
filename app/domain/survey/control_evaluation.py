# ruff: noqa: E501 — records are kept one per line
"""EVAL-1 — journey-level control evaluation of SYNTHETIC simulations. Pure: no database, clock, randomness or model.

This is NOT a second evaluation engine. Every answer is judged by the existing S3-A evaluator
(``answer_evaluation.evaluate_one``) under a rule of the existing rule language, and every finding is produced by the
existing S3-B finding engine (``finding_engine.generate``) from the market's published finding rule set. What is new:

* an **adapter** that turns SS-03B execution evidence into the existing evaluator's input model, inventing nothing:
  a missing answer stays missing, an unknown stays unknown, a refusal is not given a business meaning;
* a **control outcome** per control instance — the existing engines have none. It follows the combination the
  governed mapping DECLARES (one exists: ``ALL_REQUIRED``); anything this module cannot decide is UNRESOLVED,
  INSUFFICIENT_EVIDENCE or REQUIRES_REVIEW, never SATISFIED;
* a **processing status** of the evaluation, kept apart from survey completion and from control outcomes.

Grain: journey (evaluation run) → survey execution (evidence-producing) → control instance (atomic result) → evidence
observation (one placement of one mapped item in one execution). A completed survey does not make a control
satisfied, and a satisfied control is not a compliance verdict.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import ConditionError, evaluate
from app.domain.survey.documents import Bundle
from app.domain.survey.wording import is_missing

CONTRACT = "call360.survey.control-evaluation/1"
OUTCOMES = ("SATISFIED", "NOT_SATISFIED", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE", "UNRESOLVED", "REQUIRES_REVIEW")
PROCESSING = ("COMPLETED", "INCOMPLETE", "REQUIRES_REVIEW", "FAILED_TECHNICALLY")
#: How a control's evidence combines is DECLARED by its governed mapping. One value exists; nothing else is approved.
COMBINATIONS = ("ALL_REQUIRED",)
EVIDENCE_TYPES = ("ANSWER", "DELIVERY")
#: Survey Studio answer type → the existing evaluator's answer type. A type that is not here has no evaluation
#: method and is reported as unsupported. (Multiple choice is evaluated by SET_MATCH since EVAL-2A.)
ANSWER_TYPE = {
    "YES_NO": "YES_NO", "ACKNOWLEDGEMENT": "ACKNOWLEDGEMENT", "NUMERIC": "NUMERIC", "FREE_TEXT": "FREE_TEXT",
    "SINGLE_SELECT": "ENUM",
    "MULTI_SELECT": "MULTI_SELECT",
}  # fmt: skip
#: observation results that leave a required piece of evidence missing (never read as satisfied, never as failed)
GAPS = (
    "UNRESOLVED", "NOT_ASKED", "MISSING_EXPECTED_FACT", "NOT_APPLICABLE", "NOT_DELIVERED", "UNSUPPORTED_EVIDENCE",
)  # fmt: skip
MODULE_GAP = {
    "SKIPPED_UNKNOWN": "MODULE_ELIGIBILITY_UNKNOWN", "SKIPPED_PRIOR_OUTCOME": "MODULE_SKIPPED_PRIOR_OUTCOME",
    "SKIPPED_BY_ROUTE": "MODULE_SKIPPED_BY_ROUTE", "HALTED_MISSING_INFORMATION": "MODULE_HALTED_MISSING_INFORMATION",
    "NOT_REACHED": "NOT_REACHED", "RUNNING": "NOT_REACHED", "ACTIVATED": "NOT_ON_PATH_TAKEN",
}  # fmt: skip
#: The application's catalog facts are NOT the existing evaluator's policy facts: no approved mapping exists, so none
#: is supplied and a fact-based rule evaluates to MISSING_EXPECTED_FACT.
NO_FACTS = ae.FactSource("SYNTHETIC_APPLICATION_NO_POLICY_FACTS", None, None, {})
COVERAGE_NOTE = (
    "Complete compliance coverage is NOT asserted: no authoritative policy says which controls apply to an "
    "application. Every control of the register is reported, and a control without a published mapping is unresolved."
)
NOTE = (
    "EVALUATION OF A SIMULATION, for a synthetic application. Answers are judged by the existing deterministic "
    "evaluator and findings come from the published finding rules; a match is not a compliance pass, a satisfied "
    "control is not a compliance verdict, and nothing here is an operational finding or a case disposition."
)


def control_sha256(c: Mapping[str, Any]) -> str:
    """The control register has no revisions: this fingerprint of the row stands for 'the control as it was'."""
    return sha256_hex({k: c[k] for k in ("control_code", "name", "owner_role", "content_approval_status")})


def placements(bundle: Bundle) -> list[dict[str, Any]]:
    """Every place of every item in the survey, in sequence order: the key the execution engine uses for it."""
    out = []
    for inst in bundle.survey.get("sequence") or []:
        m = bundle.module_of(inst)
        for n in (m or {}).get("nodes", []):
            ref = n.get("item") or {}
            item = bundle.item_of(n)
            if n.get("type") == "DECISION" or item is None:
                continue
            out.append(
                {
                    "key": f"{inst['instance']}/{n['node']}", "instance": inst["instance"], "node": n["node"],
                    "item_code": ref["code"], "item_version": int(ref["version"]), "wording_version": ref.get("wording_version"),
                    "answer_type": item["answer_type"], "item_name": item.get("name") or item.get("label") or ref["code"],
                }
            )  # fmt: skip
    return out


def _value(answer_type: str, a: Mapping[str, Any]) -> Any:
    """The accepted answer as the existing evaluator reads it. Nothing is coerced beyond the type's own meaning."""
    if answer_type == "YES_NO":
        c = a.get("choice")
        return (
            True if c == "YES" else False if c == "NO" else c
        )  # anything else stays as it is: the evaluator refuses it
    if answer_type == "ACKNOWLEDGEMENT":
        return a.get("acknowledged")
    if answer_type == "NUMERIC":
        return a.get("number")
    if answer_type == "FREE_TEXT":
        return a.get("text")
    if answer_type == "MULTI_SELECT":
        # the selection as submitted and accepted — an empty list is an explicit empty selection, not a missing answer
        return list(a.get("choices") or [])
    return a.get("choice")


def adapt(execution: Mapping[str, Any], p: Mapping[str, Any]) -> dict[str, Any]:
    """SS-03B evidence of one placement → the existing evaluator's inputs (``status``, ``applicable``, ``answer``).

    ``gap`` says, in this module's words, why there is no accepted answer. A refusal reason is never claimed, and a
    module skipped because information was MISSING is 'not asked', not 'not applicable': unknown is not false."""
    run = execution.get("run")
    base: dict[str, Any] = {
        "status": "PENDING",
        "applicable": True,
        "skip_reason": None,
        "answer": None,
        "gap": None,
        "refused_inputs": [],
    }
    if run is None:
        return base | {"gap": "SURVEY_NOT_STARTED"}
    key = p["key"]
    refused = [r["error"] for r in run["rejections"] if r["at"] == key]
    base["refused_inputs"] = refused
    given = next((e for e in run["evidence"] if e["question_instance"] == key), None)
    if given is not None:
        if p["answer_type"] == "FREE_TEXT" and not str(given["answer"].get("text") or "").strip():
            return base | {"status": "UNRESOLVED", "gap": "ANSWERED_BLANK"}
        return base | {
            "status": "COMPLETED",
            "answer": {
                "answer_kind": "ANSWER", "answer_state": run["evidence_states"].get(key),
                "value": _value(p["answer_type"], given["answer"]), "verbatim": None,
            },
        }  # fmt: skip
    if (run.get("pending") or {}).get("key") == key:
        if run["status"] == "POLICY_UNRESOLVED":
            return base | {"status": "UNRESOLVED", "gap": "NON_ANSWER_POLICY_UNRESOLVED"}
        if refused:
            return base | {"status": "UNRESOLVED", "gap": "ASKED_NO_ACCEPTED_ANSWER"}
        return base | {"gap": "AWAITING_ANSWER"}
    module = next((m for m in run["modules"] if m["instance"] == p["instance"]), None)
    mstatus = (module or {}).get("status") or "NOT_REACHED"
    if mstatus == "SKIPPED_FALSE":
        return base | {
            "status": "SKIPPED_BY_CONDITION", "applicable": False, "gap": "MODULE_EXCLUDED_BY_CONDITION",
            "skip_reason": "the survey's eligibility condition for this module is false",
        }  # fmt: skip
    return base | {"gap": MODULE_GAP.get(mstatus, "NOT_REACHED")}


def rule_of(entry: Mapping[str, Any]) -> ae.Rule:
    r, item = entry["rule"], entry["item"]
    return ae.Rule(
        question_code=item["code"], question_revision_id=f"{item['code']}@{item['version']}", revision=int(item["version"]),
        method=r["method"], answer_type=r["answer_type"], options=tuple(r.get("options") or ()), expected=r.get("expected"),
        fact_key=r.get("fact_key"),
    )  # fmt: skip


def _survey_ref(x: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "position": x["position"], "survey_code": x["survey_code"], "version_label": x["version_label"],
        "survey_version_id": str(x["survey_version_id"]), "manifest_sha256": x["manifest_sha256"], "state": x["state"],
    }  # fmt: skip


def observe(execution: Mapping[str, Any], p: Mapping[str, Any], entry: Mapping[str, Any]) -> dict[str, Any]:
    """One evidence observation: one placement of one mapped item in one survey execution."""
    run = execution.get("run")
    key = p["key"]
    delivered = next((d for d in (run or {}).get("delivered", []) if d["key"] == key), None)
    obs: dict[str, Any] = {
        "evidence_type": entry["evidence_type"], "required": bool(entry["required"]),
        "item": {"code": p["item_code"], "version": p["item_version"], "name": p["item_name"], "answer_type": p["answer_type"]},
        "survey": _survey_ref(execution),
        "simulation_id": str(execution["simulation_id"]) if execution.get("simulation_id") else None,
        "run_sha256": execution.get("run_sha256"), "placement": key,
        "wording": (
            {"wording_version": delivered["wording_version"], "delivery_mode": delivered["delivery_mode"], "text": delivered["text"]}
            if delivered else None
        ),
        "trace": [e["at"] for e in (run or {}).get("events", []) if e.get("key") == key],
        "gap": None, "refused_inputs": [], "evaluation": None,
    }  # fmt: skip
    if entry["evidence_type"] == "DELIVERY":
        if delivered:
            return obs | {
                "result": "DELIVERED",
                "explanation": "The exact pinned wording was delivered in this simulation",
            }
        gap = adapt(execution, p)["gap"] or "NOT_DELIVERED"
        return obs | {
            "result": "NOT_DELIVERED",
            "gap": gap,
            "explanation": "This item was not delivered in this simulation; it is never read as delivered",
        }
    if p["answer_type"] not in ANSWER_TYPE:
        return obs | {
            "result": "UNSUPPORTED_EVIDENCE", "gap": "ANSWER_TYPE_NOT_EVALUABLE",
            "explanation": f"The existing evaluator has no method for a {p['answer_type'].replace('_', ' ').lower()} answer; it is not evaluated",
        }  # fmt: skip
    a = adapt(execution, p)
    ev = ae.evaluate_one(rule_of(entry), a["status"], a["applicable"], a["skip_reason"], a["answer"], None, NO_FACTS)
    return obs | {
        "result": ev["result"],
        "gap": a["gap"],
        "refused_inputs": a["refused_inputs"],
        "evaluation": ev,
        "explanation": ev["explanation"],
    }


def _absent(entry: Mapping[str, Any], versions_present: Sequence[int]) -> dict[str, Any]:
    """A mapped item that is in no survey of the journey: the evidence does not exist. Never a pass."""
    item = entry["item"]
    gap = "ITEM_REVISION_NOT_IN_JOURNEY" if versions_present else "ITEM_NOT_IN_JOURNEY"
    obs: dict[str, Any] = {
        "evidence_type": entry["evidence_type"], "required": bool(entry["required"]),
        "item": {"code": item["code"], "version": int(item["version"]), "name": item["code"], "answer_type": (entry.get("rule") or {}).get("answer_type")},
        "survey": None, "simulation_id": None, "run_sha256": None, "placement": None, "wording": None, "trace": [],
        "gap": gap, "refused_inputs": [], "evaluation": None, "versions_in_journey": sorted(versions_present),
    }  # fmt: skip
    if entry["evidence_type"] == "DELIVERY":
        return obs | {
            "result": "NOT_DELIVERED",
            "explanation": "No survey of this journey contains this exact item revision",
        }
    ev = ae.evaluate_one(rule_of(entry), "PENDING", True, None, None, None, NO_FACTS)
    return obs | {
        "result": ev["result"],
        "evaluation": ev,
        "explanation": ev["explanation"] + " (no survey of this journey contains this exact item revision)",
    }


def applicability_of(mapping: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    """Three-valued. UNKNOWN is kept: it is never read as 'does not apply'."""
    a = mapping.get("applicability")
    if not a:
        return {
            "status": "APPLICABLE",
            "basis": "DECLARED_FOR_EVERY_JOURNEY",
            "explanation": "The governed mapping declares this control for every journey of its market",
        }
    clean = {k: v for k, v in facts.items() if not is_missing(v)}
    cond = a["condition"]
    try:
        ex = evaluate(a["ast"], a.get("params") or {}, clean, {})
    except ConditionError as exc:
        return {
            "status": "UNKNOWN",
            "basis": "CONDITION",
            "condition": cond,
            "explanation": f"The applicability condition could not be evaluated ({exc.code})",
        }
    reads = sorted({name for kind, name, _ in _reads(ex) if kind == "field"})
    status = {"TRUE": "APPLICABLE", "FALSE": "NOT_APPLICABLE", "UNKNOWN": "UNKNOWN"}[ex.result]
    return {
        "status": status, "basis": "CONDITION", "condition": cond, "reads": reads,
        "missing": [n for n in reads if n not in clean],
        "explanation": f"Condition {cond['code']} v{cond['version']} is {ex.result.lower()} for this application",
    }  # fmt: skip


def _reads(ex: Any) -> list[tuple[str, str, Any]]:
    out = list(ex.reads)
    for c in ex.children:
        out += _reads(c)
    return out


def _same(value: Any) -> str:
    """Two answers are the same answer when their values are equal — for a selection, as a set, whatever its order."""
    return repr(sorted(value)) if isinstance(value, list) else repr(value)


def _decide(observations: Sequence[Mapping[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Combination ALL_REQUIRED: every placement of every required entry must be a MATCH (or delivered)."""
    reasons: list[dict[str, Any]] = []
    answered: dict[tuple[str, int], dict[str, list[str]]] = {}
    for o in observations:
        ev = o.get("evaluation") or {}
        if o["evidence_type"] == "ANSWER" and (ev.get("answer") or {}).get("kind") == "ANSWER":
            answered.setdefault((o["item"]["code"], o["item"]["version"]), {}).setdefault(_same(ev["answer"]["value"]), []).append(
                f"{(o['survey'] or {}).get('survey_code')}:{o['placement']}"
            )  # fmt: skip
    for (code, version), values in sorted(answered.items()):
        if len(values) > 1:
            reasons.append(
                {
                    "code": "EVIDENCE_CONFLICT", "item": f"{code}@{version}",
                    "answers": [{"value": v, "at": at} for v, at in sorted(values.items())],
                    "text": f"{code} v{version} was answered differently in different places. Nothing governs which answer stands, so none is chosen",
                }
            )  # fmt: skip
    required = [o for o in observations if o["required"]]
    for o in required:
        if o["result"] not in ("MATCH", "DELIVERED"):
            where = f"{o['survey']['survey_code']} {o['placement']}" if o["survey"] else "no survey of this journey"
            reasons.append(
                {
                    "code": f"EVIDENCE_{o['result']}",
                    "item": f"{o['item']['code']}@{o['item']['version']}",
                    "gap": o["gap"],
                    "text": f"{o['item']['code']} v{o['item']['version']} ({where}): {o['explanation']}",
                }
            )
    results = {o["result"] for o in required}
    if any(r["code"] == "EVIDENCE_CONFLICT" for r in reasons):
        return "REQUIRES_REVIEW", reasons
    if "MISMATCH" in results:
        return "NOT_SATISFIED", reasons
    if results & set(GAPS):
        return "INSUFFICIENT_EVIDENCE", reasons
    if "HUMAN_ASSESSMENT_REQUIRED" in results:
        return "REQUIRES_REVIEW", reasons
    if required and results <= {"MATCH", "DELIVERED"}:
        return "SATISFIED", reasons
    reasons.append(
        {
            "code": "NO_EVALUABLE_REQUIRED_EVIDENCE",
            "text": "No required evidence of this control gives a deterministic result",
        }
    )
    return "UNRESOLVED", reasons


def evaluate_journey(
    journey: Mapping[str, Any],
    controls: Sequence[Mapping[str, Any]],
    mappings: Mapping[str, Mapping[str, Any]],
    rule_set: fe.RuleSet | None,
) -> dict[str, Any]:
    """The evaluation of one journey. Deterministic: the same journey, controls, mappings and rule set give the same
    result and the same fingerprint.

    ``journey``: kind, id, status, complete, trusted, problems, facts, executions[]. Each execution: position,
    survey_code, survey_name, version_label, survey_version_id, content_sha256, manifest_sha256, state,
    simulation_id | None, run | None, run_sha256, bundle.
    ``mappings``: control code → the published mapping revision (id, revision, sha256, combination, applicability, entries).
    """
    executions = list(journey["executions"])
    placed = [(x, p) for x in executions for p in placements(x["bundle"])]
    trusted = bool(journey["trusted"])
    out_controls: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    not_converted: list[dict[str, Any]] = []
    human: list[dict[str, Any]] = []
    seq = 0
    for c in sorted(controls, key=lambda c: c["control_code"]):
        code = c["control_code"]
        m = mappings.get(code)
        line: dict[str, Any] = {
            "control_code": code, "control_name": c["name"], "control_id": str(c["id"]), "control_sha256": control_sha256(c),
            "owner_role": c["owner_role"], "content_approval_status": c["content_approval_status"],
            "mapping": {"id": str(m["id"]), "revision": m["revision"], "sha256": m["mapping_sha256"], "combination": m["combination"], "source": m["source"]} if m else None,
            "applicability": {"status": "NOT_DETERMINED", "explanation": "Without a published mapping nothing says when this control applies"},
            "outcome": "UNRESOLVED", "reasons": [], "observations": [], "findings": 0,
        }  # fmt: skip
        out_controls.append(line)
        if not trusted:
            line["reasons"] = [
                {
                    "code": "EVIDENCE_INTEGRITY_FAILED",
                    "text": "The journey's evidence could not be trusted, so no control outcome is asserted",
                }
            ]
            continue
        if m is None:
            line["reasons"] = [
                {
                    "code": "MAPPING_MISSING",
                    "text": "No published mapping connects this control to survey evidence in this market. It is not treated as satisfied, and not as unnecessary",
                }
            ]
            continue
        if line["control_sha256"] != m["control_sha256"]:
            line["reasons"] = [
                {
                    "code": "CONTROL_CHANGED_SINCE_MAPPING",
                    "text": "The control was changed after this mapping was governed; the mapping no longer speaks for it",
                }
            ]
            continue
        if m["combination"] not in COMBINATIONS:
            line["reasons"] = [
                {
                    "code": "COMBINATION_UNSUPPORTED",
                    "text": f"Evidence combination {m['combination']} has no approved meaning",
                }
            ]
            continue
        line["applicability"] = applicability_of(m, journey["facts"])
        if line["applicability"]["status"] == "NOT_APPLICABLE":
            line["outcome"] = "NOT_APPLICABLE"
            line["reasons"] = [{"code": "APPLICABILITY_FALSE", "text": line["applicability"]["explanation"]}]
            continue
        for index, entry in enumerate(m["entries"]):
            item = entry["item"]
            hits = [
                (x, p) for x, p in placed
                if p["item_code"] == item["code"] and p["item_version"] == int(item["version"])
                and (not entry.get("survey_code") or x["survey_code"] == entry["survey_code"])
            ]  # fmt: skip
            got = [observe(x, p, entry) for x, p in hits] or [
                _absent(entry, sorted({p["item_version"] for x, p in placed if p["item_code"] == item["code"] and (not entry.get("survey_code") or x["survey_code"] == entry["survey_code"])}))
            ]  # fmt: skip
            for o in got:
                seq += 1
                line["observations"].append(o | {"seq": seq, "entry": index, "context": entry.get("survey_code")})
        if line["applicability"]["status"] == "UNKNOWN":
            line["reasons"] = [
                {
                    "code": "APPLICABILITY_UNKNOWN",
                    "missing": line["applicability"].get("missing", []),
                    "text": line["applicability"]["explanation"] + ". Unknown is not 'does not apply'",
                }
            ]
            continue
        line["outcome"], line["reasons"] = _decide(line["observations"])
        # findings: the EXISTING engine and the PUBLISHED rule set, once per observation. Nothing is de-duplicated.
        for o in line["observations"]:
            if rule_set is None or o["evaluation"] is None:
                continue
            ref = f"{o['simulation_id'] or 'no-execution'}#{o['placement'] or 'absent'}#{code}#{o['entry']}"
            content = {
                "sections": [
                    {
                        "questions": [
                            {
                                "question_code": o["item"]["code"],
                                "controls": [
                                    {
                                        "control_code": code,
                                        "control_name": c["name"],
                                        "mapping_status": "PUBLISHED",
                                        "regulatory_reference": None,
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
            ctx = {
                "execution_ref": ref, "case_ref": None,
                "script_label": f"{o['survey']['survey_code']} {o['survey']['version_label']}" if o["survey"] else None,
                "script_version_id": o["survey"]["survey_version_id"] if o["survey"] else None,
                "content_sha256": o["survey"]["manifest_sha256"] if o["survey"] else None,
                "evaluation_ref": None, "evaluation_engine": ae.ENGINE, "fact_source": NO_FACTS.as_dict(),
            }  # fmt: skip
            g = fe.generate([o["evaluation"] | {"mandatory": o["required"]}], content, rule_set, ctx)
            tag = {
                "control_code": code,
                "observation_seq": o["seq"],
                "survey": o["survey"],
                "simulation_id": o["simulation_id"],
                "placement": o["placement"],
                "item": o["item"],
            }
            findings += [f | tag for f in g.findings]
            not_converted += [n | tag for n in g.not_converted]
            human += [h | tag for h in g.human_assessment]
            line["findings"] += len(g.findings)

    mapped = {(e["item"]["code"], int(e["item"]["version"])) for m in mappings.values() for e in m["entries"]}
    unmapped_items = [
        {"survey": _survey_ref(x), "placement": p["key"], "item": {"code": p["item_code"], "version": p["item_version"], "name": p["item_name"], "answer_type": p["answer_type"]}}
        for x, p in placed if (p["item_code"], p["item_version"]) not in mapped
    ]  # fmt: skip
    by = {o: sum(1 for c in out_controls if c["outcome"] == o) for o in OUTCOMES}
    if not trusted:
        processing = "FAILED_TECHNICALLY"
    elif by["REQUIRES_REVIEW"]:
        processing = "REQUIRES_REVIEW"
    elif not journey["complete"] or by["INSUFFICIENT_EVIDENCE"] or by["UNRESOLVED"]:
        processing = "INCOMPLETE"
    else:
        processing = "COMPLETED"
    result: dict[str, Any] = {
        "contract": CONTRACT,
        "journey": {
            "kind": journey["kind"], "id": str(journey["id"]), "status": journey["status"], "complete": bool(journey["complete"]),
            "trusted": trusted, "problems": list(journey["problems"]),
            "executions": [_survey_ref(x) | {"survey_name": x["survey_name"], "simulation_id": str(x["simulation_id"]) if x.get("simulation_id") else None, "run_sha256": x.get("run_sha256"), "ending": ((x.get("run") or {}).get("terminal") or {}).get("state")} for x in executions],
        },
        "processing_status": processing,
        "summary": {
            "controls": len(out_controls), "by_outcome": by,
            "applicable": sum(1 for c in out_controls if c["applicability"]["status"] == "APPLICABLE"),
            "findings": len(findings), "not_converted": len(not_converted), "human_assessment_items": len(human),
            "surveys": len(executions), "surveys_completed": sum(1 for x in executions if x["state"] == "COMPLETED"),
        },
        "coverage": {
            "status": "NOT_ASSERTED", "note": COVERAGE_NOTE,
            "controls_without_mapping": [c["control_code"] for c in out_controls if c["mapping"] is None],
            "controls_with_unknown_applicability": [c["control_code"] for c in out_controls if c["applicability"]["status"] == "UNKNOWN"],
            "items_without_mapping": unmapped_items,
        },
        "finding_rules": rule_set.ref() if rule_set else None,
        "findings_status": "NOT_GENERATED_EVIDENCE_NOT_TRUSTED" if not trusted else "GENERATED" if rule_set else "FINDING_RULES_MISSING",
        "controls": out_controls, "findings": findings, "not_converted": not_converted, "human_assessment": human,
        "engines": {"answer_evaluation": ae.ENGINE, "findings": fe.ENGINE, "control_evaluation": CONTRACT},
    }  # fmt: skip
    return result | {"result_sha256": sha256_hex(result)}
