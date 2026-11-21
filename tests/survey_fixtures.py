"""The 27 golden fixtures of Call360-specs (schemas /1 … /5), read as canonical survey documents.

A TRANSLATION OF SHAPE ONLY: the five fixture schemas name the same things differently (questions / items,
business_label / label, a list of routes / a map). Nothing here decides behaviour or holds an expected value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.domain.survey.documents import SCHEMA_OF, Bundle

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "Call360-specs" / "docs" / "plans" / "survey-studio" / "fixtures"
CLASS_OF = {"COMPLETED": "NORMAL_COMPLETION", "ESCALATE": "ESCALATION", "REVIEW_REQUIRED": "REVIEW_HALT"}
OPS = {"CONTAINS_ANY": "INCLUDES_ANY", "CONTAINS_ALL": "INCLUDES_ALL", "CONTAINS_NONE": "INCLUDES_NONE"}


def load_all() -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted(FIXTURE_DIR.glob("[FGHJK]*.json"))]


def schema_version(fx: dict[str, Any]) -> int:
    return int(fx["schema"].rsplit("/", 1)[1])


def _ast(a: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    out["op"] = OPS.get(a["op"], a["op"])
    if "args" in a:
        out["args"] = [_ast(x) for x in a["args"]]
    if "arg" in a:
        out["arg"] = _ast(a["arg"])
    return out


def _target(t: Any) -> Any:
    return t


def to_bundle(fx: dict[str, Any]) -> Bundle:
    lib, sv = fx["library"], fx["survey"]
    raw_items = lib.get("items") or lib.get("questions") or []
    outcomes = fx["catalog"]["outcomes"]
    outcome_map = dict(outcomes) if isinstance(outcomes, dict) else {o: CLASS_OF.get(o, "EXCEPTION") for o in outcomes}

    option_sets = []
    for s in lib["option_sets"]:
        opts = sorted(s["options"], key=lambda o: o.get("order", 0))
        option_sets.append(
            {
                "schema": SCHEMA_OF["OPTION_SET"],
                "code": s["code"],
                "version": s["version"],
                "options": [
                    {
                        "code": o["code"],
                        "label": o.get("label", o.get("business_label", "")),
                        **{k: o[k] for k in ("exclusive", "is_other", "other_text", "interrupt") if k in o},
                    }
                    for o in opts
                ],
            }
        )

    items = []
    for q in raw_items:
        d: dict[str, Any] = {
            "schema": SCHEMA_OF["ITEM"],
            "code": q["code"],
            "version": q["version"],
            "answer_type": q["answer_type"],
            "intent": q.get("intent", ""),
        }
        for src, dst in (
            ("option_set", "option_set"),
            ("selection", "selection"),
            ("text", "text_rule"),
            ("number_rule", "number_rule"),
            ("statement_role", "statement_role"),
            ("role", "lifecycle_role"),
        ):
            if src in q:
                d[dst] = q[src]
        if q.get("mandatory"):
            d["response_obligation"] = "MANDATORY"
        items.append(d)

    wordings = [
        {
            "schema": SCHEMA_OF["WORDING"],
            "item": w.get("item", w.get("question")),
            "language": w.get("language", "en"),
            "wording_version": w["wording_version"],
            "text": w["text"],
            "delivery_mode": w.get("delivery_mode", "CONTROLLED_TTS"),
            **({"option_texts": w["option_texts"]} if "option_texts" in w else {}),
        }
        for w in lib["wordings"]
    ]

    item_by_code = {q["code"]: q for q in raw_items}

    def node_item(n: dict[str, Any]) -> dict[str, Any]:
        ref = n.get("item") or n["question"]
        return {"code": ref["code"], "version": ref["version"], "wording_version": ref["wording_version"]}

    modules = []
    for m in lib["modules"]:
        nodes = []
        for n in m["nodes"]:
            if n["type"] == "DECISION":
                b = n["binding"]
                nodes.append(
                    {
                        "node": n["node"],
                        "type": "DECISION",
                        "binding": {
                            "condition": b["condition"],
                            "params": b.get("params", {}),
                            "inputs": {k: {"node": v["answer"]["node"]} for k, v in (b.get("inputs") or {}).items()},
                            "unknown_policy": {"ROUTE_UNKNOWN": "ROUTE"}.get(b["unknown_policy"], b["unknown_policy"]),
                        },
                    }
                )
                continue
            r = n["routing"]
            routing: dict[str, Any] = {"mode": "PER_CHOICE" if r["mode"] == "PER_CHOICE_WITH_DEFAULT" else r["mode"]}
            for k in ("normal_answer", "no_followup", "rejoin", "fallback"):
                if k in r:
                    routing[k] = _target(r[k])
            if "followups" in r:
                routing["followups"] = [
                    {"option": f["option"], "nodes": f["nodes"]}
                    for f in sorted(r["followups"], key=lambda f: f.get("priority", 0))
                ]
            if "interrupts" in r:
                routing["interrupts"] = [
                    {k: v for k, v in i.items() if k != "priority"}
                    for i in sorted(r["interrupts"], key=lambda i: i.get("priority", 0))
                ]
            if "rules" in r:
                routing["rules"] = r["rules"]
            d = {"node": n["node"], "type": n["type"], "item": node_item(n), "routing": routing}
            if n.get("role"):
                d["role"] = n["role"]
            nodes.append(d)
        modules.append(
            {
                "schema": SCHEMA_OF["MODULE"],
                "code": m["code"],
                "revision": m["revision"],
                "name": m.get("name", m["code"]),
                "outcomes": m["outcomes"],
                "entry": m["entry"],
                "nodes": nodes,
                "edges": m["edges"],
            }
        )

    conditions = []
    for c in lib["conditions"]:
        inputs: dict[str, Any] = {}
        for name, decl in (c.get("inputs") or {}).items():
            if decl.get("kind") == "ANSWER":  # schema /2 onwards: typed declaration
                inputs[name] = {"answer_type": decl["answer_type"], "item": decl["question"]}
        for m in lib["modules"]:  # schema /1: the type is that of the question each input is bound to
            for n in m["nodes"]:
                if n["type"] != "DECISION" or n["binding"]["condition"]["code"] != c["code"]:
                    continue
                for name, src in (n["binding"].get("inputs") or {}).items():
                    bound = next(x for x in m["nodes"] if x["node"] == src["answer"]["node"])
                    q = item_by_code[(bound.get("item") or bound["question"])["code"]]
                    inputs.setdefault(
                        name, {"answer_type": q["answer_type"], "item": {"code": q["code"], "version": q["version"]}}
                    )
        conditions.append(
            {
                "schema": SCHEMA_OF["CONDITION"],
                "code": c["code"],
                "version": c["version"],
                "name": c.get("name", c["code"]),
                "ast": _ast(c["ast"]),
                "params": {
                    k: {kk: vv for kk, vv in v.items() if kk in ("type", "unit")}
                    for k, v in (c.get("params") or {}).items()
                },
                "inputs": inputs,
            }
        )

    by_name = {i["instance"]: i for i in sv["instances"]}
    sequence = []
    for name in sv["sequence"]:
        i = by_name[name]
        inst: dict[str, Any] = {
            "instance": name,
            "module": i["module"],
            "routes": {r["on"]: r["to"] for r in i["routes"]},
        }
        entry = i.get("entry") or {"mode": "ALWAYS"}
        if entry["mode"] == "RULE":
            b = entry["binding"]
            inst["eligibility"] = {
                "condition": b["condition"],
                "params": b.get("params", {}),
                "unknown_policy": b.get("unknown_policy"),
            }
        elif entry["mode"] == "ON_OUTCOME":
            inst["activation"] = {"of": entry["of"], "outcomes": entry["outcomes"]}
        for k in ("activation", "if_ineligible", "if_skipped_in_sequence"):
            if k in i:
                inst[k] = i[k]
        sequence.append(inst)

    return Bundle.build(
        fields=fx["catalog"]["fields"],
        outcomes=outcome_map,
        option_sets=option_sets,
        items=items,
        wordings=wordings,
        conditions=conditions,
        modules=modules,
        survey={"schema": SCHEMA_OF["SURVEY"], "code": sv["code"], "sequence": sequence},
    )
