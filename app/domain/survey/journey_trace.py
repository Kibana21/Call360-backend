# ruff: noqa: E501 — records are kept one per line
"""E2E-1 — the provenance of ONE synthetic journey, from the application to its execution assurance. READ ONLY.

This module decides nothing and stores nothing. It reads the records the existing services already keep — the
composite plan (ASG-2A), the coordinated simulation and its individual simulations (ASG-2B, SS-03B), the control
evaluation (EVAL-1, EVAL-2A) and the execution assurance (EVAL-2B) — through those services' own read functions, and
lays them out as one chain. Every link names the authoritative record, its version where it has one, its fingerprint
where one is recorded, and where the record comes from. Where no fingerprint is recorded, that is said.

Five statements are kept apart and never derived from one another: completion, control satisfaction, evidence
coverage, execution assurance, operational call eligibility. The last is always NOT_ESTABLISHED.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.domain.survey import assignment_groups, assurance, coordination, simulation
from app.domain.survey import journey_evaluation as je
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all

CONTRACT = "call360.survey.journey-trace/1"
RECORD_CLASS = "SIMULATION"
NOTE = (
    "PROVENANCE OF A SIMULATED JOURNEY, for a synthetic application. Read-only: it lays out records other services "
    "keep and decides nothing. It is not a compliance outcome and does not establish that a call may be made."
)
ELIGIBILITY = {
    "status": "NOT_ESTABLISHED",
    "note": "Nothing in a simulation, an evaluation of one or a verification of one establishes that a real customer may be called.",
}
#: The reviewer's questions, in the order a reviewer asks them, and the links that answer each.
QUESTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("REQUIRED", "What was required?", ("APPLICATION", "ASSIGNMENT_INPUTS", "RULE_VERSIONS", "BINDINGS", "REQUIREMENT_GROUPS")),
    ("SELECTED", "Which surveys were selected?", ("SURVEY_VERSIONS", "COMPOSITE_PLAN")),
    ("HAPPENED", "What happened in each survey?", ("SIMULATIONS", "COORDINATED_SIMULATION")),
    ("ASSESSED", "What controls were assessed?", ("CONTROL_POLICY", "MAPPINGS", "EVALUATION", "CONTROL_RESULTS")),
    ("GAPS", "What evidence was missing or contradictory?", ()),  # answered by ``evidence_gaps``: recorded results, filtered
    ("FINDINGS", "What findings arose?", ("FINDINGS",)),
    ("FAITHFUL", "Was execution faithful to its pinned plan?", ("EXECUTION_ASSURANCE",)),
)  # fmt: skip
ASSIGNMENT_LINKS = ("ASSIGNMENT_INPUTS", "RULE_VERSIONS", "BINDINGS", "REQUIREMENT_GROUPS", "COMPOSITE_PLAN")
TITLES = {
    "APPLICATION": "Synthetic application",
    "ASSIGNMENT_INPUTS": "Assignment inputs",
    "RULE_VERSIONS": "Matching rule versions",
    "BINDINGS": "Published bindings",
    "REQUIREMENT_GROUPS": "Requirement group versions",
    "SURVEY_VERSIONS": "Published survey versions",
    "COMPOSITE_PLAN": "Composite plan",
    "SIMULATIONS": "Individual simulation records",
    "COORDINATED_SIMULATION": "Coordinated simulation",
    "CONTROL_POLICY": "Control policy revision",
    "MAPPINGS": "Mapping revisions",
    "EVALUATION": "Evaluation run",
    "CONTROL_RESULTS": "Control-obligation results",
    "FINDINGS": "Findings",
    "EXECUTION_ASSURANCE": "Execution assurance",
}


def _rec(
    kind: str,
    rid: Any,
    label: str,
    *,
    version: Any = None,
    sha256: str | None = None,
    of: str | None = None,
    source: str,
    **facts: Any,
) -> dict[str, Any]:
    return {
        "kind": kind, "id": str(rid) if rid is not None else None, "label": label, "version": version,
        "sha256": sha256, "sha256_of": of if sha256 else None, "source": source,
        "facts": {k: v for k, v in facts.items() if v is not None},
    }  # fmt: skip


def _link(
    key: str, status: str, records: Sequence[Mapping[str, Any]] = (), notes: Sequence[str] = ()
) -> dict[str, Any]:
    return {"key": key, "title": TITLES[key], "status": status, "records": list(records), "notes": list(notes)}


def _rule_versions(db: Session, comp: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every rule version that MATCHED the application in some requirement group, with the checksum Script Studio
    recorded for it. The rule tables are read, never written."""
    seen: dict[tuple[str, int], dict[str, Any]] = {}
    for r in comp["composite"]["requirements"]:
        for t in r.get("trace") or []:
            if t.get("match") != "MATCH":
                continue
            code, _, v = str(t["ref"]).rpartition(" v")
            if not v.isdigit():
                continue
            e = seen.setdefault(
                (code, int(v)),
                {
                    "groups": [],
                    "selected_in": [],
                    "conditions": t.get("conditions") or [],
                    "priority": t.get("priority"),
                    "is_fallback": t.get("is_fallback"),
                },
            )
            e["groups"].append(r["group"]["code"])
            if t.get("selected"):
                e["selected_in"].append(r["group"]["code"])
    if not seen:
        return []
    rows = {
        (x["rule_code"], x["version"]): x
        for x in _all(
            db,
            "SELECT id, rule_code, version, checksum, status FROM script_assignment_rule_version WHERE rule_code = ANY(:c)",
            c=sorted({k[0] for k in seen}),
        )
    }
    out = []
    for (code, number), e in sorted(seen.items()):
        row = rows.get((code, number)) or {}
        out.append(
            _rec(
                "ASSIGNMENT_RULE_VERSION", row.get("id"), f"{code} v{number}", version=number, sha256=row.get("checksum"), of="the rule version as Script Studio recorded it",
                source="Published assignment rule (Script Studio rule tables; read only)",
                matched_in_groups=e["groups"], selected_in_groups=e["selected_in"], priority=e["priority"], is_fallback=e["is_fallback"],
                conditions=[{"field": c["field"], "expected": c.get("expected"), "actual": c.get("actual"), "result": c.get("result")} for c in e["conditions"]],
            )
        )  # fmt: skip
    return out


def _assignment(db: Session, comp: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    doc = comp["composite"]
    app = doc["application"]
    reqs = doc["requirements"]
    group_of = {str(r["group"]["id"]): r["group"]["code"] for r in reqs}
    notes_inputs = []
    if (doc.get("input_consistency") or {}).get("status") != "VERIFIED":
        notes_inputs.append(
            "Nothing verifies that the assignment inputs and the call-plan facts describe the same application: input consistency is "
            + str((doc.get("input_consistency") or {}).get("status", "UNVERIFIED"))
            + "."
        )
    if doc.get("missing_inputs"):
        notes_inputs.append(
            "Assignment inputs missing: "
            + ", ".join(map(str, doc["missing_inputs"]))
            + ". A missing input is never read as a value."
        )
    binding_ids = [m["binding_id"] for m in comp["members"] if m.get("binding_id")]
    bindings = (
        {
            str(b["id"]): b
            for b in _all(
                db,
                "SELECT id, rule_code, rule_version, survey_version_id, content_sha256, manifest_sha256 FROM survey_assignment_binding WHERE id = ANY(:i)",
                i=binding_ids,
            )
        }
        if binding_ids
        else {}
    )
    unselected = [
        f"{r['group']['code']}: {r.get('outcome') or r.get('state')} — {r.get('reason') or 'no survey selected'}"
        for r in reqs
        if r.get("state") != "SELECTED"
    ]
    return {
        "ASSIGNMENT_INPUTS": _link(
            "ASSIGNMENT_INPUTS", "RECORDED",
            [_rec("ASSIGNMENT_INPUTS", comp["id"], "Assignment inputs of the application", sha256=comp["application_sha256"], of="assignment inputs and call-plan facts together", source="Entered for this simulation (synthetic); stored on the composite plan", inputs=app.get("assignment_inputs"), missing_inputs=doc.get("missing_inputs") or None)],
            notes_inputs,
        ),
        "RULE_VERSIONS": _link("RULE_VERSIONS", "RECORDED", _rule_versions(db, comp), [f"{doc.get('ignored_script_rules', 0)} published rule(s) that select a script and no survey were ignored."] if doc.get("ignored_script_rules") else []),
        "BINDINGS": _link(
            "BINDINGS", "RECORDED",
            [
                _rec("SURVEY_BINDING", bid, f"{b['rule_code']} v{b['rule_version']} → survey version", sha256=b["manifest_sha256"], of="the manifest of the survey version the binding pins", source="Published survey binding (three people)", rule=f"{b['rule_code']} v{b['rule_version']}", survey_version_id=str(b["survey_version_id"]), content_sha256=b["content_sha256"])
                for bid, b in ((i, bindings[str(i)]) for i in binding_ids if str(i) in bindings)
            ],
        ),
        "REQUIREMENT_GROUPS": _link(
            "REQUIREMENT_GROUPS", "RECORDED",
            [
                _rec("REQUIREMENT_GROUP", r["group"]["id"], f"{r['group']['code']} ({r['group']['kind']})", version=r["group"]["version"], source="Published requirement group (three people)", sequence=r["group"]["sequence"], state=r.get("state"), outcome=r.get("outcome"), selection=r.get("selection"), reason=r.get("reason"), winning_rules=r.get("winning_rules"), missing_inputs=r.get("missing_inputs") or None)
                for r in reqs
            ],
            ["No fingerprint is recorded for a group revision on its own; it is identified by id and version and is covered by the composite plan's fingerprint."] + ([("Requirement groups that selected no survey — " + "; ".join(unselected))] if unselected else []),
        ),
        "COMPOSITE_PLAN": _link(
            "COMPOSITE_PLAN", "RECORDED",
            [
                _rec("COMPOSITE_PLAN", comp["id"], "Composite call plan", version=comp["contract"], sha256=comp["fingerprint"], of="the whole composite: selection, order, each survey's plan", source="Composed by the assignment engine from published rules, bindings and groups", selection_status=comp["selection_status"], ordering_status=comp["ordering_status"], plan_status=comp["plan_status"], recomputes_to_its_record=comp["recompute_consistent"], governed_order=doc["ordering"].get("order"), coordinated_simulation=comp["states"]["coordinated_simulation"]["status"], blockers=[b.get("code") for b in comp["states"]["coordinated_simulation"].get("blockers") or []] or None, cross_survey_policy=(doc.get("cross_survey_policy") or {}).get("status")),
                *[
                    _rec("CALL_PLAN", m["call_plan_id"], f"Call plan for {group_of.get(str(m['group_id']), 'requirement ' + str(m['position']))}", sha256=m["plan_fingerprint"], of="the survey's call plan: modules, items, exact wording", source="Assembled from the published survey version", intact=m.get("plan_intact"))
                    for m in comp["members"]
                    if m.get("call_plan_id")
                ],
            ],
            [] if comp["recompute_consistent"] else ["Composed again now for the recorded time, the plan would differ: governance has changed since. The record is unchanged and is what is shown."],
        ),
    }  # fmt: skip


def _surveys(comp: Mapping[str, Any] | None, executions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if comp is not None:
        order = list(comp["composite"]["ordering"].get("order") or [])  # the governed order, where there is one
        return [
            _rec("SURVEY_VERSION", s["survey_version_id"], f"{s['survey_name']} ({s['survey_code']})", version=s["version_label"], sha256=s["manifest_sha256"], of="the version's manifest: every pinned module, item and wording", source="Published survey version (three people)", survey_code=s["survey_code"], content_sha256=s["content_sha256"], selected_by=s["rule"], group=s["group"], requirement_kind=s["kind"], reason=s.get("reason"), by_fallback=s.get("by_fallback"))
            for s in sorted(comp["composite"]["selected"], key=lambda x: order.index(x["group"]) if x["group"] in order else len(order))
        ]  # fmt: skip
    return [
        _rec("SURVEY_VERSION", x["survey_version_id"], f"{x['survey_name']} ({x['survey_code']})", version=x["version_label"], sha256=x["manifest_sha256"], of="the version's manifest: every pinned module, item and wording", source="Published survey version (three people)", survey_code=x["survey_code"], content_sha256=x["content_sha256"])
        for x in executions
    ]  # fmt: skip


def _simulations(sims: Sequence[tuple[int, Mapping[str, Any] | None, str, str]]) -> list[dict[str, Any]]:
    out = []
    for position, sim, state, name in sims:
        if sim is None:
            out.append(
                _rec(
                    "SIMULATION",
                    None,
                    f"{position}. {name}",
                    source="Not started: no simulation record exists for this survey",
                    position=position,
                    state=state,
                )
            )
            continue
        inputs = sim.get("inputs") or []
        terminal = (sim["run"].get("terminal") or {}) if sim.get("run") else {}
        out.append(
            _rec(
                "SIMULATION", sim["id"], f"{position}. {name}", version=sim["engine_contract"], sha256=sim["run_sha256"], of="the run after the last recorded input",
                source="Recorded inputs, replayed by the authoritative execution engine",
                survey_code=sim.get("survey_code"), position=position, state=state, ending=terminal.get("state"), survey_outcome=terminal.get("survey_outcome"), recomputes_to_its_record=sim["replay_consistent"],
                inputs=len(inputs), accepted=sum(1 for i in inputs if i.get("accepted")), refused=[{"key": i.get("key"), "code": i.get("rejection_code")} for i in inputs if not i.get("accepted")] or None,
                delivered=len(sim["run"].get("delivered") or []) if sim.get("run") else None, pending=((sim["run"].get("pending") or {}).get("key") if sim.get("run") else None),
                facts_sha256=sim.get("facts_sha256"), initial_run_sha256=sim.get("initial_run_sha256"),
            )
        )  # fmt: skip
    return out


def _completion(
    kind: str,
    status: str | None,
    sims: Sequence[tuple[int, Mapping[str, Any] | None, str, str]],
    stop: Mapping[str, Any] | None,
) -> dict[str, Any]:
    done = sum(1 for _, _, state, _ in sims if state == "COMPLETED")
    return {
        "status": status or "NOT_STARTED", "surveys": len(sims), "surveys_completed": done,
        "surveys_started": sum(1 for _, s, _, _ in sims if s is not None), "complete": bool(sims) and done == len(sims),
        "stopped_because": dict(stop) if stop else None,
        "note": "Completion says the surveys reached their end. It says nothing about whether any control is satisfied.",
    }  # fmt: skip


def trace(
    db: Session,
    markets: Sequence[str],
    *,
    simulation_id: uuid.UUID | None = None,
    coordinated_id: uuid.UUID | None = None,
    composite_plan_id: uuid.UUID | None = None,
    evaluation_id: uuid.UUID | None = None,
    assurance_id: uuid.UUID | None = None,
    with_assignment: bool = True,
    with_assurance: bool = True,
) -> dict[str, Any]:
    """One journey — a simulation, a coordinated simulation, or a composite plan whose journey never started."""
    if sum(x is not None for x in (simulation_id, coordinated_id, composite_plan_id)) != 1:
        raise SurveyError(
            422, "JOURNEY_REQUIRED", "Name exactly one: a simulation, a coordinated simulation, or a composite plan"
        )
    co: dict[str, Any] | None = None
    comp: dict[str, Any] | None = None
    sims: list[tuple[int, Mapping[str, Any] | None, str, str]] = []
    if simulation_id is not None:
        sim = simulation.state(db, simulation_id, markets)
        kind, jid, label, market = (
            "SINGLE_SURVEY",
            sim["id"],
            sim["label"],
            simulation._row(db, simulation_id, markets)["market_code"],
        )
        sims = [(1, sim, je._single_state(sim), sim["survey_name"])]
        status = (sim["run"]["terminal"] or {}).get("state") or sim["status"]
        application = {"facts": sim["facts"], "sha256": sim["facts_sha256"], "assignment_inputs": None}
        executions = [
            {
                "survey_version_id": sim["version_id"],
                "survey_name": sim["survey_name"],
                "survey_code": sim["survey_code"],
                "version_label": sim["version_label"],
                "manifest_sha256": sim["manifest_sha256"],
                "content_sha256": sim["content_sha256"],
            }
        ]
    elif coordinated_id is not None:
        co = coordination.state(db, coordinated_id, markets)
        comp = assignment_groups.composite(db, uuid.UUID(str(co["composite_plan_id"])), markets)
        kind, jid, label, market, status = "COORDINATED", co["id"], co["label"], co["market_code"], co["status"]
        sims = [(s["position"], s["simulation"], s["state"], s["survey_name"]) for s in co["surveys"]]
        application, executions = comp["composite"]["application"], []
    else:
        assert composite_plan_id is not None
        comp = assignment_groups.composite(db, composite_plan_id, markets)
        kind, jid, label, market, status = "APPLICATION_ONLY", comp["id"], None, comp["market_code"], None
        application, executions = comp["composite"]["application"], []

    # ---- the evaluation and the assurance shown: the ones named, else the latest of this journey
    evaluations: list[dict[str, Any]] = []
    assurances: list[dict[str, Any]] = []
    ev: dict[str, Any] | None = None
    asr: dict[str, Any] | None = None
    if kind != "APPLICATION_ONLY":
        evaluations = je.for_journey(db, markets, simulation_id, coordinated_id)
        chosen = evaluation_id or (evaluations[-1]["id"] if evaluations else None)
        if chosen is not None:
            ev = je.get(db, uuid.UUID(str(chosen)), markets)
            if str(ev["simulation_id"] or ev["coordinated_id"]) != str(jid):
                raise SurveyError(409, "EVALUATION_OF_ANOTHER_JOURNEY", "That evaluation is of another journey")
        if with_assurance:
            assurances = assurance.for_journey(db, markets, simulation_id, coordinated_id)
            mine = [a for a in assurances if ev is not None and str(a["evaluation_id"]) == str(ev["id"])]
            picked = assurance_id or (
                mine[-1]["id"] if mine else (assurances[-1]["id"] if assurances and ev is None else None)
            )
            if picked is not None:
                asr = assurance.get(db, uuid.UUID(str(picked)), markets)
                if str(asr["simulation_id"] or asr["coordinated_id"]) != str(jid):
                    raise SurveyError(
                        409, "ASSURANCE_OF_ANOTHER_JOURNEY", "That assurance result is of another journey"
                    )
    elif evaluation_id is not None or assurance_id is not None:
        raise SurveyError(
            422, "NO_JOURNEY_TO_EVALUATE", "A composite plan whose journey never started has no evaluation or assurance"
        )

    links: dict[str, dict[str, Any]] = {}
    links["APPLICATION"] = _link(
        "APPLICATION", "RECORDED",
        [_rec("SYNTHETIC_APPLICATION", None, "Synthetic application" + (f": {label}" if label else ""), sha256=application["sha256"], of="the application's facts" + (" and assignment inputs" if application.get("assignment_inputs") is not None else ""), source="Entered by a person for a simulation. Synthetic; not a customer application and not read from any business system", facts=application.get("facts") or {}, record_class=RECORD_CLASS)],
        ["The application has no record of its own: it is stored on the " + ("composite plan" if comp is not None else "simulation") + " that was made from it, and identified by its fingerprint."],
    )  # fmt: skip
    if comp is None:
        why = "A simulation started directly from a survey version: no assignment rule, binding or requirement group selected it."
        for k in ASSIGNMENT_LINKS:
            links[k] = _link(k, "NOT_PART_OF_THIS_JOURNEY", notes=[why])
    elif not with_assignment:
        for k in ASSIGNMENT_LINKS:
            links[k] = _link(
                k,
                "WITHHELD",
                notes=["Reading how surveys were assigned needs the “read survey assignment” permission."],
            )
    else:
        links.update(_assignment(db, comp))
    links["SURVEY_VERSIONS"] = _link(
        "SURVEY_VERSIONS",
        "RECORDED" if (comp is None or comp["composite"]["selected"]) else "NONE_SELECTED",
        _surveys(comp, executions),
        [] if (comp is None or comp["composite"]["selected"]) else ["No survey was selected for this application."],
    )
    links["SIMULATIONS"] = _link(
        "SIMULATIONS",
        "RECORDED" if any(s is not None for _, s, _, _ in sims) else "NOT_RECORDED_YET",
        _simulations(sims),
        [
            "The event trace is not stored: it is recomputed from the recorded inputs by the authoritative engine and compared with the fingerprint recorded after every input."
        ]
        if sims
        else ["No simulation was started for this application."],
    )
    if co is not None:
        links["COORDINATED_SIMULATION"] = _link(
            "COORDINATED_SIMULATION", "RECORDED",
            [_rec("COORDINATED_SIMULATION", co["id"], "Coordinated simulation" + (f": {co['label']}" if co.get("label") else ""), version=co["contract"], sha256=co["replay_sha256"], of="the coordinated run: every step and every survey's run", source="The coordinator's recorded steps over the individual simulations", status=co["status"], composite_plan_id=str(co["composite_plan_id"]), composite_fingerprint=co["composite_fingerprint"], composite_intact=co["composite_intact"], governed_order=co["governed_order"], decisions=co["decisions"], stop=co.get("stop"), progress=co["progress"])],
            ["A survey after the first starts only when the one before it is completed; that is a rule of the simulation, not an approved rule for live calls."],
        )  # fmt: skip
    else:
        links["COORDINATED_SIMULATION"] = _link(
            "COORDINATED_SIMULATION",
            "NOT_PART_OF_THIS_JOURNEY" if kind == "SINGLE_SURVEY" else "NOT_RECORDED_YET",
            notes=[
                "A single survey was simulated on its own."
                if kind == "SINGLE_SURVEY"
                else "No coordinated simulation was started from this composite plan."
            ],
        )

    none_yet = "NOT_RECORDED_YET"
    if ev is None:
        why_not = (
            ["This journey has not been evaluated."]
            if kind != "APPLICATION_ONLY"
            else ["There is no journey to evaluate: nothing was simulated."]
        )
        for k in ("CONTROL_POLICY", "MAPPINGS", "EVALUATION", "CONTROL_RESULTS", "FINDINGS"):
            links[k] = _link(k, none_yet, notes=why_not)
    else:
        pol = ev.get("policy")
        links["CONTROL_POLICY"] = (
            _link(
                "CONTROL_POLICY", "RECORDED",
                [_rec("CONTROL_POLICY_REVISION", pol["id"], f"{pol['name']} ({pol['code']})", version=pol["revision"], sha256=pol["sha256"], of="the whole policy revision", source="Published control policy (three people)", completeness=pol.get("completeness"), scope=(ev.get("applicability") or {}).get("scope", {}).get("status"), applicability_fingerprint=(ev.get("applicability") or {}).get("fingerprint"), applicability_counts=(ev.get("applicability") or {}).get("counts"), input_lineage=((ev.get("applicability") or {}).get("input_lineage") or {}).get("status"), selected_by="NAMED_EXPLICITLY")],
                ["The policy was named explicitly by the person who ran the evaluation. Nothing selects a control policy for an application.", "Every control, obligation and condition in it is synthetic."],
            )
            if pol
            else _link("CONTROL_POLICY", "NOT_PART_OF_THIS_JOURNEY", notes=["This evaluation names no control policy: it assessed whatever controls are mapped, and asserts no coverage."])
        )  # fmt: skip
        links["MAPPINGS"] = _link(
            "MAPPINGS",
            "RECORDED",
            [
                _rec(
                    "CONTROL_MAPPING_REVISION",
                    m["id"],
                    f"Mapping of {m['control_code']}",
                    version=m["revision"],
                    sha256=m["sha256"],
                    of="the whole mapping revision",
                    source="Published control mapping (three people)",
                    control_code=m["control_code"],
                )
                for m in ev["pins"].get("mappings") or []
            ],
        )
        rules = ev.get("finding_rules") or {}
        links["EVALUATION"] = _link(
            "EVALUATION", "RECORDED",
            [
                _rec("JOURNEY_EVALUATION", ev["id"], "Evaluation of the journey", version=ev["contract"], sha256=ev["result_sha256"], of="the whole result: every control result, observation and finding", source="Computed by the existing deterministic evaluation engines from the pinned records", input_sha256=ev["input_sha256"], processing_status=ev["processing_status"], recomputes_to_its_record=ev["replay"]["consistent"], drift=ev["replay"].get("code"), engines=ev.get("engines"), superseded_by_current_governance=[s.get("code") or s.get("kind") for s in ev.get("superseded_by_current_governance") or []] or None, created_at=str(ev["created_at"])),
                *([_rec("FINDING_RULE_SET", rules.get("version_id"), str(rules.get("label")), sha256=rules.get("sha256"), of="the finding rule set version", source="Published finding rule set (existing findings engine)", status=rules.get("status"))] if rules.get("version_id") else []),
                *[_rec("CONTROL_REGISTER_ROW", c["id"], c["control_code"], sha256=c["sha256"], of="the control register row as it was read", source="Control register (read only)") for c in ev["pins"].get("controls") or []],
            ],
        )  # fmt: skip
        links["CONTROL_RESULTS"] = _link(
            "CONTROL_RESULTS", "RECORDED",
            [
                _rec(
                    "CONTROL_OBLIGATION_RESULT", None, c["control_code"] + (f" / {c['obligation']}" if c.get("obligation") else ""), source="Part of the evaluation record; covered by its result fingerprint",
                    control_code=c["control_code"], obligation=c.get("obligation"), outcome=c["outcome"], coverage=c.get("coverage"), applicability=(c.get("applicability") or {}).get("status") if isinstance(c.get("applicability"), dict) else c.get("applicability"),
                    mapping_revision=(c.get("mapping") or {}).get("revision"), reasons=[r.get("code") for r in c.get("reasons") or []] or None,
                    evidence=[{"seq": o.get("seq"), "simulation_id": o.get("simulation_id"), "survey": (o.get("survey") or {}).get("survey_code"), "placement": o.get("placement"), "result": o.get("result"), "gap": o.get("gap"), "run_sha256": o.get("run_sha256")} for o in c.get("observations") or []],
                )
                for c in ev["controls"]
            ],
        )  # fmt: skip
        links["FINDINGS"] = _link(
            "FINDINGS", "RECORDED" if ev["findings"] else "NONE",
            [
                _rec("FINDING", None, f"{f['control_code']}" + (f" / {f['obligation']}" if f.get("obligation") else "") + f": {f['rule']['rule_code']}", sha256=f["finding_key"], of="the finding's identity: rule, item and evidence", source="Generated by the existing findings engine under the pinned rule set; a simulation finding, not an operational one", control_code=f["control_code"], obligation=f.get("obligation"), rule=f["rule"].get("rule_code"), trigger=f.get("trigger"), severity=f.get("severity"), severity_source=f.get("severity_source"), simulation_id=f.get("simulation_id"), observation_seq=f.get("observation_seq"), placement=f.get("placement"), question=f.get("question_revision_id"))
                for f in ev["findings"]
            ],
            ["Severities come from the synthetic finding rule set as published; none is an approved compliance severity.", f"{len(ev.get('not_converted') or [])} evaluated discrepancy(ies) matched no rule of the pinned rule set and produced no finding." if ev.get("not_converted") else "Every evaluated discrepancy that a pinned rule covers produced a finding.", "No operational finding, case or disposition is created."],
        )  # fmt: skip
    if not with_assurance:
        links["EXECUTION_ASSURANCE"] = _link(
            "EXECUTION_ASSURANCE", "NOT_AVAILABLE", notes=["Execution assurance is not switched on for this server."]
        )
    elif asr is None:
        links["EXECUTION_ASSURANCE"] = _link(
            "EXECUTION_ASSURANCE",
            none_yet,
            notes=[
                "The execution of this journey has not been checked"
                + (" beside this evaluation." if ev is not None and assurances else ".")
            ],
        )
    else:
        links["EXECUTION_ASSURANCE"] = _link(
            "EXECUTION_ASSURANCE", "RECORDED",
            [_rec("EXECUTION_ASSURANCE", asr["id"], "Execution assurance of the journey", version=asr["contract"], sha256=asr["result_sha256"], of="the whole assurance result: every check of every survey", source="Verified from the recorded executions by the assurance verifier; executes nothing", input_sha256=asr["input_sha256"], status=asr["status"], current_status=asr["current_status"], recomputes_to_its_record=asr["replay"]["consistent"], beside_evaluation=str(asr["evaluation_id"]) if asr["evaluation_id"] else None, surveys=[{"position": s["position"], "status": s["status"], "simulation_id": s.get("simulation_id"), "run_sha256": s.get("run_sha256")} for s in asr["surveys"]], journey_checks=[{"check": c["check"], "status": c["status"]} for c in asr["journey_checks"]] or None, deviations=[f.get("code") for f in asr["findings"]] or None, summary=asr["summary"], created_at=str(asr["created_at"]))],
            ["Verified against the recording only. A simulation does not show that a person heard any wording.", "A deviation creates no finding, severity or disposition."],
        )  # fmt: skip

    # ---- the five statements, kept apart
    cov = (ev or {}).get("coverage") or {}
    dimensions = {
        "completion": _completion(kind, status, sims, (co or {}).get("stop")),
        "satisfaction": (
            {"status": "EVALUATED", "by_outcome": ev["summary"]["by_outcome"], "controls": ev["summary"]["controls"], "findings": ev["summary"]["findings"], "processing_status": ev["processing_status"], "note": "Each control obligation has its own outcome. There is no overall 'satisfied' for a journey."}
            if ev
            else {"status": "NOT_EVALUATED", "note": "No evaluation of this journey is shown."}
        ),
        "coverage": (
            {"status": cov.get("status"), "reason": cov.get("reason"), "required": cov.get("required"), "evidenced": cov.get("evidenced"), "by_instance": cov.get("by_instance"), "policy_completeness": cov.get("policy_completeness"), "note": "Coverage is about evidence within the named policy's declared scope, not about results, and not about every control the business may have."}
            if ev
            else {"status": "NOT_EVALUATED", "note": "No evaluation of this journey is shown."}
        ),
        "assurance": (
            {"status": asr["current_status"], "recorded_status": asr["status"], "surveys": asr["summary"].get("by_status"), "deviations": len(asr["findings"]), "note": "Whether the recorded execution followed the survey versions it pinned. It is not a control outcome."}
            if asr
            else {"status": "NOT_AVAILABLE" if not with_assurance else "NOT_CHECKED", "note": "The execution of this journey has not been checked." if with_assurance else "Execution assurance is not switched on for this server."}
        ),
        "eligibility": ELIGIBILITY,
    }  # fmt: skip

    # ---- what is not verified or not decided, said once and in one place
    open_points: list[dict[str, str]] = [
        {
            "code": "SYNTHETIC_CONTENT",
            "text": "Every application, rule condition, control, obligation, mapping, finding rule and severity here is synthetic. None is approved business or compliance content.",
        }
    ]
    if comp is not None:
        doc = comp["composite"]
        if (doc.get("input_consistency") or {}).get("status") != "VERIFIED":
            open_points.append(
                {
                    "code": "INPUT_CONSISTENCY_UNVERIFIED",
                    "text": "Nothing maps the assignment inputs to the facts the surveys and the control policy read: that they describe one application is unverified.",
                }
            )
        if (doc.get("cross_survey_policy") or {}).get("status") == "UNRESOLVED":
            open_points.append(
                {
                    "code": "CROSS_SURVEY_POLICY_UNRESOLVED",
                    "text": "What should happen between surveys on a live call — after a refusal, an escalation, an incomplete survey — is undecided. The simulation proceeds only after a completed survey.",
                }
            )
    if ev is not None and ev.get("policy"):
        open_points.append(
            {
                "code": "POLICY_NAMED_EXPLICITLY",
                "text": "The control policy was chosen by the person who ran the evaluation. No rule selects the control policy that applies to an application.",
            }
        )
        if ((ev.get("applicability") or {}).get("input_lineage") or {}).get("status") != "VERIFIED":
            open_points.append(
                {
                    "code": "INPUT_LINEAGE_UNVERIFIED",
                    "text": "The facts the policy's conditions read are those given to the simulation; their lineage to a real application is unverified.",
                }
            )
    open_points.append(
        {"code": "NOT_SPOKEN", "text": "No wording was spoken or heard. This is a simulation in a browser."}
    )

    # ---- "what evidence was missing or contradictory?": the evaluation's OWN results, filtered — nothing is computed
    settled = ("EVIDENCED", "NOT_REQUIRED") if ev is not None and ev.get("policy") else None
    evidence_gaps = [
        {
            "control_code": c["control_code"], "obligation": c.get("obligation"), "outcome": c["outcome"], "coverage": c.get("coverage"),
            "why": [r.get("text") for r in c.get("reasons") or [] if r.get("text")],
            "evidence": [{"survey": (o.get("survey") or {}).get("survey_code"), "simulation_id": o.get("simulation_id"), "placement": o.get("placement"), "result": o.get("result"), "gap": o.get("gap"), "explanation": o.get("explanation")} for o in c.get("observations") or []],
        }
        for c in (ev["controls"] if ev is not None else [])
        if (c.get("coverage") not in settled if settled else c["outcome"] in ("INSUFFICIENT_EVIDENCE", "REQUIRES_REVIEW", "UNRESOLVED"))
    ]  # fmt: skip

    order = [k for _, _, keys in QUESTIONS for k in keys]
    chain = [dict(links[k], step=n) for n, k in enumerate(order, start=1)]
    integrity = [
        *([{"record": "COMPOSITE_PLAN", "check": "recomputes to its recorded fingerprint", "ok": bool(comp["recompute_consistent"])}] if comp is not None else []),
        *([{"record": "COORDINATED_SIMULATION", "check": "the composite it was started from is intact", "ok": bool(co["composite_intact"])}] if co is not None else []),
        *[{"record": f"SIMULATION {p}", "check": "replays to its recorded fingerprint", "ok": bool(s["replay_consistent"])} for p, s, _, _ in sims if s is not None],
        *([{"record": "JOURNEY_EVALUATION", "check": "recomputes to its recorded result", "ok": bool(ev["replay"]["consistent"])}] if ev is not None else []),
        *([{"record": "EXECUTION_ASSURANCE", "check": "recomputes to its recorded result", "ok": bool(asr["replay"]["consistent"])}] if asr is not None else []),
    ]  # fmt: skip
    fingerprints = [[link["key"], r["kind"], r["id"], r["sha256"]] for link in chain for r in link["records"]]
    return {
        "record_class": RECORD_CLASS, "note": NOTE, "contract": CONTRACT, "market_code": market,
        "journey": {"kind": kind, "id": str(jid), "label": label, "status": status},
        "evaluation_id": ev["id"] if ev else None, "assurance_id": asr["id"] if asr else None,
        "evaluations": [{"id": e["id"], "created_at": e["created_at"], "status": e["processing_status"], "coverage_status": e.get("coverage_status"), "policy": (e.get("policy") or {}).get("code") if isinstance(e.get("policy"), dict) else None, "result_sha256": e["result_sha256"]} for e in evaluations],
        "assurances": [{"id": a["id"], "created_at": a["created_at"], "status": a["status"], "evaluation_id": a["evaluation_id"], "result_sha256": a["result_sha256"]} for a in assurances],
        "dimensions": dimensions,
        "questions": [{"key": k, "question": q, "links": list(keys)} for k, q, keys in QUESTIONS],
        "chain": chain,
        "evidence_gaps": evidence_gaps,
        "integrity": {"all_records_recompute": all(i["ok"] for i in integrity), "checks": integrity},
        "open_points": open_points,
        "trace_sha256": sha256_hex(fingerprints),
        "operational_call_eligibility": ELIGIBILITY,
    }  # fmt: skip
