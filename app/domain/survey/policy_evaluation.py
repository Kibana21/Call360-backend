# ruff: noqa: E501 — records are kept one per line
"""EVAL-2A — applicability, evaluation and COVERAGE of a journey under a governed control policy. Pure.

A control policy says which controls of the register must be assessed, when each obligation applies and what evidence
it requires — independently of any survey question. This module answers, for one synthetic journey:

  * which obligations are required, which do not apply, and which cannot be decided (three-valued; unknown stays
    unknown), with a fingerprint of that determination;
  * for each required obligation, whether a governed mapping supplies its required evidence, and what the evidence
    says — by the EVAL-1 adapter, the existing answer evaluator and the existing finding engine, unchanged;
  * how far the journey's evidence COVERS what the policy requires.

Four things are kept apart: the processing status of the evaluation, the outcome of each control instance, the
coverage of each instance and of the journey, and operational compliance eligibility — which is never established
here. Complete coverage is asserted only inside a policy that is DECLARED complete, for an application inside its
scope, when every required obligation has trustworthy evidence; never because every survey question was answered.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain.survey import control_evaluation as ce
from app.domain.survey.canonical import sha256_hex

CONTRACT = "call360.survey.control-evaluation/2 (policy-scoped)"
INSTANCE_COVERAGE = (
    "EVIDENCED", "EVIDENCE_MISSING", "NOT_MAPPED", "APPLICABILITY_UNKNOWN", "EVIDENCE_CONFLICTING",
    "EVALUATION_UNSUPPORTED", "HUMAN_ASSESSMENT_PENDING", "INTEGRITY_FAILED", "NOT_REQUIRED",
)  # fmt: skip
JOURNEY_COVERAGE = ("COMPLETE_WITHIN_POLICY_SCOPE", "INCOMPLETE", "NOT_ASSERTED")
ELIGIBILITY = {
    "status": "NOT_ESTABLISHED",
    "note": "Operational compliance eligibility is not established by any simulation, evaluation or coverage result.",
}
LINEAGE = {
    "status": "UNVERIFIED",
    "note": "The application's facts are catalog facts given to the simulation. Nothing governed maps assignment-rule inputs, call-plan facts and evaluation policy facts to one another, so their consistency and lineage are unverified.",
}
COVERAGE_NOTE = (
    "Coverage is about evidence, not about results: 'complete' means that, within this policy's declared scope, every "
    "control it requires has trustworthy evaluation evidence. It does not mean the controls are satisfied, it is never "
    "inferred from survey questions having been answered, and it establishes nothing about a real application."
)


def policy_ref(p: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(p["id"]),
        "code": p["code"],
        "revision": p["revision"],
        "name": p["name"],
        "sha256": p["policy_sha256"],
        "completeness": p["completeness"],
    }


def determine(policy: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    """Which obligations of the policy are required for this application. Deterministic, with a fingerprint."""
    scope = ce.applicability_of({"applicability": policy.get("scope")}, facts)
    scope_status = {"APPLICABLE": "IN_SCOPE", "NOT_APPLICABLE": "OUT_OF_SCOPE", "UNKNOWN": "UNKNOWN"}[scope["status"]]
    obligations = []
    for c in policy["controls"]:
        for ob in c["obligations"]:
            a = ce.applicability_of({"applicability": ob.get("applicability")}, facts)
            if a["basis"] == "DECLARED_FOR_EVERY_JOURNEY":
                a = a | {
                    "explanation": "The control policy requires this obligation for every application in its scope"
                }
            obligations.append(
                {
                    "control_code": c["control"]["code"],
                    "obligation": ob["key"],
                    "title": ob["title"],
                    "status": a["status"],
                    "applicability": a,
                }
            )
    missing = sorted(
        {m for o in obligations for m in o["applicability"].get("missing", [])} | set(scope.get("missing", []))
    )
    body = {
        "policy_sha256": policy["policy_sha256"], "facts_sha256": sha256_hex(dict(facts)), "scope": scope_status,
        "obligations": [[o["control_code"], o["obligation"], o["status"]] for o in obligations],
    }  # fmt: skip
    return {
        "policy": policy_ref(policy), "scope": {"status": scope_status, "statement": policy["scope_statement"], "detail": scope},
        "obligations": obligations, "missing_inputs": missing,
        "counts": {s: sum(1 for o in obligations if o["status"] == s) for s in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN")},
        "input_lineage": LINEAGE, "fingerprint": sha256_hex(body),
    }  # fmt: skip


def _bind(
    control: Mapping[str, Any], mapping: Mapping[str, Any] | None
) -> tuple[dict[tuple[str, str], list[tuple[int, Mapping[str, Any]]]], list[dict[str, Any]]]:
    """(obligation key, requirement key) → the mapping entries that supply it; and what is inconsistent."""
    bound: dict[tuple[str, str], list[tuple[int, Mapping[str, Any]]]] = {}
    problems: list[dict[str, Any]] = []
    if mapping is None:
        return bound, problems
    keys = {(ob["key"], r["key"]): r for ob in control["obligations"] for r in ob["evidence"]}
    only = control["obligations"][0]["key"] if len(control["obligations"]) == 1 else None
    for index, e in enumerate(mapping["entries"]):
        item = f"{e['item']['code']} v{e['item']['version']}"
        ob, req = e.get("obligation") or only, e.get("requirement")
        if not req or ob is None:
            problems.append(
                {
                    "code": "MAPPING_ENTRY_NOT_BOUND",
                    "text": f"The mapping's evidence {item} names no evidence requirement of the policy, so it cannot be counted towards any",
                }
            )
        elif (ob, req) not in keys:
            problems.append(
                {
                    "code": "MAPPING_ENTRY_NOT_IN_POLICY",
                    "text": f"The mapping's evidence {item} names requirement {ob}/{req}, which this policy revision does not have",
                }
            )
        elif keys[(ob, req)]["evidence_type"] != e["evidence_type"]:
            problems.append(
                {
                    "code": "MAPPING_EVIDENCE_TYPE_DIFFERS",
                    "text": f"{item} is mapped as {e['evidence_type'].lower()} evidence, but requirement {ob}/{req} asks for {keys[(ob, req)]['evidence_type'].lower()} evidence",
                }
            )
        else:
            bound.setdefault((ob, req), []).append((index, e))
    return bound, problems


def instance_coverage(
    outcome: str, reasons: Sequence[Mapping[str, Any]], observations: Sequence[Mapping[str, Any]]
) -> str:
    """Coverage of one APPLICABLE, fully mapped, trusted control instance, from its evidence."""
    required = [o for o in observations if o["required"]]
    results = {o["result"] for o in required}
    if any(r["code"] == "EVIDENCE_CONFLICT" for r in reasons):
        return "EVIDENCE_CONFLICTING"
    if not required or results & {"UNSUPPORTED_EVIDENCE", "NOT_EVALUATED"}:
        return "EVALUATION_UNSUPPORTED"
    if results & set(ce.GAPS):
        return "EVIDENCE_MISSING"
    if "HUMAN_ASSESSMENT_REQUIRED" in results:
        return "HUMAN_ASSESSMENT_PENDING"
    return "EVIDENCED" if outcome in ("SATISFIED", "NOT_SATISFIED") else "EVALUATION_UNSUPPORTED"


def journey_coverage(
    policy: Mapping[str, Any], scope: str, trusted: bool, instances: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    by = {c: sum(1 for i in instances if i["coverage"] == c) for c in INSTANCE_COVERAGE}
    required = [i for i in instances if i["coverage"] not in ("NOT_REQUIRED", "APPLICABILITY_UNKNOWN")]
    gaps = [
        {"control_code": i["control_code"], "obligation": i["obligation"], "coverage": i["coverage"]}
        for i in instances
        if i["coverage"] not in ("EVIDENCED", "NOT_REQUIRED")
    ]
    out: dict[str, Any] = {
        "by_instance": by, "required": len(required), "evidenced": by["EVIDENCED"], "gaps": gaps, "note": COVERAGE_NOTE,
        "policy_completeness": policy["completeness"], "scope": scope,
    }  # fmt: skip

    def no(reason: str, text: str) -> dict[str, Any]:
        return out | {"status": "NOT_ASSERTED", "reason": reason, "explanation": text}

    if not trusted:
        return no(
            "EVIDENCE_NOT_TRUSTED",
            "The journey's evidence or replay could not be trusted, so nothing is asserted about coverage",
        )
    if policy["completeness"] != "DECLARED_COMPLETE":
        return no(
            "POLICY_PARTIAL",
            "This policy is not declared complete: it does not claim to list every control to assess, so complete coverage cannot be asserted under it",
        )
    if scope == "OUT_OF_SCOPE":
        return no(
            "OUT_OF_POLICY_SCOPE",
            "This application is outside the policy's declared scope; the policy says nothing about it",
        )
    if scope == "UNKNOWN":
        return no("POLICY_SCOPE_UNKNOWN", "Whether this application is inside the policy's scope could not be decided")
    if by["APPLICABILITY_UNKNOWN"]:
        return out | {
            "status": "INCOMPLETE",
            "reason": "APPLICABILITY_UNKNOWN",
            "explanation": "Whether some obligations apply could not be decided, so the set of required controls is not known",
        }
    if not required:
        if policy.get("empty_set_is_complete"):
            return out | {
                "status": "COMPLETE_WITHIN_POLICY_SCOPE",
                "reason": "EMPTY_SET_DECLARED_COMPLETE",
                "explanation": "No obligation of this policy applies to this application, and the policy expressly declares that outcome complete",
            }
        return no(
            "EMPTY_APPLICABLE_SET",
            "No obligation of this policy applies to this application. The policy does not say that this means full coverage, so none is asserted",
        )
    if gaps:
        return out | {
            "status": "INCOMPLETE",
            "reason": "REQUIRED_CONTROLS_NOT_EVIDENCED",
            "explanation": f"{len(gaps)} of {len(required)} required control instances lack trustworthy evaluation evidence",
        }
    return out | {
        "status": "COMPLETE_WITHIN_POLICY_SCOPE",
        "reason": "ALL_REQUIRED_EVIDENCED",
        "explanation": f"Within this policy's declared scope, all {len(required)} required control instances have trustworthy evaluation evidence. This is not a statement that they are satisfied",
    }


def evaluate_under_policy(
    journey: Mapping[str, Any],
    controls: Sequence[Mapping[str, Any]],
    mappings: Mapping[str, Mapping[str, Any]],
    rule_set: fe.RuleSet | None,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """The evaluation of one journey under one policy revision. The control instances are the policy's obligations —
    not whatever happened to be mapped. Deterministic."""
    executions = list(journey["executions"])
    placed = [(x, p) for x in executions for p in ce.placements(x["bundle"])]
    trusted = bool(journey["trusted"])
    register = {c["control_code"]: c for c in controls}
    determination = determine(policy, journey["facts"])
    applies = {(o["control_code"], o["obligation"]): o["applicability"] for o in determination["obligations"]}
    instances: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    not_converted: list[dict[str, Any]] = []
    human: list[dict[str, Any]] = []
    seq = 0
    for pc in sorted(policy["controls"], key=lambda c: c["control"]["code"]):
        code = pc["control"]["code"]
        c = register.get(code)
        m = mappings.get(code)
        bound, problems = _bind(pc, m)
        for ob in pc["obligations"]:
            line: dict[str, Any] = {
                "control_code": code, "obligation": ob["key"], "obligation_title": ob["title"], "control_name": c["name"] if c else code,
                "control_id": str(c["id"]) if c else pc["control"]["id"], "control_sha256": ce.control_sha256(c) if c else None,
                "owner_role": c["owner_role"] if c else None, "content_approval_status": c["content_approval_status"] if c else None,
                "purpose": pc["purpose"], "description": pc.get("description") or "",
                "policy": {"id": str(policy["id"]), "code": policy["code"], "revision": policy["revision"], "sha256": policy["policy_sha256"]},
                "mapping": {"id": str(m["id"]), "revision": m["revision"], "sha256": m["mapping_sha256"], "combination": ob["combination"], "source": m["source"]} if m else None,
                "applicability": applies[(code, ob["key"])], "requirements": [], "outcome": "UNRESOLVED", "coverage": "NOT_MAPPED",
                "reasons": [], "observations": [], "findings": 0,
            }  # fmt: skip
            instances.append(line)
            for r in ob["evidence"]:
                entries = bound.get((ob["key"], r["key"]), [])
                line["requirements"].append(
                    r | {"mapped_entries": len(entries), "status": "MAPPED" if entries else "NOT_MAPPED"}
                )
            if not trusted:
                line["coverage"] = "INTEGRITY_FAILED"
                line["reasons"] = [
                    {
                        "code": "EVIDENCE_INTEGRITY_FAILED",
                        "text": "The journey's evidence could not be trusted, so no control outcome is asserted",
                    }
                ]
                continue
            if c is None or line["control_sha256"] != pc["control"]["sha256"]:
                line["coverage"] = "EVALUATION_UNSUPPORTED"
                line["reasons"] = [
                    {
                        "code": "CONTROL_CHANGED_SINCE_POLICY",
                        "text": "The control of the register is not the one this policy revision was governed for; the policy no longer speaks for it",
                    }
                ]
                continue
            if ob["combination"] not in ce.COMBINATIONS:
                line["coverage"] = "EVALUATION_UNSUPPORTED"
                line["reasons"] = [
                    {
                        "code": "COMBINATION_UNSUPPORTED",
                        "text": f"Evidence combination {ob['combination']} has no approved meaning",
                    }
                ]
                continue
            status = line["applicability"]["status"]
            if status == "NOT_APPLICABLE":
                line["outcome"], line["coverage"] = "NOT_APPLICABLE", "NOT_REQUIRED"
                line["reasons"] = [{"code": "APPLICABILITY_FALSE", "text": line["applicability"]["explanation"]}]
                continue
            # the evidence that IS mapped is always looked at and shown, whatever is decided about the instance
            for r in ob["evidence"]:
                for index, e in bound.get((ob["key"], r["key"]), []):
                    entry = dict(e) | {"required": bool(r["required"])}
                    item = entry["item"]
                    hits = [
                        (x, p)
                        for x, p in placed
                        if p["item_code"] == item["code"]
                        and p["item_version"] == int(item["version"])
                        and (not entry.get("survey_code") or x["survey_code"] == entry["survey_code"])
                    ]
                    got = [ce.observe(x, p, entry) for x, p in hits] or [
                        ce._absent(
                            entry,
                            sorted(
                                {
                                    p["item_version"]
                                    for x, p in placed
                                    if p["item_code"] == item["code"]
                                    and (not entry.get("survey_code") or x["survey_code"] == entry["survey_code"])
                                }
                            ),
                        )
                    ]
                    for o in got:
                        seq += 1
                        line["observations"].append(
                            o
                            | {
                                "seq": seq,
                                "entry": index,
                                "context": entry.get("survey_code"),
                                "requirement": r["key"],
                                "obligation": ob["key"],
                            }
                        )
            unmapped = [r["key"] for r in line["requirements"] if r["required"] and r["status"] == "NOT_MAPPED"]
            gaps: list[dict[str, Any]] = []
            if m is None:
                gaps.append(
                    {
                        "code": "MAPPING_MISSING",
                        "text": "The policy requires this control, and no published mapping connects it to survey evidence in this market. It is not treated as satisfied, and not as unnecessary",
                    }
                )
            else:
                gaps += [
                    {
                        "code": "REQUIRED_EVIDENCE_NOT_MAPPED",
                        "requirement": k,
                        "text": f"The policy requires evidence '{k}', and the published mapping supplies none for it",
                    }
                    for k in unmapped
                ]
                gaps += problems
            if not any(r["required"] for r in ob["evidence"]):
                gaps.append(
                    {
                        "code": "NO_REQUIRED_EVIDENCE",
                        "text": "This obligation names no required evidence; an empty requirement never satisfies a control",
                    }
                )
            if status == "UNKNOWN":
                line["coverage"] = "APPLICABILITY_UNKNOWN"
                line["reasons"] = [
                    {
                        "code": "APPLICABILITY_UNKNOWN",
                        "missing": line["applicability"].get("missing", []),
                        "text": line["applicability"]["explanation"] + ". Unknown is not 'does not apply'",
                    },
                    *gaps,
                ]
                continue
            if gaps:
                line["reasons"] = gaps
                continue
            line["outcome"], line["reasons"] = ce._decide(line["observations"])
            line["coverage"] = instance_coverage(line["outcome"], line["reasons"], line["observations"])
            for o in line["observations"]:
                if rule_set is None or o["evaluation"] is None:
                    continue
                ref = f"{o['simulation_id'] or 'no-execution'}#{o['placement'] or 'absent'}#{code}#{ob['key']}#{o['entry']}"
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
                    "evaluation_ref": None, "evaluation_engine": ae.ENGINE, "fact_source": ce.NO_FACTS.as_dict(),
                }  # fmt: skip
                g = fe.generate([o["evaluation"] | {"mandatory": o["required"]}], content, rule_set, ctx)
                tag = {
                    "control_code": code,
                    "obligation": ob["key"],
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

    in_policy = {pc["control"]["code"] for pc in policy["controls"]}
    mapped = {(e["item"]["code"], int(e["item"]["version"])) for m in mappings.values() for e in m["entries"]}
    by = {o: sum(1 for i in instances if i["outcome"] == o) for o in ce.OUTCOMES}
    coverage = journey_coverage(policy, determination["scope"]["status"], trusted, instances)
    if not trusted:
        processing = "FAILED_TECHNICALLY"
    elif by["REQUIRES_REVIEW"]:
        processing = "REQUIRES_REVIEW"
    elif not journey["complete"] or by["INSUFFICIENT_EVIDENCE"] or by["UNRESOLVED"]:
        processing = "INCOMPLETE"
    else:
        processing = "COMPLETED"
    result: dict[str, Any] = {
        "contract": CONTRACT, "policy": policy_ref(policy),
        "journey": {
            "kind": journey["kind"], "id": str(journey["id"]), "status": journey["status"], "complete": bool(journey["complete"]),
            "trusted": trusted, "problems": list(journey["problems"]),
            "executions": [ce._survey_ref(x) | {"survey_name": x["survey_name"], "simulation_id": str(x["simulation_id"]) if x.get("simulation_id") else None, "run_sha256": x.get("run_sha256"), "ending": ((x.get("run") or {}).get("terminal") or {}).get("state")} for x in executions],
        },
        "applicability": {k: determination[k] for k in ("scope", "missing_inputs", "counts", "input_lineage", "fingerprint")},
        "processing_status": processing,
        "summary": {
            "controls": len(instances), "by_outcome": by, "applicable": sum(1 for i in instances if i["applicability"]["status"] == "APPLICABLE"),
            "findings": len(findings), "not_converted": len(not_converted), "human_assessment_items": len(human),
            "surveys": len(executions), "surveys_completed": sum(1 for x in executions if x["state"] == "COMPLETED"),
        },
        "coverage": coverage | {
            "controls_without_mapping": sorted({i["control_code"] for i in instances if i["mapping"] is None}),
            "controls_with_unknown_applicability": sorted({i["control_code"] for i in instances if i["applicability"]["status"] == "UNKNOWN"}),
            "controls_outside_policy": sorted(set(register) - in_policy),
            "items_without_mapping": [
                {"survey": ce._survey_ref(x), "placement": p["key"], "item": {"code": p["item_code"], "version": p["item_version"], "name": p["item_name"], "answer_type": p["answer_type"]}}
                for x, p in placed if (p["item_code"], p["item_version"]) not in mapped
            ],
        },
        "operational_compliance_eligibility": ELIGIBILITY,
        "finding_rules": rule_set.ref() if rule_set else None,
        "findings_status": "NOT_GENERATED_EVIDENCE_NOT_TRUSTED" if not trusted else "GENERATED" if rule_set else "FINDING_RULES_MISSING",
        "controls": instances, "findings": findings, "not_converted": not_converted, "human_assessment": human,
        "engines": {"answer_evaluation": ae.ENGINE, "findings": fe.ENGINE, "control_evaluation": CONTRACT},
    }  # fmt: skip
    return result | {"result_sha256": sha256_hex(result)}
