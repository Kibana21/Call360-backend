"""S3-B deterministic compliance findings engine (COMP-008, REG-007, REV routing input; provider-independent, no LLM).

Pure: no database, clock, randomness or model. It converts S3-A answer-evaluation results into structured,
evidence-backed **findings** using a governed, versioned **finding rule set** (maker-checker; immutable once
published). Nothing is classified as a regulatory breach and no case is verified or closed here.

- **Triggers** are evaluation outcomes that may become findings: ``MISMATCH``, ``UNRESOLVED``, ``NOT_ASKED``,
  ``MISSING_EXPECTED_FACT``, ``HUMAN_ASSESSMENT_REQUIRED``. ``MATCH``, ``NOT_EVALUATED`` and ``NOT_APPLICABLE`` never
  produce a finding.
- Each trigger has a fixed **finding class** (system-defined, not configurable) so customer discrepancies are kept
  apart from missing evidence and system-data issues: MISMATCH → ``CUSTOMER_DISCREPANCY``; UNRESOLVED / NOT_ASKED →
  ``MISSING_EVIDENCE``; MISSING_EXPECTED_FACT → ``SYSTEM_DATA_ISSUE``; HUMAN_ASSESSMENT_REQUIRED → ``HUMAN_ASSESSMENT``.
- A **rule** applies to a question (by code), to the questions linked to a compliance control, or to any question
  (optionally mandatory only), for one trigger; it sets the governed finding category, description, severity with
  its justification, and whether human review is required (always for human-assessment items). Severity comes only
  from the published (or explicitly chosen draft, in simulation) rule set — never assumed.
- **Precedence** is by specificity: question rules, else control rules, else any-question rules. Every rule at the
  most specific matching level produces its own finding (two control rules → two findings, each naming its control);
  nothing is chosen arbitrarily.
- A triggering outcome that no rule covers is reported as **not converted** (with the reason), never silently dropped
  and never turned into a finding by default — not every mismatch is a finding.
- Each finding has a deterministic ``finding_key`` (execution, rule set checksum, rule, question, trigger), so
  repeated generation from the same inputs yields the same findings and duplicates can be refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.domain.digest import sha256_of

ENGINE = "call360.finding-engine/1 (S3-B deterministic)"
TRIGGERS = ("MISMATCH", "UNRESOLVED", "NOT_ASKED", "MISSING_EXPECTED_FACT", "HUMAN_ASSESSMENT_REQUIRED")
TRIGGER_CLASS = {
    "MISMATCH": "CUSTOMER_DISCREPANCY",
    "UNRESOLVED": "MISSING_EVIDENCE",
    "NOT_ASKED": "MISSING_EVIDENCE",
    "MISSING_EXPECTED_FACT": "SYSTEM_DATA_ISSUE",
    "HUMAN_ASSESSMENT_REQUIRED": "HUMAN_ASSESSMENT",
}
CLASS_LABEL = {
    "CUSTOMER_DISCREPANCY": "Customer discrepancy",
    "MISSING_EVIDENCE": "Missing evidence",
    "SYSTEM_DATA_ISSUE": "System-data issue",
    "HUMAN_ASSESSMENT": "Human assessment",
}
# The S0 finding taxonomy (ck_finding_category) plus two S3-B categories for the non-customer classes.
CATEGORIES = (
    "FACT_MISMATCH",
    "MISSING_MANDATORY_ANSWER",
    "UNCLEAR_UNDERSTANDING",
    "CONTRADICTORY_ANSWER",
    "DISCLOSURE_CONCERN",
    "POLICY_DATA_ISSUE",
    "NARRATIVE_REVIEW",
)
TRIGGER_CATEGORIES: dict[str, tuple[str, ...]] = {
    "MISMATCH": ("FACT_MISMATCH", "UNCLEAR_UNDERSTANDING", "DISCLOSURE_CONCERN", "CONTRADICTORY_ANSWER"),
    "UNRESOLVED": ("MISSING_MANDATORY_ANSWER", "UNCLEAR_UNDERSTANDING"),
    "NOT_ASKED": ("MISSING_MANDATORY_ANSWER",),
    "MISSING_EXPECTED_FACT": ("POLICY_DATA_ISSUE",),
    "HUMAN_ASSESSMENT_REQUIRED": ("NARRATIVE_REVIEW", "DISCLOSURE_CONCERN"),
}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")  # compliance finding severity — never an SBQ risk band
SCOPES = ("QUESTION", "CONTROL", "ANY_QUESTION")
SCOPE_RANK = {"QUESTION": 0, "CONTROL": 1, "ANY_QUESTION": 2}
RULE_CODE_RE = re.compile(r"^FR-[A-Z0-9][A-Z0-9_-]{2,40}$")
QUESTION_RE = re.compile(r"^Q-[A-Z0-9_-]{3,57}$")
CONTROL_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,39}$")
MAX_RULES = 200
NOTE = (
    "Findings are flagged potential concerns for human review, generated deterministically from approved finding "
    "rules. They are not regulatory breach determinations, case decisions or verification outcomes."
)


class RulesInvalid(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def normalise_rules(rules: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate structured rules (governed values only) and return the stored form. Raises ``RulesInvalid``."""
    problems: list[str] = []
    out: list[dict[str, Any]] = []
    if len(rules) > MAX_RULES:
        problems.append(f"At most {MAX_RULES} rules")
    seen: set[str] = set()
    keys: dict[tuple[str, str, str, bool], str] = {}
    for i, r in enumerate(rules, start=1):
        code = str(r.get("rule_code") or "").strip().upper()
        where = f"Rule {i}" + (f" ({code})" if code else "")
        p: list[str] = []
        if not RULE_CODE_RE.match(code):
            p.append(f"{where}: rule code must look like FR-TERM-MISMATCH")
        elif code in seen:
            p.append(f"{where}: duplicate rule code")
        seen.add(code)
        scope = r.get("scope") or "QUESTION"
        target = str(r.get("target") or "").strip().upper() or None
        if scope not in SCOPES:
            p.append(f"{where}: scope must be one of {', '.join(SCOPES)}")
        elif scope == "QUESTION" and not (target and QUESTION_RE.match(target)):
            p.append(f"{where}: choose the question code (Q-…)")
        elif scope == "CONTROL" and not (target and CONTROL_RE.match(target)):
            p.append(f"{where}: choose the compliance control code")
        elif scope == "ANY_QUESTION":
            target = None
        trigger = r.get("trigger")
        if trigger not in TRIGGERS:
            p.append(f"{where}: trigger must be one of {', '.join(TRIGGERS)}")
        category = r.get("category")
        if trigger in TRIGGERS and category not in TRIGGER_CATEGORIES[trigger]:
            p.append(
                f"{where}: category for a {trigger.replace('_', ' ').lower()} trigger must be one of "
                + ", ".join(TRIGGER_CATEGORIES[trigger])
            )
        severity = r.get("severity")
        if severity not in SEVERITIES:
            p.append(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        justification = str(r.get("severity_justification") or "").strip()
        if not 10 <= len(justification) <= 300:
            p.append(f"{where}: give the severity justification (10–300 characters); no severity is assumed")
        description = str(r.get("description") or "").strip()
        if not 10 <= len(description) <= 300:
            p.append(f"{where}: description must be 10–300 characters")
        review = bool(r.get("review_required", True)) or trigger == "HUMAN_ASSESSMENT_REQUIRED"
        mandatory_only = bool(r.get("mandatory_only")) if scope != "QUESTION" else False
        if not p:
            key = (str(scope), str(target), str(trigger), mandatory_only)
            if key in keys:
                p.append(f"{where}: same scope, target and trigger as {keys[key]} (ambiguous)")
            keys[key] = code
        problems += p
        out.append(
            {
                "rule_code": code,
                "scope": scope,
                "target": target,
                "mandatory_only": mandatory_only,
                "trigger": trigger,
                "finding_class": TRIGGER_CLASS.get(str(trigger)),
                "category": category,
                "description": description,
                "severity": severity,
                "severity_justification": justification,
                "review_required": review,
            }
        )
    if problems:
        raise RulesInvalid(problems)
    return sorted(out, key=lambda x: x["rule_code"])


def describe_rule(r: Mapping[str, Any]) -> str:
    where = {
        "QUESTION": f"question {r.get('target')}",
        "CONTROL": f"questions linked to control {r.get('target')}",
        "ANY_QUESTION": "any " + ("mandatory " if r.get("mandatory_only") else "") + "question",
    }[str(r.get("scope"))]
    return (
        f"{r['rule_code']}: when {where} is {str(r.get('trigger', '')).replace('_', ' ').lower()} → "
        f"{str(r.get('category', '')).replace('_', ' ').lower()} finding, severity {r.get('severity')}"
        + (", human review required" if r.get("review_required") else "")
    )


@dataclass(frozen=True)
class RuleSet:
    version_id: str | None
    label: str
    status: str
    rules: tuple[Mapping[str, Any], ...]
    sha256: str = ""

    @staticmethod
    def of(version_id: str | None, label: str, status: str, rules: Sequence[Mapping[str, Any]]) -> RuleSet:
        rs = [dict(r) for r in rules]
        return RuleSet(version_id, label, status, tuple(rs), sha256_of(rs))

    def ref(self) -> dict[str, Any]:
        return {"version_id": self.version_id, "label": self.label, "status": self.status, "sha256": self.sha256}


@dataclass
class Generation:
    findings: list[dict[str, Any]] = field(default_factory=list)
    not_converted: list[dict[str, Any]] = field(default_factory=list)
    human_assessment: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        by: dict[str, dict[str, int]] = {}
        for f in self.findings:
            by.setdefault(f["category"], {}).setdefault(f["severity"], 0)
            by[f["category"]][f["severity"]] += 1
        classes: dict[str, int] = {}
        for f in self.findings:
            classes[f["finding_class"]] = classes.get(f["finding_class"], 0) + 1
        return {
            "findings": len(self.findings),
            "by_category_severity": by,
            "by_class": classes,
            "review_required": sum(1 for f in self.findings if f["review_required"]),
            "not_converted": len(self.not_converted),
            "human_assessment_items": len(self.human_assessment),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "not_converted": self.not_converted,
            "human_assessment": self.human_assessment,
            "summary": self.summary(),
            "engine": ENGINE,
            "note": NOTE,
        }


def controls_of(content: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Compliance controls linked to each question in the frozen script content (code, name, mapping status, ref)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for sec in content.get("sections", []):
        for q in sec.get("questions", []):
            out[q["question_code"]] = [
                {
                    "control_code": c.get("control_code"),
                    "control_name": c.get("control_name"),
                    "mapping_status": c.get("mapping_status"),
                    "regulatory_reference": c.get("regulatory_reference"),
                }
                for c in q.get("controls") or []
            ]
    return out


def _applies(rule: Mapping[str, Any], ev: Mapping[str, Any], controls: Sequence[Mapping[str, Any]]) -> bool:
    if rule["trigger"] != ev["result"]:
        return False
    if rule["scope"] == "QUESTION":
        return bool(rule["target"] == ev["question_code"])
    if rule.get("mandatory_only") and not ev.get("mandatory"):
        return False
    if rule["scope"] == "CONTROL":
        return any(c.get("control_code") == rule["target"] for c in controls)
    return True


def generate(
    evaluations: Sequence[Mapping[str, Any]],
    content: Mapping[str, Any],
    rules: RuleSet,
    context: Mapping[str, Any],
) -> Generation:
    """Findings for one execution. ``context``: execution_ref, case_ref, script_label, script_version_id,
    content_sha256, fact_source, evaluation_engine (and optional evaluation_ref)."""
    controls = controls_of(content)
    g = Generation()
    for ev in evaluations:
        result = ev.get("result")
        code = ev["question_code"]
        qc = controls.get(code, [])
        if result == "HUMAN_ASSESSMENT_REQUIRED":
            g.human_assessment.append(
                {"question_code": code, "answer": ev.get("answer"), "explanation": ev.get("explanation")}
            )
        if result not in TRIGGERS:
            continue
        matching = [r for r in rules.rules if _applies(r, ev, qc)]
        if not matching:
            g.not_converted.append(
                {
                    "question_code": code,
                    "result": result,
                    "finding_class": TRIGGER_CLASS[str(result)],
                    "mandatory": ev.get("mandatory"),
                    "controls": [c["control_code"] for c in qc],
                    "reason": f"No rule in finding rule set {rules.label} applies to {code} for "
                    f"{str(result).replace('_', ' ').lower()}; no finding is generated (not every discrepancy is a "
                    "finding)",
                }
            )
            continue
        best = min(SCOPE_RANK[r["scope"]] for r in matching)
        for rule in sorted((r for r in matching if SCOPE_RANK[r["scope"]] == best), key=lambda r: r["rule_code"]):
            via = [c for c in qc if rule["scope"] != "CONTROL" or c.get("control_code") == rule["target"]]
            key = sha256_of(
                {
                    "execution": context.get("execution_ref"),
                    "rule_set": rules.sha256,
                    "rule": rule["rule_code"],
                    "question": code,
                    "trigger": result,
                }
            )
            scope_text = {
                "QUESTION": f"its rule targets {code}",
                "CONTROL": f"{code} is linked to control {rule['target']}",
                "ANY_QUESTION": "its rule covers any "
                + ("mandatory " if rule.get("mandatory_only") else "")
                + "question",
            }[rule["scope"]]
            g.findings.append(
                {
                    "finding_key": key,
                    "question_code": code,
                    "question_revision_id": ev.get("question_revision_id"),
                    "revision": ev.get("revision"),
                    "mandatory": ev.get("mandatory"),
                    "trigger": result,
                    "finding_class": TRIGGER_CLASS[str(result)],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "severity_justification": rule["severity_justification"],
                    "severity_source": f"Finding rule {rule['rule_code']} in rule set {rules.label}",
                    "review_required": bool(rule["review_required"]),
                    "description": rule["description"],
                    "rule": {
                        "rule_code": rule["rule_code"],
                        "text": describe_rule(rule),
                        "rule_set": rules.ref(),
                    },
                    "explanation": f"{code} was evaluated {str(result).replace('_', ' ').lower()} "
                    f"({ev.get('explanation')}); rule {rule['rule_code']} applies because {scope_text}. "
                    f"{CLASS_LABEL[TRIGGER_CLASS[str(result)]]}, not a breach determination.",
                    "controls": via,
                    "control_unmapped": not qc,
                    "evidence": {
                        "execution_ref": context.get("execution_ref"),
                        "case_ref": context.get("case_ref"),
                        "script_label": context.get("script_label"),
                        "script_version_id": context.get("script_version_id"),
                        "content_sha256": context.get("content_sha256"),
                        "evaluation_ref": context.get("evaluation_ref"),
                        "evaluation_engine": context.get("evaluation_engine"),
                        "fact_source": context.get("fact_source"),
                        "answer": ev.get("answer"),
                        "normalized_answer": ev.get("normalized_answer"),
                        "expected": ev.get("expected"),
                        "evaluation_result": result,
                        "evaluation_explanation": ev.get("explanation"),
                        "evaluation_rule": ev.get("rule_text"),
                    },
                    "engine": ENGINE,
                }
            )
    return g


def finding_set(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Comparable view for scenario expectations: (question, category, severity) sorted."""
    return sorted(
        ({"question": f["question_code"], "category": f["category"], "severity": f["severity"]} for f in findings),
        key=lambda x: (x["question"], x["category"], x["severity"]),
    )
