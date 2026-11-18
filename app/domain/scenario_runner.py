"""S2-E scenario execution over the S2-D / S2-D.1 question controller (pure: no database, clock, randomness or LLM).

A scenario is structured data, never code:

- **steps**: ordered responses, each targeting a question code — ``ANSWER`` (with a typed value), ``UNCLEAR``,
  ``REFUSED``, ``UNKNOWN``, ``CLARIFICATION``, ``NOT_DELIVERED``, ``DELIVERED`` (a statement) or ``EVENT`` (a
  conversation event — wrong person, callback requested, declined to continue, interrupted — reported when that question
  is the current item, before it is delivered);
- **default response** for items without a step: ``AFFIRMATIVE`` (statements delivered; yes/no and acknowledgement
  answered yes; numeric 1; choice = first approved option; free text a fixed synthetic sentence) or ``STRICT`` (an item
  without a step is an execution error);
- **expectations** (each optional; only what is given is checked): outcome, termination reason (``NONE`` = not
  terminated), gate states, mandatory completion, the exact set of applicable questions, the exact sequence of
  requested questions, per-question final states and (S3-A) per-question answer-evaluation results. ``basis`` records
  whether the expectations were specified independently or generated from an observed run (a generated baseline is
  not independently validated expected behaviour).

S3-A: when an evaluator is given, the deterministic answer evaluation (``answer_evaluation``) runs over the finished
controller and is reported separately from controller completion — a completed conversation may still contain
mismatches or unresolved answers.

The runner drives the *same* ``Controller`` the text simulator and (later) a voice provider use: it only reports
delivery, answers and events against the controller's current action; it never chooses the next item. Comparison of
expected and actual is exact and deterministic, with a plain-language explanation for every difference.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.domain import answer_evaluation as ae
from app.domain import lifecycle as lc
from app.domain import question_controller as qc

STEP_KINDS = ("ANSWER", "UNCLEAR", "REFUSED", "UNKNOWN", "CLARIFICATION", "NOT_DELIVERED", "DELIVERED", "EVENT")
DEFAULT_RESPONSES = ("AFFIRMATIVE", "STRICT")
OUTCOMES = ("COMPLETED", "INCOMPLETE", "TERMINATED")
GATES = ("identity", "willingness", "recording_consent", "cloud_processing")
QUESTION_STATES = ("COMPLETED", "UNRESOLVED", "SKIPPED_BY_CONDITION", "PENDING")
EVALUATION_RESULTS = ae.RESULTS
EXPECTATION_BASES = ("INDEPENDENT", "GENERATED_BASELINE")
Evaluator = Callable[[qc.Controller], list[dict[str, Any]]]
Finder = Callable[[list[dict[str, Any]]], dict[str, Any] | None]
TERMINATION_REASONS = (
    "IDENTITY_FAILED",
    "IDENTITY_INCONCLUSIVE",
    "DECLINED_TO_PROCEED",
    "RECORDING_CONSENT_DECLINED",
    "CLOUD_PROCESSING_DECLINED",
    "OPENING_NOT_DELIVERED",
    "MANDATORY_DISCLOSURE_NOT_DELIVERED",
    "DISCLOSURE_NOT_DELIVERED",
    "MANDATORY_QUESTION_UNRESOLVED",
    "QUESTION_UNRESOLVED",
    *lc.EVENTS,
)
MAX_ITERATIONS = 1000
DEFAULT_TEXT = "Synthetic answer (scenario default response)"


class ScenarioInvalid(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class Execution:
    status: str  # PASSED | FAILED | ERROR (INVALID is decided before execution)
    actual: dict[str, Any]
    failures: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    log: list[dict[str, Any]] = field(default_factory=list)  # how each item was answered (step n / default)


def _label(step: Mapping[str, Any]) -> str:
    kind = step["kind"]
    if kind == "EVENT":
        return f"event {str(step.get('event', '')).replace('_', ' ').lower()} at {step['question']}"
    if kind == "ANSWER":
        v = step.get("value")
        shown = "yes" if v is True else "no" if v is False else repr(v)
        return f"{step['question']}: answer {shown}"
    return f"{step['question']}: {kind.replace('_', ' ').lower()}"


def validate(plan: qc.Plan, steps: Sequence[Mapping[str, Any]], expectations: Mapping[str, Any]) -> list[str]:
    """Problems that make the scenario unrunnable against this plan (unknown questions, impossible step kinds)."""
    problems: list[str] = []
    codes = {q.code: q for q in plan.questions}
    for i, s in enumerate(steps, start=1):
        kind, code = s.get("kind"), s.get("question")
        if kind not in STEP_KINDS:
            problems.append(f"Step {i}: unknown step kind {kind!r}")
            continue
        pq = codes.get(str(code))
        if pq is None:
            problems.append(f"Step {i}: question {code} is not in this script version")
            continue
        if kind == "EVENT" and s.get("event") not in lc.EVENTS:
            problems.append(f"Step {i}: unknown conversation event {s.get('event')!r}")
        if pq.completes_on_delivery and kind not in ("DELIVERED", "NOT_DELIVERED", "EVENT", "ANSWER"):
            problems.append(f"Step {i}: {code} is a statement; it can only be delivered, not delivered, or interrupted")
        if not pq.completes_on_delivery and kind == "DELIVERED":
            problems.append(f"Step {i}: {code} is a question; give an answer rather than 'delivered'")
    for code in expectations.get("question_states") or {}:
        if code not in codes:
            problems.append(f"Expected state for {code}, which is not in this script version")
    for f in expectations.get("findings") or []:
        if f.get("question") not in codes:
            problems.append(f"Expected finding for {f.get('question')}, which is not in this script version")
    for code in expectations.get("evaluations") or {}:
        if code not in codes:
            problems.append(f"Expected evaluation for {code}, which is not in this script version")
    return problems


def _default(pq: qc.PlannedQuestion) -> Any:
    if pq.answer_type in ("YES_NO", "ACKNOWLEDGEMENT"):
        return True
    if pq.answer_type == "NUMERIC":
        return 1
    if pq.answer_type == "ENUM":
        return pq.options[0] if pq.options else None
    return DEFAULT_TEXT


def _present(ctrl: qc.Controller, a: qc.Action) -> None:
    if not a.presented:
        ctrl.record_delivery(a.action_id or "", True)


def _apply(ctrl: qc.Controller, a: qc.Action, pq: qc.PlannedQuestion, step: Mapping[str, Any] | None) -> None:
    aid = a.action_id or ""
    if step is None:  # default response
        if pq.completes_on_delivery:
            ctrl.record_delivery(aid, True)
        else:
            _present(ctrl, a)
            ctrl.submit_answer(aid, "ANSWER", _default(pq))
        return
    kind = step["kind"]
    if kind == "EVENT":
        ctrl.report(str(step["event"]), step.get("note"))
    elif kind == "NOT_DELIVERED":
        ctrl.record_delivery(aid, False)
    elif kind == "DELIVERED" or (kind == "ANSWER" and pq.completes_on_delivery):
        ctrl.record_delivery(aid, True)
    elif kind == "CLARIFICATION":
        _present(ctrl, a)
        ctrl.request_clarification(aid, str(step.get("note") or "Customer asked for clarification"))
    else:
        _present(ctrl, a)
        ctrl.submit_answer(aid, kind, step.get("value") if kind == "ANSWER" else None)


def actual_of(ctrl: qc.Controller) -> dict[str, Any]:
    st, life = ctrl.state(), ctrl.lifecycle()
    summary = st["summary"]
    term = life["termination"] or {}
    sequence: list[str] = []
    for e in ctrl.events:
        if e.type == "QUESTION_REQUESTED" and e.question_code and e.question_code not in sequence:
            sequence.append(e.question_code)
    return {
        "outcome": ctrl.ended,
        "termination_reason": term.get("reason"),
        "termination_stage": term.get("stage"),
        "termination_detail": term.get("detail"),
        "gates": life["gates"],
        "flags": life["flags"],
        "mandatory_complete": not summary["mandatory_open"] and not summary["mandatory_unresolved"],
        "mandatory_unresolved": summary["mandatory_unresolved"],
        "mandatory_open": summary["mandatory_open"],
        "applicable": [q.code for q in ctrl.plan.questions if q.applicable],
        "sequence": sequence,
        "question_states": {q["code"]: q["status"] for q in st["questions"]},
        "question_reasons": {q["code"]: q["reason"] for q in st["questions"] if q["reason"]},
        "included_sections": [s.module_code for s in ctrl.plan.sections if s.included],
        "disclosures_undelivered": life["disclosures_undelivered"],
        "blocked_by_identity_gate": life["blocked_by_identity_gate"],
        "compliance_outcome": "NOT_EVALUATED",
        "identity_simulated": True,
    }


def compare(actual: Mapping[str, Any], exp: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every difference between expected and actual, each with a plain-language explanation."""
    out: list[dict[str, Any]] = []

    def fail(check: str, expected: Any, got: Any, message: str) -> None:
        out.append({"check": check, "expected": expected, "actual": got, "message": message})

    def h(v: Any) -> str:
        return "none" if v is None else str(v).replace("_", " ").lower()

    if exp.get("outcome") and exp["outcome"] != actual["outcome"]:
        why = f" — {actual['termination_detail']}" if actual.get("termination_detail") else ""
        if actual["outcome"] == "INCOMPLETE" and actual["mandatory_unresolved"]:
            why = f" — mandatory unresolved: {', '.join(actual['mandatory_unresolved'])}"
        fail(
            "outcome",
            exp["outcome"],
            actual["outcome"],
            f"Outcome: expected {h(exp['outcome'])}, got {h(actual['outcome'])}{why}",
        )
    if exp.get("termination_reason"):
        want = None if exp["termination_reason"] == "NONE" else exp["termination_reason"]
        if want != actual["termination_reason"]:
            fail(
                "termination_reason",
                exp["termination_reason"],
                actual["termination_reason"] or "NONE",
                f"Termination: expected {h(want) if want else 'no termination'}, got "
                f"{h(actual['termination_reason']) if actual['termination_reason'] else 'no termination'}"
                + (f" at {h(actual['termination_stage'])}" if actual["termination_stage"] else ""),
            )
    for gate, want in (exp.get("gates") or {}).items():
        if want and actual["gates"].get(gate) != want:
            fail(
                f"gate:{gate}",
                want,
                actual["gates"].get(gate),
                f"Gate {h(gate)} (simulated): expected {h(want)}, got {h(actual['gates'].get(gate))}",
            )
    if exp.get("mandatory_complete") is not None and bool(exp["mandatory_complete"]) != actual["mandatory_complete"]:
        missing = [*actual["mandatory_unresolved"], *actual["mandatory_open"]]
        fail(
            "mandatory_complete",
            exp["mandatory_complete"],
            actual["mandatory_complete"],
            "Mandatory completion: expected "
            + ("complete" if exp["mandatory_complete"] else "incomplete")
            + (f", but these were not completed: {', '.join(missing)}" if missing else ", but all were completed"),
        )
    if exp.get("applicable_questions") is not None:
        want_set, got_set = set(exp["applicable_questions"]), set(actual["applicable"])
        if want_set != got_set:
            extra, missing = sorted(got_set - want_set), sorted(want_set - got_set)
            parts = ([f"also applicable: {', '.join(extra)}"] if extra else []) + (
                [f"not applicable: {', '.join(missing)}"] if missing else []
            )
            fail(
                "applicable_questions",
                sorted(want_set),
                sorted(got_set),
                "Applicable questions differ — " + "; ".join(parts),
            )
    if exp.get("sequence") is not None and list(exp["sequence"]) != actual["sequence"]:
        w, g = list(exp["sequence"]), actual["sequence"]
        first = next((i for i, (x, y) in enumerate(zip(w, g, strict=False)) if x != y), min(len(w), len(g)))
        at = (
            f"position {first + 1}: expected {w[first] if first < len(w) else 'end'}, asked "
            f"{g[first] if first < len(g) else 'nothing further'}"
        )
        fail("sequence", w, g, f"Question sequence differs at {at}")
    for code, want in (exp.get("question_states") or {}).items():
        got = actual["question_states"].get(code)
        if want and got != want:
            reason = actual["question_reasons"].get(code)
            fail(
                f"question:{code}",
                want,
                got,
                f"{code}: expected {h(want)}, got {h(got)}" + (f" ({reason})" if reason else ""),
            )
    if exp.get("evaluations"):
        got_map = actual.get("evaluation_results") or {}
        explain = {r["question_code"]: r["explanation"] for r in actual.get("evaluations") or []}
        for code, want_r in exp["evaluations"].items():
            got_r = got_map.get(code)
            if want_r and got_r != want_r:
                fail(
                    f"evaluation:{code}",
                    want_r,
                    got_r,
                    f"{code} answer evaluation: expected {h(want_r)}, got {h(got_r)}"
                    + (f" — {explain[code]}" if explain.get(code) else ""),
                )
    if exp.get("findings") is not None:
        out += _compare_findings(list(exp["findings"]), actual)
    return out


def _compare_findings(want: list[Mapping[str, Any]], actual: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expected findings: (question, category[, severity]); an empty list expects no findings at all."""
    if "findings_view" not in actual:
        return [
            {
                "check": "findings",
                "expected": want,
                "actual": None,
                "message": "Findings: expected findings were specified, but no finding rule set was available to "
                "generate findings",
            }
        ]
    got = list(actual["findings_view"])
    used = [False] * len(got)
    missing = []
    for w in want:
        hit = next(
            (
                i
                for i, g in enumerate(got)
                if not used[i]
                and g["question"] == w.get("question")
                and g["category"] == w.get("category")
                and (not w.get("severity") or g["severity"] == w.get("severity"))
            ),
            None,
        )
        if hit is None:
            missing.append(w)
        else:
            used[hit] = True
    extra = [g for i, g in enumerate(got) if not used[i]]

    def h(f: Mapping[str, Any]) -> str:
        sev = f" ({f['severity']})" if f.get("severity") else ""
        return f"{f.get('question')} {str(f.get('category', '')).replace('_', ' ').lower()}{sev}"

    out = []
    if missing:
        out.append(
            {
                "check": "findings:missing",
                "expected": missing,
                "actual": got,
                "message": "Expected finding(s) not generated: " + "; ".join(h(m) for m in missing),
            }
        )
    if extra:
        out.append(
            {
                "check": "findings:unexpected",
                "expected": want,
                "actual": extra,
                "message": ("No findings were expected, but generated: " if not want else "Unexpected finding(s): ")
                + "; ".join(h(x) for x in extra),
            }
        )
    return out


def execute(
    plan: qc.Plan,
    steps: Sequence[Mapping[str, Any]],
    expectations: Mapping[str, Any],
    default_response: str = "AFFIRMATIVE",
    evaluator: Evaluator | None = None,
    finder: Finder | None = None,
) -> Execution:
    """Run the scenario through a fresh controller and compare. Raises ``ScenarioInvalid`` when it cannot run."""
    problems = validate(plan, steps, expectations)
    if default_response not in DEFAULT_RESPONSES:
        problems.append(f"Unknown default response {default_response!r}")
    if problems:
        raise ScenarioInvalid(problems)
    ctrl = qc.Controller(plan)
    log: list[dict[str, Any]] = []
    i = 0
    error: str | None = None
    try:
        ctrl.start()
        for _ in range(MAX_ITERATIONS):
            a = ctrl.next_action()
            if a.kind in ("SEQUENCE_FINISHED", "ENDED", "NOT_STARTED") or a.question_code is None:
                break
            pq = plan.question(a.question_code)
            step = steps[i] if i < len(steps) and steps[i].get("question") == a.question_code else None
            if step is None and default_response == "STRICT":
                nxt = f"; the next step expects {steps[i]['question']}" if i < len(steps) else ""
                raise qc.ControllerError(
                    "NO_SCRIPTED_RESPONSE", f"No scripted response for {a.question_code} (strict scenario){nxt}"
                )
            log.append(
                {
                    "question": a.question_code,
                    "action_id": a.action_id,
                    "by": f"step {i + 1}" if step is not None else "default",
                    "response": _label(step) if step is not None else "default response",
                }
            )
            _apply(ctrl, a, pq, step)
            if step is not None:
                i += 1
        else:
            raise qc.ControllerError("RUNAWAY", "The scenario did not finish within the iteration limit")
        if not ctrl.ended:
            ctrl.end(abandon=False, reason="Scenario finished")
    except qc.ControllerError as exc:
        error = f"{exc.code}: {exc.message}" + (f" (at step {i + 1}: {_label(steps[i])})" if i < len(steps) else "")
    actual = actual_of(ctrl) if ctrl.started else {}
    if evaluator is not None and ctrl.started and error is None:
        evaluations = evaluator(ctrl)
        actual["evaluations"] = evaluations
        actual["evaluation_results"] = ae.result_map(evaluations)
        actual["evaluation_totals"] = ae.totals(evaluations)
        actual["evaluation_engine"] = ae.ENGINE
        found = finder(evaluations) if finder is not None else None
        if found is not None:
            actual["findings"] = found["findings"]
            actual["findings_view"] = found["expected_view"]
            actual["findings_summary"] = found["summary"]
            actual["findings_not_converted"] = found["not_converted"]
            actual["finding_rule_set"] = found["rule_set"]
    events = [e.as_dict() for e in ctrl.events]
    if error is not None:
        return Execution("ERROR", actual, [], error, events, log)
    failures = compare(actual, expectations)
    for n in range(i, len(steps)):
        failures.append(
            {
                "check": f"step:{n + 1}",
                "expected": "reached",
                "actual": "not reached",
                "message": f"Step {n + 1} ({_label(steps[n])}) was never reached — the conversation "
                + ("ended" if actual.get("outcome") else "moved on")
                + " before it, or steps are out of "
                "conversation order",
            }
        )
    return Execution("FAILED" if failures else "PASSED", actual, failures, None, events, log)


# ---- coverage and comparison -------------------------------------------------------------------------------------
GATE_PATHS = {"recording_consent": "RECORDING_CONSENT", "cloud_processing": "CLOUD_PROCESSING"}


def lifecycle_paths(plan: qc.Plan) -> list[str]:
    """Structural lifecycle paths the script makes possible, from its roles and each item's configured failure
    behaviour (a declined consent that continues and one that terminates are different paths)."""
    paths = ["NORMAL_COMPLETION", "INCOMPLETE"]

    def add(p: str) -> None:
        if p not in paths:
            paths.append(p)

    for q in plan.questions:
        if q.role == "IDENTITY_CHECK":
            add("IDENTITY_FAILED")
            add("IDENTITY_INCONCLUSIVE")
        elif q.role == "CONSENT_TO_PROCEED":
            add("DECLINED_TO_PROCEED")
        elif q.role in ("RECORDING_CONSENT", "CLOUD_PROCESSING_CONSENT"):
            base = "RECORDING_CONSENT" if q.role == "RECORDING_CONSENT" else "CLOUD_PROCESSING"
            add(f"{base}_DECLINED" if q.on_failure == "TERMINATE" else f"{base}_DECLINED_CONTINUED")
        elif q.role == "DISCLOSURE" and q.on_failure == "TERMINATE":
            add("MANDATORY_DISCLOSURE_NOT_DELIVERED" if q.mandatory else "DISCLOSURE_NOT_DELIVERED")
        elif q.role == "VERIFICATION" and q.on_failure == "TERMINATE":
            add("MANDATORY_QUESTION_UNRESOLVED" if q.mandatory else "QUESTION_UNRESOLVED")
    for e in lc.EVENTS:
        add(e)
    return paths


def paths_of(actual: Mapping[str, Any]) -> set[str]:
    out: set[str] = set()
    if not actual:
        return out
    reason = actual.get("termination_reason")
    if reason:
        out.add(str(reason))
    elif actual.get("outcome") == "COMPLETED":
        out.add("NORMAL_COMPLETION")
    elif actual.get("outcome") == "INCOMPLETE":
        out.add("INCOMPLETE")
    gates = actual.get("gates") or {}
    for gate, base in GATE_PATHS.items():
        if gates.get(gate) == "DECLINED" and reason != f"{base}_DECLINED":
            out.add(f"{base}_DECLINED_CONTINUED")
    return out


def coverage(plan: qc.Plan, actuals: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Structural coverage of one script version by a set of executed scenarios. Not compliance quality or readiness."""
    requested: set[str] = set()
    completed: set[str] = set()
    included: set[str] = set()
    observed: set[str] = set()
    unresolved: dict[str, set[str]] = {}
    evaluated: dict[str, set[str]] = {}
    for a in actuals:
        if not a:
            continue
        for c, r in (a.get("evaluation_results") or {}).items():
            evaluated.setdefault(c, set()).add(r)
        requested |= set(a.get("sequence") or [])
        completed |= {c for c, s in (a.get("question_states") or {}).items() if s == "COMPLETED"}
        included |= set(a.get("included_sections") or [])
        observed |= paths_of(a)
        for c in a.get("mandatory_unresolved") or []:
            unresolved.setdefault(c, set()).add(str((a.get("question_reasons") or {}).get(c) or "unresolved"))
    codes = [q.code for q in plan.questions]
    conditional = [s.module_code for s in plan.sections if s.condition != "always"]
    possible = lifecycle_paths(plan)
    mandatory = [q.code for q in plan.questions if q.mandatory]
    return {
        "runs": len([a for a in actuals if a]),
        "questions_total": len(codes),
        "questions_exercised": [c for c in codes if c in requested],
        "questions_not_exercised": [c for c in codes if c not in requested],
        "conditional_modules": conditional,
        "conditional_modules_exercised": [m for m in conditional if m in included],
        "conditional_modules_not_exercised": [m for m in conditional if m not in included],
        "lifecycle_paths_possible": possible,
        "lifecycle_paths_exercised": [p for p in possible if p in observed],
        "lifecycle_paths_not_exercised": [p for p in possible if p not in observed],
        "mandatory_never_completed": [c for c in mandatory if c not in completed],
        "mandatory_unresolved": [{"question": c, "reasons": sorted(r)} for c, r in sorted(unresolved.items())],
        "evaluation_results_observed": [
            {"question": c, "results": sorted(evaluated[c])} for c in codes if c in evaluated
        ],
        "note": "Structural coverage of the controller paths exercised by these scenarios. It is not a measure of "
        "compliance quality, wording approval or production readiness.",
    }


def plan_diff(a: qc.Plan, b: qc.Plan) -> dict[str, Any]:
    """Structural differences between two plans built from the same facts (applicability and order)."""
    qa, qb = {q.code: q for q in a.questions}, {q.code: q for q in b.questions}
    app_a = [q.code for q in a.questions if q.applicable]
    app_b = [q.code for q in b.questions if q.applicable]
    common = [c for c in app_a if c in app_b]
    order_b = [c for c in app_b if c in common]

    def shape(q: qc.PlannedQuestion) -> dict[str, Any]:
        return {
            "role": q.role,
            "stage": q.stage,
            "mandatory": q.mandatory,
            "on_failure": q.on_failure,
            "discloses_policy_information": q.discloses_policy_information,
            "deliver_on_termination": q.deliver_on_termination,
            "answer_type": q.answer_type,
            "max_reprompts": q.max_reprompts,
            "wording": q.wording,
        }

    changed = []
    for c in qa:
        if c in qb:
            x, y = shape(qa[c]), shape(qb[c])
            diffs = {k: {"from": x[k], "to": y[k]} for k in x if x[k] != y[k]}
            if diffs:
                changed.append({"question": c, "changes": diffs})
    return {
        "only_in_a": [c for c in qa if c not in qb],
        "only_in_b": [c for c in qb if c not in qa],
        "applicable_only_in_a": [c for c in app_a if c not in app_b],
        "applicable_only_in_b": [c for c in app_b if c not in app_a],
        "order_changed": common != order_b,
        "order_a": app_a,
        "order_b": app_b,
        "item_changes": changed,
    }


def outcome_diff(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    out = []
    for k in ("outcome", "termination_reason", "mandatory_complete", "sequence", "gates", "mandatory_unresolved"):
        if (a or {}).get(k) != (b or {}).get(k):
            out.append({"field": k, "a": (a or {}).get(k), "b": (b or {}).get(k)})
    fa, fb = (a or {}).get("findings_view"), (b or {}).get("findings_view")
    if fa != fb:
        out.append({"field": "findings", "a": fa, "b": fb})
    ea, eb = (a or {}).get("evaluation_results") or {}, (b or {}).get("evaluation_results") or {}
    for code in list(dict.fromkeys([*ea, *eb])):
        if ea.get(code) != eb.get(code):
            out.append({"field": f"evaluation:{code}", "a": ea.get(code), "b": eb.get(code)})
    return out
