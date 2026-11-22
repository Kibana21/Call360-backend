# ruff: noqa: E501 — comparison helpers are kept one per line
"""SS-03B.1 — the Python execution engine against the 82 expected runs of the 27 golden fixtures.

The fixtures were written by hand and are verified independently by five reference interpreters in Call360-specs. This
file holds NO expected value: it runs each expected run through ``app.domain.survey.execution`` on the canonical
documents and compares the result with what the fixture states, in the fixture's own vocabulary. Nothing in a fixture is
changed to make the engine pass.

Vocabulary of the historical schema /1 (owner decision D-136, fixtures/README "Versions"): it has ONE halted state,
``blocked: {reason: BLOCKED_UNKNOWN}`` with module status ``BLOCKED_UNKNOWN``, where the engine and schemas /2…/5 keep
the missing-information halt, the review halt and the invalid draft apart. ``in_v1_terms`` states that mapping; nothing
is collapsed inside the engine."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from app.domain.survey import execution
from app.domain.survey.execution import execute, execute_inputs, validate_answer
from tests.survey_fixtures import load_all, schema_version, to_bundle

FIXTURES = load_all()
RUNS = [(fx, run) for fx in FIXTURES for run in fx["expected_runs"]]


def drive(fx: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    """Every rejected answer is offered FIRST at its question; then the run's own answer; then nothing."""
    bad: dict[str, list[dict[str, Any]]] = {}
    for b in run.get("rejected") or []:
        bad.setdefault(b["at"], []).append(b)

    def supplier(key: str, attempt: int) -> Any:
        refused = bad.get(key, [])
        if attempt < len(refused):
            return refused[attempt]["answer"]
        return run["answers"].get(key) if attempt == len(refused) else None

    return execute(to_bundle(fx), run.get("profile") or run.get("facts") or {}, supplier)


def modules_of(r: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"instance": m["instance"], "status": m["status"], **({"outcome": m["outcome"]} if m.get("outcome") else {})}
        for m in r["modules"]
    ]


def trace_v2(r: dict[str, Any], v3: bool) -> list[str]:
    """The engine's events as the trace lines of schemas /2…/4."""
    out: list[str] = []
    for e in r["events"]:
        k = e["kind"]
        if k == "ENTRY" and e["mode"] == "RULE":
            out.append(f"{e['instance']}: entry {e['result']} via {e['arrival']}")
        elif k == "DISPOSITION":
            out.append(
                f"{e['instance']}: not eligible {'after jump' if e['after_jump'] else 'in sequence'} -> {json.dumps(e['to'])}"
            )
        elif v3 and k == "SURVEY_ROUTE" and e.get("mandatory"):
            out.append(
                f"{e['instance']}: mandatory escalation -> {e['outcome']}{'; survey route overridden' if e.get('overridden') else ''}"
            )
        elif k == "DECISION":
            out.append(f"{e['key']}: {e['result']}")
        elif k == "ROUTE" and e["via"].startswith("RULE:"):
            out.append(
                f"{e['key']}: RULE {e['via'][5:]}" + (f"; also {e['also_rules']!r}" if e.get("also_rules") else "")
            )
        elif k == "ROUTE" and e["via"] == "FALLBACK":
            out.append(f"{e['key']}: FALLBACK")
        elif k == "QUEUE" and (e.get("interrupt") or {}).get("outcome"):
            i = e["interrupt"]
            out.append(
                f"{e['key']}: INTERRUPT {i['option']} -> {i['outcome']}; skipped {i['skipped_nodes']!r}{' (mandatory)' if i['mandatory'] else ''}"
            )
        elif k == "QUEUE":
            out.append(
                f"{e['key']}: QUEUE {[q['node'] for q in e['queued']]!r}"
                + (f"; deduped {e['deduped_nodes']!r}" if e["deduped_nodes"] else "")
            )
    return out


def in_v1_terms(r: dict[str, Any]) -> dict[str, Any]:
    t = r["terminal"]
    assert not t or t["state"] != "REVIEW_REQUIRED", (
        "schema /1 has no equivalent of the governed REVIEW_REQUIRED outcome"
    )
    halted = bool(t) and t["state"] in ("MISSING_INFORMATION_HALT", "DRAFT_INVALID")
    blocked = (
        {"reason": "BLOCKED_UNKNOWN", "at": t["at"]} if t and t["state"] == "MISSING_INFORMATION_HALT"
        else {"reason": t["reason"], "at": t["at"]} if t and t["state"] == "DRAFT_INVALID" else None
    )  # fmt: skip
    return {
        "asked": r["asked"],
        "modules": [
            {**m, "status": "BLOCKED_UNKNOWN" if m["status"] == "HALTED_MISSING_INFORMATION" else m["status"]}
            for m in modules_of(r)
        ],
        "survey_outcome": t.get("survey_outcome") if t and not halted else None,
        "blocked": blocked,
    }


def test_the_82_expected_runs_of_27_fixtures_are_all_here() -> None:
    per = {v: sum(len(fx["expected_runs"]) for fx in FIXTURES if schema_version(fx) == v) for v in (1, 2, 3, 4, 5)}
    assert (len(FIXTURES), per, len(RUNS)) == (27, {1: 25, 2: 18, 3: 16, 4: 4, 5: 19}, 82)
    assert sum(len(run.get("rejected") or []) for _, run in RUNS) == 19  # 7 + 2 + 0 + 0 + 10 rejected answers


@pytest.mark.parametrize(("fx", "run"), RUNS, ids=[f"{fx['fixture'][:2]} · {run['name'][:70]}" for fx, run in RUNS])
def test_golden_run(fx: dict[str, Any], run: dict[str, Any]) -> None:
    r = drive(fx, run)
    exp, v = run["expect"], schema_version(fx)
    # the answers that must be refused, by stable code and in order — and each IS refused by the validator on its own
    assert r["rejections"] == [{"at": b["at"], "error": b["error"]} for b in run.get("rejected") or []]
    assert r["asked"] == exp["asked"]  # the delivered question sequence, by execution identity
    if v == 1:
        got = in_v1_terms(r)
        assert got["modules"] == exp["modules"]
        assert got["survey_outcome"] == exp.get("survey_outcome")
        assert got["blocked"] == exp.get("blocked")
        if "evidence" in exp:
            assert r["evidence"] == exp["evidence"]
        if "trace" in exp:
            assert r["trace"] == exp["trace"]
        if "edges_taken" in exp:
            assert r["edges"] == exp["edges_taken"]
        assert r["pending"] is None
        return
    assert modules_of(r) == exp["modules"]  # module inclusion and exclusion, with the reason as a status
    assert r["evidence_states"] == exp["evidence_states"]
    if v in (2, 3, 4):
        assert r["terminal"] == exp["terminal"]
        assert trace_v2(r, v >= 3) == exp["trace"]  # every routing decision
        assert r["pending"] is None
        return
    assert r["terminal"] == exp["terminal"]  # None while a question is pending
    assert (
        r["delivered"] == exp["delivered"]
    )  # every item delivered, statements included, with the exact text and values
    assert (r["pending"] or {}).get("key") == exp["pending"]


def test_the_same_inputs_always_give_the_same_run_and_the_engine_changes_nothing_it_is_given() -> None:
    for fx, run in RUNS:
        bundle_before = json.dumps(fx, sort_keys=True)
        first, second = drive(fx, run), drive(fx, run)
        assert json.dumps(first, sort_keys=True, default=str) == json.dumps(second, sort_keys=True, default=str), run[
            "name"
        ]
        assert json.dumps(fx, sort_keys=True) == bundle_before  # the documents, facts and answers are untouched


def test_a_run_replayed_from_its_recorded_inputs_is_identical() -> None:
    """What a simulation stores is the ordered inputs it was given, including the refused ones. Replaying them gives
    the same run, event for event."""
    for fx, run in RUNS:
        live = drive(fx, run)
        inputs = [{"key": e["key"], "answer": e["answer"]} for e in live["events"] if e["kind"] in ("ANSWER", "REJECT")]
        replay = execute_inputs(to_bundle(fx), run.get("profile") or run.get("facts") or {}, inputs)
        assert replay["input_mismatch"] is None and replay["inputs_consumed"] == len(inputs)
        for k in ("status", "terminal", "asked", "delivered", "modules", "evidence_states", "events", "rejections"):
            assert replay[k] == live[k], (run["name"], k)


def k(prefix: str) -> dict[str, Any]:
    return next(fx for fx in FIXTURES if fx["fixture"].startswith(prefix))


def test_an_input_for_any_question_but_the_current_one_is_refused_and_nothing_after_it_is_applied() -> None:
    fx = k("K1")
    run = fx["expected_runs"][0]
    full = drive(fx, run)
    inputs = [{"key": e["key"], "answer": e["answer"]} for e in full["events"] if e["kind"] == "ANSWER"]
    assert len(inputs) >= 2
    swapped = [inputs[1], inputs[0], *inputs[2:]]
    r = execute_inputs(to_bundle(fx), run.get("facts") or {}, swapped)
    assert r["input_mismatch"] == {"index": 0, "expected": inputs[0]["key"], "got": inputs[1]["key"]}
    assert (r["inputs_consumed"], r["asked"], r["status"]) == (0, [], "PENDING")
    assert r["pending"]["key"] == inputs[0]["key"]


def test_an_invalid_answer_never_advances_the_run() -> None:
    fx = k("K3")  # numeric answers
    run = next(r for r in fx["expected_runs"] if r.get("rejected"))
    bad = run["rejected"][0]
    r = execute_inputs(to_bundle(fx), run.get("facts") or {}, [{"key": bad["at"], "answer": bad["answer"]}] * 3)
    # refused three times, with the stable code; the SAME question is still current; nothing was recorded as answered
    assert [x["error"] for x in r["rejections"]] == [bad["error"]] * 3
    assert (r["status"], r["pending"]["key"], r["pending"]["attempt"]) == ("PENDING", bad["at"], 3)
    assert bad["at"] not in r["asked"] and bad["at"] not in [e["question_instance"] for e in r["evidence"]]
    assert r["terminal"] is None


def test_a_statement_is_delivered_and_takes_no_answer() -> None:
    fx = k("K1")
    r = execute(to_bundle(fx), fx["expected_runs"][0].get("facts") or {}, lambda _key, _attempt: None)
    said = [e for e in r["events"] if e["kind"] == "SAY"]
    assert said and r["delivered"][0]["statement"] is True  # delivered with no input at all
    assert r["delivered"][0]["key"] not in r["asked"]  # a statement is never "asked"
    assert r["evidence_states"][said[0]["key"]] == "DELIVERED"
    assert r["status"] == "PENDING" and r["pending"]["key"] not in [e["key"] for e in said]  # it stopped at a QUESTION


def test_wording_is_delivered_exactly_as_pinned_and_never_written_by_the_engine() -> None:
    for fx, run in RUNS:
        b = to_bundle(fx)
        r = drive(fx, run)
        texts = {str(w["text"]).strip() for w in b.wordings.values()}
        for d in r["delivered"]:
            if not d["values"]:
                assert d["text"] in texts, d["key"]  # no variables: the delivered sentence IS a pinned wording
            else:
                assert all(v["state"] == "PRESENT" and v["value"] in d["text"] for v in d["values"])


def test_a_non_answer_is_reported_as_unresolved_policy_and_is_never_turned_into_an_outcome() -> None:
    fx = k("K4")  # acknowledgement accepted or blocked as unresolved policy
    b = to_bundle(fx)
    ack_node = next(
        n
        for m in b.modules.values()
        for n in m["nodes"]
        if n.get("item") and b.item_of(n)["answer_type"] == "ACKNOWLEDGEMENT"
    )
    inst = b.survey["sequence"][0]["instance"]
    key = f"{inst}/{ack_node['node']}"
    facts = fx["expected_runs"][0].get("facts") or {}
    before: list[dict[str, Any]] = []
    while True:  # answer whatever comes before the acknowledgement, as the fixture's own run does
        r = execute_inputs(b, facts, before)
        if r["pending"]["key"] == key:
            break
        before.append({"key": r["pending"]["key"], "answer": fx["expected_runs"][0]["answers"][r["pending"]["key"]]})
    r = execute_inputs(b, facts, [*before, {"key": key, "answer": {"acknowledged": False}}])
    assert r["status"] == "POLICY_UNRESOLVED"
    assert r["policy_unresolved"] == {"key": key, "code": "POLICY_UNRESOLVED", "reason": "NON_ANSWER_POLICY_UNRESOLVED"}
    assert r["terminal"] is None and r["pending"]["key"] == key  # not a terminal outcome; the question is still current
    assert key not in r["asked"] and all(e["kind"] != "END" for e in r["events"])
    assert not [m for m in r["modules"] if m.get("outcome")]  # no completion, no escalation, nothing synthesised
    observed = [e for e in r["events"] if e["kind"] == "REJECT"]
    assert [(e["code"], e["answer"]) for e in observed] == [
        ("NON_ANSWER_POLICY_UNRESOLVED", {"acknowledged": False})
    ]  # recorded as an observation
    # no answer at all is simply pending — not a refusal, not a timeout, nothing invented
    r = execute_inputs(b, facts, before)
    assert (r["status"], r["policy_unresolved"]) == ("PENDING", None)
    # a real acknowledgement afterwards is accepted: the unresolved status was never an ending
    r = execute_inputs(
        b,
        facts,
        [*before, {"key": key, "answer": {"acknowledged": False}}, {"key": key, "answer": {"acknowledged": True}}],
    )
    assert key in r["asked"] and r["policy_unresolved"] is None
    assert validate_answer(b.item_of(ack_node), [], {}) == "ACKNOWLEDGEMENT_REQUIRED"


def test_a_missing_fact_is_unknown_never_false() -> None:
    fx = k("F6")  # an internal condition with UNKNOWN
    saw_unknown = False
    for run in fx["expected_runs"]:
        r = drive(fx, run)
        for e in r["events"]:
            if e["kind"] in ("DECISION", "ENTRY") and e.get("result") == "UNKNOWN":
                saw_unknown = True
                assert any(x["state"] in ("MISSING", "SKIPPED") for x in e["reads"])  # it says what was missing
                assert e.get("via", "UNKNOWN") == "UNKNOWN"  # and it did not take the "otherwise" route
    assert saw_unknown


def test_the_engine_is_pure_and_offers_no_way_to_speak_or_dial() -> None:
    import inspect

    src = inspect.getsource(execution)
    for forbidden in (
        "sqlalchemy",
        "datetime",
        "requests",
        "httpx",
        "socket",
        "openai",
        "random",
        "uuid",
        "os.environ",
    ):
        assert f"import {forbidden}" not in src and f"from {forbidden}" not in src, forbidden
    public = [
        n
        for n in dir(execution)
        if not n.startswith("_")
        and callable(getattr(execution, n))
        and getattr(getattr(execution, n), "__module__", "") == execution.__name__
    ]
    assert sorted(public) == ["answer_state", "execute", "execute_inputs", "validate_answer"]
    assert copy.deepcopy(execution.POLICY_UNRESOLVED_CODES) == ("NON_ANSWER_POLICY_UNRESOLVED",)
