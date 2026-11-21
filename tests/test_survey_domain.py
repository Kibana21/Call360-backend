"""SS-03A.1 — the pure survey domain: canonical documents and hashing, the validator, the condition engine, and parity
with all 27 golden fixtures (schemas /1 … /5). No database is touched by anything in this file."""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Any

import pytest

from app.domain.survey.canonical import CanonicalError, canonical_text, sha256_hex
from app.domain.survey.conditions import ConditionError, check_condition, evaluate
from app.domain.survey.documents import SCHEMA_OF, Bundle, check_document, manifest_of, manifest_sha256
from app.domain.survey.validator import RULE_SINCE, validate
from tests.survey_fixtures import FIXTURE_DIR, load_all, schema_version, to_bundle

FIXTURES = load_all()
IDS = [fx["fixture"] for fx in FIXTURES]


# ---------------- the fixtures themselves
def test_all_27_fixtures_and_82_expected_runs_are_present_and_unchanged_in_shape() -> None:
    assert FIXTURE_DIR.is_dir()
    assert len(FIXTURES) == 27
    by_schema: dict[int, list[dict[str, Any]]] = {}
    for fx in FIXTURES:
        by_schema.setdefault(schema_version(fx), []).append(fx)
    assert {v: len(x) for v, x in by_schema.items()} == {1: 8, 2: 6, 3: 4, 4: 1, 5: 8}
    assert {v: sum(len(f["expected_runs"]) for f in x) for v, x in by_schema.items()} == {
        1: 25,
        2: 18,
        3: 16,
        4: 4,
        5: 19,
    }
    assert sum(len(f["expected_runs"]) for f in FIXTURES) == 82
    assert sum(len(f.get("expected_plans", [])) for f in FIXTURES) == 14


# ---------------- canonical form
def test_canonical_bytes_ignore_key_order_and_whitespace_but_not_array_order() -> None:
    a = {"b": [1, 2, {"y": 1, "x": 2}], "a": "é"}
    b = json.loads('{ "a": "é",\n "b": [1, 2, {"x": 2, "y": 1}] }')
    assert canonical_text(a) == '{"a":"é","b":[1,2,{"x":2,"y":1}]}'
    assert sha256_hex(a) == sha256_hex(b)
    assert sha256_hex({"b": [2, 1]}) != sha256_hex({"b": [1, 2]})


def test_canonical_numbers_have_no_exponent_and_no_trailing_zeros() -> None:
    assert canonical_text([1, 1.0, 1.50, 0.1, 1e-7, 1234567.5, Decimal("3000.0050"), -0.0, 10**20]) == (
        "[1,1,1.5,0.1,0.0000001,1234567.5,3000.005,0,100000000000000000000]"
    )
    assert sha256_hex({"n": 2}) == sha256_hex({"n": 2.0}) == sha256_hex({"n": Decimal("2.00")})


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), {1: "x"}, {"a": {1, 2}}, {"a": object()}, b"bytes"])
def test_canonical_refuses_what_is_not_json_and_never_converts(bad: Any) -> None:
    with pytest.raises(CanonicalError):
        canonical_text(bad)


# ---------------- documents of all 27 fixtures
@pytest.mark.parametrize("fx", FIXTURES, ids=IDS)
def test_every_fixture_document_meets_its_contract_and_hashes_stably(fx: dict[str, Any]) -> None:
    b = to_bundle(fx)
    docs = (
        [("OPTION_SET", d) for d in b.option_sets.values()]
        + [("ITEM", d) for d in b.items.values()]
        + [("WORDING", d) for d in b.wordings.values()]
        + [("CONDITION", d) for d in b.conditions.values()]
        + [("MODULE", d) for d in b.modules.values()]
        + [("SURVEY", b.survey)]
    )
    assert docs
    for kind, doc in docs:
        assert check_document(kind, doc) == [], (kind, doc.get("code"))
        again = json.loads(json.dumps(doc, sort_keys=True))  # another key order, another object
        assert sha256_hex(doc) == sha256_hex(again)
        assert len(sha256_hex(doc)) == 64
    # the manifest pins exactly what the survey reaches, and is itself stable
    m = manifest_of(b)
    assert m == sorted(m, key=lambda e: (e["kind"], e["code"], e["version"]))
    assert manifest_of(to_bundle(fx)) == m and manifest_sha256(m) == manifest_sha256(manifest_of(to_bundle(fx)))
    assert {e["kind"] for e in m} <= {"OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE"}
    assert len({(e["kind"], e["code"], e["version"]) for e in m}) == len(m)


def test_a_document_of_an_unknown_schema_or_shape_is_refused() -> None:
    item = {"schema": SCHEMA_OF["ITEM"], "code": "Q-X", "version": 1, "answer_type": "YES_NO", "intent": ""}
    assert check_document("ITEM", item) == []
    assert [p.code for p in check_document("ITEM", {**item, "schema": "call360.survey.item/2"})] == [
        "DOCUMENT_SCHEMA_UNKNOWN"
    ]
    assert [p.code for p in check_document("ITEM", {**item, "surprise": 1})] == ["DOCUMENT_FIELD_UNKNOWN"]
    assert [p.code for p in check_document("ITEM", {**item, "answer_type": "MAYBE"})] == ["DOCUMENT_FIELD_INVALID"]
    assert [p.code for p in check_document("ITEM", {k: v for k, v in item.items() if k != "code"})] == [
        "DOCUMENT_FIELD_MISSING"
    ]
    wording = {"schema": SCHEMA_OF["WORDING"], "item": "Q-X", "language": "en", "wording_version": 1, "text": "Hi"}
    # delivery mode is always explicit in storage (TS-4); a second language is not accepted yet (AD-12)
    assert [p.code for p in check_document("WORDING", wording)] == ["DOCUMENT_FIELD_MISSING"]
    assert [
        p.code for p in check_document("WORDING", {**wording, "delivery_mode": "CONTROLLED_TTS", "language": "zh"})
    ] == ["DOCUMENT_FIELD_INVALID"]


# ---------------- validation parity, schemas /1 … /5
@pytest.mark.parametrize("fx", FIXTURES, ids=IDS)
def test_server_validation_matches_the_fixture_expectation(fx: dict[str, Any]) -> None:
    """Each fixture is read under the rules of its own schema version: a rule introduced by a later version is not
    applied to an earlier fixture. Within that, the validator must report EXACTLY the fixture's expected errors, in
    order — and nothing at all for a fixture that expects none."""
    level = schema_version(fx)
    got = [{"code": f.code, "at": f.at} for f in validate(to_bundle(fx)) if f.since <= level]
    if "validation" in fx:  # schemas /3, /4, /5 state their validation errors
        assert got == fx["validation"]["errors"]
        return
    # schemas /1 and /2 have no validation block. A draft that is invalid ON PURPOSE says so through a run that ends
    # DRAFT_INVALID with the reason (G3: "authoring validation must reject this draft"). Every other fixture is valid.
    stated = sorted(
        {
            r["expect"]["terminal"]["reason"]
            for r in fx["expected_runs"]
            if (r["expect"].get("terminal") or {}).get("state") == "DRAFT_INVALID"
        }
    )
    assert sorted({g["code"] for g in got}) == stated
    if fx["fixture"].startswith("G3"):
        assert got == [{"code": "SKIP_DISPOSITION_MISSING", "at": "mi-specialist:@SKIP"}]


def test_every_rule_has_a_stable_code_and_a_schema_version() -> None:
    assert all(re.fullmatch(r"[A-Z][A-Z0-9_]+", c) for c in RULE_SINCE)
    assert set(RULE_SINCE.values()) <= {1, 2, 3, 4, 5, 6}
    seen = {f.code for fx in FIXTURES for f in validate(to_bundle(fx))}
    assert seen <= set(RULE_SINCE)  # no finding is ever reported under a code that is not in the register


# ---------------- condition engine parity
ENTRY = re.compile(r"^(?P<inst>[\w-]+): entry (?P<res>TRUE|FALSE|UNKNOWN)\b")
DECISION = re.compile(r"^(?P<inst>[\w-]+)/(?P<node>[\w-]+): (?P<res>TRUE|FALSE|UNKNOWN)$")


def _condition_cases() -> list[tuple[str, dict[str, Any], dict[str, Any], str, str, str]]:
    """Every condition result a fixture states explicitly: (id, fixture, run, kind, where, expected)."""
    out = []
    for fx in FIXTURES:
        for r in fx["expected_runs"]:
            for line in r["expect"].get("trace", []):
                m = ENTRY.match(line) or DECISION.match(line)
                if m:
                    kind = "DECISION" if "node" in m.groupdict() else "ENTRY"
                    where = f"{m['inst']}/{m['node']}" if kind == "DECISION" else m["inst"]
                    out.append((f"{fx['fixture'][:2]}·{r['name'][:38]}·{where}", fx, r, kind, where, m["res"]))
    return out


CASES = _condition_cases()


def test_the_fixtures_state_enough_condition_results_to_mean_something() -> None:
    assert len(CASES) == 32  # 9 decision results (F6, G5) and 23 eligibility results (F8, G1–G3, H1–H3)
    assert {c[5] for c in CASES} == {"TRUE", "FALSE", "UNKNOWN"}
    assert {c[3] for c in CASES} == {"ENTRY", "DECISION"}


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_condition_evaluation_agrees_with_every_result_the_fixtures_state(case: Any) -> None:
    _, fx, run, kind, where, expected = case
    b = to_bundle(fx)
    facts = run.get("profile", run.get("facts", {}))
    if kind == "ENTRY":
        inst = next(i for i in b.survey["sequence"] if i["instance"] == where)
        binding, answers = inst["eligibility"], {}
    else:
        inst_name, node_id = where.split("/")
        inst = next(i for i in b.survey["sequence"] if i["instance"] == inst_name)
        node = next(n for n in b.module_of(inst)["nodes"] if n["node"] == node_id)  # type: ignore[index]
        binding, answers = node["binding"], {}
        asked = set(run["expect"]["asked"])
        for name, src in binding["inputs"].items():
            key = f"{inst_name}/{src['node']}"
            given = run["answers"].get(key) if key in asked else None  # not collected on this path = UNKNOWN
            if given is not None:
                answers[name] = given["choices"] if "choices" in given else given.get("choice")
    cond = b.condition_of(binding)
    assert cond is not None
    assert check_condition(cond, b.fields) == []
    assert evaluate(cond["ast"], binding.get("params", {}), facts, answers).result == expected


@pytest.mark.parametrize(
    "fx",
    [f for f in FIXTURES if f.get("expected_plans")],
    ids=[f["fixture"] for f in FIXTURES if f.get("expected_plans")],
)
def test_eligibility_from_application_data_matches_every_expected_plan(fx: dict[str, Any]) -> None:
    """A plan's module statuses are decided by eligibility alone (schema /5): TRUE → IN; FALSE → OUT; UNKNOWN → OUT when
    the policy is to skip, HALTS when it is to stop. Plan ASSEMBLY is not part of SS-03A; only the condition results are
    checked here."""
    b = to_bundle(fx)
    checked = 0
    for p in fx["expected_plans"]:
        want = {m["instance"]: m["status"] for m in p["expect"]["modules"]}
        for inst in b.survey["sequence"]:
            elig = inst.get("eligibility")
            if elig is None:
                assert want[inst["instance"]] == "IN"
                continue
            cond = b.condition_of(elig)
            assert cond is not None
            res = evaluate(cond["ast"], elig.get("params", {}), p["facts"]).result
            status = (
                "IN"
                if res == "TRUE"
                else "OUT"
                if res == "FALSE" or elig["unknown_policy"] == "SKIP_WITH_REASON"
                else "HALTS"
            )
            assert status == want[inst["instance"]], (p["name"], inst["instance"], res)
            checked += 1
    if fx["fixture"].startswith("K8"):
        assert checked == 12


# ---------------- the condition engine, directly
def _cmp(op: str, left: Any, right: Any) -> dict[str, Any]:
    return {"op": op, "left": left, "right": right}


def test_three_valued_logic_missing_is_unknown_never_false() -> None:
    premium = _cmp("GTE", {"field": "p"}, {"param": "t"})
    assert evaluate(premium, {"t": 12000}, {"p": 12000}).result == "TRUE"  # the boundary value is included
    assert evaluate(premium, {"t": 12000}, {"p": 11999.99}).result == "FALSE"
    assert evaluate(premium, {"t": 12000}, {"p": None}).result == "UNKNOWN"
    assert evaluate(premium, {"t": 12000}, {}).result == "UNKNOWN"
    assert evaluate(premium, {}, {"p": 1}).result == "UNKNOWN"
    assert evaluate({"op": "NOT", "arg": premium}, {"t": 1}, {}).result == "UNKNOWN"
    known_true = _cmp("EQ", {"literal": 1}, {"literal": 1})
    known_false = _cmp("EQ", {"literal": 1}, {"literal": 2})
    # a known operand that already decides wins over UNKNOWN; otherwise UNKNOWN is kept
    assert evaluate({"op": "OR", "args": [premium, known_true]}, {"t": 1}, {}).result == "TRUE"
    assert evaluate({"op": "OR", "args": [premium, known_false]}, {"t": 1}, {}).result == "UNKNOWN"
    assert evaluate({"op": "AND", "args": [premium, known_false]}, {"t": 1}, {}).result == "FALSE"
    assert evaluate({"op": "AND", "args": [premium, known_true]}, {"t": 1}, {}).result == "UNKNOWN"


def test_numbers_compare_as_decimals_and_answers_as_codes() -> None:
    assert evaluate(_cmp("EQ", {"field": "a"}, {"literal": 0.3}), None, {"a": Decimal("0.3")}).result == "TRUE"
    assert evaluate(_cmp("GT", {"field": "a"}, {"literal": 0.1}), None, {"a": 0.1}).result == "FALSE"
    yes = _cmp("EQ", {"input": "risk"}, {"literal": "YES"})
    assert evaluate(yes, answers={"risk": "YES"}).result == "TRUE"
    assert evaluate(yes, answers={"risk": "NO"}).result == "FALSE"
    assert evaluate(yes, answers={}).result == "UNKNOWN"  # not asked on this path
    none_of = _cmp("INCLUDES_NONE", {"input": "areas"}, {"literal": ["PREMIUM", "CLAIMS"]})
    assert evaluate(none_of, answers={"areas": []}).result == "TRUE"  # answered, nothing selected: KNOWN and empty
    assert evaluate(none_of, answers={"areas": ["CLAIMS"]}).result == "FALSE"
    assert evaluate(none_of, answers={"areas": None}).result == "UNKNOWN"  # not answered: never an empty selection
    assert evaluate(_cmp("EQ", {"field": "flag"}, {"literal": True}), None, {"flag": False}).result == "FALSE"


def test_the_explanation_says_what_was_read() -> None:
    ex = evaluate(
        {
            "op": "AND",
            "args": [_cmp("GTE", {"field": "age"}, {"param": "min"}), _cmp("EQ", {"input": "ok"}, {"literal": "NO"})],
        },
        {"min": 60},
        {"age": 67},
        {"ok": "NO"},
    )
    assert ex.result == "TRUE" and [c.result for c in ex.children] == ["TRUE", "TRUE"]
    assert ex.children[0].reads == (("field", "age", 67), ("param", "min", 60))


def test_a_malformed_condition_is_an_error_not_a_result() -> None:
    with pytest.raises(ConditionError) as e:
        evaluate({"op": "ROUGHLY", "left": {"literal": 1}, "right": {"literal": 1}})
    assert e.value.code == "CONDITION_OPERATOR_UNKNOWN"
    with pytest.raises(ConditionError):
        evaluate(_cmp("GT", {"literal": "a"}, {"literal": 1}))
    with pytest.raises(ConditionError):
        evaluate({"op": "AND", "args": []})


def test_typed_dependencies_are_checked_at_authoring_and_version_1_inputs_are_explicitly_limited() -> None:
    fields = {"p": {"type": "MONEY"}, "fam": {"type": "ENUM", "values": ["A"]}}
    cond = {
        "params": {"t": {"type": "MONEY"}},
        "inputs": {"ok": {"answer_type": "YES_NO"}, "years": {"answer_type": "NUMERIC"}},
    }
    codes = lambda ast: [c for c, _ in check_condition({**cond, "ast": ast}, fields)]  # noqa: E731
    assert codes(_cmp("GTE", {"field": "p"}, {"param": "t"})) == []
    assert codes(_cmp("GTE", {"field": "nope"}, {"param": "t"})) == ["CONDITION_FIELD_UNKNOWN"]
    assert codes(_cmp("GTE", {"field": "p"}, {"param": "nope"})) == ["CONDITION_PARAM_UNDECLARED"]
    assert codes(_cmp("EQ", {"input": "nope"}, {"literal": "YES"})) == ["CONDITION_INPUT_UNDECLARED"]
    assert codes(_cmp("GT", {"field": "fam"}, {"literal": 1})) == ["CONDITION_OPERATOR_TYPE_MISMATCH"]
    assert codes(_cmp("INCLUDES_ANY", {"input": "ok"}, {"literal": ["YES"]})) == ["CONDITION_OPERATOR_TYPE_MISMATCH"]
    # TS-10: a number answer is not readable in schema version 1 — refused explicitly, never ignored
    assert codes(_cmp("GT", {"input": "years"}, {"literal": 10})) == ["CONDITION_INPUT_TYPE_UNSUPPORTED"]


# ---------------- approved mechanisms that have no golden fixture yet
def _k5() -> tuple[dict[str, Any], Bundle]:
    fx = next(f for f in FIXTURES if f["fixture"].startswith("K5"))
    return fx, to_bundle(fx)


def _with(b: Bundle, **changes: Any) -> Bundle:
    return Bundle(**{**b.__dict__, **changes})


def test_spoken_variables_are_default_deny_until_the_catalog_allowlists_a_field() -> None:
    _, b = _k5()
    denied = [f.at for f in validate(b) if f.code == "VARIABLE_NOT_PERMITTED"]
    assert (
        len(denied) == 5 and RULE_SINCE["VARIABLE_NOT_PERMITTED"] == 6
    )  # every variable use, in a /5 fixture with no allowlist
    allowed = _with(b, fields={k: {**v, "speakable": True} for k, v in b.fields.items()})
    assert validate(allowed) == []


def test_conversational_delivery_is_never_publishable_and_a_recording_needs_an_approved_asset() -> None:
    _, b = _k5()
    b = _with(b, fields={k: {**v, "speakable": True} for k, v in b.fields.items()})
    key = ("S-END", 1)

    def codes(patch: dict[str, Any], text: str | None = None) -> list[str]:
        w = {**b.wordings[key], **patch, **({"text": text} if text else {})}
        return [f.code for f in validate(_with(b, wordings={**b.wordings, key: w}))]

    assert codes({"delivery_mode": "CONVERSATIONAL"}) == ["DELIVERY_CONVERSATIONAL_BLOCKED"]
    assert codes({"delivery_mode": "EXACT_AUDIO"}) == ["RECORDING_WITH_VARIABLE"]
    plain = "Thank you."
    assert codes({"delivery_mode": "EXACT_AUDIO"}, plain) == ["RECORDING_ASSET_MISSING"]
    assert codes(
        {"delivery_mode": "EXACT_AUDIO", "asset": {"id": "a1", "sha256": "0" * 64, "approval": "DRAFT"}}, plain
    ) == ["RECORDING_ASSET_MISSING"]
    assert (
        codes(
            {"delivery_mode": "EXACT_AUDIO", "asset": {"id": "a1", "sha256": "0" * 64, "approval": "APPROVED"}}, plain
        )
        == []
    )


def test_a_response_obligation_must_be_a_code_of_the_governed_catalog() -> None:
    fx = next(f for f in FIXTURES if f["fixture"].startswith("K3"))
    b = to_bundle(fx)
    assert [f.code for f in validate(_with(b, obligations=frozenset({"SOMETHING_ELSE"})))] == [
        "RESPONSE_OBLIGATION_UNKNOWN"
    ]
    assert validate(_with(b, obligations=frozenset({"MANDATORY"}))) == []


def test_tampering_with_any_pinned_document_changes_the_manifest() -> None:
    _, b = _k5()
    before = manifest_sha256(manifest_of(b))
    key = ("S-END", 1)
    tampered = _with(b, wordings={**b.wordings, key: {**b.wordings[key], "text": b.wordings[key]["text"] + " "}})
    after = manifest_of(tampered)
    assert manifest_sha256(after) != before
    changed = [e for e, o in zip(after, manifest_of(b), strict=True) if e != o]
    assert [(e["kind"], e["code"]) for e in changed] == [("WORDING", "S-END")]
