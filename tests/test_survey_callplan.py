# ruff: noqa: E501
"""SS-03B.2 — the Python call-plan assembler against the 14 expected plans of the schema /5 golden fixtures.

No expected value lives here: each expected plan is assembled by ``app.domain.survey.callplan`` on the canonical
documents and compared, in the fixture's vocabulary, with what the fixture states."""

from __future__ import annotations

import inspect
import json
from decimal import Decimal
from typing import Any

import pytest

from app.domain.survey import callplan
from app.domain.survey.callplan import assemble
from app.domain.survey.execution import execute
from app.domain.survey.wording import format_value, render
from tests.survey_fixtures import load_all, to_bundle

FIXTURES = [fx for fx in load_all() if fx.get("expected_plans")]
PLANS = [(fx, p) for fx in FIXTURES for p in fx["expected_plans"]]


def in_fixture_terms(plan: dict[str, Any]) -> dict[str, Any]:
    values = lambda vs: [{"variable": v["variable"], "value": v["value"], "state": v["state"]} for v in vs]  # noqa: E731
    return {
        "status": plan["status"],
        "issues": [{"code": i["code"], "at": i["at"]} for i in plan["issues"]],
        "inputs": {i["field"]: i["state"] for i in plan["inputs"]},
        "modules": [{"instance": m["instance"], "status": m["status"]} for m in plan["modules"]],
        "items": {
            i["key"]: {"statement": i["statement"], "role": i["role"], "mandatory": i["mandatory"], "delivery_mode": i["delivery_mode"], "wording_version": i["wording_version"], "text": i["text"], "values": values(i["values"]), "certainty": i["certainty"]}
            for m in plan["modules"] for i in m["items"]
        },
        "open": {o["key"]: {"kind": o["kind"], "alternatives": o["alternatives"]} for m in plan["modules"] for o in m["open"]},
    }  # fmt: skip


def test_the_14_expected_plans_are_all_here() -> None:
    assert (len(FIXTURES), len(PLANS)) == (7, 14)  # K2 is invalid on purpose and has no plan


@pytest.mark.parametrize(("fx", "p"), PLANS, ids=[f"{fx['fixture'][:2]} · {p['name'][:70]}" for fx, p in PLANS])
def test_golden_plan(fx: dict[str, Any], p: dict[str, Any]) -> None:
    assert in_fixture_terms(assemble(to_bundle(fx), p.get("facts") or {})) == p["expect"]


def test_the_same_inputs_give_the_same_plan_and_fingerprint_and_different_facts_a_different_one() -> None:
    seen: dict[str, str] = {}
    for fx, p in PLANS:
        b, facts = to_bundle(fx), p.get("facts") or {}
        one, two = (
            assemble(b, facts),
            assemble(to_bundle(fx), dict(reversed(list(facts.items())))),
        )  # key order is irrelevant
        assert one == two and one["fingerprint"] == two["fingerprint"] and len(one["fingerprint"]) == 64
        key = fx["fixture"] + json.dumps(facts, sort_keys=True)
        seen[key] = one["fingerprint"]
        assert json.dumps(p, sort_keys=True) == json.dumps(
            next(x for x in fx["expected_plans"] if x["name"] == p["name"]), sort_keys=True
        )  # inputs untouched
    k8 = next(fx for fx in FIXTURES if fx["fixture"].startswith("K8"))
    prints = {assemble(to_bundle(k8), p.get("facts") or {})["fingerprint"] for p in k8["expected_plans"]}
    assert len(prints) == len(k8["expected_plans"])  # each application has its own plan


def test_a_plan_and_a_run_agree_on_the_exact_wording_of_everything_delivered() -> None:
    for fx in FIXTURES:
        b = to_bundle(fx)
        for run in fx["expected_runs"]:
            facts = run.get("facts") or {}
            planned = {i["key"]: i for m in assemble(b, facts)["modules"] for i in m["items"]}
            r = execute(b, facts, lambda key, attempt, run=run: run["answers"].get(key) if attempt == 0 else None)
            for d in r["delivered"]:
                assert planned[d["key"]]["text"] == d["text"] and planned[d["key"]]["values"] == d["values"], d["key"]


def test_missing_is_missing_unknown_is_not_false_and_an_undeliverable_item_blocks_the_plan() -> None:
    k8 = next(fx for fx in FIXTURES if fx["fixture"].startswith("K8"))
    b = to_bundle(k8)
    full = next(p for p in k8["expected_plans"] if assemble(b, p.get("facts") or {})["status"] == "READY")["facts"]
    empty = assemble(b, {})
    assert empty["status"] == "BLOCKED" and empty["issues"]
    assert {i["state"] for i in empty["inputs"]} == {"MISSING"} and all(
        i["value"] is None for i in empty["inputs"]
    )  # nothing is defaulted
    for m in empty["modules"]:
        if m["eligibility"]:
            assert m["eligibility"]["result"] == "UNKNOWN"  # … and never FALSE
            assert m["status"] in ("HALTS", "OUT") and m["reason"] in ("UNKNOWN_HALTS", "UNKNOWN_SKIPPED")
    # an item whose wording cannot be rendered has no text at all, and is an issue
    undeliverable = [i for m in empty["modules"] for i in m["items"] if i["text"] is None]
    assert undeliverable and {i["key"] for i in undeliverable} <= {
        x["at"] for x in empty["issues"] if x["code"] == "WORDING_VALUE_MISSING"
    }
    assert all(e["code"] == "MISSING" for i in undeliverable for e in i["errors"])
    assert assemble(b, full)["status"] == "READY"
    # empty string is missing, not a value
    assert assemble(b, {k: "" for k in full})["fingerprint"] == assemble(b, {k: None for k in full})["fingerprint"]


def test_numbers_are_never_rounded_or_truncated() -> None:
    money, whole = {"type": "MONEY", "unit": "SGD"}, {"type": "INTEGER", "unit": "years"}
    assert format_value(money, 12000) == "SGD 12,000"
    assert format_value(money, 1234567.5) == "SGD 1,234,567.50"
    assert format_value(money, Decimal("0.07")) == "SGD 0.07"
    assert format_value(money, 12000.005) is None  # three decimals: refused, not rounded to 12,000.01 or 12,000.00
    assert format_value(money, 0.1 + 0.2) is None  # 0.30000000000000004 is not an amount
    assert format_value(whole, 35) == "35" and format_value(whole, 35.0) == "35"
    assert format_value(whole, 35.5) is None  # not truncated to 35
    assert (
        format_value(whole, True) is None
        and format_value(money, "12000") is None
        and format_value(money, float("nan")) is None
    )
    fields = {
        "policy.annual_premium": money,
        "customer.age_years": whole,
        "flag": {"type": "BOOLEAN"},
        "secret": {"type": "TEXT", "speakable": False},
    }
    r = render(
        "You pay {{policy.annual_premium}} at {{ customer.age_years }}.",
        fields,
        {"policy.annual_premium": 12000.5, "customer.age_years": 41},
    )
    assert r["text"] == "You pay SGD 12,000.50 at 41."
    assert render("{{policy.annual_premium}}", fields, {"policy.annual_premium": 12000.005})["text"] is None
    assert [
        v["state"]
        for v in render("{{flag}} {{nope}} {{secret}} {{oops", fields, {"flag": True, "secret": "x"})["values"]
    ] == ["UNKNOWN_VARIABLE", "UNKNOWN_VARIABLE", "NOT_PERMITTED", "MALFORMED"]


def test_a_plan_never_claims_a_call_may_be_made() -> None:
    plan = assemble(to_bundle(FIXTURES[0]), FIXTURES[0]["expected_plans"][0].get("facts") or {})
    flat = json.dumps(plan).lower()
    for word in ("eligible_for_call", "live_eligib", "may_call", "approved"):
        assert word not in flat
    assert set(plan) == {"schema", "survey", "status", "issues", "inputs", "modules", "counts", "fingerprint"}
    src = inspect.getsource(callplan)
    for forbidden in ("sqlalchemy", "datetime", "requests", "httpx", "random", "uuid"):
        assert f"import {forbidden}" not in src and f"from {forbidden}" not in src
