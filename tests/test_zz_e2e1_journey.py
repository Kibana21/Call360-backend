# ruff: noqa: E501, F811
"""E2E-1 — one governed, SYNTHETIC application-to-assurance journey across the modules that already exist, through
real HTTP and real PostgreSQL (``call360_test``). A thin harness: it reuses the helpers and golden fixtures of the
module tests and adds no engine, no rule and no business meaning of its own.

Every record is made through the governed APIs by distinct identities; nothing is written to the database directly
(the finding rule set goes through its existing service lifecycle, as in the EVAL-1 tests). The control policy is
NAMED EXPLICITLY for each evaluation: nothing selects a control policy for an application. Everything is synthetic.

Scenarios: A complete happy path · B completed journey with an unsatisfied control · C incomplete journey ·
D cross-survey conflicting answers · E missing or unknown applicability · F historical integrity ·
G security and isolation. The one drift case is INJECTED (the engine's output is altered inside the test).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.survey import journey_trace
from app.domain.survey import simulation as simulation_module
from app.main import create_app
from tests.support import make_account
from tests.test_survey_api import GRANTS, MARKETS, _client, post, with_grants
from tests.test_survey_api import trio as _trio  # noqa: F401
from tests.test_survey_assignment import OPERATIONAL, bind, clean_rules, counts, publish_rule  # noqa: F401
from tests.test_survey_assignment_groups import group
from tests.test_survey_control_policy import ev, instance, ob, pc, policy_body, published_policy, under
from tests.test_survey_evaluation import ALL, RULES_V1, YES, entry, items_of, mapped, publish_finding_rules
from tests.test_survey_execution_assurance import ON, assure
from tests.test_survey_lib1 import build, draft, empty_survey, pin_module, publish

E = "/api/v1/survey-evaluation"
A = "/api/v1/survey-assignment"
SG = {"field": "market", "values": ["SG"]}
LINKS = [k for _, _, keys in journey_trace.QUESTIONS for k in keys]
#: tables no scenario may touch: operational callback records, operational findings, and Script Studio's own rules
UNTOUCHED = (*OPERATIONAL, "review_decision", "script_version", "control", "control_mapping")
FACTS = {"policy.annual_premium": 3000, "policy.is_replacement": True, "customer.age_years": 40}
K8_ANSWERS = {"mi-opening/n2": {"choice": "YES"}, "mi-replacement/n1": {"choice": "YES"}}


@pytest.fixture()
def survey_app(settings: Settings, engine: Engine):  # type: ignore[no-untyped-def]
    app = create_app(settings.model_copy(update=ON))
    with_grants(app)
    return app


@pytest.fixture()
def trio(_trio: Any) -> Any:
    for person in _trio[3]:
        GRANTS[person.principal_id] = ALL  # every permission: only the identity rules can stop them
    return _trio


def numbers(prefix: str, term: int) -> dict[str, dict[str, Any]]:
    return {f"{prefix}/n1": {"number": term}, f"{prefix}/n2": {"number": 12.5}, f"{prefix}/n3": {"number": -3}}


def dims(t: dict[str, Any]) -> dict[str, Any]:
    return {k: v["status"] for k, v in t["dimensions"].items()}


def link(t: dict[str, Any], key: str) -> dict[str, Any]:
    return next(x for x in t["chain"] if x["key"] == key)


def trace_of(c: TestClient, **params: Any) -> dict[str, Any]:
    r = c.get(f"{E}/journey-trace", params={k: v for k, v in params.items() if v is not None})
    assert r.status_code == 200, r.text
    return r.json()


def outcomes(e: dict[str, Any]) -> dict[str, tuple[str, str]]:
    return {f"{c['control_code']}/{c['obligation']}": (c["outcome"], c["coverage"]) for c in e["controls"]}


def test_one_governed_synthetic_application_from_assignment_to_assurance(
    clean_rules: None, trio: Any, survey_app: Any, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    author, checker, publisher, people = trio
    maker = _client(survey_app, make_account(db, "LOCAL_USER_SG", prefix="rmaker"))
    rule_checker = _client(survey_app, make_account(db, "LOCAL_SC_CHECKER_SG", prefix="rchk"))
    untouched_before = counts(db, UNTOUCHED)
    publish_finding_rules(db, RULES_V1)  # the EXISTING findings engine's rule set, through its existing lifecycle

    # ================= steps 1–3: surveys authored, reviewed and published by three different people =================
    s1, code1, renamed = build(author, "K8", "Sale verification (synthetic)")
    c1 = post(author, f"/api/v1/survey-definitions/{s1}/candidates", {"note": "self-review attempt", "acknowledgements": [{"code": f["code"], "at": f["at"], "reason": "Synthetic test content; acknowledged."} for f in post(author, f"/api/v1/survey-definitions/{s1}/draft/validate").json().get("findings", []) if f["severity"] == "WARNING"]})  # fmt: skip
    assert c1.status_code == 201, c1.text
    cid = c1.json()["id"]
    assert post(author, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code in (
        403,
        409,
    )  # G: no self-approval
    assert post(checker, f"/api/v1/survey-candidates/{cid}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert post(checker, f"/api/v1/survey-candidates/{cid}/publish").status_code in (
        403,
        409,
    )  # G: the approver does not publish
    r = post(publisher, f"/api/v1/survey-candidates/{cid}/publish")
    assert r.status_code == 201, r.text
    v1 = r.json()["id"]
    s2, code2, _ = build(author, "K3", "Affordability numbers (synthetic)")  # holds the reusable module and question
    v2 = publish(trio, s2)[1]
    s3, code3 = empty_survey(author, "Follow-up (reuses the published term question)")
    assert (
        pin_module(author, s3, draft(author, s2)).status_code == 200
    )  # the PUBLISHED module of survey 2, pinned exactly
    v3 = publish(trio, s3)[1]
    it1, it2, it3 = items_of(db, v1), items_of(db, v2), items_of(db, v3)
    assert it3["mi-shared/n1"] == it2["mi-numbers/n1"]  # one published question revision, in two distinct surveys

    # ================= steps 4–5: rules, bindings and requirement groups, each governed =================
    publish_rule(maker, rule_checker, "P-A", [SG, {"field": "product_family", "values": ["PROTECTION"]}], 1)
    publish_rule(maker, rule_checker, "R-B", [SG, {"field": "premium_frequency", "values": ["SINGLE"]}], 2)
    publish_rule(maker, rule_checker, "R-C", [SG, {"field": "selling_channel", "values": ["AGENCY"]}], 3)
    binding = {"P-A": bind(trio, "P-A", v1), "R-B": bind(trio, "R-B", v2), "R-C": bind(trio, "R-C", v3)}
    group(trio, "PRIMARY-SG", "PRIMARY", ["P-A"], sequence=1)
    group(trio, "ADD-B", "ADD_REQUIRED", ["R-B"], sequence=2)
    group(trio, "ADD-C", "ADD_REQUIRED", ["R-C"], sequence=3)
    fields = {f["field"]: [v["value"] for v in f["values"]] for f in author.get(f"{A}/options").json()["fields"]}
    application = {
        "market": "SG", "product_family": "PROTECTION", "selling_channel": "AGENCY", "premium_frequency": "SINGLE",
        "case_purpose": fields["case_purpose"][0], "product_code": fields["product_code"][0], "is_ilp": False,
        "risk_band": fields["risk_band"][0], "contact_role": [fields["contact_role"][0]],
    }  # fmt: skip

    # ================= step 11: a governed synthetic control policy and separately published mappings =================
    older = {"condition": {"code": renamed["C-OLDER"], "version": 1}, "params": {"minimum_age": 60}}
    body = policy_body(
        [
            pc("SYN-CTRL-01", [ob("IDENTITY", [ev("E-ID")]), ob("OPENING", [ev("E-HELLO", "DELIVERY")]), ob("TERM", [ev("E-TERM")])]),
            pc("SYN-CTRL-02", [ob("REPLACEMENT", [ev("E-REPL")])]),
            pc("SYN-CTRL-03", [ob("SENIOR", [ev("E-ACK")], older)]),
        ],
        code="POL-E2E", name="E2E-1 synthetic control policy",
    )  # fmt: skip
    r = post(author, f"{E}/control-policies", body)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert post(author, f"{E}/control-policies/{pid}/decision", {"verdict": "APPROVE"}).status_code in (403, 409)  # G
    assert post(checker, f"{E}/control-policies/{pid}/decision", {"verdict": "APPROVE"}).status_code == 200
    assert post(checker, f"{E}/control-policies/{pid}/publish").status_code in (403, 409)  # G
    policy = post(publisher, f"{E}/control-policies/{pid}/publish").json()
    assert (policy["status"], policy["revision"], policy["completeness"]) == ("PUBLISHED", 1, "DECLARED_COMPLETE")
    term20 = {"method": "NUMERIC_COMPARE", "evaluation": {"operator": "EQ", "value": 20, "unit": "COUNT"}}
    m01 = mapped(
        trio, "SYN-CTRL-01",
        [
            entry(it1["mi-opening/n2"], YES) | {"obligation": "IDENTITY", "requirement": "E-ID"},
            entry(it1["mi-opening/n1"]) | {"obligation": "OPENING", "requirement": "E-HELLO"},
            entry(it2["mi-numbers/n1"], term20) | {"obligation": "TERM", "requirement": "E-TERM"},
        ],
    )  # fmt: skip
    mapped(trio, "SYN-CTRL-02", [entry(it1["mi-replacement/n1"], YES) | {"requirement": "E-REPL"}])
    mapped(trio, "SYN-CTRL-03", [entry(it1["mi-senior/n1"], {"method": "ACKNOWLEDGEMENT"}) | {"requirement": "E-ACK"}])

    def compose(inputs: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
        r = post(author, f"{A}/composite-plans", {"assignment_inputs": inputs, "facts": facts})
        assert r.status_code == 201, r.text
        return r.json()

    def journey(
        answers: dict[int, dict[str, Any]],
        facts: dict[str, Any] = FACTS,
        until: int | None = None,
        first: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        comp = compose(application, facts)
        r = post(author, f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "E2E-1"})
        assert r.status_code == 201, r.text
        co, n = r.json(), 0
        if first is not None:  # a refused input, recorded as refused
            co = post(
                author,
                f"{A}/coordinated-simulations/{co['id']}/inputs",
                {"expected_inputs": 0, "key": co["current"]["pending"]["key"], "answer": first},
            ).json()
        while co["status"] == "RUNNING" and (until is None or n < until):
            key = co["current"]["pending"]["key"]
            r = post(
                author,
                f"{A}/coordinated-simulations/{co['id']}/inputs",
                {
                    "expected_inputs": co["progress"]["inputs"],
                    "key": key,
                    "answer": answers[co["current"]["position"]][key],
                },
            )
            assert r.status_code == 200, r.text
            co, n = r.json(), n + 1
        return co | {"composite": comp}

    def full(term2: int, term3: int, **kw: Any) -> dict[str, Any]:
        return journey({1: K8_ANSWERS, 2: numbers("mi-numbers", term2), 3: numbers("mi-shared", term3)}, **kw)

    # =====================================================================================================
    # Scenario A — complete happy path (steps 6–15)
    # =====================================================================================================
    a = full(20, 20, first={})  # the first input is refused (no choice given) and recorded as refused
    comp = a["composite"]
    # 6–8: one application selected three surveys; exact versions, reasons and governed order
    assert (comp["selection_status"], comp["ordering_status"], comp["plan_status"]) == ("RESOLVED", "GOVERNED", "READY")
    assert [(s["group"], s["rule"], s["survey_version_id"], s["binding_id"]) for s in comp["composite"]["selected"]] == [
        ("PRIMARY-SG", "P-A v1", v1, binding["P-A"]), ("ADD-B", "R-B v1", v2, binding["R-B"]), ("ADD-C", "R-C v1", v3, binding["R-C"]),
    ]  # fmt: skip
    assert all(s["reason"] for s in comp["composite"]["selected"]) and comp["composite"]["ordering"]["order"] == [
        "PRIMARY-SG",
        "ADD-B",
        "ADD-C",
    ]
    # 9–10: the coordinated simulation; accepted answers, one refusal, each survey its own evidence
    assert a["status"] == "ALL_SURVEYS_COMPLETED" and [s["state"] for s in a["surveys"]] == ["COMPLETED"] * 3
    assert a["progress"]["refused_inputs"] == 1 and len({s["simulation_id"] for s in a["surveys"]}) == 3
    # 12–13: evaluated at control-obligation level under the EXPLICITLY NAMED policy
    ea_ = under(author, policy["id"], coordinated=a["id"])
    assert (ea_["processing_status"], ea_["coverage"]["status"], ea_["coverage"]["reason"]) == (
        "COMPLETED",
        "COMPLETE_WITHIN_POLICY_SCOPE",
        "ALL_REQUIRED_EVIDENCED",
    )
    assert outcomes(ea_) == {
        "SYN-CTRL-01/IDENTITY": ("SATISFIED", "EVIDENCED"), "SYN-CTRL-01/OPENING": ("SATISFIED", "EVIDENCED"), "SYN-CTRL-01/TERM": ("SATISFIED", "EVIDENCED"),
        "SYN-CTRL-02/REPLACEMENT": ("SATISFIED", "EVIDENCED"), "SYN-CTRL-03/SENIOR": ("NOT_APPLICABLE", "NOT_REQUIRED"),
    }  # fmt: skip
    assert ea_["findings"] == [] and ea_["applicability"]["input_lineage"]["status"] == "UNVERIFIED"
    assert (
        len({o["simulation_id"] for o in instance(ea_, "SYN-CTRL-01", "TERM")["observations"]}) == 2
    )  # one obligation, two surveys
    # 14: execution assurance
    aa = assure(author, coordinated=a["id"], evaluation=ea_["id"])
    assert (aa["status"], [s["status"] for s in aa["surveys"]], {c["status"] for c in aa["journey_checks"]}) == (
        "VERIFIED",
        ["VERIFIED"] * 3,
        {"PASSED"},
    )
    assert aa["surveys"][0]["rejections"][0]["code"] == "CHOICE_REQUIRED" and aa["findings"] == []

    # ---- step 15 and the consolidated provenance chain
    ta = trace_of(author, coordinated_simulation_id=a["id"])
    assert (ta["record_class"], ta["contract"], ta["journey"]["kind"], ta["evaluation_id"], ta["assurance_id"]) == (
        "SIMULATION",
        journey_trace.CONTRACT,
        "COORDINATED",
        ea_["id"],
        aa["id"],
    )
    assert [x["key"] for x in ta["chain"]] == LINKS and [x["step"] for x in ta["chain"]] == list(range(1, 16))
    assert {x["status"] for x in ta["chain"]} == {"RECORDED", "NONE"} and link(ta, "FINDINGS")["status"] == "NONE"
    assert dims(ta) == {
        "completion": "ALL_SURVEYS_COMPLETED",
        "satisfaction": "EVALUATED",
        "coverage": "COMPLETE_WITHIN_POLICY_SCOPE",
        "assurance": "VERIFIED",
        "eligibility": "NOT_ESTABLISHED",
    }
    # every link names the authoritative record, its version, its fingerprint and its source — the SAME ones the modules hold
    rec = lambda key: link(ta, key)["records"]  # noqa: E731
    assert rec("APPLICATION")[0]["sha256"] == comp["application_sha256"] == rec("ASSIGNMENT_INPUTS")[0]["sha256"]
    assert rec("ASSIGNMENT_INPUTS")[0]["facts"]["inputs"] == application
    rules = {x["label"]: x for x in rec("RULE_VERSIONS")}
    assert sorted(rules) == ["P-A v1", "R-B v1", "R-C v1"] and all(
        x["id"] and x["sha256"] and x["version"] == 1 for x in rules.values()
    )
    assert rules["P-A v1"]["facts"]["selected_in_groups"] == ["PRIMARY-SG"] and {
        c["result"] for c in rules["P-A v1"]["facts"]["conditions"]
    } == {"PASS"}
    stored = {
        r_["rule_code"]: r_
        for r_ in db.execute(
            text(
                "SELECT id::text AS id, rule_code, checksum FROM script_assignment_rule_version WHERE rule_code IN ('P-A','R-B','R-C')"
            )
        ).mappings()
    }
    assert {k: (v["id"], v["sha256"]) for k, v in rules.items()} == {
        f"{c} v1": (stored[c]["id"], stored[c]["checksum"]) for c in stored
    }
    assert [(x["id"], x["facts"]["survey_version_id"]) for x in rec("BINDINGS")] == [
        (binding["P-A"], v1),
        (binding["R-B"], v2),
        (binding["R-C"], v3),
    ]
    assert [(x["label"], x["version"], x["facts"]["outcome"]) for x in rec("REQUIREMENT_GROUPS")] == [
        ("PRIMARY-SG (PRIMARY)", 1, "SELECTED"),
        ("ADD-B (ADD_REQUIRED)", 1, "SELECTED"),
        ("ADD-C (ADD_REQUIRED)", 1, "SELECTED"),
    ]
    assert [(x["id"], x["version"], x["sha256"]) for x in rec("SURVEY_VERSIONS")] == [
        (s["survey_version_id"], "1.0", s["manifest_sha256"]) for s in a["surveys"]
    ]
    assert (rec("COMPOSITE_PLAN")[0]["id"], rec("COMPOSITE_PLAN")[0]["sha256"]) == (
        comp["id"],
        comp["fingerprint"],
    ) and len(rec("COMPOSITE_PLAN")) == 4
    assert [(x["id"], x["sha256"], x["facts"]["state"]) for x in rec("SIMULATIONS")] == [
        (s["simulation_id"], s["run_sha256"], "COMPLETED") for s in a["surveys"]
    ]
    assert rec("SIMULATIONS")[0]["facts"]["refused"] == [{"key": "mi-opening/n2", "code": "CHOICE_REQUIRED"}]
    assert (rec("COORDINATED_SIMULATION")[0]["id"], rec("COORDINATED_SIMULATION")[0]["sha256"]) == (
        a["id"],
        a["replay_sha256"],
    )
    assert (
        rec("CONTROL_POLICY")[0]["id"],
        rec("CONTROL_POLICY")[0]["version"],
        rec("CONTROL_POLICY")[0]["sha256"],
        rec("CONTROL_POLICY")[0]["facts"]["selected_by"],
    ) == (policy["id"], 1, ea_["policy"]["sha256"], "NAMED_EXPLICITLY")
    assert sorted((x["facts"]["control_code"], x["version"]) for x in rec("MAPPINGS")) == [
        ("SYN-CTRL-01", 1),
        ("SYN-CTRL-02", 1),
        ("SYN-CTRL-03", 1),
    ]
    assert next(x for x in rec("MAPPINGS") if x["id"] == m01["id"])["sha256"] == next(
        m["sha256"] for m in ea_["pins"]["mappings"] if m["id"] == m01["id"]
    )
    assert (
        rec("EVALUATION")[0]["id"],
        rec("EVALUATION")[0]["sha256"],
        rec("EVALUATION")[0]["facts"]["input_sha256"],
    ) == (ea_["id"], ea_["result_sha256"], ea_["input_sha256"])
    assert [
        (x["facts"]["control_code"], x["facts"]["obligation"], x["facts"]["outcome"], x["facts"]["coverage"])
        for x in rec("CONTROL_RESULTS")
    ] == [(c["control_code"], c["obligation"], c["outcome"], c["coverage"]) for c in ea_["controls"]]
    assert (
        rec("EXECUTION_ASSURANCE")[0]["id"],
        rec("EXECUTION_ASSURANCE")[0]["sha256"],
        rec("EXECUTION_ASSURANCE")[0]["facts"]["beside_evaluation"],
    ) == (aa["id"], aa["result_sha256"], ea_["id"])
    assert (
        all(r_["source"] for x in ta["chain"] for r_ in x["records"])
        and ta["integrity"]["all_records_recompute"] is True
    )
    # what is unverified or undecided is said, not hidden
    assert [o["code"] for o in ta["open_points"]] == [
        "SYNTHETIC_CONTENT",
        "INPUT_CONSISTENCY_UNVERIFIED",
        "CROSS_SURVEY_POLICY_UNRESOLVED",
        "POLICY_NAMED_EXPLICITLY",
        "INPUT_LINEAGE_UNVERIFIED",
        "NOT_SPOKEN",
    ]
    assert (
        trace_of(author, coordinated_simulation_id=a["id"])["trace_sha256"] == ta["trace_sha256"]
    )  # reading again is the same chain
    # the trace computes nothing: the same evaluation and assurance records, untouched
    assert author.get(f"{E}/evaluations/{ea_['id']}").json()["result_sha256"] == ea_["result_sha256"]

    # =====================================================================================================
    # Scenario B — a completed journey with an unsatisfied control
    # =====================================================================================================
    b = full(30, 30)
    eb = under(author, policy["id"], coordinated=b["id"])
    ab = assure(author, coordinated=b["id"], evaluation=eb["id"])
    assert b["status"] == "ALL_SURVEYS_COMPLETED"  # a completed journey …
    assert outcomes(eb)["SYN-CTRL-01/TERM"] == ("NOT_SATISFIED", "EVIDENCED")  # … can contain an unsatisfied control,
    assert eb["coverage"]["status"] == "COMPLETE_WITHIN_POLICY_SCOPE"  # … with complete evidence coverage,
    assert ab["status"] == "VERIFIED"  # … and a faithfully executed one: VERIFIED does not imply SATISFIED
    assert [(f["control_code"], f["obligation"], f["rule"]["rule_code"], f["trigger"]) for f in eb["findings"]] == [
        ("SYN-CTRL-01", "TERM", "FR-EVAL-MISMATCH", "MISMATCH")
    ] * 2
    assert sorted(f["simulation_id"] for f in eb["findings"]) == sorted(
        s["simulation_id"] for s in b["surveys"][1:]
    )  # the finding keeps its source evidence
    tb = trace_of(author, coordinated_simulation_id=b["id"])
    assert dims(tb) == {
        "completion": "ALL_SURVEYS_COMPLETED",
        "satisfaction": "EVALUATED",
        "coverage": "COMPLETE_WITHIN_POLICY_SCOPE",
        "assurance": "VERIFIED",
        "eligibility": "NOT_ESTABLISHED",
    }
    assert (
        tb["dimensions"]["satisfaction"]["by_outcome"]["NOT_SATISFIED"] == 1
        and tb["dimensions"]["completion"]["complete"] is True
    )
    fb = link(tb, "FINDINGS")
    assert fb["status"] == "RECORDED" and [
        (x["sha256"], x["facts"]["simulation_id"], x["facts"]["observation_seq"]) for x in fb["records"]
    ] == [(f["finding_key"], f["simulation_id"], f["observation_seq"]) for f in eb["findings"]]
    assert ab["control_evidence"] and [c["outcome"] for c in ab["control_evidence"]] == [
        c["outcome"] for c in eb["controls"]
    ]  # not recalculated
    assert (
        tb["operational_call_eligibility"]["status"] == "NOT_ESTABLISHED"
    )  # a technically successful simulation establishes nothing

    # ---- a correctly excluded question still leaves an evidence gap (and the execution is still faithful)
    x = full(20, 20, facts=FACTS | {"policy.is_replacement": False})
    ex = under(author, policy["id"], coordinated=x["id"])
    ax = assure(author, coordinated=x["id"], evaluation=ex["id"])
    assert x["status"] == "ALL_SURVEYS_COMPLETED" and outcomes(ex)["SYN-CTRL-02/REPLACEMENT"] == (
        "INSUFFICIENT_EVIDENCE",
        "EVIDENCE_MISSING",
    )
    assert (ex["coverage"]["status"], ax["status"]) == ("INCOMPLETE", "VERIFIED")
    gap = next(c for c in ax["control_evidence"] if c["control_code"] == "SYN-CTRL-02")
    assert (gap["execution_evidence"], gap["evidence"][0]["not_delivered_class"]) == (
        "EXECUTION_VERIFIED",
        "VALID_CONDITIONAL_EXCLUSION",
    )
    assert not [e_ for s in ax["surveys"] for e_ in s["exclusions"] if e_["class"] == "OMISSION"]

    # =====================================================================================================
    # Scenario C — an incomplete journey: pending, and stopped because policy is unresolved
    # =====================================================================================================
    c = full(20, 20, until=3)  # survey 1 done, survey 2 waiting for its second answer
    assert c["status"] == "RUNNING" and [s["state"] for s in c["surveys"]] == ["COMPLETED", "CURRENT", "NOT_STARTED"]
    assert c["surveys"][2]["simulation_id"] is None  # the downstream survey was not silently executed
    ec = under(author, policy["id"], coordinated=c["id"])
    ac = assure(author, coordinated=c["id"], evaluation=ec["id"])
    assert (ec["processing_status"], ec["coverage"]["status"], outcomes(ec)["SYN-CTRL-01/TERM"]) == (
        "INCOMPLETE",
        "INCOMPLETE",
        ("INSUFFICIENT_EVIDENCE", "EVIDENCE_MISSING"),
    )
    assert (ac["status"], [s["status"] for s in ac["surveys"]]) == (
        "INCOMPLETE",
        ["VERIFIED", "INCOMPLETE", "INCOMPLETE"],
    )
    tc = trace_of(author, coordinated_simulation_id=c["id"])
    assert dims(tc) == {
        "completion": "RUNNING",
        "satisfaction": "EVALUATED",
        "coverage": "INCOMPLETE",
        "assurance": "INCOMPLETE",
        "eligibility": "NOT_ESTABLISHED",
    }
    assert (
        tc["dimensions"]["completion"]["surveys_completed"],
        tc["dimensions"]["completion"]["surveys_started"],
        tc["dimensions"]["completion"]["complete"],
    ) == (1, 2, False)
    assert [(r_["id"], r_["facts"]["state"]) for r_ in link(tc, "SIMULATIONS")["records"]][2] == (None, "NOT_STARTED")
    # stopped because policy is unresolved: a declined acknowledgement has no decided consequence, so nothing proceeds
    senior = FACTS | {"customer.age_years": 65}
    u = journey({1: K8_ANSWERS | {"mi-senior/n1": {"acknowledged": False}}}, facts=senior)
    assert u["status"] != "ALL_SURVEYS_COMPLETED" and u["status"] != "RUNNING" and u["stop"] is not None
    assert [s["state"] for s in u["surveys"]][1:] == ["NOT_STARTED", "NOT_STARTED"] and u["surveys"][0]["simulation"][
        "status"
    ] == "POLICY_UNRESOLVED"
    eu = under(author, policy["id"], coordinated=u["id"])
    au = assure(author, coordinated=u["id"], evaluation=eu["id"])
    assert (eu["coverage"]["status"], au["status"]) == ("INCOMPLETE", "INCOMPLETE")
    assert (
        instance(eu, "SYN-CTRL-03", "SENIOR")["applicability"]["status"] == "APPLICABLE"
        and outcomes(eu)["SYN-CTRL-03/SENIOR"][0] != "SATISFIED"
    )
    tu = trace_of(author, coordinated_simulation_id=u["id"])
    assert (
        tu["dimensions"]["completion"]["stopped_because"] == u["stop"]
        and tu["dimensions"]["completion"]["surveys_started"] == 1
    )

    # =====================================================================================================
    # Scenario D — two distinct published surveys, one published question revision, conflicting accepted answers
    # =====================================================================================================
    d = full(20, 30)
    ed = under(author, policy["id"], coordinated=d["id"])
    ad = assure(author, coordinated=d["id"], evaluation=ed["id"])
    term = instance(ed, "SYN-CTRL-01", "TERM")
    assert (ed["processing_status"], term["outcome"], term["coverage"]) == (
        "REQUIRES_REVIEW",
        "REQUIRES_REVIEW",
        "EVIDENCE_CONFLICTING",
    )
    assert [(o["survey"]["survey_code"], o["placement"], o["result"]) for o in term["observations"]] == [
        (code2, "mi-numbers/n1", "MATCH"),
        (code3, "mi-shared/n1", "MISMATCH"),
    ]  # both kept; neither chosen
    assert (
        ad["status"] == "VERIFIED"
        and next(c_ for c_ in ad["control_evidence"] if c_["obligation"] == "TERM")["execution_evidence"]
        == "EXECUTION_VERIFIED"
    )
    td = trace_of(author, coordinated_simulation_id=d["id"])
    conflict = next(r_ for r_ in link(td, "CONTROL_RESULTS")["records"] if r_["facts"]["obligation"] == "TERM")
    assert (
        conflict["facts"]["outcome"],
        [e_["result"] for e_ in conflict["facts"]["evidence"]],
        len({e_["simulation_id"] for e_ in conflict["facts"]["evidence"]}),
    ) == ("REQUIRES_REVIEW", ["MATCH", "MISMATCH"], 2)
    assert dims(td)["coverage"] == "INCOMPLETE" and dims(td)["assurance"] == "VERIFIED"

    # =====================================================================================================
    # Scenario E — missing or unknown applicability: UNKNOWN is never NOT_APPLICABLE, nothing is silently dropped
    # =====================================================================================================
    # (i) the application lacks an assignment-rule input: the requirement is UNRESOLVED, not dropped; no journey starts
    lacking = {k: v for k, v in application.items() if k != "premium_frequency"}
    e1 = compose(lacking, FACTS)
    add_b = next(r_ for r_ in e1["composite"]["requirements"] if r_["group"]["code"] == "ADD-B")
    assert (e1["selection_status"], add_b["state"], add_b["outcome"], add_b["missing_inputs"]) == (
        "UNRESOLVED_REQUIREMENT",
        "UNRESOLVED",
        "INPUT_MISSING",
        ["premium_frequency"],
    )
    r = post(author, f"{A}/composite-plans/{e1['id']}/coordinated-simulations", {"label": "must not start"})
    assert (r.status_code, r.json()["code"]) == (409, "SELECTION_UNRESOLVED")
    te = trace_of(author, composite_plan_id=e1["id"])
    assert te["journey"]["kind"] == "APPLICATION_ONLY" and dims(te) == {
        "completion": "NOT_STARTED",
        "satisfaction": "NOT_EVALUATED",
        "coverage": "NOT_EVALUATED",
        "assurance": "NOT_CHECKED",
        "eligibility": "NOT_ESTABLISHED",
    }
    g = next(r_ for r_ in link(te, "REQUIREMENT_GROUPS")["records"] if r_["label"].startswith("ADD-B"))
    assert (g["facts"]["state"], g["facts"]["outcome"], g["facts"]["missing_inputs"]) == (
        "UNRESOLVED",
        "INPUT_MISSING",
        ["premium_frequency"],
    )
    assert (
        link(te, "SIMULATIONS")["status"] == "NOT_RECORDED_YET"
        and link(te, "EVALUATION")["status"] == "NOT_RECORDED_YET"
    )
    # (ii) a fact a survey needs is missing: the plan is BLOCKED, never run without it
    e2 = compose(application, {k: v for k, v in FACTS.items() if k != "customer.age_years"})
    assert (e2["plan_status"], e2["composite"]["missing_facts"]) == ("BLOCKED", ["customer.age_years"])
    assert (
        post(author, f"{A}/composite-plans/{e2['id']}/coordinated-simulations", {"label": "must not start"}).json()[
            "code"
        ]
        == "PLAN_BLOCKED"
    )
    # (iii) the POLICY lacks an input: applicability is UNKNOWN — required stays undecided, coverage is not complete
    lone = post(author, f"/api/v1/survey-versions/{v2}/simulations", {"facts": {}, "label": "E2E-1 no age"}).json()
    for key, answer in numbers("mi-numbers", 20).items():
        lone = post(
            author,
            f"/api/v1/survey-simulations/{lone['id']}/inputs",
            {"expected_inputs": len(lone["inputs"]), "key": key, "answer": answer},
        ).json()
    e3 = under(author, policy["id"], simulation_id=lone["id"])
    sen = instance(e3, "SYN-CTRL-03", "SENIOR")
    assert (sen["applicability"]["status"], sen["outcome"], sen["coverage"]) == (
        "UNKNOWN",
        "UNRESOLVED",
        "APPLICABILITY_UNKNOWN",
    )
    assert e3["coverage"]["status"] == "INCOMPLETE" and e3["coverage"]["controls_with_unknown_applicability"]
    assert e3["applicability"]["counts"]["UNKNOWN"] == 1 and e3["applicability"]["counts"]["NOT_APPLICABLE"] == 0
    t3 = trace_of(author, simulation_id=lone["id"])
    assert t3["journey"]["kind"] == "SINGLE_SURVEY" and {
        link(t3, k)["status"] for k in journey_trace.ASSIGNMENT_LINKS
    } == {"NOT_PART_OF_THIS_JOURNEY"}
    assert link(t3, "CONTROL_POLICY")["records"][0]["facts"]["applicability_counts"]["UNKNOWN"] == 1

    # =====================================================================================================
    # Scenario F — historical integrity: newer revisions do not change what an earlier record means
    # =====================================================================================================
    # a newer MAPPING revision (now expecting 30) and a newer POLICY revision (TERM dropped): both published
    mapped(
        trio, "SYN-CTRL-01",
        [
            entry(it1["mi-opening/n2"], YES) | {"obligation": "IDENTITY", "requirement": "E-ID"},
            entry(it1["mi-opening/n1"]) | {"obligation": "OPENING", "requirement": "E-HELLO"},
            entry(it2["mi-numbers/n1"], {"method": "NUMERIC_COMPARE", "evaluation": {"operator": "EQ", "value": 30, "unit": "COUNT"}}) | {"obligation": "TERM", "requirement": "E-TERM"},
        ],
    )  # fmt: skip
    policy2 = published_policy(trio, body | {"controls": [body["controls"][0], body["controls"][1]]})
    assert (policy2["revision"], policy2["code"]) == (2, "POL-E2E") and policy2["id"] != policy["id"]
    # a newer SURVEY version of the follow-up survey (it now also pins survey 1's opening module)
    assert pin_module(author, s3, draft(author, s1), "mi-extra").status_code == 200
    v3b = publish(trio, s3, "second version")[1]
    assert v3b != v3
    old_e = author.get(f"{E}/evaluations/{ea_['id']}").json()
    old_a = author.get(f"{E}/assurance/{aa['id']}").json()
    # the earlier records: the same results, the same pins, and they still recompute to themselves
    assert (old_e["result_sha256"], old_e["pins"], old_e["replay"]["consistent"], outcomes(old_e)) == (
        ea_["result_sha256"],
        ea_["pins"],
        True,
        outcomes(ea_),
    )
    assert (old_e["policy"]["revision"], [m["revision"] for m in old_e["pins"]["mappings"]]) == (1, [1, 1, 1])
    assert sorted(s_["code"] for s_ in old_e["superseded_by_current_governance"]) == [
        "MAPPING_REVISED",
        "POLICY_REVISED",
    ]  # … and they say governance moved on
    assert (old_a["result_sha256"], old_a["pins"], old_a["current_status"], old_a["replay"]["consistent"]) == (
        aa["result_sha256"],
        aa["pins"],
        "VERIFIED",
        True,
    )
    tf = trace_of(author, coordinated_simulation_id=a["id"], evaluation_id=ea_["id"], assurance_id=aa["id"])

    def ids(t: dict[str, Any]) -> list[Any]:
        return [
            (x["key"], r_["kind"], r_["id"], r_["version"], r_["sha256"]) for x in t["chain"] for r_ in x["records"]
        ]

    assert tf["trace_sha256"] == ta["trace_sha256"] and ids(tf) == ids(
        ta
    )  # the same records, versions and fingerprints
    assert link(tf, "CONTROL_RESULTS") == link(ta, "CONTROL_RESULTS") and link(tf, "EXECUTION_ASSURANCE") == link(
        ta, "EXECUTION_ASSURANCE"
    )
    assert sorted(link(tf, "EVALUATION")["records"][0]["facts"]["superseded_by_current_governance"]) == [
        "MAPPING_REVISED",
        "POLICY_REVISED",
    ]
    assert [(x["id"], x["version"]) for x in link(tf, "SURVEY_VERSIONS")["records"]][2] == (
        v3,
        "1.0",
    )  # not the newer version
    # the composite says that composed again now it would differ; the record itself is unchanged
    plan = link(tf, "COMPOSITE_PLAN")
    assert (
        plan["records"][0]["sha256"] == comp["fingerprint"]
        and plan["records"][0]["facts"]["recomputes_to_its_record"] is False
        and plan["notes"]
    )
    assert tf["integrity"]["all_records_recompute"] is False and [
        i["record"] for i in tf["integrity"]["checks"] if not i["ok"]
    ] == ["COMPOSITE_PLAN"]
    # a NEW evaluation of the SAME journey under the new revisions is a new record with its own meaning
    new_e = under(author, policy2["id"], coordinated=a["id"])
    assert (
        new_e["id"] != ea_["id"]
        and "SYN-CTRL-03/SENIOR" not in outcomes(new_e)
        and outcomes(new_e)["SYN-CTRL-01/TERM"] == ("NOT_SATISFIED", "EVIDENCED")
    )
    assert [e_["id"] for e_ in trace_of(author, coordinated_simulation_id=a["id"])["evaluations"]] == [
        ea_["id"],
        new_e["id"],
    ]
    assert (
        post(
            author, f"{E}/evaluations", {"coordinated_simulation_id": a["id"], "control_policy_id": policy["id"]}
        ).json()["code"]
        == "POLICY_NOT_PUBLISHED"
    )
    # a new application now: the binding still pins version 1.0, which is no longer effective — nothing newer is substituted
    now = compose(application, FACTS)
    add_c = next(r_ for r_ in now["composite"]["requirements"] if r_["group"]["code"] == "ADD-C")
    assert (add_c["state"], add_c["outcome"], add_c["selected"]) == ("UNRESOLVED", "TARGET_NOT_EFFECTIVE", None)

    # =====================================================================================================
    # Scenario G — security and isolation across the whole workflow
    # =====================================================================================================
    reader = make_account(db, prefix="e2eread")
    GRANTS[reader.principal_id] = ALL - {"survey.evaluation.read"}
    rc = _client(survey_app, reader)
    assert rc.get(f"{E}/journey-trace", params={"coordinated_simulation_id": a["id"]}).status_code == 403
    GRANTS[reader.principal_id] = frozenset({"survey.read", "survey.evaluation.read"})
    withheld = trace_of(rc, coordinated_simulation_id=a["id"], evaluation_id=ea_["id"])
    assert {link(withheld, k)["status"] for k in journey_trace.ASSIGNMENT_LINKS} == {"WITHHELD"} and not [
        r_ for k in journey_trace.ASSIGNMENT_LINKS for r_ in link(withheld, k)["records"]
    ]
    assert link(withheld, "EVALUATION")["status"] == "RECORDED"
    assert rc.get(f"{E}/journey-trace", params={"composite_plan_id": comp["id"]}).status_code == 403
    for path, payload in (
        (f"{A}/composite-plans", {"assignment_inputs": application, "facts": FACTS}),
        (f"{A}/composite-plans/{comp['id']}/coordinated-simulations", {"label": "x"}),
        (f"{E}/evaluations", {"coordinated_simulation_id": a["id"], "control_policy_id": policy2["id"]}),
        (f"{E}/assurance", {"coordinated_simulation_id": a["id"]}),
        (f"{E}/control-policies", body),
    ):
        assert post(rc, path, payload).status_code == 403, path  # a reader changes nothing anywhere
    rc.__exit__(None, None, None)
    GRANTS.pop(reader.principal_id)
    outsider = make_account(db, prefix="e2emy")
    GRANTS[outsider.principal_id] = ALL
    MARKETS[outsider.principal_id] = frozenset({"MY"})
    oc = _client(survey_app, outsider)
    assert [
        oc.get(f"{E}/journey-trace", params=p).status_code
        for p in (
            {"coordinated_simulation_id": a["id"]},
            {"composite_plan_id": comp["id"]},
            {"simulation_id": lone["id"]},
        )
    ] == [404, 404, 404]
    assert (
        oc.get(f"{E}/evaluations/{ea_['id']}").status_code == 404
        and oc.get(f"{E}/assurance/{aa['id']}").status_code == 404
    )
    assert (
        post(
            oc, f"{E}/evaluations", {"coordinated_simulation_id": a["id"], "control_policy_id": policy2["id"]}
        ).status_code
        == 404
    )
    oc.__exit__(None, None, None)
    GRANTS.pop(outsider.principal_id)
    MARKETS.pop(outsider.principal_id)
    for path, payload in (
        (f"{A}/composite-plans", {"assignment_inputs": application, "facts": FACTS}),
        (f"{E}/evaluations", {"coordinated_simulation_id": a["id"], "control_policy_id": policy2["id"]}),
        (f"{E}/assurance", {"coordinated_simulation_id": a["id"]}),
    ):
        assert author.post(path, json=payload).status_code == 403, path  # no CSRF token
    r = author.get(f"{E}/journey-trace", params={"coordinated_simulation_id": a["id"], "simulation_id": lone["id"]})
    assert (r.status_code, r.json()["code"]) == (422, "JOURNEY_REQUIRED")
    r = author.get(f"{E}/journey-trace", params={"coordinated_simulation_id": b["id"], "evaluation_id": ea_["id"]})
    assert (r.status_code, r.json()["code"]) == (409, "EVALUATION_OF_ANOTHER_JOURNEY")
    assert author.get(f"{E}/journey-trace", params={"coordinated_simulation_id": str(uuid.uuid4())}).status_code == 404
    assert verify_chain(db).ok

    # ---- no scenario touched an operational callback case, finding or disposition, or Script Studio's records
    assert counts(db, UNTOUCHED) == untouched_before
    classes = "SELECT DISTINCT record_class FROM {}"
    for table in (
        "survey_composite_plan",
        "survey_coordinated_simulation",
        "survey_simulation",
        "survey_journey_evaluation",
        "survey_execution_assurance",
    ):
        assert set(db.execute(text(classes.format(table))).scalars()) == {"SIMULATION"}, table  # noqa: S608 — fixed names

    # ---- F, explicit drift (INJECTED: the engine's output is altered inside this test; the executor did not do this)
    real = simulation_module.execute_inputs

    def changed(bundle: Any, facts: Any, inputs: Any) -> Any:
        out = real(bundle, facts, inputs)
        out["trace"] = [*out["trace"], "changed engine"]
        return out

    monkeypatch.setattr(simulation_module, "execute_inputs", changed)
    drift = trace_of(author, coordinated_simulation_id=b["id"])
    assert drift["integrity"]["all_records_recompute"] is False
    assert {i["record"] for i in drift["integrity"]["checks"] if not i["ok"]} >= {
        "SIMULATION 1",
        "JOURNEY_EVALUATION",
        "EXECUTION_ASSURANCE",
    }
    assert (
        dims(drift)["assurance"] == "ASSURANCE_DRIFT"
        and drift["dimensions"]["assurance"]["recorded_status"] == "VERIFIED"
    )
    assert (
        link(drift, "EVALUATION")["records"][0]["sha256"],
        link(drift, "EVALUATION")["records"][0]["facts"]["recomputes_to_its_record"],
    ) == (eb["result_sha256"], False)  # the record is not rewritten; the drift is said
    assert dims(drift)["eligibility"] == "NOT_ESTABLISHED"


def test_the_journey_trace_exists_only_with_execution_assurance_and_adds_no_table(
    settings: Settings, engine: Engine, db: Session
) -> None:
    off = create_app(settings.model_copy(update=ON | {"survey_execution_assurance_enabled": False}))
    assert "/api/v1/survey-evaluation/journey-trace" not in off.openapi()["paths"]
    on = create_app(settings.model_copy(update=ON))
    op = on.openapi()["paths"]["/api/v1/survey-evaluation/journey-trace"]
    assert list(op) == ["get"]  # read-only: one GET, nothing that writes
    assert (
        db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0037_shared_rule_services"
    )  # E2E-1 added no migration; the head is the one SHARED-1 added later
