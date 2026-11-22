# ruff: noqa: E501 — records and SQL parameter maps are kept one per line
"""EVAL-1 — journey-level control evaluations of SYNTHETIC simulations: loading the evidence, pinning, recording.

The journey is ONE single-survey simulation (a journey with one survey execution) or ONE coordinated simulation
(several). The evidence is read through the SS-03B and ASG-2B services, replayed now, so an evaluation never rests on
a simulation that no longer recomputes to its record. The result is computed by ``control_evaluation`` (pure).

Records are isolated ``SIMULATION`` records, insert-only. The same journey evaluated from the same inputs IS the same
evaluation; a changed mapping, control, finding rule set or piece of evidence gives a NEW evaluation with its own
pins. An old evaluation is never rewritten: on reading it is computed again from what it pinned, and a difference is
reported as drift. No operational table is read for a decision or written at all.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import finding_rules
from app.domain.survey import control_evaluation as ce
from app.domain.survey import control_mapping as cm
from app.domain.survey import control_policy as cp
from app.domain.survey import coordination, simulation
from app.domain.survey import policy_evaluation as pe
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

RECORD_CLASS = simulation.RECORD_CLASS
ENTITY = "survey_journey_evaluation"


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _execution(
    db: Session,
    markets: Sequence[str],
    position: int,
    version_id: uuid.UUID,
    sim: Mapping[str, Any] | None,
    state: str,
    names: Mapping[str, Any],
) -> dict[str, Any]:
    v = simulation._version(db, version_id, markets)  # published, in scope, manifest intact
    return {
        "position": position, "survey_code": names["survey_code"], "survey_name": names["survey_name"],
        "version_label": names["version_label"], "survey_version_id": v["id"], "content_sha256": v["content_sha256"],
        "manifest_sha256": v["manifest_sha256"], "state": state, "bundle": simulation.version_bundle(db, v),
        "simulation_id": sim["id"] if sim else None, "run": _plain(sim["run"]) if sim else None,
        "run_sha256": sim["run_sha256"] if sim else None, "engine_contract": sim["engine_contract"] if sim else None,
    }  # fmt: skip


def _single_state(sim: Mapping[str, Any]) -> str:
    if sim["status"] == "REPLAY_DRIFT":
        return "DRIFTED"
    if sim["run_status"] == "TERMINAL":
        return "COMPLETED" if (sim["run"]["terminal"] or {}).get("state") == "COMPLETED" else "STOPPED"
    return "CURRENT"


def journey_of(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None
) -> dict[str, Any]:
    """The journey and its evidence, as they stand now. ``trusted`` is false when any survey's simulation no longer
    recomputes to its record, or the composite a coordinated simulation was started from is no longer intact."""
    if (simulation_id is None) == (coordinated_id is None):
        raise SurveyError(422, "JOURNEY_REQUIRED", "Name exactly one journey: a simulation or a coordinated simulation")
    problems: list[dict[str, Any]] = []
    if simulation_id is not None:
        sim = simulation.state(db, simulation_id, markets)
        market = simulation._row(db, simulation_id, markets)["market_code"]
        state = _single_state(sim)
        if not sim["replay_consistent"]:
            problems.append(
                {
                    "code": "REPLAY_DRIFT",
                    "survey": sim["survey_code"],
                    "text": "The simulation no longer recomputes to its recorded result",
                }
            )
        ending = (sim["run"]["terminal"] or {}).get("state")
        return {
            "kind": "SINGLE_SURVEY", "id": sim["id"], "market_code": market, "label": sim["label"],
            "status": ending or sim["status"], "complete": state == "COMPLETED", "trusted": not problems, "problems": problems,
            "facts": sim["facts"], "application_sha256": sim["facts_sha256"], "replay_sha256": sim["run_sha256"],
            "executions": [_execution(db, markets, 1, sim["version_id"], sim, state, sim)],
        }  # fmt: skip
    assert coordinated_id is not None
    co = coordination.state(db, coordinated_id, markets)
    if not co["composite_intact"]:
        problems.append(
            {
                "code": "COMPOSITE_NOT_INTACT",
                "text": "The composite plan this coordinated simulation was started from is no longer the recorded one",
            }
        )
    for s in co["surveys"]:
        if s["state"] == "DRIFTED":
            problems.append(
                {
                    "code": "REPLAY_DRIFT",
                    "survey": s["survey_code"],
                    "text": "This survey's simulation no longer recomputes to its recorded result",
                }
            )
    return {
        "kind": "COORDINATED", "id": co["id"], "market_code": co["market_code"], "label": co["label"], "status": co["status"],
        "complete": co["status"] == "ALL_SURVEYS_COMPLETED", "trusted": not problems, "problems": problems,
        "facts": (co["application"] or {}).get("facts") or {}, "application_sha256": co["application_sha256"],
        "replay_sha256": co["replay_sha256"],
        "executions": [_execution(db, markets, s["position"], s["survey_version_id"], s["simulation"], s["state"], s) for s in co["surveys"]],
    }  # fmt: skip


def _rule_set(rules: Mapping[str, Any] | None) -> fe.RuleSet | None:
    """The finding rule set AS IT WAS USED: a published one. Its rules are immutable; its status is not (a later
    version supersedes it), so the status is not read back — a superseded set must recompute to the same findings."""
    if rules is None:
        return None
    return fe.RuleSet.of(str(rules["id"]), finding_rules.label(rules), "PUBLISHED", rules["rules"] or [])


def _controls(db: Session) -> list[dict[str, Any]]:
    return cm.controls(db)


SUMMARY_KEYS = (
    "journey", "summary", "coverage", "finding_rules", "findings_status", "engines", "not_converted", "human_assessment",
    "policy", "applicability", "operational_compliance_eligibility",
)  # fmt: skip


def _pins(
    journey: Mapping[str, Any], controls: Sequence[Mapping[str, Any]], mappings: Mapping[str, Mapping[str, Any]],
    rules: Mapping[str, Any] | None, policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:  # fmt: skip
    # the policy is pinned only when one was named: an evaluation without a policy keeps exactly the pins it always had
    extra = (
        {
            "policy": {
                "id": str(policy["id"]),
                "code": policy["code"],
                "revision": policy["revision"],
                "sha256": policy["policy_sha256"],
            }
        }
        if policy
        else {}
    )
    return extra | {
        "contract": pe.CONTRACT if policy else ce.CONTRACT,
        "journey": {"kind": journey["kind"], "id": str(journey["id"]), "replay_sha256": journey["replay_sha256"], "application_sha256": journey["application_sha256"], "trusted": journey["trusted"]},
        "executions": [
            {"position": x["position"], "survey_version_id": str(x["survey_version_id"]), "manifest_sha256": x["manifest_sha256"], "simulation_id": str(x["simulation_id"]) if x["simulation_id"] else None, "run_sha256": x["run_sha256"], "engine_contract": x["engine_contract"]}
            for x in journey["executions"]
        ],
        "controls": [{"control_code": c["control_code"], "id": str(c["id"]), "sha256": ce.control_sha256(c)} for c in sorted(controls, key=lambda c: c["control_code"])],
        "mappings": [{"control_code": k, "id": str(m["id"]), "revision": m["revision"], "sha256": m["mapping_sha256"]} for k, m in sorted(mappings.items())],
        "finding_rule_set": {"version_id": str(rules["id"]), "label": finding_rules.label(rules), "sha256": rules["rules_sha256"]} if rules else None,
        "engines": {"answer_evaluation": ae.ENGINE, "findings": fe.ENGINE},
    }  # fmt: skip


def _result(
    journey: Mapping[str, Any], controls: Sequence[Mapping[str, Any]], mappings: Mapping[str, Mapping[str, Any]],
    rules: Mapping[str, Any] | None, policy: Mapping[str, Any] | None,
) -> dict[str, Any]:  # fmt: skip
    """Without a policy: exactly the EVAL-1 evaluation. With one: the policy's obligations are the control instances."""
    if policy is None:
        return ce.evaluate_journey(journey, controls, mappings, _rule_set(rules))
    return pe.evaluate_under_policy(journey, controls, mappings, _rule_set(rules), policy)


def create(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None, actor: Actor,
    meta: RequestMeta | None = None, *, policy_id: uuid.UUID | None = None, policy_schema: bool = False,
) -> tuple[uuid.UUID, bool]:  # fmt: skip
    """Evaluate the journey as it stands, against what is published now — optionally under a named, published control
    policy revision (EVAL-2A). Returns (evaluation id, created): identical inputs give the evaluation that exists.

    ``policy_schema`` says whether control policies are switched on (migration 0034); without it no policy can be
    named. An evaluation without a policy is written to the EVAL-1 tables exactly as EVAL-1 wrote it."""
    journey = journey_of(db, markets, simulation_id, coordinated_id)
    market = journey["market_code"]
    controls = _controls(db)
    mappings = cm.published(db, market)
    rules = finding_rules.published(db, market)
    policy = None
    if policy_id is not None:
        if not policy_schema:
            raise SurveyError(404, "NOT_FOUND", "Control policies are not available on this server")
        policy = cp.policy(db, policy_id, [market])
        if policy["status"] != "PUBLISHED":
            raise SurveyError(
                409, "POLICY_NOT_PUBLISHED", "A journey is evaluated under a published control policy revision"
            )
    pins = _pins(journey, controls, mappings, rules, policy)
    input_sha = sha256_hex(pins)
    column = "simulation_id" if simulation_id else "coordinated_id"
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"survey_journey_evaluation:{journey['id']}"})
    prior = _one(
        db,
        f"SELECT id FROM survey_journey_evaluation WHERE {column} = :j AND input_sha256 = :i",
        j=journey["id"],
        i=input_sha,
    )
    if prior:
        return prior["id"], False
    result = _result(journey, controls, mappings, rules, policy)
    eid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_journey_evaluation (id, market_code, journey_kind, simulation_id, coordinated_id, contract, pins, "
            "input_sha256, processing_status, summary, result_sha256, created_by) VALUES (:i, :m, :k, :s, :c, :con, "
            "CAST(:p AS jsonb), :inp, :st, CAST(:sum AS jsonb), :res, :by)"
        ),
        {
            "i": eid, "m": market, "k": journey["kind"], "s": simulation_id, "c": coordinated_id, "con": result["contract"],
            "p": json.dumps(pins), "inp": input_sha, "st": result["processing_status"],
            "sum": json.dumps({k: result[k] for k in SUMMARY_KEYS if k in result}), "res": result["result_sha256"], "by": _ref(actor),
        },
    )  # fmt: skip
    # Without a policy: the EVAL-1 tables, exactly as EVAL-1 wrote them. Under a policy: the obligation tables of
    # migration 0034 — the EVAL-1 tables are never given a row they could not have had before.
    if policy is None:
        result_sql = (
            "INSERT INTO survey_control_result (evaluation_id, control_id, control_code, mapping_id, outcome, applicability, detail) "
            "VALUES (:e, :c, :cc, :m, :o, :a, CAST(:d AS jsonb))"
        )
        observation_sql = (
            "INSERT INTO survey_evidence_observation (evaluation_id, seq, control_code, simulation_id, survey_version_id, placement, "
            "item_code, item_version, evidence_type, result, detail) VALUES (:e, :n, :cc, :s, :v, :p, :ic, :iv, :t, :r, CAST(:d AS jsonb))"
        )
        finding_sql = (
            "INSERT INTO survey_evaluation_finding (evaluation_id, finding_key, control_code, observation_seq, rule_set_version_id, "
            "rule_code, category, severity, finding) VALUES (:e, :k, :cc, :n, :rs, :rc, :cat, :sev, CAST(:f AS jsonb))"
        )
    else:
        db.execute(
            text(
                "INSERT INTO survey_evaluation_policy (evaluation_id, control_policy_id, policy_sha256) VALUES (:e, :p, :s)"
            ),
            {"e": eid, "p": policy["id"], "s": policy["policy_sha256"]},
        )
        result_sql = (
            "INSERT INTO survey_obligation_result (evaluation_id, control_id, control_code, obligation, mapping_id, outcome, applicability, "
            "coverage, detail) VALUES (:e, :c, :cc, :ob, :m, :o, :a, :cov, CAST(:d AS jsonb))"
        )
        observation_sql = (
            "INSERT INTO survey_obligation_observation (evaluation_id, seq, control_code, obligation, requirement, simulation_id, "
            "survey_version_id, placement, item_code, item_version, evidence_type, result, detail) "
            "VALUES (:e, :n, :cc, :ob, :rq, :s, :v, :p, :ic, :iv, :t, :r, CAST(:d AS jsonb))"
        )
        finding_sql = (
            "INSERT INTO survey_obligation_finding (evaluation_id, finding_key, control_code, obligation, observation_seq, "
            "rule_set_version_id, rule_code, category, severity, finding) VALUES (:e, :k, :cc, :ob, :n, :rs, :rc, :cat, :sev, CAST(:f AS jsonb))"
        )

    def only(sql: str, **p: Any) -> dict[str, Any]:
        return {k: v for k, v in p.items() if re.search(rf":{k}\b", sql)}

    for c in result["controls"]:
        db.execute(
            text(result_sql),
            only(
                result_sql, e=eid, c=c["control_id"], cc=c["control_code"], ob=c.get("obligation"), m=(c["mapping"] or {}).get("id"),
                o=c["outcome"], a=c["applicability"]["status"], cov=c.get("coverage"), d=json.dumps({k: v for k, v in c.items() if k != "observations"}),
            ),
        )  # fmt: skip
        for o in c["observations"]:
            db.execute(
                text(observation_sql),
                only(
                    observation_sql, e=eid, n=o["seq"], cc=c["control_code"], ob=c.get("obligation"), rq=o.get("requirement"), s=o["simulation_id"],
                    v=(o["survey"] or {}).get("survey_version_id"), p=o["placement"], ic=o["item"]["code"], iv=o["item"]["version"],
                    t=o["evidence_type"], r=o["result"], d=json.dumps(o),
                ),
            )  # fmt: skip
    for f in result["findings"]:
        db.execute(
            text(finding_sql),
            only(
                finding_sql, e=eid, k=f["finding_key"], cc=f["control_code"], ob=f.get("obligation"), n=f["observation_seq"],
                rs=f["rule"]["rule_set"]["version_id"], rc=f["rule"]["rule_code"], cat=f["category"], sev=f["severity"], f=json.dumps(f),
            ),
        )  # fmt: skip
    after = {
        "journey": f"{journey['kind']} {journey['id']}",
        "processing_status": result["processing_status"],
        "input_sha256": input_sha,
        "result_sha256": result["result_sha256"],
        "findings": len(result["findings"]),
    }
    if policy:
        after |= {"policy": f"{policy['code']} r{policy['revision']}", "coverage": result["coverage"]["status"]}
    _audit(db, actor, meta, "SURVEY.JOURNEY_EVALUATED", ENTITY, eid, after)
    return eid, True


def preview(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None, *,
    policy_id: uuid.UUID | None = None, policy_draft: Mapping[str, Any] | None = None, mapping_drafts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:  # fmt: skip
    """What an evaluation of this journey WOULD say with a policy and mappings that are not (yet) published. Nothing
    is recorded, and the result says so."""
    journey = journey_of(db, markets, simulation_id, coordinated_id)
    market = journey["market_code"]
    mappings = dict(cm.published(db, market))
    drafted = []
    for body in mapping_drafts:
        m = cm.as_mapping(db, market, body)
        mappings[m["control_code"]] = m
        drafted.append(m["control_code"])
    policy = None
    if policy_draft is not None:
        policy = cp.as_policy(cp.document(db, market, policy_draft))
    elif policy_id is not None:
        policy = cp.policy(db, policy_id, [market])
    result: dict[str, Any] = _plain(
        _result(journey, _controls(db), mappings, finding_rules.published(db, market), policy)
    )
    note = "A trial against a simulated journey. Nothing was recorded and nothing was proposed."
    return result | {
        "recorded": False, "record_class": RECORD_CLASS, "market_code": market,
        "preview": {"policy": "DRAFT" if policy_draft is not None else "EXISTING_REVISION" if policy_id else "NONE", "drafted_mappings": drafted, "note": note},
        "operational_compliance_eligibility": pe.ELIGIBILITY,
    }  # fmt: skip


def journeys(db: Session, markets: Sequence[str], limit: int = 30) -> list[dict[str, Any]]:
    """Recent simulated journeys of the caller's markets, to try a policy or a mapping out against."""
    single = _all(
        db,
        "SELECT s.id, 'SINGLE_SURVEY' AS kind, s.label, s.created_at, d.name AS title, 1 AS surveys FROM survey_simulation s "
        "JOIN survey_definition d ON d.id = s.survey_definition_id WHERE d.market_code = ANY(:m) ORDER BY s.created_at DESC LIMIT :n",
        m=list(markets), n=limit,
    )  # fmt: skip
    coordinated: list[dict[str, Any]] = []
    if _one(db, "SELECT to_regclass('survey_coordinated_simulation') AS t")["t"]:  # type: ignore[index]
        coordinated = _all(
            db,
            "SELECT c.id, 'COORDINATED' AS kind, c.label, c.created_at, 'Coordinated journey' AS title, jsonb_array_length(c.governed_order) AS surveys "
            "FROM survey_coordinated_simulation c WHERE c.market_code = ANY(:m) ORDER BY c.created_at DESC LIMIT :n",
            m=list(markets), n=limit,
        )  # fmt: skip
    return sorted(single + coordinated, key=lambda r: r["created_at"], reverse=True)[:limit]


def _row(db: Session, eid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db, "SELECT * FROM survey_journey_evaluation WHERE id = :i AND market_code = ANY(:m)", i=eid, m=list(markets)
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Evaluation not found or not available to you")
    return row


def _recompute(db: Session, row: Mapping[str, Any], markets: Sequence[str]) -> dict[str, Any]:
    """The evaluation computed again NOW from exactly what it pinned. None of it is stored."""
    pins = row["pins"]
    try:
        journey = journey_of(db, markets, row["simulation_id"], row["coordinated_id"])
    except SurveyError as exc:
        return {
            "consistent": False,
            "code": "EVALUATION_DRIFT",
            "reasons": [{"code": exc.code, "text": exc.message}],
            "recorded_result_sha256": row["result_sha256"],
            "recomputed_result_sha256": None,
        }
    mappings = cm.by_ids(db, [m["id"] for m in pins["mappings"]])
    rules = None
    if pins["finding_rule_set"]:
        rules = _one(
            db,
            "SELECT * FROM finding_rule_set_version WHERE CAST(id AS text) = :i",
            i=pins["finding_rule_set"]["version_id"],
        )
    pinned_codes = {c["control_code"] for c in pins["controls"]}
    controls = [c for c in _controls(db) if c["control_code"] in pinned_codes]
    policy = cp.by_id(db, pins["policy"]["id"]) if pins.get("policy") else None
    now = _pins(journey, controls, mappings, rules, policy)
    reasons = [
        {"code": code, "text": text_}
        for code, text_, same in (
            ("EVIDENCE_CHANGED", "The journey's evidence is not what was evaluated (inputs were added, or a simulation recomputes differently)", now["journey"] == pins["journey"] and now["executions"] == pins["executions"]),
            ("CONTROL_CHANGED", "A control of the register was changed after this evaluation", now["controls"] == pins["controls"]),
            ("MAPPING_CHANGED", "A pinned mapping revision is not what was evaluated", now["mappings"] == pins["mappings"]),
            ("FINDING_RULES_CHANGED", "The pinned finding rule set is not what was evaluated", now["finding_rule_set"] == pins["finding_rule_set"]),
            ("POLICY_CHANGED", "The pinned control policy revision is not what was evaluated", now.get("policy") == pins.get("policy")),
            ("ENGINE_CHANGED", "An evaluation engine has a different version now", now["engines"] == pins["engines"] and now["contract"] == pins["contract"]),
        )
        if not same
    ]  # fmt: skip
    result = _result(journey, controls, mappings, rules, policy)
    same_result = result["result_sha256"] == row["result_sha256"]
    if not same_result and not reasons:
        reasons.append({"code": "RESULT_DIFFERS", "text": "The same pinned inputs give a different result now"})
    return {
        "consistent": same_result and not reasons, "code": None if same_result and not reasons else "EVALUATION_DRIFT", "reasons": reasons,
        "recorded_result_sha256": row["result_sha256"], "recomputed_result_sha256": result["result_sha256"],
    }  # fmt: skip


def _superseded(db: Session, row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """What is published NOW that this evaluation did not use. A newer evaluation would be a different record."""
    pins = row["pins"]
    out = []
    now = {k: str(m["id"]) for k, m in cm.published(db, row["market_code"]).items()}
    then = {m["control_code"]: m["id"] for m in pins["mappings"]}
    for code in sorted(set(now) | set(then)):
        if now.get(code) != then.get(code):
            out.append(
                {
                    "code": "MAPPING_REVISED",
                    "control_code": code,
                    "text": f"The published mapping of {code} is not the one this evaluation used",
                }
            )
    if pins.get("policy"):
        pinned = cp.by_id(db, pins["policy"]["id"])
        if pinned is None or pinned["status"] != "PUBLISHED":
            out.append(
                {
                    "code": "POLICY_REVISED",
                    "text": f"Control policy {pins['policy']['code']} revision {pins['policy']['revision']} is no longer the published revision",
                }
            )
    rules = finding_rules.published(db, row["market_code"])
    if (str(rules["id"]) if rules else None) != (pins["finding_rule_set"] or {}).get("version_id"):
        out.append(
            {
                "code": "FINDING_RULES_REVISED",
                "text": "The published finding rule set is not the one this evaluation used",
            }
        )
    return out


def get(db: Session, eid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _row(db, eid, markets)
    # an evaluation is read from the tables it was written to: the EVAL-1 tables, or — made under a policy — the
    # obligation tables. Which one is said by its own pins, never guessed.
    results, observations, found = (
        ("survey_obligation_result", "survey_obligation_observation", "survey_obligation_finding")
        if row["pins"].get("policy")
        else ("survey_control_result", "survey_evidence_observation", "survey_evaluation_finding")
    )
    instances: dict[tuple[str, str], dict[str, Any]] = {}
    for c in _all(
        db,
        f"SELECT control_code, detail FROM {results} WHERE evaluation_id = :e ORDER BY control_code, detail->>'obligation'",
        e=eid,
    ):
        instances[(c["control_code"], c["detail"].get("obligation", ""))] = c["detail"] | {"observations": []}
    for o in _all(db, f"SELECT control_code, detail FROM {observations} WHERE evaluation_id = :e ORDER BY seq", e=eid):
        instances[(o["control_code"], o["detail"].get("obligation", ""))]["observations"].append(o["detail"])
    findings = [
        f["finding"]
        for f in _all(
            db,
            f"SELECT finding FROM {found} WHERE evaluation_id = :e ORDER BY control_code, observation_seq, rule_code",
            e=eid,
        )
    ]
    s = row["summary"]
    replay = _recompute(db, row, markets)
    return {
        "id": row["id"], "record_class": RECORD_CLASS, "note": ce.NOTE, "contract": row["contract"], "market_code": row["market_code"],
        "created_at": row["created_at"], "created_by": row["created_by"],
        "journey_kind": row["journey_kind"], "simulation_id": row["simulation_id"], "coordinated_id": row["coordinated_id"],
        "journey": s["journey"], "processing_status": row["processing_status"], "summary": s["summary"], "coverage": s["coverage"],
        "finding_rules": s["finding_rules"], "findings_status": s["findings_status"], "engines": s["engines"],
        "controls": list(instances.values()), "findings": findings, "not_converted": s["not_converted"], "human_assessment": s["human_assessment"],
        "pins": row["pins"], "input_sha256": row["input_sha256"], "result_sha256": row["result_sha256"],
        "replay": replay, "status": "EVALUATION_DRIFT" if not replay["consistent"] else row["processing_status"],
        "superseded_by_current_governance": _superseded(db, row),
        "control_policy_id": (row["pins"].get("policy") or {}).get("id"), "policy": s.get("policy"), "applicability": s.get("applicability"),
        "operational_compliance_eligibility": pe.ELIGIBILITY,
    }  # fmt: skip


def for_journey(
    db: Session, markets: Sequence[str], simulation_id: uuid.UUID | None, coordinated_id: uuid.UUID | None
) -> list[dict[str, Any]]:
    if (simulation_id is None) == (coordinated_id is None):
        raise SurveyError(422, "JOURNEY_REQUIRED", "Name exactly one journey: a simulation or a coordinated simulation")
    column = "simulation_id" if simulation_id else "coordinated_id"
    return _all(
        db,
        "SELECT id, journey_kind, processing_status, input_sha256, result_sha256, created_at, created_by, summary->'summary' AS summary, "
        "summary->'policy' AS policy, summary->'coverage'->>'status' AS coverage_status "
        f"FROM survey_journey_evaluation WHERE {column} = :j AND market_code = ANY(:m) ORDER BY created_at, id",
        j=simulation_id or coordinated_id, m=list(markets),
    )  # fmt: skip
