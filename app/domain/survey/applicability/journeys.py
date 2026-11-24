# ruff: noqa: E501 — the messages people read are kept one per line
"""APPL-X5a — coordinated execution of the published surveys that a PUBLISHED Applicability Policy version selects.

One exact published policy version and one synthetic fact snapshot give — through the accepted Python evaluator, and
nothing else — an immutable SELECTION PLAN. A JOURNEY then walks the selected surveys in the plan's own order, each
one executed ONCE, at its pinned published version, by the accepted single-survey simulation service. This module
adds no selection rule and no question logic: it decides nothing a policy or a survey has not already decided.

* Selection is refused nowhere and guessed nowhere: an UNRESOLVED, OUT_OF_SCOPE or SCOPE_UNRESOLVED plan is recorded
  and inspectable, and never starts a survey. Not known is never false.
* A survey that ends other than COMPLETED does not hand over to the next one. No continuation rule is approved, so
  none exists here: the journey stops as CROSS_SURVEY_POLICY_UNRESOLVED and keeps the exact terminal reason.
* A declared shared delivery is ONE step that fulfils several requirements.
* Application facts and survey facts are two vocabularies. A fact correspondence (IDENTITY only, exact definitions,
  chosen by the person) may carry values across; everything applied is frozen in the journey's start record.
* The runtime is voice-neutral: `turn` says what is asked next, `submit` proposes one answer to exactly that turn.
  The client never decides order, eligibility, branching, replacement or completion.

SIMULATION over SYNTHETIC facts. Nothing here reads or writes an assignment rule, a survey binding, a requirement
group, a composite plan, a case, a customer, a session or a callback.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey import callplan, simulation
from app.domain.survey import store as surveys
from app.domain.survey.applicability import policies as pol
from app.domain.survey.applicability import publication as pub
from app.domain.survey.applicability import scenarios as sc
from app.domain.survey.applicability.logic import CONTRACT as EVALUATOR_CONTRACT
from app.domain.survey.applicability.logic import _check_value
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.execution import CONTRACT as ENGINE_CONTRACT
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

PLAN_CONTRACT = "call360.applicability-selection-plan/1"
START_CONTRACT = "call360.applicability-journey-start/1"
RUNTIME_CONTRACT = "call360.applicability-journey-runtime/1"
CORRESPONDENCE_SCHEMA = "call360.applicability-fact-correspondence/1"
RECORD_CLASS, SOURCE = "SYNTHETIC", "APPLICABILITY"
NOTE = "A synthetic journey: a simulation over synthetic facts. It selects nothing for a real case and starts no call."
MAX_FACTS, MAX_ENTRIES, MAX_LABEL = 400, 100, 160
OPEN = ("READY", "RUNNING")
#: source type -> target type an IDENTITY entry may connect
COMPATIBLE = {"BOOLEAN": "BOOLEAN", "ENUM": "ENUM", "INTEGER": "INTEGER", "MONEY": "MONEY", "TEXT": "TEXT"}
#: the non-answers the execution engine itself distinguishes, and the engine's own answer shape for each
NON_ANSWERS: dict[str, dict[str, Any]] = {
    "NOT_ACKNOWLEDGED": {"acknowledged": False},
    "EMPTY_TEXT": {"text": ""},
    "NONE_SELECTED": {"choices": []},
}
INTERACTION_KEYS = (
    "transcript_ref",
    "recognition_confidence",
    "proposed_answer",
    "clarification_required",
    "delivery_evidence_ref",
)
J_SQL = (
    "SELECT j.id, j.market_code, j.record_class, j.selection_source, j.selection_plan_id, j.policy_version_id, j.label, j.status, j.revision, "
    "j.correspondence_id, j.start_record, j.start_sha256, j.survey_facts, j.survey_facts_sha256, j.end_detail, j.created_by, j.created_at, "
    "j.started_by, j.started_at, j.ended_at FROM applicability_journey j "
)
P_SQL = (
    "SELECT s.id, s.market_code, s.policy_id, s.policy_version_id, s.version_no, s.version_status, s.version_sha256, s.document_sha256, "
    "s.manifest_sha256, s.facts, s.facts_sha256, s.profiles, s.origin, s.evaluator_contract, s.plan, s.plan_sha256, s.outcome, s.record_sha256, "
    "s.created_by, s.created_at, p.code AS policy_code, p.document->>'name' AS policy_name FROM applicability_selection_plan s "
    "JOIN applicability_policy p ON p.id = s.policy_id "
)
STEP_SQL = (
    "SELECT t.id, t.journey_id, t.position, t.survey_definition_id, t.survey_version_id, t.survey_code, t.version_no, t.content_sha256, "
    "t.manifest_sha256, t.required_by, t.obligations, t.status, t.simulation_id, t.outcome, t.outcome_detail, t.started_at, t.ended_at, "
    "d.name AS survey_name, v.label AS version_label FROM applicability_journey_step t JOIN survey_definition d ON d.id = t.survey_definition_id "
    "JOIN survey_version v ON v.id = t.survey_version_id "
)


def _bad(code: str, message: str, status: int = 422, details: list[dict[str, Any]] | None = None) -> SurveyError:
    return SurveyError(status, code, message, details)


def _refuse(code: str, message: str, details: list[dict[str, Any]] | None = None) -> SurveyError:
    return SurveyError(409, code, message, details)


def _json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


# ------------------------------------------------------------------------------------------- application facts
def check_application_facts(variables: Sequence[Mapping[str, Any]], facts: Any) -> dict[str, Any]:
    """A synthetic application fact snapshot, checked against the FROZEN variable definitions of the policy version.
    A value is kept exactly as given; ``None`` is "not known"; an absent fact is "not provided". Nothing is coerced,
    defaulted or guessed — and an invalid value is refused, never quietly read as not known."""
    if not isinstance(facts, Mapping) or len(facts) > MAX_FACTS:
        raise _bad("FACTS_INVALID", f"Application facts are one object of at most {MAX_FACTS} facts")
    known = {str(v.get("code")): v for v in variables}
    out: dict[str, Any] = {}
    for code in sorted(facts, key=str):
        value, var = facts[code], known.get(str(code))
        if var is None:
            raise _bad(
                "FACT_UNKNOWN",
                f"'{code}' is not a fact this published policy version reads",
                details=[{"variable": str(code)}],
            )
        if var.get("derived"):
            raise _bad(
                "FACT_DERIVED",
                f"'{var.get('name') or code}' is worked out from other facts; it is not given",
                details=[{"variable": str(code)}],
            )
        if value is not None:
            if isinstance(value, str):
                sc._synthetic_only(f"fact '{code}'", value)  # noqa: SLF001
            why = _check_value(dict(var), value)
            if why:
                raise _bad("FACT_INVALID", f"{var.get('name') or code}: {why}", details=[{"variable": str(code)}])
        out[str(code)] = value
    try:
        sha256_hex(out)
    except Exception as exc:  # noqa: BLE001 — a value that cannot be recorded exactly is refused
        raise _bad("FACTS_INVALID", "A fact value cannot be recorded exactly") from exc
    return out


# ------------------------------------------------------------------------------------------------- selection
def _outcome(plan: Mapping[str, Any]) -> str:
    status = str(plan.get("status"))
    if status == "RESOLVED":
        return "SURVEYS_SELECTED" if plan.get("selected") else "NO_SURVEY_REQUIRED"
    return {"UNRESOLVED": "UNRESOLVED", "OUT_OF_SCOPE": "OUT_OF_SCOPE", "SCOPE_UNRESOLVED": "SCOPE_UNRESOLVED"}.get(
        status, "UNRESOLVED"
    )


def _evaluate(db: Session, markets: Sequence[str], version: Mapping[str, Any], facts: Any) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:  # fmt: skip
    """The accepted evaluator, on the version's OWN frozen document and definitions. No other selection logic exists."""
    policy = pol.policy_row(db, version["policy_id"], markets)
    ev = sc.Evaluator.frozen(db, policy, version["document"], version["manifest"], source="PUBLISHED_VERSION")
    variables = list(ev.res.workspace.get("variables") or [])
    clean = check_application_facts(variables, facts)
    row = ev.plan({}, ev.res.workspace, {"facts": clean, "profiles": list(version["document"].get("profiles") or [])})
    if row.get("plan") is None:
        raise _refuse(
            "SELECTION_FAILED", f"The published version could not be evaluated: {row.get('reason') or 'unknown reason'}"
        )
    return clean, _json(row["plan"]), variables


def _version(db: Session, markets: Sequence[str], version_id: uuid.UUID) -> dict[str, Any]:
    """An exact published policy version, VERIFIED against itself before anything is selected from it."""
    v = pub.version_row(db, version_id, markets)
    proof = pub.verify_version(db, markets, version_id)
    if not proof["verified"]:
        raise _refuse(
            "VERSION_NOT_VERIFIED",
            "This published version does not verify against its own record; nothing is selected from it",
            [_json(proof)],
        )
    return v


def _current(db: Session, policy_id: Any) -> dict[str, Any] | None:
    return _one(
        db,
        "SELECT id, version_no FROM applicability_policy_version WHERE policy_id = :p AND status = 'PUBLISHED'",
        p=policy_id,
    )


def _variables_view(variables: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    keys = ("code", "name", "type", "values", "currency", "min", "max", "description", "category", "version")
    return [{k: v.get(k) for k in keys} | {"derived": bool(v.get("derived"))} for v in variables]


def _selection_view(version: Mapping[str, Any], current: Mapping[str, Any] | None, facts: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:  # fmt: skip
    return {
        "record_class": RECORD_CLASS, "selection_source": SOURCE, "note": NOTE, "evaluator_contract": EVALUATOR_CONTRACT,
        "policy_id": str(version["policy_id"]), "policy_code": version["policy_code"], "policy_name": version["document"].get("name") or version["policy_code"],
        "policy_version_id": str(version["id"]), "version_no": version["version_no"], "version_status": version["status"],
        "current_version_id": str(current["id"]) if current else None, "current_version_no": current["version_no"] if current else None,
        "version_sha256": version["version_sha256"], "document_sha256": version["document_sha256"], "manifest_sha256": version["manifest_sha256"],
        "facts": dict(facts), "facts_sha256": sha256_hex(dict(facts)), "outcome": _outcome(plan), "plan": plan, "plan_sha256": sha256_hex(plan),
    }  # fmt: skip


def options(db: Session, markets: Sequence[str], version_id: uuid.UUID) -> dict[str, Any]:
    """What a journey against this version would ask for: the version's identity and the facts it reads."""
    v = pub.version_row(db, version_id, markets)
    current = _current(db, v["policy_id"])
    variables = list((v["manifest"].get("workspace") or {}).get("variables") or [])
    return {
        "policy_id": str(v["policy_id"]), "policy_code": v["policy_code"], "policy_name": v["document"].get("name") or v["policy_code"],
        "policy_version_id": str(v["id"]), "version_no": v["version_no"], "version_status": v["status"], "published_at": v["published_at"],
        "current_version_id": str(current["id"]) if current else None, "current_version_no": current["version_no"] if current else None,
        "version_sha256": v["version_sha256"], "document_sha256": v["document_sha256"], "manifest_sha256": v["manifest_sha256"],
        "profiles": list(v["document"].get("profiles") or []), "variables": _variables_view(variables),
        "requirements": [{"id": r.get("id"), "name": r.get("name")} for r in v["document"].get("requirements") or []],
    }  # fmt: skip


def published_versions(db: Session, markets: Sequence[str]) -> dict[str, Any]:
    """Every published policy version a journey may be made against — current and superseded, never a draft."""
    rows = _all(
        db,
        "SELECT v.id, v.policy_id, v.version_no, v.status, v.published_at, v.version_sha256, v.market_code, p.code AS policy_code, "
        "v.document->>'name' AS policy_name FROM applicability_policy_version v JOIN applicability_policy p ON p.id = v.policy_id "
        "WHERE v.market_code = ANY(:m) ORDER BY p.code, v.version_no DESC",
        m=list(markets),
    )
    return {"items": [{**r, "id": str(r["id"]), "policy_id": str(r["policy_id"])} for r in rows]}


def preview(db: Session, markets: Sequence[str], version_id: uuid.UUID, facts: Any) -> dict[str, Any]:
    """What this version selects for these facts. Records nothing."""
    v = _version(db, markets, version_id)
    clean, plan, _ = _evaluate(db, markets, v, facts)
    return _selection_view(v, _current(db, v["policy_id"]), clean, plan)


def _survey_version(db: Session, markets: Sequence[str], ref: Mapping[str, Any]) -> dict[str, Any]:
    """The exact published survey version a plan pins — or a refusal. Nothing is substituted or upgraded."""
    try:
        row = surveys.version(db, uuid.UUID(str(ref.get("version_id"))), markets)
    except (ValueError, SurveyError) as exc:
        raise _refuse("SURVEY_VERSION_INVALID", f"The survey '{ref.get('code')}' pinned by this policy version does not resolve to a published version", [{"survey": ref.get("code")}]) from exc  # fmt: skip
    ok = (
        row["survey_code"] == ref.get("code") and row["version_no"] == ref.get("version") and row["content_sha256"] == ref.get("fingerprint")
        and (ref.get("manifest") is None or row["manifest_sha256"] == ref.get("manifest"))
        and surveys.status_of(db, row["id"]) in surveys.PUBLISHED_VERSION_EVENTS
    )  # fmt: skip
    if not ok:
        raise _refuse("SURVEY_VERSION_INVALID", f"The survey '{ref.get('code')}' version {ref.get('version')} is no longer what this policy version pinned", [{"survey": ref.get("code")}])  # fmt: skip
    return row


def _event(db: Session, jid: Any, event: str, actor: Actor, detail: Mapping[str, Any] | None = None, *, step: int | None = None, key: str | None = None, request_sha: str | None = None) -> None:  # fmt: skip
    db.execute(
        text("INSERT INTO applicability_journey_event (journey_id, event, step_position, actor_ref, idempotency_key, request_sha256, detail) "
             "VALUES (:j, :e, :s, :a, :k, :h, CAST(:d AS jsonb))"),
        {"j": jid, "e": event, "s": step, "a": _ref(actor), "k": key, "h": request_sha, "d": json.dumps(_json(detail or {}))},
    )  # fmt: skip


def create(db: Session, markets: Sequence[str], version_id: uuid.UUID, facts: Any, label: str, origin: Mapping[str, Any] | None, confirm_superseded: bool, actor: Actor, meta: RequestMeta | None = None) -> uuid.UUID:  # fmt: skip
    """Record the selection — immutably — and the journey over it. Execution may begin only from a RESOLVED selection
    that selected surveys; every other outcome is recorded and stays inspectable."""
    v = _version(db, markets, version_id)
    current = _current(db, v["policy_id"])
    if v["status"] != "PUBLISHED" and not confirm_superseded:
        raise _refuse(
            "SUPERSEDED_NOT_CONFIRMED",
            f"Version {v['version_no']} of this policy is superseded" + (f"; version {current['version_no']} is the published one" if current else "") + ". Confirm explicitly to run a synthetic journey against the superseded version",
            [{"version_no": v["version_no"], "status": v["status"], "current_version_no": current["version_no"] if current else None, "current_version_id": str(current["id"]) if current else None}],
        )  # fmt: skip
    label = str(label or "").strip()[:MAX_LABEL]
    sc._synthetic_only("label", label)  # noqa: SLF001
    clean, plan, _ = _evaluate(db, markets, v, facts)
    came_from: dict[str, Any] = {}
    if origin and origin.get("scenario_id"):
        s = sc.scenario_row(db, uuid.UUID(str(origin["scenario_id"])), markets)
        # copied BY VALUE: the journey never depends on the scenario afterwards
        came_from = {"kind": "SCENARIO_COPY", "scenario_id": str(s["id"]), "scenario_code": s["code"], "scenario_revision": s["draft_revision"], "scenario_document_sha256": s["document_sha256"]}  # fmt: skip
    outcome = _outcome(plan)
    steps: list[dict[str, Any]] = []
    if outcome == "SURVEYS_SELECTED":
        for entry in sorted(plan["selected"], key=lambda e: e.get("position") or 0):
            ref = entry["survey"]
            row = _survey_version(db, markets, ref)
            required = [r if isinstance(r, str) else str((r or {}).get("id")) for r in entry.get("required_by") or []]
            steps.append(
                {
                    "row": row,
                    "required_by": required,
                    "obligations": int(entry.get("obligations") or len(required) or 1),
                }
            )
    pid, jid = uuid.uuid4(), uuid.uuid4()
    profiles = list(v["document"].get("profiles") or [])
    record = {
        "contract": PLAN_CONTRACT, "record_class": RECORD_CLASS, "selection_source": SOURCE, "policy_version_id": str(v["id"]), "version_no": v["version_no"],
        "version_sha256": v["version_sha256"], "document_sha256": v["document_sha256"], "manifest_sha256": v["manifest_sha256"], "facts_sha256": sha256_hex(clean),
        "profiles": profiles, "evaluator_contract": EVALUATOR_CONTRACT, "plan_sha256": sha256_hex(plan), "outcome": outcome, "origin": came_from,
    }  # fmt: skip
    db.execute(
        text("INSERT INTO applicability_selection_plan (id, market_code, policy_id, policy_version_id, version_no, version_status, version_sha256, document_sha256, manifest_sha256, "
             "facts, facts_sha256, profiles, origin, evaluator_contract, plan, plan_sha256, outcome, record_sha256, created_by) VALUES (:i, :m, :p, :v, :n, :st, :vh, :dh, :mh, "
             "CAST(:f AS jsonb), :fh, CAST(:pr AS jsonb), CAST(:o AS jsonb), :ec, CAST(:pl AS jsonb), :ph, :out, :rh, :by)"),
        {"i": pid, "m": v["market_code"], "p": v["policy_id"], "v": v["id"], "n": v["version_no"], "st": v["status"], "vh": v["version_sha256"], "dh": v["document_sha256"],
         "mh": v["manifest_sha256"], "f": json.dumps(clean), "fh": sha256_hex(clean), "pr": json.dumps(profiles), "o": json.dumps(came_from), "ec": EVALUATOR_CONTRACT,
         "pl": json.dumps(plan), "ph": sha256_hex(plan), "out": outcome, "rh": sha256_hex(record), "by": _ref(actor)},
    )  # fmt: skip
    status = {"SURVEYS_SELECTED": "READY", "NO_SURVEY_REQUIRED": "NO_SURVEY_REQUIRED", "UNRESOLVED": "SELECTION_UNRESOLVED", "OUT_OF_SCOPE": "OUT_OF_SCOPE"}.get(outcome, "SCOPE_UNRESOLVED")  # fmt: skip
    db.execute(
        text(
            "INSERT INTO applicability_journey (id, market_code, selection_plan_id, policy_version_id, label, status, created_by) VALUES (:i, :m, :p, :v, :l, :s, :by)"
        ),
        {"i": jid, "m": v["market_code"], "p": pid, "v": v["id"], "l": label, "s": status, "by": _ref(actor)},
    )
    for n, s in enumerate(steps, start=1):
        row = s["row"]
        db.execute(
            text("INSERT INTO applicability_journey_step (id, journey_id, position, survey_definition_id, survey_version_id, survey_code, version_no, content_sha256, manifest_sha256, "
                 "required_by, obligations) VALUES (:i, :j, :n, :d, :v, :c, :vn, :ch, :mh, CAST(:r AS jsonb), :o)"),
            {"i": uuid.uuid4(), "j": jid, "n": n, "d": row["survey_definition_id"], "v": row["id"], "c": row["survey_code"], "vn": row["version_no"], "ch": row["content_sha256"],
             "mh": row["manifest_sha256"], "r": json.dumps(s["required_by"]), "o": s["obligations"]},
        )  # fmt: skip
    _event(db, jid, "CREATED", actor, {"selection_plan_id": str(pid), "outcome": outcome, "plan_sha256": sha256_hex(plan), "facts_sha256": sha256_hex(clean), "policy_version_id": str(v["id"]),
                                      "version_no": v["version_no"], "version_status": v["status"], "surveys": [s["row"]["survey_code"] for s in steps]})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.JOURNEY_CREATED", "applicability_journey", jid,
           {"record_class": RECORD_CLASS, "selection_source": SOURCE, "policy_version_id": str(v["id"]), "outcome": outcome, "plan_sha256": sha256_hex(plan)})  # fmt: skip
    return jid


# --------------------------------------------------------------------------------------------------- reading
def journey_row(db: Session, jid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    j = _one(db, J_SQL + "WHERE j.id = :i" + (" FOR UPDATE" if lock else ""), i=jid)
    if j is None or j["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such journey")
    return j


def _plan_row(db: Session, pid: Any) -> dict[str, Any]:
    row = _one(db, P_SQL + "WHERE s.id = :i", i=pid)
    assert row is not None
    return row


def _steps(db: Session, jid: Any) -> list[dict[str, Any]]:
    return _all(db, STEP_SQL + "WHERE t.journey_id = :j ORDER BY t.position", j=jid)


def _events(db: Session, jid: Any) -> list[dict[str, Any]]:
    return _all(db, "SELECT e.seq, e.event, e.step_position, e.actor_ref, e.idempotency_key, e.request_sha256, e.detail, e.occurred_at, "
                    "(SELECT p.display_name FROM principal p WHERE p.id::text = e.actor_ref) AS actor_name FROM applicability_journey_event e WHERE e.journey_id = :j ORDER BY e.seq", j=jid)  # fmt: skip


def _item_key(position: int, key: str) -> str:
    return f"{position}:{key}"


def _allowed_non_answers(p: Mapping[str, Any]) -> list[str]:
    kind = p.get("answer_type")
    if kind == "ACKNOWLEDGEMENT":
        return ["NOT_ACKNOWLEDGED"]
    if kind == "FREE_TEXT" and not (p.get("text_rule") or {"required": True}).get("required"):
        return ["EMPTY_TEXT"]
    if kind == "MULTI_SELECT" and int((p.get("selection") or {"min": 0}).get("min") or 0) == 0:
        return ["NONE_SELECTED"]
    return []


def _turn(journey: Mapping[str, Any], step: Mapping[str, Any], sim: Mapping[str, Any], inputs: int, modules: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:  # fmt: skip
    p = sim["run"].get("pending")
    if not p or sim["status"] == "REPLAY_DRIFT":
        return None
    module = next((m for m in modules if m.get("instance") == p.get("instance")), {})
    mode = p.get("delivery_mode")
    return {
        "contract": RUNTIME_CONTRACT, "journey_id": str(journey["id"]), "step": step["position"], "steps": None,
        "survey": {"code": step["survey_code"], "name": step["survey_name"], "version_no": step["version_no"], "version_label": step["version_label"],
                   "version_id": str(step["survey_version_id"]), "content_sha256": step["content_sha256"]},
        "item_key": _item_key(step["position"], p["key"]), "item": p.get("item"), "attempt": p.get("attempt") or 0,
        "module": {"instance": p.get("instance"), "name": module.get("name") or p.get("instance")},
        "question_no": len(sim["run"].get("asked") or []) + 1,
        "prompt": {"text": p.get("text"), "followup": p.get("followup"), "delivery_mode": mode, "exact_wording_required": mode in ("CONTROLLED_TTS", "EXACT_AUDIO")},
        "expects": {"answer_type": p.get("answer_type"), "options": p.get("options") or [], "selection": p.get("selection"), "number_rule": p.get("number_rule"), "text_rule": p.get("text_rule")},
        "allowed_non_answers": _allowed_non_answers(p),
        "policy_unresolved": sim["run"].get("policy_unresolved"),
        "expected_inputs": inputs, "turn_token": journey["revision"],
    }  # fmt: skip


def _step_view(step: Mapping[str, Any], sim: Mapping[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "position": step["position"], "survey_code": step["survey_code"], "survey_name": step["survey_name"], "version_no": step["version_no"], "version_label": step["version_label"],
        "survey_version_id": str(step["survey_version_id"]), "survey_definition_id": str(step["survey_definition_id"]), "content_sha256": step["content_sha256"],
        "manifest_sha256": step["manifest_sha256"], "required_by": list(step["required_by"]), "obligations": step["obligations"], "status": step["status"],
        "simulation_id": str(step["simulation_id"]) if step["simulation_id"] else None, "outcome": step["outcome"], "outcome_detail": step["outcome_detail"],
        "started_at": step["started_at"], "ended_at": step["ended_at"], "run_status": None, "replay_consistent": None, "inputs": 0, "answered": 0,
        "modules": [], "answers": [], "rejections": [],
    }  # fmt: skip
    if sim is None:
        return out
    run = sim["run"]
    answers = [{"item_key": _item_key(step["position"], e["key"]), "module": e.get("instance"), "text": e.get("text"), "answer": e.get("answer"), "state": e.get("state")}
               for e in run.get("events") or [] if e.get("kind") == "ANSWER"]  # fmt: skip
    said = [{"item_key": _item_key(step["position"], e["key"]), "module": e.get("instance"), "text": e.get("text"), "answer": None, "state": "DELIVERED"}
            for e in run.get("events") or [] if e.get("kind") == "SAY"]  # fmt: skip
    return out | {
        "run_status": sim["status"], "replay_consistent": sim["replay_consistent"], "inputs": len(sim["inputs"]), "answered": len(run.get("asked") or []),
        "modules": [{"instance": m.get("instance"), "name": m.get("name"), "status": m.get("status")} for m in run.get("modules") or []],
        "answers": answers, "statements": said, "evidence_states": run.get("evidence_states") or {},
        "rejections": [{"item_key": _item_key(step["position"], i["key"]), "code": i["rejection_code"], "seq": i["seq"]} for i in sim["inputs"] if not i["accepted"]],
        "terminal": run.get("terminal"), "policy_unresolved": run.get("policy_unresolved"), "run_sha256": sim["run_sha256"], "drift": sim["drift"],
    }  # fmt: skip


def _requirements(plan: Mapping[str, Any], steps: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Every requirement of the policy, and how it stands in THIS journey. A shared delivery satisfies each requirement
    it was declared for — or none of them."""
    by = {r: s for s in steps for r in s["required_by"]}
    out = []
    for r in plan.get("requirements") or []:
        rid, step = str(r.get("id")), by.get(str(r.get("id")))
        row: dict[str, Any] = {"id": rid, "name": r.get("name"), "selection_state": r.get("outcome") or r.get("state"), "replaced_by": r.get("replaced_by"), "step": step["position"] if step else None,
                               "survey_code": step["survey_code"] if step else None, "shared": bool(step and len(step["required_by"]) > 1)}  # fmt: skip
        if step is None:
            row |= {"fulfilment": "NOT_REQUIRED", "reason": str(r.get("outcome") or r.get("state") or "not selected")}
        elif step["status"] == "ENDED" and step["outcome"] == "COMPLETED":
            row |= {"fulfilment": "SATISFIED", "reason": "the survey was completed"}
        elif step["status"] == "ENDED":
            row |= {"fulfilment": "NOT_SATISFIED", "reason": f"the survey ended as {step['outcome']}"}
        else:
            row |= {
                "fulfilment": "NOT_SATISFIED",
                "reason": "the survey has not been completed"
                if step["status"] == "RUNNING"
                else "the survey has not started",
            }
        out.append(row)
    return out


def _describe_options(db: Session, markets: Sequence[str], step: Mapping[str, Any], turn: dict[str, Any]) -> None:
    """What the pinned survey says about each option of the current question — whether it takes free text, whether it
    excludes the others — so that a client shows the right control without knowing anything about the survey."""
    item = turn.get("item") or {}
    bundle = simulation.version_bundle(db, simulation._version(db, step["survey_version_id"], markets))  # noqa: SLF001
    doc = bundle.items.get((item.get("code"), item.get("version")))
    flags = {o["code"]: o for o in (bundle.options_of(doc) if doc else [])}
    turn["expects"]["options"] = [
        {
            "code": o["code"],
            "label": o.get("label", ""),
            "is_other": bool((flags.get(o["code"]) or {}).get("is_other")),
            "exclusive": bool((flags.get(o["code"]) or {}).get("exclusive")),
            "other_text": (flags.get(o["code"]) or {}).get("other_text")
            if (flags.get(o["code"]) or {}).get("is_other")
            else None,
        }
        for o in turn["expects"]["options"]
    ]


def state(db: Session, markets: Sequence[str], jid: uuid.UUID, *, events: bool = True) -> dict[str, Any]:
    """The journey as it stands NOW — replayed from what is recorded. Nothing is kept in a browser."""
    j = journey_row(db, jid, markets)
    plan = _plan_row(db, j["selection_plan_id"])
    steps = _steps(db, jid)
    sims = {s["position"]: simulation.state(db, s["simulation_id"], markets) for s in steps if s["simulation_id"]}
    views = [_step_view(s, sims.get(s["position"])) for s in steps]
    inputs = sum(v["inputs"] for v in views)
    current = next((s for s in steps if s["status"] == "RUNNING"), None)
    turn = None
    if j["status"] == "RUNNING" and current is not None:
        turn = _turn(
            j, current, sims[current["position"]], inputs, sims[current["position"]]["run"].get("modules") or []
        )
        if turn:
            turn["steps"] = len(steps)
            _describe_options(db, markets, current, turn)
    drift = [v["position"] for v in views if v["replay_consistent"] is False]
    condition = "REPLAY_DRIFT" if drift else "POLICY_UNRESOLVED" if turn and turn["policy_unresolved"] else None
    current_version = _current(db, plan["policy_id"])
    return {
        "id": str(j["id"]), "contract": RUNTIME_CONTRACT, "record_class": RECORD_CLASS, "selection_source": SOURCE, "note": NOTE, "market_code": j["market_code"],
        "label": j["label"], "status": j["status"], "condition": condition, "revision": j["revision"], "expected_inputs": inputs,
        "created_by": j["created_by"], "created_at": j["created_at"], "started_at": j["started_at"], "ended_at": j["ended_at"], "end_detail": j["end_detail"],
        "selection": {
            "selection_plan_id": str(plan["id"]), "policy_id": str(plan["policy_id"]), "policy_code": plan["policy_code"], "policy_name": plan["policy_name"] or plan["policy_code"],
            "policy_version_id": str(plan["policy_version_id"]), "version_no": plan["version_no"], "version_status_at_selection": plan["version_status"],
            "current_version_no": current_version["version_no"] if current_version else None, "version_sha256": plan["version_sha256"], "document_sha256": plan["document_sha256"],
            "manifest_sha256": plan["manifest_sha256"], "facts": plan["facts"], "facts_sha256": plan["facts_sha256"], "profiles": plan["profiles"], "origin": plan["origin"],
            "evaluator_contract": plan["evaluator_contract"], "outcome": plan["outcome"], "plan": plan["plan"], "plan_sha256": plan["plan_sha256"], "record_sha256": plan["record_sha256"],
            "created_at": plan["created_at"],
        },
        "start": j["start_record"], "start_sha256": j["start_sha256"], "survey_facts": j["survey_facts"], "survey_facts_sha256": j["survey_facts_sha256"],
        "steps": views, "current_step": current["position"] if current else None, "turn": turn,
        "progress": {"surveys": len(steps), "surveys_ended": sum(s["status"] == "ENDED" for s in steps), "surveys_completed": sum(s["outcome"] == "COMPLETED" for s in steps),
                     "questions_answered": sum(v["answered"] for v in views), "inputs": inputs},
        "requirements": _requirements(plan["plan"], steps),
        "events": [{**e, "detail": e["detail"]} for e in _events(db, jid)] if events else [],
    }  # fmt: skip


def listing(db: Session, markets: Sequence[str], *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    limit, offset = max(1, min(int(limit), 100)), max(0, int(offset))
    rows = _all(
        db,
        "SELECT j.id, j.label, j.status, j.revision, j.created_at, j.started_at, j.ended_at, j.created_by, s.version_no, s.version_status, s.outcome, p.code AS policy_code, "
        "p.document->>'name' AS policy_name, (SELECT count(*) FROM applicability_journey_step t WHERE t.journey_id = j.id) AS surveys, "
        "(SELECT count(*) FROM applicability_journey_step t WHERE t.journey_id = j.id AND t.outcome = 'COMPLETED') AS surveys_completed, "
        "(SELECT pr.display_name FROM principal pr WHERE pr.id::text = j.created_by) AS created_by_name "
        "FROM applicability_journey j JOIN applicability_selection_plan s ON s.id = j.selection_plan_id JOIN applicability_policy p ON p.id = s.policy_id "
        "WHERE j.market_code = ANY(:m) ORDER BY j.created_at DESC, j.id LIMIT :l OFFSET :o",
        m=list(markets), l=limit, o=offset,
    )  # fmt: skip
    total = _one(db, "SELECT count(*) AS n FROM applicability_journey WHERE market_code = ANY(:m)", m=list(markets))
    return {
        "items": [{**r, "id": str(r["id"])} for r in rows],
        "total": total["n"] if total else 0,
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------------------- fact correspondence
def _attributes_sha(field: Mapping[str, Any]) -> str:
    return sha256_hex(dict(field))


def _fields(db: Session) -> dict[str, dict[str, Any]]:
    return {
        r["code"]: dict(r["attributes"])
        for r in _all(db, "SELECT code, attributes FROM survey_catalog_entry WHERE catalog = 'FIELD' ORDER BY code")
    }


def catalog(db: Session, markets: Sequence[str], market: str) -> dict[str, Any]:
    """What a correspondence may connect: every published variable version of the market, and every catalog field."""
    if market not in markets:
        raise SurveyError(404, "MARKET_NOT_IN_SCOPE", "That market is not available to you")
    variables = _all(
        db,
        "SELECT a.code, v.id AS version_id, v.version_no, v.status, v.content_sha256, v.document FROM applicability_asset_version v JOIN applicability_asset a ON a.id = v.asset_id "
        "WHERE a.market_code = :m AND a.kind = 'VARIABLE' AND v.status IN ('PUBLISHED', 'SUPERSEDED') ORDER BY a.code, v.version_no",
        m=market,
    )
    return {
        "variables": [{"variable": r["code"], "version": r["version_no"], "version_id": str(r["version_id"]), "content_sha256": r["content_sha256"], "status": r["status"], "name": r["document"].get("name"),
                       "type": r["document"].get("type"), "values": [x.get("value") for x in r["document"].get("values") or []], "currency": r["document"].get("currency"), "derived": bool(r["document"].get("derived"))}
                      for r in variables],
        "fields": [{"field": code, "attributes_sha256": _attributes_sha(f), "label": f.get("label"), "type": f.get("type"), "values": f.get("values") or [], "unit": f.get("unit")} for code, f in _fields(db).items()],
        "rules": ["IDENTITY"],
    }  # fmt: skip


def _entry_problem(var: Mapping[str, Any], field: Mapping[str, Any]) -> str | None:
    st, tt = str(var.get("type")), str(field.get("type"))
    if var.get("derived"):
        return "a derived fact is worked out by the policy; it has no value to carry"
    if COMPATIBLE.get(st) != tt:
        return (
            f"the application fact is {st} and the survey fact is {tt}; only the same type is carried over, unchanged"
        )
    if st == "ENUM":
        missing = [x.get("value") for x in var.get("values") or [] if x.get("value") not in (field.get("values") or [])]
        if missing:
            return f"the survey fact has no value {', '.join(map(str, missing))}; a value is never translated"
    if st == "MONEY" and var.get("currency") != field.get("unit"):
        return f"the application fact is in {var.get('currency')} and the survey fact in {field.get('unit')}; no conversion exists"
    return None


def normalise_correspondence(db: Session, market: str, raw: Any) -> dict[str, Any]:
    """The stored document: exact identities on both sides, IDENTITY only. Anything else in a request is dropped."""
    if not isinstance(raw, Mapping):
        raise _bad("INVALID_DOCUMENT", "The correspondence must be an object")
    name = raw.get("name")
    if not isinstance(name, str) or len(name.strip()) < 2 or len(name) > 160:
        raise _bad("NAME_REQUIRED", "Give the correspondence a name of 2 to 160 characters")
    entries = raw.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
        raise _bad("INVALID_DOCUMENT", f"'entries' is a list of 1 to {MAX_ENTRIES} entries")
    fields, out, seen = _fields(db), [], set()
    for n, e in enumerate(entries):
        src, tgt = (e or {}).get("source") or {}, (e or {}).get("target") or {}
        if (e or {}).get("rule", "IDENTITY") != "IDENTITY":
            raise _bad(
                "RULE_NOT_ALLOWED",
                "The only rule is IDENTITY: a value is carried over unchanged. There is no expression and no conversion",
                details=[{"entry": n}],
            )
        try:
            vid = uuid.UUID(str(src.get("version_id")))
        except ValueError as exc:
            raise _bad(
                "SOURCE_REQUIRED", "Name the exact published version of the application fact", details=[{"entry": n}]
            ) from exc
        v = _one(
            db,
            "SELECT a.code, a.kind, a.market_code, v.version_no, v.status, v.content_sha256, v.document FROM applicability_asset_version v JOIN applicability_asset a ON a.id = v.asset_id WHERE v.id = :i",
            i=vid,
        )
        if (
            v is None
            or v["market_code"] != market
            or v["kind"] != "VARIABLE"
            or v["status"] not in ("PUBLISHED", "SUPERSEDED")
        ):
            raise _bad(
                "SOURCE_NOT_PUBLISHED",
                "The source is one published version of an application fact of this market",
                details=[{"entry": n}],
            )
        if (
            src.get("content_sha256") not in (None, v["content_sha256"])
            or src.get("variable") not in (None, v["code"])
            or src.get("version") not in (None, v["version_no"])
        ):
            raise _bad(
                "SOURCE_DEFINITION_DIFFERS",
                f"'{v['code']}' version {v['version_no']} is not the definition named in the request",
                details=[{"entry": n}],
            )
        code = str(tgt.get("field") or "")
        field = fields.get(code)
        if field is None:
            raise _bad("TARGET_UNKNOWN", f"'{code}' is not a field of the survey fact catalog", details=[{"entry": n}])
        if tgt.get("attributes_sha256") not in (None, _attributes_sha(field)):
            raise _bad(
                "TARGET_DEFINITION_DIFFERS",
                f"The survey fact '{code}' is not the definition named in the request",
                details=[{"entry": n}],
            )
        if code in seen:
            raise _bad(
                "TARGET_REPEATED", f"The survey fact '{code}' is given by more than one entry", details=[{"entry": n}]
            )
        seen.add(code)
        why = _entry_problem(v["document"], field)
        if why:
            raise _bad(
                "NOT_COMPATIBLE",
                f"'{v['code']}' → '{code}': {why}",
                details=[{"entry": n, "variable": v["code"], "field": code}],
            )
        out.append({"source": {"variable": v["code"], "version": v["version_no"], "version_id": str(vid), "content_sha256": v["content_sha256"]},
                    "target": {"field": code, "attributes_sha256": _attributes_sha(field)}, "rule": "IDENTITY"})  # fmt: skip
    description = str(raw.get("description") or "").strip()[:2000]
    sc._synthetic_only("name", name)  # noqa: SLF001
    sc._synthetic_only("description", description)  # noqa: SLF001
    return {
        "schema": CORRESPONDENCE_SCHEMA,
        "name": name.strip(),
        "description": description,
        "entries": sorted(out, key=lambda e: e["target"]["field"]),
    }


def _correspondence_view(r: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": str(r["id"]), "market_code": r["market_code"], "code": r["code"], "version_no": r["version_no"], "record_class": r["record_class"], "name": r["document"].get("name"),
            "description": r["document"].get("description") or "", "entries": r["document"].get("entries") or [], "document_sha256": r["document_sha256"], "created_by": r["created_by"],
            "created_by_name": r.get("created_by_name"), "created_at": r["created_at"], "note": "Synthetic execution aid. Not an approved operational data mapping."}  # fmt: skip


C_SQL = "SELECT c.*, (SELECT p.display_name FROM principal p WHERE p.id::text = c.created_by) AS created_by_name FROM applicability_fact_correspondence c "


def correspondence_row(db: Session, cid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    r = _one(db, C_SQL + "WHERE c.id = :i", i=cid)
    if r is None or r["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such fact correspondence")
    return r


def correspondences(db: Session, markets: Sequence[str]) -> dict[str, Any]:
    rows = _all(db, C_SQL + "WHERE c.market_code = ANY(:m) ORDER BY c.code, c.version_no DESC", m=list(markets))
    return {"items": [_correspondence_view(r) for r in rows]}


def correspondence(db: Session, markets: Sequence[str], cid: uuid.UUID) -> dict[str, Any]:
    return _correspondence_view(correspondence_row(db, cid, markets))


def save_correspondence(db: Session, markets: Sequence[str], market: str, code: str, document: Any, actor: Actor, meta: RequestMeta | None = None) -> uuid.UUID:  # fmt: skip
    """A NEW immutable version. An earlier version is never changed; a journey that froze it keeps what it froze."""
    if market not in markets:
        raise SurveyError(404, "MARKET_NOT_IN_SCOPE", "That market is not available to you")
    doc = normalise_correspondence(db, market, document)
    code = str(code or "").strip()
    last = _one(
        db,
        "SELECT version_no, document_sha256 FROM applicability_fact_correspondence WHERE market_code = :m AND code = :c ORDER BY version_no DESC LIMIT 1 FOR UPDATE",
        m=market,
        c=code,
    )
    if last and last["document_sha256"] == sha256_hex(doc):
        raise _refuse("NOTHING_CHANGED", "This is exactly the latest version; nothing was saved")
    cid = uuid.uuid4()
    try:
        with db.begin_nested():
            db.execute(
                text(
                    "INSERT INTO applicability_fact_correspondence (id, market_code, code, version_no, document, document_sha256, created_by) VALUES (:i, :m, :c, :n, CAST(:d AS jsonb), :h, :by)"
                ),
                {
                    "i": cid,
                    "m": market,
                    "c": code,
                    "n": (last["version_no"] + 1) if last else 1,
                    "d": json.dumps(doc),
                    "h": sha256_hex(doc),
                    "by": _ref(actor),
                },
            )
    except Exception as exc:  # noqa: BLE001 — the code pattern is a database CHECK; say it plainly
        if "applicability_fact_correspondence_code_check" in str(exc):
            raise _bad("CODE_INVALID", "A code is 2 to 80 letters, digits, dots, dashes or underscores") from exc
        raise
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.FACT_CORRESPONDENCE_SAVED",
        "applicability_fact_correspondence",
        cid,
        {"record_class": RECORD_CLASS, "code": code, "document_sha256": sha256_hex(doc)},
    )
    return cid


def _required_fields(db: Session, markets: Sequence[str], steps: Sequence[Mapping[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:  # fmt: skip
    """The catalog, and — per field a selected survey READS — which survey reads it and for what."""
    fields: dict[str, dict[str, Any]] = {}
    used: dict[str, list[dict[str, Any]]] = {}
    for s in steps:
        bundle = simulation.version_bundle(db, simulation._version(db, s["survey_version_id"], markets))  # noqa: SLF001
        fields = fields or {k: dict(v) for k, v in bundle.fields.items()}
        for line in callplan.assemble(bundle, {})["inputs"]:
            used.setdefault(line["field"], []).append(
                {"step": s["position"], "survey_code": s["survey_code"], "used_by": line["used_by"]}
            )
    return fields, used


def resolve_survey_facts(db: Session, markets: Sequence[str], jid: uuid.UUID, correspondence_id: uuid.UUID | None, typed: Any) -> dict[str, Any]:  # fmt: skip
    """Which survey facts this journey would run with, and where each comes from. Writes nothing. Deterministic: the
    start record stores exactly this, and verification must reproduce it."""
    j = journey_row(db, jid, markets)
    plan = _plan_row(db, j["selection_plan_id"])
    version = pub.version_row(db, plan["policy_version_id"], markets)
    fields, used = _required_fields(db, markets, _steps(db, jid))
    corr = correspondence_row(db, correspondence_id, markets) if correspondence_id else None
    if corr is not None and corr["market_code"] != j["market_code"]:
        raise _bad("OTHER_MARKET", "A journey uses a fact correspondence of its own market")
    return _resolve(fields, used, version["manifest"], plan["facts"], corr, typed)


def _resolve(fields: Mapping[str, Mapping[str, Any]], used: Mapping[str, Any], manifest: Mapping[str, Any], facts: Mapping[str, Any], corr: Mapping[str, Any] | None, typed: Any) -> dict[str, Any]:  # fmt: skip
    if typed is None:
        typed = {}
    if not isinstance(typed, Mapping) or len(typed) > MAX_FACTS:
        raise _bad("FACTS_INVALID", f"Survey facts are one object of at most {MAX_FACTS} fields")
    unknown = sorted(str(k) for k in typed if str(k) not in fields)
    if unknown:
        raise _bad(
            "FACT_UNKNOWN",
            "A survey fact names a field the governed catalog does not have",
            details=[{"field": k} for k in unknown],
        )
    pinned = {
        str(e["code"]): e
        for e in (manifest.get("snapshot") or {}).get("dependencies") or []
        if e.get("kind") == "VARIABLE"
    }
    entries, carried = [], {}
    for e in (corr["document"].get("entries") if corr else None) or []:
        src, tgt = e["source"], e["target"]
        pin, field = pinned.get(src["variable"]), fields.get(tgt["field"])
        why = (
            "SOURCE_NOT_IN_POLICY" if pin is None
            else "SOURCE_DEFINITION_DIFFERS" if str(pin.get("version_id")) != src["version_id"] or pin.get("content_sha256") != src["content_sha256"]
            else "TARGET_DEFINITION_DIFFERS" if field is None or _attributes_sha(field) != tgt["attributes_sha256"]
            else None
        )  # fmt: skip
        line = {
            "source": src,
            "target": tgt,
            "rule": e["rule"],
            "applies": why is None,
            "why_not": why,
            "provided": src["variable"] in facts,
            "value": facts.get(src["variable"]) if why is None else None,
        }
        entries.append(line)
        if why is None and src["variable"] in facts:
            carried[tgt["field"]] = {
                "value": facts[src["variable"]],
                "entry": {"variable": src["variable"], "version": src["version"]},
            }
    out: dict[str, Any] = {}
    conflicts = []
    for code in sorted(set(carried) | {str(k) for k in typed}):
        c, has_typed, t = carried.get(code), code in typed, typed.get(code)
        if c is not None and has_typed and c["value"] is not None and t is not None and t != c["value"]:
            conflicts.append({"field": code, "carried": c["value"], "typed": t, "from": c["entry"]})
            continue
        if has_typed and (t is not None or c is None or c["value"] is None):
            # typed by the person. A typed known value stands where the application fact is not known; a typed
            # "not known" never replaces a carried known value (that case falls through to CORRESPONDENCE below)
            out[code] = {
                "value": t,
                "origin": "TYPED" if t is not None else "MARKED_NOT_KNOWN",
                "source": c["entry"] if c else None,
                "also_carried": c is not None and c["value"] == t and t is not None,
            }
        else:
            assert c is not None
            out[code] = {"value": c["value"], "origin": "CORRESPONDENCE", "source": c["entry"], "also_carried": False}
    missing = [
        {"field": code, "label": (fields.get(code) or {}).get("label"), "read_by": used[code]}
        for code in sorted(used)
        if code not in out
    ]
    survey_facts = {code: line["value"] for code, line in out.items()}
    return {
        "correspondence": ({"id": str(corr["id"]), "code": corr["code"], "version_no": corr["version_no"], "document_sha256": corr["document_sha256"], "document": corr["document"]} if corr else None),
        "entries": entries,
        "fields": [{"field": code, "label": f.get("label"), "type": f.get("type"), "values": f.get("values") or [], "unit": f.get("unit"), "required": code in used, "read_by": used.get(code) or [],
                    **({"given": True, **out[code]} if code in out else {"given": False, "value": None, "origin": None, "source": None, "also_carried": False})}
                   for code, f in sorted(fields.items()) if code in used or code in out],
        "missing": missing, "conflicts": conflicts, "survey_facts": survey_facts, "survey_facts_sha256": sha256_hex(survey_facts), "ready": not missing and not conflicts,
    }  # fmt: skip


# ----------------------------------------------------------------------------------------------- coordination
def _bump(db: Session, j: dict[str, Any], status: str, **more: Any) -> None:
    sets, params = ["status = :s", "revision = revision + 1"], {"s": status, "i": j["id"]}
    for k, v in more.items():
        sets.append(
            f"{k} = "
            + (
                f"CAST(:{k} AS jsonb)"
                if k in ("start_record", "survey_facts", "end_detail")
                else "now()"
                if v == "now()"
                else f":{k}"
            )
        )
        if v != "now()":
            params[k] = json.dumps(_json(v)) if k in ("start_record", "survey_facts", "end_detail") else v
    db.execute(text(f"UPDATE applicability_journey SET {', '.join(sets)} WHERE id = :i"), params)  # noqa: S608 — column names are literals above
    j["status"], j["revision"] = status, j["revision"] + 1


def _start_step(
    db: Session,
    markets: Sequence[str],
    j: Mapping[str, Any],
    step: Mapping[str, Any],
    actor: Actor,
    meta: RequestMeta | None,
) -> None:
    """ONE existing single-survey simulation, of the pinned published version, with the journey's survey facts."""
    row = _survey_version(
        db,
        markets,
        {
            "version_id": step["survey_version_id"],
            "code": step["survey_code"],
            "version": step["version_no"],
            "fingerprint": step["content_sha256"],
            "manifest": step["manifest_sha256"],
        },
    )
    sim = simulation.create(
        db,
        row["id"],
        markets,
        j["survey_facts"],
        f"Applicability journey {str(j['id'])[:8]} · step {step['position']} · {step['survey_code']}",
        actor,
        meta,
    )
    db.execute(
        text(
            "UPDATE applicability_journey_step SET status = 'RUNNING', simulation_id = :m, started_at = now() WHERE id = :i"
        ),
        {"m": sim, "i": step["id"]},
    )
    _event(
        db,
        j["id"],
        "STEP_STARTED",
        actor,
        {
            "survey_code": step["survey_code"],
            "version_no": step["version_no"],
            "simulation_id": str(sim),
            "required_by": list(step["required_by"]),
        },
        step=step["position"],
    )


def _settle(db: Session, markets: Sequence[str], j: dict[str, Any], actor: Actor, meta: RequestMeta | None) -> None:
    """After anything that may have ended a survey: record how it ended, and hand over ONLY after COMPLETED."""
    while j["status"] == "RUNNING":
        steps = _steps(db, j["id"])
        cur = next((s for s in steps if s["status"] == "RUNNING"), None)
        if cur is None:
            return
        sim = simulation.state(db, cur["simulation_id"], markets)
        if sim["status"] != "TERMINAL":
            return
        terminal = sim["run"]["terminal"] or {}
        outcome = str(terminal.get("state") or "UNKNOWN")
        db.execute(text("UPDATE applicability_journey_step SET status = 'ENDED', outcome = :o, outcome_detail = CAST(:d AS jsonb), ended_at = now() WHERE id = :i"),
                   {"o": outcome, "d": json.dumps(_json(terminal)), "i": cur["id"]})  # fmt: skip
        _event(
            db,
            j["id"],
            "STEP_ENDED",
            actor,
            {
                "survey_code": cur["survey_code"],
                "outcome": outcome,
                "terminal": terminal,
                "run_sha256": sim["run_sha256"],
                "inputs": len(sim["inputs"]),
                "required_by": list(cur["required_by"]),
            },
            step=cur["position"],
        )
        nxt = next((s for s in steps if s["status"] == "WAITING"), None)
        if outcome == "COMPLETED" and nxt is not None:
            _start_step(db, markets, j, nxt, actor, meta)
            continue
        if outcome == "COMPLETED":
            detail = {"reason": "Every selected survey was completed", "last_step": cur["position"]}
            status = "ALL_SURVEYS_COMPLETED"
        else:
            # no governed rule says what follows a survey that did not complete: none is invented
            status = "CROSS_SURVEY_POLICY_UNRESOLVED" if nxt is not None else "ENDED_INCOMPLETE"
            detail = {"reason": (f"Survey '{cur['survey_code']}' ended as {outcome}. No governed rule says whether the remaining surveys follow, so none was started" if nxt is not None
                                 else f"Survey '{cur['survey_code']}' ended as {outcome}"),
                      "step": cur["position"], "survey_code": cur["survey_code"], "terminal": terminal, "not_started": [s["survey_code"] for s in steps if s["status"] == "WAITING"]}  # fmt: skip
        _bump(db, j, status, end_detail=detail, ended_at="now()")
        _event(db, j["id"], "ENDED", actor, {"status": status, **detail})
        _audit(
            db,
            actor,
            meta,
            "APPLICABILITY.JOURNEY_ENDED",
            "applicability_journey",
            j["id"],
            {"record_class": RECORD_CLASS, "status": status},
        )


def start(db: Session, markets: Sequence[str], jid: uuid.UUID, expected_revision: int, correspondence_id: uuid.UUID | None, typed: Any, actor: Actor, meta: RequestMeta | None = None) -> dict[str, Any]:  # fmt: skip
    """Freeze the survey facts — and exactly how they were obtained — and begin the first selected survey."""
    j = journey_row(db, jid, markets, lock=True)
    if j["status"] != "READY":
        raise _refuse("NOT_READY", f"This journey is {j['status'].lower().replace('_', ' ')}; it cannot be started")
    if j["revision"] != expected_revision:
        raise _refuse(
            "STALE_JOURNEY",
            "This journey changed after you looked at it; look again",
            [{"current_revision": j["revision"]}],
        )
    r = resolve_survey_facts(db, markets, jid, correspondence_id, typed)
    if r["conflicts"]:
        raise _refuse(
            "SURVEY_FACT_CONFLICT",
            "A survey fact was typed with a value different from the one carried over from the application facts. Nothing is replaced: resolve it",
            r["conflicts"],
        )
    if r["missing"]:
        raise _refuse(
            "SURVEY_FACTS_REQUIRED",
            "A selected survey reads a fact that has no value and is not marked as not known",
            r["missing"],
        )
    record = {
        "contract": START_CONTRACT, "record_class": RECORD_CLASS, "journey_id": str(jid), "selection_plan_id": str(j["selection_plan_id"]), "engine_contract": ENGINE_CONTRACT,
        "correspondence": r["correspondence"], "entries": r["entries"],
        "fields": [{k: f[k] for k in ("field", "required", "given", "value", "origin", "source", "also_carried")} for f in r["fields"]],
        "typed": {str(k): typed[k] for k in sorted(typed or {}, key=str)}, "survey_facts": r["survey_facts"], "survey_facts_sha256": r["survey_facts_sha256"],
    }  # fmt: skip
    record = _json(record)
    db.execute(
        text(
            "UPDATE applicability_journey SET status = 'RUNNING', revision = revision + 1, correspondence_id = :c, start_record = CAST(:r AS jsonb), start_sha256 = :rh, "
            "survey_facts = CAST(:f AS jsonb), survey_facts_sha256 = :fh, started_by = :by, started_at = now() WHERE id = :i"
        ),
        {
            "c": correspondence_id,
            "r": json.dumps(record),
            "rh": sha256_hex(record),
            "f": json.dumps(r["survey_facts"]),
            "fh": r["survey_facts_sha256"],
            "by": _ref(actor),
            "i": jid,
        },
    )
    j = journey_row(db, jid, markets)
    _event(db, jid, "STARTED", actor, {"start_sha256": j["start_sha256"], "survey_facts_sha256": j["survey_facts_sha256"], "correspondence": ({k: r["correspondence"][k] for k in ("id", "code", "version_no", "document_sha256")} if r["correspondence"] else None),
                                      "applied": sum(e["applies"] for e in r["entries"]), "typed": len(record["typed"])})  # fmt: skip
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.JOURNEY_STARTED",
        "applicability_journey",
        jid,
        {"record_class": RECORD_CLASS, "start_sha256": j["start_sha256"]},
    )
    _start_step(db, markets, j, _steps(db, jid)[0], actor, meta)
    _settle(db, markets, j, actor, meta)
    return state(db, markets, jid)


def turn(db: Session, markets: Sequence[str], jid: uuid.UUID) -> dict[str, Any]:
    """``next``: the ONE question the journey is waiting for — or how it ended. The server decides; a client reads."""
    s = state(db, markets, jid, events=False)
    if s["turn"] is not None:
        return {"kind": "TURN", "turn": s["turn"], "end": None, "status": s["status"], "condition": s["condition"]}
    return {"kind": "END", "turn": None, "status": s["status"], "condition": s["condition"],
            "end": {"status": s["status"], "condition": s["condition"], "detail": s["end_detail"], "requirements": s["requirements"],
                    "unresolved": [r for r in s["requirements"] if r["fulfilment"] == "NOT_SATISFIED"], "steps": [{k: v[k] for k in ("position", "survey_code", "status", "outcome")} for v in s["steps"]]}}  # fmt: skip


def _interaction(raw: Any) -> dict[str, Any] | None:
    """What a future voice adapter may attach to a submission: PROPOSED interaction evidence. It is recorded beside the
    submission and never treated as an accepted fact."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise _bad("INTERACTION_INVALID", "The interaction evidence must be an object")
    out = {k: raw[k] for k in INTERACTION_KEYS if raw.get(k) is not None}
    conf = out.get("recognition_confidence")
    if conf is not None and (isinstance(conf, bool) or not isinstance(conf, int | float) or not 0 <= conf <= 1):
        raise _bad("INTERACTION_INVALID", "A recognition confidence is a number from 0 to 1")
    for k in ("transcript_ref", "delivery_evidence_ref"):
        if k in out and (not isinstance(out[k], str) or len(out[k]) > 200):
            raise _bad("INTERACTION_INVALID", f"'{k}' is a reference of at most 200 characters")
    if len(json.dumps(_json(out))) > 4000:
        raise _bad("INTERACTION_INVALID", "The interaction evidence is too large")
    return out


def submit(db: Session, markets: Sequence[str], jid: uuid.UUID, item_key: str, expected_inputs: int, answer: Any, idempotency_key: str, interaction: Any, actor: Actor, meta: RequestMeta | None = None) -> dict[str, Any]:  # fmt: skip
    """Propose ONE answer to the question the journey is waiting for. The answer is validated by the execution engine
    against the authoritative turn; an accepted answer is persisted before anything advances. A submission for any
    other question, against another state of the journey, or for another survey is refused and nothing advances.
    Retry-safe: the same idempotency key with the same request returns the first result and records nothing again."""
    key = str(idempotency_key or "")
    if not 8 <= len(key) <= 80:
        raise _bad("IDEMPOTENCY_KEY_REQUIRED", "Send an idempotency key of 8 to 80 characters with every submission")
    proposed = _interaction(interaction)
    request_sha = sha256_hex(
        _json({"item_key": item_key, "expected_inputs": expected_inputs, "answer": answer, "interaction": proposed})
    )
    j = journey_row(db, jid, markets, lock=True)
    done = _one(
        db,
        "SELECT event, request_sha256, detail FROM applicability_journey_event WHERE journey_id = :j AND idempotency_key = :k",
        j=jid,
        k=key,
    )
    if done is not None:
        if done["request_sha256"] != request_sha:
            raise _refuse("IDEMPOTENCY_KEY_REUSED", "That idempotency key was used for a different submission")
        return {
            "result": done["detail"]["result"],
            "code": done["detail"].get("code"),
            "replayed": True,
            "recorded_seq": done["detail"].get("seq"),
            "state": state(db, markets, jid),
        }
    if j["status"] != "RUNNING":
        raise _refuse(
            "JOURNEY_NOT_RUNNING", f"This journey is {j['status'].lower().replace('_', ' ')}; it takes no answer"
        )
    steps = _steps(db, jid)
    cur = next(s for s in steps if s["status"] == "RUNNING")
    sims = {s["position"]: simulation.state(db, s["simulation_id"], markets) for s in steps if s["simulation_id"]}
    inputs = sum(len(v["inputs"]) for v in sims.values())
    if inputs != expected_inputs:
        raise _refuse(
            "STALE_TURN",
            f"The journey has {inputs} inputs; this answer was given against {expected_inputs}",
            [{"current_inputs": inputs, "expected_inputs": expected_inputs}],
        )
    sim = sims[cur["position"]]
    current = _turn(j, cur, sim, inputs, sim["run"].get("modules") or [])
    if current is None:
        raise _refuse("NO_CURRENT_TURN", "The journey is not waiting for an answer")
    if item_key != current["item_key"]:
        raise _refuse(
            "INPUT_NOT_CURRENT",
            "That is not the question the journey is waiting for",
            [{"current": current["item_key"], "given": item_key}],
        )
    base = {
        "item_key": item_key,
        "survey_code": cur["survey_code"],
        "attempt": current["attempt"],
        **({"interaction": proposed} if proposed else {}),
    }

    def refused(code: str, message: str) -> dict[str, Any]:
        # recorded as a refused submission; the engine is not given anything and the same turn stays current
        _event(
            db,
            jid,
            "SUBMISSION_REFUSED",
            actor,
            {**base, "result": "REJECTED", "code": code, "message": message},
            step=cur["position"],
            key=key,
            request_sha=request_sha,
        )
        return {
            "result": "REJECTED",
            "code": code,
            "replayed": False,
            "recorded_seq": None,
            "state": state(db, markets, jid),
        }

    if proposed and proposed.get("clarification_required"):
        return refused(
            "CLARIFICATION_REQUIRED",
            "The adapter reports that no answer could be established; the question stays current",
        )
    if not isinstance(answer, Mapping):
        raise _bad("ANSWER_INVALID", "An answer is an object")
    given = dict(answer)
    if "non_answer" in given:
        kind = str(given["non_answer"])
        if len(given) != 1 or kind not in NON_ANSWERS:
            raise _bad("ANSWER_INVALID", "A non-answer is given on its own, as one of the kinds the turn allows")
        if kind not in current["allowed_non_answers"]:
            return refused("NON_ANSWER_NOT_ALLOWED", "This question does not allow that non-answer")
        given = dict(NON_ANSWERS[kind])
    after = simulation.advance(
        db, cur["simulation_id"], markets, len(sim["inputs"]), current["item_key"].split(":", 1)[1], given, actor, meta
    )
    last = after["inputs"][-1]
    accepted = bool(last["accepted"])
    detail = {
        **base,
        "result": "ACCEPTED" if accepted else "REJECTED",
        "code": None if accepted else last["rejection_code"],
        "seq": last["seq"],
        "answer": last["answer"],
        "run_status": last["run_status"],
        "run_sha256": last["run_sha256"],
    }
    _event(
        db,
        jid,
        "INPUT_ACCEPTED" if accepted else "INPUT_REJECTED",
        actor,
        detail,
        step=cur["position"],
        key=key,
        request_sha=request_sha,
    )
    _bump(db, j, "RUNNING")
    _settle(db, markets, j, actor, meta)
    return {
        "result": detail["result"],
        "code": detail["code"],
        "replayed": False,
        "recorded_seq": last["seq"],
        "state": state(db, markets, jid),
    }


def record_refusal(
    db: Session,
    markets: Sequence[str],
    jid: uuid.UUID,
    item_key: str,
    expected_inputs: int,
    code: str,
    message: str,
    actor: Actor,
) -> None:
    """A submission the runtime refused outright (stale, out of turn, for another survey). Recorded in a transaction of
    its own, after the refused one was rolled back — so the refusal is evidence and nothing else changed."""
    try:
        journey_row(db, jid, markets)
    except SurveyError:
        return
    _event(
        db,
        jid,
        "SUBMISSION_REFUSED",
        actor,
        {
            "result": "REFUSED",
            "code": code,
            "message": message,
            "item_key": str(item_key)[:240],
            "expected_inputs": expected_inputs,
        },
    )


def abandon(db: Session, markets: Sequence[str], jid: uuid.UUID, expected_revision: int, reason: str, actor: Actor, meta: RequestMeta | None = None) -> dict[str, Any]:  # fmt: skip
    j = journey_row(db, jid, markets, lock=True)
    if j["status"] not in OPEN:
        raise _refuse("NOT_OPEN", "Only a journey that is ready or running can be abandoned")
    if j["revision"] != expected_revision:
        raise _refuse(
            "STALE_JOURNEY",
            "This journey changed after you looked at it; look again",
            [{"current_revision": j["revision"]}],
        )
    reason = str(reason or "").strip()
    if len(reason) < 10:
        raise _bad("COMMENT_REQUIRED", "Say why, in at least ten characters")
    detail = {"reason": reason[:500], "abandoned_at_status": j["status"]}
    _bump(db, j, "ABANDONED", end_detail=detail, ended_at="now()")
    _event(db, jid, "ABANDONED", actor, detail)
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.JOURNEY_ENDED",
        "applicability_journey",
        jid,
        {"record_class": RECORD_CLASS, "status": "ABANDONED"},
    )
    return state(db, markets, jid)


# ------------------------------------------------------------------------------------------------ verification
def verify(db: Session, markets: Sequence[str], jid: uuid.UUID) -> dict[str, Any]:
    """The journey reproduced from its RECORDS: the selection from the immutable policy version and the recorded facts;
    the survey facts from the frozen correspondence; every survey from its recorded inputs. Writes nothing."""
    j = journey_row(db, jid, markets)
    plan = _plan_row(db, j["selection_plan_id"])
    steps = _steps(db, jid)
    checks: list[dict[str, Any]] = []

    def check(code: str, ok: bool, what: str, **more: Any) -> None:
        checks.append({"code": code, "ok": bool(ok), "what": what, **more})

    v = pub.version_row(db, plan["policy_version_id"], markets)
    proof = pub.verify_version(db, markets, v["id"])
    check("POLICY_VERSION", proof["verified"] and (v["version_sha256"], v["document_sha256"], v["manifest_sha256"]) == (plan["version_sha256"], plan["document_sha256"], plan["manifest_sha256"]),
          f"The published policy version {plan['version_no']} verifies against its own record and is the one the selection recorded")  # fmt: skip
    check(
        "FACT_SNAPSHOT",
        sha256_hex(plan["facts"]) == plan["facts_sha256"],
        "The recorded application facts match their fingerprint",
    )
    again: dict[str, Any] | None = None
    try:
        _, again, _ = _evaluate(db, markets, v, plan["facts"])
    except SurveyError:
        again = None
    check("SELECTION_REPRODUCED", again is not None and sha256_hex(again) == plan["plan_sha256"] and sha256_hex(plan["plan"]) == plan["plan_sha256"],
          "Evaluating the recorded facts against the frozen policy version gives exactly the recorded selection plan", outcome=plan["outcome"])  # fmt: skip
    selected = (
        sorted(plan["plan"].get("selected") or [], key=lambda e: e.get("position") or 0)
        if plan["outcome"] == "SURVEYS_SELECTED"
        else []
    )
    check("STEPS_ARE_THE_SELECTION",
          [(s["survey_code"], s["version_no"], s["content_sha256"], str(s["survey_version_id"])) for s in steps] == [(e["survey"]["code"], e["survey"]["version"], e["survey"]["fingerprint"], str(e["survey"]["version_id"])) for e in selected]
          and [list(s["required_by"]) for s in steps] == [[r if isinstance(r, str) else str((r or {}).get("id")) for r in e.get("required_by") or []] for e in selected],
          "The steps are exactly the selected surveys: the same versions, in the same order, for the same requirements — nothing added, nothing left out", steps=len(steps))  # fmt: skip
    if j["start_record"] is not None:
        rec = j["start_record"]
        check(
            "START_RECORD",
            sha256_hex(rec) == j["start_sha256"]
            and sha256_hex(j["survey_facts"]) == j["survey_facts_sha256"] == rec["survey_facts_sha256"],
            "The start record and the survey facts match their fingerprints",
        )
        corr = None
        if rec.get("correspondence"):
            corr = {
                "id": rec["correspondence"]["id"],
                "code": rec["correspondence"]["code"],
                "version_no": rec["correspondence"]["version_no"],
                "document_sha256": rec["correspondence"]["document_sha256"],
                "document": rec["correspondence"]["document"],
            }
            stored = _one(
                db,
                "SELECT document_sha256 FROM applicability_fact_correspondence WHERE id = :i",
                i=uuid.UUID(corr["id"]),
            )
            check(
                "CORRESPONDENCE_FROZEN",
                sha256_hex(corr["document"]) == corr["document_sha256"]
                and stored is not None
                and stored["document_sha256"] == corr["document_sha256"],
                "The fact correspondence frozen in the journey matches its fingerprint and its stored version",
            )
        fields, used = _required_fields(db, markets, steps)
        redo = _resolve(fields, used, v["manifest"], plan["facts"], corr, rec.get("typed") or {})
        check("SURVEY_FACTS_REPRODUCED", redo["survey_facts_sha256"] == j["survey_facts_sha256"] and redo["ready"],
              "Applying the frozen correspondence and the typed survey facts to the recorded application facts gives exactly the survey facts the journey ran with")  # fmt: skip
    total, ended_ok = 0, True
    for s in steps:
        if not s["simulation_id"]:
            continue
        sim = simulation.state(db, s["simulation_id"], markets)
        total += len(sim["inputs"])
        same_version = (sim["content_sha256"], sim["manifest_sha256"], str(sim["version_id"])) == (
            s["content_sha256"],
            s["manifest_sha256"],
            str(s["survey_version_id"]),
        )
        check("SURVEY_REPRODUCED", sim["replay_consistent"] and same_version and sim["facts_sha256"] == j["survey_facts_sha256"],
              f"Step {s['position']} ({s['survey_code']} v{s['version_no']}) replays from its {len(sim['inputs'])} recorded inputs to exactly the recorded result, at the pinned version, with the journey's survey facts", step=s["position"])  # fmt: skip
        if s["status"] == "ENDED":
            ok = sim["status"] == "TERMINAL" and str((sim["run"]["terminal"] or {}).get("state")) == s["outcome"]
            ended_ok = ended_ok and ok
            check(
                "STEP_OUTCOME",
                ok,
                f"Step {s['position']} ended as {s['outcome']}, which is what its replay ends as",
                step=s["position"],
            )
    events = _events(db, jid)
    check(
        "HISTORY_CONSISTENT",
        sum(e["event"] in ("INPUT_ACCEPTED", "INPUT_REJECTED") for e in events) == total,
        "The coordination history holds one entry for every recorded input",
        inputs=total,
    )
    started = [s for s in steps if s["simulation_id"]]
    check("COORDINATION", all(a["outcome"] == "COMPLETED" for a in started[:-1]) and [s["position"] for s in started] == list(range(1, len(started) + 1)),
          "A survey was started only after every survey before it was completed, in the plan's order")  # fmt: skip
    if j["status"] == "ALL_SURVEYS_COMPLETED":
        check(
            "COMPLETION",
            bool(steps) and all(s["outcome"] == "COMPLETED" for s in steps),
            "Every selected survey was completed",
        )
    ok = all(c["ok"] for c in checks)
    return {"journey_id": str(jid), "verified": ok, "status": j["status"], "checks": checks, "failed": [c["code"] for c in checks if not c["ok"]],
            "selection_plan_sha256": plan["plan_sha256"], "start_sha256": j["start_sha256"], "inputs": total,
            "note": "Reproduced from the journey's own records: the immutable policy version, the recorded facts, the frozen correspondence and the recorded inputs. Nothing was written."}  # fmt: skip
