"""S2-E callback simulation workbench: scenario library, automated runs, coverage and version comparison.

Reuses the S2-D / S2-D.1 controller through ``scenario_runner`` — there is no second execution engine. Writes only
simulation records (``simulation_*`` tables); never a script assignment, contact attempt, session, survey run, finding,
hold, case state or KPI input. Drafts are tested from a content snapshot (``simulation_content_snapshot``), so a later
draft edit never changes a recorded result, and nothing about the draft itself changes.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import finding_rules as fr
from app.domain import lifecycle as lc
from app.domain import question_controller as qc
from app.domain import scenario_runner as sr
from app.domain import script_authoring as sa
from app.domain.digest import sha256_of

# S3-A: scenario facts are the approved condition facts plus the facts the approved evaluation mappings need.
EVALUATION_FACT_KEYS = ("premium_term_years", "premium_amount", "currency")
FACT_KEYS = (*sa.CONDITION_FACTS, *EVALUATION_FACT_KEYS)
CURRENCIES = ("SGD",)  # Singapore-only synthetic development
EXPECTATION_KEYS = (
    "findings",
    "evaluations",
    "basis",
    "outcome",
    "termination_reason",
    "gates",
    "mandatory_complete",
    "applicable_questions",
    "sequence",
    "question_states",
)
MAX_STEPS = 100
MAX_BATCH = 50


class WorkbenchError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


# ---- versions and snapshots --------------------------------------------------------------------------------------
def version(db: Session, version_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    try:
        return sa.version_row(db, version_id, list(markets))
    except sa.AuthoringError as exc:
        raise WorkbenchError(404, "NOT_FOUND", "Script version not found or not available to you") from exc


def label(v: Mapping[str, Any]) -> str:
    return f"{v['family']} v{v['version_label']}" + (" (draft)" if v["status"] == "DRAFT" else "")


def content(db: Session, v: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    c = sa.content_of(db, v)
    return sha256_of(c), c


def snapshot(db: Session, v: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Content-addressed, insert-only copy of exactly the content used (a draft's live rows at this moment)."""
    sha, c = content(db, v)
    db.execute(
        text(
            "INSERT INTO simulation_content_snapshot (sha256, script_version_id, version_status, content) "
            "VALUES (:s, :v, :st, CAST(:c AS jsonb)) ON CONFLICT (sha256) DO NOTHING"
        ),
        {"s": sha, "v": v["id"], "st": v["status"], "c": json.dumps(c, default=str)},
    )
    return sha, c


def snapshot_content(db: Session, sha: str) -> dict[str, Any]:
    r = _one(db, "SELECT content FROM simulation_content_snapshot WHERE sha256 = :s", s=sha)
    assert r is not None
    return dict(r["content"])


def build(c: Mapping[str, Any], v: Mapping[str, Any], sha: str, facts: Mapping[str, Any], band: str | None) -> qc.Plan:
    return qc.build_plan(c, script_label=label(v), manifest_sha256=sha, facts=facts, band=band)


def versions(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    """Every testable script version you can see: drafts (labelled), in review, published and superseded."""
    return _all(
        db,
        "SELECT v.id, v.version_label, v.status, v.content_approval_status, f.id AS family_id, f.code AS family, "
        "f.name AS family_name FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "WHERE f.market_code = ANY(:m) AND v.status <> 'ABANDONED' ORDER BY f.code, v.created_at DESC",
        m=list(markets),
    )


def live_eligibility(c: Mapping[str, Any]) -> dict[str, Any]:
    """D-67 (owner condition on S2-D.1): a script lacking any mandatory lifecycle gate is never eligible for a future
    live customer conversation. Structural check only — eligibility also needs approved content and later stages."""
    roles: dict[str, bool] = {}
    for sec in c.get("sections", []):
        for q in sec["questions"]:
            role = q.get("lifecycle_role") or "VERIFICATION"
            roles[role] = roles.get(role, False) or bool(q.get("mandatory"))
    missing = [r for r in lc.LIVE_REQUIRED_GATES if not roles.get(r)]
    return {
        "structurally_eligible": not missing,
        "missing_mandatory_gates": missing,
        "note": "Structural lifecycle check only. No script is approved for live customer conversations; "
        "live calling is not part of this stage.",
    }


# ---- cases as fact sources ----------------------------------------------------------------------------------------
def case_facts(db: Session, case_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    c = _one(
        db,
        "SELECT id, case_ref, sale_event_id FROM callback_case WHERE id = :c AND market_code = ANY(:m)",
        c=case_id,
        m=list(markets),
    )
    if c is None:
        raise WorkbenchError(404, "NOT_FOUND", "Not found or not available to you")
    snap = _one(
        db,
        "SELECT id, facts FROM policy_fact_snapshot WHERE sale_event_id = :s ORDER BY captured_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    if snap is None:
        raise WorkbenchError(409, "NO_FACT_SNAPSHOT", "The case has no policy fact snapshot")
    risk = _one(
        db,
        "SELECT band_code FROM risk_assessment WHERE sale_event_id = :s AND status = 'FINAL' "
        "ORDER BY valid_at DESC LIMIT 1",
        s=c["sale_event_id"],
    )
    facts = {k: (snap["facts"] or {}).get(k) for k in FACT_KEYS if (snap["facts"] or {}).get(k) is not None}
    return {
        "case_id": c["id"],
        "case_ref": c["case_ref"],
        "snapshot_id": snap["id"],
        "facts": facts,
        "risk_band": risk["band_code"] if risk else None,
    }


# ---- scenario content ---------------------------------------------------------------------------------------------
def normalise(body: Mapping[str, Any]) -> dict[str, Any]:
    """Shape validation of structured scenario content (never code)."""
    problems: list[str] = []
    name = str(body.get("name") or "").strip()
    if not 3 <= len(name) <= 120:
        problems.append("Name: 3–120 characters")
    facts = dict(body.get("facts") or {})
    for k, v in list(facts.items()):
        if v in (None, ""):
            facts.pop(k)
        elif k in sa.CONDITION_FACTS:
            if v not in sa.CONDITION_FACTS[k] or isinstance(v, bool) != (k == "is_ilp"):
                problems.append(f"Fact {k}: {v!r} is not an approved value")
        elif k == "premium_term_years":
            if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 100:
                problems.append("Fact premium_term_years: a whole number of years (1–100)")
        elif k == "premium_amount":
            d = ae.dec(v)
            if d is None or d <= 0 or d >= 10**10 or d != d.quantize(Decimal("0.01")):
                problems.append("Fact premium_amount: a positive amount with at most 2 decimal places")
            else:
                facts[k] = ae.fmt(d)
        elif k == "currency":
            if v not in CURRENCIES:
                problems.append("Fact currency: SGD (Singapore-only synthetic data)")
        else:
            problems.append(f"Fact {k}: not an approved scenario fact")
    band = body.get("risk_band")
    if band is not None and band not in sa.RISK_BANDS:
        problems.append(f"SBQ band {band!r} is not an approved band")
    steps = list(body.get("steps") or [])
    if len(steps) > MAX_STEPS:
        problems.append(f"At most {MAX_STEPS} steps")
    clean_steps = []
    for i, s in enumerate(steps, start=1):
        kind = s.get("kind")
        if kind not in sr.STEP_KINDS:
            problems.append(f"Step {i}: unknown step kind {kind!r}")
            continue
        if not s.get("question"):
            problems.append(f"Step {i}: choose the question it responds to")
        if kind == "EVENT" and s.get("event") not in lc.EVENTS:
            problems.append(f"Step {i}: choose a conversation event")
        value = s.get("value")
        if kind == "ANSWER" and (value is None or (isinstance(value, str) and not value.strip())):
            problems.append(f"Step {i}: an answer needs a value")
        if isinstance(value, str) and len(value) > 500:
            problems.append(f"Step {i}: value is limited to 500 characters")
        clean_steps.append(
            {
                "question": str(s.get("question") or ""),
                "kind": kind,
                **({"value": value} if kind == "ANSWER" else {}),
                **({"event": s.get("event")} if kind == "EVENT" else {}),
                **({"note": str(s["note"])[:300]} if s.get("note") else {}),
            }
        )
    exp = {
        k: v for k, v in dict(body.get("expectations") or {}).items() if k in EXPECTATION_KEYS and v not in ("", None)
    }
    if exp.get("outcome") and exp["outcome"] not in sr.OUTCOMES:
        problems.append(f"Expected outcome {exp['outcome']!r} is not one of {', '.join(sr.OUTCOMES)}")
    if exp.get("termination_reason") and exp["termination_reason"] not in (*sr.TERMINATION_REASONS, "NONE"):
        problems.append(f"Expected termination reason {exp['termination_reason']!r} is not known")
    gates = {g: s for g, s in dict(exp.get("gates") or {}).items() if s}
    for g in gates:
        if g not in sr.GATES:
            problems.append(f"Unknown gate {g!r}")
    exp["gates"] = gates
    states = {c: s for c, s in dict(exp.get("question_states") or {}).items() if s}
    for c, st in states.items():
        if st not in sr.QUESTION_STATES:
            problems.append(f"Expected state of {c}: {st!r} is not a final question state")
    exp["question_states"] = states
    evals = {c: r for c, r in dict(exp.get("evaluations") or {}).items() if r}
    for c, r in evals.items():
        if r not in sr.EVALUATION_RESULTS:
            problems.append(f"Expected evaluation of {c}: {r!r} is not an evaluation result")
    exp["evaluations"] = evals
    if "findings" in exp:
        fl = exp["findings"]
        if not isinstance(fl, list) or len(fl) > 100:
            problems.append("Expected findings must be a list (at most 100); an empty list expects none")
        else:
            clean_f = []
            for i, f in enumerate(fl, start=1):
                f = dict(f or {})
                if not f.get("question"):
                    problems.append(f"Expected finding {i}: choose the question")
                if f.get("category") not in fe.CATEGORIES:
                    problems.append(f"Expected finding {i}: category must be one of {', '.join(fe.CATEGORIES)}")
                if f.get("severity") and f["severity"] not in fe.SEVERITIES:
                    problems.append(f"Expected finding {i}: severity must be one of {', '.join(fe.SEVERITIES)}")
                clean_f.append(
                    {
                        "question": f.get("question"),
                        "category": f.get("category"),
                        "severity": f.get("severity") or None,
                    }
                )
            exp["findings"] = clean_f
    if exp.get("basis") and exp["basis"] not in sr.EXPECTATION_BASES:
        problems.append(f"Expectation basis {exp['basis']!r} is not known")
    for k in ("applicable_questions", "sequence"):
        if k in exp and not isinstance(exp[k], list):
            problems.append(f"{k.replace('_', ' ').capitalize()} must be a list of question codes")
    default = body.get("default_response") or "AFFIRMATIVE"
    if default not in sr.DEFAULT_RESPONSES:
        problems.append(f"Default response {default!r} is not known")
    if problems:
        raise WorkbenchError(422, "INVALID_SCENARIO", "The scenario is not valid", problems)
    return {
        "name": name,
        "description": (str(body.get("description") or "").strip() or None),
        "script_version_id": body["script_version_id"],
        "facts": facts,
        "risk_band": band,
        "source_case_id": body.get("source_case_id"),
        "steps": clean_steps,
        "expectations": exp,
        "default_response": default,
    }


def _snapshot_id_for(db: Session, case_id: Any, markets: Sequence[str]) -> Any:
    return case_facts(db, uuid.UUID(str(case_id)), markets)["snapshot_id"] if case_id else None


def _insert_revision(
    db: Session,
    scenario_id: uuid.UUID,
    n: int,
    c: dict[str, Any],
    sha: str,
    actor: str,
    note: str | None,
    snapshot_id: Any,
) -> uuid.UUID:
    rid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO simulation_scenario_revision (id, scenario_id, revision, name, description, "
            "script_version_id, "
            "script_content_sha256, facts, risk_band, source_case_id, source_snapshot_id, steps, expectations, "
            "default_response, change_note, created_by) VALUES (:i, :s, :n, :name, :d, :v, :sha, CAST(:f AS jsonb), "
            ":b, :case, :snap, CAST(:steps AS jsonb), CAST(:exp AS jsonb), :dr, :note, :by)"
        ),
        {
            "i": rid,
            "s": scenario_id,
            "n": n,
            "name": c["name"],
            "d": c["description"],
            "v": c["script_version_id"],
            "sha": sha,
            "f": json.dumps(c["facts"]),
            "b": c["risk_band"],
            "case": c["source_case_id"],
            "snap": snapshot_id,
            "steps": json.dumps(c["steps"]),
            "exp": json.dumps(c["expectations"]),
            "dr": c["default_response"],
            "note": note,
            "by": actor,
        },
    )
    return rid


def create(
    db: Session,
    markets: Sequence[str],
    actor: str,
    body: Mapping[str, Any],
    copied_from: uuid.UUID | None = None,
    note: str | None = None,
) -> uuid.UUID:
    c = normalise(body)
    v = version(db, uuid.UUID(str(c["script_version_id"])), markets)
    if v["status"] == "ABANDONED":
        raise WorkbenchError(409, "VERSION_ABANDONED", "That draft was abandoned; choose another version")
    sha, _ = content(db, v)
    snap = _snapshot_id_for(db, c["source_case_id"], markets)
    sid = uuid.uuid4()
    n = db.execute(text("SELECT count(*) + 1 FROM simulation_scenario")).scalar_one()
    db.execute(
        text(
            "INSERT INTO simulation_scenario (id, scenario_ref, market_code, script_family_id, name, copied_from_id, "
            "created_by) VALUES (:i, :ref, :m, :f, :name, :cf, :by)"
        ),
        {
            "i": sid,
            "ref": f"SCN-{n:04d}",
            "m": v["market_code"],
            "f": v["script_family_id"],
            "name": c["name"],
            "cf": copied_from,
            "by": actor,
        },
    )
    _insert_revision(db, sid, 1, c, sha, actor, note or ("Copied" if copied_from else "Created"), snap)
    return sid


def scenario_row(db: Session, scenario_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT s.*, f.code AS family FROM simulation_scenario s JOIN script_family f "
        "ON f.id = s.script_family_id WHERE s.id = :s AND s.market_code = ANY(:m)"
        + (" FOR UPDATE OF s" if lock else ""),
        s=scenario_id,
        m=list(markets),
    )
    if r is None:
        raise WorkbenchError(404, "NOT_FOUND", "Scenario not found or not available to you")
    return r


def revision_row(db: Session, scenario_id: uuid.UUID, n: int | None = None) -> dict[str, Any]:
    r = _one(
        db,
        "SELECT r.*, p.display_name FROM simulation_scenario_revision r LEFT JOIN principal p "
        "ON CAST(p.id AS text) = r.created_by WHERE r.scenario_id = :s AND r.revision = coalesce(CAST(:n AS int), "
        "(SELECT current_revision FROM simulation_scenario WHERE id = :s))",
        s=scenario_id,
        n=n,
    )
    if r is None:
        raise WorkbenchError(404, "NOT_FOUND", "Scenario revision not found")
    return r


def revise(
    db: Session,
    scenario_id: uuid.UUID,
    markets: Sequence[str],
    actor: str,
    expected_row_version: int,
    body: Mapping[str, Any],
    note: str | None,
) -> None:
    s = scenario_row(db, scenario_id, markets, lock=True)
    if s["row_version"] != expected_row_version:
        raise WorkbenchError(409, "STALE_SCENARIO", "This scenario was changed by someone else; reload it first")
    if s["status"] != "ACTIVE":
        raise WorkbenchError(409, "SCENARIO_ARCHIVED", "Archived scenarios cannot be edited; copy it instead")
    c = normalise(body)
    v = version(db, uuid.UUID(str(c["script_version_id"])), markets)
    if v["script_family_id"] != s["script_family_id"]:
        raise WorkbenchError(422, "WRONG_FAMILY", "A scenario stays within its script family; copy it for another")
    if v["status"] == "ABANDONED":
        raise WorkbenchError(409, "VERSION_ABANDONED", "That draft was abandoned; choose another version")
    sha, _ = content(db, v)
    n = s["current_revision"] + 1
    _insert_revision(db, scenario_id, n, c, sha, actor, note, _snapshot_id_for(db, c["source_case_id"], markets))
    db.execute(
        text(
            "UPDATE simulation_scenario SET current_revision = :n, name = :name, updated_at = now(), "
            "row_version = row_version + 1 WHERE id = :s"
        ),
        {"n": n, "name": c["name"], "s": scenario_id},
    )


def body_of(rev: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: rev[k]
        for k in (
            "name",
            "description",
            "script_version_id",
            "facts",
            "risk_band",
            "source_case_id",
            "steps",
            "expectations",
            "default_response",
        )
    }


def copy(db: Session, scenario_id: uuid.UUID, markets: Sequence[str], actor: str, name: str | None) -> uuid.UUID:
    s = scenario_row(db, scenario_id, markets)
    rev = revision_row(db, scenario_id)
    body = body_of(rev) | {"name": name or f"Copy of {rev['name']}"[:120]}
    return create(
        db, markets, actor, body, copied_from=scenario_id, note=f"Copied from {s['scenario_ref']} r{rev['revision']}"
    )


def set_status(
    db: Session, scenario_id: uuid.UUID, markets: Sequence[str], expected_row_version: int, status: str
) -> None:
    s = scenario_row(db, scenario_id, markets, lock=True)
    if s["row_version"] != expected_row_version:
        raise WorkbenchError(409, "STALE_SCENARIO", "This scenario was changed by someone else; reload it first")
    db.execute(
        text(
            "UPDATE simulation_scenario SET status = :st, updated_at = now(), row_version = row_version + 1 "
            "WHERE id = :s"
        ),
        {"st": status, "s": scenario_id},
    )


def scenarios(
    db: Session, markets: Sequence[str], family_id: uuid.UUID | None, q: str | None, archived: bool
) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT s.id, s.scenario_ref, s.name, s.status, s.current_revision, s.row_version, s.updated_at, "
        "f.id AS family_id, f.code AS family, v.id AS script_version_id, v.version_label, v.status AS version_status, "
        "r.description, r.default_response, jsonb_array_length(r.steps) AS steps, "
        "(SELECT x.status FROM simulation_result x WHERE x.scenario_id = s.id ORDER BY x.created_at DESC LIMIT 1) "
        "AS last_status, (SELECT x.created_at FROM simulation_result x WHERE x.scenario_id = s.id "
        "ORDER BY x.created_at DESC LIMIT 1) AS last_run_at "
        "FROM simulation_scenario s JOIN script_family f ON f.id = s.script_family_id "
        "JOIN simulation_scenario_revision r ON r.scenario_id = s.id AND r.revision = s.current_revision "
        "JOIN script_version v ON v.id = r.script_version_id WHERE s.market_code = ANY(:m) "
        "AND (CAST(:f AS uuid) IS NULL OR s.script_family_id = :f) AND (:a OR s.status = 'ACTIVE') "
        "AND (CAST(:q AS text) IS NULL OR s.name ILIKE :like OR s.scenario_ref ILIKE :like) "
        "ORDER BY s.updated_at DESC LIMIT 200",
        m=list(markets),
        f=family_id,
        a=archived,
        q=q,
        like=f"%{q}%" if q else None,
    )


# ---- execution ---------------------------------------------------------------------------------------------------
def _stale(db: Session, rev: Mapping[str, Any], v: Mapping[str, Any], sha: str) -> list[str]:
    out = []
    if v["id"] == rev["script_version_id"] and sha != rev["script_content_sha256"]:
        out.append("The script content changed after this scenario revision was saved; review the expectations")
    if v["status"] in ("SUPERSEDED", "WITHDRAWN"):
        newer = _one(
            db,
            "SELECT version_label FROM script_version WHERE script_family_id = :f AND status = "
            "'PUBLISHED' ORDER BY published_at DESC NULLS LAST LIMIT 1",
            f=v["script_family_id"],
        )
        out.append(
            f"v{v['version_label']} is {v['status'].lower()}"
            + (f"; the current published version is v{newer['version_label']}" if newer else "")
        )
    return out


def execute_one(
    db: Session,
    rev: Mapping[str, Any],
    v: dict[str, Any],
    *,
    persist: bool,
    rules: fe.RuleSet | None = None,
) -> dict[str, Any]:
    """Run one scenario revision against one version. ``persist`` snapshots the content (for a recorded result)."""
    if v["status"] == "ABANDONED":
        return {
            "status": "INVALID",
            "problems": [f"v{v['version_label']} was abandoned"],
            "stale": False,
            "stale_reasons": [],
            "content_sha256": None,
            "plan_sha256": None,
            "failures": [],
            "actual": {},
            "events": [],
            "response_log": [],
            "error": None,
            "plan": None,
        }
    sha, c = snapshot(db, v) if persist else content(db, v)
    plan = build(c, v, sha, rev["facts"] or {}, rev["risk_band"])
    pj = {"applicable": [q.code for q in plan.questions if q.applicable]}
    stale = _stale(db, rev, v, sha)
    base = {
        "content_sha256": sha,
        "plan_sha256": sha256_of(qc_plan_json(plan)),
        "stale": bool(stale),
        "stale_reasons": stale,
        "plan": plan,
    }
    facts = dict(rev["facts"] or {})
    source = ae.FactSource(
        "SCENARIO_FACTS",
        f"scenario revision {rev['id']}" if rev.get("id") else "unsaved scenario",
        sha256_of(facts),
        facts,
    )
    base["fact_source"] = source.as_dict()

    def evaluator(ctrl: qc.Controller) -> list[dict[str, Any]]:
        return ae.evaluate(c, ctrl, source)

    def finder(evaluations: list[dict[str, Any]]) -> dict[str, Any] | None:
        if rules is None:
            return None
        from app.domain import simulation_findings as sf

        ctx = {
            "execution_ref": f"scenario revision {rev.get('id') or 'unsaved'} on {sha[:12]}",
            "case_ref": None,
            "script_label": label(v),
            "script_version_id": str(v["id"]),
            "content_sha256": sha,
            "evaluation_ref": None,
            "evaluation_engine": ae.ENGINE,
            "fact_source": source.as_dict(),
        }
        return sf.scenario_findings(evaluations, c, rules, ctx)

    try:
        ex = sr.execute(plan, rev["steps"] or [], rev["expectations"] or {}, rev["default_response"], evaluator, finder)
    except sr.ScenarioInvalid as exc:
        return base | {
            "status": "INVALID",
            "problems": exc.problems,
            "failures": [],
            "actual": {"plan": pj},
            "events": [],
            "response_log": [],
            "error": None,
        }
    return base | {
        "status": ex.status,
        "problems": [],
        "failures": ex.failures,
        "actual": ex.actual | ({"fact_source": source.as_dict(), "content_sha256": sha} if ex.actual else {}),
        "events": ex.events,
        "response_log": ex.log,
        "error": ex.error,
    }


def qc_plan_json(plan: qc.Plan) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(plan)


def run(
    db: Session,
    markets: Sequence[str],
    actor: str,
    scenario_ids: Sequence[uuid.UUID],
    version_id: uuid.UUID | None,
    compare_with: uuid.UUID | None,
    finding_rule_set_id: uuid.UUID | None = None,
) -> uuid.UUID:
    if not scenario_ids or len(scenario_ids) > MAX_BATCH:
        raise WorkbenchError(422, "INVALID_BATCH", f"Choose 1–{MAX_BATCH} scenarios")
    if compare_with is not None and version_id is None:
        raise WorkbenchError(422, "INVALID_BATCH", "A comparison needs two versions (A and B)")
    va = version(db, version_id, markets) if version_id else None
    vb = version(db, compare_with, markets) if compare_with else None
    if va and vb and va["script_family_id"] != vb["script_family_id"]:
        raise WorkbenchError(422, "WRONG_FAMILY", "Compare two versions of the same script family")
    if va and vb and va["id"] == vb["id"]:
        raise WorkbenchError(422, "SAME_VERSION", "Choose two different versions to compare")
    rows = []
    for sid in dict.fromkeys(scenario_ids):
        s = scenario_row(db, sid, markets)
        if va and s["script_family_id"] != va["script_family_id"]:
            raise WorkbenchError(422, "WRONG_FAMILY", f"{s['scenario_ref']} tests another script family")
        rows.append((s, revision_row(db, sid)))
    rules = rule_set_for(db, rows[0][0]["market_code"], markets, finding_rule_set_id)
    batch_id = uuid.uuid4()
    results = []
    for s, rev in rows:
        targets = [("A", va or version(db, rev["script_version_id"], markets))] + ([("B", vb)] if vb else [])
        for side, v in targets:
            r = execute_one(db, rev, v, persist=True, rules=rules)
            results.append((s, rev, side, v, r))
    totals: dict[str, Any] = {}
    for _, _, side, _, r in results:
        t = totals.setdefault(side, {"PASSED": 0, "FAILED": 0, "ERROR": 0, "INVALID": 0, "STALE": 0, "TOTAL": 0})
        t[r["status"]] += 1
        t["STALE"] += int(r["stale"])
        t["TOTAL"] += 1
    n = db.execute(text("SELECT count(*) + 1 FROM simulation_batch")).scalar_one()
    db.execute(
        text(
            "INSERT INTO simulation_batch (id, batch_ref, market_code, kind, version_a_id, version_b_id, totals, "
            "started_by) VALUES (:i, :ref, :m, :k, :a, :b, CAST(:t AS jsonb), :by)"
        ),
        {
            "i": batch_id,
            "ref": f"BAT-{n:04d}",
            "m": rows[0][0]["market_code"],
            "k": "COMPARISON" if vb else "RUN",
            "a": va["id"] if va else None,
            "b": vb["id"] if vb else None,
            "t": json.dumps(totals),
            "by": actor,
        },
    )
    for s, rev, side, v, r in results:
        db.execute(
            text(
                "INSERT INTO simulation_result (id, batch_id, side, scenario_id, scenario_revision_id, "
                "script_version_id, content_sha256, plan_sha256, status, stale, stale_reasons, problems, failures, "
                "error, actual, response_log, events) VALUES (:i, :b, :side, :s, :r, :v, :c, :p, :st, :stale, "
                "CAST(:sr AS jsonb), CAST(:pr AS jsonb), CAST(:f AS jsonb), :e, CAST(:a AS jsonb), CAST(:l AS jsonb), "
                "CAST(:ev AS jsonb))"
            ),
            {
                "i": uuid.uuid4(),
                "b": batch_id,
                "side": side,
                "s": s["id"],
                "r": rev["id"],
                "v": v["id"],
                "c": r["content_sha256"],
                "p": r["plan_sha256"],
                "st": r["status"],
                "stale": r["stale"],
                "sr": json.dumps(r["stale_reasons"]),
                "pr": json.dumps(r["problems"]),
                "f": json.dumps(r["failures"], default=str),
                "e": r["error"],
                "a": json.dumps(r["actual"], default=str),
                "l": json.dumps(r["response_log"], default=str),
                "ev": json.dumps(r["events"], default=str),
            },
        )
    return batch_id


def batch(db: Session, batch_id: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    b = _one(
        db,
        "SELECT b.*, p.display_name FROM simulation_batch b LEFT JOIN principal p ON CAST(p.id AS text) = "
        "b.started_by WHERE b.id = :b AND b.market_code = ANY(:m)",
        b=batch_id,
        m=list(markets),
    )
    if b is None:
        raise WorkbenchError(404, "NOT_FOUND", "Test run not found or not available to you")
    results = _all(
        db,
        "SELECT x.*, s.scenario_ref, r.name AS scenario_name, r.revision, r.facts, r.risk_band, "
        "f.code || ' v' || v.version_label AS version_label, v.status AS version_status "
        "FROM simulation_result x JOIN simulation_scenario s ON s.id = x.scenario_id "
        "JOIN simulation_scenario_revision r ON r.id = x.scenario_revision_id JOIN script_version v "
        "ON v.id = x.script_version_id JOIN script_family f ON f.id = v.script_family_id WHERE x.batch_id = :b "
        "ORDER BY s.scenario_ref, x.side",
        b=batch_id,
    )
    # Coverage per exact content snapshot (the universe of questions and modules is the snapshot's full plan).
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for x in results:
        if x["content_sha256"]:
            groups.setdefault((x["side"], x["content_sha256"]), []).append(x)
    cover = []
    for (side, sha), xs in groups.items():
        v = version(db, xs[0]["script_version_id"], markets)
        plan = build(snapshot_content(db, sha), v, sha, {}, None)
        cover.append(
            {
                "side": side,
                "script_version_id": v["id"],
                "version_label": xs[0]["version_label"],
                "version_status": xs[0]["version_status"],
                "content_sha256": sha,
                **sr.coverage(plan, [x["actual"] for x in xs if x["status"] in ("PASSED", "FAILED")]),
            }
        )
    comparison = []
    if b["kind"] == "COMPARISON":
        by: dict[uuid.UUID, dict[str, dict[str, Any]]] = {}
        for x in results:
            by.setdefault(x["scenario_id"], {})[x["side"]] = x
        for pair in by.values():
            a, bb = pair.get("A"), pair.get("B")
            if not a or not bb:
                continue
            pdiff = None
            if a["content_sha256"] and bb["content_sha256"]:
                va, vb = version(db, a["script_version_id"], markets), version(db, bb["script_version_id"], markets)
                pa = build(
                    snapshot_content(db, a["content_sha256"]), va, a["content_sha256"], a["facts"] or {}, a["risk_band"]
                )
                pb = build(
                    snapshot_content(db, bb["content_sha256"]),
                    vb,
                    bb["content_sha256"],
                    bb["facts"] or {},
                    bb["risk_band"],
                )
                pdiff = sr.plan_diff(pa, pb)
                pdiff["rule_changes"] = ae.rule_changes(
                    snapshot_content(db, a["content_sha256"]), snapshot_content(db, bb["content_sha256"])
                )
            comparison.append(
                {
                    "scenario_id": a["scenario_id"],
                    "scenario_ref": a["scenario_ref"],
                    "scenario_name": a["scenario_name"],
                    "status_a": a["status"],
                    "status_b": bb["status"],
                    "plan_diff": pdiff,
                    "outcome_diff": sr.outcome_diff(a["actual"], bb["actual"]),
                }
            )
    return {"batch": b, "results": results, "coverage": cover, "comparison": comparison}


def batches(db: Session, markets: Sequence[str], scenario_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT b.id, b.batch_ref, b.kind, b.totals, b.started_at, p.display_name, "
        "fa.code || ' v' || va.version_label AS version_a, fb.code || ' v' || vb.version_label AS version_b "
        "FROM simulation_batch b LEFT JOIN principal p ON CAST(p.id AS text) = b.started_by "
        "LEFT JOIN script_version va ON va.id = b.version_a_id "
        "LEFT JOIN script_family fa ON fa.id = va.script_family_id "
        "LEFT JOIN script_version vb ON vb.id = b.version_b_id "
        "LEFT JOIN script_family fb ON fb.id = vb.script_family_id "
        "WHERE b.market_code = ANY(:m) AND (CAST(:s AS uuid) IS NULL OR EXISTS (SELECT 1 FROM simulation_result x "
        "WHERE x.batch_id = b.id AND x.scenario_id = :s)) ORDER BY b.started_at DESC LIMIT 50",
        m=list(markets),
        s=scenario_id,
    )


def rule_set_for(db: Session, market: str, markets: Sequence[str], vid: uuid.UUID | None) -> fe.RuleSet | None:
    """The finding rule set used for scenario findings: the chosen version (drafts allowed, labelled) or the
    published one; ``None`` when nothing is published (findings are then not generated, and say so)."""
    if vid is not None:
        try:
            v = fr.version(db, vid, markets)
        except fr.RuleSetError as exc:
            raise WorkbenchError(404, "NOT_FOUND", exc.message) from exc
        if v["status"] == "ABANDONED":
            raise WorkbenchError(409, "RULE_SET_ABANDONED", "That finding rule set was abandoned")
        return fr.rule_set(v)
    p = fr.published(db, market)
    return fr.rule_set(p) if p else None


def preview(
    db: Session, markets: Sequence[str], body: Mapping[str, Any], finding_rule_set_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """Dry run of unsaved scenario content (nothing is written)."""
    c = normalise({**body, "name": body.get("name") or "Unsaved scenario"})
    v = version(db, uuid.UUID(str(c["script_version_id"])), markets)
    sha, _ = content(db, v)
    rev = c | {"id": None, "script_content_sha256": sha}
    rules = rule_set_for(db, v["market_code"], markets, finding_rule_set_id)
    return execute_one(db, rev, v, persist=False, rules=rules) | {"version": v}


def plan_for(
    db: Session, markets: Sequence[str], version_id: uuid.UUID, facts: Mapping[str, Any], band: str | None
) -> tuple[qc.Plan, dict[str, Any], dict[str, Any]]:
    v = version(db, version_id, markets)
    sha, c = content(db, v)
    return build(c, v, sha, facts, band), v, live_eligibility(c)


def run_evaluation_results(db: Session, run: Mapping[str, Any], ctrl: qc.Controller) -> dict[str, str]:
    """Answer-evaluation results of an interactive run (for a generated baseline)."""
    from app.domain import simulation_evaluation as se

    results = ae.result_map(se.evaluate_controller(db, run, ctrl)[0])
    return {c: r for c, r in results.items() if r not in ("NOT_EVALUATED", "NOT_APPLICABLE")}


def scenario_from_run(
    db: Session, run: Mapping[str, Any], events: Sequence[Mapping[str, Any]], markets: Sequence[str]
) -> dict[str, Any]:
    """Structured scenario content reproducing an interactive run (responses differing from the default only) with
    expectations taken from its actual result. Not saved: the user reviews it first."""
    from app.domain import script_simulation as ss

    plan = ss.plan_from_json(run["plan"])
    snap = _one(db, "SELECT facts FROM policy_fact_snapshot WHERE id = :s", s=run["policy_fact_snapshot_id"])
    risk = (
        _one(db, "SELECT band_code FROM risk_assessment WHERE id = :r", r=run["risk_assessment_id"])
        if run["risk_assessment_id"]
        else None
    )
    steps: list[dict[str, Any]] = []
    current: str | None = None
    for e in events:
        t, code, d = e["event_type"], e["question_code"], e["data"] or {}
        if t == "QUESTION_REQUESTED":
            current = code
        elif t == "DELIVERY_RECORDED" and d.get("status") == "NOT_DELIVERED":
            steps.append({"question": code, "kind": "NOT_DELIVERED"})
        elif t == "ANSWER_RECEIVED":
            kind = d.get("answer_kind")
            pq = plan.question(code)
            if kind == "ANSWER" and d.get("value") == sr._default(pq):  # noqa: SLF001 - same module family
                continue
            steps.append({"question": code, "kind": kind, **({"value": d.get("value")} if kind == "ANSWER" else {})})
        elif t == "CLARIFICATION_REQUIRED" and str(d.get("reason", "")).startswith("CLARIFICATION:"):
            steps.append(
                {
                    "question": code,
                    "kind": "CLARIFICATION",
                    "note": str(d["reason"]).removeprefix("CLARIFICATION:").strip(),
                }
            )
        elif t == "CONVERSATION_EVENT" and current:
            steps.append({"question": current, "kind": "EVENT", "event": d.get("kind")})
    ctrl = qc.Controller(
        plan, [qc.Event(e["event_type"], e["question_code"], e["action_id"], e["data"] or {}) for e in events]
    )
    exp: dict[str, Any] = {}
    if ctrl.ended in sr.OUTCOMES:
        actual = sr.actual_of(ctrl)
        exp = {
            "outcome": actual["outcome"],
            "termination_reason": actual["termination_reason"] or "NONE",
            "gates": actual["gates"],
            "mandatory_complete": actual["mandatory_complete"],
            "sequence": actual["sequence"],
            "applicable_questions": actual["applicable"],
            "basis": "GENERATED_BASELINE",
        }
        ev = run_evaluation_results(db, run, ctrl)
        if ev:
            exp["evaluations"] = ev
    facts = {k: (snap["facts"] or {}).get(k) for k in FACT_KEYS if snap and (snap["facts"] or {}).get(k) is not None}
    return {
        "name": f"From {run['sim_ref']}",
        "description": f"Recorded from interactive run {run['sim_ref']} ({run['case_ref']})",
        "script_version_id": run["script_version_id"],
        "facts": facts,
        "risk_band": risk["band_code"] if risk else None,
        "source_case_id": run["callback_case_id"],
        "steps": steps,
        "expectations": exp,
        "default_response": "AFFIRMATIVE",
    }
