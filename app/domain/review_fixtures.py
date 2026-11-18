"""S3-C synthetic operational fixtures for testing the review workflow (explicitly synthetic; never a real contact).

``build`` records one **scripted synthetic conversation** as operational evidence on a synthetic case, the same way the
S0 seed records its synthetic conversations: a contact attempt and conversation session with transport ``SYNTHETIC``
and record origin ``SYNTHETIC_SEED`` (never ``BROWSER``/``CALL360_RUNTIME``), authored by ``SYSTEM:s3c-fixture`` (so
the S0 seed digest is unchanged), a completed survey run over the case's pinned published script and fact snapshot,
question executions and answer observations from the given structured answers, S3-A rule evaluations, and S3-B
findings from the **published** finding rule set. The case moves to ``AWAITING_REVIEW``.

It is not simulation output: simulation runs and simulated findings are never converted into operational records, and
no real (browser) voice session is evaluated. Refuses a non-synthetic or terminal case, or one without a pinned
published script. Run only through the ``call360 review-fixture`` command (development / test), never an API.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.domain import answer_evaluation as ae
from app.domain import finding_engine as fe
from app.domain import finding_rules as fr
from app.domain import lifecycle as lc
from app.domain import question_controller as qc
from app.domain import script_authoring
from app.domain import simulation_findings as sf
from app.voice.store import pins_for

FIXTURE_BY = "SYSTEM:s3c-fixture"
SOURCE_SYSTEM = "CALL360-S3C-FIXTURE"
NON_ANSWERS = ("REFUSED", "UNKNOWN", "UNCLEAR", "NOT_ASKED")
OPEN_STATES = ("VALIDATED", "READY", "IN_PROGRESS", "AWAITING_CALLBACK", "AWAITING_REVIEW")
LABEL = "Synthetic S3-C review fixture (scripted structured answers; not a customer contact or a voice session)"


class FixtureError(Exception):
    pass


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _prov(ref: str, now: datetime) -> dict[str, Any]:
    return {
        "created_by": FIXTURE_BY,
        "source_type": "SEED",
        "source_system": SOURCE_SYSTEM,
        "source_reference": ref[:160],
        "source_observed_at": now,
        "recorded_at": now,
        "is_synthetic": True,
        "record_origin": "SYNTHETIC_SEED",
    }


def _insert(db: Session, table: str, cols: Mapping[str, Any], json_cols: tuple[str, ...] = ()) -> None:
    names = list(cols)
    vals = ", ".join(f"CAST(:{n} AS jsonb)" if n in json_cols else f":{n}" for n in names)
    db.execute(
        text(f"INSERT INTO {table} ({', '.join(names)}) VALUES ({vals})"),  # noqa: S608 - fixed identifiers
        {n: (json.dumps(cols[n], default=str) if n in json_cols and cols[n] is not None else cols[n]) for n in names},
    )


def _default(pq: qc.PlannedQuestion, rule: ae.Rule, facts: Mapping[str, Any]) -> Any:
    """The correct (expected) answer for an item without a scripted answer."""
    e = dict(rule.expected or {})
    if pq.answer_type in ("YES_NO", "ACKNOWLEDGEMENT"):
        return bool(e.get("value", True)) if rule.method == "EXACT_BOOLEAN" else True
    if pq.answer_type == "NUMERIC":
        if rule.method == "NUMERIC_MATCH_POLICY_FACT" and facts.get(rule.fact_key or "") is not None:
            return float(facts[rule.fact_key or ""]) * (12 if e.get("unit") == "MONTHS" else 1)
        return float(e.get("value") or 1)
    if pq.answer_type == "ENUM":
        if rule.method == "ENUM_MATCH_POLICY_FACT" and facts.get(rule.fact_key or "") in pq.options:
            return facts[rule.fact_key or ""]
        if rule.method == "ENUM_MATCH":
            return (e.get("accepted") or [pq.options[0]])[0]
        return pq.options[0] if pq.options else None
    return "Synthetic fixture answer"


def build(db: Session, case_ref: str, answers: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Record one scripted synthetic conversation on ``case_ref``. ``answers``: question code → a typed value, or one
    of REFUSED / UNKNOWN / UNCLEAR / NOT_ASKED. Unlisted items get the expected answer (statements are delivered)."""
    answers = dict(answers or {})
    c = _one(db, "SELECT * FROM callback_case WHERE case_ref = :r FOR UPDATE", r=case_ref)
    if c is None:
        raise FixtureError(f"{case_ref} not found")
    if not c["is_synthetic"]:
        raise FixtureError("Fixtures are recorded on explicitly synthetic cases only")
    if c["state"] not in OPEN_STATES:
        raise FixtureError(f"{case_ref} is {c['state']}; fixtures need an open case")
    pins = pins_for(db, c["id"])
    if pins is None:
        raise FixtureError(f"{case_ref} has no pinned published script, final risk assessment and fact snapshot")
    v = _one(
        db,
        "SELECT v.*, f.code AS family FROM script_version v JOIN script_family f ON f.id = v.script_family_id "
        "WHERE v.id = :v",
        v=pins.script_version_id,
    )
    assert v is not None
    content = script_authoring.content_of(db, v)
    snap = _one(db, "SELECT facts FROM policy_fact_snapshot WHERE id = :f", f=pins.policy_fact_snapshot_id)
    band = _one(db, "SELECT band_code FROM risk_assessment WHERE id = :r", r=pins.risk_assessment_id)
    facts = dict((snap or {}).get("facts") or {})
    plan = qc.build_plan(
        content,
        script_label=f"{v['family']} v{v['version_label']}",
        manifest_sha256=pins.script_manifest_sha256,
        facts=facts,
        band=(band or {}).get("band_code"),
    )
    unknown = sorted(set(answers) - {q.code for q in plan.questions})
    if unknown:
        raise FixtureError(f"Not in the pinned script: {', '.join(unknown)}")
    sel = _one(
        db,
        "SELECT s.party_id, s.contact_method_id, m.channel, m.masked_value, m.valid_from FROM case_contact_selection s "
        "LEFT JOIN contact_method m ON m.id = s.contact_method_id WHERE s.callback_case_id = :c AND s.eligible "
        "AND NOT EXISTS (SELECT 1 FROM case_contact_selection x WHERE x.supersedes_id = s.id) ORDER BY s.decided_at "
        "LIMIT 1",
        c=c["id"],
    )
    if sel is None:
        raise FixtureError(f"{case_ref} has no eligible callback contact")
    now = datetime.now(UTC)
    # The conversation lies inside [t0, now]; it starts after the pinned version became published and effective
    # (INV-09), and at most 20 minutes ago.
    eff = max(x for x in (v["published_at"], v["effective_from"], now - timedelta(minutes=20)) if x is not None)
    t0 = eff + timedelta(milliseconds=10)
    span = now - t0

    def at(frac: float) -> datetime:
        return t0 + span * frac

    seq = db.execute(
        text("SELECT coalesce(max(sequence), 0) + 1 FROM contact_attempt WHERE callback_case_id = :c"), {"c": c["id"]}
    ).scalar_one()
    ref = f"{case_ref.removeprefix('CB-')}-{seq}"
    snapshot = {
        "contact_method_id": str(sel["contact_method_id"]) if sel["contact_method_id"] else None,
        "channel": sel["channel"],
        "masked_value": sel["masked_value"],
        "method_valid_from": sel["valid_from"].isoformat() if sel["valid_from"] else None,
        "fixture": LABEL,
    }
    aid, sid, rid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    _insert(
        db,
        "contact_attempt",
        {
            "id": aid,
            "attempt_ref": f"AT-{ref}",
            "callback_case_id": c["id"],
            "sequence": seq,
            "transport": "SYNTHETIC",
            "direction": "OUTBOUND",
            "status": "ENDED",
            "contacted_party_id": sel["party_id"],
            "contact_method_id": sel["contact_method_id"],
            "contact_snapshot": snapshot,
            "scheduled_at": t0,
            "started_at": t0,
            "ended_at": at(0.95),
            **_prov(f"s3c-fixture:attempt:{ref}", now),
        },
        ("contact_snapshot",),
    )
    _insert(
        db,
        "conversation_session",
        {
            "id": sid,
            "session_ref": f"SS-{ref}",
            "contact_attempt_id": aid,
            "state": "FINALIZED",
            "transport": "SYNTHETIC",
            "started_at": at(0.05),
            "ended_at": at(0.9),
            "script_version_id": pins.script_version_id,
            "script_manifest_sha256": pins.script_manifest_sha256,
            "risk_assessment_id": pins.risk_assessment_id,
            "risk_snapshot_sha256": pins.risk_snapshot_sha256,
            "policy_fact_snapshot_id": pins.policy_fact_snapshot_id,
            "policy_fact_snapshot_sha256": pins.policy_fact_snapshot_sha256,
            "contacted_party_id": sel["party_id"],
            "contact_method_snapshot": snapshot,
            "media_status": "NOT_REQUIRED",
            "transcript_status": "UNAVAILABLE",
            **_prov(f"s3c-fixture:session:{ref}", now),
        },
        ("contact_method_snapshot",),
    )
    rules = ae.rules_of(content)
    source = ae.FactSource(
        "POLICY_FACT_SNAPSHOT", str(pins.policy_fact_snapshot_id), pins.policy_fact_snapshot_sha256, facts
    )
    evaluations: list[dict[str, Any]] = []
    executions: dict[str, uuid.UUID] = {}
    unresolved_mandatory = False
    pos = 0
    for pq in plan.questions:
        if not pq.applicable:
            continue
        rule = rules.get(pq.code) or ae.Rule(
            pq.code, pq.revision_id, pq.revision, "COLLECT_ONLY", pq.answer_type, pq.options, None, None
        )
        spec = answers.get(pq.code, None)
        pos += 1
        qe = uuid.uuid4()
        executions[pq.code] = qe
        evaluations.append({"pq": pq, "rule": rule, "spec": spec, "qe": qe, "pos": pos})
    _insert(
        db,
        "survey_run",
        {
            "id": rid,
            "session_id": sid,
            "script_version_id": pins.script_version_id,
            "script_manifest_sha256": pins.script_manifest_sha256,
            "policy_fact_snapshot_id": pins.policy_fact_snapshot_id,
            "status": "IN_PROGRESS",
            "started_at": at(0.1),
            **_prov(f"s3c-fixture:run:{ref}", now),
        },
    )
    results: list[dict[str, Any]] = []
    for item in evaluations:
        pq, rule, spec, qe, pos = item["pq"], item["rule"], item["spec"], item["qe"], item["pos"]
        not_asked = spec == "NOT_ASKED"
        _insert(
            db,
            "question_execution",
            {
                "id": qe,
                "survey_run_id": rid,
                "question_revision_id": uuid.UUID(pq.revision_id),
                "position": pos,
                "delivery_status": "NOT_DELIVERED" if not_asked else "DELIVERED",
                "retries": 1 if spec == "UNCLEAR" else 0,
                "event_range": {"transcript": "NOT_AVAILABLE", "fixture": True},
                **_prov(f"s3c-fixture:qe:{ref}:{pos}", now),
            },
            ("event_range",),
        )
        if pq.completes_on_delivery:
            kind, value, state, status = "ANSWER", True, "YES", "COMPLETED"
        elif spec in NON_ANSWERS:
            kind, value = ("UNCLEAR" if spec == "UNCLEAR" else spec), None
            state = "NOT_ASKED" if not_asked else spec
            status = "PENDING" if not_asked else "UNRESOLVED"
            unresolved_mandatory = unresolved_mandatory or pq.mandatory
        else:
            kind = "ANSWER"
            value = spec if spec is not None else _default(pq, rule, facts)
            value = qc._validate(pq, value)  # noqa: SLF001 - the controller's own typed validation
            state = "YES" if value is True else "NO" if value is False else "YES"
            status = "COMPLETED"
        typed = (
            None
            if kind != "ANSWER"
            else ({"acknowledged": value} if pq.answer_type == "ACKNOWLEDGEMENT" else {"value": value})
        )
        _insert(
            db,
            "answer_observation",
            {
                "id": uuid.uuid4(),
                "question_execution_id": qe,
                "answer_state": state,
                "typed_value": typed,
                "verbatim_text_redacted": None if kind != "ANSWER" else f"[synthetic fixture] {value}",
                "extraction_engine": "S3C_FIXTURE",
                "extraction_version": "structured-1",
                **_prov(f"s3c-fixture:obs:{ref}:{pos}", now),
            },
            ("typed_value",),
        )
        if pq.completes_on_delivery:
            continue
        answer = {"answer_kind": kind, "value": value, "answer_state": state}
        ev = ae.evaluate_one(
            rule, status, True, None, None if not_asked else answer, kind if kind != "ANSWER" else None, source
        ) | {"stage": pq.stage, "role": pq.role, "mandatory": pq.mandatory, "wording": pq.wording}
        results.append(ev)
        if rule.method == "COLLECT_ONLY":
            continue
        _insert(
            db,
            "rule_evaluation",
            {
                "id": uuid.uuid4(),
                "question_execution_id": qe,
                "rule_ref": f"S3A-{rule.method}"[:60],
                "rule_version": "answer-evaluation/1",
                "expected": ev.get("expected") or {"rule": ev.get("rule_text")},
                "observed": {
                    "value": ev.get("normalized_answer"),
                    "answer": ev.get("answer"),
                    "result": ev["result"],
                    "explanation": ev["explanation"],
                },
                "result": ev["rule_evaluation_equivalent"],
                "evaluated_at": at(0.97),
                **_prov(f"s3c-fixture:re:{ref}:{pos}", now),
            },
            ("expected", "observed"),
        )
    db.execute(
        text("UPDATE survey_run SET status = :s, completed_at = :t WHERE id = :r"),
        {
            "s": "INCOMPLETE" if unresolved_mandatory else "COMPLETED",
            "t": None if unresolved_mandatory else at(0.85),
            "r": rid,
        },
    )
    # Findings: the published finding rule set only (approved severities).
    published = fr.published(db, c["market_code"])
    created: list[str] = []
    if published is not None:
        rs = fr.rule_set(published)
        g = fe.generate(
            results,
            content,
            rs,
            {
                "execution_ref": f"SS-{ref}",
                "case_ref": case_ref,
                "script_label": f"{v['family']} v{v['version_label']}",
                "script_version_id": str(v["id"]),
                "content_sha256": pins.script_manifest_sha256,
                "evaluation_engine": ae.ENGINE,
                "fact_source": source.as_dict(),
            },
        )
        for f in g.findings:
            fid, _ = sf.persist_operational(db, f, executions[f["question_code"]], FIXTURE_BY)
            ref_ = db.execute(text("SELECT finding_ref FROM finding WHERE id = :f"), {"f": fid}).scalar_one()
            created.append(ref_)
    before = c["state"]
    db.execute(
        text(
            "UPDATE callback_case SET state = 'AWAITING_REVIEW', updated_at = now(), updated_by = :by, "
            "row_version = row_version + 1 WHERE id = :c"
        ),
        {"by": FIXTURE_BY, "c": c["id"]},
    )
    for kind, summary in (
        ("SESSION_RECORDED", f"{LABEL}: session SS-{ref}"),
        ("FINDINGS_GENERATED", f"S3-B engine findings from the published rule set: {', '.join(created) or 'none'}"),
        ("STATE_CHANGED", f"{before} → AWAITING_REVIEW (synthetic fixture recorded)"),
    ):
        db.execute(
            text(
                "INSERT INTO case_event (id, callback_case_id, event_type, occurred_at, actor_ref, "
                "related_entity_type, "
                "related_entity_id, summary, created_by) VALUES (:i, :c, :k, now(), :by, 'conversation_session', :s, "
                ":sum, :by)"
            ),
            {"i": uuid.uuid4(), "c": c["id"], "k": kind, "by": FIXTURE_BY, "s": sid, "sum": summary},
        )
    return {
        "case_ref": case_ref,
        "attempt_ref": f"AT-{ref}",
        "session_ref": f"SS-{ref}",
        "survey_run_id": str(rid),
        "evaluations": ae.totals(results),
        "findings": created,
        "rule_set": fr.label(published) if published else None,
        "state": "AWAITING_REVIEW",
        "identity_items": [q.code for q in plan.questions if q.role in lc.YES_NO_ROLES[:1]],
    }
