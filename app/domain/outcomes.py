"""Case outcome categories and mandatory-control satisfaction (S0_KPI_DEFINITIONS §1, §1.1; D-17).

Derived from persisted data only. In S0 a NARRATIVE_REVIEW control can never be satisfied (review decisions
arrive in S3), so a case with an applicable mandatory narrative question cannot be VERIFIED_COMPLIANT.
NOT_VERIFIED and CANCELLED describe the callback verification, never the insurance sale.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

TERMINAL_UNANSWERED = {"NOT_ASKED", "REFUSED", "UNKNOWN"}
EVIDENCE_INCOMPLETE = "VERIFIED_CONTROL_EVIDENCE_INCOMPLETE"


def condition_holds(cond: dict[str, Any] | None, facts: dict[str, Any], band: str | None) -> bool:
    """Evaluate the small S0 predicate language: ``{"fact": k, "equals": v}``, ``{"risk_band_in": [..]}``,
    ``{"all": [..]}``. ``None`` is always true."""
    if cond is None:
        return True
    if "all" in cond:
        return all(condition_holds(c, facts, band) for c in cond["all"])
    if "risk_band_in" in cond:
        return band in cond["risk_band_in"]
    if "fact" in cond:
        return bool(facts.get(cond["fact"]) == cond["equals"])
    raise ValueError(f"unsupported condition {cond!r}")


@dataclass(frozen=True)
class Outcome:
    case_ref: str
    state: str
    category: str  # VERIFIED_COMPLIANT | VERIFIED_WITH_FINDINGS | NOT_VERIFIED | CANCELLED | OPEN | guard
    controls_satisfied: bool
    open_findings: int


def _satisfied(policy: str, state: str | None, rule_result: str | None) -> bool:
    if state is None or state in TERMINAL_UNANSWERED or state == "UNCLEAR":
        return False
    if policy in {
        "EXACT_BOOLEAN",
        "NUMERIC_MATCH_POLICY_FACT",
        "NUMERIC_COMPARE",
        "ENUM_MATCH",
        "ENUM_MATCH_POLICY_FACT",
    }:  # S3-A methods: satisfied only by a deterministic MATCH
        return rule_result == "MATCH"
    if policy == "ACKNOWLEDGEMENT":
        return state == "YES" and rule_result == "MATCH"
    if policy == "COLLECT_ONLY":
        return True
    return False  # NARRATIVE_REVIEW: needs a human review disposition (S3)


def controls_satisfied(conn: Connection, schema: str, run_id: uuid.UUID | None) -> bool:
    """§1.1 on the verifying run: every applicable mandatory question in its frozen manifest is satisfied."""
    if run_id is None:
        return False
    run = conn.execute(
        text(
            f"SELECT v.manifest, pfs.facts, ra.band_code FROM {schema}.survey_run r "  # noqa: S608
            f"JOIN {schema}.conversation_session cs ON cs.id = r.session_id "
            f"JOIN {schema}.script_version v ON v.id = r.script_version_id "
            f"JOIN {schema}.policy_fact_snapshot pfs ON pfs.id = r.policy_fact_snapshot_id "
            f"JOIN {schema}.risk_assessment ra ON ra.id = cs.risk_assessment_id WHERE r.id = :r"
        ),
        {"r": run_id},
    ).one()
    evidence = {
        row.question_revision_id: (row.answer_state, row.result)
        for row in conn.execute(
            text(
                "SELECT qe.question_revision_id, "  # noqa: S608
                f"(SELECT ao.answer_state FROM {schema}.answer_observation ao WHERE ao.question_execution_id = qe.id "
                f"  AND NOT EXISTS (SELECT 1 FROM {schema}.answer_observation x WHERE x.supersedes_id = ao.id) "
                "  ORDER BY ao.created_at DESC LIMIT 1) AS answer_state, "
                f"(SELECT re.result FROM {schema}.rule_evaluation re WHERE re.question_execution_id = qe.id "
                "  ORDER BY re.evaluated_at DESC LIMIT 1) AS result "
                f"FROM {schema}.question_execution qe WHERE qe.survey_run_id = :r"
            ),
            {"r": run_id},
        )
    }
    for q in applicable_mandatory(run.manifest, run.facts, run.band_code):
        state, result = evidence.get(uuid.UUID(q["question_revision_id"]), (None, None))
        if not _satisfied(q["expected_answer_policy"], state, result):
            return False
    return True


def applicable_mandatory(manifest: dict[str, Any], facts: dict[str, Any], band: str | None) -> list[dict[str, Any]]:
    """§1.1: mandatory questions of the included sections whose not-applicable predicate does not hold."""
    out = []
    for section in manifest["sections"]:
        if not condition_holds(section["inclusion_condition"], facts, band):
            continue
        for q in section["questions"]:
            if q["mandatory"] and not condition_holds_na(q.get("not_applicable_predicate"), facts, band):
                out.append(q)
    return out


def question_satisfied(policy: str, state: str | None, rule_result: str | None) -> bool:
    """Public form of the §1.1 per-question test, for read-only display (Call Detail)."""
    return _satisfied(policy, state, rule_result)


def condition_holds_na(pred: dict[str, Any] | None, facts: dict[str, Any], band: str | None) -> bool:
    return pred is not None and condition_holds(pred, facts, band)


def derive_outcomes(conn: Connection, schema: str, markets: Sequence[str] | None = None) -> dict[str, Outcome]:
    """Outcome per case. With ``markets`` the cases are filtered in SQL first (scope before aggregation)."""
    assert schema in {"call360", "call360_test"}, schema
    rows = conn.execute(
        text(
            "SELECT c.case_ref, c.state, "  # noqa: S608
            f"(SELECT count(*) FROM {schema}.finding f WHERE f.callback_case_id = c.id AND f.status <> 'DISMISSED') "
            "  AS open_findings, "
            f"(SELECT r.id FROM {schema}.survey_run r JOIN {schema}.conversation_session cs ON cs.id = r.session_id "
            f"  JOIN {schema}.contact_attempt a ON a.id = cs.contact_attempt_id "
            "  WHERE a.callback_case_id = c.id AND r.status = 'COMPLETED' ORDER BY r.completed_at DESC LIMIT 1) "
            f"  AS verifying_run FROM {schema}.callback_case c"
            + (" WHERE c.market_code = ANY(:m)" if markets is not None else "")
        ),
        {"m": list(markets or [])},
    ).all()
    out: dict[str, Outcome] = {}
    for r in rows:
        satisfied = controls_satisfied(conn, schema, r.verifying_run) if r.state == "VERIFIED" else False
        if r.state == "VERIFIED":
            category = (
                "VERIFIED_WITH_FINDINGS"
                if r.open_findings
                else ("VERIFIED_COMPLIANT" if satisfied else EVIDENCE_INCOMPLETE)
            )
        elif r.state == "CLOSED_UNVERIFIED":
            category = "NOT_VERIFIED"
        elif r.state == "CANCELLED":
            category = "CANCELLED"
        else:
            category = "OPEN"
        out[r.case_ref] = Outcome(r.case_ref, r.state, category, satisfied, int(r.open_findings))
    return out
