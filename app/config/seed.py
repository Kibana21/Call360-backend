"""Idempotent configuration seed (D-26, D-27). Used by migration 0002 and by BE-CFG-03.

Definitions for all ten Stage 0 lists; version-1 values for `market` only (synthetic). Governed business
values are seeded by CP0.2. No AIA-approved thresholds, classifications or rules are invented here.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import Connection, text

NS = uuid.UUID("5d6c0a2e-3b1f-4c9e-9a51-360000000002")
SEEDED_BY = "SYSTEM:migration-0002"

# (code, name, governed, description) — classification per S0_IDENTITY_ACCESS_DESIGN §8 (D-25).
LISTS = [
    (
        "market",
        "Market",
        False,
        "Synthetic markets. Labels are editable; the code set is fixed because codes become access scopes (CP0.1B-2).",
    ),
    (
        "sbq_risk_band",
        "SBQ risk band",
        True,
        "Callback-selection risk bands. Values seeded in CP0.2; business-governed.",
    ),
    (
        "risk_factor",
        "Risk factor",
        True,
        "SBQ risk-factor vocabulary (RISK-006). Values seeded in CP0.2; business-governed.",
    ),
    (
        "case_hold_reason",
        "Case hold reason",
        True,
        "Hold reasons and their blocking flag (ADR-0008 §2). Seeded in CP0.2.",
    ),
    ("case_closure_reason", "Closure reason", True, "Case closure reasons; values pending DEC-008. Seeded in CP0.2."),
    (
        "case_cancellation_reason",
        "Cancellation reason",
        True,
        "Cancellation reasons and SLA-exemption eligibility (SLA-EX-001). Seeded in CP0.2.",
    ),
    ("finding_materiality_policy", "Materiality", True, "Material finding severities and approved exceptions (K-2)."),
    ("kpi_sla_exemption_rule", "SLA exemption", True, "Approved SLA exemption rules (K-3, D-18)."),
    ("callable_party_roles", "Callable roles", True, "Party roles eligible to receive a callback (PARTY-004)."),
    (
        "synthetic_contact_ranges",
        "Synthetic contact ranges",
        True,
        "Reserved synthetic contact ranges enforced under DATA_POLICY=SYNTHETIC_ONLY (ADR-0008 §6).",
    ),
]
MARKET_VALUES = [("SG", "Singapore (synthetic)", 10), ("MY", "Malaysia (synthetic)", 20)]
# (code, description, stage_gate) — D-27. All disabled; none of these features exists in S0.
FLAGS = [
    ("voice.browser_sessions", "Browser voice sessions (GPT-Live)", "S1"),
    ("scripts.authoring", "Script authoring, review and publication", "S2"),
    ("reviews.decisions", "Compliance review decisions", "S3"),
    ("exports.evidence", "Evidence and report export", "S4"),
]


def _id(kind: str, code: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"{kind}:{code}")


def seed_config(conn: Connection, schema: str) -> None:
    assert schema in {"call360", "call360_test"}, schema
    s = schema
    for code, name, governed, desc in LISTS:
        conn.execute(
            text(
                f"INSERT INTO {s}.code_list (id, code, name, description, governed) "
                "VALUES (:id, :code, :name, :desc, :gov) ON CONFLICT (code) DO NOTHING"
            ),
            {"id": _id("list", code), "code": code, "name": name, "desc": desc, "gov": governed},
        )
    version_id = _id("version", "market:1")
    conn.execute(
        text(
            f"INSERT INTO {s}.code_list_version (id, code_list_id, version, status, effective_from, "
            "change_reason, created_by) VALUES (:id, (SELECT id FROM " + s + ".code_list WHERE code = "
            "'market'), 1, 'DRAFT', now(), :reason, :by) ON CONFLICT (id) DO NOTHING"
        ),
        {"id": version_id, "reason": "Initial synthetic market list (CP0.1B-1, D-26)", "by": SEEDED_BY},
    )
    for code, label, order in MARKET_VALUES:
        conn.execute(
            text(
                f"INSERT INTO {s}.code_value (id, code_list_version_id, code, label, attributes, sort_order) "
                f"SELECT :id, :v, :code, :label, CAST(:attrs AS jsonb), :ord WHERE EXISTS (SELECT 1 FROM "
                f"{s}.code_list_version WHERE id = :v AND status = 'DRAFT') ON CONFLICT (id) DO NOTHING"
            ),
            {
                "id": _id("value", f"market:1:{code}"),
                "v": version_id,
                "code": code,
                "label": label,
                "attrs": json.dumps({"synthetic": True}),
                "ord": order,
            },
        )
    conn.execute(
        text(
            f"UPDATE {s}.code_list_version SET status = 'ACTIVE', activated_at = now() "
            "WHERE id = :v AND status = 'DRAFT'"
        ),
        {"v": version_id},
    )
    for code, desc, gate in FLAGS:
        conn.execute(
            text(
                f"INSERT INTO {s}.feature_flag (id, code, description, enabled, stage_gate, updated_by) "
                "VALUES (:id, :code, :desc, false, :gate, :by) ON CONFLICT (code) DO NOTHING"
            ),
            {"id": _id("flag", code), "code": code, "desc": desc, "gate": gate, "by": SEEDED_BY},
        )
