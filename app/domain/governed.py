"""Governed code lists, version 1 (S0_DATA_MODEL §6.1; D-36, D-37). Seeded by migration 0007.

These are **synthetic development fixtures, not AIA-approved business rules**. No numeric risk threshold
and no regulatory interpretation is defined. Closure reasons remain pending DEC-008. A callable role is
only a candidate: it never establishes verified authority or consent (D-36).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

NS = uuid.UUID("5d6c0a2e-3b1f-4c9e-9a51-360000000007")
CREATED_BY = "SYSTEM:seed"
EFFECTIVE_FROM = datetime(2025, 11, 14, 16, 0, tzinfo=UTC)  # 2025-11-15 00:00 Asia/Singapore (anchor - 365 days)
REASON = "CP0.2 version 1: synthetic development fixtures (D-36), not AIA-approved business rules"
REMOVAL_REASON = "Migration 0007 downgrade (development only): governed version 1 removed"
REFERENCE_DATA_VERSION = "0007_governed_values"
AUDIT_ACTOR = "migration:0007_governed_values"
ACTIVATED = "CONFIG.CODE_LIST_VERSION_ACTIVATED"  # same action as the CP0.1B-1 API (S0_IDENTITY_ACCESS_DESIGN §8)
REMOVED = "CONFIG.CODE_LIST_VERSION_REMOVED"
SYN = {"synthetic": True}

# list code -> [(code, label, attributes)]
VALUES: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "sbq_risk_band": [
        ("LOW", "Low (synthetic)", {}),
        ("MEDIUM", "Medium (synthetic)", {}),
        ("HIGH", "High (synthetic)", {}),
        ("UNKNOWN", "Unknown (synthetic)", {}),
    ],
    "risk_factor": [
        ("SELLING_CHANNEL", "Selling channel", {"value_type": "ENUM"}),
        ("SELLING_LOCATION", "Selling location", {"value_type": "ENUM"}),
        ("PREMIUM_AMOUNT_BAND", "Premium amount band (source-supplied label)", {"value_type": "ENUM"}),
        ("PRODUCT_CLASS", "Product class", {"value_type": "ENUM"}),
        ("ILP_INDICATOR", "Investment-linked indicator", {"value_type": "BOOLEAN"}),
    ],
    "case_hold_reason": [
        ("AWAITING_SCRIPT_ASSIGNMENT", "Awaiting script assignment", {"blocking": True}),
        ("AWAITING_SCRIPT_REVIEW", "Awaiting script review", {"blocking": True}),
        ("RISK_TRIAGE", "Risk triage", {"blocking": True}),
        ("NO_ELIGIBLE_CONTACT", "No eligible contact", {"blocking": True}),
        ("DATA_CONFLICT", "Data conflict", {"blocking": True}),
        ("OPERATOR_HOLD", "Operator hold", {"blocking": False}),
    ],
    "case_closure_reason": [
        ("ATTEMPTS_EXHAUSTED", "Attempts exhausted", {"pending": "DEC-008"}),
        ("CUSTOMER_REFUSED", "Customer refused", {"pending": "DEC-008"}),
        ("INELIGIBLE", "Ineligible", {"pending": "DEC-008"}),
        ("UNABLE_TO_VERIFY", "Unable to verify", {"pending": "DEC-008"}),
        ("UNRESOLVED_MATERIAL_EXCEPTION", "Unresolved material exception", {"pending": "DEC-008"}),
        ("POLICY_CANCELLED", "Policy cancelled", {"pending": "DEC-008"}),
        ("DUPLICATE_OBLIGATION", "Duplicate obligation", {"pending": "DEC-008"}),
    ],
    "case_cancellation_reason": [
        ("POLICY_NOT_TAKEN_UP", "Policy not taken up", {"sla_exempt_eligible": True}),
        ("POLICY_FREE_LOOK_CANCELLED", "Cancelled in free-look period", {"sla_exempt_eligible": True}),
        ("DUPLICATE_OBLIGATION", "Duplicate obligation", {"sla_exempt_eligible": True}),
        ("SOURCE_WITHDRAWN", "Source request withdrawn", {"sla_exempt_eligible": False}),
        ("OTHER", "Other", {"sla_exempt_eligible": False}),
    ],
    "finding_materiality_policy": [
        ("HIGH", "High severity is material (provisional, K-2)", {"material": True}),
        ("CRITICAL", "Critical severity is material (provisional, K-2)", {"material": True}),
    ],
    "kpi_sla_exemption_rule": [
        (
            "SLA-EX-001",
            "Authorised cancellation recorded before due date",
            {
                "predicate_ref": "S0_KPI_DEFINITIONS SLA-EX-001",
                "approval_ref": "Owner decision D-18 (local development)",
                "effective_from": "2025-11-15",
            },
        ),
    ],
    "callable_party_roles": [
        ("OWNER", "Policy owner", {"callable": True, "requires_authorization_evidence": False}),
        ("AUTHORIZED_CONTACT", "Authorised contact", {"callable": True, "requires_authorization_evidence": True}),
        ("INSURED", "Insured person", {"callable": False}),
        ("PAYER", "Payer", {"callable": False}),
        ("PROPOSER", "Proposer", {"callable": False}),
        ("BENEFICIARY", "Beneficiary", {"callable": False}),
    ],
    "synthetic_contact_ranges": [
        (
            "PHONE_SYNTHETIC_ID",
            "Non-dialable synthetic phone identifier",
            {"channel": "PHONE", "pattern": r"^SYN-TEL-(SG|MY)-[0-9]{6}$", "dialable": False},
        ),
        (
            "EMAIL_EXAMPLE_INVALID",
            "Undeliverable example.invalid address",
            {"channel": "EMAIL", "pattern": r"^[a-z0-9.]+@example\.invalid$", "dialable": False},
        ),
    ],
}


def version_id(list_code: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"version:{list_code}:1")


def value_id(list_code: str, code: str) -> uuid.UUID:
    return uuid.uuid5(NS, f"value:{list_code}:1:{code}")


def _snapshot(list_code: str) -> list[dict[str, Any]]:
    """Same shape as the CP0.1B-1 API audit snapshot (app.config.service._snapshot)."""
    return [
        {"code": code, "label": label, "attributes": {**attrs, **SYN}, "sort_order": order * 10}
        for order, (code, label, attrs) in enumerate(VALUES[list_code], start=1)
    ]


def _latest_lifecycle_action(conn: Connection, schema: str, list_code: str) -> str | None:
    return conn.execute(
        text(
            f"SELECT action FROM {schema}.audit_event WHERE entity_type = 'code_list' AND entity_id = :list "
            "AND action = ANY(:actions) AND :vid IN (after ->> 'version_id', before ->> 'version_id') "
            "ORDER BY seq DESC LIMIT 1"
        ),
        {"list": list_code, "actions": [ACTIVATED, REMOVED], "vid": str(version_id(list_code))},
    ).scalar()


def _audit(conn: Connection, list_code: str, action: str) -> None:
    from sqlalchemy.orm import Session  # local: keep the module importable by migrations without ORM setup

    from app.audit.chain import Actor, write_audit

    state = {
        "version": 1,
        "version_id": str(version_id(list_code)),
        "reference_data_version": REFERENCE_DATA_VERSION,
        "values": _snapshot(list_code),
    }
    activated = action == ACTIVATED
    write_audit(
        Session(bind=conn),
        action=action,
        outcome="SUCCEEDED",
        actor=Actor(service=AUDIT_ACTOR),
        entity_type="code_list",
        entity_id=list_code,
        entity_version=1,
        reason=REASON if activated else REMOVAL_REASON,
        before=None if activated else state,
        after=state if activated else None,
    )


def audit_governed(conn: Connection, schema: str) -> int:
    """Bootstrap audit (idempotent): one CONFIG.CODE_LIST_VERSION_ACTIVATED event per governed version 1 that is
    present but whose latest lifecycle event is not an activation. Re-running writes nothing; a downgrade
    records CONFIG.CODE_LIST_VERSION_REMOVED, so a later re-upgrade is audited again. Returns events written."""
    assert schema in {"call360", "call360_test"}, schema
    written = 0
    for list_code in VALUES:
        present = conn.execute(
            text(f"SELECT 1 FROM {schema}.code_list_version WHERE id = :v AND status = 'ACTIVE'"),
            {"v": version_id(list_code)},
        ).scalar()
        if present and _latest_lifecycle_action(conn, schema, list_code) != ACTIVATED:
            _audit(conn, list_code, ACTIVATED)
            written += 1
    return written


def audit_governed_removal(conn: Connection, schema: str) -> None:
    """Record the removal of each governed version 1 before a (development-only) downgrade deletes it."""
    assert schema in {"call360", "call360_test"}, schema
    for list_code in VALUES:
        if _latest_lifecycle_action(conn, schema, list_code) == ACTIVATED:
            _audit(conn, list_code, REMOVED)


def seed_governed(conn: Connection, schema: str) -> None:
    """Insert version 1 of each governed list as DRAFT, add its values, activate it, and audit the activation
    (audit_governed). Idempotent: existing versions and their audit events are left as they are."""
    assert schema in {"call360", "call360_test"}, schema
    for list_code, values in VALUES.items():
        vid = version_id(list_code)
        exists = conn.execute(text(f"SELECT 1 FROM {schema}.code_list_version WHERE id = :v"), {"v": vid}).scalar()
        if exists:
            continue
        conn.execute(
            text(
                f"INSERT INTO {schema}.code_list_version (id, code_list_id, version, status, effective_from, "
                "change_reason, created_by) SELECT :v, id, 1, 'DRAFT', :eff, :reason, :by "
                f"FROM {schema}.code_list WHERE code = :list AND governed"
            ),
            {"v": vid, "eff": EFFECTIVE_FROM, "reason": REASON, "by": CREATED_BY, "list": list_code},
        )
        for order, (code, label, attrs) in enumerate(values, start=1):
            conn.execute(
                text(
                    f"INSERT INTO {schema}.code_value (id, code_list_version_id, code, label, attributes, sort_order) "
                    "VALUES (:id, :v, :code, :label, CAST(:attrs AS jsonb), :ord)"
                ),
                {
                    "id": value_id(list_code, code),
                    "v": vid,
                    "code": code,
                    "label": label,
                    "attrs": json.dumps({**attrs, **SYN}, sort_keys=True),
                    "ord": order * 10,
                },
            )
        conn.execute(
            text(f"UPDATE {schema}.code_list_version SET status = 'ACTIVE', activated_at = now() WHERE id = :v"),
            {"v": vid},
        )
    audit_governed(conn, schema)
