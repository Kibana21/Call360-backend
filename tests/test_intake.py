"""CP0.4a manual transaction intake (API-080, API-082…085): BE-ING-02 (idempotent replay), BE-ING-03 (MANUAL records
with actor, reason, source; duplicate source event rejected), BE-ING-04 (validation with field details; preview
persists nothing), BE-ING-06 (USER → 403, audited), BE-ING-08 (ineligible contact → reason and hold), BE-ING-09 (ILP
without risk → RISK_TRIAGE), BE-ING-10 (AWAITING_SCRIPT_ASSIGNMENT; routing not evaluated), BE-SEC-02 (SG only),
GOV-001 (synthetic only), encryption/masking/audit integrity, existing-policy reuse and material-field conflicts,
visibility through the existing read APIs, and the seed digest proving seeded rows are unchanged.

Intake commits real rows, so the module restores a freshly seeded test schema when it finishes."""

from __future__ import annotations

import copy
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.digest import content_digest
from app.domain.intake import SYNTHETIC_PRODUCTS
from app.domain.protection import DataProtection, aad
from app.domain.seed import _manifest_event, seed
from tests.domain_support import SCHEMA
from tests.support import Account, csrf_header, login, make_account, reset_test_schema

pytestmark = pytest.mark.usefixtures("seeded")
NOW = datetime.now(UTC).replace(microsecond=0)
PATH = "/api/v1/intake/manual"


@pytest.fixture(scope="module", autouse=True)
def restore_seed(engine: Engine, settings: Settings) -> Iterator[None]:
    yield
    reset_test_schema(engine, settings)
    with engine.begin() as c:
        seed(c, settings.target_schema, DataProtection.from_settings(settings))


@pytest.fixture()
def signed_in(client: TestClient, admin: Account) -> TestClient:
    login(client, admin)
    return client


def scalar(db: Session, sql: str, **p: Any) -> Any:
    return db.execute(text(sql), p).scalar()


def txn(**over: Any) -> dict[str, Any]:
    """A valid synthetic Singapore transaction with unique references."""
    n = uuid.uuid4().int % 90000 + 900000
    sold = NOW - timedelta(days=2)
    body: dict[str, Any] = {
        "is_synthetic": True,
        "source_system": "SYN-POLICY-ADMIN",
        "source_event_id": f"SYN-EVT-{uuid.uuid4().hex[:12]}",
        "source_observed_at": (NOW - timedelta(hours=1)).isoformat(),
        "reason": "Synthetic intake test",
        "policy": {
            "policy_ref": f"POL-SG-{n}",
            "market_code": "SG",
            "product_code": "SYN-PROT-TERM",
            "product_family": "PROTECTION",
            "product_subtype": "TERM_LIFE",
            "status": "IN_FORCE",
            "premium_amount": "250.00",
            "currency": "SGD",
            "premium_frequency": "MONTHLY",
            "premium_term_years": 20,
            "sum_assured": "300000.00",
            "sum_assured_currency": "SGD",
            "effective_from": (sold + timedelta(days=1)).isoformat(),
        },
        "sale": {
            "sale_ref": f"SALE-SG-{n}",
            "sale_event_type": "NEW_BUSINESS",
            "sold_at": sold.isoformat(),
            "fsc_ref": "FSC-0001",
            "selling_channel": "AGENCY",
            "selling_location": "SYN-BRANCH-01",
            "proposal_ref": f"PRP-{n}",
            "premium_amount": "250.00",
            "currency": "SGD",
            "premium_amount_band": "BAND_A",
        },
        "parties": [
            {
                "kind": "PERSON",
                "name": f"Example Intake Holder {n}",
                "date_of_birth_year": 1984,
                "roles": ["OWNER", "PROPOSER", "PAYER", "INSURED"],
                "contacts": [
                    {"channel": "PHONE", "value": f"SYN-TEL-SG-{n}", "consent_status": "GRANTED"},
                    {
                        "channel": "EMAIL",
                        "value": f"example.intake.{n}@example.invalid",
                        "consent_status": "GRANTED",
                        "preference_rank": 2,
                    },
                ],
            }
        ],
        "source_risk": {
            "band_code": "HIGH",
            "source_original_value": "SBQ-H",
            "status": "FINAL",
            "assessed_at": (sold + timedelta(hours=6)).isoformat(),
            "reason_codes": ["SRC-HIGH"],
        },
        "callback_request": {
            "source_request_ref": f"SYN-REQ-{n}",
            "due_at": (sold + timedelta(days=30)).isoformat(),
            "priority": 2,
        },
    }
    for path, value in over.items():
        target = body
        *head, last = path.split("__")
        for k in head:
            target = target[int(k)] if k.isdigit() else target[k]
        if value is _DROP:
            target.pop(last, None)
        else:
            target[last] = value
    return body


_DROP = object()


def post(client: TestClient, body: dict[str, Any], key: str | None = "auto", path: str = PATH) -> Any:
    headers = csrf_header(client)
    if key == "auto":
        key = f"test-{uuid.uuid4().hex}"
    if key is not None and path == PATH:
        headers["Idempotency-Key"] = key
    return client.post(path, json=body, headers=headers)


def counts(db: Session) -> dict[str, int]:
    return {
        t: scalar(db, f"SELECT count(*) FROM {SCHEMA}.{t}")  # noqa: S608 — fixed table names
        for t in ("policy", "sale_event", "party", "callback_case", "risk_assessment", "intake_run", "case_hold")
    }


def audit(db: Session, action: str, entity_id: str) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in db.execute(
            text(f"SELECT * FROM {SCHEMA}.audit_event WHERE action = :a AND entity_id = :e ORDER BY seq"),
            {"a": action, "e": entity_id[:64]},
        ).mappings()
    ]


# ---- happy path -------------------------------------------------------------------------------------------------
def test_preview_persists_nothing_and_commit_writes_one_linked_transaction(
    signed_in: TestClient, db: Session, settings: Settings
) -> None:
    body = txn()
    before = counts(db)
    pv = post(signed_in, body, path=f"{PATH}/preview")
    assert pv.status_code == 200, pv.text
    p = pv.json()
    assert p["mode"] == "PREVIEW" and p["case"]["case_ref"] is None and p["policy"]["outcome"] == "NEW"
    assert [h["reason"] for h in p["holds"]] == ["AWAITING_SCRIPT_ASSIGNMENT"]
    assert p["script_routing"] == "NOT_EVALUATED_IN_S0" and p["case"]["callable"] is False
    assert counts(db) == before  # API-084 persists nothing except its audit event
    assert len(audit(db, "INTAKE.PREVIEWED", body["source_event_id"])) == 1

    r = post(signed_in, body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["mode"] == "COMMITTED" and not out["replayed"] and out["case"]["case_ref"].startswith("CB-")
    assert {k: v - before[k] for k, v in counts(db).items()} == {
        "policy": 1,
        "sale_event": 1,
        "party": 1,
        "callback_case": 1,
        "risk_assessment": 1,
        "intake_run": 1,
        "case_hold": 1,
    }
    case = (
        db.execute(text(f"SELECT * FROM {SCHEMA}.callback_case WHERE id = :i"), {"i": out["case"]["case_id"]})
        .mappings()
        .one()
    )
    assert (case["state"], case["has_blocking_hold"], case["priority"], case["owner_principal_id"]) == (
        "VALIDATED",
        True,
        2,
        None,
    )
    assert case["due_at"] == datetime.fromisoformat(body["callback_request"]["due_at"])
    assert (case["source_type"], case["source_system"], case["is_synthetic"]) == ("MANUAL", "SYN-POLICY-ADMIN", True)
    item = scalar(db, f"SELECT id FROM {SCHEMA}.intake_item WHERE source_event_id = :e", e=body["source_event_id"])
    for table in ("policy", "sale_event", "party", "contact_method", "policy_party_role", "risk_assessment",
                  "callback_case", "case_contact_selection", "policy_fact_snapshot"):  # fmt: skip
        rows = db.execute(
            text(
                f"SELECT source_type, intake_item_id, is_synthetic, recorded_at FROM {SCHEMA}.{table} "  # noqa: S608
                "WHERE intake_item_id = :i"
            ),
            {"i": item},  # fmt: skip
        ).all()
        assert rows and all(x.source_type == "MANUAL" and x.is_synthetic for x in rows), table
    risk = (
        db.execute(text(f"SELECT * FROM {SCHEMA}.risk_assessment WHERE id = :i"), {"i": out["risk"]["assessment_id"]})
        .mappings()
        .one()
    )
    assert (risk["origin"], risk["status"], risk["band_code"], risk["score"], risk["rule_set_version_id"]) == (
        "SOURCE_ASSIGNED",
        "FINAL",
        "HIGH",
        None,
        None,
    )
    assert risk["source_original_value"] == "SBQ-H"
    events = (
        db.execute(
            text(f"SELECT event_type FROM {SCHEMA}.case_event WHERE callback_case_id = :c ORDER BY occurred_at, id"),
            {"c": case["id"]},
        )
        .scalars()
        .all()
    )
    assert set(events) == {"CASE_CREATED", "RISK_RECORDED", "CONTACTS_SELECTED", "HOLD_PLACED"}
    assert out["eligibility"] == [
        {
            "party_ref": out["parties"][0]["party_ref"],
            "masked_name": out["parties"][0]["masked_name"],
            "role": "OWNER",
            "eligible": True,
            "ineligibility_reason": None,
            "contact_masked": out["eligibility"][0]["contact_masked"],
        }
    ]


def test_encryption_masking_and_audit_integrity(signed_in: TestClient, db: Session, settings: Settings) -> None:
    body = txn()
    out = post(signed_in, body).json()
    name, phone = body["parties"][0]["name"], body["parties"][0]["contacts"][0]["value"]
    dp = DataProtection.from_settings(settings)
    party = (
        db.execute(text(f"SELECT * FROM {SCHEMA}.party WHERE party_ref = :r"), {"r": out["parties"][0]["party_ref"]})
        .mappings()
        .one()
    )
    assert dp.decrypt(party["name_ciphertext"], aad=aad("party", "name", party["id"])) == name
    assert party["masked_name"] == f"E••• I••• H••• {name.split()[-1]}"  # every word reduced to its initial
    assert name.encode() not in bytes(party["name_ciphertext"])
    m = (
        db.execute(
            text(f"SELECT * FROM {SCHEMA}.contact_method WHERE party_id = :p AND channel = 'PHONE'"), {"p": party["id"]}
        )
        .mappings()
        .one()
    )
    assert m["value_hmac"] == dp.token("PHONE", phone) and m["masked_value"].endswith(phone[-2:])
    assert dp.decrypt(m["value_ciphertext"], aad=aad("contact_method", "value", m["id"])) == phone
    blob = json.dumps(out)
    assert name not in blob and phone not in blob  # responses carry masked values only
    events = db.execute(
        text(f"SELECT action, after, reason FROM {SCHEMA}.audit_event WHERE entity_id IN (:e, :c)"),
        {"e": body["source_event_id"], "c": out["case"]["case_ref"]},
    ).all()
    assert {e.action for e in events} >= {"INTAKE.COMMITTED", "CASE.HOLD_PLACED"}
    assert name not in json.dumps([dict(e._mapping) for e in events], default=str) and phone not in str(events)
    assert verify_chain(db).ok
    # The search token finds the new contact by exact value without decrypting anything.
    hits = signed_in.get("/api/v1/search", params={"q": phone}).json()
    assert any(h["ref"] == body["policy"]["policy_ref"] or h["ref"] == out["case"]["case_ref"] for h in hits["items"])


def test_new_records_appear_in_the_existing_portal_apis(signed_in: TestClient) -> None:
    kpis_before = {k["definition_id"]: k for k in signed_in.get("/api/v1/dashboard/kpis").json()["items"]}
    queues_before = {q["code"]: q for q in signed_in.get("/api/v1/work-queues").json()["items"]}
    body = txn()
    out = post(signed_in, body).json()
    pol_ref, case_ref = body["policy"]["policy_ref"], out["case"]["case_ref"]

    pol = signed_in.get("/api/v1/policies", params={"q": pol_ref}).json()
    assert pol["total"] == 1 and pol["items"][0]["policy_id"] == out["policy"]["policy_id"]
    detail = signed_in.get(f"/api/v1/policies/{out['policy']['policy_id']}").json()
    assert detail["policy_ref"] == pol_ref
    sales = signed_in.get(f"/api/v1/policies/{out['policy']['policy_id']}/sales").json()
    assert [s["sale_ref"] for s in sales["items"]] == [body["sale"]["sale_ref"]]
    parties = signed_in.get(f"/api/v1/policies/{out['policy']['policy_id']}/parties").json()
    assert {e["role"] for p in parties["items"] for e in p["roles"]} == {"OWNER", "PROPOSER", "PAYER", "INSURED"}

    cases = signed_in.get("/api/v1/cases", params={"q": case_ref}).json()
    assert cases["total"] == 1 and cases["items"][0]["holds"] == ["AWAITING_SCRIPT_ASSIGNMENT"]
    case = signed_in.get(f"/api/v1/cases/{out['case']['case_id']}").json()
    assert case["callable"] is False and "HOLD:AWAITING_SCRIPT_ASSIGNMENT" in case["callable_blockers"]
    assert signed_in.get(f"/api/v1/cases/{out['case']['case_id']}/script-assignment").status_code == 200

    queues = {q["code"]: q for q in signed_in.get("/api/v1/work-queues").json()["items"]}
    assert queues["ON_HOLD"]["count"] == queues_before["ON_HOLD"]["count"] + 1
    held = {r["hold_reason"]: r["count"] for r in queues["ON_HOLD"]["by_reason"]}
    held_before = {r["hold_reason"]: r["count"] for r in queues_before["ON_HOLD"]["by_reason"]}
    assert held["AWAITING_SCRIPT_ASSIGNMENT"] == held_before.get("AWAITING_SCRIPT_ASSIGNMENT", 0) + 1

    kpis = {k["definition_id"]: k for k in signed_in.get("/api/v1/dashboard/kpis").json()["items"]}
    assert kpis["KPI-13"]["numerator"] == kpis_before["KPI-13"]["numerator"] + 1  # created today, in range
    assert kpis["KPI-13"]["breakdown"]["by_source_type"]["MANUAL"] >= 1
    assert kpis["KPI-14"]["status"] == "MEASURED"
    assert kpis["KPI-14"]["numerator"] == kpis_before["KPI-14"]["numerator"] + 1

    risk = signed_in.get("/api/v1/risk-assessments", params={"q": body["sale"]["sale_ref"]}).json()
    assert risk["total"] == 1 and risk["items"][0]["origin"] == "SOURCE_ASSIGNED" and risk["items"][0]["effective"]
    assert signed_in.get("/api/v1/search", params={"q": pol_ref}).json()["items"][0]["ref"] == pol_ref


# ---- idempotency and duplicates (BE-ING-02, BE-ING-03) ----------------------------------------------------------
def test_idempotent_replay_and_key_reuse(signed_in: TestClient, db: Session) -> None:
    body, key = txn(), f"demo-{uuid.uuid4().hex}"
    first = post(signed_in, body, key)
    assert first.status_code == 201
    before = counts(db)
    again = post(signed_in, body, key)
    assert again.status_code == 200 and again.json()["replayed"] is True
    assert {**again.json(), "replayed": False} == first.json()
    assert counts(db) == before
    other = post(signed_in, txn(), key)
    assert other.status_code == 409 and other.json()["code"] == "IDEMPOTENCY_KEY_REUSED"
    missing = post(signed_in, txn(), key=None)
    assert missing.status_code == 428 and missing.json()["code"] == "IDEMPOTENCY_KEY_REQUIRED"
    assert counts(db) == before


def test_duplicate_source_event_with_a_new_key_is_rejected_and_audited(signed_in: TestClient, db: Session) -> None:
    body = txn()
    assert post(signed_in, body).status_code == 201
    before = counts(db)
    dup = post(signed_in, body)
    assert dup.status_code == 409 and dup.json()["code"] == "INGEST_DUPLICATE_SOURCE_EVENT"
    sale_again = txn(sale__sale_ref=body["sale"]["sale_ref"])
    sale_again["policy"] = body["policy"]
    r = post(signed_in, sale_again)
    assert r.status_code == 409 and r.json()["code"] == "INGEST_SALE_REF_EXISTS"
    assert counts(db) == before
    rejected = audit(db, "INTAKE.REJECTED", body["source_event_id"])
    assert rejected and rejected[-1]["after"]["code"] == "INGEST_DUPLICATE_SOURCE_EVENT"


# ---- existing policy reuse ---------------------------------------------------------------------------------------
def _seeded_policy(db: Session) -> dict[str, Any]:
    return dict(
        db.execute(
            text(
                f"SELECT * FROM {SCHEMA}.policy p WHERE market_code = 'SG' AND product_family = 'PROTECTION' "
                f"AND EXISTS (SELECT 1 FROM {SCHEMA}.policy_party_role r WHERE r.policy_id = p.id "
                "AND r.role = 'OWNER') ORDER BY policy_ref LIMIT 1"
            )
        )
        .mappings()
        .one()
    )


def _policy_body(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: row[k] for k in ("policy_ref", "market_code", "product_code", "product_family", "product_subtype",
                                "status", "premium_frequency", "premium_term_years", "currency",
                                "sum_assured_currency")}  # fmt: skip
    out["premium_amount"] = str(row["premium_amount"])
    out["sum_assured"] = str(row["sum_assured"]) if row["sum_assured"] is not None else None
    out["effective_from"] = row["effective_from"].isoformat()
    return out


def test_a_new_sale_attaches_to_a_matching_seeded_policy_without_changing_it(
    signed_in: TestClient, db: Session
) -> None:
    row = _seeded_policy(db)
    sales_before = scalar(db, f"SELECT count(*) FROM {SCHEMA}.sale_event WHERE policy_id = :p", p=row["id"])
    body = txn(sale__sale_event_type="TOP_UP", sale__premium_amount="5000.00", parties=[])
    body["policy"] = _policy_body(row)
    r = post(signed_in, body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["policy"] == {"outcome": "REUSED", "policy_ref": row["policy_ref"], "policy_id": str(row["id"])}
    assert out["parties"] == [] and out["eligibility"]  # eligibility from the policy's existing roles
    after = dict(db.execute(text(f"SELECT * FROM {SCHEMA}.policy WHERE id = :i"), {"i": row["id"]}).mappings().one())
    assert after == row  # nothing on the seeded policy changed (no overwrite, no row_version bump)
    sales = scalar(db, f"SELECT count(*) FROM {SCHEMA}.sale_event WHERE policy_id = :p", p=row["id"])
    assert sales == sales_before + 1
    snaps = (
        db.execute(
            text(f"SELECT sale_event_id FROM {SCHEMA}.policy_fact_snapshot WHERE policy_id = :p"), {"p": row["id"]}
        )
        .scalars()
        .all()
    )
    assert uuid.UUID(out["sale_event_id"]) in snaps and len(set(snaps)) == len(snaps)  # one snapshot per sale
    # Naming an existing party with its current role is accepted; a role the policy does not hold is a correction.
    party_ref = scalar(
        db,
        f"SELECT pa.party_ref FROM {SCHEMA}.policy_party_role r JOIN {SCHEMA}.party pa ON pa.id = r.party_id "
        "WHERE r.policy_id = :p AND r.role = 'OWNER' LIMIT 1",
        p=row["id"],
    )
    change = txn(sale__sale_event_type="TOP_UP", parties=[{"party_ref": party_ref, "roles": ["BENEFICIARY"]}])
    change["policy"] = _policy_body(row)
    bad = post(signed_in, change)
    assert bad.status_code == 422 and {d["code"] for d in bad.json()["details"]} == {"ROLE_CHANGE_NOT_SUPPORTED"}


def test_conflicting_material_policy_fields_are_rejected(signed_in: TestClient, db: Session) -> None:
    row = _seeded_policy(db)
    before = counts(db)
    body = txn(sale__sale_event_type="TOP_UP", parties=[])
    body["policy"] = {**_policy_body(row), "premium_amount": str(row["premium_amount"] + Decimal("1.00"))}
    r = post(signed_in, body)
    assert r.status_code == 409 and r.json()["code"] == "INGEST_POLICY_FIELDS_DIFFER"
    assert [d["loc"] for d in r.json()["details"]] == [["body", "policy", "premium_amount"]]
    body["policy"] = _policy_body(row)
    body["sale"]["sale_event_type"] = "NEW_BUSINESS"
    nb = post(signed_in, body)
    assert nb.status_code == 409 and nb.json()["code"] == "INGEST_DUPLICATE_NEW_BUSINESS"
    assert counts(db) == before


# ---- validation (BE-ING-04), SG-only and synthetic-only ---------------------------------------------------------
@pytest.mark.parametrize(
    ("over", "loc", "code"),
    [
        ({"parties__0__roles": ["OWNER", "SPOUSE"]}, ["body", "parties", "0", "roles", "1"], "literal_error"),
        ({"policy__product_code": "SYN-UNKNOWN"}, ["body", "policy", "product_code"], "UNKNOWN_PRODUCT"),
        ({"policy__currency": "USD"}, ["body", "policy", "currency"], "CURRENCY_NOT_ALLOWED"),
        ({"sale__premium_amount": "-5.00"}, ["body", "sale", "premium_amount"], "greater_than"),
        ({"sale__premium_amount": "10.123"}, ["body", "sale", "premium_amount"], "decimal_max_places"),
        ({"callback_request__due_at": "2026-01-01T00:00:00"}, ["body", "callback_request", "due_at"], "timezone_aware"),
        ({"callback_request__priority": 6}, ["body", "callback_request", "priority"], "less_than_equal"),
        ({"callback_request__due_at": _DROP}, ["body", "callback_request", "due_at"], "missing"),
        ({"sale__fsc_ref": "FSC-9999"}, ["body", "sale", "fsc_ref"], "UNKNOWN_FSC"),
        ({"source_risk__band_code": "SEVERE"}, ["body", "source_risk", "band_code"], "UNKNOWN_BAND"),
        ({"parties__0__roles": ["PAYER"]}, ["body", "parties"], "OWNER_REQUIRED"),
        ({"source_system": "SYN-SEED"}, ["body", "source_system"], "SOURCE_SYSTEM_NOT_SYNTHETIC"),
    ],
)
def test_invalid_transactions_are_rejected_with_field_details(
    signed_in: TestClient, db: Session, over: dict[str, Any], loc: list[str], code: str
) -> None:
    before = counts(db)
    body = txn(**over)
    for path in (f"{PATH}/preview", PATH):
        r = post(signed_in, copy.deepcopy(body), path=path)
        assert r.status_code == 422, (path, r.text)
        assert r.json()["code"] == "INGEST_VALIDATION_FAILED"
        assert {"loc": loc, "code": code} in [{"loc": d["loc"], "code": d["code"]} for d in r.json()["details"]]
        assert "Example Intake Holder" not in r.text
    assert counts(db) == before


def test_due_date_rules(signed_in: TestClient) -> None:
    sold = datetime.fromisoformat(txn()["sale"]["sold_at"])
    before_sale = post(signed_in, txn(callback_request__due_at=(sold - timedelta(hours=1)).isoformat()))
    assert before_sale.status_code == 422
    assert before_sale.json()["details"][0]["code"] == "BEFORE_SALE"
    overdue = txn(
        sale__sold_at=(NOW - timedelta(days=60)).isoformat(),
        callback_request__due_at=(NOW - timedelta(days=30)).isoformat(),
    )
    r = post(signed_in, overdue)
    assert r.status_code == 201, r.text  # a past due date is accepted: the callback is already overdue
    case = signed_in.get(f"/api/v1/cases/{r.json()['case']['case_id']}").json()
    assert case["sla"]["breached"] is True


def test_singapore_only_and_synthetic_only(signed_in: TestClient, db: Session) -> None:
    before = counts(db)
    my = txn(policy__market_code="MY", policy__policy_ref="POL-MY-900001", sale__sale_ref="SALE-MY-900001")
    r = post(signed_in, my)
    assert r.status_code == 422 and r.json()["code"] == "INGEST_MARKET_NOT_IN_SCOPE"
    mixed = post(signed_in, txn(policy__policy_ref="POL-MY-900002"))
    assert mixed.status_code == 422 and mixed.json()["code"] == "INGEST_MARKET_NOT_IN_SCOPE"
    real = txn(is_synthetic=False)
    r = post(signed_in, real)
    assert r.status_code == 422 and r.json()["code"] == "INGEST_NON_SYNTHETIC_REJECTED"
    assert audit(db, "INTAKE.REJECTED", real["source_event_id"])[-1]["after"]["code"] == "INGEST_NON_SYNTHETIC_REJECTED"
    phone = txn()
    phone["parties"][0]["contacts"][0]["value"] = "+6591234567"
    r = post(signed_in, phone)
    assert r.status_code == 422 and r.json()["code"] == "INGEST_CONTACT_NOT_SYNTHETIC"
    assert "+6591234567" not in r.text
    assert "+6591234567" not in json.dumps(audit(db, "INTAKE.REJECTED", phone["source_event_id"]), default=str)
    # A Malaysian party cannot be named: missing and out of scope look the same.
    my_party = scalar(
        db,
        f"SELECT pa.party_ref FROM {SCHEMA}.party pa JOIN {SCHEMA}.policy_party_role r ON r.party_id = pa.id "
        f"JOIN {SCHEMA}.policy p ON p.id = r.policy_id WHERE p.market_code = 'MY' LIMIT 1",
    )
    body = txn()
    body["parties"].append({"party_ref": my_party, "roles": ["BENEFICIARY"]})
    r = post(signed_in, body)
    assert r.status_code == 422 and r.json()["details"][0]["code"] == "UNKNOWN_PARTY"
    body["parties"][-1]["party_ref"] = "PTY-999999"
    assert post(signed_in, body).json()["details"][0]["code"] == "UNKNOWN_PARTY"
    assert counts(db) == before


# ---- holds (BE-ING-08, BE-ING-09, BE-ING-10) -------------------------------------------------------------------
def test_holds_follow_the_existing_rules(signed_in: TestClient) -> None:
    ilp = txn(
        policy__product_code="SYN-ILP-GROWTH",
        policy__product_family="ILP",
        policy__product_subtype="ILP_REGULAR",
        source_risk=None,
    )
    out = post(signed_in, ilp).json()
    assert [h["reason"] for h in out["holds"]] == ["AWAITING_SCRIPT_ASSIGNMENT", "RISK_TRIAGE"]
    assert out["risk"] is None and "does not calculate" in out["risk_note"]
    no_risk = post(signed_in, txn(source_risk=None)).json()  # non-ILP without risk: unassessed, no triage hold
    assert [h["reason"] for h in no_risk["holds"]] == ["AWAITING_SCRIPT_ASSIGNMENT"]

    suppressed = txn()
    suppressed["parties"][0]["contacts"] = [
        {"channel": "PHONE", "value": "SYN-TEL-SG-777001", "consent_status": "GRANTED", "suppressed": True}
    ]
    out = post(signed_in, suppressed).json()
    assert [h["reason"] for h in out["holds"]] == ["AWAITING_SCRIPT_ASSIGNMENT", "NO_ELIGIBLE_CONTACT"]
    assert out["eligibility"][0]["ineligibility_reason"] == "CONTACT_SUPPRESSED"

    contact = txn()
    contact["parties"][0]["contacts"] = []
    sold = contact["sale"]["sold_at"]
    contact["parties"].append(
        {
            "kind": "PERSON",
            "name": "Example Authorised Contact",
            "roles": ["AUTHORIZED_CONTACT"],
            "authorization": {"reference": "SYN-AUTH-INTAKE-1", "valid_from": sold},
            "contacts": [{"channel": "PHONE", "value": "SYN-TEL-SG-777002", "consent_status": "GRANTED"}],
        }
    )
    contact["parties"].append(
        {
            "kind": "PERSON",
            "name": "Example Unevidenced Contact",
            "roles": ["AUTHORIZED_CONTACT"],
            "contacts": [{"channel": "PHONE", "value": "SYN-TEL-SG-777003", "consent_status": "GRANTED"}],
        }
    )
    out = post(signed_in, contact).json()
    reasons = {(e["role"], e["ineligibility_reason"]) for e in out["eligibility"]}
    assert reasons == {
        ("OWNER", "NO_CONTACT_METHOD"),
        ("AUTHORIZED_CONTACT", None),
        ("AUTHORIZED_CONTACT", "AUTHORIZATION_NOT_EVIDENCED"),
    }
    assert [h["reason"] for h in out["holds"]] == ["AWAITING_SCRIPT_ASSIGNMENT"]  # one eligible contact
    assert not any(h["reason"] == "DATA_CONFLICT" for h in out["holds"])  # a new sale has no competing assessment


# ---- runs, permissions, seed integrity ------------------------------------------------------------------------
def test_runs_and_sources(signed_in: TestClient) -> None:
    body = txn()
    out = post(signed_in, body).json()
    src = signed_in.get("/api/v1/intake/sources").json()
    assert {s["source_type"]: s["available"] for s in src["items"]} == {
        "MANUAL": True,
        "MOCK_API": False,
        "BULK": False,
        "INTERNAL_API": False,
    }
    runs = signed_in.get("/api/v1/intake/import-runs").json()
    row = next(r for r in runs["items"] if r["id"] == out["run_id"])
    assert row["status"] == "ACCEPTED" and row["counts"]["received"] == row["counts"]["new"] == 1
    assert not row["requested_by"].count("-") == 4  # display name, not a raw principal id
    d = signed_in.get(f"/api/v1/intake/import-runs/{out['run_id']}").json()
    assert d["items"][0]["source_event_id"] == body["source_event_id"] and d["result"]["case"] == out["case"]
    assert signed_in.get(f"/api/v1/intake/import-runs/{uuid.uuid4()}").status_code == 404


def test_permissions_csrf_and_audit(client: TestClient, user: Account, db: Session) -> None:
    assert client.get("/api/v1/intake/sources").status_code == 401
    login(client, user)
    for method, path in (
        ("GET", "/api/v1/intake/sources"),
        ("GET", "/api/v1/intake/reference"),
        ("GET", "/api/v1/intake/import-runs"),
        ("GET", f"/api/v1/intake/import-runs/{uuid.uuid4()}"),
        ("POST", f"{PATH}/preview"),
        ("POST", PATH),
    ):
        r = client.request(method, path, json=txn() if method == "POST" else None, headers=csrf_header(client))
        assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN", path
    denied = scalar(
        db,
        f"SELECT count(*) FROM {SCHEMA}.audit_event WHERE action = 'ACCESS.DENIED_FUNCTION' "
        "AND actor_principal_id = :p AND entity_id LIKE '/api/v1/intake%'",
        p=user.principal_id,
    )
    assert denied == 6
    client.cookies.clear()
    login(client, make_account(db, "LOCAL_ADMIN", prefix="admin"))
    r = client.post(PATH, json=txn(), headers={"Idempotency-Key": f"k-{uuid.uuid4().hex}"})
    assert r.status_code == 403 and r.json()["code"] == "CSRF_INVALID"


def test_reference_data_lists_what_the_validator_accepts(signed_in: TestClient, db: Session) -> None:
    """API-087 (CP0.4b): values come from the validator's own sources; a transaction built from them previews."""
    r = signed_in.get("/api/v1/intake/reference")
    assert r.status_code == 200, r.text
    ref = r.json()
    assert (ref["market_code"], ref["currency"], ref["source_system_prefix"]) == ("SG", "SGD", "SYN-")
    products = {(p["product_code"], p["product_family"], p["product_subtype"]) for p in ref["products"]}
    assert products == SYNTHETIC_PRODUCTS
    active = scalar(db, f"SELECT count(*) FROM {SCHEMA}.fsc_representative WHERE status = 'ACTIVE'")
    assert len(ref["fscs"]) == active and all(f["channel"] in ref["enums"]["selling_channel"] for f in ref["fscs"])
    assert [b["code"] for b in ref["risk_bands"]] == ["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
    assert {c["channel"] for c in ref["contact_formats"]} == {"PHONE", "EMAIL"}
    assert all(re.fullmatch(c["pattern"], c["example"]) for c in ref["contact_formats"])
    assert ref["enums"]["party_role"][0] == "OWNER" and "TOP_UP" in ref["enums"]["sale_event_type"]
    assert (ref["priority_min"], ref["priority_max"]) == (1, 5)
    fsc = ref["fscs"][1]
    body = txn(sale__fsc_ref=fsc["fsc_ref"], sale__selling_channel=fsc["channel"])
    assert signed_in.post(f"{PATH}/preview", json=body, headers=csrf_header(signed_in)).status_code == 200


def test_seeded_records_are_unchanged_after_intake(signed_in: TestClient, engine: Engine) -> None:
    assert post(signed_in, txn()).status_code == 201
    with engine.connect() as c:
        manifest = _manifest_event(c, SCHEMA)
        assert manifest is not None and content_digest(c, SCHEMA) == manifest["digest"]
