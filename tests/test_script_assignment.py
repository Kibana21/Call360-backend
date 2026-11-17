"""S2-C deterministic script assignment: preview (read-only), apply (pin + hold release), idempotency, never reassign,
precedence and specificity, same-rank conflicts (review hold), missing inputs, selected contact role (D-62 clarified),
superseded targets, explicit fallback, preservation of unrelated holds, historical immutability, batch run, Singapore
scope and permissions. The schema is reset and reseeded around this module so the live ruleset is controlled."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.settings import Settings
from app.domain.digest import content_digest, sha256_of
from app.domain.protection import DataProtection
from app.domain.seed import seed
from tests.domain_support import SCHEMA
from tests.support import ORIGIN, Account, csrf_header, login, make_account, reset_test_schema
from tests.test_intake import txn
from tests.test_script_authoring import ok

NOW = datetime.now(UTC)


@pytest.fixture(scope="module", autouse=True)
def controlled_schema(engine: Engine, settings: Settings) -> Iterator[None]:
    def fresh() -> None:
        reset_test_schema(engine, settings)
        with engine.begin() as c:
            seed(c, settings.target_schema, DataProtection.from_settings(settings))

    fresh()
    yield
    fresh()


@pytest.fixture
def admin_c(app) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        yield c


@pytest.fixture
def checker(db: Session) -> Account:
    return make_account(db, "LOCAL_SC_CHECKER_SG", prefix="achk")


def q1(db: Session, sql: str, **p: Any) -> Any:
    v = db.execute(text(sql), p).scalar()
    db.rollback()
    return v


def intake(c: TestClient, body: dict[str, Any]) -> str:
    h = csrf_header(c) | {"Idempotency-Key": f"t-{uuid.uuid4().hex}"}
    out = ok(c.post("/api/v1/intake/manual", json=body, headers=h), 201)
    return str(out["case"]["case_id"])


def ilp(**over: Any) -> dict[str, Any]:
    return txn(
        policy__product_code="SYN-ILP-GROWTH",
        policy__product_family="ILP",
        policy__product_subtype="ILP_REGULAR",
        **over,
    )


def preview(c: TestClient, case_id: str) -> dict[str, Any]:
    return ok(c.get(f"/api/v1/cases/{case_id}/script-assignment/preview"))


def apply(c: TestClient, case_id: str, key: str | None = None, status: int = 200, **body: Any) -> dict[str, Any]:
    h = csrf_header(c)
    if key != "":
        h["Idempotency-Key"] = key or f"apply-{uuid.uuid4().hex}"
    r = c.post(f"/api/v1/cases/{case_id}/script-assignment/apply", json=body, headers=h)
    assert r.status_code == status, r.text
    return dict(r.json())


def seeded_version(db: Session, label: str) -> str:
    return str(
        q1(
            db,
            f"SELECT v.id FROM {SCHEMA}.script_version v JOIN {SCHEMA}.script_family f ON f.id = "
            f"v.script_family_id WHERE f.code = 'SALES_VERIFICATION_SG' AND v.version_label = :l",
            l=label,
        )
    )


def publish_script(user_c: TestClient, checker_c: TestClient, code: str) -> str:
    from tests.test_script_authoring import approve, build_basic

    _, vid, d = build_basic(user_c, code)
    d.post("/submit", {"change_summary": "Target script for assignment tests"})
    for step, body in (("review", approve(checker_c, vid)), ("publish", {})):
        ok(checker_c.post(f"/api/v1/script-versions/{vid}/{step}", json=body, headers=csrf_header(checker_c)))
    return vid


def publish_rule(
    user_c: TestClient,
    checker_c: TestClient,
    code: str,
    conditions: list[dict[str, Any]],
    priority: int,
    target: str,
    *,
    fallback: bool = False,
) -> str:
    out = ok(
        user_c.post(
            "/api/v1/assignment-rules", json={"code": code, "name": f"{code} (test)"}, headers=csrf_header(user_c)
        ),
        201,
    )
    did = out["draft_id"]
    d = ok(user_c.get(f"/api/v1/assignment-rule-drafts/{did}"))
    content = {
        "name": d["name"],
        "conditions": [{"field": "market", "values": ["SG"]}, *conditions],
        "priority": priority,
        "is_fallback": fallback,
        "target_script_version_id": target,
    }
    ok(
        user_c.put(
            f"/api/v1/assignment-rule-drafts/{did}",
            json={"expected_row_version": d["row_version"], "content": content},
            headers=csrf_header(user_c),
        )
    )
    d = ok(user_c.get(f"/api/v1/assignment-rule-drafts/{did}"))
    assert d["analysis"]["valid"], d["analysis"]["issues"]
    ok(
        user_c.post(
            f"/api/v1/assignment-rule-drafts/{did}/submit",
            json={"expected_row_version": d["row_version"], "change_summary": "Rule for S2-C assignment tests"},
            headers=csrf_header(user_c),
        )
    )
    ok(
        checker_c.post(
            f"/api/v1/assignment-rule-drafts/{did}/review",
            json={"decision": "APPROVE", "reason": "Reviewed for tests"},
            headers=csrf_header(checker_c),
        )
    )
    pub = ok(checker_c.post(f"/api/v1/assignment-rule-drafts/{did}/publish", json={}, headers=csrf_header(checker_c)))
    return str(pub["rule_version_id"])


def legacy_rule(db: Session, code: str, conditions: list[dict[str, Any]], priority: int, target: str) -> str:
    """A rule version inserted outside Rule Studio (as seeded / legacy rows are): S2-B validation would refuse an
    equal-rank conflict, so this is how an ambiguous live ruleset can exist and must still fail closed."""
    pred = {"all": [{"fact": "market", "equals": "SG"}, *({"fact": c["field"], "in": c["values"]} for c in conditions)]}
    rid = uuid.uuid4()
    db.execute(
        text(
            f"INSERT INTO {SCHEMA}.script_assignment_rule_version (id, rule_code, version, predicate, priority, "
            "specificity, target_script_version_id, effective_from, status, checksum, author_ref, checker_ref, "
            "created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) VALUES (:i, :c, 1, "
            "CAST(:p AS jsonb), :pr, :sp, :t, :ef, 'PUBLISHED', :sum, 'SYN-LEGACY-A', 'SYN-LEGACY-C', 'SYSTEM:pytest', "
            "'SEED', 'PYTEST-LEGACY', :c, now(), true)"
        ),
        {
            "i": rid,
            "c": code,
            "p": json.dumps(pred),
            "pr": priority,
            "sp": 1 + len(conditions),
            "t": target,
            "ef": NOW - timedelta(days=1),
            "sum": sha256_of(pred | {"c": code}),
        },
    )
    db.commit()
    return str(rid)


def retire(db: Session, rule_version_id: str) -> None:
    db.execute(
        text(
            f"UPDATE {SCHEMA}.script_assignment_rule_version SET status = 'WITHDRAWN', effective_to = now() "
            "WHERE id = :i"
        ),
        {"i": rule_version_id},
    )
    db.commit()


def holds(db: Session, case_id: str) -> list[str]:
    rows = (
        db.execute(
            text(
                f"SELECT hold_reason FROM {SCHEMA}.case_hold WHERE callback_case_id = :c AND released_at "
                "IS NULL ORDER BY hold_reason"
            ),
            {"c": case_id},
        )
        .scalars()
        .all()
    )
    db.rollback()
    return list(rows)


def test_preview_apply_pin_release_idempotent_and_never_reassign(
    client: TestClient,
    other_client: TestClient,
    admin_c: TestClient,
    user: Account,
    admin: Account,
    checker: Account,
    db: Session,
) -> None:
    login(admin_c, admin)
    login(client, user)
    case_id = intake(admin_c, txn())  # PROTECTION / AGENCY / HIGH; one eligible contact (OWNER)
    assert holds(db, case_id) == ["AWAITING_SCRIPT_ASSIGNMENT"]
    seed_assignments = q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment")
    digest = content_digest(db.connection(), SCHEMA)
    db.rollback()
    # Preview is read-only and explains the decision.
    p = preview(client, case_id)
    assert p["status"] == "READY_TO_ASSIGN" and p["can_apply"] and p["current"] is None
    pv = p["preview"]
    assert pv["outcome"] == "SELECTED" and pv["winning_rules"] == ["SG-SALES-VERIFY v2"]
    assert pv["script_label"] == "SALES_VERIFICATION_SG v1.1" and pv["would_release"] == ["AWAITING_SCRIPT_ASSIGNMENT"]
    assert pv["remaining_blocking"] == [] and pv["contact_resolution"]["status"] == "SINGLE"
    assert "when the market is" in pv["explanation"]
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment_attempt") == 0
    # Apply needs an Idempotency-Key; a stale preview is refused.
    apply(client, case_id, key="", status=428)
    assert apply(client, case_id, status=409, expected_decision_sha256="0" * 64)["code"] == "PREVIEW_STALE"
    key = f"apply-{uuid.uuid4().hex}"
    out = apply(client, case_id, key=key, expected_decision_sha256=pv["decision_sha256"])
    assert out["status"] == "ASSIGNED" and out["attempt"]["holds_released"] == ["AWAITING_SCRIPT_ASSIGNMENT"]
    assert out["current"]["script_label"] == "SALES_VERIFICATION_SG v1.1"
    assert out["current"]["matched_rule"] == "SG-SALES-VERIFY v2" and out["current"]["origin"] == "ENGINE"
    row = (
        db.execute(
            text(
                f"SELECT a.*, v.manifest_sha256 AS vsha, c.state, c.has_blocking_hold, c.verified_at FROM "
                f"{SCHEMA}.script_assignment a JOIN {SCHEMA}.script_version v ON v.id = a.script_version_id "
                f"JOIN {SCHEMA}.callback_case c ON c.id = a.callback_case_id WHERE a.callback_case_id = :c"
            ),
            {"c": case_id},
        )
        .mappings()
        .one()
    )
    db.rollback()
    assert row["script_manifest_sha256"] == row["vsha"] and row["rule_trace"]["matched"] == "SG-SALES-VERIFY v2"
    assert row["input_snapshot"]["inputs"]["product_family"] == "PROTECTION" and len(row["input_sha256"]) == 64
    assert (row["state"], row["has_blocking_hold"], row["verified_at"]) == ("VALIDATED", False, None)  # no outcome
    assert holds(db, case_id) == []
    events = (
        db.execute(text(f"SELECT event_type FROM {SCHEMA}.case_event WHERE callback_case_id = :c"), {"c": case_id})
        .scalars()
        .all()
    )
    db.rollback()
    assert {"SCRIPT_ASSIGNED", "HOLD_RELEASED"} <= set(events)
    # Idempotent: the same key replays; a new key never reassigns.
    again = apply(client, case_id, key=key)
    assert again["status"] == "REPLAYED" and again["attempt"]["id"] == out["attempt"]["id"]
    assert apply(client, case_id)["status"] == "ALREADY_ASSIGNED"
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment") == seed_assignments + 1
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment_attempt") == 1
    assert preview(client, case_id)["status"] == "ASSIGNED"
    listed = ok(client.get(f"/api/v1/cases/{case_id}/script-assignment"))  # API-039 shows the engine pin
    assert listed["items"][0]["origin"] == "ENGINE"
    # The pin and the ledger are immutable; seeded assignments are untouched.
    for sql in (
        f"UPDATE {SCHEMA}.script_assignment SET assigned_by = 'x' WHERE callback_case_id = :c",
        f"DELETE FROM {SCHEMA}.script_assignment_attempt WHERE callback_case_id = :c",
    ):
        with pytest.raises(Exception, match="immutable|not allowed|forbid"):
            db.execute(text(sql), {"c": case_id})
        db.rollback()
    assert content_digest(db.connection(), SCHEMA) == digest
    db.rollback()
    # Permissions: ADMIN and the checker cannot apply; another key cannot be reused on another case.
    other = intake(admin_c, txn())
    assert apply(admin_c, other, status=403)["code"] == "FORBIDDEN"
    login(other_client, checker)
    assert apply(other_client, other, status=403)["code"] == "FORBIDDEN"
    assert apply(client, other, key=key, status=409)["code"] == "IDEMPOTENCY_KEY_REUSED"


def test_precedence_contact_roles_ambiguity_and_unrelated_holds(
    client: TestClient,
    other_client: TestClient,
    admin_c: TestClient,
    user: Account,
    admin: Account,
    checker: Account,
    db: Session,
) -> None:
    login(admin_c, admin)
    login(client, user)
    login(other_client, checker)
    v11 = seeded_version(db, "1.1")
    alt = publish_script(client, other_client, "S2C_ALT")
    # Priority beats specificity; on equal priority the more specific rule wins.
    publish_rule(client, other_client, "S2C-ILP", [{"field": "is_ilp", "values": [True]}], 8, alt)
    publish_rule(
        client,
        other_client,
        "S2C-ILP-HIGH",
        [{"field": "is_ilp", "values": [True]}, {"field": "risk_band", "values": ["HIGH"]}],
        8,
        v11,
    )
    high = intake(admin_c, ilp())
    medium = intake(admin_c, ilp(source_risk__band_code="MEDIUM"))
    assert preview(client, high)["preview"]["winning_rules"] == ["S2C-ILP-HIGH v1"]  # specificity 3 beats 2
    assert preview(client, medium)["preview"]["winning_rules"] == ["S2C-ILP v1"]
    # Selected contact role (D-62 clarified): one eligible contact → its role decides.
    publish_rule(
        client, other_client, "S2C-AUTH-CONTACT", [{"field": "contact_role", "values": ["AUTHORIZED_CONTACT"]}], 3, alt
    )
    only_auth = txn()
    sold = only_auth["sale"]["sold_at"]
    only_auth["parties"][0]["contacts"] = []
    only_auth["parties"].append(
        {
            "kind": "PERSON",
            "name": "Example Authorised Contact",
            "roles": ["AUTHORIZED_CONTACT"],
            "authorization": {"reference": "SYN-AUTH-S2C-1", "valid_from": sold},
            "contacts": [{"channel": "PHONE", "value": "SYN-TEL-SG-778001", "consent_status": "GRANTED"}],
        }
    )
    single = preview(client, intake(admin_c, only_auth))["preview"]
    assert single["winning_rules"] == ["S2C-AUTH-CONTACT v1"]
    assert single["contact_resolution"]["status"] == "SINGLE"
    assert single["contact_resolution"]["selected"]["role"] == "AUTHORIZED_CONTACT"
    # Two eligible contacts whose roles lead to different scripts → fail closed, never guess.
    both = txn()
    both["parties"].append(
        {
            "kind": "PERSON",
            "name": "Example Second Contact",
            "roles": ["AUTHORIZED_CONTACT"],
            "authorization": {"reference": "SYN-AUTH-S2C-2", "valid_from": both["sale"]["sold_at"]},
            "contacts": [{"channel": "PHONE", "value": "SYN-TEL-SG-778002", "consent_status": "GRANTED"}],
        }
    )
    both_id = intake(admin_c, both)
    unresolved = preview(client, both_id)
    assert unresolved["status"] == "BLOCKED" and unresolved["preview"]["outcome"] == "CONTACT_UNRESOLVED"
    assert {c["role"] for c in unresolved["preview"]["contact_resolution"]["considered"]} >= {
        "AUTHORIZED_CONTACT",
        "OWNER",
    }
    res = apply(client, both_id)
    assert res["status"] == "NOT_ASSIGNED" and holds(db, both_id) == ["AWAITING_SCRIPT_ASSIGNMENT"]
    # No eligible contact while a rule depends on the role → fail closed; the NO_ELIGIBLE_CONTACT hold stays.
    none = txn()
    none["parties"][0]["contacts"] = [
        {"channel": "PHONE", "value": "SYN-TEL-SG-778003", "consent_status": "GRANTED", "suppressed": True}
    ]
    none_id = intake(admin_c, none)
    assert preview(client, none_id)["preview"]["outcome"] == "CONTACT_UNRESOLVED"
    # Same-rank conflict (only possible outside Rule Studio, e.g. a legacy row) → AMBIGUOUS, review hold, no pin;
    # an unrelated hold (RISK_TRIAGE: ILP without SBQ risk) is preserved throughout.
    legacy_a = legacy_rule(db, "S2C-LEGACY-A", [{"field": "product_code", "values": ["SYN-ILP-GROWTH"]}], 2, v11)
    legacy_rule(db, "S2C-LEGACY-B", [{"field": "is_ilp", "values": [True]}], 2, alt)
    amb = intake(admin_c, ilp(source_risk=None))
    assert holds(db, amb) == ["AWAITING_SCRIPT_ASSIGNMENT", "RISK_TRIAGE"]
    pv = preview(client, amb)["preview"]
    assert (
        pv["outcome"] == "AMBIGUOUS" and pv["would_place"] == ["AWAITING_SCRIPT_REVIEW"] and pv["script_label"] is None
    )
    first = apply(client, amb)
    assert first["status"] == "NOT_ASSIGNED" and first["attempt"]["holds_placed"] == ["AWAITING_SCRIPT_REVIEW"]
    assert apply(client, amb)["attempt"]["holds_placed"] == []  # the review hold is placed once
    assert holds(db, amb) == ["AWAITING_SCRIPT_ASSIGNMENT", "AWAITING_SCRIPT_REVIEW", "RISK_TRIAGE"]
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment WHERE callback_case_id = :c", c=amb) == 0
    # Once the conflict is resolved, assignment releases only the script holds.
    retire(db, legacy_a)
    done = apply(client, amb)
    assert done["status"] == "ASSIGNED" and done["current"]["matched_rule"] == "S2C-LEGACY-B v1"
    assert sorted(done["attempt"]["holds_released"]) == ["AWAITING_SCRIPT_ASSIGNMENT", "AWAITING_SCRIPT_REVIEW"]
    assert holds(db, amb) == ["RISK_TRIAGE"]
    assert preview(client, amb)["preview"]["remaining_blocking"] == ["RISK_TRIAGE"]


def test_superseded_target_fallback_no_match_batch_and_scope(
    client: TestClient,
    other_client: TestClient,
    admin_c: TestClient,
    user: Account,
    admin: Account,
    checker: Account,
    db: Session,
) -> None:
    login(admin_c, admin)
    login(client, user)
    login(other_client, checker)
    # A winning rule whose target script was superseded fails closed (no fall-through to a lower rule).
    from tests.test_script_authoring import approve

    target = publish_script(client, other_client, "S2C_OLD")
    publish_rule(client, other_client, "S2C-ENDOW", [{"field": "product_family", "values": ["ENDOWMENT"]}], 1, target)
    fam = q1(db, f"SELECT script_family_id FROM {SCHEMA}.script_version WHERE id = :v", v=target)
    new = ok(client.post(f"/api/v1/scripts/{fam}/drafts", json={}, headers=csrf_header(client)), 201)
    nv = new["script_version_id"]
    d = ok(client.get(f"/api/v1/script-versions/{nv}"))
    ok(
        client.post(
            f"/api/v1/script-versions/{nv}/submit",
            json={"expected_row_version": d["row_version"], "change_summary": "Next version for the test"},
            headers=csrf_header(client),
        )
    )
    ok(
        other_client.post(
            f"/api/v1/script-versions/{nv}/review", json=approve(other_client, nv), headers=csrf_header(other_client)
        )
    )
    ok(
        other_client.post(
            f"/api/v1/script-versions/{nv}/publish",
            json={"supersede_version_id": target},
            headers=csrf_header(other_client),
        )
    )
    endow = intake(
        admin_c,
        txn(
            policy__product_code="SYN-END-SAVER",
            policy__product_family="ENDOWMENT",
            policy__product_subtype="ENDOWMENT",
        ),
    )
    pv = preview(client, endow)["preview"]
    assert pv["outcome"] == "TARGET_NOT_EFFECTIVE" and pv["script_label"] is None
    assert apply(client, endow)["status"] == "NOT_ASSIGNED"
    assert holds(db, endow) == ["AWAITING_SCRIPT_ASSIGNMENT"]
    # Without the seeded catch-all rule, nothing matches (no silent fallback) until an explicit fallback is approved.
    seeded = q1(
        db,
        f"SELECT id FROM {SCHEMA}.script_assignment_rule_version WHERE rule_code = 'SG-SALES-VERIFY' "
        "AND status = 'PUBLISHED'",
    )
    retire(db, str(seeded))
    plain = intake(admin_c, txn())
    assert preview(client, plain)["preview"]["outcome"] == "NO_MATCH"
    publish_rule(client, other_client, "S2C-FALLBACK", [], 999, seeded_version(db, "1.1"), fallback=True)
    fb = preview(client, plain)["preview"]
    assert fb["outcome"] == "SELECTED_BY_FALLBACK" and fb["winning_rules"] == ["S2C-FALLBACK v1"]
    # Batch: preview, then apply to eligible unassigned cases only; assigned and terminal cases are never touched.
    before = db.execute(text(f"SELECT id, script_version_id FROM {SCHEMA}.script_assignment ORDER BY id")).all()
    db.rollback()
    dry = ok(client.post("/api/v1/script-assignments/run", json={"dry_run": True}, headers=csrf_header(client)))
    assert dry["cases"] > 0 and all(r["status"] == "PREVIEW" for r in dry["results"])
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment") == len(before)
    h = csrf_header(client) | {"Idempotency-Key": f"batch-{uuid.uuid4().hex}"}
    run = ok(client.post("/api/v1/script-assignments/run", json={"dry_run": False}, headers=h))
    assert {r["status"] for r in run["results"]} <= {"ASSIGNED", "NOT_ASSIGNED"}
    assert run["summary"].get("SELECTED_BY_FALLBACK", 0) >= 1
    after = dict(db.execute(text(f"SELECT id, script_version_id FROM {SCHEMA}.script_assignment")).all())
    db.rollback()
    assert all(after[i] == v for i, v in before)  # historical assignments unchanged
    replay = ok(client.post("/api/v1/script-assignments/run", json={"dry_run": False}, headers=h))
    assert all(r["status"] in ("NOT_ASSIGNED", "REPLAYED", "ASSIGNED") for r in replay["results"])
    assert q1(db, f"SELECT count(*) FROM {SCHEMA}.script_assignment") == len(after)
    # Singapore only: a Malaysian case is an identical 404 for preview and apply.
    my = q1(db, f"SELECT id FROM {SCHEMA}.callback_case WHERE market_code = 'MY' LIMIT 1")
    assert client.get(f"/api/v1/cases/{my}/script-assignment/preview").status_code == 404
    assert apply(client, str(my), status=404)["code"] == "NOT_FOUND"
