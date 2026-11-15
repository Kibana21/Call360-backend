"""BE-CFG-01…03 — versioned code lists, feature flags, additive migration (CP0.1B-1)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.config.models import CodeList, CodeListVersion, CodeValue, FeatureFlag, FeatureFlagChange
from app.config.seed import seed_config
from app.config.service import active_values, values_of
from app.core.settings import Settings
from app.domain.governed import VALUES as GOVERNED_VALUES
from app.security.models import AuditEvent, AuthSession, Principal
from tests.domain_support import assert_audit_append_only, audit_rows
from tests.support import Account, csrf_header, login, migrate

GOVERNED = {
    "sbq_risk_band",
    "risk_factor",
    "case_hold_reason",
    "case_closure_reason",
    "case_cancellation_reason",
    "finding_materiality_policy",
    "kpi_sla_exemption_rule",
    "callable_party_roles",
    "synthetic_contact_ranges",
}


def _lists(client: TestClient) -> dict[str, dict[str, Any]]:
    r = client.get("/api/v1/admin/code-lists")
    assert r.status_code == 200, r.text
    return {cl["code"]: cl for cl in r.json()["items"]}


def _market_payload(market: dict[str, Any], label_suffix: str, reason: str = "Relabel for clarity") -> dict[str, Any]:
    active = next(v for v in market["versions"] if v["status"] == "ACTIVE")
    values = [{**v, "label": f"{v['label'].split(' [')[0]} [{label_suffix}]"} for v in active["values"]]
    return {"based_on_version": market["active_version"], "values": values, "reason": reason}


def _post_version(client: TestClient, code: str, body: dict[str, Any]):  # type: ignore[no-untyped-def]
    return client.post(f"/api/v1/admin/code-lists/{code}/versions", json=body, headers=csrf_header(client))


# ---- BE-CFG-01 code lists ------------------------------------------------------------------------
def test_be_cfg_01_seeded_definitions_and_classification(client: TestClient, admin: Account) -> None:
    login(client, admin)
    lists = _lists(client)
    assert set(lists) == GOVERNED | {"market"}
    assert all(lists[c]["governed"] for c in GOVERNED) and not lists["market"]["governed"]
    # Governed lists receive version 1 from CP0.2 migration 0007 (D-26, D-36); they stay read-only.
    for c in GOVERNED:
        assert lists[c]["active_version"] == 1 and [v["version"] for v in lists[c]["versions"]] == [1], c
        codes = [x["code"] for x in lists[c]["versions"][0]["values"]]
        assert codes == [code for code, _, _ in GOVERNED_VALUES[c]], c
    market = lists["market"]
    v1 = next(v for v in market["versions"] if v["version"] == 1)
    assert {(x["code"], x["attributes"].get("synthetic")) for x in v1["values"]} == {("SG", True), ("MY", True)}


def test_be_cfg_01_market_label_version_supersedes_and_history_survives(
    client: TestClient, admin: Account, db: Session
) -> None:
    login(client, admin)
    before = _lists(client)["market"]
    old_active = before["active_version"]
    old_values = next(v for v in before["versions"] if v["status"] == "ACTIVE")["values"]
    tag = uuid.uuid4().hex[:6]
    r = _post_version(client, "market", _market_payload(before, tag, "Clarify synthetic labels"))
    assert r.status_code == 201, r.text
    after = r.json()
    assert after["active_version"] == old_active + 1
    statuses = {v["version"]: v["status"] for v in after["versions"]}
    assert statuses[old_active] == "SUPERSEDED" and statuses[old_active + 1] == "ACTIVE"
    assert list(statuses.values()).count("ACTIVE") == 1
    previous = next(v for v in after["versions"] if v["version"] == old_active)
    assert previous["values"] == old_values  # historical values remain explainable
    assert all(tag in v["label"] for v in after["versions"][0]["values"])
    assert after["versions"][0]["created_by_name"] == "Test Admin"
    # service helpers resolve both current and historical values
    assert {v.label for v in active_values(db, "market")} == {v["label"] for v in after["versions"][0]["values"]}
    old_version = db.execute(
        select(CodeListVersion).join(CodeList).where(CodeList.code == "market", CodeListVersion.version == old_active)
    ).scalar_one()
    assert [v.label for v in values_of(db, old_version.id)] == [v["label"] for v in old_values]
    event = db.execute(
        select(AuditEvent)
        .where(AuditEvent.action == "CONFIG.CODE_LIST_VERSION_ACTIVATED")
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    ).scalar_one()
    assert event.actor_principal_id == admin.principal_id and event.reason == "Clarify synthetic labels"
    assert event.before["version"] == old_active and event.after["version"] == old_active + 1  # type: ignore[index]


def test_be_cfg_01_stale_based_on_version_rejected(client: TestClient, admin: Account) -> None:
    login(client, admin)
    market = _lists(client)["market"]
    assert _post_version(client, "market", _market_payload(market, uuid.uuid4().hex[:6])).status_code == 201
    stale = _post_version(client, "market", _market_payload(market, uuid.uuid4().hex[:6]))  # same base again
    assert stale.status_code == 409 and stale.json()["code"] == "CONFLICT_STALE_VERSION"


@pytest.mark.parametrize(
    "mutate, code",
    [
        (
            lambda vs: vs + [{"code": "ID", "label": "Indonesia", "attributes": {}, "sort_order": 30}],
            "CODE_SET_CHANGE_NOT_ALLOWED",
        ),
        (lambda vs: vs[:1], "CODE_SET_CHANGE_NOT_ALLOWED"),
        (lambda vs: vs + [dict(vs[0])], "DUPLICATE_CODE"),
        (lambda vs: vs, "NO_CHANGE"),
        (lambda vs: [{**vs[0], "code": "sg lower"}, *vs[1:]], "VALIDATION_FAILED"),
    ],
)
def test_be_cfg_01_market_code_set_is_fixed_and_values_validated(
    client: TestClient, admin: Account, mutate: Any, code: str
) -> None:
    login(client, admin)
    market = _lists(client)["market"]
    values = next(v for v in market["versions"] if v["status"] == "ACTIVE")["values"]
    r = _post_version(
        client,
        "market",
        {"based_on_version": market["active_version"], "values": mutate(values), "reason": "Attempted change"},
    )
    assert r.status_code == 422 and r.json()["code"] == code, r.text


@pytest.mark.parametrize("list_code", sorted(GOVERNED))
def test_be_cfg_01_governed_lists_are_read_only_and_audited(
    client: TestClient, admin: Account, db: Session, list_code: str
) -> None:
    login(client, admin)

    def versions() -> int:
        return db.execute(
            select(func.count()).select_from(CodeListVersion).join(CodeList).where(CodeList.code == list_code)
        ).scalar_one()

    before = versions()
    r = _post_version(
        client,
        list_code,
        {
            "based_on_version": 0,
            "reason": "Try to edit governed list",
            "values": [{"code": "X1", "label": "Invented", "attributes": {}}],
        },
    )
    assert r.status_code == 403 and r.json()["code"] == "GOVERNED_LIST_READ_ONLY"
    db.rollback()
    assert versions() == before == 1  # only the CP0.2 version 1; the denied attempt created nothing
    assert (
        db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "CONFIG.GOVERNED_CHANGE_DENIED", AuditEvent.entity_id == list_code
            )
        )
        .scalars()
        .first()
    )


def test_be_cfg_01_request_validation(client: TestClient, admin: Account) -> None:
    login(client, admin)
    market = _lists(client)["market"]
    body = _market_payload(market, "x")
    assert _post_version(client, "market", {**body, "reason": ""}).status_code == 422
    assert _post_version(client, "market", {**body, "status": "ACTIVE"}).status_code == 422  # unknown field
    assert _post_version(client, "nonexistent_list", body).status_code == 404
    no_csrf = client.post("/api/v1/admin/code-lists/market/versions", json=body)
    assert no_csrf.status_code == 403 and no_csrf.json()["code"] == "CSRF_INVALID"


def test_be_cfg_01_user_denied(client: TestClient, user: Account) -> None:
    login(client, user)
    assert client.get("/api/v1/admin/code-lists").status_code == 403
    r = _post_version(
        client,
        "market",
        {"based_on_version": 1, "reason": "nope", "values": [{"code": "SG", "label": "x", "attributes": {}}]},
    )
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"


def test_be_cfg_01_database_enforces_immutability(db: Session) -> None:
    active = db.execute(
        select(CodeListVersion).join(CodeList).where(CodeList.code == "market", CodeListVersion.status == "ACTIVE")
    ).scalar_one()
    tamper = (
        "UPDATE code_value SET label = 'tampered' WHERE code_list_version_id = :v",
        "DELETE FROM code_value WHERE code_list_version_id = :v",
        "UPDATE code_list_version SET change_reason = 'tampered' WHERE id = :v",
        "UPDATE code_list_version SET status = 'DRAFT' WHERE id = :v",
        "DELETE FROM code_list_version WHERE id = :v",
        "INSERT INTO code_value (id, code_list_version_id, code, label) VALUES (gen_random_uuid(), :v, 'XX', 'x')",
    )
    for stmt in tamper:
        with pytest.raises(DBAPIError):
            db.execute(text(stmt), {"v": active.id})
        db.rollback()
    with pytest.raises(IntegrityError):  # a second ACTIVE version for the same list
        db.execute(
            text(
                "INSERT INTO code_list_version (id, code_list_id, version, status, effective_from, "
                "change_reason, created_by) VALUES (:i, :l, 999, 'ACTIVE', now(), 'x', 'test')"
            ),
            {"i": uuid.uuid4(), "l": active.code_list_id},
        )
    db.rollback()


# ---- BE-CFG-02 feature flags -------------------------------------------------------------------
def _flags(client: TestClient) -> dict[str, dict[str, Any]]:
    r = client.get("/api/v1/admin/feature-flags")
    assert r.status_code == 200, r.text
    assert r.json()["current_stage"] == "S0"
    return {f["code"]: f for f in r.json()["items"]}


def _patch_flag(client: TestClient, code: str, enabled: bool, row_version: int | None, reason: str = "Test change"):  # type: ignore[no-untyped-def]
    headers = csrf_header(client) | ({"If-Match": str(row_version)} if row_version is not None else {})
    return client.patch(
        f"/api/v1/admin/feature-flags/{code}", json={"enabled": enabled, "reason": reason}, headers=headers
    )


def test_be_cfg_02_registry_is_disabled_and_stage_locked(client: TestClient, admin: Account, db: Session) -> None:
    login(client, admin)
    flags = _flags(client)
    seeded = {
        "voice.browser_sessions": "S1",
        "scripts.authoring": "S2",
        "reviews.decisions": "S3",
        "exports.evidence": "S4",
    }
    for code, gate in seeded.items():
        assert flags[code]["stage_gate"] == gate and flags[code]["enabled"] is False and flags[code]["locked"] is True
        r = _patch_flag(client, code, True, flags[code]["row_version"], "Try early enablement")
        assert r.status_code == 422 and r.json()["code"] == "STAGE_GATED"
    assert (
        db.execute(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "CONFIG.FLAG_STAGE_GATED_DENIED")
        ).scalar_one()
        >= 4
    )
    with pytest.raises(IntegrityError):  # the database also refuses a stage-locked enable
        db.execute(text("UPDATE feature_flag SET enabled = true WHERE code = 'voice.browser_sessions'"))
    db.rollback()


def test_be_cfg_02_stage_reached_fixture_flag_toggles_with_history(
    client: TestClient, admin: Account, db: Session
) -> None:
    code = f"test.fixture_{uuid.uuid4().hex[:8]}"  # test-schema-only fixture (D-27)
    db.add(FeatureFlag(code=code, description="Test fixture flag", enabled=False, stage_gate="S0", updated_by="test"))
    db.commit()
    login(client, admin)
    flag = _flags(client)[code]
    assert flag["locked"] is False
    assert _patch_flag(client, code, True, None).status_code == 428
    on = _patch_flag(client, code, True, flag["row_version"], "Enable for test")
    assert on.status_code == 200 and on.json()["enabled"] is True
    assert on.json()["history"][0]["reason"] == "Enable for test"
    assert _patch_flag(client, code, False, flag["row_version"]).status_code == 409  # stale row version
    assert _patch_flag(client, code, True, on.json()["row_version"]).json()["code"] == "NO_CHANGE"
    assert _patch_flag(client, code, False, on.json()["row_version"], "").status_code == 422  # reason required
    event = db.execute(
        select(AuditEvent).where(AuditEvent.action == "CONFIG.FLAG_CHANGED", AuditEvent.entity_id == code)
    ).scalar_one()
    assert event.before == {"enabled": False} and event.after == {"enabled": True}
    for stmt in ("UPDATE feature_flag_change SET reason = 'x'", "DELETE FROM feature_flag_change"):
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text(stmt))
        db.rollback()
    assert db.execute(select(func.count()).select_from(FeatureFlagChange)).scalar_one() >= 1


def test_be_cfg_02_user_denied(client: TestClient, user: Account) -> None:
    login(client, user)
    assert client.get("/api/v1/admin/feature-flags").status_code == 403
    assert _patch_flag(client, "exports.evidence", True, 1).status_code == 403


# ---- BE-CFG-03 additive migration and idempotent seed ----------------------------------------
def _identity_counts(db: Session) -> tuple[int, int, int]:
    return (
        db.execute(select(func.count()).select_from(Principal)).scalar_one(),
        db.execute(select(func.count()).select_from(AuthSession)).scalar_one(),
        db.execute(select(func.count()).select_from(AuditEvent)).scalar_one(),
    )


def test_be_cfg_03_migration_preserves_cp01a_data(
    fresh_schema: None, client: TestClient, admin: Account, db: Session, settings: Settings, engine: Engine
) -> None:
    login(client, admin)
    before = _identity_counts(db)
    audit_before = audit_rows(engine)
    db.rollback()
    migrate(settings, "0001_identity_foundation", down=True)
    assert _identity_counts(db)[:2] == before[:2]
    db.rollback()
    migrate(settings, "head")
    assert _identity_counts(db)[:2] == before[:2]
    # Audit is append-only: the CP0.2 governed values (0007) audit their removal and re-activation (D-36).
    assert assert_audit_append_only(audit_before, audit_rows(engine)) == {
        "CONFIG.CODE_LIST_VERSION_REMOVED": 9,
        "CONFIG.CODE_LIST_VERSION_ACTIVATED": 9,
        "ADMIN.GROUP_MAPPING_CHANGED": 4,
    }
    assert db.execute(select(func.count()).select_from(CodeList)).scalar_one() == 10


def test_be_cfg_03_seed_is_idempotent(engine: Engine, settings: Settings, db: Session) -> None:
    def counts() -> tuple[int, ...]:
        return tuple(
            db.execute(select(func.count()).select_from(m)).scalar_one()
            for m in (CodeList, CodeListVersion, CodeValue, FeatureFlag)
        )

    first = counts()
    db.rollback()
    with engine.begin() as conn:
        seed_config(conn, settings.target_schema)
        seed_config(conn, settings.target_schema)
    assert counts() == first
