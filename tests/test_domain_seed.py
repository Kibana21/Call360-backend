"""S0-SEED-1 acceptance tests (S0_DATA_MODEL §6; AC-0.2-02…11). Run only against call360_test."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, text

from app.core.settings import Settings
from app.domain import seed_content as C
from app.domain.catalog import CODE_REFS, E_TABLES, P_TABLES
from app.domain.digest import content_digest, sha256_of
from app.domain.governed import VALUES, version_id
from app.domain.outcomes import EVIDENCE_INCOMPLETE, _satisfied, derive_outcomes
from app.domain.protection import DataProtection, aad, generate_key
from app.domain.seed import GOLDEN, SEED_VERSION, TARGETS, SeedError, counts, seed
from tests.domain_support import SCHEMA
from tests.support import migrate, reset_test_schema

pytestmark = pytest.mark.usefixtures("seeded")


def q(conn: Connection, sql: str, **params: Any) -> list[Any]:
    return list(conn.execute(text(sql.replace("§", SCHEMA + ".")), params))


def one(conn: Connection, sql: str, **params: Any) -> Any:
    return conn.execute(text(sql.replace("§", SCHEMA + ".")), params).scalar_one()


def case(conn: Connection, ref: str) -> Any:
    return q(conn, "SELECT * FROM §callback_case WHERE case_ref = :r", r=ref)[0]


# ---- BE-DATA-02: determinism and idempotency --------------------------------------------------------------
def test_be_data_02_two_fresh_seeds_give_identical_digests(engine: Engine, settings: Settings) -> None:
    protection = DataProtection.from_settings(settings)
    digests = []
    for _ in range(2):
        reset_test_schema(engine, settings)
        with engine.begin() as c:
            digests.append(seed(c, SCHEMA, protection).digest)
    assert digests[0] == digests[1]
    with engine.begin() as c:
        assert content_digest(c, SCHEMA) == digests[0]


def test_be_data_02_rerun_is_idempotent(engine: Engine, settings: Settings, conn: Connection) -> None:
    before = (counts(conn, SCHEMA), one(conn, "SELECT count(*) FROM §audit_event"))
    with engine.begin() as c:
        report = seed(c, SCHEMA, DataProtection.from_settings(settings))
    assert not report.created
    with engine.connect() as c:
        assert (
            counts(c, SCHEMA),
            int(c.execute(text(f"SELECT count(*) FROM {SCHEMA}.audit_event")).scalar_one()),
        ) == before
    manifest = q(conn, "SELECT after FROM §audit_event WHERE action = 'SEED.MANIFEST'")
    assert len(manifest) == 1 and manifest[0].after["digest"] == report.digest
    assert set(manifest[0].after["key_ids"]) == {"encryption", "hmac"}  # identifiers, never key material


def test_be_data_02_digest_depends_on_the_hmac_key(fresh_schema: None, engine: Engine, settings: Settings) -> None:
    """D-33: keyed comparison values make the digest key-dependent (documented, not a seed defect)."""
    with engine.connect() as c:
        tx = c.begin()
        other = DataProtection(uuid.uuid4().bytes * 2, uuid.uuid4().bytes * 2)
        digest_other = seed(c, SCHEMA, other).digest
        tx.rollback()
    with engine.begin() as c:
        digest = seed(c, SCHEMA, DataProtection.from_settings(settings)).digest
    assert digest != digest_other


def test_seed_refuses_foreign_data_and_downgrade_refuses_seeded_data(
    engine: Engine, settings: Settings, conn: Connection
) -> None:
    try:
        with pytest.raises(RuntimeError, match="refusing to remove governed values"):
            migrate(settings, "0006_case_evidence", down=True)
        # 0008 (scope mappings) stepped down in its own transaction; 0007 refused and kept every row.
        assert one(conn, "SELECT version_num FROM §alembic_version") == "0007_governed_values"
    finally:
        migrate(settings, "head")
    with engine.connect() as c:
        tx = c.begin()
        c.execute(text(f"DELETE FROM {SCHEMA}.audit_event WHERE false"))
        c.execute(text(f"UPDATE {SCHEMA}.fsc_representative SET display_name = 'tampered' WHERE fsc_ref = 'FSC-0001'"))
        with pytest.raises(SeedError, match="differs from the recorded seed manifest"):
            seed(c, SCHEMA, DataProtection.from_settings(settings))
        tx.rollback()


# ---- BE-DATA-03: volumes, distribution, invariants ----------------------------------------------------------
def test_be_data_03_exact_volumes(conn: Connection) -> None:
    got = counts(conn, SCHEMA)
    for table, n in TARGETS.items():
        assert got[table] == n, table
    per_case = Counter(
        r.n
        for r in q(
            conn,
            "SELECT c.id, count(a.id) AS n FROM §callback_case c "
            "LEFT JOIN §contact_attempt a ON a.callback_case_id = c.id GROUP BY c.id",
        )
    )
    assert per_case == {0: 10, 1: 135, 2: 60, 3: 35, 4: 10}
    assert one(conn, "SELECT count(*) FROM §policy WHERE market_code = 'MY'") == 55
    assert {r[0] for r in q(conn, "SELECT DISTINCT product_family FROM §policy")} == {"PROTECTION", "ILP", "ENDOWMENT"}
    sev = Counter(r[0] for r in q(conn, "SELECT severity FROM §finding"))
    assert sev == {"LOW": 6, "MEDIUM": 8, "HIGH": 7, "CRITICAL": 3}
    assert Counter(r[0] for r in q(conn, "SELECT state FROM §conversation_session")) == {
        "COMPLETED": 62,
        "INTERRUPTED": 10,
        "ABORTED": 8,
    }
    assert Counter(r[0] for r in q(conn, "SELECT status FROM §script_version")) == {
        "PUBLISHED": 2,
        "SUPERSEDED": 1,
        "DRAFT": 1,
        "WITHDRAWN": 1,
    }


def test_be_data_03_every_state_and_hold_reason_and_outcome(conn: Connection) -> None:
    assert {r[0] for r in q(conn, "SELECT DISTINCT state FROM §callback_case")} == {
        "CREATED",
        "VALIDATED",
        "READY",
        "IN_PROGRESS",
        "AWAITING_CALLBACK",
        "AWAITING_REVIEW",
        "ESCALATED",
        "VERIFIED",
        "CLOSED_UNVERIFIED",
        "CANCELLED",
    }
    assert {r[0] for r in q(conn, "SELECT DISTINCT hold_reason FROM §case_hold")} == {
        c for c, _, _ in VALUES["case_hold_reason"]
    }
    outcomes = derive_outcomes(conn, SCHEMA)
    cats = Counter(o.category for o in outcomes.values())
    assert set(cats) == {"VERIFIED_COMPLIANT", "VERIFIED_WITH_FINDINGS", "NOT_VERIFIED", "CANCELLED", "OPEN"}
    assert cats[EVIDENCE_INCOMPLETE] == 0
    assert (cats["VERIFIED_COMPLIANT"], cats["VERIFIED_WITH_FINDINGS"]) == (30, 8)


def test_inv_01_every_case_resolves_to_policy_parties(conn: Connection) -> None:
    broken = q(
        conn,
        "SELECT c.case_ref FROM §callback_case c JOIN §sale_event s ON s.id = c.sale_event_id "
        "JOIN §policy p ON p.id = s.policy_id WHERE NOT EXISTS (SELECT 1 FROM §policy_party_role r "
        "WHERE r.policy_id = p.id AND r.role = 'OWNER')",
    )
    assert broken == []
    assert (
        one(
            conn,
            "SELECT count(*) FROM §callback_case c JOIN §sale_event s ON s.id = c.sale_event_id "
            "JOIN §policy p ON p.id = s.policy_id WHERE p.market_code <> c.market_code",
        )
        == 0
    )


def test_inv_03_sessions_only_on_connected_attempts(conn: Connection) -> None:
    statuses = {
        r[0]
        for r in q(
            conn, "SELECT a.status FROM §conversation_session s JOIN §contact_attempt a ON a.id = s.contact_attempt_id"
        )
    }
    assert statuses == {"CONNECTED"}


def test_inv_14_and_t32_contact_eligibility_in_seed(conn: Connection) -> None:
    rows = q(conn, "SELECT rule_basis, eligible, ineligibility_reason FROM §case_contact_selection")
    by = Counter((r.rule_basis, r.eligible, r.ineligibility_reason) for r in rows)
    assert by[("AUTHORIZED_CONTACT", False, "AUTHORIZATION_NOT_EVIDENCED")] > 0
    assert by[("AUTHORIZED_CONTACT", True, None)] > 0
    assert by[("INSURED", False, "ROLE_NOT_CALLABLE")] > 0
    assert not [k for k in by if k[0] not in {"OWNER", "AUTHORIZED_CONTACT", "INSURED"}]
    joint = q(
        conn,
        "SELECT callback_case_id FROM §case_contact_selection WHERE eligible AND rule_basis = 'OWNER' "
        "GROUP BY callback_case_id HAVING count(DISTINCT party_id) >= 2",
    )
    assert len(joint) >= 25
    # Attempts only reach eligible parties, and the contacted party is recorded (T-32).
    assert (
        one(
            conn,
            "SELECT count(*) FROM §contact_attempt a WHERE NOT EXISTS (SELECT 1 FROM "
            "§case_contact_selection s WHERE s.callback_case_id = a.callback_case_id AND s.eligible "
            "AND s.party_id = a.contacted_party_id)",
        )
        == 0
    )


def test_be_data_07_multi_sale_policies_have_distinct_cases(conn: Connection) -> None:
    multi = q(
        conn,
        "SELECT s.policy_id, count(DISTINCT c.id) AS cases, count(DISTINCT s.id) AS sales, "
        "array_agg(DISTINCT s.sale_event_type) AS kinds FROM §sale_event s JOIN §callback_case c "
        "ON c.sale_event_id = s.id GROUP BY s.policy_id HAVING count(DISTINCT s.id) > 1",
    )
    assert len(multi) == 20
    assert all(r.cases == r.sales == 2 and "NEW_BUSINESS" in r.kinds for r in multi)


def test_be_data_08_contact_changes_keep_attempt_snapshots(conn: Connection) -> None:
    closed = q(conn, "SELECT id, valid_to FROM §contact_method WHERE valid_to IS NOT NULL")
    assert len(closed) == 15
    for row in closed:
        before = q(
            conn, "SELECT contact_snapshot, started_at FROM §contact_attempt WHERE contact_method_id = :m", m=row.id
        )
        assert before and all(a.started_at < row.valid_to for a in before)
        assert all(a.contact_snapshot["contact_method_id"] == str(row.id) for a in before)
    superseding = one(conn, "SELECT count(*) FROM §case_contact_selection WHERE supersedes_id IS NOT NULL")
    assert superseding == 15


def test_be_data_09_holds_consistent_and_audited(conn: Connection) -> None:
    assert (
        one(
            conn,
            "SELECT count(*) FROM §callback_case c WHERE c.has_blocking_hold <> EXISTS (SELECT 1 FROM "
            "§case_hold h WHERE h.callback_case_id = c.id AND h.is_blocking AND h.released_at IS NULL)",
        )
        == 0
    )
    assert (
        one(conn, "SELECT count(*) FROM §callback_case WHERE has_blocking_hold AND state IN ('READY', 'IN_PROGRESS')")
        == 0
    )
    holds = one(conn, "SELECT count(*) FROM §case_hold")
    released = one(conn, "SELECT count(*) FROM §case_hold WHERE released_at IS NOT NULL")
    assert released == 2
    assert one(conn, "SELECT count(*) FROM §audit_event WHERE action = 'CASE.HOLD_PLACED'") == holds
    assert one(conn, "SELECT count(*) FROM §audit_event WHERE action = 'CASE.HOLD_RELEASED'") == released
    assert (
        one(conn, "SELECT count(*) FROM §case_event WHERE event_type IN ('HOLD_PLACED', 'HOLD_RELEASED')")
        == holds + released
    )


# ---- BE-DATA-04: pins and frozen content against the seed ----------------------------------------------------
def test_be_data_04_seed_pins_are_historically_valid_and_hashes_verify(conn: Connection) -> None:
    assert (
        one(
            conn,
            "SELECT count(*) FROM §conversation_session s WHERE NOT §script_version_valid_at("
            "s.script_version_id, s.started_at)",
        )
        == 0
    )
    superseded = q(
        conn,
        "SELECT count(*) AS n FROM §conversation_session s JOIN §script_version v "
        "ON v.id = s.script_version_id WHERE v.status = 'SUPERSEDED'",
    )
    assert superseded[0].n > 0  # T-15: an old session still references the superseded version
    for v in q(conn, "SELECT manifest, manifest_sha256 FROM §script_version WHERE manifest IS NOT NULL"):
        assert sha256_of(v.manifest) == v.manifest_sha256
    for s in q(conn, "SELECT facts, sha256 FROM §policy_fact_snapshot"):
        assert sha256_of(s.facts) == s.sha256
    # CASE-002: a policy has a later snapshot (its top-up sale) while an earlier session pins the original.
    assert (
        one(
            conn,
            "SELECT count(*) FROM §conversation_session cs JOIN §policy_fact_snapshot p ON "
            "p.id = cs.policy_fact_snapshot_id WHERE EXISTS (SELECT 1 FROM §policy_fact_snapshot later "
            "WHERE later.policy_id = p.policy_id AND later.captured_at > p.captured_at)",
        )
        >= 1
    )


def test_be_data_06_three_risk_concepts_stay_separate(conn: Connection) -> None:
    assert {r[0] for r in q(conn, "SELECT DISTINCT kind FROM §risk_assessment")} == {"CALLBACK_SELECTION"}
    assert one(conn, "SELECT count(*) FROM §policy_fact_snapshot WHERE facts ? 'suitability'") == 250
    assert one(conn, "SELECT count(*) FROM §risk_assessment WHERE explanation ILIKE '%suitab%'") == 0
    bands = {c for c, _, _ in VALUES["sbq_risk_band"]}
    assert {r[0] for r in q(conn, "SELECT DISTINCT severity FROM §finding")} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert "CRITICAL" not in bands  # finding severity is its own enum, not a risk band


def test_be_data_11_factor_values_reproduce_input_hash(conn: Connection) -> None:
    rule = q(conn, "SELECT id, input_snapshot_sha256 FROM §risk_assessment WHERE origin = 'RULE_ASSESSED'")
    assert rule
    for a in rule:
        factors = q(
            conn,
            "SELECT factor_code, value_type, value, source FROM §risk_factor_result "
            "WHERE assessment_id = :a ORDER BY factor_code",
            a=a.id,
        )
        payload = [
            {"factor_code": f.factor_code, "value_type": f.value_type, "value": f.value, "source": f.source}
            for f in factors
        ]
        assert len(payload) == 5 and sha256_of(payload) == a.input_snapshot_sha256
    assert (
        one(
            conn,
            "SELECT count(*) FROM §risk_factor_result f JOIN §risk_assessment a ON a.id = f.assessment_id "
            "WHERE a.origin <> 'RULE_ASSESSED'",
        )
        == 0
    )
    assert one(conn, "SELECT count(*) FROM §risk_assessment WHERE score IS NOT NULL") == 0  # no scoring in S0
    by = Counter((r.status, r.origin) for r in q(conn, "SELECT status, origin FROM §risk_assessment"))
    assert by[("SUPERSEDED", "SOURCE_ASSIGNED")] == 17
    pairs = q(
        conn,
        "SELECT sale_event_id FROM §risk_assessment WHERE status = 'FINAL' GROUP BY sale_event_id "
        "HAVING count(DISTINCT origin) = 2",
    )
    assert len(pairs) == 25


def test_be_kpi_05_be_data_12_expected_answer_policies_and_yes_is_not_auto_compliant(conn: Connection) -> None:
    policies = {r[0] for r in q(conn, "SELECT DISTINCT expected_answer_policy FROM §question_revision")}
    assert policies == {
        "EXACT_BOOLEAN",
        "NUMERIC_MATCH_POLICY_FACT",
        "ACKNOWLEDGEMENT",
        "NARRATIVE_REVIEW",
        "COLLECT_ONLY",
    }
    assert {r[0] for r in q(conn, "SELECT DISTINCT answer_type FROM §question_revision")} == {
        "YES_NO",
        "NUMERIC",
        "ENUM",
        "FREE_TEXT",
        "ACKNOWLEDGEMENT",
    }
    assert not _satisfied("NARRATIVE_REVIEW", "YES", None)
    assert not _satisfied("ACKNOWLEDGEMENT", "YES", None) and not _satisfied("ACKNOWLEDGEMENT", "YES", "MISMATCH")
    assert not _satisfied("EXACT_BOOLEAN", "YES", "MISMATCH") and not _satisfied("COLLECT_ONLY", "UNCLEAR", None)
    # Narrative YES answers exist, yet no case with an applicable mandatory narrative question is compliant.
    assert (
        one(
            conn,
            "SELECT count(*) FROM §answer_observation o JOIN §question_execution e ON "
            "e.id = o.question_execution_id JOIN §question_revision r ON r.id = e.question_revision_id "
            "WHERE r.expected_answer_policy = 'NARRATIVE_REVIEW' AND o.answer_state = 'YES'",
        )
        > 0
    )
    ilp_verified = one(
        conn,
        "SELECT count(*) FROM §callback_case c JOIN §sale_event s ON s.id = c.sale_event_id "
        "JOIN §policy p ON p.id = s.policy_id WHERE c.state = 'VERIFIED' AND p.is_ilp",
    )
    assert ilp_verified == 0


def test_be_data_13_governed_values_and_seed_references(conn: Connection) -> None:
    for list_code, values in VALUES.items():
        rows = q(
            conn,
            "SELECT code, attributes FROM §code_value WHERE code_list_version_id = :v ORDER BY sort_order",
            v=version_id(list_code),
        )
        assert [r.code for r in rows] == [c for c, _, _ in values], list_code
        assert all(r.attributes.get("synthetic") is True for r in rows)
    for table, code_col, ver_col, list_code in CODE_REFS:
        bad = one(
            conn,
            f"SELECT count(*) FROM §{table} WHERE {code_col} IS NOT NULL AND {ver_col} <> :v",
            v=version_id(list_code),
        )
        assert bad == 0, (table, code_col)


# ---- synthetic-only, labelling and data protection (AC-0.2-09) ----------------------------------------------
def test_be_data_10_everything_is_synthetic_and_labelled(conn: Connection) -> None:
    for table in P_TABLES:
        assert one(conn, f"SELECT count(*) FROM §{table} WHERE NOT is_synthetic") == 0, table
    for table in E_TABLES:
        assert one(conn, f"SELECT count(*) FROM §{table} WHERE record_origin <> 'SYNTHETIC_SEED'") == 0, table
    for table in ("question_revision", "script_version", "risk_rule_set_version", "control"):
        assert one(conn, f"SELECT count(*) FROM §{table} WHERE content_approval_status <> 'SYNTHETIC_UNAPPROVED'") == 0
    assert (
        one(conn, f"SELECT count(*) FROM §question_revision WHERE customer_wording NOT LIKE '{C.WORDING_PREFIX}%'") == 0
    )
    assert {r[0] for r in q(conn, "SELECT DISTINCT transport FROM §contact_attempt")} == {"SYNTHETIC"}
    assert {
        (r.media_status, r.transcript_status)
        for r in q(conn, "SELECT media_status, transcript_status FROM §conversation_session")
    } == {("NOT_REQUIRED", "UNAVAILABLE")}
    assert one(conn, "SELECT count(*) FROM §principal WHERE created_by = 'SYSTEM:seed'") == 0  # no credentials


def test_be_data_10_readiness_fails_on_a_non_synthetic_row(client: TestClient, engine: Engine) -> None:
    assert client.get("/health/ready").json() == {"status": "ok"}
    fsc = uuid.uuid4()
    with engine.begin() as c:
        c.execute(
            text(
                f"INSERT INTO {SCHEMA}.fsc_representative (id, fsc_ref, display_name, channel, status, "
                "created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) VALUES "
                "(:i, 'FSC-REAL', 'x', 'AGENCY', 'ACTIVE', 't', 'MANUAL', 's', 'r', now(), false)"
            ),
            {"i": fsc},
        )
    try:
        r = client.get("/health/ready")
        assert r.status_code == 503 and r.json() == {"status": "not_ready"}
    finally:
        with engine.begin() as c:
            c.execute(text(f"DELETE FROM {SCHEMA}.fsc_representative WHERE id = :i"), {"i": fsc})
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_ac_09_encryption_hmac_and_masking(conn: Connection, settings: Settings) -> None:
    dp = DataProtection.from_settings(settings)
    patterns = {
        r.attributes["channel"]: r.attributes["pattern"]
        for r in q(
            conn,
            "SELECT attributes FROM §code_value WHERE code_list_version_id = :v",
            v=version_id("synthetic_contact_ranges"),
        )
    }
    rows = q(conn, "SELECT id, channel, value_ciphertext, value_hmac, masked_value FROM §contact_method")
    for r in rows:
        value = dp.decrypt(bytes(r.value_ciphertext), aad=aad("contact_method", "value", r.id))
        assert re.fullmatch(patterns[r.channel], value), r.channel
        assert not value.startswith("+") and dp.token(r.channel, value) == r.value_hmac
        assert value != r.masked_value and r.masked_value[-2:] == value[-2:] if r.channel == "PHONE" else True
    assert all(r.channel != "EMAIL" or "@example.invalid" in r.masked_value for r in rows)
    # Exact-match lookup by HMAC token finds the method without decrypting anything.
    sample = rows[0]
    plain = dp.decrypt(bytes(sample.value_ciphertext), aad=aad("contact_method", "value", sample.id))
    assert (
        q(conn, "SELECT id FROM §contact_method WHERE value_hmac = :h", h=dp.token(sample.channel, plain))[0].id
        == sample.id
    )
    # AAD binds a ciphertext to its row: copied to another row it does not decrypt.
    with pytest.raises(Exception):  # noqa: B017 — cryptography raises InvalidTag
        dp.decrypt(bytes(sample.value_ciphertext), aad=aad("contact_method", "value", rows[1].id))
    for p in q(conn, "SELECT id, name_ciphertext, masked_name FROM §party LIMIT 20"):
        name = dp.decrypt(bytes(p.name_ciphertext), aad=aad("party", "name", p.id))
        assert re.fullmatch(r"Example Policyholder \d{3}", name) and name != p.masked_name
    with pytest.raises(ValueError):
        DataProtection(bytes(32), bytes(32))  # identical keys refused
    assert generate_key() != generate_key()


# ---- golden fixtures and outcomes ---------------------------------------------------------------------------
def test_golden_fixtures_exist(conn: Connection) -> None:
    refs = {r[0] for r in q(conn, "SELECT case_ref FROM §callback_case WHERE case_ref = ANY(:g)", g=list(GOLDEN))}
    assert refs == set(GOLDEN)


def test_golden_10482(conn: Connection) -> None:
    c = case(conn, "CB-2026-10482")
    assert (c.market_code, c.state) == ("SG", "AWAITING_REVIEW")
    attempts = [
        r.status
        for r in q(conn, "SELECT status FROM §contact_attempt WHERE callback_case_id = :c ORDER BY sequence", c=c.id)
    ]
    assert attempts == ["NO_ANSWER", "BUSY", "CONNECTED"]
    sessions = q(
        conn,
        "SELECT s.id FROM §conversation_session s JOIN §contact_attempt a ON a.id = "
        "s.contact_attempt_id WHERE a.callback_case_id = :c",
        c=c.id,
    )
    assert len(sessions) == 1
    run = q(conn, "SELECT status FROM §survey_run WHERE session_id = :s", s=sessions[0].id)
    assert [r.status for r in run] == ["COMPLETED"]
    risk = q(
        conn,
        "SELECT r.band_code, r.origin, r.rule_set_version_id FROM §conversation_session s "
        "JOIN §risk_assessment r ON r.id = s.risk_assessment_id WHERE s.id = :s",
        s=sessions[0].id,
    )[0]
    assert (risk.band_code, risk.origin) == ("HIGH", "RULE_ASSESSED") and risk.rule_set_version_id
    trace = q(conn, "SELECT rule_trace FROM §script_assignment WHERE callback_case_id = :c", c=c.id)[0].rule_trace
    assert trace["resolved_sections"] == ["COMMON_SALES_CONDUCT", "ILP", "ELEVATED_RISK"] and trace["excluded"]
    ev = q(
        conn,
        "SELECT e.expected, e.observed, e.result, f.severity FROM §rule_evaluation e JOIN "
        "§question_execution qe ON qe.id = e.question_execution_id JOIN §question_revision r ON "
        "r.id = qe.question_revision_id JOIN §finding f ON f.question_execution_id = qe.id WHERE "
        "f.callback_case_id = :c AND r.policy_fact_key = 'premium_term_years'",
        c=c.id,
    )[0]
    assert (ev.expected, ev.observed, ev.result, ev.severity) == ({"value": 10}, {"value": 5}, "MISMATCH", "HIGH")
    assert derive_outcomes(conn, SCHEMA)["CB-2026-10482"].category == "OPEN"


def test_golden_contact_risk_and_script_fixtures(conn: Connection) -> None:
    def attempts(ref: str) -> int:
        return one(
            conn,
            "SELECT count(*) FROM §contact_attempt a JOIN §callback_case c ON c.id = a.callback_case_id "
            "WHERE c.case_ref = :r",
            r=ref,
        )

    def sessions(ref: str) -> int:
        return one(
            conn,
            "SELECT count(*) FROM §conversation_session s JOIN §contact_attempt a ON a.id = "
            "s.contact_attempt_id JOIN §callback_case c ON c.id = a.callback_case_id WHERE c.case_ref = :r",
            r=ref,
        )

    def holds(ref: str) -> set[str]:
        return {
            r[0]
            for r in q(
                conn,
                "SELECT h.hold_reason FROM §case_hold h JOIN §callback_case c ON c.id = "
                "h.callback_case_id WHERE c.case_ref = :r AND h.released_at IS NULL",
                r=ref,
            )
        }

    def assigned(ref: str) -> int:
        return one(
            conn,
            "SELECT count(*) FROM §script_assignment s JOIN §callback_case c ON c.id = "
            "s.callback_case_id WHERE c.case_ref = :r",
            r=ref,
        )

    assert (attempts("CB-2026-10483"), sessions("CB-2026-10483")) == (2, 0)
    assert case(conn, "CB-2026-20001").market_code == "MY"
    assert holds("CB-2026-10490") == {"AWAITING_SCRIPT_ASSIGNMENT"} and assigned("CB-2026-10490") == 0
    assert holds("CB-2026-10491") == {"NO_ELIGIBLE_CONTACT"} and attempts("CB-2026-10491") == 0
    sel = q(
        conn,
        "SELECT s.eligible, s.ineligibility_reason FROM §case_contact_selection s JOIN §callback_case c ON "
        "c.id = s.callback_case_id WHERE c.case_ref = 'CB-2026-10491'",
    )
    assert [(r.eligible, r.ineligibility_reason) for r in sel] == [(False, "CONTACT_SUPPRESSED")]
    for ref in ("CB-2026-10492", "CB-2026-10498"):
        c = case(conn, ref)
        assert holds(ref) == {"RISK_TRIAGE"} and assigned(ref) == 0 and c.has_blocking_hold
        assert one(conn, "SELECT count(*) FROM §risk_assessment WHERE sale_event_id = :s", s=c.sale_event_id) == 0
        assert one(
            conn,
            "SELECT p.is_ilp FROM §sale_event s JOIN §policy p ON p.id = s.policy_id WHERE s.id = :s",
            s=c.sale_event_id,
        )
    anchor_due = q(
        conn, "SELECT due_at < '2026-11-15'::date AS past FROM §callback_case WHERE case_ref = :r", r="CB-2026-10498"
    )[0]
    assert anchor_due.past  # held past due: holds do not pause SLA
    c = case(conn, "CB-2026-10493")
    assert (c.state, c.closure_reason, attempts("CB-2026-10493")) == ("CLOSED_UNVERIFIED", "ATTEMPTS_EXHAUSTED", 4)


def _sla_exempt(conn: Connection, ref: str) -> bool:
    """SLA-EX-001 (S0_KPI_DEFINITIONS D-18) evaluated on persisted data."""
    c = case(conn, ref)
    eligible = q(
        conn,
        "SELECT attributes FROM §code_value WHERE code_list_version_id = :v AND code = :c",
        v=c.cancellation_reason_list_version_id,
        c=c.cancellation_reason,
    )[0].attributes["sla_exempt_eligible"]
    return bool(
        c.state == "CANCELLED"
        and eligible
        and c.cancellation_authorized_by
        and c.cancellation_authorization_ref
        and c.cancelled_recorded_at < c.due_at
    )


def test_golden_cancellation_fixtures(conn: Connection) -> None:
    assert _sla_exempt(conn, "CB-2026-10494")
    c = case(conn, "CB-2026-10495")
    assert c.cancelled_recorded_at < c.due_at and c.cancellation_authorized_by is None
    assert not _sla_exempt(conn, "CB-2026-10495")
    c = case(conn, "CB-2026-10496")
    assert c.cancelled_recorded_at > c.due_at and c.cancellation_authorized_by is not None
    assert not _sla_exempt(conn, "CB-2026-10496")


def test_golden_10497_is_verified_compliant(conn: Connection) -> None:
    o = derive_outcomes(conn, SCHEMA)["CB-2026-10497"]
    assert (o.category, o.controls_satisfied, o.open_findings) == ("VERIFIED_COMPLIANT", True, 0)
    trace = q(
        conn,
        "SELECT a.rule_trace FROM §script_assignment a JOIN §callback_case c ON c.id = a.callback_case_id "
        "WHERE c.case_ref = 'CB-2026-10497'",
    )[0].rule_trace
    assert trace["resolved_sections"] == ["COMMON_SALES_CONDUCT", "PROTECTION"]


def test_seed_manifest_records_version(conn: Connection) -> None:
    after = q(conn, "SELECT after FROM §audit_event WHERE action = 'SEED.MANIFEST' AND entity_id = :v", v=SEED_VERSION)[
        0
    ].after
    assert after["rng_seed"] == 360 and after["anchor"] == "2026-11-15"
    assert after["outcomes"].get(EVIDENCE_INCOMPLETE) is None
