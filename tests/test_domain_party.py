"""Migration 0003 integrity — market codes, versioned contacts (INV-05), frozen sale context (POL-003),
immutable fact snapshots (CASE-002/POL-006, INV-04), external references (PARTY-002), authorisation evidence."""

from __future__ import annotations

from sqlalchemy import Connection

from tests.domain_support import (
    NOW,
    SCHEMA,
    ins,
    make_contact,
    make_party,
    make_policy,
    make_sale,
    make_snapshot,
    rejected,
)

IMMUTABLE = "42501"  # insufficient_privilege (as in CP0.1B-1)
CHECK = "23514"


def test_market_code_must_exist_in_market_list(conn: Connection) -> None:
    make_policy(conn, "SG")
    make_policy(conn, "MY")
    sql = (
        f"INSERT INTO {SCHEMA}.policy (id, policy_ref, market_code, product_code, product_family, product_subtype, "
        "is_ilp, status, premium_amount, currency, premium_frequency, effective_from, created_by, source_type, "
        "source_system, source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), 'P-X', 'XX', 'p', "
        "'f', 's', false, 'IN_FORCE', 1, 'SGD', 'MONTHLY', now(), 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, sql) == CHECK
    pid = make_policy(conn)
    assert rejected(conn, f"UPDATE {SCHEMA}.policy SET market_code = 'XX' WHERE id = :i", {"i": pid}) == CHECK


def test_be_data_08_contact_change_inserts_new_row_and_closes_old(conn: Connection) -> None:
    party = make_party(conn)
    old = make_contact(conn, party)
    sql = f"UPDATE {SCHEMA}.contact_method SET masked_value = 'changed' WHERE id = :i"
    assert rejected(conn, sql, {"i": old}) == IMMUTABLE
    assert (
        rejected(conn, f"UPDATE {SCHEMA}.contact_method SET suppressed = true WHERE id = :i", {"i": old}) == IMMUTABLE
    )
    assert rejected(conn, f"DELETE FROM {SCHEMA}.contact_method WHERE id = :i", {"i": old}) == IMMUTABLE
    from sqlalchemy import text

    conn.execute(text(f"UPDATE {SCHEMA}.contact_method SET valid_to = :t WHERE id = :i"), {"t": NOW, "i": old})
    sql = f"UPDATE {SCHEMA}.contact_method SET valid_to = now() + interval '1 day' WHERE id = :i"
    assert rejected(conn, sql, {"i": old}) == IMMUTABLE  # closed once, never re-opened or moved
    make_contact(conn, party, valid_from=NOW)


def test_sale_context_and_fsc_frozen_at_sale(conn: Connection) -> None:
    sale = make_sale(conn, make_policy(conn))
    for col, val in [("fsc_id", "gen_random_uuid()"), ("selling_channel", "'BROKER'"), ("sold_at", "now()")]:
        assert rejected(conn, f"UPDATE {SCHEMA}.sale_event SET {col} = {val} WHERE id = :i", {"i": sale}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.sale_event WHERE id = :i", {"i": sale}) == IMMUTABLE


def test_fact_snapshot_is_immutable_and_belongs_to_its_policy(conn: Connection) -> None:
    policy = make_policy(conn)
    snap = make_snapshot(conn, policy, make_sale(conn, policy))
    sql = f"UPDATE {SCHEMA}.policy_fact_snapshot SET facts = '{{}}' WHERE id = :i"
    assert rejected(conn, sql, {"i": snap}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.policy_fact_snapshot WHERE id = :i", {"i": snap}) == IMMUTABLE
    other_sale = make_sale(conn, make_policy(conn))
    sp = conn.begin_nested()
    try:
        make_snapshot(conn, policy, other_sale)
        raise AssertionError("cross-policy snapshot accepted")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == CHECK


def test_external_reference_unique_and_immutable(conn: Connection) -> None:
    party = make_party(conn)
    ref = ins(
        conn, "external_reference", p=False, source_system="SYN", object_type="PARTY", external_id="C1", entity_id=party
    )
    sql = f"UPDATE {SCHEMA}.external_reference SET external_id = 'C2' WHERE id = :i"
    assert rejected(conn, sql, {"i": ref}) == IMMUTABLE
    dup = (
        f"INSERT INTO {SCHEMA}.external_reference (id, source_system, object_type, external_id, entity_id, created_by) "
        "VALUES (gen_random_uuid(), 'SYN', 'PARTY', 'C1', gen_random_uuid(), 't')"
    )
    assert rejected(conn, dup) == "23505"


def test_authorisation_evidence_is_all_or_nothing(conn: Connection) -> None:
    policy, party = make_policy(conn), make_party(conn)
    ins(conn, "policy_party_role", policy_id=policy, party_id=party, role="AUTHORIZED_CONTACT", valid_from=NOW)
    sql = (
        f"INSERT INTO {SCHEMA}.policy_party_role (id, policy_id, party_id, role, valid_from, authorization_ref, "
        "created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) VALUES "
        "(gen_random_uuid(), :p, :y, 'AUTHORIZED_CONTACT', now() + interval '1 day', 'AUTH-1', 't', 'SEED', 's', 'r', "
        "now(), true)"
    )
    assert rejected(conn, sql, {"p": policy, "y": party}) == CHECK  # ref without validity start
