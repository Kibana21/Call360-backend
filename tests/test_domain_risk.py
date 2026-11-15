"""Migration 0004 integrity — SBQ selection risk only (INV-08), governed band and factor references (INV-12,
BE-DATA-13), supersession transitions (D-31, INV-13), frozen factor results (RISK-003)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from tests.domain_support import (
    FACTORS,
    NOW,
    SCHEMA,
    draft_version,
    ensure_active,
    ins,
    make_assessment,
    make_policy,
    make_sale,
    rejected,
)

IMMUTABLE, CHECK, FK = "42501", "23514", "23503"


def _status(conn: Connection, aid: uuid.UUID, status: str) -> None:
    conn.execute(text(f"UPDATE {SCHEMA}.risk_assessment SET status = :s WHERE id = :i"), {"s": status, "i": aid})


def _sale(conn: Connection) -> uuid.UUID:
    return make_sale(conn, make_policy(conn))


def test_be_data_06_only_callback_selection_kind(conn: Connection) -> None:
    aid = make_assessment(conn, _sale(conn))
    sql = f"UPDATE {SCHEMA}.risk_assessment SET kind = 'INVESTMENT_SUITABILITY' WHERE id = :i"
    assert rejected(conn, sql, {"i": aid}) in {CHECK, IMMUTABLE}
    cols = {
        r[0]
        for r in conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema='{SCHEMA}' AND table_name='risk_assessment'"
            )
        )
    }
    assert not {c for c in cols if "suitab" in c or "tolerance" in c or "severity" in c}


def test_be_data_13_band_reference_rejects_unknown_wrong_list_and_inactive(conn: Connection) -> None:
    sale = _sale(conn)
    active = ensure_active(conn, "sbq_risk_band", {"HIGH": {}, "LOW": {}, "MEDIUM": {}, "UNKNOWN": {}})
    sql = f"UPDATE {SCHEMA}.risk_assessment SET band_code = :c, band_list_version_id = :v WHERE id = :i"
    aid = make_assessment(conn, sale, band_list_version_id=active)
    # Unknown code in the right version: composite FK.
    assert rejected(conn, sql, {"c": "SEVERE", "v": active, "i": aid}) in {FK, IMMUTABLE}
    wrong_list = ensure_active(conn, "risk_factor", {"HIGH": {}})  # an ACTIVE version of another list
    ins_sql = (
        f"INSERT INTO {SCHEMA}.risk_assessment (id, sale_event_id, kind, origin, status, band_code, "
        "band_list_version_id, "
        "explanation, assessed_at, valid_at, input_snapshot_sha256, created_by, source_type, source_system, "
        "source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), :s, 'CALLBACK_SELECTION', "
        "'SOURCE_ASSIGNED', 'PROVISIONAL', :c, :v, 'x', now(), now(), repeat('a', 64), 't', 'SEED', 's', 'r', "
        "now(), true)"
    )
    assert rejected(conn, ins_sql, {"s": sale, "c": "HIGH", "v": wrong_list}) == CHECK  # code exists, wrong list
    assert rejected(conn, ins_sql, {"s": sale, "c": "SEVERE", "v": active}) == FK
    draft = draft_version(conn, "sbq_risk_band", {"HIGH": {}})
    assert rejected(conn, ins_sql, {"s": sale, "c": "HIGH", "v": draft}) == CHECK  # not ACTIVE at insert


def test_be_data_13_pinned_band_survives_a_later_list_version(conn: Connection) -> None:
    aid = make_assessment(conn, _sale(conn))
    _status(conn, aid, "FINAL")
    pinned = conn.execute(text(f"SELECT band_list_version_id FROM {SCHEMA}.risk_assessment WHERE id=:i"), {"i": aid})
    old = pinned.scalar_one()
    new = draft_version(conn, "sbq_risk_band", {"LOW": {}, "HIGH": {}})
    conn.execute(text(f"UPDATE {SCHEMA}.code_list_version SET status='SUPERSEDED' WHERE id=:v"), {"v": old})
    conn.execute(text(f"UPDATE {SCHEMA}.code_list_version SET status='ACTIVE' WHERE id=:v"), {"v": new})
    row = conn.execute(
        text(f"SELECT band_code, band_list_version_id FROM {SCHEMA}.risk_assessment WHERE id=:i"), {"i": aid}
    ).one()
    assert (row.band_code, row.band_list_version_id) == ("HIGH", old)
    # A later status change on the row does not re-validate its (now superseded) pin.
    successor = make_assessment(
        conn,
        conn.execute(text(f"SELECT sale_event_id FROM {SCHEMA}.risk_assessment WHERE id=:i"), {"i": aid}).scalar_one(),
        supersedes_id=aid,
        band_list_version_id=new,
    )
    _status(conn, aid, "SUPERSEDED")
    assert successor


def test_inv_13_supersession_transitions(conn: Connection) -> None:
    sale = _sale(conn)
    a = make_assessment(conn, sale)
    _status(conn, a, "FINAL")
    for bad in ("PROVISIONAL", "SUPERSEDED"):  # back to provisional; superseded with no successor
        assert rejected(conn, f"UPDATE {SCHEMA}.risk_assessment SET status='{bad}' WHERE id=:i", {"i": a}) == IMMUTABLE
    for col, val in [("explanation", "'edited'"), ("band_code", "'LOW'"), ("valid_at", "now()")]:
        sql = f"UPDATE {SCHEMA}.risk_assessment SET {col} = {val} WHERE id = :i"
        assert rejected(conn, sql, {"i": a}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.risk_assessment WHERE id=:i", {"i": a}) == IMMUTABLE
    b = make_assessment(conn, sale, supersedes_id=a, band_code="LOW")
    _status(conn, a, "SUPERSEDED")
    _status(conn, b, "FINAL")
    assert rejected(conn, f"UPDATE {SCHEMA}.risk_assessment SET status='FINAL' WHERE id=:i", {"i": a}) == IMMUTABLE
    # A successor must supersede a current assessment of the same sale, and only one successor each.
    assert rejected_insert(conn, sale, supersedes_id=a) == CHECK
    assert rejected_insert(conn, _sale(conn), supersedes_id=b) == CHECK
    assert rejected_insert(conn, sale, status="SUPERSEDED") == CHECK


def rejected_insert(conn: Connection, sale: uuid.UUID, **over: object) -> str:
    sp = conn.begin_nested()
    try:
        make_assessment(conn, sale, **over)
    except DBAPIError as exc:
        sp.rollback()
        return str(getattr(exc.orig, "sqlstate", ""))
    sp.rollback()
    raise AssertionError("insert unexpectedly succeeded")


def test_inv_13_successor_without_superseding_fails_at_commit(engine: Engine) -> None:
    with engine.connect() as c:
        sale = _sale(c)
        a = make_assessment(c, sale)
        _status(c, a, "FINAL")
        make_assessment(c, sale, supersedes_id=a)
        with pytest.raises(DBAPIError) as exc:
            c.commit()  # deferred check: predecessor still FINAL
        assert getattr(exc.value.orig, "sqlstate", None) == CHECK


def test_rule_assessed_needs_rule_set_and_score_needs_rule_set(conn: Connection) -> None:
    sale = _sale(conn)
    assert rejected_insert(conn, sale, origin="RULE_ASSESSED") == CHECK
    assert rejected_insert(conn, sale, score=1) == CHECK


def test_factor_results_frozen_once_assessment_is_final(conn: Connection) -> None:
    a = make_assessment(conn, _sale(conn))
    fv = ensure_active(conn, "risk_factor", FACTORS)
    fid = ins(
        conn,
        "risk_factor_result",
        assessment_id=a,
        factor_code="ILP_INDICATOR",
        factor_list_version_id=fv,
        value_type="BOOLEAN",
        value=True,
        source="PYTEST",
        result="MATCHED",
    )
    _status(conn, a, "FINAL")
    assert (
        rejected(conn, f"UPDATE {SCHEMA}.risk_factor_result SET result='NOT_MATCHED' WHERE id=:i", {"i": fid})
        == IMMUTABLE
    )
    assert rejected(conn, f"DELETE FROM {SCHEMA}.risk_factor_result WHERE id=:i", {"i": fid}) == IMMUTABLE
    sql = (
        f"INSERT INTO {SCHEMA}.risk_factor_result (id, assessment_id, factor_code, factor_list_version_id, value_type, "
        "value, source, result, created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) "
        "VALUES (gen_random_uuid(), :a, 'SELLING_CHANNEL', :v, 'ENUM', '\"AGENCY\"', 's', 'MATCHED', 't', 'SEED', 's', "
        "'r', now(), true)"
    )
    assert rejected(conn, sql, {"a": a, "v": fv}) == IMMUTABLE
    assert NOW
