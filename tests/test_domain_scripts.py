"""Migration 0005 integrity — script lifecycle and frozen content (ADR-0005 §3, ADR-0007), question revisions
immutable from insert (D-35), historical validity (D-32, INV-09), rules and regulatory references (REG-001)."""

from __future__ import annotations

from sqlalchemy import Connection, text

from tests.domain_support import (
    NOW,
    SCHEMA,
    days,
    ins,
    make_module,
    make_question,
    make_version,
    rejected,
)

IMMUTABLE, CHECK = "42501", "23514"
UPD = f"UPDATE {SCHEMA}.script_version SET "


def _valid_at(conn: Connection, vid: object, ts: object) -> bool:
    return bool(conn.execute(text(f"SELECT {SCHEMA}.script_version_valid_at(:v, :t)"), {"v": vid, "t": ts}).scalar())


def test_d35_question_revision_immutable_from_insert(conn: Connection) -> None:
    q = make_question(conn)
    sql = f"UPDATE {SCHEMA}.question_revision SET customer_wording = 'edited' WHERE id = :i"
    assert rejected(conn, sql, {"i": q}) == IMMUTABLE
    assert rejected(conn, f"DELETE FROM {SCHEMA}.question_revision WHERE id = :i", {"i": q}) == IMMUTABLE


def test_numeric_match_requires_a_policy_fact_key(conn: Connection) -> None:
    sp = conn.begin_nested()
    try:
        make_question(conn, answer_type="NUMERIC", expected_answer_policy="NUMERIC_MATCH_POLICY_FACT")
        raise AssertionError("accepted")
    except Exception as exc:  # noqa: BLE001
        sp.rollback()
        assert getattr(getattr(exc, "orig", None), "sqlstate", None) == CHECK
    make_question(
        conn,
        answer_type="NUMERIC",
        expected_answer_policy="NUMERIC_MATCH_POLICY_FACT",
        expected_value=None,
        policy_fact_key="premium_term_years",
    )


def test_lifecycle_and_content_frozen_after_draft(conn: Connection) -> None:
    module = make_module(conn, [make_question(conn)])
    draft = make_version(conn, [module], final="DRAFT")
    assert rejected(conn, UPD + "status = 'PUBLISHED' WHERE id = :i", {"i": draft}) == IMMUTABLE  # skips review
    assert rejected(conn, UPD + "status = 'SUBMITTED_FOR_REVIEW' WHERE id = :i", {"i": draft}) == CHECK  # no manifest
    v = make_version(conn, [module])
    for col, val in [("manifest", "'{}'"), ("manifest_sha256", "repeat('b', 64)"), ("language", "'ms'")]:
        assert rejected(conn, UPD + f"{col} = {val} WHERE id = :i", {"i": v}) == IMMUTABLE
    assert rejected(conn, UPD + "published_at = now() WHERE id = :i", {"i": v}) == IMMUTABLE  # set once
    assert rejected(conn, UPD + "status = 'SUPERSEDED' WHERE id = :i", {"i": v}) == CHECK  # needs effective_to
    assert rejected(conn, f"DELETE FROM {SCHEMA}.script_version WHERE id = :i", {"i": v}) == IMMUTABLE
    assert (
        rejected(
            conn,
            f"INSERT INTO {SCHEMA}.script_section (id, script_version_id, script_module_id, position, "
            "created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) VALUES "
            "(gen_random_uuid(), :v, :m, 9, 't', 'SEED', 's', 'r', now(), true)",
            {"v": v, "m": module},
        )
        == IMMUTABLE
    )
    conn.execute(text(UPD + "status = 'SUPERSEDED', effective_to = :e WHERE id = :i"), {"e": NOW, "i": v})
    assert rejected(conn, UPD + "effective_to = now() WHERE id = :i", {"i": v}) == IMMUTABLE  # set once
    assert rejected(conn, UPD + "status = 'PUBLISHED' WHERE id = :i", {"i": v}) == IMMUTABLE


def test_insert_must_be_draft_and_reviewer_must_differ(conn: Connection) -> None:
    fam = ins(conn, "script_family", code="F-INS", name="x", market_code="SG", purpose="P", description="x")
    base = (
        f"INSERT INTO {SCHEMA}.script_version (id, script_family_id, version_label, status, validation_status, "
        "language, author_ref, reviewer_ref, content_approval_status, created_by, source_type, source_system, "
        "source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), :f, :l, :s, 'NOT_VALIDATED', 'en', "
        "'a', :r, 'SYNTHETIC_UNAPPROVED', 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, base, {"f": fam, "l": "9.0", "s": "PUBLISHED", "r": None}) == CHECK
    assert rejected(conn, base, {"f": fam, "l": "9.1", "s": "DRAFT", "r": "a"}) == CHECK  # maker = checker


def test_module_questions_frozen_once_module_published(conn: Connection) -> None:
    module = make_module(conn, [make_question(conn)])
    sql = f"UPDATE {SCHEMA}.module_question SET position = 7 WHERE script_module_id = :m"
    assert rejected(conn, sql, {"m": module}) == IMMUTABLE
    assert rejected(conn, f"UPDATE {SCHEMA}.script_module SET name = 'x' WHERE id = :m", {"m": module}) == IMMUTABLE
    draft_module = make_module(conn, [make_question(conn)], publish=False)
    draft = make_version(conn, [draft_module], final="DRAFT")
    sql = (
        UPD + "manifest = '{}', manifest_sha256 = repeat('c', 64), validation_status = 'VALID', "
        "status = 'SUBMITTED_FOR_REVIEW' WHERE id = :i"
    )
    # S2-A (0015): a draft may be submitted and approved with its own DRAFT modules (the checker reviews them before
    # anything is published), but it cannot be PUBLISHED until every module is.
    conn.execute(text(sql), {"i": draft})
    conn.execute(text(UPD + "status = 'APPROVED', reviewer_ref = 'SYNTHETIC-REVIEWER-02' WHERE id = :i"), {"i": draft})
    publish = UPD + "status = 'PUBLISHED', published_at = now(), effective_from = now() WHERE id = :i"
    assert rejected(conn, publish, {"i": draft}) == CHECK  # module still DRAFT


def test_d32_validity_uses_history_not_current_status(conn: Connection) -> None:
    module = make_module(conn, [make_question(conn)])
    superseded = make_version(
        conn, [module], published_at=NOW - days(300), effective_to=NOW - days(100), final="SUPERSEDED"
    )
    withdrawn = make_version(
        conn, [module], published_at=NOW - days(90), effective_to=NOW - days(60), final="WITHDRAWN"
    )
    draft = make_version(conn, [module], final="DRAFT")
    assert _valid_at(conn, superseded, NOW - days(200))  # valid then, SUPERSEDED now
    assert not _valid_at(conn, superseded, NOW - days(100))  # interval end is exclusive
    assert not _valid_at(conn, superseded, NOW - days(301))  # before publication
    assert _valid_at(conn, withdrawn, NOW - days(70))
    assert not _valid_at(conn, withdrawn, NOW - days(10))
    assert not _valid_at(conn, draft, NOW)


def test_assignment_rule_cannot_target_draft_and_is_immutable(conn: Connection) -> None:
    module = make_module(conn, [make_question(conn)])
    draft = make_version(conn, [module], final="DRAFT")
    sql = (
        f"INSERT INTO {SCHEMA}.script_assignment_rule_version (id, rule_code, version, predicate, priority, "
        "specificity, "
        "target_script_version_id, effective_from, status, checksum, author_ref, checker_ref, created_by, source_type, "
        "source_system, source_reference, recorded_at, is_synthetic) VALUES (gen_random_uuid(), 'R', 1, '{}', 1, 1, "
        ":v, "
        "now(), 'PUBLISHED', repeat('d', 64), 'a', :c, 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, sql, {"v": draft, "c": "b"}) == CHECK
    assert rejected(conn, sql, {"v": make_version(conn, [module]), "c": "a"}) == CHECK  # maker = checker


def test_regulatory_reference_market_and_status(conn: Connection) -> None:
    base = (
        f"INSERT INTO {SCHEMA}.regulatory_reference (id, issuer, jurisdiction, market_code, title, document_version, "
        "interpretation_status, created_by, source_type, source_system, source_reference, recorded_at, is_synthetic) "
        "VALUES (gen_random_uuid(), 'SYN', 'SG', :m, 't', '1', :s, 't', 'SEED', 's', 'r', now(), true)"
    )
    assert rejected(conn, base, {"m": "XX", "s": "NOT_REVIEWED"}) == CHECK
    assert rejected(conn, base, {"m": "SG", "s": "APPROVED"}) == CHECK
