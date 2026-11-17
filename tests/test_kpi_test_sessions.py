"""D-48 (owner decision 2026-11-17): marked Call360 browser test sessions are excluded from operational callback KPI
numerators and denominators, while ordinary (seeded) attempts are never excluded because the database is synthetic.
Pure predicate tests over constructed facts; the integrated API check is in test_recording.py."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

from app.domain.kpis import Case, Facts, compute_kpis, is_test_attempt, kpi_01, kpi_12, local_range, trend

NOW = datetime(2026, 11, 17, 4, 0, tzinfo=UTC)
DAY = date(2026, 11, 17)
S, E = local_range(DAY - timedelta(days=1), DAY + timedelta(days=1))


def _case(ref: str) -> Case:
    return Case(
        uuid.uuid4(),
        ref,
        "OPEN",
        NOW + timedelta(hours=2),
        NOW - timedelta(days=3),
        "SYNTHETIC",
        None,
        None,
        None,
        None,
        None,
        False,
        True,
        uuid.uuid4(),
    )


def _facts(rows: list[tuple[Case, int, str, bool]]) -> Facts:
    """rows: (case, sequence, status, is_test). Mirrors load_facts: Case.attempts keeps every row."""
    f = Facts(["SG"], NOW, {}, [], [], [], {}, set(), None, [])
    for c, seq, status, test in rows:
        f.cases[c.id] = c
        aid, at = uuid.uuid4(), NOW - timedelta(minutes=60 - seq)
        c.attempts.append((seq, status, at))
        f.attempts.append((aid, c.id, status, at))
        if test:
            f.test_attempts.add(aid)
        else:
            c.ops_attempts.append((seq, status, at))
    return f


def test_marker_is_explicit_runtime_browser_origin_only() -> None:
    assert is_test_attempt("BROWSER", "CALL360_RUNTIME")
    assert not is_test_attempt("BROWSER", "SYNTHETIC_SEED")  # a seeded browser attempt is an ordinary attempt
    assert not is_test_attempt("PHONE", "CALL360_RUNTIME")
    assert not is_test_attempt(None, None)


def test_case_covered_only_by_a_test_session_is_not_covered() -> None:
    only_test, seeded = _case("ONLY-TEST"), _case("SEEDED")
    f = _facts([(only_test, 1, "ENDED", True), (seeded, 1, "NO_ANSWER", False)])
    den, num = kpi_01(f, S, E)
    assert den == {only_test.id, seeded.id}  # the case still counts in the coverage denominator (it is due)
    assert num == {seeded.id}
    assert len(only_test.attempts) == 1  # still visible to case history


def test_connection_rate_and_trend_exclude_test_sessions_from_both_sides() -> None:
    a, b = _case("A"), _case("B")
    f = _facts([(a, 1, "NO_ANSWER", False), (a, 2, "CONNECTED", False), (b, 1, "ENDED", True), (b, 2, "ENDED", True)])
    k02 = next(
        k
        for k in compute_kpis(f, DAY - timedelta(days=1), DAY + timedelta(days=1), frozenset())
        if k["definition_id"] == "KPI-02"
    )
    assert (k02["numerator"], k02["denominator"], k02["value"]) == (1, 2, 50.0)
    assert k02["exclusions"]["test_sessions_excluded"] is True
    assert k02["exclusions"]["test_sessions_excluded_count"] == 2
    today = next(p for p in trend(f, "KPI-02", 7) if p["date"] == DAY)  # NOW is 12:00 on DAY in Singapore
    assert (today["numerator"], today["denominator"]) == (1, 2)


def test_retry_conversion_ignores_test_sessions_and_interleaved_ordinals() -> None:
    interleaved, test_retry = _case("INTERLEAVED"), _case("TEST-RETRY")
    f = _facts(
        [
            # test session first, then one real attempt that connects: first operational attempt, not a retry
            (interleaved, 1, "ENDED", True),
            (interleaved, 2, "CONNECTED", False),
            # one real no-answer plus a test session: fewer than two operational attempts, not in the denominator
            (test_retry, 1, "NO_ANSWER", False),
            (test_retry, 2, "CONNECTED", True),
        ]
    )
    den, num = kpi_12(f, S, E)
    assert den == set() and num == set()
    retried = _case("RETRIED")
    f2 = _facts([(retried, 1, "NO_ANSWER", False), (retried, 2, "ENDED", True), (retried, 3, "CONNECTED", False)])
    den, num = kpi_12(f2, S, E)
    assert den == {retried.id} and num == {retried.id}  # second operational attempt connected
