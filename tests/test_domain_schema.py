"""BE-DATA-01 and BE-DATA-05 for CP0.2 — physical build scope per revision, round trips, provenance."""

from __future__ import annotations

from sqlalchemy import Engine, func, select, text

from app.core.settings import Settings
from app.domain.catalog import (
    CP02_TABLES,
    DEFERRED_TABLES,
    LATER_MIGRATION_TABLES,
    MIGRATION_TABLES,
    P_TABLES,
    PROVENANCE_COLUMNS,
)
from app.security.models import AuditEvent, Principal
from tests.domain_support import SCHEMA, assert_audit_append_only, audit_rows, revisions, tables_at
from tests.support import Account, migrate


def _tables(engine: Engine) -> set[str]:
    with engine.connect() as c:
        return set(c.execute(text(f"SELECT tablename FROM pg_tables WHERE schemaname='{SCHEMA}'")).scalars())


def _identity_counts(engine: Engine) -> tuple[int, int, int]:
    with engine.connect() as c:
        return (
            c.execute(select(func.count()).select_from(Principal.__table__)).scalar_one(),
            c.execute(select(func.count()).select_from(AuditEvent.__table__)).scalar_one(),
            c.execute(text(f"SELECT count(*) FROM {SCHEMA}.code_value")).scalar_one(),
        )


def test_be_data_01_each_cp02_revision_round_trips_and_preserves_earlier_data(
    fresh_schema: None, admin: Account, engine: Engine, settings: Settings
) -> None:
    revs = revisions()
    cp02 = [r for r in revs if r in MIGRATION_TABLES or r in LATER_MIGRATION_TABLES]
    assert cp02, "no CP0.2 revisions"
    before = _identity_counts(engine)
    audit_before = audit_rows(engine)
    for rev in reversed(cp02):  # step down one revision at a time to 0002
        target = revs[revs.index(rev) - 1]
        migrate(settings, target, down=True)
        assert _tables(engine) == tables_at(target) | {"alembic_version"}, target
    assert _tables(engine) == tables_at("0002_config_foundation") | {"alembic_version"}
    principals, _, values_at_0002 = _identity_counts(engine)
    assert principals == before[0]
    for rev in cp02:  # and back up one at a time
        migrate(settings, rev)
        assert _tables(engine) == tables_at(rev) | {"alembic_version"}, rev
    after = _identity_counts(engine)
    assert (after[0], after[2]) == (before[0], before[2])  # identity unchanged; governed values re-created
    assert values_at_0002 == before[2] - _governed_value_count(engine)
    # Audit is append-only: earlier events are untouched; the round trip adds one removal and one
    # re-activation per governed list (bootstrap audit, D-36).
    appended = assert_audit_append_only(audit_before, audit_rows(engine))
    assert appended == {
        "CONFIG.CODE_LIST_VERSION_REMOVED": 9,
        "CONFIG.CODE_LIST_VERSION_ACTIVATED": 9,
        "ADMIN.GROUP_MAPPING_CHANGED": 4,  # 2 seeded scope mappings removed and re-added (D-39)
    }


def _governed_value_count(engine: Engine) -> int:
    with engine.connect() as c:
        return int(
            c.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.code_value cv JOIN {SCHEMA}.code_list_version v "
                    f"ON v.id = cv.code_list_version_id JOIN {SCHEMA}.code_list l ON l.id = v.code_list_id "
                    "WHERE l.governed"
                )
            ).scalar_one()
        )


def test_be_data_01_deferred_tables_are_not_built(engine: Engine) -> None:
    built = _tables(engine)
    assert not (built & DEFERRED_TABLES)
    assert built - {"alembic_version"} <= tables_at(revisions()[-1])


def test_be_data_01_cp02_table_catalogue_has_34_tables() -> None:
    assert len(CP02_TABLES) == 34 and len(set(CP02_TABLES)) == 34


def test_be_data_05_provenance_not_null_on_every_p_table(engine: Engine) -> None:
    built = _tables(engine)
    with engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT table_name, column_name, is_nullable FROM information_schema.columns "
                f"WHERE table_schema = '{SCHEMA}'"
            )
        ).all()
    nullable = {(r.table_name, r.column_name): r.is_nullable for r in rows}
    checked = [t for t in P_TABLES if t in built]
    assert checked
    for table in checked:
        for col in PROVENANCE_COLUMNS:
            assert nullable.get((table, col)) == "NO", f"{table}.{col}"
