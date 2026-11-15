"""DDL helpers shared by the CP0.2 migrations (S0_DATA_MODEL §2 common columns, §3 enumerations).

Enumerations are text columns with named CHECK constraints (as in CP0.1B-1), so later stages can widen
them by replacing a constraint. Reserved values (italic in §3) are accepted now and never produced in S0.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

TS = sa.DateTime(timezone=True)

SOURCE_TYPES = ("SEED", "MOCK_API", "MANUAL", "BULK", "INTERNAL_API")
RECORD_ORIGINS = ("SYNTHETIC_SEED", "CALL360_RUNTIME")
CONTENT_APPROVAL = ("SYNTHETIC_UNAPPROVED", "APPROVED_BY_SC")


def uid() -> UUID[uuid.UUID]:
    return UUID(as_uuid=True)


def pk() -> sa.Column[object]:
    return sa.Column("id", uid(), primary_key=True)


def fk(name: str, target: str, schema: str, *, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, uid(), sa.ForeignKey(f"{schema}.{target}.id"), nullable=nullable)


def enum_check(column: str, values: tuple[str, ...], name: str, *, nullable: bool = False) -> sa.CheckConstraint:
    allowed = ", ".join(f"'{v}'" for v in values)
    expr = f"{column} IN ({allowed})"
    return sa.CheckConstraint(f"{column} IS NULL OR {expr}" if nullable else expr, name=name)


def operational(*, mutable: bool) -> list[sa.Column[object]]:
    cols: list[sa.Column[object]] = [
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("correlation_id", sa.String(80)),
    ]
    if mutable:
        cols += [
            sa.Column("updated_at", TS),
            sa.Column("updated_by", sa.String(80)),
            sa.Column("row_version", sa.Integer, nullable=False, server_default="1"),
        ]
    return cols


def provenance(table: str) -> list[sa.Column[object] | sa.CheckConstraint]:
    """Provenance and data-classification columns for **P** tables (INV-07). ``intake_item_id`` gets its FK
    in CP0.4, when ``intake_item`` exists. ``is_synthetic`` has no CHECK (ADR-0008 §6)."""
    return [
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("source_system", sa.String(80), nullable=False),
        sa.Column("source_reference", sa.String(160), nullable=False),
        sa.Column("source_observed_at", TS),
        sa.Column("recorded_at", TS, nullable=False),
        sa.Column("mapping_version", sa.String(40)),
        sa.Column("intake_item_id", uid()),
        sa.Column("is_synthetic", sa.Boolean, nullable=False),
        enum_check("source_type", SOURCE_TYPES, f"ck_{table}_source_type"),
        sa.CheckConstraint("length(source_system) > 0 AND length(source_reference) > 0", name=f"ck_{table}_source"),
    ]


def record_origin(table: str) -> list[sa.Column[object] | sa.CheckConstraint]:
    return [
        sa.Column("record_origin", sa.String(16), nullable=False),
        enum_check("record_origin", RECORD_ORIGINS, f"ck_{table}_record_origin"),
    ]


def sha256_check(column: str, table: str, *, nullable: bool = False) -> sa.CheckConstraint:
    expr = f"{column} ~ '^[0-9a-f]{{64}}$'"
    return sa.CheckConstraint(f"{column} IS NULL OR {expr}" if nullable else expr, name=f"ck_{table}_{column}")


def code_ref(table: str, code_col: str, version_col: str, schema: str) -> list[sa.Column[object] | sa.Constraint]:
    """Governed decision code + list version (S0_DATA_MODEL §2.1, D-30). The composite FK proves the code
    exists in that version; trigger ``assert_code_ref`` proves the list and the ACTIVE-at-insert rule."""
    return [
        sa.Column(code_col, sa.String(40)),
        sa.Column(version_col, uid()),
        sa.ForeignKeyConstraint(
            [version_col, code_col],
            [f"{schema}.code_value.code_list_version_id", f"{schema}.code_value.code"],
            name=f"fk_{table}_{code_col}",
        ),
        sa.CheckConstraint(f"num_nonnulls({code_col}, {version_col}) IN (0, 2)", name=f"ck_{table}_{code_col}_pair"),
    ]


def forbid_change_trigger(schema: str, table: str) -> str:
    return (
        f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {schema}.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION {schema}.forbid_change();"
    )


def code_ref_trigger(schema: str, table: str, code_col: str, version_col: str, list_code: str) -> str:
    return (
        f"CREATE TRIGGER {table}_{code_col}_ref BEFORE INSERT OR UPDATE ON {schema}.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION {schema}.assert_code_ref('{list_code}', '{code_col}', '{version_col}');"
    )


def market_trigger(schema: str, table: str) -> str:
    return (
        f"CREATE TRIGGER {table}_market BEFORE INSERT OR UPDATE OF market_code ON {schema}.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION {schema}.assert_market_code();"
    )
