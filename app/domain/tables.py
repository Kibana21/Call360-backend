"""Reflected Core tables for the CP0.2 domain. The migrations own the DDL; the seed and tests bind to the
reflected tables so there is a single schema definition (ORM models arrive with the CP0.3 read APIs)."""

from __future__ import annotations

from sqlalchemy import Connection, MetaData, Table

from app.domain.catalog import CP02_TABLES

CONFIG_TABLES = ("code_list", "code_list_version", "code_value", "audit_event", "principal")


def reflect(conn: Connection, schema: str) -> dict[str, Table]:
    assert schema in {"call360", "call360_test"}, schema
    md = MetaData(schema=schema)
    names = [*CONFIG_TABLES, *CP02_TABLES]
    md.reflect(bind=conn, only=lambda name, _: name in names)
    return {t.name: t for t in md.tables.values()}
