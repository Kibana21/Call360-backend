"""Canonical hashing for snapshots, manifests and the seed content digest (S0_DATA_MODEL §6, D-33)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import Connection, text

from app.domain.catalog import CIPHERTEXT_SUFFIX, CP02_TABLES, DIGEST_EXCLUDED_COLUMNS, GOVERNED_LISTS


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def content_digest(conn: Connection, schema: str) -> str:
    """SHA-256 over every CP0.2 business row and the governed code-list values, in migration order and id
    order. Excludes randomised ciphertext and operational metadata. Keyed values (``value_hmac``) are
    included, so the digest is reproducible only with the same HMAC key."""
    assert schema in {"call360", "call360_test"}, schema
    conn.execute(text("SET LOCAL TIME ZONE 'UTC'"))  # stable jsonb timestamp text
    h = hashlib.sha256()
    for table in (*CP02_TABLES, "code_value"):
        where = ""
        if table == "code_value":
            where = (
                f" WHERE t.code_list_version_id IN (SELECT v.id FROM {schema}.code_list_version v "
                f"JOIN {schema}.code_list l ON l.id = v.code_list_id WHERE l.code = ANY(:lists))"
            )
        rows = conn.execute(
            text(f"SELECT to_jsonb(t) FROM {schema}.{table} t{where} ORDER BY t.id"),  # noqa: S608
            {"lists": list(GOVERNED_LISTS)},
        ).scalars()
        h.update(f"#{table}\n".encode())
        for row in rows:
            kept = {
                k: v for k, v in row.items() if k not in DIGEST_EXCLUDED_COLUMNS and not k.endswith(CIPHERTEXT_SUFFIX)
            }
            h.update(canonical(kept).encode() + b"\n")
    return h.hexdigest()
