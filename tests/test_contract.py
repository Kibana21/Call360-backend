"""BE-CT-01 — OpenAPI regenerates byte-identically and matches the committed artifact."""

from __future__ import annotations

import hashlib

from scripts.export_openapi import OUT, render


def test_be_ct_01_openapi_is_deterministic_and_current() -> None:
    first, second = render(), render()
    assert first == second
    assert (OUT / "openapi.json").read_text() == first, "run `make openapi`"
    assert (OUT / "openapi.sha256").read_text().strip() == hashlib.sha256(first.encode()).hexdigest()
    assert '"operationId": "auth_login"' in first and "/api/v1/admin/users/{principal_id}" in first
