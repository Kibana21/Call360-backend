"""Prepare the TEST schema for browser E2E runs: guarded reset of call360_test (never call360), then create
E2E accounts with random passwords written to the JSON path given (gitignored in the frontend).

Usage: CALL360_ENV_FILE=.env.test uv run python scripts/e2e_setup.py <accounts.json>
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.audit.chain import Actor, RequestMeta  # noqa: E402
from app.core.settings import load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from app.domain.protection import DataProtection  # noqa: E402
from app.domain.seed import seed  # noqa: E402
from app.security.identity import create_local_account  # noqa: E402
from tests.support import reset_test_schema  # noqa: E402

ACCOUNTS = [
    ("e2e.admin", "E2E Administrator", "LOCAL_ADMIN"),
    ("e2e.user", "E2E Operations User", "LOCAL_USER_SG"),
    ("e2e.victim", "E2E Disable Target", "LOCAL_USER_SG"),
    ("e2e.tabs", "E2E Multi Tab", "LOCAL_USER_SG"),
]


def main() -> int:
    settings = load_settings(ROOT / ".env.test")
    if settings.app_env != "test":
        raise SystemExit("e2e_setup requires the test configuration")
    engine = make_engine(settings)
    reset_test_schema(engine, settings)
    with engine.begin() as conn:  # S0-SEED-1 so the Overview runs on real seeded data (call360_test only)
        seed(conn, settings.target_schema, DataProtection.from_settings(settings))
    out: dict[str, dict[str, str]] = {}
    with make_session_factory(engine)() as db, db.begin():
        for username, display, group in ACCOUNTS:
            password = secrets.token_urlsafe(18)
            create_local_account(
                db,
                username=username,
                display_name=display,
                password=password,
                group_code=group,
                created_by="SYSTEM:e2e",
                actor=Actor(service="e2e-setup"),
                meta=RequestMeta(),
            )
            out[username.split(".")[1]] = {"username": username, "password": password, "display_name": display}
    target = Path(sys.argv[1])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out))
    target.chmod(0o600)
    print(f"E2E schema reset, S0-SEED-1 seeded and {len(out)} accounts created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
