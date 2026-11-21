# ruff: noqa: E501
"""FI-1 — prepare the TEST schema for the persisted Survey Studio browser journey: the standard E2E reset, seed and
accounts (scripts/e2e_setup.py), then synthetic people who hold survey permissions through TEST-ONLY roles. Never the
development schema: it refuses anything but the test configuration. No existing role is given a survey permission.

Usage: CALL360_ENV_FILE=.env.test uv run python scripts/e2e_survey_setup.py <accounts.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core.settings import load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from scripts import e2e_setup  # noqa: E402
from scripts.dev_survey_identities import _create  # noqa: E402

EDIT = ("survey.read", "survey.edit")
SG = (
    ("E2E_SURVEY_AUTHOR", "E2E survey author", "E2E_SURVEY_AUTHOR_SG", "e2e.survey.author", "E2E Survey Author", EDIT),
    ("E2E_SURVEY_AUTHOR", "E2E survey author", "E2E_SURVEY_AUTHOR2_SG", "e2e.survey.second", "E2E Second Author", EDIT),
    ("E2E_SURVEY_READER", "E2E survey reader", "E2E_SURVEY_READER_SG", "e2e.survey.reader", "E2E Survey Reader", ("survey.read",)),
)  # fmt: skip
#: holds read and edit, but is scoped to a market that is not enabled: sees no survey at all
ELSEWHERE = (
    ("E2E_SURVEY_AUTHOR", "E2E survey author", "E2E_SURVEY_AUTHOR_MY", "e2e.survey.elsewhere", "E2E Other Market", EDIT),
)  # fmt: skip


def main() -> int:
    settings = load_settings(ROOT / ".env.test")
    if settings.app_env != "test" or settings.target_schema != "call360_test":
        raise SystemExit("e2e_survey_setup requires the test configuration")
    target = Path(sys.argv[1])
    e2e_setup.main()  # reset of call360_test, seed, the standard accounts
    passwords: dict[str, str] = {}
    with make_session_factory(make_engine(settings))() as db, db.begin():
        _create(db, passwords, SG, "SG")
        _create(db, passwords, ELSEWHERE, "MY")
    out = json.loads(target.read_text())
    names = {u: d for _, _, _, u, d, _ in (*SG, *ELSEWHERE)}
    for username, password in passwords.items():
        out["survey_" + username.split(".")[-1]] = {
            "username": username, "password": password, "display_name": names[username],
        }  # fmt: skip
    target.write_text(json.dumps(out))
    target.chmod(0o600)
    print(f"Survey identities created in the test schema: {len(passwords)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
