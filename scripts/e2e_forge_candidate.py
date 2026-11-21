# ruff: noqa: E501
"""FI-2 — TEST SCHEMA ONLY: write a tampered candidate around the service, as someone with database access might, so the
browser journey and the backend tests can show that the application detects it and refuses to approve or publish it.

The forged row copies the survey's newest candidate and changes ONE pinned hash in its manifest (and the manifest hash to
match, so only a real re-verification can catch it). Refuses anything but the test configuration.

Usage: CALL360_ENV_FILE=.env.test uv run python scripts/e2e_forge_candidate.py <survey code>
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.settings import load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from app.domain.survey.canonical import sha256_hex  # noqa: E402


def forge(db: Session, survey_code: str) -> uuid.UUID:
    """Insert the forged candidate and its SUBMITTED event. Returns its id. The caller commits."""
    real = db.execute(
        text(
            "SELECT c.* FROM survey_candidate c JOIN survey_definition d ON d.id = c.survey_definition_id "
            "WHERE d.code = :c ORDER BY c.n DESC LIMIT 1"
        ),
        {"c": survey_code},
    ).mappings().one()  # fmt: skip
    manifest = [{**e, "sha256": "0" * 64} if i == 0 else e for i, e in enumerate(real["manifest"])]
    fid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_candidate (id, survey_definition_id, n, draft_revision, content, content_sha256, manifest, "
            "manifest_sha256, makers, note, acknowledgements, submitted_by) VALUES (:i, :s, :n, :r, CAST(:c AS jsonb), :ch, "
            "CAST(:m AS jsonb), :mh, CAST(:mk AS jsonb), :note, CAST(:a AS jsonb), :by)"
        ),
        {
            "i": fid, "s": real["survey_definition_id"], "n": real["n"] + 1, "r": real["draft_revision"],
            "c": json.dumps(real["content"]), "ch": real["content_sha256"], "m": json.dumps(manifest),
            "mh": sha256_hex(manifest), "mk": json.dumps(real["makers"]), "note": "FORGED for a tamper test",
            "a": json.dumps(real["acknowledgements"]), "by": real["submitted_by"],
        },
    )  # fmt: skip
    db.execute(
        text(
            "INSERT INTO survey_lifecycle_event (id, subject_type, subject_id, survey_definition_id, event, actor_ref) "
            "VALUES (:i, 'CANDIDATE', :s, :d, 'SUBMITTED', :by)"
        ),
        {"i": uuid.uuid4(), "s": fid, "d": real["survey_definition_id"], "by": real["submitted_by"]},
    )
    return fid


def main() -> int:
    settings = load_settings(ROOT / ".env.test")
    if settings.app_env != "test" or settings.target_schema != "call360_test":
        raise SystemExit("e2e_forge_candidate requires the test configuration")
    with make_session_factory(make_engine(settings))() as db, db.begin():
        db.execute(text("SET search_path TO call360_test"))
        fid = forge(db, sys.argv[1])
    print(fid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
