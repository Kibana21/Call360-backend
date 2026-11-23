"""Deterministic OpenAPI export (ADR-0006 §1). Uses fixed, non-secret settings so the artifact never
depends on the local environment. ``--check`` fails if the committed artifact differs."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.settings import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "contracts" / "generated"


def render() -> str:
    fixed = Settings(  # type: ignore[call-arg]
        _env_file=None,
        app_env="local",
        app_database_url="postgresql+psycopg://openapi@localhost/Call360_db",
        app_db_schema="call360",
        expected_db_role="openapi",
        refresh_token_pepper="openapi-export",  # noqa: S106 — fixed non-secret; no DB/tokens used
        csrf_secret="openapi-export",  # noqa: S106 — fixed non-secret placeholder
        # SS-03A: the contract documents the survey-definition operations so the client is typed for them. A running
        # server registers them only when this setting is on, and it is OFF by default.
        survey_definitions_enabled=True,
        survey_library_enabled=True,  # LIB-1: documented in the contract; registered only when both settings are on
        survey_simulation_enabled=True,  # SS-03B: documented in the contract; registered only when switched on
        survey_assignment_enabled=True,  # ASG-1: likewise
        survey_assignment_groups_enabled=True,  # ASG-2A: likewise
        survey_coordinated_simulation_enabled=True,  # ASG-2B: likewise
        survey_evaluation_enabled=True,  # EVAL-1: likewise
        survey_control_policy_enabled=True,  # EVAL-2A: likewise
        survey_execution_assurance_enabled=True,  # EVAL-2B: likewise
        survey_module_authoring_enabled=True,  # LIB-2: likewise
        shared_rule_services_enabled=True,  # SHARED-1: likewise
        survey_applicability_prototype_enabled=True,  # APPL-X1: the stateless prototype operations
    )
    spec = create_app(fixed, with_database=False).openapi()
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    text = render()
    digest = hashlib.sha256(text.encode()).hexdigest()
    target, sha = OUT / "openapi.json", OUT / "openapi.sha256"
    if "--check" in sys.argv:
        ok = target.exists() and target.read_text() == text and sha.read_text().strip() == digest
        print(f"OpenAPI {'matches' if ok else 'DRIFT: regenerate with make openapi'} ({digest})")
        return 0 if ok else 1
    OUT.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    sha.write_text(digest + "\n")
    print(f"Wrote contracts/generated/openapi.json ({digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
