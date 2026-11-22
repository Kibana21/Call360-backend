# ruff: noqa: E501
"""EVAL-1 — TEST SCHEMA ONLY: what the browser journey needs that has no Survey Studio screen.

1. Publishes a SYNTHETIC finding rule set through the EXISTING finding-rule lifecycle (one person makes it, another
   reviews and publishes it), unless the market already has a published one.
2. Prints, for each named published survey, the exact item (code, version) at each placement — so the journey can
   propose governed control mappings through the real API.

Refuses anything but the test configuration. The rules and severities are test fixtures, not business policy.

Usage: CALL360_ENV_FILE=.env.test uv run python scripts/e2e_eval_setup.py "<survey name>" ["<survey name>" ...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import text  # noqa: E402

from app.core.settings import load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from app.domain import finding_rules  # noqa: E402
from app.domain.survey import control_evaluation as ce  # noqa: E402
from app.domain.survey import simulation, store  # noqa: E402

RULES = [
    {
        "rule_code": "FR-E2E-MISMATCH", "scope": "ANY_QUESTION", "target": None, "mandatory_only": False, "trigger": "MISMATCH",
        "category": "FACT_MISMATCH", "severity": "MEDIUM", "severity_justification": "Synthetic severity for the browser journey only",
        "description": "Synthetic: the answer differs from the governed expectation", "review_required": True,
    },
    {
        "rule_code": "FR-E2E-NOT-ASKED", "scope": "ANY_QUESTION", "target": None, "mandatory_only": True, "trigger": "NOT_ASKED",
        "category": "MISSING_MANDATORY_ANSWER", "severity": "LOW", "severity_justification": "Synthetic severity for the browser journey only",
        "description": "Synthetic: required evidence was never asked for", "review_required": True,
    },
]  # fmt: skip


def main() -> int:
    settings = load_settings(ROOT / ".env.test")
    if settings.app_env != "test" or settings.target_schema != "call360_test":
        raise SystemExit("e2e_eval_setup requires the test configuration")
    out: dict[str, object] = {}
    with make_session_factory(make_engine(settings))() as db, db.begin():
        db.execute(text("SET search_path TO call360_test"))
        if finding_rules.published(db, "SG") is None:
            vid = finding_rules.create_draft(db, "SG", "e2e.rules.maker", empty=True)
            finding_rules.update(db, vid, ["SG"], "e2e.rules.maker", 1, RULES, None)
            rv = finding_rules.version(db, vid, ["SG"])["row_version"]
            finding_rules.submit(db, vid, ["SG"], "e2e.rules.maker", rv, "Synthetic rules for the EVAL-1 journey")
            finding_rules.review(db, vid, ["SG"], "e2e.rules.checker", "APPROVE", "Synthetic approval")
            finding_rules.publish(db, vid, ["SG"], "e2e.rules.checker")
        published = finding_rules.published(db, "SG")
        assert published is not None
        out["finding_rule_set"] = {
            "version_id": str(published["id"]),
            "label": finding_rules.label(published),
            "sha256": published["rules_sha256"],
        }
        surveys: dict[str, object] = {}
        for name in sys.argv[1:]:
            v = next(
                x
                for x in reversed(store.published_versions(db, ["SG"]))
                if x["survey_name"] == name and x["event"] == "PUBLISHED"
            )
            bundle = simulation.version_bundle(db, simulation._version(db, v["version_id"], ["SG"]))
            surveys[name] = {
                "survey_code": v["survey_code"], "version_id": str(v["version_id"]),
                "items": {p["key"]: {"code": p["item_code"], "version": p["item_version"]} for p in ce.placements(bundle)},
            }  # fmt: skip
        out["surveys"] = surveys
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
