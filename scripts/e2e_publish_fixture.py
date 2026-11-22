# ruff: noqa: E501
"""LIB-1 — TEST SCHEMA ONLY: publish one golden fixture as a survey, through the real service, by three different
people, under server-issued codes — so the browser journey has a published component with CONDITIONS to find in the
library without building a condition by hand. Refuses anything but the test configuration.

Usage: CALL360_ENV_FILE=.env.test uv run python scripts/e2e_publish_fixture.py <fixture prefix> "<survey name>" <author> <checker> <publisher>
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import text  # noqa: E402

from app.audit.chain import Actor  # noqa: E402
from app.core.settings import load_settings  # noqa: E402
from app.db.session import make_engine, make_session_factory  # noqa: E402
from app.domain.survey import store  # noqa: E402
from tests.survey_support import fixture_bundle, operations_for  # noqa: E402

MARKETS = ["SG"]


def main() -> int:
    settings = load_settings(ROOT / ".env.test")
    if settings.app_env != "test" or settings.target_schema != "call360_test":
        raise SystemExit("e2e_publish_fixture requires the test configuration")
    prefix, name, *usernames = sys.argv[1:6]
    with make_session_factory(make_engine(settings))() as db, db.begin():
        db.execute(text("SET search_path TO call360_test"))

        def actor(username: str) -> Actor:
            pid = db.execute(
                text("SELECT principal_id FROM identity_binding WHERE username = :u"), {"u": username}
            ).scalar_one()
            return Actor(principal_id=pid, display_name=username, username=username)

        author, checker, publisher = (actor(u) for u in usernames)
        code = "S-E2E-" + uuid.uuid4().hex[:8].upper()
        sid = store.create_survey(
            db, code=code, name=name, purpose="synthetic library source", market="SG", actor=author
        )
        b = fixture_bundle(prefix)
        old = {
            "OPTION_SET": [k[0] for k in b.option_sets],
            "ITEM": sorted({k[0] for k in b.items}),
            "CONDITION": sorted({k[0] for k in b.conditions}),
            "MODULE": sorted({k[0] for k in b.modules}),
        }
        issued = store.issue_codes(
            db, sid, MARKETS, [{"kind": k, "count": len(v)} for k, v in old.items() if v], author
        )
        by_kind: dict[str, list[str]] = {}
        for x in issued:
            by_kind.setdefault(x["kind"], []).append(x["code"])
        ops_text = json.dumps(operations_for(b, code))
        for k, codes in old.items():
            for o, n in zip(codes, by_kind.get(k, []), strict=True):
                ops_text = ops_text.replace(json.dumps(o), json.dumps(n))
        ops = json.loads(ops_text)
        for op in ops:  # a wording that speaks a customer field cannot be published (default-deny): use plain words
            if op.get("kind") == "WORDING":
                op["document"]["text"] = re.sub(r"\{\{[^}]*\}\}", "the stated amount", op["document"]["text"])
        store.apply_batch(db, sid, MARKETS, 0, ops, author, require_issued=True)
        acks = [
            {"code": f["code"], "at": f["at"], "reason": "Synthetic library source for the browser journey."}
            for f in store.findings_of(db, store.draft(db, sid)["content"], sid)
            if f["severity"] == "WARNING"
        ]
        cid = store.submit(db, sid, MARKETS, "library source", acks, author)
        store.decide(db, cid, MARKETS, "APPROVE", "library source", checker)
        store.publish(db, cid, MARKETS, None, publisher)
    print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
