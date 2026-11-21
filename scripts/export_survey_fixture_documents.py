"""FI-1 — the 27 golden fixtures as canonical survey documents with the server's hashes, for the frontend's round-trip
proof (Workspace <-> documents). ONE source: the same translation the backend tests use (``tests.survey_fixtures``) and
the server's own canonical hash. Nothing here holds an expected behaviour; the golden fixtures themselves are not read
for writing and are never changed.

    uv run python scripts/export_survey_fixture_documents.py           # write
    uv run python scripts/export_survey_fixture_documents.py --check   # fail if the committed files have drifted
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.domain.survey.canonical import sha256_hex  # noqa: E402
from app.domain.survey.documents import manifest_of, manifest_sha256  # noqa: E402
from tests.survey_fixtures import FIXTURE_DIR, load_all, to_bundle  # noqa: E402

OUT = FIXTURE_DIR.parent / "canonical-documents"


def export_one(fx: dict[str, Any]) -> dict[str, Any]:
    b = to_bundle(fx)
    assets = []
    for kind, docs in (
        ("OPTION_SET", b.option_sets), ("ITEM", b.items), ("WORDING", b.wordings), ("CONDITION", b.conditions),
        ("MODULE", b.modules),
    ):  # fmt: skip
        for (code, version), doc in sorted(docs.items()):
            assets.append({"kind": kind, "code": code, "version": version, "sha256": sha256_hex(doc), "document": doc})
    manifest = manifest_of(b)
    return {
        "source_fixture": fx["fixture"],
        "source_schema": fx["schema"],
        "note": "Generated from the golden fixture by Call360-backend. Do not edit by hand.",
        "content": b.survey,
        "content_sha256": sha256_hex(b.survey),
        "assets": assets,
        "manifest_sha256": manifest_sha256(manifest),
        "catalogs": {"fields": dict(b.fields), "outcomes": dict(b.outcomes)},
    }


def main() -> int:
    check = "--check" in sys.argv[1:]
    drift = []
    OUT.mkdir(exist_ok=True)
    wanted = set()
    for fx in load_all():
        name = f"{fx['fixture']}.documents.json"
        wanted.add(name)
        text = json.dumps(export_one(fx), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
        path = OUT / name
        if check:
            if not path.exists() or path.read_text() != text:
                drift.append(name)
        else:
            path.write_text(text)
    extra = sorted(p.name for p in OUT.glob("*.documents.json") if p.name not in wanted)
    if check:
        if drift or extra:
            print(f"Canonical fixture documents have drifted: {drift + extra}")
            return 1
        print(f"Canonical fixture documents match ({len(wanted)} files)")
        return 0
    print(f"Wrote {len(wanted)} files to {OUT.relative_to(FIXTURE_DIR.parents[3])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
