# ruff: noqa: E501 — report lines are kept one per line
"""APPL-X2 — publish the SYNTHETIC showcase applicability library through the governed HTTP API only.

Twelve variables, seven application profiles and seven reusable conditions (``scripts/appl_library_seed.json``) are
created as drafts by the author, approved by the checker and published by the publisher — three different signed-in
people, exactly as a person would do it in the portal. No SQL, nothing imported from the application.

    uv run python scripts/appl_library_setup.py --base-url URL --origin ORIGIN --accounts PATH \
        --author KEY --checker KEY --publisher KEY [--market SG] [--verify-only] [--report PATH]

Idempotent: an item already published with the same content is reused and nothing is written. Anything found that this
script would not have made — a different published definition under the same code, someone's open draft or candidate —
is reported as a conflict and left alone, with a non-zero exit. Nothing is ever deleted or overwritten.

EVERYTHING HERE IS A SYNTHETIC ILLUSTRATION: ILP, NFTF, replacement and riders are not approved business definitions
and no source mapping is invented. A password is never printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import appl_showcase_setup as showcase  # noqa: E402

SEED = Path(__file__).with_name("appl_library_seed.json")
A = "/applicability"
NOTE = "Applicability showcase library — synthetic illustration, created by scripts/appl_library_setup.py."
OK = ("PUBLISHED", "REUSED")


def _same(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Whether a published document is the seed document (the server drops empty fields and normalises the source)."""

    def clean(doc: Mapping[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in doc.items() if v not in (None, "", [], {})}
        if isinstance(out.get("source"), Mapping):
            out["source"] = {k: v for k, v in out["source"].items() if v not in (None, "")}
            if out.get("derived"):
                out["source"]["status"] = "DERIVED"
        return out

    return clean(a) == clean(b)


def _put(client: httpx.Client, path: str, body: Mapping[str, Any]) -> Any:
    r = client.put(showcase.API + path, json=dict(body), headers={"X-CSRF-Token": showcase._csrf(client)})  # noqa: SLF001
    if r.status_code != 200:
        raise showcase._fail("PUT", path, r)  # noqa: SLF001
    return r.json()


def _publish(author: httpx.Client, checker: httpx.Client, publisher: httpx.Client, asset: Mapping[str, Any]) -> Any:
    # the author states the exact versions it would pin (owner ruling A4); the server refuses if they are not those
    seen = showcase.api_post(author, f"{A}/assets/{asset['id']}/validate", {})["pins"]
    out = showcase.api_post(
        author,
        f"{A}/assets/{asset['id']}/submit",
        {
            "expected_revision": asset["draft"]["revision"],
            "note": NOTE,
            "pins": [{k: p[k] for k in ("kind", "code", "version_no")} for p in seen],
        },
    )
    cid = out["candidate"]["id"]
    showcase.api_post(checker, f"{A}/candidates/{cid}/decision", {"verdict": "APPROVE", "comment": NOTE})
    return showcase.api_post(publisher, f"{A}/candidates/{cid}/publish")


def run(
    author: httpx.Client, checker: httpx.Client, publisher: httpx.Client, *, market: str = "SG",
    verify_only: bool = False,
) -> dict[str, Any]:  # fmt: skip
    seed = json.loads(SEED.read_text())
    people = [showcase.whoami(c) for c in (author, checker, publisher)]
    if len({p.principal_id for p in people}) != 3:
        raise showcase.ShowcaseError("the author, the checker and the publisher must be three different people")
    plan: list[tuple[str, str, list[dict[str, Any]]]] = [
        *(("VARIABLE", v["code"], [v["document"]]) for v in seed["variables"]),
        *(("PROFILE", p["code"], [p["document"]]) for p in seed["profiles"]),
        *(("CONDITION", c["code"], list(c["versions"])) for c in seed["conditions"]),
    ]
    items: list[dict[str, Any]] = []
    for kind, code, versions in plan:
        listed = showcase.api_get(author, f"{A}/assets?kind={kind}")["items"]
        found = next((x for x in listed if x["code"] == code and x["market_code"] == market), None)
        row: dict[str, Any] = {
            "kind": kind,
            "code": code,
            "name": versions[-1]["name"],
            "wanted_versions": len(versions),
        }
        have = found["published_versions"] if found else 0
        if found and (found["draft"] or found["candidate"]):
            row.update(state="CONFLICT", detail="it has an open draft or candidate that this script did not finish")
        elif found and have >= len(versions):
            ok = have == len(versions) and _same(found["published"]["document"], versions[-1])
            row.update(state="REUSED" if ok else "CONFLICT", detail="" if ok else "a different definition is published under this code")  # fmt: skip
        elif verify_only:
            row.update(state="MISSING", detail=f"{have} of {len(versions)} version(s) published")
        else:
            asset = found
            for number, doc in enumerate(versions, start=1):
                if number <= have:
                    continue
                if asset is None:
                    asset = showcase.api_post(author, f"{A}/assets", {"market_code": market, "kind": kind, "code": code, "document": doc})  # fmt: skip
                else:
                    started = showcase.api_post(author, f"{A}/assets/{asset['id']}/draft", {})
                    asset = _put(author, f"{A}/assets/{asset['id']}/draft", {"expected_revision": started["draft"]["revision"], "document": doc})  # fmt: skip
                asset = _publish(author, checker, publisher, asset)
            found = asset
            row.update(state="PUBLISHED", detail="")
        if found and found.get("published"):
            v = found["published"]
            row.update(
                asset_id=found["id"], version_no=v["version_no"], version_id=v["id"], content_sha256=v["content_sha256"],
                manifest_sha256=v["manifest_sha256"], submitted_by=v["submitted_by"], approved_by=v["decided_by"],
                published_by=v["published_by"], pins=[f"{p['kind'].lower()} {p['code']} v{p['version_no']}" for p in v["pins"]],
            )  # fmt: skip
        items.append(row)
    return {
        "ok": all(i["state"] in OK for i in items), "market": market, "verify_only": verify_only, "items": items,
        "people": {r: p.display_name for r, p in zip(("author", "checker", "publisher"), people, strict=True)},
        "summary": {s: sum(1 for i in items if i["state"] == s) for s in sorted({i["state"] for i in items})},
    }  # fmt: skip


def render(report: Mapping[str, Any]) -> str:
    lines = [f"Applicability showcase library — market {report['market']} — {'OK' if report['ok'] else 'NOT OK'} — {report['summary']}"]  # fmt: skip
    for i in report["items"]:
        version = f"v{i['version_no']} {str(i.get('content_sha256'))[:12]}…" if i.get("version_no") else "—"
        lines.append(f"  {i['state']:<10} {i['kind']:<9} {i['code']:<24} {version}  {i.get('detail') or ''}".rstrip())
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--accounts", required=True, type=Path)
    parser.add_argument("--author", required=True)
    parser.add_argument("--checker", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--market", default="SG")
    parser.add_argument("--verify-only", action="store_true", help="change nothing; non-zero unless all is published")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    clients: list[httpx.Client] = []
    try:
        accounts = json.loads(args.accounts.read_text())
        for role in ("author", "checker", "publisher"):
            username, password = showcase.credentials(accounts, getattr(args, role))
            client = showcase.make_client(args.base_url, args.origin)
            clients.append(client)
            try:
                showcase.sign_in(client, username, password)
            except showcase.ApiError as exc:
                raise showcase.ShowcaseError(
                    f"could not sign in the {role} ({username}): {exc.status} {exc.code}"
                ) from None
        report = run(clients[0], clients[1], clients[2], market=args.market, verify_only=args.verify_only)
    except (showcase.ShowcaseError, showcase.ApiError, OSError, ValueError, httpx.HTTPError) as exc:
        print(f"appl_library_setup: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        for client in clients:
            client.close()
    print(render(report))
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
