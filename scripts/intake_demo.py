"""CP0.4a demo: submit one synthetic Singapore policy-sale transaction through the intake API.

Each run builds a new synthetic transaction (fresh POL-SG-9xxxxx / SALE-SG-9xxxxx references), then calls
preview (API-084, writes nothing), commit (API-085) and the same commit again with the same Idempotency-Key to show
the replay. It prints the created references and the portal routes to open. Only synthetic values are sent.

Usage (development API on 127.0.0.1:8000, signed in as an ADMIN):
    CALL360_DEMO_USERNAME=<admin user> uv run python scripts/intake_demo.py            # password is prompted
    uv run python scripts/intake_demo.py --preview-only
    uv run python scripts/intake_demo.py --print-payload                                 # show the JSON only
Credentials come from CALL360_DEMO_USERNAME / CALL360_DEMO_PASSWORD or a prompt and are never printed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


def transaction() -> dict[str, Any]:
    n = 900000 + secrets.randbelow(90000)
    now = datetime.now(UTC).replace(microsecond=0)
    sold = now - timedelta(days=1)
    return {
        "is_synthetic": True,
        "source_system": "SYN-POLICY-ADMIN",
        "source_event_id": f"SYN-EVT-DEMO-{n}-{now:%Y%m%d%H%M%S}",
        "source_observed_at": now.isoformat(),
        "reason": "Owner demonstration of CP0.4a manual intake (synthetic)",
        "policy": {
            "policy_ref": f"POL-SG-{n}",
            "market_code": "SG",
            "product_code": "SYN-ILP-GROWTH",
            "product_family": "ILP",
            "product_subtype": "ILP_REGULAR",
            "status": "IN_FORCE",
            "premium_amount": "420.00",
            "currency": "SGD",
            "premium_frequency": "MONTHLY",
            "premium_term_years": 10,
            "sum_assured": "150000.00",
            "sum_assured_currency": "SGD",
            "effective_from": (sold + timedelta(days=1)).isoformat(),
        },
        "sale": {
            "sale_ref": f"SALE-SG-{n}",
            "sale_event_type": "NEW_BUSINESS",
            "sold_at": sold.isoformat(),
            "fsc_ref": "FSC-0002",
            "selling_channel": "BANCASSURANCE",
            "selling_location": "SYN-BANK-03",
            "proposal_ref": f"PRP-DEMO-{n}",
            "premium_amount": "420.00",
            "currency": "SGD",
            "premium_amount_band": "BAND_B",
        },
        "parties": [
            {
                "source_party_id": f"C-DEMO-{n}",
                "kind": "PERSON",
                "name": f"Example Demo Policyholder {n}",
                "date_of_birth_year": 1987,
                "roles": ["OWNER", "PROPOSER", "PAYER", "INSURED"],
                "contacts": [
                    {"channel": "PHONE", "value": f"SYN-TEL-SG-{n}", "consent_status": "GRANTED"},
                    {
                        "channel": "EMAIL",
                        "value": f"example.demo.{n}@example.invalid",
                        "consent_status": "GRANTED",
                        "preference_rank": 2,
                    },
                ],
            }
        ],
        "source_risk": {
            "band_code": "HIGH",
            "source_original_value": "SBQ-H",
            "status": "FINAL",
            "assessed_at": (sold + timedelta(hours=6)).isoformat(),
            "reason_codes": ["SRC-HIGH"],
        },
        "callback_request": {
            "source_request_ref": f"SYN-REQ-DEMO-{n}",
            "due_at": (sold + timedelta(days=30)).isoformat(),
            "priority": 1,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="backend base URL (development)")
    ap.add_argument("--origin", default="http://127.0.0.1:5173", help="an allowed browser origin (ALLOWED_ORIGINS)")
    ap.add_argument("--portal", default="http://127.0.0.1:5173", help="portal base URL for the printed links")
    ap.add_argument("--preview-only", action="store_true")
    ap.add_argument("--print-payload", action="store_true")
    args = ap.parse_args()
    body = transaction()
    if args.print_payload:
        print(json.dumps(body, indent=2))
        return 0
    username = os.environ.get("CALL360_DEMO_USERNAME") or input("ADMIN username: ")
    password = os.environ.get("CALL360_DEMO_PASSWORD") or getpass.getpass("Password (not echoed): ")
    with httpx.Client(base_url=args.api, headers={"Origin": args.origin}, timeout=30) as c:
        c.get("/api/v1/auth/csrf").raise_for_status()
        r = c.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
            headers={"X-CSRF-Token": c.cookies["c360_csrf"]},
        )
        if r.status_code != 200:
            print(f"Sign-in failed: {r.status_code} {r.json().get('code')}")
            return 1
        write = {"X-CSRF-Token": c.cookies["c360_csrf"]}

        pv = c.post("/api/v1/intake/manual/preview", json=body, headers=write)
        print(f"Preview  {pv.status_code}  {summary(pv)}")
        if pv.status_code != 200 or args.preview_only:
            return 0 if pv.status_code == 200 else 1
        key = f"demo-{body['source_event_id']}"
        first = c.post("/api/v1/intake/manual", json=body, headers={**write, "Idempotency-Key": key})
        print(f"Commit   {first.status_code}  {summary(first)}")
        again = c.post("/api/v1/intake/manual", json=body, headers={**write, "Idempotency-Key": key})
        print(f"Replay   {again.status_code}  replayed={again.json().get('replayed')} (same key and payload)")
        if first.status_code != 201:
            return 1
        out = first.json()
        print(f"\nPolicy Detail: {args.portal}{out['routes']['policy']}")
        print(f"Call Detail:   {args.portal}{out['routes']['case']}")
        print(
            f"Work Queue:    {args.portal}/queues  → On hold → Awaiting script assignment → {out['case']['case_ref']}"
        )
    return 0


def summary(r: httpx.Response) -> str:
    b = r.json()
    if r.status_code >= 400:
        return f"{b.get('code')}: {b.get('message')} {[d.get('loc') for d in b.get('details') or []]}"
    case = b["case"]
    holds = ", ".join(h["reason"] for h in b["holds"])
    return (
        f"policy {b['policy']['policy_ref']} ({b['policy']['outcome']}) · sale {b['sale_ref']} · "
        f"case {case['case_ref'] or '(not created in preview)'} due {case['due_at'][:10]} P{case['priority']} · "
        f"risk {b['risk']['band_code'] if b['risk'] else 'none'} (source-assigned) · holds: {holds} · "
        f"script routing {b['script_routing']}"
    )


if __name__ == "__main__":
    sys.exit(main())
