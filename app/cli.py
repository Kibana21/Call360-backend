"""Operator CLI: ``uv run call360 <command>`` (CP0.1A).

Commands
  generate-keys        Create the Ed25519 JWT signing key pair (gitignored .secrets/).
  bootstrap-admin      Create the first administrator; refuses if an active admin exists (C-6).
  create-local-user    Create a developer account in a local group (developer-specific secret).
  audit-verify         Recompute the audit hash chain and report the head digest.
  seed                 Deterministic synthetic seed S0-SEED-1 (CP0.2). The development schema needs
                       --allow-development (owner-approved deployment only).
  seed-digest          Print the CP0.2 content digest and row counts (no writes).

Passwords are read from a no-echo prompt or a one-shot environment variable that is removed from the
process environment immediately; they are never printed or logged.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import text

from app.audit.chain import Actor, RequestMeta, verify_chain
from app.core.settings import load_settings
from app.db.guards import verify_connection
from app.db.session import make_engine, make_session_factory
from app.domain.digest import content_digest
from app.domain.protection import DataProtection, DataProtectionUnavailable
from app.domain.seed import SeedError, counts, seed
from app.main import MIGRATION_HEAD
from app.security.identity import AccountError, active_admin_count, create_local_account
from app.security.passwords import PasswordPolicyError
from app.security.tokens import generate_keypair


def _password(env_var: str) -> str:
    value = os.environ.pop(env_var, None)
    if value:
        return value
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    return first


def _session(env_file: str | None):  # type: ignore[no-untyped-def]
    settings = load_settings(env_file)
    engine = make_engine(settings)
    with engine.connect() as conn:
        verify_connection(conn, settings)
    return settings, make_session_factory(engine)


def cmd_generate_keys(args: argparse.Namespace) -> int:
    settings = load_settings(args.env_file)
    private, public = settings.resolve(settings.jwt_private_key_path), settings.resolve(settings.jwt_public_key_path)
    if private.exists() and not args.force:
        print(f"Key already exists at {private.name}; use --force to rotate.")
        return 0
    generate_keypair(private, public)
    print(f"Generated Ed25519 key pair in {private.parent.name}/ (gitignored).")
    return 0


def _create(args: argparse.Namespace, *, group: str, action: str, bootstrap: bool) -> int:
    settings, factory = _session(args.env_file)
    with factory() as db, db.begin():
        if bootstrap and active_admin_count(db) > 0:
            print("Refusing: an active administrator already exists. Use Administration to manage users.")
            return 2
        password = _password(args.password_env)
        try:
            principal = create_local_account(
                db,
                username=args.username,
                display_name=args.display_name,
                password=password,
                group_code=group,
                created_by="SYSTEM:cli",
                actor=Actor(service="call360-cli"),
                meta=RequestMeta(),
                audit_action=action,
            )
        except (AccountError, PasswordPolicyError) as exc:
            print(f"Refusing: {exc}")
            return 2
    print(f"Created {args.username!r} in {group} (principal {principal.id}).")
    return 0


def cmd_bootstrap_admin(args: argparse.Namespace) -> int:
    return _create(args, group="LOCAL_ADMIN", action="SECURITY.BOOTSTRAP_ADMIN_CREATED", bootstrap=True)


def cmd_create_local_user(args: argparse.Namespace) -> int:
    return _create(args, group=args.group, action="ADMIN.USER_CREATED", bootstrap=False)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    _, factory = _session(args.env_file)
    with factory() as db:
        report = verify_chain(db)
    if report.ok:
        print(f"Audit chain OK: {report.events} events; head {report.head}")
        return 0
    print(f"Audit chain BROKEN at seq {report.first_break_seq} after {report.events - 1} valid events")
    return 1


def _seed_target(args: argparse.Namespace):  # type: ignore[no-untyped-def]
    settings = load_settings(args.env_file)
    if settings.target_schema == "call360" and not getattr(args, "allow_development", False):
        raise SystemExit("Refusing: seeding the development schema needs --allow-development (owner approval).")
    engine = make_engine(settings)
    with engine.connect() as conn:
        verify_connection(conn, settings)
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    if head != MIGRATION_HEAD:
        raise SystemExit(f"Refusing: schema is at {head}, expected {MIGRATION_HEAD} (run migrations first).")
    return settings, engine


def cmd_seed(args: argparse.Namespace) -> int:
    settings, engine = _seed_target(args)
    try:
        protection = DataProtection.from_settings(settings)
        with engine.begin() as conn:
            report = seed(conn, settings.target_schema, protection)
    except (SeedError, DataProtectionUnavailable) as exc:
        print(f"Refusing: {exc}")
        return 2
    verb = "Seeded" if report.created else "Already seeded (no changes)"
    print(f"{verb} {report.version} in {settings.target_schema}: digest {report.digest}")
    print(f"Key ids (not key material): {report.key_ids}")
    for table, n in report.counts.items():
        print(f"  {table:32} {n}")
    return 0


def cmd_seed_digest(args: argparse.Namespace) -> int:
    settings, engine = _seed_target(args)
    with engine.begin() as conn:
        print(f"{settings.target_schema}: digest {content_digest(conn, settings.target_schema)}")
        for table, n in counts(conn, settings.target_schema).items():
            print(f"  {table:32} {n}")
    return 0


def cmd_gpt_live_mock(args: argparse.Namespace) -> int:
    """A test double of the GPT-Live primary WebSocket on 127.0.0.1 (no network, no key, no money)."""
    import asyncio

    from app.voice.gpt_live_mock import serve_forever

    asyncio.run(serve_forever("127.0.0.1", args.port))
    return 0


def cmd_voicelab_report(args: argparse.Namespace) -> int:
    """Read-only report of one Voice Lab session for the live smoke-test review (no network, no change)."""
    import json

    from app.voice import lab

    settings = load_settings(args.env_file)
    engine = make_engine(settings)
    with engine.connect() as conn:
        from sqlalchemy.orm import Session

        db = Session(bind=conn)
        db.execute(text("SET TRANSACTION READ ONLY"))
        sid = db.execute(text("SELECT id FROM lab_session WHERE session_ref = :r"), {"r": args.session}).scalar()
        if sid is None:
            print(f"no lab session {args.session}")  # noqa: T201
            return 1
        s = lab.session(db, sid)
        m = s["metrics"]
        kinds = [e["event_type"] for e in s["events"]]
        report = {
            "session": s["session_ref"],
            "provider": s["provider"],
            "model": s["model"],
            "voice": s["voice"],
            "spend_class": s["spend_class"],
            "authorisation": s["authorisation_ref"],
            "connection": "SUCCEEDED"
            if "PROVIDER_SESSION_STARTED" in kinds
            else ("FAILED" if "PROVIDER_CONNECT_FAILED" in kinds else "NOT_STARTED"),
            "provider_session_id": s["provider_session_id"],
            "first_audio_ms": m.get("first_audio_ms"),
            "interruptions": m.get("interruptions"),
            "interruption_latency_ms": m.get("interruption_latency_ms"),
            "duration_ms": m.get("duration_ms"),
            "max_duration_s": s["max_duration_s"],
            "end_reason": s["end_reason"],
            "termination": s["termination_status"],
            "provider_close_reason": m.get("provider_close_reason"),
            "provider_usage_seconds": str(s["provider_usage_seconds"])
            if s["provider_usage_seconds"] is not None
            else None,
            "usage_source": s["usage_source"],
            "estimated_max_usd": str(s["estimated_max_usd"]),
            "reserved_usd": str(s["reserved_usd"]),
            "reconciled_usd": str(s["reconciled_usd"]) if s["reconciled_usd"] is not None else None,
            "reservation": s["reservation_status"],
            "delegations": m.get("delegations"),
            "instructions_sent": m.get("instructions_sent"),
            "provider_errors": m.get("provider_errors"),
            "invalid_provider_events": m.get("invalid_provider_events"),
            "recording": [
                {
                    "track": x["track"],
                    "seconds": round(x["samples"] / 16000, 1),
                    "basis": x["basis"],
                    "purged": bool(x["purged_at"]),
                }
                for x in s["media"]
            ],
            "transcripts": [
                {"source": t["source"], "track": t["track"], "chars": len(t["text"])} for t in s["transcripts"]
            ],
            "transcript_status": s["transcript_status"],
            "event_types": sorted(set(kinds)),
            "events": len(kinds),
        }
        print(json.dumps(report, indent=2, default=str))  # noqa: T201
    return 0


def cmd_review_fixture(args: argparse.Namespace) -> int:
    """S3-C: record one scripted synthetic conversation on a synthetic case (development / test only)."""
    import json as _json

    from app.domain import review_fixtures

    if not args.confirm_synthetic:
        raise SystemExit(
            "Refusing: pass --confirm-synthetic (records a synthetic fixture conversation, never a real one)"
        )
    settings = load_settings(args.env_file)
    _, factory = _session(args.env_file)
    with factory() as db:
        head = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        if head != MIGRATION_HEAD:
            raise SystemExit(f"Refusing: schema is at {head}, expected {MIGRATION_HEAD}")
        try:
            out = review_fixtures.build(db, args.case, _json.loads(args.answers) if args.answers else {})
        except review_fixtures.FixtureError as exc:
            db.rollback()
            print(f"Refusing: {exc}")
            return 2
        db.commit()
    print(f"{settings.target_schema}: {_json.dumps(out, default=str)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="call360")
    parser.add_argument("--env-file", default=None, help="env file (default: $CALL360_ENV_FILE or .env)")
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("generate-keys")
    keys.add_argument("--force", action="store_true")
    keys.set_defaults(func=cmd_generate_keys)

    for name, func, needs_group in (
        ("bootstrap-admin", cmd_bootstrap_admin, False),
        ("create-local-user", cmd_create_local_user, True),
    ):
        p = sub.add_parser(name)
        p.add_argument("--username", required=True)
        p.add_argument("--display-name", required=True)
        p.add_argument(
            "--password-env",
            default="CALL360_NEW_PASSWORD",
            help="environment variable holding the password (removed after reading)",
        )
        if needs_group:
            p.add_argument(
                "--group",
                required=True,
                choices=["LOCAL_ADMIN", "LOCAL_USER_SG", "LOCAL_USER_MY", "LOCAL_SC_CHECKER_SG"],
            )
        p.set_defaults(func=func)

    verify = sub.add_parser("audit-verify")
    verify.set_defaults(func=cmd_audit_verify)

    for name, func in (("seed", cmd_seed), ("seed-digest", cmd_seed_digest)):
        p = sub.add_parser(name)
        p.add_argument("--allow-development", action="store_true", help="permit schema call360 (owner approval)")
        p.set_defaults(func=func)

    fx = sub.add_parser("review-fixture", help="S3-C synthetic operational fixture conversation (dev/test only)")
    fx.add_argument("--case", required=True, help="synthetic case reference, e.g. CB-2026-10504")
    fx.add_argument(
        "--answers", default=None, help='JSON: {"Q-CODE": value or "REFUSED"/"UNKNOWN"/"UNCLEAR"/"NOT_ASKED"}'
    )
    fx.add_argument("--confirm-synthetic", action="store_true")
    fx.set_defaults(func=cmd_review_fixture)
    rp = sub.add_parser("voicelab-report", help="S1-E.2 read-only report of one Voice Lab session (no network)")
    rp.add_argument("--session", required=True)
    rp.set_defaults(func=cmd_voicelab_report)
    mk = sub.add_parser("gpt-live-mock", help="S1-E.2 mocked GPT-Live protocol server (loopback only; no model)")
    mk.add_argument("--port", type=int, default=8765)
    mk.set_defaults(func=cmd_gpt_live_mock)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
