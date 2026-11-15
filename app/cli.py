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
            p.add_argument("--group", required=True, choices=["LOCAL_ADMIN", "LOCAL_USER_SG", "LOCAL_USER_MY"])
        p.set_defaults(func=func)

    verify = sub.add_parser("audit-verify")
    verify.set_defaults(func=cmd_audit_verify)

    for name, func in (("seed", cmd_seed), ("seed-digest", cmd_seed_digest)):
        p = sub.add_parser(name)
        p.add_argument("--allow-development", action="store_true", help="permit schema call360 (owner approval)")
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
