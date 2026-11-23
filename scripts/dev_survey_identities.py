"""Development-only identities for the survey definition API (SS-03A enablement, owner decision of 2026-11-22).

Creates, in the LOCAL DEVELOPMENT schema only, three synthetic people who each hold exactly what their part of the
workflow needs, through three development-only roles:

    DEV_SURVEY_AUTHOR     survey.read, survey.edit, survey.simulate (the last from migration 0029; simulation only)
    DEV_SURVEY_CHECKER    survey.read, survey.approve
    DEV_SURVEY_PUBLISHER  survey.read, survey.publish

No existing role (ADMIN, USER, SC_CHECKER) is given a survey permission, and no migration does this: it is a
deliberate local action, audited, and refused anywhere but ``APP_ENV=local`` on schema ``call360``. The identity rules
(no self-review, no self-publication, no publication by the approver) are enforced by the service and by the database
whatever these roles hold. These people hold nothing else: they cannot open the rest of the portal.

Passwords are generated here and written only to a gitignored file under ``.secrets/``. They are never printed.

    uv run python scripts/dev_survey_identities.py --confirm-development           # create (idempotent)
    uv run python scripts/dev_survey_identities.py --confirm-development --remove  # disable them and drop the grants
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, text

from app.audit.chain import Actor, RequestMeta, write_audit
from app.core.settings import BACKEND_ROOT, load_settings
from app.db.guards import verify_connection
from app.db.session import make_engine, make_session_factory
from app.security.identity import create_local_account, local_provider
from app.security.models import (
    AppGroup,
    GroupRoleMapping,
    GroupScopeMapping,
    IdentityBinding,
    Permission,
    Principal,
    Role,
    RolePermission,
)

MARKET = "SG"
BY = "SYSTEM:dev-survey-identities"
ACCOUNTS_FILE = Path(".secrets") / "dev_survey_accounts.json"
REASON = "Development-only survey identity (SS-03A enablement)"
ROLE_REASON = "Development-only survey role (SS-03A enablement)"

#: role code, role name, group code, username, display name, permissions
PEOPLE = (
    ("DEV_SURVEY_AUTHOR", "Development survey author", "LOCAL_DEV_SURVEY_AUTHOR_SG", "dev.survey.author",
     "Dev Survey Author",
     ("survey.read", "survey.edit", "survey.simulate", "survey.assignment.read", "survey.evaluation.read", "survey.evaluate")),  # noqa: E501
    ("DEV_SURVEY_CHECKER", "Development survey checker", "LOCAL_DEV_SURVEY_CHECKER_SG", "dev.survey.checker",
     "Dev Survey Checker", ("survey.read", "survey.approve", "survey.assignment.read", "survey.evaluation.read")),
    ("DEV_SURVEY_PUBLISHER", "Development survey publisher", "LOCAL_DEV_SURVEY_PUBLISHER_SG", "dev.survey.publisher",
     "Dev Survey Publisher", ("survey.read", "survey.publish", "survey.assignment.read", "survey.evaluation.read")),
)  # fmt: skip


def _create(db, accounts: dict[str, str], people=None, market: str = MARKET, reason: str = REASON) -> list[str]:  # type: ignore[no-untyped-def]  # noqa: E501
    """``people`` and ``market`` default to the three development identities in SG; the browser end-to-end setup
    (scripts/e2e_survey_setup.py) passes its own, for the isolated TEST schema only."""
    done: list[str] = []
    now = datetime.now(UTC)
    provider = local_provider(db)
    # the survey permissions, and any other EXISTING permission a person is explicitly given (the browser test setup
    # gives one read-only identity `script.read` and `queue.read` to walk the whole navigation; the development
    # identities are given survey permissions only)
    asked = sorted({code for *_, wanted in (people or PEOPLE) for code in wanted})
    perms = {
        p.code: p
        for p in db.execute(
            select(Permission).where(Permission.code.like("survey.%") | Permission.code.in_(asked))
        ).scalars()
    }
    if not {"survey.read", "survey.edit", "survey.approve", "survey.publish"} <= set(perms):
        raise SystemExit(
            "Refusing: the survey permissions do not exist. Apply migration 0027_survey_definitions first."
        )
    for role_code, role_name, group_code, username, display, wanted in people or PEOPLE:
        role = db.execute(select(Role).where(Role.code == role_code)).scalar()
        if role is None:
            role = Role(id=uuid.uuid4(), code=role_code, name=role_name)
            db.add(role)
            db.flush()
        held = set(db.execute(select(RolePermission.permission_id).where(RolePermission.role_id == role.id)).scalars())
        for code in wanted:
            if code not in perms:
                # `survey.simulate` exists from migration 0029, `survey.assignment.read` from 0030 and the two
                # evaluation permissions from 0033 (the author may evaluate; all three may read): before them, the
                # identity simply does not hold them
                continue
            if perms[code].id not in held:
                db.add(RolePermission(role_id=role.id, permission_id=perms[code].id))
        group = db.execute(select(AppGroup).where(AppGroup.code == group_code)).scalar()
        if group is None:
            group = AppGroup(
                id=uuid.uuid4(), identity_provider_id=provider.id, code=group_code, name=role_name, status="ACTIVE"
            )
            db.add(group)
            db.flush()
            db.add(GroupRoleMapping(id=uuid.uuid4(), group_id=group.id, role_id=role.id, approved_by=BY))
            db.add(
                GroupScopeMapping(
                    id=uuid.uuid4(), group_id=group.id, market_code=market, effective_from=now, created_by=BY,
                    change_reason=reason,
                )
            )  # fmt: skip
        group.status = "ACTIVE"
        db.flush()
        existing = db.execute(select(IdentityBinding.principal_id).where(IdentityBinding.username == username)).scalar()
        if existing is None:
            password = secrets.token_urlsafe(24)
            create_local_account(
                db, username=username, display_name=display, password=password, group_code=group_code, created_by=BY,
                actor=Actor(service="dev-survey-identities"), meta=RequestMeta(),
                audit_reason=reason,
            )  # fmt: skip
            accounts[username] = password
            done.append(f"created {username} in {group_code} ({role_code}: {', '.join(wanted)})")
        else:
            principal = db.get(Principal, existing)
            if principal is not None and principal.status != "ACTIVE":
                principal.status, principal.disabled_at, principal.disabled_by = "ACTIVE", None, None
                principal.updated_by, principal.row_version = BY, principal.row_version + 1
            done.append(f"exists  {username} in {group_code} ({role_code}: {', '.join(wanted)})")
        write_audit(
            db, action="ADMIN.ROLE_PERMISSIONS_SET", outcome="SUCCEEDED", actor=Actor(service="dev-survey-identities"),
            entity_type="role", entity_id=role_code,
            reason=ROLE_REASON if reason == REASON else reason,
            after={"role": role_code, "permissions": list(wanted), "group": group_code, "market": market},
        )  # fmt: skip
    return done


def _remove(db) -> list[str]:  # type: ignore[no-untyped-def]
    done: list[str] = []
    for role_code, _, group_code, username, _, _ in PEOPLE:
        pid = db.execute(select(IdentityBinding.principal_id).where(IdentityBinding.username == username)).scalar()
        principal = db.get(Principal, pid) if pid else None
        if principal is not None and principal.status == "ACTIVE":
            principal.status, principal.disabled_at, principal.disabled_by = "DISABLED", datetime.now(UTC), BY
            principal.updated_by, principal.row_version = BY, principal.row_version + 1
        group = db.execute(select(AppGroup).where(AppGroup.code == group_code)).scalar()
        if group is not None:
            group.status = "DISABLED"
        role = db.execute(select(Role).where(Role.code == role_code)).scalar()
        if role is not None:
            db.execute(text("DELETE FROM role_permission WHERE role_id = :r"), {"r": role.id})
        write_audit(
            db, action="ADMIN.ROLE_PERMISSIONS_SET", outcome="SUCCEEDED", actor=Actor(service="dev-survey-identities"),
            entity_type="role", entity_id=role_code, reason="Development-only survey role removed",
            after={"role": role_code, "permissions": [], "group": group_code, "account": "DISABLED"},
        )  # fmt: skip
        done.append(f"disabled {username}; {role_code} holds no permission; {group_code} disabled")
    return done


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--confirm-development", action="store_true", help="required: this writes to schema call360")
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    settings = load_settings(".env")
    if settings.app_env != "local" or settings.target_schema != "call360":
        print("Refusing: development identities exist only for APP_ENV=local on schema call360.")
        return 2
    if not args.confirm_development:
        print("Refusing: pass --confirm-development (this changes the development database).")
        return 2
    engine = make_engine(settings)
    with engine.connect() as conn:
        verify_connection(conn, settings)
    accounts: dict[str, str] = {}
    with make_session_factory(engine)() as db, db.begin():
        lines = _remove(db) if args.remove else _create(db, accounts)
    if accounts:
        path = BACKEND_ROOT / ACCOUNTS_FILE
        path.parent.mkdir(exist_ok=True)
        known = json.loads(path.read_text()) if path.exists() else {}
        path.write_text(json.dumps({**known, **accounts}, indent=1) + "\n")
        os.chmod(path, 0o600)
        print(f"Passwords for {len(accounts)} new account(s) written to {ACCOUNTS_FILE} (gitignored; not shown).")
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
