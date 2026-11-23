"""Development-only identities for the shared rule services (SHARED-1 enablement, owner decision of 2026-11-23).

Creates, in the LOCAL DEVELOPMENT schema only, four synthetic people who hold ONLY a dedicated rule permission family,
through four development-only roles:

    DEV_RULE_AUTHOR      assignment_rule.read, assignment_rule.edit
    DEV_RULE_CHECKER     assignment_rule.read, assignment_rule.approve, assignment_rule.publish
    DEV_FINDING_AUTHOR   finding_rule.read, finding_rule.edit
    DEV_FINDING_CHECKER  finding_rule.read, finding_rule.approve, finding_rule.publish

The checker also publishes: assignment rules and finding rule sets keep their existing two-person lifecycle (an author
and a different checker). No existing role (ADMIN, USER, SC_CHECKER, DEV_SURVEY_*) is given a dedicated permission and
none loses a legacy ``script.*`` one. These people hold nothing else: no script, survey, case or queue permission.

Passwords are generated here and written only to the gitignored file under ``.secrets/``. They are never printed.

    uv run python scripts/dev_rule_identities.py --confirm-development           # create (idempotent)
    uv run python scripts/dev_rule_identities.py --confirm-development --remove  # disable them and drop the grants
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

from sqlalchemy import select, text

from app.audit.chain import Actor, write_audit
from app.core.settings import BACKEND_ROOT, load_settings
from app.db.guards import verify_connection
from app.db.session import make_engine, make_session_factory
from app.security.models import AppGroup, IdentityBinding, Principal, Role
from scripts.dev_survey_identities import ACCOUNTS_FILE, _create

BY = "SYSTEM:dev-rule-identities"
REASON = "Development-only shared rule identity (SHARED-1 enablement)"
DEDICATED = ("assignment_rule.read", "assignment_rule.edit", "assignment_rule.approve", "assignment_rule.publish",
             "finding_rule.read", "finding_rule.edit", "finding_rule.approve", "finding_rule.publish")  # fmt: skip

#: role code, role name, group code, username, display name, permissions
PEOPLE = (
    ("DEV_RULE_AUTHOR", "Development assignment rule author", "LOCAL_DEV_RULE_AUTHOR_SG", "dev.rule.author",
     "Dev Rule Author", ("assignment_rule.read", "assignment_rule.edit")),
    ("DEV_RULE_CHECKER", "Development assignment rule checker", "LOCAL_DEV_RULE_CHECKER_SG", "dev.rule.checker",
     "Dev Rule Checker", ("assignment_rule.read", "assignment_rule.approve", "assignment_rule.publish")),
    ("DEV_FINDING_AUTHOR", "Development finding rule author", "LOCAL_DEV_FINDING_AUTHOR_SG", "dev.finding.author",
     "Dev Finding Author", ("finding_rule.read", "finding_rule.edit")),
    ("DEV_FINDING_CHECKER", "Development finding rule checker", "LOCAL_DEV_FINDING_CHECKER_SG", "dev.finding.checker",
     "Dev Finding Checker", ("finding_rule.read", "finding_rule.approve", "finding_rule.publish")),
)  # fmt: skip


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
            db, action="ADMIN.ROLE_PERMISSIONS_SET", outcome="SUCCEEDED", actor=Actor(service="dev-rule-identities"),
            entity_type="role", entity_id=role_code, reason="Development-only shared rule role removed",
            after={"role": role_code, "permissions": [], "group": group_code, "account": "DISABLED"},
        )  # fmt: skip
        done.append(f"disabled {username}; {role_code} holds no permission; {group_code} disabled")
    return done


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
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
        have = set(
            db.execute(text("SELECT code FROM permission WHERE code = ANY(:c)"), {"c": list(DEDICATED)}).scalars()
        )
        if have != set(DEDICATED):
            print("Refusing: the dedicated rule permissions do not exist. Apply migration 0037_shared_rule_services.")
            return 2
        lines = _remove(db) if args.remove else _create(db, accounts, PEOPLE, "SG", REASON)
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
