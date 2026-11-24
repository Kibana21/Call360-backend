"""Development-only identities for the governed Applicability library (APPL-X2 enablement, owner decision 2026-11-24).

Creates, in the LOCAL DEVELOPMENT schema only, three synthetic people who each hold ONLY their own part of the
applicability permissions, through three development-only roles:

    DEV_APPL_AUTHOR     applicability.read, applicability.edit,    survey.read
    DEV_APPL_CHECKER    applicability.read, applicability.approve, survey.read
    DEV_APPL_PUBLISHER  applicability.read, applicability.publish, survey.read

``survey.read`` is an explicit, READ-ONLY dependency of the screen, authorised by the owner on 2026-11-24 for these
three development roles only: Survey Applicability Studio is part of Survey Studio and reads the published survey
versions it links to, and its live evaluation runs behind the same permission. It is declared here, per role; it is
never implied by an applicability permission and is not given automatically to any future role. These roles hold no
``survey.edit``, ``survey.approve``, ``survey.publish`` or ``survey.simulate``.

Publishing a library item needs all three: the server refuses a decision by the submitter and a publication by the
submitter or the approver, whatever anyone holds. No existing role (ADMIN, USER, SC_CHECKER, DEV_SURVEY_*, DEV_RULE_*)
is given an applicability permission. These people hold nothing else: no script, case or queue permission, and no
survey permission other than the read-only one above.

Passwords are generated here and written only to the gitignored file under ``.secrets/``. They are never printed.

    uv run python scripts/dev_applicability_identities.py --confirm-development           # create (idempotent)
    uv run python scripts/dev_applicability_identities.py --confirm-development --remove  # disable, drop the grants
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

BY = "SYSTEM:dev-applicability-identities"
REASON = "Development-only applicability library identity (APPL-X2 enablement; survey.read owner-authorised 2026-11-24)"
DEDICATED = ("applicability.read", "applicability.edit", "applicability.approve", "applicability.publish")

#: role code, role name, group code, username, display name, permissions
PEOPLE = (
    ("DEV_APPL_AUTHOR", "Development applicability author", "LOCAL_DEV_APPL_AUTHOR_SG", "dev.applicability.author",
     "Dev Applicability Author", ("applicability.read", "applicability.edit", "survey.read")),
    ("DEV_APPL_CHECKER", "Development applicability checker", "LOCAL_DEV_APPL_CHECKER_SG", "dev.applicability.checker",
     "Dev Applicability Checker", ("applicability.read", "applicability.approve", "survey.read")),
    ("DEV_APPL_PUBLISHER", "Development applicability publisher", "LOCAL_DEV_APPL_PUBLISHER_SG",
     "dev.applicability.publisher", "Dev Applicability Publisher",
     ("applicability.read", "applicability.publish", "survey.read")),
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
            db, action="ADMIN.ROLE_PERMISSIONS_SET", outcome="SUCCEEDED", actor=Actor(service="dev-applicability-identities"),  # noqa: E501
            entity_type="role", entity_id=role_code, reason="Development-only applicability role removed",
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
            print("Refusing: the applicability permissions do not exist. Apply migration 0038 first.")
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
