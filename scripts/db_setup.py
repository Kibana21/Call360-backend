"""One-time database setup for Call360_db (S0_IDENTITY_ACCESS_DESIGN §10; D-22, D-24).

Run with the development configuration (Call360_db_user). It:
  * creates schema ``call360`` (development) if missing;
  * creates the least-privilege role ``call360_test_user`` with an independently generated password,
    written only to gitignored ``.env.test`` (never printed);
  * creates schema ``call360_test`` owned by that role, grants CONNECT only, and pins its search_path;
  * verifies the test role has no privilege on ``call360`` and is not a superuser.
Existing objects are inspected and never overwritten unless they carry this project's marker comment.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.settings import load_settings  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TEST_ROLE = "call360_test_user"
MARKER = "Call360 CP0.1A automated-test role (least privilege, schema call360_test only)"


def main() -> int:
    settings = load_settings(ROOT / ".env")
    if settings.app_env != "local":
        raise SystemExit("db_setup must run with the development configuration (.env)")
    engine = create_engine(settings.database_url, isolation_level="AUTOCOMMIT", hide_parameters=True)
    with engine.connect() as c:
        info = c.execute(
            text(
                "SELECT current_database(), current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)"
            )
        ).one()
        if info[0] != settings.expected_database or info[1] != settings.expected_db_role:
            raise SystemExit(f"refusing: connected to {info[0]} as {info[1]}")
        print(f"Connected to {info[0]} as {info[1]} (superuser={info[2]}).")

        owner = c.execute(text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='call360'")).scalar()
        if owner is None:
            c.execute(text('CREATE SCHEMA call360 AUTHORIZATION "Call360_db_user"'))
            print("Created schema call360 (owner Call360_db_user).")
        elif owner != settings.expected_db_role:
            raise SystemExit(f"refusing: schema call360 exists with unexpected owner {owner}")
        c.execute(text("REVOKE ALL ON SCHEMA call360 FROM PUBLIC"))

        env_test = ROOT / ".env.test"
        role = c.execute(text("SELECT oid FROM pg_roles WHERE rolname = :r"), {"r": TEST_ROLE}).scalar()
        if role is not None:
            comment = c.execute(text("SELECT shobj_description(:o, 'pg_authid')"), {"o": role}).scalar()
            if comment != MARKER:
                raise SystemExit(f"refusing: role {TEST_ROLE} exists but was not created by this project")
            if not env_test.exists():
                raise SystemExit(
                    f"role {TEST_ROLE} exists but .env.test is missing; drop the role or restore .env.test"
                )
            print(f"Role {TEST_ROLE} already exists (project marker present); keeping it.")
        else:
            password = secrets.token_urlsafe(32)
            # DDL cannot take bind parameters: quote server-side with format(%L) and never echo the statement.
            ddl = c.execute(
                text(
                    "SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', CAST(:r AS text), CAST(:p AS text))"
                ),
                {"r": TEST_ROLE, "p": password},
            ).scalar_one()
            try:
                c.exec_driver_sql(ddl)
            except Exception as exc:  # the statement contains the secret: report only the error class
                raise SystemExit(f"CREATE ROLE failed ({type(exc).__name__}); no credentials were written") from None
            del ddl
            c.execute(text(f"COMMENT ON ROLE {TEST_ROLE} IS '{MARKER}'"))
            env_test.write_text(
                "APP_ENV=test\nDATA_POLICY=SYNTHETIC_ONLY\n"
                f"TEST_DATABASE_URL=postgresql+psycopg://{TEST_ROLE}:{password}@localhost:5432/Call360_db\n"
                "TEST_DB_SCHEMA=call360_test\nEXPECTED_DATABASE=Call360_db\n"
                f"EXPECTED_DB_ROLE={TEST_ROLE}\nAPP_DB_ROLE=Call360_db_user\n"
                f"REFRESH_TOKEN_PEPPER={secrets.token_urlsafe(32)}\nCSRF_SECRET={secrets.token_urlsafe(32)}\n"
                'ALLOWED_ORIGINS=["http://localhost:5174","http://127.0.0.1:5174","http://testserver"]\n'
                "COOKIE_SECURE=false\nJWT_PRIVATE_KEY_PATH=.secrets/test_jwt_ed25519_private.pem\n"
                "JWT_PUBLIC_KEY_PATH=.secrets/test_jwt_ed25519_public.pem\n"
            )
            env_test.chmod(0o600)
            print(f"Created role {TEST_ROLE}; credentials written to .env.test (gitignored, mode 600).")

        c.execute(text(f'GRANT CONNECT ON DATABASE "{settings.expected_database}" TO {TEST_ROLE}'))
        test_owner = c.execute(
            text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='call360_test'")
        ).scalar()
        if test_owner is None:
            c.execute(text(f"CREATE SCHEMA call360_test AUTHORIZATION {TEST_ROLE}"))
            print("Created schema call360_test (owner call360_test_user).")
        elif test_owner != TEST_ROLE:
            raise SystemExit(f"refusing: schema call360_test has unexpected owner {test_owner}")
        c.execute(
            text(f'ALTER ROLE {TEST_ROLE} IN DATABASE "{settings.expected_database}" SET search_path = call360_test')
        )

        checks = c.execute(
            text(
                "SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole, "
                "has_schema_privilege(:r, 'call360', 'USAGE'), has_schema_privilege(:r, 'call360', 'CREATE'), "
                "has_schema_privilege(:r, 'public', 'CREATE') FROM pg_roles r WHERE r.rolname = :r"
            ),
            {"r": TEST_ROLE},
        ).one()
        if any(checks):
            raise SystemExit(f"privilege check FAILED for {TEST_ROLE}: {tuple(checks)}")
        print(
            "Verified: test role is not superuser/createdb/createrole and has no access to call360 "
            "and cannot create in public."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
