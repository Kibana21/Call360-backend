# Call360 backend

FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL. **Current checkpoint: CP0.1A** — core authentication,
sessions, ADMIN/USER authorization, append-only audit (Call360-specs `docs/acceptance/CP0.1A.md`).

## Database layout (D-22)

| Purpose | Database | Schema | Role | Config |
|---|---|---|---|---|
| Development app | `Call360_db` | `call360` | `Call360_db_user` (superuser — local-only risk RR-11) | `.env` |
| Automated tests | `Call360_db` | `call360_test` | `call360_test_user` (no superuser, no access to `call360`) | `.env.test` |

Tests can never touch `call360`: settings, Alembic and the test harness verify database, role and schema
before doing anything, and the test role has no privileges on the development schema.

## First-time setup (already done on this machine)

```bash
uv sync                      # install locked dependencies
make env                     # writes .env (prompts for the Call360_db_user password)
make db-setup                # schemas + least-privilege test role; test credentials → .env.test
make keys                    # Ed25519 JWT signing keys (dev + test) in .secrets/
make migrate                 # migrate schema call360
make bootstrap-admin USERNAME=<you> DISPLAY_NAME="<Your Name>"     # first admin, prompts for password
make create-user USERNAME=<u> DISPLAY_NAME="<Name>" GROUP=LOCAL_USER_SG
```

All of `.env`, `.env.test`, `.env.local` and `.secrets/` are gitignored. No default passwords exist.

## Everyday commands

```bash
make dev             # API on http://127.0.0.1:8000 (use the frontend on :5173)
make test            # all backend tests (schema call360_test only)
make lint typecheck  # ruff + mypy --strict
make openapi         # regenerate contracts/generated/openapi.json (+ .sha256)
make contract-check  # fail if the committed OpenAPI artifact drifted
make audit-verify    # verify the development audit hash chain
make secret-scan     # gitleaks over every committable file
```
