# Call360 backend — local commands (ADR-0003 §5). No CI; captured output is the evidence.
UV ?= uv
TEST_ENV = CALL360_ENV_FILE=.env.test

.PHONY: setup env db-setup keys migrate bootstrap-admin create-user dev test lint typecheck openapi contract-check audit-verify secret-scan check

setup:            ## install locked dependencies
	$(UV) sync --frozen

env:              ## create gitignored .env (prompts for the Call360_db_user password)
	$(UV) run python scripts/make_env.py

db-setup:         ## create schemas call360 / call360_test and the least-privilege test role (once)
	$(UV) run python scripts/db_setup.py

keys:             ## Ed25519 signing keys for dev and test (gitignored .secrets/)
	$(UV) run call360 generate-keys
	$(UV) run call360 --env-file .env.test generate-keys

migrate:          ## migrate the DEVELOPMENT schema call360 (guarded)
	$(UV) run alembic upgrade head

bootstrap-admin:  ## first administrator; prompts for a password (or CALL360_NEW_PASSWORD)
	$(UV) run call360 bootstrap-admin --username $(USERNAME) --display-name "$(DISPLAY_NAME)"

create-user:      ## developer account: make create-user USERNAME=.. DISPLAY_NAME=".." GROUP=LOCAL_USER_SG
	$(UV) run call360 create-local-user --username $(USERNAME) --display-name "$(DISPLAY_NAME)" --group $(GROUP)

dev:              ## API on 127.0.0.1:8000 against schema call360
	$(UV) run uvicorn --factory app.main:app_factory --host 127.0.0.1 --port 8000 --reload

test:             ## all backend tests — ONLY schema call360_test via call360_test_user
	$(TEST_ENV) $(UV) run pytest

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

typecheck:
	$(UV) run mypy app

openapi:          ## regenerate contracts/generated/openapi.json + .sha256
	$(UV) run python scripts/export_openapi.py

contract-check:   ## fail if the committed OpenAPI artifact has drifted
	$(UV) run python scripts/export_openapi.py --check

audit-verify:     ## verify the development audit hash chain
	$(UV) run call360 audit-verify

secret-scan:      ## gitleaks over the working tree (including untracked files)
	scripts/secret_scan.sh

check: lint typecheck test contract-check secret-scan
