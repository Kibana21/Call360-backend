# Claude Code instructions — Call360-backend

**Product:** Call360 | **Screen name exposed to users:** Call Detail | **Current stage:** S0

This is a **separate Git repository**, sibling to `../Call360-specs` and `../Call360-frontend`. It owns the backend, not the BRD or React UI. Read before making changes:

- `../Call360-specs/docs/spec/01_MASTER_BRD.md`
- `../Call360-specs/docs/spec/02_CLAUDE_CODE_EXECUTION_PLAN.md`
- `../Call360-specs/docs/engineering/MULTI_REPO_ARCHITECTURE.md`
- `../Call360-specs/docs/contracts/API_CONTRACT_POLICY.md`
- `../Call360-specs/docs/product/SCREEN_NAMING_AND_ROUTES.md`

## Backend responsibility

- Python 3.12+, FastAPI/Pydantic v2, PostgreSQL, SQLAlchemy 2/Alembic; real persisted `CallbackCase`, `ContactAttempt`, `ConversationSession`, surveys, media manifests, transcripts, evidence, events and reviews.
- Canonical `/api/v1/` endpoint behavior, auth/scope, idempotency, state transitions and error contracts. Generate and publish deterministic `contracts/generated/openapi.json`; frontend must generate types from this artifact.
- Structured survey engine, business rules, escalation, recording metadata, provider sideband events; introduce browser voice in S1, survey logic in S2, compliance rules in S3 and Genesys adapter only in S6.
- Synthetic seeded dataset (>=250 cases for S0), separate test DB, migrations, domain/API/security tests, mock voice provider for CI.

## Non-negotiables

1. Implement only accepted stage scope; **S0 has no live model or Genesys dependency**.
2. Domain and rules are transport-independent. Never let GPT-Live or frontend decide survey/compliance verdicts.
3. Do not invent approved AIA policy language, regulatory restrictions or recording completeness. Source evidence and uncertainty must remain explicit.
4. Auth + object scope on endpoints; no secrets, real customer info, or production audio in source/fixtures/logs; avoid exposing production keys to browsers.
5. Preserve original evidence and append attributable revisions; auditable actions and idempotent event processing.
6. Generate OpenAPI from actual backend routes, check in stable artifact and test backward-compatible contract against frontend consumers.
7. No fake placeholder routes as production success paths; failed recordings, incomplete sessions and unanswered questions have explicit statuses.
8. Test migration on clean DB, seed, API/unit/security tests, lint/type checks and integration with frontend before claiming a gate.
9. Record exact backend SHA, Alembic revision and OpenAPI SHA-256 in `../Call360-specs/docs/acceptance/Sx.md` (through the separately reviewed specs PR).
10. The term **Call Detail** is UI navigation, not a reason to rename domain objects or database tables.

Before committing, inspect branch/status and supply requirement IDs and tests in PR summary. Do not modify sibling repos unexpectedly.

## v0.3 expansion — mandatory context

**v0.3 expansion (237 requirements, 55 business tests):** Read `Call360-specs/docs/process/SBQ_AS_IS_TO_BE_AND_DECISIONS.md`, `docs/data/CANONICAL_GRAIN_AND_RELATIONSHIPS.md`, `docs/product/SCRIPT_GOVERNANCE_AND_ASSIGNMENT.md`, `docs/product/SEARCH_WORKSPACE_AND_POLICY_VIEWS.md`, `docs/integrations/POLICY_PARTY_RISK_INTAKE.md`, and `docs/security/IDENTITY_AUTHORIZATION_AND_AUDIT.md` (paths relative to specs repository; use `../Call360-specs` from implementation repos). The existing AIA SBQ workflow is a working hypothesis, not an approved SOP. Keep sale-selection risk distinct from customer investment risk tolerance and compliance finding severity.

At S0 build persistent synthetic policy/sale/risk/party data, mock and manual intake, accessible secured search and local login with ADMIN/USER role mapping; enforce server-side access and audit from the start. Do not implement Genesys, real customer interfaces or real call scripts before approval. Never promise zero security defects.
