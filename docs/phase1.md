# Phase 1 — runtime, persistence, secrets, and project foundations

Status: implemented and verified on 2026-10-06. The architecture and Phase 0
integration supplied most of the runtime; this checkpoint closes the remaining
provisioning, key-custody, readiness, resource-boundary, and packaging gaps.

## Coverage

| Planned foundation | Implementation and evidence |
| --- | --- |
| Python packaging and locked dependencies | `pyproject.toml` / `uv.lock`; built wheel includes both Alembic histories and the PostgreSQL probe configuration |
| Typed FastAPI factories and settings | Independent IDP/SP composition roots; strict mypy for API, service, persistence, configuration, and tests |
| IDP, SP A, SP B, and PostgreSQL | Compose dependency chain and identical real-process entry points; optional initially unregistered SP C |
| Distinct hostnames and verified TLS | Generated CA and separate TLS identities; actual HTTPS/database TLS and untrusted-CA rejection tests |
| Migrations and restricted roles | Separate IDP/SP histories; no cross-database CONNECT or administrative privileges for application roles |
| Idempotent seeded users and identities | Alice/Bob have stable generated subjects, generated passwords, and salted Argon2id hashes; reruns preserve persisted password/account changes |
| Deliberate secret custody | Owner-private encrypted key/provisioning bundles; per-service encryption keys; local and immutable database key bindings |
| Startup/readiness failures | Startup validates role/database identity, migration head, persisted key binding, and seeded-user readiness; failed construction disposes its pool |
| Logging and bounded requests | Fixed structured event names and selected public fields; body/deadline/concurrency limits; bounded off-thread password verification |
| Initial CI | Type/lint/tests, production audit, Compose health checks, and installed-wheel proof outside the checkout |

Migrations at this checkpoint were `idp_foundations_04` and `sp_foundations_03`.

## Exit checks

| Planned guarantee | Verification |
| --- | --- |
| Startup from clean state | `federationctl verify-architecture` and `federation-phase0` generate temporary state, migrate role-owned databases, and start three HTTPS processes; the installed-wheel proof also passed outside the repository |
| Certificates and hostnames are verified | `tests/integration/test_https.py`, architecture TLS checks, and real Chromium trust/cookie checks with HTTPS errors enabled |
| Each SP is isolated from other service state | `test_independent_processes_tls_and_database_access_boundaries` checks restricted role attributes, absence of IDP tables, and denied cross-database access |
| Bootstrap preserves secrets and identities | `test_bootstrap_and_migrations_preserve_existing_keys_and_passwords`; `test_seeded_users_survive_bootstrap_and_restart_without_resetting_account_state` |
| Wrong/missing encryption keys fail clearly | Unit checks cover missing bundle material and valid replacement keys; `test_valid_replacement_key_and_local_check_cannot_reenroll_existing_database` also checks startup rejection and recovery |
| Credentials/private keys stay out of logs/public output | `test_log_formatter_does_not_interpolate_credentials_or_dependency_exceptions`; `test_public_runtime_output_does_not_expose_generated_credentials` |

Additional checks cover schema-aware readiness, immutable key/subject bindings,
first enrollment against existing ciphertext, account disabling during password
verification, request size/deadline/capacity limits, and cancellation-safe worker
capacity.

## Seeded-user provisioning

Bootstrap creates Alice and Bob with random passwords and random stable subject
IDs. It encrypts `seed-users.enc` using only the IDP's envelope key. The database
stores the subject, username, enabled state, and salted Argon2id hash; it stores
no plaintext password. Initial provisioning uses 64 MiB, three iterations, and
one lane through `argon2-cffi`.

Owner-side retrieval is explicit:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl seed-credentials --username alice
docker compose exec -T idp /app/.venv/bin/federationctl seed-credentials --username bob
```

These commands intentionally print the selected initial credential. Startup,
health pages, public configuration, and logs do not reveal it. The command reads
private IDP provisioning material; an SP cannot retrieve it. After a future
credential change it still describes the initial provisioning password, while
bootstrap preserves the current database hash and disabled state.

`PasswordAuthenticator` is installed in the IDP composition root. Verification
runs in a worker with two bounded Argon2 slots, performs a dummy verification
for an unknown username, and rechecks the stored credential before producing
password-only `TrustedAuthentication`. Cancelling a caller does not release a
slot until its actual worker finishes. The Phase 2 browser flow will connect
this boundary to login/session orchestration.

## Key binding and recovery

`encryption.check` binds a secret volume to its service and encryption-key ID.
`runtime_key_binding` holds an authenticated encrypted check in each database.
Its record is immutable. Initialization enrolls it once; normal startup only
verifies it. Replacing both a key and its local check cannot reset existing
database trust.

On upgrade from pre-binding storage, initialization first verifies existing
encrypted session, transaction, token, and outbox data. If it cannot decrypt
that data, it rejects enrollment. A `bundle.complete` marker also prevents
bootstrap from regenerating missing material in an established bundle.

Recovery restores the original secret bundle together with its matching data.
Preserve `encryption.key`, `encryption.check`, identity/TLS keys and passwords,
`bundle.complete`, and the IDP provisioning envelope. Generating a replacement
key is not data recovery. Readiness returns unavailable for outdated schema or
mismatched custody, and startup reports a credential-free failure reason.

## Runtime bounds and observability

Defaults in `RuntimeSettings` / `ProtocolPolicy`:

- Maximum request body: 16 KiB, enforced for declared and streamed bodies.
- Whole-request deadline: 5 seconds, configurable up to 30 seconds.
- In-flight runtime requests: 64, bounded by configuration.
- Keep-alive: 5 seconds; graceful shutdown: 10 seconds.
- Password encoded length: at most 1,024 bytes; two active verification workers.

`/health/live` checks process liveness. `/health/ready` checks authenticated
database identity, the required migration revision, and encryption binding;
the IDP additionally checks seeded-user initialization. Public responses contain
only selected configuration and status.

Structured logs interpolate neither dependency messages nor their arguments.
Application logs use fixed event names, optional service identity, level,
logger, and exception type. Exception text, request bodies, URLs, SQL parameters,
and arbitrary extra fields are excluded.

## Verification results

- **210 tests passed** with warnings treated as errors, in about ten minutes in
  this WSL checkout, including actual PostgreSQL/process and Chromium checks.
- Strict mypy passed for **95** source/test files.
- Ruff lint and formatting passed for **104** Python files.
- The locked production dependency audit reported no known vulnerabilities.
- The built wheel completed the three-process HTTPS/database-TLS protocol proof
  from `/tmp/opencode`, using an isolated environment and no checkout imports.

Docker Desktop's WSL integration is unavailable in this local shell, so local
verification used actual independent processes. Container image/startup checks
are included in the CI workflow; no local container execution is claimed.

See [runtime instructions](runtime.md) for Compose startup, trust setup, updates,
credential retrieval, and recovery. [Phase 2](phase2.md) now connects these
foundations to browser login, callbacks, and credential-backed SSO.
