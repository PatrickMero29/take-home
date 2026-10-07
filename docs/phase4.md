# Phase 4 — authenticated onboarding and the operator control plane

Implemented and verified on 2026-10-06. **60 selected new/affected cases pass**,
including a real HTTPS/Chromium four-process onboarding scenario. Verification
uses selected tests and shared fixtures; no full regression run is claimed.

## Operator authority

Bootstrap separately generates the `operator` account with its own stable ID,
random password, and Argon2id hash. Its owner-private provisioning envelope is
`idp/seed-operator.enc`, encrypted with purpose `operator-provisioning`. The IDP
database stores only the hash and explicit `clients:read` / `clients:write`
permissions. Users, registered SP keys, ID/access tokens, and IDP/SP cookies grant
no operator authority.

Browser operators use `__Host-fid-operator`: Secure, HttpOnly, SameSite=Lax,
Path=/, no Domain. The IDP user cookie remains independent. Operator CLI/API
login returns a short-lived opaque bearer credential with a distinct channel
binding. Browser cookies cannot be transplanted into bearer authentication to
bypass CSRF, and an API token cannot become an operator browser or IDP user cookie.
Cookie plus bearer authentication is rejected as ambiguous.

Every operation checks the current account, session expiry, credential version,
and required permission. Account/password/permission changes increment the
credential epoch and invalidate older sessions. Expiry defaults to 900 seconds;
`FID_OPERATOR_SESSION_TTL_SECONDS` validates configurable bounds. Password work
shares the existing bounded off-thread Argon2 slots. Final binding locks and
rechecks the verified credential snapshot before commit.

## Endpoints and browser controls

| Endpoint | Contract |
| --- | --- |
| `POST /admin/api/session` | Separate operator username/password JSON; returns API-channel opaque session |
| `DELETE /admin/api/session` | End that operator session |
| `GET /admin/api/clients`, `GET /admin/api/clients/{id}` | Current read permission; public-only live metadata |
| `POST /admin/api/clients` | Current write permission; register validated client |
| `PUT /admin/api/clients/{id}` | Update destinations/grants/scopes/logout metadata with `expected_version` |
| `POST /admin/api/clients/{id}/disable`, `/enable` | Explicit state transition with `expected_version` |
| `POST /admin/api/clients/{id}/credential` | Replace public authentication key with new key ID/material and `expected_version` |
| `GET /admin/api/intent` | Issue purpose/target-bound intention for an authenticated operator browser |
| `/admin`, `/admin/login`, `/admin/clients/new`, `/admin/clients/{id}` | Script-free operator login, client list, registration, inspection, updates, disable/enable, replacement |

Browser changes require same-origin POST plus a persisted, one-use challenge bound
to the current operator cookie, operation purpose, and target. API cookie mutations
also require `X-CSRF-Token`; API bearer mutations use explicit header authority.
No redirect or posted subject/session selects a different privilege context.
Validation errors return fixed safe messages, never rejected password/private-key
input. Responses are no-store; pages escape public metadata and deny framing.

## Registration policy

- Stable client IDs are bounded lowercase actor identifiers, distinct from `idp`
  and `operator`. The registry is database-backed and consulted per request.
- Redirect URIs are exact HTTPS identifiers with bounded, unambiguous paths.
  Userinfo, fragments (including empty fragments), queries, wildcards, invalid
  hostnames/ports, backslashes, controls, and dot-segment aliases are rejected.
- A client's redirect/post-logout/back-channel destinations share one HTTPS
  origin. Client hostnames are distinct from the IDP and every other registered
  client, preserving owning-host cookie boundaries.
- Authentication keys are public-only PEM RSA, 2048–4096 bits, exponent 65537,
  for `private_key_jwt` / RS256. Private/encrypted-private/mixed bundles, embedded
  JWK fields, weak RSA, other key types/algorithms, and untrusted key URLs fail.
- Keys/IDs are client-specific, separate from issuer signing trust, and retained
  in append-only history. Replacement requires new material and a new key ID;
  retired credentials cannot be uploaded again.
- Allowed grants/scopes enable only the implemented `authorization_code` / `openid`
  profile. Refresh capabilities become available with their implementation phase.

These are the deliberately closed local-federation metadata rules. Returned URI
identifiers retain exact values; policy does not normalize incoming protocol
callbacks into an acceptable registration.

## Transactions and persistence

Registration changes and protocol issuance share the IDP security gate. Client
identity remains immutable; database triggers advance `registration_version`
whenever metadata changes. Mutations use optimistic `expected_version` checks,
so a stale operator edit cannot silently overwrite a concurrent change.

Authorization codes record the registration version that approved them. Metadata
updates, disable/enable transitions, and replacement invalidate pending older
codes. Destination or credential changes revoke existing client grants/families
in the same transaction; other recipients stay usable. Disabling stops client
authentication and trusted interactions. Replacement preserves disabled state;
recovery uses an explicit enable operation. No operation restores revoked grants.

An append-only audit records operator, action, client, resulting version, and
timestamp without raw credentials or uploaded metadata. Audit, key history,
registration, containment, and browser-intention consumption commit together.
Injected commit failure proves no partial registration/audit can be published.

Migration head is `idp_operator_control_07`; SP head remains `sp_lifecycle_05`.
The new constant default preserves pending/consumed immutable Phase 3 code proofs
without UPDATEs through their existing guard. Bootstrap upgrades the IDP bundle
marker from v1 to v2 once, then refuses missing established operator material.
Initialization preserves changed account state, registration, keys, hashes,
permissions, and metadata rather than restoring provisioning defaults.

## CLI and manual onboarding

Start the system and trust its CA using [runtime instructions](runtime.md).
Start the initially unregistered C profile:

```bash
docker compose --profile onboarding up --build --wait sp-c
```

Retrieve the distinct initial operator credential explicitly:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator-credentials
```

Open `https://idp.localhost:8443/admin` and sign in as `operator`. Retrieve public
C metadata and paste it into **Register a client**:

```bash
docker compose exec -T sp-c /app/.venv/bin/federationctl client-metadata
```

Now open `https://sp-c.localhost:8446`, select **Sign in**, and complete SSO.
The IDP need not restart, and A/B remain available.

The CLI authenticates over verified HTTPS and ends its API session after each
command. Credentials can come from an interactive hidden prompt, an owner-private
`--password-file`, or explicit `--provisioned` reading inside the IDP runtime.
Passwords/tokens are not command arguments.

In-container registration using public metadata on stdin:

```bash
docker compose exec -T sp-c /app/.venv/bin/federationctl client-metadata | docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned register --metadata /dev/stdin
```

Inspect current metadata/version:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned inspect --client-id sp-c
```

Additional subcommands: `update --client-id ID --metadata FILE`,
`disable --client-id ID --expected-version N`, `enable ...`, and
`replace-credentials --client-id ID --metadata FILE`. Update/replacement JSON
contains `expected_version`; replacement also contains `public_key_pem` and
`key_id`. The recovered SP owner separately deploys the matching private key.

## Working set

| Package path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/schemas/clients.py`, `idp/schemas/operator.py` | Validated metadata, permissions, separate channels |
| `idp/repositories/operator.py`, `idp/repositories/clients.py` | Operator credentials/binding, key history/audit, live snapshots |
| `idp/services/operator.py`, `idp/services/clients.py` | Credential verification, current authority, transactional registry changes |
| `idp/api/operator.py` | Bounded API parsing, safe errors, CSRF-bound control plane |
| `idp/repositories/database.py`, `idp/protocol/authlib_adapter.py` | Live capability checks and version-bound codes |
| `cli/operator.py`, `cli/main.py` | Metadata export, explicit credential retrieval, authenticated commands |
| `cli/bootstrap.py`, `cli/databases.py` | Stable private provisioning and idempotent migration/enrollment |

## Exit checks and verification

| Guarantee | Selected evidence |
| --- | --- |
| C login while IDP remains running | Shared runtime onboarding and four-process Chromium registration with unchanged IDP PID |
| A/B continue functioning | Existing A/B authenticated pages remain usable in both scenarios |
| Unregistered authentication fails | C authorization and signed assertion rejected before registration |
| SP/user credentials cannot operate | Password, cookie, renamed cookie, ID token, SP cookie/token, and client assertion negatives |
| Invalid metadata/private uploads fail | URI ambiguity/insecurity, mixed origins, private/mixed/weak keys, algorithms, unsupported capabilities |
| Registrations/metadata survive restart | Rebuilt factories/pools, initialization preservation, live IDP restart and operator/C browser recovery |

Additional tests cover permission-vs-authentication separation, credential epochs,
channel transplantation, expiry, CSRF purpose/target/origin, logout replay,
concurrent registration/updates, immutable-proof migration, and commit rollback.

Exact selected commands/results:

```bash
uv run pytest tests/unit/test_client_metadata.py tests/integration/test_operator.py tests/integration/test_operator_upgrade.py -q
# 40 passed in 21.57s

uv run pytest tests/unit/test_foundations.py::test_private_seeded_credentials_are_generated_once_and_never_public_config tests/unit/test_foundations.py::test_bootstrap_never_replaces_missing_material_in_an_existing_bundle tests/unit/test_foundations.py::test_operator_provisioning_is_distinct_private_and_preserved tests/unit/test_foundations.py::test_existing_secret_bundle_gains_operator_material_once_without_resetting_users -q
# 8 passed in 12.41s

uv run pytest tests/e2e/test_operator_onboarding.py -q
# 1 passed in 89.19s; verified HTTPS/Chromium/live C onboarding

uv run pytest tests/integration/test_protocol.py::test_pkce_oidc_and_private_key_jwt_round_trip tests/integration/test_protocol.py::test_concurrent_code_redemption_has_one_issuance tests/integration/test_protocol.py::test_original_redirect_uri_is_bound_even_when_both_are_registered tests/integration/test_protocol.py::test_missing_or_wrong_verifier_rejected tests/integration/test_protocol.py::test_disabled_client_rejected tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_client_compromise_is_scoped_and_blocks_issuance_and_refresh tests/integration/test_phase0_lineage.py::test_upgrade_preserves_but_never_trusts_unbound_prototype_codes tests/integration/test_lifecycle.py::test_authenticated_code_replay_requires_original_callback_and_pkce_before_containment -q
# 10 passed in 20.73s

uv run pytest tests/integration/test_browser_login.py::test_id_tokens_never_authenticate_sp_or_idp_user_or_operator_endpoints -q
# 1 passed in 48.96s

make check
uv run federationctl operator --help
```

The global lint/format/type gate and CLI parser passed. Full pytest, repeated
wheel/deployment probes, and dependency auditing were not run for this checkpoint;
no production dependency changed.
Observed `make check`: Ruff lint/format passed for **141** Python files and
strict mypy passed for **127** source/test files.
