# Phase 5 — live signing-key rotation

Implemented and verified on 2026-10-06. **58 distinct selected new/affected cases
pass**, including verified-HTTPS process checks and a Chromium rotation/restart
scenario. This is a targeted checkpoint with shared database fixtures and injected
time for expiry checks.

## Signing lifecycle and operator authority

Issuer trust progresses `prepared → active → draining → retired`; `revoked` is
terminal containment state. A partial unique index permits one active signer.

Operators need explicit `keys:read` / `keys:write` capabilities. Existing
operator cookie/API channel, credential-epoch, expiry, and CSRF rules apply.
Browser mutations require same-origin POST and one-use purpose/target-bound
intent. Signing responses expose IDs, public keys, state, publication time, and
verification deadlines; they never return private material.

| Endpoint/control | Contract |
| --- | --- |
| `GET /admin/api/signing-keys` | Current read permission; inspect public trust/history |
| `POST /admin/api/signing-keys/prepare` | Current write permission; empty JSON request; generate a new IDP-owned key |
| `GET /jwks.json` | Public-only prepared/active/draining trust; validated read records first publication; no-store |
| `POST /admin/api/signing-keys/{id}/activate` | Published prepared key plus matching `expected_active_key_id` |
| `POST /admin/api/signing-keys/{id}/retire` | Draining key, matching `expected_verification_deadline`, and expiry-plus-skew boundary |
| `/admin/signing-keys` | Script-free preparation, publication link, activation, and retirement forms |

RSA generation runs off-thread outside the security gate. Preparation rechecks
current authority before committing encrypted material, prepared trust, and
append-only audit together. Activation checks publication and current active
identity under the same gate, drains the old signer, then activates the new one.
Stale concurrent activation attempts reject rather than overwrite trust.

Retirement removes the old public key from future JWKS responses. It does not
revoke historical grants or rewrite established SP authentication evidence.
Those sessions remain subject to their original expiry and fresh authoritative
authorization. Emergency compromise recovery has its own Phase 6 controls.

## Durable private custody and all-purpose retention

Migration head is `idp_signing_rotation_08`, following `idp_operator_control_07`;
SP head remains `sp_lifecycle_05`.

| Record | Responsibility |
| --- | --- |
| `signing_trust` | Immutable public identity, lifecycle state, irreversible `published_at`, nonshrinking verification deadline |
| `signing_key_material` | Immutable private envelope with purpose `issuer-signing-key`, bound to key ID and public identity |
| `signed_artifacts` | Immutable artifact ID, key, purpose, recipient, issuance time, and expiry |
| `signing_audit` | Immutable operator/action/key/previous-active identity and timestamp |

The migration backfills committed ID-token evidence into `signed_artifacts`.
It adds key permissions only to the enabled default `operator` with its original
fully privileged registry permission set. Customized accounts retain their
policy; the existing credential-epoch guard invalidates sessions when permissions
change.

Startup enrolls only the known original volume identity when its private envelope
is absent. Rotated keys must have their persisted encrypted material; decryption
also checks key ID and exact public-key match. Startup restores the database's
active signer, including after rotation, rather than selecting the bootstrap
volume key again. Wrong wrapping keys fail to load persisted material.

`OidcService.exchange()` selects `SigningKeyService.active_in(work)` inside the
issuance savepoint. The selected signer, actual ID token, canonical evidence,
grant, code consumption, replay reservation, and retention share the gated
transaction. Signing or commit failure cannot publish partial issuance.

`IdpSecurityModel.record_signed_artifact_in()` accounts for every IDP-signed
purpose before publication. It requires the active key and a bounded lifetime,
then raises `verification_deadline` to the maximum artifact expiry. Retirement is
allowed at `verification_deadline + clock_skew_seconds`, default skew 5 seconds.

The ledger supports `id_token` and `logout_token`, each with a separate TTL policy.
The retention test records a modeled future logout-token artifact expiring later
than the ID token and proves retirement waits for it. Actual logout JWT creation,
validation, and delivery integrate in Phase 8 using this same ledger.

## SP public-trust cache

Each `OidcClient` owns an `IssuerJwksCache` namespaced by configured issuer,
pinned `issuer + /jwks.json`, and RS256. Discovery endpoints remain exact pinned
values. Public responses are streamed over verified HTTPS, bounded to 32 KiB and
16 unique public-only RSA/RS256 keys, and validated before replacing good trust.

Ordinary warming/expiry and unknown-key refresh share one lock. Concurrent cold
loads fetch once. The first unknown key after ordinary warming may refresh
immediately; all unknown IDs then share the 10-second default cooldown. Random
IDs do not create a growing negative-cache map or multiply outbound requests.
Failures and cancellation spend the refresh budget. Known cached keys remain
usable until their 300-second default cache expiry; expired trust requires reload.

`login_header()` obtains only an unverified kid routing hint through joserfc.
It enforces the bounded strict login header before refresh: RS256, `typ=JWT`, and
no embedded key or token-supplied key URL. Refresh does not authenticate a token.
The full signature/issuer/recipient/nonce/time/at_hash checks and exact current
authoritative issuance match still precede SP session creation.

The TTL is configurable from 1–900 seconds and cooldown from 1–60 seconds using
`FID_JWKS_CACHE_TTL_SECONDS` and `FID_JWKS_REFRESH_COOLDOWN_SECONDS`. Rate-limited or
unavailable new-key trust fails closed; a subsequent login can retry after the
cooldown. Existing-session authorization continues to use current IDP authority.

Client registration/replacement rejects every issuer signing key, including
prepared and historical trust, as a client authentication credential.

## CLI and manual rotation

Use the [runtime guide](runtime.md) to start the system and trust its CA. Sign in
at both SPs first to warm their caches and retain existing sessions.

At `/admin`, sign in with the separate operator credential and select **Manage
signing keys**. Select **Prepare signing key**, open **Publish public JWKS**, then
**Reload key state**. Activation appears for the published prepared key. Activate
it; existing SP pages remain usable, and **Sign in** obtains new-key evidence
through SSO without restarting either SP. Retire the draining key after its
displayed deadline plus skew.

The CLI uses verified HTTPS and ends its opaque API session after each command.
Use an interactive hidden password prompt, owner-private `--password-file`, or
explicit `--provisioned` inside the IDP container.

Inspect public trust and prepare/publish a new key:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned keys-inspect
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-prepare
```

`key-prepare` reads public JWKS before returning the prepared key's published
state. Substitute the returned IDs for uppercase placeholders:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-activate --key-id NEW_KEY_ID --expected-active-key-id CURRENT_KEY_ID
```

Inspect again before retirement; substitute the draining key's current deadline
as a decimal timestamp. Early/stale requests return conflict:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-retire --key-id OLD_KEY_ID --expected-verification-deadline VERIFICATION_DEADLINE
```

## Working set

| Package path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/schemas/signing.py`, `idp/repositories/signing.py` | Public controls, signed purposes, encrypted custody, immutable ledger/audit |
| `idp/services/signing.py` | Restore active material, publish public trust, authorized lifecycle |
| `idp/services/security_model.py`, `idp/services/oidc.py` | Caller-owned trust transitions, all-purpose retention, atomic signer selection/issuance |
| `idp/api/signing.py`, `idp/api/app.py` | Operator API/browser controls and persisted public JWKS |
| `common/security/oidc.py`, `common/security/keys.py` | Strict routing hint and public-only bounded key schema |
| `sp/protocol/jwks.py`, `sp/protocol/oidc.py` | Pinned cache namespace, bounded HTTPS loader, single-flight/cooldown |
| `cli/operator.py`, `cli/service.py` | Authenticated commands and persisted-signing composition |

## Exit checks and verification

| Guarantee | Selected evidence |
| --- | --- |
| Both SPs accept new-key artifacts without restart | Shared runtime exchanges and Chromium SSO after activation; SP PIDs unchanged |
| Legitimate old-key evidence survives its lifetime | Previous actual ID token verifies with draining public trust; retirement waits through all-purpose expiry/skew |
| Established sessions survive routine rotation | Original A/B cookies and protected pages remain usable; model retirement preserves grant trust |
| Prewarmed caches recover | Both actual SP instances encounter the new signer with their initial JWKS cache |
| Unknown-key work stays bounded | Concurrent cold/new-key loads; two batches of 100 random IDs; failed/cancelled refresh budgets; issuer isolation |
| Active/draining state survives restart | Factory reconstruction and live IDP restart preserve keys/state; subsequent evidence uses the rotated signer |

Additional cases cover publication-before-activation rejection, public-only
responses, encrypted material, permission separation, issuer/client key reuse,
concurrent issuance/activation, activation rollback/retry, wrong-cipher loading,
direct SQL immutability/publication guards, migration backfill, and existing
signing/commit/authoritative-evidence regressions.

Exact selected commands/results:

```bash
uv run pytest tests/unit/test_jwks_cache.py tests/unit/test_id_token.py tests/integration/test_signing_rotation.py tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_routine_rotation_and_retirement_preserve_established_grant_trust tests/integration/test_security_model.py::test_key_compromise_revokes_only_affected_evidence_and_cannot_be_undone tests/integration/test_security_model.py::test_refresh_preserves_expired_login_evidence_history_and_absolute_ceilings tests/integration/test_security_model.py::test_failed_commit_cannot_publish_or_partially_change_model_state tests/integration/test_transactions.py::test_signing_failure_rolls_back_issuance_consumption_and_replay tests/integration/test_transactions.py::test_http_success_waits_for_database_commit tests/integration/test_operator_upgrade.py tests/integration/test_phase0_lineage.py::test_upgrade_preserves_but_never_trusts_unbound_prototype_codes tests/integration/test_phase0_lineage.py::test_rp_rejects_valid_signatures_without_matching_authoritative_evidence -q
# 55 passed in 49.39s, before adding the direct signing-history guard case

uv run pytest tests/integration/test_signing_rotation.py::test_operator_key_permissions_and_issuer_key_namespace_are_explicit tests/integration/test_signing_rotation.py::test_database_guards_private_material_signed_history_audit_and_publication tests/integration/test_operator_upgrade.py tests/integration/test_foundations.py::test_public_runtime_output_does_not_expose_generated_credentials -q
# 3 passed, 1 setup error in 44.69s; strengthened key-reuse/backfill and new history checks passed

uv run pytest tests/integration/test_foundations.py::test_public_runtime_output_does_not_expose_generated_credentials -q
# 1 setup error in 32.04s; reproduced the 15-second process-readiness timeout

uv run pytest tests/integration/test_foundations.py::test_public_runtime_output_does_not_expose_generated_credentials tests/e2e/test_signing_rotation.py -q
# 2 passed in 137.71s after correcting the verification startup window

make check
uv run federationctl operator --help
```

The process diagnostic reached verified-HTTPS readiness at 15.7 seconds, just
beyond the old 15-second probe limit. The verification-only process harness now
allows a bounded 30 seconds. The final grouped run checks public output and actual
Chromium rotation/restart with certificate verification enabled.

The 58-case count is distinct cases, not the sum of repeated runs. Ruff lint and
format passed for 150 Python files; strict mypy passed for 135 source/test files.
CLI help lists all four signing commands. Existing installed-wheel/dependency-audit
evidence remains in [Phase 2](phase2.md); production dependencies did not change.
