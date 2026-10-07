# Phase 6 — signing-key and SP compromise containment

Implemented and verified on 2026-10-07. **44 distinct selected new/affected cases
pass**, including one verified-HTTPS/Chromium deployment exercising both recovery
paths and actual owner CLI execution. This is a targeted checkpoint; related
database scenarios share factories and use the injected Clock.

## Signing-key containment

`POST /admin/api/signing-keys/{key_id}/contain` requires current `keys:write`
authority and a closed request:

```json
{"replacement_key_id":"NEW_KEY_ID","expected_active_key_id":"CURRENT_KEY_ID"}
```

The replacement must be distinct from the compromised key. A new replacement
must be prepared and published; an already active distinct signer can contain
historical prepared/draining/retired trust without another rotation. The expected
active ID prevents a stale operation from replacing a concurrent trust decision.

Under the issuance security gate, the service validates/decrypts replacement
material, activates it when needed, marks the target `revoked`, revokes its
evidence-linked grants and refresh families, and writes append-only audit with
target, previous active ID, replacement ID, operator, and timestamp. All effects
commit before success; failure rolls back the whole transition. Responses contain
public compromised/active snapshots and the newly revoked grant count.

Revocation is irreversible and overrides ordinary expiry/retention. JWKS excludes
the revoked key, but removal alone is not enforcement: fresh authenticated grant
checks deny its lineage even when a cached public key still verifies the JWT.
Historical unaffected keys/clients and the parent password-authenticated IDP
session retain their own authority. New code redemption can issue under the
replacement without treating issuance as new user authentication.

`revoke_signer_in()` joins a caller-owned transaction. Issuance and service-level
refresh use the same gate, so work that precedes containment is subsequently
revoked, and work that follows cannot restore the compromised lineage. Actual
refresh protocol/coordination remains the Phase 7 integration.

## SP containment and recovery barrier

`POST /admin/api/clients/{client_id}/contain` requires current `clients:write`
authority and `{"expected_version":N}`. It disables the client, records its
current `compromised_key_id`, advances live registration policy, revokes only
that client's grants/families, and records audit in one gated transaction.

Disabled credentials cannot authenticate token, introspection, or revocation
requests. Protected SP requests fail closed; other clients remain functional.
The compromised SP's local rows may remain stored, but their authorization is
revoked centrally. Replacing credentials and restarting does not revive those
grants or captured cookies.

The durable compromise marker makes **Enable client** reject while the current
key is the captured key. PostgreSQL also rejects direct enable or marker reset.
Replacement must use a new key ID and new public material; existing append-only
key history forbids reuse. Replacement preserves disabled state. Only explicit
re-enable permits new authorization, and older pending codes remain invalid
through their registration-version binding.

Ordinary administrative **Disable client** retains its existing reversible
availability-control behavior. **Contain compromised client** supplies the
credential-replacement barrier for an incident.

## Owner-side credential custody

`federationctl client-key-replace --expected-key-id ID --expected-version N` runs
only in the owning SP's private runtime. It generates RSA/RS256 material and
returns **public replacement metadata only** for the operator. It has no IDP
administrative authority and cannot select an issuer signer.

The SP stores `client-identity.enc` with owner-only permissions and authenticated
envelope purpose `sp-client-identity`. The payload binds service ID, kid, private
key, and exact public identity. Startup checks ownership, decryption, key shape,
and public/private equality before selecting it. Wrong-cipher, transplanted,
inconsistent, public-readable, or symlink material fails closed.

A private no-follow file lock serializes simultaneous owner replacements. The
expected current kid rejects stale/repeated writers. Exclusive staging, fsync,
atomic rename, and directory fsync install one envelope; failed installation
preserves the previous selected identity. Bootstrap preserves the override and
the original identity, database password, TLS material, and wrapping-key binding.
Backups include the whole SP secret volume and matching database.

The running SP retains its loaded key until restart. Registry replacement and
owner deployment are separate operations; the client stays disabled while they
are coordinated. If a registry request needs retry, retain the returned public
metadata or retrieve the current public key with `client-metadata`; generating
another key is not needed to retry that request.

## Operator workflows

Use [runtime setup](runtime.md) and the separately generated operator credential.
Browser controls require same-origin, one-use purpose/target/cookie-bound intent.
CLI sessions use verified HTTPS and end after each command. Current credential
epochs and explicit registry/signing permissions are rechecked for every mutation.

### Recover SP A

1. Sign in at both SPs. At `/admin/clients/sp-a`, select **Contain compromised
   client**. A loses trusted interactions; B remains usable.
2. Read the contained client's current key ID and registration version. Substitute
   those values below inside A's owner runtime:

```bash
docker compose exec -T sp-a /app/.venv/bin/federationctl client-key-replace --expected-key-id CAPTURED_KEY_ID --expected-version CURRENT_VERSION
```

3. Paste that public JSON into **Replace client credentials JSON** and submit.
   A remains disabled. Restart only A, then select **Enable client**:

```bash
docker compose restart sp-a
```

4. The captured credential and original cookie remain rejected. Select **Sign in**
   at A for fresh SSO evidence. B and the IDP need no restart for this recovery.

Equivalent operator CLI operations use `inspect`, `contain-client`,
`replace-credentials`, and `enable`, with current versions:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned contain-client --client-id sp-a --expected-version CURRENT_VERSION
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned replace-credentials --client-id sp-a --metadata PUBLIC_REPLACEMENT_JSON_FILE
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned enable --client-id sp-a --expected-version REPLACED_VERSION
```

The replacement file is public JSON containing `expected_version`, new `key_id`,
and `public_key_pem`. CLI password input follows the existing hidden prompt,
owner-private `--password-file`, or explicit in-container `--provisioned` flow.

### Recover signing trust

At **Manage signing keys**, prepare a replacement, open **Publish public JWKS**,
and **Reload key state**. In the compromised key's section, choose that published
key under **Replacement signing key**, then **Contain compromised signing key**.
Existing affected SP sessions are denied even with warmed keys. Fresh SSO uses
replacement trust; unaffected signing lineage remains usable.

CLI preparation/publication is `key-prepare`; inspect using `keys-inspect`, then:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-contain --key-id COMPROMISED_KEY_ID --replacement-key-id REPLACEMENT_KEY_ID --expected-active-key-id CURRENT_KEY_ID
```

For historical compromise, an already active distinct key is an accepted
replacement. Self-replacement, unpublished material, revoked targets, and stale
active assumptions reject. Already-authorized in-flight work cannot be recalled;
containment applies at subsequent authorization decisions.

## Persistence and working set

IDP head is `idp_compromise_control_09`; SP head remains `sp_lifecycle_05`.
Migration 09 adds nullable `clients.compromised_key_id`, the recovery check/guard,
and nullable `signing_audit.replacement_key_id`. Existing registrations, code
proofs, signed retention, and prior immutable audit facts remain intact.

| Package path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/services/security_model.py` | Caller-owned scoped client/signer revocation |
| `idp/services/signing.py`, `idp/schemas/signing.py` | Atomic replacement/revocation and public result |
| `idp/services/clients.py`, `idp/repositories/tables.py` | Version-bound containment and recovery barrier |
| `idp/api/signing.py`, `idp/api/operator.py` | Explicit browser/API controls, CSRF and fresh permissions |
| `cli/operator.py`, `cli/credentials.py`, `cli/main.py` | Authenticated containment and owner key replacement |
| `common/security/secrets.py` | Bound encrypted owner override loading |

## Exit checks and verification

| Exit check | Evidence |
| --- | --- |
| Disabling A stops trusted interactions while B remains usable | Shared runtime and real-browser client containment; token/introspection/revocation negatives; B protected page/PID preserved |
| Captured A credentials stay rejected after replacement | Real owner CLI, registry replacement, A restart, explicit enable, and old-key endpoint rejection |
| Cached compromised-key artifacts fail | Actual old JWT still verifies cryptographically, while establishment/refresh/protected access reject revoked authority |
| Forged unissued JWT cannot establish a session | Vetted active-key forgery of jti/subject in actual callback transport; exact canonical evidence rejects and creates no authenticated session |
| Refresh/concurrent issuance cannot revive trust | Eight concurrent redemptions plus refresh/containment for both incident kinds; affected resulting authority stays revoked |
| Containment survives restart | Bootstrap/database rerun, factory reconstruction, live SP/IDP restart, and captured-cookie replay rejection |

Additional cases exercise unrelated historical-key lineage, self/unpublished/stale
recovery rejection, transactional failure, permissions and CSRF origin/purpose/
target/replay, database recovery guards, owner writer races, atomic-install failure,
encrypted custody, and affected rotation/operator/migration contracts.

Exact selected commands/results:

```bash
uv run pytest tests/integration/test_security_model.py::test_client_compromise_is_scoped_and_blocks_issuance_and_refresh tests/integration/test_security_model.py::test_key_compromise_revokes_only_affected_evidence_and_cannot_be_undone tests/integration/test_operator_upgrade.py -q
# 3 passed in 7.90s

uv run pytest tests/unit/test_client_recovery.py tests/integration/test_containment.py -q
# 22 passed in 22.47s

uv run pytest tests/integration/test_containment.py::test_sp_containment_requires_new_credentials_and_never_revives_old_sessions tests/integration/test_signing_rotation.py tests/integration/test_operator.py::test_metadata_update_replacement_and_disabling_are_live_and_scoped tests/integration/test_operator.py::test_operator_browser_csrf_is_session_purpose_origin_and_target_bound tests/integration/test_operator.py::test_operator_mutations_and_audit_rollback_together tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_issuance_racing_client_disable_cannot_escape_durable_revocation 'tests/integration/test_security_model.py::test_refresh_racing_containment_cannot_resurrect_authority[key]' 'tests/integration/test_security_model.py::test_refresh_racing_containment_cannot_resurrect_authority[client]' 'tests/integration/test_phase0_lineage.py::test_redemption_racing_containment_cannot_publish_reusable_authority[key]' 'tests/integration/test_phase0_lineage.py::test_redemption_racing_containment_cannot_publish_reusable_authority[client]' -q
# 19 passed in 37.81s; includes strengthened old-credential rejection after recovery

uv run pytest tests/e2e/test_containment.py -q
# Initial: 1 failed in 56.79s; test assumed every invalid_client response was HTTP 401
# Corrected assertion: 1 passed in 88.98s; accepts endpoint-specific 400/401 and requires invalid_client

make check
uv run federationctl operator --help
uv run federationctl client-key-replace --help
```

The count is 44 distinct cases, excluding repeated executions. Final Ruff
lint/format passed for 155 Python files; strict mypy passed for 139 source/test
files. The browser uses verified TLS with an isolated CA profile and executes the
actual owner CLI. Existing installed-wheel/audit evidence remains in Phase 2;
production dependencies did not change.
