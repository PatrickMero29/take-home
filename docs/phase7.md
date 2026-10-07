# Phase 7 — refresh-token rotation and re-authentication

Implemented and verified on 2026-10-07. **133 distinct selected new/affected cases
pass**, including real HTTPS/Chromium renewal, password re-authentication, and
restart with injected process time. This is a targeted checkpoint.

## IDP rotating refresh grants

The token endpoint accepts `grant_type=refresh_token`, a bounded opaque
`refresh_token`, optional `scope=openid`, and a fresh endpoint-bound
`private_key_jwt`. Authlib's `RotatingRefreshGrant` explicitly sets
`INCLUDE_NEW_REFRESH_TOKEN=True`; its client/ownership/scope validation and token
creation hooks are joined to the existing async-backed provider boundary.

Code redemption emits a refresh credential only for a refresh-enabled client.
New registrations default to `authorization_code` plus `refresh_token`; code-only
registrations remain supported. Migration 10 upgrades the original A/B default
code-only capability set once, retaining enabled state, keys, and destinations.
That metadata change advances registration policy and rejects older pending code
approvals while preserving their immutable history and existing grant authority.

Initial protocol access/refresh values are the exact values hashed into canonical
storage. Each successor records its consumed predecessor, family, generation,
issuance/expiry, and one-way token verifier. PostgreSQL enforces one successor per
predecessor and exact family/generation ancestry. Existing pre-upgrade facts remain
intact; newly inserted successors require their bound consumed predecessor.

The authenticated owning client is checked before reuse observation or mutation.
Wrong-client refresh cannot revoke the rightful family's authority. Authenticated
reuse commits grant/family containment before returning `invalid_grant`. A valid
client assertion's replay reservation remains durable on expected policy denial;
unexpected signing/commit failure rolls back rotation and reservation together.

Refresh uses the issuance gate and savepoint. Active-key selection, library-signed
ID token, predecessor consumption, successor/access records, signed-artifact
retention, and immutable `refresh_issuances` commit before success. A deferred
constraint requires complete bound rotation and evidence. Logout, client
containment, signer revocation, account disabling, and parent expiry deny renewal.

## Authentication history and signed renewal evidence

The original `authentication_evidence` and SP `encrypted_evidence` remain
immutable. Refresh records a separate signed evidence row for each generation;
it preserves issuer/subject, sid/event, original `auth_time`, and verified acr/amr.
The fresh iat/jti/at_hash describe issuance, not another password/MFA event.

Authenticated introspection returns the original grant/session lineage plus
`credential_evidence` for the exact current access credential. SP renewal compares
the vetted JWT against that new evidence and its original local authentication,
grant/family identity, and expected next generation. Protected session binding
continues to use the original evidence rather than rewriting historical facts.

Renewal JWTs use a distinct validation context: nonce may be absent; if present it
must match the original flow. The code-login validator still requires nonce.
Signature, strict RS256/JWT header, exact issuer/single recipient, timestamps,
at_hash, and immutable authentication equality remain mandatory. Fake subject,
session, authentication time, assurance/methods, type, keys, or token pair reject.

Each renewal signer contributes to retention and containment. Revoking a key used
for renewal also revokes the associated grant/family even when its original login
was signed by another key. Routine key rotation remains compatible with renewal.

## SP coordination and ambiguous outcomes

SPs seal refresh credentials with purpose `sp-refresh-token`, separately from
access/evidence custody. Protected requests validate local idle/absolute state,
then obtain a usable access credential through `SpRenewalService` and perform the
usual fresh authoritative check.

Renewal is a durable state machine on the local authentication row:

| State | Effect |
| --- | --- |
| `ready` | Valid access can be reused; expired access can claim one attempt |
| `pending` | Attempt ID/generation/start time committed before network work; other processes wait for installation |
| `blocked` | Outcome is uncertain; the old refresh credential cannot be sent again |

Claims lock browser then authentication state and release both before verified
HTTPS. Completion rechecks attempt/generation, local lifetime/revocation, returned
family/grant/authentication, and credential expiry before committing encrypted
successors. Concurrent local logout wins. Ordinary renewal leaves the cookie,
original evidence, auth_time/assurance, and absolute/idle ceilings unchanged.

The lease lasts request timeout plus five seconds. Abandoned pending claims become
blocked using the injected Clock; concurrent waiters have a bounded monotonic
wait. Lost responses, cancellation, verification failure, or local install failure
block further use. A worker that crashes after claim never causes a second send.

The recovery page offers **Start a fresh sign-in**, **Re-authenticate**, and local
logout. Fresh browser-bound code authorization can establish a new session through
valid IDP SSO; forced re-authentication additionally requests actual credentials.
The previous local session is retired on successful establishment. The ambiguous
refresh value is never retried or treated as an idempotency credential.

## Forced re-authentication

At an authenticated SP, select **Re-authenticate**. The same-origin one-use form
offers **Force password sign-in** (`prompt=login`, `max_age=0`) or **Require recent
sign-in** with a bounded maximum age of 0–86,400 seconds. It is tied to the current
cookie, purpose, and grant. The encrypted authorization transaction retains the
requested policy/time alongside state, nonce, and S256 proof.

The IDP requires real Argon2id password verification for unmet freshness, appends
a new event for the same subject, and preserves the parent's absolute lifetime.
The SP rechecks returned freshness and subject continuity, consumes its callback
once, creates a new local identifier, and invalidates the prior browser binding.
Another established SP's event/cookie is not elevated or replaced. Wrong password,
account substitution, invalid intent/origin/purpose, and replay fail.

The script-free form permits only its pinned issuer as the cross-origin redirect
destination in CSP. Failed password submission returns a fresh blank form; both
username and password must be submitted again.

## Runtime and persistence

IDP head is `idp_refresh_10`; SP head is `sp_refresh_06`.

| Record | Added behavior |
| --- | --- |
| `refresh_credentials.predecessor_digest` | Immutable hashed ancestry; consumed predecessor and unique successor |
| `refresh_issuances` | Immutable signed jti/digest/key, family/generation, predecessor/successor/access binding, dates |
| SP authentication renewal columns | Access deadline, generation, durable ready/pending/blocked state, attempt and start time |
| Encrypted SP evidence payload | Original nonce and family ID alongside immutable session evidence |
| Encrypted authorization transaction | Re-authentication prompt/max_age/request time |

Existing code-only SP rows cannot invent a refresh credential. Sign in again to
establish refresh-enabled custody. Default access lifetime is 300 seconds, with
one-hour parent/grant/family/session ceilings and a 15-minute SP idle window.
Configure bounded protocol values through `FID_POLICY`, for example
`{"access_token_ttl_seconds":60}` at the IDP. Changing a policy never extends
persisted absolute lifetimes.

The browser checkpoint uses `VerificationClock` only in the verification runtime.
An owner-private atomically published clock file is polled off-thread; protocol
hooks read an in-memory timestamp. Tests advance expiry rather than waiting real
lifetimes. Normal application serving uses its ordinary injected/SystemClock.

## Working set

| Path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/protocol/authlib_adapter.py` | Rotating refresh grant and vetted OpenID response hooks |
| `idp/services/oidc.py`, `idp/services/security_model.py` | Gated candidate/reuse/issuance and complete rotation publication |
| `idp/repositories/security_tables.py`, `idp/repositories/security.py` | Immutable ancestry/evidence and signer containment queries |
| `common/security/artifacts.py`, `common/security/oidc.py` | Separate nonce/login/refresh models and exact history verification |
| `sp/protocol/oidc.py`, `sp/services/revocation.py` | Verified HTTPS refresh and authenticated exact renewal evidence |
| `sp/services/renewal.py` | Durable single-flight claims, installation, and ambiguity barrier |
| `sp/services/browser.py`, `sp/api/browser.py`, `sp/repositories/transactions.py` | Bound re-authentication forms/transactions and fresh-session recovery |
| `cli/architecture_runtime.py` | Verification-only background process clock |

## Exit checks and verification

| Exit check | Selected evidence |
| --- | --- |
| Expired access renews without password | Actual wire refresh and SP account request; real Chromium A/B renew with unchanged cookies/history |
| Consumed credential reuse revokes family | Authenticated replay, eight wire redeemers, and restart; resulting access is inactive |
| Concurrent legitimate requests avoid false reuse | Two separate renewer instances share database claim; twelve callers obtain one successor |
| Wrong-client refresh leaves owner usable | B tries consumed/current A credentials; A's generation and authority stay intact |
| Logout/client/key containment prevents renewal | Local finish-versus-logout, three authoritative race kinds, non-root renewal-key compromise, and retained model checks |
| Forced authentication requires credentials | Wrong password, correct password/new event/cookie, max_age demand, account substitution, intent/origin/replay negatives |
| Refreshed ID tokens preserve history | Separate verifier rejects changed subject/sid/auth_time/acr/amr; exact committed evidence and parent ceilings checked |

Exact selected commands/results:

```bash
uv run pytest tests/integration/test_protocol.py::test_pkce_oidc_and_private_key_jwt_round_trip -q
# 1 passed in 2.94s

uv run pytest tests/unit/test_refresh_token.py tests/unit/test_client_metadata.py tests/integration/test_refresh.py -q
# 67 passed in 25.70s

uv run pytest tests/integration/test_operator_upgrade.py tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_refresh_preserves_expired_login_evidence_history_and_absolute_ceilings tests/integration/test_phase0_lineage.py::test_failure_after_grant_creation_rolls_back_both_protocol_and_security_records -q
# Initial: 1 failed, 3 passed in 17.85s; default refresh capability changes registry version

uv run pytest tests/unit/test_id_token.py tests/integration/test_operator_upgrade.py tests/integration/test_security_model.py -k 'token or refresh or routine_rotation or key_compromise or migrations or failed_commit or operator_upgrade' -q
# 43 passed, 20 deselected in 33.92s after verifying old-approval rejection and fresh-code recovery

uv run pytest tests/integration/test_lifecycle.py::test_exact_server_expiry_rejects_a_cookie_still_held_by_the_browser tests/integration/test_containment.py tests/integration/test_protocol.py::test_concurrent_code_redemption_has_one_issuance tests/integration/test_phase0_lineage.py::test_policy_denial_discards_draft_issuance_but_commits_valid_assertion_replay -q
# 20 passed in 31.96s

uv run pytest tests/e2e/test_refresh.py -q
# Initial: 1 failed in 88.72s; the fresh rejected-password form clears username
# Corrected browser input: 1 passed in 84.74s with verified TLS and injected process time

make check
```

The count is 133 distinct selected cases, excluding repeated runs. Earlier
re-authentication checks also corrected an assertion expecting 303 where the
credential-backed authorization response returns 302 directly to the callback.
Final Ruff lint/format passed for 161 Python files; strict mypy passed for 143
source/test files. Dependency/package evidence remains the Phase 2 checkpoint;
production dependencies did not change.
