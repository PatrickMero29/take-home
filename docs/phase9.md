# Phase 9 — real step-up authentication

Implemented and verified on 2026-10-07. **252 distinct selected new/affected cases
pass**, including real HTTPS/Chromium, owner CLI provisioning, password/TOTP proof,
replay after IDP restart, stale MFA after refresh, and sensitive access after SP
restart. This is a targeted checkpoint.

## Provisioning and secret custody

Alice and Bob receive independent PyOTP-generated 160-bit base32 TOTP secrets.
`seed-totp.enc` seals stable subject/secret pairs with `seeded-totp-provisioning`;
initialization enrolls each in `totp_credentials.encrypted_secret` with purpose
`totp-secret`. Envelopes bind the subject, preventing ciphertext transplantation.
Password, factor, database, signing, and TLS custody remain distinct.

Bootstrap upgrades v1/v2 bundles once to v3, preserving users/passwords, operator
material, and identities. A v3 marker requires its established factor file and
refuses silent regeneration. Enrollment preserves custody and replay counters.
Startup/readiness checks schema, database key binding, and factor decryption.

Retrieve the enrolled authenticator through the explicit IDP-owner command:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl totp-provisioning --username alice
```

The returned `otpauth://` URI intentionally contains the selected factor secret.
Import it into an authenticator app. Retrieval reads enrolled encrypted database
custody and requires the IDP owner; normal startup, pages, metadata and logs never
export it. The URI uses six-digit SHA-1 TOTP with a 30-second period. Back up
database and secret volume together to preserve provisioning and accepted history.

## Actual proof and atomic replay protection

The step-up form requires the same account's password and authenticator code in
one submission. Its encrypted continuation retains validated OIDC policy, expected
subject, original absolute deadline, and attempts. CSRF challenge, cookie, exact
Origin, state, nonce, and S256 remain enforced. Posted assurance/time is not proof.

Argon2id runs outside the security transaction. After it succeeds, gate/browser/
user locks recheck the credential snapshot, current session and subject continuity.
PyOTP matches using the injected Clock and a bounded one-step drift window. The
factor row is locked and its counter must exceed the durable high-water mark.

One transaction creates the immutable `pwd`+`otp` event, advances the counter,
appends `(subject, counter)` consumption linked to that event, and rotates the
IDP browser binding. A deferred constraint requires receipt subject and stronger
event to match. Receipt edits/deletion and counter rollback are prohibited. Code
validity is rechecked before consumption; expiry, revocation or commit failure
publishes no new event/cookie/consumption.

Password proof derives `urn:take-home:acr:password` and `amr=["pwd"]`.
Password plus consumed TOTP derives `urn:take-home:acr:password-totp` and
`amr=["pwd","otp"]`. Authentication time describes actual proof completion.
Wrong password/account, malformed/expired/future-out-of-window code, reused counter,
and concurrent reuse cannot raise assurance. Allowed future-drift acceptance also
prevents later acceptance of an older unused step.

## Attempt budgets and rate limiting

Valid credential submissions reserve durable source, browser, and account budgets
before password work. Source identity is the actual connection peer, not forwarded
headers; keys contain digests rather than raw cookie/source/account values.
Fixed lock order and atomic reservations coordinate workers. New forms, other
browsers and restart cannot reset the account budget. Source exhaustion stops
username-spraying bucket creation. Later failures still count as attempts.

MFA continuations additionally retain submission limits and original expiry across
rejected forms. Exhaustion returns 429/`Retry-After` without OTP consumption or new
authentication. Fresh forms become usable after the rate window. Valid existing
sessions persist; throttling trades repeated-login availability for bounded
guessing/password work. Budget history has no production cleanup worker yet.

| Setting | Default |
| --- | --- |
| `FID_AUTHENTICATION_WINDOW_SECONDS` | 60 seconds |
| `FID_AUTHENTICATION_ACCOUNT_ATTEMPTS` | 5 per window |
| `FID_AUTHENTICATION_BROWSER_ATTEMPTS` | 10 per window |
| `FID_AUTHENTICATION_SOURCE_ATTEMPTS` | 30 per window |
| `FID_MFA_FORM_MAX_ATTEMPTS` | 5 for one continuation |
| `FID_SENSITIVE_MAX_AGE_SECONDS` | 120 seconds |

## OIDC and RP enforcement

Discovery advertises password and password/TOTP assurance. The closed profile
accepts one supported `acr_values` as a minimum alongside `prompt` and `max_age`.
Authlib's consent hook requires a canonical event meeting that policy;
noninteractive unmet proof returns `login_required`. Unsupported assurance fails
before a credential continuation.

At an SP select **Step up authentication**, then **Verify password and TOTP**.
The purpose/grant/cookie-bound intent requests the stronger `acr_values`,
`prompt=login`, and `max_age=0`. Its encrypted transaction retains minimum
assurance, request time, and expected subject. Authlib/JOSE and RP policy check
issuer, recipient, nonce, signature, times, actual methods/assurance, freshness,
subject and exact committed evidence before installation.

Successful step-up rotates that SP's cookie and invalidates its old binding.
Another established SP retains its own immutable original event/assurance.
The IDP parent absolute lifetime remains fixed. Tampering/downgrading an
authorization request cannot satisfy the originally saved RP requirement.

## Sensitive operation

`GET /sensitive` requires stronger assurance and authentication within the SP's
maximum age. It offers a one-use same-origin approval form after fresh grant
authorization. `POST /sensitive` repeats that authorization, then rechecks local
lifetime/revocation, identity and recency under the browser lock before consuming
its independent `sp_sensitive` intent. Network calls remain outside local locks.

Approval commits an immutable `sensitive_operations` record with encrypted subject,
grant, actual event/method/assurance/time evidence. Unauthorized/stale proof cannot
create a row; commit failure preserves the retryable intent. Already-authorized
in-flight work follows the shared revocation contract.

Refresh retains original MFA event/auth_time and cannot manufacture recent proof.
Stale sensitive access requires real renewed password/TOTP proof. Factor, receipt,
operation, session and revocation history survive restart.

## Schema and working set

Heads are `idp_step_up_12` and `sp_step_up_08`. Upgrade adds encrypted factor,
consumption, throttle and sensitive-operation state while preserving existing
password authority and encrypted session/refresh custody.

| Path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/schemas/mfa.py`, `idp/services/provisioning.py`, `cli/bootstrap.py`, `cli/databases.py` | Stable encrypted provisioning, bundle upgrade and enrollment |
| `idp/repositories/mfa.py`, `idp/services/mfa.py` | PyOTP matching, locked replay protection and event-bound consumption |
| `idp/repositories/throttling.py`, `idp/services/browser.py` | Pre-password budgets and atomic proof/event/binding |
| `idp/api/browser.py`, `idp/protocol/authlib_adapter.py` | MFA forms and assurance/recency consent hooks |
| `sp/protocol/oidc.py`, `sp/repositories/transactions.py`, `sp/services/browser.py` | Saved minimum/subject/time and enforced callback |
| `sp/api/step_up.py`, `sp/services/sensitive.py`, `sp/repositories/sensitive.py` | Sensitive authorization, intent and encrypted committed evidence |
| `cli/totp.py`, `common/persistence/foundations.py` | Private factor retrieval and readiness |

## Exit checks and exact evidence

All eight Phase 9 exits are covered: password-only denial; actual two-factor
approval; wrong/expired/replayed/concurrent code rejection; durable replay after
restart; refresh history preservation; renewed proof after stale assurance;
account-substitution rejection; and established sibling-SP isolation. Additional
checks cover ciphertext/seed preservation, owner retrieval, form/source/account
budgets, SQL guards, callback downgrade, recency at commit, expiry during event
creation, logout versus proof, and transaction rollback.

```bash
uv run pytest tests/unit/test_totp.py tests/integration/test_step_up.py tests/integration/test_step_up_upgrade.py -q
# 42 passed in 39.18s

uv run pytest tests/e2e/test_step_up.py -q --durations=5
# 1 passed in 101.03s, actual verified Chromium TLS and owner CLI

uv run pytest tests/unit/test_foundations.py tests/unit/test_security_model.py tests/unit/test_id_token.py tests/unit/test_refresh_token.py tests/integration/test_browser_transactions.py tests/integration/test_refresh.py tests/integration/test_logout.py -q
# 170 passed in 81.46s

uv run pytest tests/unit/test_step_up_evidence.py tests/integration/test_lifecycle.py tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_reauthentication_changes_one_sp_event_without_elevating_other_sessions tests/integration/test_security_model.py::test_account_substitution_during_idp_and_sp_reauthentication_is_rejected -q
# 39 passed in 32.59s

make check
# Ruff lint/format passed for 189 Python files; strict mypy passed for 167 source/test files

uv run federationctl totp-provisioning --help
# Passed
```

The 252 count excludes repeats, including the initial 35-case checkpoint. Strict
typing caught a legacy test constructor missing the factor dependency; it now
supplies the typed service. Lint caught a migration-test loop closure and
intentional Unicode-code representation; both were corrected. Production
dependency/package configuration retains historical audit/wheel evidence in Phase 2.

## Requested full-regression follow-up

The user reported 34 failures in a full run. A requested local reproduction with
`uv run pytest -q` confirmed **34 failed, 530 passed in 1749.67s**. Independent
cases in the module-scoped real-network login fixture inherited persisted
authentication budgets, causing cascading 429 responses. Two older assertions
also predated Phase 7: default SP sessions now carry encrypted refresh credentials,
and discovery advertises the implemented refresh grant.

The login fixture now clears only authentication-budget rows before each
independent scenario, retaining full limits within requests/restarts in that
scenario. Its custody check verifies a distinct encrypted refresh credential.
Protocol checks verify advertised refresh requires authenticated valid credentials,
and explicitly code-only clients receive no refresh value and cannot use the grant.

```bash
uv run pytest tests/integration/test_browser_login.py tests/integration/test_protocol.py tests/integration/test_step_up.py -q
# 102 passed in 200.31s

make check
# Ruff lint/format passed for 189 Python files; strict mypy passed for 167 source/test files

uv run pytest -q
# 565 passed in 1654.82s (0:27:34)
```

This follow-up is a completed full regression run, explicitly requested by the
user, and retains the original targeted checkpoint separately.
