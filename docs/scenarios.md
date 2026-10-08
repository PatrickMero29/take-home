# Operator commands and reproducible feature scenarios

Start with [README setup](../README.md#start-and-try-it), trusted browser CA, and
Alice's generated password. Default URLs use `idp.localhost:8443`,
`sp-a.localhost:8444`, `sp-b.localhost:8445`, and optional `sp-c.localhost:8446`.
Use separate browser profiles to demonstrate independent federation sessions.
Passwords and enrollment secrets are retrieved only through explicit owner commands.

## 1. Login, local logout and revocation

Sign in at A with Alice, then at B using SSO. `/account` shows the same issuer/
subject/sid/authentication history with distinct host-only opaque session cookies.

- **Sign out locally** at A ends its local session; B and IDP SSO remain available.
- **Revoke application access** at A revokes its grant/family at the IDP, then ends
  its local session. Start a fresh sign-in for a new grant.
- At the IDP, **Manage application access** revokes one selected grant. **End IDP
  session** revokes that parent and its derived authority and dispatches logout.

Protected SP requests check current authoritative state; dependency outages return
unavailability and preserve otherwise-valid persisted sessions. Capture/replay
tests run automatically without exporting reusable cookies/tokens in documentation.

## 2. Live C onboarding

```bash
docker compose --profile onboarding up --build --wait sp-c
docker compose exec -T idp /app/.venv/bin/federationctl operator-credentials
docker compose exec -T sp-c /app/.venv/bin/federationctl client-metadata
```

C's login initially fails as unregistered. At `/admin`, use the separate operator
credential, select **Register a client**, paste the public metadata, and submit.
Then C completes SSO while IDP/A/B remain running.

Equivalent verified-HTTPS CLI registration and inspection:

```bash
docker compose exec -T sp-c /app/.venv/bin/federationctl client-metadata | docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned register --metadata /dev/stdin
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned inspect --client-id sp-c
```

`--provisioned` reads the IDP owner's initial operator envelope. For changed
credentials, use the hidden prompt or an owner-private `--password-file`; passwords
are not command arguments. Metadata updates and credential changes require the
current `expected_version`, supplied in public JSON. [Registry contract](phase4.md).

## 3. Routine signing-key rotation

Warm A/B/C through login. At `/admin`, **Manage signing keys** → **Prepare signing
key** → **Publish public JWKS** → **Reload key state** → activate the prepared key.
Existing sessions remain usable; new login/renewal uses current trust. Retire a
draining key only after its displayed verification deadline plus skew.

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned keys-inspect
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-prepare
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-activate --key-id NEW_KEY_ID --expected-active-key-id CURRENT_KEY_ID
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-retire --key-id OLD_KEY_ID --expected-verification-deadline VERIFICATION_DEADLINE
```

Substitute IDs/deadlines from current inspection; stale or early assumptions are
rejected. Retention includes actual login, renewal and logout JWTs. [Key policy](phase5.md).

## 4. Compromise containment and recovery

**SP incident:** at `/admin/clients/sp-a`, select **Contain compromised client**.
A loses trusted interactions while B remains usable. Read A's contained key ID and
current registration version, then install a new encrypted owner-side key:

```bash
docker compose exec -T sp-a /app/.venv/bin/federationctl client-key-replace --expected-key-id CAPTURED_KEY_ID --expected-version CURRENT_VERSION
```

Paste the returned public JSON into **Replace client credentials JSON**. Keep A
disabled until owner deployment and registry replacement agree, then restart A
and explicitly **Enable client**. Old credentials/cookies remain rejected.

```bash
docker compose restart sp-a
```

**Signer incident:** prepare/publish a distinct replacement, choose it in the
compromised key's section, and **Contain compromised signing key**. Replacement,
revocation, affected grant/family denial and audit commit together. Fresh SSO uses
replacement trust; cached compromised signatures cannot justify authorization.

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned contain-client --client-id sp-a --expected-version CURRENT_VERSION
docker compose exec -T idp /app/.venv/bin/federationctl operator --issuer https://idp.localhost:8443 --ca-file /run/federation/ca.crt --provisioned key-contain --key-id COMPROMISED_KEY_ID --replacement-key-id REPLACEMENT_KEY_ID --expected-active-key-id CURRENT_KEY_ID
```

CLI replacement/enable fields and retry-safe public recovery files are detailed in
[Phase 6](phase6.md#operator-workflows). Recovery does not clear historical revocation.

## 5. Renewal, re-authentication and real step-up

Access lasts at most five minutes. Continued protected use automatically rotates
refresh credentials within the original session/grant ceilings, preserving the
cookie and immutable `auth_time`/assurance. **Re-authenticate** requests actual
password proof or the selected recency policy and rotates only that SP's binding.

```bash
docker compose exec -T idp /app/.venv/bin/federationctl totp-provisioning --username alice
```

Import this selected enrolled secret URI into an authenticator app. At A choose
**Step up authentication** → **Verify password and TOTP**, enter the same account's
password and current code, then open **Sensitive operation** and approve it.
Password-only and stale MFA fail; B's established session retains its own event.
Accepted OTP steps cannot be reused after restart. Fresh forms do not reset attempt
budgets; 429 exposes `Retry-After`. [Proof/limits](phase9.md).

An abandoned or uncertain refresh becomes `blocked` and requires **Start a fresh
sign-in**; resending the possibly consumed value is deliberately forbidden.
Automated acceptance uses injected time to exercise expiry and lost installation
without waiting real lifetimes. [Renewal recovery](phase7.md).

## 6. Global logout and offline recovery

With A/B/C signed in under the same IDP session, stop C:

```bash
docker compose stop sp-c
```

At A use **Sign out everywhere** and confirm at the IDP. That parent/grants are
revoked before delivery; other browser profiles with different sids are independent.
Restart the dispatcher and C to inspect recovery:

```bash
docker compose restart idp
docker compose start sp-c
docker compose exec -T idp /app/.venv/bin/federationctl logout-deliveries
```

C's old cookie cannot authorize access on return, including before notification.
Pending delivery resumes after its due time/lease; an expired JWT is freshly signed
for the original sid. Exact retries acknowledge prior effects and cannot terminate
a fresh different sid. Explicitly recover a failed/skipped bound delivery after
repairing live metadata/service availability:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl logout-retry --delivery-id DELIVERY_ID
```

The owner summary exports fixed statuses, not signed payloads. [Delivery policy](phase8.md).

## Acceptance and video working set

```bash
make test TESTS="tests/integration/test_system_acceptance.py tests/e2e/test_system_acceptance.py"
make check
```

[Phase 11](phase11.md) maps restart/replay/race evidence to the selected scope.
The browser acceptance combines onboarding, rotation, ambiguous refresh recovery,
MFA, global logout and database/application restart in one deployment. The README
maps the four writeup requirements; architecture and decision links support
explaining one major design choice in the subsequent demo video. A recorded video
and GitHub publication are separate submission artifacts, not executed by these tests.

The [timed demo-video script](demo-video-script.md) gives ordered setup/recording
commands and spoken explanations for an under-ten-minute revocation/durable-logout
walkthrough. [Study/rehearsal notes](demo-video-notes.md) explain object/credential
roles, failure and replay boundaries, recording timing, and evidence claims.
