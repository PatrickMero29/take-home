# Runtime and trust setup

## Compose startup

Prerequisites: Docker with Compose. Run from the repository root:

```bash
make up
```

The dependency chain generates initial secrets/certificates, starts PostgreSQL,
creates application roles/databases, applies migrations, enrolls database
encryption-key bindings, provisions Alice/Bob and public SP A/B registrations,
then starts application processes only after readiness validation succeeds.

| Service | Browser URL | Database and role |
| --- | --- | --- |
| IDP | `https://idp.localhost:8443` | `fid_idp` |
| SP A | `https://sp-a.localhost:8444` | `fid_sp_a` |
| SP B | `https://sp-b.localhost:8445` | `fid_sp_b` |
| Optional SP C | `https://sp-c.localhost:8446` | `fid_sp_c` |

Chromium-based browsers resolve `*.localhost` to loopback. If a client resolver
does not, map these hostnames to `127.0.0.1`. Container networking uses declared
DNS aliases and the same ports/hostnames, so issuer identifiers remain identical.

## Trust the generated development CA

Export only the public certificate after startup:

```bash
make export-ca > federation-local-ca.crt
```

Import that certificate into the browser/OS **trusted root certificate** store
used by your local browser. On Windows, the certificate import wizard provides
the Current User / Trusted Root Certification Authorities destination. Firefox
may use its own Authorities store. Export/import is a local development setup
step; private CA or application keys are never exported by this command.

Every application and database client already receives this CA explicitly.
Application requests do not disable certificate or hostname verification.

## Seeded user credentials

Alice and Bob receive generated passwords and stable subject IDs. Retrieve one
initial credential through the IDP's owner-side command:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl seed-credentials --username alice
docker compose exec -T idp /app/.venv/bin/federationctl seed-credentials --username bob
```

The selected command intentionally prints that initial credential. Bootstrap
and normal startup do not print credentials. Passwords are encrypted in the
owner-private IDP provisioning envelope; PostgreSQL stores salted Argon2id
hashes. Restart/bootstrap reruns preserve stable IDs, hashes, and account state.
If a password is changed later, this command still shows initial provisioning
material; the persisted current password is not reset by bootstrap.

The IDP browser login uses bounded off-thread Argon2id verification and commits
its session/event with a new opaque browser identifier. SP callbacks validate
recipient-specific evidence and establish independent authenticated sessions.

## Browser SSO

1. Open `https://sp-a.localhost:8444` and select **Sign in**.
2. Enter `alice` and her generated password on the IDP form.
3. SP A displays her stable authenticated subject and `sp-a` application identity.
4. Open `https://sp-b.localhost:8445` and select **Sign in**. SP B establishes its
   own session through the existing IDP sign-in, without another password.

`/account` at each service returns only that service's authenticated identity
and assurance. Cookies are independent, opaque, HttpOnly, Secure, and host-only.
Expired/consumed transactions require a new login attempt. Password failures
provide a fresh browser-bound form without reflecting the submitted credentials.

Access tokens last up to five minutes. Refresh-enabled SP sessions automatically
renew expired access using rotating, encrypted refresh credentials; ordinary
renewal keeps their cookie and original authentication history. Selecting
**Sign in** obtains fresh authorization through the existing IDP session.
[Phase 2](phase2.md) records the flow and
the cross-SP, CSRF, nonce/PKCE, and restart guarantees.

## Session lifecycle controls

On each SP, **Sign out locally** leads to a local confirmation form. Confirming
ends its own persisted session, invalidates pending browser transactions, and
clears that host's cookie after commit. It does not require the IDP to be online.
Other SPs and the IDP remain signed in.

**Revoke application access** confirms the SP's current grant, authenticates the
SP to `/revoke`, and ends its local session after acknowledgement. On the IDP,
**Manage application access** displays only the current session's grants and
offers per-grant revocation. **End IDP session** revokes its derived grants at
both SPs; subsequent protected requests are denied.

### Global logout and delivery recovery

At either SP select **Sign out everywhere**, then **Continue to global sign out**.
The IDP confirms the matching current browser session. Select **Sign out everywhere**
there to revoke that parent and every derived grant/family before notification.
Other browsers with different IDP session IDs remain active. **End IDP session**
also sends the same signed back-channel notifications.

The initiating SP retains its sealed original ID token as a hint; expired tokens
and routinely retired signing keys can identify the matching historical context.
A hint never signs a user in. Active-session termination requires the matching
IDP cookie and its own one-use same-origin confirmation. Returned destinations
are exact registered HTTPS URIs and revalidated at commit.

Each SP checks the `logout+jwt`/event/no-nonce profile and authenticated current
logout issuance, then atomically expires its bindings, invalidates pending
callbacks, and retains issuer/sid termination and replay receipts. Back-channel
HTTP cannot clear another host's cookie; that retained value already fails server
authorization. Retried old-sid notifications do not end fresh different sessions.

The IDP runs its dispatcher in application lifespan. Default limits are one-second
polling, four concurrent attempts, two-second delivery deadlines, eight attempts,
and exponential delays from two up to 60 seconds. Set validated
`FID_LOGOUT_POLL_SECONDS`, `FID_LOGOUT_BATCH_SIZE`,
`FID_LOGOUT_DELIVERY_TIMEOUT_SECONDS`, `FID_LOGOUT_MAX_ATTEMPTS`,
`FID_LOGOUT_RETRY_BASE_SECONDS`, and `FID_LOGOUT_RETRY_MAX_SECONDS` as needed.
`FID_POLICY` includes `logout_token_ttl_seconds` (default 300 seconds).

Restart recovers expired leases and pending deliveries. A still-valid token is
retried idempotently; expiry or changed signing trust causes fresh signed evidence
for the same original sid. A dependency outage blocks protected access before
notification and preserves delivery state for recovery.

Inspect the latest 100 summaries and explicitly recover a failed/skipped delivery
from the IDP owner's private runtime:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl logout-deliveries
docker compose exec -T idp /app/.venv/bin/federationctl logout-retry --delivery-id DELIVERY_ID
```

These commands expose fixed status/error labels and obtain the destination from
current client metadata. They export no payloads/credentials and cannot reset
acknowledged delivery or restore revoked grants. HTTP redirects/permanent
rejections stop automatic retries; network/service interruption receives bounded
retry. A missing endpoint remains `skipped` until configured and explicitly
recovered. Global revocation stays effective throughout.

The Phase 8 migration enables logout metadata for original uncustomized A/B
registrations. Customized clients retain their approved metadata; configure their
`backchannel_logout_uri` and `post_logout_redirect_uris` through the existing
operator control plane. Normal SP destinations are `/backchannel-logout` and `/`
under each SP's own configured HTTPS origin. Existing encrypted sessions survive
upgrade; older hint-free payloads use confirmed browser/grant matching.
See [Phase 8](phase8.md) for schema, trust contracts, races, and exact evidence.

Defaults: 30-minute IDP browser storage, one-hour IDP/grant/SP absolute lifetimes,
15-minute SP idle window, five-minute access credentials, and five-minute one-use
confirmation intents. All child lifetimes are parent-bounded. `/account` at an
SP includes its known absolute/idle deadlines. The server enforces expiry even
when the browser retains a cookie. Sessions and revocation survive restart.

Configure validated policy through `FID_LIFECYCLE` JSON, for example on an SP:

```text
FID_LIFECYCLE={"sp_session_seconds":1800,"sp_idle_seconds":120}
```

`FID_SESSION_TTL_SECONDS` bounds generic/IDP browser storage;
`FID_BROWSER_ACTION_TTL_SECONDS` bounds confirmation intents. Changing settings
does not extend persisted absolute lifetimes. Dependencies fail closed and keep
otherwise-valid persisted state for recovery. [Phase 3](phase3.md) documents
permissions, replay containment, and targeted acceptance evidence.

## Refresh and re-authentication

New client registrations default to code plus refresh; code-only profiles remain
valid. The Phase 7 migration upgrades the original A/B code-only default once.
Registry policy changes invalidate older pending codes, so start a new sign-in
after upgrading. Existing code-only sessions need a new sign-in to acquire
refresh custody. Customized/client C profiles can opt in through approved
`allowed_grants: ["authorization_code", "refresh_token"]` metadata.

Continue using `/account` after access expiry. While idle/absolute and parent
authorization remain valid, the SP performs one authenticated renewal and seals
its successor. Concurrent workers share a database claim. Refresh cannot advance
auth_time, increase assurance, extend absolute lifetime, or undo containment.

At an SP select **Re-authenticate**. **Force password sign-in** requests
`prompt=login`/`max_age=0`; **Require recent sign-in** uses the entered maximum age.
Actual fresh password proof preserves the subject, rotates only that SP's cookie,
and leaves another established SP's history unchanged. Each form is origin,
cookie, purpose, and one-use bound.

If a renewal response, cancellation, or local installation is uncertain, the
old refresh token is blocked from another send. Use **Start a fresh sign-in**
for new code authorization or **Re-authenticate** for explicit credential proof.
A restarted worker encountering an abandoned claim follows the same barrier.

Access/ID-token bounds are configured through `FID_POLICY` JSON, for example
`FID_POLICY={"access_token_ttl_seconds":60}` at the IDP. Parent/session/family
ceilings remain in `FID_LIFECYCLE`. [Phase 7](phase7.md) documents rotation,
ambiguity recovery, validation contexts, and exact selected checks.

## Password/TOTP step-up and sensitive access

Retrieve Alice's enrolled authenticator through the explicit IDP-owner command:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl totp-provisioning --username alice
```

Import the returned `otpauth://` URI into a TOTP app. This owner command
intentionally exposes the selected factor secret; startup, public pages and logs
keep it private. The factor is encrypted in the provisioning envelope and database,
bound to the stable user subject, and preserved on normal restart/bootstrap.

1. Sign in at A and B with a password. Open **Sensitive operation** at A; password-only assurance is denied.
2. Select **Step up authentication**, then **Verify password and TOTP**.
3. Enter the same account's password and current six-digit code at the IDP.
4. A rotates its session cookie. Open **Sensitive operation** and approve it.
5. B's established session retains its original assurance. Stale sensitive access requires another actual password/code event.

The SP requests the stronger `acr_values`, `prompt=login`, and `max_age=0`, retains
its expected subject/minimum/time, and verifies actual returned event/evidence.
Refresh never advances that authentication time. Sensitive approval repeats
online authority and locally rechecks recency/lifetime before committing immutable
encrypted operation evidence and its one-use intent.

Accepted OTP steps have a durable high-water mark and immutable subject/event
receipts; same-step reuse is rejected across processes/restart. Default drift is
one 30-second step. Code expiry or failed commit cannot consume a factor or rotate
authentication. Invalid credentials/code return a fresh bounded continuation;
its original deadline and attempt count are preserved.

Validated defaults: `FID_AUTHENTICATION_WINDOW_SECONDS=60`,
`FID_AUTHENTICATION_ACCOUNT_ATTEMPTS=5`,
`FID_AUTHENTICATION_BROWSER_ATTEMPTS=10`,
`FID_AUTHENTICATION_SOURCE_ATTEMPTS=30`, `FID_MFA_FORM_MAX_ATTEMPTS=5`, and
`FID_SENSITIVE_MAX_AGE_SECONDS=120`. Budgets are reserved before password work,
persist across new forms/browsers/restart, and return 429 with `Retry-After` when
exhausted. Source identity uses the actual peer, not forwarded headers.
See [Phase 9](phase9.md) for schema, transactions and exact verification.

## Inspect and stop

```bash
make status
make down
```

`down` preserves named data/secret volumes. Bootstrap and migration commands are
idempotent and do not rotate identities or reset database passwords on restart.

Root pages show the current authenticated user/application, with anonymous
server-side storage for guests. `/health/live`
checks process liveness; `/health/ready` checks authenticated database identity,
migration head, and persisted encryption-key binding, plus IDP seeded-user readiness.
`/architecture` exposes selected public component configuration.

Optional profile:

```bash
docker compose --profile onboarding up --build --wait sp-c
```

SP C initially has no IDP registration. Register it live through the operator
control plane or authenticated CLI before the IDP accepts its credentials.

## Operator control plane and onboarding

The operator account has independently generated credentials, stored in the
private IDP provisioning envelope. Explicit retrieval and public C metadata:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl operator-credentials
docker compose exec -T sp-c /app/.venv/bin/federationctl client-metadata
```

Open `https://idp.localhost:8443/admin`, enter the generated `operator` credential,
and register C using its public metadata. Its cookie is independent of the IDP
user cookie; no user/SP artifact provides administrative authority. After
registration, C completes SSO without restarting the IDP, A, or B.

Client pages update metadata, disable/enable, and replace credentials. Metadata
requires exact same-origin HTTPS destinations, distinct client hostnames, and
public-only RSA/RS256 keys. Trust changes increment the registration version,
invalidate old codes, and revoke affected grants. Replacement preserves disabled
state and requires owner deployment of the matching new private key.

CLI subcommands are `register`, `inspect`, `update`, `disable`, `enable`, and
`replace-credentials`. TLS verification is mandatory. Use an interactive password
prompt, owner-private `--password-file`, or explicit IDP `--provisioned` credentials;
passwords/tokens are not command arguments. See [Phase 4](phase4.md#cli-and-manual-onboarding)
for container commands and field/version contracts.

## Live issuer signing-key rotation

Sign in to `/admin` with the operator credential and open **Manage signing keys**.
The workflow requires `keys:read` and `keys:write`; ordinary user/SP credentials
confer no signing authority.

1. **Prepare signing key** generates a new RSA/RS256 key inside the IDP and stores
   its private material in an encrypted database envelope.
2. Open **Publish public JWKS** and then **Reload key state**. A validated public
   JWKS read records publication; activation is available only afterwards.
3. **Activate signing key** atomically moves the previous signer to draining and
   makes the prepared key active. The form binds the expected previous signer.
4. Keep the existing A/B pages open and select **Sign in** at each SP. Both accept
   new-key evidence through SSO with their existing processes and warmed caches.
5. **Retire signing key** is accepted only after the displayed verification
   deadline plus clock skew. All recorded signed purposes contribute to that
   deadline; stale deadline submissions are rejected.

The CLI exposes `keys-inspect`, `key-prepare`, `key-activate`, and `key-retire`
through the same verified-HTTPS operator session. `key-prepare` also fetches the
public JWKS before returning. [Phase 5 commands](phase5.md#cli-and-manual-rotation)
show the required key IDs and expected-deadline arguments.

SP cache settings:

| Environment setting | Default | Bounds |
| --- | --- | --- |
| `FID_JWKS_CACHE_TTL_SECONDS` | 300 seconds | 1–900 seconds |
| `FID_JWKS_REFRESH_COOLDOWN_SECONDS` | 10 seconds | 1–60 seconds |

Each SP pins its configured issuer/JWKS URI and RS256. Concurrent loads are
single-flight, and all unknown key IDs share one refresh budget. Failed/cancelled
refreshes spend that budget. Valid cached keys can be used until cache expiry;
expired cache entries require a successful reload. JWT claims and current
authoritative grant state are still checked independently.

Public JWKS is bounded to 16 keys and 32 KiB on the SP fetch path. Prepared,
active, and draining keys are public; retired/revoked keys are excluded. A new
preparation is rejected at the public-key limit until eligible keys are retired.
IDP restart restores the persisted active signer and retention state.

## Compromise containment and recovery

Use **Contain compromised client** at `/admin/clients/sp-a` for an SP incident.
This disables authentication, revokes that client's grant/family authority, and
records the captured key. B remains usable. **Enable client** rejects until the
captured credential has been replaced.

Read A's contained key ID and current registration version, then generate its
owner-side replacement inside A's private runtime:

```bash
docker compose exec -T sp-a /app/.venv/bin/federationctl client-key-replace --expected-key-id CAPTURED_KEY_ID --expected-version CURRENT_VERSION
```

Paste the public JSON output into **Replace client credentials JSON**. The
private key stays encrypted in A's `client-identity.enc`; the registry remains
disabled. Restart A and explicitly **Enable client**:

```bash
docker compose restart sp-a
```

Old keys/cookies and old pending codes remain rejected. **Sign in** obtains fresh
SSO evidence with the recovered credential. The IDP and B continue running.
Ordinary **Disable client** remains the reversible administrative availability
control; incident containment supplies the durable replacement barrier.

For a signer incident, **Prepare signing key**, **Publish public JWKS**, and
**Reload key state**. In the compromised key's section choose **Replacement
signing key**, then **Contain compromised signing key**. Replacement activation,
terminal revocation, affected grant/family denial, and audit commit together.
Cached signatures do not override authoritative revocation. Historical compromise
can use an already active distinct signer as replacement.

CLI operators use `contain-client --client-id ID --expected-version N` and
`key-contain --key-id ID --replacement-key-id ID --expected-active-key-id ID`.
[Phase 6](phase6.md#operator-workflows) gives complete authenticated commands,
field contracts, and exact verified acceptance evidence.

## Updates and secret recovery

Stop and restart using `make down` followed by `make up` to preserve named
volumes while applying initialization/migrations from the new image. Established
bundles are validated, not regenerated. Complete pre-binding bundles gain a
local check and a database binding during upgrade; existing encrypted data is
validated before first enrollment.

Each service owns `encryption.key`, `encryption.check`, and `bundle.complete`
alongside its identity/TLS/password material. The IDP also owns `seed-users.enc`
plus `seed-operator.enc` and `seed-totp.enc`. Existing v1/v2 bundles upgrade once
to v3 with preserved users/operator identities and newly generated encrypted
TOTP factors. A v3 bundle requires its established envelopes. Initialization
preserves current account, permission, registration, factor and replay state.
Rotated issuer private keys live in `signing_key_material`, encrypted with the
IDP wrapping key. Recovery pairs the persisted database with the matching IDP
secret volume; the original volume identity remains stable through rotation.
Recovered SP credentials live in an owner-private `client-identity.enc` envelope
with purpose `sp-client-identity`; service ID and public/private identity are
validated at startup. Bootstrap preserves it and the original identity/TLS/
wrapping-key bundle. Existing processes load the replacement on restart.
Back up the whole secret volume together with its corresponding PostgreSQL data.
Missing/inconsistent material causes explicit startup or bootstrap failure.
Restore the original matching bundle from backup; replacing a key and its local
check cannot decrypt or reenroll the existing database. Retain the database's
immutable `runtime_key_binding` rather than deleting it to bypass failure.

Defaults bound whole requests to 5 seconds, bodies to 16 KiB, and concurrency
to 64 in-flight requests. Keep-alive/graceful shutdown are also bounded. Settings
expose validated limits; password workers remain capacity-bounded after caller
cancellation. Structured logs exclude dependency messages/arguments and arbitrary
extra fields, recording fixed events and selected public metadata only.

## Verification without a Docker daemon

With Python 3.12+, uv, and PostgreSQL server binaries:

```bash
uv sync --frozen
uv run federationctl verify-architecture
uv run federation-phase0
uv run federationctl verify-login
```

This creates isolated temporary state, migrates separate databases, and starts
three independent application processes over verified TLS. It alters no host
trust store. `FID_POSTGRES_BIN` can select a PostgreSQL binary directory.
The verification harness allows up to 30 seconds for each process to become ready.
The Phase 7 browser scenario injects shared process time through the verification
entry point: an owner-private clock file is polled off-thread into memory, so
expiry tests advance time without waiting real token lifetimes.

The protocol verifier uses that topology with both SP identities, official
migrations, isolated database roles, and verified HTTPS/database TLS. Its
verification-only IDP process reads an owner-private encrypted fixture whose
authentication event is already persisted. Each SP saves and consumes a
browser-bound authorization transaction, exchanges a PKCE code, and matches
the signed ID token to authenticated authoritative issuance. Normal deployment
uses its credential-backed opaque-cookie principal provider. `verify-login`
exercises that actual browser flow, both callbacks, SSO, and replay rejection.
Its results contain no reusable credential or token values.

The local-process runner supplies an explicit loopback DNS transport for SP
back-channel calls because system Python resolvers may not resolve `*.localhost`.
It retains real HTTP/TLS, the original host/SNI, and certificate verification.
Deployment uses Compose's DNS aliases; no application trust check is disabled.

All tests, including real Chromium checks, require PostgreSQL server binaries,
`certutil` (`libnss3-tools` on Debian/Ubuntu), and the Playwright browser/system
dependencies:

```bash
uv run playwright install --with-deps chromium
uv run pytest tests/integration/test_lifecycle.py tests/e2e/test_lifecycle.py -q
```

Browser CA trust is installed only into a temporary NSS/home profile by the
test, with `ignore_https_errors=False`. CI installs these dependencies on an
isolated runner and also exercises Compose startup.

Select tests being created/changed and those affected by functionality. The fast
lifecycle checks share one role-owned TLS PostgreSQL deployment and advance an
injected clock. The separate browser scenario checks actual HTTPS processes.
`make check` is the normal lint/format/type gate; full regression and repeated
long probes require an explicit need. See [AGENTS.md](../AGENTS.md).

## Installed-package verification

The wheel contains migration histories and probe PostgreSQL configuration.
Build it with `uv build --wheel`. CI installs it into an isolated environment,
runs `federation-phase0` and `federationctl verify-login` outside the checkout,
and verifies the three-process TLS/role/migration and credential-backed SSO
boundaries. Installed-package checkpoint evidence is in [Phase 2](phase2.md);
current lifecycle evidence is in [Phase 3](phase3.md). This WSL shell uses actual
independent processes for local verification; container startup is a CI check.
Current live-signing, migration, and verified-HTTPS/browser evidence is in
[Phase 5](phase5.md).
Both operator containment and owner recovery are verified in [Phase 6](phase6.md).
Automatic renewal, re-authentication, and injected-time browser restart checks
are verified in [Phase 7](phase7.md).
Reliable global logout, offline-SP denial, dispatcher recovery, expired-token
reissue, and new-session preservation are verified in [Phase 8](phase8.md).
Actual password/TOTP proof, owner provisioning, replay restart, stale-sensitive
denial after refresh, and selected-SP assurance are verified in [Phase 9](phase9.md).

## Final selected-scope acceptance

[Phase 11](phase11.md) records 84 distinct selected passing cases, the combined
four-application browser scenario, the five race families, PostgreSQL/application
restart, consumed/expired/revoked history, and fresh isolated installed-wheel
startup/migration probes. [Scenario commands](scenarios.md) consolidate onboarding,
rotation, containment, renewal, step-up and delivery recovery.

CA export's Make recipe is quiet so redirection produces only certificate bytes.
Database socket refusal follows the same 503, session-preserving contract as wrapped
database failures; pool pre-ping avoids stale handles after infrastructure return.
The CA-output format test uses a command stand-in, while runtime TLS/certificate
checks use actual generated authority and trusted browsers. Local Docker is
unavailable in this WSL environment; the checkpoint records verified process
evidence and configured container CI separately.
