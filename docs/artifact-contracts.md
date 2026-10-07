# Artifact-validation contracts

## Current authorization-code profile

All protocol endpoints are configured HTTPS URLs. URI matching does not
normalize an incoming redirect or issuer into an acceptable identifier.
Repeated query/form parameters are rejected before conversion to a dictionary.

| Artifact | Authority and validation | Intended use |
| --- | --- | --- |
| Authorization code | IDP-generated opaque value; SHA-256 verifier; exact client/callback/nonce/S256 proof and canonical event/session binding; parent state checked at redemption; lifetime from issuance clamped to the parent; immutable identity and irreversible consumption | Authenticated token exchange by the owning SP |
| Client assertion | Registered public key selected by client identity; RS256 / `JWT` / matching `kid`; `iss == sub == client_id`; exact requested token or introspection endpoint audience; integer dates, bounded lifetime, durable unique `(client_id, jti)` | Authentication of that client protocol request; endpoint substitution is rejected |
| ID token | Trusted issuer JWKS, allowed algorithm and type, known `kid`; explicit issuer and single recipient audience; required subject, issuance/expiry/authentication times, nonce, session/evidence IDs, assurance/method claims; verified `at_hash` and `azp` when present | Authentication evidence for the owning RP's code flow |
| Refresh ID token | Same pinned crypto/issuer/recipient/time/at_hash profile; exact original subject/sid/auth_time/acr/amr; nonce optional and original-bound if present; exact new `credential_evidence` | Bound renewal evidence, not an independent login or fresh authentication event |
| Logout hint | Login-purpose RS256/JWT header, persisted nonrevoked public trust including routine retirement, exact issued digest/jti/recipient/subject/sid/dates; matching current IDP cookie and confirmation for active effects | Historical logout context only; expiry relaxation never applies to login or user/admin authentication |
| Logout token | RS256/logout+jwt, pinned issuer and single SP audience, strict iat/exp/jti/sid, logout event object, no nonce; authenticated exact current logout issuance and durable issuer/jti receipt | Session-specific back-channel termination; cannot become login evidence |
| Refresh token | High-entropy value, SHA-256 verifier at IDP and encrypted SP custody; authenticated owner, family/generation/predecessor, current parent/client/key, expiry, irreversible consumption | Single-use rotation; authenticated reuse contains only the owning family |
| Opaque access token | IDP-generated high-entropy value, stored as a one-way verifier; canonical grant/family and exact signed `at_hash` pair; current parent/client/signing state checked | Authenticated, owning-client introspection and subsequent SP authorization |
| Login form challenge | Hashed short-lived value and initiating browser digest; encrypted, previously validated continuation; exact POST Origin; atomic one-use consumption | Credential verification at the IDP, not a user identity or arbitrary return URL |
| TOTP factor/code | Subject-bound encrypted factor; PyOTP matching against bounded Clock drift; fresh locked high-water step; immutable subject/event consumption; real password snapshot and attempt budgets | Actual password/TOTP authentication; a matched counter alone is not assurance or a bearer credential |
| Step-up transaction | Cookie/state/nonce/S256 binding plus persisted minimum assurance, expected subject and requested time; exact returned/canonical event and freshness | Same-subject stronger SP session rotation |
| Sensitive approval intent | One-use cookie/purpose/grant challenge; fresh authority plus actual stronger/recent local event rechecked at commit | One committed immutable encrypted sensitive-operation record |
| IDP cookie | Random host-only opaque identifier; IDP-local hashed lookup and encrypted session/event references; active parent, enabled account, and verified password event | IDP browser principal only |
| SP cookie | Random host-only opaque identifier; owning SP database only; exact stored evidence and fresh recipient-bound grant state | That SP's authenticated browser session only |
| Lifecycle challenge | Hashed, one-use, browser/purpose-bound value with encrypted server-selected target and bounded expiry; same-origin POST; RP logout additionally seals/rechecks client/version/return/state | Local/global logout, current IDP session termination, or explicitly selected own grant revocation |
| Operator browser/API session | Separate Argon2id operator verification; hashed opaque token, sealed actor/credential epoch and channel; fresh enabled-account/permission and expiry checks | Explicit registry or signing-key read/write authority; browser/API channels cannot substitute for each other |
| Operator mutation intent | One-use operator-cookie/purpose/target-bound challenge; same-origin request and current write permission; transactional consumption | Approved registry/key lifecycle or scoped containment; no user/SP/JWT fallback |
| Fixture proof | Generated high-entropy credential, verifier stored only by the injected local harness provider | Supplies a labelled test authentication event; creates no password/MFA assurance claim |

The closed profile requires an `at_hash` even though it is optional in the general
OIDC code flow. It always emits that claim and verifies the returned token pair.

## Time model

Current defaults in `ProtocolPolicy`:

- Code lifetime: at most 60 seconds and never beyond the parent session, without added leeway.
- ID-token lifetime: 300 seconds; access lifetime: at most 300 seconds, clamped to its parents.
- Client assertion lifetime: at most 60 seconds.
- JWT clock skew allowance: 5 seconds, bounded by settings validation.
- Signing-key retention: latest recorded signed-artifact expiry plus skew; each actual logout token/reissue has its own 300-second default TTL.

The application rejects expiration at the exact end of the permitted window.
Numeric dates have strict integer types; booleans are not valid timestamps.
Authentication time comes from the verified event, independently of token/code
issuance time. SSO preserves that history. `prompt=login`, `max_age=0`, and unmet
age demands require actual password verification through the persisted browser
continuation; `prompt=none` returns `login_required` when proof is unavailable.
Standalone non-interactive protocol calls cannot manufacture freshness.

Login forms and SP authorization transactions last at most 300 seconds by
default, bounded by their initiating browser sessions. Authentication cookies
are bounded by their corresponding session/parent expiry.

## Publication and replay

- A code is published only after its verifier commits.
- Code consumption, protocol linkage, canonical grant/evidence/credentials, and signing retention commit atomically before token response publication.
- A valid client assertion is one-use even if subsequent grant validation fails.
- A forged/invalid assertion cannot reserve a legitimate assertion's replay ID.
- Later policy denial rolls back an issuance savepoint; unexpected failures roll back the entire transaction.
- Replay and code state are database-backed; reconstructing an application/pool preserves them.
- IDP session/event/browser rotation commits atomically after credential verification and transactional credential rechecking.
- A login form or callback transaction is one-use even when later verification/exchange fails; a new attempt obtains fresh state.
- A consumed authorization code requires owning-client authentication, exact original callback, and valid S256 proof before revoking its derived grant/family. Wrong-client or wrong-proof attempts cannot contain someone else's authorization.
- Local/IDP lifecycle intent consumption and revocation commit together; commit failure preserves the original cookie/session and retryable intent. Remote SP revocation commits its one-use intent before network work and needs a new intent after a dependency outage.
- Local logout/rotation invalidates the initiating browser binding and its pending callbacks, preventing a paused token exchange from resurrecting that session.
- Codes bind the live registration version. Metadata/state/credential changes invalidate older pending approvals and revoke affected grants/families without reviving historical trust.
- Operator metadata/audit/key-history changes share the protocol security gate and commit atomically; stale expected versions reject concurrent lost updates.
- Prepared signing keys require a validated public JWKS read before operator activation; expected active-key identity prevents stale swaps.
- Active signer selection, actual ID-token evidence, signed-artifact retention, and code/grant issuance share one gated transaction.
- Signing material, artifact history, and operator signing audit are immutable; publication and retention cannot be reversed.
- Signer containment activates a distinct published replacement when needed, revokes affected trust/grants/families, and records replacement-aware audit in one transaction.
- Client containment records the captured key and prevents re-enable until new credentials replace it; recovery never clears historical grant/family revocation.
- Refresh predecessor consumption, successor/access verifiers, actual signed evidence, and retention commit together; authenticated reuse contains the family before returning an error.
- SP renewal claims commit before network work; exact attempt/generation installation rechecks local expiry/revocation. Unknown outcomes never resend the old credential.
- Re-authentication requests preserve origin/cookie/purpose/state/nonce/S256 binding and validate returned subject/freshness before rotating the local identifier.
- Global confirmation joins current-cookie/metadata rechecking, one-use intent, revocation, browser deletion, and recipient delivery intents in one transaction.
- Outbox signer/token/retention/lease commits before transmission; stale lease acknowledgements cannot overwrite recovered work. Expired/revoked signing evidence is reissued for the same original sid.
- SP termination, binding/pending-transaction invalidation, issuer/sid history, and replay receipts commit together. Callback establishment shares that session lock; refresh finish rechecks local revocation.

## Signing trust and JWKS cache

`GET /jwks.json` exposes only prepared/active/draining RSA/RS256 public keys.
Retired/revoked keys are excluded. Preparation is bounded to 16 simultaneously
published-state keys; SP streaming fetches also enforce a 32 KiB body limit.

SP caches are scoped to the configured issuer, exact JWKS endpoint, and RS256.
Cold/expiry and unknown-kid loads are single-flight. All unknown IDs share one
cooldown, including failure/cancellation; unknown traffic cannot grow a per-kid
map. Expired trust requires successful reload. An unverified strict header is a
routing hint only and cannot supply a key URL, embedded key, or another namespace.
Full login-purpose verification and current canonical issuance matching follow.

Routine rotation retains old public keys through every recorded signed purpose's
expiry plus skew. Retirement preserves historical grant evidence rather than
revoking it. Actual logout JWTs and reissues join the generic signed-purpose ledger
in Phase 8, extending retention before delivery.

## Current revocation contract

`/introspect` and `/revoke` authenticate the registered client with distinct exact
endpoint audiences. Introspection returns no authority to a different recipient.
Revocation returns the same successful empty HTTP 200 for unknown, wrong-owner,
expired, or already revoked token values; only the owning client's grant/family
can change. A type hint is an optimization, never an ownership/purpose grant.
Session cookies, ID tokens, and operator credentials are not accepted as opaque
revocable access/refresh credentials.

## Compromise enforcement

Removing a public key from JWKS is not a revocation decision. Cached signatures
may remain cryptographically valid, but fresh recipient-bound authority denies
revoked key/client lineage. Login additionally requires exact committed jti,
digest, subject, session/event, recipient, signer, and issuance facts. A vetted
forged JWT with no matching evidence cannot establish an SP session.

SP owner credentials are service-bound encrypted material, never operator
authority. Replacement metadata is public-only; private files are loaded after
owner deployment/restart. Captured keys, cookies, and registration-version-bound
pending codes cannot resume authority after explicit recovery. Model and wire
refresh enforce irreversible containment, including a key used for later signed
renewal evidence. A revoked/expired local session cannot install a raced renewal.

## Current renewal and re-authentication contract

Refresh preserves immutable original authentication and lifetime ceilings. The
returned JWT is separately validated against exact authenticated renewal evidence;
its new iat/jti/signer do not advance auth_time or manufacture assurance. The
login validator continues to require nonce, while a refresh nonce, if present,
must equal the original flow value.

SPs retain ready/pending/blocked renewal state in the database. A lost/cancelled
response, failed installation, or abandoned claim blocks retry of the old value
and requires fresh code authorization. Same-subject `prompt=login`/`max_age`
requests require genuine credential proof when stale, then renew the selected
SP cookie without changing another established SP's event.

## Current logout contract

RP initiation supports GET and URL-encoded POST, followed by an independent
same-origin one-use IDP confirmation. A supplied hint must identify exact committed
ID-token issuance and the current browser's subject/sid. An active hinted session
without that cookie is rejected. Recent inactive hints can acknowledge completed
logout; they do not clear or authenticate a new different browser session.
Return paths match current registration literally and retain a checked metadata
version through confirmation; bounded state is URL-encoded only after approval.

`/backchannel-logout` accepts only its logout profile. Unknown form extensions are
ignored, duplicate relevant parameters rejected, and nonce is forbidden inside
the token even when null. After cryptographic verification, the owning SP
authenticates with a separate `/logout/introspect` assertion audience. An active
result requires exact persisted logout-purpose token/retention and revoked parent,
with unrevoked signing trust. Cached signatures and forged unissued JWTs cannot
substitute for that check. Outage returns 503 without consuming local replay state.

Valid exact retries receive 200 with no repeated mutation. Invalid tokens receive
400. Termination matches issuer/sid, checks optional subject, expires bindings and
pending work, and records immutable replay/termination. Later different sids stay
independent. Authoritative protected access is denied from global commit onward,
including before an unavailable SP receives its recoverable notification.

## Purpose boundaries

Step-up accepts one supported minimum `acr_values`. Required proof is fulfilled
through actual password and fresh PyOTP verification. Counter history, immutable
stronger event and IDP binding rotate in one transaction, with expiry rechecking
and durable replay. RP state retains original minimum/subject/time; a downgraded
request or inconsistent method/assurance claim cannot replace those requirements.
Sensitive access independently enforces `pwd`+`otp` and current authentication age,
including after online authorization. Refresh keeps the original event/time.

Authentication source/browser/account windows are reserved before password work.
MFA continuation attempts and original deadlines persist across rejected forms.
429/Retry-After exhaustion creates no stronger event and consumes no OTP step.

- Credential-backed IDP/SP cookies are opaque, host-scoped identifiers backed by separate stores; neither cookie kind is interchangeable with JWT artifacts.
- SP transactions enforce initiating-browser binding and atomic one-time consumption through the actual browser callbacks, including after restart.
- Refresh preserves subject, original `auth_time`, and assurance. It is not fresh user authentication.
- Logout tokens use their own `logout+jwt`/event profile, an SP-specific audience, expiry, and replay policy; nonce is prohibited.
- Logout hints may identify a confirmed logout context. They never create an IDP user/admin session.
- Administrator authentication and authorization remain separate from user and SP artifacts.
- Central revocation is checked for later protected requests; already-authorized in-flight work cannot be recalled.

Cross-SP integrity applies to an artifact's purpose and actor. Codes necessarily
return to the IDP for redemption, and introspection/logout flows likewise
have documented return paths. Those paths confer no unrelated login or
administrative authority.

## Implemented shared-model enforcement

The [shared security model](shared-security-model.md) gives artifact purposes
explicit allowed uses and recipient bindings. A snapshot or valid ID-token
signature is insufficient to establish an SP session: its evidence must match
fresh, authenticated authoritative issuance. Access checks also enforce current
session/grant/family state, recipient enablement, and compromised signing trust.
An active introspection response requires full bound lineage and a lifetime
within its parents; expiry is checked after the dependency response arrives.

Refresh-family operations preserve the immutable authentication event and
absolute lifetime ceilings. Ownership is checked before replay detection; reuse
containment commits before returning a denial. Routine key retirement leaves
historical session evidence valid; key revocation overrides cached verification
keys. These operations and policies are available at service boundaries; the
corresponding protocol/browser integrations follow their owning phases.

Phase 0 now connects these rules to code exchange and authenticated
introspection. RP exchange yields `VerifiedLogin` only after the exact vetted
login evidence matches fresh canonical issuance. Historical unbound code
records are retained during schema upgrade and cannot become authentication.
