# Confirmed extension points

Inspected against the installed Authlib 1.8.0 implementation and the relevant
final specifications. Current metadata advertises code/rotating-refresh profiles
and authenticated introspection/revocation plus RP-Initiated and Back-Channel
Logout and the password/password-TOTP assurance profile.

## Refresh — Phase 7

`authlib.oauth2.rfc6749.grants.RefreshTokenGrant` supplies client authentication,
token ownership checking, scope restriction, and token-response creation.
Its application hooks include `authenticate_refresh_token`, `authenticate_user`,
and `revoke_old_credential`.

Its `INCLUDE_NEW_REFRESH_TOKEN` default is false: rotation must be explicitly
enabled. Application persistence must retain family/predecessor state, atomically
consume a credential, and detect authenticated reuse. Ownership is checked
before any reuse-triggered revocation. The transaction layer must commit those
intentional security effects even when the request returns a protocol error.

OIDC refresh responses may include an ID token. The [refresh rules](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)
preserve issuer, subject, audience, and original authentication time. New `iat`
does not provide fresh user authentication. A refresh ID token normally omits
nonce; if present, nonce must equal the original value. The refresh validation
context therefore differs from the login context's required nonce.

Phase 7 implements these hooks in `RotatingRefreshGrant` and
`OpenIdRefreshProfile`. Library-generated credentials and signed ID tokens join
`refresh_candidate_in()` / `commit_refresh_in()` with owner-first reuse handling,
hashed ancestry, deferred complete evidence, and all-purpose retention. Authlib's
async client refreshes over pinned verified HTTPS; SP database claims and blocked
ambiguity states prevent multiple sends of a possibly consumed credential.

## Re-authentication and step-up — Phases 7 and 9

Authlib's OIDC extensions expose consent-validation hooks and prompt handling;
code credentials provide `get_auth_time`, `get_acr`, and `get_amr`.

Phase 0 binds the immutable persisted authentication event and rejects unmet
`prompt=login`/`max_age` requirements. Phase 2's persisted browser continuation
fulfills them only after actual password verification and a genuinely new event
for the same subject, with an unchanged parent absolute lifetime. Phase 7 now
supplies purpose-bound SP controls, persisted freshness policy, and validated
same-subject cookie renewal. Step-up uses that event's real methods,
assurance, and time; refresh cannot upgrade these values. RPs enforce the
returned context, not merely the requested `acr_values`.

Phase 9 connects `acr_values` minimum policy to the consent-validation hook and
uses PyOTP for actual matching. Locked factor counters, event-bound consumption,
credential rechecking and browser rotation commit together. Persistent budgets
precede Argon2id. RP transactions retain minimum/subject/time, enforce returned
facts, and rotate only the selected SP. Sensitive approval applies independent
assurance/age policy at access and local commit; renewal cannot refresh proof.

## RP-initiated logout — Phase 8

`authlib.oidc.rpinitiated.EndSessionEndpoint` supports a two-step validation and
response path with application `get_server_jwks` and `end_session` hooks.
It permits expired hints as specified for current/recent sessions.

The application must add exact issuer/purpose policy, correlate the hint with
the current browser/session, protect logout intent, and honor the specification's
confirmation requirements. A cryptographically valid hint is not a user-login
credential. Historical hint verification and fresh-login token acceptance have
different lifetime rules.

Phase 8 supplies the two-stage interactive contract through typed async
`RpInitiatedLogout`, with joserfc cryptography, current opaque-cookie matching,
exact canonical issued hints, persisted one-use confirmation, and versioned
literal return validation. Historical verification uses persisted public identity
for routine-retired keys. Active-session effects require the matching browser;
an ID token alone cannot create that identity or end someone else's session.

## Back-channel logout — Phase 8

Use the [final Back-Channel Logout profile](https://openid.net/specs/openid-connect-backchannel-1_0.html)
with vetted JOSE signing/verification. Application policy supplies session
matching, replay state, and durable outbox delivery.

Require issuer, audience, `iat`, `exp`, `jti`, the logout event object, and a
session identifier in our deployment profile. Require `typ=logout+jwt` and
prohibit nonce. Use the issuer's signing key model and retain verification keys
through all relevant artifact lifetimes. Revocation commits before delivery;
recoverable delivery failures receive bounded retries with fresh valid tokens.
Phase 5 supplies `SigningKeyService.active_in(work)` and
`IdpSecurityModel.record_signed_artifact_in()` with a separate logout-token
purpose/TTL. Phase 8 creation selects/signs/records and seals a leased delivery
in the same gated transaction. The worker sends only after commit, outside locks.
Actual logout retention delays retirement; expired/revoked evidence receives a
fresh token for the original sid. Lease fencing, capped backoff, and private owner
recovery preserve failed/pending work across restart.

SP validation adds a separate authenticated exact logout-purpose check so cached
compromised signatures and unissued messages cannot terminate sessions. Atomic
issuer/sid termination and issuer/jti digest receipts coordinate with callback
establishment and refresh completion. Exact valid retries acknowledge committed
effects; different new sids remain independent.

## Key/session/client control — Phases 3 through 6

The request-local adapter receives its signer, clock, and registration
repository. Phase 0 now checks persisted active signing trust and links its
consumed code/token ID to canonical grants and evidence in one gated async
transaction. Authenticated introspection enforces current client, session,
grant/family, and key state; RP exchange requires matching authoritative evidence.

The async lifecycle service exposes `issue_grant_in()` / `check_access_in()`
for caller-owned units of work. The rotating refresh adapter and logout
adapters must join that transaction and preserve the security-gate-before-
credential-lock order. The application invokes Authlib's public request
validation and response-creation phases explicitly, allowing an issuance
savepoint while keeping client replay reservations outside it. Phase 4's operator authority,
live registration versions, metadata/audit/key history, and scoped grant effects
already share that caller-owned gate and explicit authorization boundary.

Phase 5 now selects actual active private material inside that issuance savepoint,
records generic signed-artifact retention with evidence, and publishes persisted
prepared/active/draining public trust. Operator prepare/activate/retire use
explicit key capabilities and the same gate. SP public-key caches remain pinned
and bounded, with single-flight refresh on a strict untrusted kid hint; this never
substitutes for full claims validation or authoritative grant checks.

Phase 6 connects `disable_client_in()` / `revoke_signer_in()` to operator-owned
transactions. Signer replacement/terminal revocation/audit and client capture/
scoped revocation share the issuance gate. Owner-side `client-key-replace`
provides encrypted private deployment separate from public registry authority.
The refresh implementation and logout adapters retain these key/client checks
and irreversible revocation instead of treating new tokens as restored trust.

Phase 3 now uses Authlib's `RevocationEndpoint` client authentication and the
same endpoint-bound assertion policy for `/revoke`. Its application transaction
checks ownership and revokes the entire bound grant/family, independent of hint
selection or credential consumption/expiry. `end_session_in()` and the revoke
operations share caller-owned units of work.

Consumed-code replay is detected after Authlib validates original redirect and
S256 proof, then persisted containment precedes the OAuth error response. The
retained proof is not redeemable a second time. Local/IDP browser termination
controls use dedicated purpose-bound CSRF intents. Phase 8 adds RP confirmation,
current logout-purpose authority, and durable signed delivery to those boundaries.
