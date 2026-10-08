# Threat model — credential-backed federation and shared security model

## Data flow and boundaries

```mermaid
sequenceDiagram
    participant Browser
    participant RP as SP application / async RP client
    participant API as HTTPS FastAPI IDP
    participant Protocol as Request-local Authlib adapter
    participant DB as Role-owned PostgreSQL over verified TLS
    Browser->>RP: Login initiation; persist browser-bound state / nonce / verifier
    Browser->>API: Code request / S256 challenge
    API->>Protocol: Validate exact callback and complete request profile
    API->>DB: Persist browser-bound one-use credential continuation
    Browser->>API: Same-origin credential POST with CSRF challenge
    API->>DB: Atomically consume browser-bound form
    API->>API: Bounded off-thread Argon2id verification
    API->>DB: Recheck credential; commit session/event/browser rotation
    API->>Protocol: Validated input and trusted principal
    Protocol->>DB: Gate; registration/event/session validation; save bound hashed code
    DB-->>API: Commit
    API-->>Browser: Code and state at registered callback
    Browser->>RP: Initiating cookie + code/state; atomically consume transaction
    RP->>API: Check pinned issuer metadata; load/cache public JWKS over verified TLS
    RP->>API: Code + verifier + private_key_jwt assertion
    API->>Protocol: Request-local transaction
    Protocol->>DB: Gate; reserve client jti; lock code; validate callback/PKCE
    API->>DB: Same session/savepoint: active signer, code consumption, grant/evidence, signed retention
    DB-->>API: Commit complete canonical issuance
    API-->>RP: ID/access tokens
    RP->>API: Unknown kid only: bounded single-flight refresh from pinned JWKS
    RP->>RP: Validate signature, purpose, issuer, audience, nonce, time and at_hash
    RP->>API: Fresh introspection-endpoint private_key_jwt + opaque access credential
    API->>DB: Gate; reserve client jti; current recipient-scoped lineage check
    API-->>RP: Current authoritative evidence after commit
    RP->>RP: Exact signed evidence/canonical lineage match
    RP->>RP: Commit encrypted local session evidence and access custody
    RP-->>Browser: Independent rotated opaque SP cookie
```

Application routes derive IDP identity only from its own opaque cookie bound to
a committed password event and active account/session. Browser forms carry no
identity or assurance authority. SPs derive identity only from their own
browser-bound code flow and exact authoritative issuance. The standalone
protocol factory defaults to denial; the Phase 0 verification-only provider
still uses an explicitly labelled persisted fixture event.

## Adversaries and evidence

| Adversary | Goal | Controls/evidence |
| --- | --- | --- |
| Unauthenticated web caller | Obtain a code for an arbitrary subject; manipulate callbacks | Credential-backed opaque-cookie principal boundary; literal callback registration before displaying a form; error-path redirect tests |
| Registered malicious client | Redeem another SP's code or repurpose its artifacts | Client-key pinning, code owner/callback binding, exact audience checks, independent token-purpose validators |
| Replay attacker | Redeem a code twice or reuse a client assertion | PostgreSQL row lock, consumed tombstone, unique client/jti reservation, concurrent and reconstruction tests |
| Callback attacker | Inject a code/state from another transaction or exploit duplicated fields | Pre-network state validation, duplicate rejection, callback origin/path checks, nonce validation |
| Login-CSRF attacker or malicious sibling SP | Substitute an account or transplant login forms / browser state | Exact Origin, browser-bound one-use forms/transactions, subject continuity, PKCE, nonce, and actual HTTP/Chromium negatives |
| Cookie/JWT substitution attacker | Authenticate another service or repurpose an ID token as an IDP/admin credential | Host-only opaque cookies, independent databases, required recipient-specific evidence, no bearer-JWT principal path |
| Network attacker | Impersonate the IDP or serve substituted keys | TLS hostname/certificate validation; pinned issuer/endpoints; no token-supplied key retrieval; actual untrusted-CA rejection test |
| Read-only database disclosure | Recover reusable codes/access tokens | Stored high-entropy verifiers rather than plaintext artifacts; client registrations contain public keys |
| Failure/concurrency adversary | Induce duplicate issuance, partial writes, or premature success | Transaction/uniqueness constraints, pause-at-commit test, injected signing/commit failures |
| Logout-CSRF/hint attacker | End another browser's federation session or inject a return destination | Current IDP cookie/subject/sid matching, exact issued hints, separate one-use confirmations, literal live/versioned redirect allowlist |
| Forged/cross-purpose notification sender | Terminate local sessions using an ID token or cached compromised key | Explicit logout+jwt/event/no-nonce profile, exact recipient/time, authenticated current logout-purpose issuance |
| Notification replay/recovery attacker | End a fresh different session using an old or retried message | Immutable issuer/sid termination, issuer/jti digest receipts, atomic binding invalidation and database session locks |

Protocol unit/integration databases use an owner-private Unix socket. The
deployed protocol proof uses actual TCP PostgreSQL with verified TLS and
restricted per-service roles. Persistent encrypted secret/key custody is
installed by architecture setup and exercised in restart tests.

## Trust assumptions and accepted residual risk

- Host control, application code execution, and writable IDP database compromise
  are outside Phase 0's containment guarantees. Signing/client keys in process
  memory are trusted assets. Model containment, authoritative enforcement, and
  operator/owner recovery are implemented for leaked credentials/signing trust.
- Seeded-user password verification, browser SSO, actual TOTP step-up, and
  authentication attempt/rate controls are implemented. Expanded user-directory
  behavior remains outside the seeded-account scope.
  Session termination and live operator registration/rotation are implemented.
- Standalone valid signatures do not provide revocation. RP exchange now
  requires fresh canonical grant state, including compromised-key policy;
   operator containment and lifecycle controls now use that same authority.
- Replay/code tombstones have expiry data but no production retention worker yet.
  The disposable probe database is removed after the run.
- The integrated probe uses isolated temporary encrypted key bundles matching
  deployment custody. Operational wrapping-key recovery remains an explicit
  deployment responsibility.

These boundaries are explicit so the protocol feasibility result is not
mistaken for completion of the full federated service system.

## Shared-model and integrated protocol threats

Architecture setup supplies persistent encrypted secrets, per-service roles/
databases, and real-browser cookie isolation. Section 2's
[model](shared-security-model.md) adds the following service-level defenses:

| Threat | Model control and verification |
| --- | --- |
| Valid signature but forged/unissued login facts | SP session creation compares exact verified evidence against authenticated committed issuance; missing/altered records create no local session |
| Cross-SP or cross-purpose substitution | Purpose/use policy, recipient-specific grants, composite lineage FKs, separate SP databases, and exact issuer/subject/evidence binding |
| Leaked refresh value used by another client to cause denial of service | Authenticate/bind the owner before observing reuse or changing family state; wrong-client replay leaves the rightful family usable |
| Refresh reuse or refresh racing revocation | Serialized database transitions, one generation per family, irreversible consumption, commit-before-replay-rejection; concurrency tests ensure no resurrected authority |
| Fake freshness or assurance from renewal | Immutable events, verified-method-derived assurance, fixed parent lifetimes, and per-SP recency checks |
| Compromised cached signing key or client identity | Scoped persisted revocation/disable state consulted by each authoritative check; unaffected clients/key lineage remain usable |
| Partial logout or failed notification storage | Session/grant/family revocation and encrypted unique delivery intents commit together; injected encryption/commit failures roll everything back |
| Dependency outage mistaken for a valid session or destructive logout | Fail-closed checks preserve persisted state for recovery; local locks are released before dependency calls |
| Application mutation of historical facts or lifetimes | PostgreSQL immutable-fact/lifecycle/trust/consumption guards plus model validation; direct SQL negative tests |

Credential verification, browser authentication/CSRF handling, live signing,
refresh coordination, and back-channel delivery/validation use these boundaries.
Internal model methods accept trusted application inputs; HTTP callers must
not be allowed to supply authentication events or operator authority directly.

Phase 0 now puts canonical parent/event validation, code redemption, current
signing trust, and normalized issuance under the same database gate. An
issuance savepoint prevents a policy denial from leaving partial grants or
consumption while preserving a verified assertion's replay reservation. A
deferred completeness constraint also rejects accidental missing linkage at
commit. Upgrade tests show historical unbound codes remain non-authoritative.

The integrated verifier uses three separate processes, actual TLS-authenticated
roles/databases, and each SP's persisted browser-bound transaction. The fixture
event remains distinct from real password/MFA assurance. Normal deployment
uses an opaque-cookie principal backed by actual Argon2id password verification.

Phase 2 adds actual password/SSO network and Chromium flows, origin and one-use
form validation, callback/cookie transplantation, nonce/PKCE changes, pending
transaction restart, concurrent consumption, and failed/paused browser-binding
commits. Final binding rechecks the password snapshot under a row lock so a
credential change after verification cannot create an authenticated session.
Temporary IDP outages block protected SP pages without discarding their valid
persisted cookies/evidence.

Phase 3 makes lifecycle intent explicit: a user supplies only a one-use challenge;
its encrypted target/purpose and the current persisted browser principal select
the effect. IDP users can revoke only their own session's grants. SPs authenticate
to a separate revocation audience and can change only their own grants/families.
Opaque cookies, ID tokens, and posted session/grant identities confer no other
revocation or operator authority.

Local logout/rotation invalidates browser bindings and pending transactions under
the same lock order as establishment. A callback paused after exchange cannot
revive a logged-out initiator. Retained consumed-code proof is validated against
the authenticated owning client, original callback, and S256 verifier before
containment; a stolen code alone cannot revoke someone else's grant.

Actual database stop/start and injected IDP outages verify fail-closed protected
access with persisted-state recovery. Local logout remains available independently
of IDP availability. Phase 8 notifications remain downstream of authoritative
revocation, with durable delivery/token integration and recoverable failure.

Phase 4 separates operator credentials and permissions from federation actors.
Opaque operator browser/API sessions carry distinct purpose/channel/credential
epochs; current account and registry permission are checked on each action. A
user password/cookie, SP key/assertion/cookie, ID token, or opaque access token
cannot register a client or mutate administrative state. Browser mutations also
require same-origin purpose/target/cookie-bound one-use intent.

Strict metadata rejects private/mixed/weak/wrong-type keys, unsupported algorithms
and capabilities, ambiguous HTTP destinations, shared origins, and issuer/client
key reuse. The registry is live and database-backed. Registration versions bind
code approvals and prevent stale metadata or credentials from re-establishing
trust after replacement. Audit/history/containment share the issuance transaction;
concurrent operator edits reject stale versions and commit failure publishes no
partial registration. The operator remains a trusted administrator for approved
client destinations and explicit signing lifecycle capabilities.

Phase 5 adds encrypted, immutable issuer private custody and restores persisted
active trust after restart. Prepared keys must be publicly serialized before
operator activation. Active selection, signed evidence, all-purpose expiry, and
issuance share one transaction; concurrent rotation and commit failures cannot
publish mismatched or partial trust. Retirement waits through recorded expiry
plus skew without revoking established historical evidence.

Unknown-kid traffic receives a shared issuer-scoped refresh budget and single-flight
loading rather than unbounded HTTP or per-kid state. Response size/key count are
bounded; strict headers reject embedded/token-supplied key locations. Failed or
cancelled attempts spend the budget, and expired caches require reload. This
can defer genuine new-key retries during a spent cooldown; signature and exact
authoritative issuance remain mandatory throughout. Compromise-recovery operator
controls are implemented in Phase 6; revoked-key authority continues to override
cached public keys.

Phase 6 makes replacement/revocation one gated signer decision and scopes client
containment to the affected recipient. A durable captured-key marker and database
guard prevent re-enable with leaked credentials or policy-reset bypass. Historical
credential reuse is rejected, and new credentials plus explicit enable cannot
revive revoked grants. Direct SQL, commit-failure, and issuance/refresh race tests
challenge these boundaries.

Owner key replacement uses a private no-follow lock, stale-kid rejection, and an
atomic encrypted envelope. Startup rejects corruption, cross-service binding,
public permissions, symlinks, and mismatched private/public material. The operator
gets public metadata only. The browser proof uses actual owner CLI output and
real SP/IDP restarts; captured credentials/cookies remain denied, while unrelated
client/key lineage retains authority.

Phase 7 makes refresh a single-use, owner-authenticated, signed-evidence-backed
rotation. Wrong-client attempts cannot trigger family containment. Reuse commits
irreversible denial; issuance, signer selection, ancestry, and exact credentials
commit together. New signed evidence is added without rewriting original subject,
sid/event, authentication time, or assurance. A renewal signer's compromise also
contains related grants, even when the root key differs.

SPs commit one attempt before releasing local locks for HTTPS and recheck its
generation/current session before installation. Concurrent workers share that
attempt. Loss, cancellation, failed install, and abandoned lease cannot resend
the old token; fresh authorization is explicit recovery. Protected access fails
closed and absolute/idle/parent ceilings remain enforced.

Re-authentication has a separate cookie/purpose/grant-bound intention, persisted
prompt/max_age/time, and state/nonce/PKCE. Genuine credential verification and
same-subject binding precede a new local identifier. Another SP's existing
authentication does not become fresh. The browser test uses actual TLS and an
owner-private verification Clock; production serving retains its ordinary boundary.

Phase 8 adds the confirmed RP browser path and signed downstream messages.
Historical hints verify exact issued context with nonrevoked public trust,
including routine retirement, but never create IDP user/admin identity. Active
effects require the matching current cookie. Return paths and registration
versions are rechecked at confirmation; no error redirects to an unapproved RP.

Parent/grant/family revocation and encrypted recipient intents commit together.
Claimed signing/retention/lease state commits before network work. Crashes and
lost acknowledgements recover through leases and exact replay receipts, while
stale workers cannot overwrite newer acknowledgements. Expired/revoked signing
evidence is replaced under current trust for the same original sid. Bounded
retry and private owner recovery preserve failures without restoring authority.

Recipient SPs validate explicit purpose/time/event/nonce policy, then authenticate
to a distinct exact logout-introspection audience. Only exact committed logout
issuance with current signing trust is accepted; a forged signed token or cached
revoked key cannot create a termination record. Temporary dependency failure
preserves local replay state and returns recoverable unavailability.

Local revocation, browser expiry, pending callback/intent invalidation, and
issuer/sid plus issuer/jti history share one transaction. Establishment uses the
same database session lock and termination check; refresh completion rechecks
local state. A notification before callback installation cannot be bypassed,
and an old sid cannot end another browser's or a fresh different session. A
single verified-HTTPS/Chromium deployment exercises both directions of TLS,
offline B, dispatcher restart, expiry/reissue, and idempotent new-session-safe retry.

Online enforcement intentionally depends on IDP/database availability. The
singleton database gate trades throughput for auditable transition ordering.
Already-authorized in-flight work cannot be recalled. Writable database/host
compromise remains outside these controls; retained security history has no
production retention worker yet. Read-only disclosure reveals identity/trust
metadata and credential verifiers, but not reusable credential plaintext or
private keys protected by separate secret custody.

Phase 9 derives stronger events from a rechecked password snapshot plus actual
PyOTP proof. Subject-bound encrypted factors and high-water/immutable accepted-step
history deny replay, including concurrent use and restart. Consumption, event,
and binding rotate together; expiry or failed commit cannot publish partial proof.
Fixed continuation deadlines and durable source/browser/account budgets bound
guessing and Argon2id work across forms and workers. The source is the real peer;
no forwarded header resets its budget. Rate exhaustion can temporarily limit
legitimate repeated authentication and preserves otherwise-valid sessions.

Step-up transactions retain minimum/subject/time, and returned/canonical
methods/assurance/freshness must meet them. An altered request cannot manufacture
stronger authority. Sensitive approval repeats grant authorization and locally
rechecks lifetime/recency before committing encrypted immutable evidence. Refresh
does not make old MFA fresh; another established SP's event remains independent.
TOTP remains a shared, phishing-sensitive factor; the application does not claim
phishing-resistant authentication. Explicit owner URI retrieval exposes only the
selected enrolled secret for provisioning, with regular pages/logs kept private.

Selected real-database and Chromium/TLS checks include password-only denial,
invalid/replayed/concurrent codes, subject substitution, persistent budgets,
rollback, proof-versus-logout, expiry and recency at commit, owner provisioning,
restarted replay and stale assurance after refresh. [Phase 9](phase9.md) records
the exact targeted checkpoint.

## Phase 10 pipeline-assurance gap

Phase 10's optional real-finding CI demonstration and separate hostile-flow
evidence expansion are intentionally skipped. The decision prioritizes the
implemented federation trust/lifecycle properties and their demonstrated runtime
behavior within the take-home's bounded scope. [ADR 0005](decisions/0005-phase10-scope-cut.md)
documents the boundary and reasoning.

The existing workflow invokes the locked-dependency scanner with `pipefail`, so
nonzero failures are configured to fail the audit step. It has no deliberately
vulnerable advisory negative control demonstrating finding identity/reporting and
end-to-end failure propagation, nor Phase 10's dedicated machine-readable evidence.
Scanner/input/configuration drift could therefore yield false confidence from a
green result. Passing application tests and historical clean audits do not close
that assurance gap or establish exhaustive attack coverage.

Specific existing defenses and negative tests remain evidence for their stated
feature scenarios. The shipped security model and mandatory code standards remain
acceptance requirements; the omitted claim is additional validated CI/evidence
assurance, not a substitute for those application controls.

Phase 11 challenges that selected application model in an integrated fresh
deployment: C onboarding, routine rotation, ambiguous refresh, real stronger
authentication, all-application and PostgreSQL restart, and global logout with an
offline recipient. Active authority recovers; expired/consumed/revoked state does
not. Real cold socket failure exposed an HTTP-500 availability gap, corrected to
the existing fail-closed 503 contract without discarding valid persisted sessions.
Pool pre-ping recovers stale infrastructure connections. Tested negative scopes
and the five race families remain the claimed coverage; full/exhaustive attacker
or production deployment certification is not implied. [Phase 11](phase11.md)
records observed results and the local Docker limitation. I knew that I could attain
the same results using simpler faster methods for this submission.
