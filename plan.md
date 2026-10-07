# Phased implementation plan and conscious scope decisions
This plan tracks all six possible features and the selected logout, refresh/re-authentication, and step-up extensions in take-home-requirements.md. It includes both signing-key and SP compromise containment paths. Phase 10's additional attack-defense evidence/security-CI expansion is intentionally skipped for the submission; the optional real-finding CI demonstration is not claimed complete. See [ADR 0005](docs/decisions/0005-phase10-scope-cut.md) for the boundary, rationale, existing controls, and accepted evidence gap.
Each implemented phase ends with a runnable, tested checkpoint. The UI provides controls for the chosen security features; Phase 11 acceptance/documentation and video planning concern that selected scope.
## Build order (revised)

1. Set up **Target architecture**: runnable service topology, configuration, libraries, storage, TLS, migrations, and capability boundaries.
2. Work through **Shared security model**: agree entity relationships, policy, and state transitions on that architecture.
3. Revisit **Phase 0** on the assembled system, complete **Phases 1–9**, then proceed to **Phase 11** acceptance/documentation. **Phase 10 is a conscious scope cut.**

Architecture setup installs the listed components; Section 2 supplies persisted lineage, policy, and lifecycle operations. Phase 0 has been revisited: code redemption, replay, signing trust, and normalized issuance share one transaction, and both SP identities verify canonical lineage over authenticated HTTPS. Evidence is tracked in [docs/target-architecture.md](docs/target-architecture.md), [docs/shared-security-model.md](docs/shared-security-model.md), and [docs/phase0.md](docs/phase0.md). The remaining foundation and browser/feature work follows.

## 1. Target architecture

| Area | Planned choice |
| --- | --- |
| Application services | One FastAPI IDP and two independently configured FastAPI SPs. An additional SP profile exercises onboarding. |
| Federation protocol | OIDC Authorization Code Flow with mandatory S256 PKCE, browser-bound state, and nonce validation. |
| Service authentication | Verified TLS plus asymmetric `private_key_jwt` SP authentication. |
| Protocol and crypto libraries | Authlib for OAuth/OIDC, joserfc and cryptography for JOSE/crypto, HTTPX2 for the current async client integration. |
| Persistence | PostgreSQL, SQLAlchemy async, and asyncpg. Separate databases/roles for the IDP and each SP. |
| Browser sessions | Independent opaque, server-side sessions for the IDP and each SP. |
| Revocation enforcement | Authenticated online grant checks for protected SP requests. |
| Global logout | OIDC RP-Initiated Logout and Back-Channel Logout, with durable delivery state. |
| Step-up authentication | Password plus TOTP through PyOTP, with explicit assurance and recency policies. |
| Runtime | Docker Compose, generated local certificates, distinct hostnames, and documented trust setup. |
| Verification | pytest, strict typing, linting, real-network integration tests, browser tests, and dependency auditing. |
Verified HTTPS will be part of the application setup. Browser and automated-test trust configuration will be documented alongside startup instructions.
### Repository structure
```text
src/federated_identity/
  idp/
    api/
    schemas/
    services/
    repositories/
    protocol/
  sp/
    api/
    schemas/
    services/
    repositories/
    protocol/
  common/
    settings/
    security/
    observability/
  cli/

migrations/
  idp/
  sp/

tests/
  unit/
  integration/
  security/
  e2e/

ops/
docs/
compose.yaml
pyproject.toml
README.md
```
Both SPs use the same application implementation, with separate credentials, configuration, database access, and session state.
## 2. Shared security model — model foundation implemented
The early phases establish the relationships needed by later features:
```text
IDP session
  └── Authentication event: user, methods, assurance, authentication time
       └── SP-specific grant
            ├── Issued authentication evidence and signing-key ID
            ├── Access tokens
            ├── Refresh-token family
             └── SP-local session
```
Logout notifications reference the relevant issuer and IDP session identifier.
Important contracts:
- Artifact purposes stay separate. ID tokens, client assertions, logout tokens, access tokens, and browser cookies have distinct validation rules.
- Protocol return paths remain explicit. Codes are redeemed at the IDP; ID-token logout hints can identify a logout context. Neither establishes an IDP user or administrator session.
- Routine rotation preserves legitimate artifacts. Emergency key revocation intentionally invalidates affected trust.
- Revocation takes effect at subsequent authorization checks. Already-authorized in-flight work cannot be recalled.
- Refresh preserves authentication history. It does not advance auth_time, raise assurance, or extend the parent session’s absolute lifetime.
- Dependency outages fail closed. Temporary outages block protected access without deleting otherwise valid persisted sessions.
- Security-sensitive races are resolved in the database. Code consumption, assertion replay detection, token rotation, and revocation use transactions and atomic constraints.

Implemented at the model/service boundary: typed immutable events/evidence, normalized IDP/SP migrations, recipient-bound authoritative checks, hashed and encrypted credential custody, bounded lifetimes, refresh-family transitions, scoped client/key containment, atomic logout intents, and SP assurance/recency policy. The [shared-model record](docs/shared-security-model.md) documents trust inputs, serialization, tested guarantees, and protocol integration boundaries.

**Phase 0–9 integration:** code/assertion replay, active-signer selection, and canonical grant/evidence/retention issuance share one gated transaction. SSO includes live onboarding, routine rotation, and both compromise-containment paths. Authenticated refresh rotates hashed family credentials and records new signed evidence without rewriting authentication history; SPs coordinate encrypted renewal through durable claims and require fresh authorization after ambiguous outcomes. Purpose-bound re-authentication enforces actual password proof, subject continuity, and session identifier renewal. Confirmed browser-matched global logout commits revocation and recipient intents together; leased signed delivery, current logout-purpose trust checks, and durable SP sid/replay fences recover across outage and restart. Real password/TOTP proof commits consumed counters, immutable stronger events, and binding rotation together; persistent attempt budgets and each SP's assurance/recency enforcement guard sensitive operations.

Implementation phases
Phase 0 — Prove the protocol adapter and lock security contracts
Status: revisited and verified on the assembled architecture/security model on 2026-10-06; all 192 tests pass. See [the checkpoint record](docs/phase0.md).
Goal: Resolve the highest-risk integration before building the feature set.
Build
- Prototype Authlib authorization-code/OIDC handling behind FastAPI.
- Prove the provider’s synchronous-shaped hooks can use async database drivers through an isolated adapter.
- Establish request-scoped protocol state and database transactions.
- Validate private_key_jwt support, including endpoint audiences, approved keys, short lifetimes, and durable jti replay detection.
- Confirm extension points for refresh, re-authentication, and logout.
- Write initial architecture decisions, threat model, and artifact-validation contracts.
Exit checks
- A valid PKCE code exchange produces a correctly validated ID token.
- Concurrent redemption produces at most one successful issuance.
- Invalid client assertions and replayed assertions are rejected.
- Delayed database work does not block unrelated requests.
- Issuance is committed before a successful response is returned.
Dependency: Foundation for every subsequent phase. The async requirement remains an acceptance condition for the chosen adapter.
Phase 1 — Runtime, persistence, secrets, and project foundations
Status: implemented and verified on 2026-10-06; all 210 tests pass. See [Phase 1 coverage and exit-check evidence](docs/phase1.md).
Goal: Establish the deployable service boundaries and durable storage.
Build
- Python packaging, locked dependencies, FastAPI factories, Pydantic settings, and typed interfaces.
- Compose services for the IDP, SP A, SP B, and PostgreSQL.
- Distinct application hostnames and verified TLS connections.
- Database migrations and separate application database roles.
- Idempotent bootstrap for seeded users, initial SP identities, certificates, keys, and generated credentials.
- Per-service secret storage and encryption keys supplied separately from encrypted database values.
- Structured logging, redaction, health/readiness endpoints, and bounded request handling.
- Initial lint, type-check, and test CI jobs.
Secrets must survive normal restarts. Bootstrap creates missing state rather than resetting existing identities or keys.
Exit checks
- A documented startup command brings up the system from a clean checkout.
- Certificates and hostnames are verified.
- Each SP’s database credentials cannot access another service’s state.
- Bootstrap reruns preserve existing secrets and identities.
- Wrong or missing encryption keys produce a clear startup failure.
- Logs and public configuration contain no credentials or private key material.

Completed gaps: stable seeded users and encrypted generated credentials with Argon2id hashes; immutable local/database encryption-key binding and checked enrollment; preservation of existing password/account state; schema-aware startup/readiness and pool cleanup on failure; bounded requests and cancellation-safe verification workers; credential-safe structured logging; migration/configuration resources in built wheels and installed-wheel CI verification. Container startup remains exercised by CI; local evidence uses the same factories in actual independent HTTPS/database-TLS processes.

Phase 2 — Federated login, mutual authentication, and cross-SP integrity
Status: implemented and verified on 2026-10-06; all 270 tests pass. See [Phase 2 coverage and exit-check evidence](docs/phase2.md).
Goal: Deliver the first complete SSO flow.
Build
IDP functionality:
- Discovery and public JWKS endpoints.
- Seeded-user login with vetted password hashing.
- Authorization and token endpoints.
- Exact redirect-URI validation.
- Mandatory S256 PKCE.
- Atomic, short-lived authorization codes.
- Per-SP ID tokens and opaque grants.
SP functionality:
- Login initiation and persisted browser-bound authorization transactions.
- Callback handling using Authlib’s async client functionality.
- Explicit issuer, audience, signature, algorithm, nonce, and time validation.
- Independent opaque authenticated sessions.
- Minimal pages showing the authenticated user and application identity.
Persist authentication events and signing-key evidence now so later containment and step-up features can use them.
Exit checks
- Signing in through SP A enables login at SP B without another password entry.
- SP A’s code cannot be redeemed by SP B.
- Changing the original callback URI causes rejection.
- SP A’s ID token and session cookie cannot authenticate at SP B.
- ID tokens cannot authenticate IDP user/admin endpoints.
- Missing or mismatched state, nonce, and PKCE values are rejected.
- Authentication cookies remain scoped to their owning host.

Implemented: credential-backed IDP cookie principals; persisted one-use, origin-checked login forms; async Authlib SP initiation/callbacks with browser-bound state/nonce/S256; independent opaque authenticated sessions; canonical authentication/signing evidence; minimal user/application pages; and real-network/Chromium attack, concurrency, expiry, and restart checks. `federationctl verify-login` exercises password sign-in at A and password-free SSO at B on three verified-HTTPS processes.

Phase 3 — Session lifecycle and authoritative revocation
Status: implemented and verified on 2026-10-06; 49 selected new/affected cases pass, with lint/format/type checks. See [Phase 3 coverage and exit-check evidence](docs/phase3.md).
Goal: Make session termination and expiry effective.
Build
- Explicit session and grant expiry policies.
- Server-enforced SP idle and absolute timeouts.
- Session identifier rotation after authentication.
- CSRF-protected local logout.
- IDP-session termination and grant revocation.
- Authenticated introspection and token revocation endpoints.
- SP authorization checks against authoritative grant state.
- Client-scoped introspection and revocation permissions.
- Retained code-consumption records sufficient to detect authenticated replay and revoke derived grants where appropriate.
Exit checks
- Replaying a captured cookie after local logout fails.
- Expired sessions fail even if a browser retains the cookie.
- Revoking an IDP session blocks subsequent protected requests at both SPs.
- SP A cannot inspect or revoke SP B’s grants.
- IDP/database outages block protected access; recovery preserves valid sessions.
- Restarting an application preserves active and revoked session state.
Checkpoint: A secure, runnable federated system with cross-SP integrity, effective sessions, and durable state.

Implemented: persisted purpose/browser-bound one-use lifecycle intents; local SP logout and grant revocation; IDP session and selected-grant controls; endpoint-bound private_key_jwt revocation; exact authoritative checks on protected requests; expiry and logout/callback race enforcement; consumed-code proof retention and owning-client/redirect/PKCE-gated replay containment. Tests share runtime state and use the injected Clock for expiry.

Phase 4 — Authenticated onboarding and the operator control plane
Status: implemented and verified on 2026-10-06; 60 selected new/affected cases pass, with lint/format/type checks. See [Phase 4 coverage and exit-check evidence](docs/phase4.md).
Goal: Add SPs without redeploying the IDP.
Build
- Operator authentication with separate administrative credentials and authorization.
- Client registration and metadata-management endpoints.
- Registration fields for:
- Client identity and public authentication keys.
- Approved redirect URIs.
- Allowed grants and scopes.
- Post-logout redirect URIs.
- Back-channel logout URI.
- Validation of URI schemes, origins, key types, algorithms, and public-only key material.
- Live database-backed client lookup.
- Operator CLI commands for registration, inspection, disabling, and credential replacement.
- An initially unregistered SP C runtime profile.
Exit checks
- Register SP C and complete its login flow while the IDP process remains running.
- SP A and SP B continue functioning during onboarding.
- Unregistered clients fail authentication.
- SP/user credentials cannot perform operator actions.
- Invalid metadata and private-key uploads are rejected.
- Registrations and metadata changes survive restart.

Implemented: separately provisioned Argon2id operator credentials and channel-bound opaque browser/API sessions; current registry read/write permissions; CSRF-protected browser control plane; typed authenticated CLI; public-only RSA/RS256 registration and same-origin HTTPS destinations; versioned live metadata, disabling/explicit enabling, new-key replacement, append-only audit/key history, and safe upgrade of immutable code proofs. Real Chromium onboards initially unregistered SP C while the IDP keeps running and A/B continue working.

Phase 5 — Live signing-key rotation
Status: implemented and verified on 2026-10-06; 58 distinct selected new/affected cases pass, with lint/format/type checks. See [Phase 5 coverage and exit-check evidence](docs/phase5.md).
Goal: Rotate signing keys without interrupting normal authentication.
Build
- Persisted key states: prepared, active, draining, retired, and revoked.
- Operator-controlled key preparation and activation.
- Publication of a new public key before signing with it.
- Transactional coordination of active-key selection and issuance records.
- Retention based on the latest relevant artifact expiry plus clock skew.
- SP JWKS caching with bounded, single-flight refresh on unknown kid.
- Correct cache namespacing and public-only JWKS serialization.
The key service must account for every IDP-signed artifact type, including logout tokens introduced later.
Exit checks
- Both SPs accept new-key artifacts without restarting.
- Legitimate old-key artifacts continue verifying until expiry.
- Established sessions continue through routine rotation.
- Prewarmed JWKS caches recover on encountering a new key.
- Unknown-key traffic does not create unbounded fetches.
- Active and draining key state survives IDP restart.

Implemented: encrypted database-backed issuer key custody; explicit operator key permissions, browser/API/CLI preparation, publication, activation, and retirement; generic immutable ID-token/logout-token-purpose retention; gated active selection and atomic issuance; public-only prepared/active/draining JWKS; pinned, bounded single-flight SP trust caches with shared unknown-kid cooldown. Real verified-HTTPS/Chromium rotation preserves sessions, recovers both prewarmed SPs, and retains active/draining trust across IDP restart. Verification startup waits are bounded at 30 seconds after observing readiness just beyond the old 15-second window.

Phase 6 — Signing-key and SP compromise containment
Status: implemented and verified on 2026-10-07; 44 distinct selected new/affected cases pass, including real HTTPS/Chromium recovery, with lint/format/type checks. See [Phase 6 coverage and exit-check evidence](docs/phase6.md).
Goal: Implement both containment paths.
Build
SP compromise path:
- Disable a client’s authentication credentials.
- Revoke its grants and associated sessions.
- Prevent further code redemption and refresh.
- Replace credentials and explicitly re-enable the recovered client.
Signing-key compromise path:
- Activate a replacement key.
- Mark the compromised key revoked.
- Revoke grants/sessions linked to affected signing evidence.
- Enforce revoked-key state through authoritative checks, including when an SP still has the public key cached.
- Check authentication evidence against trusted issuance/grant records.
Exit checks
- Disabling SP A stops its trusted IDP interactions while SP B remains functional.
- Old SP A credentials remain rejected after replacement.
- Compromised-key artifacts fail despite cached verification keys.
- A forged ID token without matching trusted issuance/grant state cannot establish a session.
- Refresh or concurrent issuance cannot revive revoked trust.
- Containment state survives restart.
Checkpoint: All six possible-feature categories have working implementations and targeted acceptance tests.

Implemented: purpose/target-bound operator API/browser/CLI containment; atomic published-replacement activation, irreversible signer revocation, affected grant/family revocation, and replacement-aware audit; durable client compromise markers with database-enforced credential replacement before re-enable; encrypted atomic owner-side SP key replacement; cached-signature/unissued-evidence rejection and serialized issuance/refresh races. One verified-HTTPS/Chromium deployment recovers SP A while B remains usable, rejects old credentials/cookies, contains the issuer key with prewarmed caches, and preserves recovery/revocation across SP/IDP restart. Refresh denial is verified at the existing service boundary; the refresh protocol integrates in Phase 7.

Phase 7 — Refresh-token rotation and re-authentication
Status: implemented and verified on 2026-10-07; 133 distinct selected new/affected cases pass, including real HTTPS/Chromium with injected process time, with lint/format/type checks. See [Phase 7 coverage and exit-check evidence](docs/phase7.md).
Goal: Support renewal while preserving revocation and assurance guarantees.
Build
- Authlib refresh grants with explicit refresh-token rotation enabled.
- Persisted token families, predecessor relationships, expiry, consumption, and revocation.
- Hashed refresh-token storage at the IDP.
- Encrypted recoverable token storage at SPs.
- Atomic family rotation and reuse detection.
- Database-backed refresh coordination at each SP.
- Forced re-authentication through prompt=login and max_age.
- Subject continuity checks and session identifier renewal.
- Defined recovery for ambiguous refresh failures.
Reuse detection must occur after authenticating the client and checking token ownership. This prevents another client from using a stolen token value to revoke someone else’s family.
Exit checks
- An expired access token is renewed without another password entry while the underlying grant permits it.
- Authenticated reuse of a consumed refresh token revokes the affected family.
- Concurrent legitimate SP requests do not trigger false reuse detection.
- Wrong-client refresh requests fail without modifying the rightful client’s family.
- Logout, client disabling, and key revocation prevent further refresh.
- Forced re-authentication requires actual credential verification.
- Refreshed ID tokens preserve the original subject, authentication time, and assurance.
OIDC refresh rules (https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse) explicitly distinguish new token issuance from a new authentication event.

Implemented: Authlib rotating refresh grants and OpenID token hooks; hashed predecessor/successor families and immutable signed renewal evidence; authenticated owner-first reuse containment; active-key selection and all-purpose retention in the same transaction; encrypted SP credentials with database single-flight claims, committed installation, cancellation/response-loss barriers, and fresh-login recovery; CSRF-protected prompt=login/max_age controls with immutable subject/authentication binding and cookie renewal. Verified browser TLS renews both SPs without password/cookie changes, re-authenticates only A, rejects captured cookies, and renews across SP/IDP restart using injected process time.

Phase 8 — Reliable single logout across SPs
Status: implemented and verified on 2026-10-07; 220 distinct selected new/affected cases pass, including real HTTPS/Chromium outage and dispatcher recovery, with lint/format/type checks. See [Phase 8 coverage and exit-check evidence](docs/phase8.md).
Goal: Terminate the relevant sessions across the federation.
Build
- OIDC RP-Initiated Logout.
- OIDC Back-Channel Logout.
- Distinct local and global logout controls.
- Session matching using issuer and sid.
- Signed, SP-specific logout tokens with:
- Correct issuer and audience.
- Required issuance and expiry times.
- Unique jti.
- Logout event claim.
- Explicit logout+jwt type.
- No nonce.
- A transactional outbox recording logout deliveries alongside revocation.
- Async delivery, bounded retry behavior, durable replay handling, and idempotent session termination.
- Strict post-logout redirect validation.
- Browser-session matching and CSRF protection for logout intent.
Authoritative revocation takes effect before notification delivery. Failed deliveries remain recoverable without allowing continued access.
Exit checks
- Global logout terminates the relevant sessions at both SPs.
- An unavailable SP rejects its old session when it returns.
- Dispatcher restart recovers pending deliveries.
- Retried notifications do not terminate a newly created, different session.
- Wrong-audience, expired, forged, and cross-purpose logout tokens fail.
- An ID token is rejected as a back-channel logout token.
- A logout token is rejected as login evidence.
Implementation follows the Back-Channel Logout (https://openid.net/specs/openid-connect-backchannel-1_0.html) and RP-Initiated Logout (https://openid.net/specs/openid-connect-rpinitiated-1_0.html) specifications.

Implemented: distinct local/global controls; GET/POST RP initiation with exact issued historical hints, current-browser matching, one-use confirmation, and versioned literal return validation; revocation plus encrypted recipient intents in one transaction; lifespan-owned verified-HTTPS delivery with gated signing/retention, durable leases, fenced acknowledgement, bounded backoff, fresh-token reissue, and private owner recovery commands. SPs require the logout+jwt/event/no-nonce profile and authenticated exact logout-purpose authority, then atomically commit issuer/sid termination, binding/callback invalidation, and durable replay receipts. Verified browser TLS stops B, restarts the dispatcher, rejects old cookies before delivery, reissues an expired notification, and preserves fresh different sessions under retry/restart.

Phase 9 — Real step-up authentication
Status: implemented and verified on 2026-10-07; 252 distinct selected new/affected cases pass, including real HTTPS/Chromium and owner authenticator provisioning, with lint/format/type checks. See [Phase 9 coverage and exit-check evidence](docs/phase9.md).
Goal: Enforce a stronger, recent authentication event for sensitive access.
Build
- TOTP provisioning for seeded users.
- Encrypted TOTP secrets.
- Library-based OTP verification.
- Atomic, persisted consumption of accepted OTP time steps.
- Attempt limits and rate limiting.
- Explicit password-only and password-plus-TOTP assurance classes.
- acr, amr, and auth_time issuance and validation.
- Step-up requests using OIDC assurance and recency parameters.
- A sensitive SP operation requiring the stronger assurance class.
- Session rotation following successful step-up.
Each SP enforces the returned assurance and authentication time. Requesting a higher assurance level is insufficient by itself.
Exit checks
- Password-only sessions cannot access the sensitive operation.
- Valid password-plus-TOTP authentication enables access.
- Wrong, expired, replayed, and concurrently reused OTPs fail.
- OTP replay protection survives restart.
- Refresh does not manufacture a newer authentication event.
- Stale step-up assurance requires renewed proof.
- Account substitution during re-authentication is rejected.
- Elevating one SP’s session does not automatically elevate another established SP session.
PyOTP’s guidance (https://pyotp.readthedocs.io/en/stable/) identifies secret confidentiality, replay prevention, and throttling as application responsibilities.

Implemented: idempotent v3 seeded-factor bundles and subject-bound encrypted enrollment; vetted PyOTP matching with locked durable high-water/accepted-step history; atomic password/TOTP proof, immutable event, counter consumption and cookie rotation; persistent source/browser/account budgets, bounded one-use MFA continuation attempts, and fixed deadlines. OIDC assurance/recency requests are persisted and enforced against actual returned subject/methods/time and exact canonical evidence. Each SP independently guards a CSRF-protected sensitive approval operation and commits encrypted immutable authorization evidence. Verified browser TLS retrieves enrolled provisioning through the owner CLI, rejects invalid and restarted replay, preserves sibling-SP assurance, renews without manufacturing freshness, and requires real new proof for stale sensitive access.

Phase 10 — Attack-defense evidence and security CI
Status: intentionally skipped for this submission, by the user's scope decision on 2026-10-07. This is an optional evidence/security-CI extension, not a completed checkpoint or a dependency of Phase 11. [ADR 0005](docs/decisions/0005-phase10-scope-cut.md) records the reasoning and residual pipeline-assurance gap.

Rationale: prioritize the brief's application trust/lifecycle decisions and the demonstrated security of the implemented properties. Authentic advisory selection, isolated vulnerable input, scanner collection/error classification, machine-readable evidence, and finding-specific pipeline failure propagation are substantive additional assurance work. Existing feature-specific attack tests, mandatory lint/type/testing standards, and the configured locked-dependency audit support the selected scope; they do not establish the omitted real-finding negative-control proof.

Original proposed goal (out of committed scope): demonstrate additional specific defenses and prove the CI security gate detects a real finding.
Original proposed work (retained for traceability, not remaining acceptance work)
A repeatable hostile-flow test suite covering:
- Login CSRF and authorization-code injection.
- PKCE stripping and downgrade attempts.
- Browser-state transplantation.
- Code, assertion, and refresh-token replay.
- Cross-SP and cross-JWT substitution.
- Forged assurance claims.
- Untrusted token-supplied key locations.
- Open redirects through error and logout paths.
Expand CI with:
- Strict typing and linting.
- Relevant unit, integration, security, and browser tests.
- pip-audit against the locked production dependency set.
- Machine-readable audit output.
- A negative-control test using an isolated manifest containing a dependency version affected by a real published advisory.
The negative control must verify the expected advisory appears and the scanner returns failure. It must distinguish a vulnerability finding from a collection or network error.
Original proposed exit checks (not claimed passed for Phase 10)
- The named attack scenarios fail while legitimate equivalent flows succeed.
- Current production dependencies pass the audit.
- The vulnerable manifest produces the expected real finding and failing result.
- The production CI audit preserves its failure status.
- Test evidence contains no reusable secrets.
pip-audit (https://github.com/pypa/pip-audit) provides the dependency findings and failure behavior for this gate.
Phase 11 — Full-system acceptance and documentation
Status: completed for the selected scope on 2026-10-07; 84 distinct selected cases pass, including combined real HTTPS/Chromium restart/recovery, five race families, and both containment paths. Current isolated installed-wheel login/protocol probes and lint/format/type checks pass. Docker/Compose execution was unavailable locally and is explicitly distinguished from configured CI. See [Phase 11 acceptance and writeup evidence](docs/phase11.md).
Goal: Verify that the chosen implemented properties and extensions work together; Phase 10 is excluded by the documented scope cut.
Build and verify
- Restart matrix for the IDP, each SP, and persisted infrastructure.
- Recovery tests for pending logout and refresh operations.
- Concurrency tests involving:
- Refresh versus logout.
- Issuance versus client disabling.
- Rotation versus signing.
- Key revocation versus refresh.
- Step-up versus session revocation.
- End-to-end scenarios combining onboarding, rotation, refresh, step-up, and global logout.
- Fresh-checkout startup and migration verification.
- Operator CLI documentation and reproducible feature scenarios.
- Final architecture, data-flow, and threat-model documentation.
- README feature inventory linked to acceptance evidence.
- Actual AI-usage notes: assistance, corrections, and how errors were caught.
Exit checks
- All in-scope property and selected-extension scenarios pass across real service processes.
- Restart does not resurrect expired, consumed, or revoked state.
- Race conditions cannot bypass revocation or create duplicate issuance.
- The README accurately describes behavior, trust assumptions, residual risk, and operational commands.
- The repository is ready for the subsequent demo-video planning task.

Implemented and verified: one fresh four-application/browser scenario combines live C onboarding, key rotation/retirement, normal and abandoned refresh, real step-up, PostgreSQL/application restart, and offline-recipient global logout recovery. Additional infrastructure/factory reconstruction preserves active, expired, revoked, consumed-code and refresh state; selected real-database race and publication checks plus the real containment scenario pass. Acceptance corrected cold database connection errors/stale-pool recovery and Make CA-export contamination. The current packaged runtime proves fresh migration/seed/SSO/protocol startup outside the checkout. A concise 144-line README covers the brief's four writeup sections, with linked operator/scenario and detailed threat/architecture/AI evidence. Phase 10 remains skipped; GitHub publication and the recorded demo video are separate submission artifacts.
3. Requirements coverage
Requirement or extension	Owning phases
Cross-SP integrity	2; feature-specific negative checks also continue in implemented phases
Mutual authentication and onboarding	2, 4
Signing-key rotation without downtime	5
Compromise containment	6
Session lifecycle	3
Persistence and deliberate at-rest handling	1, 3, 11; extended with each new state type
Single logout across SPs	8
Refresh	7
Re-authentication	7
Step-up authentication	9
CI gate that fails on a real finding	10 — intentionally skipped optional demonstration; existing scanner configuration is not negative-control acceptance evidence
Defense against a specific attack	2: implemented login CSRF/code injection/PKCE defenses; separate Phase 10 evidence expansion intentionally skipped
Typed, layered, fully async application code	Every phase
Seeded users and at least two SPs	1, 2
Straightforward startup	1, verified again in 11
Required README/writeup	Maintained throughout, finalized in 11
4. Definition of done for each phase
Verification runtime policy: run new/changed pytest cases and those affected by the functionality, selecting files, node IDs, or -k expressions. Share runtime/database fixtures and use the injected Clock. Full regression, repeated packaging/deployment, and audits are reserved for explicit requests or concrete uncovered concerns. Record exact commands/results; a targeted run is not a full regression run. See [AGENTS.md](AGENTS.md).
An in-scope implementation phase is complete when (the explicitly skipped Phase 10 is not counted as complete):
1. Its feature works through the relevant API or browser flow.
2. Its security guarantees have meaningful positive and negative tests.
3. New durable state has the necessary restart and replay checks.
4. Type checking, linting, and applicable CI checks pass.
5. Architecture decisions, threat assumptions, and operator instructions are updated.
6. Its implementation can be explained, including library hooks and security-sensitive lines.
The milestones are:
- Phase 3: secure federated-login foundation.
- Phase 6: all six possible features implemented.
- Phase 10: intentionally skipped; real-finding CI proof and separate evidence expansion are outside submission scope.
- Phase 11: chosen implemented properties/extensions integrated, verified, documented, and ready for submission preparation, with the scope cut explicit.
