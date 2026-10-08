# AI usage and corrections

This log records actual research/build corrections. The implementation and its tests must remain explainable line by line.

## Phase 0 assistance

AI worked off of the plan laid out by the usedr for requirements mapping, primary-spec/source inspection,
architecture and transaction design, typed scaffolding, adversarial test cases,
and the local HTTPS/PostgreSQL verification runner.

## Corrections and how they were caught

| Initial assumption or scaffolding issue | Detection | Correction |
| --- | --- | --- |
| The older `httpx` dependency matched Authlib's current integration | The installed Authlib 1.8 compatibility shim emitted a deprecation warning during the first probe | Selected its supported HTTPX2 transport and updated the locked dependency and typed transport boundaries |
| Framework-independent `OAuth2Client` could be constructed without a session argument | The first live probe raised a constructor error | Passed `session=None` explicitly for the no-I/O authorization-URL builder |
| Authlib's parsed response had exactly the wire model fields | The probe's strict response model rejected the library-added `expires_at` | Removed only the known local bookkeeping field; kept strict validation of all wire fields |
| A state-mismatch test could catch generic `ValueError` | The rejection test showed Authlib's specific `MismatchingStateException` | Added a typed application rejection boundary and validated callbacks before any network work |
| The callback parser safely retained repeated query fields | Inspection showed Authlib uses `dict(parse_qsl(...))` | Reject duplicates before parsing; add positive/negative callback tests |
| Library PKCE support alone provided the selected profile | Source inspection showed optional challenges and a `plain` default, including confidential-client nuances | Mandatory S256 extension plus downgrade/missing-challenge tests |
| Signature verification/default claims checking was enough for our strict artifact policy | Source inspection showed audience-list membership behavior and expiry boundary tolerance | Explicit typed audience/purpose/clock policy, including multi-audience, boolean-date, and exact-expiry tests |

## Verification used to challenge the design

- Actual asyncpg/PostgreSQL, not a mocked transaction engine.
- An actual database wait inside the sync-shaped hook while health remains responsive.
- Eight simultaneous code redeemers and eight assertion replayers.
- Paused commit and injected commit/signing failure to challenge publication ordering.
- A real HTTPS exchange and untrusted-CA rejection.
- Invalid artifacts paired with legitimate positive controls.
- Strict typing, lint/format checks, warnings-as-errors, and the locked dependency audit.

Continue recording actual implementation corrections, tests, and tradeoffs as
subsequent phases add deployment, user authentication, and lifecycle features.

## Architecture-first reorientation

The user corrected the execution order: install the target architecture before
designing the shared security model and revisiting the protocol phases. The
prior proof was preserved, while deployable applications, isolated databases,
persistent secrets/PKI, migrations, and typed capability boundaries were added.

Actual checks include three separate Python application processes, verified
HTTPS/database TLS, cross-database denial, stable secrets on bootstrap rerun,
opaque encrypted state after application restart, and Chromium cookie isolation.
Browser certificate trust was installed only in a temporary NSS profile;
`ignore_https_errors` remained false. Compose config was validated locally;
actual container startup is covered by the CI workflow because the local shell
has no Docker daemon.

PyOTP's current type signature expects a datetime for verification, so its
counter adapter was corrected to provide an aware UTC timestamp. The Pydantic
type-checker plugin was enabled so environment-populated settings remain typed
without dummy configuration defaults.

## Shared security model

AI assisted with immutable entity contracts, recipient/purpose separation,
normalized migrations, lifecycle operations, and PostgreSQL concurrency tests.
Actual corrections during review/verification:

- The initial SP establishment path trusted a supplied grant snapshot. It was
  changed to require a fresh authenticated issuance check before persistence.
  Library-signed forged/unissued evidence now fails while the positive flow works.
- Initial scalar repository reads leaked `Any`, and an untyped logout payload
  failed strict mypy. Typed SQLAlchemy results and `JsonValue` payloads corrected both.
- Generating an access token after receiving signed evidence would break the
  `at_hash` pair. Initial issuance now records the protocol's exact token;
  model tests use Authlib's encoder and the existing JOSE/OIDC validator.
- Python immutability alone was insufficient for durable history. Migrations
  gained immutable-fact, lifetime, trust-transition, revocation, and consumption
  guards, challenged by direct SQL and restart/reconstruction checks.
- An introspection request can cross the credential's expiry while waiting for
  its response. The adapter now checks the completion-time clock; a delayed
  response at the exact expiry boundary is rejected.
- The full regression command initially exhausted a four-minute execution
  budget during WSL process startup. The isolated test passed with about
  35 seconds of setup; the full-suite budget was increased for actual verification.

Focused verification includes real PostgreSQL transitions and locks, concurrent
refresh/containment, commit pauses/failures, atomic logout-intent rollback,
outage recovery, subject continuity, and per-SP assurance isolation. The retained
HTTPS protocol proof and locked production dependency audit also passed.
The completed regression run passed all **168 tests** in about six and a half
minutes in this WSL checkout; strict mypy, Ruff lint, and formatting passed.

## Phase 0 revisit on the assembled system

AI helped review the retained proof against the architecture and shared model,
inspect Authlib's public validation/creation and introspection hooks, integrate
the shared unit of work, and add targeted failure/race/upgrade tests.

Actual issues found and corrected:

- The protocol ledger was still independent of canonical sessions/events and
  grants. Codes now bind to stored events; one transaction creates canonical
  issuance, consumes the code, updates key retention, and links the ledger.
- A separate model transaction could race containment or publish partial state.
  Caller-owned model operations share the protocol session and gate, with a
  savepoint for expected late denial. Tests inject failure after actual grant
  creation and omit the ledger link to challenge atomicity and commit guards.
- Assertion validation initially retained the token endpoint's audience inside
  its claims registry even for introspection. The positive introspection test
  caught the rejection; both exact-audience checks now use the configured
  endpoint for that request, with substitution/replay negatives.
- The temporary architecture selected random SP ports but seeded default-port
  callbacks. Bootstrap now accepts those temporary public ports, and a real
  role-owned deployed protocol proof exercises the matching callback allowlists.
- Simply re-running the old isolated probe would miss integration defects.
  `federation-phase0` now uses the deployed factories/topology, encrypted fixture
  event, role-owned migrations, browser-bound transaction stores, and current
  authenticated lineage for both SPs.
- Upgrading old prototype rows must not manufacture trusted authentication.
  The new migration preserves them, rejects their redemption, and constrains
  all new protocol issuance to complete canonical linkage at commit.

Final verification passed all **192 tests** in about seven and a half minutes,
strict mypy for 85 files, and Ruff lint/format checks for 92 Python files. The
locked production dependency audit reported no known vulnerabilities.

## Phase 2 credential-backed browser login

AI assisted with repository orientation, persisted credential continuations,
cookie-principal and SP callback orchestration, typed transaction integration,
real-network/Chromium hostile flows, and the runnable installed-runtime SSO proof.
Actual corrections caught during implementation:

- The RP's async token client raises Authlib's integration `OAuthError`, rather
  than the provider's `OAuth2Error`. Real cross-SP code injection and changed-PKCE
  tests initially received 500 responses instead of controlled denials. The
  protocol boundary now translates that actual library exception into the typed
  authorization-response rejection; the legitimate flow and both negatives pass.
- HTTP-client flows passed while the first real browser flow failed. Sanitized
  Chromium diagnostics showed `Origin: null` under `no-referrer`, then a CSP
  `form-action` redirect block. Credential forms now use same-origin referrer
  policy and permit only their previously validated RP callback origin alongside
  the fixed local form action. Chromium SSO and cookie isolation pass with HTTPS
  errors enabled; no raw credential/code/cookie values were logged in diagnostics.
- Code-only sessions initially had only the model's refresh-bearing establishment
  interface available. A typed verified-login path now stores an absent refresh
  credential as `NULL`, preserving existing encrypted model-level refresh custody
  rather than inventing a token that the protocol never issued.
- Password verification alone leaves a gap before committing browser binding.
  The verifier now returns an internal credential snapshot; the short final
  transaction locks/rechecks it. Tests change the password or disable the account
  after verification and confirm no session/event is created.
- Real local SP processes need issuer DNS resolution that the external protocol
  probe previously supplied only to its own client. The verification-only runtime
  now maps declared loopback hosts while retaining SNI/CA checks and real traffic.
  Request-local pools prevent concurrent protected requests from closing each
  other's test transport; deployment continues to use Compose's DNS aliases.

Verification also challenges login/callback replay and concurrency, browser
transplantation, altered nonce/PKCE/state, literal callback binding, cross-purpose
tokens/cookies, pending/authenticated restarts, atomic binding publication and
rollback, subject continuity, and fail-closed outage recovery. Results are
recorded in [Phase 2](phase2.md).

Final review identified an Origin serialization edge: browsers lowercase hosts
and omit explicit HTTPS port 443, while protocol URI identifiers retain exact
configured values. The expected Origin is now derived from the validated service
hostname/listening port; eight positive/negative cases cover this boundary.
The final full regression passed **270 tests**, strict mypy and Ruff checks
passed, both isolated installed-wheel proofs passed, and the locked production
audit reported no known vulnerabilities.

## Phase 3 session lifecycle and targeted verification

AI assisted with lifecycle boundary review, user controls, client-scoped revocation,
authenticated code-replay containment, and the logout/callback race. Existing
model operations were connected through caller-owned transactions and a separate
browser intent store rather than accepting posted identities or JWT hints.

Actual review/test corrections:

- A pending exchange could otherwise recreate authentication using a logged-out
  initiating cookie. Establishment now validates the locked browser/authentication
  rows; logout expires the binding and removes pending callbacks/intents. A test
  pauses exchange after token validation, commits logout, and verifies rejection.
- A browser intent transaction initially reopened another pool session to load
  local evidence while holding a browser lock. The evidence read now shares its
  caller's transaction, avoiding nested connection acquisition under concurrency.
- Code tombstones alone did not contain derived authorization on authenticated
  reuse. Consumed proof now survives initial code expiry and is validated through
  owning-client authentication, exact callback, and library S256 verification
  before the linked grant/family is revoked. Wrong-proof/client negatives keep
  the rightful grant usable; commit failure rolls back containment and assertion
  reservation together.
- The missing-CSRF test initially sent an empty body without a form content type,
  so it exercised media-type rejection instead. It now supplies the proper form
  type and specifically verifies absent intent rejection without logout.
- The user identified excessive full-suite/runtime costs. Repository instructions
  now require selected new/changed/affected cases and necessity-based long checks.
  Lifecycle scenarios share a role-owned TLS database deployment and advance the
  injected Clock instead of waiting out expiry; one Chromium deployment checks
  actual HTTPS controls and process restart.

Phase 3 evidence records **49 selected passing cases**, including the consumed-
refresh ownership/family path and affected existing model/protocol cases. No
full regression, dependency audit, or repeated packaging proof is claimed for
this phase. Dependency/packaging checkpoint evidence remains in Phase 2.

## Phase 4 authenticated onboarding

AI assisted with registry/operator boundary review, strict public metadata,
separate credential provisioning and session channels, transactional management,
the verified-HTTPS CLI, and shared runtime/Chromium onboarding checks.

Actual corrections and verification:

- Argparse's statically generic `_SubParsersAction` is not runtime-subscriptable
  in Python 3.12. Collection caught the initial annotation error; deferred
  annotations fixed it, and the real CLI help/parser check passes.
- New code metadata must preserve immutable existing proofs. Review identified
  that an UPDATE backfill would trip the prior code guard. A constant ALTER
  default now assigns the original version without modifying facts; a test
  downgrades with pending/consumed codes and verifies upgrade plus redemption.
- Separate cookies alone are insufficient if their tokens can become API bearer
  credentials. Persisted session channels now reject that transplantation,
  preserve browser CSRF requirements, and exclude federation/JWT/user credentials.
- Registration replacement must not accept retired/shared credentials or revive
  old approvals. Append-only key history and registration versions now prevent
  reuse, invalidate pending codes, and scope grant revocation to the client.
- Initialization upgrades the operator bundle once and preserves modified
  account/password/permissions and live registrations. Missing established v2
  material remains a recovery failure rather than a reset.

The selected cases verify permissions, expiry, channel/cookie/JWT substitution,
origin/purpose/target CSRF, concurrent updates, rollback/retry, public-only key
validation, and registration persistence. One real HTTPS/Chromium scenario
registers initially untrusted C with an unchanged IDP PID, retains A/B access,
exercises disable/enable, and checks IDP restart. [Phase 4](phase4.md) records
**60 selected passing cases** and the lint/format/type gate, with no full suite
or repeated dependency/package audit claim.

## Phase 5 live signing-key rotation

AI assisted with persisted signer custody, operator lifecycle controls, generic
artifact retention, pinned JWKS cache integration, concurrency/failure tests,
and real-process/browser rotation evidence.

Actual corrections and verification:

- Runtime composition previously supplied the bootstrap volume signer. Live
  rotation now restores database-backed active material and selects it within
  the issuance savepoint. Factory and real-process restart tests prove the
  bootstrap identity does not become active again after rotation.
- ID-token-only retention was expanded into immutable signed-purpose history.
  A modeled later logout-token expiry delays retirement through its exact skew
  boundary, and migration assertions verify existing committed evidence is
  backfilled without changing consumed/pending code facts.
- Client key separation originally checked the bootstrap signing key. It now
  checks all persisted issuer public trust; registration and replacement with
  a prepared rotated key both reject without changing the existing client.
- Strict mypy caught an inferred permission variable that excluded key
  capabilities. An explicit `OperatorPermission | None` annotation preserves
  the intended registry/signing permission branches.
- Direct SQL tests challenge private-material edits, signed-expiry rewrites,
  audit deletion, and publication reset rather than relying only on application
  immutability. All four database guards reject the changes.
- The existing public-output process test timed out twice before IDP readiness.
  A diagnostic reached verified-HTTPS readiness at 15.7 seconds, just beyond the
  harness's 15-second limit. Its bounded verification startup window is now
  30 seconds; the grouped public-output/Chromium rotation run then passed.

The [Phase 5 checkpoint](phase5.md) records **58 distinct selected passing cases**,
single-flight/random-kid/failure/cancellation budgets, all-purpose retention,
atomic rotation/issuance and rollback, encrypted/public separation, migration,
and unchanged SP processes through live rotation and IDP restart. Ruff lint/format,
strict mypy, and the CLI help/parser check pass. Dependency/package evidence
remains the existing Phase 2 checkpoint.

## Phase 6 compromise containment and owner recovery

AI assisted with review of the existing scoped model transitions, atomic operator
signer recovery, client recovery barriers, encrypted owner credential deployment,
adversarial/race/rollback tests, and a combined HTTPS/Chromium acceptance scenario.

Actual corrections and verification:

- Independently activating and then revoking a compromised signer leaves a gap
  between decisions. Caller-owned `revoke_signer_in()` now joins replacement,
  affected grant/family revocation, and complete audit in one gated transaction.
  Injected commit failure preserves old authority instead of publishing a partial
  transition, and concurrent issuance/refresh cannot revive revoked lineage.
- Ordinary reversible client disabling alone could re-enable a captured key.
  Explicit containment now persists `compromised_key_id` with database/service
  barriers. New material and explicit enable recover only fresh authorization.
- Registry public-key replacement lacked an executable private deployment step.
  The owner CLI now atomically installs a service-bound encrypted override under
  a private lock and expected-kid check. Writer-race/install-failure tests and
  real CLI/SP restart verify deployment without changing wrapping/TLS/database state.
- Strict mypy caught a test patching an unexported imported `os` alias. The test
  now patches the standard-library object directly, preserving the typed boundary.
- The first real-browser negative assumed all `invalid_client` responses were
  HTTP 401. The token endpoint returned HTTP 400 under the existing OAuth adapter.
  The test now allows endpoint-specific 400/401 while requiring `invalid_client`;
  the complete combined browser/CLI/restart scenario passes.

[Phase 6](phase6.md) records **44 distinct selected passing cases**, including
vetted forged-jti/subject callback rejection, cached signature versus current
authority, scoped recovery, direct SQL barriers, owner custody, and both race
paths. Ruff lint/format, strict mypy, and both operator/owner CLI help checks pass.
Dependency/package evidence remains the existing Phase 2 checkpoint.

## Phase 7 rotating refresh and re-authentication

AI assisted with inspection of installed Authlib refresh/OpenID hooks, immutable
renewal evidence and hashed ancestry, SP database claims/ambiguity recovery,
purpose-bound freshness controls, hostile/race tests, and injected-time browser TLS.

Actual corrections and verification:

- Refresh cannot rewrite the original signed event/evidence without breaking
  historical session binding. New signed generation records and separate
  `credential_evidence` now bind renewal while retaining original auth_time/acr/amr.
  Key containment also queries renewal signatures, challenged with a non-root key.
- A process-local lock would not coordinate separate workers, and retry after a
  lost response could look like authenticated reuse. Durable ready/pending/blocked
  state now commits before network work, and cancellation/loss/install/lease tests
  verify one send and fresh-authorization recovery across reconstruction.
- An integration assertion expected a 303 after credentials, but Authlib returns
  a 302 directly to the approved callback. The test now follows that actual response.
- Enabling default A/B refresh capabilities increments registration version.
  The migration regression now proves immutable code facts survive, old approval
  rejects, fresh-code redemption succeeds, and existing issued authority stays valid.
- The browser negative submits a wrong password and receives a new blank form.
  The retry initially filled only password and timed out; filling username again
  matches the real form contract and the complete browser scenario passes.
- Verification now supplies shared owner-controlled time through an asynchronous
  background poll into an in-memory Clock. Expiry/restart is exercised over real
  TLS without blocking protocol hooks on files or waiting whole token lifetimes.

[Phase 7](phase7.md) records **133 distinct selected passing cases**, separate
login/refresh nonce validation, exact immutable history, owner/replay isolation,
rollback, races, local lifetime barriers, actual re-authentication, and SP/IDP
restart. Ruff lint/format and strict mypy pass. Historical package/dependency
evidence remains the Phase 2 checkpoint.

## Phase 8 reliable single logout

AI assisted with local repository orientation, primary specification and installed
Authlib source inspection, typed RP/logout policy, transactional signing/outbox
delivery, SP replay/session races, migrations, and real HTTPS/Chromium recovery.

Actual corrections and verification:

- A signature-only notification verifier would miss the prior compromise contract
  for cached keys and exact issuance. A distinct authenticated `/logout/introspect`
  audience now binds the real signed logout record, recipient, revoked parent, and
  current signing trust. Tests reject unissued signed messages and cached revoked
  trust while legitimate delivery works.
- Terminating only existing local rows leaves a callback-installation race.
  Immutable issuer/sid termination and a shared database session lock now fence
  already-validated installation even when the SP has no authenticated row yet.
  Paused callback/refresh checks challenge that ordering.
- Replay and session lock namespaces were made distinct, with replay preceding
  session locks and browser preceding authentication rows. Receipt/effect commit
  failure leaves both state and pending callbacks intact; exact retry commits once.
- Missing-CSRF requests initially omitted form content type and returned 415.
  Supplying the actual URL-encoded form type now tests absent-intent 403 rejection.
- Strict mypy rejected dynamic GET/POST keyword expansion in a test. Explicit
  params/data branches retain the typed HTTP boundary.
- The combined 82-case verification selection reached its 240-second shell budget
  during the last process check. It produced no completed summary and is not
  counted as passed. Separate shared-database, browser, and process selections
  completed; owned leftover disposable PostgreSQL processes were stopped.

[Phase 8](phase8.md) records **220 distinct selected passing cases**, including
lost acknowledgement, stale lease fencing, cancellation/exhaustion and owner
recovery, encrypted signing publication/retention, live destination changes,
historical hints, exact redirects, canonical/cross-purpose negatives, migrations,
affected lifecycle/renewal/signing checks, and real bidirectional TLS/Chromium.
The browser uses injected process time for expired retry and preserves fresh
different sessions across IDP/SP restart. Ruff lint/format, strict mypy, and both
owner queue CLI help commands pass.

## Phase 9 real step-up authentication

AI assisted with authentication/assurance orientation, PyOTP guidance, encrypted
idempotent factor provisioning, persisted attempt/counter policy, OIDC minimum and
subject/recency checks, sensitive commit enforcement, and actual browser proof.

Actual implementation corrections and challenged boundaries:

- A TOTP match alone was kept separate from an assurance grant. Password snapshot
  rechecking, locked counter consumption, immutable stronger event and cookie
  rotation now commit together. Concurrent/restarted reuse, expiry during event
  creation, and injected commit failure prove that no partial proof is published.
- OTP guessing limits must survive fresh forms and worker restart. Durable real-
  source/browser/account reservations precede password work, and the original
  MFA continuation retains its own attempt/deadline bound. Tests spray usernames,
  switch browsers, restart the IDP, and advance only the injected Clock.
- Original seed material must not reset factor replay. V3 envelope checks and
  enrollment preserve identity/ciphertext/counters; owner retrieval reads enrolled
  state. Bootstrap and real CLI/browser checks validate that boundary.
- Strict mypy caught a legacy browser-service test constructor missing the new
  typed factor dependency. The test now composes that service explicitly.
- Lint caught a migration-test closure that did not capture its loop configuration;
  an explicit default binding fixes it. Intentional non-ASCII digit negatives use
  escaped characters while preserving strict OTP-format coverage.
- Sensitive recency is rechecked after online authority, and accepted code validity
  is rechecked before consumption. Paused/stale and expiry-at-event tests confirm
  rejection with unchanged operation/receipt state.

[Phase 9](phase9.md) records **252 distinct selected passing cases** and the
189-file lint/format plus 167-source/test-file strict typing gate. Actual Chromium
uses enrolled owner CLI provisioning, rejects invalid/restarted replay, preserves
B's established assurance, and requires new password/code proof after refresh
leaves A's event stale. Existing logout/renewal/authentication checks also pass.

### Requested full-regression correction after Phase 9

The user then ran the full suite and reported 34 failures that the selected
checkpoint had not exposed. A requested local `uv run pytest -q` reproduced the
same **34 failed / 530 passed** result. Investigation found independent browser-
login scenarios sharing persisted account/source budgets, plus legacy expectations
that refresh remained unimplemented and SP refresh custody was absent.

The shared real-network fixture now isolates authentication-budget state at each
scenario boundary. Request/restart persistence and production-budget enforcement
remain exercised within scenarios. Updated custody checks validate distinct
encrypted refresh values, and protocol checks cover advertised refresh
authentication/invalid credentials plus explicit code-only denial.

The affected selection passed **102 tests**; `make check` passed. The requested
repaired full suite passed **565 tests in 1654.82s**. [Phase 9](phase9.md#requested-full-regression-follow-up)
records exact commands and distinguishes that full result from earlier selections.

## Conscious Phase 10 scope cut

The user explicitly cut Phase 10 from the submission scope. The original
AI-assisted plan targeted every optional extension, exceeding the brief's
requirement to choose and defend a bounded set of properties. The revised README
and plan now state the cut up front and apply remaining acceptance to the chosen
implemented scope.

AI assisted with checking the brief's optional-extension/writeup requirements and
reading the actual CI workflow before describing the decision. That inspection
confirmed a configured `pip-audit` step with `pipefail` and no `continue-on-error`;
the docs do not describe scanning as absent or treat its presence as the omitted
known-advisory negative-control proof. [ADR 0005](decisions/0005-phase10-scope-cut.md)
records why runtime trust/lifecycle depth was prioritized and the accepted gap in
finding-specific pipeline assurance. Existing verification results remain recorded
as executed, and no Phase 10 checkpoint is claimed.

## Phase 11 integrated acceptance and concise writeup

AI assisted with mapping the plan to executed coverage, combining the feature flows
on one actual HTTPS/Chromium deployment, persisted infrastructure restart/replay,
current installed-wheel validation, operator scenarios and the requirements-complete
short README. Phase 10's user-directed scope cut remains explicit.

Actual corrections and evidence:

- A cold asyncpg socket refusal is not always wrapped as a SQLAlchemy error.
  The first combined database-shutdown check received 500. The browser dependency
  boundary now handles raw socket failure as 503 and pools pre-ping stale handles;
  cold-pool lifecycle and real process restart preserve valid sessions.
- Review of `make export-ca > ...` found the recipe echo could prefix certificate
  bytes. Quiet Make output plus a redirected-output test fixes the documented
  trust-setup command; actual runtime TLS/Chromium independently verifies the CA.
- An expired-recipient credential followed uncertain refresh's 503 recovery, not
  the initial test's assumed 401. The combined test renews recipients before
  logout to isolate authoritative denial; abandoned/expired renewal is covered
  separately. New captured snapshots use `SecretStr` to keep failure evidence safe.
- Literal logout-delivery status constants now use `HTTPStatus`, and public
  runtime metadata describes full-system acceptance.

[Phase 11](phase11.md) records **84 distinct selected passing cases**, current
isolated wheel/password and protocol proofs outside the checkout, CLI parser
checks and the lint/format/type gate. Docker is unavailable locally; configured
Compose checks are not reported as executed. The README was reduced from 444 to
144 lines, with all four required writeup sections and detailed commands/evidence
linked. The recorded demo video and GitHub publication are separate artifacts.
