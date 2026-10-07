# Phase 2 — federated login, mutual authentication, and cross-SP integrity

Status: implemented and verified on 2026-10-06. All 270 tests pass, including
credential-backed HTTPS/Chromium flows and the cross-SP security checks below.

## Coverage and working set

| Planned feature | Main implementation |
| --- | --- |
| Discovery / public JWKS | `src/federated_identity/idp/api/app.py`; configured HTTPS issuer and public-only RSA key serialization |
| Seeded-user password login | `idp/api/browser.py`, `idp/services/authentication.py`, `idp/services/browser.py`; bounded off-thread Argon2id verification |
| Authorization / token endpoints | `idp/services/oidc.py`, `idp/protocol/authlib_adapter.py`; request-local Authlib extensions on asyncpg-backed transactions |
| Exact callbacks, mandatory S256, short one-use codes | Existing code profile and immutable protocol ledger, reused by browser login |
| Browser-bound credential forms | `idp/repositories/browser.py`, `idp/schemas/browser.py`; hashed challenges/browser IDs, encrypted validated continuations, atomic consumption |
| SP initiation / callback | `sp/api/browser.py`, `sp/services/browser.py`, `sp/repositories/transactions.py`; persisted state, nonce, PKCE verifier and browser binding |
| Async Authlib client / explicit ID-token validation | `sp/protocol/oidc.py`, `common/security/oidc.py`; pinned issuer/endpoints, TLS, registered client key, RS256/type/nonce/time/at_hash policy |
| Independent authenticated sessions | `sp/services/security_model.py`, `sp/repositories/security.py`; exact authoritative evidence and encrypted local credentials |
| Minimal authenticated pages | `/` and `/account` at each service; stable user subject and application identity, with IDP username |
| Durable schema / custody | IDP `idp_browser_login_05`, SP `sp_browser_login_04`; secret-key enrollment also verifies login continuations |
| Runnable proof | `federationctl verify-login`; independent HTTPS services and TLS-authenticated role-owned PostgreSQL databases |

Paths without the `src/federated_identity/` prefix in this table are relative to
that package. Both SPs use the same implementation with independently configured
keys, databases, sessions, and callback origins. Compose and the existing startup
commands provision everything needed for this checkpoint.

## Request flow

```mermaid
sequenceDiagram
    participant Browser
    participant A as SP A
    participant IDP
    participant B as SP B
    Browser->>A: GET /auth/login
    A->>A: Persist browser-bound state, nonce and PKCE verifier
    A-->>Browser: Opaque cookie and configured authorization URL
    Browser->>IDP: Authorization request with S256 challenge
    IDP->>IDP: Validate registration / exact callback / profile
    IDP-->>Browser: One-use, browser-bound credential form
    Browser->>IDP: Same-origin POST /login with password and CSRF challenge
    IDP->>IDP: Argon2id; recheck credential; commit session/event/browser rotation
    IDP->>IDP: Revalidate stored authorization request; commit bound code
    IDP-->>Browser: Code and state at SP A's registered callback
    Browser->>A: GET /auth/callback with A's initiating cookie
    A->>A: Atomically consume matching transaction
    A->>IDP: Verified HTTPS discovery/JWKS and private_key_jwt code exchange
    IDP->>IDP: Commit code consumption, replay, grant and signed evidence
    IDP-->>A: A-specific ID token and opaque access credential
    A->>A: Validate signature / issuer / audience / nonce / time / at_hash
    A->>IDP: Fresh endpoint-bound authenticated issuance checks
    A->>A: Commit exact evidence and encrypted credential; rotate local cookie
    A-->>Browser: Authenticated application page
    Browser->>B: GET /auth/login
    Browser->>IDP: B's authorization request with existing IDP cookie
    IDP-->>Browser: B-specific code; no additional password
    Browser->>B: B's independently bound callback
    B->>IDP: B's own key, code/verifier and authoritative checks
    B-->>Browser: Independent authenticated B session
```

SSO reuses the original verified authentication event and `auth_time`. It creates
separate grants, signing evidence, access credentials, and SP-local cookies for
each recipient. No browser request supplies a user, assurance class, authentication
time, event identifier, client assertion, or PKCE verifier to create an identity.

### Credential and continuation contracts

- Authlib validates the entire authorization request before the IDP offers a
  login form. Invalid/unregistered callbacks receive local errors, never a form
  or an attacker-selected redirect.
- Each login challenge lasts at most five minutes and is bounded by its initiating
  browser session. `DELETE ... RETURNING` checks the challenge digest, browser
  digest, and expiry together. Another browser cannot consume the rightful form.
- Only `csrf`, `username`, and `password` are accepted by `/login`. Duplicate
  fields, query continuations, JSON, missing/foreign Origin, and posted identity
  claims are rejected. Password failures use the same generic message and a new
  challenge; consumed forms stay consumed.
- Origin permission uses browser serialization (lowercase host, default HTTPS
  port omitted), derived from the validated service hostname/listening port.
  Issuer and callback URI identifiers keep their exact configured values.
- Argon2id runs before the short database gate/row locks. The final transaction
  locks and rechecks the verified credential snapshot, then commits the immutable
  authentication event, parent session, and new encrypted browser reference
  together. Failed binding/commit cannot publish a cookie or orphan trusted history.
- `prompt=none` returns `login_required` for an anonymous browser. Explicit login
  or unmet authentication-age demands require credentials. The trusted fresh-proof
  flag is supplied only after verification; it is not an HTTP parameter. A new
  event preserves the existing subject and parent absolute lifetime.

### Callback, trust, and cookie contracts

- Each SP consumes state only with its own initiating cookie and unexpired
  transaction. Ambiguous callbacks and unknown input fields are rejected before
  exchange. A failed exchange requires starting a new transaction.
- Authlib's async client creates a fresh `private_key_jwt` assertion for the exact
  token endpoint. The IDP validates the registered client key, approved algorithm,
  short lifetime, identity, audience, and durable `jti` replay record. Discovery,
  JWKS, token exchange, and introspection all retain hostname/CA verification.
- The shared verifier checks the configured issuer and single SP audience,
  signature/algorithm/type/key, nonce, required times, and `at_hash`. Fresh
  recipient-scoped introspection must match that exact committed evidence before
  a local session is persisted.
- Cookies use `__Host-fid-<service>`, `Secure`, `HttpOnly`, `SameSite=Lax`, and
  `Path=/`, with no Domain attribute. Each service hashes and resolves its own
  cookie only in its own database. Authentication rotates the browser identifier.
- ID tokens are accepted only as code-flow evidence. Neither bearer ID tokens
  nor transplanted JWT/cookie values authenticate `/account` or the IDP principal
  provider. Operator authentication belongs to the later control-plane phase;
  `/admin` currently has no route or authority to acquire.
- SP code-flow sessions store an encrypted access credential and exact evidence.
  Their refresh field is `NULL` because this protocol phase issues no refresh
  credential. Existing model-level refresh custody remains supported.

### Real-browser headers

All pages use no-store, escaping, nosniff, a script-free CSP, and framing denial.
Normal pages/callback responses use `Referrer-Policy: no-referrer`. Credential
forms use `same-origin`: Chromium otherwise sends `Origin: null` on a navigation
POST, conflicting with strict origin validation. Cross-origin referrers remain
suppressed.

Chromium also applies `form-action` to post-login redirects. An authorization
form permits `'self'` and only its already-validated RP callback origin. The
actual form action is always `/login`; standalone IDP forms permit only `'self'`.
No arbitrary return origin or provider error text is placed into a page/header.

## Exit checks and evidence

| Required guarantee | Verification |
| --- | --- |
| A login enables B without another password | Real-process `test_browser_sso_commits_one_event_and_separate_sp_evidence`; real Chromium `test_browser_password_sso_and_authenticated_cookie_isolation`; installed-runtime `verify-login` |
| A's code cannot be redeemed by B | Authenticated real-network code exchange; browser code injection into B's valid transaction; existing protocol owner checks |
| Changed original callback is rejected | Real-network token rejection plus the existing test using two otherwise registered A callbacks |
| A's ID token / cookie cannot authenticate at B | Independent audience validation and HTTP/browser cookie transplantation negatives, including renaming A's cookie to B's name |
| ID tokens cannot authenticate IDP users/admins | `/account` denies bearer and cookie JWTs; `/authorize` still requires a credential-backed IDP cookie; `/admin` grants no authority |
| Missing/mismatched state, nonce and PKCE fail | Callback duplicate/state/browser tests; actual modified authorization requests; retained missing/wrong token-verifier checks |
| Authentication cookies stay with their owning host | Chromium cookie visibility, HttpOnly checks, separate values, cross-host transplantation and authenticated restart |

Additional tests exercise concurrent form/callback consumption, expiry,
credential-change races, failed/paused commits, wrong-password retries,
`prompt=none`, fresh-proof subject continuity, restart of pending/consumed state,
and fail-closed IDP outage recovery without discarding SP sessions.

The local-process verifier supplies an explicit loopback DNS transport only in
`cli/architecture_runtime.py`. It preserves the real hostname, SNI, CA, ports,
and HTTP/TLS traffic; request-local pools prevent concurrent test clients from
closing one another's connections. Compose uses its normal declared DNS aliases.

## Verification results

- **270 tests passed** with warnings treated as errors; the final full run took
  884.35 seconds (about 14 minutes 44 seconds) in this WSL checkout.
- **60 Phase 2 checks added**, covering actual browser/credential flows, hostile
  protocol/browser substitution, transaction races/failures, restart, and origin policy.
- Strict mypy passed for **110** source/test files; Ruff lint and formatting
  passed for **121** Python files.
- The built wheel passed both `federation-phase0` and `federationctl verify-login`
  from `/tmp/opencode` in isolated environments with no checkout imports. The
  proofs exercised real independent HTTPS services, packaged migrations, and
  TLS-authenticated, isolated database roles.
- The locked production dependency audit reported **no known vulnerabilities**.
- CI now includes the installed-wheel credential-backed SSO proof. Local
  verification used independent processes; image/Compose startup is CI's
  separate deployment check.

## Reproduce

For browser interaction, follow [runtime startup and trust setup](runtime.md).
Retrieve Alice's generated password through the owner-side IDP command, then
use **Sign in** first at SP A and then at SP B.

```bash
uv sync --frozen
uv run federationctl verify-login
uv run pytest tests/unit/test_browser_origin.py tests/integration/test_browser_login.py tests/integration/test_browser_transactions.py tests/e2e -q
uv run pytest -q
make check
```

Tests require PostgreSQL binaries and Playwright Chromium/NSS tooling. The wheel
includes both migration histories. CI verifies installed-wheel credential-backed
SSO outside the checkout as well as the retained Phase 0 proof and Compose health.

At this checkpoint an access credential lasts at most 300 seconds; **Sign in**
obtains new SP evidence through the IDP session. The next checkpoint adds the
user-facing session termination and revocation controls in Phase 3.
