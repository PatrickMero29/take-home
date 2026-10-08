# Phase 8 — reliable single logout across SPs

Implemented and verified on 2026-10-07. **220 distinct selected new/affected cases
pass**, including actual HTTPS/Chromium, an unavailable SP, dispatcher restart,
expired notification reissue, and captured-cookie/replay checks. This is a
targeted checkpoint.

## Browser controls and RP-Initiated Logout

- **Sign out locally** at an SP ends its own session independently of the IDP.
- **Sign out everywhere** leads through an SP cookie/purpose/grant-bound one-use
  form to the IDP's `GET`/form-`POST /end-session` endpoint. The IDP displays its
  own confirmation; `POST /end-session/confirm` requires its current opaque cookie,
  exact Origin, and persisted one-use `rp_logout` challenge.
- **End IDP session** at the IDP uses the same revocation/outbox/notification
  pipeline. Other browsers with different IDP session identifiers remain active.

New SP evidence payloads seal the original ID token as a logout hint. Its expiry
does not prevent logout while the matching parent/browser remains active.
Historical verification uses persisted issuer public identity, including routinely
retired keys, and requires exact committed digest/jti, recipient, subject, sid,
signer, and dates. Revoked keys are rejected. Recent inactive hints are recognized
through the later of parent expiry/revocation plus the browser-action window,
permitting idempotent completed-logout redirects.

A hint never establishes an IDP principal. An active hinted session requires its
matching IDP cookie; another browser, a new different sid, and missing browser
authentication are rejected. Every active-session logout requires confirmation.
Older SP payloads without hints use the confirmed current IDP browser and its
recorded relationship with that client.

`client_id`, when supplied with a hint, must match its audience. The return URI
must literally match current registered `post_logout_redirect_uris`. The sealed
confirmation retains client/version/URI/state, then rechecks live metadata before
commit. State is bounded and URL-encoded only into the approved URI. Errors stay
at the IDP; advisory `logout_hint`/`ui_locales` cannot select an account.

Confirmation atomically consumes intent, revokes the parent and derived
grants/families, records one encrypted outbox intent per recipient, and deletes
the IDP browser binding. Initial notification attempts run after commit with a
half-request-deadline bound. The lifespan-owned dispatcher continues delivery;
pending or failed notifications cannot allow protected access.

Authlib 1.8's inspected `EndSessionEndpoint` exposes the two-stage interactive
contract and historical non-expiring hint validation. `RpInitiatedLogout` supplies
that flow in a typed async service with explicit cookie/canonical policy.
Signing and signature/registered-claim validation use joserfc; RSA hint
verification and outbox signing are off-thread.

## Back-channel tokens and current trust

Discovery advertises the pinned end-session endpoint, back-channel support, and
sid support. `POST /backchannel-logout` accepts a bounded URL-encoded
`logout_token` and ignores unknown form extensions.

| Element | Closed deployment profile |
| --- | --- |
| Header | RS256, explicit `typ=logout+jwt`, known kid; token-supplied trust locations/keys rejected |
| Identity | Exact configured issuer and one SP-specific audience; required sid; optional sub must match |
| Time | Strict positive integer iat/exp, bounded lifetime, future-issuance check, exact expiry-plus-skew rejection |
| Event | `http://schemas.openid.net/event/backchannel-logout` with a JSON-object value |
| Replay/purpose | Required unique jti; nonce prohibited, including null; ID tokens cannot substitute |

JWKS loading uses the existing issuer-scoped bounded single-flight cache. A valid
signature additionally requires authenticated `private_key_jwt` verification at
the pinned `/logout/introspect` application endpoint. Only the recipient gets an
active result for exact committed logout-purpose issuance, a revoked parent, and
currently unrevoked signing trust. Assertion endpoint substitution/replay,
another SP's inspection, unissued signed tokens, and cached revoked keys fail.
This adds a dependency round trip; outage returns 503 without local mutation so
delivery can recover.

## Atomic SP termination and races

After validation/authority checking, one SP transaction commits matching local
revocation, browser-binding expiry, pending callback/intent removal, immutable
`(issuer, sid)` termination, and immutable `(issuer, jti)` digest/date receipts.

The replay namespace is locked before the federation-session namespace, then
browser rows precede authentication rows. Establishment shares the same
database-owned session lock and checks termination history. A notification before
callback installation fences the already-validated response even without an
authenticated local row. Refresh installation rechecks local revocation/lifetime
after releasing network work.

Exact valid retries return HTTP 200 without repeating effects. A fresh different
sid, including the same user's new session, stays active. Expiry is rechecked after
lock waits. Invalid notifications return 400 without a receipt; commit failure
rolls back termination, replay state, and pending-transaction invalidation together.

Back-channel requests cannot erase another host's browser cookie. Captured or
retained values are unusable server-side; visiting an ended SP creates its own
anonymous binding. Termination and receipts survive restart. These immutable
records conservatively retain replay history; retention cleanup is not part of
this checkpoint.

## Durable delivery and owner recovery

The IDP claims each due intent under the security gate. Active-signer selection,
actual JWT creation, logout-purpose retention, encrypted payload, attempt count,
and lease commit before transmission. HTTP runs outside database locks, over
verified TLS with no redirects and a bounded deadline. Only 200/204 acknowledge
delivery. Acknowledgements are fenced by lease ID; delivered state is terminal.

Cancelled/crashed/lost-ack workers leave durable leases. After expiry, another
worker retries the same still-valid JWT. An expired token or a retired/revoked
signer requires a fresh jti/token under current active trust for the original sid.
Every actual token extends its signer's all-purpose verification deadline.

Network/timeouts, 408/425/429, and 5xx receive capped exponential retries.
Permanent rejection or attempt exhaustion retains `failed`; missing destinations
retain `skipped`. Metadata changes stop obsolete-endpoint delivery. Recovery adopts
current registered metadata, resets the budget, and preserves revocation/replay.

Owner commands inside the IDP's private runtime:

```bash
docker compose exec -T idp /app/.venv/bin/federationctl logout-deliveries
docker compose exec -T idp /app/.venv/bin/federationctl logout-retry --delivery-id DELIVERY_ID
```

Inspection shows the latest 100 IDs, recipients, statuses, attempts, next-attempt
times, and fixed error labels. It exports no JWTs, hints, cookies, or private keys.
Recovery accepts only a failed/skipped bound delivery and gets its URI from live
metadata. The IDP owner supplies role/secret-volume authority; ordinary user/SP
credentials cannot access these commands.

| Setting | Default |
| --- | --- |
| `FID_LOGOUT_POLL_SECONDS` | 1 second |
| `FID_LOGOUT_BATCH_SIZE` | 4 concurrent attempts per batch |
| `FID_LOGOUT_DELIVERY_TIMEOUT_SECONDS` | 2 seconds; lease lasts integer timeout + 5 seconds |
| `FID_LOGOUT_MAX_ATTEMPTS` | 8 per recovery cycle |
| `FID_LOGOUT_RETRY_BASE_SECONDS` / `FID_LOGOUT_RETRY_MAX_SECONDS` | 2 / 60 seconds |
| `FID_POLICY.logout_token_ttl_seconds` | 300 seconds; JWT skew remains 5 seconds |

## Migration and working set

Heads are `idp_logout_11` and `sp_logout_07`. IDP migration adds leased/fenced
delivery and state guards, preserves bound Phase 7 intents, and enables original
uncustomized A/B destinations once. Customized registrations remain intact. Fresh
bootstrap/C metadata includes logout destinations. SP migration adds termination/
receipt tables and an index without changing encrypted authentication/refresh
custody. Unbound prototype payloads remain non-authoritative terminal failures.

| Path under `src/federated_identity/` | Responsibility |
| --- | --- |
| `idp/api/logout.py`, `idp/services/end_session.py` | Browser matching, historical hints, confirmation, literal redirects |
| `idp/services/security_model.py`, `idp/services/oidc.py` | Atomic revocation/intents and authenticated logout-purpose authority |
| `idp/repositories/outbox.py`, `idp/services/logout.py` | Encrypted claims, leases, retention, dispatch, backoff, acknowledgement/recovery |
| `common/security/logout.py` | Purpose-specific signing/validation and strict wire models |
| `sp/api/logout.py`, `sp/services/logout.py`, `sp/services/revocation.py` | Recipient validation and current-trust check |
| `sp/repositories/logout.py`, `sp/repositories/security.py` | Durable replay/termination and callback/refresh fences |
| `sp/api/browser.py`, `sp/services/browser.py` | Local/global controls and encrypted original hints |
| `cli/service.py`, `idp/api/runtime.py`, `cli/logout.py` | Composition, worker lifecycle, private owner commands |

## Exit checks and exact verification

| Phase 8 exit check | Selected evidence |
| --- | --- |
| Global logout ends both SPs | HTTP and Chromium controls; parent/grants, local rows, bindings, receipts, and captured cookies |
| Unavailable SP denies its old session on return | Online authority rejects before retry; real B stops/returns across IDP restart |
| Dispatcher restart recovers pending work | Pending/lost-ack leased reconstruction; real restart and expired-token reissue |
| Retry preserves a new different session | Retries target old sid; same-user fresh A/B remain active across restart |
| Wrong-audience/expired/forged/cross-purpose tokens fail | Crypto positives/negatives, canonical issuance, cached revoked trust, unchanged local/replay state |
| ID token is not a logout token | Actual endpoint returns 400 without a receipt |
| Logout token is not login evidence | Login verifier rejects logout type and absent nonce |

```bash
uv run pytest tests/unit/test_logout_token.py tests/integration/test_logout.py tests/integration/test_logout_upgrade.py -q
# 80 passed in 42.70s

uv run pytest tests/e2e/test_logout.py -q --durations=5
# 1 passed in 133.53s; verified Chromium TLS and injected process time

uv run pytest tests/integration/test_architecture.py::test_durable_outbox_rejects_unbound_legacy_payloads_after_restart -vv --setup-show --durations=5
# 1 passed in 55.75s

uv run pytest tests/unit/test_id_token.py tests/unit/test_refresh_token.py tests/unit/test_jwks_cache.py tests/unit/test_browser_origin.py tests/unit/test_architecture.py tests/integration/test_lifecycle.py tests/integration/test_refresh.py -q
# 121 passed in 56.69s

uv run pytest tests/integration/test_security_model.py -q -k "logout or failed_commit or migrations_preserve or reauthentication or sp_restart or dependency_outage"
# 12 passed, 26 deselected in 25.43s

uv run pytest tests/integration/test_signing_rotation.py::test_both_sp_warm_caches_recover_new_signer_and_old_artifacts_and_sessions_survive tests/integration/test_signing_rotation.py::test_retirement_waits_for_every_signed_purpose_and_exact_skew_boundary tests/integration/test_containment.py::test_active_signer_containment_overrides_cached_signatures_and_survives_restart tests/integration/test_containment.py::test_vetted_forged_token_cannot_create_a_session_without_exact_committed_evidence -q
# 5 passed in 18.03s

make check
# Ruff lint/format checks passed (174 Python files); strict mypy passed for 154 source/test files
```

The 220 count excludes repeated runs. Initial checks corrected two missing-CSRF
requests without form content type (415 instead of the intended 403), and mypy
required explicit GET-params/POST-data branches. A combined 82-case selection with
the browser and final process check reached the 240-second shell deadline without
a completed summary; it is not counted as passing. Successful selections above
provide complete evidence. Historical audit/wheel evidence remains in Phase 2.

```bash
uv run federationctl logout-deliveries --help && uv run federationctl logout-retry --help
# Both owner command parsers passed
```
