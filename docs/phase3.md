# Phase 3 — session lifecycle and authoritative revocation

Status: implemented and verified on 2026-10-06; **49 selected cases pass** and
`make check` passes. This checkpoint connects the
persisted lifecycle model to browser controls, client-authenticated revocation,
and authenticated authorization-code replay containment.

## Controls and request flows

| Service / endpoint | Effect |
| --- | --- |
| SP `GET /auth/logout` | Show a local, one-use confirmation form; requires only the SP's own persisted cookie |
| SP `POST /auth/logout` | Revoke that local session, expire its browser binding, discard pending callbacks/intents, and clear the cookie after commit |
| SP `GET /auth/revoke`, `POST /auth/revoke` | Confirm the current grant, then authenticate the owning SP to the IDP's `/revoke`; end the local session after acknowledgement |
| IDP `GET /logout`, `POST /logout` | End the current IDP session and its derived grants/families, retain logout delivery intents, and delete the IDP browser binding in one transaction |
| IDP `GET /grants`, `POST /grants/revoke` | List only the current IDP session's grants and revoke the server-selected recipient's grant/family |
| IDP `POST /introspect` | Fresh, authenticated, recipient-scoped access and exact issuance check |
| IDP `POST /revoke` | Authlib revocation client authentication with exact endpoint audience; owning-token grant/family revocation before a non-disclosing HTTP 200 response |

Root pages link to the confirmation controls. GET never terminates a session.
POST accepts only `csrf`; identity, grant, session, and return-path parameters
cannot select an action target. The target and purpose are chosen by the server
and sealed in its own database.

Local logout preserves IDP SSO and other SPs. It remains available while the IDP
is down, provided the SP database is healthy. Ending the IDP session blocks both
SPs at their next authoritative authorization check. A selected grant revocation
affects only that grant; future legitimate SSO can create a new one.

## Storage, security boundaries, and edit points

- `common/persistence/actions.py` and `common/security/actions.py` supply hashed
  one-use browser/purpose-bound challenges, encrypted targets, and bounded expiry.
  Consumption participates in the caller's database transaction. Wrong-browser,
  wrong-purpose, expired, or transplanted challenges establish no authority.
- `common/security/browser.py` requires HTTPS and the owning service's serialized
  Origin, rejects ambiguous/unsupported fields, and clears only its host-only
  cookie. Confirmation pages use same-origin referrer policy so Chromium supplies
  that Origin. Their form actions and final redirects stay local.
- `idp/services/browser.py` re-resolves the current persisted principal inside
  the IDP security gate. A user can affect only its actual session and grants.
  Session/event/grant references and JWT hints never provide operator authority.
- `idp/services/security_model.py` supplies caller-owned `end_session_in()`,
  `revoke_grant_in()`, and `revoke_token_in()`. Revocation covers the grant's access
  and refresh family, including a consumed/expired refresh credential. Ownership
  is checked before state changes, independently of a type hint.
- `idp/protocol/authlib_adapter.py` uses Authlib's RFC 7009 endpoint authentication
  and the existing strict `private_key_jwt` validator. Token, introspection, and
  revocation assertion audiences are distinct; valid assertions reserve durable
  client-scoped `jti` state.
- `sp/services/revocation.py` performs verified-HTTPS, request-local authenticated
  revocation. Dependency failure preserves local state; the consumed intent must
  be replaced before retrying. A successful remote revocation takes effect even
  if a later local cleanup request fails.
- `sp/repositories/security.py` locks the browser binding before establishment or
  logout. Rotation/logout preserve authenticated tombstones while expiring the
  old browser row and deleting pending transactions/intents. A callback paused
  across logout cannot publish a fresh cookie for its invalidated initiator.
  Local lifecycle reads share the caller's session rather than acquiring another
  pool connection under a lock.

Paths above are relative to `src/federated_identity/`. Current migration heads
are `idp_lifecycle_06` and `sp_lifecycle_05`. Both databases have `browser_actions`;
key enrollment verifies their envelope purpose. The SP migration forbids browser
lifetime extension; the IDP migration retains consumed authorization proofs.

## Expiry and authorization

| Policy | Default | Enforcement |
| --- | --- | --- |
| IDP browser storage | 1,800 seconds | Cookie lookup expiry, bounded by its IDP parent |
| IDP security session | 3,600 seconds | Absolute expiry; reauthentication appends history without extending it |
| Grant / refresh family | 3,600 seconds | Parent-bounded, checked at issuance, introspection, and revocation-sensitive authorization |
| SP authenticated session | 3,600 seconds | Grant/family/IDP ceiling, immutable absolute expiry |
| SP idle window | 900 seconds | Checked before network work; successful authorization atomically touches activity within the absolute ceiling |
| Access credential | Up to 300 seconds | Checked against current authoritative state; no refresh flow is enabled yet |
| Lifecycle confirmation | Up to 300 seconds | Bounded by browser/session lifetime; one-use |

Session checks reject at the exact server expiry boundary; JWT clock skew never
extends a browser session. A cookie retained by the browser is insufficient.
Expired/revoked bindings receive a fresh anonymous identifier before a new login.
Authentication rotates into a new opaque identifier and invalidates its predecessor.

Every protected SP request performs fresh authenticated introspection and exact
recipient/issuer/subject/event/evidence checks. IDP or database outages yield
unavailable responses without deleting otherwise-valid sessions. Recovery uses
the persisted state. Already-authorized in-flight work cannot be recalled.

## Authorization-code replay containment

Code consumption is retained with the original client, callback, S256 challenge,
authentication event, and committed issuance/grant link. A consumed code is still
examined after its initial 60-second issuance lifetime, while its derived grant
may remain usable.

The token endpoint first authenticates the client, validates the exact original
callback, and lets Authlib check the PKCE verifier. Only a successful owning-client
proof identifies an authenticated replay. That grant/family is then revoked and
the `invalid_grant` response is published after commit. Another client, a missing
or incorrect verifier, a changed callback, or an invalid/replayed client assertion
cannot weaponize a captured code to revoke the rightful grant.

Unexpected commit failure rolls back both containment and assertion reservation;
the original issuance stays usable until a committed valid replay or other
revocation. The code can never produce another issuance.

## Exit-check evidence

| Required guarantee | Selected evidence |
| --- | --- |
| Captured cookie fails after local logout | Local logout/pending-callback integration case; real Chromium controls; authenticated tombstone restart test |
| Server expiry wins over retained cookies | Clock-driven idle, absolute, parent, grant, and access expiry cases; existing exact idle/absolute tests |
| IDP termination blocks A and B | IDP logout integration case; Chromium termination followed by SP B process restart |
| A cannot inspect/revoke B's grants | Wrong-client `/revoke` and introspection checks; user-session-bound grant controls; consumed-refresh ownership test |
| Dependency failure blocks access and recovery preserves state | Injected IDP outage plus actual PostgreSQL stop/start, with cookies preserved; remote-revocation outage and offline local logout |
| Active and revoked state survives restart | Rebuilt deployment factories/pools with pending confirmations, active sessions, and revoked cookies; real SP process restart |

Additional checks exercise purpose/origin/browser/expiry CSRF binding, rollback
and retry of local/IDP logout, concurrent consumption, authenticated replay after
code expiry, replay-containment commit failure, proof retention, and a callback
paused after token exchange while local logout commits.

## Verification commands and observed results

These are targeted runs, not a full regression run. The lifecycle module shares
one TLS PostgreSQL deployment and uses the injected Clock; the browser scenario
starts one three-process HTTPS deployment.

```bash
uv run pytest tests/integration/test_lifecycle.py -q
# 32 passed in 27.66s

uv run pytest tests/e2e/test_lifecycle.py -q
# 1 passed in 72.87s; verified HTTPS/Chromium, independent services

uv run pytest tests/integration/test_security_model.py::test_revocation_of_consumed_refresh_is_owner_scoped_and_ends_the_whole_family -q
# 1 passed in 3.09s
```

The affected existing protocol/lifecycle selection also passed: **15 cases in
19.97 seconds** using the exact selected node IDs below.

```bash
uv run pytest tests/integration/test_protocol.py::test_pkce_oidc_and_private_key_jwt_round_trip tests/integration/test_protocol.py::test_concurrent_code_redemption_has_one_issuance tests/integration/test_protocol.py::test_original_redirect_uri_is_bound_even_when_both_are_registered tests/integration/test_protocol.py::test_missing_or_wrong_verifier_rejected tests/integration/test_protocol.py::test_code_expiry_uses_issuance_time_and_is_enforced tests/integration/test_security_model.py::test_migrations_preserve_bound_facts_and_separate_service_storage tests/integration/test_security_model.py::test_logout_atomically_revokes_lineage_with_one_encrypted_intent_per_recipient tests/integration/test_security_model.py::test_logout_outbox_failure_rolls_back_every_revocation tests/integration/test_security_model.py::test_local_logout_during_remote_check_wins_without_holding_a_network_lock tests/integration/test_security_model.py::test_sp_exact_idle_and_absolute_expiry_are_server_enforced tests/integration/test_security_model.py::test_sp_restart_preserves_active_and_revoked_cookies_and_db_lifetime_guard tests/integration/test_security_model.py::test_reauthentication_changes_one_sp_event_without_elevating_other_sessions tests/integration/test_security_model.py::test_account_substitution_during_idp_and_sp_reauthentication_is_rejected -q
```

Normal lint/format/type verification uses `make check`. Packaging, audit, and
deployment probes are selected when their corresponding inputs change; the
Phase 2 full-suite/audit/wheel results remain historical checkpoint evidence.
The observed `make check` run passed Ruff lint/format for **128** Python files
and strict mypy for **115** source/test files. The full pytest suite and long
package/deployment/audit proofs were not rerun for this checkpoint.

## Exercise manually

Start the system and sign in at A and B using [runtime instructions](runtime.md).
Use **Sign out locally** at A: its old cookie fails, B still works, and A can use
the existing IDP SSO session. Use **Revoke application access** at A to exercise
the client-authenticated revocation endpoint. On the IDP, **Manage application
access** revokes a selected grant; **End IDP session** blocks both SPs on their
next protected request.

The existing outbox records termination intent atomically. OIDC RP-initiated and
back-channel logout delivery/token processing follow Phase 8.
