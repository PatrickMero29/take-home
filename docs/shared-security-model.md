# Shared security model

Section 2 of [the plan](../plan.md) supplies typed policy and persisted lifecycle
operations on the deployed IDP/SP architecture. The composition roots install
`IdpSecurityModel` and `SpSecurityModel` supply internal service boundaries.
The [Phase 0 revisit](phase0.md) now connects code issuance, authenticated
introspection, and RP evidence binding to those operations.
The [Phase 2 browser layer](phase2.md) now supplies verified password events and
commits IDP browser binding with session/event creation. SP callbacks use the
same exact-evidence enforcement to establish independent local sessions.
The [Phase 3 lifecycle layer](phase3.md) now supplies one-use browser controls,
authenticated token revocation, and correctly proven code-replay containment.
The [Phase 4 operator layer](phase4.md) checks separate credential-backed
authority and serializes live registration/audit/key history with the same gate.
The [Phase 5 signing layer](phase5.md) restores persisted active material,
publishes prepared trust, and accounts for every signed purpose under that gate.
The [Phase 6 containment layer](phase6.md) exposes both scoped revocation paths
through operator controls and separates registry recovery from owner key custody.
The [Phase 7 renewal layer](phase7.md) wires rotating refresh into the protocol,
preserves original immutable lineage, and adds separate signed renewal evidence.
The [Phase 8 logout layer](phase8.md) confirms the current browser, joins durable
delivery with revocation, and supplies exact logout-purpose trust and SP sid/replay fences.
The [Phase 9 proof layer](phase9.md) supplies actual password/PyOTP events,
transactional accepted-step history, persistent budgets and sensitive SP enforcement.

## Identity and lineage

```text
SubjectIdentity = (exact HTTPS issuer, opaque subject)
  IDP session: immutable identity, creation time, absolute expiry
    Authentication event: immutable event ID, auth_time, verified methods, assurance
      Recipient-specific federation grant
        Original ID-token evidence: jti, digest, signing key, issuance/expiry
        Access credentials: one-way verifiers, grant/family references, expiry
        Refresh family: fixed lifetime, current generation, revocation
          Refresh credentials: one-way verifiers, generation, consumption tombstone
        SP-local authenticated session: bound evidence, encrypted credentials,
                                        fixed absolute expiry, renewable idle expiry

Logout intent = (issuer, IDP session ID, recipient client ID)
```

The same subject string under another issuer is another identity. A grant's
event belongs to its parent session; its evidence belongs to that grant and
signing key; its access credentials belong to the same grant and family.
Composite foreign keys enforce those relationships in the IDP database.
SPs retain references and evidence in their own databases, not IDP table access.

`AuthenticationEvent` and `LoginEvidence` describe historical facts.
`GrantSnapshot` is an immutable snapshot containing both those facts and current
authorization state. Possessing a snapshot does not establish current authority:
the SP makes a fresh authenticated grant check when establishing a session and
on each protected authorization.

## Trusted inputs and artifact purposes

- `TrustedAuthentication` is supplied only after an IDP-side authenticator has
  verified credentials. It is never constructed from a browser's requested
  `acr`, incoming JWT claims, or an OTP counter match alone.
- Assurance is derived from verified methods: `pwd` gives password assurance;
  `pwd` plus `otp` gives password/TOTP assurance. Fixture events have their own
  class and cannot satisfy either real assurance requirement.
- IDP model methods receive client identities already authenticated at the
  protocol boundary. Operator actions require separately authenticated and
  authorized operator callers; current account, credential epoch, channel, and
  registry/signing permission are checked on every control-plane operation.
- The RP's `verified_login_evidence()` performs the existing joserfc/Authlib
  signature, issuer, single-audience, nonce, time, type, and `at_hash` validation.
  Its event ID must come from authenticated authoritative lineage, not browser
  input. `SpSecurityModel.establish()` / `establish_login()` compare the exact evidence with
  committed IDP issuance, so a valid signature alone is insufficient.
- Access tokens are generated before their `at_hash`-bound ID token is signed.
  `issue_grant()` records that exact access/evidence pair; it does not replace
  the protocol's access token after signing.

`ArtifactPurpose`/`ArtifactUse` specify allowed uses independently of crypto
validation. ID tokens support recipient-specific login evidence and the
explicit logout-hint return path. Codes support owning-client redemption at
the IDP. Client assertions, access/refresh tokens, logout tokens, IDP cookies,
and SP cookies each have separate purposes. None is an operator credential;
returning an artifact to the IDP grants no unrelated user/admin authority.
See [the artifact contracts](artifact-contracts.md) for the wire profile.

## Lifetime and assurance policy

`RuntimeSettings.lifecycle` holds validated `LifecyclePolicy` values:

| Lifetime | Default | Ceiling |
| --- | --- | --- |
| IDP session | 3,600 seconds | Fixed at session creation |
| Federation grant | 3,600 seconds | Parent IDP session expiry |
| Refresh family | 3,600 seconds | Grant expiry |
| SP session | 3,600 seconds | Grant, family, and IDP session expiry |
| SP idle timeout | 900 seconds | SP absolute expiry |

Access-token lifetime remains 300 seconds under `ProtocolPolicy`, clamped to
grant/family expiry. Authorization rejects at the exact absolute/idle expiry;
JWT-validation clock leeway does not extend server-side sessions.

Refresh advances the family's generation and issues new opaque credentials.
It preserves the original event, subject, methods, assurance, evidence, and
parent lifetime ceilings, including after the original login JWT expires.
It cannot make a stale MFA event recent. `AuthenticationRequirement` independently
checks minimum assurance, maximum authentication age, and an optional earliest
acceptable authentication time.

Reauthentication appends a new verified event for the same issuer/subject and
does not rewrite the old event or extend the IDP session. An SP can replace its
local session with the new event and a new cookie; another established SP's
event remains unchanged. The credential-backed browser continuation honors
`prompt=login`/`max_age=0` through actual fresh proof, rather than treating
issuance or refresh as proof. SP-facing controls now retain prompt/max_age/time,
validate returned freshness, and rotate only the selected same-subject session.

## Authoritative state transitions

| Operation | Committed effect |
| --- | --- |
| Open session | New absolute-lifetime session and verified event |
| Reauthenticate | New event, same identity and unchanged parent lifetime |
| Password/TOTP step-up | Verified password snapshot and fresh matched factor; counter consumption, stronger event and binding rotation commit together |
| Reserve authentication attempt | Durable source/browser/account budgets before password work; fresh forms cannot reset the account limit |
| Sensitive SP approval | Current grant plus actual stronger/recent local event; one-use intent and encrypted immutable operation evidence |
| Issue grant | Enabled recipient, active signer, matching stored event, immutable evidence and hashed credentials |
| Check access | Current credential, parent session/grant/family, client enablement, and signing trust |
| Rotate refresh | Owner checked before reuse; old credential consumed once; generation advances atomically |
| Publish refresh evidence | New signed generation bound to exact access/successor/predecessor; original event/evidence unchanged |
| Detect refresh reuse | Grant and family revoked; containment commits before replay rejection |
| End IDP session | Session, derived grants/families revoked; one encrypted logout intent per recipient in the same transaction |
| Claim logout delivery | Current signer, actual purpose-specific JWT, retention, encrypted payload, attempt and fenced lease commit before network |
| Check logout token | Authenticated recipient, exact committed logout issuance, revoked parent, and currently unrevoked signing trust |
| Terminate SP federation session | Issuer/sid matches revoked; bindings/pending transactions invalidated; termination and replay receipt committed together |
| Disable client | That client's interactions and grants/families disabled; other clients remain usable |
| Contain compromised client | Disable, capture current key, invalidate old approvals, revoke scoped authority; require replacement before enable |
| Revoke signer | Affected evidence-linked grants/families revoked; unrelated signing lineage remains usable |
| Contain signer | Activate a distinct published replacement when needed, revoke target/grants/families, and record replacement-aware audit atomically |
| Revoke own token/grant | Ownership checked before mutation; that grant/family revoked without ending another recipient or parent session |
| Authenticate consumed-code replay | Original client/callback/PKCE proof checked before linked-grant containment; rejection follows commit |

Signing trust progresses `prepared → active → draining → retired`, with
revocation available from every state and terminal once set. A partial unique
index permits one active signer. Each signed artifact raises its signing key's
verification deadline; retirement waits for that deadline plus protocol skew. Draining and
retired keys remain valid historical evidence for established grants. Emergency
revocation is different: authoritative checks deny that lineage even when an SP
still has the public key cached.

Phase 5 wires `rotate_trust_in()` / `retire_trust_in()` into explicit operator
controls, with publication and expected-active/deadline checks. Public JWKS
records irreversible publication before prepared-key activation. The request-local
adapter selects actual active private material inside the issuance savepoint.
`record_signed_artifact_in()` commits bounded purpose/recipient/expiry history
and advances retention with canonical issuance; the migration backfills existing
ID-token evidence. Phase 8 logout signing/reissue joins the same generic ledger.

Issuer-scoped SP caches pin the JWKS URI and RS256, validate bounded public-only
responses, and single-flight loads. Unknown IDs share one cooldown rather than
allocating individual negative entries. Strict unverified headers supply only a
kid hint; signature/purpose/claims and authoritative evidence remain mandatory.

`disable_client_in()` and `revoke_signer_in()` join operator-owned gated work.
The client compromise marker cannot be cleared or enabled with the same key;
append-only credential history prevents replacement with previously used material.
New credentials do not enable a client or revive old grants. Key containment can
reuse a distinct active signer for historical compromise, and activation of a
prepared replacement shares revocation's transaction. Parent IDP password sessions
and unrelated signing/client lineage remain independently valid.

SP authorization is denied by current authority even if its local row/cookie is
retained. Disabled client authentication fails closed; after credential recovery,
introspection still reports the original grants/families revoked. Signatures
alone, including attacker-minted jti/subject claims, cannot create local authority.

## Transactions and concurrency

IDP model transitions lock the singleton `security_gate` row with `FOR UPDATE`
before reading/changing lifecycle state. This includes authoritative access
checks, giving each check a coherent decision point relative to revocation.
Transactions contain database work and bounded in-memory crypto only; no
network operation or user interaction occurs under the gate.

The gate provides simple, auditable serialization for this take-home; it is also
a throughput bottleneck. Future refinement to narrower locks must preserve the
same issuance/refresh/revocation ordering. Model operations publish success only
after commit. Replay containment deliberately commits before raising its typed
denial; unexpected failures roll back all effects.

Database triggers prohibit rewriting authentication/issuance facts, extending
absolute lifetimes, clearing revocation/consumption tombstones, changing signing
key identities, shrinking retention, or reversing signing-state transitions.
Phase 5 also protects encrypted signing material, signed-artifact/audit history,
and irreversible publication against direct SQL mutation.
Phase 6 guards captured client credentials against enable/marker-reset bypass.
SP triggers likewise protect authentication evidence and absolute lifetime.
Phase 8 guards immutable SP termination/receipts and acknowledged outbox delivery.
SP establishment and notification share database issuer/sid locks before browser/
authentication rows. A pre-install notification records termination even without
an existing local session. Network work remains outside local and IDP locks.

The SP releases its local read before awaiting the remote grant check. After
validation it atomically checks/touches the local row; concurrent local logout
wins over that touch. Temporary dependency failure raises `GrantUnavailable`
without deleting or refreshing otherwise-valid local state. Recovery can reuse
that state if its lifetimes and authoritative grant still permit it.

Revocation affects subsequent decision points. Already-authorized in-flight
work cannot be recalled; notification delivery is not an authorization gate.

## Storage and notification custody

The IDP stores only SHA-256 verifiers of high-entropy access/refresh credentials.
SP cookies are also hashed. SP authentication evidence and recoverable access/
refresh credentials are encrypted with distinct envelope purposes and each
SP's own encryption key. Identity/event/trust metadata remains readable to its
own database role; private keys and recoverable credentials are not stored as
plaintext in these tables.
Code-only Phase 2 sessions have no issued refresh credential, represented by a
nullable encrypted-refresh column. Model-level refresh sessions retain their
existing encrypted custody.

The IDP's `signing_key_material` holds immutable `issuer-signing-key` envelopes.
Startup checks decryption, key ID, and exact public identity for prepared/active/
draining material. The unchanged volume identity permits initial enrollment;
rotated active trust is restored from persistence. Private caches accelerate
crypto but never choose authority without the database's current active decision.

SP owner recovery uses `client-identity.enc` with service-bound authenticated
encryption purpose `sp-client-identity`. A file lock and expected-kid check
serialize replacement; atomic installation and startup validation preserve
private/public binding. Bootstrap preserves that override and existing database/
TLS/wrapping custody. The recovered process uses its new key after restart.

Logout intents carry encrypted recipient-specific payloads and unique
`(session_id, client_id)` delivery identities. Missing registered delivery URIs
retain `skipped` intent without preventing authoritative revocation. Claims seal
actual signed tokens under `logout-delivery` and commit retention/leases before
HTTP. Bounded retry and lease fencing recover failures; terminal delivery remains
acknowledged, while failed/skipped work supports explicit owner recovery.

SP original hints remain sealed in immutable authentication payloads. Historical
hint verification permits expired ID tokens and routinely retired public trust
only for the exact issued context; active-session effects still require the
matching IDP browser and one-use intent. Back-channel artifacts have their own
profile and authenticated current-issuance check. Immutable issuer/sid termination
and issuer/jti digest receipts make retry idempotent without affecting new sids.

Phase 7 hashes protocol refresh values and adds immutable predecessor and signed
generation records. Introspection preserves the original context and returns the
exact access credential's new evidence separately. Signer containment covers both
root and renewal signatures. SP payloads seal original nonce/family identity and
recoverable refresh credentials, with durable attempt/generation/ambiguity state.
Claims/installation use short local transactions around verified HTTPS; no local
lock spans the dependency. Unknown results require a fresh session instead of
clearing the ambiguity barrier or retrying a consumed token.

## Verification and next checkpoint

The Section 2 baseline passed 168 tests. After Phase 0 integration on
2026-10-06, **192 tests passed**, including the shared-model, protocol,
real-process, database-isolation, and Chromium checks. Strict mypy passed for
85 source/test files; Ruff lint and formatting passed for 92 Python files.
The three-process HTTPS/database-TLS protocol proof passed for both SPs, with
persisted browser-bound transactions and authenticated canonical lineage.
The locked production dependency audit reported no known vulnerabilities.

The focused checks comprise 38 policy/adapter tests and 37 actual-PostgreSQL
model/migration tests. They exercise immutable facts, composite bindings,
exact expiry, refresh preservation/ownership/replay, concurrent containment,
routine retirement, compromised-key caching, atomic outbox rollback, failed
and paused commits, encrypted storage, pool reconstruction, account continuity,
SP-specific assurance elevation, and dependency outage/recovery. Forged JWTs
are signed with vetted libraries and paired with legitimate positive controls.

```bash
uv run pytest -q tests/unit/test_security_model.py tests/integration/test_security_model.py
```

Phase 0 integration is complete: trusted provider events are matched against
canonical session/event records, and code consumption, assertion replay,
signing trust, issuance evidence, and grant creation share one gated unit of
work. `issue_grant_in()` and `check_access_in()` join that caller-owned
transaction. An issuance savepoint preserves valid client replay reservations
on later policy denial; a deferred constraint requires complete protocol/grant
linkage at commit. Authenticated introspection and RP exchange bind the exact
committed evidence. See [ADR 0002](decisions/0002-unified-protocol-security-transaction.md).

Phase 2 now connects seeded-user authentication and browser SSO to these
verified boundaries. Guests use anonymous browser storage; credential-backed
IDP sessions and validated SP callbacks establish authenticated identities.
The separate Phase 0 verifier retains its labelled fixture event. Phase 3 now
provides user-facing session termination and revocation controls.

Phase 3 completes those controls. Cookie/purpose-bound encrypted targets and
one-use CSRF intents join the lifecycle transaction. A revoked browser binding
cannot authorize a pending callback, and its absolute expiry cannot be extended.
`end_session_in()`/`revoke_grant_in()`/`revoke_token_in()` join the existing gate.
The Phase 3 evidence records selected cases, injected-clock expiry, actual
PostgreSQL recovery, and a real-process Chromium lifecycle scenario. Routine
development now uses the targeted verification policy in `AGENTS.md`.

Phase 5 records **58 distinct selected passing cases** for live publication,
rotation, public/private separation, bounded caches, all-purpose retention,
immutable signing history, migration backfill, and affected model/issuance
contracts. Real verified-HTTPS/Chromium preserves both SP processes and existing
sessions through rotation, then restores active/draining trust after IDP restart.
See [the checkpoint](phase5.md) for exact commands and the startup-window correction.

Phase 6 records **44 distinct selected passing cases** covering both live incident
paths, cached-key/unissued-evidence rejection, owner custody and writer races,
rollback, issuance/refresh containment races, and affected operator/migration
contracts. A single verified-HTTPS/Chromium scenario executes owner recovery,
preserves B during A's incident, rejects captured credentials/cookies, and restores
replacement/revoked trust across real SP/IDP restart. [Phase 6](phase6.md) records
exact selections/results and the endpoint-status test correction.

Phase 7 records **133 distinct selected passing cases** for wire rotation/reuse,
owner isolation, single-flight claims, cancellation/loss/install recovery,
parent/idle expiry, renewal-key containment, real password proof, subject/freshness
and intent binding, and affected canonical/lifecycle/migration guarantees.
Verified TLS/Chromium advances an injected process Clock for A/B renewal and
selected-SP re-authentication, then renews across actual SP/IDP restart.

Phase 8 records **220 distinct selected passing cases** covering browser/purpose/
return-path matching, current logout trust, encrypted leased delivery, fenced
acknowledgement, expiry/reissue, callback/refresh races, replay, rollback, migration,
and affected lifecycle/renewal/signing contracts. Chromium stops B, restarts the
dispatcher, and preserves fresh different sessions under recovered/retried
notifications. [Phase 8](phase8.md) records exact commands and results.

Phase 9 records **252 distinct selected passing cases** for actual stronger proof,
replay/concurrency/restart, factor/bundle/enrollment preservation, attempt budgets,
immutable event/counter binding, callback minimum/subject/time, sensitive commit
recency and rollback, and affected authentication/session/logout/renewal contracts.
Chromium invokes owner provisioning, rejects bad/replayed codes, preserves sibling
assurance, and requires new proof after refresh leaves MFA stale. [Phase 9](phase9.md)
records exact selected commands, results and library responsibilities.
