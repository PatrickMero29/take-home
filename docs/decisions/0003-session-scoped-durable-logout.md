# ADR 0003 — session-scoped durable single logout

Status: accepted on 2026-10-07; implemented in [Phase 8](../phase8.md).

## Context

The IDP and SPs have separate databases/cookies. Authoritative grant checks already
enforce revocation, while logout notifications must recover network failure,
process loss, short JWT expiry, and callback/refresh installation races. Routine
key retirement differs from emergency revocation, and a valid cached signature
alone cannot establish current artifact authority.

## Decision

1. Require current IDP browser matching and an independent one-use confirmation
   for RP-Initiated Logout. Historical ID tokens identify exact issued context;
   they confer no user/admin principal. Seal and recheck literal registered return
   paths and metadata versions.
2. Commit parent/grant/family revocation and one encrypted recipient intent in the
   same security transaction. Protected access is denied from that commit onward.
3. Sign when claiming delivery. Current signer selection, actual logout-purpose
   retention, encrypted JWT, attempts, and lease commit together before HTTPS.
   Recover an abandoned lease with the same valid JWT or fresh signed evidence
   for the original sid when expiry/containment requires it.
4. Fence acknowledgement by lease ID, cap automatic backoff/attempts, and retain
   failed/skipped work for IDP-owner recovery from live registered metadata.
5. Require the explicit logout+jwt/event/no-nonce profile and a separate
   SP-authenticated exact-current-issuance check. This extends existing cached-key
   compromise defenses to logout-purpose artifacts.
6. Match `(issuer, sid)` and atomically commit local revocation/binding expiry,
   pending-work invalidation, termination history, and `(issuer, jti)` receipts.
   Share the database session lock with establishment. Exact retries acknowledge
   committed effects; a different sid stays independent.

## Consequences and evidence

The protocol adds a current-trust round trip and a lifespan-owned dispatcher.
Dependency unavailability preserves queue/local state and blocks protected access.
Notification completion does not gate revocation or recall previously authorized
in-flight work. Global logout concerns the matched federation session; other
browser sessions have independent sids. Replay/termination history is retained
conservatively and session identifiers are never reused.

Selected tests challenge atomic rollback/publication, stale leases, lost
acknowledgements, cancellation, expired-token reissue, live destination changes,
cached revoked trust, and callback/refresh races. The real HTTPS/Chromium scenario
stops B, restarts the dispatcher, and preserves fresh different A/B sessions under
recovered/replayed notifications. Exact commands/results are in the checkpoint.
