# ADR 0004 — atomic real password/TOTP step-up

Status: accepted on 2026-10-07; implemented in [Phase 9](../phase9.md).

## Decision

1. Provision stable independent factors for seeded subjects, with subject-bound
   encrypted database custody and an owner-private encrypted bootstrap envelope.
   Upgrade bundles once and preserve factor/counter state on normal initialization.
2. Require password and TOTP in one browser-bound submission for stronger proof.
   Verify Argon2id outside locks, then recheck its snapshot and subject under the
   security gate. PyOTP performs matching using the injected Clock.
3. Lock a durable factor high-water mark and commit accepted-step/event history,
   immutable stronger authentication and opaque browser rotation together.
   Recheck code validity before consumption. Reject old or concurrent reuse.
4. Reserve durable source/browser/account budgets before password work and retain
   a per-continuation attempt/deadline bound. New forms and worker restart cannot
   reset guessing limits; source identity comes from the real connection peer.
5. Bind RP step-up to its existing cookie/grant and retain requested minimum,
   expected subject and time. Enforce actual returned methods/assurance/time and
   canonical issuance before rotating that SP's session.
6. Recheck independent assurance/recency and local lifecycle at sensitive commit.
   Refresh preserves historical proof; a sibling's established event is independent.

## Consequences and evidence

Factors are reusable enrollment secrets, intentionally exported only through the
explicit IDP-owner provisioning command. Budget exhaustion can temporarily limit
legitimate repeated login; sensitive recency and replay are enforced without real
time sleeps. Counter/receipt history is retained conservatively with normal
database/secret backup. Sensitive approvals demonstrate a committed protected
operation with immutable encrypted authorization evidence.

Selected tests cover invalid factors/credentials, concurrent and restarted replay,
drift high-water, ciphertext/enrollment preservation, form/account/source budgets,
rollback, expiry during event creation, logout versus pending proof, callback
downgrade, and sensitive recency at commit. Actual Chromium/TLS uses enrolled
owner CLI provisioning and requires fresh proof after renewal leaves MFA stale.
