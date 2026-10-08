# ADR 0005 — Phase 10 scope cut

## Context

Skipped Phase 10 due to exisiting elements

The implementation covers the six possible-feature categories, both compromise
paths, and the selected logout, refresh/re-authentication, and step-up extensions.
Feature checkpoints already contain positive/negative adversarial, database-race,
restart, and verified-HTTPS/browser evidence. The requested full regression passed
565 tests; that result establishes tested application behavior, not a real-finding
negative control for the dependency scanner.

## Decision and precise boundary

Skip Phase 10's additional attack-defense evidence/security-CI expansion. The
submission does not claim completion of its optional real-finding CI extension.
The omitted deliverables are:

- An isolated deliberately vulnerable manifest pinned to a real published advisory.
- A negative control proving the expected advisory is reported and a finding's
  failing exit status propagates through the pipeline, separately from collection
  or network failures.
- Dedicated machine-readable audit reporting and its evidence/artifact handling.
- A separately consolidated/expanded Phase 10 hostile-flow acceptance package.

This is a final submission scope decision, not a completed checkpoint or a promise
to implement these deliverables during Phase 11. Phase 11 acceptance concerns the
chosen implemented properties and extensions.

## Rationale

Prioritize the application trust decisions the brief emphasizes: recipient-bound
identity, live onboarding/rotation, compromise containment, session termination,
durable state, and genuinely proved authentication. These require coordinated
process/database behavior and explainable failure/race handling; they are the
central security argument of this submission.

The incremental Phase 10 work primarily strengthens assurance about the delivery
pipeline and packages additional evidence. A credible real-finding demonstration
requires an authentic advisory, an isolated vulnerable input, reproducible
collection, checked advisory identity, and tested failure propagation. A nominal
scanner command or synthetic failure would not meet that bar. Within the brief's
bounded scope, choose the implemented, tested federation depth and its review/demo
writeup rather than claiming an unproved additional extension.

## Existing verification and accepted limitation

[The existing workflow](../../.github/workflows/verify.yml) runs lint/format/typing,
pytest, packaging/installed-runtime checks, Compose checks, and `pip-audit` against
locked runtime dependencies. The audit step uses Bash `pipefail` and does not
configure `continue-on-error`, so nonzero audit failures are configured to fail it.
Historical audit results and the manual audit command remain useful evidence.

Those controls do not demonstrate that the expected real vulnerability/advisory
will be detected and correctly reported end to end. Scanner/input/configuration
drift could create false confidence in a green result, and finding-specific failure
handling has no negative-control acceptance evidence. The submission owns that
unverified pipeline assurance rather than treating test count or a clean scan as
proof of it.

Existing login-CSRF, code-injection/PKCE, replay, cross-recipient/cross-purpose,
forged-evidence, and redirect defenses are implemented and tested under their
feature checkpoints. Skipping their Phase 10 evidence expansion does not imply
exhaustive attack coverage; the claims remain the scenarios actually executed.
The mandatory typed/layered/async code standards and security of the shipped
features remain part of acceptance.
