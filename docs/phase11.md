# Phase 11 — full-system acceptance and documentation

Completed for the selected implementation scope on 2026-10-07. **84 distinct
selected cases pass**, including integrated verified-HTTPS/Chromium and both
compromise paths. Lint/format/strict typing and fresh isolated installed-wheel
probes pass. Phase 10 remains the explicit [scope cut](decisions/0005-phase10-scope-cut.md).

## Integrated acceptance

`tests/e2e/test_system_acceptance.py` uses one fresh PostgreSQL/TLS deployment,
independent IDP/A/B/C processes, an isolated Chromium CA profile with HTTPS errors
enabled, and injected process time. It verifies:

1. Current IDP/SP migration heads, stable bootstrap identities, and idempotent
   reinitialization from the current runtime.
2. Password SSO at A/B; initially unregistered C fails, then live authenticated
   onboarding succeeds without IDP restart.
3. Signing preparation/publication/activation, ordinary old-key retirement, and
   established-session continuity.
4. Normal A/C renewal under rotated trust preserves subject/time. B's durable
   refresh claim rotates at the IDP but loses local installation; SP/database
   restart retains the claim, blocks resend, and requires fresh authorization.
   The original family advances only once and is not falsely replay-contained.
5. Database shutdown returns fail-closed unavailability. Restart recovers valid
   persisted sessions. A, B, C and IDP restart independently with current signing,
   registration, session and encryption custody preserved.
6. Actual password/TOTP step-up and sensitive approval at A, with established B/C
   retaining their own password events. Refresh does not make MFA recent.
7. Global logout includes newly registered, offline C. Current authority rejects
   its old session before delivery; dispatcher restart recovers due work, exact
   retry is idempotent, and database/C restart never restores the ended sid.

The separate real-process containment scenario verifies encrypted owner-side SP
key deployment/restart, old-credential rejection, unaffected B, cached-key signer
containment and durable recovery. Secrets in new acceptance snapshots use
`SecretStr`; reports and docs contain no reusable captured values.

## Restart, replay and race coverage

| Acceptance item | Executed evidence |
| --- | --- |
| IDP/A/B/C individual restart; PostgreSQL restart | Combined browser scenario; current migrations and live metadata restored |
| Active vs expired/revoked sessions after infrastructure/factory reconstruction | `test_system_acceptance.py::test_expired_revoked_and_active_sessions_keep_their_state_across_all_restarts` |
| Consumed code and refresh history after restart | `test_system_acceptance.py::test_consumed_code_and_refresh_replay_proofs_survive_infrastructure_restart` |
| Abandoned refresh recovery | Combined B claim/IDP rotation lost installation; family generation remains one and fresh authorization recovers |
| Pending/lost-ack logout recovery | Combined offline-C dispatcher restart; `test_logout.py::test_lost_ack_restart_and_stale_worker_are_fenced_while_exact_retry_is_idempotent` |
| Refresh vs logout | `test_logout.py::test_notification_racing_verified_refresh_prevents_installation_without_network_locks`; refresh containment `logout` case |
| Issuance vs client disabling/containment | `test_containment.py::test_issuance_and_refresh_racing_containment_cannot_restore_revoked_authority[client]` |
| Rotation vs signing | `test_signing_rotation.py::test_rotation_and_concurrent_issuance_share_one_active_signer_decision` |
| Key revocation vs refresh | Refresh containment `key` case; issuance/refresh containment `key` case |
| Step-up vs session revocation | `test_step_up.py::test_logout_while_password_proof_is_pending_cannot_consume_otp_or_create_an_event` |
| Async bridge and publication/rollback | Four selected `test_transactions.py` cases, including real database wait and failed signing/commit |

All referenced race/replay checks use real PostgreSQL and injected Clock rather
than real lifetime waits. The accepted contract remains revocation at subsequent
authorization decisions; already-authorized in-flight work cannot be recalled.

## Corrections caught during acceptance

- A cold asyncpg connection after database shutdown can expose `OSError` before
  SQLAlchemy wraps a DBAPI operation. The shared browser boundary now maps that
  dependency error to the same session-preserving 503 contract. Pool pre-ping
  replaces stale connections on infrastructure return. The lifecycle check now
  forces cold pools as well as real database stop/start; integrated restart passes.
- Redirected `make export-ca` previously included Make's recipe echo. The recipe
  is now quiet, and a command-output test proves stdout contains only certificate
  bytes. This format check uses a Docker stand-in; generated runtime certificates
  are independently trusted/verified by the actual TLS/browser probes.
- The first combined scenario assumed an old, expired access credential would
  return 401 before notification. Its failed renewal correctly followed ambiguous
  503 recovery. The test renews recipients before logout to isolate fresh-grant
  authoritative denial; expired/abandoned renewal is exercised separately above.
- HTTP status literals in logout delivery classification now use `HTTPStatus`,
  and public runtime metadata identifies full-system acceptance.

## Fresh-runtime and packaging evidence

The current wheel bundles both migration histories and PostgreSQL probe policy.
It was built into a separate temporary directory and installed with production
dependencies in an isolated environment outside the checkout. Both probes generate
fresh owner-private state, migrate separate roles/databases, and start independent
HTTPS processes. The login probe uses actual seeded Argon2id proof; the protocol
probe verifies PKCE, client assertions, canonical issuance and browser binding.
This validates current packaging and clean-state process startup rather than a
Git clone; the workspace has not been published/committed by this task.

Docker is unavailable in this WSL distro (`docker version` reports it cannot be
found). Compose image/startup/config execution is therefore **not locally claimed**.
The checked-in workflow configures those container checks; local evidence uses
the same factories and custody model on actual independent HTTPS/database-TLS
processes. Reviewers with Docker use the documented `make up` path. Production
dependency inputs did not change; historical audit evidence is retained without
claiming Phase 10's omitted negative-control demonstration.

## Exact verification

```bash
uv run pytest tests/unit/test_runtime_commands.py tests/e2e/test_system_acceptance.py -q --durations=5
# 2 passed in 214.40s

uv run pytest tests/integration/test_system_acceptance.py tests/integration/test_transactions.py tests/integration/test_containment.py::test_issuance_and_refresh_racing_containment_cannot_restore_revoked_authority tests/integration/test_signing_rotation.py::test_rotation_and_concurrent_issuance_share_one_active_signer_decision tests/integration/test_refresh.py::test_refresh_racing_authoritative_containment_cannot_revive_authority tests/integration/test_logout.py::test_notification_racing_verified_refresh_prevents_installation_without_network_locks tests/integration/test_logout.py::test_lost_ack_restart_and_stale_worker_are_fenced_while_exact_retry_is_idempotent tests/integration/test_step_up.py::test_logout_while_password_proof_is_pending_cannot_consume_otp_or_create_an_event -q
# 15 passed in 75.97s

uv run pytest tests/integration/test_foundations.py tests/integration/test_protocol.py tests/integration/test_lifecycle.py tests/integration/test_system_acceptance.py tests/unit/test_runtime_commands.py -q
# 69 passed in 185.13s

uv run pytest tests/e2e/test_containment.py -q --durations=5
# 1 passed in 106.09s

make check
# Ruff lint/format passed for 192 Python files; strict mypy passed for 170 source/test files

uv build --wheel --out-dir "/tmp/opencode/phase11-final"
# Built federated_identity_take_home-0.0.1-py3-none-any.whl

# Both run with workdir=/tmp/opencode, outside the source checkout:
uv run --isolated --no-project --with "/tmp/opencode/phase11-final/federated_identity_take_home-0.0.1-py3-none-any.whl" federationctl verify-login
# Passed: actual password/SSO, verified HTTPS/PostgreSQL TLS, independent sessions, callback replay denial
uv run --isolated --no-project --with "/tmp/opencode/phase11-final/federated_identity_take_home-0.0.1-py3-none-any.whl" federation-phase0
# Passed: three processes, PKCE/private_key_jwt, canonical issuance and authenticated recipient evidence

uv run federationctl operator --help && uv run federationctl operator key-activate --help && uv run federationctl operator key-contain --help && uv run federationctl client-key-replace --help && uv run federationctl logout-retry --help
# Passed
git diff --check
# Passed
```

The 84 count is the union of successful selections, excluding repeated cases.
Earlier combined runs detected the cold-connection 500 (1 failed in 109.90s) and
the expired-credential status expectation (1 failed, 1 passed in 236.84s). The
commands above are completed passing runs. The prior explicitly requested full
regression remains **565 passing tests** in [Phase 9](phase9.md#requested-full-regression-follow-up);
Phase 11 is selected acceptance, not a new full-suite result.

## Required writeup and submission working set

| Brief/writeup requirement | Final location |
| --- | --- |
| Built and cut up front; why | README scope table and Phase 10 rationale, ADR 0005 |
| Straightforward startup | README commands/URLs/CA/seeded credential flow; runtime guide |
| Services' trust, key/session model, uncertain calls | README decisions; architecture/security-model/ADRs |
| Adversaries, residual risk, quick data flow | README threat section and Mermaid; detailed threat model |
| Actual AI assistance, errors and detection | README AI summary; actual corrections log |
| Operator CLI and feature reproduction | [Scenario guide](scenarios.md) with current versions/IDs and owner commands |
| Feature inventory linked to evidence | README table and checkpoint links |

The README is reduced from 444 to 144 lines and gives the reviewer the required
story and runnable first flow, with deeper procedures linked. The chosen system
and explanation working set are ready for the next demo-video planning task.
GitHub publication and an actual recorded video remain distinct submission
artifacts; this acceptance checkpoint does not claim either was produced.
