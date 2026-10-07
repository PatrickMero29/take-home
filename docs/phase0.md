# Phase 0 — protocol and async-persistence gate

Status: revisited on the deployed architecture and shared security model;
implemented and verified on 2026-10-06.

## What changed during the revisit

- Codes now reference a persisted authentication event and its IDP session.
  Supplied identity, time, methods, and assurance must match those immutable
  records, and the parent session must remain active.
- One gated async unit of work owns Authlib's storage hooks, assertion replay,
  code consumption, normalized grant/evidence/credential creation, signing-key
  retention, and the protocol issuance link. No nested independent transaction
  can publish a grant outside code redemption.
- Authlib's public token-request validation and token-response creation are
  orchestrated separately to preserve legitimate assertion reservations across
  a later policy denial. An issuance savepoint discards all draft effects;
  unexpected signing/storage/commit failures roll back the whole transaction.
- The configured signer must match current persisted active trust. Code and
  access lifetimes respect their parent session ceiling.
- Authenticated `/introspect` uses its own exact endpoint audience, registered
  client keys, and durable assertion replay. It returns complete canonical
  lineage only to the credential's recipient, otherwise `active: false`.
- RP exchange validates the JWT with shared Authlib/joserfc policy, then compares
  its exact evidence with fresh authoritative issuance before returning a
  `VerifiedLogin`. A valid but substituted/unissued JWT cannot pass this boundary.
- Migration `idp_protocol_lineage_03` binds new protocol records and enforces
  complete linkage at commit. Historical unbound prototype codes survive
  upgrade as history and cannot be redeemed.
- `federation-phase0` now runs on the same three-process topology, TLS/database
  roles, migrations, key custody, and callback configuration as deployment.
  Each SP's encrypted, browser-bound transaction is consumed once at callback.

## Exit checks

| Planned check | Evidence |
| --- | --- |
| Valid PKCE exchange yields a correctly validated ID token | `tests/integration/test_protocol.py::test_pkce_oidc_and_private_key_jwt_round_trip`; `tests/integration/test_https.py::test_real_https_code_exchange_and_certificate_verification`; `federation-phase0` |
| Concurrent redemption yields at most one issuance | `tests/integration/test_protocol.py::test_concurrent_code_redemption_has_one_issuance`: eight contenders, one success, one committed row |
| Invalid assertions and assertion replay are rejected | `tests/security/test_client_assertions.py`: identity/audience/key/type/time failures, eight simultaneous replay attempts, replay after application/pool recreation |
| Database waits do not block unrelated requests | `tests/integration/test_transactions.py::test_pg_sleep_in_a_sync_shaped_hook_does_not_block_health`: health responds while actual PostgreSQL work remains unfinished |
| Successful issuance is committed before response | `test_http_success_waits_for_database_commit`: response remains pending during a controlled commit barrier; other connections see no uncommitted issuance |
| Failures preserve atomicity | `test_commit_failure_cannot_publish_or_consume`; `test_signing_failure_rolls_back_issuance_consumption_and_replay` |
| Refresh, re-authentication, and logout extension points are confirmed | [Extension points](extension-points.md); the current code profile rejects unregistered refresh and returns `login_required` for unmet re-authentication demands |
| Trust and protocol contracts are recorded | [Architecture](architecture.md), [artifact contracts](artifact-contracts.md), [threat model](threat-model.md), and decision records |
| Protocol and canonical lineage commit together | `tests/integration/test_phase0_lineage.py::test_code_issuance_and_authoritative_result_share_one_persisted_lineage`; deferred database completeness constraint |
| Normalized failures cannot leave a consumed code or partial grant | `test_failure_after_grant_creation_rolls_back_both_protocol_and_security_records`; `test_database_refuses_a_success_without_the_protocol_to_grant_binding` |
| Revocation cannot be bypassed by code redemption | `test_parent_session_state_is_checked_before_code_redemption`; `test_redemption_racing_containment_cannot_publish_reusable_authority` |
| Introspection and RP evidence are recipient/purpose bound | `test_authenticated_introspection_is_recipient_scoped`; `test_client_assertion_audiences_are_endpoint_specific_and_replay_is_durable`; `test_rp_rejects_valid_signatures_without_matching_authoritative_evidence` |
| The assembled deployment exercises both SP identities | `tests/integration/test_architecture.py::test_phase0_protocol_on_deployed_processes_and_service_roles`; verified HTTPS/database TLS with three processes and isolated roles |
| Schema upgrades preserve historical data without fabricating trust | `test_upgrade_preserves_but_never_trusts_unbound_prototype_codes` |

## Verification

- `uv run pytest -q --durations=10`: **192 passing tests**, warnings treated as errors.
- `uv run ruff check src tests migrations`: passed.
- `uv run ruff format --check src tests migrations`: passed for 92 Python files.
- `uv run mypy src tests`: passed for 85 source/test files in strict mode.
- Verified-HTTPS three-process proof: passed for SP A and SP B, including
  committed normalized evidence, preserved authentication time, and online checks.
- Hash-locked runtime dependency audit: no known findings.
- Database used here: PostgreSQL 16.15, both isolated asyncpg integration
  databases and the actual TLS/password-authenticated service-role topology.

These are checks of the implementation at this checkpoint, not an OIDC
conformance-certification or a claim that later feature phases are complete.

## Promoted implementation

- API transport: `src/federated_identity/idp/api/app.py`.
- Async orchestration: `src/federated_identity/idp/services/oidc.py`.
- Isolated Authlib extension layer: `src/federated_identity/idp/protocol/authlib_adapter.py`.
- Async-backed persistence: `src/federated_identity/idp/repositories/database.py`.
- RP protocol/validation boundary: `src/federated_identity/sp/protocol/oidc.py`.
- Shared vetted JWT/evidence validation: `src/federated_identity/common/security/oidc.py`.
- Canonical security lifecycle: `src/federated_identity/idp/services/security_model.py`.
- Disposable deployed-topology verification: `src/federated_identity/cli/phase0.py`.

The normal IDP factory still defaults to `NoPrincipal`. The verification runner
explicitly injects an owner-private encrypted fixture whose event is already
persisted and carries fixture-only assurance. The runtime exposes no route for
choosing a subject or supplying an authentication event.

See [ADR 0002](decisions/0002-unified-protocol-security-transaction.md) for the
savepoint/commit decision and the resulting lock order.

## Next checkpoint

Continue through Phase 1's remaining foundation items, especially seeded-user
credential/bootstrap handling, then Phase 2's real IDP authentication and
browser SSO/callback orchestration. Deployment, migrations, secret custody,
typed composition roots, and the normalized protocol boundary are already
verified foundations for that work.
