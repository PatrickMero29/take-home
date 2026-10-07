# ADR 0002 — one transaction for protocol issuance and canonical authorization

Status: accepted and verified on 2026-10-06.

## Context

The original Phase 0 proof atomically persisted code consumption and a compact
issuance ledger. Section 2 subsequently introduced canonical authentication
events, grants, credential families, mutable trust, and scoped containment.
Independent transactions between those components would let code redemption
race revocation or return tokens without committed authoritative lineage.

## Decision

`ProtocolUnitOfWork` shares the same `AsyncSession` and security gate with
`IdpSecurityModel.issue_grant_in()` / `check_access_in()`. The lock order is
security gate before client/replay/code/credential work. All database operations
remain asyncpg-backed; synchronous-shaped Authlib calls occur only in `run_sync`.

The application invokes Authlib's public `validate_token_request()` and
`create_token_response()` phases through the isolated adapter. Authentication
and legitimate assertion replay reservation precede an issuance savepoint.
Token generation, code consumption, exact vetted ID-token evidence, normalized
grant/credential writes, signer retention, and the protocol-to-grant link occur
inside that savepoint and the outer transaction.

- Expected later policy/OAuth denial rolls back draft issuance and consumption,
  then commits the valid assertion reservation before returning an error.
- Unexpected signing, storage, validation, or commit failure rolls back the
  entire transaction; neither tokens nor a code-consumption result is published.
- Successful HTTP responses wait for the outer commit.

PostgreSQL composite foreign keys and a deferred completeness trigger prevent
committing a new protocol issuance without its consumed code, exact evidence,
access verifier, and canonical grant. Bound issuance and code facts are
immutable; historical unbound records remain non-authoritative after upgrade.

An RP validates the signed artifact and performs fresh authenticated
introspection. The exact issuer/subject/event/session/evidence/recipient
binding and current parent lifetimes must match before exchange yields a
`VerifiedLogin`. The shared active-grant policy is also used by SP session
authorization.

## Evidence

- Existing eight-way code/assertion replay and nonblocking PostgreSQL-wait tests.
- Paused outer commit: neither compact nor canonical issuance is visible, and
  HTTP success remains pending.
- Failed signing/commit and failure after canonical grant creation: complete rollback.
- Expected policy denial: no draft grant/consumption survives, but verified
  assertion replay does.
- Omitted protocol binding: deferred database constraint rejects commit.
- Redemption versus logout/client disable/key revoke: no reusable authority escapes.
- Real three-process HTTPS/database-TLS proof with both SP credentials and
  browser-bound transactions in separate role-owned databases.

## Consequences

The compact protocol ledger now links to canonical authorization rather than
forming a separate source of trust. The singleton gate provides simple
serialization and remains the known throughput tradeoff. Authlib compatibility
logic is explicit and covered by tests; no SQLAlchemy session is shared between
concurrent requests, and no remote request is made while the IDP gate is held.
