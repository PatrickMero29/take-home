# ADR 0001 — isolate Authlib's provider hooks over an async database driver

Status: accepted for Phase 0; revalidated on the assembled system on 2026-10-06.

## Context

Authlib 1.8 provides async client integrations, but its core provider hooks
(`query_client`, code storage, token storage, and assertion replay validation)
are synchronous-shaped. Replacing the protocol to make every hook a coroutine
would expand the protocol code we own.

SQLAlchemy documents `AsyncSession.run_sync` as a compatibility boundary: an
instrumented greenlet adapts SQLAlchemy database operations to the actual async
driver. It is not a general-purpose adapter for blocking HTTP or filesystem I/O.

## Decision

- API and application orchestration are async.
- Each request has an independent `AsyncSession` and Authlib adapter.
- The typed `ProtocolRepository` is callable only inside `run_sync` with its supplied session.
- That repository uses SQLAlchemy operations backed by asyncpg and performs no other I/O.
- Commit and rollback are explicitly awaited outside the protocol callback.
- Public responses are constructed from constrained Pydantic DTOs after transaction completion.
- Untyped-library allowances are confined to the provider/RP adapters and shared vetted OIDC verifier.

## Evidence

A test inserts an actual `SELECT pg_sleep(0.5)` into a provider storage hook.
The health request completes before that query finishes. Other tests pause
commit, inject commit/signing failures, and race code/assertion redemption.
Those tests prove the important runtime properties rather than inferring them
from an `async def` declaration.

The revisit retains this bridge and shares its session with canonical security
operations. [ADR 0002](0002-unified-protocol-security-transaction.md) describes
the gated unit of work, issuance savepoint, and complete-issuance constraint.

## Consequences and open call

Synchronous-shaped hooks remain visible at the compatibility boundary. This
is a deliberate maintenance and readability tradeoff: their I/O uses an async
driver, while the library's method signatures stay intact. Reviewers can find
and audit the boundary in one module. New hooks must stay within these limits;
the SQLAlchemy session is never shared across concurrent tasks.

Reference: [SQLAlchemy's documented sync-method bridge](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html#running-synchronous-methods-and-functions-under-asyncio).
