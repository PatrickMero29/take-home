"""Async transaction ownership; synchronous-shaped hooks are isolated to run_sync."""

from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypeVar

from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.policy import verifier_digest
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.model import AuthenticationEvent, KeyState
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.clients import client_snapshot
from federated_identity.idp.repositories.operator import ClientKeyHistoryRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork, event_snapshot
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    FederationGrantRow,
    IdpSessionRow,
    RefreshCredentialRow,
    RefreshFamilyRow,
    SigningTrustRow,
)
from federated_identity.idp.repositories.tables import (
    AssertionReplayRow,
    AuthorizationCodeRow,
    ClientRow,
    IssuanceRow,
)
from federated_identity.idp.schemas.models import (
    AuthenticatedPrincipal,
    AuthorizationCodeData,
    ClientRegistration,
    IssuanceEvidence,
    RefreshCredentialData,
)

T = TypeVar("T")


class ProtocolRepository:
    """Only call within AsyncSession.run_sync using its supplied Session.

    These SQLAlchemy operations suspend through the asyncpg driver. This class
    never opens a connection, reads a file, or performs an HTTP request itself.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_client(self, client_id: str) -> ClientRegistration | None:
        row = self.session.get(ClientRow, client_id)
        if row is None or not row.enabled:
            return None
        return client_snapshot(row)

    def verified_event(
        self,
        principal: AuthenticatedPrincipal,
        *,
        issuer: str,
        now: int,
        allow_inactive: bool = False,
    ) -> AuthenticationEvent | None:
        session = self.session.get(IdpSessionRow, principal.sid)
        event = self.session.get(AuthenticationEventRow, principal.event_id)
        if (
            session is None
            or event is None
            or session.issuer != issuer
            or event.session_id != session.session_id
            or (
                not allow_inactive and (session.revoked_at is not None or session.expires_at <= now)
            )
        ):
            return None
        verified = event_snapshot(event, session)
        if AuthenticatedPrincipal.from_event(verified) != principal:
            return None
        return verified

    def session_expiry(self, principal: AuthenticatedPrincipal) -> int:
        session = self.session.get(IdpSessionRow, principal.sid)
        if session is None:
            raise RuntimeError("Authorization requires a persisted session")
        return session.expires_at

    def signer_is_active(self, signer: SigningKey) -> bool:
        row = self.session.get(SigningTrustRow, signer.kid)
        return bool(
            row is not None
            and row.state == KeyState.ACTIVE.value
            and row.public_key_pem == signer.public_pem()
        )

    def refresh_credential(self, token: str) -> RefreshCredentialData | None:
        if not 32 <= len(token) <= 128:
            return None
        credential = self.session.get(RefreshCredentialRow, verifier_digest(token))
        family = self.session.get(RefreshFamilyRow, credential.family_id) if credential else None
        grant = self.session.get(FederationGrantRow, family.grant_id) if family else None
        parent = self.session.get(IdpSessionRow, grant.session_id) if grant else None
        event = self.session.get(AuthenticationEventRow, grant.event_id) if grant else None
        if credential is None or family is None or grant is None or parent is None or event is None:
            return None
        return RefreshCredentialData(
            token_digest=credential.token_digest,
            client_id=grant.client_id,
            grant_id=grant.grant_id,
            family_id=family.family_id,
            generation=credential.generation,
            expires_at=credential.expires_at,
            consumed_at=credential.consumed_at,
            authentication=event_snapshot(event, parent),
        )

    def reserve_assertion(self, client_id: str, jti: str, expires_at: int) -> bool:
        # A read-then-insert replay check races. PostgreSQL's unique constraint
        # arbitrates simultaneous claims while leaving the transaction usable.
        statement = (
            insert(AssertionReplayRow)
            .values(client_id=client_id, jti=jti, expires_at=expires_at)
            .on_conflict_do_nothing()
            .returning(AssertionReplayRow.jti)
        )
        return self.session.execute(statement).scalar_one_or_none() is not None

    def nonce_exists(self, client_id: str, nonce: str) -> bool:
        statement = select(AuthorizationCodeRow.code_digest).where(
            AuthorizationCodeRow.client_id == client_id,
            AuthorizationCodeRow.nonce == nonce,
        )
        return self.session.execute(statement.limit(1)).scalar_one_or_none() is not None

    def save_code(self, data: AuthorizationCodeData) -> None:
        self.session.add(
            AuthorizationCodeRow(
                code_digest=data.code_digest,
                client_id=data.client_id,
                redirect_uri=data.redirect_uri,
                scope=data.scope,
                nonce=data.nonce,
                code_challenge=data.code_challenge,
                created_at=data.created_at,
                expires_at=data.expires_at,
                consumed_at=None,
                sub=data.principal.sub,
                sid=data.principal.sid,
                event_id=data.principal.event_id,
                client_version=data.client_version,
                auth_time=data.principal.auth_time,
                acr=data.principal.acr,
                amr=list(data.principal.amr),
            )
        )

    def lock_code(
        self, code: str, client_id: str, now: int, *, issuer: str
    ) -> AuthorizationCodeData | None:
        # Hold this row lock until token issuance and consumption commit. A
        # contender sees consumed_at after the successful transaction finishes.
        statement = (
            select(AuthorizationCodeRow)
            .where(
                AuthorizationCodeRow.code_digest == verifier_digest(code),
                AuthorizationCodeRow.client_id == client_id,
            )
            .with_for_update()
        )
        row = self.session.execute(statement).scalar_one_or_none()
        client = self.session.get(ClientRow, client_id)
        if (
            row is None
            or row.event_id is None
            or client is None
            or not client.enabled
            or row.client_version != client.registration_version
            or (row.consumed_at is None and row.expires_at <= now)
        ):
            return None
        principal = AuthenticatedPrincipal(
            sub=row.sub,
            sid=row.sid,
            event_id=row.event_id,
            auth_time=row.auth_time,
            acr=row.acr,
            amr=tuple(row.amr),
        )
        if (
            self.verified_event(
                principal, issuer=issuer, now=now, allow_inactive=row.consumed_at is not None
            )
            is None
        ):
            return None
        return AuthorizationCodeData(
            code_digest=row.code_digest,
            client_id=row.client_id,
            redirect_uri=row.redirect_uri,
            scope="openid",
            nonce=row.nonce,
            code_challenge=row.code_challenge,
            created_at=row.created_at,
            expires_at=row.expires_at,
            consumed_at=row.consumed_at,
            principal=principal,
            client_version=client.registration_version,
        )

    def consume_code(self, digest: str, now: int) -> None:
        row = self.session.get(AuthorizationCodeRow, digest)
        if row is None or row.consumed_at is not None:
            raise RuntimeError("Code consumption requires the locked, unused row")
        row.consumed_at = now

    def grant_for_code(self, digest: str, client_id: str) -> str | None:
        return self.session.scalar(
            select(IssuanceRow.grant_id).where(
                IssuanceRow.code_digest == digest, IssuanceRow.client_id == client_id
            )
        )

    def save_issuance(
        self,
        issuance_id: str,
        code: AuthorizationCodeData,
        access_token: str,
        signing_key_id: str,
        now: int,
    ) -> None:
        self.session.add(
            IssuanceRow(
                issuance_id=issuance_id,
                grant_id=None,
                code_digest=code.code_digest,
                client_id=code.client_id,
                access_token_digest=verifier_digest(access_token),
                id_token_digest=None,
                signing_key_id=signing_key_id,
                sub=code.principal.sub,
                sid=code.principal.sid,
                created_at=now,
            )
        )

    def finish_issuance(self, issuance_id: str, id_token: str) -> None:
        row = self.session.get(IssuanceRow, issuance_id)
        if row is None:
            raise RuntimeError("No issuance exists for the generated ID token")
        row.id_token_digest = verifier_digest(id_token)
        self.session.flush()

    def bind_issuance(self, issuance_id: str, grant_id: str) -> None:
        row = self.session.get(IssuanceRow, issuance_id)
        if row is None or row.grant_id is not None or row.id_token_digest is None:
            raise RuntimeError("Grant binding requires complete, unpublished token evidence")
        row.grant_id = grant_id
        self.session.flush()


class ProtocolUnitOfWork(SecurityUnitOfWork):
    async def protocol(self, operation: Callable[[ProtocolRepository], T]) -> T:
        return await self.session.run_sync(lambda session: operation(ProtocolRepository(session)))


class Database(AsyncDatabase):
    def __init__(
        self,
        url: SecretStr,
        *,
        ca_file: Path | None = None,
        session_class: type[AsyncSession] = AsyncSession,
    ) -> None:
        super().__init__(url, ca_file=ca_file, session_class=session_class)

    async def initialize(self, clients: Sequence[ClientRegistration]) -> None:
        # The probe and deployment now exercise the same versioned schema.
        await migrate(self, ServiceId.IDP)
        await self.seed_clients(clients)

    async def seed_clients(self, clients: Sequence[ClientRegistration]) -> None:
        async with self.sessions() as session:
            for client in clients:
                existing = await session.get(ClientRow, client.client_id)
                if existing is None:
                    existing = ClientRow(**client.model_dump(mode="json"))
                    session.add(existing)
                    await session.flush()
                if await session.get(ClientKeyHistoryRow, existing.key_id) is None:
                    session.add(
                        ClientKeyHistoryRow(
                            key_id=existing.key_id,
                            client_id=existing.client_id,
                            public_key_pem=existing.public_key_pem,
                            created_at=1,
                        )
                    )
            await session.commit()

    @asynccontextmanager
    async def protocol_transaction(self) -> AsyncIterator[ProtocolUnitOfWork]:
        async with self.sessions() as session:
            try:
                yield await ProtocolUnitOfWork.acquire(session)
                # Authlib returns OAuth errors as values. Commit legitimate
                # assertion replay reservations even when a later grant check
                # rejects the request. Unexpected failures roll everything back.
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        # No HTTP success (including redirect/code delivery) can precede commit.

    async def transact(self, operation: Callable[[ProtocolRepository], T]) -> T:
        async with self.protocol_transaction() as work:
            result = await work.protocol(operation)
        return result

    async def issuance_count(self, code: str) -> int:
        async with self.sessions() as session:
            statement = (
                select(func.count())
                .select_from(IssuanceRow)
                .where(IssuanceRow.code_digest == verifier_digest(code))
            )
            return int((await session.execute(statement)).scalar_one())

    async def issuance_evidence(self, access_token: str) -> IssuanceEvidence | None:
        async with self.sessions() as session:
            statement = select(IssuanceRow).where(
                IssuanceRow.access_token_digest == verifier_digest(access_token)
            )
            row = (await session.execute(statement)).scalar_one_or_none()
            if row is None or row.id_token_digest is None or row.grant_id is None:
                return None
            return IssuanceEvidence(
                issuance_id=row.issuance_id,
                grant_id=row.grant_id,
                client_id=row.client_id,
                sub=row.sub,
                sid=row.sid,
                signing_key_id=row.signing_key_id,
                id_token_digest=row.id_token_digest,
                created_at=row.created_at,
            )
