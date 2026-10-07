"""Async security UOWs with a database-owned serialization point and typed lineage reads."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Self, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationMethod,
    FederationGrant,
    GrantSnapshot,
    IdpSession,
    KeyState,
    LoginEvidence,
    RefreshFamily,
    RevocationReason,
    SigningTrust,
    SubjectIdentity,
)
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    AuthenticationEvidenceRow,
    FederationGrantRow,
    IdpSessionRow,
    RefreshFamilyRow,
    RefreshIssuanceRow,
    SecurityGateRow,
    SigningTrustRow,
)
from federated_identity.idp.repositories.tables import ClientRow

T = TypeVar("T")


def session_snapshot(row: IdpSessionRow) -> IdpSession:
    return IdpSession(
        session_id=row.session_id,
        subject=SubjectIdentity(issuer=row.issuer, subject=row.subject),
        created_at=row.created_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        revocation_reason=(
            RevocationReason(row.revocation_reason) if row.revocation_reason else None
        ),
    )


def event_snapshot(row: AuthenticationEventRow, session: IdpSessionRow) -> AuthenticationEvent:
    return AuthenticationEvent(
        event_id=row.event_id,
        session_id=row.session_id,
        subject=SubjectIdentity(issuer=session.issuer, subject=session.subject),
        authenticated_at=row.authenticated_at,
        assurance=Assurance(row.assurance),
        methods=tuple(AuthenticationMethod(method) for method in row.methods),
    )


def grant_snapshot(row: FederationGrantRow) -> FederationGrant:
    return FederationGrant(
        grant_id=row.grant_id,
        client_id=row.client_id,
        session_id=row.session_id,
        event_id=row.event_id,
        root_signing_key_id=row.root_signing_key_id,
        created_at=row.created_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        revocation_reason=(
            RevocationReason(row.revocation_reason) if row.revocation_reason else None
        ),
    )


def key_snapshot(row: SigningTrustRow) -> SigningTrust:
    return SigningTrust(
        key_id=row.key_id,
        state=KeyState(row.state),
        created_at=row.created_at,
        verification_deadline=row.verification_deadline,
    )


@dataclass(frozen=True)
class Lineage:
    session: IdpSessionRow
    event: AuthenticationEventRow
    grant: FederationGrantRow
    key: SigningTrustRow
    client: ClientRow
    family: RefreshFamilyRow
    evidence: AuthenticationEvidenceRow

    def snapshot(self, revision: int) -> GrantSnapshot:
        authentication = event_snapshot(self.event, self.session)
        return GrantSnapshot(
            grant=grant_snapshot(self.grant),
            authentication=authentication,
            evidence=LoginEvidence(
                token_id=self.evidence.token_id,
                token_digest=self.evidence.token_digest,
                client_id=self.grant.client_id,
                signing_key_id=self.evidence.signing_key_id,
                authentication=authentication,
                issued_at=self.evidence.issued_at,
                expires_at=self.evidence.expires_at,
            ),
            session_expires_at=self.session.expires_at,
            family=RefreshFamily(
                family_id=self.family.family_id,
                grant_id=self.family.grant_id,
                created_at=self.family.created_at,
                expires_at=self.family.expires_at,
                generation=self.family.generation,
                revoked_at=self.family.revoked_at,
            ),
            policy_revision=revision,
        )


class SecurityUnitOfWork:
    def __init__(self, session: AsyncSession, gate: SecurityGateRow) -> None:
        self.session = session
        self.gate = gate

    @classmethod
    async def acquire(cls, session: AsyncSession) -> Self:
        gate = await session.get(SecurityGateRow, 1, with_for_update=True)
        if gate is None:
            raise RuntimeError("Security model migrations must initialize the policy gate")
        return cls(session, gate)

    async def get(self, model: type[T], identifier: str) -> T | None:
        return await self.session.get(model, identifier)

    def add(self, record: object) -> None:
        self.session.add(record)

    async def flush(self) -> None:
        await self.session.flush()

    async def active_key(self) -> SigningTrustRow | None:
        statement = select(SigningTrustRow).where(SigningTrustRow.state == "active")
        return (await self.session.execute(statement)).scalar_one_or_none()

    async def grants_for_session(self, session_id: str) -> list[FederationGrantRow]:
        return list(
            await self.session.scalars(
                select(FederationGrantRow).where(FederationGrantRow.session_id == session_id)
            )
        )

    async def grants_for_client(self, client_id: str) -> list[FederationGrantRow]:
        return list(
            await self.session.scalars(
                select(FederationGrantRow).where(FederationGrantRow.client_id == client_id)
            )
        )

    async def grants_for_key(self, key_id: str) -> list[FederationGrantRow]:
        return list(
            await self.session.scalars(
                select(FederationGrantRow).where(
                    (FederationGrantRow.root_signing_key_id == key_id)
                    | FederationGrantRow.grant_id.in_(
                        select(RefreshIssuanceRow.grant_id).where(
                            RefreshIssuanceRow.signing_key_id == key_id
                        )
                    )
                )
            )
        )

    async def family_for_grant(self, grant_id: str) -> RefreshFamilyRow | None:
        statement = select(RefreshFamilyRow).where(RefreshFamilyRow.grant_id == grant_id)
        return (await self.session.execute(statement)).scalar_one_or_none()

    async def lineage(self, grant_id: str) -> Lineage | None:
        grant = await self.get(FederationGrantRow, grant_id)
        if grant is None:
            return None
        session = await self.get(IdpSessionRow, grant.session_id)
        event = await self.get(AuthenticationEventRow, grant.event_id)
        key = await self.get(SigningTrustRow, grant.root_signing_key_id)
        client = await self.get(ClientRow, grant.client_id)
        family = await self.family_for_grant(grant_id)
        statement = select(AuthenticationEvidenceRow).where(
            AuthenticationEvidenceRow.grant_id == grant_id
        )
        evidence = (await self.session.execute(statement)).scalar_one_or_none()
        if session is None or event is None or key is None or client is None:
            return None
        if family is None or evidence is None:
            return None
        return Lineage(session, event, grant, key, client, family, evidence)


class SecurityRepository:
    def __init__(self, database: AsyncDatabase) -> None:
        self.database = database

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[SecurityUnitOfWork]:
        async with self.database.sessions() as session:
            async with session.begin():
                yield await SecurityUnitOfWork.acquire(session)
        # The service publishes success or an intentional replay rejection only
        # after this context has committed. No network call or user interaction
        # occurs while the short database-only model transition is serialized.
