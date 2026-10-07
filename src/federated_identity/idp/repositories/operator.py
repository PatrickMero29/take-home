"""IDP-owned operator credentials, separate session authority, and append-only audit."""

import json

from pydantic import SecretStr
from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, String, Text, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.model import Denial, SecurityDenied
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, verifier_digest
from federated_identity.idp.schemas.operator import (
    OperatorChannel,
    OperatorCredential,
    OperatorPermission,
    OperatorPrincipal,
)


class OperatorBase(DeclarativeBase):
    pass


class OperatorRow(OperatorBase):
    __tablename__ = "operators"

    operator_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    username: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    credential_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class OperatorSessionRow(OperatorBase):
    __tablename__ = "operator_sessions"

    token_digest: Mapped[str] = mapped_column(
        ForeignKey(BrowserSessionRow.__table__.c.token_digest, ondelete="CASCADE"), primary_key=True
    )
    operator_id: Mapped[str] = mapped_column(ForeignKey(OperatorRow.operator_id), nullable=False)
    credential_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)


class ClientKeyHistoryRow(OperatorBase):
    __tablename__ = "client_key_history"

    key_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class OperatorAuditRow(OperatorBase):
    __tablename__ = "operator_audit"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey(OperatorRow.operator_id), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    registration_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


def operator_credential(row: OperatorRow) -> OperatorCredential:
    return OperatorCredential.model_validate_json(
        json.dumps(
            {
                "operator_id": row.operator_id,
                "username": row.username,
                "password_hash": row.password_hash,
                "enabled": row.enabled,
                "permissions": row.permissions,
                "credential_version": row.credential_version,
            }
        )
    )


class OperatorRepository:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def seed(self, credential: OperatorCredential) -> None:
        async with self.database.sessions() as session:
            async with session.begin():
                await session.execute(text("SELECT pg_advisory_xact_lock(728117)"))
                existing = await session.get(OperatorRow, credential.operator_id)
                username = await session.scalar(
                    select(OperatorRow).where(OperatorRow.username == credential.username)
                )
                if existing is not None:
                    if existing.username != credential.username:
                        raise RuntimeError("Operator provisioning identity is inconsistent")
                    return
                if username is not None:
                    raise RuntimeError("Operator bootstrap cannot replace an existing identity")
                session.add(
                    OperatorRow(
                        operator_id=credential.operator_id,
                        username=credential.username,
                        password_hash=credential.password_hash.get_secret_value(),
                        enabled=credential.enabled,
                        permissions=[permission.value for permission in credential.permissions],
                        credential_version=credential.credential_version,
                        created_at=self.clock.now(),
                    )
                )

    async def credential(self, username: str) -> OperatorCredential | None:
        async with self.database.sessions() as session:
            row = await session.scalar(select(OperatorRow).where(OperatorRow.username == username))
            return operator_credential(row) if row is not None else None

    async def initialized(self) -> bool:
        async with self.database.sessions() as session:
            row = await session.scalar(select(OperatorRow).limit(1))
            if row is None:
                return False
            operator_credential(row)
            return True

    async def authorize_in(
        self,
        session: AsyncSession,
        token: SecretStr,
        channel: OperatorChannel,
        permission: OperatorPermission | None = None,
    ) -> OperatorPrincipal:
        digest = verifier_digest(token.get_secret_value())
        browser = await session.get(BrowserSessionRow, digest)
        binding = await session.get(OperatorSessionRow, digest)
        now = self.clock.now()
        if (
            browser is None
            or binding is None
            or browser.expires_at <= now
            or binding.channel != channel.value
        ):
            raise SecurityDenied(Denial.MISSING)
        payload = self.cipher.decrypt(browser.encrypted_payload, purpose="browser-session")
        if payload != {
            "kind": f"operator-{channel.value}",
            "operator_id": binding.operator_id,
            "credential_version": binding.credential_version,
        }:
            raise SecurityDenied(Denial.PURPOSE)
        operator = await session.get(OperatorRow, binding.operator_id)
        if (
            operator is None
            or not operator.enabled
            or operator.credential_version != binding.credential_version
        ):
            raise SecurityDenied(Denial.REVOKED)
        credential = operator_credential(operator)
        if permission is not None and permission not in credential.permissions:
            raise SecurityDenied(Denial.RECIPIENT)
        if browser.expires_at <= self.clock.now():
            raise SecurityDenied(Denial.EXPIRED)
        return OperatorPrincipal(
            operator_id=credential.operator_id,
            username=credential.username,
            permissions=credential.permissions,
            credential_version=credential.credential_version,
            expires_at=browser.expires_at,
        )
