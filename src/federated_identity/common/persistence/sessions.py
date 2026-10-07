"""Opaque, encrypted server-side storage; authentication semantics are supplied separately."""

import secrets
from typing import Protocol

from pydantic import JsonValue, SecretStr
from sqlalchemy import BigInteger, LargeBinary, String, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, FrozenModel, verifier_digest


class SessionBase(DeclarativeBase):
    pass


class BrowserSessionRow(SessionBase):
    __tablename__ = "browser_sessions"

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class BrowserSession(FrozenModel):
    payload: dict[str, JsonValue]
    created_at: int
    expires_at: int


class SessionBackend(Protocol):
    async def create(self, payload: dict[str, JsonValue], *, ttl: int) -> SecretStr: ...
    async def lookup(self, token: SecretStr) -> BrowserSession | None: ...
    async def destroy(self, token: SecretStr) -> None: ...


class PostgresSessionBackend:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def create(self, payload: dict[str, JsonValue], *, ttl: int) -> SecretStr:
        if ttl <= 0:
            raise ValueError("A positive session lifetime is required")
        token = SecretStr(secrets.token_urlsafe(32))
        now = self.clock.now()
        async with self.database.sessions() as session:
            session.add(
                BrowserSessionRow(
                    token_digest=verifier_digest(token.get_secret_value()),
                    encrypted_payload=self.cipher.encrypt(payload, purpose="browser-session"),
                    created_at=now,
                    expires_at=now + ttl,
                )
            )
            await session.commit()
        return token

    async def lookup(self, token: SecretStr) -> BrowserSession | None:
        value = token.get_secret_value()
        if not 32 <= len(value) <= 128:
            return None
        async with self.database.sessions() as session:
            row = await session.get(BrowserSessionRow, verifier_digest(value))
            if row is None or row.expires_at <= self.clock.now():
                return None
            return BrowserSession(
                payload=self.cipher.decrypt(row.encrypted_payload, purpose="browser-session"),
                created_at=row.created_at,
                expires_at=row.expires_at,
            )

    async def destroy(self, token: SecretStr) -> None:
        async with self.database.sessions() as session:
            await session.execute(
                delete(BrowserSessionRow).where(
                    BrowserSessionRow.token_digest == verifier_digest(token.get_secret_value())
                )
            )
            await session.commit()
