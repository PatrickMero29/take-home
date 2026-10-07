"""Async seeded-user storage; bootstrap never resets credentials or account state."""

from collections.abc import Sequence

from pydantic import SecretStr
from sqlalchemy import BigInteger, Boolean, String, Text, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.settings.policy import Clock
from federated_identity.idp.schemas.users import UserCredential


class UserBase(DeclarativeBase):
    pass


class UserRow(UserBase):
    __tablename__ = "users"

    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    username: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class UserRepository:
    def __init__(self, database: AsyncDatabase, clock: Clock) -> None:
        self.database = database
        self.clock = clock

    async def seed(self, users: Sequence[UserCredential]) -> None:
        async with self.database.sessions() as session:
            async with session.begin():
                await session.execute(text("SELECT pg_advisory_xact_lock(728116)"))
                for user in users:
                    existing = await session.get(UserRow, user.subject)
                    username = (
                        await session.execute(
                            select(UserRow).where(UserRow.username == user.username)
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        if existing.username != user.username:
                            raise RuntimeError(
                                "Seeded identity does not match its persisted username"
                            )
                        continue
                    if username is not None:
                        raise RuntimeError(
                            "Seed bootstrap cannot replace an existing user's identity"
                        )
                    session.add(
                        UserRow(
                            subject=user.subject,
                            username=user.username,
                            password_hash=user.password_hash.get_secret_value(),
                            enabled=user.enabled,
                            created_at=self.clock.now(),
                        )
                    )

    async def credential(self, username: str) -> UserCredential | None:
        async with self.database.sessions() as session:
            row = (
                await session.execute(select(UserRow).where(UserRow.username == username))
            ).scalar_one_or_none()
            if row is None:
                return None
            return UserCredential(
                subject=row.subject,
                username=row.username,
                password_hash=SecretStr(row.password_hash),
                enabled=row.enabled,
            )

    async def initialized(self) -> bool:
        async with self.database.sessions() as session:
            rows = list(await session.scalars(select(UserRow).limit(2)))
            for row in rows:
                UserCredential(
                    subject=row.subject,
                    username=row.username,
                    password_hash=SecretStr(row.password_hash),
                    enabled=row.enabled,
                )
            return len(rows) >= 2
