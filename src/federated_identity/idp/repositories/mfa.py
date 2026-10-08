"""Encrypted factor custody and consumed-step history in the authentication transaction."""

import json
from collections.abc import Sequence

from pydantic import SecretStr
from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock
from federated_identity.idp.schemas.mfa import SeededTotp


class MfaBase(DeclarativeBase):
    pass


class TotpCredentialRow(MfaBase):
    __tablename__ = "totp_credentials"
    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_accepted_counter: Mapped[int] = mapped_column(BigInteger, nullable=False, default=-1)


class TotpConsumptionRow(MfaBase):
    __tablename__ = "totp_consumptions"
    subject: Mapped[str] = mapped_column(ForeignKey(TotpCredentialRow.subject), primary_key=True)
    counter: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    accepted_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class TotpRepository:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database, self.cipher, self.clock = database, cipher, clock

    def secret(self, row: TotpCredentialRow) -> SecretStr:
        value = SeededTotp.model_validate_json(
            json.dumps(self.cipher.decrypt(row.encrypted_secret, purpose="totp-secret"))
        )
        if value.subject != row.subject:
            raise ValueError("Stored TOTP secret must match its immutable subject")
        return value.secret

    async def seed(self, values: Sequence[SeededTotp]) -> None:
        async with self.database.sessions() as session:
            async with session.begin():
                await session.execute(text("SELECT pg_advisory_xact_lock(728118)"))
                for value in values:
                    existing = await session.get(TotpCredentialRow, value.subject)
                    if existing is not None:
                        self.secret(existing)
                        continue
                    session.add(
                        TotpCredentialRow(
                            subject=value.subject,
                            created_at=self.clock.now(),
                            last_accepted_counter=-1,
                            encrypted_secret=self.cipher.encrypt(
                                {
                                    "subject": value.subject,
                                    "secret": value.secret.get_secret_value(),
                                },
                                purpose="totp-secret",
                            ),
                        )
                    )

    async def get_in(self, session: AsyncSession, subject: str) -> TotpCredentialRow | None:
        return await session.get(TotpCredentialRow, subject, with_for_update=True)

    async def initialized(self) -> bool:
        async with self.database.sessions() as session:
            rows = list(await session.scalars(select(TotpCredentialRow).limit(2)))
            for row in rows:
                self.secret(row)
            return len(rows) >= 2
