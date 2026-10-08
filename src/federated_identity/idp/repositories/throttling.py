"""Durable source/browser/account budgets; reservations precede password work."""

from pydantic import SecretStr
from sqlalchemy import BigInteger, Integer, String
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.settings.policy import Clock, verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings


class LimitBase(DeclarativeBase):
    pass


class AuthenticationLimitRow(LimitBase):
    __tablename__ = "authentication_limits"
    bucket_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_started_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)


class AuthenticationThrottled(ValueError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Authentication attempt limit reached")
        self.retry_after = retry_after


class AuthenticationLimiter:
    def __init__(self, database: AsyncDatabase, clock: Clock, settings: RuntimeSettings) -> None:
        self.database, self.clock, self.settings = database, clock, settings

    async def reserve(self, username: str, browser: SecretStr, source: str) -> None:
        buckets = (
            ("source", source, self.settings.authentication_source_attempts),
            ("browser", browser.get_secret_value(), self.settings.authentication_browser_attempts),
            ("account", username, self.settings.authentication_account_attempts),
        )
        retry_after = 0
        async with self.database.sessions() as session:
            async with session.begin():
                for kind, value, limit in buckets:
                    digest = verifier_digest(f"authentication\0{kind}\0{value}")
                    now = self.clock.now()
                    await session.execute(
                        insert(AuthenticationLimitRow)
                        .values(bucket_digest=digest, window_started_at=now, attempts=0)
                        .on_conflict_do_nothing()
                    )
                    row = await session.get(AuthenticationLimitRow, digest, with_for_update=True)
                    if row is None:
                        raise RuntimeError("An authentication bucket must exist after reservation")
                    now = self.clock.now()
                    if now >= row.window_started_at + self.settings.authentication_window_seconds:
                        row.window_started_at, row.attempts = now, 0
                    if row.attempts >= limit:
                        retry_after = max(
                            1,
                            row.window_started_at
                            + self.settings.authentication_window_seconds
                            - now,
                        )
                        break
                    row.attempts += 1
        if retry_after:
            raise AuthenticationThrottled(retry_after)
