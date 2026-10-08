"""Durable encrypted logout delivery with database leases and fenced acknowledgement."""

import uuid

from pydantic import JsonValue
from sqlalchemy import BigInteger, Integer, LargeBinary, String, Text, func, or_, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, FrozenModel, HttpsUrl
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import IdpSessionRow
from federated_identity.idp.repositories.tables import ClientRow


class OutboxBase(DeclarativeBase):
    pass


class LogoutOutboxRow(OutboxBase):
    __tablename__ = "logout_outbox"

    delivery_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    destination: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    next_attempt_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    token_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    signing_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    completed_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(32), nullable=True)


class LogoutDeliveryStatus(FrozenModel):
    delivery_id: str
    client_id: str | None
    status: str
    attempts: int
    next_attempt_at: int
    last_error: str | None


class PostgresLogoutOutbox:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def enqueue(self, destination: HttpsUrl, payload: dict[str, JsonValue]) -> str:
        identifier = str(uuid.uuid4())
        now = self.clock.now()
        async with self.database.sessions() as session:
            session.add(
                LogoutOutboxRow(
                    delivery_id=identifier,
                    destination=destination,
                    encrypted_payload=self.cipher.encrypt(payload, purpose="logout-delivery"),
                    created_at=now,
                    next_attempt_at=now,
                    attempts=0,
                    status="pending",
                )
            )
            await session.commit()
        return identifier

    async def pending_count(self) -> int:
        async with self.database.sessions() as session:
            value = await session.scalar(
                select(func.count())
                .select_from(LogoutOutboxRow)
                .where(LogoutOutboxRow.status == "pending")
            )
            return int(value or 0)

    async def due(self, *, limit: int, session_id: str | None = None) -> list[str]:
        now = self.clock.now()
        statement = select(LogoutOutboxRow.delivery_id).where(
            LogoutOutboxRow.status == "pending",
            LogoutOutboxRow.next_attempt_at <= now,
            or_(
                LogoutOutboxRow.lease_expires_at.is_(None), LogoutOutboxRow.lease_expires_at <= now
            ),
        )
        if session_id is not None:
            statement = statement.where(LogoutOutboxRow.session_id == session_id)
        async with self.database.sessions() as session:
            return list(
                await session.scalars(
                    statement.order_by(
                        LogoutOutboxRow.created_at, LogoutOutboxRow.delivery_id
                    ).limit(limit)
                )
            )

    async def inspect(self) -> list[LogoutDeliveryStatus]:
        async with self.database.sessions() as session:
            rows = await session.scalars(
                select(LogoutOutboxRow).order_by(LogoutOutboxRow.created_at.desc()).limit(100)
            )
            return [
                LogoutDeliveryStatus(
                    delivery_id=row.delivery_id,
                    client_id=row.client_id,
                    status=row.status,
                    attempts=row.attempts,
                    next_attempt_at=row.next_attempt_at,
                    last_error=row.last_error,
                )
                for row in rows
            ]

    async def retry(self, delivery_id: str) -> None:
        """Owner-controlled recovery; use current registered metadata, never an input URL."""
        async with self.database.sessions() as session:
            async with session.begin():
                work = await SecurityUnitOfWork.acquire(session)
                row = await session.get(LogoutOutboxRow, delivery_id, with_for_update=True)
                if row is None or row.status not in {"failed", "skipped"}:
                    raise ValueError("Only failed or skipped deliveries can be recovered")
                parent = await work.get(IdpSessionRow, row.session_id) if row.session_id else None
                client = await work.get(ClientRow, row.client_id) if row.client_id else None
                if (
                    parent is None
                    or parent.revoked_at is None
                    or parent.issuer != row.issuer
                    or client is None
                    or client.backchannel_logout_uri is None
                ):
                    raise ValueError("Recovery requires bound revocation and registered delivery")
                row.destination = client.backchannel_logout_uri
                row.status, row.attempts, row.last_error = "pending", 0, None
                row.lease_id = row.lease_expires_at = row.completed_at = None
                row.next_attempt_at = self.clock.now()
