"""Durable session termination and exact-token replay receipts, owned by each SP."""

import hashlib

from sqlalchemy import BigInteger, CheckConstraint, String, Text, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class LogoutBase(DeclarativeBase):
    pass


class LogoutSessionRow(LogoutBase):
    __tablename__ = "sp_logout_sessions"

    issuer: Mapped[str] = mapped_column(Text, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class LogoutReceiptRow(LogoutBase):
    __tablename__ = "sp_logout_receipts"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="logout_receipt_positive_lifetime"),
    )

    issuer: Mapped[str] = mapped_column(Text, primary_key=True)
    token_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    received_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


async def lock_federation_session(
    session: AsyncSession, issuer: str, sid: str, *, namespace: str = "oidc-session"
) -> None:
    # All establishment/termination paths take this lock before browser/auth rows.
    # The database owns arbitration across workers; a process-local lock cannot.
    digest = hashlib.sha256(f"{namespace}\0{issuer}\0{sid}".encode()).digest()
    key = int.from_bytes(digest[:8], "big", signed=True)
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
