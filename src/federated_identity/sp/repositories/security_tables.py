"""SP-local evidence and credentials; remote grant IDs do not provide shared DB access."""

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.sessions import BrowserSessionRow


class SpSecurityBase(DeclarativeBase):
    pass


class SpAuthenticationRow(SpSecurityBase):
    __tablename__ = "sp_authentication_sessions"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="sp_positive_lifetime"),
        CheckConstraint("idle_expires_at <= expires_at", name="sp_idle_absolute_ceiling"),
        CheckConstraint(
            "last_seen_at >= created_at AND idle_expires_at > last_seen_at",
            name="sp_activity_lifetime",
        ),
    )

    token_digest: Mapped[str] = mapped_column(
        ForeignKey(BrowserSessionRow.__table__.c.token_digest, ondelete="CASCADE"),
        primary_key=True,
    )
    encrypted_evidence: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_access_token: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_refresh_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    grant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_seen_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    idle_expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    access_expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    refresh_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    refresh_state: Mapped[str] = mapped_column(String(16), nullable=False, default="ready")
    refresh_attempt_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    refresh_started_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
