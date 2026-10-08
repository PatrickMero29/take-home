"""Immutable, encrypted evidence of a committed sensitive demonstration operation."""

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.sp.repositories.security_tables import SpAuthenticationRow


class SensitiveBase(DeclarativeBase):
    pass


class SensitiveOperationRow(SensitiveBase):
    __tablename__ = "sensitive_operations"
    operation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_digest: Mapped[str] = mapped_column(
        ForeignKey(SpAuthenticationRow.token_digest), nullable=False
    )
    encrypted_evidence: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
