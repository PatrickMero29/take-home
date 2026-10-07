"""Encrypted issuer key custody and immutable retention for every signed artifact purpose."""

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.idp.repositories.operator import OperatorRow
from federated_identity.idp.repositories.security_tables import SigningTrustRow


class SigningBase(DeclarativeBase):
    pass


class SigningMaterialRow(SigningBase):
    __tablename__ = "signing_key_material"

    key_id: Mapped[str] = mapped_column(ForeignKey(SigningTrustRow.key_id), primary_key=True)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class SignedArtifactRow(SigningBase):
    __tablename__ = "signed_artifacts"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="signed_artifact_positive_lifetime"),
        CheckConstraint("purpose IN ('id_token','logout_token')", name="signed_artifact_purpose"),
    )

    artifact_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    key_id: Mapped[str] = mapped_column(ForeignKey(SigningTrustRow.key_id), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class SigningAuditRow(SigningBase):
    __tablename__ = "signing_audit"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey(OperatorRow.operator_id), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    key_id: Mapped[str] = mapped_column(ForeignKey(SigningTrustRow.key_id), nullable=False)
    previous_active_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    replacement_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
