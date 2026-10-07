"""Normalized IDP security lineage and irreversible lifecycle state."""

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.idp.repositories.tables import ClientRow


class SecurityBase(DeclarativeBase):
    pass


class SecurityGateRow(SecurityBase):
    __tablename__ = "security_gate"
    __table_args__ = (
        CheckConstraint("gate_id = 1", name="security_gate_singleton"),
        CheckConstraint("revision >= 0", name="security_revision_nonnegative"),
    )

    gate_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class SigningTrustRow(SecurityBase):
    __tablename__ = "signing_trust"
    __table_args__ = (
        CheckConstraint(
            "state IN ('prepared','active','draining','retired','revoked')",
            name="signing_trust_state",
        ),
        CheckConstraint("verification_deadline >= 0", name="signing_deadline_nonnegative"),
        Index("one_active_signer", "state", unique=True, postgresql_where=text("state='active'")),
    )

    key_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    verification_deadline: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    published_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class IdpSessionRow(SecurityBase):
    __tablename__ = "idp_security_sessions"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="idp_session_positive_lifetime"),
        CheckConstraint(
            "(revoked_at IS NULL) = (revocation_reason IS NULL)", name="idp_session_revocation_pair"
        ),
    )

    session_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)


class AuthenticationEventRow(SecurityBase):
    __tablename__ = "authentication_events"
    __table_args__ = (UniqueConstraint("event_id", "session_id", name="event_session_binding"),)

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("idp_security_sessions.session_id"), nullable=False
    )
    authenticated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    assurance: Mapped[str] = mapped_column(String(255), nullable=False)
    methods: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class FederationGrantRow(SecurityBase):
    __tablename__ = "federation_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["event_id", "session_id"],
            ["authentication_events.event_id", "authentication_events.session_id"],
            name="grant_event_session_binding",
        ),
        CheckConstraint("expires_at > created_at", name="grant_positive_lifetime"),
        CheckConstraint(
            "(revoked_at IS NULL) = (revocation_reason IS NULL)", name="grant_revocation_pair"
        ),
        UniqueConstraint("grant_id", "root_signing_key_id", name="grant_signing_binding"),
    )

    grant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        ForeignKey(ClientRow.__table__.c.client_id), nullable=False
    )
    session_id: Mapped[str] = mapped_column(
        ForeignKey("idp_security_sessions.session_id"), nullable=False
    )
    event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    root_signing_key_id: Mapped[str] = mapped_column(
        ForeignKey("signing_trust.key_id"), nullable=False
    )
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)


class AuthenticationEvidenceRow(SecurityBase):
    __tablename__ = "authentication_evidence"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="evidence_positive_lifetime"),
        ForeignKeyConstraint(
            ["grant_id", "signing_key_id"],
            ["federation_grants.grant_id", "federation_grants.root_signing_key_id"],
            name="evidence_grant_signing_binding",
        ),
    )

    token_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    grant_id: Mapped[str] = mapped_column(
        ForeignKey("federation_grants.grant_id"), unique=True, nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    signing_key_id: Mapped[str] = mapped_column(ForeignKey("signing_trust.key_id"), nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class RefreshFamilyRow(SecurityBase):
    __tablename__ = "refresh_families"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="family_positive_lifetime"),
        CheckConstraint("generation >= 0", name="family_generation_nonnegative"),
        UniqueConstraint("family_id", "grant_id", name="family_grant_binding"),
    )

    family_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    grant_id: Mapped[str] = mapped_column(
        ForeignKey("federation_grants.grant_id"), unique=True, nullable=False
    )
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class RefreshCredentialRow(SecurityBase):
    __tablename__ = "refresh_credentials"
    __table_args__ = (
        UniqueConstraint("family_id", "generation", name="refresh_family_generation"),
        CheckConstraint("generation >= 0", name="refresh_generation_nonnegative"),
        CheckConstraint("expires_at > issued_at", name="refresh_positive_lifetime"),
    )

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    family_id: Mapped[str] = mapped_column(ForeignKey("refresh_families.family_id"), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    consumed_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    predecessor_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AccessCredentialRow(SecurityBase):
    __tablename__ = "access_credentials"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="access_positive_lifetime"),
        ForeignKeyConstraint(
            ["family_id", "grant_id"],
            ["refresh_families.family_id", "refresh_families.grant_id"],
            name="access_family_grant_binding",
        ),
    )

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("federation_grants.grant_id"), nullable=False)
    family_id: Mapped[str] = mapped_column(ForeignKey("refresh_families.family_id"), nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class RefreshIssuanceRow(SecurityBase):
    __tablename__ = "refresh_issuances"

    token_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    family_id: Mapped[str] = mapped_column(String(255), nullable=False)
    grant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    successor_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    access_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
