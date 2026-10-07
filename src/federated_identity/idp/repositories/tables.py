"""Phase 0 persistence: public registrations, one-use codes, replay, and issuance."""

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ClientRow(Base):
    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    backchannel_logout_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowed_grants: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=lambda: ["authorization_code", "refresh_token"]
    )
    allowed_scopes: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=lambda: ["openid"]
    )
    post_logout_redirect_uris: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    token_endpoint_auth_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="private_key_jwt"
    )
    token_endpoint_auth_signing_alg: Mapped[str] = mapped_column(
        String(16), nullable=False, default="RS256"
    )
    registration_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    compromised_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AuthorizationCodeRow(Base):
    __tablename__ = "authorization_codes"

    code_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(256), nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    consumed_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sub: Mapped[str] = mapped_column(String(255), nullable=False)
    sid: Mapped[str] = mapped_column(String(255), nullable=False)
    # Nullable only for pre-normalization historical rows, which cannot be redeemed.
    event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_version: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    auth_time: Mapped[int] = mapped_column(Integer, nullable=False)
    acr: Mapped[str] = mapped_column(String(255), nullable=False)
    amr: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class AssertionReplayRow(Base):
    __tablename__ = "client_assertion_replays"

    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), primary_key=True)
    jti: Mapped[str] = mapped_column(String(256), primary_key=True)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)


class IssuanceRow(Base):
    __tablename__ = "token_issuances"

    issuance_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    grant_id: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    code_digest: Mapped[str] = mapped_column(
        ForeignKey("authorization_codes.code_digest"), unique=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), nullable=False)
    access_token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    id_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signing_key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    sub: Mapped[str] = mapped_column(String(255), nullable=False)
    sid: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
