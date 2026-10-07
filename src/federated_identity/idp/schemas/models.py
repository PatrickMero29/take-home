"""Typed application data at the protocol and persistence boundaries."""

from dataclasses import dataclass
from http import HTTPStatus
from typing import Annotated, Literal

from pydantic import Field, field_validator

from federated_identity.common.policy import (
    FrozenModel,
    HttpsUrl,
    Identifier,
    TransactionValue,
)
from federated_identity.common.security.artifacts import IdTokenClaims as IdTokenClaims
from federated_identity.common.security.artifacts import JwtHeader as JwtHeader
from federated_identity.common.security.artifacts import TokenResponse as TokenResponse
from federated_identity.common.security.contracts import LogoutTokenStatus
from federated_identity.common.security.model import (
    AuthenticationEvent,
    GrantSnapshot,
    LoginEvidence,
)
from federated_identity.idp.schemas.clients import ClientRegistration as ClientRegistration


class AuthenticatedPrincipal(FrozenModel):
    """An authentication event supplied by a trusted upstream authenticator."""

    sub: Identifier
    sid: Identifier
    event_id: Identifier
    auth_time: int = Field(ge=1)
    acr: Identifier
    amr: tuple[Identifier, ...] = Field(min_length=1, max_length=8)

    @classmethod
    def from_event(cls, event: AuthenticationEvent) -> "AuthenticatedPrincipal":
        return cls(
            sub=event.subject.subject,
            sid=event.session_id,
            event_id=event.event_id,
            auth_time=event.authenticated_at,
            acr=event.assurance.value,
            amr=tuple(method.value for method in event.methods),
        )


class AuthorizationParameters(FrozenModel):
    response_type: Literal["code"]
    client_id: Identifier
    redirect_uri: HttpsUrl
    scope: Literal["openid"]
    state: TransactionValue
    nonce: TransactionValue
    code_challenge: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    code_challenge_method: Literal["S256"]
    prompt: Literal["none", "login"] | None = None
    max_age: int | None = Field(default=None, ge=0, le=86400)
    acr_values: Literal["urn:take-home:acr:password", "urn:take-home:acr:password-totp"] | None = (
        None
    )

    @field_validator("max_age", mode="before")
    @classmethod
    def decimal_max_age(cls, value: object) -> object:
        # Form/query values are strings. No float, boolean, or coercion of a
        # malformed age is allowed at this protocol boundary.
        if isinstance(value, str) and value.isascii() and value.isdecimal():
            return int(value)
        return value


class AuthorizationCodeData(FrozenModel):
    code_digest: str
    client_id: Identifier
    redirect_uri: HttpsUrl
    scope: Literal["openid"]
    nonce: TransactionValue
    code_challenge: str
    created_at: int
    expires_at: int
    consumed_at: int | None
    principal: AuthenticatedPrincipal
    client_version: int = Field(default=1, ge=1)


class RefreshCredentialData(FrozenModel):
    token_digest: str
    client_id: Identifier
    grant_id: Identifier
    family_id: Identifier
    generation: int
    expires_at: int
    consumed_at: int | None
    authentication: AuthenticationEvent


class ClientAssertionClaims(FrozenModel):
    iss: Identifier
    sub: Identifier
    aud: HttpsUrl
    iat: int
    exp: int
    jti: TransactionValue


class OAuthErrorResponse(FrozenModel):
    error: str
    error_description: str | None = None
    error_uri: str | None = None
    state: str | None = None


class IssuanceEvidence(FrozenModel):
    issuance_id: Identifier
    grant_id: Identifier
    client_id: Identifier
    sub: Identifier
    sid: Identifier
    signing_key_id: Identifier
    id_token_digest: str
    created_at: int


class IntrospectionPayload(FrozenModel):
    active: bool
    client_id: Identifier | None = None
    sub: Identifier | None = None
    exp: int | None = None
    context: GrantSnapshot | None = None
    credential_evidence: LoginEvidence | None = None


class ProviderMetadata(FrozenModel):
    issuer: HttpsUrl
    authorization_endpoint: HttpsUrl
    token_endpoint: HttpsUrl
    jwks_uri: HttpsUrl
    introspection_endpoint: HttpsUrl
    revocation_endpoint: HttpsUrl
    end_session_endpoint: HttpsUrl
    backchannel_logout_supported: Literal[True]
    backchannel_logout_session_supported: Literal[True]
    response_types_supported: list[Literal["code"]]
    grant_types_supported: list[Literal["authorization_code", "refresh_token"]]
    subject_types_supported: list[Literal["public"]]
    scopes_supported: list[Literal["openid"]]
    id_token_signing_alg_values_supported: list[Literal["RS256"]]
    token_endpoint_auth_methods_supported: list[Literal["private_key_jwt"]]
    token_endpoint_auth_signing_alg_values_supported: list[Literal["RS256"]]
    introspection_endpoint_auth_methods_supported: list[Literal["private_key_jwt"]]
    introspection_endpoint_auth_signing_alg_values_supported: list[Literal["RS256"]]
    revocation_endpoint_auth_methods_supported: list[Literal["private_key_jwt"]]
    revocation_endpoint_auth_signing_alg_values_supported: list[Literal["RS256"]]
    code_challenge_methods_supported: list[Literal["S256"]]
    acr_values_supported: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class ProtocolMessage:
    method: str
    endpoint: str
    parameters: dict[str, str]


@dataclass(frozen=True)
class AuthorizationInteraction:
    parameters: AuthorizationParameters


@dataclass(frozen=True)
class ProtocolResponse:
    status: HTTPStatus
    body: TokenResponse | OAuthErrorResponse | IntrospectionPayload | LogoutTokenStatus | str
    headers: tuple[tuple[str, str], ...] = ()
