"""Shared typed wire artifacts; protocol implementations own their validation."""

from typing import Literal

from pydantic import ConfigDict, Field

from federated_identity.common.settings.policy import (
    FrozenModel,
    HttpsUrl,
    Identifier,
    TransactionValue,
)


class JwtHeader(FrozenModel):
    alg: Literal["RS256"]
    typ: Literal["JWT"]
    kid: Identifier


class BaseIdTokenClaims(FrozenModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="ignore", hide_input_in_errors=True)

    iss: HttpsUrl
    sub: Identifier
    aud: Identifier
    iat: int
    exp: int
    auth_time: int
    sid: Identifier
    jti: Identifier
    acr: Identifier
    amr: list[Identifier]
    at_hash: str
    azp: Identifier | None = None


class IdTokenClaims(BaseIdTokenClaims):
    nonce: TransactionValue


class RefreshIdTokenClaims(BaseIdTokenClaims):
    nonce: TransactionValue | None = None


class TokenResponse(FrozenModel):
    token_type: Literal["Bearer"]
    access_token: str = Field(min_length=32, max_length=128, repr=False)
    id_token: str = Field(min_length=100, repr=False)
    expires_in: int = Field(gt=0)
    scope: Literal["openid"]
    refresh_token: str | None = Field(default=None, min_length=32, max_length=128, repr=False)


class RefreshTokenResponse(TokenResponse):
    refresh_token: str = Field(min_length=32, max_length=128, repr=False)
