"""Purpose-specific OIDC logout JWTs; none of these artifacts confer login authority."""

from typing import Literal

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jws import extract_compact
from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

from federated_identity.common.security.keys import PublicJwks, SigningKey
from federated_identity.common.security.oidc import OidcValidationProfile
from federated_identity.common.settings.policy import (
    SIGNING_ALGORITHM,
    Clock,
    FrozenModel,
    HttpsUrl,
    Identifier,
    verifier_digest,
)

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class InvalidLogoutToken(ValueError):
    pass


class LogoutHeader(FrozenModel):
    alg: Literal["RS256"]
    typ: Literal["logout+jwt"]
    kid: Identifier


class LogoutClaims(FrozenModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="ignore", hide_input_in_errors=True)

    iss: HttpsUrl
    aud: Identifier
    iat: int = Field(ge=1)
    exp: int = Field(ge=1)
    jti: Identifier
    sid: Identifier  # This deployment requires session-specific logout.
    sub: Identifier | None = None
    events: dict[str, dict[str, JsonValue]]

    @model_validator(mode="before")
    @classmethod
    def prohibit_nonce(cls, value: object) -> object:
        if isinstance(value, dict) and "nonce" in value:
            raise ValueError("A logout token must not contain nonce, including null")
        return value

    @model_validator(mode="after")
    def logout_event(self) -> "LogoutClaims":
        if LOGOUT_EVENT not in self.events:
            raise ValueError("The back-channel logout event is required")
        return self


class VerifiedLogout(FrozenModel):
    header: LogoutHeader
    claims: LogoutClaims
    token_digest: str


def logout_header(token: str, *, max_bytes: int) -> LogoutHeader:
    """Only a bounded kid routing hint, followed by pinned cryptographic validation."""
    try:
        if len(token.encode("utf-8")) > max_bytes:
            raise ValueError("Oversized logout token")
        return LogoutHeader.model_validate(extract_compact(token.encode("ascii")).headers())
    except (JoseError, ValueError, TypeError, UnicodeError) as error:
        raise InvalidLogoutToken("Invalid logout token header") from error


def sign_logout_token(claims: LogoutClaims, signer: SigningKey) -> str:
    header = LogoutHeader(alg=SIGNING_ALGORITHM, typ="logout+jwt", kid=signer.kid)
    return jwt.encode(
        header.model_dump(),
        claims.model_dump(exclude_none=True),
        signer.key,
        algorithms=[SIGNING_ALGORITHM],
    )


def validate_logout_token(
    token: str, *, settings: OidcValidationProfile, keys: PublicJwks, clock: Clock
) -> VerifiedLogout:
    logout_header(token, max_bytes=settings.policy.max_jwt_bytes)
    try:
        decoded = jwt.decode(token, keys.key_set(), algorithms=[SIGNING_ALGORITHM])
        header = LogoutHeader.model_validate(decoded.header)
        claims = LogoutClaims.model_validate(decoded.claims)
        now, skew = clock.now(), settings.policy.clock_skew_seconds
        jwt.JWTClaimsRegistry(now=now, leeway=skew).validate(decoded.claims)
        if (
            claims.iss != settings.issuer
            or claims.aud != settings.client_id
            or not 0 < claims.exp - claims.iat <= settings.policy.logout_token_ttl_seconds
            or claims.iat > now + skew
            or now >= claims.exp + skew
        ):
            raise ValueError("Invalid logout identity or lifetime")
        return VerifiedLogout(header=header, claims=claims, token_digest=verifier_digest(token))
    except (JoseError, ValidationError, ValueError, TypeError) as error:
        raise InvalidLogoutToken("Invalid back-channel logout token") from error
