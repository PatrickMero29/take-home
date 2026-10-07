"""One vetted login-purpose verifier shared by the issuer and relying parties."""

from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jws import extract_compact
from pydantic import ValidationError

from federated_identity.common.security.artifacts import (
    BaseIdTokenClaims,
    IdTokenClaims,
    JwtHeader,
    RefreshIdTokenClaims,
    RefreshTokenResponse,
    TokenResponse,
)
from federated_identity.common.security.keys import PublicJwks
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationMethod,
    GrantSnapshot,
    LoginEvidence,
    SubjectIdentity,
)
from federated_identity.common.settings.policy import (
    SIGNING_ALGORITHM,
    Clock,
    FrozenModel,
    HttpsUrl,
    Identifier,
    ProtocolPolicy,
    TransactionValue,
    verifier_digest,
)


class OidcValidationProfile(FrozenModel):
    issuer: HttpsUrl
    client_id: Identifier
    policy: ProtocolPolicy


class InvalidIdToken(ValueError):
    pass


def login_header(token: str, *, max_bytes: int) -> JwtHeader:
    """Unverified routing hint only; never an issuer, key URL, or signature verdict."""
    try:
        if len(token.encode("utf-8")) > max_bytes:
            raise ValueError("Oversized ID token")
        extracted = extract_compact(token.encode("ascii"))
        return JwtHeader.model_validate(extracted.headers())
    except (JoseError, ValueError, TypeError, UnicodeError) as error:
        raise InvalidIdToken("Invalid login token header") from error


class VerifiedIdToken(FrozenModel):
    """A local validation result, not an assertion of current grant authority."""

    header: JwtHeader
    claims: IdTokenClaims
    token_digest: str

    def evidence(self, event_id: str) -> LoginEvidence:
        return token_evidence(self.header, self.claims, self.token_digest, event_id)


def token_evidence(
    header: JwtHeader, claims: BaseIdTokenClaims, digest: str, event_id: str
) -> LoginEvidence:
    try:
        return LoginEvidence(
            token_id=claims.jti,
            token_digest=digest,
            client_id=claims.aud,
            signing_key_id=header.kid,
            authentication=AuthenticationEvent(
                event_id=event_id,
                session_id=claims.sid,
                subject=SubjectIdentity(issuer=claims.iss, subject=claims.sub),
                authenticated_at=claims.auth_time,
                assurance=Assurance(claims.acr),
                methods=tuple(AuthenticationMethod(method) for method in claims.amr),
            ),
            issued_at=claims.iat,
            expires_at=claims.exp,
        )
    except ValueError as error:
        raise InvalidIdToken("ID-token authentication facts do not meet the profile") from error


class VerifiedRefreshToken(FrozenModel):
    header: JwtHeader
    claims: RefreshIdTokenClaims
    token_digest: str

    def evidence(self, event_id: str) -> LoginEvidence:
        return token_evidence(self.header, self.claims, self.token_digest, event_id)


class VerifiedRefresh(FrozenModel):
    response: RefreshTokenResponse
    claims: RefreshIdTokenClaims
    evidence: LoginEvidence
    context: GrantSnapshot
    access_expires_at: int


def validate_refresh_token(
    response: RefreshTokenResponse,
    *,
    settings: OidcValidationProfile,
    authentication: AuthenticationEvent,
    nonce: str | None,
    keys: PublicJwks,
    clock: Clock,
) -> VerifiedRefreshToken:
    if len(response.id_token.encode("utf-8")) > settings.policy.max_jwt_bytes:
        raise InvalidIdToken("Refresh ID token exceeds the profile limit")
    try:
        decoded = jwt.decode(response.id_token, keys.key_set(), algorithms=[SIGNING_ALGORITHM])
        header = JwtHeader.model_validate(decoded.header)
        claims = RefreshIdTokenClaims.model_validate(decoded.claims)
        params = {"client_id": settings.client_id, "access_token": response.access_token}
        if claims.nonce is not None:
            if nonce is None or claims.nonce != nonce:
                raise ValueError("Refresh nonce does not match the original flow")
            params["nonce"] = nonce
        registered = CodeIDToken(
            decoded.claims,
            decoded.header,
            {
                "iss": {"essential": True, "value": settings.issuer},
                "aud": {"essential": True, "value": settings.client_id},
            },
            params,
        )
        registered.validate(now=clock.now(), leeway=settings.policy.clock_skew_seconds)
        verified = VerifiedRefreshToken(
            header=header, claims=claims, token_digest=verifier_digest(response.id_token)
        )
        if (
            claims.iss != settings.issuer
            or claims.aud != settings.client_id
            or claims.exp <= claims.iat
            or claims.exp - claims.iat > settings.policy.id_token_ttl_seconds
            or clock.now() >= claims.exp + settings.policy.clock_skew_seconds
            or verified.evidence(authentication.event_id).authentication != authentication
        ):
            raise ValueError("Refresh changed authentication history or lifetime")
        return verified
    except (JoseError, ValidationError, ValueError, TypeError) as error:
        raise InvalidIdToken("Invalid refresh authentication evidence") from error


class VerifiedLogin(FrozenModel):
    response: TokenResponse
    claims: IdTokenClaims
    evidence: LoginEvidence
    context: GrantSnapshot


def validate_login_token(
    response: TokenResponse,
    *,
    settings: OidcValidationProfile,
    nonce: TransactionValue,
    keys: PublicJwks,
    clock: Clock,
) -> VerifiedIdToken:
    if len(response.id_token.encode("utf-8")) > settings.policy.max_jwt_bytes:
        raise InvalidIdToken("ID token exceeds the profile limit")
    try:
        decoded = jwt.decode(response.id_token, keys.key_set(), algorithms=[SIGNING_ALGORITHM])
        header = JwtHeader.model_validate(decoded.header)
        claims = IdTokenClaims.model_validate(decoded.claims)
        code_claims = CodeIDToken(
            decoded.claims,
            decoded.header,
            {
                "iss": {"essential": True, "value": settings.issuer},
                "aud": {"essential": True, "value": settings.client_id},
            },
            {
                "client_id": settings.client_id,
                "nonce": nonce,
                "access_token": response.access_token,
            },
        )
        code_claims.validate(now=clock.now(), leeway=settings.policy.clock_skew_seconds)
    except (JoseError, ValidationError, ValueError, TypeError) as error:
        raise InvalidIdToken("Invalid ID token") from error
    now = clock.now()
    if (
        claims.iss != settings.issuer
        or claims.aud != settings.client_id
        or claims.exp <= claims.iat
        or claims.exp - claims.iat > settings.policy.id_token_ttl_seconds
        or now >= claims.exp + settings.policy.clock_skew_seconds
        or claims.auth_time > claims.iat + settings.policy.clock_skew_seconds
    ):
        raise InvalidIdToken("Invalid ID-token identity or lifetime")
    return VerifiedIdToken(
        header=header, claims=claims, token_digest=verifier_digest(response.id_token)
    )


def validate_id_token(
    response: TokenResponse,
    *,
    settings: OidcValidationProfile,
    nonce: TransactionValue,
    keys: PublicJwks,
    clock: Clock,
) -> IdTokenClaims:
    return validate_login_token(
        response, settings=settings, nonce=nonce, keys=keys, clock=clock
    ).claims


def verified_login_evidence(
    response: TokenResponse,
    *,
    settings: OidcValidationProfile,
    nonce: TransactionValue,
    keys: PublicJwks,
    clock: Clock,
    event_id: str,
) -> LoginEvidence:
    return validate_login_token(
        response, settings=settings, nonce=nonce, keys=keys, clock=clock
    ).evidence(event_id)
