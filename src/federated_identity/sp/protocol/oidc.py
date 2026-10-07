"""A typed async RP boundary with pinned discovery and explicit OIDC validation."""

import secrets
import ssl
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

import httpx2 as httpx
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.client import OAuth2Client
from authlib.oauth2.rfc6749.errors import MismatchingStateException, MissingCodeException
from authlib.oauth2.rfc6749.parameters import parse_authorization_code_response
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from pydantic import Field, SecretStr

from federated_identity.common.keys import PublicJwks, SigningKey
from federated_identity.common.policy import (
    CLIENT_AUTH_METHOD,
    OPENID_SCOPE,
    SIGNING_ALGORITHM,
    Clock,
    HttpsUrl,
)
from federated_identity.common.security.artifacts import RefreshTokenResponse
from federated_identity.common.security.contracts import GrantChecker
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationRequirement,
    SecurityDenied,
)
from federated_identity.common.security.oidc import InvalidIdToken as InvalidIdToken
from federated_identity.common.security.oidc import (
    OidcValidationProfile,
    VerifiedLogin,
    VerifiedRefresh,
    login_header,
    validate_login_token,
    validate_refresh_token,
)
from federated_identity.common.security.oidc import validate_id_token as validate_id_token
from federated_identity.common.security.oidc import (
    verified_login_evidence as verified_login_evidence,
)
from federated_identity.common.security.policies import require_active_grant, require_assurance
from federated_identity.idp.schemas.models import (
    IdTokenClaims,
    ProviderMetadata,
    TokenResponse,
)
from federated_identity.sp.protocol.jwks import IssuerJwksCache
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker


class RpSettings(OidcValidationProfile):
    redirect_uri: HttpsUrl
    request_timeout_seconds: float = Field(default=5, gt=0, le=30)
    jwks_cache_ttl_seconds: int = Field(default=300, ge=1, le=900)
    jwks_refresh_cooldown_seconds: int = Field(default=10, ge=1, le=60)

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.issuer}/introspect"

    @property
    def revocation_endpoint(self) -> str:
        return f"{self.issuer}/revoke"


@dataclass(frozen=True)
class AuthorizationTransaction:
    client_id: str
    redirect_uri: str
    authorization_url: str = field(repr=False)
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    verifier: str = field(repr=False)
    prompt: Literal["login"] | None = None
    max_age: int | None = None
    requested_at: int | None = None
    acr_values: Assurance | None = None
    expected_subject: str | None = None


class InvalidAuthorizationResponse(ValueError):
    pass


class OidcClient:
    def __init__(
        self,
        settings: RpSettings,
        key: SigningKey,
        clock: Clock,
        *,
        tls_context: ssl.SSLContext,
        transport: httpx.AsyncBaseTransport | None = None,
        grant_checker: GrantChecker | None = None,
    ) -> None:
        self.settings = settings
        self.key = key
        self.clock = clock
        self.tls_context = tls_context
        self.transport = transport
        self.jwks = IssuerJwksCache(
            issuer=settings.issuer,
            jwks_uri=f"{settings.issuer}/jwks.json",
            clock=clock,
            loader=self.fetch_jwks,
            ttl_seconds=settings.jwks_cache_ttl_seconds,
            refresh_cooldown_seconds=settings.jwks_refresh_cooldown_seconds,
        )
        self.grant_checker = (
            grant_checker
            if grant_checker is not None
            else AuthenticatedGrantChecker(settings, key, tls_context, clock, transport=transport)
        )

    def begin(
        self,
        *,
        prompt: Literal["login"] | None = None,
        max_age: int | None = None,
        acr_values: Assurance | None = None,
        expected_subject: str | None = None,
    ) -> AuthorizationTransaction:
        if max_age is not None and not 0 <= max_age <= 86400:
            raise ValueError("A bounded authentication age is required")
        if acr_values is not None and acr_values not in {
            Assurance.PASSWORD,
            Assurance.PASSWORD_TOTP,
        }:
            raise ValueError("An implemented authentication assurance is required")
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(32)
        # Authlib's framework-independent client creates the authorization
        # parameters and S256 challenge; it performs no I/O here.
        client = OAuth2Client(
            session=None,
            client_id=self.settings.client_id,
            scope=OPENID_SCOPE,
            redirect_uri=self.settings.redirect_uri,
            code_challenge_method="S256",
        )
        url, state = client.create_authorization_url(
            f"{self.settings.issuer}/authorize",
            code_verifier=verifier,
            nonce=nonce,
            **({"prompt": prompt} if prompt else {}),
            **({"max_age": max_age} if max_age is not None else {}),
            **({"acr_values": acr_values.value} if acr_values is not None else {}),
        )
        return AuthorizationTransaction(
            client_id=self.settings.client_id,
            redirect_uri=self.settings.redirect_uri,
            authorization_url=str(url),
            state=str(state),
            nonce=nonce,
            verifier=verifier,
            prompt=prompt,
            max_age=max_age,
            requested_at=self.clock.now()
            if prompt or max_age is not None or acr_values is not None
            else None,
            acr_values=acr_values,
            expected_subject=expected_subject,
        )

    async def provider(self) -> tuple[ProviderMetadata, PublicJwks]:
        async with httpx.AsyncClient(
            verify=self.tls_context,
            transport=self.transport,
            timeout=self.settings.request_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.get(f"{self.settings.issuer}/.well-known/openid-configuration")
            response.raise_for_status()
            metadata = ProviderMetadata.model_validate(response.json())
            if (
                metadata.issuer != self.settings.issuer
                or metadata.authorization_endpoint != f"{self.settings.issuer}/authorize"
                or metadata.token_endpoint != f"{self.settings.issuer}/token"
                or metadata.jwks_uri != f"{self.settings.issuer}/jwks.json"
                or metadata.introspection_endpoint != self.settings.introspection_endpoint
                or metadata.revocation_endpoint != self.settings.revocation_endpoint
                or metadata.end_session_endpoint != f"{self.settings.issuer}/end-session"
            ):
                raise InvalidIdToken("Provider metadata does not match the pinned issuer")
        keys = await self.jwks.get()
        return metadata, keys

    async def fetch_jwks(self) -> PublicJwks:
        async with httpx.AsyncClient(
            verify=self.tls_context,
            transport=self.transport,
            timeout=self.settings.request_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            async with client.stream("GET", f"{self.settings.issuer}/jwks.json") as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > 32768:
                        raise InvalidIdToken("Issuer public key response exceeds the trust limit")
                    body.extend(chunk)
                return PublicJwks.model_validate_json(body)

    async def exchange(
        self, transaction: AuthorizationTransaction, callback_url: str
    ) -> tuple[TokenResponse, IdTokenClaims]:
        result = await self.exchange_verified(transaction, callback_url)
        return result.response, result.claims

    async def exchange_verified(
        self, transaction: AuthorizationTransaction, callback_url: str
    ) -> VerifiedLogin:
        if (
            transaction.client_id != self.settings.client_id
            or transaction.redirect_uri != self.settings.redirect_uri
        ):
            raise InvalidAuthorizationResponse("Transaction belongs to another relying party")
        # Validate the callback and browser-transaction state before any network
        # operation. Authlib's parser flattens duplicate query parameters, so
        # reject ambiguity before handing the response to the library.
        try:
            received = urlsplit(callback_url)
            expected = urlsplit(transaction.redirect_uri)
            if (
                len(callback_url.encode("utf-8")) > self.settings.policy.max_form_bytes
                or (received.scheme, received.netloc, received.path)
                != (expected.scheme, expected.netloc, expected.path)
                or received.fragment
                or len(transaction.state) < 16
            ):
                raise ValueError("Invalid callback URI")
            items = parse_qsl(received.query, keep_blank_values=True, max_num_fields=16)
            if (
                len({name for name, _ in items}) != len(items)
                or any(
                    name not in {"code", "state", "error", "error_description", "error_uri"}
                    for name, _ in items
                )
                or any(name == "error" for name, _ in items)
            ):
                raise ValueError("Ambiguous or unsuccessful callback response")
            parameters = parse_authorization_code_response(callback_url, state=transaction.state)
            code = str(parameters["code"])
            if not 32 <= len(code) <= 128:
                raise ValueError("Invalid authorization code")
        except (ValueError, MissingCodeException, MismatchingStateException) as error:
            raise InvalidAuthorizationResponse("Invalid authorization response") from error
        metadata, keys = await self.provider()
        now = self.clock.now()
        authentication = PrivateKeyJWT(
            metadata.token_endpoint,
            claims={"iat": now, "exp": now + self.settings.policy.assertion_ttl_seconds},
            headers={"kid": self.key.kid},
            alg=SIGNING_ALGORITHM,
        )
        # Request-local client/token state and fresh assertions prevent a
        # shared OAuth client from bleeding credentials across concurrent flows.
        async with AsyncOAuth2Client(
            client_id=self.settings.client_id,
            client_secret=self.key.key,
            scope=OPENID_SCOPE,
            redirect_uri=self.settings.redirect_uri,
            state=transaction.state,
            token_endpoint_auth_method=CLIENT_AUTH_METHOD,
            verify=self.tls_context,
            transport=self.transport,
            timeout=self.settings.request_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            client.register_client_auth_method(authentication)
            try:
                raw_response = await client.fetch_token(
                    metadata.token_endpoint,
                    code=code,
                    code_verifier=transaction.verifier,
                )
            except OAuthError as error:
                raise InvalidAuthorizationResponse("The IDP rejected the code exchange") from error
        # Authlib augments the wire response with its local expires_at cache.
        # Strip only that known library field; retain strict wire validation.
        wire_response = {
            name: value for name, value in raw_response.items() if name != "expires_at"
        }
        response = TokenResponse.model_validate(wire_response)
        header = login_header(response.id_token, max_bytes=self.settings.policy.max_jwt_bytes)
        if not any(key.kid == header.kid for key in keys.keys):
            keys = await self.jwks.for_key(header.kid)
        verified = validate_login_token(
            response,
            settings=self.settings,
            nonce=transaction.nonce,
            keys=keys,
            clock=self.clock,
        )
        status = await self.grant_checker.check(SecretStr(response.access_token))
        try:
            context = require_active_grant(
                status,
                issuer=self.settings.issuer,
                client_id=self.settings.client_id,
                subject=verified.claims.sub,
                now=self.clock.now(),
            )
        except SecurityDenied as error:
            raise InvalidIdToken("Login evidence has no active bound authorization") from error
        evidence = verified.evidence(context.authentication.event_id)
        if context.evidence != evidence:
            raise InvalidIdToken("Login evidence does not match committed recipient-bound issuance")
        if (
            transaction.expected_subject is not None
            and verified.claims.sub != transaction.expected_subject
        ):
            raise InvalidIdToken("Re-authentication substituted the expected subject")
        if transaction.acr_values is not None:
            try:
                require_assurance(
                    context.authentication,
                    AuthenticationRequirement(
                        minimum=transaction.acr_values,
                        max_age_seconds=transaction.max_age if transaction.max_age != 0 else None,
                        reauthenticate_since=transaction.requested_at
                        if transaction.prompt == "login"
                        else None,
                    ),
                    now=self.clock.now(),
                )
            except SecurityDenied as error:
                raise InvalidIdToken(
                    "The returned event does not meet requested assurance/recency"
                ) from error
        if transaction.requested_at is not None and (
            (
                (transaction.prompt == "login" or transaction.max_age == 0)
                and verified.claims.auth_time < transaction.requested_at
            )
            or (
                transaction.max_age is not None
                and self.clock.now() - verified.claims.auth_time
                > transaction.max_age + self.settings.policy.clock_skew_seconds
            )
        ):
            raise InvalidIdToken("Re-authentication did not meet the requested freshness")
        return VerifiedLogin(
            response=response, claims=verified.claims, evidence=evidence, context=context
        )

    async def refresh_verified(
        self, token: SecretStr, *, authentication: AuthenticationEvent, nonce: str | None
    ) -> VerifiedRefresh:
        endpoint = f"{self.settings.issuer}/token"
        now = self.clock.now()
        assertion = PrivateKeyJWT(
            endpoint,
            claims={"iat": now, "exp": now + self.settings.policy.assertion_ttl_seconds},
            headers={"kid": self.key.kid},
            alg=SIGNING_ALGORITHM,
        )
        async with AsyncOAuth2Client(
            client_id=self.settings.client_id,
            client_secret=self.key.key,
            scope=OPENID_SCOPE,
            token_endpoint_auth_method=CLIENT_AUTH_METHOD,
            verify=self.tls_context,
            transport=self.transport,
            timeout=self.settings.request_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            client.register_client_auth_method(assertion)
            try:
                raw = await client.refresh_token(endpoint, refresh_token=token.get_secret_value())
            except OAuthError as error:
                raise InvalidAuthorizationResponse(
                    "The IDP rejected refresh authorization"
                ) from error
        response = RefreshTokenResponse.model_validate(
            {name: value for name, value in raw.items() if name != "expires_at"}
        )
        if response.refresh_token == token.get_secret_value():
            raise InvalidIdToken("The refresh response did not rotate its credential")
        header = login_header(response.id_token, max_bytes=self.settings.policy.max_jwt_bytes)
        keys = await self.jwks.for_key(header.kid)
        verified = validate_refresh_token(
            response,
            settings=self.settings,
            authentication=authentication,
            nonce=nonce,
            keys=keys,
            clock=self.clock,
        )
        status = await self.grant_checker.check(SecretStr(response.access_token))
        try:
            context = require_active_grant(
                status,
                issuer=self.settings.issuer,
                client_id=self.settings.client_id,
                subject=authentication.subject.subject,
                now=self.clock.now(),
            )
        except SecurityDenied as error:
            raise InvalidIdToken("Refreshed evidence has no active bound authority") from error
        evidence = verified.evidence(context.authentication.event_id)
        if (
            status.credential_evidence != evidence
            or context.authentication != authentication
            or status.expires_at is None
        ):
            raise InvalidIdToken("Refresh does not match committed canonical issuance")
        return VerifiedRefresh(
            response=response,
            claims=verified.claims,
            evidence=evidence,
            context=context,
            access_expires_at=status.expires_at,
        )
