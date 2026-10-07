"""Request-local Authlib extensions for the Phase 0 closed federation profile.

This is the sole provider boundary to Authlib's untyped APIs. Protocol/crypto
implementations stay in Authlib/joserfc; application policy and storage hooks
are explicit, typed, and scoped to one async-backed database transaction.
"""

import secrets
from collections.abc import Callable
from http import HTTPStatus
from typing import Any, cast

from authlib.oauth2.rfc6749 import (
    AuthorizationServer,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    OAuth2Error,
    OAuth2Request,
)
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oidc.core import OpenIDCode, UserInfo
from authlib.oidc.core.errors import LoginRequiredError
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from pydantic import ValidationError

from federated_identity.common.keys import SigningKey
from federated_identity.common.policy import (
    CLIENT_AUTH_METHOD,
    OPENID_SCOPE,
    SIGNING_ALGORITHM,
    Clock,
    IdpSettings,
    verifier_digest,
)
from federated_identity.common.security.artifacts import RefreshTokenResponse
from federated_identity.common.security.model import Assurance, LoginEvidence
from federated_identity.common.security.oidc import (
    OidcValidationProfile,
    validate_refresh_token,
    verified_login_evidence,
)
from federated_identity.idp.repositories.database import ProtocolRepository
from federated_identity.idp.schemas.models import (
    AuthenticatedPrincipal,
    AuthorizationCodeData,
    AuthorizationInteraction,
    AuthorizationParameters,
    ClientAssertionClaims,
    ClientRegistration,
    JwtHeader,
    OAuthErrorResponse,
    ProtocolMessage,
    ProtocolResponse,
    RefreshCredentialData,
    TokenResponse,
)


class ClientAdapter:
    def __init__(self, data: ClientRegistration) -> None:
        self.data = data
        self.public_key = RSAKey.import_key(
            data.public_key_pem,
            parameters={"kid": data.key_id, "alg": SIGNING_ALGORITHM, "use": "sig"},
        )
        if self.public_key.is_private:
            raise ValueError("Client authentication requires a registered public-only key")

    def get_client_id(self) -> str:
        return self.data.client_id

    def get_default_redirect_uri(self) -> str:
        return self.data.redirect_uris[0]

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.data.redirect_uris

    def get_allowed_scope(self, scope: str | None) -> str | None:
        return OPENID_SCOPE if scope == OPENID_SCOPE and scope in self.data.allowed_scopes else None

    def check_response_type(self, response_type: str) -> bool:
        return response_type == "code"

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.data.allowed_grants

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        return method == self.data.token_endpoint_auth_method and endpoint in {
            "token",
            "introspection",
            "revocation",
        }


class CodeAdapter:
    def __init__(self, data: AuthorizationCodeData) -> None:
        self.data = data
        self.code_challenge = data.code_challenge
        self.code_challenge_method = "S256"

    def get_redirect_uri(self) -> str:
        return self.data.redirect_uri

    def get_scope(self) -> str:
        return self.data.scope

    def get_nonce(self) -> str:
        return self.data.nonce

    def get_auth_time(self) -> int:
        return self.data.principal.auth_time

    def get_acr(self) -> str:
        return self.data.principal.acr

    def get_amr(self) -> list[str]:
        return list(self.data.principal.amr)


class RefreshAdapter:
    def __init__(self, data: RefreshCredentialData) -> None:
        self.data = data

    def check_client(self, client: ClientAdapter) -> bool:
        return self.data.client_id == client.data.client_id

    def get_scope(self) -> str:
        return OPENID_SCOPE


class AdapterRequest(OAuth2Request):
    client: ClientAdapter | None
    user: AuthenticatedPrincipal | None
    authorization_code: CodeAdapter | None
    refresh_token: RefreshAdapter | None

    def __init__(self, message: ProtocolMessage) -> None:
        # Use the current payload API; the deprecated body constructor loses
        # context and emits a warning in Authlib 1.8.
        super().__init__(message.method, message.endpoint)
        self.parameters = message.parameters
        self.endpoint_url = message.endpoint
        self.payload = BasicOAuth2Payload(self.parameters)
        self.authorization_code = None
        self.refresh_token = None

    @property
    def form(self) -> dict[str, str]:
        return self.parameters if self.method == "POST" else {}

    @property
    def args(self) -> dict[str, str]:
        return self.parameters if self.method == "GET" else {}


class StrictPrivateKeyJwt(JWTBearerClientAssertion):
    CLIENT_AUTH_METHOD = CLIENT_AUTH_METHOD

    def __init__(self, server: "AuthlibAdapter") -> None:
        super().__init__(validate_jti=True, leeway=server.settings.policy.clock_skew_seconds)
        self.server = server
        self.client: ClientAdapter | None = None

    def __call__(
        self,
        query_client: Callable[[str], ClientAdapter | None],
        request: AdapterRequest,
    ) -> ClientAdapter | None:
        assertion = request.form.get("client_assertion", "")
        if len(assertion.encode("utf-8")) > self.server.settings.policy.max_jwt_bytes:
            raise InvalidClientError("Client assertion exceeds the profile limit")
        try:
            result = super().__call__(query_client, request)
        except (JoseError, ValidationError, ValueError, TypeError) as error:
            raise InvalidClientError("Invalid client assertion") from error
        return cast(ClientAdapter | None, result)

    def resolve_client_public_key(self, client: ClientAdapter) -> RSAKey:
        self.client = client
        return client.public_key

    def process_assertion_claims(self, assertion: str, key: RSAKey) -> dict[str, Any]:
        policy = self.server.settings.policy
        if len(assertion.encode("utf-8")) > policy.max_jwt_bytes:
            raise InvalidClientError("Client assertion exceeds the profile limit")
        headers, _ = self.extract_assertion(assertion)
        header = JwtHeader.model_validate(headers)
        if self.client is None or header.kid != self.client.data.key_id:
            raise InvalidClientError("Invalid client key identifier")
        token = jwt.decode(assertion, key, algorithms=[SIGNING_ALGORITHM])
        self.verify_claims(token.claims)
        return token.claims

    def verify_claims(self, claims: dict[str, Any]) -> None:
        parsed = ClientAssertionClaims.model_validate(claims)
        if self.client is None:
            raise RuntimeError("Assertion verification needs its registered client")
        client_id = self.client.data.client_id
        if parsed.iss != client_id or parsed.sub != client_id:
            raise InvalidClientError("Invalid client identity")
        supplied_client_id = self.server.request.parameters.get("client_id")
        if supplied_client_id is not None and supplied_client_id != client_id:
            raise InvalidClientError("Conflicting client identity")
        if parsed.aud != self.server.request.endpoint_url:
            raise InvalidClientError("Invalid client assertion audience")

        policy = self.server.settings.policy
        now = self.server.clock.now()
        registry = jwt.JWTClaimsRegistry(
            now=now,
            leeway=policy.clock_skew_seconds,
            iss={"essential": True, "value": client_id},
            sub={"essential": True, "value": client_id},
            aud={"essential": True, "value": self.server.request.endpoint_url},
            iat={"essential": True},
            exp={"essential": True},
            jti={"essential": True},
        )
        registry.validate(claims)
        if (
            parsed.exp <= parsed.iat
            or parsed.exp - parsed.iat > policy.assertion_ttl_seconds
            or now - parsed.iat > policy.assertion_ttl_seconds + policy.clock_skew_seconds
            or now >= parsed.exp + policy.clock_skew_seconds
        ):
            raise InvalidClientError("Invalid client assertion lifetime")
        if not self.validate_jti(claims, parsed.jti):
            raise InvalidClientError("Client assertion has already been used")

    def validate_jti(self, claims: dict[str, Any], jti: str) -> bool:
        # This is reached only after signature, identity, audience, and time
        # validation. An invalid assertion cannot burn a legitimate replay ID.
        parsed = ClientAssertionClaims.model_validate(claims)
        return self.server.repository.reserve_assertion(
            parsed.sub, jti, parsed.exp + self.server.settings.policy.clock_skew_seconds
        )

    def get_audiences(self) -> list[str]:
        return [self.server.request.endpoint_url]


class MandatoryS256(CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ("S256",)
    DEFAULT_CODE_CHALLENGE_METHOD = "S256"

    def validate_code_challenge(self, grant: "CodeGrant", redirect_uri: str) -> None:
        if grant.request.parameters.get("code_challenge_method") != "S256":
            raise InvalidRequestError("S256 PKCE is required")
        if not grant.request.parameters.get("code_challenge"):
            raise InvalidRequestError("A PKCE challenge is required")
        super().validate_code_challenge(grant, redirect_uri)


class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = (CLIENT_AUTH_METHOD,)
    server: "AuthlibAdapter"
    request: AdapterRequest

    def validate_authorization_request(self) -> str:
        redirect_uri = cast(str, super().validate_authorization_request())
        try:
            AuthorizationParameters.model_validate(self.request.parameters)
        except ValidationError as error:
            raise InvalidRequestError(
                "Invalid authorization parameters", redirect_uri=redirect_uri
            ) from error
        return redirect_uri

    def save_authorization_code(self, code: str, request: AdapterRequest) -> None:
        if request.client is None or request.user is None:
            raise RuntimeError("An authorization code needs its client and authenticated principal")
        parameters = AuthorizationParameters.model_validate(request.parameters)
        now = self.server.clock.now()
        self.server.repository.save_code(
            AuthorizationCodeData(
                code_digest=verifier_digest(code),
                client_id=request.client.data.client_id,
                redirect_uri=parameters.redirect_uri,
                scope=OPENID_SCOPE,
                nonce=parameters.nonce,
                code_challenge=parameters.code_challenge,
                created_at=now,
                expires_at=min(
                    now + self.server.settings.policy.code_ttl_seconds,
                    self.server.repository.session_expiry(request.user),
                ),
                consumed_at=None,
                principal=request.user,
                client_version=request.client.data.registration_version,
            )
        )

    def query_authorization_code(self, code: str, client: ClientAdapter) -> CodeAdapter | None:
        data = self.server.repository.lock_code(
            code, client.data.client_id, self.server.clock.now(), issuer=self.server.settings.issuer
        )
        return CodeAdapter(data) if data is not None else None

    def delete_authorization_code(self, authorization_code: CodeAdapter) -> None:
        # Keep a tombstone instead of deleting: later phases use its lineage
        # for replay response and compromise containment.
        self.server.repository.consume_code(
            authorization_code.data.code_digest, self.server.clock.now()
        )

    def authenticate_user(self, authorization_code: CodeAdapter) -> AuthenticatedPrincipal:
        return authorization_code.data.principal


class OpenIdProfile(OpenIDCode):
    def __init__(self, server: "AuthlibAdapter") -> None:
        super().__init__(require_nonce=True)
        self.server = server

    def __call__(self, grant: CodeGrant) -> None:
        super().__call__(grant)
        grant.register_hook("after_validate_consent_request", self.require_authentication)

    def require_authentication(self, grant: CodeGrant, redirect_uri: str) -> None:
        principal = grant.request.user
        parameters = AuthorizationParameters.model_validate(grant.request.parameters)
        if principal is None or (
            parameters.prompt == "login" and not self.server.fresh_authentication
        ):
            raise LoginRequiredError(redirect_uri=redirect_uri)
        now = self.server.clock.now()
        if (
            self.server.repository.verified_event(
                principal, issuer=self.server.settings.issuer, now=now
            )
            is None
        ):
            raise LoginRequiredError(redirect_uri=redirect_uri)
        if principal.auth_time > now + self.server.settings.policy.clock_skew_seconds:
            raise LoginRequiredError(redirect_uri=redirect_uri)
        if parameters.max_age is not None and (
            (parameters.max_age > 0 and now - principal.auth_time > parameters.max_age)
            or (parameters.max_age == 0 and not self.server.fresh_authentication)
        ):
            raise LoginRequiredError(redirect_uri=redirect_uri)
        if parameters.acr_values is not None and (
            (
                parameters.acr_values == Assurance.PASSWORD_TOTP.value
                and principal.acr != Assurance.PASSWORD_TOTP.value
            )
            or (
                parameters.acr_values == Assurance.PASSWORD.value
                and principal.acr not in {Assurance.PASSWORD.value, Assurance.PASSWORD_TOTP.value}
            )
        ):
            raise LoginRequiredError(redirect_uri=redirect_uri)

    def exists_nonce(self, nonce: str, request: AdapterRequest) -> bool:
        if request.client is None:
            raise RuntimeError("Nonce validation requires a registered client")
        return self.server.repository.nonce_exists(request.client.data.client_id, nonce)

    def resolve_client_private_key(self, client: ClientAdapter) -> RSAKey:
        if not self.server.repository.signer_is_active(self.server.signer):
            raise InvalidGrantError("Signing trust is unavailable")
        return self.server.signer.key

    def get_client_algorithm(self, client: ClientAdapter) -> str:
        return SIGNING_ALGORITHM

    def get_encode_header(self, client: ClientAdapter) -> dict[str, str]:
        return {"alg": SIGNING_ALGORITHM, "typ": "JWT", "kid": self.server.signer.kid}

    def get_client_claims(self, client: ClientAdapter) -> dict[str, Any]:
        if self.server.issuance_id is None:
            raise RuntimeError("ID-token signing requires a pending issuance record")
        now = self.server.clock.now()
        return {
            "iss": self.server.settings.issuer,
            "aud": client.data.client_id,
            "iat": now,
            "exp": now + self.server.settings.policy.id_token_ttl_seconds,
            "jti": self.server.issuance_id,
        }

    def generate_user_info(self, user: AuthenticatedPrincipal, scope: str) -> UserInfo:
        return UserInfo(sub=user.sub, sid=user.sid)


class RotatingRefreshGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = (CLIENT_AUTH_METHOD,)
    INCLUDE_NEW_REFRESH_TOKEN = True
    server: "AuthlibAdapter"
    request: AdapterRequest

    def authenticate_refresh_token(self, token: str) -> RefreshAdapter | None:
        data = self.server.repository.refresh_credential(token)
        return RefreshAdapter(data) if data is not None else None

    def authenticate_user(self, token: RefreshAdapter) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal.from_event(token.data.authentication)

    def revoke_old_credential(self, token: RefreshAdapter) -> None:
        # The async service consumes this exact predecessor with canonical
        # evidence/credentials after the library has completed signing.
        self.server.refresh_to_consume = token.data.token_digest


class OpenIdRefreshProfile(OpenIdProfile):
    def __call__(self, grant: CodeGrant | RotatingRefreshGrant) -> None:
        grant.register_hook("after_create_token_response", self.process_token)

    def get_client_claims(self, client: ClientAdapter) -> dict[str, Any]:
        claims = super().get_client_claims(client)
        token = self.server.request.refresh_token
        if token is None:
            raise RuntimeError("Refresh signing requires its original authentication")
        event = token.data.authentication
        claims.update(
            {
                "auth_time": event.authenticated_at,
                "acr": event.assurance.value,
                "amr": [method.value for method in event.methods],
            }
        )
        return claims


class ClosedIntrospectionEndpoint(IntrospectionEndpoint):
    CLIENT_AUTH_METHODS = (CLIENT_AUTH_METHOD,)
    SUPPORTED_TOKEN_TYPES = ("access_token",)


class ClosedRevocationEndpoint(RevocationEndpoint):
    CLIENT_AUTH_METHODS = (CLIENT_AUTH_METHOD,)
    SUPPORTED_TOKEN_TYPES = ("access_token", "refresh_token")

    def check_params(self, request: AdapterRequest, client: ClientAdapter) -> None:
        # RFC 7009 says an unrecognized hint must not prevent searching the
        # supported credential stores. It is not a token-purpose authority.
        if "token" not in request.form or not request.form["token"]:
            raise InvalidRequestError("An opaque token is required")


class AuthlibAdapter(AuthorizationServer):
    """One instance per request, inside Database.transact's async bridge."""

    def __init__(
        self,
        message: ProtocolMessage,
        repository: ProtocolRepository,
        settings: IdpSettings,
        signer: SigningKey,
        clock: Clock,
        *,
        fresh_authentication: bool = False,
    ) -> None:
        super().__init__(scopes_supported=[OPENID_SCOPE])
        self.request = AdapterRequest(message)
        self.repository = repository
        self.settings = settings
        self.signer = signer
        self.clock = clock
        self.fresh_authentication = fresh_authentication
        self.issuance_id: str | None = None
        self.token_grant: CodeGrant | RotatingRefreshGrant | None = None
        self.replayed_code: tuple[str, str] | None = None
        self.refresh_to_consume: str | None = None
        self.register_client_auth_method(CLIENT_AUTH_METHOD, StrictPrivateKeyJwt(self))
        self.register_token_generator(
            "default",
            BearerTokenGenerator(
                access_token_generator=self.generate_access_token,
                refresh_token_generator=self.generate_access_token,
                expires_generator=settings.policy.access_token_ttl_seconds,
            ),
        )
        self.register_grant(CodeGrant, extensions=[MandatoryS256(), OpenIdProfile(self)])
        self.register_grant(RotatingRefreshGrant, extensions=[OpenIdRefreshProfile(self)])

    @property
    def is_refresh(self) -> bool:
        return self.request.parameters.get("grant_type") == "refresh_token"

    @staticmethod
    def generate_access_token(**kwargs: object) -> str:
        return secrets.token_urlsafe(32)

    def create_oauth2_request(self, request: AdapterRequest | None) -> AdapterRequest:
        return self.request

    def query_client(self, client_id: str) -> ClientAdapter | None:
        data = self.repository.get_client(client_id)
        return ClientAdapter(data) if data is not None else None

    def send_signal(self, name: str, *args: object, **kwargs: object) -> None:
        # The library's optional synchronous signal integration performs no I/O.
        return None

    def save_token(self, token: dict[str, Any], request: AdapterRequest) -> None:
        self.issuance_id = secrets.token_urlsafe(32)
        if request.authorization_code is None:
            if request.refresh_token is None:
                raise RuntimeError("Issuance requires its code or refresh credential")
            return
        self.repository.save_issuance(
            self.issuance_id,
            request.authorization_code.data,
            cast(str, token["access_token"]),
            self.signer.kid,
            self.clock.now(),
        )

    def handle_response(
        self, status: int, body: dict[str, Any] | str, headers: list[tuple[str, str]]
    ) -> ProtocolResponse:
        parsed: TokenResponse | OAuthErrorResponse | str
        if isinstance(body, str):
            parsed = body
        elif "error" in body:
            parsed = OAuthErrorResponse.model_validate(body)
        else:
            parsed = (
                RefreshTokenResponse.model_validate(body)
                if self.is_refresh
                else TokenResponse.model_validate(body)
            )
        return ProtocolResponse(HTTPStatus(status), parsed, tuple(headers))

    def authorize(self, principal: AuthenticatedPrincipal | None) -> ProtocolResponse:
        result = self.authorization(principal)
        if not isinstance(result, ProtocolResponse):
            raise RuntimeError("Non-interactive authorization cannot request a login form")
        return result

    def authorization(
        self, principal: AuthenticatedPrincipal | None, *, interactive: bool = False
    ) -> ProtocolResponse | AuthorizationInteraction:
        try:
            grant = self.get_consent_grant(self.request, end_user=principal)
            return cast(
                ProtocolResponse,
                self.create_authorization_response(self.request, grant_user=principal, grant=grant),
            )
        except LoginRequiredError as error:
            # This hook runs only after Authlib validates registration, the exact
            # callback and this closed profile. Never offer an unvalidated return path.
            if interactive and self.request.parameters.get("prompt") != "none":
                return AuthorizationInteraction(
                    AuthorizationParameters.model_validate(self.request.parameters)
                )
            return self.error_response(error)
        except OAuth2Error as error:
            return cast(ProtocolResponse, self.handle_error_response(self.request, error))

    def validate_exchange(self) -> ProtocolResponse | None:
        """Authlib validates/authenticates before the issuance savepoint begins."""
        try:
            self.token_grant = cast(
                CodeGrant | RotatingRefreshGrant, self.get_token_grant(self.request)
            )
            self.token_grant.validate_token_request()
            code = self.request.authorization_code
            if code is not None and code.data.consumed_at is not None:
                # Reached only after client signature/audience/replay checks,
                # exact original redirect, and Authlib's S256 verifier check.
                grant_id = self.repository.grant_for_code(
                    code.data.code_digest, code.data.client_id
                )
                if grant_id is not None:
                    self.replayed_code = (grant_id, code.data.client_id)
                raise InvalidGrantError("The authorization code has already been consumed")
        except OAuth2Error as error:
            return self.error_response(error)
        return None

    def issue_tokens(self) -> ProtocolResponse:
        if self.token_grant is None:
            raise RuntimeError("Issuance requires an Authlib-validated token request")
        if not self.is_refresh and (
            self.request.authorization_code is None
            or self.request.authorization_code.data.consumed_at is not None
        ):
            raise InvalidGrantError("A fresh authorization code is required")
        response = self.handle_response(*self.token_grant.create_token_response())
        if isinstance(response.body, TokenResponse):
            if self.issuance_id is None:
                raise RuntimeError("A token response needs its issuance record")
            if not self.is_refresh:
                self.repository.finish_issuance(self.issuance_id, response.body.id_token)
            elif (
                self.request.refresh_token is None
                or self.refresh_to_consume != self.request.refresh_token.data.token_digest
            ):
                raise RuntimeError("Refresh rotation must identify the exact consumed predecessor")
        return response

    def refresh_evidence(self, response: RefreshTokenResponse) -> LoginEvidence:
        token = self.request.refresh_token
        if token is None:
            raise RuntimeError("Refresh evidence requires the authenticated credential")
        return validate_refresh_token(
            response,
            settings=OidcValidationProfile(
                issuer=self.settings.issuer,
                client_id=token.data.client_id,
                policy=self.settings.policy,
            ),
            authentication=token.data.authentication,
            nonce=None,
            keys=self.signer.public_jwks(),
            clock=self.clock,
        ).evidence(token.data.authentication.event_id)

    def login_evidence(self, response: TokenResponse) -> LoginEvidence:
        code = self.request.authorization_code
        if code is None:
            raise RuntimeError("Login evidence requires its validated authorization code")
        return verified_login_evidence(
            response,
            settings=OidcValidationProfile(
                issuer=self.settings.issuer,
                client_id=code.data.client_id,
                policy=self.settings.policy,
            ),
            nonce=code.data.nonce,
            keys=self.signer.public_jwks(),
            clock=self.clock,
            event_id=code.data.principal.event_id,
        )

    def introspection_client(self) -> ClientAdapter | ProtocolResponse:
        try:
            endpoint = ClosedIntrospectionEndpoint(self)
            client = cast(ClientAdapter, endpoint.authenticate_endpoint_client(self.request))
            endpoint.check_params(self.request, client)
            return client
        except OAuth2Error as error:
            return self.error_response(error)

    def revocation_client(self) -> ClientAdapter | ProtocolResponse:
        try:
            endpoint = ClosedRevocationEndpoint(self)
            client = cast(ClientAdapter, endpoint.authenticate_endpoint_client(self.request))
            endpoint.check_params(self.request, client)
            return client
        except OAuth2Error as error:
            return self.error_response(error)

    def error_response(self, error: OAuth2Error) -> ProtocolResponse:
        return cast(ProtocolResponse, self.handle_error_response(self.request, error))
