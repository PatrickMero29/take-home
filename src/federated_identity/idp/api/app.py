"""A small FastAPI protocol boundary with no ambient or fabricated user identity."""

from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from http import HTTPStatus
from typing import Literal, Protocol
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, Request
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response

from federated_identity.idp.schemas.models import (
    AuthenticatedPrincipal,
    OAuthErrorResponse,
    ProtocolMessage,
    ProtocolResponse,
    ProviderMetadata,
)
from federated_identity.idp.services.oidc import OidcService

AUTHORIZATION_FIELDS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "prompt",
        "max_age",
        "acr_values",
    }
)
TOKEN_FIELDS = frozenset(
    {
        "grant_type",
        "client_id",
        "code",
        "redirect_uri",
        "code_verifier",
        "client_assertion_type",
        "client_assertion",
        "refresh_token",
        "scope",
    }
)
INTROSPECTION_FIELDS = frozenset(
    {
        "token",
        "token_type_hint",
        "client_id",
        "client_assertion_type",
        "client_assertion",
    }
)
NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class PrincipalProvider(Protocol):
    """A trusted credential/session layer supplies this authenticated event."""

    async def authenticate(self, request: Request) -> AuthenticatedPrincipal | None: ...


class AuthorizationHandler(Protocol):
    async def authorize(
        self, request: Request, message: ProtocolMessage, principal: AuthenticatedPrincipal | None
    ) -> Response: ...


class NoPrincipal:
    async def authenticate(self, request: Request) -> AuthenticatedPrincipal | None:
        return None


class ProtocolInputError(Exception):
    def __init__(self, description: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(description)
        self.description = description
        self.status = status


def protocol_http_response(result: ProtocolResponse) -> Response:
    headers = {**dict(result.headers), **NO_STORE_HEADERS}
    if isinstance(result.body, str):
        return Response(result.body, status_code=result.status, headers=headers)
    return JSONResponse(
        result.body.model_dump(mode="json", exclude_none=True),
        status_code=result.status,
        headers=headers,
    )


def single_parameters(
    items: Sequence[tuple[str, str]], allowed_fields: frozenset[str]
) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in items:
        if name in result:
            raise ProtocolInputError("Repeated protocol parameters are not allowed")
        if name not in allowed_fields:
            raise ProtocolInputError("Unsupported protocol parameter")
        result[name] = value
    return result


async def protocol_message(
    request: Request,
    service: OidcService,
    endpoint: Literal["authorize", "token", "introspect", "revoke", "logout_introspect"],
) -> ProtocolMessage:
    if request.url.scheme != "https":
        raise ProtocolInputError("HTTPS is required")
    allowed = {
        "authorize": AUTHORIZATION_FIELDS,
        "token": TOKEN_FIELDS,
        "introspect": INTROSPECTION_FIELDS,
        "revoke": INTROSPECTION_FIELDS,
        "logout_introspect": INTROSPECTION_FIELDS,
    }[endpoint]
    limit = service.settings.policy.max_form_bytes
    if request.method == "GET":
        if len(request.scope.get("query_string", b"")) > limit:
            raise ProtocolInputError(
                "Request exceeds the profile limit", HTTPStatus.REQUEST_URI_TOO_LONG
            )
        items = request.query_params.multi_items()
    else:
        if request.query_params:
            raise ProtocolInputError("Form endpoints do not accept query parameters")
        content_type = request.headers.get("content-type", "").partition(";")[0].lower()
        if content_type != "application/x-www-form-urlencoded":
            raise ProtocolInputError(
                "A URL-encoded form is required", HTTPStatus.UNSUPPORTED_MEDIA_TYPE
            )
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise ProtocolInputError(
                    "Request exceeds the profile limit", HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                )
            body.extend(chunk)
        try:
            items = parse_qsl(
                body.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=len(allowed),
                errors="strict",
            )
        except (UnicodeError, ValueError) as error:
            raise ProtocolInputError("Malformed URL-encoded form") from error
    parameters = single_parameters(items, allowed)
    url = {
        "authorize": service.settings.authorization_endpoint,
        "token": service.settings.token_endpoint,
        "introspect": service.settings.introspection_endpoint,
        "revoke": service.settings.revocation_endpoint,
        "logout_introspect": f"{service.settings.issuer}/logout/introspect",
    }[endpoint]
    # The issuer and endpoints are configuration, never untrusted Host or
    # forwarded headers. Duplicate parameters were rejected before flattening.
    return ProtocolMessage(request.method, url, parameters)


def create_app(
    service: OidcService,
    *,
    principal_provider: PrincipalProvider | None = None,
    authorization_handler: AuthorizationHandler | None = None,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
) -> FastAPI:
    provider = principal_provider if principal_provider is not None else NoPrincipal()
    app = FastAPI(
        title="Federated Identity — IDP", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    hostname = urlsplit(service.settings.issuer).hostname
    if hostname is None:
        raise ValueError("A configured issuer hostname is required")
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[hostname],
        www_redirect=False,
    )

    @app.exception_handler(ProtocolInputError)
    async def input_error(request: Request, error: ProtocolInputError) -> Response:
        return protocol_http_response(
            ProtocolResponse(
                error.status,
                OAuthErrorResponse(error="invalid_request", error_description=error.description),
            )
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/openid-configuration")
    async def discovery() -> ProviderMetadata:
        settings = service.settings
        return ProviderMetadata(
            issuer=settings.issuer,
            authorization_endpoint=settings.authorization_endpoint,
            token_endpoint=settings.token_endpoint,
            jwks_uri=settings.jwks_uri,
            introspection_endpoint=settings.introspection_endpoint,
            revocation_endpoint=settings.revocation_endpoint,
            end_session_endpoint=f"{settings.issuer}/end-session",
            backchannel_logout_supported=True,
            backchannel_logout_session_supported=True,
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            subject_types_supported=["public"],
            scopes_supported=["openid"],
            id_token_signing_alg_values_supported=["RS256"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            token_endpoint_auth_signing_alg_values_supported=["RS256"],
            introspection_endpoint_auth_methods_supported=["private_key_jwt"],
            introspection_endpoint_auth_signing_alg_values_supported=["RS256"],
            revocation_endpoint_auth_methods_supported=["private_key_jwt"],
            revocation_endpoint_auth_signing_alg_values_supported=["RS256"],
            code_challenge_methods_supported=["S256"],
            acr_values_supported=["urn:take-home:acr:password", "urn:take-home:acr:password-totp"],
        )

    @app.get("/jwks.json")
    async def jwks() -> JSONResponse:
        keys = await service.keys.public_jwks()
        return JSONResponse(keys.model_dump(mode="json"), headers={"Cache-Control": "no-store"})

    @app.api_route("/authorize", methods=["GET", "POST"])
    async def authorize(request: Request) -> Response:
        message = await protocol_message(request, service, "authorize")
        principal = await provider.authenticate(request)
        if authorization_handler is not None:
            return await authorization_handler.authorize(request, message, principal)
        return protocol_http_response(await service.authorize(message, principal))

    @app.post("/token")
    async def token(request: Request) -> Response:
        message = await protocol_message(request, service, "token")
        return protocol_http_response(await service.exchange(message))

    @app.post("/introspect")
    async def introspect(request: Request) -> Response:
        message = await protocol_message(request, service, "introspect")
        return protocol_http_response(await service.introspect(message))

    @app.post("/revoke")
    async def revoke(request: Request) -> Response:
        message = await protocol_message(request, service, "revoke")
        return protocol_http_response(await service.revoke(message))

    @app.post("/logout/introspect")
    async def logout_introspect(request: Request) -> Response:
        message = await protocol_message(request, service, "logout_introspect")
        return protocol_http_response(await service.check_logout(message))

    return app
