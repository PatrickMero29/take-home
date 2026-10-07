"""Strict browser inputs and host-only cookies; neither accepts bearer login artifacts."""

import html
import re
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import HTMLResponse, RedirectResponse, Response

from federated_identity.common.persistence.sessions import SessionBackend
from federated_identity.common.security.contracts import GrantUnavailable
from federated_identity.common.settings.policy import Clock
from federated_identity.common.settings.runtime import RuntimeSettings

BROWSER_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
OPAQUE_COOKIE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class BrowserInputError(ValueError):
    def __init__(self, description: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(description)
        self.description = description
        self.status = status


def require_https(request: Request) -> None:
    if request.url.scheme != "https":
        raise BrowserInputError("HTTPS is required")


def opaque_cookie(request: Request, settings: RuntimeSettings) -> SecretStr | None:
    value = request.cookies.get(settings.cookie_name, "")
    return SecretStr(value) if OPAQUE_COOKIE.fullmatch(value) else None


async def browser_parameters(
    request: Request, allowed: frozenset[str], *, limit: int, ignore_unknown: bool = False
) -> dict[str, str]:
    require_https(request)
    if request.method == "GET":
        body = request.scope.get("query_string", b"")
        if len(body) > limit:
            raise BrowserInputError(
                "Request exceeds the profile limit", HTTPStatus.REQUEST_URI_TOO_LONG
            )
    else:
        if request.query_params:
            raise BrowserInputError("Form endpoints do not accept query parameters")
        if request.headers.get("content-type", "").partition(";")[0].lower() != (
            "application/x-www-form-urlencoded"
        ):
            raise BrowserInputError(
                "A URL-encoded form is required", HTTPStatus.UNSUPPORTED_MEDIA_TYPE
            )
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise BrowserInputError(
                    "Request exceeds the profile limit", HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                )
            body.extend(chunk)
    try:
        items = parse_qsl(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=32 if ignore_unknown else max(1, len(allowed)),
            errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        raise BrowserInputError("Malformed browser parameters") from error
    parameters: dict[str, str] = {}
    for name, value in items:
        if ignore_unknown and name not in allowed:
            continue
        if name not in allowed or name in parameters:
            raise BrowserInputError("Unsupported or repeated browser parameters")
        parameters[name] = value
    return parameters


def require_form_origin(request: Request, settings: RuntimeSettings) -> None:
    require_https(request)
    # Origin uses the browser's serialization: lowercase host and no default
    # HTTPS port. Protocol issuer/callback identifiers still retain exact values.
    origin = f"https://{settings.service_id.hostname}"
    if settings.listen_port != 443:
        origin = f"{origin}:{settings.listen_port}"
    if request.headers.get("origin") != origin:
        raise BrowserInputError(
            "The form must originate at its owning service", HTTPStatus.FORBIDDEN
        )


async def action_parameters(
    request: Request, settings: RuntimeSettings
) -> tuple[SecretStr, SecretStr]:
    require_form_origin(request, settings)
    fields = await browser_parameters(
        request, frozenset({"csrf"}), limit=settings.policy.max_form_bytes
    )
    cookie = opaque_cookie(request, settings)
    if cookie is None or set(fields) != {"csrf"} or not OPAQUE_COOKIE.fullmatch(fields["csrf"]):
        raise BrowserInputError("An active browser-bound action is required", HTTPStatus.FORBIDDEN)
    return cookie, SecretStr(fields["csrf"])


def action_form(location: str, label: str, challenge: SecretStr) -> str:
    return (
        f"<form method='post' action='{html.escape(location, quote=True)}'>"
        f"<input type='hidden' name='csrf' value='{html.escape(challenge.get_secret_value())}'>"
        f"<button type='submit'>{html.escape(label)}</button></form>"
    )


def clear_cookie(response: Response, settings: RuntimeSettings) -> None:
    response.delete_cookie(
        settings.cookie_name, path="/", secure=True, httponly=True, samesite="lax"
    )


def page(
    service: str, title: str, content: str, *, status: HTTPStatus = HTTPStatus.OK
) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title></head><body>"
        f"<h1>{html.escape(service)}</h1>{content}</body></html>",
        status_code=status,
        headers=BROWSER_HEADERS,
    )


def redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=HTTPStatus.SEE_OTHER, headers=BROWSER_HEADERS)


def set_cookie(
    response: Response, settings: RuntimeSettings, token: SecretStr, *, ttl: int
) -> None:
    response.set_cookie(
        settings.cookie_name,
        token.get_secret_value(),
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=ttl,
    )


@dataclass(frozen=True)
class BrowserBinding:
    token: SecretStr
    ttl: int
    created: bool


async def browser_binding(
    cookie: SecretStr | None,
    *,
    settings: RuntimeSettings,
    sessions: SessionBackend,
    clock: Clock,
) -> BrowserBinding:
    existing = await sessions.lookup(cookie) if cookie is not None else None
    if existing is not None and cookie is not None:
        ttl = existing.expires_at - clock.now()
        if ttl > 0:
            return BrowserBinding(cookie, ttl, False)
    token = await sessions.create(
        {"kind": "anonymous", "service": settings.service_id.value},
        ttl=settings.session_ttl_seconds,
    )
    return BrowserBinding(token, settings.session_ttl_seconds, True)


def install_browser_errors(app: FastAPI, settings: RuntimeSettings) -> None:
    @app.exception_handler(BrowserInputError)
    async def invalid_input(request: Request, error: BrowserInputError) -> Response:
        return page(
            settings.service_id.value,
            "Request rejected",
            f"<p>{html.escape(error.description)}</p><a href='/'>Return to application</a>",
            status=error.status,
        )

    async def unavailable(request: Request, error: Exception) -> Response:
        return page(
            settings.service_id.value,
            "Service temporarily unavailable",
            "<p>Sign-in is temporarily unavailable. Please try again.</p>"
            "<a href='/'>Return to application</a>",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )

    app.add_exception_handler(SQLAlchemyError, unavailable)
    # asyncpg connection establishment can expose a socket error before
    # SQLAlchemy has a DBAPI operation to wrap. Preserve the same outage contract.
    app.add_exception_handler(OSError, unavailable)
    app.add_exception_handler(GrantUnavailable, unavailable)
