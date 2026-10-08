"""Two-step RP-Initiated Logout and bounded first notification attempts."""

import asyncio
import logging
from http import HTTPStatus
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from pydantic import ValidationError
from starlette.responses import Response

from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    BrowserInputError,
    action_form,
    action_parameters,
    browser_parameters,
    clear_cookie,
    opaque_cookie,
    page,
    redirect,
)
from federated_identity.common.security.model import SecurityDenied
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.services.end_session import EndSessionParameters, InvalidLogoutRequest

END_SESSION_FIELDS = frozenset(
    {"id_token_hint", "client_id", "post_logout_redirect_uri", "state", "logout_hint", "ui_locales"}
)


async def notify_logout(components: IdpComponents, session_id: str) -> None:
    # Notification starts after commit, in parallel, with a request-sized bound.
    # Outages/cancellation preserve the queue and cannot delay effective revocation.
    components.logout_dispatcher.wakeup.set()
    try:
        async with asyncio.timeout(components.settings.request_timeout_seconds / 2):
            await components.logout_dispatcher.dispatch_once(session_id=session_id)
    except Exception:
        logging.getLogger(__name__).exception("logout_dispatch_failed", extra={"service": "idp"})
        components.logout_dispatcher.wakeup.set()


def install_logout_routes(app: FastAPI, components: IdpComponents) -> None:
    settings = components.settings

    @app.api_route("/end-session", methods=["GET", "POST"])
    async def end_session(request: Request) -> Response:
        fields = await browser_parameters(
            request, END_SESSION_FIELDS, limit=settings.policy.max_form_bytes
        )
        try:
            parameters = EndSessionParameters.model_validate(fields)
            prompt = await components.logout.begin(opaque_cookie(request, settings), parameters)
        except (ValidationError, InvalidLogoutRequest):
            raise BrowserInputError("The logout request is invalid") from None
        except SecurityDenied:
            raise BrowserInputError(
                "The logout request does not match this IDP browser session", HTTPStatus.FORBIDDEN
            ) from None
        if prompt.challenge is None:
            return (
                redirect(prompt.return_uri)
                if prompt.return_uri
                else page(
                    "idp",
                    "Signed out",
                    "<p>No active matching IDP browser session.</p><a href='/'>Return</a>",
                )
            )
        response = page(
            "idp",
            "Sign out everywhere",
            "<p>End this IDP session and its sessions at every connected application?</p>"
            + action_form("/end-session/confirm", "Sign out everywhere", prompt.challenge)
            + "<p><a href='/'>Cancel</a></p>",
        )
        response.headers["Referrer-Policy"] = "same-origin"
        if parameters.post_logout_redirect_uri is not None:
            destination = urlsplit(parameters.post_logout_redirect_uri)
            response.headers["Content-Security-Policy"] = (
                f"{BROWSER_HEADERS['Content-Security-Policy']} https://{destination.netloc}"
            )
        return response

    @app.post("/end-session/confirm")
    async def confirm(request: Request) -> Response:
        cookie, challenge = await action_parameters(request, settings)
        try:
            result = await components.logout.confirm(cookie, challenge)
        except SecurityDenied:
            raise BrowserInputError(
                "The logout intent is invalid or expired", HTTPStatus.FORBIDDEN
            ) from None
        await notify_logout(components, result.session_id)
        response = redirect(result.return_uri or "/")
        clear_cookie(response, settings)
        return response
