"""Script-free step-up and a server-enforced sensitive approval operation."""

import html
from http import HTTPStatus

from fastapi import FastAPI, Request
from starlette.responses import Response

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    BrowserInputError,
    action_form,
    action_parameters,
    browser_parameters,
    opaque_cookie,
    page,
    redirect,
)
from federated_identity.common.security.model import Denial, SecurityDenied
from federated_identity.sp.schemas.components import SpComponents


def install_step_up_routes(app: FastAPI, components: SpComponents) -> None:
    settings = components.settings

    @app.get("/auth/step-up")
    async def step_up_form(request: Request) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        cookie = opaque_cookie(request, settings)
        if cookie is None:
            raise BrowserInputError("Sign in before requesting step-up", HTTPStatus.UNAUTHORIZED)
        try:
            await components.browser.authorize(cookie)
            challenge = await components.browser.action_challenge(
                cookie, BrowserActionPurpose.SP_STEP_UP
            )
        except SecurityDenied:
            raise BrowserInputError(
                "An active session is required", HTTPStatus.UNAUTHORIZED
            ) from None
        response = page(
            settings.client_id,
            "Step up authentication",
            "<p>Verify the same account with a fresh password and authenticator code.</p>"
            + action_form("/auth/step-up", "Verify password and TOTP", challenge),
        )
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            f"{BROWSER_HEADERS['Content-Security-Policy']} {settings.issuer}"
        )
        return response

    @app.post("/auth/step-up")
    async def step_up(request: Request) -> Response:
        cookie, challenge = await action_parameters(request, settings)
        try:
            result = await components.browser.step_up(cookie, challenge)
        except SecurityDenied:
            raise BrowserInputError("The step-up intent is invalid", HTTPStatus.FORBIDDEN) from None
        return redirect(result.authorization_url)

    @app.get("/sensitive")
    async def sensitive(request: Request) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        cookie = opaque_cookie(request, settings)
        if cookie is None:
            raise BrowserInputError("Sign in first", HTTPStatus.UNAUTHORIZED)
        try:
            local = await components.sensitive.authorize(cookie)
        except SecurityDenied as error:
            status = (
                HTTPStatus.FORBIDDEN
                if error.reason in {Denial.ASSURANCE, Denial.RECENCY}
                else HTTPStatus.UNAUTHORIZED
            )
            return page(
                settings.client_id,
                "Stronger recent authentication required",
                "<p>This operation requires a recent password and TOTP event.</p>"
                "<a href='/auth/step-up'>Step up authentication</a>",
                status=status,
            )
        challenge = await components.sensitive.challenge(cookie, local)
        response = page(
            settings.client_id,
            "Sensitive operation",
            f"<p>Assurance: {html.escape(local.authentication.assurance.value)}; "
            f"authentication time: {local.authentication.authenticated_at}.</p>"
            + action_form("/sensitive", "Approve sensitive operation", challenge),
        )
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.post("/sensitive")
    async def approve(request: Request) -> Response:
        cookie, challenge = await action_parameters(request, settings)
        try:
            operation = await components.sensitive.act(cookie, challenge)
        except SecurityDenied:
            raise BrowserInputError(
                "Recent stronger authentication and a valid intent are required",
                HTTPStatus.FORBIDDEN,
            ) from None
        return page(
            settings.client_id,
            "Sensitive operation approved",
            f"<p data-testid='approval'>Sensitive operation approved: {html.escape(operation)}</p>"
            "<a href='/'>Return to application</a>",
        )
