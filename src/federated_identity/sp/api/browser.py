"""Minimal relying-party pages; only a verified code callback creates authentication."""

import html
from http import HTTPStatus
from urllib.parse import urlencode

import httpx2 as httpx
from fastapi import FastAPI, Request
from pydantic import SecretStr, ValidationError
from starlette.responses import HTMLResponse, JSONResponse, Response

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    BrowserInputError,
    action_form,
    action_parameters,
    browser_parameters,
    clear_cookie,
    install_browser_errors,
    opaque_cookie,
    page,
    redirect,
    require_form_origin,
    require_https,
    set_cookie,
)
from federated_identity.common.security.contracts import GrantUnavailable
from federated_identity.common.security.model import SecurityDenied
from federated_identity.sp.protocol.oidc import InvalidAuthorizationResponse, InvalidIdToken
from federated_identity.sp.schemas.components import SpComponents

CALLBACK_FIELDS = frozenset({"code", "state", "error", "error_description", "error_uri"})


def install_sp_browser_routes(app: FastAPI, components: SpComponents) -> None:
    settings = components.settings
    install_browser_errors(app, settings)

    @app.exception_handler(GrantUnavailable)
    async def renewal_unavailable(request: Request, error: GrantUnavailable) -> Response:
        return page(
            settings.service_id.value,
            "Authorization temporarily unavailable",
            "<p>Retry after a dependency outage. "
            "If renewal is uncertain, start a fresh sign-in.</p>"
            "<a href='/auth/login'>Start a fresh sign-in</a>"
            "<p><a href='/auth/reauthenticate'>Re-authenticate</a></p>"
            "<a href='/auth/logout'>Sign out locally</a>",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(httpx.HTTPError)
    async def unavailable(request: Request, error: httpx.HTTPError) -> Response:
        return page(
            settings.service_id.value,
            "Identity provider unavailable",
            "<p>Sign-in is temporarily unavailable. "
            "Start a new login when the IDP is available.</p>"
            "<p><a href='/auth/logout'>Sign out locally</a></p>"
            "<a href='/'>Return to application</a>",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        require_https(request)
        cookie = opaque_cookie(request, settings)
        identity = None
        if cookie is not None:
            try:
                identity = await components.browser.authorize(cookie)
            except SecurityDenied:
                pass
        binding = await components.browser.binding(cookie)
        if identity is None:
            content = "<p>Not signed in.</p><a href='/auth/login'>Sign in</a>"
        else:
            content = (
                "<p>Authenticated user: <span data-testid='subject'>"
                f"{html.escape(identity.subject)}</span></p>"
                f"<p>Application: {html.escape(identity.client_id)}</p>"
                f"<p>Authentication: {html.escape(identity.authentication.assurance.value)}</p>"
                "<a href='/account'>Account details</a>"
                "<p><a href='/auth/logout'>Sign out locally</a></p>"
                "<p><a href='/auth/logout/global'>Sign out everywhere</a></p>"
                "<p><a href='/auth/revoke'>Revoke application access</a></p>"
                "<p><a href='/auth/reauthenticate'>Re-authenticate</a></p>"
                "<p><a href='/auth/step-up'>Step up authentication</a></p>"
                "<p><a href='/sensitive'>Sensitive operation</a></p>"
                f"<p>Session expires at {identity.expires_at}; "
                f"idle deadline {identity.idle_expires_at}.</p>"
            )
        response = page(
            settings.service_id.value,
            f"Federated application — {settings.service_id.value}",
            f"{content}<p>Issuer: {html.escape(settings.issuer)}</p>"
            "<p><a href='/architecture'>Component configuration</a></p>",
        )
        if binding.created:
            set_cookie(response, settings, binding.token, ttl=binding.ttl)
        return response

    async def lifecycle_form(request: Request, purpose: BrowserActionPurpose) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        cookie = opaque_cookie(request, settings)
        if cookie is None:
            return page(
                settings.service_id.value,
                "Authentication required",
                "<p>No local session.</p>",
                status=HTTPStatus.UNAUTHORIZED,
            )
        try:
            challenge = await components.browser.action_challenge(cookie, purpose)
        except SecurityDenied:
            return page(
                settings.service_id.value,
                "Authentication required",
                "<p>No active local session.</p>",
                status=HTTPStatus.UNAUTHORIZED,
            )
        label = (
            "Sign out locally"
            if purpose == BrowserActionPurpose.SP_LOGOUT
            else "Revoke application access"
        )
        target = "/auth/logout" if purpose == BrowserActionPurpose.SP_LOGOUT else "/auth/revoke"
        explanation = (
            "End this application's local session. Your IDP sign-in remains available."
            if purpose == BrowserActionPurpose.SP_LOGOUT
            else "Revoke this application's current grant at the IDP and end this local session."
        )
        response = page(
            settings.service_id.value,
            label,
            f"<p>{explanation}</p>" + action_form(target, label, challenge),
        )
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    async def lifecycle_action(request: Request, purpose: BrowserActionPurpose) -> Response:
        cookie, challenge = await action_parameters(request, settings)
        try:
            await components.browser.act(cookie, challenge, purpose)
        except SecurityDenied:
            raise BrowserInputError(
                "The action is invalid or expired", HTTPStatus.FORBIDDEN
            ) from None
        response = redirect("/")
        clear_cookie(response, settings)
        return response

    @app.get("/auth/logout")
    async def logout_form(request: Request) -> Response:
        return await lifecycle_form(request, BrowserActionPurpose.SP_LOGOUT)

    @app.post("/auth/logout")
    async def logout(request: Request) -> Response:
        return await lifecycle_action(request, BrowserActionPurpose.SP_LOGOUT)

    @app.get("/auth/revoke")
    async def revoke_form(request: Request) -> Response:
        return await lifecycle_form(request, BrowserActionPurpose.SP_REVOKE)

    @app.post("/auth/revoke")
    async def revoke(request: Request) -> Response:
        return await lifecycle_action(request, BrowserActionPurpose.SP_REVOKE)

    @app.get("/auth/logout/global")
    async def global_logout_form(request: Request) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        cookie = opaque_cookie(request, settings)
        if cookie is None:
            raise BrowserInputError("An active local session is required", HTTPStatus.UNAUTHORIZED)
        try:
            challenge = await components.browser.action_challenge(
                cookie, BrowserActionPurpose.SP_GLOBAL_LOGOUT
            )
        except SecurityDenied:
            raise BrowserInputError(
                "An active local session is required", HTTPStatus.UNAUTHORIZED
            ) from None
        response = page(
            settings.service_id.value,
            "Sign out everywhere",
            "<p>Continue to the IDP to confirm ending this federation session.</p>"
            + action_form("/auth/logout/global", "Continue to global sign out", challenge),
        )
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            f"{BROWSER_HEADERS['Content-Security-Policy']} {settings.issuer}"
        )
        return response

    @app.post("/auth/logout/global")
    async def global_logout(request: Request) -> Response:
        cookie, challenge = await action_parameters(request, settings)
        try:
            location = await components.browser.global_logout(cookie, challenge)
        except SecurityDenied:
            raise BrowserInputError(
                "The global logout intent is invalid", HTTPStatus.FORBIDDEN
            ) from None
        return redirect(location)

    @app.get("/auth/reauthenticate")
    async def reauthentication_form(request: Request) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        cookie = opaque_cookie(request, settings)
        if cookie is None:
            raise BrowserInputError(
                "An existing local session is required", HTTPStatus.UNAUTHORIZED
            )
        try:
            challenge = await components.browser.action_challenge(
                cookie, BrowserActionPurpose.SP_REAUTHENTICATE
            )
        except SecurityDenied:
            raise BrowserInputError(
                "An existing local session is required", HTTPStatus.UNAUTHORIZED
            ) from None
        response = page(
            settings.service_id.value,
            "Re-authenticate",
            "<p>Verify the same account again or require a recent authentication event.</p>"
            "<form method='post' action='/auth/reauthenticate'>"
            "<input type='hidden' name='csrf' "
            f"value='{html.escape(challenge.get_secret_value())}'>"
            "<p><label>Authentication policy <select name='mode'>"
            "<option value='force'>Force password sign-in</option>"
            "<option value='recent'>Require recent sign-in</option></select></label></p>"
            "<p><label>Maximum authentication age in seconds "
            "<input type='number' name='max_age' min='0' max='86400' "
            "value='60' required></label></p>"
            "<button type='submit'>Re-authenticate</button></form>",
        )
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            f"{BROWSER_HEADERS['Content-Security-Policy']} {settings.issuer}"
        )
        return response

    @app.post("/auth/reauthenticate")
    async def reauthenticate(request: Request) -> Response:
        require_form_origin(request, settings)
        fields = await browser_parameters(
            request, frozenset({"csrf", "mode", "max_age"}), limit=settings.policy.max_form_bytes
        )
        cookie = opaque_cookie(request, settings)
        value = fields.get("max_age", "")
        if (
            cookie is None
            or set(fields) != {"csrf", "mode", "max_age"}
            or fields["mode"] not in {"force", "recent"}
            or not value.isascii()
            or not value.isdecimal()
            or len(value) > 5
            or int(value) > 86400
        ):
            raise BrowserInputError("A bound authentication policy form is required")
        try:
            started = await components.browser.reauthenticate(
                cookie,
                SecretStr(fields["csrf"]),
                force=fields["mode"] == "force",
                max_age=int(value),
            )
        except SecurityDenied:
            raise BrowserInputError(
                "The re-authentication intention is invalid", HTTPStatus.FORBIDDEN
            ) from None
        return redirect(started.authorization_url)

    @app.get("/auth/login")
    async def login(request: Request) -> Response:
        await browser_parameters(request, frozenset(), limit=settings.policy.max_form_bytes)
        result = await components.browser.begin(opaque_cookie(request, settings))
        response = redirect(result.authorization_url)
        if result.binding.created:
            set_cookie(response, settings, result.binding.token, ttl=result.binding.ttl)
        return response

    @app.get("/auth/callback")
    async def callback(request: Request) -> Response:
        fields = await browser_parameters(
            request, CALLBACK_FIELDS, limit=settings.policy.max_form_bytes
        )
        state = fields.get("state", "")
        cookie = opaque_cookie(request, settings)
        if (
            cookie is None
            or not 16 <= len(state) <= 256
            or bool(fields.get("code")) == bool(fields.get("error"))
        ):
            raise BrowserInputError("An active browser-bound code response is required")
        try:
            result = await components.browser.complete(
                state, cookie, f"{settings.redirect_uri}?{urlencode(fields)}"
            )
        except (
            InvalidAuthorizationResponse,
            InvalidIdToken,
            SecurityDenied,
            ValidationError,
        ):
            # Provider error text and protocol artifacts are never reflected into a page.
            raise BrowserInputError("Sign-in could not be completed. Start a new login.") from None
        response = redirect("/")
        set_cookie(response, settings, result.cookie, ttl=result.ttl)
        return response

    @app.get("/account")
    async def account(request: Request) -> Response:
        require_https(request)
        cookie = opaque_cookie(request, settings)
        identity = None
        if cookie is not None:
            try:
                identity = await components.browser.authorize(cookie)
            except SecurityDenied:
                pass
        if identity is None:
            return JSONResponse(
                {"error": "authentication_required", "service": settings.service_id.value},
                status_code=HTTPStatus.UNAUTHORIZED,
                headers=BROWSER_HEADERS,
            )
        event = identity.authentication
        return JSONResponse(
            {
                "service": settings.service_id.value,
                "issuer": settings.issuer,
                "subject": identity.subject,
                "sid": event.session_id,
                "auth_time": event.authenticated_at,
                "acr": event.assurance.value,
                "amr": [method.value for method in event.methods],
                "expires_at": identity.expires_at,
                "idle_expires_at": identity.idle_expires_at,
            },
            headers=BROWSER_HEADERS,
        )
