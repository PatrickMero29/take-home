"""IDP login forms and account pages accept only the IDP's own opaque session cookie."""

import html
from http import HTTPStatus
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from pydantic import SecretStr
from starlette.responses import HTMLResponse, JSONResponse, Response

from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.browser import (
    BROWSER_HEADERS,
    OPAQUE_COOKIE,
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
from federated_identity.common.security.model import SecurityDenied
from federated_identity.idp.api.app import protocol_http_response
from federated_identity.idp.api.logout import notify_logout
from federated_identity.idp.repositories.throttling import AuthenticationThrottled
from federated_identity.idp.schemas.browser import LoginContinuation
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.schemas.models import (
    AuthenticatedPrincipal,
    AuthorizationInteraction,
    ProtocolMessage,
)
from federated_identity.idp.services.browser import InvalidLoginForm, RejectedCredentials

LOGIN_FIELDS = frozenset({"csrf", "username", "password", "otp"})
PASSWORD_FIELDS = frozenset({"csrf", "username", "password"})


class IdpBrowserRoutes:
    def __init__(self, components: IdpComponents) -> None:
        self.components = components
        self.settings = components.settings

    async def authenticate(self, request: Request) -> AuthenticatedPrincipal | None:
        identity = await self.components.browser.identity(opaque_cookie(request, self.settings))
        return AuthenticatedPrincipal.from_event(identity.authentication) if identity else None

    async def authorize(
        self, request: Request, message: ProtocolMessage, principal: AuthenticatedPrincipal | None
    ) -> Response:
        result = await self.components.oidc.authorize_browser(message, principal)
        if isinstance(result, AuthorizationInteraction):
            return await self.login_form(
                request,
                LoginContinuation(
                    authorization=result.parameters,
                    expected_subject=principal.sub if principal is not None else None,
                ),
            )
        response = protocol_http_response(result)
        response.headers.update(BROWSER_HEADERS)
        return response

    async def login_form(
        self,
        request: Request,
        continuation: LoginContinuation,
        *,
        rejected: bool = False,
    ) -> HTMLResponse:
        if (
            continuation.requires_totp
            and continuation.attempts >= self.settings.mfa_form_max_attempts
        ):
            response = page(
                "idp",
                "Authentication attempt limit",
                "<p>This authentication attempt is exhausted. "
                "Start a fresh sign-in after the rate-limit window.</p>"
                "<a href='/'>Return to identity provider</a>",
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
            response.headers["Retry-After"] = str(self.settings.authentication_window_seconds)
            return response
        binding = await self.components.browser.binding(opaque_cookie(request, self.settings))
        challenge = await self.components.browser.challenge(binding, continuation)
        destination = (
            f"<p>Continue to {html.escape(continuation.authorization.client_id)}.</p>"
            if continuation.authorization is not None
            else "<p>Sign in to the identity provider.</p>"
        )
        message = (
            "Invalid credentials or authentication code."
            if continuation.requires_totp
            else "Invalid username or password."
        )
        error = f"<p role='alert'>{message}</p>" if rejected else ""
        factor = (
            "<p><label>Authenticator code <input name='otp' inputmode='numeric' "
            "autocomplete='one-time-code' pattern='[0-9]{6}' minlength='6' "
            "maxlength='6' required></label></p>"
            if continuation.requires_totp
            else ""
        )
        response = page(
            self.settings.service_id.value,
            "Sign in",
            "<h2>Sign in</h2>"
            f"{destination}{error}"
            "<form method='post' action='/login'>"
            f"<input type='hidden' name='csrf' value='{html.escape(challenge.get_secret_value())}'>"
            "<p><label>Username <input name='username' autocomplete='username' "
            "maxlength='32' required></label></p>"
            "<p><label>Password <input name='password' type='password' "
            "autocomplete='current-password' maxlength='1024' required></label></p>"
            f"{factor}<button type='submit'>Sign in</button></form>",
            status=HTTPStatus.UNAUTHORIZED if rejected else HTTPStatus.OK,
        )
        # A no-referrer navigation form sends Origin: null in Chromium. Retain
        # same-origin form provenance while suppressing cross-origin referrers.
        response.headers["Referrer-Policy"] = "same-origin"
        if continuation.authorization is not None:
            # Chromium applies form-action to the post-login redirect chain.
            # The fixed /login action stays local; permit only this already
            # validated RP origin as the subsequent authorization destination.
            callback = urlsplit(continuation.authorization.redirect_uri)
            response.headers["Content-Security-Policy"] = (
                f"{BROWSER_HEADERS['Content-Security-Policy']} https://{callback.netloc}"
            )
        if binding.created:
            set_cookie(response, self.settings, binding.token, ttl=binding.ttl)
        return response

    def install(self, app: FastAPI) -> None:
        install_browser_errors(app, self.settings)

        @app.exception_handler(AuthenticationThrottled)
        async def throttled(request: Request, error: AuthenticationThrottled) -> Response:
            response = page(
                "idp",
                "Authentication temporarily limited",
                "<p>Too many authentication attempts. Start a new form after the retry window.</p>"
                "<a href='/'>Return</a>",
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
            response.headers["Retry-After"] = str(error.retry_after)
            return response

        @app.exception_handler(InvalidLoginForm)
        async def invalid_form(request: Request, error: InvalidLoginForm) -> Response:
            return page(
                self.settings.service_id.value,
                "Sign-in form rejected",
                "<p>The sign-in form is invalid or expired. Start again.</p>"
                "<a href='/login'>Sign in</a>",
                status=HTTPStatus.FORBIDDEN,
            )

        @app.get("/", response_class=HTMLResponse)
        async def home(request: Request) -> Response:
            require_https(request)
            cookie = opaque_cookie(request, self.settings)
            identity = await self.components.browser.identity(cookie)
            binding = await self.components.browser.binding(cookie)
            if identity is None:
                content = "<p>Not signed in.</p><a href='/login'>Sign in</a>"
            else:
                content = (
                    f"<p>Signed in as <strong>{html.escape(identity.username)}</strong>.</p>"
                    "<p>Authenticated user: <span data-testid='subject'>"
                    f"{html.escape(identity.session.subject.subject)}</span></p>"
                    "<p>This IDP session enables single sign-on at registered applications.</p>"
                    "<a href='/account'>Account details</a>"
                    "<p><a href='/grants'>Manage application access</a></p>"
                    "<p><a href='/logout'>End IDP session</a></p>"
                )
            response = page(
                self.settings.service_id.value,
                "Identity provider",
                f"{content}<p>Issuer: {html.escape(self.settings.issuer)}</p>"
                "<p><a href='/architecture'>Component configuration</a></p>"
                "<p><a href='/admin'>Operator control plane</a></p>",
            )
            if binding.created:
                set_cookie(response, self.settings, binding.token, ttl=binding.ttl)
            return response

        @app.get("/logout")
        async def logout_form(request: Request) -> Response:
            await browser_parameters(
                request, frozenset(), limit=self.settings.policy.max_form_bytes
            )
            cookie = opaque_cookie(request, self.settings)
            identity = await self.components.browser.identity(cookie)
            if identity is None or cookie is None:
                return page(
                    "idp",
                    "Authentication required",
                    "<p>Sign in first.</p>",
                    status=HTTPStatus.UNAUTHORIZED,
                )
            try:
                challenge = await self.components.browser.action_challenge(
                    cookie,
                    BrowserAction(
                        purpose=BrowserActionPurpose.IDP_LOGOUT, target=identity.session.session_id
                    ),
                )
            except SecurityDenied:
                raise BrowserInputError(
                    "The session is no longer active", HTTPStatus.FORBIDDEN
                ) from None
            response = page(
                "idp",
                "End IDP session",
                "<p>End this IDP session and revoke its application grants.</p>"
                + action_form("/logout", "End IDP session", challenge),
            )
            response.headers["Referrer-Policy"] = "same-origin"
            return response

        @app.post("/logout")
        async def logout(request: Request) -> Response:
            cookie, challenge = await action_parameters(request, self.settings)
            try:
                ended = await self.components.browser.act(
                    cookie, challenge, BrowserActionPurpose.IDP_LOGOUT
                )
            except SecurityDenied:
                raise BrowserInputError(
                    "The action is invalid or expired", HTTPStatus.FORBIDDEN
                ) from None
            if ended is not None:
                await notify_logout(self.components, ended)
            response = redirect("/")
            clear_cookie(response, self.settings)
            return response

        @app.get("/grants")
        async def grants(request: Request) -> Response:
            await browser_parameters(
                request, frozenset(), limit=self.settings.policy.max_form_bytes
            )
            cookie = opaque_cookie(request, self.settings)
            if cookie is None or await self.components.browser.identity(cookie) is None:
                return page(
                    "idp",
                    "Authentication required",
                    "<p>Sign in first.</p>",
                    status=HTTPStatus.UNAUTHORIZED,
                )
            try:
                records = await self.components.browser.grants(cookie)
                content = "<h2>Application access for this IDP session</h2>"
                for grant in records:
                    active = (
                        grant.revoked_at is None
                        and grant.expires_at > self.components.oidc.clock.now()
                    )
                    content += f"<section><h3>{html.escape(grant.client_id)}</h3>"
                    content += (
                        f"<p>Status: {'active' if active else 'ended'}; "
                        f"expires at {grant.expires_at}.</p>"
                    )
                    if active:
                        challenge = await self.components.browser.action_challenge(
                            cookie,
                            BrowserAction(
                                purpose=BrowserActionPurpose.IDP_REVOKE, target=grant.grant_id
                            ),
                        )
                        content += action_form(
                            "/grants/revoke", f"Revoke {grant.client_id} access", challenge
                        )
                    content += "</section>"
                content += "<a href='/'>Return to identity provider</a>"
            except SecurityDenied:
                raise BrowserInputError(
                    "The session is no longer active", HTTPStatus.FORBIDDEN
                ) from None
            response = page("idp", "Application access", content)
            response.headers["Referrer-Policy"] = "same-origin"
            return response

        @app.post("/grants/revoke")
        async def revoke_grant(request: Request) -> Response:
            cookie, challenge = await action_parameters(request, self.settings)
            try:
                await self.components.browser.act(
                    cookie, challenge, BrowserActionPurpose.IDP_REVOKE
                )
            except SecurityDenied:
                raise BrowserInputError(
                    "The action is invalid or expired", HTTPStatus.FORBIDDEN
                ) from None
            return redirect("/grants")

        @app.get("/login")
        async def login(request: Request) -> Response:
            await browser_parameters(
                request, frozenset(), limit=self.settings.policy.max_form_bytes
            )
            if await self.components.browser.identity(opaque_cookie(request, self.settings)):
                return redirect("/")
            return await self.login_form(request, LoginContinuation())

        @app.post("/login")
        async def submit(request: Request) -> Response:
            require_form_origin(request, self.settings)
            fields = await browser_parameters(
                request, LOGIN_FIELDS, limit=self.settings.policy.max_form_bytes
            )
            cookie = opaque_cookie(request, self.settings)
            if (
                cookie is None
                or not PASSWORD_FIELDS <= set(fields)
                or not OPAQUE_COOKIE.fullmatch(fields["csrf"])
            ):
                raise InvalidLoginForm("Missing browser-bound credential form")
            try:
                result = await self.components.browser.submit(
                    SecretStr(fields["csrf"]),
                    cookie,
                    fields["username"],
                    SecretStr(fields["password"]),
                    SecretStr(fields["otp"]) if "otp" in fields else None,
                    source=request.client.host if request.client is not None else "unknown",
                )
            except SecurityDenied:
                raise InvalidLoginForm(
                    "Authentication expired or was revoked during verification"
                ) from None
            if isinstance(result, RejectedCredentials):
                return await self.login_form(request, result.continuation, rejected=True)
            authorization = result.continuation.authorization
            response: Response
            if authorization is None:
                response = redirect("/")
            else:
                message = ProtocolMessage(
                    "GET",
                    self.components.oidc.settings.authorization_endpoint,
                    {
                        name: str(value)
                        for name, value in authorization.model_dump(exclude_none=True).items()
                    },
                )
                response = protocol_http_response(
                    await self.components.oidc.authorize(
                        message,
                        AuthenticatedPrincipal.from_event(result.identity.authentication),
                        fresh_authentication=True,
                    )
                )
                response.headers.update(BROWSER_HEADERS)
            set_cookie(response, self.settings, result.cookie, ttl=result.ttl)
            return response

        @app.get("/account")
        async def account(request: Request) -> Response:
            require_https(request)
            identity = await self.components.browser.identity(opaque_cookie(request, self.settings))
            if identity is None:
                return JSONResponse(
                    {"error": "authentication_required", "service": self.settings.service_id.value},
                    status_code=HTTPStatus.UNAUTHORIZED,
                    headers=BROWSER_HEADERS,
                )
            event = identity.authentication
            return JSONResponse(
                {
                    "service": self.settings.service_id.value,
                    "issuer": self.settings.issuer,
                    "username": identity.username,
                    "subject": event.subject.subject,
                    "sid": event.session_id,
                    "auth_time": event.authenticated_at,
                    "acr": event.assurance.value,
                    "amr": [method.value for method in event.methods],
                },
                headers=BROWSER_HEADERS,
            )
