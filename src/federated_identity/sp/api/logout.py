"""Back-channel requests authenticate with logout-purpose JWTs, never browser cookies."""

from http import HTTPStatus

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from federated_identity.common.security.browser import BrowserInputError, browser_parameters
from federated_identity.common.security.logout import InvalidLogoutToken
from federated_identity.common.security.model import SecurityDenied
from federated_identity.sp.protocol.oidc import InvalidIdToken
from federated_identity.sp.schemas.components import SpComponents


def install_logout_routes(app: FastAPI, components: SpComponents) -> None:
    @app.post("/backchannel-logout")
    async def backchannel_logout(request: Request) -> Response:
        try:
            fields = await browser_parameters(
                request,
                frozenset({"logout_token"}),
                limit=components.settings.policy.max_form_bytes,
                ignore_unknown=True,
            )
            if not fields.get("logout_token"):
                raise InvalidLogoutToken("A logout token is required")
            await components.logout.receive(fields["logout_token"])
        except (BrowserInputError, InvalidLogoutToken, InvalidIdToken, SecurityDenied):
            return JSONResponse(
                {"error": "invalid_request"},
                status_code=HTTPStatus.BAD_REQUEST,
                headers={"Cache-Control": "no-store"},
            )
        return Response(status_code=HTTPStatus.OK, headers={"Cache-Control": "no-store"})
