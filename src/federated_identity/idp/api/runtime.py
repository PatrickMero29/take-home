"""A deployment factory for the IDP with its independently owned resources."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from federated_identity.common.observability.runtime_routes import install_runtime_routes
from federated_identity.idp.api.app import PrincipalProvider, create_app
from federated_identity.idp.api.browser import IdpBrowserRoutes
from federated_identity.idp.api.logout import install_logout_routes
from federated_identity.idp.api.operator import install_operator_routes
from federated_identity.idp.api.signing import install_signing_routes
from federated_identity.idp.schemas.components import IdpComponents


def create_idp_application(
    components: IdpComponents, *, principal_provider: PrincipalProvider | None = None
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        dispatcher = asyncio.create_task(
            components.logout_dispatcher.run(), name="logout-dispatcher"
        )
        try:
            yield
        finally:
            dispatcher.cancel()
            await asyncio.gather(dispatcher, return_exceptions=True)
            await components.oidc.database.dispose()

    browser = IdpBrowserRoutes(components)
    app = create_app(
        components.oidc,
        principal_provider=principal_provider if principal_provider is not None else browser,
        authorization_handler=browser,
        lifespan=lifespan,
    )
    app.state.components = components
    install_runtime_routes(
        app,
        components.settings,
        components.oidc.database,
        components.readiness,
    )
    browser.install(app)
    install_logout_routes(app, components)
    install_operator_routes(app, components)
    install_signing_routes(app, components)
    return app
