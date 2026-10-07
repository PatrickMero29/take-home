"""One shared SP implementation instantiated as independent application processes."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from federated_identity.common.observability.runtime_routes import install_runtime_routes
from federated_identity.sp.api.browser import install_sp_browser_routes
from federated_identity.sp.api.logout import install_logout_routes
from federated_identity.sp.api.step_up import install_step_up_routes
from federated_identity.sp.schemas.components import SpComponents


def create_sp_application(components: SpComponents) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await components.database.dispose()

    app = FastAPI(
        title=f"Federated Identity — {components.settings.service_id.value}",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[components.settings.service_id.hostname],
        www_redirect=False,
    )
    app.state.components = components
    install_runtime_routes(app, components.settings, components.database, components.readiness)
    install_sp_browser_routes(app, components)
    install_logout_routes(app, components)
    install_step_up_routes(app, components)
    return app
