"""Shared runtime health and selected public component visibility."""

from http import HTTPStatus

from fastapi import FastAPI
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse

from federated_identity.common.observability.boundaries import RuntimeBoundaries
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.foundations import RuntimeReadiness
from federated_identity.common.settings.runtime import RuntimeSettings


def install_runtime_routes(
    app: FastAPI,
    settings: RuntimeSettings,
    database: AsyncDatabase,
    readiness: RuntimeReadiness,
) -> None:
    app.add_middleware(
        RuntimeBoundaries,
        timeout_seconds=settings.request_timeout_seconds,
        max_body_bytes=settings.policy.max_form_bytes,
        max_inflight=settings.max_inflight_requests,
    )

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live", "service": settings.service_id.value}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        try:
            healthy = await readiness.ready()
        except (SQLAlchemyError, OSError):
            healthy = False
        status = HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE
        return JSONResponse(
            {"status": "ready" if healthy else "unavailable", "service": settings.service_id.value},
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/architecture")
    async def architecture() -> dict[str, object]:
        return {
            "service": settings.service_id.value,
            "public_origin": settings.public_url,
            "issuer": settings.issuer,
            "persistence": "postgresql+asyncpg",
            "session_backend": settings.session_backend,
            "service_authentication": list(settings.authentication_methods),
            "revocation_backend": settings.revocation_backend,
            "logout_backend": settings.logout_backend,
            "step_up_backend": settings.step_up_backend,
            "stage": "full_system_acceptance",
        }
