"""ASGI request size, concurrency and deadline boundaries for all runtime routes."""

import asyncio
from http import HTTPStatus

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimit(ValueError):
    pass


class RuntimeBoundaries:
    def __init__(
        self, app: ASGIApp, *, timeout_seconds: float, max_body_bytes: int, max_inflight: int
    ) -> None:
        self.app = app
        self.timeout_seconds = timeout_seconds
        self.max_body_bytes = max_body_bytes
        self.slots = asyncio.Semaphore(max_inflight)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self.slots.locked():
            await self.reject(
                scope, receive, send, HTTPStatus.SERVICE_UNAVAILABLE, "request_capacity"
            )
            return
        content_lengths = [
            value for name, value in scope["headers"] if name.lower() == b"content-length"
        ]
        if content_lengths:
            try:
                if len(content_lengths) != 1 or not content_lengths[0].isdigit():
                    raise ValueError
                length = int(content_lengths[0])
            except ValueError:
                await self.reject(scope, receive, send, HTTPStatus.BAD_REQUEST, "invalid_length")
                return
            if length > self.max_body_bytes:
                await self.reject(
                    scope, receive, send, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_limit"
                )
                return
        received = 0
        started = False

        async def bounded_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyLimit
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        async with self.slots:
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    await self.app(scope, bounded_receive, tracked_send)
            except RequestBodyLimit:
                if started:
                    raise
                await self.reject(
                    scope, receive, send, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_limit"
                )
            except TimeoutError:
                if started:
                    raise
                await self.reject(
                    scope, receive, send, HTTPStatus.GATEWAY_TIMEOUT, "request_timeout"
                )

    @staticmethod
    async def reject(
        scope: Scope, receive: Receive, send: Send, status: HTTPStatus, error: str
    ) -> None:
        await JSONResponse(
            {"error": error},
            status_code=status,
            headers={"Cache-Control": "no-store", "Connection": "close"},
        )(scope, receive, send)
