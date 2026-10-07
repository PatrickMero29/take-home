"""Verification-only DNS mapping for local processes, retaining real HTTPS/SNI checks."""

import asyncio
import os
import ssl
from pathlib import Path

import httpx2 as httpx

from federated_identity.cli.architecture_probe import LoopbackTransport
from federated_identity.cli.service import serve
from federated_identity.common.security.secrets import private_bytes
from federated_identity.common.settings.runtime import RuntimeSettings


class LocalServiceTransport(httpx.AsyncBaseTransport):
    """Request-local pools match production clients and cannot close each other's work."""

    def __init__(self, tls: ssl.SSLContext) -> None:
        self.tls = tls

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        async with LoopbackTransport(self.tls) as transport:
            response = await transport.handle_async_request(request)
            await response.aread()
            return response


async def run() -> None:
    settings = RuntimeSettings()
    tls = await asyncio.to_thread(
        ssl.create_default_context, cafile=str(settings.secrets_directory / "ca.crt")
    )
    path = os.environ.get("FID_VERIFICATION_CLOCK")
    if path is None:
        await serve(settings, backchannel_transport=LocalServiceTransport(tls))
        return
    clock = VerificationClock(int(await asyncio.to_thread(private_bytes, Path(path))))
    updater = asyncio.create_task(clock.follow(Path(path)))
    try:
        await serve(settings, backchannel_transport=LocalServiceTransport(tls), clock=clock)
    finally:
        updater.cancel()
        await asyncio.gather(updater, return_exceptions=True)


class VerificationClock:
    """Owner-controlled probe time; protocol hooks read memory, never files."""

    def __init__(self, value: int) -> None:
        self.value = value

    def now(self) -> int:
        return self.value

    async def follow(self, path: Path) -> None:
        while True:
            value = int(await asyncio.to_thread(private_bytes, path))
            if value < self.value:
                raise ValueError("Verification time cannot move backwards")
            self.value = value
            await asyncio.sleep(0.01)


if __name__ == "__main__":
    asyncio.run(run())
