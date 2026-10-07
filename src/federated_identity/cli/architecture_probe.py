"""Real-process architecture verification with isolated local state and verified TLS."""

import asyncio
import os
import shlex
import socket
import ssl
import sys
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory

import httpcore2
import httpx2 as httpx

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.probe_runtime import command, postgres_bin
from federated_identity.common.settings.runtime import ServiceId


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.bind(("127.0.0.1", 0))
        return int(connection.getsockname()[1])


class LoopbackBackend(httpcore2.AsyncNetworkBackend):
    """Test DNS mapping preserves original host/SNI and all TLS verification."""

    def __init__(self) -> None:
        self.backend = httpcore2.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore2's required interface
        local_address: str | None = None,
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        if host not in {service.hostname for service in ServiceId}:
            raise ValueError("The architecture verifier only resolves declared local services")
        return await self.backend.connect_tcp(
            "127.0.0.1", port, timeout, local_address, socket_options
        )


class LoopbackTransport(httpx.AsyncHTTPTransport):
    def __init__(self, tls: ssl.SSLContext) -> None:
        super().__init__(verify=tls, trust_env=False)
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=tls, network_backend=LoopbackBackend()
        )


@dataclass
class ArchitectureStack:
    root: Path
    postgres_port: int
    ports: dict[ServiceId, int]
    tls: ssl.SSLContext
    postgres_options: str
    processes: dict[ServiceId, asyncio.subprocess.Process] = field(default_factory=dict)

    @property
    def issuer(self) -> str:
        return self.origin(ServiceId.IDP)

    def origin(self, service: ServiceId) -> str:
        return f"https://{service.hostname}:{self.ports[service]}"

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=LoopbackTransport(self.tls),
            trust_env=False,
            timeout=5,
            follow_redirects=False,
        )

    async def start(self, service: ServiceId, *, fixture_file: Path | None = None) -> None:
        if fixture_file is not None and service != ServiceId.IDP:
            raise ValueError("The isolated principal fixture belongs only to the IDP")
        environment = {
            **os.environ,
            "FID_SERVICE_ID": service.value,
            "FID_PUBLIC_URL": self.origin(service),
            "FID_ISSUER": self.issuer,
            "FID_SECRETS_DIRECTORY": str(self.root / service.value),
            "FID_DATABASE_HOST": "127.0.0.1",
            "FID_DATABASE_PORT": str(self.postgres_port),
            "FID_LISTEN_HOST": "127.0.0.1",
            "FID_LISTEN_PORT": str(self.ports[service]),
        }
        arguments = (
            ("federated_identity.cli.phase0_runtime", str(fixture_file))
            if fixture_file is not None
            else ("federated_identity.cli.architecture_runtime",)
        )
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            *arguments,
            env=environment,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self.processes[service] = process
        async with self.client() as client:
            async with asyncio.timeout(30):
                while True:
                    if process.returncode is not None:
                        await process.communicate()
                        # stderr is fixed-event logging and dependency error
                        # types; never serialize a request or secret bundle.
                        raise RuntimeError(f"{service.value} exited during startup")
                    try:
                        response = await client.get(f"{self.origin(service)}/health/ready")
                        if response.is_success:
                            return
                    except httpx.HTTPError:
                        pass
                    await asyncio.sleep(0.05)

    async def stop(self, service: ServiceId) -> None:
        process = self.processes.pop(service, None)
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.communicate(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.communicate()


@asynccontextmanager
async def architecture_stack(
    binaries: Path | None = None, *, start_applications: bool = True
) -> AsyncIterator[ArchitectureStack]:
    binaries = postgres_bin(binaries)
    temporary = await asyncio.to_thread(TemporaryDirectory, prefix="fid-architecture-")
    root = Path(temporary.name)
    stack: ArchitectureStack | None = None
    started = False
    try:
        ports = {service: free_port() for service in ServiceId}
        await asyncio.to_thread(bootstrap_assets, root, public_ports=ports)
        data = root / "pgdata"
        log = root / "postgres.log"
        pg_port = free_port()
        await command(
            str(binaries / "initdb"),
            "-D",
            str(data),
            "-U",
            "fid_admin",
            "--auth-local=trust",
            "--auth-host=scram-sha-256",
            "--pwfile",
            str(root / "postgres" / "admin.password"),
            "--locale=C",
        )

        def hba_path() -> Path:
            packaged = resources.files("federated_identity").joinpath("resources", "pg_hba.conf")
            if packaged.is_file():
                return Path(str(packaged))
            return Path(__file__).resolve().parents[3] / "ops" / "postgres" / "pg_hba.conf"

        hba = await asyncio.to_thread(hba_path)
        options = " ".join(
            [
                "-p",
                str(pg_port),
                "-h",
                "127.0.0.1",
                "-k",
                shlex.quote(str(root)),
                "-c",
                "ssl=on",
                "-c",
                f"ssl_cert_file={shlex.quote(str(root / 'postgres' / 'server.crt'))}",
                "-c",
                f"ssl_key_file={shlex.quote(str(root / 'postgres' / 'server.key'))}",
                "-c",
                f"hba_file={shlex.quote(str(hba))}",
            ]
        )
        await command(
            str(binaries / "pg_ctl"),
            "-D",
            str(data),
            "-l",
            str(log),
            "-w",
            "-t",
            "10",
            "-o",
            options,
            "start",
        )
        started = True
        await initialize_databases(root, host="127.0.0.1", port=pg_port)
        tls = await asyncio.to_thread(
            ssl.create_default_context, cafile=str(root / "authority" / "ca.crt")
        )
        stack = ArchitectureStack(
            root=root,
            postgres_port=pg_port,
            ports=ports,
            tls=tls,
            postgres_options=options,
        )
        if start_applications:
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
                await stack.start(service)
        yield stack
    finally:
        if stack is not None:
            for service in tuple(stack.processes):
                await stack.stop(service)
        try:
            if started:
                await command(
                    str(binaries / "pg_ctl"),
                    "-D",
                    str(root / "pgdata"),
                    "-w",
                    "-t",
                    "10",
                    "-m",
                    "fast",
                    "stop",
                )
        finally:
            await asyncio.to_thread(temporary.cleanup)


async def verify_architecture() -> dict[str, object]:
    async with architecture_stack() as stack:
        async with stack.client() as client:
            services = []
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
                response = await client.get(f"{stack.origin(service)}/architecture")
                response.raise_for_status()
                services.append(service.value)
            return {
                "stage": "target_architecture",
                "services": services,
                "independent_processes": len({process.pid for process in stack.processes.values()}),
                "tls": "verified hostname and CA",
                "databases": "separate role and database per service",
                "migrations": "applied",
            }
