"""Disposable local infrastructure for Phase 0 verification, not deployment bootstrap."""

import asyncio
import ipaddress
import os
import secrets
import shutil
import socket
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, Request
from pydantic import SecretStr

from federated_identity.common.policy import verifier_digest
from federated_identity.idp.schemas.models import AuthenticatedPrincipal


async def command(*arguments: str) -> None:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate()
    if process.returncode:
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {output.decode(errors='replace')}")


def postgres_bin(explicit: Path | None = None) -> Path:
    if explicit is not None:
        candidate = explicit
    elif configured := os.environ.get("FID_POSTGRES_BIN"):
        candidate = Path(configured)
    elif executable := shutil.which("initdb"):
        candidate = Path(executable).parent
    else:
        candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin/initdb"))
        if not candidates:
            raise RuntimeError(
                "Install PostgreSQL server binaries or set FID_POSTGRES_BIN to their bin directory"
            )
        candidate = candidates[-1].parent
    for name in ("initdb", "pg_ctl", "postgres"):
        if not (candidate / name).is_file():
            raise RuntimeError(f"Missing PostgreSQL executable: {candidate / name}")
    return candidate


@asynccontextmanager
async def temporary_postgres(binaries: Path | None = None) -> AsyncIterator[SecretStr]:
    """A separate PostgreSQL process, private Unix socket, and disposable data directory."""
    bin_path = postgres_bin(binaries)
    directory = await asyncio.to_thread(TemporaryDirectory, prefix="fid-pg-")
    root = Path(directory.name)
    data = root / "data"
    socket_dir = root / "socket"
    log = root / "postgres.log"
    # This port names the Unix socket; PostgreSQL has no TCP listener here.
    port = 20000 + secrets.randbelow(40000)
    started = False
    try:
        await asyncio.to_thread(socket_dir.mkdir, mode=0o700)
        await command(
            str(bin_path / "initdb"),
            "-D",
            str(data),
            "-U",
            "postgres",
            "--auth-local=trust",
            "--auth-host=reject",
            "--encoding=UTF8",
            "--locale=C",
        )
        await command(
            str(bin_path / "pg_ctl"),
            "-D",
            str(data),
            "-l",
            str(log),
            "-w",
            "-t",
            "10",
            "-o",
            f"-k {socket_dir} -p {port} -c listen_addresses=''",
            "start",
        )
        started = True
        query = urlencode({"host": str(socket_dir), "port": str(port)})
        yield SecretStr(f"postgresql+asyncpg://postgres@/postgres?{query}")
    finally:
        try:
            if started:
                await command(
                    str(bin_path / "pg_ctl"),
                    "-D",
                    str(data),
                    "-w",
                    "-t",
                    "10",
                    "-m",
                    "fast",
                    "stop",
                )
        finally:
            await asyncio.to_thread(directory.cleanup)


@dataclass(frozen=True)
class TlsMaterial:
    certificate: Path
    private_key: Path
    ca_certificate: Path
    password: SecretStr

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca_certificate))


def create_tls_material(directory: Path) -> TlsMaterial:
    """Use cryptography's X.509 implementation for an ephemeral CA and server certificate."""
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 0 ephemeral CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    password = SecretStr(secrets.token_urlsafe(32))
    paths = TlsMaterial(
        certificate=directory / "server.crt",
        private_key=directory / "server.key",
        ca_certificate=directory / "ca.crt",
        password=password,
    )
    paths.certificate.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    paths.ca_certificate.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    # Even the disposable server key is encrypted and private to its owner.
    key_bytes = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.get_secret_value().encode("ascii")),
    )
    descriptor = os.open(paths.private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(key_bytes)
    return paths


class FixturePrincipalProvider:
    """A generated proof authenticates a labelled fixture event for the local probe.

    This is injected only by the verification harness. The application factory
    otherwise has no principal and cannot mint authenticated authorization codes.
    """

    def __init__(self, proof: SecretStr, principal: AuthenticatedPrincipal) -> None:
        self._proof_digest = verifier_digest(proof.get_secret_value())
        self._principal = principal

    async def authenticate(self, request: Request) -> AuthenticatedPrincipal | None:
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if (
            scheme.lower() == "bearer"
            and len(value) <= 256
            and secrets.compare_digest(verifier_digest(value), self._proof_digest)
        ):
            return self._principal
        return None


def loopback_socket() -> socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind(("127.0.0.1", 0))
    connection.listen(128)
    connection.setblocking(False)
    return connection


@asynccontextmanager
async def https_server(
    app: FastAPI, connection: socket.socket, tls: TlsMaterial
) -> AsyncIterator[None]:
    configuration = uvicorn.Config(
        app,
        ssl_certfile=str(tls.certificate),
        ssl_keyfile=str(tls.private_key),
        ssl_keyfile_password=tls.password.get_secret_value(),
        proxy_headers=False,
        access_log=False,
        log_level="warning",
        lifespan="off",
        ws="none",
    )
    server = uvicorn.Server(configuration)
    task = asyncio.create_task(server.serve(sockets=[connection]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("HTTPS server stopped before becoming ready")
                await asyncio.sleep(0.01)
        yield
    finally:
        server.should_exit = True
        try:
            async with asyncio.timeout(5):
                await task
        finally:
            if not task.done():
                task.cancel()
            connection.close()
