"""Privileged, one-shot role/database creation separated from application processes."""

import asyncio
import ssl
from pathlib import Path

import asyncpg
from pydantic import TypeAdapter

from federated_identity.common.persistence.foundations import enroll_encryption_binding
from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.security.secrets import load_runtime_secrets, private_bytes
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.mfa import TotpRepository
from federated_identity.idp.repositories.operator import OperatorRepository
from federated_identity.idp.repositories.users import UserRepository
from federated_identity.idp.schemas.models import ClientRegistration
from federated_identity.idp.services.provisioning import (
    load_seeded_operator,
    load_seeded_totps,
    load_seeded_users,
)


async def initialize_databases(root: Path, *, host: str = "postgres", port: int = 5432) -> None:
    password = await asyncio.to_thread(private_bytes, root / "postgres" / "admin.password")
    tls = await asyncio.to_thread(
        ssl.create_default_context, cafile=str(root / "postgres" / "ca.crt")
    )
    connection = await asyncpg.connect(
        host=host,
        port=port,
        user="fid_admin",
        database="postgres",
        password=password.decode("ascii"),
        ssl=tls,
        timeout=10,
    )
    try:
        await connection.execute("SELECT pg_advisory_lock(728114)")
        for service in ServiceId:
            role = service.role  # Constant enum-derived SQL identifiers, never request input.
            exists = await connection.fetchval("SELECT 1 FROM pg_roles WHERE rolname=$1", role)
            if exists is None:
                secret = await asyncio.to_thread(
                    private_bytes, root / service.value / "database.password"
                )
                quoted = await connection.fetchval(
                    "SELECT quote_literal($1)", secret.decode("ascii")
                )
                await connection.execute(
                    f'CREATE ROLE "{role}" LOGIN PASSWORD {quoted} '
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT"
                )
            attributes = await connection.fetchrow(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_roles WHERE rolname=$1",
                role,
            )
            memberships = await connection.fetchval(
                "SELECT count(*) FROM pg_auth_members "
                "WHERE member=(SELECT oid FROM pg_roles WHERE rolname=$1)",
                role,
            )
            if attributes is None or any(attributes) or memberships:
                raise RuntimeError("An application database role has unexpected privileges")
            database_exists = await connection.fetchval(
                "SELECT 1 FROM pg_database WHERE datname=$1", service.database
            )
            if database_exists is None:
                await connection.execute(f'CREATE DATABASE "{service.database}" OWNER "{role}"')
            owner = await connection.fetchval(
                "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1",
                service.database,
            )
            if owner != role:
                raise RuntimeError("An application database has an unexpected owner")
            await connection.execute(f'REVOKE CONNECT ON DATABASE "{service.database}" FROM PUBLIC')
            await connection.execute(f'GRANT CONNECT ON DATABASE "{service.database}" TO "{role}"')
        await connection.execute("REVOKE CONNECT ON DATABASE postgres FROM PUBLIC")
        await connection.execute("REVOKE CONNECT ON DATABASE template1 FROM PUBLIC")
    finally:
        await connection.close()

    for service in ServiceId:
        settings = RuntimeSettings(
            service_id=service,
            public_url=f"https://{service.hostname}:{service.default_port}",
            listen_port=service.default_port,
            secrets_directory=root / service.value,
            database_host=host,
            database_port=port,
        )
        secrets = await asyncio.to_thread(load_runtime_secrets, settings)
        database = await asyncio.to_thread(
            Database, secrets.database_url, ca_file=secrets.ca_certificate
        )
        try:
            await migrate(database, service)
            await enroll_encryption_binding(database, secrets, service)
            if service == ServiceId.IDP:
                raw = await asyncio.to_thread(
                    (settings.secrets_directory / "clients.json").read_bytes
                )
                clients = TypeAdapter(list[ClientRegistration]).validate_json(raw)
                await database.seed_clients(clients)
                users = await asyncio.to_thread(
                    load_seeded_users, settings.secrets_directory, secrets.envelope
                )
                await UserRepository(database, SystemClock()).seed(users.users)
                totps = await asyncio.to_thread(
                    load_seeded_totps, settings.secrets_directory, secrets.envelope
                )
                await TotpRepository(database, secrets.envelope, SystemClock()).seed(
                    totps.credentials
                )
                operator = await asyncio.to_thread(
                    load_seeded_operator, settings.secrets_directory, secrets.envelope
                )
                await OperatorRepository(database, secrets.envelope, SystemClock()).seed(operator)
        finally:
            await database.dispose()
