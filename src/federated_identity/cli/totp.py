"""Explicit IDP-owner authenticator provisioning, using the enrolled encrypted factor."""

import asyncio

import pyotp
from sqlalchemy import select

from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.mfa import TotpCredentialRow, TotpRepository
from federated_identity.idp.repositories.users import UserRow


async def totp_provisioning(settings: RuntimeSettings, username: str) -> dict[str, str]:
    if settings.service_id != ServiceId.IDP:
        raise ValueError("TOTP provisioning belongs only to the IDP owner")
    assets = await asyncio.to_thread(load_runtime_secrets, settings)
    database = await asyncio.to_thread(Database, assets.database_url, ca_file=assets.ca_certificate)
    try:
        repository = TotpRepository(database, assets.envelope, SystemClock())
        async with database.sessions() as session:
            user = await session.scalar(select(UserRow).where(UserRow.username == username))
            row = await session.get(TotpCredentialRow, user.subject) if user else None
            if user is None or row is None:
                raise ValueError("No enrolled seeded authenticator for this username")
            otp = pyotp.TOTP(repository.secret(row).get_secret_value())
            return {
                "username": username,
                "provisioning_uri": otp.provisioning_uri(
                    name=username, issuer_name="Federated Identity"
                ),
            }
    finally:
        await database.dispose()
