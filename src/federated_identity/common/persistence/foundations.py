"""Durable encryption-key binding and schema-aware runtime readiness."""

import json

from cryptography.fernet import InvalidToken
from pydantic import ValidationError
from sqlalchemy import BigInteger, CheckConstraint, Integer, LargeBinary, String, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import EncryptionBinding, RuntimeSecrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.mfa import TotpRepository
from federated_identity.idp.repositories.operator import OperatorRepository
from federated_identity.idp.repositories.users import UserRepository


class RuntimeFoundationError(RuntimeError):
    """A public-safe startup explanation, with dependency details kept out of logs."""


class FoundationBase(DeclarativeBase):
    pass


class RuntimeBindingRow(FoundationBase):
    __tablename__ = "runtime_key_binding"
    __table_args__ = (CheckConstraint("binding_id=1", name="runtime_binding_singleton"),)

    binding_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[str] = mapped_column(String(16), nullable=False)
    encrypted_check: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


def verify_binding(row: RuntimeBindingRow, assets: RuntimeSecrets, service: ServiceId) -> None:
    try:
        payload = assets.envelope.decrypt(row.encrypted_check, purpose="runtime-database-key-check")
        bound = EncryptionBinding.model_validate_json(json.dumps(payload))
    except (InvalidToken, ValidationError, ValueError) as error:
        raise RuntimeFoundationError(
            "Encryption key cannot decrypt its persisted database binding"
        ) from error
    if row.service_id != service.value or bound != assets.binding:
        raise RuntimeFoundationError(
            "Secret bundle does not match this service's persisted database"
        )


async def enroll_encryption_binding(
    database: AsyncDatabase, assets: RuntimeSecrets, service: ServiceId
) -> None:
    """Initialization alone enrolls a key, after verifying all pre-binding encrypted data."""
    if assets.binding.service_id != service:
        raise RuntimeFoundationError("Cannot enroll another service's secret bundle")
    columns = [
        ("browser_sessions", "encrypted_payload", "browser-session"),
        ("browser_actions", "encrypted_payload", "browser-action"),
    ]
    if service == ServiceId.IDP:
        columns.append(("logout_outbox", "encrypted_payload", "logout-delivery"))
        columns.append(("login_challenges", "encrypted_payload", "idp-login"))
        columns.append(("signing_key_material", "encrypted_private_key", "issuer-signing-key"))
        columns.append(("totp_credentials", "encrypted_secret", "totp-secret"))
    else:
        columns.extend(
            [
                ("authorization_transactions", "encrypted_payload", "oidc-transaction"),
                ("sp_authentication_sessions", "encrypted_evidence", "sp-authentication"),
                ("sp_authentication_sessions", "encrypted_access_token", "sp-access-token"),
                ("sp_authentication_sessions", "encrypted_refresh_token", "sp-refresh-token"),
                ("sensitive_operations", "encrypted_evidence", "sensitive-operation"),
            ]
        )
    async with database.sessions() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(728115)"))
            existing = await session.get(RuntimeBindingRow, 1)
            if existing is not None:
                verify_binding(existing, assets, service)
                return
            for table, column, purpose in columns:
                # These identifiers are internal migration-owned constants.
                rows = await session.stream(
                    text(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL")
                )
                async for row in rows:
                    ciphertext = row[0]
                    if not isinstance(ciphertext, bytes):
                        raise RuntimeFoundationError("Persisted encrypted data has an invalid type")
                    try:
                        assets.envelope.decrypt(ciphertext, purpose=purpose)
                    except (InvalidToken, ValueError) as error:
                        raise RuntimeFoundationError(
                            "Existing data cannot be decrypted; restore the original encryption key"
                        ) from error
            session.add(
                RuntimeBindingRow(
                    binding_id=1,
                    service_id=service.value,
                    created_at=SystemClock().now(),
                    encrypted_check=assets.envelope.encrypt(
                        assets.binding.model_dump(mode="json"), purpose="runtime-database-key-check"
                    ),
                )
            )


class RuntimeReadiness:
    def __init__(
        self, database: AsyncDatabase, assets: RuntimeSecrets, service: ServiceId, revision: str
    ) -> None:
        self.database = database
        self.assets = assets
        self.service = service
        self.revision = revision

    async def validate(self) -> None:
        if not await self.database.ready():
            raise RuntimeFoundationError("Runtime database identity does not match configuration")
        if (
            self.database.engine.url.username != self.service.role
            or self.database.engine.url.database != self.service.database
        ):
            raise RuntimeFoundationError(
                "Runtime requires its own restricted service database role"
            )
        try:
            async with self.database.sessions() as session:
                revisions = list(
                    await session.scalars(text("SELECT version_num FROM alembic_version"))
                )
                if revisions != [self.revision]:
                    raise RuntimeFoundationError(
                        "Runtime schema is not at its required migration head"
                    )
                binding = await session.get(RuntimeBindingRow, 1)
                if binding is None:
                    raise RuntimeFoundationError(
                        "Database initialization must enroll its encryption key"
                    )
                verify_binding(binding, self.assets, self.service)
            if self.service == ServiceId.IDP:
                if not await UserRepository(self.database, SystemClock()).initialized():
                    raise RuntimeFoundationError(
                        "Database initialization must provision seeded users"
                    )
                if not await OperatorRepository(
                    self.database, self.assets.envelope, SystemClock()
                ).initialized():
                    raise RuntimeFoundationError(
                        "Database initialization must provision the operator"
                    )
                if not await TotpRepository(
                    self.database, self.assets.envelope, SystemClock()
                ).initialized():
                    raise RuntimeFoundationError(
                        "Database initialization must provision seeded TOTP factors"
                    )
        except SQLAlchemyError as error:
            raise RuntimeFoundationError(
                "Runtime schema or database dependency is unavailable"
            ) from error

    async def ready(self) -> bool:
        try:
            await self.validate()
        except (RuntimeFoundationError, SQLAlchemyError, OSError, ValueError):
            return False
        return True
