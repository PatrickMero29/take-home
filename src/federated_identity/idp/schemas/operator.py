"""Operator facts and credentials are deliberately separate from users and SPs."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import Field, SecretStr, model_validator

from federated_identity.common.security.passwords import approved_hash
from federated_identity.common.settings.policy import FrozenModel, Identifier
from federated_identity.idp.schemas.users import Username


class OperatorPermission(StrEnum):
    CLIENTS_READ = "clients:read"
    CLIENTS_WRITE = "clients:write"
    KEYS_READ = "keys:read"
    KEYS_WRITE = "keys:write"


class OperatorChannel(StrEnum):
    BROWSER = "browser"
    API = "api"


class OperatorCredential(FrozenModel):
    operator_id: Identifier
    username: Username
    password_hash: SecretStr
    enabled: bool = True
    permissions: tuple[OperatorPermission, ...] = (
        OperatorPermission.CLIENTS_READ,
        OperatorPermission.CLIENTS_WRITE,
        OperatorPermission.KEYS_READ,
        OperatorPermission.KEYS_WRITE,
    )
    credential_version: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def valid_credential(self) -> "OperatorCredential":
        if not approved_hash(self.password_hash) or len(set(self.permissions)) != len(
            self.permissions
        ):
            raise ValueError("Operator credentials require vetted hashes and unique permissions")
        return self


class SeededOperator(OperatorCredential):
    password: SecretStr


class OperatorLogin(FrozenModel):
    username: Username
    password: SecretStr = Field(min_length=1, max_length=1024)


class OperatorPrincipal(FrozenModel):
    operator_id: Identifier
    username: Username
    permissions: tuple[OperatorPermission, ...]
    credential_version: int
    expires_at: int


@dataclass(frozen=True)
class OperatorAuthorization:
    token: SecretStr
    channel: OperatorChannel
    challenge: SecretStr | None = None


class OperatorLoginResponse(FrozenModel):
    token_type: Annotated[str, Field(pattern="^Bearer$")] = "Bearer"
    access_token: SecretStr
    expires_in: int
