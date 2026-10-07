"""Stable seeded identities and private provisioning material."""

from typing import Annotated

from pydantic import Field, SecretStr, model_validator

from federated_identity.common.security.passwords import approved_hash
from federated_identity.common.settings.policy import FrozenModel, Identifier

type Username = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]


class UserCredential(FrozenModel):
    subject: Identifier
    username: Username
    password_hash: SecretStr
    enabled: bool = True

    @model_validator(mode="after")
    def hash_profile(self) -> "UserCredential":
        if not approved_hash(self.password_hash):
            raise ValueError("User credentials require an approved Argon2id password hash")
        return self


class SeededUser(UserCredential):
    password: SecretStr


class SeededUsers(FrozenModel):
    users: tuple[SeededUser, ...] = Field(min_length=2, max_length=8)

    @model_validator(mode="after")
    def distinct_identities(self) -> "SeededUsers":
        if len({user.subject for user in self.users}) != len(self.users) or len(
            {user.username for user in self.users}
        ) != len(self.users):
            raise ValueError("Seeded users require unique stable subjects and usernames")
        return self
