"""Private provisioned TOTP material and immutable counter proof."""

import re

from pydantic import Field, SecretStr, model_validator

from federated_identity.common.settings.policy import FrozenModel, Identifier


class SeededTotp(FrozenModel):
    subject: Identifier
    secret: SecretStr

    @model_validator(mode="after")
    def secret_profile(self) -> "SeededTotp":
        if not re.fullmatch(r"[A-Z2-7]{32}", self.secret.get_secret_value()):
            raise ValueError("TOTP requires a generated 160-bit base32 secret")
        return self


class SeededTotps(FrozenModel):
    credentials: tuple[SeededTotp, ...] = Field(min_length=2, max_length=8)

    @model_validator(mode="after")
    def unique_subjects(self) -> "SeededTotps":
        if len({value.subject for value in self.credentials}) != len(self.credentials):
            raise ValueError("Each subject has one seeded TOTP credential")
        return self
