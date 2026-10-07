"""Small, typed wrappers around vetted JOSE key generation and serialization."""

import secrets
from dataclasses import dataclass, field
from typing import Literal

from joserfc.jwk import KeySet, KeySetSerialization, RSAKey
from pydantic import Field, field_validator

from federated_identity.common.settings.policy import SIGNING_ALGORITHM, FrozenModel, Identifier


class PublicRsaJwk(FrozenModel):
    kty: Literal["RSA"]
    use: Literal["sig"]
    alg: Literal["RS256"]
    kid: Identifier
    n: str = Field(min_length=256, max_length=1024)
    e: str = Field(min_length=1, max_length=16)


class PublicJwks(FrozenModel):
    keys: list[PublicRsaJwk] = Field(min_length=1, max_length=16)

    @field_validator("keys")
    @classmethod
    def unique_key_ids(cls, keys: list[PublicRsaJwk]) -> list[PublicRsaJwk]:
        if len({key.kid for key in keys}) != len(keys):
            raise ValueError("Key identifiers must be unique within an issuer")
        return keys

    def key_set(self) -> KeySet:
        serialized: KeySetSerialization = {
            "keys": [
                {
                    "kty": key.kty,
                    "use": key.use,
                    "alg": key.alg,
                    "kid": key.kid,
                    "n": key.n,
                    "e": key.e,
                }
                for key in self.keys
            ]
        }
        return KeySet.import_key_set(serialized)


@dataclass(frozen=True)
class SigningKey:
    key: RSAKey = field(repr=False)
    kid: str

    @classmethod
    def generate(cls) -> "SigningKey":
        kid = secrets.token_urlsafe(24)
        key = RSAKey.generate_key(
            2048,
            parameters={"kid": kid, "alg": SIGNING_ALGORITHM, "use": "sig"},
        )
        return cls(key=key, kid=kid)

    def public_jwks(self) -> PublicJwks:
        # The schema also rejects private JWK members if serialization changes.
        return PublicJwks(keys=[PublicRsaJwk.model_validate(self.key.as_dict(private=False))])

    def public_pem(self) -> str:
        return self.key.as_pem(private=False).decode("ascii")
