"""Shared federation policy; deployment configuration is kept in runtime.py."""

import hashlib
import time
from typing import Annotated, Final, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy.engine import make_url

SIGNING_ALGORITHM: Final[Literal["RS256"]] = "RS256"
CLIENT_AUTH_METHOD: Final[Literal["private_key_jwt"]] = "private_key_jwt"
OPENID_SCOPE: Final[Literal["openid"]] = "openid"
FIXTURE_ACR = "urn:take-home:acr:phase0-fixture"
FIXTURE_AMR = "urn:take-home:amr:phase0-fixture"


def validate_https_url(value: str) -> str:
    """Validate syntax without normalizing an exact-match protocol identifier."""
    parsed = urlsplit(value)
    if (
        not value.isascii()
        or any(char.isspace() for char in value)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("An absolute HTTPS URL without credentials or fragment is required")
    # Accessing port also rejects malformed or out-of-range ports.
    _ = parsed.port
    return value


type HttpsUrl = Annotated[str, AfterValidator(validate_https_url)]
type Identifier = Annotated[str, Field(min_length=1, max_length=255)]
type TransactionValue = Annotated[str, Field(min_length=16, max_length=256)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid", hide_input_in_errors=True)


class ProtocolPolicy(FrozenModel):
    code_ttl_seconds: int = Field(default=60, ge=1, le=300)
    id_token_ttl_seconds: int = Field(default=300, ge=1, le=900)
    logout_token_ttl_seconds: int = Field(default=300, ge=1, le=900)
    access_token_ttl_seconds: int = Field(default=300, ge=1, le=900)
    assertion_ttl_seconds: int = Field(default=60, ge=1, le=120)
    clock_skew_seconds: int = Field(default=5, ge=0, le=30)
    max_jwt_bytes: int = Field(default=8192, ge=1024, le=16384)
    max_form_bytes: int = Field(default=16384, ge=1024, le=32768)


class IdpSettings(FrozenModel):
    issuer: HttpsUrl
    database_url: SecretStr
    policy: ProtocolPolicy = Field(default_factory=ProtocolPolicy)

    @field_validator("issuer")
    @classmethod
    def root_issuer(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.path not in {"", "/"} or parsed.query:
            raise ValueError("The Phase 0 issuer must be rooted at its HTTPS origin")
        return value.rstrip("/")

    @field_validator("database_url")
    @classmethod
    def async_postgres(cls, value: SecretStr) -> SecretStr:
        if make_url(value.get_secret_value()).drivername != "postgresql+asyncpg":
            raise ValueError("Phase 0 requires the actual PostgreSQL asyncpg driver")
        return value

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.issuer}/introspect"

    @property
    def revocation_endpoint(self) -> str:
        return f"{self.issuer}/revoke"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/jwks.json"


class Clock(Protocol):
    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


def verifier_digest(value: str) -> str:
    """A standard one-way verifier for high-entropy opaque values, not passwords."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
