"""Configuration used by independently deployed IDP and SP processes."""

from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from federated_identity.common.security.model import LifecyclePolicy
from federated_identity.common.settings.policy import ProtocolPolicy, validate_https_url


class ServiceId(StrEnum):
    IDP = "idp"
    SP_A = "sp-a"
    SP_B = "sp-b"
    SP_C = "sp-c"

    @property
    def role(self) -> str:
        return f"fid_{self.value.replace('-', '_')}"

    @property
    def database(self) -> str:
        return self.role

    @property
    def hostname(self) -> str:
        return f"{self.value}.localhost"

    @property
    def default_port(self) -> int:
        return {self.IDP: 8443, self.SP_A: 8444, self.SP_B: 8445, self.SP_C: 8446}[self]


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FID_", frozen=True, extra="ignore", hide_input_in_errors=True
    )

    service_id: ServiceId
    public_url: str
    issuer: str = "https://idp.localhost:8443"
    secrets_directory: Path = Path("/run/federation")
    database_host: str = "postgres"
    database_port: int = Field(default=5432, ge=1, le=65535)
    listen_host: str = "0.0.0.0"
    listen_port: int = Field(default=8443, ge=1, le=65535)
    session_ttl_seconds: int = Field(default=1800, ge=60, le=86400)
    login_transaction_ttl_seconds: int = Field(default=300, ge=30, le=600)
    browser_action_ttl_seconds: int = Field(default=300, ge=30, le=600)
    operator_session_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    jwks_cache_ttl_seconds: int = Field(default=300, ge=1, le=900)
    jwks_refresh_cooldown_seconds: int = Field(default=10, ge=1, le=60)
    request_timeout_seconds: float = Field(default=5, gt=0, le=30)
    max_inflight_requests: int = Field(default=64, ge=1, le=1024)
    keep_alive_seconds: int = Field(default=5, ge=1, le=30)
    graceful_shutdown_seconds: int = Field(default=10, ge=1, le=60)
    logout_poll_seconds: float = Field(default=1, ge=0.1, le=60)
    logout_delivery_timeout_seconds: float = Field(default=2, gt=0, le=10)
    logout_batch_size: int = Field(default=4, ge=1, le=16)
    logout_max_attempts: int = Field(default=8, ge=1, le=20)
    logout_retry_base_seconds: int = Field(default=2, ge=1, le=60)
    logout_retry_max_seconds: int = Field(default=60, ge=1, le=3600)
    authentication_window_seconds: int = Field(default=60, ge=30, le=3600)
    authentication_account_attempts: int = Field(default=5, ge=1, le=20)
    authentication_browser_attempts: int = Field(default=10, ge=1, le=30)
    authentication_source_attempts: int = Field(default=30, ge=5, le=120)
    mfa_form_max_attempts: int = Field(default=5, ge=1, le=20)
    sensitive_max_age_seconds: int = Field(default=120, ge=30, le=600)
    authentication_methods: tuple[Literal["private_key_jwt"], ...] = ("private_key_jwt",)
    session_backend: Literal["postgresql"] = "postgresql"
    revocation_backend: Literal["authenticated_introspection"] = "authenticated_introspection"
    logout_backend: Literal["oidc_backchannel_outbox"] = "oidc_backchannel_outbox"
    step_up_backend: Literal["password_totp"] = "password_totp"
    policy: ProtocolPolicy = Field(default_factory=ProtocolPolicy)
    lifecycle: LifecyclePolicy = Field(default_factory=LifecyclePolicy)

    @field_validator("public_url", "issuer")
    @classmethod
    def https_origin(cls, value: str) -> str:
        validate_https_url(value)
        parsed = urlsplit(value)
        if parsed.path not in {"", "/"} or parsed.query:
            raise ValueError("A configured public origin must not have a path or query")
        return value.rstrip("/")

    @model_validator(mode="after")
    def service_origin(self) -> "RuntimeSettings":
        public = urlsplit(self.public_url)
        if public.hostname != self.service_id.hostname:
            raise ValueError("Each service requires its distinct configured hostname")
        if (public.port or 443) != self.listen_port:
            raise ValueError("Published and listening ports must agree for local federation")
        if self.service_id == ServiceId.IDP and self.public_url != self.issuer:
            raise ValueError("The IDP public origin must equal the federation issuer")
        return self

    @property
    def cookie_name(self) -> str:
        return f"__Host-fid-{self.service_id.value}"

    @property
    def operator_cookie_name(self) -> str:
        return "__Host-fid-operator"

    @property
    def client_id(self) -> str:
        return self.service_id.value

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_url}/auth/callback"

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.issuer}/introspect"

    @property
    def revocation_endpoint(self) -> str:
        return f"{self.issuer}/revoke"
