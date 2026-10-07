"""Typed capability boundaries for authoritative checks, logout delivery, and step-up."""

from typing import Protocol

from pydantic import SecretStr

from federated_identity.common.security.model import GrantSnapshot, LoginEvidence
from federated_identity.common.settings.policy import FrozenModel, HttpsUrl, ProtocolPolicy


class GrantStatus(FrozenModel):
    active: bool
    client_id: str | None = None
    subject: str | None = None
    expires_at: int | None = None
    context: GrantSnapshot | None = None
    credential_evidence: LoginEvidence | None = None


class GrantUnavailable(RuntimeError):
    """Dependency failure must never be interpreted as active authorization."""


class GrantChecker(Protocol):
    async def check(self, token: SecretStr) -> GrantStatus: ...


class GrantRevoker(Protocol):
    async def revoke(self, token: SecretStr) -> None: ...


class SessionRenewer(Protocol):
    async def ensure_access(self, cookie: SecretStr) -> SecretStr: ...


class GrantCheckSettings(Protocol):
    @property
    def issuer(self) -> str: ...

    @property
    def client_id(self) -> str: ...

    @property
    def introspection_endpoint(self) -> str: ...

    @property
    def revocation_endpoint(self) -> str: ...

    @property
    def request_timeout_seconds(self) -> float: ...

    @property
    def policy(self) -> ProtocolPolicy: ...


class LogoutDelivery(FrozenModel):
    destination: HttpsUrl
    token: SecretStr


class LogoutTransport(Protocol):
    async def deliver(self, delivery: LogoutDelivery) -> bool: ...


class LogoutTokenStatus(FrozenModel):
    active: bool


class LogoutTokenChecker(Protocol):
    async def check_logout(self, token: SecretStr) -> bool: ...


class StepUpEngine(Protocol):
    def matched_counter(self, secret: SecretStr, code: SecretStr, *, now: int) -> int | None: ...
