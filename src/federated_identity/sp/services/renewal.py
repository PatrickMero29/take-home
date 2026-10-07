"""Database-claimed single-flight refresh; an ambiguous attempt is never sent twice."""

import asyncio
import secrets
import time
from dataclasses import dataclass

from pydantic import SecretStr

from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.contracts import GrantUnavailable
from federated_identity.common.security.model import Denial, SecurityDenied, SpSessionEvidence
from federated_identity.common.security.oidc import VerifiedRefresh
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.sp.protocol.oidc import OidcClient
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow


@dataclass(frozen=True)
class RefreshAttempt:
    cookie: SecretStr
    attempt_id: str
    generation: int
    local: SpSessionEvidence
    token: SecretStr
    nonce: str | None
    family_id: str


class SpRenewalService:
    def __init__(self, repository: SpSecurityRepository, oidc: OidcClient) -> None:
        self.repository = repository
        self.oidc = oidc
        self.clock = oidc.clock
        self.lease_seconds = int(oidc.settings.request_timeout_seconds) + 5

    async def claim(self, cookie: SecretStr) -> RefreshAttempt | SecretStr | None:
        now = self.clock.now()
        digest = verifier_digest(cookie.get_secret_value())
        blocked = False
        result: RefreshAttempt | SecretStr | None = None
        async with self.repository.database.sessions() as session:
            async with session.begin():
                browser = await session.get(BrowserSessionRow, digest, with_for_update=True)
                row = await session.get(SpAuthenticationRow, digest, with_for_update=True)
                if (
                    browser is None
                    or row is None
                    or row.revoked_at is not None
                    or min(browser.expires_at, row.expires_at, row.idle_expires_at) <= now
                ):
                    raise SecurityDenied(Denial.REVOKED)
                if row.refresh_state == "blocked":
                    blocked = True
                elif row.access_expires_at > now:
                    data = self.repository.cipher.decrypt(
                        row.encrypted_access_token, purpose="sp-access-token"
                    )
                    result = SecretStr(str(data["token"]))
                elif row.encrypted_refresh_token is None:
                    data = self.repository.cipher.decrypt(
                        row.encrypted_access_token, purpose="sp-access-token"
                    )
                    result = SecretStr(str(data["token"]))
                elif row.refresh_state == "pending":
                    if (
                        row.refresh_started_at is None
                        or now >= row.refresh_started_at + self.lease_seconds
                    ):
                        row.refresh_state = "blocked"
                        blocked = True
                else:
                    loaded = await self.repository.load_in(session, cookie)
                    if loaded is None:
                        raise SecurityDenied(Denial.MISSING)
                    value = self.repository.cipher.decrypt(
                        row.encrypted_evidence, purpose="sp-authentication"
                    )
                    family_id = value.get("refresh_family_id")
                    if not isinstance(family_id, str):
                        raise SecurityDenied(Denial.BINDING)
                    token = self.repository.cipher.decrypt(
                        row.encrypted_refresh_token, purpose="sp-refresh-token"
                    )
                    if not isinstance(token.get("token"), str):
                        raise SecurityDenied(Denial.BINDING)
                    row.refresh_state = "pending"
                    row.refresh_attempt_id = secrets.token_urlsafe(24)
                    row.refresh_started_at = now
                    result = RefreshAttempt(
                        cookie=cookie,
                        attempt_id=row.refresh_attempt_id,
                        generation=row.refresh_generation,
                        local=loaded[0],
                        token=SecretStr(str(token["token"])),
                        nonce=str(value["nonce"]) if isinstance(value.get("nonce"), str) else None,
                        family_id=family_id,
                    )
        if blocked:
            raise GrantUnavailable("Renewal outcome is unknown; start a fresh login")
        return result

    async def block(self, attempt: RefreshAttempt) -> None:
        async with self.repository.database.sessions() as session:
            async with session.begin():
                row = await session.get(
                    SpAuthenticationRow,
                    verifier_digest(attempt.cookie.get_secret_value()),
                    with_for_update=True,
                )
                if (
                    row is not None
                    and row.revoked_at is None
                    and row.refresh_attempt_id == attempt.attempt_id
                ):
                    row.refresh_state = "blocked"

    async def finish(self, attempt: RefreshAttempt, refreshed: VerifiedRefresh) -> SecretStr:
        digest = verifier_digest(attempt.cookie.get_secret_value())
        async with self.repository.database.sessions() as session:
            async with session.begin():
                browser = await session.get(BrowserSessionRow, digest, with_for_update=True)
                row = await session.get(SpAuthenticationRow, digest, with_for_update=True)
                if (
                    browser is None
                    or row is None
                    or row.revoked_at is not None
                    or min(browser.expires_at, row.expires_at, row.idle_expires_at)
                    <= self.clock.now()
                ):
                    raise SecurityDenied(Denial.REVOKED)
                if (
                    row.refresh_state != "pending"
                    or row.refresh_attempt_id != attempt.attempt_id
                    or row.refresh_generation != attempt.generation
                    or refreshed.context.grant.grant_id != attempt.local.grant_id
                    or refreshed.context.family.family_id != attempt.family_id
                    or refreshed.context.family.generation != attempt.generation + 1
                    or refreshed.context.authentication != attempt.local.authentication
                    or refreshed.access_expires_at <= self.clock.now()
                ):
                    raise SecurityDenied(Denial.BINDING)
                row.encrypted_access_token = self.repository.cipher.encrypt(
                    {"token": refreshed.response.access_token}, purpose="sp-access-token"
                )
                row.encrypted_refresh_token = self.repository.cipher.encrypt(
                    {"token": refreshed.response.refresh_token}, purpose="sp-refresh-token"
                )
                row.access_expires_at = refreshed.access_expires_at
                row.refresh_generation += 1
                row.refresh_state = "ready"
                row.refresh_attempt_id = None
                row.refresh_started_at = None
        return SecretStr(refreshed.response.access_token)

    async def ensure_access(self, cookie: SecretStr) -> SecretStr:
        deadline = time.monotonic() + self.lease_seconds + 1
        while True:
            claim = await self.claim(cookie)
            if isinstance(claim, SecretStr):
                return claim
            if claim is None:
                if time.monotonic() >= deadline:
                    raise GrantUnavailable("Another renewal is pending; retry after it completes")
                await asyncio.sleep(0.02)
                continue
            try:
                refreshed = await self.oidc.refresh_verified(
                    claim.token, authentication=claim.local.authentication, nonce=claim.nonce
                )
                return await self.finish(claim, refreshed)
            except BaseException as error:
                await asyncio.shield(self.block(claim))
                if isinstance(error, (asyncio.CancelledError, SecurityDenied)):
                    raise
                if not isinstance(error, Exception):
                    raise
                raise GrantUnavailable("Renewal failed; start a fresh login") from error
