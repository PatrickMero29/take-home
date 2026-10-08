"""Signed, durable, bounded delivery; authoritative revocation always precedes network work."""

import asyncio
import logging
import ssl
import uuid
from dataclasses import dataclass
from http import HTTPStatus

import httpx2 as httpx
from pydantic import SecretStr

from federated_identity.common.security.contracts import LogoutDelivery, LogoutTransport
from federated_identity.common.security.logout import LOGOUT_EVENT, LogoutClaims, sign_logout_token
from federated_identity.common.security.model import KeyState
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.idp.repositories.outbox import LogoutOutboxRow, PostgresLogoutOutbox
from federated_identity.idp.repositories.security_tables import IdpSessionRow, SigningTrustRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.signing import SignedArtifactPurpose
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.idp.services.signing import SigningKeyService


class HttpsLogoutTransport:
    def __init__(
        self,
        tls: ssl.SSLContext,
        *,
        timeout: float = 2,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.tls = tls
        self.timeout = timeout
        self.transport = transport

    async def deliver(self, delivery: LogoutDelivery) -> bool:
        async with httpx.AsyncClient(
            verify=self.tls,
            timeout=self.timeout,
            trust_env=False,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            async with client.stream(
                "POST",
                delivery.destination,
                data={"logout_token": delivery.token.get_secret_value()},
            ) as response:
                response.raise_for_status()
                return response.status_code in {HTTPStatus.OK, HTTPStatus.NO_CONTENT}


@dataclass(frozen=True)
class LeasedLogout:
    delivery_id: str
    lease_id: str
    delivery: LogoutDelivery


class LogoutDispatcher:
    def __init__(
        self,
        settings: RuntimeSettings,
        outbox: PostgresLogoutOutbox,
        security: IdpSecurityModel,
        keys: SigningKeyService,
        transport: LogoutTransport,
    ) -> None:
        self.settings = settings
        self.outbox = outbox
        self.security = security
        self.keys = keys
        self.transport = transport
        self.wakeup = asyncio.Event()

    async def claim(self, delivery_id: str) -> LeasedLogout | None:
        async with self.security.repository.transaction() as work:
            row = await work.session.get(LogoutOutboxRow, delivery_id, with_for_update=True)
            now = self.security.clock.now()
            if (
                row is None
                or row.status != "pending"
                or row.next_attempt_at > now
                or (row.lease_expires_at is not None and row.lease_expires_at > now)
            ):
                return None
            if row.attempts >= self.settings.logout_max_attempts:
                row.status, row.last_error = "failed", "attempts_exhausted"
                row.lease_id = row.lease_expires_at = None
                return None
            parent = await work.get(IdpSessionRow, row.session_id) if row.session_id else None
            client = await work.get(ClientRow, row.client_id) if row.client_id else None
            if (
                parent is None
                or client is None
                or parent.revoked_at is None
                or row.issuer != self.security.issuer
                or parent.issuer != row.issuer
            ):
                row.status, row.last_error = "failed", "unbound_intent"
                row.lease_id = row.lease_expires_at = None
                return None
            if row.destination is None:
                row.status, row.last_error = "skipped", "no_destination"
                row.lease_id = row.lease_expires_at = None
                return None
            if row.destination != client.backchannel_logout_uri:
                row.status, row.last_error = "failed", "destination_changed"
                row.lease_id = row.lease_expires_at = None
                return None
            payload = self.outbox.cipher.decrypt(row.encrypted_payload, purpose="logout-delivery")
            if (
                payload.get("issuer") != row.issuer
                or payload.get("sid") != row.session_id
                or payload.get("client_id") != row.client_id
            ):
                row.status, row.last_error = "failed", "invalid_payload"
                row.lease_id = row.lease_expires_at = None
                return None
            key = (
                await work.get(SigningTrustRow, row.signing_key_id) if row.signing_key_id else None
            )
            token = payload.get("token")
            if (
                not isinstance(token, str)
                or row.token_expires_at is None
                or row.token_expires_at <= now
                or key is None
                or key.state not in {KeyState.ACTIVE.value, KeyState.DRAINING.value}
            ):
                signer = await self.keys.active_in(work)
                claims = LogoutClaims(
                    iss=parent.issuer,
                    aud=client.client_id,
                    sid=parent.session_id,
                    sub=parent.subject,
                    iat=now,
                    exp=now + self.security.protocol.logout_token_ttl_seconds,
                    jti=str(uuid.uuid4()),
                    events={LOGOUT_EVENT: {}},
                )
                # Crypto runs off-thread, but the selected signer, retention and
                # sealed delivery remain inside the same short gated transaction.
                token = await asyncio.to_thread(sign_logout_token, claims, signer)
                await self.security.record_signed_artifact_in(
                    work,
                    artifact_id=claims.jti,
                    key_id=signer.kid,
                    purpose=SignedArtifactPurpose.LOGOUT_TOKEN,
                    client_id=client.client_id,
                    issued_at=claims.iat,
                    expires_at=claims.exp,
                )
                row.token_id, row.token_expires_at, row.signing_key_id = (
                    claims.jti,
                    claims.exp,
                    signer.kid,
                )
                row.encrypted_payload = self.outbox.cipher.encrypt(
                    {**payload, "token": token}, purpose="logout-delivery"
                )
            row.lease_id = str(uuid.uuid4())
            row.lease_expires_at = now + int(self.settings.logout_delivery_timeout_seconds) + 5
            row.attempts += 1
            result = LeasedLogout(
                row.delivery_id,
                row.lease_id,
                LogoutDelivery(destination=row.destination, token=SecretStr(token)),
            )
        return result  # Committed lease/token/retention before any transmission.

    async def finish(
        self, claim: LeasedLogout, *, delivered: bool, retryable: bool, error: str | None
    ) -> None:
        async with self.security.repository.transaction() as work:
            row = await work.session.get(LogoutOutboxRow, claim.delivery_id, with_for_update=True)
            if row is None or row.status != "pending" or row.lease_id != claim.lease_id:
                # A recovered worker owns the newer lease; stale results cannot overwrite it.
                return
            now = self.security.clock.now()
            row.lease_id = row.lease_expires_at = None
            row.last_error = error
            if delivered:
                row.status, row.completed_at = "delivered", now
            elif not retryable or row.attempts >= self.settings.logout_max_attempts:
                row.status = "failed"
            else:
                delay = min(
                    self.settings.logout_retry_max_seconds,
                    self.settings.logout_retry_base_seconds * 2 ** min(row.attempts - 1, 12),
                )
                row.next_attempt_at = now + delay

    async def deliver_one(self, delivery_id: str) -> bool:
        claim = await self.claim(delivery_id)
        if claim is None:
            return False
        delivered, retryable, error = False, False, None
        try:
            async with asyncio.timeout(self.settings.logout_delivery_timeout_seconds):
                delivered = await self.transport.deliver(claim.delivery)
            if not delivered:
                error = "invalid_response"
        except httpx.HTTPStatusError as failure:
            status = failure.response.status_code
            retryable = (
                status
                in {HTTPStatus.REQUEST_TIMEOUT, HTTPStatus.TOO_EARLY, HTTPStatus.TOO_MANY_REQUESTS}
                or status >= HTTPStatus.INTERNAL_SERVER_ERROR
            )
            error = "recipient_unavailable" if retryable else "recipient_rejected"
        except (httpx.HTTPError, TimeoutError):
            retryable, error = True, "network_failure"
        # Cancellation/crash leaves a durable lease. Recovery resends the same
        # valid JWT, or a fresh jti for the same sid if expiry/containment requires it.
        await self.finish(claim, delivered=delivered, retryable=retryable, error=error)
        return True

    async def dispatch_once(self, *, session_id: str | None = None) -> int:
        identifiers = await self.outbox.due(
            limit=self.settings.logout_batch_size, session_id=session_id
        )
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(self.deliver_one(value)) for value in identifiers]
        return sum(task.result() for task in tasks)

    async def run(self) -> None:
        while True:
            self.wakeup.clear()
            try:
                await self.dispatch_once()
            except Exception:
                logging.getLogger(__name__).exception(
                    "logout_dispatch_failed", extra={"service": "idp"}
                )
            try:
                await asyncio.wait_for(
                    self.wakeup.wait(), timeout=self.settings.logout_poll_seconds
                )
            except TimeoutError:
                pass
