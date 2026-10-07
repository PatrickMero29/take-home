"""SP-owned authenticated session evidence, separate from anonymous storage and IDP authority."""

import json
import secrets

from pydantic import JsonValue, SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from federated_identity.common.persistence.actions import BrowserActionRow
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.logout import VerifiedLogout
from federated_identity.common.security.model import Denial, SecurityDenied, SpSessionEvidence
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, verifier_digest
from federated_identity.sp.repositories.logout import (
    LogoutReceiptRow,
    LogoutSessionRow,
    lock_federation_session,
)
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.repositories.transactions import AuthorizationTransactionRow


class SpSecurityRepository:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher) -> None:
        self.database = database
        self.cipher = cipher

    async def establish(
        self,
        evidence: SpSessionEvidence,
        access_token: SecretStr,
        refresh_token: SecretStr | None,
        *,
        previous_cookie: SecretStr | None = None,
        access_expires_at: int = 0,
        nonce: str | None = None,
        refresh_family_id: str | None = None,
        id_token: str | None = None,
    ) -> SecretStr:
        token = SecretStr(secrets.token_urlsafe(32))
        digest = verifier_digest(token.get_secret_value())
        async with self.database.sessions() as session:
            async with session.begin():
                await lock_federation_session(session, evidence.issuer, evidence.session_id)
                if await session.get(LogoutSessionRow, (evidence.issuer, evidence.session_id)):
                    raise SecurityDenied(Denial.REVOKED)
                if previous_cookie is not None:
                    browser = await session.get(
                        BrowserSessionRow,
                        verifier_digest(previous_cookie.get_secret_value()),
                        with_for_update=True,
                    )
                    if browser is None or browser.expires_at <= evidence.created_at:
                        raise SecurityDenied(Denial.EXPIRED)
                    previous_auth = await session.get(
                        SpAuthenticationRow, browser.token_digest, with_for_update=True
                    )
                    if previous_auth is not None:
                        if (
                            previous_auth.revoked_at is not None
                            or min(previous_auth.expires_at, previous_auth.idle_expires_at)
                            <= evidence.created_at
                        ):
                            raise SecurityDenied(Denial.REVOKED)
                        previous_payload = self.cipher.decrypt(
                            previous_auth.encrypted_evidence, purpose="sp-authentication"
                        )
                        previous_evidence = SpSessionEvidence.model_validate_json(
                            json.dumps(previous_payload["evidence"])
                        )
                        if (
                            previous_evidence.authentication.subject
                            != evidence.authentication.subject
                        ):
                            raise SecurityDenied(Denial.BINDING)
                session.add(
                    BrowserSessionRow(
                        token_digest=digest,
                        encrypted_payload=self.cipher.encrypt(
                            {"kind": "authenticated"}, purpose="browser-session"
                        ),
                        created_at=evidence.created_at,
                        expires_at=evidence.expires_at,
                    )
                )
                await session.flush()
                payload: dict[str, JsonValue] = {
                    "evidence": evidence.model_dump(mode="json"),
                    "nonce": nonce,
                    "refresh_family_id": refresh_family_id,
                    "id_token": id_token,
                }
                session.add(
                    SpAuthenticationRow(
                        token_digest=digest,
                        encrypted_evidence=self.cipher.encrypt(
                            payload, purpose="sp-authentication"
                        ),
                        encrypted_access_token=self.cipher.encrypt(
                            {"token": access_token.get_secret_value()}, purpose="sp-access-token"
                        ),
                        encrypted_refresh_token=(
                            self.cipher.encrypt(
                                {"token": refresh_token.get_secret_value()},
                                purpose="sp-refresh-token",
                            )
                            if refresh_token is not None
                            else None
                        ),
                        grant_id=evidence.grant_id,
                        session_id=evidence.session_id,
                        client_id=evidence.client_id,
                        created_at=evidence.created_at,
                        expires_at=evidence.expires_at,
                        last_seen_at=evidence.last_seen_at,
                        idle_expires_at=evidence.idle_expires_at,
                        revoked_at=None,
                        access_expires_at=access_expires_at,
                        refresh_generation=0,
                        refresh_state="ready",
                    )
                )
                if previous_cookie is not None:
                    previous = await session.get(
                        SpAuthenticationRow,
                        verifier_digest(previous_cookie.get_secret_value()),
                        with_for_update=True,
                    )
                    if previous is not None and previous.revoked_at is None:
                        await self.revoke_in(session, previous_cookie, now=evidence.created_at)
                    elif previous is None:
                        anonymous = await session.get(
                            BrowserSessionRow,
                            verifier_digest(previous_cookie.get_secret_value()),
                            with_for_update=True,
                        )
                        if anonymous is not None:
                            await session.delete(anonymous)
                        await self.invalidate_pending_in(session, previous_cookie)
        return token

    async def load(self, token: SecretStr) -> tuple[SpSessionEvidence, SecretStr] | None:
        async with self.database.sessions() as session:
            return await self.load_in(session, token)

    async def load_in(
        self, session: AsyncSession, token: SecretStr
    ) -> tuple[SpSessionEvidence, SecretStr] | None:
        if not 32 <= len(token.get_secret_value()) <= 128:
            return None
        row = await session.get(SpAuthenticationRow, verifier_digest(token.get_secret_value()))
        if row is None:
            return None
        value = self.cipher.decrypt(row.encrypted_evidence, purpose="sp-authentication")
        evidence = SpSessionEvidence.model_validate_json(json.dumps(value["evidence"]))
        if (
            evidence.grant_id != row.grant_id
            or evidence.session_id != row.session_id
            or evidence.client_id != row.client_id
            or evidence.created_at != row.created_at
            or evidence.expires_at != row.expires_at
        ):
            raise ValueError("Stored session indexes must match authenticated evidence")
        evidence = SpSessionEvidence.model_validate_json(
            json.dumps(
                {
                    **evidence.model_dump(mode="json"),
                    "last_seen_at": row.last_seen_at,
                    "idle_expires_at": row.idle_expires_at,
                    "revoked_at": row.revoked_at,
                }
            )
        )
        access = self.cipher.decrypt(row.encrypted_access_token, purpose="sp-access-token")
        if not isinstance(access.get("token"), str):
            raise ValueError("Stored access credential must be a string")
        return evidence, SecretStr(str(access["token"]))

    async def touch(self, token: SecretStr, *, now: int, idle_seconds: int) -> bool:
        async with self.database.sessions() as session:
            async with session.begin():
                row = await session.get(
                    SpAuthenticationRow,
                    verifier_digest(token.get_secret_value()),
                    with_for_update=True,
                )
                if (
                    row is None
                    or row.revoked_at is not None
                    or min(row.expires_at, row.idle_expires_at) <= now
                ):
                    return False
                row.last_seen_at = max(row.last_seen_at, now)
                row.idle_expires_at = min(row.expires_at, row.last_seen_at + idle_seconds)
        return True

    async def revoke(self, token: SecretStr, *, now: int) -> None:
        async with self.database.sessions() as session:
            async with session.begin():
                await self.revoke_in(session, token, now=now)

    async def revoke_in(self, session: AsyncSession, token: SecretStr, *, now: int) -> None:
        digest = verifier_digest(token.get_secret_value())
        await self.revoke_digest_in(session, digest, now=now)

    async def revoke_digest_in(self, session: AsyncSession, digest: str, *, now: int) -> None:
        # Establishment and logout take the browser lock first, preventing a
        # completed network exchange from reviving its logged-out initiator.
        browser = await session.get(BrowserSessionRow, digest, with_for_update=True)
        row = await session.get(SpAuthenticationRow, digest, with_for_update=True)
        if row is not None and row.revoked_at is None:
            row.revoked_at = now
        if browser is not None:
            browser.expires_at = min(browser.expires_at, now)
        await self.invalidate_digest_in(session, digest)

    async def invalidate_pending_in(self, session: AsyncSession, token: SecretStr) -> None:
        digest = verifier_digest(token.get_secret_value())
        await self.invalidate_digest_in(session, digest)

    async def invalidate_digest_in(self, session: AsyncSession, digest: str) -> None:
        await session.execute(
            delete(AuthorizationTransactionRow).where(
                AuthorizationTransactionRow.browser_digest == digest
            )
        )
        await session.execute(
            delete(BrowserActionRow).where(BrowserActionRow.browser_digest == digest)
        )

    async def accept_logout(
        self, logout: VerifiedLogout, *, client_id: str, clock: Clock, skew: int
    ) -> None:
        claims = logout.claims
        if claims.aud != client_id:
            raise SecurityDenied(Denial.RECIPIENT)
        async with self.database.sessions() as session:
            async with session.begin():
                # A unique replay key also arbitrates different sid values using
                # the same jti. Lock its namespace before attempting reservation.
                await lock_federation_session(
                    session, claims.iss, claims.jti, namespace="logout-receipt"
                )
                await lock_federation_session(session, claims.iss, claims.sid)
                now = clock.now()
                if now >= claims.exp + skew:
                    raise SecurityDenied(Denial.EXPIRED)
                receipt = await session.get(LogoutReceiptRow, (claims.iss, claims.jti))
                if receipt is not None:
                    if receipt.token_digest != logout.token_digest:
                        raise SecurityDenied(Denial.REPLAY)
                    return  # Exact retry acknowledges the already committed effect.
                digests = list(
                    await session.scalars(
                        select(SpAuthenticationRow.token_digest)
                        .where(
                            SpAuthenticationRow.session_id == claims.sid,
                            SpAuthenticationRow.client_id == client_id,
                        )
                        .order_by(SpAuthenticationRow.token_digest)
                    )
                )
                for digest in digests:
                    await session.get(BrowserSessionRow, digest, with_for_update=True)
                    row = await session.get(SpAuthenticationRow, digest, with_for_update=True)
                    if row is None:
                        continue
                    payload = self.cipher.decrypt(
                        row.encrypted_evidence, purpose="sp-authentication"
                    )
                    evidence = SpSessionEvidence.model_validate_json(
                        json.dumps(payload["evidence"])
                    )
                    if evidence.issuer != claims.iss:
                        continue
                    if claims.sub is not None and claims.sub != evidence.subject:
                        raise SecurityDenied(Denial.BINDING)
                    await self.revoke_digest_in(session, digest, now=now)
                if clock.now() >= claims.exp + skew:
                    raise SecurityDenied(Denial.EXPIRED)
                if await session.get(LogoutSessionRow, (claims.iss, claims.sid)) is None:
                    session.add(
                        LogoutSessionRow(issuer=claims.iss, session_id=claims.sid, received_at=now)
                    )
                session.add(
                    LogoutReceiptRow(
                        issuer=claims.iss,
                        token_id=claims.jti,
                        token_digest=logout.token_digest,
                        session_id=claims.sid,
                        issued_at=claims.iat,
                        expires_at=claims.exp,
                        received_at=now,
                    )
                )
