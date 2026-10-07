"""RP authorization requires matching local evidence and fresh authoritative grant state."""

from pydantic import SecretStr

from federated_identity.common.security.contracts import GrantChecker, GrantStatus, SessionRenewer
from federated_identity.common.security.model import (
    AuthenticationRequirement,
    Denial,
    GrantSnapshot,
    IssuedCredentials,
    LifecyclePolicy,
    LoginEvidence,
    SecurityDenied,
    SpSessionEvidence,
)
from federated_identity.common.security.oidc import VerifiedLogin
from federated_identity.common.security.policies import (
    require_active_grant,
    require_assurance,
    require_sp_binding,
)
from federated_identity.common.settings.policy import Clock
from federated_identity.sp.repositories.security import SpSecurityRepository


class SpSecurityModel:
    def __init__(
        self,
        repository: SpSecurityRepository,
        checker: GrantChecker,
        *,
        issuer: str,
        client_id: str,
        clock: Clock,
        lifecycle: LifecyclePolicy,
        renewer: SessionRenewer | None = None,
    ) -> None:
        self.repository = repository
        self.checker = checker
        self.issuer = issuer
        self.client_id = client_id
        self.clock = clock
        self.lifecycle = lifecycle
        self.renewer = renewer

    async def establish(
        self,
        verified: LoginEvidence,
        credentials: IssuedCredentials,
        *,
        previous_cookie: SecretStr | None = None,
    ) -> SecretStr:
        if verified != credentials.context.evidence:
            raise SecurityDenied(Denial.BINDING)
        return await self._establish(
            verified,
            credentials.access_token,
            credentials.context,
            credentials.refresh_token,
            previous_cookie=previous_cookie,
            nonce=None,
            id_token=None,
        )

    async def establish_login(
        self, login: VerifiedLogin, *, previous_cookie: SecretStr | None = None
    ) -> SecretStr:
        if login.evidence != login.context.evidence:
            raise SecurityDenied(Denial.BINDING)
        return await self._establish(
            login.evidence,
            SecretStr(login.response.access_token),
            login.context,
            SecretStr(login.response.refresh_token) if login.response.refresh_token else None,
            previous_cookie=previous_cookie,
            nonce=login.claims.nonce,
            id_token=login.response.id_token,
        )

    async def _establish(
        self,
        verified: LoginEvidence,
        access_token: SecretStr,
        issuance: GrantSnapshot,
        refresh_token: SecretStr | None,
        *,
        previous_cookie: SecretStr | None,
        nonce: str | None,
        id_token: str | None,
    ) -> SecretStr:
        # A valid signature (including a forged JWT using a compromised key) is
        # insufficient: the IDP must also have committed this exact issuance.
        status = await self.checker.check(access_token)
        context = self._active_context(status, subject=verified.authentication.subject.subject)
        now = self.clock.now()
        if (
            verified != context.evidence
            or issuance.grant.grant_id != context.grant.grant_id
            or issuance.family.family_id != context.family.family_id
        ):
            raise SecurityDenied(Denial.BINDING)
        if verified.expires_at <= now:
            raise SecurityDenied(Denial.EXPIRED)
        expires = min(
            now + self.lifecycle.sp_session_seconds,
            context.grant.expires_at,
            context.session_expires_at,
            context.family.expires_at,
        )
        local = SpSessionEvidence(
            issuer=self.issuer,
            client_id=self.client_id,
            subject=verified.authentication.subject.subject,
            session_id=verified.authentication.session_id,
            grant_id=context.grant.grant_id,
            event_id=verified.authentication.event_id,
            evidence_id=verified.token_id,
            token_digest=verified.token_digest,
            signing_key_id=verified.signing_key_id,
            authentication=verified.authentication,
            created_at=now,
            expires_at=expires,
            last_seen_at=now,
            idle_expires_at=min(expires, now + self.lifecycle.sp_idle_seconds),
            revoked_at=None,
        )
        require_sp_binding(
            local, context, expected_issuer=self.issuer, expected_client=self.client_id, now=now
        )
        if previous_cookie is not None:
            previous = await self.repository.load(previous_cookie)
            if (
                previous is not None
                and previous[0].authentication.subject != local.authentication.subject
            ):
                raise SecurityDenied(Denial.BINDING)
        return await self.repository.establish(
            local,
            access_token,
            refresh_token,
            previous_cookie=previous_cookie,
            access_expires_at=status.expires_at or 0,
            nonce=nonce,
            refresh_family_id=context.family.family_id,
            id_token=id_token,
        )

    async def authorize(
        self, cookie: SecretStr, requirement: AuthenticationRequirement
    ) -> SpSessionEvidence:
        loaded = await self.repository.load(cookie)
        if loaded is None:
            raise SecurityDenied(Denial.MISSING)
        local, access = loaded
        now = self.clock.now()
        if local.revoked_at is not None:
            raise SecurityDenied(Denial.REVOKED)
        if min(local.expires_at, local.idle_expires_at) <= now:
            raise SecurityDenied(Denial.EXPIRED)
        # No local transaction/row lock is held across the network call. A
        # transient dependency failure blocks access without deleting local state.
        if self.renewer is not None:
            access = await self.renewer.ensure_access(cookie)
        status = await self.checker.check(access)
        context = self._active_context(status, subject=local.subject)
        require_sp_binding(
            local,
            context,
            expected_issuer=self.issuer,
            expected_client=self.client_id,
            now=self.clock.now(),
        )
        require_assurance(local.authentication, requirement, now=self.clock.now())
        if not await self.repository.touch(
            cookie, now=self.clock.now(), idle_seconds=self.lifecycle.sp_idle_seconds
        ):
            raise SecurityDenied(Denial.REVOKED)
        return local

    def _active_context(self, status: GrantStatus, *, subject: str) -> GrantSnapshot:
        return require_active_grant(
            status,
            issuer=self.issuer,
            client_id=self.client_id,
            subject=subject,
            now=self.clock.now(),
        )

    async def logout_local(self, cookie: SecretStr) -> None:
        await self.repository.revoke(cookie, now=self.clock.now())
