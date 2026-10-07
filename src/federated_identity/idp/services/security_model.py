"""Authoritative, database-serialized security transitions for trusted application callers."""

import asyncio
import secrets
import uuid

from joserfc.jwk import RSAKey
from pydantic import JsonValue, SecretStr
from sqlalchemy import select

from federated_identity.common.security.contracts import GrantStatus
from federated_identity.common.security.keys import PublicJwks, PublicRsaJwk, SigningKey
from federated_identity.common.security.logout import (
    InvalidLogoutToken,
    logout_header,
    validate_logout_token,
)
from federated_identity.common.security.model import (
    AuthenticationEvent,
    Denial,
    IdpSession,
    IssuedCredentials,
    KeyState,
    LifecyclePolicy,
    LoginEvidence,
    RevocationReason,
    SecurityDenied,
    SigningTrust,
    TrustedAuthentication,
    assurance_for,
)
from federated_identity.common.security.oidc import OidcValidationProfile
from federated_identity.common.security.policies import require_key_transition, require_lineage
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, ProtocolPolicy, verifier_digest
from federated_identity.idp.repositories.outbox import LogoutOutboxRow
from federated_identity.idp.repositories.security import (
    Lineage,
    SecurityRepository,
    SecurityUnitOfWork,
    event_snapshot,
    key_snapshot,
    session_snapshot,
)
from federated_identity.idp.repositories.security_tables import (
    AccessCredentialRow,
    AuthenticationEventRow,
    AuthenticationEvidenceRow,
    FederationGrantRow,
    IdpSessionRow,
    RefreshCredentialRow,
    RefreshFamilyRow,
    RefreshIssuanceRow,
    SigningTrustRow,
)
from federated_identity.idp.repositories.signing import SignedArtifactRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.repositories.users import UserRow
from federated_identity.idp.schemas.signing import SignedArtifactPurpose


def identifier() -> str:
    return str(uuid.uuid4())


class IdpSecurityModel:
    def __init__(
        self,
        repository: SecurityRepository,
        *,
        issuer: str,
        clock: Clock,
        lifecycle: LifecyclePolicy,
        protocol: ProtocolPolicy,
        cipher: EnvelopeCipher,
    ) -> None:
        self.repository = repository
        self.issuer = issuer
        self.clock = clock
        self.lifecycle = lifecycle
        self.protocol = protocol
        self.cipher = cipher

    async def register_runtime_signer(self, signer: SigningKey) -> SigningTrust:
        async with self.repository.transaction() as work:
            row = await work.get(SigningTrustRow, signer.kid)
            if row is None:
                active = await work.active_key()
                if active is not None:
                    raise SecurityDenied(Denial.BINDING)
                row = SigningTrustRow(
                    key_id=signer.kid,
                    public_key_pem=signer.public_pem(),
                    state=KeyState.ACTIVE.value,
                    created_at=self.clock.now(),
                    verification_deadline=0,
                )
                work.add(row)
                await work.flush()
            if row.public_key_pem != signer.public_pem() or row.state != KeyState.ACTIVE.value:
                raise SecurityDenied(Denial.KEY_REVOKED)
            result = key_snapshot(row)
        return result

    async def prepare_signer(self, signer: SigningKey) -> SigningTrust:
        async with self.repository.transaction() as work:
            if await work.get(SigningTrustRow, signer.kid) is not None:
                raise SecurityDenied(Denial.BINDING)
            row = SigningTrustRow(
                key_id=signer.kid,
                public_key_pem=signer.public_pem(),
                state=KeyState.PREPARED.value,
                created_at=self.clock.now(),
                verification_deadline=0,
            )
            work.add(row)
            await work.flush()
            result = key_snapshot(row)
        return result

    async def rotate_trust(self, prepared_key_id: str) -> None:
        async with self.repository.transaction() as work:
            await self.rotate_trust_in(work, prepared_key_id)

    async def rotate_trust_in(self, work: SecurityUnitOfWork, prepared_key_id: str) -> None:
        previous = await work.active_key()
        replacement = await work.get(SigningTrustRow, prepared_key_id)
        if previous is None or replacement is None:
            raise SecurityDenied(Denial.MISSING)
        require_key_transition(
            key_snapshot(replacement),
            KeyState.ACTIVE,
            now=self.clock.now(),
            skew=self.protocol.clock_skew_seconds,
        )
        previous.state = KeyState.DRAINING.value
        await work.flush()  # Preserve the unique active-signer invariant during the swap.
        replacement.state = KeyState.ACTIVE.value
        work.gate.revision += 1

    async def retire_trust(self, key_id: str) -> None:
        async with self.repository.transaction() as work:
            await self.retire_trust_in(work, key_id)

    async def retire_trust_in(self, work: SecurityUnitOfWork, key_id: str) -> None:
        row = await work.get(SigningTrustRow, key_id)
        if row is None:
            raise SecurityDenied(Denial.MISSING)
        require_key_transition(
            key_snapshot(row),
            KeyState.RETIRED,
            now=self.clock.now(),
            skew=self.protocol.clock_skew_seconds,
        )
        row.state = KeyState.RETIRED.value
        work.gate.revision += 1

    async def record_signed_artifact_in(
        self,
        work: SecurityUnitOfWork,
        *,
        artifact_id: str,
        key_id: str,
        purpose: SignedArtifactPurpose,
        client_id: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        """Every IDP signing adapter joins this ledger before publishing its artifact."""
        key = await work.get(SigningTrustRow, key_id)
        limit = (
            self.protocol.id_token_ttl_seconds
            if purpose == SignedArtifactPurpose.ID_TOKEN
            else self.protocol.logout_token_ttl_seconds
        )
        if key is None or key.state != KeyState.ACTIVE.value:
            raise SecurityDenied(Denial.KEY_REVOKED)
        if (
            not key.created_at <= issued_at <= self.clock.now() + self.protocol.clock_skew_seconds
            or not 0 < expires_at - issued_at <= limit
        ):
            raise SecurityDenied(Denial.BINDING)
        work.add(
            SignedArtifactRow(
                artifact_id=artifact_id,
                key_id=key_id,
                purpose=purpose.value,
                client_id=client_id,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        key.verification_deadline = max(key.verification_deadline, expires_at)
        await work.flush()

    async def open_session(
        self, authentication: TrustedAuthentication
    ) -> tuple[IdpSession, AuthenticationEvent]:
        async with self.repository.transaction() as work:
            result = await self.open_session_in(work, authentication)
        return result

    async def open_session_in(
        self, work: SecurityUnitOfWork, authentication: TrustedAuthentication
    ) -> tuple[IdpSession, AuthenticationEvent]:
        """Allow the credential layer to commit the browser binding with its event."""
        now = self.clock.now()
        if authentication.subject.issuer != self.issuer or authentication.authenticated_at > now:
            raise SecurityDenied(Denial.BINDING)
        row = IdpSessionRow(
            session_id=identifier(),
            issuer=self.issuer,
            subject=authentication.subject.subject,
            created_at=now,
            expires_at=now + self.lifecycle.idp_session_seconds,
            revoked_at=None,
            revocation_reason=None,
        )
        work.add(row)
        await work.flush()
        event = self._authentication_event(row.session_id, authentication)
        work.add(event)
        await work.flush()
        return session_snapshot(row), event_snapshot(event, row)

    def _authentication_event(
        self, session_id: str, authentication: TrustedAuthentication
    ) -> AuthenticationEventRow:
        return AuthenticationEventRow(
            event_id=identifier(),
            session_id=session_id,
            authenticated_at=authentication.authenticated_at,
            assurance=assurance_for(authentication.methods).value,
            methods=[method.value for method in authentication.methods],
        )

    async def reauthenticate(
        self, session_id: str, authentication: TrustedAuthentication
    ) -> AuthenticationEvent:
        async with self.repository.transaction() as work:
            result = await self.reauthenticate_in(work, session_id, authentication)
        return result

    async def reauthenticate_in(
        self,
        work: SecurityUnitOfWork,
        session_id: str,
        authentication: TrustedAuthentication,
    ) -> AuthenticationEvent:
        row = await work.get(IdpSessionRow, session_id)
        if row is None:
            raise SecurityDenied(Denial.MISSING)
        session = session_snapshot(row)
        if session.revoked_at is not None:
            raise SecurityDenied(Denial.REVOKED)
        if self.clock.now() >= session.expires_at:
            raise SecurityDenied(Denial.EXPIRED)
        if (
            authentication.subject != session.subject
            or authentication.authenticated_at > self.clock.now()
        ):
            raise SecurityDenied(Denial.BINDING)
        event = self._authentication_event(session_id, authentication)
        work.add(event)
        await work.flush()
        return event_snapshot(event, row)

    async def issue_grant(
        self, evidence: LoginEvidence, *, access_token: SecretStr
    ) -> IssuedCredentials:
        async with self.repository.transaction() as work:
            result = await self.issue_grant_in(work, evidence, access_token=access_token)
        return result

    async def issue_grant_in(
        self,
        work: SecurityUnitOfWork,
        evidence: LoginEvidence,
        *,
        access_token: SecretStr,
        refresh_token: SecretStr | None = None,
    ) -> IssuedCredentials:
        """Join the caller's gated transaction; the caller owns commit/publication."""
        # The protocol layer generates the access token before signing its
        # at_hash-bound ID token. Preserve that exact pair in the committed ledger.
        if not 32 <= len(access_token.get_secret_value()) <= 128:
            raise SecurityDenied(Denial.BINDING)
        now = self.clock.now()
        session = await work.get(IdpSessionRow, evidence.authentication.session_id)
        event = await work.get(AuthenticationEventRow, evidence.authentication.event_id)
        client = await work.get(ClientRow, evidence.client_id)
        key = await work.get(SigningTrustRow, evidence.signing_key_id)
        if session is None or event is None or client is None or key is None:
            raise SecurityDenied(Denial.MISSING)
        if event_snapshot(event, session) != evidence.authentication:
            raise SecurityDenied(Denial.BINDING)
        if not client.enabled:
            raise SecurityDenied(Denial.CLIENT_DISABLED)
        if key.state == KeyState.REVOKED.value:
            raise SecurityDenied(Denial.KEY_REVOKED)
        if session.revoked_at is not None:
            raise SecurityDenied(Denial.REVOKED)
        if min(session.expires_at, evidence.expires_at) <= now:
            raise SecurityDenied(Denial.EXPIRED)
        if (
            key.state != KeyState.ACTIVE.value
            or session.issuer != self.issuer
            or not session.created_at
            <= evidence.issued_at
            <= now + self.protocol.clock_skew_seconds
            or evidence.authentication.authenticated_at
            > (evidence.issued_at + self.protocol.clock_skew_seconds)
            or evidence.expires_at - evidence.issued_at > self.protocol.id_token_ttl_seconds
        ):
            raise SecurityDenied(Denial.BINDING)
        expires = min(session.expires_at, now + self.lifecycle.grant_seconds)
        family_expires = min(expires, now + self.lifecycle.refresh_family_seconds)
        grant = FederationGrantRow(
            grant_id=identifier(),
            client_id=client.client_id,
            session_id=session.session_id,
            event_id=event.event_id,
            root_signing_key_id=key.key_id,
            created_at=now,
            expires_at=expires,
            revoked_at=None,
            revocation_reason=None,
        )
        work.add(grant)
        await work.flush()
        family = RefreshFamilyRow(
            family_id=identifier(),
            grant_id=grant.grant_id,
            created_at=now,
            expires_at=family_expires,
            generation=0,
            revoked_at=None,
        )
        record = AuthenticationEvidenceRow(
            token_id=evidence.token_id,
            grant_id=grant.grant_id,
            token_digest=evidence.token_digest,
            signing_key_id=key.key_id,
            issued_at=evidence.issued_at,
            expires_at=evidence.expires_at,
        )
        work.add(family)
        work.add(record)
        await self.record_signed_artifact_in(
            work,
            artifact_id=evidence.token_id,
            key_id=key.key_id,
            purpose=SignedArtifactPurpose.ID_TOKEN,
            client_id=client.client_id,
            issued_at=evidence.issued_at,
            expires_at=evidence.expires_at,
        )
        await work.flush()
        lineage = Lineage(session, event, grant, key, client, family, record)
        return await self._issue_credentials(
            work, lineage, access_token=access_token, refresh_token=refresh_token
        )

    async def _issue_credentials(
        self,
        work: SecurityUnitOfWork,
        lineage: Lineage,
        *,
        access_token: SecretStr | None = None,
        refresh_token: SecretStr | None = None,
        predecessor_digest: str | None = None,
    ) -> IssuedCredentials:
        now = self.clock.now()
        access = access_token if access_token is not None else SecretStr(secrets.token_urlsafe(32))
        refresh = (
            refresh_token if refresh_token is not None else SecretStr(secrets.token_urlsafe(32))
        )
        if not 32 <= len(refresh.get_secret_value()) <= 128:
            raise SecurityDenied(Denial.BINDING)
        access_expires = min(
            now + self.protocol.access_token_ttl_seconds,
            lineage.grant.expires_at,
            lineage.family.expires_at,
        )
        work.add(
            AccessCredentialRow(
                token_digest=verifier_digest(access.get_secret_value()),
                grant_id=lineage.grant.grant_id,
                family_id=lineage.family.family_id,
                issued_at=now,
                expires_at=access_expires,
            )
        )
        work.add(
            RefreshCredentialRow(
                token_digest=verifier_digest(refresh.get_secret_value()),
                family_id=lineage.family.family_id,
                generation=lineage.family.generation,
                issued_at=now,
                expires_at=lineage.family.expires_at,
                consumed_at=None,
                predecessor_digest=predecessor_digest,
            )
        )
        await work.flush()
        return IssuedCredentials(
            access_token=access,
            refresh_token=refresh,
            access_expires_at=access_expires,
            refresh_expires_at=lineage.family.expires_at,
            context=lineage.snapshot(work.gate.revision),
        )

    def _require_active(self, lineage: Lineage, client_id: str) -> None:
        if lineage.session.issuer != self.issuer:
            raise SecurityDenied(Denial.BINDING)
        require_lineage(
            session_snapshot(lineage.session),
            event_snapshot(lineage.event, lineage.session),
            lineage.snapshot(0).grant,
            key_snapshot(lineage.key),
            client_id=client_id,
            client_enabled=lineage.client.enabled,
            now=self.clock.now(),
        )
        if lineage.family.revoked_at is not None:
            raise SecurityDenied(Denial.REVOKED)
        if lineage.family.expires_at <= self.clock.now():
            raise SecurityDenied(Denial.EXPIRED)

    async def check_access(self, token: SecretStr, *, authenticated_client: str) -> GrantStatus:
        async with self.repository.transaction() as work:
            result = await self.check_access_in(
                work, token, authenticated_client=authenticated_client
            )
        return result

    async def check_access_in(
        self, work: SecurityUnitOfWork, token: SecretStr, *, authenticated_client: str
    ) -> GrantStatus:
        access = await work.get(AccessCredentialRow, verifier_digest(token.get_secret_value()))
        if access is None or access.expires_at <= self.clock.now():
            return GrantStatus(active=False)
        lineage = await work.lineage(access.grant_id)
        if lineage is None:
            return GrantStatus(active=False)
        try:
            self._require_active(lineage, authenticated_client)
        except SecurityDenied:
            return GrantStatus(active=False)
        if access.expires_at <= self.clock.now():
            return GrantStatus(active=False)
        context = lineage.snapshot(work.gate.revision)
        signed = await work.session.scalar(
            select(RefreshIssuanceRow).where(
                RefreshIssuanceRow.access_digest == access.token_digest
            )
        )
        evidence = context.evidence
        if signed is not None:
            key = await work.get(SigningTrustRow, signed.signing_key_id)
            if key is None or key.state == KeyState.REVOKED.value:
                return GrantStatus(active=False)
            evidence = LoginEvidence(
                token_id=signed.token_id,
                token_digest=signed.token_digest,
                client_id=authenticated_client,
                signing_key_id=signed.signing_key_id,
                authentication=context.authentication,
                issued_at=signed.issued_at,
                expires_at=signed.expires_at,
            )
        return GrantStatus(
            active=True,
            client_id=authenticated_client,
            subject=context.authentication.subject.subject,
            expires_at=access.expires_at,
            context=context,
            credential_evidence=evidence,
        )

    async def rotate_refresh(
        self, token: SecretStr, *, authenticated_client: str
    ) -> IssuedCredentials:
        rejected: Denial | None = None
        result: IssuedCredentials | None = None
        async with self.repository.transaction() as work:
            credential = await work.get(
                RefreshCredentialRow, verifier_digest(token.get_secret_value())
            )
            if credential is None:
                raise SecurityDenied(Denial.MISSING)
            family = await work.get(RefreshFamilyRow, credential.family_id)
            if family is None:
                raise SecurityDenied(Denial.MISSING)
            lineage = await work.lineage(family.grant_id)
            if lineage is None:
                raise SecurityDenied(Denial.MISSING)
            # Authenticate/bind the owner before inspecting reuse or changing
            # family state. Another client cannot weaponize a leaked token value.
            self._require_active(lineage, authenticated_client)
            if credential.expires_at <= self.clock.now():
                raise SecurityDenied(Denial.EXPIRED)
            if credential.consumed_at is not None or credential.generation != family.generation:
                await self._revoke_grant(work, lineage.grant, RevocationReason.REFRESH_REPLAY)
                work.gate.revision += 1
                rejected = Denial.REPLAY
            else:
                credential.consumed_at = self.clock.now()
                family.generation += 1
                result = await self._issue_credentials(
                    work, lineage, predecessor_digest=credential.token_digest
                )
        # Reuse containment is intentionally committed before returning an error.
        if rejected is not None:
            raise SecurityDenied(rejected)
        if result is None:
            raise RuntimeError("A refresh transition must issue credentials or reject")
        return result

    async def refresh_candidate_in(
        self, work: SecurityUnitOfWork, token: SecretStr, *, authenticated_client: str
    ) -> Lineage | None:
        credential = await work.get(RefreshCredentialRow, verifier_digest(token.get_secret_value()))
        family = await work.get(RefreshFamilyRow, credential.family_id) if credential else None
        lineage = await work.lineage(family.grant_id) if family else None
        if credential is None or family is None or lineage is None:
            raise SecurityDenied(Denial.MISSING)
        # The authenticated owner is bound before any consumption/reuse observation.
        self._require_active(lineage, authenticated_client)
        user = await work.get(UserRow, lineage.session.subject)
        if user is not None and not user.enabled:
            raise SecurityDenied(Denial.REVOKED)
        if credential.expires_at <= self.clock.now():
            raise SecurityDenied(Denial.EXPIRED)
        if credential.consumed_at is not None or credential.generation != family.generation:
            await self._revoke_grant(work, lineage.grant, RevocationReason.REFRESH_REPLAY)
            work.gate.revision += 1
            return None
        return lineage

    async def commit_refresh_in(
        self,
        work: SecurityUnitOfWork,
        predecessor: SecretStr,
        evidence: LoginEvidence,
        *,
        access_token: SecretStr,
        refresh_token: SecretStr,
        authenticated_client: str,
    ) -> IssuedCredentials:
        lineage = await self.refresh_candidate_in(
            work, predecessor, authenticated_client=authenticated_client
        )
        if lineage is None:
            raise SecurityDenied(Denial.REPLAY)
        if (
            evidence.authentication != event_snapshot(lineage.event, lineage.session)
            or evidence.client_id != authenticated_client
        ):
            raise SecurityDenied(Denial.BINDING)
        credential = await work.get(
            RefreshCredentialRow, verifier_digest(predecessor.get_secret_value())
        )
        if credential is None:
            raise SecurityDenied(Denial.MISSING)
        credential.consumed_at = self.clock.now()
        lineage.family.generation += 1
        await work.flush()
        result = await self._issue_credentials(
            work,
            lineage,
            access_token=access_token,
            refresh_token=refresh_token,
            predecessor_digest=credential.token_digest,
        )
        await self.record_signed_artifact_in(
            work,
            artifact_id=evidence.token_id,
            key_id=evidence.signing_key_id,
            purpose=SignedArtifactPurpose.ID_TOKEN,
            client_id=authenticated_client,
            issued_at=evidence.issued_at,
            expires_at=evidence.expires_at,
        )
        work.add(
            RefreshIssuanceRow(
                token_id=evidence.token_id,
                token_digest=evidence.token_digest,
                family_id=lineage.family.family_id,
                grant_id=lineage.grant.grant_id,
                generation=lineage.family.generation,
                predecessor_digest=credential.token_digest,
                successor_digest=verifier_digest(refresh_token.get_secret_value()),
                access_digest=verifier_digest(access_token.get_secret_value()),
                signing_key_id=evidence.signing_key_id,
                issued_at=evidence.issued_at,
                expires_at=evidence.expires_at,
            )
        )
        await work.flush()
        return result

    async def _revoke_grant(
        self, work: SecurityUnitOfWork, grant: FederationGrantRow, reason: RevocationReason
    ) -> None:
        if grant.revoked_at is None:
            grant.revoked_at = self.clock.now()
            grant.revocation_reason = reason.value
        family = await work.family_for_grant(grant.grant_id)
        if family is not None and family.revoked_at is None:
            family.revoked_at = self.clock.now()

    async def revoke_grant_in(
        self,
        work: SecurityUnitOfWork,
        grant_id: str,
        *,
        authenticated_client: str,
        reason: RevocationReason,
    ) -> bool:
        grant = await work.get(FederationGrantRow, grant_id)
        if grant is None or grant.client_id != authenticated_client:
            return False
        if grant.revoked_at is None:
            await self._revoke_grant(work, grant, reason)
            work.gate.revision += 1
        return True

    async def revoke_token_in(
        self,
        work: SecurityUnitOfWork,
        token: SecretStr,
        *,
        authenticated_client: str,
        token_type_hint: str | None = None,
    ) -> None:
        value = token.get_secret_value()
        if not 32 <= len(value) <= 128:
            return
        digest = verifier_digest(value)
        # A hint is only a lookup optimization. Ownership is checked before
        # revoking anything, including expired or consumed refresh credentials.
        grant_id: str | None = None
        if token_type_hint != "refresh_token":
            access = await work.get(AccessCredentialRow, digest)
            if access is not None:
                grant_id = access.grant_id
        if grant_id is None:
            refresh = await work.get(RefreshCredentialRow, digest)
            if refresh is not None:
                family = await work.get(RefreshFamilyRow, refresh.family_id)
                if family is not None:
                    grant_id = family.grant_id
        if grant_id is None:
            access = await work.get(AccessCredentialRow, digest)
            if access is not None:
                grant_id = access.grant_id
        if grant_id is not None:
            await self.revoke_grant_in(
                work,
                grant_id,
                authenticated_client=authenticated_client,
                reason=RevocationReason.TOKEN_REVOCATION,
            )

    async def end_session(self, session_id: str) -> None:
        async with self.repository.transaction() as work:
            await self.end_session_in(work, session_id)

    async def check_logout_in(
        self, work: SecurityUnitOfWork, token: SecretStr, *, authenticated_client: str
    ) -> bool:
        """A cached signature cannot restore revoked or unissued logout trust."""
        raw = token.get_secret_value()
        try:
            header = logout_header(raw, max_bytes=self.protocol.max_jwt_bytes)
            key = await work.get(SigningTrustRow, header.kid)
            if key is None or key.state == KeyState.REVOKED.value:
                return False
            public = RSAKey.import_key(
                key.public_key_pem, parameters={"kid": key.key_id, "alg": "RS256", "use": "sig"}
            )
            verified = await asyncio.to_thread(
                validate_logout_token,
                raw,
                settings=OidcValidationProfile(
                    issuer=self.issuer, client_id=authenticated_client, policy=self.protocol
                ),
                keys=PublicJwks(keys=[PublicRsaJwk.model_validate(public.as_dict(private=False))]),
                clock=self.clock,
            )
        except InvalidLogoutToken:
            return False
        claims = verified.claims
        row = await work.session.scalar(
            select(LogoutOutboxRow).where(
                LogoutOutboxRow.token_id == claims.jti,
                LogoutOutboxRow.client_id == authenticated_client,
            )
        )
        artifact = await work.get(SignedArtifactRow, claims.jti)
        if (
            row is None
            or artifact is None
            or artifact.purpose != SignedArtifactPurpose.LOGOUT_TOKEN.value
            or artifact.client_id != authenticated_client
            or artifact.key_id != header.kid
            or artifact.issued_at != claims.iat
            or artifact.expires_at != claims.exp
            or row.session_id != claims.sid
            or row.issuer != self.issuer
        ):
            return False
        parent = await work.get(IdpSessionRow, claims.sid)
        if parent is None or parent.revoked_at is None or parent.issuer != self.issuer:
            return False
        payload = self.cipher.decrypt(row.encrypted_payload, purpose="logout-delivery")
        return payload.get("token") == raw

    async def end_session_in(self, work: SecurityUnitOfWork, session_id: str) -> None:
        session = await work.get(IdpSessionRow, session_id)
        if session is None:
            raise SecurityDenied(Denial.MISSING)
        if session.issuer != self.issuer:
            raise SecurityDenied(Denial.BINDING)
        if session.revoked_at is not None:
            return
        session.revoked_at = self.clock.now()
        session.revocation_reason = RevocationReason.LOGOUT.value
        work.gate.revision += 1
        grants = await work.grants_for_session(session_id)
        recipients: set[str] = set()
        for grant in grants:
            await self._revoke_grant(work, grant, RevocationReason.LOGOUT)
            recipients.add(grant.client_id)
        for client_id in sorted(recipients):
            client = await work.get(ClientRow, client_id)
            if client is None:
                raise RuntimeError("A logout recipient must remain registered")
            payload: dict[str, JsonValue] = {
                "issuer": session.issuer,
                "sid": session.session_id,
                "client_id": client_id,
                "reason": RevocationReason.LOGOUT.value,
                "revision": work.gate.revision,
            }
            work.add(
                LogoutOutboxRow(
                    delivery_id=identifier(),
                    destination=client.backchannel_logout_uri,
                    encrypted_payload=self.cipher.encrypt(payload, purpose="logout-delivery"),
                    created_at=self.clock.now(),
                    next_attempt_at=self.clock.now(),
                    attempts=0,
                    status="pending" if client.backchannel_logout_uri else "skipped",
                    last_error=None if client.backchannel_logout_uri else "no_destination",
                    issuer=session.issuer,
                    session_id=session.session_id,
                    client_id=client_id,
                )
            )

    async def disable_client(self, client_id: str) -> None:
        async with self.repository.transaction() as work:
            await self.disable_client_in(work, client_id)

    async def disable_client_in(self, work: SecurityUnitOfWork, client_id: str) -> None:
        client = await work.get(ClientRow, client_id)
        if client is None:
            raise SecurityDenied(Denial.MISSING)
        if client.enabled or client.compromised_key_id != client.key_id:
            client.enabled = False
            client.compromised_key_id = client.key_id
            client.registration_version += 1
        for grant in await work.grants_for_client(client_id):
            await self._revoke_grant(work, grant, RevocationReason.CLIENT_COMPROMISE)
        work.gate.revision += 1
        await work.flush()

    async def revoke_signer(self, key_id: str) -> None:
        async with self.repository.transaction() as work:
            await self.revoke_signer_in(work, key_id)

    async def revoke_signer_in(self, work: SecurityUnitOfWork, key_id: str) -> int:
        key = await work.get(SigningTrustRow, key_id)
        if key is None:
            raise SecurityDenied(Denial.MISSING)
        if key.state == KeyState.REVOKED.value:
            return 0
        require_key_transition(
            key_snapshot(key),
            KeyState.REVOKED,
            now=self.clock.now(),
            skew=self.protocol.clock_skew_seconds,
        )
        key.state = KeyState.REVOKED.value
        revoked = 0
        for grant in await work.grants_for_key(key_id):
            revoked += int(grant.revoked_at is None)
            await self._revoke_grant(work, grant, RevocationReason.KEY_COMPROMISE)
        work.gate.revision += 1
        await work.flush()
        return revoked
