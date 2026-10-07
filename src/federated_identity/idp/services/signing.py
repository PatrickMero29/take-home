"""Persisted live issuer signing, public publication, and operator-controlled lifecycle."""

import asyncio
import uuid
from http import HTTPStatus

from joserfc.jwk import RSAKey
from sqlalchemy import select

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.keys import PublicJwks, PublicRsaJwk, SigningKey
from federated_identity.common.security.model import Denial, KeyState, SecurityDenied
from federated_identity.common.settings.policy import SIGNING_ALGORITHM
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import SigningTrustRow
from federated_identity.idp.repositories.signing import SigningAuditRow, SigningMaterialRow
from federated_identity.idp.schemas.operator import OperatorAuthorization, OperatorPermission
from federated_identity.idp.schemas.signing import (
    SigningKeyActivation,
    SigningKeyContainment,
    SigningKeyContainmentResult,
    SigningKeyInfo,
    SigningKeyRetirement,
)
from federated_identity.idp.services.operator import OperatorError, OperatorService
from federated_identity.idp.services.security_model import IdpSecurityModel

PUBLISHED_STATES = (KeyState.PREPARED.value, KeyState.ACTIVE.value, KeyState.DRAINING.value)


def public_key(row: SigningTrustRow) -> PublicRsaJwk:
    key = RSAKey.import_key(
        row.public_key_pem,
        parameters={"kid": row.key_id, "alg": SIGNING_ALGORITHM, "use": "sig"},
    )
    if key.is_private:
        raise SecurityDenied(Denial.BINDING)
    return PublicRsaJwk.model_validate(key.as_dict(private=False))


def key_info(row: SigningTrustRow) -> SigningKeyInfo:
    return SigningKeyInfo(
        key_id=row.key_id,
        state=KeyState(row.state),
        created_at=row.created_at,
        published_at=row.published_at,
        verification_deadline=row.verification_deadline,
        public_key=public_key(row),
    )


class SigningKeyService:
    def __init__(self, security: IdpSecurityModel, bootstrap: SigningKey) -> None:
        self.security = security
        self.bootstrap = bootstrap
        self._private: dict[str, SigningKey] = {}

    def _encrypt(self, signer: SigningKey) -> bytes:
        return self.security.cipher.encrypt(
            {"kid": signer.kid, "private_pem": signer.key.as_pem(private=True).decode("ascii")},
            purpose="issuer-signing-key",
        )

    def _decrypt(self, row: SigningTrustRow, encrypted: bytes) -> SigningKey:
        payload = self.security.cipher.decrypt(encrypted, purpose="issuer-signing-key")
        pem = payload.get("private_pem")
        if payload.get("kid") != row.key_id or not isinstance(pem, str) or len(pem) > 16384:
            raise SecurityDenied(Denial.BINDING)
        key = RSAKey.import_key(
            pem, parameters={"kid": row.key_id, "alg": SIGNING_ALGORITHM, "use": "sig"}
        )
        signer = SigningKey(key, row.key_id)
        if not key.is_private or signer.public_pem() != row.public_key_pem:
            raise SecurityDenied(Denial.BINDING)
        return signer

    async def _material_in(self, work: SecurityUnitOfWork, row: SigningTrustRow) -> SigningKey:
        material = await work.get(SigningMaterialRow, row.key_id)
        if material is None:
            # Enroll only the original known volume identity. A missing rotated
            # private key is not permission to regenerate or reset active trust.
            if (
                row.key_id != self.bootstrap.kid
                or row.public_key_pem != self.bootstrap.public_pem()
            ):
                raise SecurityDenied(Denial.MISSING)
            material = SigningMaterialRow(
                key_id=row.key_id,
                encrypted_private_key=self._encrypt(self.bootstrap),
                created_at=self.security.clock.now(),
            )
            work.add(material)
            await work.flush()
            self._private[row.key_id] = self.bootstrap
        cached = self._private.get(row.key_id)
        if cached is None:
            cached = await asyncio.to_thread(self._decrypt, row, material.encrypted_private_key)
            self._private[row.key_id] = cached
        if cached.public_pem() != row.public_key_pem:
            raise SecurityDenied(Denial.BINDING)
        return cached

    async def initialize(self) -> None:
        async with self.security.repository.transaction() as work:
            original = await work.get(SigningTrustRow, self.bootstrap.kid)
            active = await work.active_key()
            if original is None:
                if active is not None:
                    raise SecurityDenied(Denial.BINDING)
                original = SigningTrustRow(
                    key_id=self.bootstrap.kid,
                    public_key_pem=self.bootstrap.public_pem(),
                    state=KeyState.ACTIVE.value,
                    created_at=self.security.clock.now(),
                    verification_deadline=0,
                    published_at=None,
                )
                work.add(original)
                await work.flush()
            if original.public_key_pem != self.bootstrap.public_pem():
                raise SecurityDenied(Denial.BINDING)
            rows = list(
                await work.session.scalars(
                    select(SigningTrustRow).where(SigningTrustRow.state.in_(PUBLISHED_STATES))
                )
            )
            for row in rows:
                await self._material_in(work, row)
            if await work.active_key() is None:
                raise SecurityDenied(Denial.MISSING)

    async def active_in(self, work: SecurityUnitOfWork) -> SigningKey:
        row = await work.active_key()
        if row is None:
            raise SecurityDenied(Denial.MISSING)
        return await self._material_in(work, row)

    async def public_jwks(self) -> PublicJwks:
        async with self.security.repository.transaction() as work:
            rows = list(
                await work.session.scalars(
                    select(SigningTrustRow)
                    .where(SigningTrustRow.state.in_(PUBLISHED_STATES))
                    .order_by(SigningTrustRow.created_at, SigningTrustRow.key_id)
                )
            )
            # Validate/serialize public-only data before recording publication.
            result = PublicJwks(keys=[public_key(row) for row in rows])
            for row in rows:
                if row.published_at is None:
                    row.published_at = max(row.created_at, self.security.clock.now())
        return result


class SigningKeyAdministration:
    def __init__(self, operators: OperatorService, keys: SigningKeyService) -> None:
        self.operators = operators
        self.keys = keys
        self.security = operators.security

    def _audit(
        self,
        work: SecurityUnitOfWork,
        operator_id: str,
        action: str,
        row: SigningTrustRow,
        previous: str | None = None,
        replacement: str | None = None,
    ) -> None:
        work.add(
            SigningAuditRow(
                event_id=str(uuid.uuid4()),
                operator_id=operator_id,
                action=action,
                key_id=row.key_id,
                previous_active_key_id=previous,
                replacement_key_id=replacement,
                created_at=self.security.clock.now(),
            )
        )

    async def inspect(self, authorization: OperatorAuthorization) -> list[SigningKeyInfo]:
        async with self.security.repository.transaction() as work:
            await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.KEYS_READ
            )
            rows = list(
                await work.session.scalars(
                    select(SigningTrustRow).order_by(
                        SigningTrustRow.created_at, SigningTrustRow.key_id
                    )
                )
            )
            result = [key_info(row) for row in rows]
        return result

    async def prepare(self, authorization: OperatorAuthorization) -> SigningKeyInfo:
        await self.operators.principal(authorization, OperatorPermission.KEYS_WRITE)
        # Generate bounded key material off-thread and outside the database gate.
        signer = await asyncio.to_thread(SigningKey.generate)
        encrypted = self.keys._encrypt(signer)
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.KEYS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.SIGNING_PREPARE, "signing:new"
            )
            visible = list(
                await work.session.scalars(
                    select(SigningTrustRow.key_id).where(
                        SigningTrustRow.state.in_(PUBLISHED_STATES)
                    )
                )
            )
            if len(visible) >= 16:
                raise OperatorError(
                    "Retire eligible draining keys before preparing more", HTTPStatus.CONFLICT
                )
            row = SigningTrustRow(
                key_id=signer.kid,
                public_key_pem=signer.public_pem(),
                state=KeyState.PREPARED.value,
                created_at=self.security.clock.now(),
                verification_deadline=0,
                published_at=None,
            )
            work.add(row)
            await work.flush()
            work.add(
                SigningMaterialRow(
                    key_id=row.key_id, encrypted_private_key=encrypted, created_at=row.created_at
                )
            )
            self._audit(work, principal.operator_id, "prepare", row)
            work.gate.revision += 1
            result = key_info(row)
        self.keys._private[signer.kid] = signer
        return result

    async def activate(
        self, authorization: OperatorAuthorization, key_id: str, request: SigningKeyActivation
    ) -> SigningKeyInfo:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.KEYS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.SIGNING_ACTIVATE, key_id
            )
            current = await work.active_key()
            row = await work.get(SigningTrustRow, key_id)
            if current is None or current.key_id != request.expected_active_key_id:
                raise OperatorError(
                    "Active signing trust changed; inspect current keys", HTTPStatus.CONFLICT
                )
            if row is None or row.state != KeyState.PREPARED.value or row.published_at is None:
                raise OperatorError(
                    "Activation requires a published prepared signing key", HTTPStatus.CONFLICT
                )
            await self.keys._material_in(work, row)
            previous = current.key_id
            await self.security.rotate_trust_in(work, key_id)
            await work.flush()
            self._audit(work, principal.operator_id, "activate", row, previous)
            result = key_info(row)
        return result

    async def retire(
        self, authorization: OperatorAuthorization, key_id: str, request: SigningKeyRetirement
    ) -> SigningKeyInfo:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.KEYS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.SIGNING_RETIRE, key_id
            )
            row = await work.get(SigningTrustRow, key_id)
            if row is None or row.state != KeyState.DRAINING.value:
                raise OperatorError(
                    "Only a draining signing key can be retired", HTTPStatus.CONFLICT
                )
            if row.verification_deadline != request.expected_verification_deadline:
                raise OperatorError(
                    "Signing retention changed; inspect current keys", HTTPStatus.CONFLICT
                )
            try:
                await self.security.retire_trust_in(work, key_id)
            except SecurityDenied:
                raise OperatorError(
                    "Unexpired signed artifacts still require this key", HTTPStatus.CONFLICT
                ) from None
            await work.flush()
            self._audit(work, principal.operator_id, "retire", row)
            result = key_info(row)
        self.keys._private.pop(key_id, None)
        return result

    async def contain(
        self, authorization: OperatorAuthorization, key_id: str, request: SigningKeyContainment
    ) -> SigningKeyContainmentResult:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.KEYS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.SIGNING_CONTAIN, key_id
            )
            current = await work.active_key()
            compromised = await work.get(SigningTrustRow, key_id)
            replacement = await work.get(SigningTrustRow, request.replacement_key_id)
            if current is None or current.key_id != request.expected_active_key_id:
                raise OperatorError(
                    "Active signing trust changed; inspect current keys", HTTPStatus.CONFLICT
                )
            if compromised is None or compromised.state == KeyState.REVOKED.value:
                raise OperatorError("An unrevoked signing key is required", HTTPStatus.CONFLICT)
            if (
                replacement is None
                or replacement.key_id == key_id
                or (
                    replacement.key_id != current.key_id
                    and (
                        replacement.state != KeyState.PREPARED.value
                        or replacement.published_at is None
                    )
                )
            ):
                raise OperatorError(
                    "Recovery requires a distinct active or published prepared key",
                    HTTPStatus.CONFLICT,
                )
            await self.keys._material_in(work, replacement)
            previous = current.key_id
            if replacement.key_id != current.key_id:
                await self.security.rotate_trust_in(work, replacement.key_id)
            revoked = await self.security.revoke_signer_in(work, key_id)
            self._audit(
                work, principal.operator_id, "contain", compromised, previous, replacement.key_id
            )
            result = SigningKeyContainmentResult(
                compromised=key_info(compromised),
                active=key_info(replacement),
                revoked_grants=revoked,
            )
        self.keys._private.pop(key_id, None)
        return result
