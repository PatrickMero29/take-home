"""Credential-backed authentication facts with a snapshot for transactional rechecking."""

from dataclasses import dataclass

from pydantic import SecretStr

from federated_identity.common.security.model import (
    AuthenticationMethod,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.common.security.passwords import Argon2Passwords
from federated_identity.common.settings.policy import Clock
from federated_identity.idp.repositories.users import UserRepository
from federated_identity.idp.schemas.users import UserCredential


@dataclass(frozen=True)
class VerifiedPassword:
    authentication: TrustedAuthentication
    credential: UserCredential


class PasswordAuthenticator:
    def __init__(
        self, users: UserRepository, passwords: Argon2Passwords, *, issuer: str, clock: Clock
    ) -> None:
        self.users = users
        self.passwords = passwords
        self.issuer = issuer
        self.clock = clock

    async def authenticate(
        self, username: str, password: SecretStr
    ) -> TrustedAuthentication | None:
        verified = await self.verify_credentials(username, password)
        return verified.authentication if verified is not None else None

    async def verify_credentials(
        self, username: str, password: SecretStr
    ) -> VerifiedPassword | None:
        if not 1 <= len(username) <= 32 or not username.isascii():
            return None
        credential = await self.users.credential(username)
        matched = await self.passwords.verify(
            password, credential.password_hash if credential is not None else None
        )
        if not matched or credential is None or not credential.enabled:
            return None
        if await self.users.credential(username) != credential:
            return None
        return VerifiedPassword(
            authentication=TrustedAuthentication(
                subject=SubjectIdentity(issuer=self.issuer, subject=credential.subject),
                authenticated_at=self.clock.now(),
                methods=(AuthenticationMethod.PASSWORD,),
            ),
            credential=credential,
        )
