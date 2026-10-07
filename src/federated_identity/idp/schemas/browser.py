"""IDP-local login continuations contain trusted references, never browser-supplied identity."""

from dataclasses import dataclass

from pydantic import Field, SecretStr

from federated_identity.common.security.model import Assurance, AuthenticationEvent, IdpSession
from federated_identity.common.settings.policy import FrozenModel, Identifier
from federated_identity.idp.schemas.models import AuthorizationParameters
from federated_identity.idp.schemas.users import Username


class LoginContinuation(FrozenModel):
    authorization: AuthorizationParameters | None = None
    expected_subject: Identifier | None = None
    attempts: int = Field(default=0, ge=0, le=20)
    expires_at: int | None = Field(default=None, ge=1)

    @property
    def requires_totp(self) -> bool:
        return (
            self.authorization is not None
            and self.authorization.acr_values == Assurance.PASSWORD_TOTP.value
        )


class IdpBrowserIdentity(FrozenModel):
    session: IdpSession
    authentication: AuthenticationEvent
    username: Username


@dataclass(frozen=True)
class CompletedLogin:
    cookie: SecretStr
    identity: IdpBrowserIdentity
    continuation: LoginContinuation
    ttl: int
