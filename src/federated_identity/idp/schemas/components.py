"""Typed IDP composition root for the target architecture."""

from dataclasses import dataclass

from federated_identity.common.persistence.foundations import RuntimeReadiness
from federated_identity.common.persistence.sessions import SessionBackend
from federated_identity.common.security.contracts import LogoutTransport, StepUpEngine
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.idp.repositories.outbox import PostgresLogoutOutbox
from federated_identity.idp.repositories.users import UserRepository
from federated_identity.idp.services.authentication import PasswordAuthenticator
from federated_identity.idp.services.browser import IdpBrowserService
from federated_identity.idp.services.clients import ClientAdministration
from federated_identity.idp.services.end_session import RpInitiatedLogout
from federated_identity.idp.services.logout import LogoutDispatcher
from federated_identity.idp.services.oidc import OidcService
from federated_identity.idp.services.operator import OperatorService
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.idp.services.signing import SigningKeyAdministration


@dataclass(frozen=True)
class IdpComponents:
    settings: RuntimeSettings
    oidc: OidcService
    sessions: SessionBackend
    logout_outbox: PostgresLogoutOutbox
    logout_transport: LogoutTransport
    logout: RpInitiatedLogout
    logout_dispatcher: LogoutDispatcher
    step_up: StepUpEngine
    security: IdpSecurityModel
    users: UserRepository
    authentication: PasswordAuthenticator
    browser: IdpBrowserService
    operators: OperatorService
    clients: ClientAdministration
    signing: SigningKeyAdministration
    readiness: RuntimeReadiness
