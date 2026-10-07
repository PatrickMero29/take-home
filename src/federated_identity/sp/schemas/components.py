"""The independently configured components of a relying application."""

from dataclasses import dataclass

from federated_identity.common.persistence.foundations import RuntimeReadiness
from federated_identity.common.persistence.sessions import SessionBackend
from federated_identity.common.security.contracts import GrantChecker, StepUpEngine
from federated_identity.common.security.secrets import RuntimeSecrets
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.sp.protocol.oidc import OidcClient
from federated_identity.sp.repositories.database import SpDatabase
from federated_identity.sp.repositories.transactions import PostgresAuthorizationTransactions
from federated_identity.sp.services.browser import SpBrowserService
from federated_identity.sp.services.logout import SpLogoutService
from federated_identity.sp.services.security_model import SpSecurityModel
from federated_identity.sp.services.sensitive import SpSensitiveService


@dataclass(frozen=True)
class SpComponents:
    settings: RuntimeSettings
    secrets: RuntimeSecrets
    database: SpDatabase
    sessions: SessionBackend
    oidc: OidcClient
    transactions: PostgresAuthorizationTransactions
    grants: GrantChecker
    step_up: StepUpEngine
    security: SpSecurityModel
    browser: SpBrowserService
    logout: SpLogoutService
    sensitive: SpSensitiveService
    readiness: RuntimeReadiness
