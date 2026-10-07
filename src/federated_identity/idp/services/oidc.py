"""One gated transaction across Authlib's async-backed hooks and security lineage."""

from http import HTTPStatus

from authlib.oauth2.rfc6749 import InvalidGrantError, OAuth2Error
from pydantic import SecretStr

from federated_identity.common.keys import SigningKey
from federated_identity.common.policy import Clock, IdpSettings
from federated_identity.common.security.artifacts import RefreshTokenResponse
from federated_identity.common.security.contracts import LogoutTokenStatus
from federated_identity.common.security.model import RevocationReason, SecurityDenied
from federated_identity.idp.protocol.authlib_adapter import AuthlibAdapter
from federated_identity.idp.repositories.database import (
    Database,
    ProtocolRepository,
    ProtocolUnitOfWork,
)
from federated_identity.idp.schemas.models import (
    AuthenticatedPrincipal,
    AuthorizationInteraction,
    IntrospectionPayload,
    ProtocolMessage,
    ProtocolResponse,
    TokenResponse,
)
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.idp.services.signing import SigningKeyService


class OidcService:
    def __init__(
        self,
        settings: IdpSettings,
        database: Database,
        signer: SigningKey,
        clock: Clock,
        *,
        security: IdpSecurityModel,
        keys: SigningKeyService | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.signer = signer
        self.clock = clock
        self.security = security
        self.keys = keys if keys is not None else SigningKeyService(security, signer)
        if security.issuer != settings.issuer or security.repository.database is not database:
            raise ValueError("Protocol and security services must share their issuer and database")

    async def authorize(
        self,
        message: ProtocolMessage,
        principal: AuthenticatedPrincipal | None,
        *,
        fresh_authentication: bool = False,
    ) -> ProtocolResponse:
        def operation(repository: ProtocolRepository) -> ProtocolResponse:
            return AuthlibAdapter(
                message,
                repository,
                self.settings,
                self.signer,
                self.clock,
                fresh_authentication=fresh_authentication,
            ).authorize(principal)

        return await self.database.transact(operation)

    async def authorize_browser(
        self, message: ProtocolMessage, principal: AuthenticatedPrincipal | None
    ) -> ProtocolResponse | AuthorizationInteraction:
        def operation(
            repository: ProtocolRepository,
        ) -> ProtocolResponse | AuthorizationInteraction:
            return AuthlibAdapter(
                message, repository, self.settings, self.signer, self.clock
            ).authorization(principal, interactive=True)

        return await self.database.transact(operation)

    async def exchange(self, message: ProtocolMessage) -> ProtocolResponse:
        async with self.database.protocol_transaction() as work:
            adapter = await work.protocol(
                lambda repository: AuthlibAdapter(
                    message, repository, self.settings, self.signer, self.clock
                )
            )
            rejected = await work.protocol(lambda repository: adapter.validate_exchange())
            if rejected is not None:
                if adapter.replayed_code is not None:
                    grant_id, client_id = adapter.replayed_code
                    await self.security.revoke_grant_in(
                        work,
                        grant_id,
                        authenticated_client=client_id,
                        reason=RevocationReason.CODE_REPLAY,
                    )
                return rejected
            if adapter.is_refresh:
                return await self.refresh_in(work, adapter)
            try:
                # Preserve legitimate assertion replay reservations on a later
                # policy denial; discard all draft issuance/code changes together.
                async with work.session.begin_nested():
                    adapter.signer = await self.keys.active_in(work)
                    response = await work.protocol(lambda repository: adapter.issue_tokens())
                    if not isinstance(response.body, TokenResponse) or adapter.issuance_id is None:
                        raise RuntimeError("Successful code issuance needs typed token evidence")
                    evidence = adapter.login_evidence(response.body)
                    credentials = await self.security.issue_grant_in(
                        work,
                        evidence,
                        access_token=SecretStr(response.body.access_token),
                        refresh_token=(
                            SecretStr(response.body.refresh_token)
                            if response.body.refresh_token
                            else None
                        ),
                    )
                    await work.protocol(
                        lambda repository: repository.bind_issuance(
                            evidence.token_id, credentials.context.grant.grant_id
                        )
                    )
                    remaining = credentials.access_expires_at - self.clock.now()
                    if remaining <= 0:
                        raise InvalidGrantError("The parent authorization lifetime has ended")
                    response = ProtocolResponse(
                        response.status,
                        response.body.model_copy(update={"expires_in": remaining}),
                        response.headers,
                    )
            except SecurityDenied:
                return adapter.error_response(
                    InvalidGrantError("Authorization is no longer active")
                )
            except OAuth2Error as error:
                return adapter.error_response(error)
        return response

    async def refresh_in(
        self, work: ProtocolUnitOfWork, adapter: AuthlibAdapter
    ) -> ProtocolResponse:
        client = adapter.request.client
        if client is None:
            raise RuntimeError("Refresh requires authenticated client authority")
        predecessor = SecretStr(adapter.request.parameters["refresh_token"])
        try:
            lineage = await self.security.refresh_candidate_in(
                work, predecessor, authenticated_client=client.data.client_id
            )
            if lineage is None:
                # Keep intentional family containment outside the issuance savepoint.
                return adapter.error_response(
                    InvalidGrantError("The refresh credential was reused")
                )
            async with work.session.begin_nested():
                adapter.signer = await self.keys.active_in(work)
                response = await work.protocol(lambda repository: adapter.issue_tokens())
                if not isinstance(response.body, RefreshTokenResponse):
                    raise RuntimeError("Refresh requires a rotating typed token response")
                evidence = adapter.refresh_evidence(response.body)
                credentials = await self.security.commit_refresh_in(
                    work,
                    predecessor,
                    evidence,
                    access_token=SecretStr(response.body.access_token),
                    refresh_token=SecretStr(response.body.refresh_token),
                    authenticated_client=client.data.client_id,
                )
                remaining = credentials.access_expires_at - self.clock.now()
                if remaining <= 0:
                    raise InvalidGrantError("The parent authorization lifetime has ended")
                response = ProtocolResponse(
                    response.status,
                    response.body.model_copy(update={"expires_in": remaining}),
                    response.headers,
                )
            return response
        except SecurityDenied:
            return adapter.error_response(
                InvalidGrantError("Refresh authorization is no longer active")
            )
        except OAuth2Error as error:
            return adapter.error_response(error)

    async def introspect(self, message: ProtocolMessage) -> ProtocolResponse:
        async with self.database.protocol_transaction() as work:
            adapter = await work.protocol(
                lambda repository: AuthlibAdapter(
                    message, repository, self.settings, self.signer, self.clock
                )
            )
            client = await work.protocol(lambda repository: adapter.introspection_client())
            if isinstance(client, ProtocolResponse):
                return client
            status = await self.security.check_access_in(
                work,
                SecretStr(message.parameters["token"]),
                authenticated_client=client.data.client_id,
            )
            response = ProtocolResponse(
                HTTPStatus.OK,
                IntrospectionPayload(
                    active=status.active,
                    client_id=status.client_id,
                    sub=status.subject,
                    exp=status.expires_at,
                    context=status.context,
                    credential_evidence=status.credential_evidence,
                ),
            )
        return response

    async def revoke(self, message: ProtocolMessage) -> ProtocolResponse:
        async with self.database.protocol_transaction() as work:
            adapter = await work.protocol(
                lambda repository: AuthlibAdapter(
                    message, repository, self.settings, self.signer, self.clock
                )
            )
            client = await work.protocol(lambda repository: adapter.revocation_client())
            if isinstance(client, ProtocolResponse):
                return client
            await self.security.revoke_token_in(
                work,
                SecretStr(message.parameters["token"]),
                authenticated_client=client.data.client_id,
                token_type_hint=message.parameters.get("token_type_hint"),
            )
            response = ProtocolResponse(HTTPStatus.OK, "")
        # Unknown, wrong-client, expired and previously revoked tokens have the
        # same non-disclosing response; an owning-client effect commits first.
        return response

    async def check_logout(self, message: ProtocolMessage) -> ProtocolResponse:
        async with self.database.protocol_transaction() as work:
            adapter = await work.protocol(
                lambda repository: AuthlibAdapter(
                    message, repository, self.settings, self.signer, self.clock
                )
            )
            client = await work.protocol(lambda repository: adapter.introspection_client())
            if isinstance(client, ProtocolResponse):
                return client
            active = await self.security.check_logout_in(
                work,
                SecretStr(message.parameters["token"]),
                authenticated_client=client.data.client_id,
            )
            response = ProtocolResponse(HTTPStatus.OK, LogoutTokenStatus(active=active))
        return response
