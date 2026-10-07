"""Operator-authorized, live registration changes join the federation security gate."""

import json
import uuid
from http import HTTPStatus

from sqlalchemy import select

from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.model import RevocationReason
from federated_identity.idp.repositories.clients import client_snapshot
from federated_identity.idp.repositories.operator import ClientKeyHistoryRow, OperatorAuditRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import SigningTrustRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.clients import (
    ClientCreate,
    ClientCredentialReplacement,
    ClientRegistration,
    ClientStateChange,
    ClientUpdate,
    public_authentication_key,
    uri_origin,
)
from federated_identity.idp.schemas.operator import OperatorAuthorization, OperatorPermission
from federated_identity.idp.services.operator import OperatorError, OperatorService


class ClientAdministration:
    def __init__(self, operators: OperatorService, issuer_public_key: str) -> None:
        self.operators = operators
        self.security = operators.security
        self.issuer_public_key = public_authentication_key(issuer_public_key)

    async def inspect(
        self, authorization: OperatorAuthorization, client_id: str | None = None
    ) -> list[ClientRegistration]:
        async with self.security.repository.transaction() as work:
            await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_READ
            )
            statement = select(ClientRow).order_by(ClientRow.client_id)
            if client_id is not None:
                statement = statement.where(ClientRow.client_id == client_id)
            rows = list(await work.session.scalars(statement))
            if client_id is not None and not rows:
                raise OperatorError("Client registration does not exist", HTTPStatus.NOT_FOUND)
            result = [client_snapshot(row) for row in rows]
        return result

    async def _validate(
        self, work: SecurityUnitOfWork, metadata: ClientRegistration, *, replacement: bool
    ) -> None:
        origin = uri_origin(metadata.redirect_uris[0])
        if origin[1] == uri_origin(self.security.issuer)[1]:
            raise OperatorError(
                "A client must own a hostname distinct from the IDP", HTTPStatus.BAD_REQUEST
            )
        clients = list(await work.session.scalars(select(ClientRow)))
        for client in clients:
            if (
                client.client_id != metadata.client_id
                and uri_origin(client.redirect_uris[0])[1] == origin[1]
            ):
                raise OperatorError(
                    "Each client requires a distinct hostname", HTTPStatus.BAD_REQUEST
                )
        issuer_keys = list(await work.session.scalars(select(SigningTrustRow.public_key_pem)))
        if (
            metadata.public_key_pem == self.issuer_public_key
            or metadata.public_key_pem in issuer_keys
        ):
            raise OperatorError(
                "Issuer and client authentication keys must be distinct", HTTPStatus.BAD_REQUEST
            )
        if replacement:
            used = await work.session.scalar(
                select(ClientKeyHistoryRow).where(
                    (ClientKeyHistoryRow.key_id == metadata.key_id)
                    | (ClientKeyHistoryRow.public_key_pem == metadata.public_key_pem)
                )
            )
            if used is not None:
                raise OperatorError(
                    "Replacement credentials must be new and client-specific", HTTPStatus.CONFLICT
                )

    def _audit(
        self, work: SecurityUnitOfWork, operator_id: str, action: str, row: ClientRow
    ) -> None:
        work.add(
            OperatorAuditRow(
                event_id=str(uuid.uuid4()),
                operator_id=operator_id,
                action=action,
                client_id=row.client_id,
                registration_version=row.registration_version,
                created_at=self.operators.repository.clock.now(),
            )
        )

    async def _contain(
        self, work: SecurityUnitOfWork, client_id: str, reason: RevocationReason
    ) -> None:
        for grant in await work.grants_for_client(client_id):
            await self.security.revoke_grant_in(
                work, grant.grant_id, authenticated_client=client_id, reason=reason
            )

    @staticmethod
    def _version(row: ClientRow, expected: int) -> None:
        if row.registration_version != expected:
            raise OperatorError(
                "Client registration changed; inspect its current version", HTTPStatus.CONFLICT
            )

    async def register(
        self, authorization: OperatorAuthorization, request: ClientCreate
    ) -> ClientRegistration:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.CLIENT_REGISTER, "clients:new"
            )
            if await work.get(ClientRow, request.client_id) is not None:
                raise OperatorError("Client registration already exists", HTTPStatus.CONFLICT)
            metadata = ClientRegistration.model_validate_json(request.model_dump_json())
            await self._validate(work, metadata, replacement=True)
            row = ClientRow(**metadata.model_dump(mode="json"))
            work.add(row)
            await work.flush()
            work.add(
                ClientKeyHistoryRow(
                    key_id=row.key_id,
                    client_id=row.client_id,
                    public_key_pem=row.public_key_pem,
                    created_at=self.operators.repository.clock.now(),
                )
            )
            self._audit(work, principal.operator_id, "register", row)
            work.gate.revision += 1
            await work.flush()
            result = client_snapshot(row)
        return result

    async def update(
        self, authorization: OperatorAuthorization, client_id: str, request: ClientUpdate
    ) -> ClientRegistration:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.CLIENT_UPDATE, client_id
            )
            row = await work.get(ClientRow, client_id)
            if row is None:
                raise OperatorError("Client registration does not exist", HTTPStatus.NOT_FOUND)
            self._version(row, request.expected_version)
            values = {
                **client_snapshot(row).model_dump(mode="json"),
                **request.model_dump(mode="json", exclude={"expected_version"}),
            }
            metadata = ClientRegistration.model_validate_json(json.dumps(values))
            await self._validate(work, metadata, replacement=False)
            updates = request.model_dump(mode="json", exclude={"expected_version"})
            if all(getattr(row, name) == value for name, value in updates.items()):
                return client_snapshot(row)
            for name, value in updates.items():
                setattr(row, name, value)
            row.registration_version += 1
            await self._contain(work, row.client_id, RevocationReason.CLIENT_METADATA_CHANGE)
            work.gate.revision += 1
            await work.flush()
            self._audit(work, principal.operator_id, "update", row)
            result = client_snapshot(row)
        return result

    async def set_enabled(
        self,
        authorization: OperatorAuthorization,
        client_id: str,
        request: ClientStateChange,
        *,
        enabled: bool,
    ) -> ClientRegistration:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_WRITE
            )
            purpose = (
                BrowserActionPurpose.CLIENT_ENABLE
                if enabled
                else BrowserActionPurpose.CLIENT_DISABLE
            )
            await self.operators.consume_in(work.session, authorization, purpose, client_id)
            row = await work.get(ClientRow, client_id)
            if row is None:
                raise OperatorError("Client registration does not exist", HTTPStatus.NOT_FOUND)
            self._version(row, request.expected_version)
            if enabled and row.compromised_key_id == row.key_id:
                raise OperatorError(
                    "Replace compromised credentials before enabling the client",
                    HTTPStatus.CONFLICT,
                )
            if row.enabled != enabled:
                row.enabled = enabled
                row.registration_version += 1
                if not enabled:
                    await self._contain(work, client_id, RevocationReason.CLIENT_COMPROMISE)
                work.gate.revision += 1
                await work.flush()
                self._audit(work, principal.operator_id, "enable" if enabled else "disable", row)
            result = client_snapshot(row)
        return result

    async def contain(
        self, authorization: OperatorAuthorization, client_id: str, request: ClientStateChange
    ) -> ClientRegistration:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.CLIENT_CONTAIN, client_id
            )
            row = await work.get(ClientRow, client_id)
            if row is None:
                raise OperatorError("Client registration does not exist", HTTPStatus.NOT_FOUND)
            self._version(row, request.expected_version)
            await self.security.disable_client_in(work, client_id)
            self._audit(work, principal.operator_id, "contain", row)
            result = client_snapshot(row)
        return result

    async def replace_credential(
        self,
        authorization: OperatorAuthorization,
        client_id: str,
        request: ClientCredentialReplacement,
    ) -> ClientRegistration:
        async with self.security.repository.transaction() as work:
            principal = await self.operators.authorize_in(
                work.session, authorization, OperatorPermission.CLIENTS_WRITE
            )
            await self.operators.consume_in(
                work.session, authorization, BrowserActionPurpose.CLIENT_REPLACE, client_id
            )
            row = await work.get(ClientRow, client_id)
            if row is None:
                raise OperatorError("Client registration does not exist", HTTPStatus.NOT_FOUND)
            self._version(row, request.expected_version)
            values = {
                **client_snapshot(row).model_dump(mode="json"),
                **request.model_dump(mode="json", exclude={"expected_version"}),
            }
            metadata = ClientRegistration.model_validate_json(json.dumps(values))
            await self._validate(work, metadata, replacement=True)
            row.public_key_pem, row.key_id = metadata.public_key_pem, metadata.key_id
            row.registration_version += 1
            await self._contain(work, client_id, RevocationReason.CLIENT_KEY_REPLACEMENT)
            work.gate.revision += 1
            await work.flush()
            work.add(
                ClientKeyHistoryRow(
                    key_id=row.key_id,
                    client_id=client_id,
                    public_key_pem=row.public_key_pem,
                    created_at=self.operators.repository.clock.now(),
                )
            )
            self._audit(work, principal.operator_id, "replace_credential", row)
            result = client_snapshot(row)
        return result
