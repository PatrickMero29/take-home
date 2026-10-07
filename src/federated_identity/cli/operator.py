"""Verified HTTPS operator tooling; never treats user/SP credentials as authority."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import ssl
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx2 as httpx
from pydantic import SecretStr, TypeAdapter

from federated_identity.common.security.keys import PublicJwks
from federated_identity.common.security.secrets import load_runtime_secrets, private_bytes
from federated_identity.common.settings.policy import validate_https_url
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.schemas.clients import (
    ClientCreate,
    ClientCredentialReplacement,
    ClientId,
    ClientRegistration,
    ClientStateChange,
    ClientUpdate,
    KeyId,
)
from federated_identity.idp.schemas.signing import (
    SigningKeyActivation,
    SigningKeyContainment,
    SigningKeyContainmentResult,
    SigningKeyInfo,
    SigningKeyRetirement,
)
from federated_identity.idp.services.provisioning import load_seeded_operator


class OperatorClientError(RuntimeError):
    pass


def client_identity(value: str) -> str:
    return TypeAdapter(ClientId).validate_python(value)


class OperatorClient:
    def __init__(
        self, issuer: str, tls: ssl.SSLContext, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        validate_https_url(issuer)
        parsed = urlsplit(issuer)
        if parsed.path not in {"", "/"} or parsed.query:
            raise ValueError("The operator issuer must be a configured HTTPS origin")
        self.issuer = issuer.rstrip("/")
        self.tls = tls
        self.transport = transport
        self.token: SecretStr | None = None

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        *,
        payload: dict[str, object] | None = None,
    ) -> httpx.Response:
        headers = (
            {"Authorization": f"Bearer {self.token.get_secret_value()}"}
            if self.token is not None
            else {}
        )
        try:
            async with httpx.AsyncClient(
                verify=self.tls,
                transport=self.transport,
                trust_env=False,
                follow_redirects=False,
                timeout=5,
            ) as client:
                response = await client.request(
                    method, f"{self.issuer}{path}", json=payload, headers=headers
                )
            if not response.is_success:
                raise OperatorClientError(
                    f"Operator request rejected (HTTP {response.status_code})"
                )
            return response
        except httpx.HTTPError as error:
            raise OperatorClientError("The verified operator service is unavailable") from error

    async def login(self, username: str, password: SecretStr) -> None:
        response = await self._request(
            "POST",
            "/admin/api/session",
            payload={"username": username, "password": password.get_secret_value()},
        )
        body = response.json()
        if body.get("token_type") != "Bearer" or not isinstance(body.get("access_token"), str):
            raise OperatorClientError("Operator login returned invalid session evidence")
        self.token = SecretStr(body["access_token"])

    async def logout(self) -> None:
        if self.token is not None:
            try:
                await self._request("DELETE", "/admin/api/session")
            finally:
                self.token = None

    async def inspect(self, client_id: str | None = None) -> list[ClientRegistration]:
        path = (
            "/admin/api/clients"
            if client_id is None
            else f"/admin/api/clients/{client_identity(client_id)}"
        )
        response = await self._request("GET", path)
        bodies = response.json()["clients"] if client_id is None else [response.json()]
        return [ClientRegistration.model_validate_json(json.dumps(body)) for body in bodies]

    async def register(self, metadata: ClientCreate) -> ClientRegistration:
        response = await self._request(
            "POST", "/admin/api/clients", payload=metadata.model_dump(mode="json")
        )
        return ClientRegistration.model_validate_json(response.content)

    async def update(self, client_id: str, metadata: ClientUpdate) -> ClientRegistration:
        response = await self._request(
            "PUT",
            f"/admin/api/clients/{client_identity(client_id)}",
            payload=metadata.model_dump(mode="json"),
        )
        return ClientRegistration.model_validate_json(response.content)

    async def disable(
        self, client_id: str, expected_version: int, *, enabled: bool = False
    ) -> ClientRegistration:
        action = "enable" if enabled else "disable"
        response = await self._request(
            "POST",
            f"/admin/api/clients/{client_identity(client_id)}/{action}",
            payload=ClientStateChange(expected_version=expected_version).model_dump(mode="json"),
        )
        return ClientRegistration.model_validate_json(response.content)

    async def replace(
        self, client_id: str, metadata: ClientCredentialReplacement
    ) -> ClientRegistration:
        response = await self._request(
            "POST",
            f"/admin/api/clients/{client_identity(client_id)}/credential",
            payload=metadata.model_dump(mode="json"),
        )
        return ClientRegistration.model_validate_json(response.content)

    async def contain_client(self, client_id: str, expected_version: int) -> ClientRegistration:
        response = await self._request(
            "POST",
            f"/admin/api/clients/{client_identity(client_id)}/contain",
            payload=ClientStateChange(expected_version=expected_version).model_dump(mode="json"),
        )
        return ClientRegistration.model_validate_json(response.content)

    async def signing_keys(self) -> list[SigningKeyInfo]:
        response = await self._request("GET", "/admin/api/signing-keys")
        return [
            SigningKeyInfo.model_validate_json(json.dumps(body)) for body in response.json()["keys"]
        ]

    async def prepare_key(self) -> SigningKeyInfo:
        response = await self._request("POST", "/admin/api/signing-keys/prepare", payload={})
        prepared = SigningKeyInfo.model_validate_json(response.content)
        publication = await self._request("GET", "/jwks.json")
        public = PublicJwks.model_validate_json(publication.content)
        if not any(key.kid == prepared.key_id for key in public.keys):
            raise OperatorClientError("Prepared signing trust was not published")
        return next(key for key in await self.signing_keys() if key.key_id == prepared.key_id)

    async def activate_key(self, key_id: str, expected_active_key_id: str) -> SigningKeyInfo:
        key_id = TypeAdapter(KeyId).validate_python(key_id)
        request = SigningKeyActivation(expected_active_key_id=expected_active_key_id)
        response = await self._request(
            "POST",
            f"/admin/api/signing-keys/{key_id}/activate",
            payload=request.model_dump(mode="json"),
        )
        return SigningKeyInfo.model_validate_json(response.content)

    async def retire_key(self, key_id: str, expected_verification_deadline: int) -> SigningKeyInfo:
        key_id = TypeAdapter(KeyId).validate_python(key_id)
        request = SigningKeyRetirement(
            expected_verification_deadline=expected_verification_deadline
        )
        response = await self._request(
            "POST",
            f"/admin/api/signing-keys/{key_id}/retire",
            payload=request.model_dump(mode="json"),
        )
        return SigningKeyInfo.model_validate_json(response.content)

    async def contain_key(
        self, key_id: str, replacement_key_id: str, expected_active_key_id: str
    ) -> SigningKeyContainmentResult:
        key_id = TypeAdapter(KeyId).validate_python(key_id)
        request = SigningKeyContainment(
            replacement_key_id=replacement_key_id, expected_active_key_id=expected_active_key_id
        )
        response = await self._request(
            "POST",
            f"/admin/api/signing-keys/{key_id}/contain",
            payload=request.model_dump(mode="json"),
        )
        return SigningKeyContainmentResult.model_validate_json(response.content)


def install_operator_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    operator = commands.add_parser(
        "operator", help="Authenticated live IDP client and signing-key management"
    )
    operator.add_argument("--issuer", required=True)
    operator.add_argument("--ca-file", type=Path, required=True)
    operator.add_argument("--username", default="operator")
    credentials = operator.add_mutually_exclusive_group()
    credentials.add_argument("--password-file", type=Path)
    credentials.add_argument(
        "--provisioned", action="store_true", help="Read private IDP initial operator provisioning"
    )
    actions = operator.add_subparsers(dest="operator_action", required=True)
    registration = actions.add_parser("register")
    registration.add_argument("--metadata", type=Path, required=True)
    inspection = actions.add_parser("inspect")
    inspection.add_argument("--client-id")
    update = actions.add_parser("update")
    update.add_argument("--client-id", required=True)
    update.add_argument("--metadata", type=Path, required=True)
    replacement = actions.add_parser("replace-credentials")
    replacement.add_argument("--client-id", required=True)
    replacement.add_argument("--metadata", type=Path, required=True)
    for action in ("disable", "enable", "contain-client"):
        parser = actions.add_parser(action)
        parser.add_argument("--client-id", required=True)
        parser.add_argument("--expected-version", type=int, required=True)
    actions.add_parser("keys-inspect")
    actions.add_parser("key-prepare")
    activate = actions.add_parser("key-activate")
    activate.add_argument("--key-id", required=True)
    activate.add_argument("--expected-active-key-id", required=True)
    retire = actions.add_parser("key-retire")
    retire.add_argument("--key-id", required=True)
    retire.add_argument("--expected-verification-deadline", type=int, required=True)
    contain = actions.add_parser("key-contain")
    contain.add_argument("--key-id", required=True)
    contain.add_argument("--replacement-key-id", required=True)
    contain.add_argument("--expected-active-key-id", required=True)


def operator_credentials(settings: RuntimeSettings) -> dict[str, str]:
    if settings.service_id != ServiceId.IDP:
        raise ValueError("Operator provisioning belongs only to the private IDP volume")
    assets = load_runtime_secrets(settings)
    credential = load_seeded_operator(settings.secrets_directory, assets.envelope)
    return {"username": credential.username, "password": credential.password.get_secret_value()}


def client_metadata(settings: RuntimeSettings) -> ClientCreate:
    if settings.service_id == ServiceId.IDP:
        raise ValueError("Public client metadata belongs to an SP runtime")
    assets = load_runtime_secrets(settings)
    return ClientCreate(
        client_id=settings.client_id,
        redirect_uris=(settings.redirect_uri,),
        public_key_pem=assets.signer.public_pem(),
        key_id=assets.signer.kid,
        post_logout_redirect_uris=(f"{settings.public_url}/",),
        backchannel_logout_uri=f"{settings.public_url}/backchannel-logout",
    )


async def run_operator(arguments: argparse.Namespace) -> dict[str, object]:
    if arguments.provisioned:
        credential = await asyncio.to_thread(operator_credentials, RuntimeSettings())
        if arguments.username != credential["username"]:
            raise ValueError("Operator username does not match private provisioning")
        password = SecretStr(credential["password"])
    elif arguments.password_file is not None:
        password = SecretStr(
            (await asyncio.to_thread(private_bytes, arguments.password_file))
            .decode("utf-8")
            .rstrip("\r\n")
        )
    else:
        password = SecretStr(await asyncio.to_thread(getpass.getpass, "Operator password: "))
    tls = await asyncio.to_thread(ssl.create_default_context, cafile=str(arguments.ca_file))
    client = OperatorClient(arguments.issuer, tls)
    await client.login(arguments.username, password)
    try:
        action = arguments.operator_action
        if action == "keys-inspect":
            return {"keys": [key.model_dump(mode="json") for key in await client.signing_keys()]}
        if action == "contain-client":
            return (
                await client.contain_client(arguments.client_id, arguments.expected_version)
            ).model_dump(mode="json")
        if action == "key-contain":
            return (
                await client.contain_key(
                    arguments.key_id, arguments.replacement_key_id, arguments.expected_active_key_id
                )
            ).model_dump(mode="json")
        if action == "key-prepare":
            return (await client.prepare_key()).model_dump(mode="json")
        if action == "key-activate":
            return (
                await client.activate_key(arguments.key_id, arguments.expected_active_key_id)
            ).model_dump(mode="json")
        if action == "key-retire":
            return (
                await client.retire_key(arguments.key_id, arguments.expected_verification_deadline)
            ).model_dump(mode="json")
        if action == "inspect":
            records = await client.inspect(arguments.client_id)
            return {"clients": [record.model_dump(mode="json") for record in records]}
        if action in {"register", "update", "replace-credentials"}:
            raw = await asyncio.to_thread(arguments.metadata.read_bytes)
            if len(raw) > 16384:
                raise ValueError("Client metadata exceeds the bounded profile")
            if action == "register":
                record = await client.register(ClientCreate.model_validate_json(raw))
            elif action == "update":
                record = await client.update(
                    arguments.client_id, ClientUpdate.model_validate_json(raw)
                )
            else:
                record = await client.replace(
                    arguments.client_id, ClientCredentialReplacement.model_validate_json(raw)
                )
        else:
            record = await client.disable(
                arguments.client_id, arguments.expected_version, enabled=action == "enable"
            )
        return record.model_dump(mode="json")
    finally:
        await client.logout()
