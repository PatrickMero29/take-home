"""Shared role-owned PostgreSQL runtime with an injected clock for fast lifecycle acceptance."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from html.parser import HTMLParser
from http import HTTPStatus

import httpx2 as httpx
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from fastapi import FastAPI

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.login_probe import credential_challenge, seeded_user, submit_password
from federated_identity.cli.phase0 import process_settings
from federated_identity.cli.service import build_application
from federated_identity.common.security.model import LifecyclePolicy
from federated_identity.common.security.secrets import RuntimeSecrets, load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.schemas.users import SeededUser
from federated_identity.sp.protocol.oidc import AuthorizationTransaction
from federated_identity.sp.schemas.components import SpComponents
from tests.helpers import ASSERTION_TYPE, MutableClock, callback_code


class RoutedApplications(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.apps: dict[str, FastAPI] = {}
        self.unavailable: set[str] = set()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host in self.unavailable:
            raise httpx.ConnectError("Injected IDP outage", request=request)
        return await httpx.ASGITransport(app=self.apps[request.url.host]).handle_async_request(
            request
        )


class ActionForms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: dict[str, str] = {}
        self.challenge = ""
        self.label = ""
        self.in_button = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        fields = dict(attrs)
        if tag == "form":
            self.challenge, self.label = "", ""
        elif tag == "input" and fields.get("name") == "csrf":
            self.challenge = fields.get("value") or ""
        elif tag == "button":
            self.in_button = True

    def handle_data(self, data: str) -> None:
        if self.in_button:
            self.label += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "button":
            self.in_button = False
        elif tag == "form":
            self.forms[self.label] = self.challenge


def action_challenge(response: httpx.Response, label: str | None = None) -> str:
    assert response.status_code == HTTPStatus.OK
    if label is None:
        return credential_challenge(response.text).get_secret_value()
    parser = ActionForms()
    parser.feed(response.text)
    return parser.forms[label]


@dataclass
class LifecycleLab:
    stack: ArchitectureStack
    clock: MutableClock
    transport: RoutedApplications
    assets: dict[ServiceId, RuntimeSecrets]
    user: SeededUser

    def idp(self) -> IdpComponents:
        components = self.transport.apps[ServiceId.IDP.hostname].state.components
        assert isinstance(components, IdpComponents)
        return components

    def sp(self, service: ServiceId = ServiceId.SP_A) -> SpComponents:
        components = self.transport.apps[service.hostname].state.components
        assert isinstance(components, SpComponents)
        return components

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, trust_env=False, follow_redirects=False)

    async def restart(self, service: ServiceId) -> None:
        if service.hostname in self.transport.apps:
            database = (
                self.idp().oidc.database if service == ServiceId.IDP else self.sp(service).database
            )
            await database.dispose()
        self.transport.apps[service.hostname] = await build_application(
            process_settings(self.stack, service),
            self.assets[service],
            backchannel_transport=self.transport,
            clock=self.clock,
        )

    async def login(self, browser: httpx.AsyncClient) -> None:
        form = await browser.get(f"{self.stack.issuer}/login")
        assert form.status_code == HTTPStatus.OK
        response = await submit_password(browser, self.stack.issuer, form, self.user)
        assert response.status_code == HTTPStatus.SEE_OTHER

    async def sign_in(self, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A) -> str:
        start = await browser.get(f"{self.stack.origin(service)}/auth/login")
        assert start.status_code == HTTPStatus.SEE_OTHER
        authorized = await browser.get(start.headers["location"])
        assert authorized.status_code == HTTPStatus.FOUND
        callback = str(authorized.headers["location"])
        finished = await browser.get(callback)
        assert finished.status_code == HTTPStatus.SEE_OTHER
        assert (await self.account(browser, service)).status_code == HTTPStatus.OK
        return callback

    async def account(
        self, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
    ) -> httpx.Response:
        return await browser.get(f"{self.stack.origin(service)}/account")

    async def post_action(
        self, browser: httpx.AsyncClient, service: ServiceId, path: str, challenge: str
    ) -> httpx.Response:
        return await browser.post(
            f"{self.stack.origin(service)}{path}",
            headers={"Origin": self.stack.origin(service)},
            data={"csrf": challenge},
        )

    def assertion(self, service: ServiceId, endpoint: str) -> str:
        result: str = private_key_jwt_sign(
            self.assets[service].signer.key,
            client_id=service.value,
            token_endpoint=f"{self.stack.issuer}{endpoint}",
            alg="RS256",
            claims={"iat": self.clock.now(), "exp": self.clock.now() + 60},
            header={"kid": self.assets[service].signer.kid},
        )
        return result

    def token_parameters(
        self, transaction: AuthorizationTransaction, callback: str
    ) -> dict[str, str]:
        return {
            "grant_type": "authorization_code",
            "client_id": transaction.client_id,
            "code": callback_code(callback),
            "redirect_uri": transaction.redirect_uri,
            "code_verifier": transaction.verifier,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": self.assertion(ServiceId(transaction.client_id), "/token"),
        }


@asynccontextmanager
async def lifecycle_lab() -> AsyncIterator[LifecycleLab]:
    async with architecture_stack(start_applications=False) as stack:
        assets = {
            service: await asyncio.to_thread(load_runtime_secrets, process_settings(stack, service))
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B)
        }
        lab = LifecycleLab(
            stack,
            MutableClock(SystemClock().now()),
            RoutedApplications(),
            assets,
            await seeded_user(stack),
        )
        try:
            for service in assets:
                await lab.restart(service)
            yield lab
        finally:
            for service in assets:
                if service.hostname in lab.transport.apps:
                    database = (
                        lab.idp().oidc.database
                        if service == ServiceId.IDP
                        else lab.sp(service).database
                    )
                    await database.dispose()


def next_scenario(lab: LifecycleLab) -> None:
    # Fresh clients/transactions per scenario; old durable data remains available.
    lab.clock.value += 10000
    lab.transport.unavailable.clear()
    lab.idp().security.lifecycle = LifecyclePolicy()
    for service in (ServiceId.SP_A, ServiceId.SP_B):
        lab.sp(service).security.lifecycle = LifecyclePolicy()
