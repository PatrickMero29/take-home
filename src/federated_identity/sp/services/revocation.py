"""Authenticated, verified-HTTPS introspection adapter with fail-closed failure semantics."""

import json
import ssl
from collections.abc import Callable
from http import HTTPStatus

import httpx2 as httpx
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from pydantic import BaseModel, ConfigDict, JsonValue, SecretStr, ValidationError

from federated_identity.common.security.contracts import (
    GrantCheckSettings,
    GrantStatus,
    GrantUnavailable,
    LogoutTokenStatus,
)
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.model import GrantSnapshot, LoginEvidence
from federated_identity.common.settings.policy import SIGNING_ALGORITHM, Clock


class IntrospectionResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore", hide_input_in_errors=True)

    active: bool
    client_id: str | None = None
    sub: str | None = None
    exp: int | None = None
    context: dict[str, JsonValue] | None = None
    credential_evidence: dict[str, JsonValue] | None = None


class AuthenticatedGrantChecker:
    def __init__(
        self,
        settings: GrantCheckSettings,
        signer: SigningKey,
        tls: ssl.SSLContext,
        clock: Clock,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.signer = signer
        self.tls = tls
        self.clock = clock
        self.transport = transport

    async def check_logout(self, token: SecretStr) -> bool:
        endpoint = f"{self.settings.issuer}/logout/introspect"
        now = self.clock.now()
        sign: Callable[..., str] = private_key_jwt_sign
        assertion = sign(
            self.signer.key,
            client_id=self.settings.client_id,
            token_endpoint=endpoint,
            alg=SIGNING_ALGORITHM,
            claims={"iat": now, "exp": now + self.settings.policy.assertion_ttl_seconds},
            header={"kid": self.signer.kid},
        )
        try:
            async with httpx.AsyncClient(
                verify=self.tls,
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                async with client.stream(
                    "POST",
                    endpoint,
                    data={
                        "token": token.get_secret_value(),
                        "client_assertion_type": (
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        ),
                        "client_assertion": assertion,
                    },
                ) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > 1024:
                            raise ValueError("Logout authority response exceeds its bound")
                        body.extend(chunk)
                    return LogoutTokenStatus.model_validate_json(body).active
        except (httpx.HTTPError, ValidationError, ValueError) as error:
            raise GrantUnavailable("Authoritative logout trust is unavailable") from error

    async def revoke(self, token: SecretStr) -> None:
        endpoint = self.settings.revocation_endpoint
        now = self.clock.now()
        sign: Callable[..., str] = private_key_jwt_sign
        assertion = sign(
            self.signer.key,
            client_id=self.settings.client_id,
            token_endpoint=endpoint,
            alg=SIGNING_ALGORITHM,
            claims={"iat": now, "exp": now + self.settings.policy.assertion_ttl_seconds},
            header={"kid": self.signer.kid},
        )
        try:
            async with httpx.AsyncClient(
                verify=self.tls,
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    endpoint,
                    data={
                        "token": token.get_secret_value(),
                        "token_type_hint": "access_token",
                        "client_assertion_type": (
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        ),
                        "client_assertion": assertion,
                    },
                )
                response.raise_for_status()
                if response.status_code != HTTPStatus.OK:
                    raise ValueError("Revocation requires a successful endpoint acknowledgement")
        except (httpx.HTTPError, ValueError) as error:
            raise GrantUnavailable("The authoritative revocation service is unavailable") from error

    async def check(self, token: SecretStr) -> GrantStatus:
        endpoint = self.settings.introspection_endpoint
        now = self.clock.now()
        sign: Callable[..., str] = private_key_jwt_sign
        assertion = sign(
            self.signer.key,
            client_id=self.settings.client_id,
            token_endpoint=endpoint,
            alg=SIGNING_ALGORITHM,
            claims={"iat": now, "exp": now + self.settings.policy.assertion_ttl_seconds},
            header={"kid": self.signer.kid},
        )
        try:
            async with httpx.AsyncClient(
                verify=self.tls,
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    endpoint,
                    data={
                        "token": token.get_secret_value(),
                        "client_assertion_type": (
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        ),
                        "client_assertion": assertion,
                    },
                )
                response.raise_for_status()
                parsed = IntrospectionResponse.model_validate(response.json())
        except (httpx.HTTPError, ValidationError, ValueError) as error:
            raise GrantUnavailable("The authoritative grant service is unavailable") from error
        checked_at = self.clock.now()
        if parsed.active and (
            parsed.client_id != self.settings.client_id
            or parsed.sub is None
            or parsed.exp is None
            or parsed.exp <= checked_at
        ):
            raise GrantUnavailable(
                "The grant response lacks recipient-bound authorization evidence"
            )
        context: GrantSnapshot | None = None
        credential_evidence: LoginEvidence | None = None
        if parsed.active:
            try:
                if parsed.context is None:
                    raise ValueError("Missing authoritative lineage")
                context = GrantSnapshot.model_validate_json(json.dumps(parsed.context))
                if parsed.credential_evidence is not None:
                    credential_evidence = LoginEvidence.model_validate_json(
                        json.dumps(parsed.credential_evidence)
                    )
                    if (
                        credential_evidence.client_id != self.settings.client_id
                        or credential_evidence.authentication != context.authentication
                    ):
                        raise ValueError("Renewal evidence is not bound to current authority")
                if (
                    context.grant.client_id != parsed.client_id
                    or context.authentication.subject.subject != parsed.sub
                    or context.authentication.subject.issuer != self.settings.issuer
                    or context.grant.revoked_at is not None
                    or context.family.revoked_at is not None
                    or parsed.exp is None
                    or not checked_at
                    < parsed.exp
                    <= min(
                        context.grant.expires_at,
                        context.family.expires_at,
                        context.session_expires_at,
                    )
                ):
                    raise ValueError("Inconsistent authoritative lineage")
            except (ValueError, ValidationError) as error:
                raise GrantUnavailable("The grant response has invalid security lineage") from error
        return GrantStatus(
            active=parsed.active,
            client_id=parsed.client_id,
            subject=parsed.sub,
            expires_at=parsed.exp,
            context=context,
            credential_evidence=credential_evidence,
        )
