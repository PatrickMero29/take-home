import asyncio
from http import HTTPStatus
from pathlib import Path

import httpx2 as httpx
import pytest
from pydantic import SecretStr

from federated_identity.cli.probe_runtime import (
    FixturePrincipalProvider,
    create_tls_material,
    https_server,
    loopback_socket,
)
from federated_identity.common.security.model import (
    AuthenticationMethod,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.idp.api.app import create_app
from federated_identity.idp.schemas.models import AuthenticatedPrincipal, IssuanceEvidence
from federated_identity.idp.services.oidc import OidcService
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from tests.helpers import ProtocolLab

pytestmark = pytest.mark.integration


async def test_real_https_code_exchange_and_certificate_verification(
    lab: ProtocolLab, tmp_path: Path
) -> None:
    connection = loopback_socket()
    issuer = f"https://127.0.0.1:{connection.getsockname()[1]}"
    settings = lab.settings.model_copy(update={"issuer": issuer})
    security = lab.security_for(lab.database, issuer=issuer)
    _, event = await security.open_session(
        TrustedAuthentication(
            subject=SubjectIdentity(issuer=issuer, subject=lab.principal.sub),
            authenticated_at=lab.principal.auth_time,
            methods=(AuthenticationMethod.FIXTURE,),
        )
    )
    principal = AuthenticatedPrincipal.from_event(event)
    service = OidcService(settings, lab.database, lab.keys.issuer, lab.clock, security=security)
    proof = SecretStr(lab.proof_headers["Authorization"].removeprefix("Bearer "))
    app = create_app(service, principal_provider=FixturePrincipalProvider(proof, principal))
    tls = await asyncio.to_thread(create_tls_material, tmp_path)
    context = await asyncio.to_thread(tls.client_context)
    async with https_server(app, connection, tls):
        rp = OidcClient(
            RpSettings(
                issuer=issuer,
                client_id="sp-a",
                redirect_uri="https://sp-a.localhost/callback",
                policy=settings.policy,
            ),
            lab.keys.client_a,
            lab.clock,
            tls_context=context,
        )
        transaction = rp.begin()
        async with httpx.AsyncClient(verify=context, trust_env=False, timeout=5) as browser:
            response = await browser.get(
                transaction.authorization_url, headers=lab.proof_headers, follow_redirects=False
            )
            assert response.status_code == HTTPStatus.FOUND
        token, claims = await rp.exchange(transaction, response.headers["location"])
        assert claims.iss == issuer
        evidence = await lab.database.issuance_evidence(token.access_token)
        assert isinstance(evidence, IssuanceEvidence)
        assert evidence.issuance_id == claims.jti

        # A default trust store must not accept this generated private CA.
        async with httpx.AsyncClient(trust_env=False, timeout=5) as untrusted:
            with pytest.raises(httpx.ConnectError):
                await untrusted.get(f"{issuer}/health")
