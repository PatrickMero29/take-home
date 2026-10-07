"""Verification-only process: explicitly inject an encrypted, persisted fixture event."""

import argparse
import asyncio
import json
from pathlib import Path

from pydantic import SecretStr

from federated_identity.cli.probe_runtime import FixturePrincipalProvider
from federated_identity.cli.service import serve
from federated_identity.common.security.secrets import load_runtime_secrets, private_bytes
from federated_identity.common.settings.policy import FrozenModel
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.schemas.models import AuthenticatedPrincipal


class PrincipalFixture(FrozenModel):
    principal: AuthenticatedPrincipal
    proof: SecretStr


def load_fixture(settings: RuntimeSettings, path: Path) -> PrincipalFixture:
    if settings.service_id != ServiceId.IDP:
        raise ValueError("The principal verification fixture can only run an IDP")
    assets = load_runtime_secrets(settings)
    payload = assets.envelope.decrypt(private_bytes(path), purpose="phase0-principal-fixture")
    return PrincipalFixture.model_validate_json(json.dumps(payload))


async def run(path: Path) -> None:
    settings = RuntimeSettings()
    fixture = await asyncio.to_thread(load_fixture, settings, path)
    await serve(
        settings, principal_provider=FixturePrincipalProvider(fixture.proof, fixture.principal)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    arguments = parser.parse_args()
    asyncio.run(run(arguments.fixture))


if __name__ == "__main__":
    main()
