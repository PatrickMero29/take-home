"""Architecture bootstrap and deployment commands."""

import argparse
import asyncio
import json
import ssl
from pathlib import Path

import httpx2 as httpx

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.credentials import replace_client_key
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.logout import logout_queue
from federated_identity.cli.operator import (
    client_metadata,
    install_operator_commands,
    operator_credentials,
    run_operator,
)
from federated_identity.cli.service import serve
from federated_identity.cli.totp import totp_provisioning
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.services.provisioning import load_seeded_users


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap-assets")
    bootstrap.add_argument("--state-directory", type=Path, default=Path("/state"))
    bootstrap.add_argument("--app-uid", type=int)
    bootstrap.add_argument("--postgres-uid", type=int)
    databases = commands.add_parser("initialize-databases")
    databases.add_argument("--state-directory", type=Path, default=Path("/state"))
    databases.add_argument("--database-host", default="postgres")
    databases.add_argument("--database-port", type=int, default=5432)
    commands.add_parser("serve")
    commands.add_parser("healthcheck")
    commands.add_parser("verify-architecture")
    commands.add_parser("verify-login")
    credentials = commands.add_parser("seed-credentials")
    credentials.add_argument("--username", required=True)
    totp = commands.add_parser("totp-provisioning")
    totp.add_argument("--username", required=True)
    commands.add_parser("operator-credentials")
    commands.add_parser("client-metadata")
    commands.add_parser("logout-deliveries")
    logout_retry = commands.add_parser("logout-retry")
    logout_retry.add_argument("--delivery-id", required=True)
    replacement = commands.add_parser("client-key-replace")
    replacement.add_argument("--expected-key-id", required=True)
    replacement.add_argument("--expected-version", type=int, required=True)
    install_operator_commands(commands)
    arguments = parser.parse_args()
    if arguments.command == "bootstrap-assets":
        bootstrap_assets(
            arguments.state_directory,
            app_uid=arguments.app_uid,
            postgres_uid=arguments.postgres_uid,
        )
    elif arguments.command == "initialize-databases":
        asyncio.run(
            initialize_databases(
                arguments.state_directory,
                host=arguments.database_host,
                port=arguments.database_port,
            )
        )
    elif arguments.command == "verify-architecture":
        from federated_identity.cli.architecture_probe import verify_architecture

        print(json.dumps(asyncio.run(verify_architecture()), indent=2))
    elif arguments.command == "verify-login":
        from federated_identity.cli.login_probe import verify_login

        print(json.dumps(asyncio.run(verify_login()), indent=2))
    elif arguments.command == "healthcheck":
        if not asyncio.run(healthcheck(RuntimeSettings())):
            raise SystemExit(1)
    elif arguments.command == "seed-credentials":
        print(json.dumps(seed_credentials(RuntimeSettings(), arguments.username), indent=2))
    elif arguments.command == "totp-provisioning":
        print(
            json.dumps(
                asyncio.run(totp_provisioning(RuntimeSettings(), arguments.username)), indent=2
            )
        )
    elif arguments.command == "operator-credentials":
        print(json.dumps(operator_credentials(RuntimeSettings()), indent=2))
    elif arguments.command == "client-metadata":
        print(client_metadata(RuntimeSettings()).model_dump_json(indent=2))
    elif arguments.command == "client-key-replace":
        try:
            result = replace_client_key(
                RuntimeSettings(),
                expected_key_id=arguments.expected_key_id,
                expected_version=arguments.expected_version,
            )
            print(result.model_dump_json(indent=2))
        except (ValueError, OSError, RuntimeError):
            raise SystemExit(
                "Client recovery failed; verify owner custody and current key/version"
            ) from None
    elif arguments.command in {"logout-deliveries", "logout-retry"}:
        try:
            print(
                json.dumps(
                    asyncio.run(
                        logout_queue(
                            RuntimeSettings(),
                            retry_id=arguments.delivery_id
                            if arguments.command == "logout-retry"
                            else None,
                        )
                    ),
                    indent=2,
                )
            )
        except (ValueError, OSError, RuntimeError):
            raise SystemExit(
                "Logout recovery failed; verify IDP owner custody and queue state"
            ) from None
    elif arguments.command == "operator":
        try:
            print(json.dumps(asyncio.run(run_operator(arguments)), indent=2))
        except (ValueError, OSError, RuntimeError):
            raise SystemExit(
                "Operator command failed; verify credentials, public metadata, "
                "and service availability"
            ) from None
    else:
        asyncio.run(serve(RuntimeSettings()))


def seed_credentials(settings: RuntimeSettings, username: str) -> dict[str, str]:
    """Explicit owner-side retrieval; startup, public routes and logs never reveal passwords."""
    if settings.service_id != ServiceId.IDP:
        raise ValueError("Seeded credentials belong only to the IDP's private provisioning volume")
    assets = load_runtime_secrets(settings)
    users = load_seeded_users(settings.secrets_directory, assets.envelope)
    for user in users.users:
        if user.username == username:
            return {"username": user.username, "password": user.password.get_secret_value()}
    raise ValueError("No such seeded username")


async def healthcheck(settings: RuntimeSettings) -> bool:
    context = await asyncio.to_thread(
        ssl.create_default_context, cafile=str(settings.secrets_directory / "ca.crt")
    )
    async with httpx.AsyncClient(verify=context, trust_env=False, timeout=3) as client:
        try:
            response = await client.get(f"{settings.public_url}/health/ready")
        except httpx.HTTPError:
            return False
        return response.is_success


if __name__ == "__main__":
    main()
