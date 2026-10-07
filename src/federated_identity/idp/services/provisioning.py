"""Owner-private, encrypted seeded credentials for idempotent local deployment."""

import json
import secrets
import uuid
from pathlib import Path

import pyotp
from pydantic import JsonValue, SecretStr

from federated_identity.common.security.passwords import hash_password
from federated_identity.common.security.secrets import EnvelopeCipher, private_bytes
from federated_identity.idp.schemas.mfa import SeededTotp, SeededTotps
from federated_identity.idp.schemas.operator import SeededOperator
from federated_identity.idp.schemas.users import SeededUser, SeededUsers


def generate_seeded_users() -> SeededUsers:
    users = []
    for username in ("alice", "bob"):
        password = SecretStr(secrets.token_urlsafe(32))
        users.append(
            SeededUser(
                subject=str(uuid.uuid4()),
                username=username,
                password=password,
                password_hash=hash_password(password),
            )
        )
    return SeededUsers(users=tuple(users))


def encrypt_seeded_users(users: SeededUsers, envelope: EnvelopeCipher) -> bytes:
    payload: dict[str, JsonValue] = {
        "users": [
            {
                "subject": user.subject,
                "username": user.username,
                "enabled": user.enabled,
                "password": user.password.get_secret_value(),
                "password_hash": user.password_hash.get_secret_value(),
            }
            for user in users.users
        ]
    }
    return envelope.encrypt(payload, purpose="seeded-user-provisioning")


def load_seeded_users(directory: Path, envelope: EnvelopeCipher) -> SeededUsers:
    payload = envelope.decrypt(
        private_bytes(directory / "seed-users.enc"), purpose="seeded-user-provisioning"
    )
    return SeededUsers.model_validate_json(json.dumps(payload))


def generate_seeded_totps(users: SeededUsers) -> SeededTotps:
    return SeededTotps(
        credentials=tuple(
            SeededTotp(subject=user.subject, secret=SecretStr(pyotp.random_base32()))
            for user in users.users
        )
    )


def encrypt_seeded_totps(values: SeededTotps, envelope: EnvelopeCipher) -> bytes:
    return envelope.encrypt(
        {
            "credentials": [
                {"subject": value.subject, "secret": value.secret.get_secret_value()}
                for value in values.credentials
            ]
        },
        purpose="seeded-totp-provisioning",
    )


def load_seeded_totps(directory: Path, envelope: EnvelopeCipher) -> SeededTotps:
    payload = envelope.decrypt(
        private_bytes(directory / "seed-totp.enc"), purpose="seeded-totp-provisioning"
    )
    return SeededTotps.model_validate_json(json.dumps(payload))


def generate_seeded_operator() -> SeededOperator:
    password = SecretStr(secrets.token_urlsafe(32))
    return SeededOperator(
        operator_id=str(uuid.uuid4()),
        username="operator",
        password=password,
        password_hash=hash_password(password),
    )


def encrypt_seeded_operator(operator: SeededOperator, envelope: EnvelopeCipher) -> bytes:
    payload: dict[str, JsonValue] = {
        "operator_id": operator.operator_id,
        "username": operator.username,
        "password": operator.password.get_secret_value(),
        "password_hash": operator.password_hash.get_secret_value(),
        "enabled": operator.enabled,
        "credential_version": operator.credential_version,
        "permissions": [permission.value for permission in operator.permissions],
    }
    return envelope.encrypt(payload, purpose="operator-provisioning")


def load_seeded_operator(directory: Path, envelope: EnvelopeCipher) -> SeededOperator:
    payload = envelope.decrypt(
        private_bytes(directory / "seed-operator.enc"), purpose="operator-provisioning"
    )
    return SeededOperator.model_validate_json(json.dumps(payload))
