import hashlib
from pathlib import Path

import pyotp
import pytest
from cryptography.fernet import InvalidToken
from pydantic import SecretStr, ValidationError

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.security.totp import TotpEngine
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId


def settings(directory: Path, service: ServiceId = ServiceId.IDP) -> RuntimeSettings:
    return RuntimeSettings(
        service_id=service,
        public_url=f"https://{service.hostname}:{service.default_port}",
        listen_port=service.default_port,
        secrets_directory=directory / service.value,
    )


def test_idempotent_assets_separate_private_identity_keys_and_encryption(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    one = load_runtime_secrets(settings(tmp_path))
    two = load_runtime_secrets(settings(tmp_path, ServiceId.SP_A))
    assert one.signer.kid != two.signer.kid
    assert one.signer.public_pem() != two.signer.public_pem()
    encrypted_key = (tmp_path / "idp" / "identity.key").read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in encrypted_key
    before = hashlib.sha256(encrypted_key).hexdigest()
    bootstrap_assets(tmp_path)
    assert hashlib.sha256((tmp_path / "idp" / "identity.key").read_bytes()).hexdigest() == before
    ciphertext = one.envelope.encrypt({"private": "test payload"}, purpose="browser-session")
    expected = {"private": "test payload"}
    assert one.envelope.decrypt(ciphertext, purpose="browser-session") == expected
    with pytest.raises(InvalidToken):
        one.envelope.decrypt(ciphertext, purpose="logout-delivery")
    with pytest.raises(InvalidToken):
        two.envelope.decrypt(ciphertext, purpose="browser-session")


def test_runtime_settings_enforce_distinct_https_service_origins(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        RuntimeSettings(
            service_id=ServiceId.SP_A, public_url="https://idp.localhost:8444", listen_port=8444
        )
    with pytest.raises(ValidationError):
        RuntimeSettings(
            service_id=ServiceId.SP_A, public_url="http://sp-a.localhost:8444", listen_port=8444
        )


def test_secret_permissions_and_wrong_password_fail_closed(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    password = tmp_path / "sp-a" / "identity.password"
    password.write_text("wrong password", encoding="ascii")
    with pytest.raises(ValueError):
        load_runtime_secrets(settings(tmp_path, ServiceId.SP_A))
    password.chmod(0o644)
    with pytest.raises(ValueError, match="owner-private"):
        load_runtime_secrets(settings(tmp_path, ServiceId.SP_A))


def test_totp_adapter_matches_bounded_counter_without_granting_assurance() -> None:
    secret = SecretStr(pyotp.random_base32())
    now = 1800000000
    code = SecretStr(pyotp.TOTP(secret.get_secret_value()).at(now))
    engine = TotpEngine()
    assert engine.matched_counter(secret, code, now=now) == now // 30
    assert engine.matched_counter(secret, code, now=now + 120) is None
    assert engine.matched_counter(secret, SecretStr("not an OTP"), now=now) is None
