"""Per-service secret custody and vetted authenticated encryption."""

import json
import ssl
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from joserfc.jwk import RSAKey
from pydantic import Field, JsonValue, SecretBytes, SecretStr, TypeAdapter, ValidationError
from sqlalchemy.engine import URL

from federated_identity.common.security.keys import SigningKey
from federated_identity.common.settings.policy import SIGNING_ALGORITHM, FrozenModel, Identifier
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId

JSON_PAYLOAD = TypeAdapter(dict[str, JsonValue])


class RuntimeSecretsError(ValueError):
    """A fixed, credential-free explanation of invalid startup secret custody."""


class EncryptionBinding(FrozenModel):
    service_id: ServiceId
    key_id: Identifier


class ClientIdentityEnvelope(FrozenModel):
    service_id: ServiceId
    kid: Identifier = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    public_pem: str = Field(min_length=100, max_length=8192)
    private_pem: str = Field(min_length=100, max_length=16384, repr=False)


def client_identity(
    directory: Path, service: ServiceId, cipher: "EnvelopeCipher", original: SigningKey
) -> SigningKey:
    path = directory / "client-identity.enc"
    if not path.exists() and not path.is_symlink():
        return original
    if service == ServiceId.IDP:
        raise RuntimeSecretsError("Client credential overrides cannot select an issuer signer")
    try:
        value = ClientIdentityEnvelope.model_validate_json(
            json.dumps(cipher.decrypt(private_bytes(path), purpose="sp-client-identity"))
        )
        if value.service_id != service:
            raise ValueError("Wrong owner")
        key = RSAKey.import_key(
            value.private_pem, parameters={"kid": value.kid, "alg": SIGNING_ALGORITHM, "use": "sig"}
        )
        signer = SigningKey(key, value.kid)
        if (
            not key.is_private
            or not 2048 <= key.public_key.key_size <= 4096
            or key.public_key.public_numbers().e != 65537
            or signer.public_pem() != value.public_pem
        ):
            raise ValueError("Mismatched identity")
        return signer
    except (InvalidToken, ValidationError, ValueError) as error:
        raise RuntimeSecretsError(
            "Persisted client credential recovery material is invalid"
        ) from error


def private_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeSecretsError(f"Missing required secret file: {path.name}") from error
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError(f"An owner-private regular secret file is required: {path.name}")
    return path.read_bytes()


@dataclass(frozen=True)
class EnvelopeCipher:
    cipher: Fernet = field(repr=False)

    @classmethod
    def from_key(cls, key: SecretBytes) -> "EnvelopeCipher":
        return cls(Fernet(key.get_secret_value()))

    def encrypt(self, payload: Mapping[str, JsonValue], *, purpose: str) -> bytes:
        value = {"purpose": purpose, "payload": dict(payload)}
        return self.cipher.encrypt(json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def decrypt(self, ciphertext: bytes, *, purpose: str) -> dict[str, JsonValue]:
        value = JSON_PAYLOAD.validate_json(self.cipher.decrypt(ciphertext))
        if value.get("purpose") != purpose or not isinstance(value.get("payload"), dict):
            raise InvalidToken
        return JSON_PAYLOAD.validate_python(value["payload"])


@dataclass(frozen=True)
class RuntimeSecrets:
    database_url: SecretStr
    signer: SigningKey = field(repr=False)
    envelope: EnvelopeCipher = field(repr=False)
    binding: EncryptionBinding
    tls_password: SecretStr
    certificate: Path
    private_key: Path
    ca_certificate: Path


def load_envelope(directory: Path, service: ServiceId) -> tuple[EnvelopeCipher, EncryptionBinding]:
    try:
        envelope = EnvelopeCipher.from_key(SecretBytes(private_bytes(directory / "encryption.key")))
        payload = envelope.decrypt(
            private_bytes(directory / "encryption.check"), purpose="runtime-key-check"
        )
        binding = EncryptionBinding.model_validate_json(json.dumps(payload))
    except RuntimeSecretsError:
        raise
    except (InvalidToken, ValidationError, ValueError) as error:
        raise RuntimeSecretsError(
            "Encryption key does not match its persisted secret binding"
        ) from error
    if binding.service_id != service:
        raise RuntimeSecretsError("Secret bundle belongs to a different application service")
    return envelope, binding


def load_runtime_secrets(settings: RuntimeSettings) -> RuntimeSecrets:
    """Called in a worker during startup, never in a request's protocol hook."""
    directory = settings.secrets_directory
    envelope, binding = load_envelope(directory, settings.service_id)
    database_password = private_bytes(directory / "database.password").decode("ascii").strip()
    signing_password = private_bytes(directory / "identity.password")
    kid = (directory / "identity.kid").read_text(encoding="ascii").strip()
    key = RSAKey.import_key(
        private_bytes(directory / "identity.key"),
        password=signing_password,
        parameters={"kid": kid, "alg": SIGNING_ALGORITHM, "use": "sig"},
    )
    if not key.is_private or key.public_key.key_size < 2048:
        raise ValueError("A private RSA identity key of at least 2048 bits is required")
    public = (directory / "identity.pub").read_text(encoding="ascii")
    if SigningKey(key, kid).public_pem() != public:
        raise RuntimeSecretsError(
            "Private identity key does not match its public registration material"
        )
    tls_password = SecretStr(private_bytes(directory / "tls.password").decode("ascii"))
    private_bytes(directory / "server.key")
    # Fail before serving if the TLS key, password or certificate are inconsistent.
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        tls.load_cert_chain(
            str(directory / "server.crt"),
            str(directory / "server.key"),
            password=tls_password.get_secret_value(),
        )
    except (ssl.SSLError, OSError) as error:
        raise RuntimeSecretsError(
            "Application TLS key and certificate bundle is invalid"
        ) from error
    url = URL.create(
        "postgresql+asyncpg",
        username=settings.service_id.role,
        password=database_password,
        host=settings.database_host,
        port=settings.database_port,
        database=settings.service_id.database,
    )
    return RuntimeSecrets(
        database_url=SecretStr(url.render_as_string(hide_password=False)),
        signer=client_identity(directory, settings.service_id, envelope, SigningKey(key, kid)),
        envelope=envelope,
        binding=binding,
        tls_password=tls_password,
        certificate=directory / "server.crt",
        private_key=directory / "server.key",
        ca_certificate=directory / "ca.crt",
    )
