"""Owner-side atomic encrypted SP credential replacement, independent of operator authority."""

import fcntl
import os
import stat

from pydantic import TypeAdapter

from federated_identity.cli.bootstrap import write_new
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.secrets import ClientIdentityEnvelope, load_runtime_secrets
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.schemas.clients import ClientCredentialReplacement, KeyId


def replace_client_key(
    settings: RuntimeSettings, *, expected_key_id: str, expected_version: int
) -> ClientCredentialReplacement:
    if settings.service_id == ServiceId.IDP:
        raise ValueError("Client recovery belongs to the owning SP")
    expected_key_id = TypeAdapter(KeyId).validate_python(expected_key_id)
    if expected_version < 1:
        raise ValueError("A current registration version is required")
    directory = settings.secrets_directory
    descriptor = os.open(
        directory / "client-identity.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "a+b") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("An owner-private credential lock is required")
        fcntl.flock(lock, fcntl.LOCK_EX)
        assets = load_runtime_secrets(settings)
        if assets.signer.kid != expected_key_id:
            raise ValueError("Client identity changed; inspect current public metadata")
        signer = SigningKey.generate()
        value = ClientIdentityEnvelope(
            service_id=settings.service_id,
            kid=signer.kid,
            public_pem=signer.public_pem(),
            private_pem=signer.key.as_pem(private=True).decode("ascii"),
        )
        encrypted = assets.envelope.encrypt(
            value.model_dump(mode="json"), purpose="sp-client-identity"
        )
        staging = directory / "client-identity.enc.new"
        # Exclusive creation preserves an unfamiliar/incomplete recovery artifact.
        write_new(staging, encrypted)
        try:
            os.replace(staging, directory / "client-identity.enc")
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if staging.exists():
                staging.unlink()
        return ClientCredentialReplacement(
            expected_version=expected_version, public_key_pem=signer.public_pem(), key_id=signer.kid
        )
