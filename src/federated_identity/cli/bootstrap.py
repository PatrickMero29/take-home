"""Idempotent, owner-scoped local PKI and per-service secret provisioning."""

import fcntl
import ipaddress
import json
import os
import secrets
import stat
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import SecretBytes

from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.secrets import (
    EncryptionBinding,
    EnvelopeCipher,
    load_envelope,
    private_bytes,
)
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.services.provisioning import (
    encrypt_seeded_operator,
    encrypt_seeded_totps,
    encrypt_seeded_users,
    generate_seeded_operator,
    generate_seeded_totps,
    generate_seeded_users,
    load_seeded_operator,
    load_seeded_totps,
    load_seeded_users,
)

SERVICE_BUNDLE = frozenset(
    {
        "database.password",
        "encryption.key",
        "identity.key",
        "identity.password",
        "identity.kid",
        "identity.pub",
        "server.key",
        "server.crt",
        "ca.crt",
        "tls.password",
    }
)


def require_complete_existing_bundle(directory: Path, names: frozenset[str]) -> None:
    present = {
        name for name in names if (directory / name).exists() or (directory / name).is_symlink()
    }
    if present and present != names:
        raise RuntimeError(f"Incomplete existing secret bundle requires recovery: {directory.name}")
    for name in present:
        if not stat.S_ISREG((directory / name).lstat().st_mode):
            raise RuntimeError("Secret provisioning refuses non-regular asset files")


def write_new(path: Path, data: bytes, *, mode: int = 0o600, uid: int | None = None) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if uid is not None:
        os.chown(path, uid, uid)


def ensure_bundle(
    directory: Path,
    values: Mapping[str, bytes],
    *,
    public: frozenset[str] = frozenset(),
    uid: int | None = None,
) -> bool:
    present = [name for name in values if (directory / name).exists()]
    if present:
        if len(present) != len(values):
            raise RuntimeError(f"Incomplete secret bundle requires recovery: {directory.name}")
        for name in values:
            info = (directory / name).lstat()
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Secret provisioning refuses non-regular asset files")
        return False
    for name, value in values.items():
        write_new(directory / name, value, mode=0o644 if name in public else 0o600, uid=uid)
    return True


def private_pem(key: rsa.RSAPrivateKey, password: bytes | None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def authority(directory: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    if (directory / "authority.key").exists():
        key = serialization.load_pem_private_key(
            private_bytes(directory / "authority.key"),
            password=private_bytes(directory / "authority.password"),
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("The local CA requires its original RSA private key")
        return key, x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Federation local development CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    password = secrets.token_urlsafe(32).encode("ascii")
    ensure_bundle(
        directory,
        {
            "authority.key": private_pem(key, password),
            "authority.password": password,
            "ca.crt": certificate.public_bytes(serialization.Encoding.PEM),
        },
        public=frozenset({"ca.crt"}),
    )
    return key, certificate


def server_bundle(
    directory: Path,
    hostname: str,
    ca_key: rsa.RSAPrivateKey,
    ca: x509.Certificate,
    *,
    uid: int | None = None,
    postgres: bool = False,
) -> None:
    if (directory / "server.key").exists():
        required = {"server.key", "server.crt", "ca.crt"}
        if not postgres:
            required.add("tls.password")
        if not all((directory / name).is_file() for name in required):
            raise RuntimeError("An incomplete TLS bundle must not be regenerated silently")
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    names: list[x509.GeneralName] = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    password = None if postgres else secrets.token_urlsafe(32).encode("ascii")
    bundle = {
        "server.key": private_pem(key, password),
        "server.crt": certificate.public_bytes(serialization.Encoding.PEM),
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
    }
    if password is not None:
        bundle["tls.password"] = password
    # PostgreSQL's TLS key is owner-private and readable only by its OS user.
    # Application TLS and identity keys are encrypted PKCS#8. No application
    # receives the CA private key or the PostgreSQL secret volume.
    ensure_bundle(directory, bundle, public=frozenset({"server.crt", "ca.crt"}), uid=uid)


def bootstrap_assets(
    root: Path,
    *,
    app_uid: int | None = None,
    postgres_uid: int | None = None,
    public_ports: Mapping[ServiceId, int] | None = None,
) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    directories = {name: root / name for name in ("authority", "postgres", *ServiceId)}
    for directory in directories.values():
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    with (directories["authority"] / "bootstrap.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_complete_existing_bundle(
            directories["authority"], frozenset({"authority.key", "authority.password", "ca.crt"})
        )
        require_complete_existing_bundle(
            directories["postgres"],
            frozenset({"admin.password", "server.key", "server.crt", "ca.crt"}),
        )
        for service in ServiceId:
            require_complete_existing_bundle(directories[service], SERVICE_BUNDLE)
            if (directories[service] / "bundle.complete").exists():
                expected = SERVICE_BUNDLE | {"encryption.check", "bundle.complete"}
                if service == ServiceId.IDP:
                    expected = expected | {"seed-users.enc"}
                    marker = private_bytes(directories[service] / "bundle.complete")
                    if marker in {b"runtime-secret-bundle-v2", b"runtime-secret-bundle-v3"}:
                        expected = expected | {"seed-operator.enc"}
                        if marker == b"runtime-secret-bundle-v3":
                            expected = expected | {"seed-totp.enc"}
                    elif marker != b"runtime-secret-bundle-v1":
                        raise RuntimeError("The IDP secret bundle has an unsupported version")
                require_complete_existing_bundle(directories[service], frozenset(expected))
        ca_key, ca = authority(directories["authority"])
        for service in ServiceId:
            directory = directories[service]
            if not (directory / "database.password").exists():
                write_new(
                    directory / "database.password",
                    secrets.token_urlsafe(32).encode("ascii"),
                    uid=app_uid,
                )
            if not (directory / "encryption.key").exists():
                write_new(directory / "encryption.key", Fernet.generate_key(), uid=app_uid)
            if not (directory / "encryption.check").exists():
                cipher = EnvelopeCipher.from_key(
                    SecretBytes(private_bytes(directory / "encryption.key"))
                )
                binding = EncryptionBinding(service_id=service, key_id=str(uuid.uuid4()))
                write_new(
                    directory / "encryption.check",
                    cipher.encrypt(binding.model_dump(mode="json"), purpose="runtime-key-check"),
                    uid=app_uid,
                )
            envelope, _ = load_envelope(directory, service)
            if not (directory / "identity.key").exists():
                key = SigningKey.generate()
                password = secrets.token_urlsafe(32)
                ensure_bundle(
                    directory,
                    {
                        "identity.key": key.key.as_pem(private=True, password=password),
                        "identity.password": password.encode("ascii"),
                        "identity.kid": key.kid.encode("ascii"),
                        "identity.pub": key.public_pem().encode("ascii"),
                    },
                    public=frozenset({"identity.kid", "identity.pub"}),
                    uid=app_uid,
                )
            elif not all(
                (directory / name).is_file()
                for name in ("identity.password", "identity.kid", "identity.pub")
            ):
                raise RuntimeError(
                    "Identity provisioning refuses an incomplete existing key bundle"
                )
            server_bundle(directory, service.hostname, ca_key, ca, uid=app_uid)
            if service == ServiceId.IDP:
                seed_path = directory / "seed-users.enc"
                if not seed_path.exists():
                    write_new(
                        seed_path,
                        encrypt_seeded_users(generate_seeded_users(), envelope),
                        uid=app_uid,
                    )
                else:
                    load_seeded_users(directory, envelope)
                operator_path = directory / "seed-operator.enc"
                if not operator_path.exists():
                    write_new(
                        operator_path,
                        encrypt_seeded_operator(generate_seeded_operator(), envelope),
                        uid=app_uid,
                    )
                else:
                    load_seeded_operator(directory, envelope)
                users = load_seeded_users(directory, envelope)
                totp_path = directory / "seed-totp.enc"
                if not totp_path.exists():
                    write_new(
                        totp_path,
                        encrypt_seeded_totps(generate_seeded_totps(users), envelope),
                        uid=app_uid,
                    )
                else:
                    totps = load_seeded_totps(directory, envelope)
                    if {value.subject for value in totps.credentials} != {
                        user.subject for user in users.users
                    }:
                        raise RuntimeError("Seeded TOTP provisioning does not match stable users")
            if not (directory / "bundle.complete").exists():
                marker = (
                    b"runtime-secret-bundle-v3"
                    if service == ServiceId.IDP
                    else b"runtime-secret-bundle-v1"
                )
                write_new(directory / "bundle.complete", marker, uid=app_uid)
            elif service == ServiceId.IDP and private_bytes(directory / "bundle.complete") in {
                b"runtime-secret-bundle-v1",
                b"runtime-secret-bundle-v2",
            }:
                # Upgrade once under the bootstrap lock; v3 requires established
                # operator/TOTP custody rather than silently recreating missing factors.
                upgrade = directory / "bundle.complete.upgrade"
                if upgrade.exists():
                    raise RuntimeError("An incomplete secret-bundle upgrade requires recovery")
                write_new(upgrade, b"runtime-secret-bundle-v3", uid=app_uid)
                os.replace(upgrade, directory / "bundle.complete")
            if app_uid is not None:
                os.chown(directory, app_uid, app_uid)
        postgres = directories["postgres"]
        if not (postgres / "admin.password").exists():
            write_new(
                postgres / "admin.password",
                secrets.token_urlsafe(32).encode("ascii"),
                uid=postgres_uid,
            )
        server_bundle(postgres, "postgres", ca_key, ca, uid=postgres_uid, postgres=True)
        write_registration_manifest(directories, app_uid, public_ports=public_ports)
        if postgres_uid is not None:
            os.chown(postgres, postgres_uid, postgres_uid)


def write_registration_manifest(
    directories: dict[str, Path],
    uid: int | None,
    *,
    public_ports: Mapping[ServiceId, int] | None = None,
) -> None:
    target = directories["idp"] / "clients.json"
    if target.exists():
        return
    clients = []
    for service in (ServiceId.SP_A, ServiceId.SP_B):
        directory = directories[service]
        port = public_ports[service] if public_ports is not None else service.default_port
        clients.append(
            {
                "client_id": service.value,
                "redirect_uris": [f"https://{service.hostname}:{port}/auth/callback"],
                "post_logout_redirect_uris": [f"https://{service.hostname}:{port}/"],
                "backchannel_logout_uri": f"https://{service.hostname}:{port}/backchannel-logout",
                "public_key_pem": (directory / "identity.pub").read_text(encoding="ascii"),
                "key_id": (directory / "identity.kid").read_text(encoding="ascii"),
                "enabled": True,
            }
        )
    write_new(target, json.dumps(clients, indent=2).encode("utf-8"), mode=0o644, uid=uid)
