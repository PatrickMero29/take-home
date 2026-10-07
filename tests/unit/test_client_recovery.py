"""Owner replacement must survive restart without changing unrelated custody or leaking a key."""

import concurrent.futures
import os
import shutil
from pathlib import Path

import pytest

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.credentials import replace_client_key
from federated_identity.common.security.secrets import RuntimeSecretsError, load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from tests.unit.test_architecture import settings


@pytest.fixture(scope="module")
def recovery_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("credential-template")
    bootstrap_assets(root)
    return root


@pytest.fixture
def recovery_bundle(recovery_template: Path, tmp_path: Path) -> Path:
    shutil.copytree(recovery_template, tmp_path, dirs_exist_ok=True)
    return tmp_path


def test_owner_replacement_is_private_public_only_and_preserves_bootstrap_custody(
    recovery_bundle: Path,
) -> None:
    root = recovery_bundle
    configuration = settings(root, ServiceId.SP_A)
    original = load_runtime_secrets(configuration)
    preserved = {
        name: (root / "sp-a" / name).read_bytes()
        for name in (
            "identity.key",
            "encryption.key",
            "encryption.check",
            "database.password",
            "server.key",
        )
    }
    other = load_runtime_secrets(settings(root, ServiceId.SP_B))
    public = replace_client_key(
        configuration, expected_key_id=original.signer.kid, expected_version=2
    )
    assert public.key_id != original.signer.kid and "PRIVATE KEY" not in public.model_dump_json()
    path = root / "sp-a" / "client-identity.enc"
    encrypted = path.read_bytes()
    assert b"PRIVATE KEY" not in encrypted and b"private_pem" not in encrypted
    assert path.stat().st_mode & 0o077 == 0
    restored = load_runtime_secrets(configuration)
    assert restored.signer.kid == public.key_id
    assert restored.signer.public_pem() == public.public_key_pem
    bootstrap_assets(root)
    assert path.read_bytes() == encrypted
    assert load_runtime_secrets(configuration).signer.kid == public.key_id
    assert load_runtime_secrets(settings(root, ServiceId.SP_B)).signer.kid == other.signer.kid
    for name, value in preserved.items():
        assert (root / "sp-a" / name).read_bytes() == value
    with pytest.raises(ValueError, match="changed"):
        replace_client_key(configuration, expected_key_id=original.signer.kid, expected_version=2)
    with pytest.raises(ValueError, match="owning SP"):
        replace_client_key(settings(root), expected_key_id=public.key_id, expected_version=2)


def test_failed_atomic_install_preserves_the_previous_client_identity(
    recovery_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = settings(recovery_bundle, ServiceId.SP_A)
    original = load_runtime_secrets(configuration)

    def fail(source: Path, destination: Path) -> None:
        raise OSError("Injected atomic-install failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="Injected"):
        replace_client_key(configuration, expected_key_id=original.signer.kid, expected_version=2)
    assert load_runtime_secrets(configuration).signer.kid == original.signer.kid
    assert not (configuration.secrets_directory / "client-identity.enc.new").exists()


def test_simultaneous_owner_replacements_have_one_winner(recovery_bundle: Path) -> None:
    configuration = settings(recovery_bundle, ServiceId.SP_A)
    original = load_runtime_secrets(configuration)

    def replace() -> str | None:
        try:
            return replace_client_key(
                configuration, expected_key_id=original.signer.kid, expected_version=2
            ).key_id
        except ValueError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: replace(), range(2)))
    winners = [kid for kid in outcomes if kid is not None]
    assert len(winners) == 1 and load_runtime_secrets(configuration).signer.kid == winners[0]


@pytest.mark.parametrize("case", ["cipher", "owner", "public", "permissions", "symlink", "idp"])
def test_corrupt_or_transplanted_owner_material_fails_closed(
    recovery_bundle: Path, case: str
) -> None:
    configuration = settings(recovery_bundle, ServiceId.SP_A)
    assets = load_runtime_secrets(configuration)
    replace_client_key(configuration, expected_key_id=assets.signer.kid, expected_version=2)
    path = configuration.secrets_directory / "client-identity.enc"
    if case == "cipher":
        path.write_bytes(b"invalid encrypted identity")
    elif case in {"owner", "public"}:
        payload = assets.envelope.decrypt(path.read_bytes(), purpose="sp-client-identity")
        payload["service_id" if case == "owner" else "public_pem"] = (
            "sp-b" if case == "owner" else assets.signer.public_pem()
        )
        path.write_bytes(assets.envelope.encrypt(payload, purpose="sp-client-identity"))
    elif case == "permissions":
        path.chmod(0o644)
    elif case == "symlink":
        path.unlink()
        path.symlink_to(configuration.secrets_directory / "identity.key")
    else:
        shutil.copyfile(path, recovery_bundle / "idp" / "client-identity.enc")
        configuration = settings(recovery_bundle)
    with pytest.raises(RuntimeSecretsError):
        load_runtime_secrets(configuration)
