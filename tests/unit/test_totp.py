"""PyOTP matching and owner-private provisioning are security inputs, not assurance grants."""

from pathlib import Path

import pyotp
import pytest
from pydantic import SecretStr

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.security.totp import TotpEngine
from federated_identity.idp.services.provisioning import load_seeded_totps, load_seeded_users
from tests.unit.test_architecture import settings


@pytest.mark.parametrize("offset", [-90, -60, -30, 0, 30, 60, 90])
def test_library_codes_obey_the_bounded_drift_window(offset: int) -> None:
    secret = SecretStr(pyotp.random_base32())
    now = 1800000000
    code = SecretStr(pyotp.TOTP(secret.get_secret_value()).at(now + offset))
    match = TotpEngine().matched_counter(secret, code, now=now)
    assert match == ((now + offset) // 30 if abs(offset) <= 30 else None)


@pytest.mark.parametrize(
    "code", ["", "12345", "1234567", "\uff11\uff12\uff13\uff14\uff15\uff16", "abc123", "123 45"]
)
def test_otp_format_is_strict(code: str) -> None:
    assert (
        TotpEngine().matched_counter(
            SecretStr(pyotp.random_base32()), SecretStr(code), now=1800000000
        )
        is None
    )


def test_seeded_totp_is_encrypted_bound_preserved_and_upgraded_once(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    assets = load_runtime_secrets(settings(tmp_path))
    users = load_seeded_users(tmp_path / "idp", assets.envelope)
    values = load_seeded_totps(tmp_path / "idp", assets.envelope)
    assert {value.subject for value in values.credentials} == {user.subject for user in users.users}
    path = tmp_path / "idp" / "seed-totp.enc"
    ciphertext = path.read_bytes()
    for value in values.credentials:
        assert value.secret.get_secret_value().encode() not in ciphertext
    assert path.stat().st_mode & 0o077 == 0
    bootstrap_assets(tmp_path)
    assert path.read_bytes() == ciphertext
    # A v2 upgrade adds factors to the existing identities and preserves passwords.
    path.unlink()
    marker = tmp_path / "idp" / "bundle.complete"
    marker.write_bytes(b"runtime-secret-bundle-v2")
    original = (tmp_path / "idp" / "seed-users.enc").read_bytes()
    bootstrap_assets(tmp_path)
    assert marker.read_bytes() == b"runtime-secret-bundle-v3"
    assert (tmp_path / "idp" / "seed-users.enc").read_bytes() == original
    upgraded = path.read_bytes()
    bootstrap_assets(tmp_path)
    assert path.read_bytes() == upgraded
    path.unlink()
    with pytest.raises(RuntimeError, match="recovery"):
        bootstrap_assets(tmp_path)
