"""The documented redirected CA export must contain only certificate bytes."""

import os
import subprocess
from pathlib import Path


def test_make_export_ca_does_not_prefix_the_certificate_with_its_recipe(tmp_path: Path) -> None:
    certificate = "-----BEGIN CERTIFICATE-----\npublic-test-ca\n-----END CERTIFICATE-----\n"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\nprintf '%s\\n' '-----BEGIN CERTIFICATE-----' "
        "'public-test-ca' '-----END CERTIFICATE-----'\n",
        encoding="ascii",
    )
    docker.chmod(0o700)
    result = subprocess.run(
        ["make", "--no-print-directory", "export-ca"],
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"},
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == certificate
