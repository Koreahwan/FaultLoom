from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "packages" / "protocol"


def test_protocol_package_carries_license_and_notice() -> None:
    for name in ("LICENSE", "NOTICE"):
        package_text = (PACKAGE / name).read_text(encoding="utf-8")
        root_text = (ROOT / name).read_text(encoding="utf-8")
        assert package_text.rstrip("\n") == root_text.rstrip("\n")
    metadata = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["license"] == "Apache-2.0"
    assert metadata["project"]["license-files"] == ["LICENSE", "NOTICE"]


def test_reproducible_build_verifier_is_documented_and_network_independent() -> None:
    verifier = (PACKAGE / "tools" / "verify_reproducible_wheel.py").read_text(
        encoding="utf-8"
    )
    assert "--no-deps" in verifier
    assert "--no-build-isolation" in verifier
    assert 'PIP_NO_INDEX="1"' in verifier
    assert "SOURCE_DATE_EPOCH" in verifier
    assert "TemporaryDirectory" in verifier
