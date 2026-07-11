from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "packages" / "sdk"


def test_sdk_package_carries_core_license_notice_and_pinned_protocol_dependency() -> None:
    for name in ("LICENSE", "NOTICE"):
        assert (PACKAGE / name).read_text(encoding="utf-8").rstrip("\n") == (
            ROOT / name
        ).read_text(encoding="utf-8").rstrip("\n")
    metadata = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["license"] == "Apache-2.0"
    assert metadata["project"]["license-files"] == ["LICENSE", "NOTICE"]
    assert metadata["project"]["dependencies"] == ["faultloom-protocol==0.1.0"]
    assert "entry-points" not in metadata["project"]
