from __future__ import annotations

import tomllib
from pathlib import Path


def test_runtime_package_uses_strict_pep_639_metadata() -> None:
    package_root = Path(__file__).parents[2] / "packages" / "runtime"
    metadata = tomllib.loads((package_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata["project"]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE", "NOTICE"]
    assert project["readme"] == "README.md"
    for name in ("LICENSE", "NOTICE", "README.md"):
        assert (package_root / name).is_file()
