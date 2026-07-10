#!/usr/bin/env python3
"""Build faultloom-protocol twice and require byte-identical wheels."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
IGNORED_NAMES = {
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
}


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in IGNORED_NAMES or name.endswith(".egg-info") or name.endswith(".pyc")
    }


def _build_once(root: Path, label: str, environment: dict[str, str]) -> Path:
    source = root / f"source-{label}"
    output = root / f"wheel-{label}"
    shutil.copytree(PACKAGE_ROOT, source, ignore=_ignore)
    output.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(output),
            str(source),
        ],
        check=True,
        env=environment,
        stdout=subprocess.DEVNULL,
    )
    wheels = tuple(output.glob("faultloom_protocol-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {len(wheels)}")
    return wheels[0]


def main() -> int:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "946684800")
    if not source_date_epoch.isdecimal():
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    environment = os.environ.copy()
    environment.update(
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PIP_NO_INDEX="1",
        PYTHONHASHSEED="0",
        SOURCE_DATE_EPOCH=source_date_epoch,
    )
    with tempfile.TemporaryDirectory(prefix="faultloom-protocol-repro-") as temporary:
        root = Path(temporary)
        first = _build_once(root, "a", environment).read_bytes()
        second = _build_once(root, "b", environment).read_bytes()
    if first != second:
        raise RuntimeError("wheel builds are not byte-identical")
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        names = set(archive.namelist())
        for legal_file in ("LICENSE", "NOTICE"):
            if not any(name.endswith(f".dist-info/licenses/{legal_file}") for name in names):
                raise RuntimeError(f"wheel is missing {legal_file}")
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name)
        if b"License-Expression: Apache-2.0" not in metadata:
            raise RuntimeError("wheel metadata is missing the Apache-2.0 license expression")
    print(f"sha256:{hashlib.sha256(first).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
