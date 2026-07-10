#!/usr/bin/env python3
"""Verify a clean FaultLoom checkout and reproduce its artifacts offline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_public_tree import scan
from tools.reproducible_build import (
    BuildPolicyError,
    build_reproducibly,
    git_identity,
    load_policy,
    require_clean_checkout,
)


class VerificationError(RuntimeError):
    """A clean-checkout build invariant failed."""


def _run(command: list[str], *, root: Path, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"command failed ({' '.join(command)}): {result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def _version_from_rustc(output: str) -> str:
    fields = output.split()
    if len(fields) < 2 or fields[0] != "rustc":
        raise VerificationError(f"unexpected rustc version output: {output!r}")
    return fields[1]


def verify_toolchains(root: Path, rust_toolchain: str, environment: dict[str, str]) -> None:
    policy = load_policy(root)
    actual_python = ".".join(str(item) for item in sys.version_info[:3])
    if actual_python != policy.python_version:
        raise VerificationError(
            f"Python mismatch: expected {policy.python_version}, found {actual_python}"
        )
    rust_output = _run(
        ["rustc", f"+{rust_toolchain}", "--version"], root=root, environment=environment
    )
    actual_rust = _version_from_rustc(rust_output)
    if actual_rust != policy.rust_version:
        raise VerificationError(
            f"Rust mismatch: expected {policy.rust_version}, found {actual_rust}"
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_checksums(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    if not checksum_path.is_file():
        raise VerificationError("SHA256SUMS is missing")
    expected: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise VerificationError("malformed SHA256SUMS") from exc
        if len(digest) != 64 or name in expected or "/" in name:
            raise VerificationError("unsafe or duplicate SHA256SUMS entry")
        expected[name] = digest
    actual = {
        path.name: _sha256(path.read_bytes())
        for path in output.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if expected != actual:
        raise VerificationError("artifact checksums do not match SHA256SUMS")


def verify_source_archive(output: Path) -> None:
    archive_path = output / "faultloom-core-source.tar.gz"
    if not archive_path.is_file():
        raise VerificationError("tracked-source archive is missing")
    with tarfile.open(archive_path, "r:gz") as archive:
        names = set(archive.getnames())
        if "faultloom-core/LICENSE" not in names or "faultloom-core/NOTICE" not in names:
            raise VerificationError("source archive omits LICENSE or NOTICE")
        for member in archive.getmembers():
            if member.issym() or member.islnk() or member.name.startswith("/") or ".." in Path(
                member.name
            ).parts:
                raise VerificationError(f"unsafe source archive member: {member.name}")


def verify_wheels(output: Path) -> None:
    for wheel_path in sorted(output.glob("*.whl")):
        with zipfile.ZipFile(wheel_path) as wheel:
            names = set(wheel.namelist())
            license_names = {name for name in names if name.endswith(".dist-info/licenses/LICENSE")}
            notice_names = {name for name in names if name.endswith(".dist-info/licenses/NOTICE")}
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            if not license_names or not notice_names or len(record_names) != 1:
                raise VerificationError(f"wheel policy files or RECORD missing: {wheel_path.name}")
            record_name = record_names[0]
            rows = list(csv.reader(io.StringIO(wheel.read(record_name).decode("utf-8"))))
            recorded = {row[0] for row in rows if len(row) == 3}
            if recorded != names:
                raise VerificationError(f"wheel RECORD is incomplete: {wheel_path.name}")


def verify_metadata(output: Path) -> None:
    sbom = json.loads((output / "faultloom-core.sbom.cdx.json").read_text(encoding="utf-8"))
    provenance = json.loads(
        (output / "faultloom-core.provenance.intoto.json").read_text(encoding="utf-8")
    )
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise VerificationError("SBOM schema marker is invalid")
    subjects = provenance.get("subject")
    if provenance.get("_type") != "https://in-toto.io/Statement/v1" or not isinstance(
        subjects, list
    ):
        raise VerificationError("provenance schema marker is invalid")
    expected = {
        path.name: _sha256(path.read_bytes())
        for path in output.iterdir()
        if path.is_file()
        and path.name
        not in {
            "SHA256SUMS",
            "faultloom-core.sbom.cdx.json",
            "faultloom-core.provenance.intoto.json",
        }
    }
    observed = {
        item["name"]: item["digest"]["sha256"]
        for item in subjects
        if isinstance(item, dict)
        and isinstance(item.get("digest"), dict)
        and isinstance(item.get("name"), str)
    }
    if observed != expected:
        raise VerificationError("provenance subjects do not match built artifacts")


def _offline_environment(rust_toolchain: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "UV_OFFLINE": "1",
            "CARGO_NET_OFFLINE": "true",
            "FAULTLOOM_RUST_TOOLCHAIN": rust_toolchain,
        }
    )
    return environment


def verify(root: Path, *, rust_toolchain: str, run_tests: bool = True) -> dict[str, object]:
    root = root.resolve()
    environment = _offline_environment(rust_toolchain)
    require_clean_checkout(root)
    verify_toolchains(root, rust_toolchain, environment)
    violations = scan(root)
    if violations:
        raise VerificationError(f"public tree gate failed with {len(violations)} violation(s)")
    if run_tests:
        _run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_reproducible_build.py",
            ],
            root=root,
            environment=environment,
        )
    epoch_raw = _run(
        ["git", "show", "-s", "--format=%ct", "HEAD"], root=root, environment=environment
    )
    try:
        epoch = int(epoch_raw)
    except ValueError as exc:
        raise VerificationError("Git commit time is not an integer") from exc
    with tempfile.TemporaryDirectory(prefix="faultloom-verified-") as raw_output:
        output = Path(raw_output)
        manifest = build_reproducibly(root, output, epoch)
        verify_checksums(output)
        verify_source_archive(output)
        verify_wheels(output)
        verify_metadata(output)
    require_clean_checkout(root)
    return {
        "ok": True,
        "source": git_identity(root),
        "source_date_epoch": epoch,
        "artifacts": manifest,
        "network": "offline",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--rust-toolchain",
        default=os.environ.get("FAULTLOOM_RUST_TOOLCHAIN", "stable"),
        help="preinstalled rustup alias to inspect; reported version must still match the pin",
    )
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    try:
        receipt = verify(
            args.root, rust_toolchain=args.rust_toolchain, run_tests=not args.skip_tests
        )
    except (BuildPolicyError, VerificationError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
