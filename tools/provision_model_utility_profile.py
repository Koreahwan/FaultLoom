#!/usr/bin/env python3
"""Atomically provision the fixed offline model-utility profile from local files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

_PROFILE_ROOT = Path("/opt/faultloom/model-utility-v1")
_BWRAP_DIGEST = "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
_WRAPPER_DIGEST = "0feee3c2b0bf91d64850841c754d8b122573cf1c2209672d48c006e3c89bf98d"
_MODEL_DIGEST = "48ab3034d0dd401fbc721eb1df3217902fee7dab9078992d66431f09b7750201"
_BUNDLE_DIGEST = "afe1ae0b706c4a0830b218a9249037b7a6cc723f81deb78825662128b25453e6"
_MODEL_SIZE = 386_404_992
_BUNDLE_SIZE = 16_275_561
_MODEL_CARD_DIGEST = "5d65a9f761fb64443b565d247593aa3d4ec0f06633a0e16c0231625cdba6a7cd"
_MODEL_CARD_SIZE = 1_847
_BUNDLE_LICENSE_DIGEST = "94f29bbed6a22c35b992c5c6ebf0e7c92f13b836b90f36f461c9cf2f0f1d010d"
_MODEL_REVISION = "593b5a2e04c8f3e4ee880263f93e0bd2901ad47f"
_BUNDLE_COMMIT = "c0bc8591e8815c63cb01dd3f051a8b0df02501c9"


class ProvisionError(RuntimeError):
    """A staged input or target failed a provisioning precondition."""


@dataclass(frozen=True, slots=True)
class StagedProfile:
    bwrap: Path
    wrapper: Path
    bundle: Path
    model: Path
    bundle_metadata: Path
    model_metadata: Path
    model_license: Path


def _copy_verified(
    source: Path,
    destination: Path,
    *,
    expected_digest: str | None,
    expected_size: int | None,
    mode: int,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError:
        raise ProvisionError("staged input is unavailable") from None
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProvisionError("staged input is not an admissible regular file")
        if expected_size is not None and before.st_size != expected_size:
            raise ProvisionError("staged input size mismatch")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(source_fd, 1024 * 1024):
            digest.update(chunk)
            copied += len(chunk)
            pending = memoryview(chunk)
            offset = 0
            while offset < len(pending):
                offset += os.write(destination_fd, pending[offset:])
        after = os.fstat(source_fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or copied != before.st_size:
            raise ProvisionError("staged input changed during provisioning")
        if expected_digest is not None and digest.hexdigest() != expected_digest:
            raise ProvisionError("staged input digest mismatch")
        os.fchmod(destination_fd, mode)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def _read_metadata(path: Path, *, expected: dict[str, object]) -> dict[str, object]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024:
            raise ProvisionError("provenance metadata is not admissible")
        raw = os.read(descriptor, 64 * 1024 + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ProvisionError("provenance metadata changed during validation")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        raise ProvisionError("provenance metadata is invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if type(value) is not dict or any(value.get(key) != item for key, item in expected.items()):
        raise ProvisionError("provenance metadata does not match the pinned profile")
    return value


def _write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_bundle_license(bundle: Path, destination: Path) -> None:
    try:
        with tarfile.open(bundle, "r:gz") as archive:
            member = archive.getmember("llama-b10107/LICENSE")
            if not member.isreg() or member.size < 1 or member.size > 64 * 1024:
                raise ProvisionError("runtime bundle license is invalid")
            source = archive.extractfile(member)
            if source is None:
                raise ProvisionError("runtime bundle license is invalid")
            value = source.read(64 * 1024 + 1)
            source.close()
            if len(value) != member.size:
                raise ProvisionError("runtime bundle license is invalid")
    except (KeyError, OSError, tarfile.TarError):
        raise ProvisionError("runtime bundle license is invalid") from None
    if hashlib.sha256(value).hexdigest() != _BUNDLE_LICENSE_DIGEST:
        raise ProvisionError("runtime bundle license digest mismatch")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def provision_profile(
    staged: StagedProfile,
    *,
    profile_root: Path = _PROFILE_ROOT,
    enforce_root_owner: bool = True,
) -> Path:
    """Verify staged local bytes and atomically publish one fixed profile."""

    if enforce_root_owner and os.geteuid() != 0:
        raise ProvisionError("profile provisioning requires root")
    if not profile_root.is_absolute() or profile_root.name != "model-utility-v1":
        raise ProvisionError("profile target is invalid")
    parent = profile_root.parent
    if not parent.is_dir() or profile_root.exists() or profile_root.is_symlink():
        raise ProvisionError("profile target is not empty")
    bundle_metadata = _read_metadata(
        staged.bundle_metadata,
        expected={
            "archive": "llama-b10107-bin-ubuntu-x64.tar.gz",
            "commit": _BUNDLE_COMMIT,
            "release": "b10107",
            "sha256": _BUNDLE_DIGEST,
            "size": _BUNDLE_SIZE,
        },
    )
    model_metadata = _read_metadata(
        staged.model_metadata,
        expected={
            "file": "smollm2-360m-instruct-q8_0.gguf",
            "repository": "HuggingFaceTB/SmolLM2-360M-Instruct-GGUF",
            "revision": _MODEL_REVISION,
            "sha256": _MODEL_DIGEST,
            "size": _MODEL_SIZE,
        },
    )
    stage = Path(tempfile.mkdtemp(prefix=".model-utility-v1.stage-", dir=parent))
    published = False
    try:
        os.chmod(stage, 0o755)
        _copy_verified(
            staged.bwrap,
            stage / "bwrap",
            expected_digest=_BWRAP_DIGEST,
            expected_size=None,
            mode=0o555,
        )
        _copy_verified(
            staged.wrapper,
            stage / "runtime",
            expected_digest=_WRAPPER_DIGEST,
            expected_size=None,
            mode=0o555,
        )
        _copy_verified(
            staged.model,
            stage / "model.gguf",
            expected_digest=_MODEL_DIGEST,
            expected_size=_MODEL_SIZE,
            mode=0o444,
        )
        _copy_verified(
            staged.bundle,
            stage / "llama-b10107-bin-ubuntu-x64.tar.gz",
            expected_digest=_BUNDLE_DIGEST,
            expected_size=_BUNDLE_SIZE,
            mode=0o444,
        )
        _copy_verified(
            staged.model_license,
            stage / "MODEL_CARD.md",
            expected_digest=_MODEL_CARD_DIGEST,
            expected_size=_MODEL_CARD_SIZE,
            mode=0o444,
        )
        _copy_bundle_license(
            stage / "llama-b10107-bin-ubuntu-x64.tar.gz", stage / "LLAMA.CPP-LICENSE"
        )
        _write_json(stage / "llama-b10107.provenance.json", bundle_metadata)
        _write_json(stage / "model.provenance.json", model_metadata)
        _write_json(
            stage / "config.json",
            {
                "maximum_request_bytes": 16_777_216,
                "maximum_response_bytes": 16_777_216,
                "profile": "faultloom_utility_v1",
                "timeout_seconds": 300,
            },
        )
        _write_json(
            stage / "profile.provenance.json",
            {
                "artifacts": {
                    "bwrap": {"sha256": _BWRAP_DIGEST},
                    "runtime": {"sha256": _WRAPPER_DIGEST},
                    "runtime_bundle": {
                        "sha256": _BUNDLE_DIGEST,
                        "size": _BUNDLE_SIZE,
                    },
                    "model": {"sha256": _MODEL_DIGEST, "size": _MODEL_SIZE},
                },
                "bundle": bundle_metadata,
                "model": model_metadata,
            },
        )
        directory_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.rename(stage, profile_root)
        published = True
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return profile_root
    except OSError:
        raise ProvisionError("profile provisioning failed") from None
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bwrap", required=True, type=Path)
    parser.add_argument("--wrapper", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--bundle-metadata", required=True, type=Path)
    parser.add_argument("--model-metadata", required=True, type=Path)
    parser.add_argument("--model-license", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        provision_profile(
            StagedProfile(
                bwrap=args.bwrap,
                wrapper=args.wrapper,
                bundle=args.bundle,
                model=args.model,
                bundle_metadata=args.bundle_metadata,
                model_metadata=args.model_metadata,
                model_license=args.model_license,
            )
        )
    except ProvisionError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
