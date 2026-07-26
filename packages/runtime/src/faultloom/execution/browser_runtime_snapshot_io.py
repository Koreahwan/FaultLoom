from __future__ import annotations

import hashlib
import hmac
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .browser_contracts import BrowserContractError
from .browser_runtime_manifest import ChromiumRuntimeAsset

_READ_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class StagedChromiumAsset:
    asset: ChromiumRuntimeAsset
    descriptor: int


def open_source_root(root: Path) -> int:
    try:
        return os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise BrowserContractError("pinned Chromium runtime root is unavailable") from exc


def validate_source_closure(
    root_descriptor: int,
    assets: tuple[ChromiumRuntimeAsset, ...],
) -> None:
    expected = {asset.name.value for asset in assets}
    regular: set[str] = set()
    try:
        for entry in os.listdir(root_descriptor):
            state = os.stat(entry, dir_fd=root_descriptor, follow_symlinks=False)
            if stat.S_ISDIR(state.st_mode):
                continue
            if not stat.S_ISREG(state.st_mode):
                raise BrowserContractError(
                    "Chromium runtime closure contains a non-regular asset"
                )
            regular.add(entry)
    except BrowserContractError:
        raise
    except OSError as exc:
        raise BrowserContractError("Chromium runtime closure cannot be inspected") from exc
    if regular != expected:
        raise BrowserContractError("Chromium runtime source closure differs from manifest")


def copy_asset(
    source_root: int,
    snapshot_root: int,
    asset: ChromiumRuntimeAsset,
) -> StagedChromiumAsset:
    name = asset.name.value
    source = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=source_root,
    )
    destination: int | None = None
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise BrowserContractError("Chromium runtime asset is not a regular file")
        if bool(before.st_mode & 0o111) is not asset.executable:
            raise BrowserContractError("Chromium runtime asset executable mode mismatch")
        destination = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=snapshot_root,
        )
        observed_digest, byte_length = _copy_and_hash(source, destination)
        after = os.fstat(source)
        current = os.stat(name, dir_fd=source_root, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current):
            raise BrowserContractError("Chromium runtime asset changed during snapshot")
        if byte_length != asset.byte_length:
            raise BrowserContractError("Chromium runtime asset byte length mismatch")
        if not hmac.compare_digest(observed_digest, asset.digest):
            raise BrowserContractError("Chromium runtime asset digest mismatch")
        os.fsync(destination)
        os.fchmod(destination, 0o500 if asset.executable else 0o400)
    finally:
        os.close(source)
        if destination is not None:
            os.close(destination)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=snapshot_root,
    )
    return StagedChromiumAsset(asset=asset, descriptor=descriptor)


def hash_descriptor(descriptor: int) -> tuple[str, int, bool]:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    byte_length = 0
    while block := os.read(descriptor, _READ_SIZE):
        digest.update(block)
        byte_length += len(block)
    after = os.fstat(descriptor)
    return f"sha256:{digest.hexdigest()}", byte_length, _identity(before) == _identity(after)


def cleanup_partial(
    root: tempfile.TemporaryDirectory[str] | None,
    root_descriptor: int | None,
    held_assets: list[StagedChromiumAsset],
) -> None:
    for held in held_assets:
        try:
            os.close(held.descriptor)
        except OSError:
            pass
    if root_descriptor is not None:
        try:
            os.fchmod(root_descriptor, 0o700)
            os.close(root_descriptor)
        except OSError:
            pass
    if root is not None:
        try:
            root.cleanup()
        except OSError:
            pass


def _copy_and_hash(source: int, destination: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_length = 0
    while block := os.read(source, _READ_SIZE):
        digest.update(block)
        byte_length += len(block)
        _write_all(destination, block)
    return f"sha256:{digest.hexdigest()}", byte_length


def _write_all(descriptor: int, block: bytes) -> None:
    view = memoryview(block)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("snapshot write made no progress")
        view = view[written:]


def _identity(state: os.stat_result) -> tuple[int, int, int, int, int]:
    return state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns
