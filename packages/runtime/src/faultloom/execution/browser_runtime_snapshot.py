from __future__ import annotations

import hmac
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from faultloom_protocol.base import Sha256Digest

from .browser_contracts import BrowserContractError
from .browser_runtime_manifest import (
    ChromiumAssetName,
    ChromiumRuntimeAsset,
)
from .browser_runtime_snapshot_io import (
    StagedChromiumAsset,
    cleanup_partial,
    copy_asset,
    hash_descriptor,
    open_source_root,
    validate_source_closure,
)


@dataclass(frozen=True, slots=True)
class ChromiumRuntimeMount:
    asset: ChromiumRuntimeAsset
    source: Path


class ChromiumRuntimeSnapshot:
    def __init__(
        self,
        root: tempfile.TemporaryDirectory[str],
        root_descriptor: int,
        held_assets: tuple[StagedChromiumAsset, ...],
    ) -> None:
        self._root = root
        self._root_descriptor = root_descriptor
        self._held_assets = held_assets
        self._closed = False

    @classmethod
    def stage(
        cls,
        executable: Path,
        executable_digest: Sha256Digest,
        assets: tuple[ChromiumRuntimeAsset, ...],
    ) -> Self:
        ordered_assets = _validate_manifest(executable, executable_digest, assets)
        source_descriptor = open_source_root(executable.parent)
        root: tempfile.TemporaryDirectory[str] | None = None
        root_descriptor: int | None = None
        held_assets: list[StagedChromiumAsset] = []
        try:
            validate_source_closure(source_descriptor, ordered_assets)
            root = tempfile.TemporaryDirectory(prefix="faultloom-chromium-runtime-")
            root_descriptor = os.open(
                root.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            for asset in ordered_assets:
                held_assets.append(
                    copy_asset(source_descriptor, root_descriptor, asset)
                )
            os.fchmod(root_descriptor, 0o500)
            os.fsync(root_descriptor)
            snapshot = cls(root, root_descriptor, tuple(held_assets))
            snapshot.assert_launchable()
            return snapshot
        except BrowserContractError:
            cleanup_partial(root, root_descriptor, held_assets)
            raise
        except OSError as exc:
            cleanup_partial(root, root_descriptor, held_assets)
            raise BrowserContractError("Chromium runtime snapshot staging failed") from exc
        finally:
            os.close(source_descriptor)

    @property
    def mounts(self) -> tuple[ChromiumRuntimeMount, ...]:
        if self._closed:
            raise BrowserContractError("Chromium runtime snapshot is closed")
        process = os.getpid()
        return tuple(
            ChromiumRuntimeMount(
                asset=held.asset,
                source=Path(f"/proc/{process}/fd/{held.descriptor}"),
            )
            for held in self._held_assets
        )

    @property
    def descriptors(self) -> tuple[int, ...]:
        if self._closed:
            raise BrowserContractError("Chromium runtime snapshot is closed")
        return tuple(held.descriptor for held in self._held_assets)

    def assert_launchable(self) -> None:
        if self._closed:
            raise BrowserContractError("Chromium runtime snapshot is closed")
        for held in self._held_assets:
            try:
                observed_digest, observed_length, stable = hash_descriptor(
                    held.descriptor
                )
                mode = stat.S_IMODE(os.fstat(held.descriptor).st_mode)
            except OSError as exc:
                raise BrowserContractError(
                    "Chromium runtime snapshot cannot be verified"
                ) from exc
            expected_mode = 0o500 if held.asset.executable else 0o400
            if not stable:
                raise BrowserContractError(
                    "Chromium runtime snapshot changed during launch verification"
                )
            if observed_length != held.asset.byte_length:
                raise BrowserContractError("Chromium runtime snapshot byte length mismatch")
            if not hmac.compare_digest(observed_digest, held.asset.digest):
                raise BrowserContractError("Chromium runtime snapshot digest mismatch")
            if mode != expected_mode:
                raise BrowserContractError("Chromium runtime snapshot mode mismatch")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_failed = False
        for held in self._held_assets:
            try:
                os.close(held.descriptor)
            except OSError:
                cleanup_failed = True
        try:
            os.fchmod(self._root_descriptor, 0o700)
            os.close(self._root_descriptor)
        except OSError:
            cleanup_failed = True
        try:
            self._root.cleanup()
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise BrowserContractError("Chromium runtime snapshot cleanup failed")


def _validate_manifest(
    executable: Path,
    executable_digest: Sha256Digest,
    assets: tuple[ChromiumRuntimeAsset, ...],
) -> tuple[ChromiumRuntimeAsset, ...]:
    expected_names = tuple(ChromiumAssetName)
    by_name = {asset.name: asset for asset in assets}
    if len(assets) != len(expected_names) or set(by_name) != set(expected_names):
        raise BrowserContractError("Chromium runtime manifest is not the exact closure")
    chrome = by_name[ChromiumAssetName.CHROME]
    if not hmac.compare_digest(chrome.digest, executable_digest):
        raise BrowserContractError("pinned Chromium executable digest mismatch")
    if executable.name != ChromiumAssetName.CHROME.value:
        raise BrowserContractError("Chromium runtime manifest executable path is invalid")
    return tuple(by_name[name] for name in expected_names)
