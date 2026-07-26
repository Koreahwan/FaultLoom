from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

import faultloom.execution as execution
from faultloom.execution.browser_launcher import ChromiumLauncher
from faultloom.execution.browser_launcher_wrapper import create_wrapper_bytes
from faultloom.execution.browser_runtime_snapshot import (
    ChromiumRuntimeMount,
    ChromiumRuntimeSnapshot,
)


@dataclass(frozen=True)
class _RuntimeFixture:
    root: Path
    config: execution.ChromiumLaunchConfig
    content_by_name: dict[str, bytes]


def _tiny_runtime(tmp_path: Path) -> _RuntimeFixture:
    root = tmp_path / "chromium-runtime"
    root.mkdir()
    assets: list[execution.ChromiumRuntimeAsset] = []
    content_by_name: dict[str, bytes] = {}
    for index, pinned in enumerate(execution.PINNED_CHROMIUM_RUNTIME_ASSETS):
        name = pinned.name.value
        content = f"asset-{index:02d}:{name}\n".encode()
        path = root / name
        path.write_bytes(content)
        path.chmod(0o500 if pinned.executable else 0o400)
        content_by_name[name] = content
        assets.append(
            pinned.model_copy(
                update={
                    "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                    "byte_length": len(content),
                }
            )
        )
    chrome = next(asset for asset in assets if asset.name.value == "chrome")
    return _RuntimeFixture(
        root=root,
        config=execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=root / "chrome",
            executable_digest=chrome.digest,
            runtime_assets=tuple(assets),
        ),
        content_by_name=content_by_name,
    )


def _stage(fixture: _RuntimeFixture) -> ChromiumRuntimeSnapshot:
    return ChromiumRuntimeSnapshot.stage(
        fixture.config.executable,
        fixture.config.executable_digest,
        fixture.config.runtime_assets,
    )


def _mount(
    snapshot: ChromiumRuntimeSnapshot,
    name: str,
) -> ChromiumRuntimeMount:
    return next(mount for mount in snapshot.mounts if mount.asset.name.value == name)


def test_runtime_exports_exact_eighteen_file_chromium_manifest() -> None:
    asset_type = getattr(execution, "ChromiumRuntimeAsset", None)
    manifest = getattr(execution, "PINNED_CHROMIUM_RUNTIME_ASSETS", ())

    assert callable(asset_type)
    assert len(manifest) == 18


def test_launch_config_carries_the_exact_runtime_asset_manifest(tmp_path: Path) -> None:
    executable = tmp_path / "chrome"
    executable.write_bytes(b"chrome")
    executable.chmod(0o500)

    config = execution.ChromiumLaunchConfig(
        schema_version="0.1.0",
        executable=executable,
        executable_digest="sha256:" + "11" * 32,
        runtime_assets=execution.PINNED_CHROMIUM_RUNTIME_ASSETS,
    )

    assert config.runtime_assets == execution.PINNED_CHROMIUM_RUNTIME_ASSETS


@pytest.mark.parametrize(
    ("defect", "message"),
    (("missing", "closure"), ("extra", "closure"), ("symlink", "non-regular")),
)
def test_launcher_rejects_non_exact_source_closure(
    tmp_path: Path,
    defect: str,
    message: str,
) -> None:
    fixture = _tiny_runtime(tmp_path)
    about = fixture.root / "ABOUT"
    if defect == "missing":
        about.unlink()
    elif defect == "extra":
        (fixture.root / "unexpected.bin").write_bytes(b"not admitted")
    else:
        about.unlink()
        about.symlink_to(fixture.root / "chrome")

    with pytest.raises(execution.BrowserContractError, match=message):
        launcher = ChromiumLauncher(fixture.config)
        launcher.close()


def test_launcher_rejects_incomplete_manifest(tmp_path: Path) -> None:
    fixture = _tiny_runtime(tmp_path)
    config = fixture.config.model_copy(
        update={"runtime_assets": fixture.config.runtime_assets[:-1]}
    )

    with pytest.raises(execution.BrowserContractError, match="manifest"):
        launcher = ChromiumLauncher(config)
        launcher.close()


def test_snapshot_is_detached_from_source_mutation(tmp_path: Path) -> None:
    fixture = _tiny_runtime(tmp_path)
    snapshot = _stage(fixture)
    source = fixture.root / "chrome"
    source.chmod(0o700)
    source.write_bytes(b"mutated caller source")
    try:
        snapshot.assert_launchable()

        mounted = _mount(snapshot, "chrome")
        assert mounted.source.read_bytes() == fixture.content_by_name["chrome"]
        assert mounted.source.stat().st_ino != source.stat().st_ino
    finally:
        snapshot.close()


def test_snapshot_descriptors_survive_caller_root_path_swap(tmp_path: Path) -> None:
    fixture = _tiny_runtime(tmp_path)
    snapshot = _stage(fixture)
    parked = tmp_path / "parked-runtime"
    fixture.root.rename(parked)
    fixture.root.mkdir()
    (fixture.root / "chrome").write_bytes(b"replacement root")
    try:
        snapshot.assert_launchable()

        mounted = _mount(snapshot, "chrome")
        assert mounted.source.read_bytes() == fixture.content_by_name["chrome"]
        assert str(fixture.root) not in os.readlink(mounted.source)
    finally:
        snapshot.close()


def test_wrapper_binds_all_assets_by_descriptor_without_caller_root(
    tmp_path: Path,
) -> None:
    fixture = _tiny_runtime(tmp_path)
    snapshot = _stage(fixture)
    try:
        mounts = snapshot.mounts
        wrapper = create_wrapper_bytes(
            Path("/usr/bin/bwrap"),
            mounts,
            tmp_path / "browser.pid",
            tmp_path / "runtime-fds.sock",
            bytes.fromhex("ab" * 32),
        ).decode()

        assert len(mounts) == 18
        assert len({mount.source for mount in mounts}) == 18
        assert str(fixture.root) not in wrapper
        assert "/proc/" not in wrapper
        assert '"--ro-bind-fd"' in wrapper
        for mount in mounts:
            assert str(mount.source) not in wrapper
            assert f"/opt/faultloom-chromium/{mount.asset.name.value}" in wrapper
    finally:
        snapshot.close()


def test_launcher_rechecks_snapshot_tamper_immediately_before_launch(
    tmp_path: Path,
) -> None:
    fixture = _tiny_runtime(tmp_path)
    launcher = ChromiumLauncher(fixture.config)
    snapshot = getattr(launcher, "_snapshot")
    assert isinstance(snapshot, ChromiumRuntimeSnapshot)
    mount_source = _mount(snapshot, "chrome").source
    mount_source.chmod(0o700)
    mount_source.write_bytes(b"tampered private snapshot")

    with pytest.raises(execution.BrowserContractError, match="snapshot"):
        launcher.browser()

    assert not mount_source.exists()
    launcher.close()
