from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from faultloom.execution import (
    GatewayChannelConfig,
    GatewayDispatchCommand,
    GatewayLaunchBundle,
    GatewayLaunchError,
    GatewayLauncher,
    GatewayProvisioningError,
    GatewayProvisioningMaterial,
    provision_gateway_handoff,
)

from .execution_helpers import command


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _material(
    tmp_path: Path,
) -> tuple[GatewayProvisioningMaterial, tuple[int, int, int, int]]:
    executable = tmp_path / "faultloom-gateway"
    _ = executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    _ = executable.chmod(0o700)
    bootstrap = tmp_path / "bootstrap.flbs"
    _ = bootstrap.write_bytes(b"FLBSexisting-controller-signed-fixture")
    _ = bootstrap.chmod(0o600)
    journal_read, journal_write = os.pipe()
    reply_read, reply_write = os.pipe()
    now = int(time.time() * 1000)
    material = GatewayProvisioningMaterial(
        executable=executable,
        executable_digest=_digest(executable),
        bootstrap=bootstrap,
        bootstrap_digest=_digest(bootstrap),
        journal_write_fd=journal_write,
        journal_read_fd=reply_read,
        channel=GatewayChannelConfig(
            key_id="channel-key.1",
            key=bytes(range(1, 33)),
            boot_id="gateway-boot.1",
            nonce=bytes(range(16)),
            issued_at_millis=now - 1_000,
            expires_at_millis=now + 60_000,
        ),
    )
    return material, (journal_read, journal_write, reply_read, reply_write)


def _close_all(descriptors: tuple[int, ...]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def test_private_handoff_is_consumable_by_one_inheriting_cli_process(
    tmp_path: Path,
) -> None:
    _ = tmp_path.chmod(0o700)
    material, sources = _material(tmp_path)
    approved = command()
    retained: tuple[int, int] | None = None
    directory: Path | None = None
    try:
        with provision_gateway_handoff(tmp_path, material, approved) as handoff:
            retained = handoff.pass_fds
            directory = handoff.directory
            assert stat.S_IMODE(handoff.directory.stat().st_mode) == 0o700
            assert stat.S_IMODE(handoff.bundle_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(handoff.command_path.stat().st_mode) == 0o600
            loaded = GatewayLaunchBundle.load(handoff.bundle_path)
            assert (loaded.journal_write_fd, loaded.journal_read_fd) == retained
            assert (
                GatewayDispatchCommand.model_validate_json(
                    handoff.command_path.read_bytes()
                )
                == approved
            )

            _close_all((sources[1], sources[2]))
            consumer_program = (
                "import json,os,stat,sys; "
                "d=json.load(open(sys.argv[1], encoding='utf-8')); "
                "assert stat.S_ISFIFO(os.fstat(d['journal_write_fd']).st_mode); "
                "assert stat.S_ISFIFO(os.fstat(d['journal_read_fd']).st_mode); "
                "print('HANDOFF_OK')"
            )
            consumer = subprocess.run(
                (
                    sys.executable,
                    "-c",
                    consumer_program,
                    str(handoff.bundle_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                pass_fds=handoff.pass_fds,
            )
            assert consumer.returncode == 0, consumer.stderr
            assert consumer.stdout == "HANDOFF_OK\n"

        assert directory is not None and not directory.exists()
        assert retained is not None
        for descriptor in retained:
            with pytest.raises(OSError):
                _ = os.fstat(descriptor)
    finally:
        _close_all(sources)


def test_stale_json_cannot_reuse_unowned_descriptor_numbers(tmp_path: Path) -> None:
    _ = tmp_path.chmod(0o700)
    material, sources = _material(tmp_path)
    stale_bundle = tmp_path / "stale-bundle.json"
    try:
        with provision_gateway_handoff(tmp_path, material, command()) as handoff:
            bundle_content = handoff.bundle_path.read_bytes()

        _ = stale_bundle.write_bytes(bundle_content)
        _ = stale_bundle.chmod(0o600)
        launcher = GatewayLauncher(GatewayLaunchBundle.load(stale_bundle))
        with pytest.raises(GatewayLaunchError, match="journal write fd"):
            _ = launcher.start()
        assert launcher.process is None
    finally:
        _close_all(sources)


@pytest.mark.parametrize(
    ("bootstrap", "digest", "message"),
    (
        (b"FLBStampered", "sha256:" + "00" * 32, "digest differs"),
        (b"not-a-signed-envelope", None, "FLBS envelope magic"),
    ),
)
def test_invalid_supplied_bootstrap_fails_before_handoff_artifacts(
    tmp_path: Path,
    bootstrap: bytes,
    digest: str | None,
    message: str,
) -> None:
    _ = tmp_path.chmod(0o700)
    material, sources = _material(tmp_path)
    try:
        _ = material.bootstrap.write_bytes(bootstrap)
        _ = material.bootstrap.chmod(0o600)
        invalid_material = GatewayProvisioningMaterial(
            executable=material.executable,
            executable_digest=material.executable_digest,
            bootstrap=material.bootstrap,
            bootstrap_digest=digest or _digest(material.bootstrap),
            journal_write_fd=material.journal_write_fd,
            journal_read_fd=material.journal_read_fd,
            channel=material.channel,
        )

        with pytest.raises(GatewayProvisioningError, match=message):
            _ = provision_gateway_handoff(
                tmp_path,
                invalid_material,
                command(),
            )

        assert list(tmp_path.glob("gateway-handoff-*")) == []
    finally:
        _close_all(sources)


def test_handoff_rejects_world_accessible_destination(tmp_path: Path) -> None:
    _ = tmp_path.chmod(0o755)
    material, sources = _material(tmp_path)
    try:
        with pytest.raises(GatewayProvisioningError, match="owner-only"):
            _ = provision_gateway_handoff(tmp_path, material, command())
    finally:
        _close_all(sources)
