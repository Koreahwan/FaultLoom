"""Prepare one private, short-lived handoff to the supervised Gateway launcher.

The provisioner packages authority material that already exists.  It never
creates controller keys, grants, leases, bootstrap signatures, or journal
authentication state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self, final

from .contracts import GatewayDispatchCommand
from .gateway_client import GatewayChannelConfig
from .gateway_launcher import GatewayLaunchBundle
from .http_validation import ExecutionContractError


class GatewayProvisioningError(ExecutionContractError):
    """Supplied controller material cannot form a safe live handoff."""


@dataclass(frozen=True, slots=True)
class GatewayProvisioningMaterial:
    """Existing controller outputs required by one supervised Gateway run."""

    executable: Path
    executable_digest: str
    bootstrap: Path
    bootstrap_digest: str
    journal_write_fd: int
    journal_read_fd: int
    channel: GatewayChannelConfig = field(repr=False)


@final
class GatewayProvisionedHandoff:
    """A live descriptor handoff, valid only until this object is closed."""

    def __init__(
        self,
        directory: Path,
        bundle_path: Path,
        command_path: Path,
        descriptors: tuple[int, int],
    ) -> None:
        self.directory = directory
        self.bundle_path = bundle_path
        self.command_path = command_path
        self._descriptors = descriptors
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def pass_fds(self) -> tuple[int, int]:
        """Descriptors that a controller must pass to the FaultLoom CLI child."""

        if self._closed:
            raise GatewayProvisioningError("Gateway handoff is already closed")
        return self._descriptors

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for descriptor in self._descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        shutil.rmtree(self.directory)


def provision_gateway_handoff(
    destination: Path,
    material: GatewayProvisioningMaterial,
    command: GatewayDispatchCommand,
) -> GatewayProvisionedHandoff:
    """Create one private bundle/command pair backed by inherited journal FDs.

    The returned object must remain open until the child process that consumes
    ``bundle_path`` has exited.  Its ``pass_fds`` must be inherited by that
    child.  Closing the handoff removes the secret bundle and closes its copied
    journal descriptors.
    """

    if type(material) is not GatewayProvisioningMaterial:
        raise GatewayProvisioningError("provisioning material must be exact")
    if type(command) is not GatewayDispatchCommand:
        raise GatewayProvisioningError("dispatch command must be preapproved and exact")
    _require_private_directory(destination)
    _verify_pinned_file(
        material.executable,
        material.executable_digest,
        executable=True,
        bootstrap=False,
    )
    _verify_pinned_file(
        material.bootstrap,
        material.bootstrap_digest,
        executable=False,
        bootstrap=True,
    )
    _require_journal_fifo(material.journal_write_fd, "journal write")
    _require_journal_fifo(material.journal_read_fd, "journal read")
    if material.journal_write_fd == material.journal_read_fd:
        raise GatewayProvisioningError("journal read and write descriptors must differ")
    if type(material.channel) is not GatewayChannelConfig:
        raise GatewayProvisioningError("Gateway channel configuration must be exact")

    directory = Path(tempfile.mkdtemp(prefix="gateway-handoff-", dir=destination))
    directory.chmod(0o700)
    descriptors: tuple[int, int] | None = None
    try:
        descriptors = (
            _duplicate_descriptor(material.journal_write_fd),
            _duplicate_descriptor(material.journal_read_fd),
        )
        bundle_path = directory / "gateway-bundle.json"
        command_path = directory / "dispatch-command.json"
        bundle = {
            "schema": "faultloom.gateway-launch-bundle.v1",
            "executable": str(material.executable),
            "executable_digest": material.executable_digest,
            "bootstrap": str(material.bootstrap),
            "bootstrap_digest": material.bootstrap_digest,
            "journal_write_fd": descriptors[0],
            "journal_read_fd": descriptors[1],
            "channel": {
                "key_id": material.channel.key_id,
                "key_hex": material.channel.key.hex(),
                "boot_id": material.channel.boot_id,
                "nonce_hex": material.channel.nonce.hex(),
                "issued_at_millis": material.channel.issued_at_millis,
                "expires_at_millis": material.channel.expires_at_millis,
            },
        }
        _write_private_json(bundle_path, bundle)
        _write_private_bytes(
            command_path,
            (command.model_dump_json(indent=2) + "\n").encode("utf-8"),
        )
        loaded = GatewayLaunchBundle.load(bundle_path)
        if (
            loaded.journal_write_fd,
            loaded.journal_read_fd,
        ) != descriptors:
            raise GatewayProvisioningError("Gateway bundle descriptor binding changed")
        if GatewayDispatchCommand.model_validate_json(command_path.read_bytes()) != command:
            raise GatewayProvisioningError("dispatch command changed during handoff")
        return GatewayProvisionedHandoff(
            directory,
            bundle_path,
            command_path,
            descriptors,
        )
    except Exception:
        if descriptors is not None:
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        shutil.rmtree(directory, ignore_errors=True)
        raise


def _require_private_directory(path: Path) -> None:
    if os.name != "posix":
        raise GatewayProvisioningError("Gateway descriptor handoff requires POSIX")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GatewayProvisioningError(f"invalid handoff destination {path}: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise GatewayProvisioningError(
            "handoff destination must be an owner-only real directory"
        )


def _verify_pinned_file(
    path: Path,
    expected_digest: str,
    *,
    executable: bool,
    bootstrap: bool,
) -> None:
    if (
        len(expected_digest) != 71
        or not expected_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in expected_digest[7:])
    ):
        raise GatewayProvisioningError("supplied digest is not lowercase SHA-256")
    descriptor: int | None = None
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("not a single-link regular file")
        if executable and not metadata.st_mode & stat.S_IXUSR:
            raise ValueError("Gateway executable is not owner-executable")
        if bootstrap and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("Gateway bootstrap is not private")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ValueError("file changed before verification")
        digest_state = hashlib.sha256()
        prefix = b""
        while chunk := os.read(descriptor, 64 * 1024):
            if len(prefix) < 4:
                prefix += chunk[: 4 - len(prefix)]
            digest_state.update(chunk)
        final = os.fstat(descriptor)
        if (
            final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise ValueError("file changed during verification")
        actual_digest = f"sha256:{digest_state.hexdigest()}"
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError("digest differs from the supplied pin")
        if bootstrap and prefix != b"FLBS":
            raise ValueError("bootstrap does not have the signed FLBS envelope magic")
    except (OSError, ValueError) as exc:
        raise GatewayProvisioningError(f"invalid supplied controller file {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_journal_fifo(descriptor: int, label: str) -> None:
    if type(descriptor) is not int:
        raise GatewayProvisioningError(f"{label} descriptor is not exact")
    try:
        if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise GatewayProvisioningError(f"{label} descriptor is not a journal FIFO")
    except OSError as exc:
        raise GatewayProvisioningError(f"invalid {label} descriptor: {exc}") from exc


def _duplicate_descriptor(descriptor: int) -> int:
    try:
        import fcntl

        return fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 64)
    except (ImportError, OSError) as exc:
        raise GatewayProvisioningError(f"cannot retain journal descriptor: {exc}") from exc


def _write_private_json(path: Path, value: object) -> None:
    _write_private_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _write_private_bytes(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise GatewayProvisioningError(f"cannot write private handoff file {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
