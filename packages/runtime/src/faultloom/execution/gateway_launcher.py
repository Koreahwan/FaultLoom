"""Launch one controller-provisioned Gateway and dispatch one approved command."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from .contracts import GatewayDispatchCommand, GatewayResult
from .gateway_client import AuthenticatedGatewayClient, GatewayChannelConfig
from .http import SemanticHttpExecutor
from .http_validation import ExecutionContractError

_SUPERVISED_ARGUMENTS = (
    "--supervised-stdio",
    "--bootstrap-fd",
    "3",
    "--journal-write-fd",
    "4",
    "--journal-read-fd",
    "5",
)
_MAX_BUNDLE_BYTES = 64 * 1024
_MAX_BOOTSTRAP_BYTES = 1024 * 1024


class GatewayLaunchError(ExecutionContractError):
    """A provisioned Gateway bundle or child lifecycle is invalid."""


@dataclass(frozen=True, slots=True)
class GatewayLaunchBundle:
    executable: Path
    executable_digest: str
    bootstrap: Path
    bootstrap_digest: str
    journal_write_fd: int
    journal_read_fd: int
    channel: GatewayChannelConfig

    @classmethod
    def load(cls, path: Path) -> Self:
        document = _load_private_json(path)
        if document.get("schema") != "faultloom.gateway-launch-bundle.v1":
            raise GatewayLaunchError("unsupported Gateway launch bundle schema")
        channel = document.get("channel")
        if not isinstance(channel, dict):
            raise GatewayLaunchError("Gateway launch bundle is missing channel configuration")
        try:
            key_hex = channel["key_hex"]
            nonce_hex = channel["nonce_hex"]
            if not isinstance(key_hex, str) or not isinstance(nonce_hex, str):
                raise ValueError("channel secrets must be hexadecimal strings")
            return cls(
                executable=_absolute_path(document["executable"], "Gateway executable"),
                executable_digest=_digest(document["executable_digest"], "Gateway executable"),
                bootstrap=_absolute_path(document["bootstrap"], "Gateway bootstrap"),
                bootstrap_digest=_digest(document["bootstrap_digest"], "Gateway bootstrap"),
                journal_write_fd=_fd_number(document["journal_write_fd"], "journal write"),
                journal_read_fd=_fd_number(document["journal_read_fd"], "journal read"),
                channel=GatewayChannelConfig(
                    key_id=channel["key_id"],
                    key=bytes.fromhex(key_hex),
                    boot_id=channel["boot_id"],
                    nonce=bytes.fromhex(nonce_hex),
                    issued_at_millis=channel["issued_at_millis"],
                    expires_at_millis=channel["expires_at_millis"],
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayLaunchError(f"invalid Gateway launch bundle: {exc}") from exc


class GatewayLauncher:
    """Own exactly one supervised child and one semantic dispatch."""

    def __init__(self, bundle: GatewayLaunchBundle) -> None:
        if type(bundle) is not GatewayLaunchBundle:
            raise GatewayLaunchError("Gateway launcher requires an exact provisioned bundle")
        self._bundle = bundle
        self._process: subprocess.Popen[bytes] | None = None
        self._client: AuthenticatedGatewayClient | None = None
        self._dispatched = False

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        return self._process

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def start(self) -> AuthenticatedGatewayClient:
        if self._process is not None:
            raise GatewayLaunchError("Gateway launcher is single-use")
        if threading.active_count() != 1:
            raise GatewayLaunchError(
                "supervised Gateway launch requires a single-threaded controller process"
            )
        bundle = self._bundle
        opened_executable_fd = _open_pinned_file(
            bundle.executable,
            bundle.executable_digest,
            executable=True,
            maximum_bytes=512 * 1024 * 1024,
        )
        try:
            executable_fd = _duplicate_fd(opened_executable_fd)
        finally:
            os.close(opened_executable_fd)
        try:
            bootstrap_fd = _open_bootstrap(bundle.bootstrap, bundle.bootstrap_digest)
        except Exception:
            os.close(executable_fd)
            raise
        sources: list[int] = []
        saved_targets: list[tuple[int, int | None, bool]] = []
        try:
            _require_fifo(bundle.journal_write_fd, "journal write")
            _require_fifo(bundle.journal_read_fd, "journal read")
            sources = [
                _duplicate_fd(bootstrap_fd),
                _duplicate_fd(bundle.journal_write_fd),
                _duplicate_fd(bundle.journal_read_fd),
            ]

            saved_targets = _install_fixed_gateway_fds(sources)
            executable_handoff = f"/proc/self/fd/{executable_fd}"
            process = subprocess.Popen(
                (executable_handoff, *_SUPERVISED_ARGUMENTS),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(3, 4, 5, executable_fd),
            )
        except GatewayLaunchError:
            os.close(executable_fd)
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            os.close(executable_fd)
            raise GatewayLaunchError(f"cannot start supervised Gateway: {exc}") from exc
        finally:
            _restore_fixed_gateway_fds(saved_targets)
            os.close(bootstrap_fd)
            for descriptor in sources:
                os.close(descriptor)

        self._process = process
        try:
            self._client = AuthenticatedGatewayClient(
                process,
                bundle.channel,
                expected_binary_digest=bundle.executable_digest,
            )
        except Exception:
            _reap_process(process)
            self._process = None
            raise
        finally:
            os.close(executable_fd)
        return self._client

    def dispatch(self, command: GatewayDispatchCommand) -> GatewayResult:
        if type(command) is not GatewayDispatchCommand:
            raise GatewayLaunchError("live dispatch requires an exact approved command")
        if self._dispatched:
            raise GatewayLaunchError("Gateway launcher permits exactly one dispatch")
        client = self._client or self.start()
        self._dispatched = True
        return SemanticHttpExecutor(client).execute(command)

    def close(self) -> None:
        client = self._client
        process = self._process
        self._client = None
        self._process = None
        if client is not None:
            try:
                client.interrupt()
            finally:
                client.close()
        elif process is not None:
            _reap_process(process)


def _load_private_json(path: Path) -> dict[str, object]:
    descriptor: int | None = None
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("bundle must be a single-link regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("bundle must not be accessible by group or other users")
        if metadata.st_size == 0 or metadata.st_size > _MAX_BUNDLE_BYTES:
            raise ValueError("bundle size is outside the allowed boundary")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("bundle changed before opening")
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_BUNDLE_BYTES:
            chunk = os.read(descriptor, _MAX_BUNDLE_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        final = os.fstat(descriptor)
        if len(raw) != metadata.st_size or final.st_mtime_ns != metadata.st_mtime_ns:
            raise ValueError("bundle changed while reading")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(value, dict):
            raise ValueError("bundle must be a JSON object")
        return value
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GatewayLaunchError(f"invalid Gateway launch bundle {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"{label} path must be text")
    path = Path(value)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError(f"{label} path must be absolute and normalized")
    return path


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} digest must be one lowercase SHA-256 digest")
    return value


def _fd_number(value: object, label: str) -> int:
    if type(value) is not int or value < 6:
        raise ValueError(f"{label} fd must be an inherited descriptor at least 6")
    return value


def _open_pinned_file(
    path: Path,
    expected_digest: str,
    *,
    executable: bool,
    maximum_bytes: int,
) -> int:
    descriptor: int | None = None
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("not a single-link regular file")
        if executable and not metadata.st_mode & stat.S_IXUSR:
            raise ValueError("not owner-executable")
        if metadata.st_size == 0 or metadata.st_size > maximum_bytes:
            raise ValueError("file size is outside the allowed boundary")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ValueError("file changed while opening")
        digest_state = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest_state.update(chunk)
        final = os.fstat(descriptor)
        if (
            final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise ValueError("file changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = f"sha256:{digest_state.hexdigest()}"
    except (OSError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise GatewayLaunchError(f"invalid pinned file {path}: {exc}") from exc
    if not hmac.compare_digest(digest, expected_digest):
        os.close(descriptor)
        raise GatewayLaunchError(f"pinned file digest differs for {path}")
    return descriptor


def _open_bootstrap(path: Path, expected_digest: str) -> int:
    try:
        metadata = path.lstat()
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("bootstrap must be private")
    except (OSError, ValueError) as exc:
        raise GatewayLaunchError(f"invalid Gateway bootstrap {path}: {exc}") from exc
    return _open_pinned_file(
        path,
        expected_digest,
        executable=False,
        maximum_bytes=_MAX_BOOTSTRAP_BYTES,
    )


def _require_fifo(descriptor: int, label: str) -> None:
    try:
        if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise GatewayLaunchError(f"{label} fd is not an authenticated journal FIFO")
    except OSError as exc:
        raise GatewayLaunchError(f"invalid {label} fd: {exc}") from exc


def _duplicate_fd(descriptor: int) -> int:
    try:
        import fcntl
    except ImportError as exc:
        raise GatewayLaunchError("supervised Gateway launch requires POSIX inherited FDs") from exc
    return fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 64)


def _install_fixed_gateway_fds(
    sources: list[int],
) -> list[tuple[int, int | None, bool]]:
    saved: list[tuple[int, int | None, bool]] = []
    try:
        for source, target in zip(sources, (3, 4, 5), strict=True):
            try:
                inherited = os.get_inheritable(target)
                saved_fd = _duplicate_fd(target)
            except OSError:
                inherited = False
                saved_fd = None
            saved.append((target, saved_fd, inherited))
            os.dup2(source, target, inheritable=True)
        return saved
    except OSError:
        _restore_fixed_gateway_fds(saved)
        raise


def _restore_fixed_gateway_fds(saved: list[tuple[int, int | None, bool]]) -> None:
    for target, saved_fd, inherited in reversed(saved):
        if saved_fd is None:
            try:
                os.close(target)
            except OSError:
                pass
            continue
        try:
            os.dup2(saved_fd, target, inheritable=inherited)
        finally:
            os.close(saved_fd)


def _reap_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired as exc:
                    raise GatewayLaunchError("Gateway child did not terminate") from exc
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
