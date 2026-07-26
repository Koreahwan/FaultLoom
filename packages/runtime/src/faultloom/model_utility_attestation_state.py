"""Durable, monotonic sequence allocation for transient model attestations."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import threading
from pathlib import Path
from types import TracebackType

_ALLOCATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_HEADER = b"FAULTLOOM-ATTESTATION-SEQUENCE-V1\n"
_MAX_INT64 = (2**63) - 1
_MAX_STATE_BYTES = 64 * 1024 * 1024


class AttestationStateError(RuntimeError):
    """Persistent attestation state is unavailable or cannot be trusted."""


class MonotonicAttestationState:
    """Allocate sequences using one never-reopened state file descriptor."""

    __slots__ = (
        "_closed",
        "_file_fd",
        "_file_identity",
        "_name",
        "_parent_fd",
        "_parent_identity",
        "_parent_path",
        "_thread_lock",
    )

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("attestation state path must be a Path")
        absolute = Path(os.path.abspath(path))
        if absolute == Path("/opt") or Path("/opt") in absolute.parents:
            raise AttestationStateError("attestation state must be stored outside /opt")
        if absolute.name in ("", ".", ".."):
            raise AttestationStateError("attestation state path is invalid")
        parent_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            parent_fd = os.open(absolute.parent, parent_flags)
        except OSError as exc:
            raise AttestationStateError("attestation state parent is unavailable") from exc
        self._closed = True
        self._file_fd = -1
        self._name = absolute.name
        self._parent_fd = parent_fd
        self._parent_path = absolute.parent
        self._thread_lock = threading.Lock()
        try:
            parent = os.fstat(parent_fd)
            self._parent_identity = (parent.st_dev, parent.st_ino)
            self._validate_parent()
            file_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_fd = os.open(
                    self._name,
                    file_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                try:
                    file_fd = os.open(self._name, file_flags, dir_fd=parent_fd)
                except OSError as exc:
                    raise AttestationStateError(
                        "attestation state file metadata is unsafe"
                    ) from exc
            self._file_fd = file_fd
            self._file_identity = self._validate_file()
            fcntl.flock(file_fd, fcntl.LOCK_EX)
            try:
                if os.fstat(file_fd).st_size == 0:
                    self._write_all(_HEADER)
                    os.fsync(file_fd)
                    os.fsync(parent_fd)
                else:
                    self._read_state()
            finally:
                fcntl.flock(file_fd, fcntl.LOCK_UN)
            self._closed = False
        except BaseException:
            if self._file_fd >= 0:
                os.close(self._file_fd)
            os.close(parent_fd)
            raise

    def close(self) -> None:
        if not getattr(self, "_closed", True):
            os.close(self._file_fd)
            os.close(self._parent_fd)
            self._closed = True

    def __enter__(self) -> "MonotonicAttestationState":
        if self._closed:
            raise AttestationStateError("attestation sequence state is closed")
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def allocate(
        self,
        allocation_id: str,
        *,
        trusted_minimum_sequence: int = 0,
    ) -> int:
        if type(allocation_id) is not str or _ALLOCATION_ID.fullmatch(allocation_id) is None:
            raise AttestationStateError("allocation_id is invalid")
        if (
            type(trusted_minimum_sequence) is not int
            or not 0 <= trusted_minimum_sequence < _MAX_INT64
        ):
            raise AttestationStateError("trusted minimum sequence is invalid")
        if self._closed:
            raise AttestationStateError("attestation sequence state is closed")
        with self._thread_lock:
            return self._allocate_locked(
                allocation_id,
                trusted_minimum_sequence=trusted_minimum_sequence,
            )

    def _allocate_locked(
        self,
        allocation_id: str,
        *,
        trusted_minimum_sequence: int,
    ) -> int:
        try:
            fcntl.flock(self._file_fd, fcntl.LOCK_EX)
            self._validate_identities()
            last_sequence, allocation_ids = self._read_state()
            if last_sequence < trusted_minimum_sequence:
                raise AttestationStateError("attestation sequence rollback detected")
            if last_sequence >= _MAX_INT64:
                raise AttestationStateError("attestation sequence is exhausted")
            if allocation_id in allocation_ids:
                raise AttestationStateError("attestation allocation_id reuse detected")
            sequence = last_sequence + 1
            encoded = json.dumps(
                {"allocation_id": allocation_id, "sequence": sequence},
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            if os.fstat(self._file_fd).st_size + len(encoded) > _MAX_STATE_BYTES:
                raise AttestationStateError("attestation sequence state exceeds its limit")
            _ = os.lseek(self._file_fd, 0, os.SEEK_END)
            self._write_all(encoded)
            os.fsync(self._file_fd)
            self._validate_identities()
            os.fsync(self._parent_fd)
            return sequence
        except AttestationStateError:
            raise
        except OSError as exc:
            raise AttestationStateError("attestation sequence state is unavailable") from exc
        finally:
            try:
                fcntl.flock(self._file_fd, fcntl.LOCK_UN)
            except OSError:
                pass

    def _validate_parent(self) -> None:
        try:
            current = os.fstat(self._parent_fd)
            named = os.stat(self._parent_path, follow_symlinks=False)
        except OSError as exc:
            raise AttestationStateError("attestation state parent is unavailable") from exc
        if (
            (current.st_dev, current.st_ino) != self._parent_identity
            or (named.st_dev, named.st_ino) != self._parent_identity
        ):
            raise AttestationStateError("attestation state parent identity changed")

    def _validate_file(self) -> tuple[int, int]:
        try:
            opened = os.fstat(self._file_fd)
            named = os.stat(self._name, dir_fd=self._parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise AttestationStateError("attestation state file is unavailable") from exc
        metadata = (opened, named)
        if any(
            not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            for value in metadata
        ):
            raise AttestationStateError("attestation state file metadata is unsafe")
        opened_identity = (opened.st_dev, opened.st_ino)
        if (named.st_dev, named.st_ino) != opened_identity:
            raise AttestationStateError("attestation state file identity changed")
        return opened_identity

    def _validate_identities(self) -> None:
        self._validate_parent()
        if self._validate_file() != self._file_identity:
            raise AttestationStateError("attestation state file identity changed")

    def _read_state(self) -> tuple[int, set[str]]:
        size = os.fstat(self._file_fd).st_size
        if size < len(_HEADER) or size > _MAX_STATE_BYTES:
            raise AttestationStateError("attestation sequence state is corrupt")
        raw = bytearray()
        offset = 0
        while offset < size:
            chunk = os.pread(self._file_fd, min(65_536, size - offset), offset)
            if not chunk:
                raise AttestationStateError("attestation sequence state is corrupt")
            raw.extend(chunk)
            offset += len(chunk)
        if not raw.startswith(_HEADER) or not raw.endswith(b"\n"):
            raise AttestationStateError("attestation sequence state is corrupt")
        records = bytes(raw[len(_HEADER) :]).splitlines()
        allocation_ids: set[str] = set()
        last_sequence = 0
        for encoded in records:
            try:
                record = json.loads(encoded)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise AttestationStateError("attestation sequence state is corrupt") from None
            if (
                type(record) is not dict
                or set(record) != {"allocation_id", "sequence"}
                or type(record["allocation_id"]) is not str
                or _ALLOCATION_ID.fullmatch(record["allocation_id"]) is None
                or type(record["sequence"]) is not int
                or record["sequence"] != last_sequence + 1
                or record["allocation_id"] in allocation_ids
            ):
                raise AttestationStateError("attestation sequence state is corrupt")
            canonical = json.dumps(
                record,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if canonical != encoded:
                raise AttestationStateError("attestation sequence state is corrupt")
            last_sequence = record["sequence"]
            allocation_ids.add(record["allocation_id"])
        return last_sequence, allocation_ids

    def _write_all(self, value: bytes) -> None:
        offset = 0
        while offset < len(value):
            written = os.write(self._file_fd, value[offset:])
            if written <= 0:
                raise AttestationStateError("attestation sequence state write failed")
            offset += written


__all__ = ["AttestationStateError", "MonotonicAttestationState"]
