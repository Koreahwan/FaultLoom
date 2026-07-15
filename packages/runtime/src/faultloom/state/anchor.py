"""Authenticated external checkpoints and engagement-scoped process locks."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .cas import EngagementKey
from .filesystem import (
    DirectoryBinding,
    NOFOLLOW,
    PRIVATE_FILE_MODE,
    inode_identity,
    open_private_directory,
    require_private_file,
)
from .types import ChainIntegrityError, CrossEngagementError, StorageError, require_identifier


ANCHOR_SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
MAX_ANCHOR_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class AnchorCheckpoint:
    """A caller-retained freshness floor for one authenticated chain head."""

    engagement_id: str
    seq: int
    head: str

    def __post_init__(self) -> None:
        require_identifier(self.engagement_id, field="engagement_id")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 0:
            raise StorageError("anchor sequence is invalid")
        if (
            not isinstance(self.head, str)
            or len(self.head) != 64
            or any(character not in "0123456789abcdef" for character in self.head)
        ):
            raise StorageError("anchor head is not a lowercase SHA-256 digest")
        if self.seq == 0 and self.head != ZERO_HASH:
            raise StorageError("empty anchor must use the zero hash")


class EngagementLock:
    """A private stable-inode advisory lock shared by all StateStore processes."""

    def __init__(
        self,
        anchor_root: Path,
        engagement_id: str,
        *,
        path_validator: Callable[[], None] | None = None,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        self._path_validator = path_validator
        self._root_binding = DirectoryBinding(
            Path(anchor_root), create=True, context="external anchor root"
        )
        self._root_fd = self._root_binding.descriptor
        try:
            self._locks_fd = open_private_directory(
                self._root_fd, "locks", create=True
            )
        except Exception:
            self._root_binding.close()
            raise
        self._locks_identity = inode_identity(os.fstat(self._locks_fd))
        namespace = hashlib.sha256(self.engagement_id.encode("utf-8")).hexdigest()
        self._name = f"{namespace}.lock"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self._name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                PRIVATE_FILE_MODE,
                dir_fd=self._locks_fd,
            )
            os.fsync(descriptor)
            os.fsync(self._locks_fd)
        except FileExistsError:
            try:
                descriptor = os.open(
                    self._name,
                    os.O_RDWR | NOFOLLOW,
                    dir_fd=self._locks_fd,
                )
            except OSError as exc:
                self._close_directories()
                raise StorageError("cannot safely open engagement lock") from exc
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            self._close_directories()
            raise StorageError("cannot create engagement lock") from exc
        if descriptor is None:
            self._close_directories()
            raise StorageError("cannot initialize engagement lock")
        try:
            require_private_file(os.fstat(descriptor), context="engagement lock")
        except Exception:
            os.close(descriptor)
            self._close_directories()
            raise
        self._descriptor = descriptor
        self._identity = inode_identity(os.fstat(descriptor))
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._closed = False
        try:
            self._revalidate()
        except Exception:
            os.close(self._descriptor)
            self._close_directories()
            self._closed = True
            raise

    def _close_directories(self) -> None:
        os.close(self._locks_fd)
        self._root_binding.close()

    def _revalidate(self) -> None:
        self._root_binding.revalidate()
        locks_fd = open_private_directory(self._root_fd, "locks", create=False)
        try:
            if inode_identity(os.fstat(locks_fd)) != self._locks_identity:
                raise StorageError("engagement lock directory path identity changed")
        finally:
            os.close(locks_fd)
        try:
            metadata = os.stat(self._name, dir_fd=self._locks_fd, follow_symlinks=False)
        except OSError as exc:
            raise StorageError("engagement lock path disappeared") from exc
        require_private_file(metadata, context="engagement lock path")
        if inode_identity(metadata) != self._identity:
            raise StorageError("engagement lock inode changed")
        if self._path_validator is not None:
            self._path_validator()

    def __enter__(self) -> EngagementLock:
        if self._closed:
            raise StorageError("engagement lock is closed")
        self._thread_lock.acquire()
        flock_acquired = False
        try:
            if self._depth == 0:
                self._revalidate()
                fcntl.flock(self._descriptor, fcntl.LOCK_EX)
                flock_acquired = True
                self._revalidate()
            self._depth += 1
            return self
        except Exception:
            if flock_acquired:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            self._thread_lock.release()
            raise

    def __exit__(self, *_: object) -> None:
        failure: Exception | None = None
        try:
            self._depth -= 1
            if self._depth == 0:
                try:
                    self._revalidate()
                except Exception as exc:
                    failure = exc
        finally:
            if self._depth == 0:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            self._thread_lock.release()
        if failure is not None:
            raise failure

    def close(self) -> None:
        if self._closed:
            return
        if self._depth:
            raise StorageError("cannot close a held engagement lock")
        failure: Exception | None = None
        try:
            self._revalidate()
        except Exception as exc:
            failure = exc
        finally:
            os.close(self._descriptor)
            self._close_directories()
            self._closed = True
        if failure is not None:
            raise failure


class AuthenticatedAnchor:
    """Key-authenticated chain checkpoint stored outside the mutable state root."""

    def __init__(
        self,
        anchor_root: Path,
        engagement_id: str,
        key: EngagementKey,
        *,
        path_validator: Callable[[], None] | None = None,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        material = key._copy_for_cipher()
        context = self.engagement_id.encode("utf-8")
        self._authentication_key = hmac.digest(
            material, b"faultloom-anchor-auth-v1\0" + context, "sha256"
        )
        self._key_commitment = hmac.digest(
            material, b"faultloom-engagement-key-v1\0" + context, "sha256"
        ).hex()
        self._path_validator = path_validator
        self._root_binding = DirectoryBinding(
            Path(anchor_root), create=True, context="external anchor root"
        )
        self._root_fd = self._root_binding.descriptor
        try:
            self._anchors_fd = open_private_directory(
                self._root_fd, "anchors", create=True
            )
        except Exception:
            self._root_binding.close()
            raise
        self._anchors_identity = inode_identity(os.fstat(self._anchors_fd))
        namespace = hashlib.sha256(self.engagement_id.encode("utf-8")).hexdigest()
        self._name = f"{namespace}.anchor"
        self._closed = False
        try:
            self._validate_paths()
        except Exception:
            os.close(self._anchors_fd)
            self._root_binding.close()
            self._closed = True
            raise

    def _validate_paths(self) -> None:
        self._root_binding.revalidate()
        anchors_fd = open_private_directory(self._root_fd, "anchors", create=False)
        try:
            if inode_identity(os.fstat(anchors_fd)) != self._anchors_identity:
                raise StorageError("authenticated anchor directory path identity changed")
        finally:
            os.close(anchors_fd)
        if self._path_validator is not None:
            self._path_validator()

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        try:
            self._validate_paths()
        except Exception as exc:
            failure = exc
        finally:
            os.close(self._anchors_fd)
            self._root_binding.close()
            self._closed = True
        if failure is not None:
            raise failure

    def _body(self, checkpoint: AnchorCheckpoint) -> dict[str, Any]:
        return {
            "engagement_id": checkpoint.engagement_id,
            "head": checkpoint.head,
            "key_commitment": self._key_commitment,
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "seq": checkpoint.seq,
        }

    def _encoded(self, checkpoint: AnchorCheckpoint) -> bytes:
        body = self._body(checkpoint)
        tag = hmac.digest(
            self._authentication_key,
            canonical_json(body).encode("utf-8"),
            "sha256",
        ).hex()
        return (canonical_json({**body, "tag": tag}) + "\n").encode("utf-8")

    def load_optional(self) -> AnchorCheckpoint | None:
        if self._closed:
            raise StorageError("authenticated anchor is closed")
        self._validate_paths()
        try:
            descriptor = os.open(
                self._name,
                os.O_RDONLY | NOFOLLOW,
                dir_fd=self._anchors_fd,
            )
        except FileNotFoundError:
            self._validate_paths()
            return None
        except OSError as exc:
            raise StorageError("cannot safely open authenticated anchor") from exc
        try:
            opened = os.fstat(descriptor)
            require_private_file(opened, context="authenticated anchor")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(4096, MAX_ANCHOR_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_ANCHOR_BYTES:
                    raise ChainIntegrityError("authenticated anchor is oversized")
            data = b"".join(chunks)
        finally:
            os.close(descriptor)
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChainIntegrityError("authenticated anchor is invalid JSON") from exc
        expected_keys = {
            "engagement_id",
            "head",
            "key_commitment",
            "schema_version",
            "seq",
            "tag",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ChainIntegrityError("authenticated anchor schema is invalid")
        if value["schema_version"] != ANCHOR_SCHEMA_VERSION:
            raise ChainIntegrityError("authenticated anchor version is unsupported")
        if value["engagement_id"] != self.engagement_id:
            raise CrossEngagementError("authenticated anchor belongs to another engagement")
        body = {key: value[key] for key in expected_keys if key != "tag"}
        expected_tag = hmac.digest(
            self._authentication_key,
            canonical_json(body).encode("utf-8"),
            "sha256",
        ).hex()
        if not isinstance(value["tag"], str) or not hmac.compare_digest(
            value["tag"], expected_tag
        ):
            raise ChainIntegrityError("authenticated anchor key or tag is invalid")
        if not hmac.compare_digest(str(value["key_commitment"]), self._key_commitment):
            raise ChainIntegrityError("engagement key commitment is invalid")
        checkpoint = AnchorCheckpoint(
            engagement_id=self.engagement_id,
            seq=value["seq"],
            head=value["head"],
        )
        if self._encoded(checkpoint) != data:
            raise ChainIntegrityError("authenticated anchor encoding is not canonical")
        named_after = os.stat(
            self._name, dir_fd=self._anchors_fd, follow_symlinks=False
        )
        if inode_identity(named_after) != inode_identity(opened):
            raise ChainIntegrityError("authenticated anchor name changed while reading")
        self._validate_paths()
        return checkpoint

    def write(self, checkpoint: AnchorCheckpoint) -> None:
        self._validate_paths()
        if checkpoint.engagement_id != self.engagement_id:
            raise CrossEngagementError("cannot write a foreign engagement anchor")
        encoded = self._encoded(checkpoint)
        temporary = f".{self._name}.tmp-{secrets.token_hex(16)}"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                PRIVATE_FILE_MODE,
                dir_fd=self._anchors_fd,
            )
            offset = 0
            while offset < len(encoded):
                count = os.write(descriptor, encoded[offset:])
                if count <= 0:
                    raise StorageError("short write to authenticated anchor")
                offset += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary,
                self._name,
                src_dir_fd=self._anchors_fd,
                dst_dir_fd=self._anchors_fd,
            )
            os.fsync(self._anchors_fd)
            self._validate_paths()
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._anchors_fd)
            except FileNotFoundError:
                pass
