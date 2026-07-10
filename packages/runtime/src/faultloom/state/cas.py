"""Encrypted, engagement-namespaced content-addressed storage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_json
from .types import (
    ChainIntegrityError,
    CrossEngagementError,
    StorageError,
    require_identifier,
    require_sha256,
)


MAGIC = b"FLCAS01\0"
NONCE_BYTES = 12
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_REFERENCE_BYTES = 2**31
MAX_PAGE_BYTES = 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """A typed reference to encrypted bytes owned by one engagement."""

    engagement_id: str
    sha256: str
    byte_length: int
    media_type: str = "application/octet-stream"
    schema_version: int = 1

    def __post_init__(self) -> None:
        require_identifier(self.engagement_id, field="engagement_id")
        require_sha256(self.sha256)
        if self.schema_version != 1:
            raise StorageError("unsupported ArtifactRef schema_version")
        if not isinstance(self.byte_length, int) or isinstance(self.byte_length, bool):
            raise StorageError("byte_length must be an integer")
        if self.byte_length < 0 or self.byte_length > MAX_REFERENCE_BYTES:
            raise StorageError("byte_length is outside the supported range")
        if (
            not isinstance(self.media_type, str)
            or not self.media_type
            or len(self.media_type) > 255
            or "\x00" in self.media_type
        ):
            raise StorageError("media_type is invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ArtifactRef:
        if set(value) != {
            "engagement_id",
            "sha256",
            "byte_length",
            "media_type",
            "schema_version",
        }:
            raise StorageError("ArtifactRef keys do not match schema version 1")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class RetrievalPage:
    data: bytes
    offset: int
    total_bytes: int
    next_cursor: str | None


class EngagementKey:
    """Non-serializable in-memory key material supplied by the operator vault."""

    __slots__ = ("__material",)

    def __init__(self, material: bytes) -> None:
        if not isinstance(material, bytes) or len(material) != 32:
            raise StorageError("engagement encryption key must be exactly 32 bytes")
        self.__material = material

    @classmethod
    def generate(cls) -> EngagementKey:
        return cls(secrets.token_bytes(32))

    def _copy_for_cipher(self) -> bytes:
        return bytes(self.__material)

    def __repr__(self) -> str:
        return "EngagementKey(<redacted>)"

    def __reduce__(self) -> object:
        raise TypeError("EngagementKey cannot be serialized")


def _open_directory(parent_fd: int, name: str, *, create: bool) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise StorageError("unsafe CAS directory component")
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise StorageError(f"cannot safely open CAS directory component {name!r}") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        raise StorageError("CAS path component is not a directory")
    return descriptor


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise StorageError("short write to encrypted CAS")
        written += count


def _read_all(descriptor: int, *, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ChainIntegrityError("encrypted artifact exceeds its configured maximum")


class EncryptedCAS:
    """AES-GCM CAS that never stores plaintext or keys on disk."""

    def __init__(
        self,
        root: Path,
        engagement_id: str,
        key: EngagementKey,
        *,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        if not isinstance(max_artifact_bytes, int) or not 1 <= max_artifact_bytes <= 2**31:
            raise StorageError("max_artifact_bytes is invalid")
        self.max_artifact_bytes = max_artifact_bytes
        self._key = key
        self._cipher = AESGCM(key._copy_for_cipher())
        self._cursor_key = hmac.digest(
            key._copy_for_cipher(), b"faultloom-cas-cursor-v1", "sha256"
        )
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink():
            raise StorageError("CAS root must not be a symlink")
        os.chmod(root, 0o700)
        self._root_fd = os.open(root, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        opened = os.fstat(self._root_fd)
        if not stat.S_ISDIR(opened.st_mode):
            os.close(self._root_fd)
            raise StorageError("CAS root is not a directory")
        namespace = hashlib.sha256(self.engagement_id.encode("utf-8")).hexdigest()
        self._namespace_fd = _open_directory(self._root_fd, namespace, create=True)
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        os.close(self._namespace_fd)
        os.close(self._root_fd)
        self._closed = True

    def __enter__(self) -> EncryptedCAS:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise StorageError("CAS is closed")

    def _validate_ref(self, reference: ArtifactRef) -> None:
        if reference.engagement_id != self.engagement_id:
            raise CrossEngagementError("artifact belongs to another engagement")
        if reference.byte_length > self.max_artifact_bytes:
            raise StorageError("artifact exceeds this CAS limit")

    def _aad(self, reference: ArtifactRef) -> bytes:
        # Media type is descriptive metadata, not part of the content address.
        # Excluding it permits the same immutable bytes to be referenced from
        # different observations without rewriting or weakening the envelope.
        return canonical_json(
            {
                "byte_length": reference.byte_length,
                "engagement_id": reference.engagement_id,
                "schema_version": reference.schema_version,
                "sha256": reference.sha256,
            }
        ).encode("utf-8")

    def _open_shard(self, digest: str, *, create: bool) -> int:
        require_sha256(digest)
        return _open_directory(self._namespace_fd, digest[:2], create=create)

    @staticmethod
    def _filename(digest: str) -> str:
        return f"{digest}.flcas"

    def _read_envelope(self, reference: ArtifactRef) -> bytes:
        self._validate_ref(reference)
        shard_fd = self._open_shard(reference.sha256, create=False)
        try:
            try:
                descriptor = os.open(
                    self._filename(reference.sha256), os.O_RDONLY | NOFOLLOW, dir_fd=shard_fd
                )
            except OSError as exc:
                raise ChainIntegrityError("encrypted artifact is missing") from exc
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise ChainIntegrityError("encrypted artifact is not a private regular file")
                maximum = self.max_artifact_bytes + len(MAGIC) + NONCE_BYTES + 16
                return _read_all(descriptor, maximum=maximum)
            finally:
                os.close(descriptor)
        finally:
            os.close(shard_fd)

    def _decrypt(self, reference: ArtifactRef, envelope: bytes) -> bytes:
        if len(envelope) < len(MAGIC) + NONCE_BYTES + 16 or not envelope.startswith(MAGIC):
            raise ChainIntegrityError("encrypted artifact envelope is invalid")
        nonce_start = len(MAGIC)
        nonce = envelope[nonce_start : nonce_start + NONCE_BYTES]
        ciphertext = envelope[nonce_start + NONCE_BYTES :]
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, self._aad(reference))
        except InvalidTag as exc:
            raise ChainIntegrityError("artifact authentication failed") from exc
        if len(plaintext) != reference.byte_length:
            raise ChainIntegrityError("artifact length does not match its reference")
        actual = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual, reference.sha256):
            raise ChainIntegrityError("artifact plaintext digest mismatch")
        return plaintext

    def put(self, data: bytes, *, media_type: str = "application/octet-stream") -> ArtifactRef:
        self._require_open()
        if not isinstance(data, bytes):
            raise StorageError("CAS accepts bytes only")
        if len(data) > self.max_artifact_bytes:
            raise StorageError("artifact exceeds configured byte limit")
        reference = ArtifactRef(
            engagement_id=self.engagement_id,
            sha256=hashlib.sha256(data).hexdigest(),
            byte_length=len(data),
            media_type=media_type,
        )
        nonce = secrets.token_bytes(NONCE_BYTES)
        envelope = MAGIC + nonce + self._cipher.encrypt(nonce, data, self._aad(reference))
        shard_fd = self._open_shard(reference.sha256, create=True)
        temporary = f".tmp-{secrets.token_hex(16)}"
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                    0o600,
                    dir_fd=shard_fd,
                )
                _write_all(descriptor, envelope)
                os.fsync(descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            os.replace(
                temporary,
                self._filename(reference.sha256),
                src_dir_fd=shard_fd,
                dst_dir_fd=shard_fd,
            )
            os.fsync(shard_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=shard_fd)
            except FileNotFoundError:
                pass
            os.close(shard_fd)
        return reference

    def get(self, reference: ArtifactRef) -> bytes:
        self._require_open()
        return self._decrypt(reference, self._read_envelope(reference))

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64decode(value: str) -> bytes:
        if not isinstance(value, str) or not value:
            raise StorageError("cursor segment is invalid")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, UnicodeEncodeError) as exc:
            raise StorageError("cursor is not valid Base64URL") from exc
        if EncryptedCAS._b64encode(decoded) != value:
            raise StorageError("cursor is not canonical Base64URL")
        return decoded

    def _cursor(self, reference: ArtifactRef, offset: int) -> str:
        payload = canonical_json(
            {
                "engagement_id": self.engagement_id,
                "offset": offset,
                "sha256": reference.sha256,
                "version": 1,
            }
        ).encode("utf-8")
        signature = hmac.digest(self._cursor_key, payload, "sha256")
        return f"{self._b64encode(payload)}.{self._b64encode(signature)}"

    def _cursor_offset(self, reference: ArtifactRef, cursor: str) -> int:
        segments = cursor.split(".")
        if len(segments) != 2:
            raise StorageError("cursor format is invalid")
        payload = self._b64decode(segments[0])
        signature = self._b64decode(segments[1])
        expected = hmac.digest(self._cursor_key, payload, "sha256")
        if not hmac.compare_digest(signature, expected):
            raise StorageError("cursor signature is invalid")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError("cursor payload is invalid") from exc
        expected_keys = {"engagement_id", "offset", "sha256", "version"}
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise StorageError("cursor payload schema is invalid")
        if canonical_json(value).encode("utf-8") != payload:
            raise StorageError("cursor payload is not canonical")
        if value["engagement_id"] != self.engagement_id:
            raise CrossEngagementError("cursor belongs to another engagement")
        if value["sha256"] != reference.sha256 or value["version"] != 1:
            raise StorageError("cursor does not match the requested artifact")
        offset = value["offset"]
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or not 0 <= offset <= reference.byte_length
        ):
            raise StorageError("cursor offset is invalid")
        return offset

    def read_page(
        self,
        reference: ArtifactRef,
        *,
        cursor: str | None = None,
        max_bytes: int = 64 * 1024,
    ) -> RetrievalPage:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
            raise StorageError("max_bytes must be an integer")
        if not 1 <= max_bytes <= MAX_PAGE_BYTES:
            raise StorageError("max_bytes is outside the bounded retrieval range")
        offset = 0 if cursor is None else self._cursor_offset(reference, cursor)
        plaintext = self.get(reference)
        end = min(len(plaintext), offset + max_bytes)
        next_cursor = self._cursor(reference, end) if end < len(plaintext) else None
        return RetrievalPage(
            data=plaintext[offset:end],
            offset=offset,
            total_bytes=len(plaintext),
            next_cursor=next_cursor,
        )

    def blob_digests(self) -> tuple[str, ...]:
        """Return only live CAS object IDs; orphan quarantine is excluded."""

        self._require_open()
        result: list[str] = []
        for shard in os.listdir(self._namespace_fd):
            if len(shard) != 2 or any(character not in "0123456789abcdef" for character in shard):
                continue
            shard_fd = _open_directory(self._namespace_fd, shard, create=False)
            try:
                for filename in os.listdir(shard_fd):
                    if not filename.endswith(".flcas"):
                        continue
                    digest = filename.removesuffix(".flcas")
                    if len(digest) == 64 and digest.startswith(shard):
                        require_sha256(digest)
                        entry = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
                        if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                            raise ChainIntegrityError("CAS contains a non-private artifact entry")
                        result.append(digest)
            finally:
                os.close(shard_fd)
        return tuple(sorted(result))

    def temporary_entries(self) -> tuple[tuple[str, str], ...]:
        """Return interrupted pre-publication writes for crash reconciliation."""

        self._require_open()
        result: list[tuple[str, str]] = []
        for shard in os.listdir(self._namespace_fd):
            if len(shard) != 2 or any(character not in "0123456789abcdef" for character in shard):
                continue
            shard_fd = _open_directory(self._namespace_fd, shard, create=False)
            try:
                for filename in os.listdir(shard_fd):
                    if not filename.startswith(".tmp-"):
                        continue
                    suffix = filename.removeprefix(".tmp-")
                    if len(suffix) != 32 or any(
                        character not in "0123456789abcdef" for character in suffix
                    ):
                        raise ChainIntegrityError("CAS contains an unknown temporary entry")
                    entry = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
                    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                        raise ChainIntegrityError(
                            "CAS temporary entry is not a private regular file"
                        )
                    result.append((shard, filename))
            finally:
                os.close(shard_fd)
        return tuple(sorted(result))

    def quarantine_temporary(
        self, shard: str, filename: str, *, recovery_id: str
    ) -> None:
        self._require_open()
        if (
            len(shard) != 2
            or any(character not in "0123456789abcdef" for character in shard)
            or not filename.startswith(".tmp-")
        ):
            raise StorageError("temporary CAS entry identity is invalid")
        require_identifier(recovery_id, field="recovery_id")
        source_fd = _open_directory(self._namespace_fd, shard, create=False)
        orphan_fd = _open_directory(self._namespace_fd, "orphaned", create=True)
        recovery_fd = _open_directory(orphan_fd, recovery_id, create=True)
        target = f"{shard}-{filename.removeprefix('.tmp-')}.interrupted"
        try:
            descriptor = os.open(filename, os.O_RDONLY | NOFOLLOW, dir_fd=source_fd)
            try:
                entry = os.fstat(descriptor)
                if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                    raise ChainIntegrityError("interrupted write changed during recovery")
            finally:
                os.close(descriptor)
            try:
                os.link(
                    filename,
                    target,
                    src_dir_fd=source_fd,
                    dst_dir_fd=recovery_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ChainIntegrityError("interrupted-write quarantine collision") from exc
            os.unlink(filename, dir_fd=source_fd)
            os.fsync(source_fd)
            os.fsync(recovery_fd)
        finally:
            os.close(recovery_fd)
            os.close(orphan_fd)
            os.close(source_fd)

    def quarantine_orphan(self, digest: str, *, recovery_id: str) -> None:
        self._require_open()
        require_sha256(digest)
        require_identifier(recovery_id, field="recovery_id")
        source_fd = self._open_shard(digest, create=False)
        orphan_fd = _open_directory(self._namespace_fd, "orphaned", create=True)
        recovery_fd = _open_directory(orphan_fd, recovery_id, create=True)
        try:
            try:
                descriptor = os.open(
                    self._filename(digest),
                    os.O_RDONLY | NOFOLLOW,
                    dir_fd=source_fd,
                )
                try:
                    entry = os.fstat(descriptor)
                    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                        raise ChainIntegrityError("orphan is not a private regular file")
                finally:
                    os.close(descriptor)
                os.link(
                    self._filename(digest),
                    self._filename(digest),
                    src_dir_fd=source_fd,
                    dst_dir_fd=recovery_fd,
                    follow_symlinks=False,
                )
                os.unlink(self._filename(digest), dir_fd=source_fd)
            except FileNotFoundError as exc:
                raise ChainIntegrityError("orphan disappeared during recovery") from exc
            except FileExistsError as exc:
                raise ChainIntegrityError("orphan quarantine collision") from exc
            os.fsync(source_fd)
            os.fsync(recovery_fd)
        finally:
            os.close(recovery_fd)
            os.close(orphan_fd)
            os.close(source_fd)
