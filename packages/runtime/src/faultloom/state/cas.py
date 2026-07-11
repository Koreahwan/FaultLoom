"""Encrypted, engagement-namespaced content-addressed storage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_json
from .filesystem import (
    DirectoryBinding,
    NOFOLLOW,
    PRIVATE_FILE_MODE,
    inode_identity,
    open_private_directory,
    require_private_file,
)
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
MAX_NONCE_ATTEMPTS = 32


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
    return open_private_directory(parent_fd, name, create=create)


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
        path_validator: Callable[[], None] | None = None,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        if not isinstance(max_artifact_bytes, int) or not 1 <= max_artifact_bytes <= 2**31:
            raise StorageError("max_artifact_bytes is invalid")
        self.max_artifact_bytes = max_artifact_bytes
        self._key = key
        key_material = key._copy_for_cipher()
        engagement_context = self.engagement_id.encode("utf-8")
        aead_key = hmac.digest(
            key_material,
            b"faultloom-cas-aead-v1\0" + engagement_context,
            "sha256",
        )
        self._cipher = AESGCM(aead_key)
        self._cursor_key = hmac.digest(
            key_material,
            b"faultloom-cas-cursor-v1\0" + engagement_context,
            "sha256",
        )
        self._path_validator = path_validator
        self._root_binding = DirectoryBinding(
            Path(root), create=True, context="encrypted CAS root"
        )
        self._root_fd = self._root_binding.descriptor
        self._namespace = hashlib.sha256(
            self.engagement_id.encode("utf-8")
        ).hexdigest()
        namespace_fd: int | None = None
        nonces_fd: int | None = None
        try:
            namespace_fd = _open_directory(
                self._root_fd, self._namespace, create=True
            )
            self._namespace_fd = namespace_fd
            self._namespace_identity = inode_identity(os.fstat(self._namespace_fd))
            nonces_fd = _open_directory(
                self._namespace_fd, "nonces", create=True
            )
            self._nonces_fd = nonces_fd
            self._nonces_identity = inode_identity(os.fstat(self._nonces_fd))
        except Exception:
            if nonces_fd is not None:
                os.close(nonces_fd)
            if namespace_fd is not None:
                os.close(namespace_fd)
            self._root_binding.close()
            raise
        self._closed = False
        try:
            self._validate_paths()
        except Exception:
            os.close(self._nonces_fd)
            os.close(self._namespace_fd)
            self._root_binding.close()
            self._closed = True
            raise

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        try:
            self._validate_paths()
        except Exception as exc:
            failure = exc
        finally:
            os.close(self._nonces_fd)
            os.close(self._namespace_fd)
            self._root_binding.close()
            self._closed = True
        if failure is not None:
            raise failure

    def __enter__(self) -> EncryptedCAS:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise StorageError("CAS is closed")
        self._validate_paths()

    def _validate_paths(self) -> None:
        self._root_binding.revalidate()
        namespace_fd = _open_directory(
            self._root_fd, self._namespace, create=False
        )
        try:
            if inode_identity(os.fstat(namespace_fd)) != self._namespace_identity:
                raise StorageError("encrypted CAS namespace path identity changed")
            nonces_fd = _open_directory(namespace_fd, "nonces", create=False)
            try:
                if inode_identity(os.fstat(nonces_fd)) != self._nonces_identity:
                    raise StorageError("CAS nonce registry path identity changed")
            finally:
                os.close(nonces_fd)
        finally:
            os.close(namespace_fd)
        if self._path_validator is not None:
            self._path_validator()

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

    @contextmanager
    def _opened_envelope(self, reference: ArtifactRef) -> Iterator[bytes]:
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
                try:
                    require_private_file(opened, context="encrypted artifact")
                except StorageError as exc:
                    raise ChainIntegrityError(str(exc)) from exc
                filename = self._filename(reference.sha256)
                try:
                    named = os.stat(
                        filename, dir_fd=shard_fd, follow_symlinks=False
                    )
                except OSError as exc:
                    raise ChainIntegrityError(
                        "encrypted artifact name changed while opening"
                    ) from exc
                if inode_identity(named) != inode_identity(opened):
                    raise ChainIntegrityError(
                        "encrypted artifact name changed while opening"
                    )
                maximum = self.max_artifact_bytes + len(MAGIC) + NONCE_BYTES + 16
                envelope = _read_all(descriptor, maximum=maximum)
                yield envelope
                self._validate_paths()
                visible_shard = self._open_shard(reference.sha256, create=False)
                try:
                    if inode_identity(os.fstat(visible_shard)) != inode_identity(
                        os.fstat(shard_fd)
                    ):
                        raise ChainIntegrityError(
                            "encrypted artifact shard path identity changed"
                        )
                    after = os.fstat(descriptor)
                    try:
                        named_after = os.stat(
                            filename,
                            dir_fd=visible_shard,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise ChainIntegrityError(
                            "encrypted artifact final name changed during validation"
                        ) from exc
                    if (
                        inode_identity(after) != inode_identity(opened)
                        or inode_identity(named_after) != inode_identity(opened)
                        or after.st_nlink != opened.st_nlink
                        or after.st_size != opened.st_size
                        or after.st_mtime_ns != opened.st_mtime_ns
                        or after.st_ctime_ns != opened.st_ctime_ns
                    ):
                        raise ChainIntegrityError(
                            "encrypted artifact final name changed during validation"
                        )
                    try:
                        require_private_file(after, context="encrypted artifact")
                        require_private_file(
                            named_after, context="encrypted artifact path"
                        )
                    except StorageError as exc:
                        raise ChainIntegrityError(str(exc)) from exc
                finally:
                    os.close(visible_shard)
                self._validate_paths()
            finally:
                os.close(descriptor)
        finally:
            os.close(shard_fd)

    def _read_envelope(self, reference: ArtifactRef) -> bytes:
        with self._opened_envelope(reference) as envelope:
            return envelope

    def _decrypt(self, reference: ArtifactRef, envelope: bytes) -> bytes:
        if len(envelope) < len(MAGIC) + NONCE_BYTES + 16 or not envelope.startswith(MAGIC):
            raise ChainIntegrityError("encrypted artifact envelope is invalid")
        nonce_start = len(MAGIC)
        nonce = envelope[nonce_start : nonce_start + NONCE_BYTES]
        nonce_name = f"{nonce.hex()}.nonce"
        try:
            reservation = os.stat(
                nonce_name, dir_fd=self._nonces_fd, follow_symlinks=False
            )
            require_private_file(reservation, context="artifact nonce reservation")
        except (OSError, StorageError) as exc:
            raise ChainIntegrityError("artifact nonce is not durably reserved") from exc
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

    def _reserve_nonce(self) -> bytes:
        for _ in range(MAX_NONCE_ATTEMPTS):
            nonce = secrets.token_bytes(NONCE_BYTES)
            name = f"{nonce.hex()}.nonce"
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                    PRIVATE_FILE_MODE,
                    dir_fd=self._nonces_fd,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise StorageError("cannot reserve an encryption nonce") from exc
            try:
                require_private_file(os.fstat(descriptor), context="nonce reservation")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(self._nonces_fd)
            return nonce
        raise StorageError("encryption nonce generator repeated a reserved nonce")

    def _object_path_exists(self, reference: ArtifactRef) -> bool:
        try:
            os.stat(reference.sha256[:2], dir_fd=self._namespace_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        try:
            shard_fd = self._open_shard(reference.sha256, create=False)
            try:
                os.stat(
                    self._filename(reference.sha256),
                    dir_fd=shard_fd,
                    follow_symlinks=False,
                )
            finally:
                os.close(shard_fd)
        except FileNotFoundError:
            return False
        return True

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
        if self._object_path_exists(reference):
            with self._opened_envelope(reference) as existing:
                self._decrypt(reference, existing)
                self._validate_paths()
                return reference
        nonce = self._reserve_nonce()
        envelope = MAGIC + nonce + self._cipher.encrypt(nonce, data, self._aad(reference))
        shard_fd = self._open_shard(reference.sha256, create=True)
        temporary = f".tmp-{secrets.token_hex(16)}"
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                    PRIVATE_FILE_MODE,
                    dir_fd=shard_fd,
                )
                require_private_file(os.fstat(descriptor), context="temporary CAS artifact")
                _write_all(descriptor, envelope)
                os.fsync(descriptor)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            try:
                os.link(
                    temporary,
                    self._filename(reference.sha256),
                    src_dir_fd=shard_fd,
                    dst_dir_fd=shard_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass
            os.fsync(shard_fd)
            os.unlink(temporary, dir_fd=shard_fd)
            temporary = ""
            os.fsync(shard_fd)
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=shard_fd)
                except FileNotFoundError:
                    pass
            os.close(shard_fd)
        with self._opened_envelope(reference) as persisted:
            self._decrypt(reference, persisted)
            self._validate_paths()
            return reference

    def get(self, reference: ArtifactRef) -> bytes:
        self._require_open()
        with self._opened_envelope(reference) as envelope:
            plaintext = self._decrypt(reference, envelope)
            self._validate_paths()
            return plaintext

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
        page = RetrievalPage(
            data=plaintext[offset:end],
            offset=offset,
            total_bytes=len(plaintext),
            next_cursor=next_cursor,
        )
        self._validate_paths()
        return page

    def blob_digests(self) -> tuple[str, ...]:
        """Return only live CAS object IDs; orphan quarantine is excluded."""

        self._require_open()
        result: list[str] = []
        for shard in self._validated_shards():
            shard_fd = _open_directory(self._namespace_fd, shard, create=False)
            try:
                finals, _ = self._validated_shard_entries(shard_fd, shard)
                for filename in finals:
                    digest = filename.removesuffix(".flcas")
                    result.append(digest)
            finally:
                os.close(shard_fd)
        digests = tuple(sorted(result))
        self._validate_paths()
        return digests

    def temporary_entries(self) -> tuple[tuple[str, str], ...]:
        """Return interrupted pre-publication writes for crash reconciliation."""

        self._require_open()
        result: list[tuple[str, str]] = []
        for shard in self._validated_shards():
            shard_fd = _open_directory(self._namespace_fd, shard, create=False)
            try:
                _, temporary = self._validated_shard_entries(shard_fd, shard)
                for filename in temporary:
                    result.append((shard, filename))
            finally:
                os.close(shard_fd)
        entries = tuple(sorted(result))
        self._validate_paths()
        return entries

    @staticmethod
    def _is_lower_hex(value: str, length: int) -> bool:
        return len(value) == length and all(
            character in "0123456789abcdef" for character in value
        )

    def _validate_nonce_registry(self) -> None:
        for filename in os.listdir(self._nonces_fd):
            stem = filename.removesuffix(".nonce")
            if not filename.endswith(".nonce") or not self._is_lower_hex(stem, 24):
                raise ChainIntegrityError("CAS nonce registry contains an unknown entry")
            try:
                metadata = os.stat(filename, dir_fd=self._nonces_fd, follow_symlinks=False)
                require_private_file(metadata, context="CAS nonce reservation")
            except (OSError, StorageError) as exc:
                raise ChainIntegrityError("CAS nonce reservation is not private") from exc
            if metadata.st_size != 0:
                raise ChainIntegrityError("CAS nonce reservation has unexpected content")

    def _validate_orphan_quarantine(self) -> None:
        try:
            orphan_fd = _open_directory(self._namespace_fd, "orphaned", create=False)
        except StorageError as exc:
            try:
                os.stat("orphaned", dir_fd=self._namespace_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ChainIntegrityError("CAS orphan quarantine is unsafe") from exc
        try:
            for recovery_id in os.listdir(orphan_fd):
                try:
                    require_identifier(recovery_id, field="recovery_id")
                    recovery_fd = _open_directory(orphan_fd, recovery_id, create=False)
                except StorageError as exc:
                    raise ChainIntegrityError(
                        "CAS orphan quarantine contains an unknown entry"
                    ) from exc
                try:
                    for filename in os.listdir(recovery_fd):
                        digest = filename.removesuffix(".flcas")
                        interrupted = filename.removesuffix(".interrupted")
                        valid = (
                            filename.endswith(".flcas")
                            and self._is_lower_hex(digest, 64)
                        ) or (
                            filename.endswith(".interrupted")
                            and len(interrupted) == 35
                            and interrupted[2] == "-"
                            and self._is_lower_hex(interrupted[:2], 2)
                            and self._is_lower_hex(interrupted[3:], 32)
                        )
                        if not valid:
                            raise ChainIntegrityError(
                                "CAS orphan quarantine contains an unknown file"
                            )
                        try:
                            metadata = os.stat(
                                filename, dir_fd=recovery_fd, follow_symlinks=False
                            )
                            require_private_file(
                                metadata, context="quarantined CAS artifact"
                            )
                        except (OSError, StorageError) as exc:
                            raise ChainIntegrityError(
                                "quarantined CAS artifact is not private"
                            ) from exc
                finally:
                    os.close(recovery_fd)
        finally:
            os.close(orphan_fd)

    def _validated_shards(self) -> tuple[str, ...]:
        self._validate_nonce_registry()
        self._validate_orphan_quarantine()
        shards: list[str] = []
        for entry in os.listdir(self._namespace_fd):
            if entry in {"nonces", "orphaned"}:
                continue
            if not self._is_lower_hex(entry, 2):
                raise ChainIntegrityError("CAS namespace contains an unknown entry")
            shards.append(entry)
        return tuple(sorted(shards))

    def _validated_shard_entries(
        self, shard_fd: int, shard: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        finals: list[str] = []
        temporary: list[str] = []
        identities: dict[tuple[int, int], list[tuple[str, str, int]]] = {}
        for filename in os.listdir(shard_fd):
            digest = filename.removesuffix(".flcas")
            suffix = filename.removeprefix(".tmp-")
            if (
                filename.endswith(".flcas")
                and self._is_lower_hex(digest, 64)
                and digest.startswith(shard)
            ):
                kind = "final"
                finals.append(filename)
            elif filename.startswith(".tmp-") and self._is_lower_hex(suffix, 32):
                kind = "temporary"
                temporary.append(filename)
            else:
                raise ChainIntegrityError("CAS shard contains an unknown entry")
            try:
                metadata = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
                require_private_file(
                    metadata,
                    context="CAS shard entry",
                    allowed_links=(1, 2),
                )
            except (OSError, StorageError) as exc:
                raise ChainIntegrityError("CAS shard entry is not private") from exc
            identities.setdefault(inode_identity(metadata), []).append(
                (kind, filename, metadata.st_nlink)
            )
        for names in identities.values():
            link_count = names[0][2]
            if link_count == 1 and len(names) == 1:
                continue
            kinds = sorted(name[0] for name in names)
            if link_count != 2 or len(names) != 2 or kinds != ["final", "temporary"]:
                raise ChainIntegrityError("CAS shard contains an unexpected hard link")
        return tuple(sorted(finals)), tuple(sorted(temporary))

    @staticmethod
    def _rename_checked(
        source_fd: int,
        source: str,
        target_fd: int,
        target: str,
        *,
        context: str,
    ) -> None:
        descriptor = os.open(source, os.O_RDONLY | NOFOLLOW, dir_fd=source_fd)
        try:
            before = os.fstat(descriptor)
            require_private_file(before, context=context)
            named_before = os.stat(source, dir_fd=source_fd, follow_symlinks=False)
            if inode_identity(named_before) != inode_identity(before):
                raise ChainIntegrityError(f"{context} changed before quarantine")
            try:
                os.stat(target, dir_fd=target_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ChainIntegrityError(f"{context} quarantine collision")
            try:
                os.rename(source, target, src_dir_fd=source_fd, dst_dir_fd=target_fd)
                os.fsync(target_fd)
                os.fsync(source_fd)
            except OSError as exc:
                raise StorageError(f"cannot durably quarantine {context}") from exc
            target_descriptor = os.open(target, os.O_RDONLY | NOFOLLOW, dir_fd=target_fd)
            try:
                after = os.fstat(target_descriptor)
                require_private_file(after, context=f"quarantined {context}")
                if inode_identity(after) != inode_identity(before):
                    raise ChainIntegrityError(f"{context} changed during quarantine")
            finally:
                os.close(target_descriptor)
        finally:
            os.close(descriptor)

    def quarantine_temporary(
        self, shard: str, filename: str, *, recovery_id: str
    ) -> str:
        self._require_open()
        if not self._is_lower_hex(shard, 2) or not (
            filename.startswith(".tmp-")
            and self._is_lower_hex(filename.removeprefix(".tmp-"), 32)
        ):
            raise StorageError("temporary CAS entry identity is invalid")
        require_identifier(recovery_id, field="recovery_id")
        source_fd = _open_directory(self._namespace_fd, shard, create=False)
        try:
            descriptor = os.open(filename, os.O_RDONLY | NOFOLLOW, dir_fd=source_fd)
            try:
                entry = os.fstat(descriptor)
                require_private_file(
                    entry,
                    context="interrupted CAS write",
                    allowed_links=(1, 2),
                )
                if entry.st_nlink == 2:
                    finals, temporary = self._validated_shard_entries(source_fd, shard)
                    if filename not in temporary:
                        raise ChainIntegrityError(
                            "interrupted publication is not discoverable"
                        )
                    matching = []
                    for final in finals:
                        metadata = os.stat(
                            final, dir_fd=source_fd, follow_symlinks=False
                        )
                        if inode_identity(metadata) == inode_identity(entry):
                            matching.append(final)
                    if len(matching) != 1:
                        raise ChainIntegrityError(
                            "interrupted publication has no unique final entry"
                        )
                    final = matching[0]
                    named_temporary = os.stat(
                        filename, dir_fd=source_fd, follow_symlinks=False
                    )
                    named_final = os.stat(
                        final, dir_fd=source_fd, follow_symlinks=False
                    )
                    expected_identity = inode_identity(entry)
                    if (
                        inode_identity(named_temporary) != expected_identity
                        or inode_identity(named_final) != expected_identity
                        or named_temporary.st_nlink != 2
                        or named_final.st_nlink != 2
                    ):
                        raise ChainIntegrityError(
                            "interrupted publication changed before reconciliation"
                        )
                    os.unlink(filename, dir_fd=source_fd)
                    os.fsync(source_fd)
                    reconciled = os.fstat(descriptor)
                    final_after = os.stat(
                        final, dir_fd=source_fd, follow_symlinks=False
                    )
                    if (
                        inode_identity(reconciled) != expected_identity
                        or inode_identity(final_after) != expected_identity
                        or reconciled.st_nlink != 1
                        or final_after.st_nlink != 1
                    ):
                        raise ChainIntegrityError(
                            "interrupted publication changed during reconciliation"
                        )
                    self._validate_paths()
                    return "published"
            finally:
                os.close(descriptor)
            orphan_fd = _open_directory(self._namespace_fd, "orphaned", create=True)
            recovery_fd = _open_directory(orphan_fd, recovery_id, create=True)
            target = f"{shard}-{filename.removeprefix('.tmp-')}.interrupted"
            try:
                self._rename_checked(
                    source_fd,
                    filename,
                    recovery_fd,
                    target,
                    context="interrupted CAS write",
                )
            finally:
                os.close(recovery_fd)
                os.close(orphan_fd)
            self._validate_paths()
            return "quarantined"
        finally:
            os.close(source_fd)

    def quarantine_orphan(self, digest: str, *, recovery_id: str) -> None:
        self._require_open()
        require_sha256(digest)
        require_identifier(recovery_id, field="recovery_id")
        source_fd = self._open_shard(digest, create=False)
        try:
            orphan_fd = _open_directory(self._namespace_fd, "orphaned", create=True)
            recovery_fd = _open_directory(orphan_fd, recovery_id, create=True)
            try:
                self._rename_checked(
                    source_fd,
                    self._filename(digest),
                    recovery_fd,
                    self._filename(digest),
                    context="orphaned CAS artifact",
                )
            finally:
                os.close(recovery_fd)
                os.close(orphan_fd)
        finally:
            os.close(source_fd)
        self._validate_paths()
