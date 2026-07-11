"""Descriptor-relative private filesystem helpers for durable state."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .types import StorageError


NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _owned_by_current_user(metadata: os.stat_result) -> bool:
    getuid = getattr(os, "geteuid", None)
    return getuid is None or metadata.st_uid == getuid()


def require_private_directory(metadata: os.stat_result, *, context: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise StorageError(f"{context} is not a directory")
    if not _owned_by_current_user(metadata):
        raise StorageError(f"{context} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise StorageError(f"{context} must have mode 0700")


def require_private_file(
    metadata: os.stat_result, *, context: str, allowed_links: tuple[int, ...] = (1,)
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink not in allowed_links:
        raise StorageError(f"{context} is not a private regular file")
    if not _owned_by_current_user(metadata):
        raise StorageError(f"{context} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
        raise StorageError(f"{context} must have mode 0600")


def open_root_directory(path: Path, *, create: bool) -> int:
    """Open every absolute path component without following symbolic links."""

    raw = Path(path)
    if not raw.is_absolute():
        raise StorageError("durable state roots must be absolute paths")
    if any(part in {"", ".", ".."} for part in raw.parts[1:]):
        raise StorageError("durable state root is not canonical")
    descriptor = os.open("/", os.O_RDONLY | DIRECTORY)
    try:
        for component in raw.parts[1:]:
            if create:
                try:
                    os.mkdir(component, PRIVATE_DIRECTORY_MODE, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | DIRECTORY | NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise StorageError(
                    "cannot safely open durable state path component "
                    f"{component!r}; symlinks are forbidden"
                ) from exc
            os.close(descriptor)
            descriptor = child
        require_private_directory(os.fstat(descriptor), context="durable state root")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_private_directory(parent_fd: int, name: str, *, create: bool) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise StorageError("unsafe private directory component")
    if create:
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | DIRECTORY | NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise StorageError(f"cannot safely open private directory {name!r}") from exc
    try:
        require_private_directory(os.fstat(descriptor), context=f"private directory {name!r}")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def open_private_file(
    parent_fd: int,
    name: str,
    flags: int,
    *,
    create: bool = False,
    exclusive: bool = False,
) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise StorageError("unsafe private file component")
    open_flags = flags | NOFOLLOW
    if create:
        open_flags |= os.O_CREAT
    if exclusive:
        open_flags |= os.O_EXCL
    try:
        descriptor = os.open(
            name,
            open_flags,
            PRIVATE_FILE_MODE,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise StorageError(f"cannot safely open private file {name!r}") from exc
    try:
        require_private_file(os.fstat(descriptor), context=f"private file {name!r}")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino
