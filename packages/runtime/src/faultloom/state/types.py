"""Shared state errors and validation helpers."""

from __future__ import annotations

import re


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StorageError(RuntimeError):
    """A durable state operation failed closed."""


class ChainIntegrityError(StorageError):
    """The event chain or an artifact failed integrity verification."""


class CrossEngagementError(StorageError):
    """An object from another engagement was presented to this store."""


def require_identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise StorageError(f"{field} is not a valid stable identifier")
    return value


def require_sha256(value: str, *, field: str = "sha256") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise StorageError(f"{field} is not a lowercase SHA-256 digest")
    return value

