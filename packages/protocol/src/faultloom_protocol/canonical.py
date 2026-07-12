"""Deterministic JSON and digest helpers for signed protocol state."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Mapping, Sequence

from .base import (
    _normalize_protocol_datetime,
    _snapshot_protocol_value,
    assert_no_raw_secret_fields,
)


def _normalize(value: object) -> object:
    if type(value) is datetime:
        utc_value = _normalize_protocol_datetime(value, label="canonical datetime")
        return utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _normalize(object.__getattribute__(value, "_value_"))
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _normalize(child) for key, child in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(child) for child in value]
    if isinstance(value, float):
        raise TypeError("canonical protocol JSON forbids floating-point values")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("canonical protocol JSON integers must fit signed 64-bit")
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return the unique UTF-8 JSON representation used for hashes/signatures."""

    snapshot = _snapshot_protocol_value(value, _enum_values=True)
    assert_no_raw_secret_fields(snapshot)
    normalized = _normalize(snapshot)
    return json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_json(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def sha256_digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"
