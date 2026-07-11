"""Small deterministic JSON profile used by the state hash chain."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from .types import StorageError


MIN_INT64 = -(2**63)
MAX_INT64 = 2**63 - 1


def _validate(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if value < MIN_INT64 or value > MAX_INT64:
            raise StorageError(f"integer outside signed int64 at {path}")
        return
    if isinstance(value, float):
        raise StorageError(f"floating point values are forbidden at {path}")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise StorageError(f"non-string object key at {path}")
            _validate(child, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate(child, path=f"{path}[{index}]")
        return
    raise StorageError(f"unsupported canonical value {type(value).__name__} at {path}")


def canonical_json(value: Any) -> str:
    _validate(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
