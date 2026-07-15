from __future__ import annotations

import sys
from datetime import datetime
from enum import Enum
from typing import Final

from pydantic.fields import FieldInfo

from faultloom_protocol import ProtocolModel
from faultloom_protocol import canonical_json_bytes as protocol_canonical_json_bytes
from faultloom_protocol import sha256_digest as protocol_sha256_digest

_EXECUTION_MODULES: Final = frozenset(
    {
        "faultloom.execution.contracts",
        "faultloom.execution.gateway",
    }
)
_MAX_DEPTH: Final = 128


class ExecutionWireError(ValueError):
    pass


def execution_canonical_json_bytes(value: object) -> bytes:
    return protocol_canonical_json_bytes(_snapshot(value))


def execution_sha256_digest(value: object) -> str:
    return protocol_sha256_digest(_snapshot(value))


def _snapshot(
    value: object,
    *,
    path: str = "$",
    ancestors: frozenset[int] = frozenset(),
    depth: int = 0,
) -> object:
    if depth > _MAX_DEPTH:
        raise ExecutionWireError(f"{path} exceeds the execution snapshot depth")
    value_type = type(value)
    if value is None or value_type in (str, int, bool, float, datetime):
        return value
    if value_type is bytes:
        return {"$faultloom_bytes_hex": value.hex()}
    descendants = ancestors
    if value_type in (tuple, list, dict) or isinstance(value, ProtocolModel):
        value_id = id(value)
        if value_id in ancestors:
            raise ExecutionWireError(f"{path} contains a cycle")
        descendants = ancestors | {value_id}
    if value_type is tuple:
        return tuple(
            _snapshot(
                child,
                path=f"{path}[{index}]",
                ancestors=descendants,
                depth=depth + 1,
            )
            for index, child in enumerate(value)
        )
    if value_type is list:
        return [
            _snapshot(
                child,
                path=f"{path}[{index}]",
                ancestors=descendants,
                depth=depth + 1,
            )
            for index, child in enumerate(value)
        ]
    if value_type is dict:
        result: dict[str, object] = {}
        for key, child in dict.items(value):
            if type(key) is not str:
                raise ExecutionWireError(f"{path} contains a non-string key")
            result[key] = _snapshot(
                child,
                path=f"{path}.{key}",
                ancestors=descendants,
                depth=depth + 1,
            )
        return result
    if isinstance(value, Enum):
        if not _is_exact_execution_type(value_type):
            return value
        enum_value = object.__getattribute__(value, "_value_")
        if type(enum_value) is not str:
            raise ExecutionWireError(f"{path} contains a non-string execution enum")
        return enum_value
    if isinstance(value, ProtocolModel) and _is_exact_execution_type(value_type):
        storage = object.__getattribute__(value, "__dict__")
        fields: dict[str, FieldInfo] = type.__getattribute__(
            value_type, "__pydantic_fields__"
        )
        extra = object.__getattribute__(value, "__pydantic_extra__")
        if type(storage) is not dict or type(fields) is not dict or extra not in (None, {}):
            raise ExecutionWireError(f"{path} has invalid execution model storage")
        if tuple(storage) != tuple(fields):
            raise ExecutionWireError(f"{path} execution model fields differ from storage")
        return {
            name: _snapshot(
                storage[name],
                path=f"{path}.{name}",
                ancestors=descendants,
                depth=depth + 1,
            )
            for name in fields
        }
    if isinstance(value, ProtocolModel):
        return value
    raise ExecutionWireError(f"{path} contains an unsupported execution value")


def _is_exact_execution_type(value_type: type[object]) -> bool:
    module_name = type.__getattribute__(value_type, "__module__")
    type_name = type.__getattribute__(value_type, "__name__")
    if (
        type(module_name) is not str
        or type(type_name) is not str
        or module_name not in _EXECUTION_MODULES
    ):
        return False
    module = sys.modules.get(module_name)
    return module is not None and vars(module).get(type_name) is value_type
