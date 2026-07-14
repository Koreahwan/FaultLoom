from __future__ import annotations

import sys
from datetime import datetime
from enum import Enum
from typing import Final

from pydantic.fields import FieldInfo

from faultloom.egress_wire import EgressWireError, ExactEnumCatalog, WireValue
from faultloom_protocol import ProtocolModel
from faultloom_protocol import canonical_json_bytes as protocol_canonical_json_bytes
from faultloom_protocol import sha256_digest as protocol_sha256_digest

_MAX_SNAPSHOT_DEPTH: Final = 128
_PROTOCOL_MODEL_MODULES: Final = frozenset(
    {"faultloom_protocol.base", "faultloom_protocol.models"}
)


class ExactWireBoundary:
    def __init__(
        self,
        *,
        enum_catalog: ExactEnumCatalog,
        enum_types: tuple[type[Enum], ...],
        model_types: tuple[type[ProtocolModel], ...],
    ) -> None:
        self._enum_catalog = enum_catalog
        self._enum_types = enum_types
        self._model_types = model_types

    def canonical_json_bytes(self, value: WireValue) -> bytes:
        return protocol_canonical_json_bytes(self.snapshot(value))

    def digest(self, value: WireValue) -> str:
        return protocol_sha256_digest(self.snapshot(value))

    def snapshot(
        self,
        value: WireValue,
        *,
        path: str = "$",
        ancestors: frozenset[int] = frozenset(),
        depth: int = 0,
    ) -> WireValue:
        if depth > _MAX_SNAPSHOT_DEPTH:
            raise EgressWireError("snapshot_depth", path=path)
        value_type = type(value)
        if value is None or value_type in (str, int, bool, bytes, float, datetime):
            return value
        descendants = ancestors
        if value_type in (tuple, list, dict) or value_type in self._model_types:
            value_id = id(value)
            if value_id in ancestors:
                raise EgressWireError("snapshot_cycle", path=path)
            descendants = ancestors | {value_id}
        if value_type is tuple and isinstance(value, tuple):
            return tuple(
                self.snapshot(
                    child,
                    path=f"{path}[{index}]",
                    ancestors=descendants,
                    depth=depth + 1,
                )
                for index, child in enumerate(value)
            )
        if value_type is list and isinstance(value, list):
            return [
                self.snapshot(
                    child,
                    path=f"{path}[{index}]",
                    ancestors=descendants,
                    depth=depth + 1,
                )
                for index, child in enumerate(value)
            ]
        if value_type is dict and isinstance(value, dict):
            result: dict[str, WireValue] = {}
            for key, child in value.items():
                if type(key) is not str or not isinstance(key, str):
                    raise EgressWireError("key_type", path=path)
                result[key] = self.snapshot(
                    child,
                    path=f"{path}.{key}",
                    ancestors=descendants,
                    depth=depth + 1,
                )
            return result
        if value_type in self._enum_types:
            return self._enum_catalog.exact_value(value)
        if value_type in self._model_types:
            raw_fields: dict[str, WireValue] = object.__getattribute__(value, "__dict__")
            model_fields: dict[str, FieldInfo] = type.__getattribute__(
                value_type, "__pydantic_fields__"
            )
            extra: dict[str, WireValue] | None = object.__getattribute__(
                value, "__pydantic_extra__"
            )
            if (
                type(raw_fields) is not dict
                or not isinstance(raw_fields, dict)
                or type(model_fields) is not dict
                or not isinstance(model_fields, dict)
                or (extra is not None and (type(extra) is not dict or bool(extra)))
            ):
                raise EgressWireError("model_storage", path=path)
            field_names = tuple(model_fields)
            stored_names = tuple(raw_fields)
            if (
                any(type(name) is not str for name in field_names)
                or any(type(name) is not str for name in stored_names)
                or stored_names != field_names
            ):
                raise EgressWireError("model_schema", path=path)
            return {
                name: self.snapshot(
                    raw_fields[name],
                    path=f"{path}.{name}",
                    ancestors=descendants,
                    depth=depth + 1,
                )
                for name in field_names
                if isinstance(name, str)
            }
        if self._trusted_protocol_model(value, value_type):
            return value
        if isinstance(value, (Enum, ProtocolModel, str, int, bytes, float, datetime)):
            raise EgressWireError("untrusted_value", path=path)
        raise EgressWireError("unsupported_value", path=path)

    @staticmethod
    def _trusted_protocol_model(value: WireValue, value_type: type[WireValue]) -> bool:
        if not isinstance(value, ProtocolModel):
            return False
        module_name: str = type.__getattribute__(value_type, "__module__")
        type_name: str = type.__getattribute__(value_type, "__name__")
        if (
            type(module_name) is not str
            or not isinstance(module_name, str)
            or type(type_name) is not str
            or not isinstance(type_name, str)
            or module_name not in _PROTOCOL_MODEL_MODULES
        ):
            return False
        module = sys.modules.get(module_name)
        return module is not None and vars(module).get(type_name) is value_type
