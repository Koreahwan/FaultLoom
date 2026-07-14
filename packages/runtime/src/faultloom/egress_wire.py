from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from faultloom_protocol import ProtocolModel

type WireValue = (
    None
    | bool
    | int
    | float
    | str
    | bytes
    | datetime
    | Enum
    | ProtocolModel
    | tuple[WireValue, ...]
    | list[WireValue]
    | dict[str, WireValue]
)
type WireErrorCode = Literal[
    "catalog_storage",
    "catalog_member",
    "catalog_value",
    "catalog_identity",
    "enum_value",
    "enum_member",
    "enum_identity",
    "snapshot_depth",
    "snapshot_cycle",
    "key_type",
    "model_storage",
    "model_schema",
    "untrusted_value",
    "unsupported_value",
]


class EgressWireError(ValueError):
    code: WireErrorCode
    path: str

    def __init__(self, code: WireErrorCode, *, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{path}: {code}")


@dataclass(frozen=True, slots=True)
class _EnumMemberSnapshot:
    enum_type: type[Enum]
    name: str
    member: Enum
    value: str


class ExactEnumCatalog:
    def __init__(self, enum_types: tuple[type[Enum], ...]) -> None:
        snapshots: list[_EnumMemberSnapshot] = []
        for enum_type in enum_types:
            member_map: dict[str, Enum] = type.__getattribute__(enum_type, "_member_map_")
            value_map: dict[str, Enum] = type.__getattribute__(
                enum_type, "_value2member_map_"
            )
            if (
                type(member_map) is not dict
                or not isinstance(member_map, dict)
                or type(value_map) is not dict
                or not isinstance(value_map, dict)
            ):
                raise EgressWireError("catalog_storage")
            for name, member in member_map.items():
                if (
                    type(name) is not str
                    or type(member) is not enum_type
                    or not isinstance(member, Enum)
                    or not isinstance(member, str)
                ):
                    raise EgressWireError("catalog_member")
                raw_value: str = object.__getattribute__(member, "_value_")
                if type(raw_value) is not str or not isinstance(raw_value, str):
                    raise EgressWireError("catalog_value")
                if (
                    type.__getattribute__(enum_type, name) is not member
                    or value_map.get(raw_value) is not member
                    or str.__str__(member) != raw_value
                ):
                    raise EgressWireError("catalog_identity")
                snapshots.append(
                    _EnumMemberSnapshot(
                        enum_type=enum_type,
                        name=name,
                        member=member,
                        value=raw_value,
                    )
                )
        self._snapshots = tuple(snapshots)

    def normalize_input(
        self,
        value: WireValue,
        *,
        enum_type: type[Enum],
        allowed_values: tuple[str, ...],
    ) -> WireValue:
        if type(value) is str and isinstance(value, str):
            if value not in allowed_values:
                raise EgressWireError("enum_value")
            return value
        exact_value = self.exact_value(value, expected_type=enum_type)
        if exact_value not in allowed_values:
            raise EgressWireError("enum_value")
        return value

    def exact_value(
        self, value: WireValue, *, expected_type: type[Enum] | None = None
    ) -> str:
        value_type = type(value)
        for snapshot in self._snapshots:
            if (
                value_type is snapshot.enum_type
                and (expected_type is None or value_type is expected_type)
                and value is snapshot.member
            ):
                return self._validate_snapshot(snapshot)
        raise EgressWireError("enum_member")

    @staticmethod
    def _validate_snapshot(snapshot: _EnumMemberSnapshot) -> str:
        member_map: dict[str, Enum] = type.__getattribute__(
            snapshot.enum_type, "_member_map_"
        )
        value_map: dict[str, Enum] = type.__getattribute__(
            snapshot.enum_type, "_value2member_map_"
        )
        member_name: str = object.__getattribute__(snapshot.member, "_name_")
        member_value: str = object.__getattribute__(snapshot.member, "_value_")
        if (
            type(member_map) is not dict
            or not isinstance(member_map, dict)
            or type(value_map) is not dict
            or not isinstance(value_map, dict)
            or type(member_name) is not str
            or not isinstance(member_name, str)
            or type(member_value) is not str
            or not isinstance(member_value, str)
            or member_name != snapshot.name
            or member_value != snapshot.value
            or member_map.get(snapshot.name) is not snapshot.member
            or value_map.get(snapshot.value) is not snapshot.member
            or type.__getattribute__(snapshot.enum_type, snapshot.name)
            is not snapshot.member
        ):
            raise EgressWireError("enum_identity")
        return snapshot.value


@dataclass(frozen=True, slots=True)
class ExactEnumInput:
    catalog: ExactEnumCatalog
    enum_type: type[Enum]
    allowed_values: tuple[str, ...]

    def __call__(self, value: WireValue) -> WireValue:
        return self.catalog.normalize_input(
            value,
            enum_type=self.enum_type,
            allowed_values=self.allowed_values,
        )
