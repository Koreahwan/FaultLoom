from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import ModuleType
from typing import Literal, cast

import faultloom.egress_enum_integrity as enum_integrity
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


class ExactEnumCatalog:
    def __init__(self, enum_types: tuple[type[Enum], ...]) -> None:
        type_snapshots: list[enum_integrity.EnumTypeSnapshot] = []
        for enum_type in enum_types:
            class_entries = enum_integrity.exact_class_entries(
                enum_type, error=EgressWireError("catalog_identity")
            )
            raw_member_map = enum_integrity.entry(class_entries, "_member_map_")
            raw_value_map = enum_integrity.entry(class_entries, "_value2member_map_")
            if type(raw_member_map) is not dict or type(raw_value_map) is not dict:
                raise EgressWireError("catalog_storage")
            member_map = cast(dict[object, object], raw_member_map)
            value_map = cast(dict[object, object], raw_value_map)
            member_entries = enum_integrity.exact_dict_entries(
                member_map,
                value_type=enum_type,
                error=EgressWireError("catalog_member"),
            )
            value_entries = enum_integrity.exact_dict_entries(
                value_map,
                value_type=enum_type,
                error=EgressWireError("catalog_value"),
            )
            members: list[enum_integrity.EnumMemberSnapshot] = []
            for name, raw_member in member_entries:
                member = cast(Enum, raw_member)
                member_name, member_value = enum_integrity.member_metadata(
                    member, error=EgressWireError("catalog_identity")
                )
                backing_value = str.__str__(cast(str, cast(object, member)))
                if (
                    type(member_name) is not str
                    or type(member_value) is not str
                    or type(backing_value) is not str
                ):
                    raise EgressWireError("catalog_member")
                if (
                    member_name != name
                    or member_value != backing_value
                    or enum_integrity.entry(class_entries, name) is not member
                    or not enum_integrity.contains_identity(value_entries, backing_value, member)
                ):
                    raise EgressWireError("catalog_identity")
                members.append(
                    enum_integrity.EnumMemberSnapshot(name=name, member=member, value=backing_value)
                )
            module_name = enum_integrity.entry(class_entries, "__module__")
            class_name = cast(object, type.__getattribute__(enum_type, "__name__"))
            if type(module_name) is not str or type(class_name) is not str:
                raise EgressWireError("catalog_identity")
            module = enum_integrity.entry(
                enum_integrity.exact_dict_entries(
                    sys.modules,
                    value_type=None,
                    error=EgressWireError("catalog_identity"),
                ),
                module_name,
            )
            if type(module) is not ModuleType:
                raise EgressWireError("catalog_identity")
            exact_module = cast(ModuleType, module)
            if enum_integrity.entry(
                enum_integrity.module_entries(
                    exact_module, error=EgressWireError("catalog_identity")
                ),
                class_name,
            ) is not enum_type:
                raise EgressWireError("catalog_identity")
            type_snapshots.append(
                enum_integrity.EnumTypeSnapshot(
                    enum_type=enum_type,
                    module=exact_module,
                    module_name=module_name,
                    class_name=class_name,
                    class_entry_count=len(class_entries),
                    members=tuple(members),
                    member_count=dict.__len__(member_map),
                    value_count=dict.__len__(value_map),
                )
            )
        self._type_snapshots = tuple(type_snapshots)

    def normalize_input(
        self,
        value: WireValue,
        *,
        enum_type: type[Enum],
        allowed_values: tuple[str, ...],
    ) -> WireValue:
        snapshot = self._snapshot_for_type(enum_type)
        self._validate_snapshot(snapshot)
        if type(value) is str and isinstance(value, str):
            if value not in allowed_values:
                raise EgressWireError("enum_value")
            return value
        exact_value = self._member_value(value, snapshot)
        if exact_value not in allowed_values:
            raise EgressWireError("enum_value")
        return value

    def exact_value(self, value: WireValue, *, expected_type: type[Enum] | None = None) -> str:
        value_type = type(value)
        if expected_type is not None and value_type is not expected_type:
            raise EgressWireError("enum_member")
        for snapshot in self._type_snapshots:
            if value_type is snapshot.enum_type:
                exact_value = self._member_value(value, snapshot)
                self._validate_snapshot(snapshot)
                return exact_value
        raise EgressWireError("enum_member")

    @staticmethod
    def _member_value(value: WireValue, snapshot: enum_integrity.EnumTypeSnapshot) -> str:
        if type(value) is snapshot.enum_type:
            for member_snapshot in snapshot.members:
                if value is member_snapshot.member:
                    return member_snapshot.value
        raise EgressWireError("enum_member")

    def _snapshot_for_type(self, enum_type: type[Enum]) -> enum_integrity.EnumTypeSnapshot:
        for snapshot in self._type_snapshots:
            if snapshot.enum_type is enum_type:
                return snapshot
        raise EgressWireError("enum_member")

    @staticmethod
    def _validate_snapshot(snapshot: enum_integrity.EnumTypeSnapshot) -> None:
        identity_error = EgressWireError("enum_identity")
        class_entries = enum_integrity.exact_class_entries(
            snapshot.enum_type, error=identity_error
        )
        current_class_name = cast(
            object, type.__getattribute__(snapshot.enum_type, "__name__")
        )
        current_module_name = enum_integrity.entry(class_entries, "__module__")
        if (
            len(class_entries) != snapshot.class_entry_count
            or type(current_class_name) is not str
            or current_class_name != snapshot.class_name
            or type(current_module_name) is not str
            or current_module_name != snapshot.module_name
        ):
            raise EgressWireError("enum_identity")
        raw_member_map = enum_integrity.entry(class_entries, "_member_map_")
        raw_value_map = enum_integrity.entry(class_entries, "_value2member_map_")
        if type(raw_member_map) is not dict or type(raw_value_map) is not dict:
            raise EgressWireError("enum_identity")
        member_map = cast(dict[object, object], raw_member_map)
        value_map = cast(dict[object, object], raw_value_map)
        if (
            dict.__len__(member_map) != snapshot.member_count
            or dict.__len__(value_map) != snapshot.value_count
        ):
            raise EgressWireError("enum_identity")
        member_entries = enum_integrity.exact_dict_entries(
            member_map,
            value_type=snapshot.enum_type,
            error=EgressWireError("enum_identity"),
        )
        value_entries = enum_integrity.exact_dict_entries(
            value_map,
            value_type=snapshot.enum_type,
            error=EgressWireError("enum_identity"),
        )
        module_entries = enum_integrity.module_entries(
            snapshot.module, error=EgressWireError("enum_identity")
        )
        if (
            enum_integrity.entry(module_entries, snapshot.class_name)
            is not snapshot.enum_type
        ):
            raise EgressWireError("enum_identity")
        for member_snapshot in snapshot.members:
            member_name, member_value = enum_integrity.member_metadata(
                member_snapshot.member, error=EgressWireError("enum_identity")
            )
            backing_value = str.__str__(
                cast(str, cast(object, member_snapshot.member))
            )
            if (
                type(member_name) is not str
                or member_name != member_snapshot.name
                or type(member_value) is not str
                or member_value != member_snapshot.value
                or type(backing_value) is not str
                or backing_value != member_snapshot.value
                or enum_integrity.entry(class_entries, member_snapshot.name)
                is not member_snapshot.member
                or not enum_integrity.contains_identity(
                    member_entries, member_snapshot.name, member_snapshot.member
                )
                or not enum_integrity.contains_identity(
                    value_entries, member_snapshot.value, member_snapshot.member
                )
            ):
                raise EgressWireError("enum_identity")


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
