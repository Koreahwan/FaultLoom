from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType, ModuleType
from typing import cast


_MISSING = object()


@dataclass(frozen=True, slots=True)
class EnumMemberSnapshot:
    name: str
    member: Enum
    value: str


@dataclass(frozen=True, slots=True)
class EnumTypeSnapshot:
    enum_type: type[Enum]
    module: ModuleType
    module_name: str
    class_name: str
    class_entry_count: int
    members: tuple[EnumMemberSnapshot, ...]
    member_count: int
    value_count: int


def exact_dict_entries(
    raw_mapping: object,
    *,
    value_type: type[Enum] | None,
    error: Exception,
) -> tuple[tuple[str, object], ...]:
    if type(raw_mapping) is not dict:
        raise error
    mapping = cast(dict[object, object], raw_mapping)
    try:
        raw_entries = tuple(dict.items(mapping))
    except RuntimeError as exc:
        raise error from exc
    if any(
        type(key) is not str
        or (value_type is not None and type(value) is not value_type)
        for key, value in raw_entries
    ):
        raise error
    return cast(tuple[tuple[str, object], ...], raw_entries)


def exact_class_entries(
    enum_type: type[Enum], *, error: Exception
) -> tuple[tuple[str, object], ...]:
    raw_namespace = cast(object, type.__getattribute__(enum_type, "__dict__"))
    if type(raw_namespace) is not MappingProxyType:
        raise error
    namespace = cast(MappingProxyType[object, object], raw_namespace)
    try:
        raw_entries = tuple(namespace.items())
    except RuntimeError as exc:
        raise error from exc
    if any(type(key) is not str for key, _ in raw_entries):
        raise error
    return cast(tuple[tuple[str, object], ...], raw_entries)


def entry(entries: tuple[tuple[str, object], ...], expected_key: str) -> object:
    for key, value in entries:
        if key == expected_key:
            return value
    return _MISSING


def contains_identity(
    entries: tuple[tuple[str, object], ...], expected_key: str, expected: object
) -> bool:
    return any(key == expected_key and value is expected for key, value in entries)


def member_metadata(member: Enum, *, error: Exception) -> tuple[object, object]:
    entries = exact_dict_entries(
        cast(object, object.__getattribute__(member, "__dict__")),
        value_type=None,
        error=error,
    )
    return entry(entries, "_name_"), entry(entries, "_value_")


def module_entries(
    module: ModuleType, *, error: Exception
) -> tuple[tuple[str, object], ...]:
    if type(module) is not ModuleType:
        raise error
    return exact_dict_entries(
        cast(object, ModuleType.__getattribute__(module, "__dict__")),
        value_type=None,
        error=error,
    )
