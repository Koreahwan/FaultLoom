from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType, ModuleType
from typing import Literal, Protocol, TypeGuard, final, overload


class IdentityValue(Protocol):
    pass


class _TypeAttributeReader(Protocol):
    @overload
    def __call__(
        self, instance: type[Enum], name: Literal["__dict__"], /
    ) -> IdentityValue: ...

    @overload
    def __call__(
        self, instance: type[Enum], name: Literal["__name__"], /
    ) -> IdentityValue: ...


class _MemberAttributeReader(Protocol):
    def __call__(
        self, instance: str, name: Literal["__dict__"], /
    ) -> IdentityValue: ...


class _ModuleAttributeReader(Protocol):
    def __call__(
        self, instance: ModuleType, name: Literal["__dict__"], /
    ) -> IdentityValue: ...


@final
class _MissingValue:
    __slots__ = ()


_MISSING = _MissingValue()


@dataclass(frozen=True, slots=True)
class EnumMemberSnapshot:
    name: str
    member: str
    value: str


@dataclass(frozen=True, slots=True)
class EnumTypeSnapshot:
    enum_type: type[Enum]
    module_registry: IdentityValue
    module: ModuleType
    module_name: str
    class_name: str
    class_entry_count: int
    members: tuple[EnumMemberSnapshot, ...]
    member_count: int
    value_count: int


def is_exact_dict(
    value: IdentityValue,
) -> TypeGuard[dict[IdentityValue, IdentityValue]]:
    return type(value) is dict


def is_exact_proxy(
    value: IdentityValue,
) -> TypeGuard[MappingProxyType[IdentityValue, IdentityValue]]:
    return type(value) is MappingProxyType


def is_exact_string(value: IdentityValue) -> TypeGuard[str]:
    return type(value) is str


def is_exact_module(value: IdentityValue) -> TypeGuard[ModuleType]:
    return type(value) is ModuleType


def exact_dict_entries(
    raw_mapping: IdentityValue,
    *,
    value_type: type[Enum] | None,
    error: Exception,
) -> tuple[tuple[str, IdentityValue], ...]:
    if not is_exact_dict(raw_mapping):
        raise error
    mapping: dict[IdentityValue, IdentityValue] = raw_mapping
    try:
        raw_entries = tuple(mapping.items())
    except RuntimeError as exc:
        raise error from exc
    entries: list[tuple[str, IdentityValue]] = []
    for key, value in raw_entries:
        if not is_exact_string(key) or (
            value_type is not None and type(value) is not value_type
        ):
            raise error
        entries.append((key, value))
    return tuple(entries)


def exact_class_entries(
    enum_type: type[Enum],
    *,
    error: Exception,
    attribute_reader: _TypeAttributeReader = type.__getattribute__,
) -> tuple[tuple[str, IdentityValue], ...]:
    raw_namespace = attribute_reader(enum_type, "__dict__")
    if not is_exact_proxy(raw_namespace):
        raise error
    try:
        raw_entries = tuple(raw_namespace.items())
    except RuntimeError as exc:
        raise error from exc
    entries: list[tuple[str, IdentityValue]] = []
    for key, value in raw_entries:
        if not is_exact_string(key):
            raise error
        entries.append((key, value))
    return tuple(entries)


def raw_class_name(
    enum_type: type[Enum],
    *,
    attribute_reader: _TypeAttributeReader = type.__getattribute__,
) -> IdentityValue:
    return attribute_reader(enum_type, "__name__")


def entry(
    entries: tuple[tuple[str, IdentityValue], ...], expected_key: str
) -> IdentityValue:
    for key, value in entries:
        if key == expected_key:
            return value
    return _MISSING


def contains_identity(
    entries: tuple[tuple[str, IdentityValue], ...],
    expected_key: str,
    expected: IdentityValue,
) -> bool:
    return any(key == expected_key and value is expected for key, value in entries)


def exact_string_member(
    value: IdentityValue, *, enum_type: type[Enum]
) -> TypeGuard[str]:
    return type(value) is enum_type and isinstance(value, str)


def member_metadata(
    member: str,
    *,
    error: Exception,
    attribute_reader: _MemberAttributeReader = object.__getattribute__,
) -> tuple[IdentityValue, IdentityValue]:
    raw_mapping = attribute_reader(member, "__dict__")
    entries = exact_dict_entries(
        raw_mapping,
        value_type=None,
        error=error,
    )
    return entry(entries, "_name_"), entry(entries, "_value_")


def module_entries(
    module: ModuleType,
    *,
    error: Exception,
    attribute_reader: _ModuleAttributeReader = ModuleType.__getattribute__,
) -> tuple[tuple[str, IdentityValue], ...]:
    if type(module) is not ModuleType:
        raise error
    raw_mapping = attribute_reader(module, "__dict__")
    return exact_dict_entries(
        raw_mapping,
        value_type=None,
        error=error,
    )


def validate_module_binding(
    snapshot: EnumTypeSnapshot, *, error: Exception
) -> None:
    try:
        module_registry = sys.modules
    except AttributeError as exc:
        raise error from exc
    if module_registry is not snapshot.module_registry:
        raise error
    registry_entries = exact_dict_entries(
        snapshot.module_registry,
        value_type=None,
        error=error,
    )
    if entry(registry_entries, snapshot.module_name) is not snapshot.module:
        raise error
    entries = module_entries(snapshot.module, error=error)
    module_name = entry(entries, "__name__")
    if (
        not is_exact_string(module_name)
        or module_name != snapshot.module_name
        or entry(entries, snapshot.class_name) is not snapshot.enum_type
    ):
        raise error
