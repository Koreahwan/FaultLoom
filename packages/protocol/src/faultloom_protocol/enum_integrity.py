from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TypeVar, cast


_EnumT = TypeVar("_EnumT", bound=Enum)
_MISSING = object()


@dataclass(frozen=True, slots=True)
class _ProtocolEnumIdentity:
    enum_type: type[Enum]
    member: object
    name: str
    value: str


class _ProtocolEnumIntegrityError(ValueError):
    pass


_protocol_enum_identities: tuple[_ProtocolEnumIdentity, ...] = ()


def _capture_enum(enum_type: type[Enum]) -> tuple[_ProtocolEnumIdentity, ...]:
    if not issubclass(enum_type, str):
        raise RuntimeError("protocol enum catalog contains an untrusted type")
    raw_member_map = cast(object, type.__getattribute__(enum_type, "_member_map_"))
    if type(raw_member_map) is not dict:
        raise RuntimeError("protocol enum catalog requires an exact member map")
    member_map = cast(dict[object, object], raw_member_map)
    identities: list[_ProtocolEnumIdentity] = []
    for name, member in dict.items(member_map):
        if type(name) is not str or type(member) is not enum_type:
            raise RuntimeError("protocol enum catalog contains a malformed member")
        member_name = cast(object, object.__getattribute__(member, "_name_"))
        member_value = cast(object, object.__getattribute__(member, "_value_"))
        backing_value = str.__str__(member)
        if (
            type(member_name) is not str
            or type(member_value) is not str
            or type(backing_value) is not str
            or name != member_name
            or member_value != backing_value
        ):
            raise RuntimeError("protocol enum catalog contains a malformed member")
        identities.append(
            _ProtocolEnumIdentity(
                enum_type=enum_type,
                member=member,
                name=name,
                value=backing_value,
            )
        )
    return tuple(identities)


def _install_protocol_enum_catalog(enum_types: tuple[type[Enum], ...]) -> None:
    global _protocol_enum_identities

    if _protocol_enum_identities:
        raise RuntimeError("protocol enum catalog is already installed")
    identities = tuple(
        identity
        for enum_type in enum_types
        for identity in _capture_enum(enum_type)
    )
    if not identities:
        raise RuntimeError("protocol enum catalog cannot be empty")
    _protocol_enum_identities = identities


def _integrity_error() -> _ProtocolEnumIntegrityError:
    return _ProtocolEnumIntegrityError(
        "protocol enum member differs from its immutable expected value"
    )


def _exact_registry_entries(
    registry: dict[object, object],
    value_type: type[Enum],
) -> tuple[tuple[str, object], ...]:
    try:
        raw_entries = tuple(dict.items(registry))
    except RuntimeError as exc:
        raise _integrity_error() from exc
    if any(
        type(key) is not str or type(member) is not value_type
        for key, member in raw_entries
    ):
        raise _integrity_error()
    return cast(tuple[tuple[str, object], ...], raw_entries)


def _contains_identity(
    entries: tuple[tuple[str, object], ...],
    expected_key: str,
    expected_member: object,
) -> bool:
    return any(
        key == expected_key and member is expected_member
        for key, member in entries
    )


def _exact_class_entries(
    value_type: type[Enum],
) -> tuple[tuple[str, object], ...]:
    raw_namespace = cast(object, type.__getattribute__(value_type, "__dict__"))
    if type(raw_namespace) is not MappingProxyType:
        raise _integrity_error()
    namespace = cast(MappingProxyType[object, object], raw_namespace)
    try:
        raw_entries = tuple(namespace.items())
    except RuntimeError as exc:
        raise _integrity_error() from exc
    if any(type(key) is not str for key, _ in raw_entries):
        raise _integrity_error()
    entries = cast(tuple[tuple[str, object], ...], raw_entries)
    if any(key in {"_name_", "_value_"} for key, _ in entries):
        raise _integrity_error()
    return entries


def _class_entry(
    entries: tuple[tuple[str, object], ...],
    expected_key: str,
) -> object:
    for key, value in entries:
        if key == expected_key:
            return value
    return _MISSING


def _exact_member_metadata(member: object) -> tuple[object, object]:
    raw_state = cast(object, object.__getattribute__(member, "__dict__"))
    if type(raw_state) is not dict:
        raise _integrity_error()
    state = cast(dict[object, object], raw_state)
    try:
        entries = tuple(dict.items(state))
    except RuntimeError as exc:
        raise _integrity_error() from exc
    if any(type(key) is not str for key, _ in entries):
        raise _integrity_error()

    member_name: object | None = None
    member_value: object | None = None
    for key, field_value in entries:
        if key == "_name_":
            member_name = field_value
        elif key == "_value_":
            member_value = field_value
    return member_name, member_value


def _protocol_enum_member(enum_type: type[_EnumT], name: str) -> _EnumT:
    if type(name) is not str:
        raise _ProtocolEnumIntegrityError("protocol enum member name must be exact")
    for identity in _protocol_enum_identities:
        if identity.enum_type is enum_type and identity.name == name:
            return cast(_EnumT, identity.member)
    raise _ProtocolEnumIntegrityError("must contain a registered protocol enum member")


def _protocol_enum_value(value: Enum) -> str:
    value_type = type(value)
    matched_identity: _ProtocolEnumIdentity | None = None
    class_identities: list[_ProtocolEnumIdentity] = []
    for identity in _protocol_enum_identities:
        if identity.enum_type is value_type:
            class_identities.append(identity)
            if identity.member is value:
                matched_identity = identity
    if not class_identities:
        raise _ProtocolEnumIntegrityError("must contain an exact protocol enum")
    if matched_identity is None:
        raise _ProtocolEnumIntegrityError(
            "must contain a registered protocol enum member"
        )

    class_entries = _exact_class_entries(value_type)
    raw_member_map = _class_entry(class_entries, "_member_map_")
    raw_value_map = _class_entry(class_entries, "_value2member_map_")
    if type(raw_member_map) is not dict or type(raw_value_map) is not dict:
        raise _integrity_error()
    member_map = cast(dict[object, object], raw_member_map)
    value_map = cast(dict[object, object], raw_value_map)
    if (
        dict.__len__(member_map) != len(class_identities)
        or dict.__len__(value_map) != len(class_identities)
    ):
        raise _integrity_error()
    member_entries = _exact_registry_entries(member_map, value_type)
    value_entries = _exact_registry_entries(value_map, value_type)

    for identity in class_identities:
        bound_member = _class_entry(class_entries, identity.name)
        member_name, member_value = _exact_member_metadata(identity.member)
        backing_value = str.__str__(cast(str, identity.member))
        if (
            type(identity.member) is not value_type
            or bound_member is not identity.member
            or type(member_name) is not str
            or member_name != identity.name
            or type(member_value) is not str
            or member_value != identity.value
            or type(backing_value) is not str
            or backing_value != identity.value
            or not _contains_identity(
                member_entries,
                identity.name,
                identity.member,
            )
            or not _contains_identity(
                value_entries,
                identity.value,
                identity.member,
            )
        ):
            raise _integrity_error()
    return matched_identity.value
