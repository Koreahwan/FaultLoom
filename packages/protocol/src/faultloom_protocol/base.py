"""Shared protocol invariants."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationInfo,
)
from pydantic_core import TzInfo

from .enum_integrity import _ProtocolEnumIntegrityError, _protocol_enum_value

PROTOCOL_VERSION = "0.1.0"
SCHEMA_VERSION = "0.1.0"
SUPPORTED_PROTOCOL_RANGE = ">=0.1.0,<0.2.0"
MAX_INT64 = 2**63 - 1

SchemaVersion = Literal["0.1.0"]
NonEmptyStr = Annotated[str, Field(min_length=1, max_length=4096)]
ShortStr = Annotated[str, Field(min_length=1, max_length=256)]
Identifier = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


def _normalize_protocol_datetime(value: object, *, label: str) -> datetime:
    """Return an exact UTC datetime without invoking caller-defined hooks."""

    if type(value) is not datetime:
        raise ValueError(f"{label} must be an exact datetime")
    timezone_value = value.tzinfo
    if timezone_value is None:
        raise ValueError(f"{label} cannot be a naive datetime; timezone is required")
    if type(timezone_value) not in (timezone, TzInfo):
        raise ValueError(
            f"{label} must use a trusted timezone implementation such as timezone.utc"
        )
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{label} is outside the supported UTC datetime range") from exc


_JSON_DATETIME_ADAPTER = TypeAdapter(datetime)


def _guard_datetime_input(value: object, info: ValidationInfo) -> object:
    if isinstance(value, datetime):
        return _normalize_protocol_datetime(value, label="datetime")
    if info.mode == "json" and type(value) is str:
        parsed = _JSON_DATETIME_ADAPTER.validate_python(value)
        return _normalize_protocol_datetime(parsed, label="datetime")
    return value


def _require_aware(value: datetime) -> datetime:
    return _normalize_protocol_datetime(value, label="datetime")


AwareDatetime = Annotated[
    datetime,
    BeforeValidator(_guard_datetime_input),
    AfterValidator(_require_aware),
]


class ProtocolModel(BaseModel):
    """Strict immutable base for every wire-level protocol object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    schema_version: SchemaVersion


class SecretRef(ProtocolModel):
    """Opaque reference to secret material held outside serialized protocol state."""

    uri: Annotated[
        str,
        Field(
            min_length=10,
            max_length=512,
            pattern=r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]*$",
        ),
    ]
    purpose: ShortStr


ProtocolModelT = TypeVar("ProtocolModelT", bound=ProtocolModel)
_MAX_PROTOCOL_SNAPSHOT_DEPTH = 128


class _ProtocolSnapshotError(ValueError):
    def __init__(self, path: str, value_kind: str, message: str) -> None:
        super().__init__(message)
        self.path = path
        self.value_kind = value_kind


def _trusted_protocol_type(value_type: type[object]) -> bool:
    module_name = type.__getattribute__(value_type, "__module__")
    type_name = type.__getattribute__(value_type, "__name__")
    if type(module_name) is not str or type(type_name) is not str:
        return False
    if module_name not in {
        "faultloom_protocol.base",
        "faultloom_protocol.evaluation_manifest",
        "faultloom_protocol.evaluation_results",
        "faultloom_protocol.models",
    }:
        return False
    module = sys.modules.get(module_name)
    return module is not None and vars(module).get(type_name) is value_type


def _safe_type_name(value_type: type[object]) -> str:
    type_name = type.__getattribute__(value_type, "__name__")
    return type_name if type(type_name) is str else "<unknown>"


def _snapshot_protocol_enum_value(value: Enum, *, path: str) -> str:
    try:
        return _protocol_enum_value(value)
    except _ProtocolEnumIntegrityError as exc:
        raise _ProtocolSnapshotError(path, "enum", f"{path} {exc}") from exc


def _snapshot_protocol_value(
    value: object,
    *,
    path: str = "$",
    _ancestor_ids: frozenset[int] | None = None,
    _depth: int = 0,
    _enum_values: bool = False,
) -> object:
    """Copy protocol data from field storage without calling user methods."""

    if _depth > _MAX_PROTOCOL_SNAPSHOT_DEPTH:
        raise _ProtocolSnapshotError(
            path,
            "depth",
            f"{path} exceeds the maximum protocol nesting depth",
        )
    value_type = type(value)
    if value is None or value_type in (str, int, bool, bytes, float):
        return value
    if value_type is datetime:
        try:
            return _normalize_protocol_datetime(value, label=path)
        except ValueError as exc:
            raise _ProtocolSnapshotError(path, "datetime", str(exc)) from exc
    if isinstance(value, datetime):
        raise _ProtocolSnapshotError(
            path,
            "datetime",
            f"{path} must be an exact datetime",
        )
    is_protocol_model = isinstance(value, ProtocolModel)
    descendant_ancestors = _ancestor_ids or frozenset()
    if value_type in (tuple, list, dict) or is_protocol_model:
        value_id = id(value)
        if value_id in descendant_ancestors:
            raise _ProtocolSnapshotError(
                path,
                "cycle",
                f"{path} contains a protocol container cycle",
            )
        descendant_ancestors = descendant_ancestors | {value_id}
    if value_type is tuple:
        return tuple(
            _snapshot_protocol_value(
                child,
                path=f"{path}[{index}]",
                _ancestor_ids=descendant_ancestors,
                _depth=_depth + 1,
                _enum_values=_enum_values,
            )
            for index, child in enumerate(value)
        )
    if value_type is list:
        return [
            _snapshot_protocol_value(
                child,
                path=f"{path}[{index}]",
                _ancestor_ids=descendant_ancestors,
                _depth=_depth + 1,
                _enum_values=_enum_values,
            )
            for index, child in enumerate(value)
        ]
    if value_type is dict:
        safe_items: list[tuple[str, object]] = []
        for key, child in dict.items(value):
            if type(key) is not str:
                raise TypeError(f"{path} keys must be exact strings")
            safe_items.append(
                (
                    key,
                    _snapshot_protocol_value(
                        child,
                        path=f"{path}.{key}",
                        _ancestor_ids=descendant_ancestors,
                        _depth=_depth + 1,
                        _enum_values=_enum_values,
                    ),
                )
            )
        return dict(safe_items)
    if isinstance(value, Enum):
        expected_value = _snapshot_protocol_enum_value(value, path=path)
        return expected_value if _enum_values else value
    if is_protocol_model:
        if not _trusted_protocol_type(value_type):
            raise _ProtocolSnapshotError(
                path,
                "model",
                f"{path} must contain an exact protocol model",
            )
        storage = object.__getattribute__(value, "__dict__")
        if type(storage) is not dict:
            raise ValueError(f"{path} has invalid protocol model storage")
        stored: dict[str, object] = {}
        for key, child in dict.items(storage):
            if type(key) is not str:
                raise ValueError(f"{path} has a non-canonical field name")
            stored[key] = child
        field_names = tuple(value_type.model_fields)
        if len(stored) != len(field_names) or any(
            name not in stored for name in field_names
        ):
            raise ValueError(f"{path} has incomplete or extra protocol fields")
        return {
            name: _snapshot_protocol_value(
                stored[name],
                path=f"{path}.{name}",
                _ancestor_ids=descendant_ancestors,
                _depth=_depth + 1,
                _enum_values=_enum_values,
            )
            for name in field_names
        }
    if isinstance(value, str):
        raise _ProtocolSnapshotError(
            path,
            "string",
            f"{path} must be an exact string",
        )
    if isinstance(value, int):
        raise _ProtocolSnapshotError(
            path,
            "integer",
            f"{path} must be an exact integer",
        )
    if isinstance(value, bytes):
        raise _ProtocolSnapshotError(
            path,
            "bytes",
            f"{path} must be exact bytes",
        )
    if isinstance(value, float):
        raise _ProtocolSnapshotError(
            path,
            "float",
            f"{path} must be an exact float",
        )
    raise TypeError(
        f"unsupported canonical JSON value at {path}: {_safe_type_name(value_type)}"
    )


def _snapshot_protocol_model(
    value: object,
    model_type: type[ProtocolModelT],
    *,
    label: str,
) -> ProtocolModelT:
    if type(value) is not model_type:
        raise _ProtocolSnapshotError(
            label,
            "model",
            f"{label} must be an exact protocol model",
        )
    document = _snapshot_protocol_value(value, path=label)
    if type(document) is not dict:
        raise ValueError(f"{label} must contain protocol model fields")
    return model_type.model_validate(document)


_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "auth_token",
        "authorization",
        "aws_secret_access_key",
        "bearer",
        "client_secret",
        "cookie",
        "credential",
        "id_token",
        "password",
        "passwd",
        "private_key",
        "proxy_authorization",
        "refresh_token",
        "request_body",
        "secret",
        "session_cookie",
        "set_cookie",
        "token",
        "x_api_key",
    }
)
_FORBIDDEN_SECRET_KEY_COMPACT = frozenset(
    key.replace("_", "") for key in _FORBIDDEN_SECRET_KEYS
)


def _normalize_key(value: str) -> str:
    with_word_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", with_word_boundaries)
    return normalized.strip("_").casefold()


def _is_raw_secret_key(value: str) -> bool:
    normalized = _normalize_key(value)
    return (
        normalized in _FORBIDDEN_SECRET_KEYS
        or normalized.replace("_", "") in _FORBIDDEN_SECRET_KEY_COMPACT
    )


def assert_no_raw_secret_fields(value: object, *, path: str = "$") -> None:
    """Reject raw-secret-shaped keys in generic documents before signing.

    Protocol models do not expose generic metadata dictionaries. This recursive
    guard additionally protects callers that ask canonical/signing helpers to
    process an ordinary mapping.
    """

    if isinstance(value, BaseModel):
        value = _snapshot_protocol_value(value, path=path)
    if isinstance(value, dict):
        if isinstance(value.get("key"), str) and _is_raw_secret_key(value["key"]):
            raise ValueError(f"raw secret field is forbidden at {path}.key={value['key']!r}")
        for key, child in value.items():
            key_text = str(key)
            if _is_raw_secret_key(key_text):
                raise ValueError(f"raw secret field is forbidden at {path}.{key_text}")
            assert_no_raw_secret_fields(child, path=f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            assert_no_raw_secret_fields(child, path=f"{path}[{index}]")
