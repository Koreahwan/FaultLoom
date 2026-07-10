"""Shared protocol invariants."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

PROTOCOL_VERSION = "0.1.0"
SCHEMA_VERSION = "0.1.0"
SUPPORTED_PROTOCOL_RANGE = ">=0.1.0,<0.2.0"

SchemaVersion = Literal["0.1.0"]
NonEmptyStr = Annotated[str, Field(min_length=1, max_length=4096)]
ShortStr = Annotated[str, Field(min_length=1, max_length=256)]
Identifier = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include a timezone")
    return value


AwareDatetime = Annotated[datetime, AfterValidator(_require_aware)]


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

    schema_version: SchemaVersion = SCHEMA_VERSION


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


_FORBIDDEN_SECRET_KEYS = re.compile(
    r"^(password|passwd|credential|cookie|authorization|bearer|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret)$",
    re.IGNORECASE,
)


def assert_no_raw_secret_fields(value: object, *, path: str = "$") -> None:
    """Reject raw-secret-shaped keys in generic documents before signing.

    Protocol models do not expose generic metadata dictionaries. This recursive
    guard additionally protects callers that ask canonical/signing helpers to
    process an ordinary mapping.
    """

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if _FORBIDDEN_SECRET_KEYS.fullmatch(key_text):
                raise ValueError(f"raw secret field is forbidden at {path}.{key_text}")
            assert_no_raw_secret_fields(child, path=f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            assert_no_raw_secret_fields(child, path=f"{path}[{index}]")
