from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from faultloom_protocol import ProtocolModel, canonical_json_bytes, sha256_digest

from ..context import RetrievalUnit
from .models import CheckpointReason, ResumeError, UnresolvedActionState

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

_RUNTIME_ENUM_VALUES = (
    (CheckpointReason.BEFORE_STATE_CHANGE, "before_state_change"),
    (CheckpointReason.BEFORE_LONG_BATCH, "before_long_batch"),
    (CheckpointReason.BEFORE_PROVIDER_FAILOVER, "before_provider_failover"),
    (CheckpointReason.BEFORE_COMPACTION, "before_compaction"),
    (CheckpointReason.STABLE_WATERMARK, "stable_watermark"),
    (CheckpointReason.TURN_END, "turn_end"),
    (UnresolvedActionState.PENDING, "pending"),
    (UnresolvedActionState.UNKNOWN_OUTCOME, "unknown_outcome"),
    (RetrievalUnit.BYTES, "bytes"),
    (RetrievalUnit.LINES, "lines"),
)


def canonical_model_bytes[ModelT: BaseModel](
    value: ModelT,
    expected_type: type[ModelT],
) -> bytes:
    return canonical_json_bytes(_model_document(value, expected_type))


def model_digest[ModelT: BaseModel](
    value: ModelT,
    expected_type: type[ModelT],
) -> str:
    return sha256_digest(_model_document(value, expected_type))


def _model_document[ModelT: BaseModel](
    value: ModelT,
    expected_type: type[ModelT],
) -> dict[str, WireValue]:
    if type(value) is not expected_type:
        raise ResumeError("resume wire model must have its exact registered type")
    document = _snapshot(value.model_dump(mode="python", exclude_none=False))
    if type(document) is not dict:
        raise ResumeError("resume wire model did not produce an object")
    return document


def _snapshot(value: WireValue) -> WireValue:
    value_type = type(value)
    if value_type is tuple:
        return tuple(_snapshot(child) for child in value)
    if value_type is list:
        return [_snapshot(child) for child in value]
    if value_type is dict:
        if any(type(key) is not str for key in value):
            raise ResumeError("resume wire object keys must be exact strings")
        return {key: _snapshot(child) for key, child in value.items()}
    if value_type in (CheckpointReason, UnresolvedActionState, RetrievalUnit):
        for member, wire_value in _RUNTIME_ENUM_VALUES:
            if value is member:
                return wire_value
        raise ResumeError("resume wire enum is not an exact registered member")
    return value
