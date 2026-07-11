"""Typed local RPC envelopes shared with out-of-process extensions."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from faultloom_protocol import (
    ActionIntent,
    AdapterManifest,
    ObservationRef,
    PackManifest,
    ProtocolModel,
)
from faultloom_protocol.base import Identifier, NonEmptyStr, Sha256Digest

RPC_VERSION = "0.1.0"


class RpcMethod(str, Enum):
    DESCRIBE = "describe"
    COMPILE_ACTION = "compile_action"
    NORMALIZE_OBSERVATION = "normalize_observation"


class DescribeRequest(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    method: Literal[RpcMethod.DESCRIBE]


class CompileActionRequest(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    method: Literal[RpcMethod.COMPILE_ACTION]
    authority_grant_digest: Sha256Digest
    action_intent: ActionIntent


class NormalizeObservationRequest(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    method: Literal[RpcMethod.NORMALIZE_OBSERVATION]
    authority_grant_digest: Sha256Digest
    adapter_id: Identifier
    capability: Identifier
    observation: ObservationRef


class CompiledAction(ProtocolModel):
    action_id: Identifier
    pack_id: Identifier
    compiler_id: Identifier
    intent_digest: Sha256Digest
    required_network_mode: Literal["gateway_only"]
    dispatch_authorized: Literal[False]


class NormalizedObservation(ProtocolModel):
    adapter_id: Identifier
    normalizer_id: Identifier
    observation_id: Identifier
    source_digest: Sha256Digest


class DescribeResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    status: Literal["ok"]
    pack_manifest: PackManifest
    adapter_manifest: AdapterManifest
    network_guard_active: Literal[True]


class CompileActionResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    status: Literal["ok"]
    compiled_action: CompiledAction


class NormalizeObservationResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    status: Literal["ok"]
    normalized_observation: NormalizedObservation


class RpcErrorResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"]
    request_id: Identifier
    status: Literal["error"]
    error_code: Identifier
    error_message: NonEmptyStr


def _rpc_union_schema(
    *,
    schema_id: str,
    title: str,
    models: tuple[type[ProtocolModel], ...],
) -> dict[str, object]:
    definitions: dict[str, object] = {}
    variants: list[dict[str, str]] = []
    for model in models:
        schema = model.model_json_schema(mode="validation")
        nested = schema.pop("$defs", {})
        for name, definition in nested.items():
            current = definitions.get(name)
            if current is not None and current != definition:
                raise RuntimeError(f"conflicting RPC schema definition: {name}")
            definitions[name] = definition
        name = model.__name__
        if name in definitions:
            raise RuntimeError(f"duplicate RPC schema definition: {name}")
        definitions[name] = schema
        variants.append({"$ref": f"#/$defs/{name}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        "title": title,
        "$defs": definitions,
        "oneOf": variants,
    }


def rpc_input_schema() -> dict[str, object]:
    """Return the complete canonicalizable validation schema for RPC requests."""

    schema = _rpc_union_schema(
        schema_id="urn:faultloom:reference-rpc:input:0.1.0",
        title="FaultLoom reference RPC requests",
        models=(DescribeRequest, CompileActionRequest, NormalizeObservationRequest),
    )
    schema["discriminator"] = {
        "propertyName": "method",
        "mapping": {
            method.value: f"#/$defs/{model.__name__}"
            for method, model in (
                (RpcMethod.DESCRIBE, DescribeRequest),
                (RpcMethod.COMPILE_ACTION, CompileActionRequest),
                (RpcMethod.NORMALIZE_OBSERVATION, NormalizeObservationRequest),
            )
        },
    }
    return schema


def rpc_output_schema() -> dict[str, object]:
    """Return the complete canonicalizable validation schema for RPC responses."""

    return _rpc_union_schema(
        schema_id="urn:faultloom:reference-rpc:output:0.1.0",
        title="FaultLoom reference RPC responses",
        models=(
            DescribeResponse,
            CompileActionResponse,
            NormalizeObservationResponse,
            RpcErrorResponse,
        ),
    )
