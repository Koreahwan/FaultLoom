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
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    method: Literal[RpcMethod.DESCRIBE] = RpcMethod.DESCRIBE


class CompileActionRequest(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    method: Literal[RpcMethod.COMPILE_ACTION] = RpcMethod.COMPILE_ACTION
    authority_grant_digest: Sha256Digest
    action_intent: ActionIntent


class NormalizeObservationRequest(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    method: Literal[RpcMethod.NORMALIZE_OBSERVATION] = RpcMethod.NORMALIZE_OBSERVATION
    authority_grant_digest: Sha256Digest
    adapter_id: Identifier
    capability: Identifier
    observation: ObservationRef


class CompiledAction(ProtocolModel):
    action_id: Identifier
    pack_id: Identifier
    compiler_id: Identifier
    intent_digest: Sha256Digest
    required_network_mode: Literal["gateway_only"] = "gateway_only"
    dispatch_authorized: Literal[False] = False


class NormalizedObservation(ProtocolModel):
    adapter_id: Identifier
    normalizer_id: Identifier
    observation_id: Identifier
    source_digest: Sha256Digest


class DescribeResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    status: Literal["ok"] = "ok"
    pack_manifest: PackManifest
    adapter_manifest: AdapterManifest
    network_guard_active: Literal[True] = True


class CompileActionResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    status: Literal["ok"] = "ok"
    compiled_action: CompiledAction


class NormalizeObservationResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    status: Literal["ok"] = "ok"
    normalized_observation: NormalizedObservation


class RpcErrorResponse(ProtocolModel):
    rpc_version: Literal["0.1.0"] = RPC_VERSION
    request_id: Identifier
    status: Literal["error"] = "error"
    error_code: Identifier
    error_message: NonEmptyStr
