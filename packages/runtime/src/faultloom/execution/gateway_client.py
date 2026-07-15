from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import BinaryIO, assert_never

from faultloom_protocol import (
    BudgetReservation,
    DispatchOutcome,
    DispatchReceipt,
    EgressPlane,
    SCHEMA_VERSION,
)

from .contracts import (
    GatewayDeniedResult,
    GatewayDispatchResult,
    GatewayResult,
    SemanticHttpObservation,
    SemanticResponseHeader,
)
from .gateway import (
    ExecutionFlowKind,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    bind_gateway_response,
    gateway_frame_digest,
)
from .http_validation import ExecutionContractError, GatewayChannelError

_MAX_FRAME_BYTES = 65_536
_CHANNEL_MAGIC = b"FLAC"
_CHANNEL_VERSION = 1
_CHANNEL_REQUEST = 1
_CHANNEL_RESPONSE = 2
_SUPERVISOR_MAGIC = b"FLSC"
_SUPERVISOR_VERSION = 5
_SUPERVISOR_COMMAND = 1
_SUPERVISOR_RESPONSE = 2
_GATEWAY_MAGIC = b"FLGW"
_GATEWAY_VERSION = 5
_GATEWAY_RESPONSE = 2
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


@dataclass(frozen=True, slots=True, repr=False)
class GatewayChannelConfig:
    key_id: str
    key: bytes
    boot_id: str
    nonce: bytes
    issued_at_millis: int
    expires_at_millis: int

    def __post_init__(self) -> None:
        if (
            not _valid_identifier(self.key_id)
            or not _valid_identifier(self.boot_id)
            or len(self.key) != 32
            or len(set(self.key)) < 4
            or len(self.nonce) != 16
            or len(set(self.nonce)) < 4
            or self.issued_at_millis >= self.expires_at_millis
        ):
            raise ExecutionContractError("invalid pinned Gateway channel configuration")

    @property
    def challenge_id(self) -> bytes:
        payload = bytearray(b"faultloom-gateway-channel-challenge-v1\0")
        _push_string(payload, self.key_id)
        _push_string(payload, self.boot_id)
        payload.extend(self.nonce)
        payload.extend(_u64(self.issued_at_millis))
        payload.extend(_u64(self.expires_at_millis))
        return hashlib.sha256(payload).digest()

    @property
    def session_id(self) -> str:
        return f"supervisor:channel:v1:{self.challenge_id.hex()}"


@dataclass(frozen=True, slots=True)
class _ChannelRequest:
    encoded: bytes
    envelope_id: bytes
    frame_digest: bytes
    sequence: int


@dataclass(frozen=True, slots=True)
class _RustReceipt:
    receipt_id: bytes
    authentication_tag: bytes
    action_id: str
    correlation_id: str
    lease_id: str
    grant_id: str
    grant_version: int
    authority_key_id: str
    scope_epoch_binding_digest: bytes
    lease_key_id: str
    gateway_boot_id: str
    boot_challenge_digest: bytes
    intent_digest: bytes
    decision_digest: bytes
    scope_epoch: int
    semantic_action_digest: bytes
    request_binding_digest: bytes
    request_frame_digest: bytes
    control_envelope_id: bytes
    hold_binding_digest: bytes
    resolution_digest: bytes
    effect_digest: bytes
    dispatch_nonce: bytes
    lease_issued_at_millis: int
    lease_expires_at_millis: int
    retry_of_intent_digest: bytes | None
    reserved_action_count: int
    reserved_request_bytes: int
    reserved_response_bytes: int
    reserved_duration_seconds: int
    request_digest: bytes
    response_digest: bytes | None
    outcome: int
    dispatched_at_millis: int
    completed_at_millis: int
    bytes_sent: int
    bytes_received: int
    reconciliation_required: bool


class AuthenticatedGatewayClient:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        channel: GatewayChannelConfig,
        *,
        expected_binary_digest: str,
        now_millis: Callable[[], int] | None = None,
    ) -> None:
        if type(process) is not subprocess.Popen or process.stdin is None or process.stdout is None:
            raise ExecutionContractError("Gateway process requires private stdin/stdout pipes")
        if process.poll() is not None:
            raise ExecutionContractError("Gateway process is not running")
        args = process.args
        if type(args) not in (tuple, list) or not args or "--supervised-stdio" not in args:
            raise ExecutionContractError("Gateway process is not in supervised stdio mode")
        executable = args[0]
        if type(executable) is not str:
            raise ExecutionContractError("Gateway executable path is not canonical text")
        digest = f"sha256:{hashlib.sha256(Path(executable).read_bytes()).hexdigest()}"
        if not hmac.compare_digest(digest, expected_binary_digest):
            raise ExecutionContractError("Gateway executable digest differs from the pinned RC")
        self._initialize(process.stdout, process.stdin, channel, now_millis)

    def _initialize(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        channel: GatewayChannelConfig,
        now_millis: Callable[[], int] | None,
    ) -> None:
        if type(channel) is not GatewayChannelConfig:
            raise ExecutionContractError("Gateway channel configuration must be exact")
        self._reader = reader
        self._writer = writer
        self._channel = channel
        self._now_millis = now_millis or _system_now_millis
        self._lock = Lock()
        self._sequence = 0
        self._response_nonces: set[bytes] = set()
        self._response_envelopes: set[bytes] = set()

    @property
    def channel_key(self) -> bytes:
        return self._channel.key

    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        command = _encode_dispatch_command(frame)
        with self._lock:
            request = self._seal_request(command)
            _write_frame(self._writer, request.encoded)
            encoded_response = _read_frame(self._reader)
            response_frame = self._verify_response(request, encoded_response)
            result = _decode_supervisor_response(response_frame, frame)
            acknowledgement = _encode_acknowledgement(
                request.envelope_id,
                hashlib.sha256(response_frame).digest(),
            )
            acknowledgement_request = self._seal_request(acknowledgement)
            _write_frame(self._writer, acknowledgement_request.encoded)
        return bind_gateway_response(frame, result, self._channel.key)

    def reconcile(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope | None:
        raise GatewayChannelError(
            "unknown outcomes require the T18 signed reconciliation control plane"
        )

    def close(self) -> None:
        self._writer.close()
        self._reader.close()

    def _seal_request(self, frame: bytes) -> _ChannelRequest:
        now = self._now_millis()
        if type(now) is not int or now < self._channel.issued_at_millis:
            raise GatewayChannelError("Gateway channel clock is invalid")
        expires = min(now + 30_000, self._channel.expires_at_millis)
        if now >= expires:
            raise GatewayChannelError("Gateway channel challenge expired")
        self._sequence += 1
        nonce = _fresh_nonce()
        frame_digest = hashlib.sha256(frame).digest()
        unsigned = bytearray(_CHANNEL_MAGIC)
        unsigned.extend((_CHANNEL_VERSION, _CHANNEL_REQUEST))
        _push_string(unsigned, self._channel.key_id)
        _push_string(unsigned, self._channel.boot_id)
        unsigned.extend(self._channel.challenge_id)
        _push_string(unsigned, self._channel.session_id)
        unsigned.extend(_u64(self._sequence))
        unsigned.extend(nonce)
        unsigned.extend(_u64(now))
        unsigned.extend(_u64(expires))
        unsigned.extend(frame_digest)
        _push_bytes(unsigned, frame)
        tag = hmac.new(
            self._channel.key,
            b"faultloom-channel-request-v1\0" + unsigned,
            hashlib.sha256,
        ).digest()
        encoded = bytes(unsigned + tag)
        return _ChannelRequest(
            encoded=encoded,
            envelope_id=hashlib.sha256(encoded).digest(),
            frame_digest=frame_digest,
            sequence=self._sequence,
        )

    def _verify_response(self, request: _ChannelRequest, encoded: bytes) -> bytes:
        decoder = _Decoder(encoded, _CHANNEL_MAGIC, _CHANNEL_VERSION, _CHANNEL_RESPONSE)
        key_id = decoder.string()
        boot_id = decoder.string()
        challenge_id = decoder.digest()
        session_id = decoder.string()
        sequence = decoder.u64()
        request_envelope_id = decoder.digest()
        request_frame_digest = decoder.digest()
        nonce = decoder.nonce()
        issued_at = decoder.u64()
        expires_at = decoder.u64()
        response_frame_digest = decoder.digest()
        response_frame = decoder.bytes(_MAX_FRAME_BYTES)
        unsigned_end = decoder.offset
        authentication_tag = decoder.digest()
        decoder.finish()
        now = self._now_millis()
        envelope_id = hashlib.sha256(encoded).digest()
        expected_tag = hmac.new(
            self._channel.key,
            b"faultloom-channel-response-v1\0" + encoded[:unsigned_end],
            hashlib.sha256,
        ).digest()
        if (
            key_id != self._channel.key_id
            or boot_id != self._channel.boot_id
            or challenge_id != self._channel.challenge_id
            or session_id != self._channel.session_id
            or sequence != request.sequence
            or request_envelope_id != request.envelope_id
            or request_frame_digest != request.frame_digest
            or len(set(nonce)) < 4
            or issued_at > now
            or expires_at <= now
            or issued_at >= expires_at
            or expires_at > self._channel.expires_at_millis
            or expires_at - issued_at > 30_000
            or response_frame_digest != hashlib.sha256(response_frame).digest()
            or not hmac.compare_digest(authentication_tag, expected_tag)
            or nonce in self._response_nonces
            or envelope_id in self._response_envelopes
        ):
            raise GatewayChannelError("Gateway response authentication failed")
        self._response_nonces.add(nonce)
        self._response_envelopes.add(envelope_id)
        return response_frame


def _encode_dispatch_command(frame: GatewayDispatchFrame) -> bytes:
    command = frame.command
    request = command.request
    if (
        request.endpoint.scheme.value != "http"
        or request.endpoint.query
        or request.headers
        or request.body_ref is not None
    ):
        raise ExecutionContractError(
            "T19 supervised semantic HTTP supports plain HTTP without unresolved refs"
        )
    output = bytearray(_SUPERVISOR_MAGIC)
    output.extend((_SUPERVISOR_VERSION, _SUPERVISOR_COMMAND, 2))
    for value in (
        command.intent.action_id,
        command.lease.correlation_id,
        command.lease.lease_id,
        command.intent.target_id,
    ):
        _push_string(output, value)
    output.extend(_u64(command.lease.scope_epoch))
    output.append(_action_class_tag(command.intent.action_class.value))
    output.append(_flow_kind_tag(frame.flow_kind))
    _push_optional_string(output, frame.parent_action_id)
    _push_string(output, request.method)
    _push_string(output, request.endpoint.path)
    output.extend(_digest_bytes(command.intent_digest))
    output.extend(_digest_bytes(command.decision_digest))
    output.extend(bytes.fromhex(command.lease.dispatch_nonce))
    output.extend(_u64(_datetime_millis(command.lease.issued_at)))
    output.extend(_u64(_datetime_millis(command.lease.expires_at)))
    _push_optional_digest(output, command.lease.retry_of_intent_digest)
    _push_bytes(output, b"")
    _push_optional_string(output, command.intent.canary_ref)
    _push_optional_string(output, command.intent.checkpoint_ref)
    _push_optional_string(output, command.intent.cleanup_plan_ref)
    if len(output) > _MAX_FRAME_BYTES:
        raise ExecutionContractError("Gateway supervisor command exceeds the frame limit")
    return bytes(output)


def _encode_acknowledgement(request_id: bytes, response_digest: bytes) -> bytes:
    output = bytearray(_SUPERVISOR_MAGIC)
    output.extend((_SUPERVISOR_VERSION, _SUPERVISOR_COMMAND, 5))
    output.extend(request_id)
    output.extend(response_digest)
    return bytes(output)


def _decode_supervisor_response(
    encoded: bytes,
    frame: GatewayDispatchFrame,
) -> GatewayResult:
    decoder = _Decoder(
        encoded,
        _SUPERVISOR_MAGIC,
        _SUPERVISOR_VERSION,
        _SUPERVISOR_RESPONSE,
    )
    if decoder.byte() != 2:
        raise GatewayChannelError("Gateway dispatch returned a control response")
    gateway = decoder.bytes(_MAX_FRAME_BYTES)
    decoder.finish()
    return _decode_gateway_response(gateway, frame)


def _decode_gateway_response(encoded: bytes, frame: GatewayDispatchFrame) -> GatewayResult:
    decoder = _Decoder(encoded, _GATEWAY_MAGIC, _GATEWAY_VERSION, _GATEWAY_RESPONSE)
    kind = decoder.byte()
    if kind == 1:
        denial_id = decoder.digest()
        action_id = decoder.string()
        request_digest = decoder.digest()
        reason = decoder.byte()
        decoder.finish()
        expected = bytearray(b"faultloom-gateway-denial-v1\0")
        _push_string(expected, action_id)
        expected.extend(request_digest)
        expected.append(reason)
        if denial_id != hashlib.sha256(expected).digest():
            raise GatewayChannelError("Gateway denial ID is invalid")
        return GatewayDeniedResult(
            schema_version=SCHEMA_VERSION,
            action_id=action_id,
            request_digest=gateway_frame_digest(frame),
            reason_code=f"gateway.denial.{reason}",
        )
    if kind != 2:
        raise GatewayChannelError("Gateway response kind is unknown")
    action_id = decoder.string()
    receipt = _decode_receipt(decoder)
    semantic = _decode_semantic_http(decoder)
    decoder.finish()
    return _translate_receipt(action_id, receipt, semantic, frame)


def _decode_receipt(decoder: _Decoder) -> _RustReceipt:
    receipt_id = decoder.digest()
    authentication_tag = decoder.digest()
    action_id = decoder.string()
    correlation_id = decoder.string()
    lease_id = decoder.string()
    grant_id = decoder.string()
    grant_version = decoder.u64()
    authority_key_id = decoder.string()
    scope_epoch_binding_digest = decoder.digest()
    lease_key_id = decoder.string()
    gateway_boot_id = decoder.string()
    boot_challenge_digest = decoder.digest()
    intent_digest = decoder.digest()
    decision_digest = decoder.digest()
    scope_epoch = decoder.u64()
    semantic_action_digest = decoder.digest()
    request_binding_digest = decoder.digest()
    request_frame_digest = decoder.digest()
    control_envelope_id = decoder.digest()
    hold_binding_digest = decoder.digest()
    resolution_digest = decoder.digest()
    if decoder.byte() != 1 or decoder.byte() != 1:
        raise GatewayChannelError("Gateway receipt action or egress kind is unsupported")
    effect_digest = decoder.digest()
    dispatch_nonce = decoder.nonce()
    lease_issued_at_millis = decoder.u64()
    lease_expires_at_millis = decoder.u64()
    retry_of_intent_digest = decoder.optional_digest()
    reserved_action_count = decoder.u64()
    reserved_request_bytes = decoder.u64()
    reserved_response_bytes = decoder.u64()
    reserved_duration_seconds = decoder.u64()
    request_digest = decoder.digest()
    response_digest = decoder.optional_digest()
    outcome = decoder.byte()
    dispatched_at_millis = decoder.u64()
    completed_at_millis = decoder.u64()
    bytes_sent = decoder.u64()
    bytes_received = decoder.u64()
    reconciliation_required = decoder.boolean()
    if authentication_tag == bytes(32) or receipt_id == bytes(32):
        raise GatewayChannelError("Gateway receipt authentication is absent")
    return _RustReceipt(
        receipt_id,
        authentication_tag,
        action_id,
        correlation_id,
        lease_id,
        grant_id,
        grant_version,
        authority_key_id,
        scope_epoch_binding_digest,
        lease_key_id,
        gateway_boot_id,
        boot_challenge_digest,
        intent_digest,
        decision_digest,
        scope_epoch,
        semantic_action_digest,
        request_binding_digest,
        request_frame_digest,
        control_envelope_id,
        hold_binding_digest,
        resolution_digest,
        effect_digest,
        dispatch_nonce,
        lease_issued_at_millis,
        lease_expires_at_millis,
        retry_of_intent_digest,
        reserved_action_count,
        reserved_request_bytes,
        reserved_response_bytes,
        reserved_duration_seconds,
        request_digest,
        response_digest,
        outcome,
        dispatched_at_millis,
        completed_at_millis,
        bytes_sent,
        bytes_received,
        reconciliation_required,
    )


def _decode_semantic_http(decoder: _Decoder) -> SemanticHttpObservation | None:
    if not decoder.boolean():
        return None
    status_code = decoder.u16()
    header_count = decoder.u16()
    if header_count > 128:
        raise GatewayChannelError("Gateway semantic response has too many headers")
    headers = tuple(
        SemanticResponseHeader(
            schema_version=SCHEMA_VERSION,
            name=decoder.short_string(),
            value=decoder.short_bytes(),
        )
        for _ in range(header_count)
    )
    body = decoder.long_bytes()
    body_digest = decoder.digest()
    raw_response_digest = decoder.digest()
    raw_response_length = decoder.u64()
    if body_digest != hashlib.sha256(body).digest():
        raise GatewayChannelError("Gateway semantic body digest is invalid")
    return SemanticHttpObservation(
        schema_version=SCHEMA_VERSION,
        status_code=status_code,
        headers=headers,
        body=body,
        body_digest=_digest_text(body_digest),
        raw_response_digest=_digest_text(raw_response_digest),
        raw_response_length=raw_response_length,
    )


def _translate_receipt(
    action_id: str,
    rust: _RustReceipt,
    observation: SemanticHttpObservation | None,
    frame: GatewayDispatchFrame,
) -> GatewayDispatchResult:
    command = frame.command
    lease = command.lease
    caller_bindings_match = (
        action_id == rust.action_id == command.intent.action_id
        and rust.correlation_id == lease.correlation_id
        and rust.lease_id == lease.lease_id
        and rust.grant_id == lease.grant_id
        and rust.grant_version == lease.grant_version
        and _digest_text(rust.intent_digest) == command.intent_digest
        and _digest_text(rust.decision_digest) == command.decision_digest
        and rust.scope_epoch == lease.scope_epoch
        and rust.dispatch_nonce.hex() == lease.dispatch_nonce
        and rust.lease_issued_at_millis == _datetime_millis(lease.issued_at)
        and rust.lease_expires_at_millis == _datetime_millis(lease.expires_at)
        and _optional_digest_text(rust.retry_of_intent_digest)
        == lease.retry_of_intent_digest
    )
    if not caller_bindings_match:
        raise GatewayChannelError("Gateway receipt differs from the approved command")
    outcome = _dispatch_outcome(rust.outcome)
    response_status = observation.status_code if observation is not None else None
    if observation is not None and (
        _optional_digest_text(rust.response_digest) != observation.raw_response_digest
        or rust.bytes_received != observation.raw_response_length
    ):
        raise GatewayChannelError("Gateway semantic artifact differs from its receipt")
    receipt = DispatchReceipt(
        schema_version=SCHEMA_VERSION,
        receipt_id=f"receipt.{rust.receipt_id.hex()}",
        receipt_authentication_tag=_digest_text(rust.authentication_tag),
        action_id=rust.action_id,
        correlation_id=rust.correlation_id,
        lease_id=rust.lease_id,
        lease_key_id=rust.lease_key_id,
        grant_id=rust.grant_id,
        grant_version=rust.grant_version,
        authority_key_id=rust.authority_key_id,
        scope_epoch_binding_digest=_digest_text(rust.scope_epoch_binding_digest),
        gateway_boot_id=rust.gateway_boot_id,
        boot_challenge_digest=_digest_text(rust.boot_challenge_digest),
        intent_digest=_digest_text(rust.intent_digest),
        decision_digest=_digest_text(rust.decision_digest),
        scope_epoch=rust.scope_epoch,
        target_id=command.intent.target_id,
        identity_id=command.identity.identity_id or lease.identity_id,
        tenant_id=command.identity.tenant_id,
        action_kind=command.intent.action_kind,
        semantic_action_digest=_digest_text(rust.semantic_action_digest),
        request_binding_digest=_digest_text(rust.request_binding_digest),
        request_frame_digest=_digest_text(rust.request_frame_digest),
        resolution_digest=_digest_text(rust.resolution_digest),
        egress_plane=EgressPlane.TARGET_GATEWAY,
        dispatch_nonce=rust.dispatch_nonce.hex(),
        lease_issued_at=_millis_datetime(rust.lease_issued_at_millis),
        lease_expires_at=_millis_datetime(rust.lease_expires_at_millis),
        retry_of_intent_digest=_optional_digest_text(rust.retry_of_intent_digest),
        reservation=BudgetReservation(
            schema_version=SCHEMA_VERSION,
            action_count=rust.reserved_action_count,
            request_bytes=rust.reserved_request_bytes,
            response_bytes=rust.reserved_response_bytes,
            duration_seconds=rust.reserved_duration_seconds,
        ),
        request_digest=_digest_text(rust.request_digest),
        response_digest=_optional_digest_text(rust.response_digest),
        outcome=outcome,
        dispatched_at=_millis_datetime(rust.dispatched_at_millis),
        completed_at=_millis_datetime(rust.completed_at_millis),
        response_status=response_status,
        bytes_sent=rust.bytes_sent,
        bytes_received=rust.bytes_received,
        reconciliation_required=rust.reconciliation_required,
    )
    return GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=receipt,
        observation=observation,
    )


class _Decoder:
    def __init__(self, data: bytes, magic: bytes, version: int, kind: int) -> None:
        if len(data) < 6 or len(data) > _MAX_FRAME_BYTES or data[:4] != magic:
            raise GatewayChannelError("Gateway frame header is invalid")
        if data[4] != version or data[5] != kind:
            raise GatewayChannelError("Gateway frame version or kind is unsupported")
        self._data = data
        self.offset = 6

    def take(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self._data):
            raise GatewayChannelError("Gateway frame ended unexpectedly")
        value = self._data[self.offset:end]
        self.offset = end
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def boolean(self) -> bool:
        value = self.byte()
        if value not in (0, 1):
            raise GatewayChannelError("Gateway boolean is not canonical")
        return value == 1

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def digest(self) -> bytes:
        return self.take(32)

    def nonce(self) -> bytes:
        return self.take(16)

    def bytes(self, maximum: int) -> bytes:
        length = self.u32()
        if length > maximum:
            raise GatewayChannelError("Gateway byte field exceeds its limit")
        return self.take(length)

    def long_bytes(self) -> bytes:
        return self.bytes(_MAX_FRAME_BYTES)

    def short_bytes(self) -> bytes:
        length = self.u16()
        return self.take(length)

    def string(self) -> str:
        return self.bytes(4_096).decode("utf-8")

    def short_string(self) -> str:
        return self.short_bytes().decode("utf-8")

    def optional_digest(self) -> bytes | None:
        return self.digest() if self.boolean() else None

    def finish(self) -> None:
        if self.offset != len(self._data):
            raise GatewayChannelError("Gateway frame has trailing bytes")


def _write_frame(writer: BinaryIO, payload: bytes) -> None:
    if not payload or len(payload) > _MAX_FRAME_BYTES:
        raise GatewayChannelError("Gateway frame length is invalid")
    writer.write(struct.pack(">I", len(payload)))
    writer.write(payload)
    writer.flush()


def _read_frame(reader: BinaryIO) -> bytes:
    length = _read_exact(reader, 4)
    size = struct.unpack(">I", length)[0]
    if size == 0 or size > _MAX_FRAME_BYTES:
        raise GatewayChannelError("Gateway response frame length is invalid")
    return _read_exact(reader, size)


def _read_exact(reader: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = reader.read(length - len(chunks))
        if not chunk:
            raise GatewayChannelError("Gateway channel closed before a complete frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _action_class_tag(value: str) -> int:
    tags = {"observe": 1, "safe_probe": 2, "state_change": 3}
    try:
        return tags[value]
    except KeyError as exc:
        raise ExecutionContractError("unsupported Gateway action class") from exc


def _flow_kind_tag(flow: ExecutionFlowKind) -> int:
    match flow:
        case ExecutionFlowKind.DIRECT | ExecutionFlowKind.NAVIGATION:
            return 1
        case ExecutionFlowKind.REDIRECT:
            return 3
        case ExecutionFlowKind.SUBRESOURCE:
            return 4
        case ExecutionFlowKind.IFRAME:
            return 5
        case ExecutionFlowKind.SERVICE_WORKER:
            return 6
        case ExecutionFlowKind.DOWNLOAD:
            return 8
        case unreachable:
            assert_never(unreachable)


def _dispatch_outcome(value: int) -> DispatchOutcome:
    match value:
        case 1:
            return DispatchOutcome.COMPLETED
        case 2:
            return DispatchOutcome.FAILED
        case 3:
            return DispatchOutcome.UNKNOWN_OUTCOME
        case _:
            raise GatewayChannelError("Gateway dispatch outcome is unknown")


def _digest_bytes(value: str) -> bytes:
    if not value.startswith("sha256:"):
        raise ExecutionContractError("Gateway binding is not a SHA-256 digest")
    try:
        digest = bytes.fromhex(value.removeprefix("sha256:"))
    except ValueError as exc:
        raise ExecutionContractError("Gateway binding is not hexadecimal") from exc
    if len(digest) != 32:
        raise ExecutionContractError("Gateway binding has the wrong digest length")
    return digest


def _digest_text(value: bytes) -> str:
    return f"sha256:{value.hex()}"


def _optional_digest_text(value: bytes | None) -> str | None:
    return None if value is None else _digest_text(value)


def _push_string(output: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    if len(encoded) > 4_096:
        raise ExecutionContractError("Gateway text field exceeds its limit")
    _push_bytes(output, encoded)


def _push_bytes(output: bytearray, value: bytes) -> None:
    output.extend(struct.pack(">I", len(value)))
    output.extend(value)


def _push_optional_string(output: bytearray, value: str | None) -> None:
    output.append(int(value is not None))
    if value is not None:
        _push_string(output, value)


def _push_optional_digest(output: bytearray, value: str | None) -> None:
    output.append(int(value is not None))
    if value is not None:
        output.extend(_digest_bytes(value))


def _u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ExecutionContractError("Gateway integer is outside u64")
    return struct.pack(">Q", value)


def _datetime_millis(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None or value.microsecond % 1_000:
        raise ExecutionContractError("Gateway timestamps require UTC millisecond precision")
    return int(value.timestamp() * 1_000)


def _millis_datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000, tz=timezone.utc)


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value))


def _fresh_nonce() -> bytes:
    while True:
        nonce = os.urandom(16)
        if len(set(nonce)) >= 4:
            return nonce


def _system_now_millis() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1_000)
