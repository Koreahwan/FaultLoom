"""Transient, digest-bound attestations for one local model exchange."""

from __future__ import annotations

import base64
import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, ClassVar

from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    ModelProducerAttestation,
    SignedModelProducerAttestation,
    attestation_signing_bytes,
    sha256_digest,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .model_utility_attestation_state import MonotonicAttestationState
from .model_utility_process import BoundedProcessError, run_bounded_process
from .model_utility_proxy import DigestPinnedLocalProcessProxy
from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)
from .model_utility_sandbox import pinned_process_launch

_DIGEST_PREFIX = "sha256:"
_MAX_ATTESTOR_REQUEST_BYTES = 16_781_312
_MAX_INT64 = (2**63) - 1


@dataclass(frozen=True, slots=True)
class ModelUtilityExchangeTranscript:
    """Ephemeral parsed response and exact launch identity."""

    response: LocalModelProcessResponse
    fixed_argv_digest: str


@dataclass(frozen=True, slots=True)
class AttestedModelUtilityExchange:
    response: LocalModelProcessResponse
    producer_receipt: SignedModelProducerAttestation


class _AttestorModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )


class ProducerAttestorRequest(_AttestorModel):
    request: LocalModelProcessRequest
    session_id: Annotated[
        str,
        Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"),
    ]
    evaluator_challenge: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    allocation_id: Annotated[
        str,
        Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"),
    ]
    trusted_minimum_sequence: Annotated[int, Field(strict=True, ge=0, lt=_MAX_INT64)]


class ProducerAttestorResponse(_AttestorModel):
    response: LocalModelProcessResponse
    producer_receipt: SignedModelProducerAttestation


def _raw_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _canonical_local_model_bytes(
    value: LocalModelProcessRequest | LocalModelProcessResponse,
) -> bytes:
    return json.dumps(
        value.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _wire_bytes(value: BaseModel) -> bytes:
    return json.dumps(
        value.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _signer_fingerprint(signer: AuthoritySigner) -> str:
    record = signer.public_key_record
    raw = base64.urlsafe_b64decode(record.public_key + "==")
    return _raw_digest(raw)


def _config_from_proxy(proxy: DigestPinnedLocalProcessProxy) -> LocalModelProcessConfig:
    if type(proxy) is not DigestPinnedLocalProcessProxy:
        raise LocalModelProcessError("attestor requires an exact digest-pinned proxy")
    config = object.__getattribute__(proxy, "_config")
    if type(config) is not LocalModelProcessConfig:
        raise LocalModelProcessError("digest-pinned proxy config is unavailable")
    return config


def exchange_with_transcript(
    proxy: DigestPinnedLocalProcessProxy,
    request: LocalModelProcessRequest,
) -> ModelUtilityExchangeTranscript:
    """Run the existing pinned launch while retaining exact stdout in memory."""

    config = _config_from_proxy(proxy)
    if type(request) is not LocalModelProcessRequest:
        raise LocalModelProcessError("local model proxy requires an exact request")
    if (
        request.model_snapshot_digest != config.model_snapshot_digest
        or request.runtime_artifact_digest != config.runtime_executable_digest
    ):
        raise LocalModelProcessError("local model request artifact digest mismatch")
    encoded = _canonical_local_model_bytes(request) + b"\n"
    if len(encoded) > config.maximum_request_bytes:
        raise LocalModelProcessError("local model request exceeds its byte limit")
    try:
        with pinned_process_launch(config, encoded) as launch:
            completed = run_bounded_process(launch)
            fixed_argv_digest = sha256_digest(launch.argv)
    except subprocess.TimeoutExpired:
        error = LocalModelProcessError("local model process timed out")
    except BoundedProcessError:
        error = LocalModelProcessError("local model process exceeded an I/O limit")
    except LocalModelProcessError:
        raise
    except OSError:
        error = LocalModelProcessError("local model process launch failed")
    else:
        if completed.returncode != 0:
            raise LocalModelProcessError("local model process returned nonzero status")
        try:
            response = LocalModelProcessResponse.model_validate_json(completed.stdout)
        except ValidationError:
            raise LocalModelProcessError(
                "local model process returned a malformed response"
            ) from None
        if _canonical_local_model_bytes(response) != completed.stdout:
            raise LocalModelProcessError("local model response JSON is not canonical")
        if (
            response.request_id != request.request_id
            or response.model_snapshot_digest != request.model_snapshot_digest
            or response.runtime_artifact_digest != request.runtime_artifact_digest
        ):
            raise LocalModelProcessError("local model response identity mismatch")
        return ModelUtilityExchangeTranscript(
            response=response,
            fixed_argv_digest=fixed_argv_digest,
        )
    raise error from None


class TransientModelUtilityAttestor:
    """Run one pinned exchange and sign its exact public-safe bindings."""

    __slots__ = ("_core_wheel_digest", "_proxy", "_signer", "_state")

    def __init__(
        self,
        *,
        proxy: DigestPinnedLocalProcessProxy,
        signer: AuthoritySigner,
        sequence_state: MonotonicAttestationState,
        core_wheel_digest: str,
    ) -> None:
        _ = _config_from_proxy(proxy)
        if type(signer) is not AuthoritySigner:
            raise TypeError("producer signer must be an operator-injected AuthoritySigner")
        if type(sequence_state) is not MonotonicAttestationState:
            raise TypeError("producer sequence state must be exact monotonic state")
        if not _is_digest(core_wheel_digest):
            raise ValueError("core wheel digest is invalid")
        self._proxy = proxy
        self._signer = signer
        self._state = sequence_state
        self._core_wheel_digest = core_wheel_digest

    def exchange(
        self,
        request: LocalModelProcessRequest,
        *,
        session_id: str,
        evaluator_challenge: str,
        allocation_id: str,
        trusted_minimum_sequence: int = 0,
    ) -> AttestedModelUtilityExchange:
        transcript = exchange_with_transcript(self._proxy, request)
        sequence = self._state.allocate(
            allocation_id,
            trusted_minimum_sequence=trusted_minimum_sequence,
        )
        config = _config_from_proxy(self._proxy)
        response = transcript.response
        payload = ModelProducerAttestation(
            schema_version=SCHEMA_VERSION,
            producer_key_id=self._signer.key_id,
            producer_key_fingerprint=_signer_fingerprint(self._signer),
            session_id=session_id,
            sequence=sequence,
            evaluator_challenge=evaluator_challenge,
            canonical_request_digest=_raw_digest(_canonical_local_model_bytes(request)),
            parsed_response_digest=_raw_digest(_canonical_local_model_bytes(response)),
            raw_llama_stdout_digest=response.raw_llama_stdout_digest,
            output_digest=response.output_digest,
            model_digest=config.model_snapshot_digest,
            runtime_wrapper_digest=config.runtime_executable_digest,
            runtime_bundle_digest=config.runtime_bundle_digest,
            bwrap_digest=FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
            fixed_argv_digest=transcript.fixed_argv_digest,
            core_wheel_digest=self._core_wheel_digest,
            profile_digest=_raw_digest(
                json.dumps(
                    config.model_dump(mode="json"),
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ),
            status="accepted",
            prompt_tokens=response.input_tokens,
            completion_tokens=response.output_tokens,
            total_tokens=response.input_tokens + response.output_tokens,
        )
        payload_digest = sha256_digest(payload)
        envelope = SignedModelProducerAttestation(
            schema_version=SCHEMA_VERSION,
            payload=payload,
            payload_digest=payload_digest,
            signature=self._signer.sign(
                attestation_signing_bytes(payload, payload_digest)
            ),
        )
        return AttestedModelUtilityExchange(
            response=response,
            producer_receipt=envelope,
        )


def parse_producer_attestor_request(raw: bytes) -> ProducerAttestorRequest:
    if type(raw) is not bytes:
        raise TypeError("producer attestor request must be exact bytes")
    if (
        len(raw) > _MAX_ATTESTOR_REQUEST_BYTES
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
    ):
        raise LocalModelProcessError("producer attestor request framing is invalid")
    try:
        request = ProducerAttestorRequest.model_validate_json(raw[:-1])
    except ValidationError:
        raise LocalModelProcessError("producer attestor request schema is invalid") from None
    if _wire_bytes(request) != raw[:-1]:
        raise LocalModelProcessError("producer attestor request JSON is not canonical")
    return request


def _read_signer(descriptor: int) -> AuthoritySigner:
    if type(descriptor) is not int or descriptor < 3:
        raise LocalModelProcessError("producer signing key descriptor is invalid")
    try:
        material = os.read(descriptor, 33)
    except OSError as exc:
        raise LocalModelProcessError("producer signing key descriptor is unavailable") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if len(material) != 32:
        raise LocalModelProcessError("producer signing key must be exactly 32 bytes")
    try:
        return AuthoritySigner.from_private_bytes(material)
    finally:
        del material


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--signing-key-fd", required=True, type=int)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument(
        "--profile",
        required=True,
        choices=tuple(profile.value for profile in LocalModelRuntimeProfile),
    )
    parser.add_argument("--timeout-seconds", required=True, type=int)
    parser.add_argument("--maximum-request-bytes", required=True, type=int)
    parser.add_argument("--maximum-response-bytes", required=True, type=int)
    parser.add_argument("--core-wheel-digest", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(argv)
        framed = sys.stdin.buffer.read(_MAX_ATTESTOR_REQUEST_BYTES + 1)
        request = parse_producer_attestor_request(framed)
        signer = _read_signer(arguments.signing_key_fd)
        config = LocalModelProcessConfig(
            profile=LocalModelRuntimeProfile(arguments.profile),
            timeout_seconds=arguments.timeout_seconds,
            maximum_request_bytes=arguments.maximum_request_bytes,
            maximum_response_bytes=arguments.maximum_response_bytes,
        )
        with MonotonicAttestationState(arguments.state) as state:
            result = TransientModelUtilityAttestor(
                proxy=DigestPinnedLocalProcessProxy(config),
                signer=signer,
                sequence_state=state,
                core_wheel_digest=arguments.core_wheel_digest,
            ).exchange(
                request.request,
                session_id=request.session_id,
                evaluator_challenge=request.evaluator_challenge,
                allocation_id=request.allocation_id,
                trusted_minimum_sequence=request.trusted_minimum_sequence,
            )
        response = ProducerAttestorResponse(
            response=result.response,
            producer_receipt=result.producer_receipt,
        )
        sys.stdout.buffer.write(_wire_bytes(response) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (OSError, TypeError, ValueError, LocalModelProcessError):
        return 2


def _is_digest(value: object) -> bool:
    if type(value) is not str or not value.startswith(_DIGEST_PREFIX) or len(value) != 71:
        return False
    try:
        _ = bytes.fromhex(value[len(_DIGEST_PREFIX) :])
    except ValueError:
        return False
    return value == value.lower()


__all__ = [
    "AttestedModelUtilityExchange",
    "ModelUtilityExchangeTranscript",
    "ProducerAttestorRequest",
    "ProducerAttestorResponse",
    "TransientModelUtilityAttestor",
    "exchange_with_transcript",
    "main",
    "parse_producer_attestor_request",
]


if __name__ == "__main__":
    raise SystemExit(main())
