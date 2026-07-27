"""Canonical producer-attestation bindings for the formal T40 runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Annotated, ClassVar, Literal, Self

from faultloom_protocol import Sha256Digest, canonical_json_bytes
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST,
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelRuntimeProfile,
)
from .model_utility_sandbox import (
    canonical_model_utility_launch_digest,
    pinned_process_launch,
)

FORMAL_PRODUCER_BINDING_SCHEMA = "faultloom.core.t40-formal-producer-binding.v1"
FORMAL_MAXIMUM_REQUEST_BYTES = 65_536
_MAX_DOCUMENT_BYTES = 16_384


class _BindingModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class FormalProducerBinding(_BindingModel):
    """Public, immutable values expected in every formal producer receipt."""

    schema_id: Literal["faultloom.core.t40-formal-producer-binding.v1"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    core_wheel_digest: Sha256Digest
    producer_model_digest: Sha256Digest
    producer_runtime_wrapper_digest: Sha256Digest
    producer_runtime_bundle_digest: Sha256Digest
    producer_sandbox_digest: Sha256Digest
    producer_fixed_argv_digest: Sha256Digest
    producer_profile_digest: Sha256Digest
    profile: Literal[LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1]
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    maximum_request_bytes: Literal[65_536]
    maximum_response_bytes: Annotated[
        int, Field(strict=True, ge=1, le=16_777_216)
    ]

    @model_validator(mode="after")
    def _fixed_profile_values_are_exact(self) -> Self:
        config = _config(
            timeout_seconds=self.timeout_seconds,
            maximum_request_bytes=self.maximum_request_bytes,
            maximum_response_bytes=self.maximum_response_bytes,
        )
        with pinned_process_launch(config, b"") as launch:
            expected_fixed_argv_digest = canonical_model_utility_launch_digest(launch)
        if (
            self.producer_model_digest != config.model_snapshot_digest
            or self.producer_runtime_wrapper_digest
            != config.runtime_executable_digest
            or self.producer_runtime_bundle_digest != config.runtime_bundle_digest
            or self.producer_sandbox_digest
            != FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST
            or self.producer_fixed_argv_digest != expected_fixed_argv_digest
            or self.producer_profile_digest != _profile_digest(config)
        ):
            raise ValueError("formal producer binding does not match the fixed profile")
        return self


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _config(
    *,
    timeout_seconds: int,
    maximum_request_bytes: int,
    maximum_response_bytes: int,
) -> LocalModelProcessConfig:
    if type(maximum_request_bytes) is not int or maximum_request_bytes != 65_536:
        raise LocalModelProcessError(
            "formal producer maximum request bytes must be exactly 65536"
        )
    return LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=timeout_seconds,
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
    )


def _profile_digest(config: LocalModelProcessConfig) -> str:
    return _digest(
        json.dumps(
            config.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def materialize_formal_producer_binding(
    *,
    core_wheel_digest: str,
    timeout_seconds: int,
    maximum_request_bytes: int,
    maximum_response_bytes: int,
) -> FormalProducerBinding:
    """Verify installed artifacts and derive the exact attestor bindings."""

    config = _config(
        timeout_seconds=timeout_seconds,
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
    )
    with pinned_process_launch(config, b"") as launch:
        fixed_argv_digest = canonical_model_utility_launch_digest(launch)
    return FormalProducerBinding(
        schema=FORMAL_PRODUCER_BINDING_SCHEMA,
        core_wheel_digest=core_wheel_digest,
        producer_model_digest=FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
        producer_runtime_wrapper_digest=FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
        producer_runtime_bundle_digest=FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST,
        producer_sandbox_digest=FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
        producer_fixed_argv_digest=fixed_argv_digest,
        producer_profile_digest=_profile_digest(config),
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=maximum_response_bytes,
    )


def parse_formal_producer_binding(raw: bytes) -> FormalProducerBinding:
    """Re-verify a canonical binding against the installed fixed profile."""

    if type(raw) is not bytes or not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise LocalModelProcessError("formal producer binding framing is invalid")
    try:
        binding = FormalProducerBinding.model_validate_json(raw)
    except ValidationError:
        raise LocalModelProcessError("formal producer binding schema is invalid") from None
    if raw != canonical_json_bytes(binding.model_dump(mode="json", by_alias=True)):
        raise LocalModelProcessError("formal producer binding JSON is not canonical")
    return binding


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--core-wheel-digest", required=True)
    parser.add_argument("--timeout-seconds", required=True, type=int)
    parser.add_argument("--maximum-request-bytes", required=True, type=int)
    parser.add_argument("--maximum-response-bytes", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(argv)
        binding = materialize_formal_producer_binding(
            core_wheel_digest=arguments.core_wheel_digest,
            timeout_seconds=arguments.timeout_seconds,
            maximum_request_bytes=arguments.maximum_request_bytes,
            maximum_response_bytes=arguments.maximum_response_bytes,
        )
        sys.stdout.buffer.write(
            canonical_json_bytes(binding.model_dump(mode="json", by_alias=True))
        )
        sys.stdout.buffer.flush()
        return 0
    except (OSError, TypeError, ValueError, LocalModelProcessError):
        return 2


__all__ = [
    "FORMAL_MAXIMUM_REQUEST_BYTES",
    "FORMAL_PRODUCER_BINDING_SCHEMA",
    "FormalProducerBinding",
    "main",
    "materialize_formal_producer_binding",
    "parse_formal_producer_binding",
]


if __name__ == "__main__":
    raise SystemExit(main())
