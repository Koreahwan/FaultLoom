"""Strict contracts for the local model utility process proxy."""

from __future__ import annotations

import hashlib
import hmac
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from faultloom_protocol.base import Identifier, NonEmptyStr, Sha256Digest
from faultloom_sdk import ModelUtilityArm, UtilityDecision
from pydantic import BaseModel, ConfigDict, Field, model_validator

MODEL_SNAPSHOT_TOKEN = "{MODEL_SNAPSHOT}"
FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST = (
    "sha256:52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
)
FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST = (
    "sha256:dee6503779cfa372e6f2259f888a3514b0b0f03cfad040b670b19a7e20266559"
)
FAULTLOOM_UTILITY_V1_MODEL_DIGEST = (
    "sha256:48ab3034d0dd401fbc721eb1df3217902fee7dab9078992d66431f09b7750201"
)
FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST = (
    "sha256:afe1ae0b706c4a0830b218a9249037b7a6cc723f81deb78825662128b25453e6"
)


class LocalModelProcessError(ValueError):
    """A pinned local model process failed before a trusted result existed."""


class _LocalProcessModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class LocalModelRuntimeProfile(StrEnum):
    FAULTLOOM_UTILITY_V1 = "faultloom_utility_v1"


class LocalModelProcessConfig(_LocalProcessModel):
    """One admitted runtime profile and finite execution budgets."""

    profile: LocalModelRuntimeProfile
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    maximum_request_bytes: Annotated[int, Field(strict=True, ge=1, le=16_777_216)]
    maximum_response_bytes: Annotated[int, Field(strict=True, ge=1, le=16_777_216)]

    @property
    def model_snapshot_digest(self) -> str:
        return FAULTLOOM_UTILITY_V1_MODEL_DIGEST

    @property
    def runtime_executable_digest(self) -> str:
        """Digest of the standalone wrapper bound by existing requests."""

        return FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST

    @property
    def runtime_bundle_digest(self) -> str:
        """Digest of the separately pinned llama.cpp dynamic bundle."""

        return FAULTLOOM_UTILITY_V1_BUNDLE_DIGEST


class LocalModelProcessRequest(_LocalProcessModel):
    request_id: Identifier
    case_id: Identifier
    case_digest: Sha256Digest
    arm: ModelUtilityArm
    model_snapshot_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    prompt_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    budget_digest: Sha256Digest
    generation_config_digest: Sha256Digest
    seed: Literal[42]
    payload: NonEmptyStr


class LocalModelProcessResponse(_LocalProcessModel):
    request_id: Identifier
    model_snapshot_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    decision: UtilityDecision
    output: Annotated[str, Field(max_length=4096)]
    output_digest: Sha256Digest
    raw_llama_stdout_digest: Sha256Digest
    input_tokens: Annotated[int, Field(strict=True, ge=0)]
    output_tokens: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def _output_digest_is_exact(self) -> Self:
        observed = f"sha256:{hashlib.sha256(self.output.encode()).hexdigest()}"
        if not hmac.compare_digest(observed, self.output_digest):
            raise LocalModelProcessError("local model output digest mismatch")
        return self


__all__ = [
    "MODEL_SNAPSHOT_TOKEN",
    "LocalModelProcessConfig",
    "LocalModelProcessError",
    "LocalModelProcessRequest",
    "LocalModelProcessResponse",
    "LocalModelRuntimeProfile",
]
