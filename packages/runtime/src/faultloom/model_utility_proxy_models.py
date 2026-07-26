"""Strict contracts for the local model utility process proxy."""

from __future__ import annotations

import hashlib
import hmac
from enum import StrEnum
from typing import Annotated, ClassVar, Self

from faultloom_protocol.base import Identifier, NonEmptyStr, Sha256Digest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_sdk import ModelUtilityArm, UtilityDecision

MODEL_SNAPSHOT_TOKEN = "{MODEL_SNAPSHOT}"
FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST = (
    "sha256:b7ad567477c83756aab9a542b2be04f77dbae25115d85f22070d74d8cc4779dc"
)
FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST = (
    "sha256:d92c6a81b2ff50096bcda80885427d1f59a25b5f483f7055523504925d16ab23"
)
FAULTLOOM_UTILITY_V1_MODEL_DIGEST = (
    "sha256:9372c470eeadd5ecd9c3c74c2b3cb633f8e2f2fad799250a0f70d652b6b825e4"
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
        return FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST


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
    seed: Annotated[int, Field(strict=True, ge=0)]
    payload: NonEmptyStr


class LocalModelProcessResponse(_LocalProcessModel):
    request_id: Identifier
    model_snapshot_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    decision: UtilityDecision
    output: str
    output_digest: Sha256Digest
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
