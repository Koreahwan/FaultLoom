from __future__ import annotations

from typing import Literal, Self

from faultloom_protocol import SecretRef
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest
from pydantic import Field, model_validator

from .common import (
    Signed64NonNegative,
    Signed64Positive,
    _RuntimeModel,
    provider_canonical_json_bytes as canonical_json_bytes,
)
from .metadata import ProviderToolSpec

class GenerationConfig(_RuntimeModel):
    max_output_tokens: Signed64Positive
    temperature_milli: Signed64NonNegative = Field(le=2000)
    top_p_milli: Signed64Positive = Field(le=1000)
    seed: Signed64NonNegative | None = None
    response_format: Literal["text", "json"] = "text"


class ProviderCallBudget(_RuntimeModel):
    maximum_input_tokens: Signed64Positive
    maximum_output_tokens: Signed64Positive
    remaining_model_tokens: Signed64NonNegative
    remaining_cost_microunits: Signed64NonNegative


class FailoverProvenance(_RuntimeModel):
    previous_receipt_digest: Sha256Digest
    from_profile_id: Identifier
    from_profile_digest: Sha256Digest
    to_profile_id: Identifier
    to_profile_digest: Sha256Digest
    checkpoint_id: Identifier
    checkpoint_digest: Sha256Digest
    reason_code: Identifier
    approved_at: AwareDatetime
    approver_key_id: Identifier
    approval_signature: NonEmptyStr

    @model_validator(mode="after")
    def _changes_profile(self) -> Self:
        if self.from_profile_id == self.to_profile_id:
            raise ValueError("failover must change the configured provider profile")
        return self


def failover_provenance_attestation_bytes(
    provenance: FailoverProvenance,
) -> bytes:
    """Return the exact failover approval document signed by T23."""

    if type(provenance) is not FailoverProvenance:
        raise TypeError("failover approval requires an exact provenance model")
    return canonical_json_bytes(
        {
            "purpose": "faultloom.provider_failover_approval.v1",
            "provenance": provenance.model_dump(
                mode="python",
                exclude={"approval_signature"},
            ),
        }
    )


class ProviderCallIntent(_RuntimeModel):
    call_id: Identifier
    attempt_id: Identifier
    attempt: Signed64Positive
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: Signed64Positive
    profile_id: Identifier
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    prompt_bytes: Signed64Positive
    input_tokens: Signed64NonNegative
    tools: tuple[ProviderToolSpec, ...] = ()
    output_schema_digest: Sha256Digest
    generation_config: GenerationConfig
    budget: ProviderCallBudget
    action_ids: tuple[Identifier, ...]
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    credential_ref: SecretRef
    requested_at: AwareDatetime
    previous_receipt_digest: Sha256Digest | None = None
    failover: FailoverProvenance | None = None

    @model_validator(mode="after")
    def _valid_intent(self) -> Self:
        if not self.action_ids:
            raise ValueError("provider call requires at least one action ID")
        if len(self.action_ids) != len(set(self.action_ids)):
            raise ValueError("provider action IDs must be unique")
        tool_ids = tuple(tool.tool_id for tool in self.tools)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("provider tool IDs must be unique")
        if self.attempt == 1:
            if self.previous_receipt_digest is not None or self.failover is not None:
                raise ValueError("first provider attempt cannot cite a prior receipt")
        elif self.previous_receipt_digest is None:
            raise ValueError("later provider attempts require a prior receipt digest")
        if self.failover is not None and (
            self.previous_receipt_digest != self.failover.previous_receipt_digest
        ):
            raise ValueError("failover and retry receipt digests must match")
        return self
