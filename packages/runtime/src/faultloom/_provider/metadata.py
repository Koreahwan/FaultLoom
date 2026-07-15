from __future__ import annotations

from typing import Iterable, Self

from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest, ShortStr
from pydantic import model_validator

from .common import (
    MetadataSourceKind,
    ProviderMetadataError,
    ProviderToolKind,
    SCHEMA_VERSION,
    Signed64NonNegative,
    Signed64Positive,
    _RuntimeModel,
    provider_sha256_digest as sha256_digest,
)

class MetadataProvenance(_RuntimeModel):
    source_kind: MetadataSourceKind
    source_id: Identifier
    evidence_digest: Sha256Digest
    observed_at: AwareDatetime
    exact: bool

    @model_validator(mode="after")
    def _conservative_is_not_exact(self) -> Self:
        if self.source_kind is MetadataSourceKind.CONSERVATIVE_LAB and self.exact:
            raise ValueError("conservative lab provenance cannot claim exact metadata")
        return self


class ProviderToolSpec(_RuntimeModel):
    tool_id: Identifier
    kind: ProviderToolKind
    input_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest


def provider_tool_schema_digest(tools: Iterable[ProviderToolSpec]) -> str:
    """Digest a deterministic, duplicate-free provider tool contract."""

    validated = tuple(
        ProviderToolSpec.model_validate(tool.model_dump(mode="python")) for tool in tools
    )
    tool_ids = tuple(tool.tool_id for tool in validated)
    if len(tool_ids) != len(set(tool_ids)):
        raise ValueError("provider tool IDs must be unique")
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "tools": tuple(
                tool.model_dump(mode="python")
                for tool in sorted(validated, key=lambda candidate: candidate.tool_id)
            ),
        }
    )


class ProviderModelProfile(_RuntimeModel):
    profile_id: Identifier
    provider_id: Identifier
    endpoint_id: Identifier
    requested_alias: ShortStr | None = None
    exact_snapshot: ShortStr
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive
    prompt_overhead_tokens: Signed64NonNegative
    maximum_input_tokens: Signed64Positive
    maximum_output_tokens: Signed64Positive
    maximum_request_bytes: Signed64Positive
    maximum_response_bytes: Signed64Positive
    input_cost_per_million_microunits: Signed64NonNegative
    output_cost_per_million_microunits: Signed64NonNegative
    compatibility_group: Identifier
    capability_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    metadata_exact: bool
    lab_only_conservative: bool = False
    metadata_provenance: MetadataProvenance

    @model_validator(mode="after")
    def _valid_profile(self) -> Self:
        if self.requested_alias == self.exact_snapshot:
            raise ValueError("requested alias cannot stand in for an exact model snapshot")
        if (
            self.maximum_input_tokens
            + self.maximum_output_tokens
            + self.prompt_overhead_tokens
            > self.context_window
        ):
            raise ValueError("provider token ceilings exceed the effective context window")
        exact_fields = (
            self.runtime_version,
            self.tokenizer_id,
            self.tokenizer_version,
        )
        if self.metadata_exact:
            if self.lab_only_conservative or not self.metadata_provenance.exact:
                raise ValueError("exact metadata cannot use a conservative lab provenance")
            if any(value is None for value in exact_fields):
                raise ValueError("exact provider metadata requires runtime and tokenizer facts")
        else:
            if not self.lab_only_conservative:
                raise ValueError("ambiguous metadata requires an explicit lab-only profile")
            if self.metadata_provenance.source_kind is not MetadataSourceKind.CONSERVATIVE_LAB:
                raise ValueError("ambiguous metadata requires conservative-lab provenance")
            if self.metadata_provenance.exact:
                raise ValueError("conservative lab metadata cannot claim exact provenance")
        return self

    def require_live_safe(self) -> None:
        if not self.metadata_exact or self.lab_only_conservative:
            raise ProviderMetadataError("live calls require exact pinned provider metadata")


class ProviderObservedMetadata(_RuntimeModel):
    provider_id: Identifier
    actual_snapshot: ShortStr | None = None
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive | None = None
    snapshot_exact: bool = False
    runtime_exact: bool = False
    tokenizer_exact: bool = False
    context_window_exact: bool = False
    provenance: MetadataProvenance
