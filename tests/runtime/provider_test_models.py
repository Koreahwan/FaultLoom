from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from faultloom.provider import (
    FailoverProvenance,
    GenerationConfig,
    MetadataProvenance,
    MetadataSourceKind,
    ProviderCallBudget,
    ProviderCallIntent,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderToolKind,
    ProviderToolSpec,
    provider_tool_schema_digest,
)
from faultloom_protocol import AuthoritySigner, SecretRef

NOW = datetime(2026, 7, 12, 3, 0, tzinfo=timezone.utc)
PROXY_SIGNER = AuthoritySigner.from_private_bytes(bytes(range(32)))
FAILOVER_SIGNER = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def provenance(*, exact: bool = True, lab: bool = False) -> MetadataProvenance:
    return MetadataProvenance(
        source_kind=(
            MetadataSourceKind.CONSERVATIVE_LAB
            if lab
            else MetadataSourceKind.PINNED_REGISTRY
        ),
        source_id="metadata-source",
        evidence_digest=digest("metadata-evidence"),
        observed_at=NOW,
        exact=exact,
    )


def tool(tool_id: str = "lookup", kind: ProviderToolKind = ProviderToolKind.FUNCTION):
    return ProviderToolSpec(
        tool_id=tool_id,
        kind=kind,
        input_schema_digest=digest(f"{tool_id}-input"),
        output_schema_digest=digest(f"{tool_id}-output"),
    )


def profile(
    profile_id: str = "primary",
    *,
    provider_id: str = "loopback-provider",
    snapshot: str = "frontier-2026-07-01",
    alias: str | None = "frontier",
    tools: tuple[ProviderToolSpec, ...] = (),
    exact: bool = True,
    lab_only: bool = False,
    compatibility_group: str = "frontier-compatible",
    capability_digest: str | None = None,
    context_window: int = 8192,
    maximum_input_tokens: int = 6000,
    maximum_output_tokens: int = 1024,
) -> ProviderModelProfile:
    return ProviderModelProfile(
        profile_id=profile_id,
        provider_id=provider_id,
        endpoint_id=f"endpoint-{profile_id}",
        requested_alias=alias,
        exact_snapshot=snapshot,
        runtime_version="loopback-runtime-1" if exact else None,
        tokenizer_id="loopback-tokenizer" if exact else None,
        tokenizer_version="2026.07" if exact else None,
        context_window=context_window,
        prompt_overhead_tokens=64,
        maximum_input_tokens=maximum_input_tokens,
        maximum_output_tokens=maximum_output_tokens,
        maximum_request_bytes=16_384,
        maximum_response_bytes=32_768,
        input_cost_per_million_microunits=1_000_000,
        output_cost_per_million_microunits=2_000_000,
        compatibility_group=compatibility_group,
        capability_digest=capability_digest or digest("frontier-capabilities"),
        tool_schema_digest=provider_tool_schema_digest(tools),
        policy_ref="provider-policy-v1",
        data_policy_id="data-policy-v1",
        data_consent_ref="consent-receipt-v1",
        metadata_exact=exact,
        lab_only_conservative=lab_only,
        metadata_provenance=provenance(exact=exact, lab=lab_only),
    )


def call_intent(
    profile_id: str = "primary",
    *,
    attempt: int = 1,
    attempt_id: str | None = None,
    tools: tuple[ProviderToolSpec, ...] = (),
    previous_receipt_digest: str | None = None,
    failover: FailoverProvenance | None = None,
    input_tokens: int = 100,
    prompt_bytes: int = 512,
    remaining_tokens: int = 2000,
    remaining_cost: int = 2000,
    max_output_tokens: int = 50,
) -> ProviderCallIntent:
    return ProviderCallIntent(
        call_id="call-1",
        attempt_id=attempt_id or f"call-1-attempt-{attempt}",
        attempt=attempt,
        run_id="run-1",
        authority_digest=digest("authority"),
        scope_epoch=7,
        profile_id=profile_id,
        prompt_digest=digest("compiled-prompt"),
        compiled_context_digest=digest("compiled-context"),
        prompt_bytes=prompt_bytes,
        input_tokens=input_tokens,
        tools=tools,
        output_schema_digest=digest("output-schema"),
        generation_config=GenerationConfig(
            max_output_tokens=max_output_tokens,
            temperature_milli=0,
            top_p_milli=1000,
            seed=42,
            response_format="json",
        ),
        budget=ProviderCallBudget(
            maximum_input_tokens=1000,
            maximum_output_tokens=200,
            remaining_model_tokens=remaining_tokens,
            remaining_cost_microunits=remaining_cost,
        ),
        action_ids=("action-model-1", "action-research-1"),
        policy_ref="provider-policy-v1",
        data_policy_id="data-policy-v1",
        data_consent_ref="consent-receipt-v1",
        credential_ref=SecretRef(
            schema_version="0.1.0",
            uri="secret://engagement/provider-key",
            purpose="provider.credential",
        ),
        requested_at=NOW,
        previous_receipt_digest=previous_receipt_digest,
        failover=failover,
    )


def observed(
    model: ProviderModelProfile,
    *,
    snapshot: str | None = None,
    runtime_version: str | None = "__default__",
    exact: bool = True,
    missing: bool = False,
) -> ProviderObservedMetadata:
    selected_runtime = (
        model.runtime_version
        if runtime_version == "__default__"
        else runtime_version
    )
    return ProviderObservedMetadata(
        provider_id=model.provider_id,
        actual_snapshot=None if missing else (snapshot or model.exact_snapshot),
        runtime_version=None if missing else selected_runtime,
        tokenizer_id=None if missing else model.tokenizer_id,
        tokenizer_version=None if missing else model.tokenizer_version,
        context_window=None if missing else model.context_window,
        snapshot_exact=exact and not missing,
        runtime_exact=exact and not missing,
        tokenizer_exact=exact and not missing,
        context_window_exact=exact and not missing,
        provenance=MetadataProvenance(
            source_kind=(
                MetadataSourceKind.PROVIDER_RESPONSE
                if exact
                else MetadataSourceKind.CONSERVATIVE_LAB
            ),
            source_id="loopback-response-metadata",
            evidence_digest=digest("response-metadata"),
            observed_at=NOW,
            exact=exact,
        ),
    )
