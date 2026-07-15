from __future__ import annotations

from faultloom.provider import (
    FailoverProvenance,
    ProviderCallIntent,
    ProviderCallReceipt,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderPlane,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderUsage,
    ProxyEffectDisposition,
    ProxyOutcome,
    failover_provenance_attestation_bytes,
    provider_proxy_result_attestation_bytes,
)
from faultloom_protocol import sha256_digest

from tests.runtime.provider_test_models import (
    FAILOVER_SIGNER,
    NOW,
    PROXY_SIGNER,
    digest,
    observed,
)

def completed_result(
    request: ProviderProxyRequest,
    model: ProviderModelProfile,
    intent: ProviderCallIntent,
    *,
    metadata: ProviderObservedMetadata | None = None,
    input_tokens: int = 100,
    output_tokens: int = 20,
    accepted_prompt_digest: str | None = None,
    accepted_compiled_context_digest: str | None = None,
    accepted_tool_schema_digest: str | None = None,
    accepted_output_schema_digest: str | None = None,
    accepted_config_digest: str | None = None,
    accepted_policy_ref: str | None = None,
    accepted_data_policy_id: str | None = None,
    accepted_data_consent_ref: str | None = None,
    accepted_proxy_id: str | None = None,
    accepted_proxy_contract_digest: str | None = None,
    plane: ProviderPlane = ProviderPlane.MODEL_PROVIDER,
    request_id: str | None = None,
    bytes_sent: int = 512,
    bytes_received: int = 256,
) -> ProviderProxyResult:
    return signed_proxy_result(
        plane=plane,
        request_id=request_id or request.request_id,
        proxy_request_digest=sha256_digest(request),
        attested_proxy_id=request.proxy_id,
        attested_proxy_contract_digest=request.proxy_contract_digest,
        outcome=ProxyOutcome.COMPLETED,
        effect_disposition=ProxyEffectDisposition.OBSERVED,
        response_digest=digest(f"response-{request.request_id}"),
        response_status=200,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        observed_metadata=metadata or observed(model),
        usage=ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        accepted_prompt_digest=accepted_prompt_digest or request.prompt_digest,
        accepted_compiled_context_digest=(
            accepted_compiled_context_digest or request.compiled_context_digest
        ),
        accepted_tool_schema_digest=(
            accepted_tool_schema_digest or request.tool_schema_digest
        ),
        accepted_output_schema_digest=(
            accepted_output_schema_digest or request.output_schema_digest
        ),
        accepted_config_digest=accepted_config_digest or request.config_digest,
        accepted_policy_ref=accepted_policy_ref or request.policy_ref,
        accepted_data_policy_id=accepted_data_policy_id or request.data_policy_id,
        accepted_data_consent_ref=(
            accepted_data_consent_ref or request.data_consent_ref
        ),
        accepted_proxy_id=accepted_proxy_id or request.proxy_id,
        accepted_proxy_contract_digest=(
            accepted_proxy_contract_digest or request.proxy_contract_digest
        ),
    )


def pre_send_result(request: ProviderProxyRequest) -> ProviderProxyResult:
    return signed_proxy_result(
        plane=ProviderPlane.MODEL_PROVIDER,
        request_id=request.request_id,
        proxy_request_digest=sha256_digest(request),
        attested_proxy_id=request.proxy_id,
        attested_proxy_contract_digest=request.proxy_contract_digest,
        outcome=ProxyOutcome.PRE_SEND_FAILED,
        effect_disposition=ProxyEffectDisposition.NOT_DISPATCHED,
        bytes_sent=0,
        bytes_received=0,
    )


def signed_proxy_result(**payload: object) -> ProviderProxyResult:
    """Create a deterministic loopback attestation without a live provider."""

    draft = ProviderProxyResult.model_construct(
        **payload,
        attestation_key_id=PROXY_SIGNER.key_id,
        proxy_receipt_digest=digest("unsigned-proxy-result"),
        attestation_signature="unsigned",
    )
    document = draft.model_dump(mode="python", warnings=False)
    document["proxy_receipt_digest"] = sha256_digest(
        draft.model_dump(
            mode="python",
            exclude={"proxy_receipt_digest", "attestation_signature"},
            warnings=False,
        )
    )
    unsigned = ProviderProxyResult.model_validate(document)
    document["attestation_signature"] = PROXY_SIGNER.sign(
        provider_proxy_result_attestation_bytes(unsigned)
    )
    return ProviderProxyResult.model_validate(document)


def rehashed_without_resigning(
    result: ProviderProxyResult,
    **updates: object,
) -> ProviderProxyResult:
    document = result.model_dump(mode="python")
    document.update(updates)
    draft = ProviderProxyResult.model_construct(**document)
    document["proxy_receipt_digest"] = sha256_digest(
        draft.model_dump(
            mode="python",
            exclude={"proxy_receipt_digest", "attestation_signature"},
            warnings=False,
        )
    )
    return ProviderProxyResult.model_validate(document)


def signed_failover(
    previous: ProviderCallReceipt,
    source: ProviderModelProfile,
    destination: ProviderModelProfile,
    *,
    checkpoint_id: str = "checkpoint-before-failover",
) -> FailoverProvenance:
    payload = {
        "previous_receipt_digest": previous.receipt_digest,
        "from_profile_id": source.profile_id,
        "from_profile_digest": sha256_digest(source),
        "to_profile_id": destination.profile_id,
        "to_profile_digest": sha256_digest(destination),
        "checkpoint_id": checkpoint_id,
        "checkpoint_digest": digest(checkpoint_id),
        "reason_code": "provider-unavailable-before-send",
        "approved_at": NOW,
        "approver_key_id": FAILOVER_SIGNER.key_id,
        "approval_signature": "unsigned",
    }
    unsigned = FailoverProvenance.model_validate(payload)
    payload["approval_signature"] = FAILOVER_SIGNER.sign(
        failover_provenance_attestation_bytes(unsigned)
    )
    return FailoverProvenance.model_validate(payload)
