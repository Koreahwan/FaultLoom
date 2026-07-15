from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FailureCode,
    FakeProxy,
    MemoryProviderReceiptJournal,
    MetadataProvenance,
    MetadataSourceKind,
    NOW,
    PROXY_SIGNER,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderPlane,
    ProviderReceiptError,
    RetryDisposition,
    ValidationError,
    adapter,
    call_intent,
    canonical_json,
    completed_result,
    digest,
    observed,
    profile,
    provider_tool_schema_digest,
    pytest,
    sha256_digest,
)

def test_completed_call_records_exact_identity_digests_and_accounting() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    journal = MemoryProviderReceiptJournal()

    receipt = adapter((model,), proxy, journal).call(intent)

    assert receipt.outcome is ProviderCallOutcome.COMPLETED
    assert receipt.provider_id == model.provider_id
    assert receipt.proxy_id == proxy.proxy_id
    assert receipt.proxy_attestation_key_id == PROXY_SIGNER.key_id
    assert receipt.requested_alias == "frontier"
    assert receipt.requested_snapshot == "frontier-2026-07-01"
    assert receipt.actual_snapshot == "frontier-2026-07-01"
    assert receipt.runtime_version == "loopback-runtime-1"
    assert receipt.tokenizer_id == "loopback-tokenizer"
    assert receipt.context_window == 8192
    assert receipt.metadata_exact is True
    assert receipt.prompt_digest == intent.prompt_digest
    assert receipt.compiled_context_digest == intent.compiled_context_digest
    assert receipt.tool_schema_digest == provider_tool_schema_digest(())
    assert receipt.output_schema_digest == intent.output_schema_digest
    assert receipt.config_digest == sha256_digest(intent.generation_config)
    assert receipt.reported_input_tokens == 100
    assert receipt.reported_output_tokens == 20
    assert receipt.cost_microunits == 140
    assert receipt.latency_milliseconds == 5
    assert receipt.action_ids == intent.action_ids
    assert receipt.policy_ref == "provider-policy-v1"
    assert receipt.data_consent_ref == "consent-receipt-v1"
    assert receipt.retry_disposition is RetryDisposition.BLOCKED_FINAL
    sent = proxy.requests[0]
    assert receipt.proxy_result is not None
    assert receipt.proxy_result.proxy_request_digest == sha256_digest(sent)
    assert journal.by_digest(receipt.receipt_digest) == receipt
    assert ProviderCallReceipt.model_validate(receipt.model_dump(mode="python")) == receipt

    assert sent.plane is ProviderPlane.MODEL_PROVIDER
    assert sent.proxy_id == proxy.proxy_id
    assert sent.proxy_contract_digest == proxy.contract_digest
    assert sent.proxy_attestation_key_id == PROXY_SIGNER.key_id
    assert sent.model_snapshot == model.exact_snapshot
    assert sent.prompt_digest == intent.prompt_digest
    assert sent.compiled_context_digest == intent.compiled_context_digest
    assert sent.tool_schema_digest == provider_tool_schema_digest(intent.tools)
    assert sent.output_schema_digest == intent.output_schema_digest
    assert sent.config_digest == sha256_digest(intent.generation_config)
    assert sent.policy_ref == intent.policy_ref
    assert sent.data_policy_id == intent.data_policy_id
    assert sent.data_consent_ref == intent.data_consent_ref
    assert sent.payload_digest == intent.prompt_digest
    assert sent.credential_ref.uri == "secret://engagement/provider-key"
    assert "compiled-prompt" not in canonical_json(sent)


def test_receipt_is_frozen_and_tamper_evident() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    receipt = adapter((model,), proxy).call(intent)

    with pytest.raises(ValidationError):
        receipt.cost_microunits = 1  # type: ignore[misc]
    tampered = receipt.model_copy(update={"cost_microunits": receipt.cost_microunits + 1})
    with pytest.raises(ValidationError, match="digest"):
        ProviderCallReceipt.model_validate(tampered.model_dump(mode="python"))
    with pytest.raises(ProviderReceiptError):
        MemoryProviderReceiptJournal().append(tampered)


@pytest.mark.parametrize("substitution", ["frontier", "frontier-smaller", "other-snapshot"])
def test_alias_drift_and_snapshot_substitution_are_rejected_without_fallback(
    substitution: str,
) -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, metadata=observed(model, snapshot=substitution)
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is FailureCode.METADATA_MISMATCH
    assert receipt.retry_disposition is RetryDisposition.BLOCKED_FINAL
    assert len(proxy.requests) == 1


def test_alias_cannot_be_configured_as_the_exact_snapshot() -> None:
    with pytest.raises(ValidationError, match="alias"):
        profile(snapshot="frontier", alias="frontier")


def test_conservative_provenance_cannot_claim_exact_metadata() -> None:
    with pytest.raises(ValidationError, match="conservative"):
        MetadataProvenance(
            source_kind=MetadataSourceKind.CONSERVATIVE_LAB,
            source_id="lab-profile",
            evidence_digest=digest("lab-profile"),
            observed_at=NOW,
            exact=True,
        )


@pytest.mark.parametrize(
    ("metadata", "failure"),
    [
        ("missing", FailureCode.METADATA_MISSING),
        ("runtime-lie", FailureCode.METADATA_MISMATCH),
    ],
)
def test_exact_response_metadata_missing_or_lies_is_rejected(metadata: str, failure) -> None:
    model = profile()
    intent = call_intent()
    reported = (
        observed(model, missing=True)
        if metadata == "missing"
        else observed(model, runtime_version="untrusted-runtime")
    )
    proxy = FakeProxy(
        lambda request: completed_result(request, model, intent, metadata=reported)
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is failure
    assert len(proxy.requests) == 1
