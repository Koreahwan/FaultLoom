from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from faultloom.provider import (
    FailureCode,
    FailoverProvenance,
    GenerationConfig,
    MemoryProviderReceiptJournal,
    MetadataProvenance,
    MetadataSourceKind,
    ProviderAdapter,
    ProviderBudgetError,
    ProviderCallBudget,
    ProviderCallIntent,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderMetadataError,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderPlane,
    ProviderPlaneError,
    ProviderPolicyError,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    ProviderRetryError,
    ProviderToolKind,
    ProviderToolSpec,
    ProviderUsage,
    ProxyOutcome,
    RetryDisposition,
    provider_tool_schema_digest,
)
from faultloom_protocol import SecretRef, canonical_json, sha256_digest
from pydantic import ValidationError

NOW = datetime(2026, 7, 12, 3, 0, tzinfo=timezone.utc)


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
            purpose="provider credential",
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
    selected_runtime = model.runtime_version if runtime_version == "__default__" else runtime_version
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


def completed_result(
    request: ProviderProxyRequest,
    model: ProviderModelProfile,
    intent: ProviderCallIntent,
    *,
    metadata: ProviderObservedMetadata | None = None,
    input_tokens: int = 100,
    output_tokens: int = 20,
    accepted_prompt_digest: str | None = None,
    accepted_tool_schema_digest: str | None = None,
    accepted_output_schema_digest: str | None = None,
    accepted_config_digest: str | None = None,
    plane: ProviderPlane = ProviderPlane.MODEL_PROVIDER,
    request_id: str | None = None,
    bytes_sent: int = 512,
    bytes_received: int = 256,
) -> ProviderProxyResult:
    return ProviderProxyResult(
        plane=plane,
        request_id=request_id or request.request_id,
        proxy_receipt_digest=digest(f"proxy-receipt-{request.request_id}"),
        outcome=ProxyOutcome.COMPLETED,
        response_digest=digest(f"response-{request.request_id}"),
        response_status=200,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        observed_metadata=metadata or observed(model),
        usage=ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        accepted_prompt_digest=accepted_prompt_digest or intent.prompt_digest,
        accepted_tool_schema_digest=(
            accepted_tool_schema_digest or provider_tool_schema_digest(intent.tools)
        ),
        accepted_output_schema_digest=(
            accepted_output_schema_digest or intent.output_schema_digest
        ),
        accepted_config_digest=accepted_config_digest or sha256_digest(
            intent.generation_config
        ),
    )


def pre_send_result(request: ProviderProxyRequest) -> ProviderProxyResult:
    return ProviderProxyResult(
        plane=ProviderPlane.MODEL_PROVIDER,
        request_id=request.request_id,
        proxy_receipt_digest=digest(f"proxy-pre-send-{request.request_id}"),
        outcome=ProxyOutcome.PRE_SEND_FAILED,
        bytes_sent=0,
        bytes_received=0,
    )


class FakeProxy:
    plane = ProviderPlane.MODEL_PROVIDER
    proxy_id = "loopback-provider-proxy"
    contract_digest = digest("provider-proxy-contract")

    def __init__(self, handler: Callable[[ProviderProxyRequest], ProviderProxyResult]):
        self.handler = handler
        self.requests: list[ProviderProxyRequest] = []

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult:
        self.requests.append(request)
        return self.handler(request)


class StepClock:
    def __init__(self, start: datetime = NOW, step: timedelta = timedelta(milliseconds=2)):
        self.value = start - step
        self.step = step

    def __call__(self) -> datetime:
        self.value += self.step
        return self.value


class StepMonotonic:
    def __init__(self, step_ns: int = 5_000_000):
        self.value = -step_ns
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.value += self.step_ns
        return self.value


def adapter(
    models: tuple[ProviderModelProfile, ...],
    proxy: FakeProxy,
    journal: MemoryProviderReceiptJournal | None = None,
    *,
    live: bool = True,
) -> ProviderAdapter:
    return ProviderAdapter(
        profiles=models,
        proxy=proxy,
        journal=journal or MemoryProviderReceiptJournal(),
        live=live,
        clock=StepClock(),
        monotonic_clock=StepMonotonic(),
    )


def test_completed_call_records_exact_identity_digests_and_accounting() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    journal = MemoryProviderReceiptJournal()

    receipt = adapter((model,), proxy, journal).call(intent)

    assert receipt.outcome is ProviderCallOutcome.COMPLETED
    assert receipt.provider_id == model.provider_id
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
    assert journal.by_digest(receipt.receipt_digest) == receipt
    assert ProviderCallReceipt.model_validate(receipt.model_dump(mode="python")) == receipt

    sent = proxy.requests[0]
    assert sent.plane is ProviderPlane.MODEL_PROVIDER
    assert sent.model_snapshot == model.exact_snapshot
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
def test_live_response_metadata_missing_or_lies_is_rejected(metadata: str, failure) -> None:
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


def test_ambiguous_profile_fails_closed_live_before_proxy_dispatch() -> None:
    model = profile(
        profile_id="lab",
        snapshot="lab-snapshot",
        alias="lab-alias",
        exact=False,
        lab_only=True,
        context_window=2048,
        maximum_input_tokens=1024,
        maximum_output_tokens=256,
    )
    intent = call_intent(profile_id="lab")
    proxy = FakeProxy(lambda request: pre_send_result(request))

    with pytest.raises(ProviderMetadataError, match="live"):
        adapter((model,), proxy, live=True).call(intent)
    assert proxy.requests == []


def test_explicit_conservative_lab_profile_accepts_missing_metadata() -> None:
    model = profile(
        profile_id="lab",
        snapshot="lab-snapshot",
        alias="lab-alias",
        exact=False,
        lab_only=True,
        context_window=2048,
        maximum_input_tokens=1024,
        maximum_output_tokens=256,
    )
    intent = call_intent(profile_id="lab")
    lab_metadata = observed(model, exact=False, missing=True)
    proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, metadata=lab_metadata
        )
    )

    receipt = adapter((model,), proxy, live=False).call(intent)

    assert receipt.outcome is ProviderCallOutcome.COMPLETED
    assert receipt.actual_snapshot is None
    assert receipt.metadata_exact is False
    assert receipt.profile_digest == sha256_digest(model)


def test_tool_schema_drift_is_rejected_before_dispatch() -> None:
    configured_tool = tool("configured")
    changed_tool = tool("changed")
    model = profile(tools=(configured_tool,))
    intent = call_intent(tools=(changed_tool,))
    proxy = FakeProxy(lambda request: pre_send_result(request))

    with pytest.raises(ProviderPolicyError, match="tool schema drift"):
        adapter((model,), proxy).call(intent)
    assert proxy.requests == []


def test_provider_echo_drift_is_rejected_after_send() -> None:
    configured_tool = tool()
    model = profile(tools=(configured_tool,))
    intent = call_intent(tools=(configured_tool,))
    proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            intent,
            accepted_tool_schema_digest=digest("drifted-tools"),
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is FailureCode.TOOL_SCHEMA_DRIFT


@pytest.mark.parametrize(
    ("field", "failure"),
    [
        ("prompt", FailureCode.PROMPT_DIGEST_MISMATCH),
        ("output", FailureCode.OUTPUT_SCHEMA_DRIFT),
        ("config", FailureCode.CONFIG_DRIFT),
    ],
)
def test_prompt_output_schema_and_config_echo_drift_is_rejected(field: str, failure) -> None:
    model = profile()
    intent = call_intent()
    overrides = {
        "accepted_prompt_digest": digest("wrong") if field == "prompt" else None,
        "accepted_output_schema_digest": digest("wrong") if field == "output" else None,
        "accepted_config_digest": digest("wrong") if field == "config" else None,
    }
    proxy = FakeProxy(
        lambda request: completed_result(request, model, intent, **overrides)
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is failure


@pytest.mark.parametrize(
    "intent",
    [
        call_intent(input_tokens=1001),
        call_intent(prompt_bytes=20_000),
        call_intent(remaining_tokens=149),
        call_intent(remaining_cost=199),
        call_intent(max_output_tokens=201),
    ],
)
def test_budget_overflow_fails_before_dispatch(intent: ProviderCallIntent) -> None:
    model = profile()
    proxy = FakeProxy(lambda request: pre_send_result(request))

    with pytest.raises(ProviderBudgetError):
        adapter((model,), proxy).call(intent)
    assert proxy.requests == []


def test_reported_usage_and_byte_overflow_are_rejected_after_send() -> None:
    model = profile()
    intent = call_intent()
    token_proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, output_tokens=51
        )
    )
    token_receipt = adapter((model,), token_proxy).call(intent)
    assert token_receipt.failure_code is FailureCode.TOKEN_BUDGET_EXCEEDED

    second = call_intent(attempt_id="separate-attempt")
    byte_proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            second,
            bytes_received=model.maximum_response_bytes + 1,
        )
    )
    byte_receipt = adapter((model,), byte_proxy).call(second)
    assert byte_receipt.failure_code is FailureCode.BYTE_BUDGET_EXCEEDED


def test_raw_secret_field_is_not_admitted_and_proxy_only_receives_secret_ref() -> None:
    payload = call_intent().model_dump(mode="python")
    payload["api_key"] = "super-secret-provider-key"
    with pytest.raises(ValidationError, match="api_key"):
        ProviderCallIntent.model_validate(payload)

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    receipt = adapter((model,), proxy).call(intent)
    serialized_request = canonical_json(proxy.requests[0])
    serialized_receipt = canonical_json(receipt)
    assert "super-secret-provider-key" not in serialized_request
    assert "super-secret-provider-key" not in serialized_receipt
    assert "secret://engagement/provider-key" in serialized_request
    assert "secret://engagement/provider-key" not in serialized_receipt


def test_pre_send_failure_allows_only_explicit_identical_retry() -> None:
    model = profile()
    first_intent = call_intent()
    responses: list[Callable[[ProviderProxyRequest], ProviderProxyResult]] = [
        pre_send_result,
        lambda request: completed_result(request, model, retry_intent),
    ]
    proxy = FakeProxy(lambda request: responses.pop(0)(request))
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((model,), proxy, journal)

    first = runtime.call(first_intent)
    assert first.outcome is ProviderCallOutcome.PRE_SEND_FAILED
    assert first.retry_disposition is RetryDisposition.EXPLICIT_RETRY_ALLOWED
    retry_intent = call_intent(
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
    )
    second = runtime.call(retry_intent)

    assert second.outcome is ProviderCallOutcome.COMPLETED
    assert second.previous_receipt_digest == first.receipt_digest
    assert len(proxy.requests) == 2


def test_unknown_outcome_blocks_automatic_retry_until_reconciliation() -> None:
    model = profile()
    first_intent = call_intent()

    def raises_after_possible_send(request: ProviderProxyRequest) -> ProviderProxyResult:
        raise OSError("response lost")

    proxy = FakeProxy(raises_after_possible_send)
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((model,), proxy, journal)
    first = runtime.call(first_intent)

    assert first.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert first.reconciliation_required is True
    assert first.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED
    retry = call_intent(attempt=2, previous_receipt_digest=first.receipt_digest)
    with pytest.raises(ProviderRetryError):
        runtime.call(retry)
    assert len(proxy.requests) == 1


def test_failover_requires_checkpointed_provenance_and_compatible_exact_profile() -> None:
    primary = profile()
    fallback = profile(
        profile_id="fallback",
        provider_id="loopback-provider-2",
        snapshot="frontier-2026-07-02",
        alias="frontier-backup",
    )
    first_intent = call_intent()
    proxy = FakeProxy(lambda request: pre_send_result(request))
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((primary, fallback), proxy, journal)
    first = runtime.call(first_intent)

    no_provenance = call_intent(
        profile_id="fallback",
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
    )
    with pytest.raises(ProviderRetryError, match="failover"):
        runtime.call(no_provenance)

    failover = FailoverProvenance(
        previous_receipt_digest=first.receipt_digest,
        from_profile_id="primary",
        to_profile_id="fallback",
        checkpoint_id="checkpoint-before-failover",
        checkpoint_digest=digest("checkpoint-before-failover"),
        reason_code="provider-unavailable-before-send",
        approved_at=NOW,
    )
    second_intent = call_intent(
        profile_id="fallback",
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
        failover=failover,
    )
    proxy.handler = lambda request: completed_result(
        request, fallback, second_intent
    )
    second = runtime.call(second_intent)

    assert second.outcome is ProviderCallOutcome.COMPLETED
    assert second.profile_id == "fallback"
    assert second.failover_provenance_digest == sha256_digest(failover)
    assert second.failover_checkpoint_id == "checkpoint-before-failover"
    assert second.failover_checkpoint_digest == digest("checkpoint-before-failover")
    assert second.requested_snapshot == "frontier-2026-07-02"


def test_smaller_or_capability_incompatible_failover_is_rejected() -> None:
    primary = profile()
    smaller = profile(
        profile_id="smaller",
        snapshot="frontier-small-2026-07-02",
        alias="frontier-small",
        context_window=4096,
        maximum_input_tokens=3000,
        maximum_output_tokens=512,
    )
    proxy = FakeProxy(lambda request: pre_send_result(request))
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((primary, smaller), proxy, journal)
    first = runtime.call(call_intent())
    failover = FailoverProvenance(
        previous_receipt_digest=first.receipt_digest,
        from_profile_id="primary",
        to_profile_id="smaller",
        checkpoint_id="checkpoint-before-failover",
        checkpoint_digest=digest("checkpoint-before-failover"),
        reason_code="provider-unavailable-before-send",
        approved_at=NOW,
    )
    second = call_intent(
        profile_id="smaller",
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
        failover=failover,
    )

    with pytest.raises(ProviderRetryError, match="compatible"):
        runtime.call(second)
    assert len(proxy.requests) == 1


def test_live_arbitrary_provider_tools_are_disabled() -> None:
    web_tool = tool("provider-web", ProviderToolKind.WEB)
    model = profile(tools=(web_tool,))
    intent = call_intent(tools=(web_tool,))
    proxy = FakeProxy(lambda request: pre_send_result(request))

    with pytest.raises(ProviderPolicyError, match="disabled"):
        adapter((model,), proxy, live=True).call(intent)
    assert proxy.requests == []


def test_provider_target_plane_confusion_fails_closed() -> None:
    model = profile()
    intent = call_intent()
    wrong_proxy = FakeProxy(lambda request: pre_send_result(request))
    wrong_proxy.plane = ProviderPlane.TARGET
    with pytest.raises(ProviderPlaneError):
        adapter((model,), wrong_proxy)

    result_proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, plane=ProviderPlane.TARGET
        )
    )
    receipt = adapter((model,), result_proxy).call(intent)
    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.failure_code is FailureCode.PROXY_PLANE_MISMATCH
    assert receipt.reconciliation_required is True


def test_proxy_contract_drift_fails_before_dispatch() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy)
    proxy.contract_digest = digest("substituted-provider-proxy-contract")

    with pytest.raises(ProviderPlaneError, match="contract"):
        runtime.call(intent)
    assert proxy.requests == []


def test_attempt_replay_is_rejected_without_second_dispatch() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((model,), proxy, journal)
    runtime.call(intent)

    with pytest.raises(ProviderRetryError):
        runtime.call(intent)
    assert len(proxy.requests) == 1


def test_provider_module_has_no_network_transport_imports() -> None:
    source = (
        Path(__file__).parents[2]
        / "packages"
        / "runtime"
        / "src"
        / "faultloom"
        / "provider.py"
    ).read_text(encoding="utf-8")
    forbidden = ("import socket", "import httpx", "import requests", "urllib.request")
    assert all(item not in source for item in forbidden)
