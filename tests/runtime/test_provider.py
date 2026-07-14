from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from threading import Event

import pytest
from faultloom.provider import (
    AnchoredProviderReceiptJournal,
    FailureCode,
    FailoverProvenance,
    GenerationConfig,
    MemoryProviderReceiptJournal,
    MetadataProvenance,
    MetadataSourceKind,
    ProviderAdapter,
    ProviderAdapterError,
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
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
    failover_provenance_attestation_bytes,
    provider_proxy_result_attestation_bytes,
    provider_tool_schema_digest,
)
from faultloom.state import AnchorCheckpoint, EngagementKey, StateStore
from faultloom_protocol import AuthoritySigner, SecretRef, canonical_json, sha256_digest
from pydantic import ValidationError

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


class FakeProxy:
    plane = ProviderPlane.MODEL_PROVIDER
    contract_digest = digest("provider-proxy-contract")
    attestation_public_key = PROXY_SIGNER.public_key_record

    def __init__(self, handler: Callable[[ProviderProxyRequest], ProviderProxyResult]):
        self.handler = handler
        self.requests: list[ProviderProxyRequest] = []
        self._proxy_id = "loopback-provider-proxy"
        self._dispatching = False

    @property
    def proxy_id(self) -> str:
        return self._proxy_id

    @proxy_id.setter
    def proxy_id(self, value: str) -> None:
        if self._dispatching:
            raise RuntimeError("the attested proxy binding is immutable during dispatch")
        self._proxy_id = value

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult:
        self.requests.append(request)
        handler = self.handler
        self._dispatching = True
        try:
            result = handler(request)
        finally:
            self._dispatching = False
        # A real T17 proxy signs NOT_DISPATCHED only from its transport boundary,
        # never from an arbitrary provider callback. The loopback port models
        # that distinction with one explicit no-dispatch handler.
        if result.outcome is ProxyOutcome.PRE_SEND_FAILED and handler is not pre_send_result:
            return result.model_copy(update={"attestation_signature": "unsigned"})
        return result


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
    journal: AnchoredProviderReceiptJournal | MemoryProviderReceiptJournal | None = None,
    *,
    live: bool = False,
) -> ProviderAdapter:
    return ProviderAdapter(
        profiles=models,
        proxy=proxy,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        journal=journal or MemoryProviderReceiptJournal(),
        live=live,
        trusted_failover_approval_keys=(FAILOVER_SIGNER.public_key_record,),
        clock=StepClock(),
        monotonic_clock=StepMonotonic(),
    )


def provider_state_store(
    root: Path,
    engagement_id: str = "eng.provider-runtime",
    *,
    minimum_anchor: AnchorCheckpoint | None = None,
) -> StateStore:
    return StateStore(
        root / "state",
        engagement_id,
        EngagementKey(bytes(range(32))),
        anchor_root=root / "anchor",
        minimum_anchor=minimum_anchor,
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


def test_live_provider_fails_closed_without_anchored_t20_journal() -> None:
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
    proxy = FakeProxy(pre_send_result)

    with pytest.raises(ProviderReceiptError, match="T20"):
        adapter((model,), proxy, live=True).call(intent)
    assert proxy.requests == []


def test_live_provider_uses_exact_anchored_t20_journal(tmp_path: Path) -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))

    with provider_state_store(tmp_path) as state:
        journal = AnchoredProviderReceiptJournal(
            state,
            minimum_anchor=state.checkpoint(),
        )
        receipt = adapter((model,), proxy, journal, live=True).call(intent)

        assert receipt.outcome is ProviderCallOutcome.COMPLETED
        assert receipt.live is True
        assert receipt.proxy_request.live is True
        assert journal.by_digest(receipt.receipt_digest) == receipt
        assert journal.by_attempt(intent.call_id, intent.attempt) == receipt
        assert state.checkpoint().seq == 4


def test_anchored_presend_receipt_round_trips_into_live_retry(
    tmp_path: Path,
) -> None:
    model = profile()
    first_intent = call_intent()
    proxy = FakeProxy(pre_send_result)

    with provider_state_store(tmp_path) as state:
        journal = AnchoredProviderReceiptJournal(
            state,
            minimum_anchor=state.checkpoint(),
        )
        runtime = adapter((model,), proxy, journal, live=True)
        first = runtime.call(first_intent)
        retry = call_intent(
            attempt=2,
            previous_receipt_digest=first.receipt_digest,
        )
        proxy.handler = lambda request: completed_result(request, model, retry)

        second = runtime.call(retry)

        assert first.outcome is ProviderCallOutcome.PRE_SEND_FAILED
        assert second.outcome is ProviderCallOutcome.COMPLETED
        assert second.previous_receipt_digest == first.receipt_digest
        assert journal.by_digest(first.receipt_digest) == first
        assert journal.by_attempt(retry.call_id, retry.attempt) == second
        assert state.checkpoint().seq == 8


def test_anchored_journal_recreation_blocks_live_redispatch(
    tmp_path: Path,
) -> None:
    model = profile()
    intent = call_intent()
    first_proxy = FakeProxy(lambda request: completed_result(request, model, intent))

    with provider_state_store(tmp_path) as first_state:
        first_journal = AnchoredProviderReceiptJournal(
            first_state,
            minimum_anchor=first_state.checkpoint(),
        )
        receipt = adapter(
            (model,),
            first_proxy,
            first_journal,
            live=True,
        ).call(intent)
        retained_anchor = first_state.checkpoint()

    second_proxy = FakeProxy(pre_send_result)
    with provider_state_store(
        tmp_path,
        minimum_anchor=retained_anchor,
    ) as second_state:
        second_journal = AnchoredProviderReceiptJournal(
            second_state,
            minimum_anchor=retained_anchor,
        )
        with pytest.raises(ProviderRetryError, match="already has a receipt"):
            adapter(
                (model,),
                second_proxy,
                second_journal,
                live=True,
            ).call(intent)
        assert second_journal.by_digest(receipt.receipt_digest) == receipt

    assert len(first_proxy.requests) == 1
    assert second_proxy.requests == []


def test_anchored_provider_full_receipt_survives_reopen_only_in_encrypted_state(
    tmp_path: Path,
) -> None:
    marker = "full-receipt-encrypted-marker"
    model = profile()
    intent_document = call_intent().model_dump(mode="python")
    intent_document["action_ids"] = (marker,)
    intent = ProviderCallIntent.model_validate(intent_document)
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))

    with provider_state_store(tmp_path) as state:
        journal = AnchoredProviderReceiptJournal(
            state,
            minimum_anchor=state.checkpoint(),
        )
        receipt = adapter((model,), proxy, journal, live=True).call(intent)
        retained_anchor = state.checkpoint()

        assert receipt.outcome is ProviderCallOutcome.COMPLETED
        assert retained_anchor.seq == 4

    marker_bytes = marker.encode("utf-8")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert marker_bytes not in path.read_bytes()

    with provider_state_store(
        tmp_path,
        minimum_anchor=retained_anchor,
    ) as reopened:
        journal = AnchoredProviderReceiptJournal(
            reopened,
            minimum_anchor=retained_anchor,
        )
        assert journal.by_digest(receipt.receipt_digest) == receipt
        assert journal.by_attempt(intent.call_id, intent.attempt) == receipt


def test_anchored_journal_rejects_bare_ledger_and_wrong_anchor(
    tmp_path: Path,
) -> None:
    with provider_state_store(tmp_path) as state:
        floor = state.checkpoint()
        with pytest.raises(ProviderReceiptError, match="exact T20 StateStore"):
            AnchoredProviderReceiptJournal(  # type: ignore[arg-type]
                state.ledger,
                minimum_anchor=floor,
            )
        foreign = AnchorCheckpoint(
            engagement_id="eng.foreign",
            seq=floor.seq,
            head=floor.head,
        )
        with pytest.raises(ProviderReceiptError, match="engagement mismatch"):
            AnchoredProviderReceiptJournal(state, minimum_anchor=foreign)


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
    proxy = FakeProxy(pre_send_result)

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
        ("context", FailureCode.COMPILED_CONTEXT_DRIFT),
        ("output", FailureCode.OUTPUT_SCHEMA_DRIFT),
        ("config", FailureCode.CONFIG_DRIFT),
        ("policy", FailureCode.POLICY_DRIFT),
        ("data_policy", FailureCode.POLICY_DRIFT),
        ("consent", FailureCode.POLICY_DRIFT),
    ],
)
def test_prompt_output_schema_and_config_echo_drift_is_rejected(field: str, failure) -> None:
    model = profile()
    intent = call_intent()
    overrides = {
        "accepted_prompt_digest": digest("wrong") if field == "prompt" else None,
        "accepted_compiled_context_digest": (
            digest("wrong") if field == "context" else None
        ),
        "accepted_output_schema_digest": digest("wrong") if field == "output" else None,
        "accepted_config_digest": digest("wrong") if field == "config" else None,
        "accepted_policy_ref": "wrong-policy" if field == "policy" else None,
        "accepted_data_policy_id": (
            "wrong-data-policy" if field == "data_policy" else None
        ),
        "accepted_data_consent_ref": "wrong-consent" if field == "consent" else None,
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
    proxy = FakeProxy(pre_send_result)

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


def test_raw_secret_field_is_not_admitted_and_only_secret_refs_are_receipted() -> None:
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
    assert "secret://engagement/provider-key" in serialized_receipt


def test_pre_send_failure_allows_only_explicit_identical_retry() -> None:
    model = profile()
    first_intent = call_intent()
    proxy = FakeProxy(pre_send_result)
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((model,), proxy, journal)

    first = runtime.call(first_intent)
    assert first.outcome is ProviderCallOutcome.PRE_SEND_FAILED
    assert first.retry_disposition is RetryDisposition.EXPLICIT_RETRY_ALLOWED
    retry_intent = call_intent(
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
    )
    proxy.handler = lambda request: completed_result(request, model, retry_intent)
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
    proxy = FakeProxy(pre_send_result)
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

    failover = signed_failover(first, primary, fallback)
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
    proxy = FakeProxy(pre_send_result)
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((primary, smaller), proxy, journal)
    first = runtime.call(call_intent())
    failover = signed_failover(first, primary, smaller)
    second = call_intent(
        profile_id="smaller",
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
        failover=failover,
    )

    with pytest.raises(ProviderRetryError, match="compatible"):
        runtime.call(second)
    assert len(proxy.requests) == 1


def test_live_provider_tools_cannot_bypass_missing_t20_boundary() -> None:
    web_tool = tool("provider-web", ProviderToolKind.WEB)
    model = profile(tools=(web_tool,))
    intent = call_intent(tools=(web_tool,))
    proxy = FakeProxy(pre_send_result)

    with pytest.raises(ProviderReceiptError, match="T20"):
        adapter((model,), proxy, live=True).call(intent)
    assert proxy.requests == []


def test_live_anchored_provider_tools_are_rejected_before_reservation(
    tmp_path: Path,
) -> None:
    web_tool = tool("provider-web", ProviderToolKind.WEB)
    model = profile(tools=(web_tool,))
    intent = call_intent(tools=(web_tool,))
    proxy = FakeProxy(pre_send_result)

    with provider_state_store(tmp_path) as state:
        journal = AnchoredProviderReceiptJournal(
            state,
            minimum_anchor=state.checkpoint(),
        )
        with pytest.raises(ProviderPolicyError, match="web/computer/network"):
            adapter((model,), proxy, journal, live=True).call(intent)
        assert journal.by_attempt(intent.call_id, intent.attempt) is None
        assert state.checkpoint().seq == 0
    assert proxy.requests == []


def test_provider_target_plane_confusion_fails_closed() -> None:
    model = profile()
    intent = call_intent()
    wrong_proxy = FakeProxy(pre_send_result)
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


def test_proxy_identity_drift_fails_before_dispatch() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy)
    proxy.proxy_id = "substituted-provider-proxy"

    with pytest.raises(ProviderPlaneError, match="identity"):
        runtime.call(intent)
    assert proxy.requests == []


def test_proxy_identity_toctou_is_unknown_and_requires_reconciliation() -> None:
    model = profile()
    intent = call_intent()
    proxy: FakeProxy

    def mutate_during_dispatch(request: ProviderProxyRequest) -> ProviderProxyResult:
        proxy.proxy_id = "substituted-during-dispatch"
        return completed_result(request, model, intent)

    proxy = FakeProxy(mutate_during_dispatch)
    receipt = adapter((model,), proxy).call(intent)

    assert len(proxy.requests) == 1
    assert receipt.proxy_id == "loopback-provider-proxy"
    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.failure_code is FailureCode.PROXY_EXCEPTION_UNKNOWN
    assert receipt.reconciliation_required is True
    assert receipt.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED


@pytest.mark.parametrize("field", ["accepted_proxy_id", "accepted_proxy_contract_digest"])
def test_proxy_result_identity_drift_is_unknown(field: str) -> None:
    model = profile()
    intent = call_intent()
    override = (
        {field: "other-provider-proxy"}
        if field == "accepted_proxy_id"
        else {field: digest("other-provider-proxy-contract")}
    )
    proxy = FakeProxy(
        lambda request: completed_result(request, model, intent, **override)
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.failure_code is FailureCode.PROXY_IDENTITY_MISMATCH
    assert receipt.reconciliation_required is True


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


def test_concurrent_identical_attempt_is_reserved_before_single_dispatch() -> None:
    model = profile()
    intent = call_intent()
    entered = Event()
    release = Event()

    def blocked_dispatch(request: ProviderProxyRequest) -> ProviderProxyResult:
        entered.set()
        assert release.wait(timeout=5)
        return completed_result(request, model, intent)

    proxy = FakeProxy(blocked_dispatch)
    runtime = adapter((model,), proxy, MemoryProviderReceiptJournal())

    def invoke() -> ProviderCallReceipt | Exception:
        try:
            return runtime.call(intent)
        except Exception as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke)
        assert entered.wait(timeout=5)
        second = pool.submit(invoke)
        second_outcome = second.result(timeout=5)
        release.set()
        first_outcome = first.result(timeout=5)

    assert len(proxy.requests) == 1
    assert isinstance(first_outcome, ProviderCallReceipt)
    assert first_outcome.outcome is ProviderCallOutcome.COMPLETED
    assert isinstance(second_outcome, (ProviderRetryError, ProviderReceiptError))


def test_failed_terminal_journal_transition_keeps_reserved_unknown_hold() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy, journal)

    def fail_finalize(
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None:
        raise OSError("simulated journal failure")

    runtime._journal_finalize = fail_finalize

    receipt = runtime.call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED
    assert journal.by_attempt(intent.call_id, intent.attempt) == receipt


def test_runtimeerror_from_untrusted_result_returns_reserved_unknown_hold() -> None:
    class ExplodingResult:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            raise RuntimeError("untrusted conversion failed after dispatch")

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: ExplodingResult())  # type: ignore[arg-type]

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.reconciliation_required is True


def test_clock_requires_exact_timezone_utc_without_invoking_tzinfo_hooks() -> None:
    class HookTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, value: datetime | None) -> timedelta:
            self.calls += 1
            return timedelta(0)

        def dst(self, value: datetime | None) -> timedelta:
            return timedelta(0)

    model = profile()
    intent = call_intent()
    custom_timezone = HookTimezone()
    hostile = datetime(2026, 7, 12, 3, 0, tzinfo=custom_timezone)
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = ProviderAdapter(
        profiles=(model,),
        proxy=proxy,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        journal=MemoryProviderReceiptJournal(),
        live=False,
        clock=lambda: hostile,
        monotonic_clock=StepMonotonic(),
    )

    with pytest.raises(ProviderAdapterError, match="timezone.utc"):
        runtime.call(intent)
    assert custom_timezone.calls == 0
    assert proxy.requests == []


def test_hostile_second_clock_sample_returns_reserved_unknown_hold() -> None:
    class HostileDatetime(datetime):
        pass

    hostile = HostileDatetime(2026, 7, 12, 3, 0, 1, tzinfo=timezone.utc)

    class TwoStepClock:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> datetime:
            self.calls += 1
            return NOW if self.calls == 1 else hostile

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = ProviderAdapter(
        profiles=(model,),
        proxy=proxy,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        journal=MemoryProviderReceiptJournal(),
        live=False,
        clock=TwoStepClock(),
        monotonic_clock=StepMonotonic(),
    )

    receipt = runtime.call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.reconciliation_required is True


def test_reported_input_usage_cannot_exceed_planned_or_pinned_ceiling() -> None:
    model = profile()
    intent = call_intent(remaining_tokens=2000, remaining_cost=2000)
    proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            intent,
            input_tokens=intent.budget.maximum_input_tokens + 1,
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is FailureCode.USAGE_INVALID


def test_signed_64_accounting_overflow_keeps_unknown_hold() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            intent,
            bytes_received=2**63,
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.reconciliation_required is True


def test_same_profile_id_replacement_is_rejected_before_retry_dispatch() -> None:
    original = profile(snapshot="frontier-2026-07-01", alias="frontier")
    journal = MemoryProviderReceiptJournal()
    first = adapter(
        (original,),
        FakeProxy(pre_send_result),
        journal,
    ).call(call_intent())
    replacement = profile(
        snapshot="weaker-2025-01-01",
        alias="weaker",
        provider_id="replacement-provider",
    )
    retry = call_intent(attempt=2, previous_receipt_digest=first.receipt_digest)
    proxy = FakeProxy(lambda request: completed_result(request, replacement, retry))

    with pytest.raises(ProviderRetryError, match="exact provider profile"):
        adapter((replacement,), proxy, journal).call(retry)
    assert proxy.requests == []


@pytest.mark.parametrize("ceiling", ["maximum_request_bytes", "maximum_response_bytes"])
def test_failover_cannot_reduce_either_byte_ceiling(ceiling: str) -> None:
    primary = profile()
    fallback_data = profile(
        profile_id="fallback",
        provider_id="fallback-provider",
        snapshot="frontier-2026-07-02",
        alias="fallback",
    ).model_dump(mode="python")
    fallback_data[ceiling] = fallback_data[ceiling] - 1
    fallback = ProviderModelProfile.model_validate(fallback_data)
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(pre_send_result)
    first = adapter((primary, fallback), proxy, journal).call(call_intent())
    provenance = signed_failover(
        first,
        primary,
        fallback,
        checkpoint_id="checkpoint-before-byte-failover",
    )
    retry = call_intent(
        profile_id=fallback.profile_id,
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
        failover=provenance,
    )

    with pytest.raises(ProviderRetryError, match="capability-compatible"):
        adapter((primary, fallback), proxy, journal).call(retry)
    assert len(proxy.requests) == 1


def test_journal_digest_substitution_is_rejected_before_dispatch() -> None:
    model = profile()
    first = adapter(
        (model,),
        FakeProxy(pre_send_result),
        MemoryProviderReceiptJournal(),
    ).call(call_intent())
    substituted_key = digest("substituted-journal-key")

    class SubstitutingJournal:
        authenticated_state = True
        durable_reservations = True
        journal_id = "substituting-journal"

        def by_digest(self, receipt_digest: str) -> ProviderCallReceipt:
            assert receipt_digest == substituted_key
            return first

        def by_attempt(self, call_id: str, attempt: int) -> None:
            return None

        def by_attempt_id(self, attempt_id: str) -> None:
            return None

        def reserve(self, receipt: ProviderCallReceipt) -> None:
            pytest.fail("wrong-key receipt must not reserve a dispatch")

        def finalize(
            self,
            reservation_receipt_digest: str,
            receipt: ProviderCallReceipt,
        ) -> None:
            pytest.fail("wrong-key receipt must not finalize a dispatch")

    retry = call_intent(attempt=2, previous_receipt_digest=substituted_key)
    proxy = FakeProxy(lambda request: completed_result(request, model, retry))

    with pytest.raises(ProviderReceiptError, match="exact process-local"):
        ProviderAdapter(
            profiles=(model,),
            proxy=proxy,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=SubstitutingJournal(),
            live=False,
            clock=StepClock(),
            monotonic_clock=StepMonotonic(),
        ).call(retry)
    assert proxy.requests == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("proxy_request_digest", digest("other-request")),
        ("bytes_received", 257),
        ("response_status", 201),
    ],
)
def test_proxy_signature_binds_request_and_every_result_field(
    field: str,
    value: object,
) -> None:
    model = profile()
    intent = call_intent()

    def stale_signature(request: ProviderProxyRequest) -> ProviderProxyResult:
        result = completed_result(request, model, intent)
        return rehashed_without_resigning(result, **{field: value})

    receipt = adapter((model,), FakeProxy(stale_signature)).call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.reconciliation_required is True


def test_forged_pre_send_attestation_cannot_authorize_retry() -> None:
    model = profile()
    intent = call_intent()

    def forged_pre_send(request: ProviderProxyRequest) -> ProviderProxyResult:
        result = pre_send_result(request)
        return rehashed_without_resigning(
            result,
            proxy_request_digest=digest("forged-pre-send-request"),
        )

    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(forged_pre_send)
    runtime = adapter((model,), proxy, journal)
    first = runtime.call(intent)

    assert first.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert first.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED
    with pytest.raises(ProviderRetryError):
        runtime.call(
            call_intent(attempt=2, previous_receipt_digest=first.receipt_digest)
        )
    assert len(proxy.requests) == 1


def test_unattested_mutable_callable_port_is_rejected_at_admission() -> None:
    class MutableDispatch:
        def __call__(self, request: ProviderProxyRequest) -> ProviderProxyResult:
            pytest.fail("unattested mutable dispatch must not execute")

    class MutableProxy:
        plane = ProviderPlane.MODEL_PROVIDER
        proxy_id = "mutable-proxy"
        contract_digest = digest("mutable-contract")
        dispatch = MutableDispatch()

    with pytest.raises(ValueError, match="attestation key"):
        ProviderAdapter(
            profiles=(profile(),),
            proxy=MutableProxy(),  # type: ignore[arg-type]
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=MemoryProviderReceiptJournal(),
            live=False,
        )


def test_proxy_result_schema_attests_full_canonical_request_digest() -> None:
    assert "proxy_request_digest" in ProviderProxyResult.model_fields


def test_journal_attempt_index_deletion_cannot_enable_duplicate_dispatch() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy, journal)
    runtime.call(intent)

    journal._by_attempt.clear()

    with pytest.raises(ProviderReceiptError, match="index"):
        runtime.call(intent)
    assert len(proxy.requests) == 1


def test_journal_valid_prefix_rollback_cannot_enable_duplicate_dispatch() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy, journal)
    runtime.call(intent)

    reserved_state = journal._states[0]
    reservation_digest = str(reserved_state["receipt_digest"])
    reservation = journal._by_digest[reservation_digest]
    journal._states[:] = (reserved_state,)
    journal._head = str(reserved_state["state_digest"])
    journal._by_digest = {reservation_digest: reservation}
    journal._by_attempt = {
        (reservation.call_id, reservation.attempt): reservation,
    }
    journal._by_attempt_id = {reservation.attempt_id: reservation}
    journal._state_by_receipt_digest = {reservation_digest: reserved_state}

    with pytest.raises(ProviderReceiptError, match="rollback"):
        runtime.call(intent)
    assert len(proxy.requests) == 1


def test_noop_journal_cannot_pass_reservation_readback_or_dispatch() -> None:
    class NoOpJournal:
        authenticated_state = True
        durable_reservations = True
        journal_id = "noop-journal"

        def by_digest(self, receipt_digest: str) -> None:
            return None

        def by_attempt(self, call_id: str, attempt: int) -> None:
            return None

        def by_attempt_id(self, attempt_id: str) -> None:
            return None

        def reserve(self, receipt: ProviderCallReceipt) -> None:
            return None

        def finalize(
            self,
            reservation_receipt_digest: str,
            receipt: ProviderCallReceipt,
        ) -> None:
            pytest.fail("an unreadable reservation must never finalize")

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    with pytest.raises(ProviderReceiptError, match="exact process-local"):
        ProviderAdapter(
            profiles=(model,),
            proxy=proxy,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=NoOpJournal(),
            live=False,
            clock=StepClock(),
            monotonic_clock=StepMonotonic(),
        )
    assert proxy.requests == []


@pytest.mark.parametrize(
    ("authenticated", "durable", "match"),
    [
        (False, True, "exact process-local"),
        (True, False, "exact process-local"),
    ],
)
def test_untrusted_or_nondurable_journal_is_rejected_by_default(
    authenticated: bool,
    durable: bool,
    match: str,
) -> None:
    class UntrustedJournal:
        authenticated_state = authenticated
        durable_reservations = durable
        journal_id = "untrusted-journal"

        def by_digest(self, receipt_digest: str) -> None:
            return None

        def by_attempt(self, call_id: str, attempt: int) -> None:
            return None

        def by_attempt_id(self, attempt_id: str) -> None:
            return None

        def reserve(self, receipt: ProviderCallReceipt) -> None:
            return None

        def finalize(
            self,
            reservation_receipt_digest: str,
            receipt: ProviderCallReceipt,
        ) -> None:
            return None

    with pytest.raises(ProviderReceiptError, match=match):
        ProviderAdapter(
            profiles=(profile(),),
            proxy=FakeProxy(pre_send_result),
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=UntrustedJournal(),
            live=False,
        )


def test_proxy_advertised_key_cannot_replace_independent_t17_trust_root() -> None:
    foreign_signer = AuthoritySigner.from_private_bytes(bytes(range(2, 34)))
    proxy = FakeProxy(pre_send_result)
    proxy.attestation_public_key = foreign_signer.public_key_record

    with pytest.raises(ProviderPlaneError, match="trusted T17"):
        ProviderAdapter(
            profiles=(profile(),),
            proxy=proxy,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=MemoryProviderReceiptJournal(),
            live=False,
        )


def test_retry_reverifies_stored_proxy_attestation_with_trusted_t17_key() -> None:
    model = profile()
    journal = MemoryProviderReceiptJournal()
    first = adapter((model,), FakeProxy(pre_send_result), journal).call(call_intent())
    assert first.proxy_result is not None
    forged_result = first.proxy_result.model_copy(
        update={"attestation_signature": "A" * 86}
    )
    document = first.model_dump(mode="python")
    document["proxy_result"] = forged_result.model_dump(mode="python")
    document["receipt_digest"] = sha256_digest(
        {key: value for key, value in document.items() if key != "receipt_digest"}
    )
    forged = ProviderCallReceipt.model_validate(document)

    retry = call_intent(attempt=2, previous_receipt_digest=forged.receipt_digest)
    proxy = FakeProxy(lambda request: completed_result(request, model, retry))
    runtime = adapter((model,), proxy, journal)
    runtime._journal_by_digest = (
        lambda receipt_digest: forged
        if receipt_digest == forged.receipt_digest
        else None
    )

    with pytest.raises(ProviderRetryError, match="attestation"):
        runtime.call(retry)
    assert proxy.requests == []


@pytest.mark.parametrize("tamper", ["profile_digest", "signature"])
def test_failover_requires_exact_authenticated_profile_digests(tamper: str) -> None:
    primary = profile()
    fallback = profile(
        profile_id="fallback",
        provider_id="fallback-provider",
        snapshot="frontier-2026-07-02",
        alias="fallback",
    )
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(pre_send_result)
    first = adapter((primary, fallback), proxy, journal).call(call_intent())
    provenance = signed_failover(first, primary, fallback)
    provenance = provenance.model_copy(
        update=(
            {"to_profile_digest": digest("substituted-profile")}
            if tamper == "profile_digest"
            else {"approval_signature": "A" * 86}
        )
    )
    retry = call_intent(
        profile_id=fallback.profile_id,
        attempt=2,
        previous_receipt_digest=first.receipt_digest,
        failover=provenance,
    )

    with pytest.raises(ProviderRetryError, match="provenance|signature"):
        adapter((primary, fallback), proxy, journal).call(retry)
    assert len(proxy.requests) == 1


def test_failed_result_with_possible_effect_requires_reconciliation() -> None:
    model = profile()
    intent = call_intent()

    def possible_failure(request: ProviderProxyRequest) -> ProviderProxyResult:
        return signed_proxy_result(
            plane=ProviderPlane.MODEL_PROVIDER,
            request_id=request.request_id,
            proxy_request_digest=sha256_digest(request),
            attested_proxy_id=request.proxy_id,
            attested_proxy_contract_digest=request.proxy_contract_digest,
            outcome=ProxyOutcome.FAILED,
            effect_disposition=ProxyEffectDisposition.POSSIBLE,
            bytes_sent=1,
            bytes_received=0,
        )

    receipt = adapter((model,), FakeProxy(possible_failure)).call(intent)

    assert receipt.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert receipt.reconciliation_required is True
    assert receipt.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED


def test_derived_cost_overflow_is_bounded_and_classified_usage_invalid() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            intent,
            input_tokens=2**63 - 1,
            output_tokens=1,
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is FailureCode.USAGE_INVALID
    assert receipt.cost_microunits is None


def test_baseexception_preserves_unknown_reservation_and_is_not_swallowed() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()

    def cancelled(request: ProviderProxyRequest) -> ProviderProxyResult:
        raise KeyboardInterrupt("cancelled after dispatch admission")

    proxy = FakeProxy(cancelled)
    runtime = adapter((model,), proxy, journal)

    with pytest.raises(KeyboardInterrupt):
        runtime.call(intent)
    hold = journal.by_attempt(intent.call_id, intent.attempt)
    assert hold is not None
    assert hold.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert hold.reconciliation_required is True
    with pytest.raises(ProviderRetryError):
        runtime.call(intent)
    assert len(proxy.requests) == 1


def test_transient_self_attested_journal_is_rejected_before_dispatch() -> None:
    class TransientSelfAttestedJournal:
        authenticated_state = True
        durable_reservations = True
        journal_id = "transient-self-attested-journal"

        def __init__(self) -> None:
            self.receipt: ProviderCallReceipt | None = None
            self.reads = 0

        def _read(self) -> ProviderCallReceipt | None:
            self.reads += 1
            current = self.receipt
            if self.reads == 3:
                self.receipt = None
            return current

        def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
            return self._read()

        def by_attempt(
            self,
            call_id: str,
            attempt: int,
        ) -> ProviderCallReceipt | None:
            return self._read()

        def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
            return self._read()

        def reserve(self, receipt: ProviderCallReceipt) -> None:
            self.receipt = receipt

        def finalize(
            self,
            reservation_receipt_digest: str,
            receipt: ProviderCallReceipt,
        ) -> None:
            return None

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))

    with pytest.raises(ProviderReceiptError, match="exact process-local"):
        ProviderAdapter(
            profiles=(model,),
            proxy=proxy,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=TransientSelfAttestedJournal(),
            live=False,
        )
    assert proxy.requests == []


def test_live_memory_journal_recreation_cannot_dispatch_same_attempt() -> None:
    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))

    for _ in range(2):
        with pytest.raises(ProviderReceiptError, match="T20"):
            ProviderAdapter(
                profiles=(model,),
                proxy=proxy,
                trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
                journal=MemoryProviderReceiptJournal(),
                live=True,
            )
    assert proxy.requests == []


def test_removed_process_local_override_cannot_enable_live_dispatch() -> None:
    with pytest.raises(TypeError, match="allow_process_local"):
        ProviderAdapter(
            profiles=(profile(),),
            proxy=FakeProxy(pre_send_result),
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            journal=MemoryProviderReceiptJournal(),
            live=True,
            allow_process_local_journal_for_tests=True,  # type: ignore[call-arg]
        )


def test_noop_terminal_finalize_returns_hold_and_blocks_redispatch() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy, journal)
    runtime._journal_finalize = lambda reservation_digest, receipt: None

    hold = runtime.call(intent)

    assert hold.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME
    assert hold.reconciliation_required is True
    assert journal.by_attempt(intent.call_id, intent.attempt) == hold
    with pytest.raises(ProviderRetryError):
        runtime.call(intent)
    assert len(proxy.requests) == 1


def test_terminal_cannot_change_trusted_dispatch_start() -> None:
    model = profile()
    intent = call_intent()
    journal = MemoryProviderReceiptJournal()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    runtime = adapter((model,), proxy, journal)
    captured: list[tuple[str, ProviderCallReceipt]] = []
    runtime._journal_finalize = (
        lambda reservation_digest, receipt: captured.append(
            (reservation_digest, receipt)
        )
    )

    hold = runtime.call(intent)
    reservation_digest, terminal = captured[0]
    document = terminal.model_dump(mode="python")
    document["started_at"] = terminal.started_at + timedelta(microseconds=1)
    document["receipt_digest"] = sha256_digest(
        {key: value for key, value in document.items() if key != "receipt_digest"}
    )
    changed = ProviderCallReceipt.model_validate(document)

    with pytest.raises(ProviderReceiptError, match="changed its reservation"):
        journal.finalize(reservation_digest, changed)
    assert journal.by_attempt(intent.call_id, intent.attempt) == hold


def test_valid_presend_signature_cannot_be_rebound_by_outer_receipt() -> None:
    model = profile()
    first = adapter((model,), FakeProxy(pre_send_result)).call(call_intent())
    assert first.proxy_result is not None
    original_signature = first.proxy_result.attestation_signature
    document = first.model_dump(mode="python")
    document["call_id"] = "victim-call"
    document["run_id"] = "victim-run"
    document["logical_request_digest"] = digest("victim-logical-request")
    document["dispatch_reservation_digest"] = sha256_digest(
        {
            "attempt": document["attempt"],
            "attempt_id": document["attempt_id"],
            "call_id": document["call_id"],
            "logical_request_digest": document["logical_request_digest"],
            "profile_digest": document["profile_digest"],
            "proxy_attestation_key_id": document["proxy_attestation_key_id"],
            "proxy_contract_digest": document["proxy_contract_digest"],
            "proxy_id": document["proxy_id"],
            "purpose": "faultloom.provider_dispatch_reservation.v1",
            "run_id": document["run_id"],
        }
    )
    document["receipt_digest"] = sha256_digest(
        {key: value for key, value in document.items() if key != "receipt_digest"}
    )

    with pytest.raises(ValidationError, match="canonical proxy request"):
        ProviderCallReceipt.model_validate(document)
    assert first.proxy_result.attestation_signature == original_signature


def test_receipt_embeds_full_canonical_proxy_request() -> None:
    model = profile()
    intent = call_intent()
    receipt = adapter(
        (model,),
        FakeProxy(lambda request: completed_result(request, model, intent)),
    ).call(intent)

    assert receipt.proxy_result is not None
    assert sha256_digest(receipt.proxy_request) == receipt.proxy_request_digest
    assert receipt.proxy_result.proxy_request_digest == receipt.proxy_request_digest
    assert receipt.proxy_request.run_id == receipt.run_id
    assert (
        receipt.proxy_request.dispatch_reservation_digest
        == receipt.dispatch_reservation_digest
    )
