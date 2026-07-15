from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    AnchoredProviderReceiptJournal,
    FailureCode,
    FakeProxy,
    MemoryProviderReceiptJournal,
    Path,
    ProviderCallOutcome,
    ProviderPlane,
    ProviderPlaneError,
    ProviderPolicyError,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    ProviderRetryError,
    ProviderToolKind,
    RetryDisposition,
    adapter,
    call_intent,
    completed_result,
    digest,
    pre_send_result,
    profile,
    provider_state_store,
    pytest,
    sha256_digest,
    signed_failover,
    tool,
)

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
