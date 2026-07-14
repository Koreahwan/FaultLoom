from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    ProviderAdapter,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderModelProfile,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    ProviderRetryError,
    RetryDisposition,
    StepClock,
    StepMonotonic,
    adapter,
    call_intent,
    completed_result,
    digest,
    pre_send_result,
    profile,
    pytest,
    rehashed_without_resigning,
    signed_failover,
)

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
