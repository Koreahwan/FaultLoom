from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FailureCode,
    FakeProxy,
    MemoryProviderReceiptJournal,
    NOW,
    PROXY_SIGNER,
    ProviderAdapter,
    ProviderCallOutcome,
    ProviderRetryError,
    StepMonotonic,
    adapter,
    call_intent,
    completed_result,
    datetime,
    pre_send_result,
    profile,
    pytest,
    timezone,
)

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
