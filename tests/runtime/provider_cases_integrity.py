from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    Event,
    FailureCode,
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    Path,
    ProviderAdapter,
    ProviderAdapterError,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    ProviderRetryError,
    RetryDisposition,
    StepMonotonic,
    ThreadPoolExecutor,
    adapter,
    call_intent,
    completed_result,
    datetime,
    digest,
    profile,
    pytest,
    timedelta,
    tzinfo,
)

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
