from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    ProviderAdapter,
    ProviderCallReceipt,
    ProviderPlane,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    StepClock,
    StepMonotonic,
    adapter,
    call_intent,
    completed_result,
    digest,
    profile,
    pytest,
)

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
