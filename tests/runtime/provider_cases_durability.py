from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    ProviderAdapter,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderReceiptError,
    ProviderRetryError,
    ValidationError,
    adapter,
    call_intent,
    completed_result,
    digest,
    pre_send_result,
    profile,
    pytest,
    sha256_digest,
    timedelta,
)

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
