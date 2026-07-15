from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    AuthoritySigner,
    FailureCode,
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    ProviderAdapter,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderPlane,
    ProviderPlaneError,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderReceiptError,
    ProviderRetryError,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
    adapter,
    call_intent,
    completed_result,
    digest,
    pre_send_result,
    profile,
    pytest,
    sha256_digest,
    signed_failover,
    signed_proxy_result,
)

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
