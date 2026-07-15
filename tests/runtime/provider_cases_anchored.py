from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    AnchorCheckpoint,
    AnchoredProviderReceiptJournal,
    FakeProxy,
    Path,
    ProviderCallIntent,
    ProviderCallOutcome,
    ProviderReceiptError,
    ProviderRetryError,
    adapter,
    call_intent,
    completed_result,
    pre_send_result,
    profile,
    provider_state_store,
    pytest,
)

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
