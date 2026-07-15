from __future__ import annotations

from pathlib import Path

import pytest
from faultloom.provider_output import (
    ProviderOutputCursorKey,
    ProviderOutputHandoff,
    ProviderOutputIntegrityError,
    ProviderOutputReader,
    ProviderOutputScopeError,
)

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)


CURSOR_KEY = ProviderOutputCursorKey(bytes(range(32)))


def test_reader_returns_only_bounded_pages_and_reopens(tmp_path: Path) -> None:
    body = b"0123456789abcdef"
    receipt = completed_receipt(body)

    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        floor = state.checkpoint()
        reader = ProviderOutputReader(
            state,
            CURSOR_KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=5,
        )
        first = reader.read_page(
            result,
            expected_engagement_id=state.engagement_id,
            expected_run_id=receipt.run_id,
            max_bytes=5,
        )
        assert first.data == b"01234"
        assert first.offset == 0
        assert first.total_bytes == len(body)
        assert first.next_cursor is not None
        assert "01234" not in repr(first)

    with output_state_store(tmp_path, minimum_anchor=floor) as reopened:
        reader = ProviderOutputReader(
            reopened,
            CURSOR_KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=5,
        )
        second = reader.read_page(
            result,
            expected_engagement_id=reopened.engagement_id,
            expected_run_id=receipt.run_id,
            cursor=first.next_cursor,
            max_bytes=5,
        )
        assert second.data == b"56789"
        assert second.offset == 5


def test_reader_rejects_cross_engagement_and_cross_run(tmp_path: Path) -> None:
    body = b"scoped"
    receipt = completed_receipt(body, run_id="run-a")

    with output_state_store(tmp_path / "a", engagement_id="eng.a") as state_a:
        result = ProviderOutputHandoff(
            state_a,
            engagement_id=state_a.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)

        with pytest.raises(ProviderOutputScopeError, match="run"):
            ProviderOutputReader(
                state_a,
                CURSOR_KEY,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).read_page(
                result,
                expected_engagement_id="eng.a",
                expected_run_id="run-b",
            )

    with output_state_store(tmp_path / "b", engagement_id="eng.b") as state_b:
        with pytest.raises(ProviderOutputScopeError, match="engagement"):
            ProviderOutputReader(
                state_b,
                CURSOR_KEY,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).read_page(
                result,
                expected_engagement_id="eng.b",
                expected_run_id="run-a",
            )


@pytest.mark.parametrize("max_bytes", [0, -1, True, 6, 1_048_577])
def test_reader_rejects_unbounded_page_sizes(tmp_path: Path, max_bytes: object) -> None:
    body = b"bounded"
    receipt = completed_receipt(body)

    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        reader = ProviderOutputReader(
            state,
            CURSOR_KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=5,
        )
        with pytest.raises(ProviderOutputIntegrityError, match="page"):
            reader.read_page(
                result,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
                max_bytes=max_bytes,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize(
    "tamper",
    [
        lambda value: "x" + value[1:],
        lambda value: value[:-1],
        lambda value: value + "A",
        lambda value: value.replace(".", "=.", 1),
    ],
)
def test_reader_rejects_tampered_cursor(tmp_path: Path, tamper) -> None:
    body = b"cursor-bound-output"
    receipt = completed_receipt(body)

    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        reader = ProviderOutputReader(
            state,
            CURSOR_KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=4,
        )
        first = reader.read_page(
            result,
            expected_engagement_id=state.engagement_id,
            expected_run_id=receipt.run_id,
            max_bytes=4,
        )
        assert first.next_cursor is not None
        with pytest.raises(ProviderOutputIntegrityError, match="cursor"):
            reader.read_page(
                result,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
                cursor=tamper(first.next_cursor),
                max_bytes=4,
            )


def test_cursor_cannot_cross_same_digest_outputs(tmp_path: Path) -> None:
    body = b"same-bytes-across-runs"
    first_receipt = completed_receipt(body, run_id="run-first")
    second_receipt = completed_receipt(body, run_id="run-second")

    with output_state_store(tmp_path) as state:
        handoff = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        first_result = handoff.publish(first_receipt, body)
        second_result = handoff.publish(second_receipt, body)
        reader = ProviderOutputReader(
            state,
            CURSOR_KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=4,
        )
        first_page = reader.read_page(
            first_result,
            expected_engagement_id=state.engagement_id,
            expected_run_id="run-first",
            max_bytes=4,
        )
        assert first_page.next_cursor is not None

        with pytest.raises(ProviderOutputIntegrityError, match="cursor"):
            reader.read_page(
                second_result,
                expected_engagement_id=state.engagement_id,
                expected_run_id="run-second",
                cursor=first_page.next_cursor,
                max_bytes=4,
            )
