from __future__ import annotations

from pathlib import Path

import pytest
from faultloom.provider_output import (
    ProviderOutputCursorKey,
    ProviderOutputHandoff,
    ProviderOutputReader,
    ProviderOutputRef,
)
from pydantic import ValidationError

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)


def test_handoff_policy_cannot_drift_after_admission(tmp_path: Path) -> None:
    body = b"immutable-provider-output"
    receipt = completed_receipt(body)
    with output_state_store(tmp_path) as state:
        handoff = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_output_bytes=1,
        )
        for name, value in (
            ("_maximum_output_bytes", len(body)),
            ("_media_type", "text/plain"),
            ("_media_type", "application/json\n"),
            ("_binding", object()),
            ("_receipt_verifier", object()),
        ):
            with pytest.raises(AttributeError):
                setattr(handoff, name, value)
        assert state.checkpoint().seq == 0


def test_reader_key_policy_and_page_are_immutable(tmp_path: Path) -> None:
    body = b"bounded-page"
    receipt = completed_receipt(body)
    key = ProviderOutputCursorKey(bytes(range(32)))
    with pytest.raises(AttributeError):
        setattr(key, "_ProviderOutputCursorKey__material", b"x")

    with output_state_store(tmp_path) as state:
        invocation = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        reader = ProviderOutputReader(
            state,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=1,
        )
        for name, value in (
            ("_maximum_page_bytes", len(body)),
            ("_binding", object()),
            ("_receipt_verifier", object()),
            ("_cursor_key", b"x"),
        ):
            with pytest.raises(AttributeError):
                setattr(reader, name, value)
        page = reader.read_page(
            invocation,
            expected_engagement_id=state.engagement_id,
            expected_run_id=receipt.run_id,
            max_bytes=1,
        )
        for name, value in (
            ("offset", 9),
            ("total_bytes", 99),
            ("next_cursor", None),
            ("_ProviderOutputPage__data", b"forged"),
        ):
            with pytest.raises(AttributeError):
                setattr(page, name, value)
        assert page.offset == 0
        assert page.total_bytes == len(body)
        assert page.data == body[:1]


def test_cross_engagement_capabilities_cannot_replace_admitted_binding(
    tmp_path: Path,
) -> None:
    body = b"engagement-bound"
    receipt = completed_receipt(body)
    with (
        output_state_store(
            tmp_path / "a",
            engagement_id="eng.provider-output.a",
        ) as state_a,
        output_state_store(
            tmp_path / "b",
            engagement_id="eng.provider-output.b",
        ) as state_b,
    ):
        handoff_a = ProviderOutputHandoff(
            state_a,
            engagement_id=state_a.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        handoff_b = ProviderOutputHandoff(
            state_b,
            engagement_id=state_b.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        with pytest.raises(AttributeError):
            setattr(handoff_a, "_binding", handoff_b)
        invocation_a = handoff_a.publish(receipt, body)
        assert state_a.checkpoint().seq == 1
        assert state_b.checkpoint().seq == 0

        key = ProviderOutputCursorKey(bytes(range(32)))
        reader_a = ProviderOutputReader(
            state_a,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        reader_b = ProviderOutputReader(
            state_b,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        with pytest.raises(AttributeError):
            setattr(reader_a, "_binding", reader_b)
        page = reader_a.read_page(
            invocation_a,
            expected_engagement_id=state_a.engagement_id,
            expected_run_id=receipt.run_id,
            max_bytes=len(body),
        )
        assert page.data == body


@pytest.mark.parametrize(
    "field",
    (
        "engagement_id",
        "receipt_digest",
        "observation.observation_id",
        "observation.run_id",
        "observation.cas_digest",
        "observation.media_type",
    ),
)
def test_output_ref_rejects_raw_string_normalization(
    tmp_path: Path,
    field: str,
) -> None:
    body = b"strict-ref"
    receipt = completed_receipt(body)
    with output_state_store(tmp_path) as state:
        output = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body).output_ref
        document = output.model_dump(mode="python")
        if field.startswith("observation."):
            name = field.split(".", 1)[1]
            document["observation"][name] += "\n"
        else:
            document[field] += "\n"
        with pytest.raises(ValidationError):
            ProviderOutputRef.model_validate(document)
