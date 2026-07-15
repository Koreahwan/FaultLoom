from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from faultloom.provider import ProviderCallOutcome
from faultloom.provider_output import (
    ProviderInvocationResult,
    ProviderOutputHandoff,
    ProviderOutputIntegrityError,
    ProviderOutputRef,
)
from pydantic import ValidationError

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)


BODY = b'{"hypotheses":[{"id":"h-1","summary":"bounded"}]}'


def test_publish_returns_strict_receipt_bound_observation(tmp_path: Path) -> None:
    receipt = completed_receipt(BODY)

    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            media_type="application/json",
            maximum_output_bytes=4096,
        ).publish(receipt, BODY)

        assert isinstance(result, ProviderInvocationResult)
        assert result.receipt == receipt
        assert result.output_ref.engagement_id == state.engagement_id
        assert result.output_ref.observation.run_id == receipt.run_id
        assert result.output_ref.observation.cas_digest == receipt.response_digest
        assert result.output_ref.observation.byte_length == len(BODY)
        assert result.output_ref.observation.media_type == "application/json"
        assert result.output_ref.observation.cursor is None
        assert result.output_ref.receipt_digest == receipt.receipt_digest
        assert result == ProviderInvocationResult.model_validate_json(result.model_dump_json())

        with pytest.raises(ValidationError):
            result.output_ref.engagement_id = "eng.rebound"  # type: ignore[misc]


def test_publish_is_idempotent_and_recovers_exact_observation(tmp_path: Path) -> None:
    receipt = completed_receipt(BODY)

    with output_state_store(tmp_path) as state:
        handoff = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        assert handoff.recover(receipt) is None
        first = handoff.publish(receipt, BODY)
        second = handoff.publish(receipt, BODY)
        recovered = handoff.recover(receipt)

        assert second == first
        assert recovered == first
        assert state.checkpoint().seq == 1


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (BODY + b"!", "digest"),
        (BODY[:-1], "digest"),
    ],
)
def test_publish_rejects_digest_and_length_substitution(
    tmp_path: Path,
    body: bytes,
    message: str,
) -> None:
    receipt = completed_receipt(BODY)

    with output_state_store(tmp_path) as state:
        with pytest.raises(ProviderOutputIntegrityError, match=message):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).publish(receipt, body)
        assert state.checkpoint().seq == 0


def test_publish_rejects_noncompleted_receipt_and_oversize_body(tmp_path: Path) -> None:
    receipt = completed_receipt(BODY)
    rejected = receipt.model_copy(update={"outcome": ProviderCallOutcome.REJECTED_RESPONSE})

    with output_state_store(tmp_path) as state:
        handoff = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_output_bytes=len(BODY) - 1,
        )
        with pytest.raises(ProviderOutputIntegrityError):
            handoff.publish(rejected, BODY)
        with pytest.raises(ProviderOutputIntegrityError, match="configured maximum"):
            handoff.publish(receipt, BODY)
        assert state.checkpoint().seq == 0


def test_plaintext_and_secret_body_never_enter_ledger_or_repr(tmp_path: Path) -> None:
    body = b'{"authorization":"Bearer provider-output-secret"}'
    receipt = completed_receipt(body)

    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        database = next((tmp_path / "state").rglob("state.sqlite3"))
        connection = sqlite3.connect(database)
        try:
            rows = connection.execute("SELECT payload_json FROM events").fetchall()
        finally:
            connection.close()

        assert all(body not in row[0].encode("utf-8") for row in rows)
        assert b"provider-output-secret" not in database.read_bytes()
        assert "provider-output-secret" not in repr(result)
        assert "authorization" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt_digest", "0" * 64),
        ("receipt_digest", "sha256:" + "A" * 64),
        ("event_hash", "sha256:sha256:" + "0" * 64),
        ("event_seq", True),
    ],
)
def test_output_ref_rejects_noncanonical_identity_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    receipt = completed_receipt(BODY)
    with output_state_store(tmp_path) as state:
        result = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, BODY)
        document = result.output_ref.model_dump(mode="python")
        document[field] = value
        with pytest.raises(ValidationError):
            ProviderOutputRef.model_validate(document)
        document = result.output_ref.model_dump(mode="python")
        document["body"] = BODY
        with pytest.raises(ValidationError):
            ProviderOutputRef.model_validate(document)


def test_store_namespace_rejects_hostile_string_keys_without_hooks(
    tmp_path: Path,
) -> None:
    hits = 0

    class HostileStr(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            nonlocal hits
            hits += 1
            raise AssertionError("hostile store key comparison executed")

    with output_state_store(tmp_path) as state:
        key = HostileStr("append_observation")
        state.__dict__[key] = object()
        try:
            with pytest.raises(ProviderOutputIntegrityError, match="namespace"):
                ProviderOutputHandoff(
                    state,
                    engagement_id=state.engagement_id,
                    trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
                )
            assert hits == 0
        finally:
            del state.__dict__[key]
