from __future__ import annotations

import pickle
import socket
import subprocess
from pathlib import Path

import pytest
from faultloom.provider import ProviderPlane
from faultloom.provider_output import (
    ProviderInvocationResult,
    ProviderOutputCursorKey,
    ProviderOutputError,
    ProviderOutputHandoff,
    ProviderOutputIntegrityError,
    ProviderOutputReader,
)
from faultloom_protocol import AuthoritySigner

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    forged_receipt_without_resigning,
    output_state_store,
)

KEY = ProviderOutputCursorKey(bytes(range(32)))

def publish(tmp_path: Path, body: bytes = b"hostile-output"):
    receipt = completed_receipt(body)
    state = output_state_store(tmp_path)
    result = ProviderOutputHandoff(
        state,
        engagement_id=state.engagement_id,
        trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
    ).publish(receipt, body)
    return state, receipt, result



@pytest.mark.parametrize(
    "updates",
    [
        {"response_status": 201},
        {"plane": ProviderPlane.TARGET},
        {"plane": ProviderPlane.KNOWLEDGE},
    ],
)
def test_handoff_rejects_rehashed_stale_proxy_attestation(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    body = b"signed-provider-output"
    receipt = completed_receipt(body)
    forged = forged_receipt_without_resigning(receipt, **updates)

    with output_state_store(tmp_path) as state:
        with pytest.raises(ProviderOutputIntegrityError, match="attestation|plane"):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).publish(forged, body)
        assert state.checkpoint().seq == 0


def test_reader_independently_rejects_untrusted_proxy_attestation_key(
    tmp_path: Path,
) -> None:
    state, receipt, result = publish(tmp_path, b"pinned-proxy-key")
    wrong_key = AuthoritySigner.from_private_bytes(
        bytes(range(32, 64))
    ).public_key_record
    try:
        with pytest.raises(ProviderOutputIntegrityError, match="attestation"):
            ProviderOutputReader(
                state,
                KEY,
                trusted_proxy_attestation_key=wrong_key,
            ).read_page(
                result,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
            )
    finally:
        state.close()


@pytest.mark.parametrize(
    "field",
    ["event_hash", "engagement_id", "observation.run_id", "observation.cas_digest"],
)
def test_reader_rejects_forged_output_reference(tmp_path: Path, field: str) -> None:
    state, receipt, result = publish(tmp_path)
    try:
        output = result.output_ref
        if field.startswith("observation."):
            name = field.split(".", 1)[1]
            observation = output.observation.model_copy(update={name: "run-forged"})
            forged_output = output.model_copy(update={"observation": observation})
        else:
            forged_output = output.model_copy(update={field: "eng-forged"})
        forged = result.model_copy(update={"output_ref": forged_output})
        with pytest.raises(ProviderOutputError):
            ProviderOutputReader(
                state,
                KEY,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).read_page(
                forged,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
            )
    finally:
        state.close()


def test_cursor_rejects_wrong_key_and_page_cannot_pickle(tmp_path: Path) -> None:
    state, receipt, result = publish(tmp_path, b"two-page-output")
    try:
        first = ProviderOutputReader(
            state,
            KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=4,
        ).read_page(
            result,
            expected_engagement_id=state.engagement_id,
            expected_run_id=receipt.run_id,
            max_bytes=4,
        )
        assert first.next_cursor is not None
        with pytest.raises(TypeError):
            pickle.dumps(first)
        wrong_key = ProviderOutputCursorKey(bytes(range(1, 33)))
        with pytest.raises(ProviderOutputIntegrityError, match="cursor"):
            ProviderOutputReader(
                state,
                wrong_key,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).read_page(
                result,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
                cursor=first.next_cursor,
                max_bytes=4,
            )
    finally:
        state.close()


def test_ciphertext_tamper_blocks_plaintext_page(tmp_path: Path) -> None:
    state, receipt, result = publish(tmp_path)
    artifact = next((tmp_path / "state" / "cas").rglob("*.flcas"))
    envelope = artifact.read_bytes()
    artifact.write_bytes(envelope[:-1] + bytes([envelope[-1] ^ 1]))
    try:
        with pytest.raises(ProviderOutputIntegrityError):
            ProviderOutputReader(
                state,
                KEY,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).read_page(
                result,
                expected_engagement_id=state.engagement_id,
                expected_run_id=receipt.run_id,
            )
    finally:
        state.close()


def test_ciphertext_tamper_blocks_recovered_reference(tmp_path: Path) -> None:
    state, receipt, _ = publish(tmp_path)
    artifact = next((tmp_path / "state" / "cas").rglob("*.flcas"))
    envelope = artifact.read_bytes()
    artifact.write_bytes(envelope[:-1] + bytes([envelope[-1] ^ 1]))
    try:
        with pytest.raises(ProviderOutputIntegrityError):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).recover(receipt)
    finally:
        state.close()


def test_offline_handoff_never_calls_network_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_: object, **__: object):
        raise AssertionError("offline provider-output boundary invoked an external tool")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(subprocess, "Popen", explode)
    state, receipt, result = publish(tmp_path)
    try:
        page = ProviderOutputReader(
            state,
            KEY,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).read_page(
            result,
            expected_engagement_id=state.engagement_id,
            expected_run_id=receipt.run_id,
        )
        assert page.data == b"hostile-output"
    finally:
        state.close()


def test_public_result_has_no_body_or_storage_capability(tmp_path: Path) -> None:
    state, _, result = publish(tmp_path, b"no-public-body")
    try:
        document = result.model_dump()
        serialized = result.model_dump_json()
        assert set(document) == {"schema_version", "receipt", "output_ref"}
        assert "no-public-body" not in serialized
        assert "filesystem" not in serialized
        assert "cursor_key" not in serialized
        assert ProviderInvocationResult.model_validate(document) == result
    finally:
        state.close()
