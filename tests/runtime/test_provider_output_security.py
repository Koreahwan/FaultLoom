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
    ProviderOutputScopeError,
)
from faultloom.state import StateStore
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


def test_handoff_rejects_cross_engagement_construction(tmp_path: Path) -> None:
    with output_state_store(tmp_path, engagement_id="eng.b") as state:
        with pytest.raises(ProviderOutputScopeError, match="engagement"):
            ProviderOutputHandoff(
                state,
                engagement_id="eng.a",
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            )
        assert state.checkpoint().seq == 0


def test_handoff_rejects_store_subclass_and_method_replacement(tmp_path: Path) -> None:
    class DerivedStore(StateStore):
        pass

    forged = object.__new__(DerivedStore)
    with pytest.raises(ProviderOutputIntegrityError, match="exact T20"):
        ProviderOutputHandoff(
            forged,
            engagement_id="eng.provider-output",
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )

    with output_state_store(tmp_path) as state:
        state.append_observation = lambda **_: None  # type: ignore[method-assign]
        try:
            with pytest.raises(ProviderOutputIntegrityError, match="capability"):
                ProviderOutputHandoff(
                    state,
                    engagement_id=state.engagement_id,
                    trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
                )
        finally:
            del state.append_observation


def test_handoff_rejects_hostile_cas_byte_ceiling_without_hooks(
    tmp_path: Path,
) -> None:
    hits = 0

    class HostileInt(int):
        def __eq__(self, other: object) -> bool:
            nonlocal hits
            hits += 1
            raise AssertionError("hostile CAS ceiling comparison executed")

    with output_state_store(tmp_path) as state:
        cas = state.cas
        original = cas.max_artifact_bytes
        cas.max_artifact_bytes = HostileInt(original)
        try:
            with pytest.raises(ProviderOutputIntegrityError, match="byte ceiling"):
                ProviderOutputHandoff(
                    state,
                    engagement_id=state.engagement_id,
                    trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
                )
            assert hits == 0
        finally:
            cas.max_artifact_bytes = original

        handoff = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        receipt = completed_receipt(b"post-admission-drift")
        cas.max_artifact_bytes = HostileInt(original)
        try:
            with pytest.raises(ProviderOutputIntegrityError, match="components"):
                handoff.publish(receipt, b"post-admission-drift")
            assert hits == 0
            assert state.checkpoint().seq == 0
        finally:
            cas.max_artifact_bytes = original


def test_rebound_capability_descriptors_are_not_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hits = 0

    class ExplosiveDescriptor:
        def __get__(self, *_: object) -> object:
            nonlocal hits
            hits += 1
            raise AssertionError("rebound capability descriptor executed")

    with output_state_store(tmp_path) as state:
        monkeypatch.setattr(
            StateStore,
            "append_observation",
            ExplosiveDescriptor(),
        )
        with pytest.raises(ProviderOutputIntegrityError, match="capability"):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            )
        assert hits == 0


def test_cursor_key_descriptor_rebind_is_not_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hits = 0

    class ExplosiveDescriptor:
        def __get__(self, *_: object) -> object:
            nonlocal hits
            hits += 1
            raise AssertionError("cursor key descriptor executed")

    with output_state_store(tmp_path) as state:
        monkeypatch.setattr(
            ProviderOutputCursorKey,
            "_copy_for_hmac",
            ExplosiveDescriptor(),
        )
        with pytest.raises(ProviderOutputIntegrityError, match="cursor key"):
            ProviderOutputReader(
                state,
                KEY,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            )
        assert hits == 0


@pytest.mark.parametrize(
    "media_type",
    [
        " application/json",
        "application/json ",
        "Application/JSON",
        "application/json\n",
        "application/json; charset=utf-8",
        "a/" + "b" * 64,
    ],
)
def test_handoff_rejects_noncanonical_media_type(
    tmp_path: Path,
    media_type: str,
) -> None:
    with output_state_store(tmp_path) as state:
        with pytest.raises(ValueError, match="media type"):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
                media_type=media_type,
            )


def test_handoff_rejects_output_ceiling_above_bounded_policy(
    tmp_path: Path,
) -> None:
    with output_state_store(tmp_path) as state:
        with pytest.raises(ValueError, match="maximum"):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
                maximum_output_bytes=1_048_577,
            )


def test_handoff_rejects_hostile_body_subclass(tmp_path: Path) -> None:
    class HostileBytes(bytes):
        pass

    body = b"exact-body"
    receipt = completed_receipt(body)
    with output_state_store(tmp_path) as state:
        with pytest.raises(ProviderOutputIntegrityError, match="exact bytes"):
            ProviderOutputHandoff(
                state,
                engagement_id=state.engagement_id,
                trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            ).publish(receipt, HostileBytes(body))


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
