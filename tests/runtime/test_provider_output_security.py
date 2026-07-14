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
from faultloom.state import StateStore

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)
from tests.runtime.provider_output_security_cases import (
    test_handoff_rejects_rehashed_stale_proxy_attestation,
    test_reader_independently_rejects_untrusted_proxy_attestation_key,
    test_reader_rejects_forged_output_reference,
    test_cursor_rejects_wrong_key_and_page_cannot_pickle,
    test_ciphertext_tamper_blocks_plaintext_page,
    test_ciphertext_tamper_blocks_recovered_reference,
    test_offline_handoff_never_calls_network_or_subprocess,
    test_public_result_has_no_body_or_storage_capability,
)

__all__ = [
    "test_handoff_rejects_rehashed_stale_proxy_attestation",
    "test_reader_independently_rejects_untrusted_proxy_attestation_key",
    "test_reader_rejects_forged_output_reference",
    "test_cursor_rejects_wrong_key_and_page_cannot_pickle",
    "test_ciphertext_tamper_blocks_plaintext_page",
    "test_ciphertext_tamper_blocks_recovered_reference",
    "test_offline_handoff_never_calls_network_or_subprocess",
    "test_public_result_has_no_body_or_storage_capability",
]


KEY = ProviderOutputCursorKey(bytes(range(32)))


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
