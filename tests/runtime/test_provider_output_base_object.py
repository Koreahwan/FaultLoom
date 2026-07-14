from __future__ import annotations

from pathlib import Path

import pytest
from faultloom.provider_output import (
    ProviderOutputCursorKey,
    ProviderOutputHandoff,
    ProviderOutputIntegrityError,
    ProviderOutputPage,
    ProviderOutputReader,
    ProviderOutputScopeError,
)
from faultloom.provider_output._receipt import ProviderReceiptVerifier
from faultloom.provider_output._store import ProviderOutputStoreBinding
from faultloom_protocol import AuthoritySigner

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)

Capability = (
    ProviderOutputCursorKey
    | ProviderOutputPage
    | ProviderOutputHandoff
    | ProviderOutputReader
    | ProviderOutputStoreBinding
    | ProviderReceiptVerifier
)


def test_base_object_cannot_replace_handoff_admission(tmp_path: Path) -> None:
    body = b"base-object-handoff"
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
            maximum_output_bytes=1,
        )
        handoff_b = ProviderOutputHandoff(
            state_b,
            engagement_id=state_b.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            media_type="text/plain",
        )
        admission_b = handoff_b._trusted_admission()
        with pytest.raises(AttributeError):
            object.__setattr__(
                handoff_a,
                "_ProviderOutputHandoff__admission",
                admission_b,
            )
        with pytest.raises(ProviderOutputIntegrityError):
            handoff_a.publish(receipt, body)
        small_body = b"x"
        small_receipt = completed_receipt(
            small_body,
            run_id="run-base-object-handoff-small",
        )
        invocation_a = handoff_a.publish(small_receipt, small_body)
        assert invocation_a.output_ref.observation.media_type == "application/json"
        assert state_a.checkpoint().seq == 1
        assert state_b.checkpoint().seq == 0


def test_base_object_cannot_replace_reader_admission(tmp_path: Path) -> None:
    body = b"base-object-reader"
    receipt = completed_receipt(body)
    key = ProviderOutputCursorKey(bytes(range(32)))
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
        invocation_b = ProviderOutputHandoff(
            state_b,
            engagement_id=state_b.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        reader_a = ProviderOutputReader(
            state_a,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=1,
        )
        reader_b = ProviderOutputReader(
            state_b,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        )
        admission_b = reader_b._trusted_admission()
        with pytest.raises(AttributeError):
            object.__setattr__(
                reader_a,
                "_ProviderOutputReader__admission",
                admission_b,
            )
        invocation_a = ProviderOutputHandoff(
            state_a,
            engagement_id=state_a.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        with pytest.raises(ProviderOutputIntegrityError):
            reader_a.read_page(
                invocation_a,
                expected_engagement_id=state_a.engagement_id,
                expected_run_id=receipt.run_id,
                max_bytes=len(body),
            )
        with pytest.raises(ProviderOutputScopeError):
            reader_a.read_page(
                invocation_b,
                expected_engagement_id=state_b.engagement_id,
                expected_run_id=receipt.run_id,
                max_bytes=len(body),
            )


def test_base_object_cannot_replace_cursor_or_page_values() -> None:
    key = ProviderOutputCursorKey(bytes(range(32)))
    with pytest.raises(AttributeError):
        object.__setattr__(
            key,
            "_ProviderOutputCursorKey__material",
            bytes(reversed(range(32))),
        )
    assert key._copy_for_hmac() == bytes(range(32))
    page = ProviderOutputPage(
        b"safe",
        offset=0,
        total_bytes=4,
        next_cursor=None,
    )
    for name, value in (
        ("_ProviderOutputPage__data", b"evil"),
        ("_ProviderOutputPage__offset", 3),
        ("_ProviderOutputPage__total_bytes", 99),
        ("_ProviderOutputPage__next_cursor", "forged"),
    ):
        with pytest.raises(AttributeError):
            object.__setattr__(page, name, value)
    assert (page.data, page.offset, page.total_bytes, page.next_cursor) == (
        b"safe",
        0,
        4,
        None,
    )


def test_base_object_cannot_replace_store_binding(tmp_path: Path) -> None:
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
        binding_a = ProviderOutputStoreBinding(state_a)
        binding_b = ProviderOutputStoreBinding(state_b)
        admission_b = binding_b._trusted_admission()
        with pytest.raises(AttributeError):
            object.__setattr__(
                binding_a,
                "_ProviderOutputStoreBinding__admission",
                admission_b,
            )
        assert binding_a.engagement_id == state_a.engagement_id


def test_base_object_cannot_replace_receipt_trust_root() -> None:
    verifier_a = ProviderReceiptVerifier(TRUSTED_PROXY_KEY)
    other_key = AuthoritySigner.from_private_bytes(
        bytes(range(32, 64))
    ).public_key_record
    verifier_b = ProviderReceiptVerifier(other_key)
    admission_b = verifier_b._trusted_admission()
    with pytest.raises(AttributeError):
        object.__setattr__(
            verifier_a,
            "_ProviderReceiptVerifier__admission",
            admission_b,
        )
    assert verifier_a._trusted_admission().key_id == TRUSTED_PROXY_KEY.key_id


@pytest.mark.parametrize(
    "capability",
    (
        ProviderOutputCursorKey,
        ProviderOutputPage,
        ProviderOutputHandoff,
        ProviderOutputReader,
        ProviderOutputStoreBinding,
        ProviderReceiptVerifier,
    ),
)
def test_capability_instances_have_no_mutable_state_slot(
    capability: type[Capability],
) -> None:
    assert getattr(capability, "__slots__", None) == ("__weakref__",)
    with pytest.raises(ProviderOutputIntegrityError):
        type(f"Derived{capability.__name__}", (capability,), {})
