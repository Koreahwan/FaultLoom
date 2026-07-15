from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, final
from weakref import ReferenceType

import pytest
from faultloom.provider import ProviderCallReceipt
from faultloom.provider_output import (
    ProviderOutputCursorKey,
    ProviderOutputHandoff,
    ProviderOutputIntegrityError,
    ProviderOutputPage,
    ProviderOutputReader,
)
from faultloom.provider_output._immutable import _PageValue
from faultloom.provider_output._reader_admission import ReaderAdmission
from faultloom.provider_output._receipt import (
    ProviderReceiptVerifier,
    _VerifierAdmission,
)
from faultloom.provider_output._store import ProviderOutputStoreBinding
from faultloom.provider_output._store_support import StoreAdmission
from faultloom.provider_output.handoff import _HandoffAdmission
from faultloom_protocol import AuthoritySigner

from tests.runtime import (
    provider_test_fixtures,
    provider_test_results,
    provider_test_runtime,
)
from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
    output_state_store,
)


def _foreign_receipt(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> tuple[AuthoritySigner, ProviderCallReceipt]:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    monkeypatch.setattr(provider_test_results, "PROXY_SIGNER", signer)
    monkeypatch.setattr(provider_test_runtime, "PROXY_SIGNER", signer)
    monkeypatch.setattr(provider_test_fixtures, "PROXY_SIGNER", signer)
    monkeypatch.setattr(
        provider_test_runtime.FakeProxy,
        "attestation_public_key",
        signer.public_key_record,
    )
    return signer, completed_receipt(
        body,
        run_id="run-unbound-dispatch-foreign",
    )


def test_original_page_properties_reject_class_drift() -> None:
    @final
    class PageDispatch:
        __slots__ = ("__weakref__",)
        value: ClassVar[_PageValue] = _PageValue(b"forged", None, 0, 6)

        def __init__(self) -> None:
            if TYPE_CHECKING:
                self.__weakref__: ReferenceType[PageDispatch] | None = None

        def _trusted_value(self) -> _PageValue:
            return type(self).value

    page = ProviderOutputPage(b"safe", offset=0, total_bytes=4, next_cursor=None)
    object.__setattr__(page, "__class__", PageDispatch)
    getters = (
        ProviderOutputPage.data.fget,
        ProviderOutputPage.offset.fget,
        ProviderOutputPage.total_bytes.fget,
        ProviderOutputPage.next_cursor.fget,
    )
    try:
        for getter in getters:
            assert getter is not None
            with pytest.raises(ProviderOutputIntegrityError):
                getter(page)
        with pytest.raises(ProviderOutputIntegrityError):
            ProviderOutputPage.__repr__(page)
    finally:
        object.__setattr__(page, "__class__", ProviderOutputPage)


def test_original_verifier_rejects_class_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"unbound-verifier"
    signer, receipt = _foreign_receipt(monkeypatch, body)
    verifier = ProviderReceiptVerifier(TRUSTED_PROXY_KEY)
    foreign = ProviderReceiptVerifier(signer.public_key_record)

    @final
    class VerifierDispatch:
        __slots__ = ("__weakref__",)
        admission: ClassVar[_VerifierAdmission] = foreign._trusted_admission()

        def __init__(self) -> None:
            if TYPE_CHECKING:
                self.__weakref__: ReferenceType[VerifierDispatch] | None = None

        def _trusted_admission(self) -> _VerifierAdmission:
            return type(self).admission

    object.__setattr__(verifier, "__class__", VerifierDispatch)
    try:
        with pytest.raises(ProviderOutputIntegrityError):
            ProviderReceiptVerifier.validate(verifier, receipt)
    finally:
        object.__setattr__(verifier, "__class__", ProviderReceiptVerifier)


def test_original_store_boundaries_reject_class_drift(
    tmp_path: Path,
) -> None:
    body = b"unbound-store"
    receipt = completed_receipt(body, run_id="run-unbound-store")
    with (
        output_state_store(tmp_path / "a", engagement_id="eng.unbound-a") as state_a,
        output_state_store(tmp_path / "b", engagement_id="eng.unbound-b") as state_b,
    ):
        ProviderOutputHandoff(
            state_b,
            engagement_id=state_b.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, body)
        binding_a = ProviderOutputStoreBinding(state_a)
        binding_b = ProviderOutputStoreBinding(state_b)
        admission_b = binding_b._trusted_admission()
        reference = binding_b.references()[0]

        @final
        class StoreDispatch:
            __slots__ = ("__weakref__",)
            admission: ClassVar[StoreAdmission] = admission_b

            def __init__(self) -> None:
                if TYPE_CHECKING:
                    self.__weakref__: ReferenceType[StoreDispatch] | None = None

            def _trusted_admission(self) -> StoreAdmission:
                return type(self).admission

        engagement_getter = ProviderOutputStoreBinding.engagement_id.fget
        maximum_getter = ProviderOutputStoreBinding.max_artifact_bytes.fget
        assert engagement_getter is not None
        assert maximum_getter is not None
        operations = (
            lambda: engagement_getter(binding_a),
            lambda: maximum_getter(binding_a),
            lambda: ProviderOutputStoreBinding.validate(binding_a),
            lambda: ProviderOutputStoreBinding.lock(binding_a),
            lambda: ProviderOutputStoreBinding.verify(binding_a),
            lambda: ProviderOutputStoreBinding.ledger(binding_a),
            lambda: ProviderOutputStoreBinding.cas(binding_a),
            lambda: ProviderOutputStoreBinding.find(binding_a, receipt),
            lambda: ProviderOutputStoreBinding.append(
                binding_a,
                receipt,
                body,
                media_type="application/json",
            ),
            lambda: ProviderOutputStoreBinding.references(binding_a),
            lambda: ProviderOutputStoreBinding.read_page(
                binding_a,
                reference,
                cursor=None,
                max_bytes=1,
            ),
            lambda: ProviderOutputStoreBinding.verify_artifact(
                binding_a,
                reference,
            ),
        )
        object.__setattr__(binding_a, "__class__", StoreDispatch)
        try:
            for operation in operations:
                with pytest.raises(ProviderOutputIntegrityError):
                    operation()
        finally:
            object.__setattr__(
                binding_a,
                "__class__",
                ProviderOutputStoreBinding,
            )
        assert state_a.checkpoint().seq == 0
        assert state_b.checkpoint().seq == 1


def test_original_handoff_and_reader_reject_class_drift_before_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"unbound-handoff-reader"
    signer, receipt = _foreign_receipt(monkeypatch, body)
    with (
        output_state_store(tmp_path / "a", engagement_id="eng.unbound-a") as state_a,
        output_state_store(tmp_path / "b", engagement_id="eng.unbound-b") as state_b,
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
            trusted_proxy_attestation_key=signer.public_key_record,
            media_type="text/plain",
            maximum_output_bytes=len(body),
        )

        @final
        class HandoffDispatch:
            __slots__ = ("__weakref__",)
            admission: ClassVar[_HandoffAdmission] = handoff_b._trusted_admission()

            def __init__(self) -> None:
                if TYPE_CHECKING:
                    self.__weakref__: ReferenceType[HandoffDispatch] | None = None

            def _trusted_admission(self) -> _HandoffAdmission:
                return type(self).admission

        object.__setattr__(handoff_a, "__class__", HandoffDispatch)
        try:
            with pytest.raises(ProviderOutputIntegrityError):
                ProviderOutputHandoff.publish(handoff_a, receipt, body)
            with pytest.raises(ProviderOutputIntegrityError):
                ProviderOutputHandoff.recover(handoff_a, receipt)
        finally:
            object.__setattr__(handoff_a, "__class__", ProviderOutputHandoff)
        assert state_a.checkpoint().seq == 0
        assert state_b.checkpoint().seq == 0

        invocation_b = handoff_b.publish(receipt, body)
        key = ProviderOutputCursorKey(bytes(range(32)))
        reader_a = ProviderOutputReader(
            state_a,
            key,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
            maximum_page_bytes=1,
        )
        reader_b = ProviderOutputReader(
            state_b,
            key,
            trusted_proxy_attestation_key=signer.public_key_record,
            maximum_page_bytes=len(body),
        )

        @final
        class ReaderDispatch:
            __slots__ = ("__weakref__",)
            admission: ClassVar[ReaderAdmission] = reader_b._trusted_admission()

            def __init__(self) -> None:
                if TYPE_CHECKING:
                    self.__weakref__: ReferenceType[ReaderDispatch] | None = None

            def _trusted_admission(self) -> ReaderAdmission:
                return type(self).admission

        object.__setattr__(reader_a, "__class__", ReaderDispatch)
        try:
            with pytest.raises(ProviderOutputIntegrityError):
                ProviderOutputReader.read_page(
                    reader_a,
                    invocation_b,
                    expected_engagement_id=state_b.engagement_id,
                    expected_run_id=receipt.run_id,
                    max_bytes=len(body),
                )
        finally:
            object.__setattr__(reader_a, "__class__", ProviderOutputReader)
