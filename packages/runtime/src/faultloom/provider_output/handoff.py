from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import TYPE_CHECKING, NamedTuple, NoReturn, final
from weakref import ReferenceType

from faultloom.provider import ProviderCallReceipt
from faultloom.state import StateStore
from faultloom_protocol import Ed25519PublicKeyRecord

from ._events import invocation_from_event
from ._receipt import ProviderReceiptVerifier
from ._store import ProviderOutputStoreBinding
from ._vault import identity_vault
from .contracts import (
    ProviderInvocationResult,
    ProviderOutputIntegrityError,
    ProviderOutputScopeError,
    require_media_type,
)

MAX_OUTPUT_BYTES = 1024 * 1024
_VERIFY_RECEIPT = ProviderReceiptVerifier.validate


class _HandoffAdmission(NamedTuple):
    binding: ProviderOutputStoreBinding
    media_type: str
    maximum_output_bytes: int
    verifier: ProviderReceiptVerifier


_handoff_vault: tuple[
    Callable[[ProviderOutputHandoff, _HandoffAdmission], None],
    Callable[[ProviderOutputHandoff], _HandoffAdmission],
] = identity_vault(
    "provider output handoff"
)
_bind_handoff, _read_handoff = _handoff_vault


@final
class ProviderOutputHandoff:
    __slots__ = ("__weakref__",)

    def __init_subclass__(cls) -> None:
        raise ProviderOutputIntegrityError("ProviderOutputHandoff is final")

    def __init__(
        self,
        state: StateStore,
        *,
        engagement_id: str,
        trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
        media_type: str = "application/json",
        maximum_output_bytes: int = 1024 * 1024,
    ) -> None:
        if TYPE_CHECKING:
            self.__weakref__: ReferenceType[ProviderOutputHandoff] | None = None
        binding = ProviderOutputStoreBinding(state)
        if type(engagement_id) is not str or engagement_id != binding.engagement_id:
            raise ProviderOutputScopeError(
                "provider output engagement does not match the StateStore"
            )
        if (
            type(maximum_output_bytes) is not int
            or not 1 <= maximum_output_bytes <= min(
                binding.max_artifact_bytes,
                MAX_OUTPUT_BYTES,
            )
        ):
            raise ValueError("provider output maximum byte count is invalid")
        _bind_handoff(
            self,
            _HandoffAdmission(
                binding,
                require_media_type(media_type),
                maximum_output_bytes,
                ProviderReceiptVerifier(trusted_proxy_attestation_key),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ProviderOutputHandoff is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputHandoff is immutable")

    def _trusted_admission(self) -> _HandoffAdmission:
        admission = _read_handoff(self)
        if (
            type(admission) is not _HandoffAdmission
            or type(admission.binding) is not ProviderOutputStoreBinding
            or type(admission.verifier) is not ProviderReceiptVerifier
            or type(admission.maximum_output_bytes) is not int
            or not 1 <= admission.maximum_output_bytes <= MAX_OUTPUT_BYTES
        ):
            raise ProviderOutputIntegrityError(
                "provider output handoff admission changed"
            )
        try:
            media_type = require_media_type(admission.media_type)
        except (TypeError, ValueError) as exc:
            raise ProviderOutputIntegrityError(
                "provider output handoff admission changed"
            ) from exc
        binding_admission = ProviderOutputStoreBinding._trusted_admission(
            admission.binding
        )
        ProviderOutputStoreBinding.validate(admission.binding)
        if (
            media_type != admission.media_type
            or admission.maximum_output_bytes
            > binding_admission.max_artifact_bytes
        ):
            raise ProviderOutputIntegrityError(
                "provider output handoff admission changed"
            )
        return admission

    def publish(
        self,
        receipt: ProviderCallReceipt,
        raw_output: bytes,
    ) -> ProviderInvocationResult:
        admission = ProviderOutputHandoff._trusted_admission(self)
        validated = _VERIFY_RECEIPT(admission.verifier, receipt)
        if type(raw_output) is not bytes:
            raise ProviderOutputIntegrityError(
                "provider output body must be exact bytes"
            )
        if len(raw_output) > admission.maximum_output_bytes:
            raise ProviderOutputIntegrityError(
                "provider output exceeds the configured maximum"
            )
        calculated = f"sha256:{hashlib.sha256(raw_output).hexdigest()}"
        if (
            calculated != validated.response_digest
            or len(raw_output) != validated.bytes_received
        ):
            raise ProviderOutputIntegrityError(
                "provider output digest or byte length does not match its receipt"
            )
        binding = admission.binding
        with ProviderOutputStoreBinding.lock(binding):
            ProviderOutputStoreBinding.verify(binding)
            event = ProviderOutputStoreBinding.find(binding, validated)
            if event is None:
                ProviderOutputStoreBinding.append(
                    binding,
                    validated,
                    raw_output,
                    media_type=admission.media_type,
                )
                event = ProviderOutputStoreBinding.find(binding, validated)
            if event is None:
                raise ProviderOutputIntegrityError(
                    "provider output publication was not durable"
                )
            return invocation_from_event(
                binding,
                validated,
                event,
                media_type=admission.media_type,
            )

    def recover(
        self,
        receipt: ProviderCallReceipt,
    ) -> ProviderInvocationResult | None:
        admission = ProviderOutputHandoff._trusted_admission(self)
        validated = _VERIFY_RECEIPT(admission.verifier, receipt)
        binding = admission.binding
        with ProviderOutputStoreBinding.lock(binding):
            ProviderOutputStoreBinding.verify(binding)
            event = ProviderOutputStoreBinding.find(binding, validated)
            return (
                None
                if event is None
                else invocation_from_event(
                    binding,
                    validated,
                    event,
                    media_type=admission.media_type,
                )
            )
