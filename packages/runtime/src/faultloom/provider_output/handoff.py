from __future__ import annotations

import hashlib
from typing import NamedTuple, NoReturn, final

from faultloom.provider import ProviderCallReceipt
from faultloom.state import StateStore
from faultloom_protocol import Ed25519PublicKeyRecord

from ._events import invocation_from_event
from ._receipt import ProviderReceiptVerifier
from ._store import ProviderOutputStoreBinding
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


@final
class ProviderOutputHandoff:
    __slots__ = ("__admission",)
    __admission: _HandoffAdmission

    def __init__(
        self,
        state: StateStore,
        *,
        engagement_id: str,
        trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
        media_type: str = "application/json",
        maximum_output_bytes: int = 1024 * 1024,
    ) -> None:
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
        self.__admission = _HandoffAdmission(
            binding,
            require_media_type(media_type),
            maximum_output_bytes,
            ProviderReceiptVerifier(trusted_proxy_attestation_key),
        )

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_ProviderOutputHandoff__admission":
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                object.__setattr__(self, name, value)
                return
        raise AttributeError("ProviderOutputHandoff is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputHandoff is immutable")

    def _trusted_admission(self) -> _HandoffAdmission:
        admission = object.__getattribute__(
            self,
            "_ProviderOutputHandoff__admission",
        )
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
        admission.binding.validate()
        if (
            media_type != admission.media_type
            or admission.maximum_output_bytes
            > admission.binding.max_artifact_bytes
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
        admission = self._trusted_admission()
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
        with binding.lock():
            binding.verify()
            event = binding.find(validated)
            if event is None:
                binding.append(
                    validated,
                    raw_output,
                    media_type=admission.media_type,
                )
                event = binding.find(validated)
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
        admission = self._trusted_admission()
        validated = _VERIFY_RECEIPT(admission.verifier, receipt)
        binding = admission.binding
        with binding.lock():
            binding.verify()
            event = binding.find(validated)
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
