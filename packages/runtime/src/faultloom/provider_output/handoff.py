from __future__ import annotations

import hashlib

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


class ProviderOutputHandoff:
    __slots__ = (
        "_binding",
        "_maximum_output_bytes",
        "_media_type",
        "_receipt_verifier",
    )

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
        self._binding = binding
        self._media_type = require_media_type(media_type)
        self._maximum_output_bytes = maximum_output_bytes
        self._receipt_verifier = ProviderReceiptVerifier(
            trusted_proxy_attestation_key
        )

    def publish(
        self,
        receipt: ProviderCallReceipt,
        raw_output: bytes,
    ) -> ProviderInvocationResult:
        validated = self._validated_receipt(receipt)
        if type(raw_output) is not bytes:
            raise ProviderOutputIntegrityError(
                "provider output body must be exact bytes"
            )
        if len(raw_output) > self._maximum_output_bytes:
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
        binding = self._binding
        with binding.lock():
            binding.verify()
            event = binding.find(validated)
            if event is None:
                binding.append(
                    validated,
                    raw_output,
                    media_type=self._media_type,
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
                media_type=self._media_type,
            )

    def recover(
        self,
        receipt: ProviderCallReceipt,
    ) -> ProviderInvocationResult | None:
        validated = self._validated_receipt(receipt)
        binding = self._binding
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
                    media_type=self._media_type,
                )
            )

    def _validated_receipt(
        self,
        receipt: ProviderCallReceipt,
    ) -> ProviderCallReceipt:
        verifier = self._receipt_verifier
        if type(verifier) is not ProviderReceiptVerifier:
            raise ProviderOutputIntegrityError(
                "provider output receipt verifier capability changed"
            )
        return _VERIFY_RECEIPT(verifier, receipt)
