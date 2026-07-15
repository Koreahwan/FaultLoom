from __future__ import annotations

import hmac

from faultloom_protocol import Ed25519PublicKeyRecord

from .adapter_call import _ProviderAdapterCall
from .adapter_helpers import _decode_ed25519_signature
from .common import ProviderPlane, ProviderPlaneError, ProviderReceiptError
from .proxy import (
    ProviderProxyRequest,
    ProviderProxyResult,
    provider_proxy_result_attestation_bytes,
)
from .receipt import ProviderCallReceipt


class _ProviderAdapterProxy(_ProviderAdapterCall):
    @staticmethod
    def _validated_journal_receipt(receipt: object) -> ProviderCallReceipt:
        try:
            return ProviderCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except Exception as exc:
            raise ProviderReceiptError("provider journal returned an invalid receipt") from exc

    def _validate_attempt_lookup(
        self,
        receipt: object,
        *,
        call_id: str,
        attempt: int,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if validated.call_id != call_id or validated.attempt != attempt:
            raise ProviderReceiptError("provider journal attempt lookup is not key-bound")
        return validated

    def _validate_digest_lookup(
        self,
        receipt: object,
        receipt_digest: str,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if not hmac.compare_digest(validated.receipt_digest, receipt_digest):
            raise ProviderReceiptError("provider journal digest lookup is not key-bound")
        return validated

    def _validate_attempt_id_lookup(
        self,
        receipt: object,
        attempt_id: str,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if validated.attempt_id != attempt_id:
            raise ProviderReceiptError("provider journal attempt-ID lookup is not key-bound")
        return validated

    def _validate_reservation_readback(
        self,
        reservation: ProviderCallReceipt,
    ) -> None:
        by_digest = self._journal_by_digest(reservation.receipt_digest)
        by_attempt = self._journal_by_attempt(
            reservation.call_id,
            reservation.attempt,
        )
        by_attempt_id = self._journal_by_attempt_id(reservation.attempt_id)
        if by_digest is None or by_attempt is None or by_attempt_id is None:
            raise ProviderReceiptError(
                "provider journal did not persist the dispatch reservation"
            )
        validated = (
            self._validate_digest_lookup(by_digest, reservation.receipt_digest),
            self._validate_attempt_lookup(
                by_attempt,
                call_id=reservation.call_id,
                attempt=reservation.attempt,
            ),
            self._validate_attempt_id_lookup(by_attempt_id, reservation.attempt_id),
        )
        if any(
            not hmac.compare_digest(
                candidate.receipt_digest,
                reservation.receipt_digest,
            )
            for candidate in validated
        ):
            raise ProviderReceiptError(
                "provider journal reservation indexes are not atomic"
            )

    def _validate_terminal_readback(
        self,
        reservation_receipt_digest: str,
        terminal: ProviderCallReceipt,
    ) -> None:
        reservation = self._journal_by_digest(reservation_receipt_digest)
        by_digest = self._journal_by_digest(terminal.receipt_digest)
        by_attempt = self._journal_by_attempt(terminal.call_id, terminal.attempt)
        by_attempt_id = self._journal_by_attempt_id(terminal.attempt_id)
        if (
            reservation is None
            or by_digest is None
            or by_attempt is None
            or by_attempt_id is None
        ):
            raise ProviderReceiptError(
                "provider journal did not persist its terminal transition"
            )
        self._validate_digest_lookup(reservation, reservation_receipt_digest)
        validated = (
            self._validate_digest_lookup(by_digest, terminal.receipt_digest),
            self._validate_attempt_lookup(
                by_attempt,
                call_id=terminal.call_id,
                attempt=terminal.attempt,
            ),
            self._validate_attempt_id_lookup(by_attempt_id, terminal.attempt_id),
        )
        if any(
            not hmac.compare_digest(
                candidate.receipt_digest,
                terminal.receipt_digest,
            )
            for candidate in validated
        ):
            raise ProviderReceiptError(
                "provider journal terminal indexes are not atomic"
            )

    def _validate_result_attestation(
        self,
        result: ProviderProxyResult,
        *,
        proxy_request: ProviderProxyRequest,
        proxy_request_digest: str,
    ) -> None:
        if (
            result.request_id != proxy_request.request_id
            or not hmac.compare_digest(
                result.proxy_request_digest,
                proxy_request_digest,
            )
        ):
            raise ProviderPlaneError("provider proxy attestation is not request-bound")
        if result.attestation_key_id != proxy_request.proxy_attestation_key_id:
            raise ProviderPlaneError("provider proxy attestation identity does not match")
        self._verify_proxy_result_attestation(result)

    def _verify_proxy_result_attestation(self, result: ProviderProxyResult) -> None:
        if (
            result.attested_proxy_id != self._proxy_id
            or not hmac.compare_digest(
                result.attested_proxy_contract_digest,
                self._proxy_contract_digest,
            )
            or result.attestation_key_id != self._proxy_attestation_record.key_id
        ):
            raise ProviderPlaneError("provider proxy attestation identity does not match")
        signature = _decode_ed25519_signature(result.attestation_signature)
        try:
            self._proxy_attestation_public_key.verify(
                signature,
                provider_proxy_result_attestation_bytes(result),
            )
        except Exception as exc:
            raise ProviderPlaneError("provider proxy result attestation is invalid") from exc

    def _proxy_binding_matches(self) -> bool:
        current_dispatch = getattr(self._proxy, "dispatch", None)
        current_attestation_key = getattr(self._proxy, "attestation_public_key", None)
        try:
            current_attestation_key = Ed25519PublicKeyRecord.model_validate(
                current_attestation_key.model_dump(mode="python")
            )
        except Exception:
            return False
        return bool(
            getattr(self._proxy, "plane", None) is ProviderPlane.MODEL_PROVIDER
            and getattr(self._proxy, "proxy_id", None) == self._proxy_id
            and getattr(self._proxy, "contract_digest", None)
            == self._proxy_contract_digest
            and current_attestation_key == self._proxy_attestation_record
            and getattr(current_dispatch, "__self__", None)
            is self._proxy_dispatch_owner
            and getattr(current_dispatch, "__func__", current_dispatch)
            is self._proxy_dispatch_function
        )
