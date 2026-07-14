from __future__ import annotations

import re
from typing import Literal

from faultloom.state import ProviderCanonicalReceipt, ProviderJournalEntry, ProviderReceiptMetadata

from .anchored_base import _AnchoredJournalBase
from .common import ProviderCallOutcome, ProviderReceiptError, RetryDisposition
from .receipt import ProviderCallReceipt

class _AnchoredJournalValidation(_AnchoredJournalBase):
    @staticmethod
    def _require_receipt_digest(value: object) -> str:
        if type(value) is not str or re.fullmatch(
            r"sha256:[0-9a-f]{64}", value
        ) is None:
            raise ProviderReceiptError("provider receipt digest is invalid")
        return value

    @staticmethod
    def _validated_receipt(receipt: object) -> ProviderCallReceipt:
        if type(receipt) is not ProviderCallReceipt:
            raise ProviderReceiptError(
                "anchored provider journal requires an exact provider receipt"
            )
        try:
            return ProviderCallReceipt.model_validate(
                receipt.model_dump(mode="python")
            )
        except Exception as exc:
            raise ProviderReceiptError("provider receipt is invalid") from exc

    @staticmethod
    def _metadata_for_receipt(
        receipt: ProviderCallReceipt,
    ) -> ProviderReceiptMetadata:
        request = receipt.proxy_request
        credential_ref = request.credential_ref
        runtime_version = request.runtime_version
        tokenizer_id = request.tokenizer_id
        tokenizer_version = request.tokenizer_version
        if (
            type(runtime_version) is not str
            or type(tokenizer_id) is not str
            or type(tokenizer_version) is not str
        ):
            raise ProviderReceiptError(
                "anchored provider journal requires exact runtime and tokenizer metadata"
            )
        try:
            return ProviderReceiptMetadata(
                call_id=receipt.call_id,
                attempt=receipt.attempt,
                attempt_id=receipt.attempt_id,
                provider_id=request.provider_id,
                endpoint_id=request.endpoint_id,
                profile_digest=receipt.profile_digest,
                requested_alias=request.requested_alias,
                exact_snapshot=request.model_snapshot,
                runtime_version=runtime_version,
                tokenizer_id=tokenizer_id,
                tokenizer_version=tokenizer_version,
                context_window=request.context_window,
                prompt_digest=request.prompt_digest,
                compiled_context_digest=request.compiled_context_digest,
                tool_schema_digest=request.tool_schema_digest,
                credential_ref_uri=credential_ref.uri,
                credential_ref_purpose=credential_ref.purpose,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt cannot form the canonical a4 projection"
            ) from exc

    @classmethod
    def _reservation_entry(
        cls,
        receipt: ProviderCallReceipt,
    ) -> ProviderJournalEntry:
        try:
            canonical = ProviderCanonicalReceipt.reserved(
                cls._metadata_for_receipt(receipt)
            )
            return ProviderJournalEntry.from_receipt(canonical)
        except ProviderReceiptError:
            raise
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt could not form an a4 reservation"
            ) from exc

    @classmethod
    def _entry_for_receipt(
        cls,
        receipt: object,
        *,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str | None,
    ) -> tuple[ProviderCallReceipt, ProviderJournalEntry]:
        validated = cls._validated_receipt(receipt)
        reservation = cls._reservation_entry(validated)
        if phase == "reserved":
            if (
                reservation_receipt_digest is not None
                or validated.proxy_result is not None
                or validated.proxy_receipt_digest is not None
                or validated.outcome is not ProviderCallOutcome.UNKNOWN_OUTCOME
                or validated.retry_disposition
                is not RetryDisposition.RECONCILIATION_REQUIRED
                or not validated.reconciliation_required
            ):
                raise ProviderReceiptError(
                    "dispatch reservation must be an unknown-outcome hold"
                )
            return validated, reservation
        if (
            reservation_receipt_digest != reservation.receipt_digest
            or validated.proxy_result is None
            or validated.proxy_receipt_digest is None
        ):
            raise ProviderReceiptError(
                "provider finalization requires its exact a4 reservation and signed result"
            )
        try:
            canonical = ProviderCanonicalReceipt.parse(
                reservation.canonical_receipt_json
            ).finalized(validated.proxy_receipt_digest)
            return validated, ProviderJournalEntry.from_receipt(canonical)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt could not form an a4 finalization"
            ) from exc
