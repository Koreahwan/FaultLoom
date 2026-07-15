from __future__ import annotations

import hashlib
import hmac

from faultloom.state import AnchorCheckpoint, EventRecord, ProviderJournalEntry

from .anchored_base import (
    _MAX_PROVIDER_RECEIPT_BYTES,
    _MAX_PROVIDER_RECEIPT_METADATA_BYTES,
    _PROVIDER_RECEIPT_EVENT_TYPE,
    _PROVIDER_RECEIPT_MEDIA_TYPE,
    _PROVIDER_RECEIPT_METADATA_MEDIA_TYPE,
)
from .anchored_events import _AnchoredJournalEvents
from .common import (
    ProviderReceiptError,
    provider_canonical_json_bytes as canonical_json_bytes,
)
from .receipt import ProviderCallReceipt


class _AnchoredJournalReceipts(_AnchoredJournalEvents):
    def _receipt_from_event(
        self,
        event: EventRecord,
    ) -> tuple[ProviderCallReceipt, ProviderJournalEntry]:
        if (
            type(event) is not EventRecord
            or event.engagement_id != self._engagement_id
            or event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE
        ):
            raise ProviderReceiptError(
                "provider receipt companion event identity is invalid"
            )
        self._actor_binding(event.actor_stream)
        payload = event.payload
        if type(payload) is not dict or set(payload) != {
            "artifact_ref",
            "metadata_ref",
            "metadata_schema_version",
        } or payload["metadata_schema_version"] != 1:
            raise ProviderReceiptError(
                "provider receipt companion event payload is invalid"
            )
        reference = self._artifact_ref(payload["artifact_ref"])
        metadata_reference = self._artifact_ref(payload["metadata_ref"])
        if (
            reference.engagement_id != self._engagement_id
            or metadata_reference.engagement_id != self._engagement_id
            or reference.media_type != _PROVIDER_RECEIPT_MEDIA_TYPE
            or reference.byte_length > _MAX_PROVIDER_RECEIPT_BYTES
            or metadata_reference.media_type
            != _PROVIDER_RECEIPT_METADATA_MEDIA_TYPE
            or metadata_reference.byte_length
            > _MAX_PROVIDER_RECEIPT_METADATA_BYTES
        ):
            raise ProviderReceiptError(
                "provider receipt companion artifact binding is invalid"
            )
        try:
            raw = self._cas_get(reference)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion decryption failed closed"
            ) from exc
        if (
            type(raw) is not bytes
            or len(raw) != reference.byte_length
            or hashlib.sha256(raw).hexdigest() != reference.sha256
        ):
            raise ProviderReceiptError(
                "provider receipt companion bytes are invalid"
            )
        try:
            receipt = ProviderCallReceipt.model_validate_json(raw)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion is invalid"
            ) from exc
        if canonical_json_bytes(receipt) != raw:
            raise ProviderReceiptError(
                "provider receipt companion is not canonical"
            )
        reservation = self._reservation_entry(receipt)
        if receipt.proxy_result is None:
            _, entry = self._entry_for_receipt(
                receipt,
                phase="reserved",
                reservation_receipt_digest=None,
            )
        else:
            _, entry = self._entry_for_receipt(
                receipt,
                phase="finalized",
                reservation_receipt_digest=reservation.receipt_digest,
            )
        if not hmac.compare_digest(
            event.actor_stream,
            self._actor(entry.receipt_digest, receipt.receipt_digest),
        ):
            raise ProviderReceiptError(
                "provider receipt companion actor changed"
            )
        try:
            metadata_raw = self._cas_get(metadata_reference)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion metadata decryption failed closed"
            ) from exc
        expected_metadata = canonical_json_bytes(
            {
                "schema_version": 1,
                "values": self._companion_metadata(receipt, entry),
            }
        )
        if (
            type(metadata_raw) is not bytes
            or len(metadata_raw) != metadata_reference.byte_length
            or hashlib.sha256(metadata_raw).hexdigest()
            != metadata_reference.sha256
            or not hmac.compare_digest(metadata_raw, expected_metadata)
        ):
            raise ProviderReceiptError(
                "provider receipt companion metadata changed"
            )
        return receipt, entry

    def _receipt_for_entry(
        self,
        entry: ProviderJournalEntry,
        checkpoint: AnchorCheckpoint,
        *,
        journal_event_seq: int,
    ) -> ProviderCallReceipt:
        events = self._matching_events(
            checkpoint,
            entry_digest=entry.receipt_digest,
        )
        if len(events) != 1 or events[0].seq <= journal_event_seq:
            raise ProviderReceiptError(
                "provider receipt encrypted companion is missing or ambiguous"
            )
        receipt, expected = self._receipt_from_event(events[0])
        if expected != entry:
            raise ProviderReceiptError(
                "provider receipt encrypted companion changed its projection"
            )
        return receipt

    def _validated_record(self, record: object) -> ProviderCallReceipt:
        entry, anchor, event_seq = self._validated_state_record(record)
        return self._receipt_for_entry(
            entry,
            anchor,
            journal_event_seq=event_seq,
        )
