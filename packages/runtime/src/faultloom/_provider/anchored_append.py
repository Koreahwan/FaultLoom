from __future__ import annotations

import hashlib

from faultloom.state import ArtifactRef, EventRecord, ProviderJournalEntry

from .anchored_base import (
    _MAX_PROVIDER_RECEIPT_BYTES,
    _PROVIDER_RECEIPT_EVENT_TYPE,
    _PROVIDER_RECEIPT_MEDIA_TYPE,
)
from .anchored_receipts import _AnchoredJournalReceipts
from .common import (
    ProviderReceiptError,
    provider_canonical_json_bytes as canonical_json_bytes,
)
from .receipt import ProviderCallReceipt


class _AnchoredJournalAppend(_AnchoredJournalReceipts):
    def _append_companion(
        self,
        receipt: ProviderCallReceipt,
        entry: ProviderJournalEntry,
        *,
        journal_event_seq: int,
    ) -> None:
        checkpoint = self._refresh_checkpoint()
        existing = self._matching_events(
            checkpoint,
            entry_digest=entry.receipt_digest,
        )
        if existing:
            stored = self._receipt_for_entry(
                entry,
                checkpoint,
                journal_event_seq=journal_event_seq,
            )
            if stored != receipt:
                raise ProviderReceiptError(
                    "provider receipt encrypted companion replay changed"
                )
            return
        raw = canonical_json_bytes(receipt)
        if len(raw) > _MAX_PROVIDER_RECEIPT_BYTES:
            raise ProviderReceiptError(
                "provider receipt exceeds the encrypted companion limit"
            )
        try:
            event, reference = self._state_append_observation(
                actor_stream=self._actor(
                    entry.receipt_digest,
                    receipt.receipt_digest,
                ),
                event_type=_PROVIDER_RECEIPT_EVENT_TYPE,
                raw_output=raw,
                metadata=self._companion_metadata(receipt, entry),
                media_type=_PROVIDER_RECEIPT_MEDIA_TYPE,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt encrypted companion persistence failed closed"
            ) from exc
        if (
            type(event) is not EventRecord
            or type(reference) is not ArtifactRef
            or event.seq <= journal_event_seq
            or event.actor_stream
            != self._actor(entry.receipt_digest, receipt.receipt_digest)
            or event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE
            or reference.engagement_id != self._engagement_id
            or reference.media_type != _PROVIDER_RECEIPT_MEDIA_TYPE
            or reference.byte_length != len(raw)
            or reference.sha256 != hashlib.sha256(raw).hexdigest()
        ):
            raise ProviderReceiptError(
                "provider receipt encrypted companion readback changed"
            )
        checkpoint = self._refresh_checkpoint()
        stored = self._receipt_for_entry(
            entry,
            checkpoint,
            journal_event_seq=journal_event_seq,
        )
        if stored != receipt:
            raise ProviderReceiptError(
                "provider receipt encrypted companion readback changed"
            )
