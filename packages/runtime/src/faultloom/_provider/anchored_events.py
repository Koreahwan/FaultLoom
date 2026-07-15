from __future__ import annotations

from faultloom.state import AnchorCheckpoint, ArtifactRef, EventRecord, ProviderJournalEntry

from .anchored_base import (
    _PROVIDER_EVENT_PAGE,
    _PROVIDER_RECEIPT_EVENT_TYPE,
)
from .anchored_state import _AnchoredJournalState
from .common import ProviderReceiptError, SCHEMA_VERSION
from .receipt import ProviderCallReceipt

class _AnchoredJournalEvents(_AnchoredJournalState):
    def _events_through(
        self,
        checkpoint: AnchorCheckpoint,
    ) -> tuple[EventRecord, ...]:
        self._verify_components()
        records: list[EventRecord] = []
        after_seq = 0
        while after_seq < checkpoint.seq:
            try:
                batch = self._ledger_events(
                    after_seq=after_seq,
                    limit=min(_PROVIDER_EVENT_PAGE, checkpoint.seq - after_seq),
                )
            except Exception as exc:
                raise ProviderReceiptError(
                    "provider receipt companion event read failed closed"
                ) from exc
            if type(batch) is not tuple or not batch:
                raise ProviderReceiptError(
                    "provider receipt companion event history is incomplete"
                )
            advanced = after_seq
            for event in batch:
                if type(event) is not EventRecord:
                    raise ProviderReceiptError(
                        "provider receipt companion event is invalid"
                    )
                if event.seq > checkpoint.seq:
                    break
                if event.engagement_id != self._engagement_id:
                    raise ProviderReceiptError(
                        "provider receipt companion crossed engagements"
                    )
                records.append(event)
                advanced = event.seq
            if advanced <= after_seq:
                raise ProviderReceiptError(
                    "provider receipt companion event history did not advance"
                )
            after_seq = advanced
        return tuple(records)

    def _matching_events(
        self,
        checkpoint: AnchorCheckpoint,
        *,
        entry_digest: str | None = None,
        receipt_digest: str | None = None,
    ) -> tuple[EventRecord, ...]:
        if entry_digest is not None:
            entry_digest = self._require_receipt_digest(entry_digest)
        if receipt_digest is not None:
            receipt_digest = self._require_receipt_digest(receipt_digest)
        matches: list[EventRecord] = []
        for event in self._events_through(checkpoint):
            if event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE:
                continue
            receipt, entry = self._receipt_from_event(event)
            if (
                (entry_digest is None or entry.receipt_digest == entry_digest)
                and (
                    receipt_digest is None
                    or receipt.receipt_digest == receipt_digest
                )
            ):
                matches.append(event)
        return tuple(matches)

    def _companion_metadata(
        self,
        receipt: ProviderCallReceipt,
        entry: ProviderJournalEntry,
    ) -> dict[str, object]:
        return {
            "call_receipt_digest": receipt.receipt_digest,
            "engagement_id": self._engagement_id,
            "journal_receipt_digest": entry.receipt_digest,
            "phase": entry.phase,
            "purpose": "faultloom.provider-call-receipt.companion.v1",
            "schema_version": SCHEMA_VERSION,
        }

    @staticmethod
    def _artifact_ref(value: object) -> ArtifactRef:
        if type(value) is not dict or set(value) != {
            "engagement_id",
            "sha256",
            "byte_length",
            "media_type",
            "schema_version",
        }:
            raise ProviderReceiptError(
                "provider receipt companion artifact reference is invalid"
            )
        try:
            return ArtifactRef(
                engagement_id=value["engagement_id"],
                sha256=value["sha256"],
                byte_length=value["byte_length"],
                media_type=value["media_type"],
                schema_version=value["schema_version"],
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion artifact reference is invalid"
            ) from exc
