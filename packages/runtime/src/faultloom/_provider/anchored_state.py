from __future__ import annotations

import hashlib
import re

from faultloom.state import (
    AnchorCheckpoint,
    EncryptedCAS,
    EventLedger,
    ProviderCanonicalReceipt,
    ProviderJournalEntry,
    ProviderJournalRecord,
)

from .anchored_base import _PROVIDER_RECEIPT_ACTOR_PREFIX
from .anchored_validation import _AnchoredJournalValidation
from .common import ProviderReceiptError


class _AnchoredJournalState(_AnchoredJournalValidation):
    def _verify_components(self) -> None:
        if (
            getattr(self._state_store, "ledger", None) is not self._ledger
            or getattr(self._state_store, "cas", None) is not self._cas
            or getattr(self._ledger_events, "__self__", None) is not self._ledger
            or getattr(self._ledger_events, "__func__", None)
            is not EventLedger.events
            or getattr(self._cas_get, "__self__", None) is not self._cas
            or getattr(self._cas_get, "__func__", None) is not EncryptedCAS.get
        ):
            raise ProviderReceiptError(
                "anchored provider journal encrypted state capability changed"
            )

    def _refresh_checkpoint(self) -> AnchorCheckpoint:
        self._verify_components()
        try:
            checkpoint = self._state_checkpoint()
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal checkpoint read failed closed"
            ) from exc
        self._minimum_anchor = self._require_fresh_checkpoint(
            checkpoint,
            minimum=self._minimum_anchor,
            engagement_id=self._engagement_id,
        )
        return self._minimum_anchor

    def _validated_state_record(
        self,
        record: object,
    ) -> tuple[ProviderJournalEntry, AnchorCheckpoint, int]:
        if type(record) is not ProviderJournalRecord:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            )
        source = record.entry
        if type(source) is not ProviderJournalEntry:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            )
        try:
            entry = ProviderJournalEntry(
                phase=source.phase,
                receipt_digest=source.receipt_digest,
                reservation_receipt_digest=source.reservation_receipt_digest,
                call_id=source.call_id,
                attempt=source.attempt,
                attempt_id=source.attempt_id,
                binding_digest=source.binding_digest,
                dispatch_reservation_digest=source.dispatch_reservation_digest,
                proxy_request_digest=source.proxy_request_digest,
                canonical_receipt_json=source.canonical_receipt_json,
            )
            anchor = self._require_fresh_checkpoint(
                record.anchor,
                minimum=self._minimum_anchor,
                engagement_id=self._engagement_id,
            )
            rebuilt = ProviderJournalRecord(
                entry=entry,
                event_seq=record.event_seq,
                event_hash=record.event_hash,
                anchor=anchor,
            )
            canonical = ProviderCanonicalReceipt.parse(
                entry.canonical_receipt_json
            )
            expected = ProviderJournalEntry.from_receipt(canonical)
        except ProviderReceiptError:
            raise
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            ) from exc
        if rebuilt != record or expected != entry:
            raise ProviderReceiptError(
                "anchored provider journal record binding changed"
            )
        self._minimum_anchor = anchor
        return entry, anchor, record.event_seq

    @classmethod
    def _actor(
        cls,
        entry_digest: str,
        receipt_digest: str,
    ) -> str:
        entry = cls._require_receipt_digest(entry_digest)[7:]
        receipt = cls._require_receipt_digest(receipt_digest)[7:]
        binding = hashlib.sha256(
            b"faultloom.provider-call-receipt.actor.v1\0"
            + entry.encode("ascii")
            + b"\0"
            + receipt.encode("ascii")
        ).hexdigest()
        return f"{_PROVIDER_RECEIPT_ACTOR_PREFIX}.{binding}"

    @classmethod
    def _actor_binding(cls, value: object) -> str:
        if type(value) is not str:
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        prefix = f"{_PROVIDER_RECEIPT_ACTOR_PREFIX}."
        if not value.startswith(prefix):
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        binding = value[len(prefix) :]
        if re.fullmatch(r"[0-9a-f]{64}", binding) is None:
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        return binding
