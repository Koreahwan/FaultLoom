from __future__ import annotations

import hmac
from typing import final

from .anchored_append import _AnchoredJournalAppend
from .common import ProviderReceiptError
from .receipt import ProviderCallReceipt, _provider_journal_binding_digest

@final
class AnchoredProviderReceiptJournal(_AnchoredJournalAppend):
    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
        digest = self._require_receipt_digest(receipt_digest)
        with self._lock:
            checkpoint = self._refresh_checkpoint()
            events = self._matching_events(
                checkpoint,
                receipt_digest=digest,
            )
            if not events:
                return None
            if len(events) != 1:
                raise ProviderReceiptError(
                    "provider receipt digest companion is ambiguous"
                )
            candidate, expected_entry = self._receipt_from_event(events[0])
            try:
                record = self._state_by_digest(expected_entry.receipt_digest)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider receipt lookup failed closed"
                ) from exc
            if record is None:
                raise ProviderReceiptError(
                    "provider receipt companion lacks an a4 projection"
                )
            stored = self._validated_record(record)
            if stored != candidate or stored.receipt_digest != digest:
                raise ProviderReceiptError(
                    "anchored provider digest lookup is not key-bound"
                )
            return stored

    def by_attempt(
        self,
        call_id: str,
        attempt: int,
    ) -> ProviderCallReceipt | None:
        with self._lock:
            try:
                record = self._state_by_attempt(call_id, attempt)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider attempt lookup failed closed"
                ) from exc
            if record is None:
                self._refresh_checkpoint()
                return None
            receipt = self._validated_record(record)
            if receipt.call_id != call_id or receipt.attempt != attempt:
                raise ProviderReceiptError(
                    "anchored provider attempt lookup is not key-bound"
                )
            return receipt

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
        with self._lock:
            try:
                record = self._state_by_attempt_id(attempt_id)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider attempt-ID lookup failed closed"
                ) from exc
            if record is None:
                self._refresh_checkpoint()
                return None
            receipt = self._validated_record(record)
            if receipt.attempt_id != attempt_id:
                raise ProviderReceiptError(
                    "anchored provider attempt-ID lookup is not key-bound"
                )
            return receipt

    def reserve(self, receipt: ProviderCallReceipt) -> None:
        validated, entry = self._entry_for_receipt(
            receipt,
            phase="reserved",
            reservation_receipt_digest=None,
        )
        with self._lock:
            try:
                record = self._state_reserve(entry)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider reservation failed closed"
                ) from exc
            stored_entry, _, event_seq = self._validated_state_record(record)
            if stored_entry != entry:
                raise ProviderReceiptError(
                    "anchored provider reservation projection changed"
                )
            self._append_companion(
                validated,
                entry,
                journal_event_seq=event_seq,
            )
            stored = self.by_digest(validated.receipt_digest)
            if stored != validated:
                raise ProviderReceiptError(
                    "anchored provider reservation readback changed"
                )

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None:
        with self._lock:
            reservation = self.by_digest(reservation_receipt_digest)
            if reservation is None or reservation.proxy_result is not None:
                raise ProviderReceiptError(
                    "anchored provider finalization reservation is missing"
                )
            if not hmac.compare_digest(
                _provider_journal_binding_digest(reservation),
                _provider_journal_binding_digest(receipt),
            ):
                raise ProviderReceiptError(
                    "provider finalization changed its full reservation binding"
                )
            reservation_entry = self._reservation_entry(reservation)
            validated, entry = self._entry_for_receipt(
                receipt,
                phase="finalized",
                reservation_receipt_digest=reservation_entry.receipt_digest,
            )
            try:
                record = self._state_finalize(
                    reservation_entry.receipt_digest,
                    entry,
                )
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider finalization failed closed"
                ) from exc
            stored_entry, _, event_seq = self._validated_state_record(record)
            if stored_entry != entry:
                raise ProviderReceiptError(
                    "anchored provider finalization projection changed"
                )
            self._append_companion(
                validated,
                entry,
                journal_event_seq=event_seq,
            )
            stored = self.by_digest(validated.receipt_digest)
            if stored != validated:
                raise ProviderReceiptError(
                    "anchored provider finalization readback changed"
                )
