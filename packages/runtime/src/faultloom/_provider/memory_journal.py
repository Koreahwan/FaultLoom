from __future__ import annotations

import hmac

from .common import ProviderCallOutcome, ProviderReceiptError, RetryDisposition
from .memory_integrity import _MemoryJournalIntegrity
from .receipt import ProviderCallReceipt, _provider_journal_binding_digest

class MemoryProviderReceiptJournal(_MemoryJournalIntegrity):
    def _commit_state(self, state: dict[str, object], receipt: ProviderCallReceipt) -> None:
        stored_state = {**state, "receipt_digest": receipt.receipt_digest}
        self._states.append(stored_state)
        self._state_by_receipt_digest[receipt.receipt_digest] = stored_state
        self._by_digest[receipt.receipt_digest] = receipt
        self._head = str(state["state_digest"])
        self._trusted_head = self._head
        self._trusted_sequence += 1

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_digest.get(receipt_digest)
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if not hmac.compare_digest(receipt.receipt_digest, receipt_digest):
                raise ProviderReceiptError("provider journal digest lookup is not key-bound")
            return receipt

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_attempt.get((call_id, attempt))
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if receipt.call_id != call_id or receipt.attempt != attempt:
                raise ProviderReceiptError("provider journal attempt lookup is not key-bound")
            return receipt

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_attempt_id.get(attempt_id)
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if receipt.attempt_id != attempt_id:
                raise ProviderReceiptError("provider journal attempt-ID lookup is not key-bound")
            return receipt

    def reserve(self, receipt: ProviderCallReceipt) -> None:
        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            if (
                receipt.outcome is not ProviderCallOutcome.UNKNOWN_OUTCOME
                or receipt.retry_disposition is not RetryDisposition.RECONCILIATION_REQUIRED
                or not receipt.reconciliation_required
            ):
                raise ProviderReceiptError("dispatch reservation must be an unknown-outcome hold")
            if (
                receipt.receipt_digest in self._by_digest
                or (receipt.call_id, receipt.attempt) in self._by_attempt
                or receipt.attempt_id in self._by_attempt_id
            ):
                raise ProviderReceiptError("provider receipt replay or attempt collision")
            state = self._new_state(
                phase="reserved",
                reservation_receipt_digest=receipt.receipt_digest,
                receipt=receipt,
            )
            self._commit_state(state, receipt)
            self._by_attempt[(receipt.call_id, receipt.attempt)] = receipt
            self._by_attempt_id[receipt.attempt_id] = receipt

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None:
        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            reservation = self._by_digest.get(reservation_receipt_digest)
            if reservation is None:
                raise ProviderReceiptError("provider dispatch reservation is unavailable")
            reservation = self._validated(reservation)
            reservation_state = self._state_by_receipt_digest.get(
                reservation_receipt_digest
            )
            if reservation_state is None or reservation_state.get("phase") != "reserved":
                raise ProviderReceiptError("provider dispatch reservation is not active")
            bound_fields = (
                "call_id",
                "attempt_id",
                "attempt",
                "run_id",
                "profile_id",
                "profile_digest",
                "proxy_id",
                "proxy_attestation_key_id",
                "proxy_contract_digest",
                "logical_request_digest",
                "dispatch_reservation_digest",
                "proxy_request_digest",
            )
            if any(
                getattr(receipt, field) != getattr(reservation, field)
                for field in bound_fields
            ) or not hmac.compare_digest(
                _provider_journal_binding_digest(receipt),
                _provider_journal_binding_digest(reservation),
            ):
                raise ProviderReceiptError("provider terminal receipt changed its reservation")
            current = self._by_attempt.get((reservation.call_id, reservation.attempt))
            if current is None or not hmac.compare_digest(
                current.receipt_digest,
                reservation_receipt_digest,
            ):
                raise ProviderReceiptError("provider reservation was already finalized")
            if receipt.receipt_digest in self._by_digest:
                raise ProviderReceiptError("provider terminal receipt digest was replayed")
            state = self._new_state(
                phase="finalized",
                reservation_receipt_digest=reservation_receipt_digest,
                receipt=receipt,
            )
            self._commit_state(state, receipt)
            self._by_attempt[(receipt.call_id, receipt.attempt)] = receipt
            self._by_attempt_id[receipt.attempt_id] = receipt

    def append(self, receipt: ProviderCallReceipt) -> None:
        """Reject legacy post-effect append calls that bypass reservation."""

        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            raise ProviderReceiptError("provider receipts require reserve/finalize admission")
