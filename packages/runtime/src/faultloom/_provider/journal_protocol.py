from __future__ import annotations

from typing import Protocol

from .receipt import ProviderCallReceipt

class ProviderReceiptJournal(Protocol):
    """Authenticated journal boundary used by T13/T20-backed implementations.

    ``reserve`` must durably and atomically claim both attempt keys before it
    returns. ``finalize`` is an append-only compare-and-swap from that exact
    reservation. A failed or interrupted finalization must leave the reserved
    unknown-outcome receipt readable; reservations never expire implicitly.
    """

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None: ...

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None: ...

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None: ...

    def reserve(self, receipt: ProviderCallReceipt) -> None: ...

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None: ...
