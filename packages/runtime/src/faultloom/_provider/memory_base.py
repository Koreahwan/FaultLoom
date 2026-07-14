from __future__ import annotations

import hmac
import secrets
import threading
from typing import Literal

from faultloom_protocol import canonical_json_bytes, sha256_digest

from .common import ProviderReceiptError, SCHEMA_VERSION
from .receipt import ProviderCallReceipt

class _MemoryJournalBase:
    """Authenticated process-local journal for loopback labs and contract tests.

    The lock and authenticated append-only chain exercise the same atomic API
    required of a durable T20 journal. This class is intentionally not durable
    and cannot support a production/live persistence claim by itself.
    """

    def __init__(self, *, authentication_key: bytes | None = None) -> None:
        key = authentication_key if authentication_key is not None else secrets.token_bytes(32)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("provider journal authentication key must be 32 bytes")
        self.journal_id = f"memory-provider-journal-{secrets.token_hex(8)}"
        self._authentication_key = key
        self._lock = threading.RLock()
        self._by_digest: dict[str, ProviderCallReceipt] = {}
        self._by_attempt: dict[tuple[str, int], ProviderCallReceipt] = {}
        self._by_attempt_id: dict[str, ProviderCallReceipt] = {}
        self._states: list[dict[str, object]] = []
        self._state_by_receipt_digest: dict[str, dict[str, object]] = {}
        self._head = sha256_digest(
            {
                "journal_id": self.journal_id,
                "purpose": "faultloom.provider_journal.genesis.v1",
            }
        )
        # This process-local freshness anchor is deliberately separate from
        # the replayable chain. A production T20 journal must pin the same
        # values in durable authenticated storage outside this object.
        self._trusted_head = self._head
        self._trusted_sequence = 0

    @staticmethod
    def _validated(receipt: ProviderCallReceipt) -> ProviderCallReceipt:
        try:
            return ProviderCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except Exception as exc:
            raise ProviderReceiptError("provider receipt is invalid") from exc

    def _state_payload(
        self,
        *,
        sequence: int,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str,
        previous_state_digest: str,
        receipt: ProviderCallReceipt,
    ) -> dict[str, object]:
        return {
            "journal_id": self.journal_id,
            "phase": phase,
            "previous_state_digest": previous_state_digest,
            "receipt": receipt,
            "reservation_receipt_digest": reservation_receipt_digest,
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
        }

    def _new_state(
        self,
        *,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> dict[str, object]:
        payload = self._state_payload(
            sequence=len(self._states) + 1,
            phase=phase,
            reservation_receipt_digest=reservation_receipt_digest,
            previous_state_digest=self._head,
            receipt=receipt,
        )
        state_digest = sha256_digest(payload)
        authentication_tag = "sha256:" + hmac.new(
            self._authentication_key,
            canonical_json_bytes({**payload, "state_digest": state_digest}),
            "sha256",
        ).hexdigest()
        return {
            **payload,
            "authentication_tag": authentication_tag,
            "state_digest": state_digest,
        }
