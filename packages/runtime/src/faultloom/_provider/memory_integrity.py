from __future__ import annotations

import hmac

from .common import (
    ProviderReceiptError,
    provider_canonical_json_bytes as canonical_json_bytes,
    provider_sha256_digest as sha256_digest,
)
from .memory_base import _MemoryJournalBase
from .receipt import ProviderCallReceipt, _provider_journal_binding_digest

class _MemoryJournalIntegrity(_MemoryJournalBase):
    def _verify_chain(self) -> None:
        if len(self._states) != self._trusted_sequence:
            raise ProviderReceiptError("provider journal rollback was detected")
        previous = sha256_digest(
            {
                "journal_id": self.journal_id,
                "purpose": "faultloom.provider_journal.genesis.v1",
            }
        )
        derived_by_digest: dict[str, ProviderCallReceipt] = {}
        derived_by_attempt: dict[tuple[str, int], ProviderCallReceipt] = {}
        derived_by_attempt_id: dict[str, ProviderCallReceipt] = {}
        derived_state_by_digest: dict[str, dict[str, object]] = {}
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
        for expected_sequence, state in enumerate(self._states, start=1):
            receipt_digest = state.get("receipt_digest")
            if not isinstance(receipt_digest, str):
                raise ProviderReceiptError("provider journal state is invalid")
            stored = self._by_digest.get(receipt_digest)
            if stored is None:
                raise ProviderReceiptError("provider journal receipt disappeared")
            receipt = self._validated(stored)
            if not hmac.compare_digest(receipt.receipt_digest, receipt_digest):
                raise ProviderReceiptError("provider journal receipt key mismatch")
            state_receipt = self._validated(state.get("receipt"))
            if not hmac.compare_digest(
                state_receipt.receipt_digest,
                receipt.receipt_digest,
            ):
                raise ProviderReceiptError("provider journal state receipt changed")
            phase = state.get("phase")
            if phase not in {"reserved", "finalized"}:
                raise ProviderReceiptError("provider journal phase is invalid")
            reservation_digest = state.get("reservation_receipt_digest")
            if not isinstance(reservation_digest, str):
                raise ProviderReceiptError("provider journal reservation is invalid")
            payload = self._state_payload(
                sequence=expected_sequence,
                phase=phase,
                reservation_receipt_digest=reservation_digest,
                previous_state_digest=previous,
                receipt=receipt,
            )
            expected_digest = sha256_digest(payload)
            expected_tag = "sha256:" + hmac.new(
                self._authentication_key,
                canonical_json_bytes({**payload, "state_digest": expected_digest}),
                "sha256",
            ).hexdigest()
            if (
                state.get("sequence") != expected_sequence
                or state.get("previous_state_digest") != previous
                or not isinstance(state.get("state_digest"), str)
                or not hmac.compare_digest(state["state_digest"], expected_digest)
                or not isinstance(state.get("authentication_tag"), str)
                or not hmac.compare_digest(state["authentication_tag"], expected_tag)
            ):
                raise ProviderReceiptError("provider journal authenticated chain is invalid")

            attempt_key = (receipt.call_id, receipt.attempt)
            if receipt_digest in derived_by_digest:
                raise ProviderReceiptError("provider journal receipt digest was replayed")
            if phase == "reserved":
                if (
                    reservation_digest != receipt_digest
                    or attempt_key in derived_by_attempt
                    or receipt.attempt_id in derived_by_attempt_id
                ):
                    raise ProviderReceiptError("provider journal reservation was replayed")
            else:
                reservation_state = derived_state_by_digest.get(reservation_digest)
                active = derived_by_attempt.get(attempt_key)
                active_id = derived_by_attempt_id.get(receipt.attempt_id)
                if (
                    reservation_state is None
                    or reservation_state.get("phase") != "reserved"
                    or active is None
                    or active_id is None
                    or not hmac.compare_digest(
                        active.receipt_digest,
                        reservation_digest,
                    )
                    or not hmac.compare_digest(
                        active_id.receipt_digest,
                        reservation_digest,
                    )
                ):
                    raise ProviderReceiptError("provider journal finalization is not linear")
                reservation = derived_by_digest[reservation_digest]
                if any(
                    getattr(receipt, field) != getattr(reservation, field)
                    for field in bound_fields
                ) or not hmac.compare_digest(
                    _provider_journal_binding_digest(receipt),
                    _provider_journal_binding_digest(reservation),
                ):
                    raise ProviderReceiptError(
                        "provider journal finalization changed its reservation"
                    )
            derived_by_digest[receipt_digest] = receipt
            derived_by_attempt[attempt_key] = receipt
            derived_by_attempt_id[receipt.attempt_id] = receipt
            derived_state_by_digest[receipt_digest] = state
            previous = expected_digest
        if (
            not hmac.compare_digest(self._head, previous)
            or not hmac.compare_digest(self._trusted_head, previous)
        ):
            raise ProviderReceiptError("provider journal head is invalid")
        if set(self._by_digest) != set(derived_by_digest):
            raise ProviderReceiptError("provider journal digest index is inconsistent")
        if set(self._by_attempt) != set(derived_by_attempt):
            raise ProviderReceiptError("provider journal attempt index is inconsistent")
        if set(self._by_attempt_id) != set(derived_by_attempt_id):
            raise ProviderReceiptError("provider journal attempt-ID index is inconsistent")
        if set(self._state_by_receipt_digest) != set(derived_state_by_digest):
            raise ProviderReceiptError("provider journal state index is inconsistent")
        if any(
            not hmac.compare_digest(
                self._by_digest[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_digest.items()
        ):
            raise ProviderReceiptError("provider journal digest index changed")
        if any(
            not hmac.compare_digest(
                self._by_attempt[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_attempt.items()
        ):
            raise ProviderReceiptError("provider journal attempt index changed")
        if any(
            not hmac.compare_digest(
                self._by_attempt_id[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_attempt_id.items()
        ):
            raise ProviderReceiptError("provider journal attempt-ID index changed")
        if any(
            self._state_by_receipt_digest[key].get("state_digest")
            != expected.get("state_digest")
            for key, expected in derived_state_by_digest.items()
        ):
            raise ProviderReceiptError("provider journal state index changed")
