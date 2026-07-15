from __future__ import annotations

import threading

from faultloom.state import AnchorCheckpoint, EncryptedCAS, EventLedger, StateStore

from .common import ProviderReceiptError

_PROVIDER_RECEIPT_ACTOR_PREFIX = "state.provider_call_receipt"
_PROVIDER_RECEIPT_EVENT_TYPE = "provider.receipt.encrypted"
_PROVIDER_RECEIPT_MEDIA_TYPE = (
    "application/vnd.faultloom.provider-call-receipt+json"
)
_PROVIDER_RECEIPT_METADATA_MEDIA_TYPE = (
    "application/vnd.faultloom.observation-metadata+json"
)
_MAX_PROVIDER_RECEIPT_BYTES = 256 * 1024
_MAX_PROVIDER_RECEIPT_METADATA_BYTES = 4096
_PROVIDER_EVENT_PAGE = 1000


class _AnchoredJournalBase:
    """a4 projection plus encrypted full-receipt readback for the adapter."""

    __slots__ = (
        "_cas",
        "_cas_get",
        "_engagement_id",
        "_ledger",
        "_ledger_events",
        "_lock",
        "_minimum_anchor",
        "_state_append_observation",
        "_state_by_attempt",
        "_state_by_attempt_id",
        "_state_by_digest",
        "_state_checkpoint",
        "_state_finalize",
        "_state_reserve",
        "_state_store",
        "journal_id",
    )

    _STATE_METHODS = (
        "append_observation",
        "checkpoint",
        "finalize_provider_receipt",
        "provider_receipt_by_attempt",
        "provider_receipt_by_attempt_id",
        "provider_receipt_by_digest",
        "reserve_provider_receipt",
    )

    def __init__(
        self,
        state_store: StateStore,
        *,
        minimum_anchor: AnchorCheckpoint,
    ) -> None:
        if type(state_store) is not StateStore:
            raise ProviderReceiptError(
                "anchored provider journal requires the exact T20 StateStore"
            )
        if type(minimum_anchor) is not AnchorCheckpoint:
            raise ProviderReceiptError(
                "anchored provider journal requires an external minimum anchor"
            )
        try:
            trusted_minimum = AnchorCheckpoint(
                engagement_id=minimum_anchor.engagement_id,
                seq=minimum_anchor.seq,
                head=minimum_anchor.head,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal minimum anchor is invalid"
            ) from exc
        engagement_id = getattr(state_store, "engagement_id", None)
        if (
            type(engagement_id) is not str
            or not engagement_id
            or trusted_minimum.engagement_id != engagement_id
        ):
            raise ProviderReceiptError(
                "anchored provider journal minimum anchor engagement mismatch"
            )
        methods = {
            name: getattr(state_store, name, None) for name in self._STATE_METHODS
        }
        if any(not callable(method) for method in methods.values()) or any(
            getattr(method, "__self__", None) is not state_store
            or getattr(method, "__func__", None) is not getattr(StateStore, name)
            for name, method in methods.items()
        ):
            raise ProviderReceiptError(
                "anchored provider journal StateStore methods were replaced"
            )
        ledger = getattr(state_store, "ledger", None)
        cas = getattr(state_store, "cas", None)
        ledger_events = getattr(ledger, "events", None)
        cas_get = getattr(cas, "get", None)
        if (
            type(ledger) is not EventLedger
            or type(cas) is not EncryptedCAS
            or not callable(ledger_events)
            or not callable(cas_get)
            or getattr(ledger_events, "__self__", None) is not ledger
            or getattr(ledger_events, "__func__", None) is not EventLedger.events
            or getattr(cas_get, "__self__", None) is not cas
            or getattr(cas_get, "__func__", None) is not EncryptedCAS.get
        ):
            raise ProviderReceiptError(
                "anchored provider journal encrypted state capability is invalid"
            )
        try:
            checkpoint = methods["checkpoint"]()
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal could not verify its T20 checkpoint"
            ) from exc
        checkpoint = self._require_fresh_checkpoint(
            checkpoint,
            minimum=trusted_minimum,
            engagement_id=engagement_id,
        )
        self._state_store = state_store
        self._engagement_id = engagement_id
        self._minimum_anchor = checkpoint
        self._lock = threading.RLock()
        self._ledger = ledger
        self._cas = cas
        self._ledger_events = ledger_events
        self._cas_get = cas_get
        self._state_append_observation = methods["append_observation"]
        self._state_checkpoint = methods["checkpoint"]
        self._state_finalize = methods["finalize_provider_receipt"]
        self._state_by_attempt = methods["provider_receipt_by_attempt"]
        self._state_by_attempt_id = methods["provider_receipt_by_attempt_id"]
        self._state_by_digest = methods["provider_receipt_by_digest"]
        self._state_reserve = methods["reserve_provider_receipt"]
        self.journal_id = f"anchored-provider-journal:{engagement_id}"

    @staticmethod
    def _require_fresh_checkpoint(
        checkpoint: object,
        *,
        minimum: AnchorCheckpoint,
        engagement_id: str,
    ) -> AnchorCheckpoint:
        if type(checkpoint) is not AnchorCheckpoint:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid checkpoint"
            )
        try:
            validated = AnchorCheckpoint(
                engagement_id=checkpoint.engagement_id,
                seq=checkpoint.seq,
                head=checkpoint.head,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid checkpoint"
            ) from exc
        if (
            validated.engagement_id != engagement_id
            or validated.seq < minimum.seq
            or (validated.seq == minimum.seq and validated.head != minimum.head)
        ):
            raise ProviderReceiptError(
                "anchored provider journal checkpoint rollback was detected"
            )
        return validated
