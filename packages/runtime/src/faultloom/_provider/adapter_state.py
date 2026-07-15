from __future__ import annotations

import re
import time
from typing import Iterable

from faultloom_protocol import Ed25519PublicKeyRecord, load_public_key

from .adapter_helpers import Clock, MonotonicClock, _profile_map, _system_clock
from .anchored_journal import AnchoredProviderReceiptJournal
from .common import ProviderPlane, ProviderPlaneError, ProviderReceiptError
from .journal_protocol import ProviderReceiptJournal
from .memory_journal import MemoryProviderReceiptJournal
from .metadata import ProviderModelProfile
from .proxy import ProviderProxyPort

class _ProviderAdapterState:
    """Validate, dispatch, account, and receipt one model-provider call."""

    def __init__(
        self,
        *,
        profiles: Iterable[ProviderModelProfile],
        proxy: ProviderProxyPort,
        trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
        journal: ProviderReceiptJournal,
        live: bool,
        trusted_failover_approval_keys: Iterable[Ed25519PublicKeyRecord] = (),
        clock: Clock = _system_clock,
        monotonic_clock: MonotonicClock = time.monotonic_ns,
    ) -> None:
        if type(live) is not bool:
            raise TypeError("provider adapter live mode must be a boolean")
        if live and type(journal) is not AnchoredProviderReceiptJournal:
            raise ProviderReceiptError(
                "live provider execution requires the exact anchored T20 journal"
            )
        if not live and type(journal) not in {
            AnchoredProviderReceiptJournal,
            MemoryProviderReceiptJournal,
        }:
            raise ProviderReceiptError(
                "non-live provider labs require an exact anchored T20 or "
                "exact process-local journal"
            )
        journal_class = type(journal)
        if getattr(proxy, "plane", None) is not ProviderPlane.MODEL_PROVIDER:
            raise ProviderPlaneError("provider adapter requires the model-provider plane")
        if not callable(getattr(proxy, "dispatch", None)):
            raise TypeError("provider adapter requires a provider-proxy dispatch port")
        dispatch = proxy.dispatch
        contract_digest = getattr(proxy, "contract_digest", None)
        proxy_id = getattr(proxy, "proxy_id", None)
        if not isinstance(contract_digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", contract_digest
        ) is None:
            raise ValueError("provider proxy requires a pinned contract digest")
        if not isinstance(proxy_id, str) or not proxy_id:
            raise ValueError("provider proxy requires an identifier")
        try:
            trusted_attestation_record = Ed25519PublicKeyRecord.model_validate(
                trusted_proxy_attestation_key.model_dump(mode="python")
            )
            attestation_public_key = load_public_key(trusted_attestation_record)
        except Exception as exc:
            raise ValueError("provider adapter requires a trusted T17 attestation key") from exc
        try:
            advertised_attestation_record = Ed25519PublicKeyRecord.model_validate(
                getattr(proxy, "attestation_public_key").model_dump(mode="python")
            )
        except Exception as exc:
            raise ValueError("provider proxy requires a pinned Ed25519 attestation key") from exc
        if advertised_attestation_record != trusted_attestation_record:
            raise ProviderPlaneError(
                "provider proxy attestation key does not match the trusted T17 key"
            )
        failover_approval_keys = {}
        for candidate in trusted_failover_approval_keys:
            try:
                record = Ed25519PublicKeyRecord.model_validate(
                    candidate.model_dump(mode="python")
                )
                public_key = load_public_key(record)
            except Exception as exc:
                raise ValueError("provider failover approval key is invalid") from exc
            if record.key_id in failover_approval_keys:
                raise ValueError("provider failover approval key IDs must be unique")
            failover_approval_keys[record.key_id] = public_key
        journal_methods = {
            name: getattr(journal, name, None)
            for name in (
                "by_digest",
                "by_attempt",
                "by_attempt_id",
                "reserve",
                "finalize",
            )
        }
        if any(not callable(method) for method in journal_methods.values()):
            raise TypeError("provider journal requires authenticated reserve/finalize operations")
        if any(
            getattr(method, "__self__", None) is not journal
            or getattr(method, "__func__", None)
            is not getattr(journal_class, name)
            for name, method in journal_methods.items()
        ):
            raise ProviderReceiptError("provider journal methods were replaced")
        journal_id = getattr(journal, "journal_id", None)
        if not isinstance(journal_id, str) or not journal_id:
            raise ProviderReceiptError("provider journal requires a trusted identifier")
        self._profiles = _profile_map(profiles)
        self._proxy = proxy
        self._live = live
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._proxy_id = proxy_id
        self._proxy_contract_digest = contract_digest
        self._proxy_attestation_record = trusted_attestation_record
        self._proxy_attestation_public_key = attestation_public_key
        self._failover_approval_keys = failover_approval_keys
        self._proxy_dispatch = dispatch
        self._proxy_dispatch_owner = getattr(dispatch, "__self__", None)
        self._proxy_dispatch_function = getattr(dispatch, "__func__", dispatch)
        self._journal_by_digest = journal_methods["by_digest"]
        self._journal_by_attempt = journal_methods["by_attempt"]
        self._journal_by_attempt_id = journal_methods["by_attempt_id"]
        self._journal_reserve = journal_methods["reserve"]
        self._journal_finalize = journal_methods["finalize"]
