from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from faultloom.provider import (
    AnchoredProviderReceiptJournal,
    MemoryProviderReceiptJournal,
    ProviderAdapter,
    ProviderModelProfile,
    ProviderPlane,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProxyOutcome,
)
from faultloom.state import AnchorCheckpoint, EngagementKey, StateStore

from tests.runtime.provider_test_models import (
    FAILOVER_SIGNER,
    NOW,
    PROXY_SIGNER,
    digest,
)
from tests.runtime.provider_test_results import pre_send_result

class FakeProxy:
    plane = ProviderPlane.MODEL_PROVIDER
    contract_digest = digest("provider-proxy-contract")
    attestation_public_key = PROXY_SIGNER.public_key_record

    def __init__(self, handler: Callable[[ProviderProxyRequest], ProviderProxyResult]):
        self.handler = handler
        self.requests: list[ProviderProxyRequest] = []
        self._proxy_id = "loopback-provider-proxy"
        self._dispatching = False

    @property
    def proxy_id(self) -> str:
        return self._proxy_id

    @proxy_id.setter
    def proxy_id(self, value: str) -> None:
        if self._dispatching:
            raise RuntimeError("the attested proxy binding is immutable during dispatch")
        self._proxy_id = value

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult:
        self.requests.append(request)
        handler = self.handler
        self._dispatching = True
        try:
            result = handler(request)
        finally:
            self._dispatching = False
        # A real T17 proxy signs NOT_DISPATCHED only from its transport boundary,
        # never from an arbitrary provider callback. The loopback port models
        # that distinction with one explicit no-dispatch handler.
        if result.outcome is ProxyOutcome.PRE_SEND_FAILED and handler is not pre_send_result:
            return result.model_copy(update={"attestation_signature": "unsigned"})
        return result


class StepClock:
    def __init__(self, start: datetime = NOW, step: timedelta = timedelta(milliseconds=2)):
        self.value = start - step
        self.step = step

    def __call__(self) -> datetime:
        self.value += self.step
        return self.value


class StepMonotonic:
    def __init__(self, step_ns: int = 5_000_000):
        self.value = -step_ns
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.value += self.step_ns
        return self.value


def adapter(
    models: tuple[ProviderModelProfile, ...],
    proxy: FakeProxy,
    journal: AnchoredProviderReceiptJournal | MemoryProviderReceiptJournal | None = None,
    *,
    live: bool = False,
) -> ProviderAdapter:
    return ProviderAdapter(
        profiles=models,
        proxy=proxy,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        journal=journal or MemoryProviderReceiptJournal(),
        live=live,
        trusted_failover_approval_keys=(FAILOVER_SIGNER.public_key_record,),
        clock=StepClock(),
        monotonic_clock=StepMonotonic(),
    )


def provider_state_store(
    root: Path,
    engagement_id: str = "eng.provider-runtime",
    *,
    minimum_anchor: AnchorCheckpoint | None = None,
) -> StateStore:
    return StateStore(
        root / "state",
        engagement_id,
        EngagementKey(bytes(range(32))),
        anchor_root=root / "anchor",
        minimum_anchor=minimum_anchor,
    )
