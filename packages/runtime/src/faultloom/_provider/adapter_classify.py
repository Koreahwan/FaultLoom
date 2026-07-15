from __future__ import annotations

from .adapter_receipt import _ProviderAdapterReceipt
from .common import (
    FailureCode,
    ProviderCallOutcome,
    ProviderPlane,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
)
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile
from .proxy import ProviderProxyRequest, ProviderProxyResult


class _ProviderAdapterClassify(_ProviderAdapterReceipt):
    def _classify_result(
        self,
        intent: ProviderCallIntent,
        profile: ProviderModelProfile,
        result: ProviderProxyResult | None,
        proxy_request: ProviderProxyRequest,
        proxy_binding_unchanged: bool,
    ) -> tuple[ProviderCallOutcome, FailureCode | None, RetryDisposition, bool]:
        if not proxy_binding_unchanged:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_IDENTITY_MISMATCH,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if result is None:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_EXCEPTION_UNKNOWN,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if result.plane is not ProviderPlane.MODEL_PROVIDER:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_PLANE_MISMATCH,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if result.request_id != intent.attempt_id:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_CORRELATION_MISMATCH,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if (
            result.outcome is ProxyOutcome.COMPLETED
            and (
                result.accepted_proxy_id != proxy_request.proxy_id
                or result.accepted_proxy_contract_digest
                != proxy_request.proxy_contract_digest
            )
        ):
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_IDENTITY_MISMATCH,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if result.effect_disposition is ProxyEffectDisposition.POSSIBLE:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_EXCEPTION_UNKNOWN,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        if result.outcome is ProxyOutcome.PRE_SEND_FAILED:
            return (
                ProviderCallOutcome.PRE_SEND_FAILED,
                FailureCode.PROXY_PRE_SEND_FAILED,
                RetryDisposition.EXPLICIT_RETRY_ALLOWED,
                False,
            )
        if result.outcome is ProxyOutcome.DENIED:
            return (
                ProviderCallOutcome.DENIED,
                FailureCode.PROXY_DENIED,
                RetryDisposition.BLOCKED_FINAL,
                False,
            )
        if result.outcome is ProxyOutcome.FAILED:
            return (
                ProviderCallOutcome.FAILED,
                FailureCode.PROXY_FAILED,
                RetryDisposition.BLOCKED_FINAL,
                False,
            )
        if result.outcome is ProxyOutcome.UNKNOWN_OUTCOME:
            return (
                ProviderCallOutcome.UNKNOWN_OUTCOME,
                FailureCode.PROXY_EXCEPTION_UNKNOWN,
                RetryDisposition.RECONCILIATION_REQUIRED,
                True,
            )
        assert result.outcome is ProxyOutcome.COMPLETED
        failure = self._completed_response_failure(
            intent, profile, result, proxy_request
        )
        if failure is not None:
            return (
                ProviderCallOutcome.REJECTED_RESPONSE,
                failure,
                RetryDisposition.BLOCKED_FINAL,
                False,
            )
        return (
            ProviderCallOutcome.COMPLETED,
            None,
            RetryDisposition.BLOCKED_FINAL,
            False,
        )
