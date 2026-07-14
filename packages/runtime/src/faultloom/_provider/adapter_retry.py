from __future__ import annotations

import hmac

from faultloom_protocol import sha256_digest

from .adapter_helpers import _decode_ed25519_signature, _logical_request_digest
from .adapter_policy import _ProviderAdapterPolicy
from .common import (
    FailureCode,
    ProviderAdapterError,
    ProviderCallOutcome,
    ProviderRetryError,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
)
from .intent import ProviderCallIntent, failover_provenance_attestation_bytes
from .metadata import ProviderModelProfile
from .receipt import ProviderCallReceipt


class _ProviderAdapterRetry(_ProviderAdapterPolicy):
    def _validate_retry(
        self, intent: ProviderCallIntent, profile: ProviderModelProfile
    ) -> None:
        if intent.attempt == 1:
            return
        assert intent.previous_receipt_digest is not None
        previous = self._journal_by_digest(intent.previous_receipt_digest)
        if previous is None:
            raise ProviderRetryError("provider retry receipt is unavailable")
        try:
            previous = ProviderCallReceipt.model_validate(previous.model_dump(mode="python"))
        except Exception as exc:
            raise ProviderRetryError("provider retry receipt is invalid") from exc
        if not hmac.compare_digest(
            previous.receipt_digest,
            intent.previous_receipt_digest,
        ):
            raise ProviderRetryError("provider retry receipt lookup is not key-bound")
        if previous.retry_disposition is RetryDisposition.EXPLICIT_RETRY_ALLOWED:
            self._validate_retry_proxy_attestation(previous)
        if (
            previous.call_id != intent.call_id
            or previous.run_id != intent.run_id
            or previous.attempt + 1 != intent.attempt
            or previous.retry_disposition is not RetryDisposition.EXPLICIT_RETRY_ALLOWED
            or previous.logical_request_digest != _logical_request_digest(intent)
            or previous.budget_digest != sha256_digest(intent.budget)
        ):
            raise ProviderRetryError("provider retry is not the next identical logical call")
        if previous.profile_id == profile.profile_id:
            if intent.failover is not None:
                raise ProviderRetryError("same-profile retry cannot carry failover provenance")
            if not hmac.compare_digest(previous.profile_digest, sha256_digest(profile)):
                raise ProviderRetryError(
                    "same-profile retry changed the exact provider profile definition"
                )
            self._validate_retry_request_profile(previous, profile)
            return
        failover = intent.failover
        if failover is None:
            raise ProviderRetryError("provider change requires explicit failover provenance")
        source = self._profiles.get(previous.profile_id)
        if source is None:
            raise ProviderRetryError("failover source profile is no longer configured")
        source = ProviderModelProfile.model_validate(source.model_dump(mode="python"))
        if not hmac.compare_digest(previous.profile_digest, sha256_digest(source)):
            raise ProviderRetryError("failover source profile changed after the prior attempt")
        self._validate_retry_request_profile(previous, source)
        if (
            failover.previous_receipt_digest != previous.receipt_digest
            or failover.from_profile_id != source.profile_id
            or failover.to_profile_id != profile.profile_id
            or not hmac.compare_digest(
                failover.from_profile_digest,
                previous.profile_digest,
            )
            or not hmac.compare_digest(
                failover.from_profile_digest,
                sha256_digest(source),
            )
            or not hmac.compare_digest(
                failover.to_profile_digest,
                sha256_digest(profile),
            )
        ):
            raise ProviderRetryError("failover provenance does not bind both profiles")
        approval_key = self._failover_approval_keys.get(failover.approver_key_id)
        if approval_key is None:
            raise ProviderRetryError("failover approval key is not trusted")
        try:
            approval_key.verify(
                _decode_ed25519_signature(failover.approval_signature),
                failover_provenance_attestation_bytes(failover),
            )
        except Exception as exc:
            raise ProviderRetryError("failover approval signature is invalid") from exc
        if (
            source.compatibility_group != profile.compatibility_group
            or source.capability_digest != profile.capability_digest
            or profile.context_window < source.context_window
            or profile.maximum_input_tokens < source.maximum_input_tokens
            or profile.maximum_output_tokens < source.maximum_output_tokens
            or profile.maximum_request_bytes < source.maximum_request_bytes
            or profile.maximum_response_bytes < source.maximum_response_bytes
            or profile.prompt_overhead_tokens > source.prompt_overhead_tokens
        ):
            raise ProviderRetryError("failover profile is not capability-compatible")
        if self._live:
            profile.require_live_safe()

    @staticmethod
    def _validate_retry_request_profile(
        previous: ProviderCallReceipt,
        source: ProviderModelProfile,
    ) -> None:
        request = previous.proxy_request
        if (
            request.endpoint_id != source.endpoint_id
            or request.provider_id != source.provider_id
            or request.requested_alias != source.requested_alias
            or request.model_snapshot != source.exact_snapshot
            or request.runtime_version != source.runtime_version
            or request.tokenizer_id != source.tokenizer_id
            or request.tokenizer_version != source.tokenizer_version
            or request.context_window != source.context_window
            or request.tool_schema_digest != source.tool_schema_digest
            or request.policy_ref != source.policy_ref
            or request.data_policy_id != source.data_policy_id
            or request.data_consent_ref != source.data_consent_ref
        ):
            raise ProviderRetryError(
                "provider retry request does not match its exact source profile"
            )

    def _validate_retry_proxy_attestation(
        self,
        previous: ProviderCallReceipt,
    ) -> None:
        result = previous.proxy_result
        if (
            previous.outcome is not ProviderCallOutcome.PRE_SEND_FAILED
            or previous.failure_code is not FailureCode.PROXY_PRE_SEND_FAILED
            or previous.reconciliation_required
            or result is None
            or result.outcome is not ProxyOutcome.PRE_SEND_FAILED
            or result.effect_disposition is not ProxyEffectDisposition.NOT_DISPATCHED
            or result.reconciliation_required
            or result.bytes_sent != 0
            or result.bytes_received != 0
            or result.request_id != previous.attempt_id
            or not hmac.compare_digest(
                result.proxy_request_digest,
                previous.proxy_request_digest,
            )
            or previous.proxy_id != self._proxy_id
            or not hmac.compare_digest(
                previous.proxy_contract_digest,
                self._proxy_contract_digest,
            )
            or previous.proxy_attestation_key_id
            != self._proxy_attestation_record.key_id
        ):
            raise ProviderRetryError(
                "provider retry lacks an exact attested no-dispatch result"
            )
        try:
            self._verify_proxy_result_attestation(result)
        except ProviderAdapterError as exc:
            raise ProviderRetryError(
                "provider retry proxy attestation is invalid"
            ) from exc
