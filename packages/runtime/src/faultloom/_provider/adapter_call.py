from __future__ import annotations

from faultloom_protocol import sha256_digest

from .adapter_helpers import _logical_request_digest, _trusted_monotonic, _trusted_now
from .adapter_state import _ProviderAdapterState
from .common import ProviderAdapterError, ProviderPolicyError, ProviderRetryError
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile, provider_tool_schema_digest
from .proxy import ProviderProxyRequest, ProviderProxyResult, _dispatch_reservation_digest
from .receipt import ProviderCallReceipt

class _ProviderAdapterCall(_ProviderAdapterState):
    def call(self, intent: ProviderCallIntent) -> ProviderCallReceipt:
        intent = ProviderCallIntent.model_validate(intent.model_dump(mode="python"))
        profile = self._profiles.get(intent.profile_id)
        if profile is None:
            raise ProviderPolicyError("provider profile is not configured")
        profile = ProviderModelProfile.model_validate(profile.model_dump(mode="python"))
        self._validate_proxy_binding()
        self._validate_pre_dispatch(intent, profile)
        self._validate_retry(intent, profile)
        existing_attempt = self._journal_by_attempt(intent.call_id, intent.attempt)
        if existing_attempt is not None:
            self._validate_attempt_lookup(
                existing_attempt,
                call_id=intent.call_id,
                attempt=intent.attempt,
            )
            raise ProviderRetryError("provider call attempt already has a receipt")
        existing_attempt_id = self._journal_by_attempt_id(intent.attempt_id)
        if existing_attempt_id is not None:
            self._validate_attempt_id_lookup(existing_attempt_id, intent.attempt_id)
            raise ProviderRetryError("provider attempt ID has already been used")

        tool_digest = provider_tool_schema_digest(intent.tools)
        config_digest = sha256_digest(intent.generation_config)
        budget_digest = sha256_digest(intent.budget)
        logical_digest = _logical_request_digest(intent)
        profile_digest = sha256_digest(profile)
        dispatch_reservation_digest = _dispatch_reservation_digest(
            call_id=intent.call_id,
            attempt_id=intent.attempt_id,
            attempt=intent.attempt,
            run_id=intent.run_id,
            logical_request_digest=logical_digest,
            profile_digest=profile_digest,
            proxy_id=self._proxy_id,
            proxy_contract_digest=self._proxy_contract_digest,
            proxy_attestation_key_id=self._proxy_attestation_record.key_id,
        )
        proxy_request = ProviderProxyRequest(
            proxy_id=self._proxy_id,
            proxy_contract_digest=self._proxy_contract_digest,
            proxy_attestation_key_id=self._proxy_attestation_record.key_id,
            dispatch_reservation_digest=dispatch_reservation_digest,
            request_id=intent.attempt_id,
            run_id=intent.run_id,
            authority_digest=intent.authority_digest,
            scope_epoch=intent.scope_epoch,
            endpoint_id=profile.endpoint_id,
            provider_id=profile.provider_id,
            requested_alias=profile.requested_alias,
            model_snapshot=profile.exact_snapshot,
            runtime_version=profile.runtime_version,
            tokenizer_id=profile.tokenizer_id,
            tokenizer_version=profile.tokenizer_version,
            context_window=profile.context_window,
            prompt_digest=intent.prompt_digest,
            compiled_context_digest=intent.compiled_context_digest,
            tool_schema_digest=tool_digest,
            output_schema_digest=intent.output_schema_digest,
            config_digest=config_digest,
            policy_ref=intent.policy_ref,
            data_policy_id=intent.data_policy_id,
            data_consent_ref=intent.data_consent_ref,
            credential_ref=intent.credential_ref,
            payload_digest=intent.prompt_digest,
            payload_bytes=intent.prompt_bytes,
            tool_ids=tuple(tool.tool_id for tool in intent.tools),
            requested_at=intent.requested_at,
            live=self._live,
        )
        proxy_request_digest = sha256_digest(proxy_request)
        started_at = _trusted_now(self._clock)
        started_ns = _trusted_monotonic(self._monotonic_clock)
        reservation_receipt = self._make_receipt(
            intent=intent,
            profile=profile,
            profile_digest=profile_digest,
            result=None,
            tool_digest=tool_digest,
            config_digest=config_digest,
            budget_digest=budget_digest,
            logical_digest=logical_digest,
            dispatch_reservation_digest=dispatch_reservation_digest,
            proxy_request=proxy_request,
            proxy_request_digest=proxy_request_digest,
            proxy_binding_unchanged=True,
            started_at=started_at,
            completed_at=started_at,
            elapsed_ns=0,
        )
        self._journal_reserve(reservation_receipt)
        self._validate_reservation_readback(reservation_receipt)

        # The reservation above is already the authoritative unknown-outcome hold.
        # Therefore every exception after this point can safely return it
        # without another fallible journal write or an automatic redispatch.
        try:
            self._validate_proxy_binding()
            untrusted_result = self._proxy_dispatch(proxy_request)
            result = ProviderProxyResult.model_validate(
                untrusted_result.model_dump(mode="python")
            )
            self._validate_result_attestation(
                result,
                proxy_request=proxy_request,
                proxy_request_digest=proxy_request_digest,
            )
            proxy_binding_unchanged = self._proxy_binding_matches()
            completed_ns = _trusted_monotonic(self._monotonic_clock)
            completed_at = _trusted_now(self._clock)
            if completed_ns < started_ns:
                raise ProviderAdapterError("provider monotonic clock moved backwards")
            if completed_at < started_at:
                completed_at = started_at

            receipt = self._make_receipt(
                intent=intent,
                profile=profile,
                profile_digest=profile_digest,
                result=result,
                tool_digest=tool_digest,
                config_digest=config_digest,
                budget_digest=budget_digest,
                logical_digest=logical_digest,
                dispatch_reservation_digest=dispatch_reservation_digest,
                proxy_request=proxy_request,
                proxy_request_digest=proxy_request_digest,
                proxy_binding_unchanged=proxy_binding_unchanged,
                started_at=started_at,
                completed_at=completed_at,
                elapsed_ns=completed_ns - started_ns,
            )
            self._journal_finalize(reservation_receipt.receipt_digest, receipt)
            self._validate_terminal_readback(
                reservation_receipt.receipt_digest,
                receipt,
            )
            return receipt
        except Exception:
            return reservation_receipt
        except BaseException:
            # Cancellation and process-control exceptions are never swallowed.
            # The already-authenticated reservation remains the authoritative
            # unknown-outcome hold and blocks redispatch after recovery.
            raise
