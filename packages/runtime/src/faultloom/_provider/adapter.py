from __future__ import annotations

from faultloom_protocol.base import MAX_INT64

from .adapter_classify import _ProviderAdapterClassify
from .adapter_helpers import _ceil_cost
from .common import FailureCode, ProviderPolicyError
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile
from .proxy import ProviderProxyRequest, ProviderProxyResult

class ProviderAdapter(_ProviderAdapterClassify):
    def configured_profile(self, profile_id: str) -> ProviderModelProfile:
        """Return a revalidated copy of one configured provider profile.

        Higher-level authority boundaries use this lookup to reject a provider
        or model snapshot before any prompt can cross the proxy boundary.
        """

        if type(profile_id) is not str or not profile_id:
            raise ProviderPolicyError("provider profile ID must be non-empty")
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise ProviderPolicyError("provider profile is not configured")
        return ProviderModelProfile.model_validate(profile.model_dump(mode="python"))

    def _completed_response_failure(
        self,
        intent: ProviderCallIntent,
        profile: ProviderModelProfile,
        result: ProviderProxyResult,
        proxy_request: ProviderProxyRequest,
    ) -> FailureCode | None:
        metadata = result.observed_metadata
        usage = result.usage
        if metadata is None or usage is None:
            return FailureCode.METADATA_MISSING
        if metadata.provider_id != profile.provider_id:
            return FailureCode.METADATA_MISMATCH
        if metadata.actual_snapshot is not None and (
            metadata.actual_snapshot != profile.exact_snapshot
        ):
            return FailureCode.METADATA_MISMATCH
        if profile.metadata_exact:
            exact = (
                metadata.actual_snapshot == profile.exact_snapshot
                and metadata.runtime_version == profile.runtime_version
                and metadata.tokenizer_id == profile.tokenizer_id
                and metadata.tokenizer_version == profile.tokenizer_version
                and metadata.context_window == profile.context_window
                and metadata.snapshot_exact
                and metadata.runtime_exact
                and metadata.tokenizer_exact
                and metadata.context_window_exact
                and metadata.provenance.exact
            )
            if not exact:
                return FailureCode.METADATA_MISSING if any(
                    value is None
                    for value in (
                        metadata.actual_snapshot,
                        metadata.runtime_version,
                        metadata.tokenizer_id,
                        metadata.tokenizer_version,
                        metadata.context_window,
                    )
                ) else FailureCode.METADATA_MISMATCH
        elif self._live:
            return FailureCode.METADATA_MISSING
        if (
            metadata.context_window is not None
            and intent.input_tokens
            + intent.generation_config.max_output_tokens
            + profile.prompt_overhead_tokens
            > metadata.context_window
        ):
            return FailureCode.METADATA_MISMATCH
        if result.accepted_prompt_digest != proxy_request.prompt_digest:
            return FailureCode.PROMPT_DIGEST_MISMATCH
        if (
            result.accepted_compiled_context_digest
            != proxy_request.compiled_context_digest
        ):
            return FailureCode.COMPILED_CONTEXT_DRIFT
        if result.accepted_tool_schema_digest != proxy_request.tool_schema_digest:
            return FailureCode.TOOL_SCHEMA_DRIFT
        if result.accepted_output_schema_digest != proxy_request.output_schema_digest:
            return FailureCode.OUTPUT_SCHEMA_DRIFT
        if result.accepted_config_digest != proxy_request.config_digest:
            return FailureCode.CONFIG_DRIFT
        if (
            result.accepted_policy_ref != proxy_request.policy_ref
            or result.accepted_data_policy_id != proxy_request.data_policy_id
            or result.accepted_data_consent_ref != proxy_request.data_consent_ref
        ):
            return FailureCode.POLICY_DRIFT
        if usage.input_tokens > min(
            intent.input_tokens,
            intent.budget.maximum_input_tokens,
            profile.maximum_input_tokens,
        ):
            return FailureCode.USAGE_INVALID
        if usage.output_tokens > min(
            intent.generation_config.max_output_tokens,
            intent.budget.maximum_output_tokens,
            profile.maximum_output_tokens,
        ):
            return FailureCode.TOKEN_BUDGET_EXCEEDED
        if (
            usage.input_tokens
            + usage.output_tokens
            + profile.prompt_overhead_tokens
            > profile.context_window
        ):
            return FailureCode.TOKEN_BUDGET_EXCEEDED
        if (
            metadata.context_window is not None
            and usage.input_tokens
            + usage.output_tokens
            + profile.prompt_overhead_tokens
            > metadata.context_window
        ):
            return FailureCode.TOKEN_BUDGET_EXCEEDED
        if (
            usage.input_tokens + usage.output_tokens
            > intent.budget.remaining_model_tokens
        ):
            return FailureCode.TOKEN_BUDGET_EXCEEDED
        cost = _ceil_cost(
            usage.input_tokens, profile.input_cost_per_million_microunits
        ) + _ceil_cost(
            usage.output_tokens, profile.output_cost_per_million_microunits
        )
        if cost > MAX_INT64:
            return FailureCode.USAGE_INVALID
        if cost > intent.budget.remaining_cost_microunits:
            return FailureCode.COST_BUDGET_EXCEEDED
        if (
            result.bytes_sent > profile.maximum_request_bytes
            or result.bytes_received > profile.maximum_response_bytes
        ):
            return FailureCode.BYTE_BUDGET_EXCEEDED
        return None
