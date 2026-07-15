from __future__ import annotations

import hmac

from faultloom_protocol import Ed25519PublicKeyRecord

from .adapter_helpers import _ceil_cost
from .adapter_proxy import _ProviderAdapterProxy
from .common import (
    ProviderBudgetError,
    ProviderMetadataError,
    ProviderPlane,
    ProviderPlaneError,
    ProviderPolicyError,
    ProviderToolKind,
    _PROVIDER_CREDENTIAL_PURPOSE,
)
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile, provider_tool_schema_digest


class _ProviderAdapterPolicy(_ProviderAdapterProxy):
    def _validate_proxy_binding(self) -> None:
        if getattr(self._proxy, "plane", None) is not ProviderPlane.MODEL_PROVIDER:
            raise ProviderPlaneError("provider proxy plane changed after admission")
        if getattr(self._proxy, "proxy_id", None) != self._proxy_id:
            raise ProviderPlaneError("provider proxy identity changed after admission")
        if getattr(self._proxy, "contract_digest", None) != self._proxy_contract_digest:
            raise ProviderPlaneError("provider proxy contract changed after admission")
        current_attestation_key = getattr(self._proxy, "attestation_public_key", None)
        try:
            current_attestation_key = Ed25519PublicKeyRecord.model_validate(
                current_attestation_key.model_dump(mode="python")
            )
        except Exception as exc:
            raise ProviderPlaneError("provider proxy attestation key changed") from exc
        if current_attestation_key != self._proxy_attestation_record:
            raise ProviderPlaneError("provider proxy attestation key changed")
        current_dispatch = getattr(self._proxy, "dispatch", None)
        if (
            getattr(current_dispatch, "__self__", None) is not self._proxy_dispatch_owner
            or getattr(current_dispatch, "__func__", current_dispatch)
            is not self._proxy_dispatch_function
        ):
            raise ProviderPlaneError("provider proxy dispatch port changed after admission")

    def _validate_pre_dispatch(
        self, intent: ProviderCallIntent, profile: ProviderModelProfile
    ) -> None:
        if self._live:
            profile.require_live_safe()
            if (
                type(intent.credential_ref.purpose) is not str
                or _PROVIDER_CREDENTIAL_PURPOSE.fullmatch(
                    intent.credential_ref.purpose
                )
                is None
            ):
                raise ProviderPolicyError(
                    "live provider credential purpose must be a canonical identifier"
                )
            forbidden = {
                ProviderToolKind.WEB,
                ProviderToolKind.COMPUTER,
                ProviderToolKind.NETWORK,
            }
            if forbidden.intersection(tool.kind for tool in intent.tools):
                raise ProviderPolicyError("live provider web/computer/network tools are disabled")
        elif not profile.metadata_exact and not profile.lab_only_conservative:
            raise ProviderMetadataError("ambiguous lab metadata requires an explicit profile")
        if (
            intent.policy_ref != profile.policy_ref
            or intent.data_policy_id != profile.data_policy_id
            or intent.data_consent_ref != profile.data_consent_ref
        ):
            raise ProviderPolicyError("provider policy or data-consent reference drift")
        tool_digest = provider_tool_schema_digest(intent.tools)
        if not hmac.compare_digest(tool_digest, profile.tool_schema_digest):
            raise ProviderPolicyError("provider tool schema drift")
        if intent.prompt_bytes > profile.maximum_request_bytes:
            raise ProviderBudgetError("provider prompt exceeds the request byte ceiling")
        if intent.input_tokens > min(
            profile.maximum_input_tokens, intent.budget.maximum_input_tokens
        ):
            raise ProviderBudgetError("provider input exceeds the token ceiling")
        reserved_output = intent.generation_config.max_output_tokens
        if reserved_output > min(
            profile.maximum_output_tokens, intent.budget.maximum_output_tokens
        ):
            raise ProviderBudgetError("provider output reservation exceeds the token ceiling")
        if (
            intent.input_tokens + reserved_output + profile.prompt_overhead_tokens
            > profile.context_window
        ):
            raise ProviderBudgetError("provider call exceeds the effective context window")
        if intent.input_tokens + reserved_output > intent.budget.remaining_model_tokens:
            raise ProviderBudgetError("provider call exceeds the remaining token budget")
        estimated_cost = _ceil_cost(
            intent.input_tokens, profile.input_cost_per_million_microunits
        ) + _ceil_cost(
            reserved_output, profile.output_cost_per_million_microunits
        )
        if estimated_cost > intent.budget.remaining_cost_microunits:
            raise ProviderBudgetError("provider call exceeds the remaining cost budget")
