from __future__ import annotations

from datetime import datetime

from faultloom_protocol.base import MAX_INT64

from .adapter_helpers import _ceil_cost
from .adapter_retry import _ProviderAdapterRetry
from .common import SCHEMA_VERSION, provider_sha256_digest as sha256_digest
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile
from .proxy import ProviderProxyRequest, ProviderProxyResult
from .receipt import ProviderCallReceipt

class _ProviderAdapterReceipt(_ProviderAdapterRetry):
    def _make_receipt(
        self,
        *,
        intent: ProviderCallIntent,
        profile: ProviderModelProfile,
        profile_digest: str,
        result: ProviderProxyResult | None,
        tool_digest: str,
        config_digest: str,
        budget_digest: str,
        logical_digest: str,
        dispatch_reservation_digest: str,
        proxy_request: ProviderProxyRequest,
        proxy_request_digest: str,
        proxy_binding_unchanged: bool,
        started_at: datetime,
        completed_at: datetime,
        elapsed_ns: int,
    ) -> ProviderCallReceipt:
        outcome, failure, retry, reconciliation = self._classify_result(
            intent,
            profile,
            result,
            proxy_request,
            proxy_binding_unchanged,
        )
        metadata = None if result is None else result.observed_metadata
        usage = None if result is None else result.usage
        cost: int | None = 0
        if usage is not None:
            cost = _ceil_cost(
                usage.input_tokens, profile.input_cost_per_million_microunits
            ) + _ceil_cost(
                usage.output_tokens, profile.output_cost_per_million_microunits
            )
            if cost > MAX_INT64:
                cost = None
        payload = {
            "schema_version": SCHEMA_VERSION,
            "call_id": intent.call_id,
            "attempt_id": intent.attempt_id,
            "attempt": intent.attempt,
            "run_id": intent.run_id,
            "authority_digest": intent.authority_digest,
            "scope_epoch": intent.scope_epoch,
            "profile_id": profile.profile_id,
            "profile_digest": profile_digest,
            "provider_id": profile.provider_id,
            "endpoint_id": profile.endpoint_id,
            "proxy_id": self._proxy_id,
            "proxy_attestation_key_id": self._proxy_attestation_record.key_id,
            "requested_alias": profile.requested_alias,
            "requested_snapshot": profile.exact_snapshot,
            "actual_snapshot": None if metadata is None else metadata.actual_snapshot,
            "runtime_version": None if metadata is None else metadata.runtime_version,
            "tokenizer_id": None if metadata is None else metadata.tokenizer_id,
            "tokenizer_version": None if metadata is None else metadata.tokenizer_version,
            "context_window": None if metadata is None else metadata.context_window,
            "metadata_exact": bool(
                metadata is not None
                and metadata.snapshot_exact
                and metadata.runtime_exact
                and metadata.tokenizer_exact
                and metadata.context_window_exact
                and metadata.provenance.exact
            ),
            "metadata_provenance_digest": (
                None if metadata is None else sha256_digest(metadata.provenance)
            ),
            "prompt_digest": intent.prompt_digest,
            "compiled_context_digest": intent.compiled_context_digest,
            "prompt_bytes": intent.prompt_bytes,
            "provider_tool_ids": tuple(tool.tool_id for tool in intent.tools),
            "tool_schema_digest": tool_digest,
            "output_schema_digest": intent.output_schema_digest,
            "config_digest": config_digest,
            "budget_digest": budget_digest,
            "logical_request_digest": logical_digest,
            "dispatch_reservation_digest": dispatch_reservation_digest,
            "proxy_request": proxy_request,
            "proxy_request_digest": proxy_request_digest,
            "proxy_receipt_digest": None if result is None else result.proxy_receipt_digest,
            "proxy_result": result,
            "proxy_contract_digest": self._proxy_contract_digest,
            "response_digest": None if result is None else result.response_digest,
            "credential_ref_digest": sha256_digest(intent.credential_ref),
            "action_ids": intent.action_ids,
            "policy_ref": intent.policy_ref,
            "data_policy_id": intent.data_policy_id,
            "data_consent_ref": intent.data_consent_ref,
            "request_requested_at": intent.requested_at,
            "live": self._live,
            "previous_receipt_digest": intent.previous_receipt_digest,
            "failover_provenance_digest": (
                None if intent.failover is None else sha256_digest(intent.failover)
            ),
            "failover_checkpoint_id": (
                None if intent.failover is None else intent.failover.checkpoint_id
            ),
            "failover_checkpoint_digest": (
                None if intent.failover is None else intent.failover.checkpoint_digest
            ),
            "planned_input_tokens": intent.input_tokens,
            "reserved_output_tokens": intent.generation_config.max_output_tokens,
            "reported_input_tokens": None if usage is None else usage.input_tokens,
            "reported_output_tokens": None if usage is None else usage.output_tokens,
            "cost_microunits": cost,
            "bytes_sent": 0 if result is None else result.bytes_sent,
            "bytes_received": 0 if result is None else result.bytes_received,
            "latency_milliseconds": (elapsed_ns + 999_999) // 1_000_000,
            "started_at": started_at,
            "completed_at": completed_at,
            "outcome": outcome,
            "failure_code": failure,
            "retry_disposition": retry,
            "reconciliation_required": reconciliation,
        }
        return ProviderCallReceipt(
            receipt_digest=sha256_digest(payload),
            **payload,
        )
