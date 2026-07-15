from __future__ import annotations

import hmac
from typing import Self

from faultloom_protocol import sha256_digest
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest, ShortStr
from pydantic import model_validator

from .common import (
    FailureCode,
    ProviderCallOutcome,
    ProviderPlane,
    RetryDisposition,
    Signed64NonNegative,
    Signed64Positive,
    _RuntimeModel,
)
from .proxy import ProviderProxyRequest, ProviderProxyResult, _dispatch_reservation_digest


class ProviderCallReceipt(_RuntimeModel):
    receipt_digest: Sha256Digest
    call_id: Identifier
    attempt_id: Identifier
    attempt: Signed64Positive
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: Signed64Positive
    profile_id: Identifier
    profile_digest: Sha256Digest
    provider_id: Identifier
    endpoint_id: Identifier
    proxy_id: Identifier
    proxy_attestation_key_id: Identifier
    requested_alias: ShortStr | None = None
    requested_snapshot: ShortStr
    actual_snapshot: ShortStr | None = None
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive | None = None
    metadata_exact: bool
    metadata_provenance_digest: Sha256Digest | None = None
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    prompt_bytes: Signed64Positive
    provider_tool_ids: tuple[Identifier, ...]
    tool_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    config_digest: Sha256Digest
    budget_digest: Sha256Digest
    logical_request_digest: Sha256Digest
    dispatch_reservation_digest: Sha256Digest
    proxy_request: ProviderProxyRequest
    proxy_request_digest: Sha256Digest
    proxy_receipt_digest: Sha256Digest | None = None
    proxy_result: ProviderProxyResult | None = None
    proxy_contract_digest: Sha256Digest
    response_digest: Sha256Digest | None = None
    credential_ref_digest: Sha256Digest
    action_ids: tuple[Identifier, ...]
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    request_requested_at: AwareDatetime
    live: bool
    previous_receipt_digest: Sha256Digest | None = None
    failover_provenance_digest: Sha256Digest | None = None
    failover_checkpoint_id: Identifier | None = None
    failover_checkpoint_digest: Sha256Digest | None = None
    planned_input_tokens: Signed64NonNegative
    reserved_output_tokens: Signed64Positive
    reported_input_tokens: Signed64NonNegative | None = None
    reported_output_tokens: Signed64NonNegative | None = None
    cost_microunits: Signed64NonNegative | None
    bytes_sent: Signed64NonNegative
    bytes_received: Signed64NonNegative
    latency_milliseconds: Signed64NonNegative
    started_at: AwareDatetime
    completed_at: AwareDatetime
    outcome: ProviderCallOutcome
    failure_code: FailureCode | None = None
    retry_disposition: RetryDisposition
    reconciliation_required: bool = False

    @model_validator(mode="after")
    def _valid_receipt(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("provider receipt completion precedes its start")
        if (self.outcome is ProviderCallOutcome.COMPLETED) != (self.failure_code is None):
            raise ValueError("only completed provider receipts omit a failure code")
        if (self.outcome is ProviderCallOutcome.UNKNOWN_OUTCOME) != (
            self.retry_disposition is RetryDisposition.RECONCILIATION_REQUIRED
            and self.reconciliation_required
        ):
            raise ValueError("unknown outcomes alone require reconciliation")
        if self.outcome is not ProviderCallOutcome.UNKNOWN_OUTCOME and self.reconciliation_required:
            raise ValueError("known provider outcomes cannot require reconciliation")
        if (
            self.retry_disposition is RetryDisposition.EXPLICIT_RETRY_ALLOWED
        ) != (self.outcome is ProviderCallOutcome.PRE_SEND_FAILED):
            raise ValueError("only explicit pre-send failures may be retried")
        if (self.failover_checkpoint_id is None) != (
            self.failover_checkpoint_digest is None
        ):
            raise ValueError("failover checkpoint ID and digest must appear together")
        if (self.failover_provenance_digest is None) != (
            self.failover_checkpoint_id is None
        ):
            raise ValueError("failover receipt requires provenance and a checkpoint")
        expected_reservation_digest = _dispatch_reservation_digest(
            call_id=self.call_id,
            attempt_id=self.attempt_id,
            attempt=self.attempt,
            run_id=self.run_id,
            logical_request_digest=self.logical_request_digest,
            profile_digest=self.profile_digest,
            proxy_id=self.proxy_id,
            proxy_contract_digest=self.proxy_contract_digest,
            proxy_attestation_key_id=self.proxy_attestation_key_id,
        )
        request = self.proxy_request
        if (
            not hmac.compare_digest(
                self.dispatch_reservation_digest,
                expected_reservation_digest,
            )
            or not hmac.compare_digest(
                request.dispatch_reservation_digest,
                expected_reservation_digest,
            )
            or not hmac.compare_digest(
                self.proxy_request_digest,
                sha256_digest(request),
            )
            or request.plane is not ProviderPlane.MODEL_PROVIDER
            or request.request_id != self.attempt_id
            or request.run_id != self.run_id
            or request.authority_digest != self.authority_digest
            or request.scope_epoch != self.scope_epoch
            or request.endpoint_id != self.endpoint_id
            or request.provider_id != self.provider_id
            or request.requested_alias != self.requested_alias
            or request.model_snapshot != self.requested_snapshot
            or request.proxy_id != self.proxy_id
            or request.proxy_contract_digest != self.proxy_contract_digest
            or request.proxy_attestation_key_id != self.proxy_attestation_key_id
            or request.prompt_digest != self.prompt_digest
            or request.compiled_context_digest != self.compiled_context_digest
            or request.payload_digest != self.prompt_digest
            or request.payload_bytes != self.prompt_bytes
            or request.tool_ids != self.provider_tool_ids
            or request.tool_schema_digest != self.tool_schema_digest
            or request.output_schema_digest != self.output_schema_digest
            or request.config_digest != self.config_digest
            or request.policy_ref != self.policy_ref
            or request.data_policy_id != self.data_policy_id
            or request.data_consent_ref != self.data_consent_ref
            or not hmac.compare_digest(
                sha256_digest(request.credential_ref),
                self.credential_ref_digest,
            )
            or request.requested_at != self.request_requested_at
            or request.live is not self.live
        ):
            raise ValueError(
                "provider receipt is not bound to its canonical proxy request"
            )
        if (self.proxy_result is None) != (self.proxy_receipt_digest is None):
            raise ValueError("proxy result and its receipt digest must appear together")
        if self.proxy_result is not None and not hmac.compare_digest(
            self.proxy_result.proxy_receipt_digest,
            self.proxy_receipt_digest,
        ):
            raise ValueError("proxy result does not match the receipted proxy digest")
        if self.proxy_result is not None:
            result = self.proxy_result
            result_usage = result.usage
            if (
                result.request_id != self.attempt_id
                or not hmac.compare_digest(
                    result.proxy_request_digest,
                    self.proxy_request_digest,
                )
                or result.attested_proxy_id != self.proxy_id
                or result.attested_proxy_contract_digest != self.proxy_contract_digest
                or result.attestation_key_id != self.proxy_attestation_key_id
                or result.response_digest != self.response_digest
                or result.bytes_sent != self.bytes_sent
                or result.bytes_received != self.bytes_received
                or (
                    None if result_usage is None else result_usage.input_tokens
                )
                != self.reported_input_tokens
                or (
                    None if result_usage is None else result_usage.output_tokens
                )
                != self.reported_output_tokens
            ):
                raise ValueError("provider receipt is not bound to its signed proxy result")
        payload = self.model_dump(mode="python", exclude={"receipt_digest"})
        if not hmac.compare_digest(self.receipt_digest, sha256_digest(payload)):
            raise ValueError("provider receipt digest does not match its fields")
        return self


def _provider_journal_binding_digest(receipt: ProviderCallReceipt) -> str:
    """Bind every attempt field that may not change during finalization."""

    return sha256_digest(
        {
            "purpose": "faultloom.provider_journal_binding.v1",
            "call_id": receipt.call_id,
            "attempt_id": receipt.attempt_id,
            "attempt": receipt.attempt,
            "run_id": receipt.run_id,
            "authority_digest": receipt.authority_digest,
            "scope_epoch": receipt.scope_epoch,
            "profile_id": receipt.profile_id,
            "profile_digest": receipt.profile_digest,
            "provider_id": receipt.provider_id,
            "endpoint_id": receipt.endpoint_id,
            "requested_alias": receipt.requested_alias,
            "requested_snapshot": receipt.requested_snapshot,
            "prompt_digest": receipt.prompt_digest,
            "compiled_context_digest": receipt.compiled_context_digest,
            "prompt_bytes": receipt.prompt_bytes,
            "provider_tool_ids": receipt.provider_tool_ids,
            "tool_schema_digest": receipt.tool_schema_digest,
            "output_schema_digest": receipt.output_schema_digest,
            "config_digest": receipt.config_digest,
            "budget_digest": receipt.budget_digest,
            "logical_request_digest": receipt.logical_request_digest,
            "dispatch_reservation_digest": receipt.dispatch_reservation_digest,
            "proxy_request_digest": receipt.proxy_request_digest,
            "proxy_id": receipt.proxy_id,
            "proxy_contract_digest": receipt.proxy_contract_digest,
            "proxy_attestation_key_id": receipt.proxy_attestation_key_id,
            "credential_ref_digest": receipt.credential_ref_digest,
            "action_ids": receipt.action_ids,
            "policy_ref": receipt.policy_ref,
            "data_policy_id": receipt.data_policy_id,
            "data_consent_ref": receipt.data_consent_ref,
            "previous_receipt_digest": receipt.previous_receipt_digest,
            "failover_provenance_digest": receipt.failover_provenance_digest,
            "failover_checkpoint_id": receipt.failover_checkpoint_id,
            "failover_checkpoint_digest": receipt.failover_checkpoint_digest,
            "planned_input_tokens": receipt.planned_input_tokens,
            "reserved_output_tokens": receipt.reserved_output_tokens,
            "request_requested_at": receipt.request_requested_at,
            "started_at": receipt.started_at,
            "live": receipt.live,
        }
    )
