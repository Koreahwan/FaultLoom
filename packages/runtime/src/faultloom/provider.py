"""Fail-closed model provider adapter.

The adapter owns model identity and accounting, but it never owns network
transport.  All dispatches cross the injected model-provider proxy port using
digests and secret references only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Callable, Iterable, Literal, Protocol, Self, final

from faultloom.state import (
    ArtifactRef,
    AnchorCheckpoint,
    EncryptedCAS,
    EventLedger,
    EventRecord,
    ProviderCanonicalReceipt,
    ProviderJournalEntry,
    ProviderJournalRecord,
    ProviderReceiptMetadata,
    StateStore,
)

from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    ProtocolModel,
    SecretRef,
    canonical_json_bytes,
    load_public_key,
    sha256_digest,
)
from faultloom_protocol.base import (
    AwareDatetime,
    Identifier,
    MAX_INT64,
    NonEmptyStr,
    Sha256Digest,
    ShortStr,
)
from pydantic import Field, model_validator

SCHEMA_VERSION = "0.1.0"
Signed64NonNegative = Annotated[int, Field(strict=True, ge=0, le=MAX_INT64)]
Signed64Positive = Annotated[int, Field(strict=True, ge=1, le=MAX_INT64)]
_PROVIDER_CREDENTIAL_PURPOSE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
)


class ProviderAdapterError(RuntimeError):
    """Base class for provider admission and accounting failures."""


class ProviderPolicyError(ProviderAdapterError):
    """A call conflicts with pinned provider policy."""


class ProviderMetadataError(ProviderAdapterError):
    """Provider identity or runtime metadata is ambiguous or inconsistent."""


class ProviderBudgetError(ProviderAdapterError):
    """A call cannot fit its pinned token, byte, or cost budget."""


class ProviderRetryError(ProviderAdapterError):
    """A retry or failover lacks an admissible prior receipt."""


class ProviderReceiptError(ProviderAdapterError):
    """An immutable call receipt failed validation or journal admission."""


class ProviderPlaneError(ProviderAdapterError):
    """A provider component attempted to use a non-provider egress plane."""


class _RuntimeModel(ProtocolModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION


class ProviderPlane(str, Enum):
    MODEL_PROVIDER = "model_provider"
    TARGET = "target"
    KNOWLEDGE = "knowledge"


class ProviderToolKind(str, Enum):
    FUNCTION = "function"
    WEB = "web"
    COMPUTER = "computer"
    NETWORK = "network"


class MetadataSourceKind(str, Enum):
    PROVIDER_RESPONSE = "provider_response"
    PINNED_REGISTRY = "pinned_registry"
    OPERATOR_PIN = "operator_pin"
    CONSERVATIVE_LAB = "conservative_lab"


class ProxyOutcome(str, Enum):
    COMPLETED = "completed"
    PRE_SEND_FAILED = "pre_send_failed"
    DENIED = "denied"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class ProxyEffectDisposition(str, Enum):
    NOT_DISPATCHED = "not_dispatched"
    POSSIBLE = "possible"
    OBSERVED = "observed"


class ProviderCallOutcome(str, Enum):
    COMPLETED = "completed"
    PRE_SEND_FAILED = "pre_send_failed"
    DENIED = "denied"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    REJECTED_RESPONSE = "rejected_response"


class RetryDisposition(str, Enum):
    EXPLICIT_RETRY_ALLOWED = "explicit_retry_allowed"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    BLOCKED_FINAL = "blocked_final"


class FailureCode(str, Enum):
    PROXY_PRE_SEND_FAILED = "proxy_pre_send_failed"
    PROXY_DENIED = "proxy_denied"
    PROXY_FAILED = "proxy_failed"
    PROXY_EXCEPTION_UNKNOWN = "proxy_exception_unknown"
    PROXY_PLANE_MISMATCH = "proxy_plane_mismatch"
    PROXY_IDENTITY_MISMATCH = "proxy_identity_mismatch"
    PROXY_CORRELATION_MISMATCH = "proxy_correlation_mismatch"
    METADATA_MISSING = "metadata_missing"
    METADATA_MISMATCH = "metadata_mismatch"
    PROMPT_DIGEST_MISMATCH = "prompt_digest_mismatch"
    COMPILED_CONTEXT_DRIFT = "compiled_context_drift"
    TOOL_SCHEMA_DRIFT = "tool_schema_drift"
    OUTPUT_SCHEMA_DRIFT = "output_schema_drift"
    CONFIG_DRIFT = "config_drift"
    POLICY_DRIFT = "policy_drift"
    USAGE_INVALID = "usage_invalid"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    COST_BUDGET_EXCEEDED = "cost_budget_exceeded"
    BYTE_BUDGET_EXCEEDED = "byte_budget_exceeded"


class MetadataProvenance(_RuntimeModel):
    source_kind: MetadataSourceKind
    source_id: Identifier
    evidence_digest: Sha256Digest
    observed_at: AwareDatetime
    exact: bool

    @model_validator(mode="after")
    def _conservative_is_not_exact(self) -> Self:
        if self.source_kind is MetadataSourceKind.CONSERVATIVE_LAB and self.exact:
            raise ValueError("conservative lab provenance cannot claim exact metadata")
        return self


class ProviderToolSpec(_RuntimeModel):
    tool_id: Identifier
    kind: ProviderToolKind
    input_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest


def provider_tool_schema_digest(tools: Iterable[ProviderToolSpec]) -> str:
    """Digest a deterministic, duplicate-free provider tool contract."""

    validated = tuple(
        ProviderToolSpec.model_validate(tool.model_dump(mode="python")) for tool in tools
    )
    tool_ids = tuple(tool.tool_id for tool in validated)
    if len(tool_ids) != len(set(tool_ids)):
        raise ValueError("provider tool IDs must be unique")
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "tools": tuple(
                tool.model_dump(mode="python")
                for tool in sorted(validated, key=lambda candidate: candidate.tool_id)
            ),
        }
    )


class ProviderModelProfile(_RuntimeModel):
    profile_id: Identifier
    provider_id: Identifier
    endpoint_id: Identifier
    requested_alias: ShortStr | None = None
    exact_snapshot: ShortStr
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive
    prompt_overhead_tokens: Signed64NonNegative
    maximum_input_tokens: Signed64Positive
    maximum_output_tokens: Signed64Positive
    maximum_request_bytes: Signed64Positive
    maximum_response_bytes: Signed64Positive
    input_cost_per_million_microunits: Signed64NonNegative
    output_cost_per_million_microunits: Signed64NonNegative
    compatibility_group: Identifier
    capability_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    metadata_exact: bool
    lab_only_conservative: bool = False
    metadata_provenance: MetadataProvenance

    @model_validator(mode="after")
    def _valid_profile(self) -> Self:
        if self.requested_alias == self.exact_snapshot:
            raise ValueError("requested alias cannot stand in for an exact model snapshot")
        if (
            self.maximum_input_tokens
            + self.maximum_output_tokens
            + self.prompt_overhead_tokens
            > self.context_window
        ):
            raise ValueError("provider token ceilings exceed the effective context window")
        exact_fields = (
            self.runtime_version,
            self.tokenizer_id,
            self.tokenizer_version,
        )
        if self.metadata_exact:
            if self.lab_only_conservative or not self.metadata_provenance.exact:
                raise ValueError("exact metadata cannot use a conservative lab provenance")
            if any(value is None for value in exact_fields):
                raise ValueError("exact provider metadata requires runtime and tokenizer facts")
        else:
            if not self.lab_only_conservative:
                raise ValueError("ambiguous metadata requires an explicit lab-only profile")
            if self.metadata_provenance.source_kind is not MetadataSourceKind.CONSERVATIVE_LAB:
                raise ValueError("ambiguous metadata requires conservative-lab provenance")
            if self.metadata_provenance.exact:
                raise ValueError("conservative lab metadata cannot claim exact provenance")
        return self

    def require_live_safe(self) -> None:
        if not self.metadata_exact or self.lab_only_conservative:
            raise ProviderMetadataError("live calls require exact pinned provider metadata")


class ProviderObservedMetadata(_RuntimeModel):
    provider_id: Identifier
    actual_snapshot: ShortStr | None = None
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive | None = None
    snapshot_exact: bool = False
    runtime_exact: bool = False
    tokenizer_exact: bool = False
    context_window_exact: bool = False
    provenance: MetadataProvenance


class GenerationConfig(_RuntimeModel):
    max_output_tokens: Signed64Positive
    temperature_milli: Signed64NonNegative = Field(le=2000)
    top_p_milli: Signed64Positive = Field(le=1000)
    seed: Signed64NonNegative | None = None
    response_format: Literal["text", "json"] = "text"


class ProviderCallBudget(_RuntimeModel):
    maximum_input_tokens: Signed64Positive
    maximum_output_tokens: Signed64Positive
    remaining_model_tokens: Signed64NonNegative
    remaining_cost_microunits: Signed64NonNegative


class FailoverProvenance(_RuntimeModel):
    previous_receipt_digest: Sha256Digest
    from_profile_id: Identifier
    from_profile_digest: Sha256Digest
    to_profile_id: Identifier
    to_profile_digest: Sha256Digest
    checkpoint_id: Identifier
    checkpoint_digest: Sha256Digest
    reason_code: Identifier
    approved_at: AwareDatetime
    approver_key_id: Identifier
    approval_signature: NonEmptyStr

    @model_validator(mode="after")
    def _changes_profile(self) -> Self:
        if self.from_profile_id == self.to_profile_id:
            raise ValueError("failover must change the configured provider profile")
        return self


def failover_provenance_attestation_bytes(
    provenance: FailoverProvenance,
) -> bytes:
    """Return the exact failover approval document signed by T23."""

    if type(provenance) is not FailoverProvenance:
        raise TypeError("failover approval requires an exact provenance model")
    return canonical_json_bytes(
        {
            "purpose": "faultloom.provider_failover_approval.v1",
            "provenance": provenance.model_dump(
                mode="python",
                exclude={"approval_signature"},
            ),
        }
    )


class ProviderCallIntent(_RuntimeModel):
    call_id: Identifier
    attempt_id: Identifier
    attempt: Signed64Positive
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: Signed64Positive
    profile_id: Identifier
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    prompt_bytes: Signed64Positive
    input_tokens: Signed64NonNegative
    tools: tuple[ProviderToolSpec, ...] = ()
    output_schema_digest: Sha256Digest
    generation_config: GenerationConfig
    budget: ProviderCallBudget
    action_ids: tuple[Identifier, ...]
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    credential_ref: SecretRef
    requested_at: AwareDatetime
    previous_receipt_digest: Sha256Digest | None = None
    failover: FailoverProvenance | None = None

    @model_validator(mode="after")
    def _valid_intent(self) -> Self:
        if not self.action_ids:
            raise ValueError("provider call requires at least one action ID")
        if len(self.action_ids) != len(set(self.action_ids)):
            raise ValueError("provider action IDs must be unique")
        tool_ids = tuple(tool.tool_id for tool in self.tools)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("provider tool IDs must be unique")
        if self.attempt == 1:
            if self.previous_receipt_digest is not None or self.failover is not None:
                raise ValueError("first provider attempt cannot cite a prior receipt")
        elif self.previous_receipt_digest is None:
            raise ValueError("later provider attempts require a prior receipt digest")
        if self.failover is not None and (
            self.previous_receipt_digest != self.failover.previous_receipt_digest
        ):
            raise ValueError("failover and retry receipt digests must match")
        return self


class ProviderUsage(_RuntimeModel):
    input_tokens: Signed64NonNegative
    output_tokens: Signed64NonNegative


class ProviderProxyRequest(_RuntimeModel):
    plane: Literal[ProviderPlane.MODEL_PROVIDER] = ProviderPlane.MODEL_PROVIDER
    proxy_id: Identifier
    proxy_contract_digest: Sha256Digest
    proxy_attestation_key_id: Identifier
    dispatch_reservation_digest: Sha256Digest
    request_id: Identifier
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: Signed64Positive
    endpoint_id: Identifier
    provider_id: Identifier
    requested_alias: ShortStr | None = None
    model_snapshot: ShortStr
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: Signed64Positive
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    config_digest: Sha256Digest
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    credential_ref: SecretRef
    payload_digest: Sha256Digest
    payload_bytes: Signed64Positive
    tool_ids: tuple[Identifier, ...] = ()
    requested_at: AwareDatetime
    live: bool


class ProviderProxyResult(_RuntimeModel):
    plane: ProviderPlane
    request_id: Identifier
    proxy_request_digest: Sha256Digest
    attested_proxy_id: Identifier
    attested_proxy_contract_digest: Sha256Digest
    attestation_key_id: Identifier
    proxy_receipt_digest: Sha256Digest
    attestation_signature: NonEmptyStr
    outcome: ProxyOutcome
    effect_disposition: ProxyEffectDisposition
    response_digest: Sha256Digest | None = None
    response_status: Signed64NonNegative | None = None
    bytes_sent: Signed64NonNegative
    bytes_received: Signed64NonNegative
    reconciliation_required: bool = False
    observed_metadata: ProviderObservedMetadata | None = None
    usage: ProviderUsage | None = None
    accepted_prompt_digest: Sha256Digest | None = None
    accepted_compiled_context_digest: Sha256Digest | None = None
    accepted_tool_schema_digest: Sha256Digest | None = None
    accepted_output_schema_digest: Sha256Digest | None = None
    accepted_config_digest: Sha256Digest | None = None
    accepted_policy_ref: Identifier | None = None
    accepted_data_policy_id: Identifier | None = None
    accepted_data_consent_ref: Identifier | None = None
    accepted_proxy_id: Identifier | None = None
    accepted_proxy_contract_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _outcome_contract(self) -> Self:
        pre_send = self.outcome in {ProxyOutcome.PRE_SEND_FAILED, ProxyOutcome.DENIED}
        if pre_send and (self.bytes_sent or self.bytes_received):
            raise ValueError("pre-send proxy outcomes cannot report transport bytes")
        if pre_send and self.effect_disposition is not ProxyEffectDisposition.NOT_DISPATCHED:
            raise ValueError("pre-send outcomes require an attested no-dispatch disposition")
        if (
            self.outcome is ProxyOutcome.COMPLETED
            and self.effect_disposition is not ProxyEffectDisposition.OBSERVED
        ):
            raise ValueError("completed outcomes require an observed upstream effect")
        if self.outcome in {ProxyOutcome.FAILED, ProxyOutcome.UNKNOWN_OUTCOME} and (
            self.effect_disposition is ProxyEffectDisposition.NOT_DISPATCHED
        ):
            raise ValueError("post-send failure outcomes cannot claim no dispatch")
        if (self.outcome is ProxyOutcome.UNKNOWN_OUTCOME) != self.reconciliation_required:
            raise ValueError("only unknown outcomes require reconciliation")
        completed_fields = (
            self.response_digest,
            self.observed_metadata,
            self.usage,
            self.accepted_prompt_digest,
            self.accepted_compiled_context_digest,
            self.accepted_tool_schema_digest,
            self.accepted_output_schema_digest,
            self.accepted_config_digest,
            self.accepted_policy_ref,
            self.accepted_data_policy_id,
            self.accepted_data_consent_ref,
            self.accepted_proxy_id,
            self.accepted_proxy_contract_digest,
        )
        if self.outcome is ProxyOutcome.COMPLETED and any(
            value is None for value in completed_fields
        ):
            raise ValueError("completed proxy responses require metadata, usage, and digests")
        if pre_send and any(value is not None for value in completed_fields):
            raise ValueError("pre-send proxy outcomes cannot carry provider response fields")
        digest_payload = self.model_dump(
            mode="python",
            exclude={"proxy_receipt_digest", "attestation_signature"},
        )
        if not hmac.compare_digest(
            self.proxy_receipt_digest,
            sha256_digest(digest_payload),
        ):
            raise ValueError("proxy receipt digest does not match its result fields")
        return self


def provider_proxy_result_attestation_bytes(result: ProviderProxyResult) -> bytes:
    """Return domain-separated bytes signed by the pinned provider proxy."""

    if type(result) is not ProviderProxyResult:
        raise TypeError("provider proxy attestation requires an exact result model")
    return canonical_json_bytes(
        {
            "purpose": "faultloom.provider_proxy_result.v1",
            "result": result.model_dump(
                mode="python",
                exclude={"attestation_signature"},
            ),
        }
    )


class ProviderProxyPort(Protocol):
    plane: ProviderPlane
    proxy_id: Identifier
    contract_digest: Sha256Digest
    attestation_public_key: Ed25519PublicKeyRecord

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult: ...


def _dispatch_reservation_digest(
    *,
    call_id: str,
    attempt_id: str,
    attempt: int,
    run_id: str,
    logical_request_digest: str,
    profile_digest: str,
    proxy_id: str,
    proxy_contract_digest: str,
    proxy_attestation_key_id: str,
) -> str:
    return sha256_digest(
        {
            "attempt": attempt,
            "attempt_id": attempt_id,
            "call_id": call_id,
            "logical_request_digest": logical_request_digest,
            "profile_digest": profile_digest,
            "proxy_attestation_key_id": proxy_attestation_key_id,
            "proxy_contract_digest": proxy_contract_digest,
            "proxy_id": proxy_id,
            "purpose": "faultloom.provider_dispatch_reservation.v1",
            "run_id": run_id,
        }
    )


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


class ProviderReceiptJournal(Protocol):
    """Authenticated journal boundary used by T13/T20-backed implementations.

    ``reserve`` must durably and atomically claim both attempt keys before it
    returns. ``finalize`` is an append-only compare-and-swap from that exact
    reservation. A failed or interrupted finalization must leave the reserved
    unknown-outcome receipt readable; reservations never expire implicitly.
    """

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None: ...

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None: ...

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None: ...

    def reserve(self, receipt: ProviderCallReceipt) -> None: ...

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None: ...


class MemoryProviderReceiptJournal:
    """Authenticated process-local journal for loopback labs and contract tests.

    The lock and authenticated append-only chain exercise the same atomic API
    required of a durable T20 journal. This class is intentionally not durable
    and cannot support a production/live persistence claim by itself.
    """

    def __init__(self, *, authentication_key: bytes | None = None) -> None:
        key = authentication_key if authentication_key is not None else secrets.token_bytes(32)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("provider journal authentication key must be 32 bytes")
        self.journal_id = f"memory-provider-journal-{secrets.token_hex(8)}"
        self._authentication_key = key
        self._lock = threading.RLock()
        self._by_digest: dict[str, ProviderCallReceipt] = {}
        self._by_attempt: dict[tuple[str, int], ProviderCallReceipt] = {}
        self._by_attempt_id: dict[str, ProviderCallReceipt] = {}
        self._states: list[dict[str, object]] = []
        self._state_by_receipt_digest: dict[str, dict[str, object]] = {}
        self._head = sha256_digest(
            {
                "journal_id": self.journal_id,
                "purpose": "faultloom.provider_journal.genesis.v1",
            }
        )
        # This process-local freshness anchor is deliberately separate from
        # the replayable chain. A production T20 journal must pin the same
        # values in durable authenticated storage outside this object.
        self._trusted_head = self._head
        self._trusted_sequence = 0

    @staticmethod
    def _validated(receipt: ProviderCallReceipt) -> ProviderCallReceipt:
        try:
            return ProviderCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except Exception as exc:
            raise ProviderReceiptError("provider receipt is invalid") from exc

    def _state_payload(
        self,
        *,
        sequence: int,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str,
        previous_state_digest: str,
        receipt: ProviderCallReceipt,
    ) -> dict[str, object]:
        return {
            "journal_id": self.journal_id,
            "phase": phase,
            "previous_state_digest": previous_state_digest,
            "receipt": receipt,
            "reservation_receipt_digest": reservation_receipt_digest,
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
        }

    def _new_state(
        self,
        *,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> dict[str, object]:
        payload = self._state_payload(
            sequence=len(self._states) + 1,
            phase=phase,
            reservation_receipt_digest=reservation_receipt_digest,
            previous_state_digest=self._head,
            receipt=receipt,
        )
        state_digest = sha256_digest(payload)
        authentication_tag = "sha256:" + hmac.new(
            self._authentication_key,
            canonical_json_bytes({**payload, "state_digest": state_digest}),
            "sha256",
        ).hexdigest()
        return {
            **payload,
            "authentication_tag": authentication_tag,
            "state_digest": state_digest,
        }

    def _verify_chain(self) -> None:
        if len(self._states) != self._trusted_sequence:
            raise ProviderReceiptError("provider journal rollback was detected")
        previous = sha256_digest(
            {
                "journal_id": self.journal_id,
                "purpose": "faultloom.provider_journal.genesis.v1",
            }
        )
        derived_by_digest: dict[str, ProviderCallReceipt] = {}
        derived_by_attempt: dict[tuple[str, int], ProviderCallReceipt] = {}
        derived_by_attempt_id: dict[str, ProviderCallReceipt] = {}
        derived_state_by_digest: dict[str, dict[str, object]] = {}
        bound_fields = (
            "call_id",
            "attempt_id",
            "attempt",
            "run_id",
            "profile_id",
            "profile_digest",
            "proxy_id",
            "proxy_attestation_key_id",
            "proxy_contract_digest",
            "logical_request_digest",
            "dispatch_reservation_digest",
            "proxy_request_digest",
        )
        for expected_sequence, state in enumerate(self._states, start=1):
            receipt_digest = state.get("receipt_digest")
            if not isinstance(receipt_digest, str):
                raise ProviderReceiptError("provider journal state is invalid")
            stored = self._by_digest.get(receipt_digest)
            if stored is None:
                raise ProviderReceiptError("provider journal receipt disappeared")
            receipt = self._validated(stored)
            if not hmac.compare_digest(receipt.receipt_digest, receipt_digest):
                raise ProviderReceiptError("provider journal receipt key mismatch")
            state_receipt = self._validated(state.get("receipt"))
            if not hmac.compare_digest(
                state_receipt.receipt_digest,
                receipt.receipt_digest,
            ):
                raise ProviderReceiptError("provider journal state receipt changed")
            phase = state.get("phase")
            if phase not in {"reserved", "finalized"}:
                raise ProviderReceiptError("provider journal phase is invalid")
            reservation_digest = state.get("reservation_receipt_digest")
            if not isinstance(reservation_digest, str):
                raise ProviderReceiptError("provider journal reservation is invalid")
            payload = self._state_payload(
                sequence=expected_sequence,
                phase=phase,
                reservation_receipt_digest=reservation_digest,
                previous_state_digest=previous,
                receipt=receipt,
            )
            expected_digest = sha256_digest(payload)
            expected_tag = "sha256:" + hmac.new(
                self._authentication_key,
                canonical_json_bytes({**payload, "state_digest": expected_digest}),
                "sha256",
            ).hexdigest()
            if (
                state.get("sequence") != expected_sequence
                or state.get("previous_state_digest") != previous
                or not isinstance(state.get("state_digest"), str)
                or not hmac.compare_digest(state["state_digest"], expected_digest)
                or not isinstance(state.get("authentication_tag"), str)
                or not hmac.compare_digest(state["authentication_tag"], expected_tag)
            ):
                raise ProviderReceiptError("provider journal authenticated chain is invalid")

            attempt_key = (receipt.call_id, receipt.attempt)
            if receipt_digest in derived_by_digest:
                raise ProviderReceiptError("provider journal receipt digest was replayed")
            if phase == "reserved":
                if (
                    reservation_digest != receipt_digest
                    or attempt_key in derived_by_attempt
                    or receipt.attempt_id in derived_by_attempt_id
                ):
                    raise ProviderReceiptError("provider journal reservation was replayed")
            else:
                reservation_state = derived_state_by_digest.get(reservation_digest)
                active = derived_by_attempt.get(attempt_key)
                active_id = derived_by_attempt_id.get(receipt.attempt_id)
                if (
                    reservation_state is None
                    or reservation_state.get("phase") != "reserved"
                    or active is None
                    or active_id is None
                    or not hmac.compare_digest(
                        active.receipt_digest,
                        reservation_digest,
                    )
                    or not hmac.compare_digest(
                        active_id.receipt_digest,
                        reservation_digest,
                    )
                ):
                    raise ProviderReceiptError("provider journal finalization is not linear")
                reservation = derived_by_digest[reservation_digest]
                if any(
                    getattr(receipt, field) != getattr(reservation, field)
                    for field in bound_fields
                ) or not hmac.compare_digest(
                    _provider_journal_binding_digest(receipt),
                    _provider_journal_binding_digest(reservation),
                ):
                    raise ProviderReceiptError(
                        "provider journal finalization changed its reservation"
                    )
            derived_by_digest[receipt_digest] = receipt
            derived_by_attempt[attempt_key] = receipt
            derived_by_attempt_id[receipt.attempt_id] = receipt
            derived_state_by_digest[receipt_digest] = state
            previous = expected_digest
        if (
            not hmac.compare_digest(self._head, previous)
            or not hmac.compare_digest(self._trusted_head, previous)
        ):
            raise ProviderReceiptError("provider journal head is invalid")
        if set(self._by_digest) != set(derived_by_digest):
            raise ProviderReceiptError("provider journal digest index is inconsistent")
        if set(self._by_attempt) != set(derived_by_attempt):
            raise ProviderReceiptError("provider journal attempt index is inconsistent")
        if set(self._by_attempt_id) != set(derived_by_attempt_id):
            raise ProviderReceiptError("provider journal attempt-ID index is inconsistent")
        if set(self._state_by_receipt_digest) != set(derived_state_by_digest):
            raise ProviderReceiptError("provider journal state index is inconsistent")
        if any(
            not hmac.compare_digest(
                self._by_digest[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_digest.items()
        ):
            raise ProviderReceiptError("provider journal digest index changed")
        if any(
            not hmac.compare_digest(
                self._by_attempt[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_attempt.items()
        ):
            raise ProviderReceiptError("provider journal attempt index changed")
        if any(
            not hmac.compare_digest(
                self._by_attempt_id[key].receipt_digest,
                expected.receipt_digest,
            )
            for key, expected in derived_by_attempt_id.items()
        ):
            raise ProviderReceiptError("provider journal attempt-ID index changed")
        if any(
            self._state_by_receipt_digest[key].get("state_digest")
            != expected.get("state_digest")
            for key, expected in derived_state_by_digest.items()
        ):
            raise ProviderReceiptError("provider journal state index changed")

    def _commit_state(self, state: dict[str, object], receipt: ProviderCallReceipt) -> None:
        stored_state = {**state, "receipt_digest": receipt.receipt_digest}
        self._states.append(stored_state)
        self._state_by_receipt_digest[receipt.receipt_digest] = stored_state
        self._by_digest[receipt.receipt_digest] = receipt
        self._head = str(state["state_digest"])
        self._trusted_head = self._head
        self._trusted_sequence += 1

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_digest.get(receipt_digest)
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if not hmac.compare_digest(receipt.receipt_digest, receipt_digest):
                raise ProviderReceiptError("provider journal digest lookup is not key-bound")
            return receipt

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_attempt.get((call_id, attempt))
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if receipt.call_id != call_id or receipt.attempt != attempt:
                raise ProviderReceiptError("provider journal attempt lookup is not key-bound")
            return receipt

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
        with self._lock:
            self._verify_chain()
            receipt = self._by_attempt_id.get(attempt_id)
            if receipt is None:
                return None
            receipt = self._validated(receipt)
            if receipt.attempt_id != attempt_id:
                raise ProviderReceiptError("provider journal attempt-ID lookup is not key-bound")
            return receipt

    def reserve(self, receipt: ProviderCallReceipt) -> None:
        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            if (
                receipt.outcome is not ProviderCallOutcome.UNKNOWN_OUTCOME
                or receipt.retry_disposition is not RetryDisposition.RECONCILIATION_REQUIRED
                or not receipt.reconciliation_required
            ):
                raise ProviderReceiptError("dispatch reservation must be an unknown-outcome hold")
            if (
                receipt.receipt_digest in self._by_digest
                or (receipt.call_id, receipt.attempt) in self._by_attempt
                or receipt.attempt_id in self._by_attempt_id
            ):
                raise ProviderReceiptError("provider receipt replay or attempt collision")
            state = self._new_state(
                phase="reserved",
                reservation_receipt_digest=receipt.receipt_digest,
                receipt=receipt,
            )
            self._commit_state(state, receipt)
            self._by_attempt[(receipt.call_id, receipt.attempt)] = receipt
            self._by_attempt_id[receipt.attempt_id] = receipt

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None:
        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            reservation = self._by_digest.get(reservation_receipt_digest)
            if reservation is None:
                raise ProviderReceiptError("provider dispatch reservation is unavailable")
            reservation = self._validated(reservation)
            reservation_state = self._state_by_receipt_digest.get(
                reservation_receipt_digest
            )
            if reservation_state is None or reservation_state.get("phase") != "reserved":
                raise ProviderReceiptError("provider dispatch reservation is not active")
            bound_fields = (
                "call_id",
                "attempt_id",
                "attempt",
                "run_id",
                "profile_id",
                "profile_digest",
                "proxy_id",
                "proxy_attestation_key_id",
                "proxy_contract_digest",
                "logical_request_digest",
                "dispatch_reservation_digest",
                "proxy_request_digest",
            )
            if any(
                getattr(receipt, field) != getattr(reservation, field)
                for field in bound_fields
            ) or not hmac.compare_digest(
                _provider_journal_binding_digest(receipt),
                _provider_journal_binding_digest(reservation),
            ):
                raise ProviderReceiptError("provider terminal receipt changed its reservation")
            current = self._by_attempt.get((reservation.call_id, reservation.attempt))
            if current is None or not hmac.compare_digest(
                current.receipt_digest,
                reservation_receipt_digest,
            ):
                raise ProviderReceiptError("provider reservation was already finalized")
            if receipt.receipt_digest in self._by_digest:
                raise ProviderReceiptError("provider terminal receipt digest was replayed")
            state = self._new_state(
                phase="finalized",
                reservation_receipt_digest=reservation_receipt_digest,
                receipt=receipt,
            )
            self._commit_state(state, receipt)
            self._by_attempt[(receipt.call_id, receipt.attempt)] = receipt
            self._by_attempt_id[receipt.attempt_id] = receipt

    def append(self, receipt: ProviderCallReceipt) -> None:
        """Reject legacy post-effect append calls that bypass reservation."""

        with self._lock:
            self._verify_chain()
            receipt = self._validated(receipt)
            raise ProviderReceiptError("provider receipts require reserve/finalize admission")


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


@final
class AnchoredProviderReceiptJournal:
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

    @staticmethod
    def _require_receipt_digest(value: object) -> str:
        if type(value) is not str or re.fullmatch(
            r"sha256:[0-9a-f]{64}", value
        ) is None:
            raise ProviderReceiptError("provider receipt digest is invalid")
        return value

    @staticmethod
    def _validated_receipt(receipt: object) -> ProviderCallReceipt:
        if type(receipt) is not ProviderCallReceipt:
            raise ProviderReceiptError(
                "anchored provider journal requires an exact provider receipt"
            )
        try:
            return ProviderCallReceipt.model_validate(
                receipt.model_dump(mode="python")
            )
        except Exception as exc:
            raise ProviderReceiptError("provider receipt is invalid") from exc

    @staticmethod
    def _metadata_for_receipt(
        receipt: ProviderCallReceipt,
    ) -> ProviderReceiptMetadata:
        request = receipt.proxy_request
        credential_ref = request.credential_ref
        runtime_version = request.runtime_version
        tokenizer_id = request.tokenizer_id
        tokenizer_version = request.tokenizer_version
        if (
            type(runtime_version) is not str
            or type(tokenizer_id) is not str
            or type(tokenizer_version) is not str
        ):
            raise ProviderReceiptError(
                "anchored provider journal requires exact runtime and tokenizer metadata"
            )
        try:
            return ProviderReceiptMetadata(
                call_id=receipt.call_id,
                attempt=receipt.attempt,
                attempt_id=receipt.attempt_id,
                provider_id=request.provider_id,
                endpoint_id=request.endpoint_id,
                profile_digest=receipt.profile_digest,
                requested_alias=request.requested_alias,
                exact_snapshot=request.model_snapshot,
                runtime_version=runtime_version,
                tokenizer_id=tokenizer_id,
                tokenizer_version=tokenizer_version,
                context_window=request.context_window,
                prompt_digest=request.prompt_digest,
                compiled_context_digest=request.compiled_context_digest,
                tool_schema_digest=request.tool_schema_digest,
                credential_ref_uri=credential_ref.uri,
                credential_ref_purpose=credential_ref.purpose,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt cannot form the canonical a4 projection"
            ) from exc

    @classmethod
    def _reservation_entry(
        cls,
        receipt: ProviderCallReceipt,
    ) -> ProviderJournalEntry:
        try:
            canonical = ProviderCanonicalReceipt.reserved(
                cls._metadata_for_receipt(receipt)
            )
            return ProviderJournalEntry.from_receipt(canonical)
        except ProviderReceiptError:
            raise
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt could not form an a4 reservation"
            ) from exc

    @classmethod
    def _entry_for_receipt(
        cls,
        receipt: object,
        *,
        phase: Literal["reserved", "finalized"],
        reservation_receipt_digest: str | None,
    ) -> tuple[ProviderCallReceipt, ProviderJournalEntry]:
        validated = cls._validated_receipt(receipt)
        reservation = cls._reservation_entry(validated)
        if phase == "reserved":
            if (
                reservation_receipt_digest is not None
                or validated.proxy_result is not None
                or validated.proxy_receipt_digest is not None
                or validated.outcome is not ProviderCallOutcome.UNKNOWN_OUTCOME
                or validated.retry_disposition
                is not RetryDisposition.RECONCILIATION_REQUIRED
                or not validated.reconciliation_required
            ):
                raise ProviderReceiptError(
                    "dispatch reservation must be an unknown-outcome hold"
                )
            return validated, reservation
        if (
            reservation_receipt_digest != reservation.receipt_digest
            or validated.proxy_result is None
            or validated.proxy_receipt_digest is None
        ):
            raise ProviderReceiptError(
                "provider finalization requires its exact a4 reservation and signed result"
            )
        try:
            canonical = ProviderCanonicalReceipt.parse(
                reservation.canonical_receipt_json
            ).finalized(validated.proxy_receipt_digest)
            return validated, ProviderJournalEntry.from_receipt(canonical)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt could not form an a4 finalization"
            ) from exc

    def _verify_components(self) -> None:
        if (
            getattr(self._state_store, "ledger", None) is not self._ledger
            or getattr(self._state_store, "cas", None) is not self._cas
            or getattr(self._ledger_events, "__self__", None) is not self._ledger
            or getattr(self._ledger_events, "__func__", None)
            is not EventLedger.events
            or getattr(self._cas_get, "__self__", None) is not self._cas
            or getattr(self._cas_get, "__func__", None) is not EncryptedCAS.get
        ):
            raise ProviderReceiptError(
                "anchored provider journal encrypted state capability changed"
            )

    def _refresh_checkpoint(self) -> AnchorCheckpoint:
        self._verify_components()
        try:
            checkpoint = self._state_checkpoint()
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal checkpoint read failed closed"
            ) from exc
        self._minimum_anchor = self._require_fresh_checkpoint(
            checkpoint,
            minimum=self._minimum_anchor,
            engagement_id=self._engagement_id,
        )
        return self._minimum_anchor

    def _validated_state_record(
        self,
        record: object,
    ) -> tuple[ProviderJournalEntry, AnchorCheckpoint, int]:
        if type(record) is not ProviderJournalRecord:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            )
        source = record.entry
        if type(source) is not ProviderJournalEntry:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            )
        try:
            entry = ProviderJournalEntry(
                phase=source.phase,
                receipt_digest=source.receipt_digest,
                reservation_receipt_digest=source.reservation_receipt_digest,
                call_id=source.call_id,
                attempt=source.attempt,
                attempt_id=source.attempt_id,
                binding_digest=source.binding_digest,
                dispatch_reservation_digest=source.dispatch_reservation_digest,
                proxy_request_digest=source.proxy_request_digest,
                canonical_receipt_json=source.canonical_receipt_json,
            )
            anchor = self._require_fresh_checkpoint(
                record.anchor,
                minimum=self._minimum_anchor,
                engagement_id=self._engagement_id,
            )
            rebuilt = ProviderJournalRecord(
                entry=entry,
                event_seq=record.event_seq,
                event_hash=record.event_hash,
                anchor=anchor,
            )
            canonical = ProviderCanonicalReceipt.parse(
                entry.canonical_receipt_json
            )
            expected = ProviderJournalEntry.from_receipt(canonical)
        except ProviderReceiptError:
            raise
        except Exception as exc:
            raise ProviderReceiptError(
                "anchored provider journal returned an invalid record"
            ) from exc
        if rebuilt != record or expected != entry:
            raise ProviderReceiptError(
                "anchored provider journal record binding changed"
            )
        self._minimum_anchor = anchor
        return entry, anchor, record.event_seq

    @classmethod
    def _actor(
        cls,
        entry_digest: str,
        receipt_digest: str,
    ) -> str:
        entry = cls._require_receipt_digest(entry_digest)[7:]
        receipt = cls._require_receipt_digest(receipt_digest)[7:]
        binding = hashlib.sha256(
            b"faultloom.provider-call-receipt.actor.v1\0"
            + entry.encode("ascii")
            + b"\0"
            + receipt.encode("ascii")
        ).hexdigest()
        return f"{_PROVIDER_RECEIPT_ACTOR_PREFIX}.{binding}"

    @classmethod
    def _actor_binding(cls, value: object) -> str:
        if type(value) is not str:
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        prefix = f"{_PROVIDER_RECEIPT_ACTOR_PREFIX}."
        if not value.startswith(prefix):
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        binding = value[len(prefix) :]
        if re.fullmatch(r"[0-9a-f]{64}", binding) is None:
            raise ProviderReceiptError(
                "provider receipt companion actor is invalid"
            )
        return binding

    def _events_through(
        self,
        checkpoint: AnchorCheckpoint,
    ) -> tuple[EventRecord, ...]:
        self._verify_components()
        records: list[EventRecord] = []
        after_seq = 0
        while after_seq < checkpoint.seq:
            try:
                batch = self._ledger_events(
                    after_seq=after_seq,
                    limit=min(_PROVIDER_EVENT_PAGE, checkpoint.seq - after_seq),
                )
            except Exception as exc:
                raise ProviderReceiptError(
                    "provider receipt companion event read failed closed"
                ) from exc
            if type(batch) is not tuple or not batch:
                raise ProviderReceiptError(
                    "provider receipt companion event history is incomplete"
                )
            advanced = after_seq
            for event in batch:
                if type(event) is not EventRecord:
                    raise ProviderReceiptError(
                        "provider receipt companion event is invalid"
                    )
                if event.seq > checkpoint.seq:
                    break
                if event.engagement_id != self._engagement_id:
                    raise ProviderReceiptError(
                        "provider receipt companion crossed engagements"
                    )
                records.append(event)
                advanced = event.seq
            if advanced <= after_seq:
                raise ProviderReceiptError(
                    "provider receipt companion event history did not advance"
                )
            after_seq = advanced
        return tuple(records)

    def _matching_events(
        self,
        checkpoint: AnchorCheckpoint,
        *,
        entry_digest: str | None = None,
        receipt_digest: str | None = None,
    ) -> tuple[EventRecord, ...]:
        if entry_digest is not None:
            entry_digest = self._require_receipt_digest(entry_digest)
        if receipt_digest is not None:
            receipt_digest = self._require_receipt_digest(receipt_digest)
        matches: list[EventRecord] = []
        for event in self._events_through(checkpoint):
            if event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE:
                continue
            receipt, entry = self._receipt_from_event(event)
            if (
                (entry_digest is None or entry.receipt_digest == entry_digest)
                and (
                    receipt_digest is None
                    or receipt.receipt_digest == receipt_digest
                )
            ):
                matches.append(event)
        return tuple(matches)

    def _companion_metadata(
        self,
        receipt: ProviderCallReceipt,
        entry: ProviderJournalEntry,
    ) -> dict[str, object]:
        return {
            "call_receipt_digest": receipt.receipt_digest,
            "engagement_id": self._engagement_id,
            "journal_receipt_digest": entry.receipt_digest,
            "phase": entry.phase,
            "purpose": "faultloom.provider-call-receipt.companion.v1",
            "schema_version": SCHEMA_VERSION,
        }

    @staticmethod
    def _artifact_ref(value: object) -> ArtifactRef:
        if type(value) is not dict or set(value) != {
            "engagement_id",
            "sha256",
            "byte_length",
            "media_type",
            "schema_version",
        }:
            raise ProviderReceiptError(
                "provider receipt companion artifact reference is invalid"
            )
        try:
            return ArtifactRef(
                engagement_id=value["engagement_id"],
                sha256=value["sha256"],
                byte_length=value["byte_length"],
                media_type=value["media_type"],
                schema_version=value["schema_version"],
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion artifact reference is invalid"
            ) from exc

    def _receipt_from_event(
        self,
        event: EventRecord,
    ) -> tuple[ProviderCallReceipt, ProviderJournalEntry]:
        if (
            type(event) is not EventRecord
            or event.engagement_id != self._engagement_id
            or event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE
        ):
            raise ProviderReceiptError(
                "provider receipt companion event identity is invalid"
            )
        self._actor_binding(event.actor_stream)
        payload = event.payload
        if type(payload) is not dict or set(payload) != {
            "artifact_ref",
            "metadata_ref",
            "metadata_schema_version",
        } or payload["metadata_schema_version"] != 1:
            raise ProviderReceiptError(
                "provider receipt companion event payload is invalid"
            )
        reference = self._artifact_ref(payload["artifact_ref"])
        metadata_reference = self._artifact_ref(payload["metadata_ref"])
        if (
            reference.engagement_id != self._engagement_id
            or metadata_reference.engagement_id != self._engagement_id
            or reference.media_type != _PROVIDER_RECEIPT_MEDIA_TYPE
            or reference.byte_length > _MAX_PROVIDER_RECEIPT_BYTES
            or metadata_reference.media_type
            != _PROVIDER_RECEIPT_METADATA_MEDIA_TYPE
            or metadata_reference.byte_length
            > _MAX_PROVIDER_RECEIPT_METADATA_BYTES
        ):
            raise ProviderReceiptError(
                "provider receipt companion artifact binding is invalid"
            )
        try:
            raw = self._cas_get(reference)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion decryption failed closed"
            ) from exc
        if (
            type(raw) is not bytes
            or len(raw) != reference.byte_length
            or hashlib.sha256(raw).hexdigest() != reference.sha256
        ):
            raise ProviderReceiptError(
                "provider receipt companion bytes are invalid"
            )
        try:
            receipt = ProviderCallReceipt.model_validate_json(raw)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion is invalid"
            ) from exc
        if canonical_json_bytes(receipt) != raw:
            raise ProviderReceiptError(
                "provider receipt companion is not canonical"
            )
        reservation = self._reservation_entry(receipt)
        if receipt.proxy_result is None:
            _, entry = self._entry_for_receipt(
                receipt,
                phase="reserved",
                reservation_receipt_digest=None,
            )
        else:
            _, entry = self._entry_for_receipt(
                receipt,
                phase="finalized",
                reservation_receipt_digest=reservation.receipt_digest,
            )
        if not hmac.compare_digest(
            event.actor_stream,
            self._actor(entry.receipt_digest, receipt.receipt_digest),
        ):
            raise ProviderReceiptError(
                "provider receipt companion actor changed"
            )
        try:
            metadata_raw = self._cas_get(metadata_reference)
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt companion metadata decryption failed closed"
            ) from exc
        expected_metadata = canonical_json_bytes(
            {
                "schema_version": 1,
                "values": self._companion_metadata(receipt, entry),
            }
        )
        if (
            type(metadata_raw) is not bytes
            or len(metadata_raw) != metadata_reference.byte_length
            or hashlib.sha256(metadata_raw).hexdigest()
            != metadata_reference.sha256
            or not hmac.compare_digest(metadata_raw, expected_metadata)
        ):
            raise ProviderReceiptError(
                "provider receipt companion metadata changed"
            )
        return receipt, entry

    def _receipt_for_entry(
        self,
        entry: ProviderJournalEntry,
        checkpoint: AnchorCheckpoint,
        *,
        journal_event_seq: int,
    ) -> ProviderCallReceipt:
        events = self._matching_events(
            checkpoint,
            entry_digest=entry.receipt_digest,
        )
        if len(events) != 1 or events[0].seq <= journal_event_seq:
            raise ProviderReceiptError(
                "provider receipt encrypted companion is missing or ambiguous"
            )
        receipt, expected = self._receipt_from_event(events[0])
        if expected != entry:
            raise ProviderReceiptError(
                "provider receipt encrypted companion changed its projection"
            )
        return receipt

    def _validated_record(self, record: object) -> ProviderCallReceipt:
        entry, anchor, event_seq = self._validated_state_record(record)
        return self._receipt_for_entry(
            entry,
            anchor,
            journal_event_seq=event_seq,
        )

    def _append_companion(
        self,
        receipt: ProviderCallReceipt,
        entry: ProviderJournalEntry,
        *,
        journal_event_seq: int,
    ) -> None:
        checkpoint = self._refresh_checkpoint()
        existing = self._matching_events(
            checkpoint,
            entry_digest=entry.receipt_digest,
        )
        if existing:
            stored = self._receipt_for_entry(
                entry,
                checkpoint,
                journal_event_seq=journal_event_seq,
            )
            if stored != receipt:
                raise ProviderReceiptError(
                    "provider receipt encrypted companion replay changed"
                )
            return
        raw = canonical_json_bytes(receipt)
        if len(raw) > _MAX_PROVIDER_RECEIPT_BYTES:
            raise ProviderReceiptError(
                "provider receipt exceeds the encrypted companion limit"
            )
        try:
            event, reference = self._state_append_observation(
                actor_stream=self._actor(
                    entry.receipt_digest,
                    receipt.receipt_digest,
                ),
                event_type=_PROVIDER_RECEIPT_EVENT_TYPE,
                raw_output=raw,
                metadata=self._companion_metadata(receipt, entry),
                media_type=_PROVIDER_RECEIPT_MEDIA_TYPE,
            )
        except Exception as exc:
            raise ProviderReceiptError(
                "provider receipt encrypted companion persistence failed closed"
            ) from exc
        if (
            type(event) is not EventRecord
            or type(reference) is not ArtifactRef
            or event.seq <= journal_event_seq
            or event.actor_stream
            != self._actor(entry.receipt_digest, receipt.receipt_digest)
            or event.event_type != _PROVIDER_RECEIPT_EVENT_TYPE
            or reference.engagement_id != self._engagement_id
            or reference.media_type != _PROVIDER_RECEIPT_MEDIA_TYPE
            or reference.byte_length != len(raw)
            or reference.sha256 != hashlib.sha256(raw).hexdigest()
        ):
            raise ProviderReceiptError(
                "provider receipt encrypted companion readback changed"
            )
        checkpoint = self._refresh_checkpoint()
        stored = self._receipt_for_entry(
            entry,
            checkpoint,
            journal_event_seq=journal_event_seq,
        )
        if stored != receipt:
            raise ProviderReceiptError(
                "provider receipt encrypted companion readback changed"
            )

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
        digest = self._require_receipt_digest(receipt_digest)
        with self._lock:
            checkpoint = self._refresh_checkpoint()
            events = self._matching_events(
                checkpoint,
                receipt_digest=digest,
            )
            if not events:
                return None
            if len(events) != 1:
                raise ProviderReceiptError(
                    "provider receipt digest companion is ambiguous"
                )
            candidate, expected_entry = self._receipt_from_event(events[0])
            try:
                record = self._state_by_digest(expected_entry.receipt_digest)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider receipt lookup failed closed"
                ) from exc
            if record is None:
                raise ProviderReceiptError(
                    "provider receipt companion lacks an a4 projection"
                )
            stored = self._validated_record(record)
            if stored != candidate or stored.receipt_digest != digest:
                raise ProviderReceiptError(
                    "anchored provider digest lookup is not key-bound"
                )
            return stored

    def by_attempt(
        self,
        call_id: str,
        attempt: int,
    ) -> ProviderCallReceipt | None:
        with self._lock:
            try:
                record = self._state_by_attempt(call_id, attempt)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider attempt lookup failed closed"
                ) from exc
            if record is None:
                self._refresh_checkpoint()
                return None
            receipt = self._validated_record(record)
            if receipt.call_id != call_id or receipt.attempt != attempt:
                raise ProviderReceiptError(
                    "anchored provider attempt lookup is not key-bound"
                )
            return receipt

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
        with self._lock:
            try:
                record = self._state_by_attempt_id(attempt_id)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider attempt-ID lookup failed closed"
                ) from exc
            if record is None:
                self._refresh_checkpoint()
                return None
            receipt = self._validated_record(record)
            if receipt.attempt_id != attempt_id:
                raise ProviderReceiptError(
                    "anchored provider attempt-ID lookup is not key-bound"
                )
            return receipt

    def reserve(self, receipt: ProviderCallReceipt) -> None:
        validated, entry = self._entry_for_receipt(
            receipt,
            phase="reserved",
            reservation_receipt_digest=None,
        )
        with self._lock:
            try:
                record = self._state_reserve(entry)
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider reservation failed closed"
                ) from exc
            stored_entry, _, event_seq = self._validated_state_record(record)
            if stored_entry != entry:
                raise ProviderReceiptError(
                    "anchored provider reservation projection changed"
                )
            self._append_companion(
                validated,
                entry,
                journal_event_seq=event_seq,
            )
            stored = self.by_digest(validated.receipt_digest)
            if stored != validated:
                raise ProviderReceiptError(
                    "anchored provider reservation readback changed"
                )

    def finalize(
        self,
        reservation_receipt_digest: str,
        receipt: ProviderCallReceipt,
    ) -> None:
        with self._lock:
            reservation = self.by_digest(reservation_receipt_digest)
            if reservation is None or reservation.proxy_result is not None:
                raise ProviderReceiptError(
                    "anchored provider finalization reservation is missing"
                )
            if not hmac.compare_digest(
                _provider_journal_binding_digest(reservation),
                _provider_journal_binding_digest(receipt),
            ):
                raise ProviderReceiptError(
                    "provider finalization changed its full reservation binding"
                )
            reservation_entry = self._reservation_entry(reservation)
            validated, entry = self._entry_for_receipt(
                receipt,
                phase="finalized",
                reservation_receipt_digest=reservation_entry.receipt_digest,
            )
            try:
                record = self._state_finalize(
                    reservation_entry.receipt_digest,
                    entry,
                )
            except Exception as exc:
                raise ProviderReceiptError(
                    "anchored provider finalization failed closed"
                ) from exc
            stored_entry, _, event_seq = self._validated_state_record(record)
            if stored_entry != entry:
                raise ProviderReceiptError(
                    "anchored provider finalization projection changed"
                )
            self._append_companion(
                validated,
                entry,
                journal_event_seq=event_seq,
            )
            stored = self.by_digest(validated.receipt_digest)
            if stored != validated:
                raise ProviderReceiptError(
                    "anchored provider finalization readback changed"
                )


Clock = Callable[[], datetime]
MonotonicClock = Callable[[], int]


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _trusted_now(clock: Clock) -> datetime:
    value = clock()
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ProviderAdapterError("provider adapter clock must return exact timezone.utc time")
    return value


def _trusted_monotonic(clock: MonotonicClock) -> int:
    value = clock()
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise ProviderAdapterError("provider monotonic clock must return a signed-64 integer")
    return value


def _decode_ed25519_signature(value: str) -> bytes:
    if type(value) is not str:
        raise ProviderPlaneError("provider proxy attestation signature is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise ProviderPlaneError("provider proxy attestation signature is invalid") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value or len(decoded) != 64:
        raise ProviderPlaneError("provider proxy attestation signature is invalid")
    return decoded


def _profile_map(profiles: Iterable[ProviderModelProfile]) -> dict[str, ProviderModelProfile]:
    result: dict[str, ProviderModelProfile] = {}
    for candidate in profiles:
        profile = ProviderModelProfile.model_validate(candidate.model_dump(mode="python"))
        if profile.profile_id in result:
            raise ValueError("provider profile IDs must be unique")
        result[profile.profile_id] = profile
    if not result:
        raise ValueError("provider adapter requires at least one profile")
    return result


def _ceil_cost(tokens: int, rate: int) -> int:
    if tokens == 0 or rate == 0:
        return 0
    return (tokens * rate + 999_999) // 1_000_000


def _logical_request_digest(intent: ProviderCallIntent) -> str:
    # This identity deliberately excludes the selected profile and proxy so an
    # explicitly approved, checkpointed failover can remain the same logical
    # call.  Derived contract digests are included as first-class values so the
    # dispatch contract cannot be weakened by changing its representation.
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "call_id": intent.call_id,
            "run_id": intent.run_id,
            "authority_digest": intent.authority_digest,
            "scope_epoch": intent.scope_epoch,
            "prompt_digest": intent.prompt_digest,
            "compiled_context_digest": intent.compiled_context_digest,
            "tool_schema_digest": provider_tool_schema_digest(intent.tools),
            "config_digest": sha256_digest(intent.generation_config),
            "prompt_bytes": intent.prompt_bytes,
            "input_tokens": intent.input_tokens,
            "tools": intent.tools,
            "output_schema_digest": intent.output_schema_digest,
            "generation_config": intent.generation_config,
            "budget": intent.budget,
            "action_ids": intent.action_ids,
            "policy_ref": intent.policy_ref,
            "data_policy_id": intent.data_policy_id,
            "data_consent_ref": intent.data_consent_ref,
            "credential_ref": intent.credential_ref,
        }
    )


class ProviderAdapter:
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

    @staticmethod
    def _validated_journal_receipt(receipt: object) -> ProviderCallReceipt:
        try:
            return ProviderCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except Exception as exc:
            raise ProviderReceiptError("provider journal returned an invalid receipt") from exc

    def _validate_attempt_lookup(
        self,
        receipt: object,
        *,
        call_id: str,
        attempt: int,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if validated.call_id != call_id or validated.attempt != attempt:
            raise ProviderReceiptError("provider journal attempt lookup is not key-bound")
        return validated

    def _validate_digest_lookup(
        self,
        receipt: object,
        receipt_digest: str,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if not hmac.compare_digest(validated.receipt_digest, receipt_digest):
            raise ProviderReceiptError("provider journal digest lookup is not key-bound")
        return validated

    def _validate_attempt_id_lookup(
        self,
        receipt: object,
        attempt_id: str,
    ) -> ProviderCallReceipt:
        validated = self._validated_journal_receipt(receipt)
        if validated.attempt_id != attempt_id:
            raise ProviderReceiptError("provider journal attempt-ID lookup is not key-bound")
        return validated

    def _validate_reservation_readback(
        self,
        reservation: ProviderCallReceipt,
    ) -> None:
        by_digest = self._journal_by_digest(reservation.receipt_digest)
        by_attempt = self._journal_by_attempt(
            reservation.call_id,
            reservation.attempt,
        )
        by_attempt_id = self._journal_by_attempt_id(reservation.attempt_id)
        if by_digest is None or by_attempt is None or by_attempt_id is None:
            raise ProviderReceiptError(
                "provider journal did not persist the dispatch reservation"
            )
        validated = (
            self._validate_digest_lookup(by_digest, reservation.receipt_digest),
            self._validate_attempt_lookup(
                by_attempt,
                call_id=reservation.call_id,
                attempt=reservation.attempt,
            ),
            self._validate_attempt_id_lookup(by_attempt_id, reservation.attempt_id),
        )
        if any(
            not hmac.compare_digest(
                candidate.receipt_digest,
                reservation.receipt_digest,
            )
            for candidate in validated
        ):
            raise ProviderReceiptError(
                "provider journal reservation indexes are not atomic"
            )

    def _validate_terminal_readback(
        self,
        reservation_receipt_digest: str,
        terminal: ProviderCallReceipt,
    ) -> None:
        reservation = self._journal_by_digest(reservation_receipt_digest)
        by_digest = self._journal_by_digest(terminal.receipt_digest)
        by_attempt = self._journal_by_attempt(terminal.call_id, terminal.attempt)
        by_attempt_id = self._journal_by_attempt_id(terminal.attempt_id)
        if (
            reservation is None
            or by_digest is None
            or by_attempt is None
            or by_attempt_id is None
        ):
            raise ProviderReceiptError(
                "provider journal did not persist its terminal transition"
            )
        self._validate_digest_lookup(reservation, reservation_receipt_digest)
        validated = (
            self._validate_digest_lookup(by_digest, terminal.receipt_digest),
            self._validate_attempt_lookup(
                by_attempt,
                call_id=terminal.call_id,
                attempt=terminal.attempt,
            ),
            self._validate_attempt_id_lookup(by_attempt_id, terminal.attempt_id),
        )
        if any(
            not hmac.compare_digest(
                candidate.receipt_digest,
                terminal.receipt_digest,
            )
            for candidate in validated
        ):
            raise ProviderReceiptError(
                "provider journal terminal indexes are not atomic"
            )

    def _validate_result_attestation(
        self,
        result: ProviderProxyResult,
        *,
        proxy_request: ProviderProxyRequest,
        proxy_request_digest: str,
    ) -> None:
        if (
            result.request_id != proxy_request.request_id
            or not hmac.compare_digest(
                result.proxy_request_digest,
                proxy_request_digest,
            )
        ):
            raise ProviderPlaneError("provider proxy attestation is not request-bound")
        if result.attestation_key_id != proxy_request.proxy_attestation_key_id:
            raise ProviderPlaneError("provider proxy attestation identity does not match")
        self._verify_proxy_result_attestation(result)

    def _verify_proxy_result_attestation(self, result: ProviderProxyResult) -> None:
        if (
            result.attested_proxy_id != self._proxy_id
            or not hmac.compare_digest(
                result.attested_proxy_contract_digest,
                self._proxy_contract_digest,
            )
            or result.attestation_key_id != self._proxy_attestation_record.key_id
        ):
            raise ProviderPlaneError("provider proxy attestation identity does not match")
        signature = _decode_ed25519_signature(result.attestation_signature)
        try:
            self._proxy_attestation_public_key.verify(
                signature,
                provider_proxy_result_attestation_bytes(result),
            )
        except Exception as exc:
            raise ProviderPlaneError("provider proxy result attestation is invalid") from exc

    def _proxy_binding_matches(self) -> bool:
        current_dispatch = getattr(self._proxy, "dispatch", None)
        current_attestation_key = getattr(self._proxy, "attestation_public_key", None)
        try:
            current_attestation_key = Ed25519PublicKeyRecord.model_validate(
                current_attestation_key.model_dump(mode="python")
            )
        except Exception:
            return False
        return bool(
            getattr(self._proxy, "plane", None) is ProviderPlane.MODEL_PROVIDER
            and getattr(self._proxy, "proxy_id", None) == self._proxy_id
            and getattr(self._proxy, "contract_digest", None)
            == self._proxy_contract_digest
            and current_attestation_key == self._proxy_attestation_record
            and getattr(current_dispatch, "__self__", None)
            is self._proxy_dispatch_owner
            and getattr(current_dispatch, "__func__", current_dispatch)
            is self._proxy_dispatch_function
        )

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


__all__ = [
    "AnchoredProviderReceiptJournal",
    "FailureCode",
    "FailoverProvenance",
    "GenerationConfig",
    "MemoryProviderReceiptJournal",
    "MetadataProvenance",
    "MetadataSourceKind",
    "ProviderAdapter",
    "ProviderAdapterError",
    "ProviderBudgetError",
    "ProviderCallBudget",
    "ProviderCallIntent",
    "ProviderCallOutcome",
    "ProviderCallReceipt",
    "ProviderMetadataError",
    "ProviderModelProfile",
    "ProviderObservedMetadata",
    "ProviderPlane",
    "ProviderPlaneError",
    "ProviderPolicyError",
    "ProviderProxyPort",
    "ProviderProxyRequest",
    "ProviderProxyResult",
    "ProviderReceiptError",
    "ProviderReceiptJournal",
    "ProviderRetryError",
    "ProviderToolKind",
    "ProviderToolSpec",
    "ProviderUsage",
    "ProxyEffectDisposition",
    "ProxyOutcome",
    "RetryDisposition",
    "failover_provenance_attestation_bytes",
    "provider_proxy_result_attestation_bytes",
    "provider_tool_schema_digest",
]
