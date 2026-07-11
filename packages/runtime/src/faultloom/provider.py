"""Fail-closed model provider adapter.

The adapter owns model identity and accounting, but it never owns network
transport.  All dispatches cross the injected model-provider proxy port using
digests and secret references only.
"""

from __future__ import annotations

import hmac
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Literal, Protocol, Self

from faultloom_protocol import ProtocolModel, SecretRef, sha256_digest
from faultloom_protocol.base import (
    AwareDatetime,
    Identifier,
    NonEmptyStr,
    Sha256Digest,
    ShortStr,
)
from pydantic import Field, NonNegativeInt, PositiveInt, field_validator, model_validator

SCHEMA_VERSION = "0.1.0"


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
    context_window: PositiveInt
    prompt_overhead_tokens: NonNegativeInt
    maximum_input_tokens: PositiveInt
    maximum_output_tokens: PositiveInt
    maximum_request_bytes: PositiveInt
    maximum_response_bytes: PositiveInt
    input_cost_per_million_microunits: NonNegativeInt
    output_cost_per_million_microunits: NonNegativeInt
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
    context_window: PositiveInt | None = None
    snapshot_exact: bool = False
    runtime_exact: bool = False
    tokenizer_exact: bool = False
    context_window_exact: bool = False
    provenance: MetadataProvenance


class GenerationConfig(_RuntimeModel):
    max_output_tokens: PositiveInt
    temperature_milli: NonNegativeInt = Field(le=2000)
    top_p_milli: PositiveInt = Field(le=1000)
    seed: NonNegativeInt | None = None
    response_format: Literal["text", "json"] = "text"


class ProviderCallBudget(_RuntimeModel):
    maximum_input_tokens: PositiveInt
    maximum_output_tokens: PositiveInt
    remaining_model_tokens: NonNegativeInt
    remaining_cost_microunits: NonNegativeInt


class FailoverProvenance(_RuntimeModel):
    previous_receipt_digest: Sha256Digest
    from_profile_id: Identifier
    to_profile_id: Identifier
    checkpoint_id: Identifier
    checkpoint_digest: Sha256Digest
    reason_code: Identifier
    approved_at: AwareDatetime

    @model_validator(mode="after")
    def _changes_profile(self) -> Self:
        if self.from_profile_id == self.to_profile_id:
            raise ValueError("failover must change the configured provider profile")
        return self


class ProviderCallIntent(_RuntimeModel):
    call_id: Identifier
    attempt_id: Identifier
    attempt: PositiveInt
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    profile_id: Identifier
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    prompt_bytes: PositiveInt
    input_tokens: NonNegativeInt
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
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt


class ProviderProxyRequest(_RuntimeModel):
    plane: Literal[ProviderPlane.MODEL_PROVIDER] = ProviderPlane.MODEL_PROVIDER
    proxy_id: Identifier
    proxy_contract_digest: Sha256Digest
    request_id: Identifier
    run_id: Identifier
    authority_digest: Sha256Digest
    scope_epoch: PositiveInt
    endpoint_id: Identifier
    provider_id: Identifier
    model_snapshot: ShortStr
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
    payload_bytes: PositiveInt
    tool_ids: tuple[Identifier, ...] = ()
    requested_at: AwareDatetime
    live: bool


class ProviderProxyResult(_RuntimeModel):
    plane: ProviderPlane
    request_id: Identifier
    proxy_receipt_digest: Sha256Digest
    outcome: ProxyOutcome
    response_digest: Sha256Digest | None = None
    response_status: NonNegativeInt | None = None
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
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
        return self


class ProviderProxyPort(Protocol):
    plane: ProviderPlane
    proxy_id: Identifier
    contract_digest: Sha256Digest

    def dispatch(self, request: ProviderProxyRequest) -> ProviderProxyResult: ...


class ProviderCallReceipt(_RuntimeModel):
    receipt_digest: Sha256Digest
    call_id: Identifier
    attempt_id: Identifier
    attempt: PositiveInt
    run_id: Identifier
    profile_id: Identifier
    profile_digest: Sha256Digest
    provider_id: Identifier
    proxy_id: Identifier
    requested_alias: ShortStr | None = None
    requested_snapshot: ShortStr
    actual_snapshot: ShortStr | None = None
    runtime_version: ShortStr | None = None
    tokenizer_id: ShortStr | None = None
    tokenizer_version: ShortStr | None = None
    context_window: PositiveInt | None = None
    metadata_exact: bool
    metadata_provenance_digest: Sha256Digest | None = None
    prompt_digest: Sha256Digest
    compiled_context_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    output_schema_digest: Sha256Digest
    config_digest: Sha256Digest
    budget_digest: Sha256Digest
    logical_request_digest: Sha256Digest
    proxy_request_digest: Sha256Digest
    proxy_receipt_digest: Sha256Digest | None = None
    proxy_contract_digest: Sha256Digest
    response_digest: Sha256Digest | None = None
    credential_ref_digest: Sha256Digest
    action_ids: tuple[Identifier, ...]
    policy_ref: Identifier
    data_policy_id: Identifier
    data_consent_ref: Identifier
    previous_receipt_digest: Sha256Digest | None = None
    failover_provenance_digest: Sha256Digest | None = None
    failover_checkpoint_id: Identifier | None = None
    failover_checkpoint_digest: Sha256Digest | None = None
    planned_input_tokens: NonNegativeInt
    reserved_output_tokens: PositiveInt
    reported_input_tokens: NonNegativeInt | None = None
    reported_output_tokens: NonNegativeInt | None = None
    cost_microunits: NonNegativeInt
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
    latency_milliseconds: NonNegativeInt
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
        payload = self.model_dump(mode="python", exclude={"receipt_digest"})
        if not hmac.compare_digest(self.receipt_digest, sha256_digest(payload)):
            raise ValueError("provider receipt digest does not match its fields")
        return self


class ProviderReceiptJournal(Protocol):
    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None: ...

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None: ...

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None: ...

    def append(self, receipt: ProviderCallReceipt) -> None: ...


class MemoryProviderReceiptJournal:
    """Small deterministic journal for loopback labs and contract tests."""

    def __init__(self) -> None:
        self._by_digest: dict[str, ProviderCallReceipt] = {}
        self._by_attempt: dict[tuple[str, int], ProviderCallReceipt] = {}
        self._by_attempt_id: dict[str, ProviderCallReceipt] = {}

    @staticmethod
    def _validated(receipt: ProviderCallReceipt) -> ProviderCallReceipt:
        try:
            return ProviderCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except (AttributeError, ValueError, TypeError) as exc:
            raise ProviderReceiptError("provider receipt is invalid") from exc

    def by_digest(self, receipt_digest: str) -> ProviderCallReceipt | None:
        receipt = self._by_digest.get(receipt_digest)
        return None if receipt is None else self._validated(receipt)

    def by_attempt(self, call_id: str, attempt: int) -> ProviderCallReceipt | None:
        receipt = self._by_attempt.get((call_id, attempt))
        return None if receipt is None else self._validated(receipt)

    def by_attempt_id(self, attempt_id: str) -> ProviderCallReceipt | None:
        receipt = self._by_attempt_id.get(attempt_id)
        return None if receipt is None else self._validated(receipt)

    def append(self, receipt: ProviderCallReceipt) -> None:
        receipt = self._validated(receipt)
        if (
            receipt.receipt_digest in self._by_digest
            or (receipt.call_id, receipt.attempt) in self._by_attempt
            or receipt.attempt_id in self._by_attempt_id
        ):
            raise ProviderReceiptError("provider receipt replay or attempt collision")
        self._by_digest[receipt.receipt_digest] = receipt
        self._by_attempt[(receipt.call_id, receipt.attempt)] = receipt
        self._by_attempt_id[receipt.attempt_id] = receipt


Clock = Callable[[], datetime]
MonotonicClock = Callable[[], int]


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _trusted_now(clock: Clock) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProviderAdapterError("provider adapter clock must be timezone-aware")
    return value


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
        journal: ProviderReceiptJournal,
        live: bool,
        clock: Clock = _system_clock,
        monotonic_clock: MonotonicClock = time.monotonic_ns,
    ) -> None:
        if type(live) is not bool:
            raise TypeError("provider adapter live mode must be a boolean")
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
        self._profiles = _profile_map(profiles)
        self._proxy = proxy
        self._journal = journal
        self._live = live
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._proxy_id = proxy_id
        self._proxy_contract_digest = contract_digest
        self._proxy_dispatch = dispatch
        self._proxy_dispatch_owner = getattr(dispatch, "__self__", None)
        self._proxy_dispatch_function = getattr(dispatch, "__func__", dispatch)

    def call(self, intent: ProviderCallIntent) -> ProviderCallReceipt:
        intent = ProviderCallIntent.model_validate(intent.model_dump(mode="python"))
        profile = self._profiles.get(intent.profile_id)
        if profile is None:
            raise ProviderPolicyError("provider profile is not configured")
        profile = ProviderModelProfile.model_validate(profile.model_dump(mode="python"))
        self._validate_proxy_binding()
        self._validate_pre_dispatch(intent, profile)
        self._validate_retry(intent, profile)
        if self._journal.by_attempt(intent.call_id, intent.attempt) is not None:
            raise ProviderRetryError("provider call attempt already has a receipt")
        if self._journal.by_attempt_id(intent.attempt_id) is not None:
            raise ProviderRetryError("provider attempt ID has already been used")

        tool_digest = provider_tool_schema_digest(intent.tools)
        config_digest = sha256_digest(intent.generation_config)
        budget_digest = sha256_digest(intent.budget)
        logical_digest = _logical_request_digest(intent)
        proxy_request = ProviderProxyRequest(
            proxy_id=self._proxy_id,
            proxy_contract_digest=self._proxy_contract_digest,
            request_id=intent.attempt_id,
            run_id=intent.run_id,
            authority_digest=intent.authority_digest,
            scope_epoch=intent.scope_epoch,
            endpoint_id=profile.endpoint_id,
            provider_id=profile.provider_id,
            model_snapshot=profile.exact_snapshot,
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
        started_ns = self._monotonic_clock()
        # Keep this check immediately adjacent to the pinned dispatch call.  A
        # conforming out-of-process proxy also validates the identity embedded
        # in ProviderProxyRequest; a concurrent in-process substitution is
        # therefore either prevented or recorded as an unknown outcome.
        self._validate_proxy_binding()
        try:
            untrusted_result = self._proxy_dispatch(proxy_request)
        except Exception:
            result = None
        else:
            try:
                result = ProviderProxyResult.model_validate(
                    untrusted_result.model_dump(mode="python")
                )
            except (AttributeError, TypeError, ValueError):
                result = None
        proxy_binding_unchanged = self._proxy_binding_matches()
        completed_ns = self._monotonic_clock()
        completed_at = _trusted_now(self._clock)
        if completed_ns < started_ns:
            raise ProviderAdapterError("provider monotonic clock moved backwards")
        if completed_at < started_at:
            completed_at = started_at

        receipt = self._make_receipt(
            intent=intent,
            profile=profile,
            result=result,
            tool_digest=tool_digest,
            config_digest=config_digest,
            budget_digest=budget_digest,
            logical_digest=logical_digest,
            proxy_request=proxy_request,
            proxy_request_digest=proxy_request_digest,
            proxy_binding_unchanged=proxy_binding_unchanged,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_ns=completed_ns - started_ns,
        )
        self._journal.append(receipt)
        return receipt

    def _proxy_binding_matches(self) -> bool:
        current_dispatch = getattr(self._proxy, "dispatch", None)
        return bool(
            getattr(self._proxy, "plane", None) is ProviderPlane.MODEL_PROVIDER
            and getattr(self._proxy, "proxy_id", None) == self._proxy_id
            and getattr(self._proxy, "contract_digest", None)
            == self._proxy_contract_digest
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
        previous = self._journal.by_digest(intent.previous_receipt_digest)
        if previous is None:
            raise ProviderRetryError("provider retry receipt is unavailable")
        try:
            previous = ProviderCallReceipt.model_validate(previous.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ProviderRetryError("provider retry receipt is invalid") from exc
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
            return
        failover = intent.failover
        if failover is None:
            raise ProviderRetryError("provider change requires explicit failover provenance")
        source = self._profiles.get(previous.profile_id)
        if source is None:
            raise ProviderRetryError("failover source profile is no longer configured")
        if (
            failover.previous_receipt_digest != previous.receipt_digest
            or failover.from_profile_id != source.profile_id
            or failover.to_profile_id != profile.profile_id
        ):
            raise ProviderRetryError("failover provenance does not bind both profiles")
        if (
            source.compatibility_group != profile.compatibility_group
            or source.capability_digest != profile.capability_digest
            or profile.context_window < source.context_window
            or profile.maximum_input_tokens < source.maximum_input_tokens
            or profile.maximum_output_tokens < source.maximum_output_tokens
        ):
            raise ProviderRetryError("failover profile is not capability-compatible")
        if self._live:
            profile.require_live_safe()

    def _make_receipt(
        self,
        *,
        intent: ProviderCallIntent,
        profile: ProviderModelProfile,
        result: ProviderProxyResult | None,
        tool_digest: str,
        config_digest: str,
        budget_digest: str,
        logical_digest: str,
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
        cost = 0
        if usage is not None:
            cost = _ceil_cost(
                usage.input_tokens, profile.input_cost_per_million_microunits
            ) + _ceil_cost(
                usage.output_tokens, profile.output_cost_per_million_microunits
            )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "call_id": intent.call_id,
            "attempt_id": intent.attempt_id,
            "attempt": intent.attempt,
            "run_id": intent.run_id,
            "profile_id": profile.profile_id,
            "profile_digest": sha256_digest(profile),
            "provider_id": profile.provider_id,
            "proxy_id": self._proxy_id,
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
            "tool_schema_digest": tool_digest,
            "output_schema_digest": intent.output_schema_digest,
            "config_digest": config_digest,
            "budget_digest": budget_digest,
            "logical_request_digest": logical_digest,
            "proxy_request_digest": proxy_request_digest,
            "proxy_receipt_digest": None if result is None else result.proxy_receipt_digest,
            "proxy_contract_digest": self._proxy_contract_digest,
            "response_digest": None if result is None else result.response_digest,
            "credential_ref_digest": sha256_digest(intent.credential_ref),
            "action_ids": intent.action_ids,
            "policy_ref": intent.policy_ref,
            "data_policy_id": intent.data_policy_id,
            "data_consent_ref": intent.data_consent_ref,
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
        if usage.output_tokens > intent.generation_config.max_output_tokens:
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
        if cost > intent.budget.remaining_cost_microunits:
            return FailureCode.COST_BUDGET_EXCEEDED
        if (
            result.bytes_sent > profile.maximum_request_bytes
            or result.bytes_received > profile.maximum_response_bytes
        ):
            return FailureCode.BYTE_BUDGET_EXCEEDED
        return None


__all__ = [
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
    "ProxyOutcome",
    "RetryDisposition",
    "provider_tool_schema_digest",
]
