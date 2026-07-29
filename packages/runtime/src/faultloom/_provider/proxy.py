from __future__ import annotations

import hmac
from typing import Literal, Protocol, Self

from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    SecretRef,
)
from faultloom_protocol.base import (
    AwareDatetime,
    Identifier,
    NonEmptyStr,
    Sha256Digest,
    ShortStr,
)
from pydantic import ConfigDict, model_validator

from .common import (
    ProviderPlane,
    ProxyEffectDisposition,
    ProxyOutcome,
    Signed64NonNegative,
    Signed64Positive,
    _RuntimeModel,
    provider_canonical_json_bytes as canonical_json_bytes,
    provider_sha256_digest as sha256_digest,
)
from .metadata import ProviderObservedMetadata


class ProviderUsage(_RuntimeModel):
    input_tokens: Signed64NonNegative
    output_tokens: Signed64NonNegative


class ProviderToolCall(_RuntimeModel):
    """A bounded, signed function invocation returned by a provider."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        str_strip_whitespace=False,
        validate_default=True,
    )

    call_id: ShortStr
    tool_id: Identifier
    name: ShortStr
    arguments_json: NonEmptyStr


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
    tool_calls: tuple[ProviderToolCall, ...] = ()
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
        if pre_send and self.tool_calls:
            raise ValueError("pre-send proxy outcomes cannot carry provider tool calls")
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
