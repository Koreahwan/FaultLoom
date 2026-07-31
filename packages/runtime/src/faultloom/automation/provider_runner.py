"""One bounded provider reasoning turn for authorized offline automation.

Only the model-provider plane is used here.  Model output remains untrusted
until the pinned proxy attestation, provider policy, and pure coordinator all
accept it; this module never dispatches a target action or submits a report.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from datetime import datetime
from typing import ClassVar, final, override

from faultloom.provider import (
    ProviderAdapter,
    ProviderCallIntent,
    provider_tool_schema_digest,
)
from faultloom_protocol import Ed25519PublicKeyRecord, sha256_digest

from .coordinator import AuthorizedAutomationCoordinator, validate_automation_request
from .disclosure import verify_model_disclosure_approval
from .models import (
    AuthorizedAutomationResult,
    AutomationRequest,
    ReasoningTurnRequest,
)
from .provider_bridge import extract_provider_tool_arguments
from .provider_contract import MODEL_TURN_TOOL_ID, model_turn_provider_tool_spec
from .provider_prompt import OneShotReasoningPromptResolver


@final
class ProviderAutomationRunnerError(RuntimeError):
    """A provider turn could not cross the authorized automation boundary."""

    __slots__: ClassVar[tuple[str, ...]] = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

    @override
    def __str__(self) -> str:
        return self.reason


def run_provider_automation_turn(
    *,
    request: AutomationRequest,
    base_intent: ProviderCallIntent,
    resolver: OneShotReasoningPromptResolver,
    adapter: ProviderAdapter,
    trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
    trusted_disclosure_keys: dict[str, Ed25519PublicKeyRecord],
    coordinator: AuthorizedAutomationCoordinator,
    trusted_clock: Callable[[], datetime],
) -> AuthorizedAutomationResult:
    """Run provider-only reasoning and compile one candidate-only result.

    ``base_intent`` supplies the already selected profile, generation settings,
    token/cost budget, consent, and credential reference.  Values derived from
    the automation request and canonical prompt are rebound here and cannot be
    caller-selected.
    """

    if type(request) is not AutomationRequest:
        raise ProviderAutomationRunnerError(
            "provider automation requires an exact automation request"
        )
    if type(base_intent) is not ProviderCallIntent:
        raise ProviderAutomationRunnerError(
            "provider automation requires an exact base provider intent"
        )
    if type(resolver) is not OneShotReasoningPromptResolver:
        raise ProviderAutomationRunnerError(
            "provider automation requires the one-shot reasoning resolver"
        )
    if type(adapter) is not ProviderAdapter:
        raise ProviderAutomationRunnerError(
            "provider automation requires the exact provider adapter"
        )
    if type(coordinator) is not AuthorizedAutomationCoordinator:
        raise ProviderAutomationRunnerError(
            "provider automation requires the exact pure coordinator"
        )

    if not callable(trusted_clock):
        raise ProviderAutomationRunnerError("provider automation requires a trusted clock")
    dispatch_at = trusted_clock()
    if (
        type(dispatch_at) is not datetime
        or dispatch_at.tzinfo is None
        or dispatch_at.utcoffset() is None
    ):
        raise ProviderAutomationRunnerError(
            "provider automation trusted clock returned an invalid time"
        )
    try:
        exact_request = validate_automation_request(request)
    except (TypeError, ValueError) as exc:
        raise ProviderAutomationRunnerError(
            "automation request failed pre-provider authority admission"
        ) from exc
    exact_base = ProviderCallIntent.model_validate(base_intent.model_dump(mode="python"))
    run_id = exact_request.observations.run_id
    grant = exact_request.authority_grant
    authority_digest = sha256_digest(grant)
    provider_policy = grant.provider_policy

    if exact_request.provider_network_access != "provider_only":
        raise ProviderAutomationRunnerError(
            "provider automation requires provider-only network authorization"
        )
    if exact_base.run_id != run_id:
        raise ProviderAutomationRunnerError("base provider intent belongs to another run")
    if not hmac.compare_digest(exact_base.authority_digest, authority_digest):
        raise ProviderAutomationRunnerError(
            "base provider intent authority does not match the request"
        )
    if exact_base.data_policy_id != provider_policy.data_policy_id:
        raise ProviderAutomationRunnerError(
            "base provider intent data policy does not match the authority grant"
        )
    if not provider_policy.allowed_providers:
        raise ProviderAutomationRunnerError("authority grant allows no model provider")
    if not provider_policy.allowed_model_snapshots:
        raise ProviderAutomationRunnerError("authority grant allows no model snapshot")
    if exact_request.issued_at > dispatch_at:
        raise ProviderAutomationRunnerError(
            "provider automation request is dated after trusted dispatch time"
        )
    if not grant.not_before <= dispatch_at < grant.expires_at:
        raise ProviderAutomationRunnerError(
            "provider automation request is outside the authority validity window"
        )
    if not any(
        window.starts_at <= dispatch_at < window.ends_at
        for window in grant.execution_windows
    ):
        raise ProviderAutomationRunnerError(
            "provider automation request is outside every execution window"
        )

    try:
        selected_profile = ProviderAdapter.configured_profile(
            adapter,
            exact_base.profile_id,
        )
    except Exception as exc:
        raise ProviderAutomationRunnerError(
            "base intent provider profile is not configured"
        ) from exc
    if selected_profile.provider_id not in provider_policy.allowed_providers:
        raise ProviderAutomationRunnerError(
            "configured provider is outside the authority grant"
        )
    if selected_profile.exact_snapshot not in provider_policy.allowed_model_snapshots:
        raise ProviderAutomationRunnerError(
            "configured model snapshot is outside the authority grant"
        )
    if selected_profile.data_policy_id != provider_policy.data_policy_id:
        raise ProviderAutomationRunnerError(
            "configured provider data policy does not match the authority grant"
        )

    evidence_refs = {
        item.evidence_id: item for item in exact_request.observations.evidence_refs
    }
    try:
        for excerpt in exact_request.observations.excerpts:
            reference = evidence_refs[excerpt.evidence_id]
            if reference.redaction_digest is None:
                raise ValueError("provider evidence has no redaction digest")
            _ = verify_model_disclosure_approval(
                excerpt.approval,
                trusted_disclosure_keys,
                expected_run_id=run_id,
                expected_evidence_id=excerpt.evidence_id,
                expected_source_cas_digest=reference.cas_digest,
                expected_redaction_digest=reference.redaction_digest,
                expected_content_digest=excerpt.content_digest,
                expected_media_type=excerpt.media_type,
                expected_data_policy_id=provider_policy.data_policy_id,
                expected_provider_id=selected_profile.provider_id,
                verification_time=dispatch_at,
            )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProviderAutomationRunnerError(
            "provider evidence lacks a trusted model disclosure approval"
        ) from exc

    context = ReasoningTurnRequest.from_request(exact_request)
    payload = resolver.publish(
        request_id=exact_base.attempt_id,
        context=context,
        generation=exact_base.generation_config,
    )
    try:
        bound_intent = ProviderCallIntent.model_validate(
            exact_base.model_copy(
                update={
                    "run_id": run_id,
                    "authority_digest": authority_digest,
                    "prompt_digest": payload.prompt_digest(),
                    "compiled_context_digest": sha256_digest(
                        context.model_dump(mode="json")
                    ),
                    "prompt_bytes": payload.prompt_bytes(),
                    # Fail-safe token accounting: without a pinned tokenizer,
                    # one UTF-8 byte is reserved as one input token.
                    "input_tokens": payload.prompt_bytes(),
                    "tools": (model_turn_provider_tool_spec(),),
                    "output_schema_digest": context.output_schema_digest,
                    "data_policy_id": provider_policy.data_policy_id,
                    "requested_at": dispatch_at,
                }
            ).model_dump(mode="python")
        )
        receipt = adapter.call(bound_intent)
    finally:
        # A pre-dispatch adapter failure may not consume the resolver entry.
        # Retire it in either case; request IDs remain tombstoned against replay.
        resolver.discard(exact_base.attempt_id)

    try:
        raw_model_turn = extract_provider_tool_arguments(
            receipt,
            trusted_proxy_attestation_key=trusted_proxy_attestation_key,
            expected_run_id=run_id,
            expected_tool_id=MODEL_TURN_TOOL_ID,
            max_bytes=exact_request.limits.max_response_bytes,
        )
    except Exception as exc:
        raise ProviderAutomationRunnerError(
            "provider receipt did not contain one admitted model turn"
        ) from exc

    if not hmac.compare_digest(receipt.authority_digest, authority_digest):
        raise ProviderAutomationRunnerError(
            "receipted authority does not match the automation request"
        )
    if receipt.request_requested_at != dispatch_at:
        raise ProviderAutomationRunnerError(
            "receipted request time does not match the automation request"
        )
    if receipt.provider_id not in provider_policy.allowed_providers:
        raise ProviderAutomationRunnerError(
            "receipted provider is outside the authority grant"
        )
    if (
        receipt.actual_snapshot is None
        or receipt.requested_snapshot not in provider_policy.allowed_model_snapshots
        or receipt.actual_snapshot not in provider_policy.allowed_model_snapshots
    ):
        raise ProviderAutomationRunnerError(
            "receipted model snapshot is outside the authority grant"
        )
    if receipt.data_policy_id != provider_policy.data_policy_id:
        raise ProviderAutomationRunnerError(
            "receipted data policy does not match the authority grant"
        )
    if not hmac.compare_digest(receipt.prompt_digest, payload.prompt_digest()):
        raise ProviderAutomationRunnerError("receipted prompt digest drifted")
    if not hmac.compare_digest(
        receipt.compiled_context_digest,
        sha256_digest(context.model_dump(mode="json")),
    ):
        raise ProviderAutomationRunnerError("receipted reasoning context drifted")
    if not hmac.compare_digest(
        receipt.output_schema_digest,
        context.output_schema_digest,
    ):
        raise ProviderAutomationRunnerError("receipted output schema drifted")
    if not hmac.compare_digest(
        receipt.tool_schema_digest,
        provider_tool_schema_digest((model_turn_provider_tool_spec(),)),
    ):
        raise ProviderAutomationRunnerError("receipted tool schema drifted")

    return coordinator.run(
        request=exact_request,
        raw_model_turn=raw_model_turn,
    )


__all__ = [
    "ProviderAutomationRunnerError",
    "run_provider_automation_turn",
]
