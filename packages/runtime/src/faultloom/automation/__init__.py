from .coordinator import (
    AuthorizedAutomationCoordinator,
    parse_model_turn,
    validate_automation_request,
)
from .admission import (
    AutomationAdmission,
    AutomationAdmissionError,
    SignedAutomationAdmission,
    automation_admission_signing_bytes,
    sign_automation_admission,
    verify_automation_admission,
)
from .models import (
    ActionContext,
    ActionEstimateProposal,
    AuthorizedAutomationError,
    AuthorizedAutomationResult,
    AutomationLimits,
    AutomationRequest,
    HypothesisProposal,
    CandidateFindingDraft,
    FindingDraftProposal,
    ModelDisclosureApproval,
    ModelTurn,
    NegativeConclusionProposal,
    ObservationBundle,
    ObservationExcerpt,
    ReasoningEvidence,
    ReasoningScopeSummary,
    ReasoningTurnRequest,
    SafePoCContext,
    SafePoCProposal,
    SafePoCStepProposal,
    SignedModelDisclosureApproval,
    ToolActionProposal,
    model_turn_output_schema,
    model_turn_schema_digest,
)
from .disclosure import (
    ModelDisclosureError,
    model_disclosure_approval_signing_bytes,
    sign_model_disclosure_approval,
    verify_model_disclosure_approval,
)
from .candidate_outbox import (
    AutomationResultBundlePublication,
    CandidateOutboxError,
    CandidateOutboxPublication,
    write_automation_result_bundle,
    write_candidate_outbox,
)
_PERSISTENCE_EXPORTS = frozenset(
    {
        "AutomationTurnEnvelope",
        "load_automation_turn",
        "persist_automation_turn",
    }
)
_PROVIDER_BRIDGE_EXPORTS = frozenset(
    {
        "MAX_PROVIDER_TOOL_ARGUMENT_BYTES",
        "ProviderToolCallBridgeError",
        "extract_provider_tool_arguments",
    }
)
_PROVIDER_CONTRACT_EXPORTS = frozenset(
    {
        "MODEL_TURN_TOOL_ID",
        "MODEL_TURN_WIRE_NAME",
        "model_turn_function_schema",
        "model_turn_function_schema_bytes",
        "model_turn_openai_function_schema",
        "model_turn_provider_output_schema",
        "model_turn_provider_tool_spec",
    }
)
_PROVIDER_PROMPT_EXPORTS = frozenset(
    {
        "MAX_REASONING_MESSAGE_BYTES",
        "OneShotReasoningPromptResolver",
        "ReasoningPromptError",
        "build_reasoning_chat_payload",
    }
)
_PROVIDER_RUNNER_EXPORTS = frozenset(
    {
        "ProviderAutomationRunnerError",
        "run_provider_automation_turn",
    }
)
_EXECUTION_BRIDGE_EXPORTS = frozenset(
    {
        "AUTOMATION_DISPATCH_ACTOR_STREAM",
        "AUTOMATION_DISPATCH_EVENT_TYPE",
        "AUTOMATION_DISPATCH_MEDIA_TYPE",
        "AutomationDispatchEnvelope",
        "AutomationDispatchError",
        "AutomationDispatchPersistence",
        "AutomationDispatchRecord",
        "execute_admitted_tool_plan",
        "load_automation_dispatch",
        "load_authenticated_automation_dispatch",
        "persist_automation_dispatch",
    }
)


def __getattr__(name: str) -> object:
    """Load non-offline automation APIs only when a caller requests one."""

    if name in _PERSISTENCE_EXPORTS:
        from . import persistence

        value = getattr(persistence, name)
    elif name in _EXECUTION_BRIDGE_EXPORTS:
        from . import execution_bridge

        value = getattr(execution_bridge, name)
    elif name in _PROVIDER_BRIDGE_EXPORTS:
        from . import provider_bridge

        value = getattr(provider_bridge, name)
    elif name in _PROVIDER_CONTRACT_EXPORTS:
        from . import provider_contract

        value = getattr(provider_contract, name)
    elif name in _PROVIDER_PROMPT_EXPORTS:
        from . import provider_prompt

        value = getattr(provider_prompt, name)
    elif name in _PROVIDER_RUNNER_EXPORTS:
        from . import provider_runner

        value = getattr(provider_runner, name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value

__all__ = [
    "ActionContext",
    "ActionEstimateProposal",
    "AUTOMATION_DISPATCH_ACTOR_STREAM",
    "AUTOMATION_DISPATCH_EVENT_TYPE",
    "AUTOMATION_DISPATCH_MEDIA_TYPE",
    "AuthorizedAutomationCoordinator",
    "AuthorizedAutomationError",
    "AuthorizedAutomationResult",
    "AutomationAdmission",
    "AutomationAdmissionError",
    "AutomationDispatchEnvelope",
    "AutomationDispatchError",
    "AutomationDispatchPersistence",
    "AutomationDispatchRecord",
    "AutomationTurnEnvelope",
    "CandidateOutboxError",
    "CandidateOutboxPublication",
    "CandidateFindingDraft",
    "AutomationLimits",
    "AutomationRequest",
    "AutomationResultBundlePublication",
    "HypothesisProposal",
    "FindingDraftProposal",
    "ModelDisclosureApproval",
    "ModelDisclosureError",
    "ModelTurn",
    "MODEL_TURN_TOOL_ID",
    "MODEL_TURN_WIRE_NAME",
    "MAX_PROVIDER_TOOL_ARGUMENT_BYTES",
    "MAX_REASONING_MESSAGE_BYTES",
    "NegativeConclusionProposal",
    "ObservationBundle",
    "ObservationExcerpt",
    "OneShotReasoningPromptResolver",
    "ProviderToolCallBridgeError",
    "ProviderAutomationRunnerError",
    "ReasoningEvidence",
    "ReasoningScopeSummary",
    "ReasoningTurnRequest",
    "ReasoningPromptError",
    "SafePoCContext",
    "SafePoCProposal",
    "SafePoCStepProposal",
    "SignedModelDisclosureApproval",
    "SignedAutomationAdmission",
    "ToolActionProposal",
    "model_turn_output_schema",
    "model_turn_schema_digest",
    "model_disclosure_approval_signing_bytes",
    "automation_admission_signing_bytes",
    "model_turn_function_schema",
    "model_turn_function_schema_bytes",
    "model_turn_openai_function_schema",
    "model_turn_provider_output_schema",
    "model_turn_provider_tool_spec",
    "parse_model_turn",
    "build_reasoning_chat_payload",
    "extract_provider_tool_arguments",
    "execute_admitted_tool_plan",
    "load_automation_dispatch",
    "load_authenticated_automation_dispatch",
    "load_automation_turn",
    "persist_automation_turn",
    "persist_automation_dispatch",
    "run_provider_automation_turn",
    "sign_model_disclosure_approval",
    "sign_automation_admission",
    "verify_automation_admission",
    "verify_model_disclosure_approval",
    "validate_automation_request",
    "write_candidate_outbox",
    "write_automation_result_bundle",
]
