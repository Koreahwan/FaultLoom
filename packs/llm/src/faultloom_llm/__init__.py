"""FaultLoom LLM/agent pack with side-effect-free public imports."""

from importlib import import_module

__all__ = [
    "AgentObservation",
    "AgentObservationNormalizer",
    "AgentToolRequest",
    "CompiledToolAction",
    "ContentSource",
    "LeaseBindingRequest",
    "LeasedToolAction",
    "LlmPackError",
    "LocalAgentHarness",
    "LocalHarnessBoundary",
    "NormalizedAgentObservation",
    "ObservationStatus",
    "PromptAnalysis",
    "PromptAnalyzer",
    "PromptOutcome",
    "PromptSelection",
    "PromptTrace",
    "RetrievalDocument",
    "RetrievalIndex",
    "RetrievalObservation",
    "RetrievalQuery",
    "RetrievalTraceRequest",
    "ToolActionCompiler",
    "ToolDescriptor",
    "ToolPolicy",
    "ToolTransport",
    "UntrustedContent",
    "candidate_research_proposal",
    "llm_agent_manifest",
    "t35_admission",
]

_EXPORT_MODULES = {
    "AgentObservation": ".observations",
    "AgentObservationNormalizer": ".observations",
    "AgentToolRequest": ".tools",
    "CompiledToolAction": ".tools",
    "ContentSource": ".content",
    "LeaseBindingRequest": ".tools",
    "LeasedToolAction": ".tools",
    "LlmPackError": ".errors",
    "LocalAgentHarness": ".harness",
    "LocalHarnessBoundary": ".harness",
    "NormalizedAgentObservation": ".observations",
    "ObservationStatus": ".observations",
    "PromptAnalysis": ".prompt",
    "PromptAnalyzer": ".prompt",
    "PromptOutcome": ".prompt",
    "PromptSelection": ".prompt",
    "PromptTrace": ".prompt",
    "RetrievalDocument": ".content",
    "RetrievalIndex": ".content",
    "RetrievalObservation": ".content",
    "RetrievalQuery": ".content",
    "RetrievalTraceRequest": ".content",
    "ToolActionCompiler": ".tools",
    "ToolDescriptor": ".tools",
    "ToolPolicy": ".tools",
    "ToolTransport": ".tools",
    "UntrustedContent": ".content",
    "candidate_research_proposal": ".interop",
    "llm_agent_manifest": ".manifest",
    "t35_admission": ".interop",
}


def __getattr__(name: str) -> object:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
