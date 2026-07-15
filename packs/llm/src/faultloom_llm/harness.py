from typing import Literal

from ._base import LlmPackModel
from .content import (
    RetrievalIndex,
    RetrievalObservation,
    RetrievalQuery,
    RetrievalTraceRequest,
)
from .prompt import PromptAnalysis, PromptAnalyzer, PromptTrace
from .tools import (
    AgentToolRequest,
    CompiledToolAction,
    LeaseBindingRequest,
    LeasedToolAction,
    ToolActionCompiler,
)


class LocalHarnessBoundary(LlmPackModel):
    boundary_id: Literal["faultloom.llm.local.v1"] = "faultloom.llm.local.v1"
    transport: Literal["typed_local_call"] = "typed_local_call"
    network_mode: Literal["none"] = "none"
    model_provider_enabled: Literal[False] = False
    arbitrary_tool_access: Literal[False] = False


class LocalAgentHarness:
    def __init__(
        self,
        retrieval: RetrievalIndex,
        compiler: ToolActionCompiler,
    ) -> None:
        self._retrieval = retrieval
        self._compiler = compiler
        self._prompt = PromptAnalyzer()

    @property
    def boundary(self) -> LocalHarnessBoundary:
        return LocalHarnessBoundary()

    def analyze_prompt(self, trace: PromptTrace) -> PromptAnalysis:
        return self._prompt.analyze(trace)

    def retrieve(self, query: RetrievalQuery) -> RetrievalObservation:
        return self._retrieval.retrieve(query)

    def observe_retrieval(
        self,
        request: RetrievalTraceRequest,
    ) -> RetrievalObservation:
        return self._retrieval.observe(request)

    def compile_tool(self, request: AgentToolRequest) -> CompiledToolAction:
        return self._compiler.compile(request)

    def bind_lease(self, request: LeaseBindingRequest) -> LeasedToolAction:
        return self._compiler.admit(request)
