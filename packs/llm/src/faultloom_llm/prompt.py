from __future__ import annotations

from enum import StrEnum
from typing import Self, assert_never

from pydantic import model_validator

from faultloom_protocol import EvidenceRef
from faultloom_protocol.base import Identifier

from ._base import LlmPackModel
from .content import UntrustedContent
from .errors import LlmPackError


class PromptSelection(StrEnum):
    TOOL_SELECTED = "tool_selected"
    TOOL_REJECTED = "tool_rejected"


class PromptTrace(LlmPackModel):
    trace_id: Identifier
    content: UntrustedContent
    selection: PromptSelection
    tool_request_id: Identifier | None = None
    evidence_refs: tuple[EvidenceRef, ...]

    @model_validator(mode="after")
    def _selection_is_bound(self) -> Self:
        match self.selection:
            case PromptSelection.TOOL_SELECTED:
                if self.tool_request_id is None:
                    raise LlmPackError(
                        "llm.prompt_tool_missing",
                        "selected tool traces require a tool request ID",
                    )
            case PromptSelection.TOOL_REJECTED:
                if self.tool_request_id is not None:
                    raise LlmPackError(
                        "llm.prompt_rejected_tool_present",
                        "rejected tool traces cannot retain a selected request",
                    )
            case unreachable:
                assert_never(unreachable)
        if any(item.run_id != self.content.run_id for item in self.evidence_refs):
            raise LlmPackError(
                "llm.prompt_evidence_run_mismatch",
                "prompt evidence belongs to another run",
            )
        observation_ids = {
            observation_id
            for item in self.evidence_refs
            for observation_id in item.observation_ids
        }
        if self.content.source_observation.observation_id not in observation_ids:
            raise LlmPackError(
                "llm.prompt_provenance_missing",
                "prompt evidence must retain the untrusted source observation",
            )
        return self


class PromptOutcome(StrEnum):
    CANDIDATE = "candidate"
    NEGATIVE_CONTROL = "negative_control"


class PromptAnalysis(LlmPackModel):
    trace_id: Identifier
    run_id: Identifier
    outcome: PromptOutcome
    candidate_kind: Identifier
    selected_tool_request_id: Identifier | None
    untrusted_content_ids: tuple[Identifier, ...]
    evidence_refs: tuple[EvidenceRef, ...]


class PromptAnalyzer:
    def analyze(self, trace: PromptTrace) -> PromptAnalysis:
        match trace.selection:
            case PromptSelection.TOOL_SELECTED:
                outcome = PromptOutcome.CANDIDATE
                selected = trace.tool_request_id
            case PromptSelection.TOOL_REJECTED:
                outcome = PromptOutcome.NEGATIVE_CONTROL
                selected = None
            case unreachable:
                assert_never(unreachable)
        return PromptAnalysis(
            trace_id=trace.trace_id,
            run_id=trace.content.run_id,
            outcome=outcome,
            candidate_kind="llm.prompt_injection",
            selected_tool_request_id=selected,
            untrusted_content_ids=(trace.content.content_id,),
            evidence_refs=trace.evidence_refs,
        )
