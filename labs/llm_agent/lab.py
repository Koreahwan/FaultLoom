from __future__ import annotations

from faultloom_llm import (
    AgentObservation,
    AgentObservationNormalizer,
    CompiledToolAction,
    LocalAgentHarness,
    LeasedToolAction,
    NormalizedAgentObservation,
    PromptAnalysis,
    RetrievalObservation,
)
from faultloom_protocol import ResourceRef, StateRef, sha256_digest

from .fixture import (
    D2,
    D3,
    LlmAgentFixture,
    foreign_retrieval_request,
    prompt_trace,
)
from .lease import lease_binding_request


class LlmAgentLab:
    def __init__(self, fixture: LlmAgentFixture) -> None:
        retrieval, compiler = fixture.harness_parts()
        self._fixture = fixture
        self._harness = LocalAgentHarness(retrieval, compiler)
        self._normalizer = AgentObservationNormalizer()

    @property
    def harness(self) -> LocalAgentHarness:
        return self._harness

    def positive_prompt_injection(self) -> PromptAnalysis:
        return self._harness.analyze_prompt(prompt_trace(self._fixture, True))

    def negative_prompt_control(self) -> PromptAnalysis:
        return self._harness.analyze_prompt(prompt_trace(self._fixture, False))

    def isolated_retrieval(self) -> RetrievalObservation:
        return self._harness.retrieve(self._fixture.query)

    def observed_foreign_retrieval(self) -> RetrievalObservation:
        return self._harness.observe_retrieval(
            foreign_retrieval_request(self._fixture)
        )

    def compile_tool(self) -> CompiledToolAction:
        return self._harness.compile_tool(self._fixture.tool_request)

    def active_tool(self) -> LeasedToolAction:
        compiled = self.compile_tool()
        return self._harness.bind_lease(
            lease_binding_request(compiled, self._fixture)
        )

    def revoked_tool(self) -> LeasedToolAction:
        compiled = self.compile_tool()
        return self._harness.bind_lease(
            lease_binding_request(compiled, self._fixture, revoked=True)
        )

    def tool_observation(self, verified: bool) -> NormalizedAgentObservation:
        compiled = self.compile_tool()
        state = StateRef(
            schema_version="0.1.0",
            state_id="state.llm.tool",
            state_kind="inert_canary",
            state_version=1,
            state_digest=D3,
        )
        source = AgentObservation(
            observation_id=(
                "observation.tool.verified" if verified else "observation.tool.candidate"
            ),
            run_id=self._fixture.web_content.run_id,
            capability_kind="llm.mcp_tool_canary",
            subject=self._fixture.subject,
            resource=ResourceRef(
                schema_version="0.1.0",
                resource_id=compiled.intent.resource.resource_id,
                resource_kind=compiled.intent.resource.resource_kind,
                target_id=compiled.intent.resource.target_id,
                tenant_id=compiled.intent.resource.tenant_id,
            ),
            pre_state=state,
            post_state=state,
            action_intent_digest=sha256_digest(compiled.intent),
            dispatch_receipt_digest=D2,
            evidence_refs=(self._fixture.prompt_evidence,),
            content_provenance=(self._fixture.web_content,),
            precondition_ids=("effect.llm.prompt",),
            effect_ids=("effect.llm.tool_canary",),
            final_effect_observed=verified,
            clean_replay=verified,
            negative_control_passed=verified,
            authorized_lease_observed=verified,
        )
        return self._normalizer.normalize(source)
