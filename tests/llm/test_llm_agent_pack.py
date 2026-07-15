import pytest

from faultloom.chain import finding_eligible, normalize_primitives
from faultloom_llm import (
    LlmPackError,
    ObservationStatus,
    PromptOutcome,
    candidate_research_proposal,
    llm_agent_manifest,
    t35_admission,
)
from faultloom_protocol import VerdictOutcome
from labs.llm_agent import (
    LlmAgentLab,
    build_llm_chain_fixture,
    clean_web_llm_tool_replay,
    llm_agent_fixture,
)
from labs.llm_agent.fixture import NOW


def test_prompt_injection_candidate_and_negative_control_are_distinct() -> None:
    fixture = llm_agent_fixture()
    lab = LlmAgentLab(fixture)

    candidate = lab.positive_prompt_injection()
    control = lab.negative_prompt_control()

    assert candidate.outcome is PromptOutcome.CANDIDATE
    assert candidate.selected_tool_request_id == fixture.tool_request.request_id
    assert candidate.untrusted_content_ids == (fixture.web_content.content_id,)
    proposal = candidate_research_proposal(candidate, NOW)
    assert proposal.proposed_hypotheses[0].supporting_evidence == (
        fixture.prompt_evidence,
    )
    assert control.outcome is PromptOutcome.NEGATIVE_CONTROL
    assert control.selected_tool_request_id is None
    with pytest.raises(LlmPackError, match="llm.prompt_not_candidate"):
        candidate_research_proposal(control, NOW)


def test_rag_retrieval_preserves_provenance_and_tenant_isolation() -> None:
    fixture = llm_agent_fixture()
    lab = LlmAgentLab(fixture)

    isolated = lab.isolated_retrieval()
    foreign = lab.observed_foreign_retrieval()

    assert tuple(item.document_id for item in isolated.documents) == (
        "document.alpha",
    )
    assert isolated.foreign_document_ids == ()
    assert isolated.documents[0].content.trusted is False
    assert isolated.documents[0].content.source_observation.observation_id == (
        "observation.rag.alpha"
    )
    assert foreign.foreign_document_ids == ("document.beta",)
    assert foreign.documents[0].tenant_id == "tenant.beta"


def test_tool_compilation_requires_allowlist_gateway_lease_and_live_scope() -> None:
    fixture = llm_agent_fixture()
    lab = LlmAgentLab(fixture)
    manifest = llm_agent_manifest()

    compiled = lab.compile_tool()
    admitted = lab.active_tool()

    assert "llm.mcp_authorization" in manifest.capability_descriptors
    assert lab.harness.boundary.network_mode == "none"
    assert lab.harness.boundary.model_provider_enabled is False
    assert compiled.intent.action_kind == "llm.tool.safe_probe"
    assert compiled.requires_action_lease is True
    assert compiled.direct_dispatch_permitted is False
    assert admitted.gateway_dispatch_required is True
    assert admitted.lease_id == "lease.llm.tool"
    unknown = fixture.tool_request.model_copy(update={"tool_id": "tool.unlisted"})
    with pytest.raises(LlmPackError, match="llm.tool_not_allowlisted"):
        lab.harness.compile_tool(unknown)
    with pytest.raises(LlmPackError, match="llm.scope_revoked"):
        lab.revoked_tool()


def test_candidate_gate_and_web_llm_tool_clean_replay() -> None:
    fixture = llm_agent_fixture()
    lab = LlmAgentLab(fixture)

    candidate = t35_admission(lab.tool_observation(verified=False))
    verified = t35_admission(lab.tool_observation(verified=True))
    registry = normalize_primitives((candidate, verified))
    built = build_llm_chain_fixture(fixture)
    verdict = clean_web_llm_tool_replay(fixture)

    assert candidate.primitive.verified is False
    assert verified.primitive.verified is True
    assert len(registry.candidate_capability_ids) == 1
    assert len(registry.verified_capability_ids) == 1
    assert lab.tool_observation(False).status is ObservationStatus.CANDIDATE
    assert verdict.outcome is VerdictOutcome.VERIFIED
    assert verdict.longest_verified_prefix == 2
    assert verdict.final_effect_verified is True
    assert finding_eligible(verdict)
    assert {item.source_pack_id for item in built.registry.capabilities} == {
        "pack.web.identity_workflow",
        "pack.llm.agent",
    }
    assert len({item.action_lease_id for item in built.graph.edges}) == 2
    assert all(item.negative_control_refs for item in built.graph.edges)
