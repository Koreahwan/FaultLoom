from faultloom.chain import (
    ChainAuthority,
    ChainBudget,
    ChainSearchSettings,
    CrossSurfaceChainEngine,
    ReplayObservation,
    ReplayRequest,
    ReplaySeed,
    normalize_primitives,
)
from faultloom_protocol import ChainGraph, ChainVerdict
from faultloom_llm import AgentToolRequest, LlmPackError

from .chain_authority import authority_grant, build_edge
from .chain_contracts import EdgeSeed, LlmChainFixture, ObservationSeed
from .chain_primitives import chain_states, llm_admission, prompt_intent, web_admission
from .fixture import D2, D3, NOW, LlmAgentFixture


def build_llm_chain_fixture(fixture: LlmAgentFixture) -> LlmChainFixture:
    states = chain_states()
    prompt_action = prompt_intent(fixture, states[0])
    request = AgentToolRequest(
        request_id=fixture.tool_request.request_id,
        run_id=fixture.tool_request.run_id,
        tool_id=fixture.tool_request.tool_id,
        subject=fixture.tool_request.subject,
        payload_digest=fixture.tool_request.payload_digest,
        requested_at=fixture.tool_request.requested_at,
        input_state=states[1],
        parent_action_ids=fixture.tool_request.parent_action_ids,
    )
    _, compiler = fixture.harness_parts()
    tool_action = compiler.compile(request)
    web = web_admission(fixture, states[0])
    prompt = llm_admission(
        fixture,
        ObservationSeed(
            observation_id="observation.chain.prompt",
            capability_kind="llm.prompt_injection_control",
            intent=prompt_action,
            pre_state=states[0],
            post_state=states[1],
            precondition_ids=("effect.web.input",),
            effect_ids=("effect.llm.prompt",),
            dispatch_digest=D2,
        ),
    )
    tool = llm_admission(
        fixture,
        ObservationSeed(
            observation_id="observation.chain.tool",
            capability_kind="llm.mcp_tool_canary",
            intent=tool_action.intent,
            pre_state=states[1],
            post_state=states[2],
            precondition_ids=("effect.llm.prompt",),
            effect_ids=("effect.llm.tool_canary",),
            dispatch_digest=D3,
        ),
    )
    registry = normalize_primitives((web, prompt, tool))
    first = build_edge(
        fixture,
        EdgeSeed(
            edge_id="edge.web-to-llm",
            source_capability_id=web.capability_id,
            target_capability_id=prompt.capability_id,
            intent=prompt_action,
            input_state=states[0],
            effect_id="effect.llm.prompt",
            effect_kind="prompt_injection_control_observed",
            effect_state=states[1],
            lease_id="lease.web-to-llm",
        ),
    )
    second = build_edge(
        fixture,
        EdgeSeed(
            edge_id="edge.llm-to-tool",
            source_capability_id=prompt.capability_id,
            target_capability_id=tool.capability_id,
            intent=tool_action.intent,
            input_state=states[1],
            effect_id="effect.llm.tool_canary",
            effect_kind="inert_tool_canary_observed",
            effect_state=states[2],
            lease_id="lease.llm-to-tool",
        ),
    )
    grant = authority_grant(
        fixture,
        (prompt_action.action_kind, tool_action.intent.action_kind),
    )
    graph = ChainGraph(
        schema_version="0.1.0",
        graph_id="chain-graph.llm.lab",
        run_id=fixture.web_content.run_id,
        capabilities=registry.capabilities,
        edges=(first[0], second[0]),
        impact_goal="Observe an inert owned canary through a scoped agent tool.",
        action_budget=2,
        time_budget_seconds=20,
        version=1,
    )
    return LlmChainFixture(
        registry=registry,
        graph=graph,
        authority=ChainAuthority(
            grant=grant,
            edge_bindings=(first[1], second[1]),
        ),
        settings=ChainSearchSettings(
            start_capability_ids=(web.capability_id,),
            goal_effect_id="effect.llm.tool_canary",
            budget=ChainBudget(actions=2, time_seconds=20, impact=2),
        ),
        reset_states=states,
    )


def clean_web_llm_tool_replay(fixture: LlmAgentFixture) -> ChainVerdict:
    built = build_llm_chain_fixture(fixture)
    engine = CrossSurfaceChainEngine.open(
        built.registry,
        built.graph,
        built.authority,
    )
    result = engine.search(built.settings)
    if result.forward is None:
        raise LlmPackError(
            "llm.chain_unreachable",
            "deterministic Web-to-LLM-to-tool chain was not reachable",
        )
    replay = engine.build_replay(
        ReplaySeed(
            planned=result.forward,
            fresh_identity_context_ids=("identity-context.llm.clean",),
            reset_state_refs=built.reset_states,
        )
    )
    edges = {item.edge_id: item for item in built.graph.edges}
    bindings = {item.edge_id: item for item in built.authority.edge_bindings}
    observations = tuple(
        ReplayObservation(
            edge_id=edge_id,
            action_lease_id=bindings[edge_id].lease.lease_id,
            observed_effect_id=edges[edge_id].observed_effect.effect_id,
            effect_verified=True,
            negative_control_passed=True,
            clean_state_replayed=True,
            evidence_refs=(fixture.prompt_evidence,),
        )
        for edge_id in replay.edge_ids
    )
    return engine.verify_replay(
        ReplayRequest(
            planned=result.forward,
            replay_plan=replay,
            observations=observations,
            verified_at=NOW,
        )
    )
