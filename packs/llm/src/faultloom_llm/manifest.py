from faultloom_protocol import PackManifest, SCHEMA_VERSION


def llm_agent_manifest() -> PackManifest:
    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.llm.agent",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.llm.agent.v1",
        capability_descriptors=(
            "llm.prompt_boundary",
            "llm.rag_provenance",
            "llm.mcp_authorization",
            "llm.agent_tool_workflow",
        ),
        action_compilers=(
            "llm.prompt.observe",
            "llm.tool.safe_probe",
        ),
        observation_normalizers=("llm.agent_observation.v1",),
        hypothesis_providers=("llm.prompt_injection_candidate.v1",),
        verifier_descriptors=("llm.clean_replay_verifier.v1",),
        evaluation_descriptors=("llm.agent_evaluator.v1",),
        required_gateway_features=(
            "gateway.action_lease",
            "gateway.scope_epoch",
            "gateway.target_egress",
        ),
        required_adapter_capabilities=(),
    )
