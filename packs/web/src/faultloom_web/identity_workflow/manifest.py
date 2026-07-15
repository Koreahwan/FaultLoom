"""Identity/workflow pack manifest."""

from faultloom_protocol import PackManifest, SCHEMA_VERSION


def identity_workflow_manifest() -> PackManifest:
    """Describe the isolated, Gateway-dependent T32 pack surface."""

    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.web.identity_workflow",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.web.identity_workflow.v1",
        capability_descriptors=(
            "web.identity_graph",
            "web.workflow_graph",
            "web.auth_semantics",
            "web.differential_planning",
        ),
        action_compilers=("web.workflow_action_compiler",),
        observation_normalizers=("web.workflow_trace_normalizer",),
        hypothesis_providers=("web.workflow_invariant_provider",),
        verifier_descriptors=("web.multi_identity_replay_verifier",),
        evaluation_descriptors=("web.identity_workflow_evaluator",),
        required_gateway_features=(
            "gateway.action_lease",
            "gateway.scope_epoch",
            "gateway.target_egress",
        ),
        required_adapter_capabilities=(
            "semantic_http",
            "isolated_browser_context",
        ),
    )
