from faultloom_protocol import PackManifest, SCHEMA_VERSION

from .descriptors import (
    ACTION_COMPILER_ID,
    EVALUATOR_ID,
    HYPOTHESIS_PROVIDER_ID,
    OBSERVATION_NORMALIZER_ID,
    VERIFIER_ID,
)


def web_api_manifest() -> PackManifest:
    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.web",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.web.api.v1",
        capability_descriptors=(
            "web.identity_workflow",
            "web.api_async_surface",
            "web.cross_surface_chain",
        ),
        action_compilers=(ACTION_COMPILER_ID,),
        observation_normalizers=(OBSERVATION_NORMALIZER_ID,),
        hypothesis_providers=(HYPOTHESIS_PROVIDER_ID,),
        verifier_descriptors=(VERIFIER_ID,),
        evaluation_descriptors=(EVALUATOR_ID,),
        required_gateway_features=(
            "gateway.action_lease",
            "gateway.scope_epoch",
            "gateway.target_egress",
            "gateway.callback_lease",
        ),
        required_adapter_capabilities=(
            "semantic_http",
            "isolated_browser_context",
            "semantic_websocket",
        ),
    )
