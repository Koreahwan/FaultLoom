"""Manifest for synthetic-only advanced-Web observation slices."""

from faultloom_protocol import PackManifest, SCHEMA_VERSION


def advanced_web_manifest() -> PackManifest:
    """Declare observation-only descriptors; no action compiler is present."""

    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.advanced_web",
        pack_version="0.2.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.advanced_web.v1",
        capability_descriptors=(
            "advanced_web.cache_desync_readonly",
            "advanced_web.raw_message_readonly",
            "advanced_web.race_window_readonly",
        ),
        action_compilers=(),
        observation_normalizers=(
            "advanced_web.cache_desync.normalizer",
            "advanced_web.raw_message.normalizer",
            "advanced_web.race_window.normalizer",
        ),
        hypothesis_providers=(
            "advanced_web.cache_desync.candidate_provider",
            "advanced_web.raw_message.candidate_provider",
            "advanced_web.race_window.candidate_provider",
        ),
        verifier_descriptors=(),
        evaluation_descriptors=(
            "advanced_web.cache_desync.evaluator",
            "advanced_web.raw_message.evaluator",
            "advanced_web.race_window.evaluator",
        ),
        required_gateway_features=(),
        required_adapter_capabilities=(),
    )
