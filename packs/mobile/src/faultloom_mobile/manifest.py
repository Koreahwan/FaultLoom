"""Manifest for the future mobile/API observation-only pack."""

from faultloom_protocol import SCHEMA_VERSION
from faultloom_protocol.models import PackManifest


def mobile_manifest() -> PackManifest:
    """Declare a normalizer only; the pack has no device or action compiler."""

    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.mobile",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.mobile.v1",
        capability_descriptors=("mobile.api_binding_readonly",),
        action_compilers=(),
        observation_normalizers=("mobile.api_binding.normalizer",),
        hypothesis_providers=("mobile.api_binding.candidate_provider",),
        verifier_descriptors=(),
        evaluation_descriptors=("mobile.api_binding.evaluator",),
        required_gateway_features=(),
        required_adapter_capabilities=(),
    )
