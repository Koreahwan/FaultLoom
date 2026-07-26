"""Manifest for observation-only Cloud/IAM/OAuth descriptors."""

from faultloom_protocol import SCHEMA_VERSION
from faultloom_protocol.models import PackManifest


def cloud_iam_oauth_manifest() -> PackManifest:
    """Declare normalization only; this pack cannot acquire or use credentials."""

    return PackManifest(
        schema_version=SCHEMA_VERSION,
        pack_id="pack.cloud.iam_oauth",
        pack_version="0.1.0",
        protocol_range=">=0.1.0,<0.2.0",
        schema_namespace="faultloom.cloud.iam_oauth.v1",
        capability_descriptors=(
            "cloud.iam_oauth.readonly_trust_projection",
            "cloud.iam_oauth.readonly_privilege_path",
        ),
        action_compilers=(),
        observation_normalizers=("cloud.iam_oauth.trust_path.normalizer",),
        hypothesis_providers=("cloud.iam_oauth.candidate_provider",),
        verifier_descriptors=(),
        evaluation_descriptors=("cloud.iam_oauth.evaluator",),
        required_gateway_features=(
            "gateway.action_lease",
            "gateway.scope_epoch",
            "gateway.target_egress",
        ),
        required_adapter_capabilities=(),
    )
