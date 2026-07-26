"""Future Cloud/IAM/OAuth observation descriptors, isolated from v0.1 packs."""

from .iam_oauth import (
    CloudTrustEvidence,
    CloudTrustRun,
    CloudTrustVerdict,
    observe_cloud_trust,
)
from .manifest import cloud_iam_oauth_manifest

__all__ = [
    "CloudTrustEvidence",
    "CloudTrustRun",
    "CloudTrustVerdict",
    "cloud_iam_oauth_manifest",
    "observe_cloud_trust",
]
