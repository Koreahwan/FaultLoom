from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from faultloom_protocol import (
    AdvisoryMatch,
    ComponentFingerprint,
    ConfidenceClass,
    DeploymentAdaptation,
    InvariantChange,
    PatchDelta,
    PoCRecipe,
    ReachabilityClaim,
    VariantHypothesis,
    VersionHypothesis,
)
from faultloom_protocol.base import Identifier, Sha256Digest

from .inputs import (
    AdvisoryProvenance,
    PatchArtifactKind,
    PatchState,
    VariantDimension,
)


class _PatchVariantResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    schema_version: Literal["0.1.0"] = "0.1.0"


class FingerprintAnalysis(_PatchVariantResult):
    fingerprint: ComponentFingerprint
    version_hypotheses: tuple[VersionHypothesis, ...]


class AdvisoryResolution(_PatchVariantResult):
    match: AdvisoryMatch
    provenance: tuple[AdvisoryProvenance, ...]


class ReachabilityAssessment(_PatchVariantResult):
    claim: ReachabilityClaim
    component_present: bool
    vulnerable_path_exposed: bool
    auth_prerequisite_satisfied: bool | None
    config_prerequisite_satisfied: bool | None
    feature_prerequisite_satisfied: bool | None
    patch_state: PatchState


class ArtifactDelta(_PatchVariantResult):
    artifact_id: Identifier
    kind: PatchArtifactKind
    diff_digest: Sha256Digest
    added_lines: tuple[str, ...]
    removed_lines: tuple[str, ...]


class PatchAnalysis(_PatchVariantResult):
    patch_delta: PatchDelta
    artifact_deltas: tuple[ArtifactDelta, ...]
    invariant_changes: tuple[InvariantChange, ...]


class VariantAssessment(_PatchVariantResult):
    candidate_id: Identifier
    confidence: ConfidenceClass
    black_box_differential: bool
    hypothesis: VariantHypothesis


class VariantSearchResult(_PatchVariantResult):
    search_dimensions: tuple[VariantDimension, ...]
    assessments: tuple[VariantAssessment, ...]


class AdaptationResult(_PatchVariantResult):
    adaptation: DeploymentAdaptation
    recipe: PoCRecipe
    omitted_nonessential_step_ids: tuple[Identifier, ...]


class PatchVariantResult(_PatchVariantResult):
    fingerprint: FingerprintAnalysis
    advisories: tuple[AdvisoryResolution, ...]
    reachability: ReachabilityAssessment
    patch: PatchAnalysis
    variants: VariantSearchResult
    adaptation: AdaptationResult
    claim_status: Literal["candidate_requires_independent_verification"] = (
        "candidate_requires_independent_verification"
    )
    zero_day_claimed: Literal[False] = False
