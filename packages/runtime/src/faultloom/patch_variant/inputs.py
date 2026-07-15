from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import ActionClass, EvidenceRef, ResourceRef, SubjectRef
from faultloom_protocol.base import (
    AwareDatetime,
    Identifier,
    NonEmptyStr,
    Sha256Digest,
    ShortStr,
)

from .errors import PatchVariantError


class _PatchVariantInput(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    schema_version: Literal["0.1.0"] = "0.1.0"


class FingerprintSignalKind(StrEnum):
    HEADER = "header"
    ASSET = "asset"
    BEHAVIOR = "behavior"
    MANIFEST = "manifest"
    SBOM = "sbom"
    SOURCE = "source"


class AdvisorySourceKind(StrEnum):
    OSV = "osv"
    NVD = "nvd"
    VENDOR = "vendor"
    RELEASE_NOTE = "release_note"
    SECURITY_COMMIT = "security_commit"


class PatchState(StrEnum):
    ABSENT = "absent"
    PRESENT = "present"
    BACKPORTED = "backported"
    UNKNOWN = "unknown"


class PatchArtifactKind(StrEnum):
    SOURCE = "source"
    CONFIG = "config"
    TEST = "test"
    API_BEHAVIOR = "api_behavior"


class VariantDimension(StrEnum):
    SIBLING_PATH = "sibling_path"
    ALTERNATE_PARSER = "alternate_parser"
    ALTERNATE_PROTOCOL = "alternate_protocol"
    SIMILAR_HELPER = "similar_helper"
    ROLE_TENANT = "role_tenant"
    CANONICALIZATION = "canonicalization"


class StepHazard(StrEnum):
    SAFE = "safe"
    SHELL = "shell"
    DATA_DUMP = "data_dump"
    PERSISTENCE = "persistence"
    DESTRUCTIVE = "destructive"
    EXTERNAL_MESSAGE = "external_message"
    PAYMENT = "payment"


class FingerprintSignal(_PatchVariantInput):
    signal_id: Identifier
    kind: FingerprintSignalKind
    version_range: ShortStr
    weight_bps: Annotated[int, Field(ge=1, le=10_000)]
    backport_indicator: bool = False
    evidence_ref: EvidenceRef


class FingerprintRequest(_PatchVariantInput):
    fingerprint_id: Identifier
    target_id: Identifier
    component_name: ShortStr
    observed_at: AwareDatetime
    signals: tuple[FingerprintSignal, ...] = Field(min_length=2)


class AdvisoryProvenance(_PatchVariantInput):
    source_id: Identifier
    source_kind: AdvisorySourceKind
    artifact_digest: Sha256Digest
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)
    security_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None = None


class AdvisoryRecord(_PatchVariantInput):
    advisory_id: Identifier
    match_id_prefix: Identifier
    affected_version_ranges: tuple[ShortStr, ...] = Field(min_length=1)
    provenance: tuple[AdvisoryProvenance, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_sources(self) -> Self:
        sources = tuple(item.source_kind for item in self.provenance)
        if len(sources) != len(set(sources)):
            raise PatchVariantError("advisory provenance sources must be unique")
        return self

class ReachabilityRequest(_PatchVariantInput):
    reachability_claim_id: Identifier
    component_present: bool
    vulnerable_path_exposed: bool
    auth_prerequisite_satisfied: bool | None
    config_prerequisite_satisfied: bool | None
    feature_prerequisite_satisfied: bool | None
    patch_state: PatchState
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class PatchArtifact(_PatchVariantInput):
    artifact_id: Identifier
    kind: PatchArtifactKind
    vulnerable_content: NonEmptyStr
    fixed_content: NonEmptyStr
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class PatchRequest(_PatchVariantInput):
    patch_delta_id: Identifier
    invariant_change_id: Identifier
    vulnerable_revision: ShortStr
    fixed_revision: ShortStr
    artifacts: tuple[PatchArtifact, ...] = Field(min_length=1)
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _one_source_and_unique_kinds(self) -> Self:
        kinds = tuple(artifact.kind for artifact in self.artifacts)
        if kinds.count(PatchArtifactKind.SOURCE) != 1:
            raise PatchVariantError("patch analysis requires exactly one source artifact")
        if len(kinds) != len(set(kinds)):
            raise PatchVariantError("patch artifact kinds must be unique")
        return self


class BehaviorDifferential(_PatchVariantInput):
    baseline_control_denied: bool
    candidate_effect_observed: bool
    prerequisites_equal: bool
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class VariantCandidate(_PatchVariantInput):
    candidate_id: Identifier
    dimension: VariantDimension
    location: ShortStr
    candidate_content: NonEmptyStr
    source_query: NonEmptyStr | None = None
    differential: BehaviorDifferential | None = None
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class CandidatePoCStep(_PatchVariantInput):
    step_id: Identifier
    action_class: ActionClass
    action_kind: Identifier
    method: ShortStr
    payload_digest: Sha256Digest | None = None
    expected_effect: NonEmptyStr
    negative_control: NonEmptyStr
    required: bool = True
    hazard: StepHazard = StepHazard.SAFE


class AdaptationRequest(_PatchVariantInput):
    adaptation_id: Identifier
    recipe_id: Identifier
    run_id: Identifier
    target_id: Identifier
    pack_id: Identifier
    route_ref: ResourceRef
    route_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$")]
    identity_context_id: Identifier | None = None
    subject: SubjectRef
    transport: ShortStr
    prerequisite_ids: tuple[Identifier, ...] = Field(min_length=1)
    prerequisites: tuple[NonEmptyStr, ...] = Field(min_length=1)
    candidate_steps: tuple[CandidatePoCStep, ...] = Field(min_length=1)
    expected_observable_effect: NonEmptyStr
    negative_controls: tuple[NonEmptyStr, ...] = Field(min_length=1)
    cleanup_plan_ref: Identifier
    requested_at: AwareDatetime
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class PatchVariantRequest(_PatchVariantInput):
    fingerprint: FingerprintRequest
    advisories: tuple[AdvisoryRecord, ...] = Field(min_length=1)
    selected_advisory_id: Identifier
    reachability: ReachabilityRequest
    patch: PatchRequest
    variant_candidates: tuple[VariantCandidate, ...] = Field(min_length=1)
    adaptation: AdaptationRequest

    @model_validator(mode="after")
    def _selected_advisory_exists(self) -> Self:
        if self.selected_advisory_id not in {
            advisory.advisory_id for advisory in self.advisories
        }:
            raise PatchVariantError("selected advisory is absent from the offline records")
        return self
