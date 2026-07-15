from __future__ import annotations

from typing import Final

from faultloom.patch_variant import (
    AdvisoryProvenance,
    AdvisoryRecord,
    AdvisorySourceKind,
    BehaviorDifferential,
    FingerprintRequest,
    FingerprintSignal,
    FingerprintSignalKind,
    PatchArtifact,
    PatchArtifactKind,
    PatchRequest,
    PatchVariantEngine,
    PatchVariantRequest,
    PatchVariantResult,
    ReachabilityRequest,
    VariantCandidate,
    VariantDimension,
)

from .adaptation_fixture import build_adaptation_request
from .contracts import PatchVariantFixtureCase, PatchVariantFixtureManifest
from .fixture_support import NOW as _NOW
from .fixture_support import digest as _digest
from .fixture_support import evidence as _evidence

_ADVISORY_ID: Final = "CVE-2030-0001"


def replay_patch_variant_fixture(
    manifest: PatchVariantFixtureManifest,
    case_id: str,
) -> PatchVariantResult:
    request = _build_request(manifest, manifest.case(case_id))
    return PatchVariantEngine().run(request)


def _build_request(
    manifest: PatchVariantFixtureManifest,
    fixture_case: PatchVariantFixtureCase,
) -> PatchVariantRequest:
    signals = tuple(
        FingerprintSignal(
            signal_id=f"{fixture_case.case_id}.signal.{kind.value}",
            kind=kind,
            version_range="1.2.x",
            weight_bps=weight,
            backport_indicator=fixture_case.backport_signal,
            evidence_ref=_evidence(f"{fixture_case.case_id}.fingerprint.{kind.value}"),
        )
        for kind, weight in (
            (FingerprintSignalKind.HEADER, 2_000),
            (FingerprintSignalKind.BEHAVIOR, 3_000),
            (FingerprintSignalKind.SBOM, 5_000),
        )
    )
    fingerprint = FingerprintRequest(
        fingerprint_id=f"{fixture_case.case_id}.fingerprint",
        target_id="target.patch-variant-lab",
        component_name=manifest.component_name,
        observed_at=_NOW,
        signals=signals,
    )
    provenance = tuple(
        AdvisoryProvenance(
            source_id=f"source.{source.value}",
            source_kind=source,
            artifact_digest=_digest(f"offline-{source.value}"),
            evidence_refs=(_evidence(f"advisory.{source.value}"),),
            security_commit="a" * 40
            if source is AdvisorySourceKind.SECURITY_COMMIT
            else None,
        )
        for source in AdvisorySourceKind
    )
    advisory = AdvisoryRecord(
        advisory_id=_ADVISORY_ID,
        match_id_prefix=f"{fixture_case.case_id}.advisory-match",
        affected_version_ranges=("1.2.x",),
        provenance=provenance,
    )
    reachability = ReachabilityRequest(
        reachability_claim_id=f"{fixture_case.case_id}.reachability",
        component_present=fixture_case.component_present,
        vulnerable_path_exposed=fixture_case.path_exposed,
        auth_prerequisite_satisfied=fixture_case.auth_satisfied,
        config_prerequisite_satisfied=fixture_case.config_satisfied,
        feature_prerequisite_satisfied=fixture_case.feature_satisfied,
        patch_state=fixture_case.patch_state,
        evidence_refs=(_evidence(f"{fixture_case.case_id}.reachability"),),
    )
    patch = _patch_request(fixture_case)
    candidates = _variant_candidates(fixture_case)
    adaptation = build_adaptation_request(fixture_case)
    return PatchVariantRequest(
        fingerprint=fingerprint,
        advisories=(advisory,),
        selected_advisory_id=_ADVISORY_ID,
        reachability=reachability,
        patch=patch,
        variant_candidates=candidates,
        adaptation=adaptation,
    )

def _patch_request(fixture_case: PatchVariantFixtureCase) -> PatchRequest:
    source_vulnerable = """def read(resource_id):
    return repository.lookup(resource_id)
"""
    source_fixed = """def read(resource_id, tenant_id):
    # invariant: resource access is tenant-bound
    # condition: tenant_id == resource.tenant_id
    # sink: resource lookup
    # boundary: tenant trust boundary
    return repository.lookup_for_tenant(resource_id, tenant_id)
"""
    artifacts = (
        PatchArtifact(
            artifact_id="artifact.source",
            kind=PatchArtifactKind.SOURCE,
            vulnerable_content=source_vulnerable,
            fixed_content=source_fixed,
            evidence_refs=(_evidence("patch.source"),),
        ),
        PatchArtifact(
            artifact_id="artifact.config",
            kind=PatchArtifactKind.CONFIG,
            vulnerable_content="tenant_binding=false",
            fixed_content="tenant_binding=true",
            evidence_refs=(_evidence("patch.config"),),
        ),
        PatchArtifact(
            artifact_id="artifact.test",
            kind=PatchArtifactKind.TEST,
            vulnerable_content="cross_tenant_expected=200",
            fixed_content="cross_tenant_expected=403",
            evidence_refs=(_evidence("patch.test"),),
        ),
        PatchArtifact(
            artifact_id="artifact.api",
            kind=PatchArtifactKind.API_BEHAVIOR,
            vulnerable_content="GET /owned/canary -> 200",
            fixed_content="GET /owned/canary -> 403 for other tenant",
            evidence_refs=(_evidence("patch.api"),),
        ),
    )
    return PatchRequest(
        patch_delta_id=f"{fixture_case.case_id}.patch",
        invariant_change_id=f"{fixture_case.case_id}.invariant",
        vulnerable_revision="revision-vulnerable",
        fixed_revision="revision-fixed",
        artifacts=artifacts,
        evidence_refs=(_evidence(f"{fixture_case.case_id}.patch"),),
    )


def _variant_candidates(
    fixture_case: PatchVariantFixtureCase,
) -> tuple[VariantCandidate, ...]:
    return (
        VariantCandidate(
            candidate_id=f"{fixture_case.case_id}.sibling",
            dimension=VariantDimension.SIBLING_PATH,
            location="routes/export.py",
            candidate_content="return repository.lookup(resource_id)",
            source_query="repository.lookup($RESOURCE_ID)",
            differential=BehaviorDifferential(
                baseline_control_denied=True,
                candidate_effect_observed=True,
                prerequisites_equal=True,
                evidence_refs=(_evidence("variant.black-box"),),
            ),
            evidence_refs=(_evidence("variant.sibling"),),
        ),
        VariantCandidate(
            candidate_id=f"{fixture_case.case_id}.parser",
            dimension=VariantDimension.ALTERNATE_PARSER,
            location="parsers/legacy.py",
            candidate_content=(
                "alternate parser performs resource lookup before tenant trust boundary"
            ),
            source_query="legacy resource lookup tenant boundary",
            evidence_refs=(_evidence("variant.parser"),),
        ),
        VariantCandidate(
            candidate_id=f"{fixture_case.case_id}.canonical",
            dimension=VariantDimension.CANONICALIZATION,
            location="normalizers/unicode.py",
            candidate_content="unicode normalization needs review",
            evidence_refs=(_evidence("variant.canonical"),),
        ),
    )
