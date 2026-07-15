from __future__ import annotations

from typing import assert_never

from faultloom_protocol import AdvisoryMatch, ReachabilityClaim, VersionHypothesis

from .errors import PatchVariantError
from .inputs import (
    AdvisoryRecord,
    AdvisoryProvenance,
    AdvisorySourceKind,
    PatchState,
    ReachabilityRequest,
)
from .results import AdvisoryResolution, ReachabilityAssessment


def resolve_advisories(
    records: tuple[AdvisoryRecord, ...],
    hypotheses: tuple[VersionHypothesis, ...],
) -> tuple[AdvisoryResolution, ...]:
    """Resolve supplied offline records without treating a match as vulnerability proof."""

    resolutions: list[AdvisoryResolution] = []
    for record in records:
        for index, hypothesis in enumerate(hypotheses, start=1):
            if hypothesis.version_range not in record.affected_version_ranges:
                continue
            primary = _primary_provenance(record)
            vendor_digest = next(
                (
                    item.artifact_digest
                    for item in record.provenance
                    if item.source_kind is AdvisorySourceKind.VENDOR
                ),
                None,
            )
            security_commit = next(
                (
                    item.security_commit
                    for item in record.provenance
                    if item.source_kind is AdvisorySourceKind.SECURITY_COMMIT
                ),
                None,
            )
            resolutions.append(
                AdvisoryResolution(
                    match=AdvisoryMatch(
                        schema_version="0.1.0",
                        advisory_match_id=f"{record.match_id_prefix}.{index}",
                        version_hypothesis_id=hypothesis.version_hypothesis_id,
                        advisory_id=record.advisory_id,
                        advisory_url_digest=primary.artifact_digest,
                        vendor_advisory_digest=vendor_digest,
                        security_commit=security_commit,
                        match_confidence_bps=min(
                            hypothesis.confidence_bps,
                            len(record.provenance) * 2_000,
                        ),
                    ),
                    provenance=record.provenance,
                )
            )
    return tuple(resolutions)


def select_advisory(
    resolutions: tuple[AdvisoryResolution, ...],
    advisory_id: str,
) -> AdvisoryResolution:
    matches = tuple(
        resolution
        for resolution in resolutions
        if resolution.match.advisory_id == advisory_id
    )
    if not matches:
        raise PatchVariantError("selected advisory does not overlap a version hypothesis")
    return sorted(
        matches,
        key=lambda item: (
            -item.match.match_confidence_bps,
            item.match.version_hypothesis_id,
        ),
    )[0]


def assess_reachability(
    match: AdvisoryMatch,
    request: ReachabilityRequest,
) -> ReachabilityAssessment:
    prerequisites = (
        request.auth_prerequisite_satisfied,
        request.config_prerequisite_satisfied,
        request.feature_prerequisite_satisfied,
    )
    prerequisite_failed = any(value is False for value in prerequisites)
    prerequisite_unknown = any(value is None for value in prerequisites)
    match request.patch_state:
        case PatchState.ABSENT:
            patch_present: bool | None = False
        case PatchState.PRESENT | PatchState.BACKPORTED:
            patch_present = True
        case PatchState.UNKNOWN:
            patch_present = None
        case unreachable:
            assert_never(unreachable)
    if (
        not request.component_present
        or not request.vulnerable_path_exposed
        or prerequisite_failed
        or patch_present is True
    ):
        conclusion = "not_reachable"
    elif prerequisite_unknown or patch_present is None:
        conclusion = "ambiguous"
    else:
        conclusion = "reachable"
    claim = ReachabilityClaim(
        schema_version="0.1.0",
        reachability_claim_id=request.reachability_claim_id,
        advisory_match_id=match.advisory_match_id,
        component_present=request.component_present,
        vulnerable_path_exposed=request.vulnerable_path_exposed,
        prerequisites_satisfied=all(value is True for value in prerequisites),
        patch_or_backport_present=patch_present,
        evidence_refs=request.evidence_refs,
        conclusion=conclusion,
    )
    return ReachabilityAssessment(
        claim=claim,
        component_present=request.component_present,
        vulnerable_path_exposed=request.vulnerable_path_exposed,
        auth_prerequisite_satisfied=request.auth_prerequisite_satisfied,
        config_prerequisite_satisfied=request.config_prerequisite_satisfied,
        feature_prerequisite_satisfied=request.feature_prerequisite_satisfied,
        patch_state=request.patch_state,
    )


def _primary_provenance(record: AdvisoryRecord) -> AdvisoryProvenance:
    rank = {
        AdvisorySourceKind.OSV: 0,
        AdvisorySourceKind.NVD: 1,
        AdvisorySourceKind.VENDOR: 2,
        AdvisorySourceKind.RELEASE_NOTE: 3,
        AdvisorySourceKind.SECURITY_COMMIT: 4,
    }
    return sorted(record.provenance, key=lambda item: rank[item.source_kind])[0]
