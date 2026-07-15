from __future__ import annotations

import hashlib
import re

from faultloom_protocol import ConfidenceClass, InvariantChange, VariantHypothesis

from .inputs import VariantCandidate, VariantDimension
from .results import PatchAnalysis, VariantAssessment, VariantSearchResult


def search_variants(
    patch: PatchAnalysis,
    candidates: tuple[VariantCandidate, ...],
) -> VariantSearchResult:
    invariant = patch.invariant_changes[0]
    removed_lines = tuple(
        line
        for delta in patch.artifact_deltas
        for line in delta.removed_lines
        if line
    )
    assessments = tuple(
        _assess_candidate(candidate, invariant, removed_lines)
        for candidate in candidates
    )
    return VariantSearchResult(
        search_dimensions=tuple(VariantDimension),
        assessments=assessments,
    )


def _assess_candidate(
    candidate: VariantCandidate,
    invariant: InvariantChange,
    removed_lines: tuple[str, ...],
) -> VariantAssessment:
    candidate_normalized = _normalize(candidate.candidate_content)
    exact_static = any(
        _normalize(line) in candidate_normalized
        for line in removed_lines
        if len(_normalize(line)) >= 12
    )
    differential = candidate.differential
    exact_behavior = (
        differential is not None
        and differential.baseline_control_denied
        and differential.candidate_effect_observed
        and differential.prerequisites_equal
    )
    semantic_tokens = _tokens(
        " ".join(
            (
                invariant.invariant,
                invariant.changed_condition,
                invariant.sink_or_boundary,
            )
        )
    )
    overlap = semantic_tokens.intersection(_tokens(candidate.candidate_content))
    if exact_static or exact_behavior:
        confidence = ConfidenceClass.EXACT
    elif len(overlap) >= 3:
        confidence = ConfidenceClass.SIMILAR
    else:
        confidence = ConfidenceClass.SPECULATIVE
    evidence_refs = tuple(
        {
            reference.evidence_id: reference
            for reference in (
                *invariant.evidence_refs,
                *candidate.evidence_refs,
                *(differential.evidence_refs if differential is not None else ()),
            )
        }.values()
    )
    query_digest = (
        _text_digest(candidate.source_query) if candidate.source_query is not None else None
    )
    hypothesis = VariantHypothesis(
        schema_version="0.1.0",
        variant_hypothesis_id=f"variant.{candidate.candidate_id}",
        invariant_change_id=invariant.invariant_change_id,
        variant_kind=candidate.dimension.value,
        statement=(
            f"{candidate.dimension.value} candidate at {candidate.location} may retain "
            "the changed invariant"
        ),
        confidence_class=confidence,
        source_query_digest=query_digest,
        evidence_refs=evidence_refs,
    )
    return VariantAssessment(
        candidate_id=candidate.candidate_id,
        confidence=confidence,
        black_box_differential=differential is not None,
        hypothesis=hypothesis,
    )


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())


def _tokens(value: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z0-9_]+", value.casefold()))


def _text_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
