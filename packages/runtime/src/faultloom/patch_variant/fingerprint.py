from __future__ import annotations

from collections import defaultdict

from faultloom_protocol import ComponentFingerprint, EvidenceRef, VersionHypothesis

from .inputs import FingerprintRequest
from .results import FingerprintAnalysis


def analyze_fingerprint(request: FingerprintRequest) -> FingerprintAnalysis:
    """Combine independent component signals into deterministic version hypotheses."""

    weights: defaultdict[str, int] = defaultdict(int)
    evidence_by_version: defaultdict[str, list[EvidenceRef]] = defaultdict(list)
    backport_by_version: defaultdict[str, bool] = defaultdict(bool)
    version_order: list[str] = []
    for signal in request.signals:
        if signal.version_range not in weights:
            version_order.append(signal.version_range)
        weights[signal.version_range] += signal.weight_bps
        evidence_by_version[signal.version_range].append(signal.evidence_ref)
        backport_by_version[signal.version_range] = (
            backport_by_version[signal.version_range] or signal.backport_indicator
        )
    total_weight = sum(weights.values())
    hypotheses = tuple(
        VersionHypothesis(
            schema_version="0.1.0",
            version_hypothesis_id=f"{request.fingerprint_id}.version.{index}",
            fingerprint_id=request.fingerprint_id,
            version_range=version_range,
            confidence_bps=(weights[version_range] * 10_000) // total_weight,
            backport_possible=backport_by_version[version_range],
            evidence_refs=tuple(evidence_by_version[version_range]),
        )
        for index, version_range in enumerate(version_order, start=1)
    )
    kinds = tuple(dict.fromkeys(signal.kind.value for signal in request.signals))
    evidence_refs = tuple(
        {
            signal.evidence_ref.evidence_id: signal.evidence_ref
            for signal in request.signals
        }.values()
    )
    fingerprint = ComponentFingerprint(
        schema_version="0.1.0",
        fingerprint_id=request.fingerprint_id,
        target_id=request.target_id,
        component_name=request.component_name,
        evidence_kinds=kinds,
        evidence_refs=evidence_refs,
        observed_at=request.observed_at,
    )
    return FingerprintAnalysis(
        fingerprint=fingerprint,
        version_hypotheses=hypotheses,
    )
