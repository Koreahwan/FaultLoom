"""Public evaluation contract surface."""

from __future__ import annotations

from .base import ProtocolModel
from .evaluation_enums import (
    EVALUATION_ENUM_TYPES,
    AdapterMetricName,
    ArtifactKind,
    ChainDepthBand,
    ContextResetMetricName,
    EvaluationArm,
    EvaluationDomain,
    EvaluationFindingKind,
    EvaluationOutcome,
    EvaluationOutcomeReason,
    ExecutionTiming,
    IdentityCardinality,
    MetricName,
    MetricUnit,
    TenantCardinality,
)
from .evaluation_manifest import (
    ArtifactAttestation,
    EvaluationArmConfig,
    EvaluationBudget,
    EvaluationCaseDescriptor,
    EvaluationManifest,
    EvaluationTaxonomy,
)
from .evaluation_results import (
    EvaluationAggregateReceipt,
    EvaluationArmResult,
    EvaluationCaseResult,
    EvaluationMetric,
    PublicEvaluationProjection,
)

EVALUATION_MODEL_TYPES: tuple[type[ProtocolModel], ...] = (
    EvaluationTaxonomy,
    EvaluationCaseDescriptor,
    EvaluationBudget,
    EvaluationArmConfig,
    EvaluationManifest,
    EvaluationMetric,
    EvaluationCaseResult,
    EvaluationArmResult,
    ArtifactAttestation,
    EvaluationAggregateReceipt,
    PublicEvaluationProjection,
)


def evaluation_schema_catalog() -> dict[str, dict[str, object]]:
    """Return closed JSON Schemas for the public evaluation projection."""

    return {
        model.__name__: model.model_json_schema()
        for model in EVALUATION_MODEL_TYPES
    }


__all__ = [
    "EVALUATION_ENUM_TYPES",
    "EVALUATION_MODEL_TYPES",
    "AdapterMetricName",
    "ArtifactAttestation",
    "ArtifactKind",
    "ChainDepthBand",
    "ContextResetMetricName",
    "EvaluationAggregateReceipt",
    "EvaluationArm",
    "EvaluationArmConfig",
    "EvaluationArmResult",
    "EvaluationBudget",
    "EvaluationCaseDescriptor",
    "EvaluationCaseResult",
    "EvaluationDomain",
    "EvaluationFindingKind",
    "EvaluationManifest",
    "EvaluationMetric",
    "EvaluationOutcome",
    "EvaluationOutcomeReason",
    "EvaluationTaxonomy",
    "ExecutionTiming",
    "IdentityCardinality",
    "MetricName",
    "MetricUnit",
    "PublicEvaluationProjection",
    "TenantCardinality",
    "evaluation_schema_catalog",
]
