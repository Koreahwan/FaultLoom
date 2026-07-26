"""Metric reduction and canonical digests for model-utility evidence."""

from __future__ import annotations

from .model_utility import (
    ModelUtilityCaseOutcome,
    ModelUtilityEvaluation,
    ModelUtilityEvaluationPlan,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    derive_model_utility_metrics,
)


def evaluate_model_utility(
    plan: ModelUtilityEvaluationPlan,
    outcomes: tuple[ModelUtilityCaseOutcome, ...],
    evidence_source: ModelUtilityEvidenceSource,
) -> ModelUtilityEvaluation:
    state = (
        ModelUtilityEvaluationState.FULLY_DONE
        if evidence_source is ModelUtilityEvidenceSource.REAL_MODEL
        else ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE
    )
    return ModelUtilityEvaluation(
        plan=plan,
        case_outcomes=outcomes,
        evidence_source=evidence_source,
        state=state,
        metrics=derive_model_utility_metrics(outcomes),
    )


def model_utility_is_proven(evaluation: ModelUtilityEvaluation) -> bool:
    _ = evaluation
    return False
