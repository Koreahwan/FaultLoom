from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_sdk import (
    ModelUtilityEvaluation,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    model_utility_digest,
)

from .model_utility_support import digest, valid_utility_evaluation


def test_evaluator_derives_metrics_only_from_paired_case_outcomes() -> None:
    # Given / When: a complete paired evaluation is reduced canonically.
    evaluation = valid_utility_evaluation()

    # Then: the treatment gains come from the two bound case pairs.
    assert evaluation.metrics.recall_gain_bps == 10_000
    assert evaluation.metrics.unique_verified_positives == 2
    assert evaluation.metrics.efficiency_gain_bps == 2_000
    assert evaluation.metrics.recall_loss_bps == 0
    assert evaluation.metrics.dispatched_oos == 0
    assert evaluation.metrics.escaped_oos == 0
    assert evaluation.metrics.tool_only_false_verified == 0
    assert evaluation.state is ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE
    assert model_utility_digest(evaluation).startswith("sha256:")


def test_evaluation_rejects_fabricated_metrics_and_case_digest_substitution() -> None:
    # Given: one valid canonical evaluation document.
    evaluation = valid_utility_evaluation()
    fabricated = evaluation.model_dump(mode="python")
    fabricated["metrics"] = evaluation.metrics.model_copy(
        update={"unique_verified_positives": 99}
    )

    # When / Then: caller-declared aggregate metrics are not accepted.
    with pytest.raises(ValidationError, match="derived from case outcomes"):
        _ = ModelUtilityEvaluation.model_validate(fabricated)

    substituted = evaluation.model_dump(mode="python")
    first = evaluation.case_outcomes[0].model_copy(
        update={"case_digest": digest("substituted-case")}
    )
    substituted["case_outcomes"] = (first, *evaluation.case_outcomes[1:])
    with pytest.raises(ValidationError, match="case pairs"):
        _ = ModelUtilityEvaluation.model_validate(substituted)


def test_protocol_stub_evaluation_is_permanently_non_acceptance() -> None:
    # Given / When: deterministic protocol plumbing produces paired outcomes.
    evaluation = valid_utility_evaluation(
        ModelUtilityEvidenceSource.DETERMINISTIC_PROTOCOL_STUB
    )

    # Then: it cannot represent fully-done evidence.
    assert evaluation.state is ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE
    forged = evaluation.model_dump(mode="python")
    forged["state"] = ModelUtilityEvaluationState.FULLY_DONE
    with pytest.raises(ValidationError, match="non-acceptance"):
        _ = ModelUtilityEvaluation.model_validate(forged)
