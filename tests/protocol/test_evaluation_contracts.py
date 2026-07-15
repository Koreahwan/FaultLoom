from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import (
    AdapterMetricName,
    ContextResetMetricName,
    EvaluationCaseResult,
    EvaluationManifest,
    EvaluationOutcome,
    EvaluationOutcomeReason,
    MetricName,
    PublicEvaluationProjection,
    canonical_json_bytes,
    evaluation_schema_catalog,
    sha256_digest,
)

from .evaluation_support import (
    DIGESTS,
    evaluation_manifest,
    public_projection,
    schema_property_names,
)


def test_public_evaluation_projection_round_trips_with_stable_digest() -> None:
    given = public_projection()

    restored = PublicEvaluationProjection.model_validate_json(given.model_dump_json())

    assert restored == given
    assert canonical_json_bytes(restored) == canonical_json_bytes(given)
    assert sha256_digest(restored) == sha256_digest(given)


def test_public_evaluation_schemas_exclude_private_eval_material() -> None:
    forbidden = {
        "oracle_answer",
        "seed",
        "evaluation_key",
        "private_scoring_logic",
        "fixture_content",
    }

    schemas = evaluation_schema_catalog()

    assert "PublicEvaluationProjection" in schemas
    assert forbidden.isdisjoint(
        {name.casefold() for schema in schemas.values() for name in schema_property_names(schema)}
    )


def test_public_projection_rejects_private_fields_at_every_boundary() -> None:
    document = public_projection().model_dump(mode="json")
    document["evaluation_key"] = "private"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PublicEvaluationProjection.model_validate(document)


def test_manifest_requires_all_three_comparable_arms() -> None:
    document = evaluation_manifest().model_dump(mode="python")
    document["arms"] = document["arms"][:2]

    with pytest.raises(ValidationError, match="exactly the three evaluation arms"):
        EvaluationManifest.model_validate(document)


@pytest.mark.parametrize(
    ("outcome", "reason", "started", "denominator", "safety"),
    [
        (
            EvaluationOutcome.INCONCLUSIVE,
            EvaluationOutcomeReason.POST_RUN_RUNTIME,
            False,
            False,
            False,
        ),
        (
            EvaluationOutcome.FAIL,
            EvaluationOutcomeReason.POST_RUN_TIMEOUT,
            True,
            False,
            False,
        ),
        (
            EvaluationOutcome.FAIL,
            EvaluationOutcomeReason.SAFETY_VIOLATION,
            True,
            True,
            False,
        ),
    ],
)
def test_case_result_rejects_invalid_classification(
    outcome: EvaluationOutcome,
    reason: EvaluationOutcomeReason,
    started: bool,
    denominator: bool,
    safety: bool,
) -> None:
    result = public_projection().case_results[0].model_dump(mode="python")
    result.update(
        outcome=outcome,
        reason=reason,
        run_started=started,
        included_in_denominator=denominator,
        safety_violation=safety,
        final_effect_verified=False,
    )

    with pytest.raises(ValidationError, match="classification"):
        EvaluationCaseResult.model_validate(result)


def test_safety_failure_stays_in_denominator_and_keeps_prefix_diagnostic() -> None:
    document = public_projection().case_results[0].model_dump(mode="python")
    document.update(
        outcome=EvaluationOutcome.FAIL,
        reason=EvaluationOutcomeReason.SAFETY_VIOLATION,
        included_in_denominator=True,
        safety_violation=True,
        final_effect_verified=False,
        longest_verified_prefix=2,
    )

    result = EvaluationCaseResult.model_validate(document)

    assert result.included_in_denominator is True
    assert result.longest_verified_prefix == 2


def test_projection_rejects_digest_substitution() -> None:
    projection = public_projection()
    document = projection.model_dump(mode="python")
    document["aggregate_receipt"] = projection.aggregate_receipt.model_copy(
        update={"manifest_digest": DIGESTS[13]}
    )

    with pytest.raises(ValidationError, match="manifest digest"):
        PublicEvaluationProjection.model_validate(document)


def test_metric_taxonomy_covers_reset_and_adapter_admission_gates() -> None:
    assert {
        ContextResetMetricName.INITIAL_CLUE_RECALL_BPS.value,
        ContextResetMetricName.SUCCESS_AFTER_TEN_RESETS_BPS.value,
        ContextResetMetricName.CROSS_ENGAGEMENT_RETRIEVAL_COUNT.value,
    }.issubset({metric.value for metric in MetricName})
    assert {
        AdapterMetricName.VERIFIED_RECALL_DELTA_BPS.value,
        AdapterMetricName.UNIQUE_VERIFIED_POSITIVES.value,
        AdapterMetricName.TOOL_ONLY_FALSE_VERIFIED_COUNT.value,
    }.issubset({metric.value for metric in MetricName})
