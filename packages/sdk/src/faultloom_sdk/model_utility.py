"""Canonical paired model-utility evaluation contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from faultloom_protocol import sha256_digest
from faultloom_protocol.base import Identifier, MAX_INT64, Sha256Digest, ShortStr
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._model_utility_reduction import (
    MetricObservation,
    MetricReductionError,
    derive_metric_values,
)

NonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=MAX_INT64)]
BasisPoints = Annotated[int, Field(strict=True, ge=-10_000, le=10_000)]
NonNegativeBasisPoints = Annotated[int, Field(strict=True, ge=0, le=10_000)]


class ModelUtilityError(ValueError):
    """A paired evaluation is incomplete or internally inconsistent."""


class ModelUtilityArm(StrEnum):
    BASELINE = "baseline"
    TREATMENT = "treatment"


class UtilityDecision(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"


class IndependentVerifierVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    INCONCLUSIVE = "inconclusive"


class ModelUtilityEvidenceSource(StrEnum):
    REAL_MODEL = "real_model"
    DETERMINISTIC_PROTOCOL_STUB = "deterministic_protocol_stub"


class ModelUtilityEvaluationState(StrEnum):
    FULLY_DONE = "fully_done"
    NON_ACCEPTANCE_FIXTURE = "non_acceptance_fixture"


_VERDICTS_BY_DECISION: dict[
    UtilityDecision, frozenset[IndependentVerifierVerdict]
] = {
    UtilityDecision.POSITIVE: frozenset(
        {
            IndependentVerifierVerdict.TRUE_POSITIVE,
            IndependentVerifierVerdict.FALSE_POSITIVE,
        }
    ),
    UtilityDecision.NEGATIVE: frozenset(
        {
            IndependentVerifierVerdict.TRUE_NEGATIVE,
            IndependentVerifierVerdict.FALSE_NEGATIVE,
        }
    ),
    UtilityDecision.INCONCLUSIVE: frozenset(
        {IndependentVerifierVerdict.INCONCLUSIVE}
    ),
}


class _UtilityModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


def model_utility_digest(value: _UtilityModel) -> str:
    """Hash one SDK utility model through the protocol canonical JSON boundary."""

    return sha256_digest(value.model_dump(mode="json"))


class ModelUtilityCase(_UtilityModel):
    case_id: Identifier
    case_digest: Sha256Digest


class ModelUtilitySuite(_UtilityModel):
    suite_id: Identifier
    suite_digest: Sha256Digest
    cases: tuple[ModelUtilityCase, ...]

    @model_validator(mode="after")
    def _case_set_is_exact(self) -> Self:
        if not self.cases:
            raise ModelUtilityError("model utility suite requires cases")
        identities = tuple((case.case_id, case.case_digest) for case in self.cases)
        if len(identities) != len(set(identities)):
            raise ModelUtilityError("model utility suite cases must be unique")
        return self


class ModelUtilityArmConfig(_UtilityModel):
    arm: ModelUtilityArm
    model_snapshot: ShortStr
    model_snapshot_digest: Sha256Digest
    runtime_version: ShortStr
    runtime_artifact_digest: Sha256Digest
    prompt_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    budget_digest: Sha256Digest
    generation_config_digest: Sha256Digest
    seed: NonNegativeInt


class IndependentVerifierOutcome(_UtilityModel):
    verifier_id: Identifier
    independent: Literal[True] = True
    verdict: IndependentVerifierVerdict
    evidence_digest: Sha256Digest


class ModelUtilityCaseOutcome(_UtilityModel):
    case_id: Identifier
    case_digest: Sha256Digest
    arm: ModelUtilityArm
    arm_config_digest: Sha256Digest
    decision: UtilityDecision
    verifier: IndependentVerifierOutcome
    provider_receipt_digest: Sha256Digest
    response_artifact_digest: Sha256Digest
    model_tokens: NonNegativeInt
    dispatched_oos: NonNegativeInt
    escaped_oos: NonNegativeInt

    @model_validator(mode="after")
    def _decision_was_independently_classified(self) -> Self:
        if self.verifier.verdict not in _VERDICTS_BY_DECISION[self.decision]:
            raise ModelUtilityError("utility decision contradicts its verifier outcome")
        return self


class ModelUtilityMetrics(_UtilityModel):
    recall_gain_bps: BasisPoints
    unique_verified_positives: NonNegativeInt
    efficiency_gain_bps: NonNegativeBasisPoints
    recall_loss_bps: NonNegativeBasisPoints
    dispatched_oos: NonNegativeInt
    escaped_oos: NonNegativeInt
    tool_only_false_verified: NonNegativeInt


def derive_model_utility_metrics(
    outcomes: tuple[ModelUtilityCaseOutcome, ...],
) -> ModelUtilityMetrics:
    observations = tuple(
        MetricObservation(
            case_id=outcome.case_id,
            arm=outcome.arm.value,
            verdict=outcome.verifier.verdict.value,
            model_tokens=outcome.model_tokens,
            dispatched_oos=outcome.dispatched_oos,
            escaped_oos=outcome.escaped_oos,
        )
        for outcome in outcomes
    )
    try:
        values = derive_metric_values(observations)
    except MetricReductionError as exc:
        raise ModelUtilityError(str(exc)) from exc
    return ModelUtilityMetrics(
        recall_gain_bps=values.recall_gain_bps,
        unique_verified_positives=values.unique_verified_positives,
        efficiency_gain_bps=values.efficiency_gain_bps,
        recall_loss_bps=values.recall_loss_bps,
        dispatched_oos=values.dispatched_oos,
        escaped_oos=values.escaped_oos,
        tool_only_false_verified=values.tool_only_false_verified,
    )


class ModelUtilityEvaluationPlan(_UtilityModel):
    adapter_id: Identifier
    manifest_digest: Sha256Digest
    suite: ModelUtilitySuite
    baseline: ModelUtilityArmConfig
    treatment: ModelUtilityArmConfig
    evaluator_artifact_digest: Sha256Digest

    @model_validator(mode="after")
    def _comparison_is_paired(self) -> Self:
        if (
            self.baseline.arm is not ModelUtilityArm.BASELINE
            or self.treatment.arm is not ModelUtilityArm.TREATMENT
        ):
            raise ModelUtilityError("utility plan requires baseline and treatment arms")
        baseline = self.baseline
        treatment = self.treatment
        if (
            baseline.model_snapshot != treatment.model_snapshot
            or baseline.model_snapshot_digest != treatment.model_snapshot_digest
            or baseline.runtime_version != treatment.runtime_version
            or baseline.runtime_artifact_digest != treatment.runtime_artifact_digest
            or baseline.budget_digest != treatment.budget_digest
            or baseline.generation_config_digest != treatment.generation_config_digest
            or baseline.seed != treatment.seed
        ):
            raise ModelUtilityError(
                "paired utility arms require identical model, runtime, budget, and seed"
            )
        return self


class ModelUtilityEvaluation(_UtilityModel):
    plan: ModelUtilityEvaluationPlan
    case_outcomes: tuple[ModelUtilityCaseOutcome, ...]
    evidence_source: ModelUtilityEvidenceSource
    state: ModelUtilityEvaluationState
    metrics: ModelUtilityMetrics

    @model_validator(mode="after")
    def _canonical_evaluation_is_bound(self) -> Self:
        expected = {
            (case.case_id, case.case_digest, arm)
            for case in self.plan.suite.cases
            for arm in ModelUtilityArm
        }
        actual = {
            (outcome.case_id, outcome.case_digest, outcome.arm)
            for outcome in self.case_outcomes
        }
        if len(actual) != len(self.case_outcomes) or actual != expected:
            raise ModelUtilityError("utility evaluation case pairs differ from the suite")
        arm_digests = {
            ModelUtilityArm.BASELINE: model_utility_digest(self.plan.baseline),
            ModelUtilityArm.TREATMENT: model_utility_digest(self.plan.treatment),
        }
        if any(
            outcome.arm_config_digest != arm_digests[outcome.arm]
            for outcome in self.case_outcomes
        ):
            raise ModelUtilityError("utility outcome arm config digest mismatch")
        if self.metrics != derive_model_utility_metrics(self.case_outcomes):
            raise ModelUtilityError("utility metrics must be derived from case outcomes")
        expected_state = (
            ModelUtilityEvaluationState.FULLY_DONE
            if self.evidence_source is ModelUtilityEvidenceSource.REAL_MODEL
            else ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE
        )
        if self.state is not expected_state:
            raise ModelUtilityError("protocol stub evidence is non-acceptance only")
        return self
