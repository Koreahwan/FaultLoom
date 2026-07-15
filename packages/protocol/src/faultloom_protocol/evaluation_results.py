"""Public evaluation results, aggregate receipts, and digest-bound projection."""

from __future__ import annotations

from typing import Annotated, assert_never

from pydantic import Field, model_validator

from .base import AwareDatetime, Identifier, MAX_INT64, ProtocolModel, Sha256Digest
from .canonical import sha256_digest
from .evaluation_enums import (
    EvaluationArm,
    EvaluationOutcome,
    EvaluationOutcomeReason,
    MetricName,
    MetricUnit,
)
from .evaluation_manifest import ArtifactAttestation, EvaluationManifest

PositiveInt = Annotated[int, Field(ge=1, le=MAX_INT64)]
NonNegativeInt = Annotated[int, Field(ge=0, le=MAX_INT64)]
SignedInt = Annotated[int, Field(ge=-MAX_INT64, le=MAX_INT64)]


class EvaluationMetric(ProtocolModel):
    name: MetricName
    unit: MetricUnit
    point: SignedInt
    lower_bound: SignedInt
    upper_bound: SignedInt
    sample_count: PositiveInt

    @model_validator(mode="after")
    def _closed_interval(self) -> "EvaluationMetric":
        if not self.lower_bound <= self.point <= self.upper_bound:
            raise ValueError("metric point must fall within its confidence interval")
        match self.unit:
            case MetricUnit.BASIS_POINTS:
                pass
            case (
                MetricUnit.COUNT
                | MetricUnit.SECONDS
                | MetricUnit.TOKENS
                | MetricUnit.MICROUNITS
                | MetricUnit.DEPTH
            ):
                if self.lower_bound < 0:
                    raise ValueError("non-rate metrics cannot contain negative values")
            case unreachable:
                assert_never(unreachable)
        return self


class EvaluationCaseResult(ProtocolModel):
    result_id: Identifier
    run_id: Identifier
    arm: EvaluationArm
    manifest_digest: Sha256Digest
    case_descriptor_digest: Sha256Digest
    outcome: EvaluationOutcome
    reason: EvaluationOutcomeReason
    run_started: bool
    included_in_denominator: bool
    safety_violation: bool
    final_effect_verified: bool
    independent_replay: bool
    longest_verified_prefix: NonNegativeInt
    metrics: tuple[EvaluationMetric, ...] = ()
    run_result_bundle_digest: Sha256Digest | None = None
    evidence_digests: tuple[Sha256Digest, ...] = ()

    @model_validator(mode="after")
    def _classification_contract(self) -> "EvaluationCaseResult":
        match self.outcome:
            case EvaluationOutcome.SUCCESS:
                valid = (
                    self.reason is EvaluationOutcomeReason.VERIFIED_SUCCESS
                    and self.run_started
                    and self.included_in_denominator
                    and not self.safety_violation
                    and (self.final_effect_verified or self.independent_replay)
                    and self.run_result_bundle_digest is not None
                    and bool(self.evidence_digests)
                )
            case EvaluationOutcome.INCONCLUSIVE:
                valid = (
                    self.reason is EvaluationOutcomeReason.PRE_RUN_INFRASTRUCTURE
                    and not self.run_started
                    and not self.included_in_denominator
                    and not self.safety_violation
                    and not self.final_effect_verified
                    and not self.independent_replay
                    and self.run_result_bundle_digest is None
                )
            case EvaluationOutcome.FAIL:
                match self.reason:
                    case (
                        EvaluationOutcomeReason.POST_RUN_TIMEOUT
                        | EvaluationOutcomeReason.POST_RUN_BUDGET
                        | EvaluationOutcomeReason.POST_RUN_RUNTIME
                        | EvaluationOutcomeReason.FINAL_EFFECT_UNVERIFIED
                    ):
                        reason_valid = not self.safety_violation
                    case EvaluationOutcomeReason.SAFETY_VIOLATION:
                        reason_valid = self.safety_violation
                    case (
                        EvaluationOutcomeReason.VERIFIED_SUCCESS
                        | EvaluationOutcomeReason.PRE_RUN_INFRASTRUCTURE
                    ):
                        reason_valid = False
                    case unreachable:
                        assert_never(unreachable)
                valid = (
                    reason_valid
                    and self.run_started
                    and self.included_in_denominator
                    and bool(self.evidence_digests)
                )
            case unreachable:
                assert_never(unreachable)
        if not valid:
            raise ValueError("evaluation result classification is inconsistent")
        if len(self.evidence_digests) != len(set(self.evidence_digests)):
            raise ValueError("evaluation result evidence digests must be unique")
        if len({metric.name for metric in self.metrics}) != len(self.metrics):
            raise ValueError("evaluation result metric names must be unique")
        return self


class EvaluationArmResult(ProtocolModel):
    arm: EvaluationArm
    case_result_digests: tuple[Sha256Digest, ...]
    denominator_count: NonNegativeInt
    success_count: NonNegativeInt
    failure_count: NonNegativeInt
    inconclusive_count: NonNegativeInt
    safety_violation_count: NonNegativeInt
    metrics: tuple[EvaluationMetric, ...] = ()

    @model_validator(mode="after")
    def _counts_match_cases(self) -> "EvaluationArmResult":
        if len(self.case_result_digests) != len(set(self.case_result_digests)):
            raise ValueError("arm result digests must be unique")
        if self.denominator_count != self.success_count + self.failure_count:
            raise ValueError("arm denominator must include every success and failure")
        total = self.denominator_count + self.inconclusive_count
        if total != len(self.case_result_digests):
            raise ValueError("arm counts must match the bound case results")
        if self.safety_violation_count > self.failure_count:
            raise ValueError("safety violations must be counted as failures")
        if len({metric.name for metric in self.metrics}) != len(self.metrics):
            raise ValueError("arm metric names must be unique")
        return self


class EvaluationAggregateReceipt(ProtocolModel):
    receipt_id: Identifier
    receipt_version: PositiveInt
    manifest_digest: Sha256Digest
    arm_results: tuple[EvaluationArmResult, ...]
    case_result_digests: tuple[Sha256Digest, ...]
    artifact_attestation_digests: tuple[Sha256Digest, ...]
    evaluator_artifact_digest: Sha256Digest
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def _aggregate_is_complete(self) -> "EvaluationAggregateReceipt":
        expected_arms = set(EvaluationArm)
        actual_arms = {result.arm for result in self.arm_results}
        if len(self.arm_results) != len(expected_arms) or actual_arms != expected_arms:
            raise ValueError("aggregate requires exactly the three evaluation arms")
        flattened = tuple(
            digest
            for arm_result in self.arm_results
            for digest in arm_result.case_result_digests
        )
        if len(flattened) != len(set(flattened)):
            raise ValueError("a case result cannot belong to multiple arms")
        if set(flattened) != set(self.case_result_digests):
            raise ValueError("aggregate case digests differ from arm result digests")
        case_counts = {len(result.case_result_digests) for result in self.arm_results}
        if len(case_counts) != 1 or not self.case_result_digests:
            raise ValueError("three-arm aggregate requires equal non-empty case counts")
        if len(self.artifact_attestation_digests) != len(
            set(self.artifact_attestation_digests)
        ):
            raise ValueError("artifact attestation digests must be unique")
        return self


class PublicEvaluationProjection(ProtocolModel):
    """The only exportable evaluation envelope; private Eval state has no field."""

    manifest: EvaluationManifest
    case_results: tuple[EvaluationCaseResult, ...]
    artifact_attestations: tuple[ArtifactAttestation, ...]
    aggregate_receipt: EvaluationAggregateReceipt

    @model_validator(mode="after")
    def _all_public_digests_are_bound(self) -> "PublicEvaluationProjection":
        manifest_digest = sha256_digest(self.manifest)
        if self.aggregate_receipt.manifest_digest != manifest_digest:
            raise ValueError("aggregate manifest digest does not match the manifest")
        if any(result.manifest_digest != manifest_digest for result in self.case_results):
            raise ValueError("case result manifest digest does not match the manifest")

        descriptor_digests = {
            sha256_digest(descriptor) for descriptor in self.manifest.cases
        }
        expected_pairs = {
            (descriptor_digest, arm)
            for descriptor_digest in descriptor_digests
            for arm in EvaluationArm
        }
        actual_pairs = {
            (result.case_descriptor_digest, result.arm) for result in self.case_results
        }
        if len(actual_pairs) != len(self.case_results) or actual_pairs != expected_pairs:
            raise ValueError("public results must cover every case in all three arms")

        result_digests = {sha256_digest(result) for result in self.case_results}
        if result_digests != set(self.aggregate_receipt.case_result_digests):
            raise ValueError("aggregate case result digests do not match public results")
        digest_arm_pairs = {
            (sha256_digest(result), result.arm) for result in self.case_results
        }
        receipt_arm_pairs = {
            (digest, arm_result.arm)
            for arm_result in self.aggregate_receipt.arm_results
            for digest in arm_result.case_result_digests
        }
        if digest_arm_pairs != receipt_arm_pairs:
            raise ValueError("aggregate arm assignment does not match public results")

        attestation_digests = {
            sha256_digest(attestation) for attestation in self.artifact_attestations
        }
        if len(attestation_digests) != len(self.artifact_attestations):
            raise ValueError("public artifact attestations must be unique")
        if attestation_digests != set(
            self.aggregate_receipt.artifact_attestation_digests
        ):
            raise ValueError("aggregate attestation digests do not match public artifacts")
        if self.aggregate_receipt.evaluator_artifact_digest not in {
            attestation.artifact_digest for attestation in self.artifact_attestations
        }:
            raise ValueError("evaluator artifact digest lacks a public attestation")
        return self
