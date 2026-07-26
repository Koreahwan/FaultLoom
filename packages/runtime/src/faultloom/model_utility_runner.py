"""Paired model-utility execution over receipted provider outputs."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import ClassVar, Protocol, Self

from pydantic import BaseModel, ConfigDict, model_validator

from faultloom.provider import (
    ProviderCallIntent,
    ProviderCallOutcome,
    provider_sha256_digest,
    provider_tool_schema_digest,
)
from faultloom.provider_output import ProviderInvocationResult
from faultloom_sdk import (
    IndependentVerifierOutcome,
    ModelUtilityArmConfig,
    ModelUtilityCase,
    ModelUtilityCaseOutcome,
    ModelUtilityEvaluation,
    ModelUtilityEvaluationPlan,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    UtilityDecision,
    evaluate_model_utility,
    model_utility_digest,
)


class ModelUtilityRunnerError(ValueError):
    """A utility run failed before canonical evaluation could be emitted."""


class UtilityProviderInvocation(BaseModel):
    """One provider result plus the local identities required by its utility arm."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    intent: ProviderCallIntent
    result: ProviderInvocationResult
    decision: UtilityDecision
    model_snapshot_digest: str
    runtime_artifact_digest: str
    dispatched_oos: int
    escaped_oos: int

    @model_validator(mode="after")
    def _receipt_is_bound_to_intent(self) -> Self:
        if type(self.intent) is not ProviderCallIntent:
            raise ModelUtilityRunnerError("utility invocation requires an exact intent")
        if type(self.result) is not ProviderInvocationResult:
            raise ModelUtilityRunnerError("utility invocation requires an exact result")
        receipt = self.result.receipt
        if (
            receipt.call_id != self.intent.call_id
            or receipt.attempt_id != self.intent.attempt_id
            or receipt.run_id != self.intent.run_id
            or receipt.prompt_digest != self.intent.prompt_digest
            or receipt.tool_schema_digest
            != provider_tool_schema_digest(self.intent.tools)
            or receipt.budget_digest != provider_sha256_digest(self.intent.budget)
            or receipt.config_digest
            != provider_sha256_digest(self.intent.generation_config)
        ):
            raise ModelUtilityRunnerError(
                "utility provider receipt is not bound to its exact intent"
            )
        if self.dispatched_oos < 0 or self.escaped_oos < 0:
            raise ModelUtilityRunnerError("utility safety counters cannot be negative")
        return self


class UtilityInvocationPort(Protocol):
    @property
    def evidence_source(self) -> ModelUtilityEvidenceSource: ...

    def invoke(
        self,
        case: ModelUtilityCase,
        arm: ModelUtilityArmConfig,
    ) -> UtilityProviderInvocation: ...


class UtilityVerifierPort(Protocol):
    @property
    def evidence_source(self) -> ModelUtilityEvidenceSource: ...

    def verify(
        self,
        case: ModelUtilityCase,
        invocation: UtilityProviderInvocation,
    ) -> IndependentVerifierOutcome: ...


class PairedModelUtilityRunner:
    """Run every suite case once through each exact utility arm."""

    _source: ModelUtilityEvidenceSource

    def __init__(
        self,
        invoker: UtilityInvocationPort,
        verifier: UtilityVerifierPort,
    ) -> None:
        self._invoke: Callable[
            [ModelUtilityCase, ModelUtilityArmConfig], UtilityProviderInvocation
        ] = invoker.invoke
        self._verify: Callable[
            [ModelUtilityCase, UtilityProviderInvocation], IndependentVerifierOutcome
        ] = verifier.verify
        self._source = self._evidence_source(
            invoker.evidence_source,
            verifier.evidence_source,
        )

    @staticmethod
    def _evidence_source(
        invoker: ModelUtilityEvidenceSource,
        verifier: ModelUtilityEvidenceSource,
    ) -> ModelUtilityEvidenceSource:
        if type(invoker) is not ModelUtilityEvidenceSource:
            raise ModelUtilityRunnerError("invoker evidence source is invalid")
        if type(verifier) is not ModelUtilityEvidenceSource:
            raise ModelUtilityRunnerError("verifier evidence source is invalid")
        if invoker is not verifier:
            raise ModelUtilityRunnerError("utility evidence sources must match")
        if invoker is ModelUtilityEvidenceSource.REAL_MODEL:
            raise ModelUtilityRunnerError(
                "trusted real-model provenance is unavailable"
            )
        return invoker

    def run(self, plan: ModelUtilityEvaluationPlan) -> ModelUtilityEvaluation:
        """Return one canonical evaluation or fail before emitting partial evidence."""

        if type(plan) is not ModelUtilityEvaluationPlan:
            raise ModelUtilityRunnerError("utility runner requires an exact plan")
        outcomes = tuple(
            self._run_arm(case, arm)
            for case in plan.suite.cases
            for arm in (plan.baseline, plan.treatment)
        )
        evaluation = evaluate_model_utility(plan, outcomes, self._source)
        expected_state = (
            ModelUtilityEvaluationState.FULLY_DONE
            if self._source is ModelUtilityEvidenceSource.REAL_MODEL
            else ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE
        )
        if evaluation.state is not expected_state:
            raise ModelUtilityRunnerError("utility evidence state mismatch")
        return evaluation

    def _run_arm(
        self,
        case: ModelUtilityCase,
        arm: ModelUtilityArmConfig,
    ) -> ModelUtilityCaseOutcome:
        invocation = self._invoke(case, arm)
        if type(invocation) is not UtilityProviderInvocation:
            raise ModelUtilityRunnerError("utility invoker returned an invalid result")
        self._validate_arm(invocation, arm)
        verifier = self._verify(case, invocation)
        if type(verifier) is not IndependentVerifierOutcome:
            raise ModelUtilityRunnerError("utility verifier returned an invalid outcome")
        receipt = invocation.result.receipt
        if receipt.reported_input_tokens is None or receipt.reported_output_tokens is None:
            raise ModelUtilityRunnerError("utility receipt is missing reported token usage")
        return ModelUtilityCaseOutcome(
            case_id=case.case_id,
            case_digest=case.case_digest,
            arm=arm.arm,
            arm_config_digest=model_utility_digest(arm),
            decision=invocation.decision,
            verifier=verifier,
            provider_receipt_digest=receipt.receipt_digest,
            response_artifact_digest=invocation.result.output_ref.observation.cas_digest,
            model_tokens=receipt.reported_input_tokens + receipt.reported_output_tokens,
            dispatched_oos=invocation.dispatched_oos,
            escaped_oos=invocation.escaped_oos,
        )

    @staticmethod
    def _validate_arm(
        invocation: UtilityProviderInvocation,
        arm: ModelUtilityArmConfig,
    ) -> None:
        receipt = invocation.result.receipt
        intent = invocation.intent
        if receipt.outcome is not ProviderCallOutcome.COMPLETED:
            raise ModelUtilityRunnerError("utility provider call did not complete")
        checks = (
            (receipt.requested_snapshot, arm.model_snapshot, "model snapshot"),
            (receipt.runtime_version, arm.runtime_version, "runtime version"),
            (
                invocation.model_snapshot_digest,
                arm.model_snapshot_digest,
                "model snapshot digest",
            ),
            (
                invocation.runtime_artifact_digest,
                arm.runtime_artifact_digest,
                "runtime artifact digest",
            ),
            (receipt.prompt_digest, arm.prompt_digest, "prompt digest"),
            (receipt.tool_schema_digest, arm.tool_schema_digest, "tool schema digest"),
            (receipt.budget_digest, arm.budget_digest, "budget digest"),
            (
                receipt.config_digest,
                arm.generation_config_digest,
                "generation config digest",
            ),
            (intent.generation_config.seed, arm.seed, "generation seed"),
        )
        for actual, expected, label in checks:
            if type(actual) is not type(expected) or not hmac.compare_digest(
                str(actual), str(expected)
            ):
                raise ModelUtilityRunnerError(f"utility {label} mismatch")
