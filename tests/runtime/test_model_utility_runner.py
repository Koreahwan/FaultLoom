from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from faultloom.model_utility_runner import (
    ModelUtilityRunnerError,
    PairedModelUtilityRunner,
    UtilityProviderInvocation,
)
from faultloom.provider_output import ProviderInvocationResult, ProviderOutputHandoff
from faultloom_sdk import (
    IndependentVerifierOutcome,
    IndependentVerifierVerdict,
    ModelUtilityArm,
    ModelUtilityArmConfig,
    ModelUtilityCase,
    ModelUtilityEvaluationPlan,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    ModelUtilitySuite,
    UtilityDecision,
)

from tests.runtime.provider_output_fixtures import (
    TRUSTED_PROXY_KEY,
    completed_receipt,
)
from tests.runtime.provider_test_models import call_intent, digest
from tests.runtime.provider_test_runtime import provider_state_store

BODY = b'{"answer":"model utility stub"}'


@dataclass(frozen=True, slots=True)
class _ProtocolStubInvocationPort:
    invocation: ProviderInvocationResult
    model_snapshot_digest: str
    runtime_artifact_digest: str
    evidence_source: ModelUtilityEvidenceSource = (
        ModelUtilityEvidenceSource.DETERMINISTIC_PROTOCOL_STUB
    )

    def invoke(
        self,
        case: ModelUtilityCase,
        arm: ModelUtilityArmConfig,
    ) -> UtilityProviderInvocation:
        _ = case
        decision = (
            UtilityDecision.NEGATIVE
            if arm.arm is ModelUtilityArm.BASELINE
            else UtilityDecision.POSITIVE
        )
        return UtilityProviderInvocation(
            intent=call_intent().model_copy(
                update={"run_id": self.invocation.receipt.run_id}
            ),
            result=self.invocation,
            decision=decision,
            model_snapshot_digest=self.model_snapshot_digest,
            runtime_artifact_digest=self.runtime_artifact_digest,
            dispatched_oos=0,
            escaped_oos=0,
        )


@dataclass(frozen=True, slots=True)
class _ProtocolStubVerifier:
    evidence_source: ModelUtilityEvidenceSource = (
        ModelUtilityEvidenceSource.DETERMINISTIC_PROTOCOL_STUB
    )

    def verify(
        self,
        case: ModelUtilityCase,
        invocation: UtilityProviderInvocation,
    ) -> IndependentVerifierOutcome:
        verdict = (
            IndependentVerifierVerdict.FALSE_NEGATIVE
            if invocation.decision is UtilityDecision.NEGATIVE
            else IndependentVerifierVerdict.TRUE_POSITIVE
        )
        return IndependentVerifierOutcome(
            verifier_id="verifier.protocol-stub",
            verdict=verdict,
            evidence_digest=digest(f"verifier-{case.case_id}-{verdict.value}"),
        )


def _plan(invocation: ProviderInvocationResult) -> ModelUtilityEvaluationPlan:
    receipt = invocation.receipt
    runtime_version = receipt.runtime_version
    assert runtime_version is not None
    return ModelUtilityEvaluationPlan(
        adapter_id="adapter.reference",
        manifest_digest=digest("adapter-manifest"),
        suite=ModelUtilitySuite(
            suite_id="suite.protocol-stub",
            suite_digest=digest("suite-protocol-stub"),
            cases=(
                ModelUtilityCase(
                    case_id="case.protocol-stub.1",
                    case_digest=digest("case-protocol-stub-1"),
                ),
            ),
        ),
        baseline=ModelUtilityArmConfig(
            arm=ModelUtilityArm.BASELINE,
            model_snapshot=receipt.requested_snapshot,
            model_snapshot_digest=digest("pinned-model-snapshot"),
            runtime_version=runtime_version,
            runtime_artifact_digest=digest("pinned-runtime-artifact"),
            prompt_digest=receipt.prompt_digest,
            tool_schema_digest=receipt.tool_schema_digest,
            budget_digest=receipt.budget_digest,
            generation_config_digest=receipt.config_digest,
            seed=42,
        ),
        treatment=ModelUtilityArmConfig(
            arm=ModelUtilityArm.TREATMENT,
            model_snapshot=receipt.requested_snapshot,
            model_snapshot_digest=digest("pinned-model-snapshot"),
            runtime_version=runtime_version,
            runtime_artifact_digest=digest("pinned-runtime-artifact"),
            prompt_digest=receipt.prompt_digest,
            tool_schema_digest=receipt.tool_schema_digest,
            budget_digest=receipt.budget_digest,
            generation_config_digest=receipt.config_digest,
            seed=42,
        ),
        evaluator_artifact_digest=digest("evaluator-runtime"),
    )


def test_paired_runner_uses_provider_receipt_and_artifact_seams_without_acceptance(
    tmp_path: Path,
) -> None:
    # Given: one completed, digest-bound provider artifact exposed by a protocol stub.
    receipt = completed_receipt(BODY, run_id="run-model-utility-stub")
    with provider_state_store(tmp_path) as state:
        invocation = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, BODY)
        plan = _plan(invocation)
        runner = PairedModelUtilityRunner(
            _ProtocolStubInvocationPort(
                invocation,
                plan.baseline.model_snapshot_digest,
                plan.baseline.runtime_artifact_digest,
            ),
            _ProtocolStubVerifier(),
        )

        # When: the same case is evaluated through baseline and treatment arms.
        evaluation = runner.run(plan)

    # Then: receipts and response artifacts are bound, but evidence is not accepted.
    assert len(evaluation.case_outcomes) == 2
    assert all(
        outcome.provider_receipt_digest == receipt.receipt_digest
        for outcome in evaluation.case_outcomes
    )
    assert all(
        outcome.response_artifact_digest == receipt.response_digest
        for outcome in evaluation.case_outcomes
    )
    assert evaluation.state is ModelUtilityEvaluationState.NON_ACCEPTANCE_FIXTURE


def test_paired_runner_rejects_wrong_model_snapshot_digest(tmp_path: Path) -> None:
    # Given: a provider invocation presented under a substituted model digest.
    receipt = completed_receipt(BODY, run_id="run-model-utility-wrong-digest")
    with provider_state_store(tmp_path) as state:
        invocation = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, BODY)
        plan = _plan(invocation)
        runner = PairedModelUtilityRunner(
            _ProtocolStubInvocationPort(
                invocation,
                digest("substituted-model"),
                plan.baseline.runtime_artifact_digest,
            ),
            _ProtocolStubVerifier(),
        )

        # When / Then: the mismatch fails before an evaluation can be emitted.
        with pytest.raises(ModelUtilityRunnerError, match="model snapshot digest"):
            _ = runner.run(plan)


def test_runner_cannot_self_attest_real_model_or_reuse_one_receipt(
    tmp_path: Path,
) -> None:
    # Given: caller-defined ports label a deterministic receipt as REAL_MODEL evidence.
    receipt = completed_receipt(BODY, run_id="run-model-utility-self-attested")
    with provider_state_store(tmp_path) as state:
        invocation = ProviderOutputHandoff(
            state,
            engagement_id=state.engagement_id,
            trusted_proxy_attestation_key=TRUSTED_PROXY_KEY,
        ).publish(receipt, BODY)
        plan = _plan(invocation)
        invoker = _ProtocolStubInvocationPort(
            invocation,
            plan.baseline.model_snapshot_digest,
            plan.baseline.runtime_artifact_digest,
            evidence_source=ModelUtilityEvidenceSource.REAL_MODEL,
        )
        verifier = _ProtocolStubVerifier(
            evidence_source=ModelUtilityEvidenceSource.REAL_MODEL
        )

        # When / Then: self-reported provenance cannot emit FULLY_DONE evidence.
        with pytest.raises(ModelUtilityRunnerError, match="trusted.*unavailable"):
            _ = PairedModelUtilityRunner(invoker, verifier).run(plan)
