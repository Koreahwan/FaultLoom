from __future__ import annotations

import hashlib

from faultloom_protocol import sha256_digest
from faultloom_sdk import (
    IndependentVerifierOutcome,
    IndependentVerifierVerdict,
    ModelUtilityArm,
    ModelUtilityArmConfig,
    ModelUtilityCase,
    ModelUtilityCaseOutcome,
    ModelUtilityEvaluation,
    ModelUtilityEvaluationPlan,
    ModelUtilityEvidenceSource,
    ModelUtilitySuite,
    UtilityDecision,
    evaluate_model_utility,
    model_utility_digest,
    reference_adapter_manifest,
)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def utility_plan() -> ModelUtilityEvaluationPlan:
    manifest = reference_adapter_manifest()
    suite = ModelUtilitySuite(
        suite_id="suite.reference.utility",
        suite_digest=digest("utility-suite"),
        cases=(
            ModelUtilityCase(case_id="case.reference.1", case_digest=digest("case-1")),
            ModelUtilityCase(case_id="case.reference.2", case_digest=digest("case-2")),
        ),
    )
    return ModelUtilityEvaluationPlan(
        adapter_id=manifest.adapter_id,
        manifest_digest=sha256_digest(manifest),
        suite=suite,
        baseline=ModelUtilityArmConfig(
            arm=ModelUtilityArm.BASELINE,
            model_snapshot="model.snapshot.2026-07-17",
            model_snapshot_digest=digest("model-snapshot"),
            runtime_version="runtime.1.0.0",
            runtime_artifact_digest=digest("runtime-artifact"),
            prompt_digest=digest("baseline-prompt"),
            tool_schema_digest=digest("baseline-tools"),
            budget_digest=digest("budget"),
            generation_config_digest=digest("generation-config"),
            seed=29,
        ),
        treatment=ModelUtilityArmConfig(
            arm=ModelUtilityArm.TREATMENT,
            model_snapshot="model.snapshot.2026-07-17",
            model_snapshot_digest=digest("model-snapshot"),
            runtime_version="runtime.1.0.0",
            runtime_artifact_digest=digest("runtime-artifact"),
            prompt_digest=digest("treatment-prompt"),
            tool_schema_digest=digest("treatment-tools"),
            budget_digest=digest("budget"),
            generation_config_digest=digest("generation-config"),
            seed=29,
        ),
        evaluator_artifact_digest=digest("evaluator-artifact"),
    )


def utility_outcomes() -> tuple[ModelUtilityCaseOutcome, ...]:
    plan = utility_plan()
    outcomes: list[ModelUtilityCaseOutcome] = []
    for index, case in enumerate(plan.suite.cases, start=1):
        for arm, config, decision, verdict, tokens in (
            (
                ModelUtilityArm.BASELINE,
                plan.baseline,
                UtilityDecision.NEGATIVE,
                IndependentVerifierVerdict.FALSE_NEGATIVE,
                100,
            ),
            (
                ModelUtilityArm.TREATMENT,
                plan.treatment,
                UtilityDecision.POSITIVE,
                IndependentVerifierVerdict.TRUE_POSITIVE,
                80,
            ),
        ):
            outcomes.append(
                ModelUtilityCaseOutcome(
                    case_id=case.case_id,
                    case_digest=case.case_digest,
                    arm=arm,
                    arm_config_digest=model_utility_digest(config),
                    decision=decision,
                    verifier=IndependentVerifierOutcome(
                        verifier_id="verifier.independent.reference",
                        verdict=verdict,
                        evidence_digest=digest(f"verifier-{index}-{arm.value}"),
                    ),
                    provider_receipt_digest=digest(f"receipt-{index}-{arm.value}"),
                    response_artifact_digest=digest(f"response-{index}-{arm.value}"),
                    model_tokens=tokens,
                    dispatched_oos=0,
                    escaped_oos=0,
                )
            )
    return tuple(outcomes)


def valid_utility_evaluation(
    source: ModelUtilityEvidenceSource = (
        ModelUtilityEvidenceSource.DETERMINISTIC_PROTOCOL_STUB
    ),
) -> ModelUtilityEvaluation:
    return evaluate_model_utility(utility_plan(), utility_outcomes(), source)
