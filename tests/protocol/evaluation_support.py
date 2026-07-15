from __future__ import annotations

from datetime import datetime, timezone

from faultloom_protocol import (
    SCHEMA_VERSION,
    ArtifactAttestation,
    ArtifactKind,
    ChainDepthBand,
    EvaluationAggregateReceipt,
    EvaluationArm,
    EvaluationArmConfig,
    EvaluationArmResult,
    EvaluationBudget,
    EvaluationCaseDescriptor,
    EvaluationCaseResult,
    EvaluationDomain,
    EvaluationFindingKind,
    EvaluationManifest,
    EvaluationMetric,
    EvaluationOutcome,
    EvaluationOutcomeReason,
    EvaluationTaxonomy,
    ExecutionTiming,
    IdentityCardinality,
    MetricName,
    MetricUnit,
    PublicEvaluationProjection,
    TenantCardinality,
    sha256_digest,
)

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
DIGESTS = tuple(f"sha256:{byte * 64}" for byte in "123456789abcdef")


def evaluation_budget() -> EvaluationBudget:
    return EvaluationBudget(
        schema_version=SCHEMA_VERSION,
        action_limit=100,
        duration_seconds=3_600,
        model_token_limit=200_000,
        cost_microunits=1_000_000,
    )


def evaluation_arm(arm: EvaluationArm, runtime_digest: str) -> EvaluationArmConfig:
    return EvaluationArmConfig(
        schema_version=SCHEMA_VERSION,
        arm=arm,
        runtime_artifact_digest=runtime_digest,
        model_snapshot_digest=DIGESTS[0],
        tool_inventory_digest=DIGESTS[1],
        gateway_artifact_digest=DIGESTS[2],
        budget=evaluation_budget(),
    )


def evaluation_manifest() -> EvaluationManifest:
    descriptor = EvaluationCaseDescriptor(
        schema_version=SCHEMA_VERSION,
        case_id="case.web-identity.1",
        case_revision=1,
        taxonomy=EvaluationTaxonomy(
            schema_version=SCHEMA_VERSION,
            domain=EvaluationDomain.WEB_IDENTITY_WORKFLOW,
            finding_kind=EvaluationFindingKind.ZERO_DAY_LIKE,
            chain_depth=ChainDepthBand.DEPTH_2_TO_3,
            identity_cardinality=IdentityCardinality.MULTI,
            tenant_cardinality=TenantCardinality.CROSS_TENANT,
            execution_timing=ExecutionTiming.ASYNCHRONOUS,
        ),
        pack_ids=("pack.web",),
        adapter_ids=("adapter.http",),
        context_reset_count=3,
        workload_context_bps=15_000,
        fixture_visibility="private_holdout",
    )
    return EvaluationManifest(
        schema_version=SCHEMA_VERSION,
        manifest_id="evaluation.manifest.1",
        manifest_version=1,
        sealed_plan_digest=DIGESTS[3],
        protocol_artifact_digest=DIGESTS[4],
        cases=(descriptor,),
        arms=(
            evaluation_arm(EvaluationArm.TERMINATOR_V1, DIGESTS[5]),
            evaluation_arm(EvaluationArm.THIN_FRONTIER_REFERENCE, DIGESTS[6]),
            evaluation_arm(EvaluationArm.FAULTLOOM_V2, DIGESTS[7]),
        ),
        created_at=NOW,
    )


def evaluation_metric() -> EvaluationMetric:
    return EvaluationMetric(
        schema_version=SCHEMA_VERSION,
        name=MetricName.VERIFIED_SUCCESS_RATE,
        unit=MetricUnit.BASIS_POINTS,
        point=7_500,
        lower_bound=6_500,
        upper_bound=8_500,
        sample_count=20,
    )


def public_projection() -> PublicEvaluationProjection:
    manifest = evaluation_manifest()
    case = manifest.cases[0]
    results = tuple(
        EvaluationCaseResult(
            schema_version=SCHEMA_VERSION,
            result_id=f"evaluation.result.{index}",
            run_id=f"run.{index}",
            arm=arm,
            manifest_digest=sha256_digest(manifest),
            case_descriptor_digest=sha256_digest(case),
            outcome=EvaluationOutcome.SUCCESS,
            reason=EvaluationOutcomeReason.VERIFIED_SUCCESS,
            run_started=True,
            included_in_denominator=True,
            safety_violation=False,
            final_effect_verified=True,
            independent_replay=False,
            longest_verified_prefix=3,
            metrics=(evaluation_metric(),),
            run_result_bundle_digest=DIGESTS[8],
            evidence_digests=(DIGESTS[9],),
        )
        for index, arm in enumerate(EvaluationArm, start=1)
    )
    attestation = ArtifactAttestation(
        schema_version=SCHEMA_VERSION,
        attestation_id="attestation.core.1",
        artifact_kind=ArtifactKind.CORE_WHEEL,
        artifact_id="faultloom",
        artifact_version="0.1.0",
        artifact_digest=DIGESTS[10],
        source_commit="1" * 40,
        sbom_digest=DIGESTS[11],
        built_at=NOW,
    )
    arm_results = tuple(
        EvaluationArmResult(
            schema_version=SCHEMA_VERSION,
            arm=arm,
            case_result_digests=(
                sha256_digest(next(result for result in results if result.arm is arm)),
            ),
            denominator_count=1,
            success_count=1,
            failure_count=0,
            inconclusive_count=0,
            safety_violation_count=0,
            metrics=(evaluation_metric(),),
        )
        for arm in EvaluationArm
    )
    receipt = EvaluationAggregateReceipt(
        schema_version=SCHEMA_VERSION,
        receipt_id="evaluation.receipt.1",
        receipt_version=1,
        manifest_digest=sha256_digest(manifest),
        arm_results=arm_results,
        case_result_digests=tuple(sha256_digest(result) for result in results),
        artifact_attestation_digests=(sha256_digest(attestation),),
        evaluator_artifact_digest=attestation.artifact_digest,
        generated_at=NOW,
    )
    return PublicEvaluationProjection(
        schema_version=SCHEMA_VERSION,
        manifest=manifest,
        case_results=results,
        artifact_attestations=(attestation,),
        aggregate_receipt=receipt,
    )


def schema_property_names(value: object) -> set[str]:
    if isinstance(value, dict):
        names = set(value.get("properties", {}))
        return names | {
            name for child in value.values() for name in schema_property_names(child)
        }
    if isinstance(value, list):
        return {name for child in value for name in schema_property_names(child)}
    return set()
