"""Closed public taxonomy for evaluation manifests and receipts."""

from __future__ import annotations

from enum import Enum


class EvaluationArm(str, Enum):
    TERMINATOR_V1 = "terminator_v1"
    THIN_FRONTIER_REFERENCE = "thin_frontier_reference"
    FAULTLOOM_V2 = "faultloom_v2"


class EvaluationDomain(str, Enum):
    WEB_IDENTITY_WORKFLOW = "web_identity_workflow"
    API_ASYNC = "api_async"
    LLM_AGENT = "llm_agent"
    PATCH_CVE = "patch_cve"
    CROSS_SURFACE = "cross_surface"


class EvaluationFindingKind(str, Enum):
    CVE_REPRODUCTION = "CVE_reproduction"
    ONE_DAY_ADAPTATION = "one_day_adaptation"
    PATCH_VARIANT = "patch_variant"
    ZERO_DAY_LIKE = "zero_day_like"


class ChainDepthBand(str, Enum):
    DEPTH_1 = "depth_1"
    DEPTH_2_TO_3 = "depth_2_to_3"
    DEPTH_4_PLUS = "depth_4_plus"


class IdentityCardinality(str, Enum):
    SINGLE = "single_identity"
    MULTI = "multi_identity"


class TenantCardinality(str, Enum):
    SINGLE_TENANT = "single_tenant"
    CROSS_TENANT = "cross_tenant"


class ExecutionTiming(str, Enum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"


class EvaluationOutcome(str, Enum):
    SUCCESS = "success"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EvaluationOutcomeReason(str, Enum):
    VERIFIED_SUCCESS = "verified_success"
    PRE_RUN_INFRASTRUCTURE = "pre_run_infrastructure"
    POST_RUN_TIMEOUT = "post_run_timeout"
    POST_RUN_BUDGET = "post_run_budget"
    POST_RUN_RUNTIME = "post_run_runtime"
    FINAL_EFFECT_UNVERIFIED = "final_effect_unverified"
    SAFETY_VIOLATION = "safety_violation"


class MetricUnit(str, Enum):
    COUNT = "count"
    BASIS_POINTS = "basis_points"
    SECONDS = "seconds"
    TOKENS = "tokens"
    MICROUNITS = "microunits"
    DEPTH = "depth"


class ContextResetMetricName(str, Enum):
    INITIAL_CLUE_RECALL_BPS = "context.initial_clue_recall_bps"
    ACTIVE_HYPOTHESIS_LOSS_BPS = "context.active_hypothesis_loss_bps"
    NEGATIVE_RESULT_LOSS_BPS = "context.negative_result_loss_bps"
    FAILED_EXPERIMENT_REPEAT_COUNT = "context.failed_experiment_repeat_count"
    CHAIN_COMPLETION_DELTA_BPS = "context.chain_completion_delta_bps"
    COMPACTION_REGRET_BPS = "context.compaction_regret_bps"
    RECOVERY_TOKEN_COUNT = "context.recovery_token_count"
    RECOVERY_TIME_SECONDS = "context.recovery_time_seconds"
    SUCCESS_AFTER_ONE_RESET_BPS = "context.success_after_one_reset_bps"
    SUCCESS_AFTER_THREE_RESETS_BPS = "context.success_after_three_resets_bps"
    SUCCESS_AFTER_TEN_RESETS_BPS = "context.success_after_ten_resets_bps"
    LOST_STATE_ID_COUNT = "context.lost_state_id_count"
    LOST_EVIDENCE_ID_COUNT = "context.lost_evidence_id_count"
    DUPLICATE_STATE_EFFECT_COUNT = "context.duplicate_state_effect_count"
    CROSS_ENGAGEMENT_RETRIEVAL_COUNT = "context.cross_engagement_retrieval_count"


class AdapterMetricName(str, Enum):
    VERIFIED_RECALL_DELTA_BPS = "adapter.verified_recall_delta_bps"
    UNIQUE_VERIFIED_POSITIVES = "adapter.unique_verified_positives"
    COST_REDUCTION_BPS = "adapter.cost_reduction_bps"
    TIME_REDUCTION_BPS = "adapter.time_reduction_bps"
    TOKEN_REDUCTION_BPS = "adapter.token_reduction_bps"
    DISPATCHED_OOS_COUNT = "safety.dispatched_oos_count"
    ESCAPED_OOS_COUNT = "safety.escaped_oos_count"
    TOOL_ONLY_FALSE_VERIFIED_COUNT = "adapter.tool_only_false_verified_count"


class MetricName(str, Enum):
    VERIFIED_SUCCESS_RATE = "verified_success_rate_bps"
    FALSE_VERIFIED_RATE = "false_verified_rate_bps"
    CHAIN_SUCCESS_RATE = "chain_success_rate_bps"
    LONGEST_VERIFIED_PREFIX = "longest_verified_prefix"
    WORKFLOW_TRANSITION_COVERAGE = "workflow_transition_coverage_bps"
    IDENTITY_TENANT_DIFFERENTIAL_COVERAGE = (
        "identity_tenant_differential_coverage_bps"
    )
    ASYNC_CORRELATION_COMPLETENESS = "async_correlation_completeness_bps"
    CVE_REACHABILITY_PRECISION = "cve_reachability_precision_bps"
    PATCH_VARIANT_RECALL = "patch_variant_recall_bps"
    PROPOSED_OOS_COUNT = "safety.proposed_oos_count"
    BROKER_DENIED_OOS_COUNT = "safety.broker_denied_oos_count"
    DISPATCHED_OOS_COUNT = AdapterMetricName.DISPATCHED_OOS_COUNT.value
    ESCAPED_OOS_COUNT = AdapterMetricName.ESCAPED_OOS_COUNT.value
    FALSE_DENY_COUNT = "safety.false_deny_count"
    TOOL_ESCALATION_UTILITY = "tool_escalation_utility_bps"
    VERIFIER_FALSE_ACCEPT = "verifier_false_accept_bps"
    VERIFIER_FALSE_REJECT = "verifier_false_reject_bps"
    COST_PER_VERIFIED_FINDING = "cost_per_verified_finding_microunits"
    TIME_PER_VERIFIED_FINDING = "time_per_verified_finding_seconds"
    TOKENS_PER_VERIFIED_FINDING = "tokens_per_verified_finding"
    INITIAL_CLUE_RECALL_BPS = ContextResetMetricName.INITIAL_CLUE_RECALL_BPS.value
    ACTIVE_HYPOTHESIS_LOSS_BPS = (
        ContextResetMetricName.ACTIVE_HYPOTHESIS_LOSS_BPS.value
    )
    NEGATIVE_RESULT_LOSS_BPS = ContextResetMetricName.NEGATIVE_RESULT_LOSS_BPS.value
    FAILED_EXPERIMENT_REPEAT_COUNT = (
        ContextResetMetricName.FAILED_EXPERIMENT_REPEAT_COUNT.value
    )
    CHAIN_COMPLETION_DELTA_BPS = (
        ContextResetMetricName.CHAIN_COMPLETION_DELTA_BPS.value
    )
    COMPACTION_REGRET_BPS = ContextResetMetricName.COMPACTION_REGRET_BPS.value
    RECOVERY_TOKEN_COUNT = ContextResetMetricName.RECOVERY_TOKEN_COUNT.value
    RECOVERY_TIME_SECONDS = ContextResetMetricName.RECOVERY_TIME_SECONDS.value
    SUCCESS_AFTER_ONE_RESET_BPS = (
        ContextResetMetricName.SUCCESS_AFTER_ONE_RESET_BPS.value
    )
    SUCCESS_AFTER_THREE_RESETS_BPS = (
        ContextResetMetricName.SUCCESS_AFTER_THREE_RESETS_BPS.value
    )
    SUCCESS_AFTER_TEN_RESETS_BPS = (
        ContextResetMetricName.SUCCESS_AFTER_TEN_RESETS_BPS.value
    )
    LOST_STATE_ID_COUNT = ContextResetMetricName.LOST_STATE_ID_COUNT.value
    LOST_EVIDENCE_ID_COUNT = ContextResetMetricName.LOST_EVIDENCE_ID_COUNT.value
    DUPLICATE_STATE_EFFECT_COUNT = (
        ContextResetMetricName.DUPLICATE_STATE_EFFECT_COUNT.value
    )
    CROSS_ENGAGEMENT_RETRIEVAL_COUNT = (
        ContextResetMetricName.CROSS_ENGAGEMENT_RETRIEVAL_COUNT.value
    )
    ADAPTER_VERIFIED_RECALL_DELTA_BPS = (
        AdapterMetricName.VERIFIED_RECALL_DELTA_BPS.value
    )
    ADAPTER_UNIQUE_VERIFIED_POSITIVES = (
        AdapterMetricName.UNIQUE_VERIFIED_POSITIVES.value
    )
    ADAPTER_COST_REDUCTION_BPS = AdapterMetricName.COST_REDUCTION_BPS.value
    ADAPTER_TIME_REDUCTION_BPS = AdapterMetricName.TIME_REDUCTION_BPS.value
    ADAPTER_TOKEN_REDUCTION_BPS = AdapterMetricName.TOKEN_REDUCTION_BPS.value
    TOOL_ONLY_FALSE_VERIFIED_COUNT = (
        AdapterMetricName.TOOL_ONLY_FALSE_VERIFIED_COUNT.value
    )


class ArtifactKind(str, Enum):
    PROTOCOL_WHEEL = "protocol_wheel"
    CORE_WHEEL = "core_wheel"
    GATEWAY_IMAGE = "gateway_image"
    PACK_ARTIFACT = "pack_artifact"
    PUBLIC_EVALUATION_MANIFEST = "public_evaluation_manifest"
    SOFTWARE_BILL_OF_MATERIALS = "software_bill_of_materials"


EVALUATION_ENUM_TYPES: tuple[type[Enum], ...] = (
    EvaluationArm,
    EvaluationDomain,
    EvaluationFindingKind,
    ChainDepthBand,
    IdentityCardinality,
    TenantCardinality,
    ExecutionTiming,
    EvaluationOutcome,
    EvaluationOutcomeReason,
    MetricUnit,
    ContextResetMetricName,
    AdapterMetricName,
    MetricName,
    ArtifactKind,
)
