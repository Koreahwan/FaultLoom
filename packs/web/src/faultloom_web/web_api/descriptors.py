from __future__ import annotations

import hashlib
from typing import Final

from faultloom_protocol import ActionIntent, sha256_digest

from ._base import WebApiIntegrationError
from .ids import (
    ACTION_COMPILER_ID,
    EVALUATOR_ID,
    HYPOTHESIS_PROVIDER_ID,
    OBSERVATION_NORMALIZER_ID,
    VERIFIER_ID,
)
from .inputs import ActionBoundaryRecord
from .results import (
    NormalizedWebObservation,
    ResetStability,
    WebApiCorrelationView,
    WebApiEvaluation,
    WebApiHypothesis,
    WebApiRunResult,
    WebApiVerification,
)

_ACTION_PACKS: Final = frozenset(
    {"pack.web.identity_workflow", "pack.web.api_async"}
)


def compile_web_action(record: ActionBoundaryRecord) -> ActionIntent:
    intent = record.intent
    if intent.pack_id not in _ACTION_PACKS:
        raise WebApiIntegrationError(
            "web_api.action_pack_unsupported",
            "the Web/API compiler accepts only integrated public pack actions",
        )
    if (
        intent.payload_digest is None
        or record.lease.semantic_action_digest != intent.payload_digest
    ):
        raise WebApiIntegrationError(
            "web_api.semantic_action_mismatch",
            "the Gateway lease must bind the compiled semantic payload",
        )
    return intent


def normalize_web_observation(
    record: ActionBoundaryRecord,
) -> NormalizedWebObservation:
    return NormalizedWebObservation(
        normalizer_id=OBSERVATION_NORMALIZER_ID,
        action_id=record.intent.action_id,
        lease_id=record.lease.lease_id,
        observation=record.observation,
    )


def provide_bridge_hypotheses(
    view: WebApiCorrelationView,
) -> tuple[WebApiHypothesis, ...]:
    run_ids = {
        view.identity_graph.run_id,
        view.workflow_graph.run_id,
        view.surface_graph.run_id,
        view.chain_graph.run_id,
    }
    if len(run_ids) != 1:
        raise WebApiIntegrationError(
            "web_api.correlation_run_mismatch",
            "hypothesis inputs must belong to one run",
        )
    if not any(
        item.identity_context_id == view.identity_context_id
        for item in view.workflow_graph.transitions
    ):
        raise WebApiIntegrationError(
            "web_api.workflow_actor_unbound",
            "the integration actor must appear in the workflow graph",
        )
    if not view.surface_graph.async_flows:
        return ()
    flow = view.surface_graph.async_flows[0]
    material = "\0".join(
        (
            view.identity_context_id,
            view.identity_graph.graph_id,
            view.workflow_graph.graph_id,
            flow.async_flow_id,
            view.chain_graph.graph_id,
        )
    ).encode()
    return (
        WebApiHypothesis(
            provider_id=HYPOTHESIS_PROVIDER_ID,
            hypothesis_id=f"hypothesis.web-api.{hashlib.sha256(material).hexdigest()}",
            identity_context_id=view.identity_context_id,
            identity_graph_id=view.identity_graph.graph_id,
            workflow_graph_id=view.workflow_graph.graph_id,
            async_flow_id=flow.async_flow_id,
            chain_graph_id=view.chain_graph.graph_id,
        ),
    )


def verify_web_api_run(result: WebApiRunResult) -> WebApiVerification:
    forward = result.chain_search.forward
    final_effect_reached = (
        forward is not None
        and forward.plan.final_effect_id in result.correlation.completed_effect_ids
    )
    correlated = bool(result.hypotheses)
    action_boundaries_valid = (
        bool(result.compiled_intents)
        and len(result.compiled_intents) == len(result.normalized_observations)
    )
    return WebApiVerification(
        verifier_id=VERIFIER_ID,
        run_id=result.correlation.identity_graph.run_id,
        identity_async_correlated=correlated,
        final_effect_reached=final_effect_reached,
        action_boundaries_valid=action_boundaries_valid,
        passed=correlated and final_effect_reached and action_boundaries_valid,
    )


def evaluate_web_api_run(
    result: WebApiRunResult,
    verification: WebApiVerification,
) -> WebApiEvaluation:
    forward = result.chain_search.forward
    edge_count = 0 if forward is None else len(forward.plan.edge_ids)
    return WebApiEvaluation(
        evaluator_id=EVALUATOR_ID,
        run_id=verification.run_id,
        verified=verification.passed,
        chain_edge_count=edge_count,
        normalized_observation_count=len(result.normalized_observations),
    )


def compare_reset_stability(
    initial: WebApiRunResult,
    resumed: WebApiRunResult,
) -> ResetStability:
    left = initial.correlation
    right = resumed.correlation
    stable = (
        left.identity_graph.graph_id == right.identity_graph.graph_id
        and left.workflow_graph.graph_id == right.workflow_graph.graph_id
        and left.surface_graph.graph_id == right.surface_graph.graph_id
        and left.chain_graph.graph_id == right.chain_graph.graph_id
        and tuple(item.operation_id for item in left.surface_graph.operations)
        == tuple(item.operation_id for item in right.surface_graph.operations)
        and tuple(item.async_flow_id for item in left.surface_graph.async_flows)
        == tuple(item.async_flow_id for item in right.surface_graph.async_flows)
        and tuple(item.edge_id for item in left.chain_graph.edges)
        == tuple(item.edge_id for item in right.chain_graph.edges)
        and tuple(item.hypothesis_id for item in initial.hypotheses)
        == tuple(item.hypothesis_id for item in resumed.hypotheses)
        and tuple(sha256_digest(item) for item in initial.compiled_intents)
        == tuple(sha256_digest(item) for item in resumed.compiled_intents)
        and initial.normalized_observations == resumed.normalized_observations
    )
    return ResetStability(
        reset_stable=stable,
        identity_graph_id=left.identity_graph.graph_id,
        surface_graph_id=left.surface_graph.graph_id,
        chain_graph_id=left.chain_graph.graph_id,
    )
