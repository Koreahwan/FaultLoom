from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import assert_never

from faultloom_protocol import (
    CapabilityPrimitive,
    ChainEdge,
    ChainGraph,
    DecisionOutcome,
    TargetAsset,
    sha256_digest,
)

from .admissions import PrimitiveRegistry
from .contracts import AssetClass, ChainAuthority, EdgeAuthorityBinding
from .errors import ChainIntegrityError, ChainPolicyError
from .scope_policy import validate_scope_policy


@dataclass(frozen=True, slots=True)
class ChainIndex:
    capabilities: Mapping[str, CapabilityPrimitive]
    edges: Mapping[str, ChainEdge]
    bindings: Mapping[str, EdgeAuthorityBinding]


@dataclass(frozen=True, slots=True)
class _EdgeContext:
    edge: ChainEdge
    source: CapabilityPrimitive
    target: CapabilityPrimitive
    binding: EdgeAuthorityBinding
    authority: ChainAuthority
    target_asset: TargetAsset


def validate_chain_authority(
    registry: PrimitiveRegistry,
    graph: ChainGraph,
    authority: ChainAuthority,
) -> ChainIndex:
    """Validate every graph edge against its own explicit grant and fresh lease."""

    capabilities = _unique_capabilities(graph)
    edges = _unique_edges(graph)
    bindings = {item.edge_id: item for item in authority.edge_bindings}
    if set(edges) != set(bindings):
        raise ChainIntegrityError(
            "chain.authority_not_closed",
            "authority bindings must cover exactly the graph edges",
        )
    for capability_id, capability in capabilities.items():
        if registry.capability(capability_id) != capability:
            raise ChainIntegrityError(
                "chain.registry_graph_mismatch",
                f"graph capability {capability_id} differs from the registry",
            )
        if capability.primitive.run_id != graph.run_id:
            raise ChainIntegrityError(
                "chain.capability_run_mismatch",
                f"capability {capability_id} belongs to another run",
            )
    targets = {item.target_id: item for item in authority.grant.targets}
    if graph.action_budget > authority.grant.budget.total_actions:
        raise ChainPolicyError(
            "chain.graph_action_budget_exceeds_grant",
            "chain graph action budget exceeds the AuthorityGrant",
        )
    if graph.time_budget_seconds > authority.grant.budget.max_duration_seconds:
        raise ChainPolicyError(
            "chain.graph_time_budget_exceeds_grant",
            "chain graph time budget exceeds the AuthorityGrant",
        )
    for edge in edges.values():
        source = capabilities.get(edge.source_capability_id)
        target = capabilities.get(edge.target_capability_id)
        if source is None or target is None:
            raise ChainIntegrityError(
                "chain.dangling_edge",
                f"edge {edge.edge_id} references an unknown capability",
            )
        target_asset = targets.get(edge.action_intent.target_id)
        if target_asset is None:
            raise ChainPolicyError(
                "chain.target_not_granted",
                f"edge {edge.edge_id} targets an asset absent from the grant",
            )
        _validate_edge(
            _EdgeContext(
                edge=edge,
                source=source,
                target=target,
                binding=bindings[edge.edge_id],
                authority=authority,
                target_asset=target_asset,
            )
        )
    return ChainIndex(capabilities=capabilities, edges=edges, bindings=bindings)


def _unique_capabilities(graph: ChainGraph) -> dict[str, CapabilityPrimitive]:
    values = {item.capability_id: item for item in graph.capabilities}
    if len(values) != len(graph.capabilities):
        raise ChainIntegrityError(
            "chain.duplicate_graph_capability",
            "chain graph capability IDs must be unique",
        )
    return values


def _unique_edges(graph: ChainGraph) -> dict[str, ChainEdge]:
    values = {item.edge_id: item for item in graph.edges}
    if len(values) != len(graph.edges):
        raise ChainIntegrityError(
            "chain.duplicate_graph_edge",
            "chain graph edge IDs must be unique",
        )
    return values


def _validate_edge(context: _EdgeContext) -> None:
    edge = context.edge
    binding = context.binding
    intent = edge.action_intent
    lease = binding.lease
    decision = binding.decision
    grant = context.authority.grant
    if not binding.explicitly_granted:
        raise ChainPolicyError(
            "chain.implicit_scope_propagation",
            f"edge {edge.edge_id} lacks an explicit per-edge scope grant",
        )
    match binding.asset_class:
        case AssetClass.PUBLIC | AssetClass.INTERNAL:
            pass
        case AssetClass.CLOUD_METADATA:
            raise ChainPolicyError(
                "chain.cloud_metadata_denied",
                "v0.1 chain planning cannot authorize cloud metadata",
            )
        case unreachable:
            assert_never(unreachable)
    if intent.pack_id != context.target.source_pack_id:
        raise ChainPolicyError(
            "chain.pack_transition_unbound",
            "edge action pack must explicitly match its target capability pack",
        )
    if intent.pack_id not in grant.pack_ids:
        raise ChainPolicyError(
            "chain.pack_not_granted",
            f"pack {intent.pack_id} is absent from the AuthorityGrant",
        )
    validate_scope_policy(edge, grant, context.target_asset)
    if not edge.evidence_refs or not edge.negative_control_refs:
        raise ChainIntegrityError(
            "chain.edge_evidence_incomplete",
            "every edge requires evidence and a negative control",
        )
    if edge.reversible and edge.cleanup_receipt_digest is None:
        raise ChainIntegrityError(
            "chain.cleanup_receipt_missing",
            "reversible edge requires a cleanup receipt",
        )
    if edge.expected_effect.effect_id != edge.observed_effect.effect_id:
        raise ChainIntegrityError(
            "chain.effect_binding_mismatch",
            "expected and observed effect IDs must identify the same effect",
        )
    if edge.observed_effect.effect_id not in context.target.effect_ids:
        raise ChainIntegrityError(
            "chain.target_effect_unbound",
            "observed effect must be exported by the target capability",
        )
    if edge.action_cost != 1 or edge.time_cost_seconds > lease.reservation.duration_seconds:
        raise ChainIntegrityError(
            "chain.edge_budget_binding_mismatch",
            "one edge is one leased action and must fit the lease duration",
        )
    if edge.action_lease_id != lease.lease_id or decision.lease_id != lease.lease_id:
        raise ChainPolicyError(
            "chain.lease_binding_mismatch",
            "edge and allow decision must identify the same ActionLease",
        )
    if sha256_digest(intent) != lease.intent_digest:
        raise ChainPolicyError(
            "chain.intent_digest_mismatch",
            "ActionLease is not bound to the edge intent",
        )
    if sha256_digest(decision) != edge.scope_decision_digest:
        raise ChainPolicyError(
            "chain.decision_digest_mismatch",
            "edge scope decision digest is not explicit or exact",
        )
    if lease.decision_digest != edge.scope_decision_digest:
        raise ChainPolicyError(
            "chain.lease_decision_mismatch",
            "ActionLease is not bound to the edge scope decision",
        )
    _validate_lease_fields(context)


def _validate_lease_fields(context: _EdgeContext) -> None:
    intent = context.edge.action_intent
    lease = context.binding.lease
    decision = context.binding.decision
    grant = context.authority.grant
    if decision.outcome is not DecisionOutcome.ALLOW:
        raise ChainPolicyError(
            "chain.scope_decision_denied",
            "a chain edge requires an explicit allow decision",
        )
    expected = (
        intent.action_id,
        intent.target_id,
        intent.action_kind,
        intent.subject.identity_id,
        intent.subject.tenant_id,
        grant.grant_id,
        grant.grant_version,
    )
    observed = (
        lease.action_id,
        lease.target_id,
        lease.action_kind,
        lease.identity_id,
        lease.tenant_id,
        lease.grant_id,
        lease.grant_version,
    )
    if expected != observed:
        raise ChainPolicyError(
            "chain.lease_fields_mismatch",
            "ActionLease fields differ from intent or grant",
        )
    if decision.scope_epoch != lease.scope_epoch:
        raise ChainPolicyError(
            "chain.scope_epoch_mismatch",
            "allow decision and ActionLease use different scope epochs",
        )
