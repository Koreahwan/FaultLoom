from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, assert_never

from faultloom.chain import (
    ApiAsyncPrimitive,
    AssetClass,
    ChainAuthority,
    ChainBudget,
    ChainSearchSettings,
    EdgeAuthorityBinding,
    IdentityWorkflowPrimitive,
    PatchVariantPrimitive,
    PrimitiveAdmission,
    PrimitiveRegistry,
    PrimitiveStatus,
    SyntheticLlmPrimitive,
    normalize_primitives,
)
from faultloom_protocol import (
    ActionIntent,
    ActionPolicy,
    AuthorityGrant,
    ChainEdge,
    ChainGraph,
    DecisionOutcome,
    EffectRecord,
    PolicyDecision,
    PrimitiveRecord,
    SCHEMA_VERSION,
    StateRef,
    sha256_digest,
)

from tests.protocol.factories import D1, D2, D3, D4, NOW, sample_models

type SourceKind = Literal["identity", "api", "patch", "llm"]


@dataclass(frozen=True, slots=True)
class ChainBuildSpec:
    sources: tuple[SourceKind, ...]
    capability_kinds: tuple[str, ...] = ()
    candidate_indexes: frozenset[int] = frozenset()
    missing_at: int | None = None
    redundant_self_loop: bool = False


@dataclass(frozen=True, slots=True)
class BuiltChain:
    registry: PrimitiveRegistry
    graph: ChainGraph
    authority: ChainAuthority
    settings: ChainSearchSettings
    states: tuple[StateRef, ...]


def build_chain(spec: ChainBuildSpec) -> BuiltChain:
    values = sample_models()
    subject = values["SubjectRef"]
    resource = values["ResourceRef"]
    evidence = values["EvidenceRef"]
    base_grant = values["AuthorityGrant"]
    base_lease = values["ActionLease"]
    if not spec.sources:
        raise AssertionError("test chain requires at least one edge")
    states = tuple(
        StateRef(
            schema_version=SCHEMA_VERSION,
            state_id="state.chain",
            state_kind=f"stage.{index}",
            state_version=index + 1,
            state_digest=(D1, D2, D3, D4)[index % 4],
        )
        for index in range(len(spec.sources))
    )
    admissions: list[PrimitiveAdmission] = []
    for index, source in enumerate(spec.sources):
        verified = index not in spec.candidate_indexes
        primitive = PrimitiveRecord(
            schema_version=SCHEMA_VERSION,
            primitive_id=f"primitive.chain.{index}",
            run_id="run.1",
            primitive_kind=f"primitive.{source}",
            subject=subject,
            resource=resource,
            pre_state=states[index - 1] if index else states[0],
            post_state=states[index],
            action_intent_digest=D1,
            dispatch_receipt_digest=D2,
            evidence_refs=(evidence,),
            verified=verified,
        )
        preconditions = () if index == 0 else (f"effect.chain.{index - 1}",)
        if spec.missing_at == index:
            preconditions = (f"prerequisite.missing.{index}",)
        common = {
            "admission_id": f"admission.chain.{index}",
            "capability_id": f"capability.chain.{index}",
            "primitive": primitive,
            "capability_kind": (
                spec.capability_kinds[index]
                if spec.capability_kinds
                else f"capability.{source}"
            ),
            "source_pack_id": _pack(source),
            "status": PrimitiveStatus.VERIFIED if verified else PrimitiveStatus.CANDIDATE,
            "precondition_ids": preconditions,
            "effect_ids": (f"effect.chain.{index}",),
        }
        match source:
            case "identity":
                admissions.append(
                    IdentityWorkflowPrimitive(
                        **common,
                        identity_graph=values["IdentityGraph"],
                        workflow_graph=values["WorkflowGraph"],
                    )
                )
            case "api":
                admissions.append(
                    ApiAsyncPrimitive(**common, surface_graph=values["SurfaceGraph"])
                )
            case "patch":
                admissions.append(
                    PatchVariantPrimitive(
                        **common,
                        reachability=values["ReachabilityClaim"],
                        variant=values["VariantHypothesis"],
                    )
                )
            case "llm":
                admissions.append(
                    SyntheticLlmPrimitive(**common, contract_id="llm.contract.synthetic")
                )
            case unreachable:
                assert_never(unreachable)
    registry = normalize_primitives(tuple(admissions))
    capabilities = {item.capability_id: item for item in registry.capabilities}
    edges: list[ChainEdge] = []
    bindings: list[EdgeAuthorityBinding] = []

    def append_edge(source_index: int, target_index: int, label: str) -> None:
        target_capability = capabilities[f"capability.chain.{target_index}"]
        action_kind = f"chain.transition.{label}"
        intent_doc = values["ActionIntent"].model_dump(mode="python")
        intent_doc.update(
            action_id=f"action.chain.{label}",
            pack_id=target_capability.source_pack_id,
            action_kind=action_kind,
            state=states[source_index],
            path=f"/api/chain/{label}",
        )
        intent = ActionIntent.model_validate(intent_doc)
        decision_doc = values["PolicyDecision"].model_dump(mode="python")
        decision_doc.update(
            decision_id=f"decision.chain.{label}",
            intent_digest=sha256_digest(intent),
            outcome=DecisionOutcome.ALLOW,
            lease_id=f"lease.chain.{label}",
        )
        decision = PolicyDecision.model_validate(decision_doc)
        lease_doc = base_lease.model_dump(mode="python")
        lease_doc.update(
            lease_id=f"lease.chain.{label}",
            action_id=intent.action_id,
            correlation_id=f"correlation.chain.{label}",
            intent_digest=sha256_digest(intent),
            decision_digest=sha256_digest(decision),
            target_id=intent.target_id,
            identity_id=intent.subject.identity_id,
            tenant_id=intent.subject.tenant_id,
            action_kind=action_kind,
            dispatch_nonce=hashlib.sha256(
                f"chain-lease:{label}".encode()
            ).hexdigest()[:32],
        )
        lease = type(base_lease).model_validate(lease_doc)
        effect = EffectRecord(
            schema_version=SCHEMA_VERSION,
            effect_id=f"effect.chain.{target_index}",
            run_id="run.1",
            effect_kind=f"effect.{label}",
            subject=subject,
            resource=resource,
            state=states[target_index],
            observed_at=NOW,
            evidence_refs=(evidence,),
            reversible=True,
            cleanup_receipt_digest=D4,
        )
        edge = ChainEdge(
            schema_version=SCHEMA_VERSION,
            edge_id=f"edge.chain.{label}",
            source_capability_id=f"capability.chain.{source_index}",
            target_capability_id=f"capability.chain.{target_index}",
            preconditions=(f"precondition {label}",),
            input_subject=subject,
            input_resource=resource,
            input_state=states[source_index],
            action_intent=intent,
            action_lease_id=lease.lease_id,
            scope_decision_digest=sha256_digest(decision),
            expected_effect=effect,
            observed_effect=effect,
            evidence_refs=(evidence,),
            negative_control_refs=(evidence,),
            reversible=True,
            cleanup_receipt_digest=D4,
            action_cost=1,
            time_cost_seconds=1,
            confidence_bps=9000,
        )
        edges.append(edge)
        bindings.append(
            EdgeAuthorityBinding(
                binding_id=f"binding.chain.{label}",
                edge_id=edge.edge_id,
                lease=lease,
                decision=decision,
                asset_class=AssetClass.PUBLIC,
                explicitly_granted=True,
                impact_cost=1,
            )
        )

    if spec.redundant_self_loop:
        append_edge(0, 0, "0.self")
    for index in range(1, len(spec.sources)):
        append_edge(index - 1, index, str(index))
    action_policy_doc = base_grant.action_policy.model_dump(mode="python")
    action_policy_doc.update(
        allowed_families=tuple(edge.action_intent.action_kind for edge in edges),
        allowed_methods=("GET",),
        allowed_path_patterns=("/api/*",),
        denied=(),
    )
    grant_doc = base_grant.model_dump(mode="python")
    grant_doc.update(
        pack_ids=tuple(sorted({_pack(item) for item in spec.sources})),
        action_policy=ActionPolicy.model_validate(action_policy_doc),
    )
    grant = AuthorityGrant.model_validate(grant_doc)
    action_budget = max(1, len(edges) + 1)
    graph = ChainGraph(
        schema_version=SCHEMA_VERSION,
        graph_id="chain-graph.fixture",
        run_id="run.1",
        capabilities=registry.capabilities,
        edges=tuple(edges),
        impact_goal="Demonstrate the final inert canary effect.",
        action_budget=action_budget,
        time_budget_seconds=60,
        version=1,
    )
    return BuiltChain(
        registry=registry,
        graph=graph,
        authority=ChainAuthority(grant=grant, edge_bindings=tuple(bindings)),
        settings=ChainSearchSettings(
            start_capability_ids=("capability.chain.0",),
            goal_effect_id=f"effect.chain.{len(spec.sources) - 1}",
            budget=ChainBudget(actions=action_budget, time_seconds=60, impact=action_budget),
        ),
        states=states,
    )


def _pack(source: SourceKind) -> str:
    match source:
        case "identity":
            return "pack.web.identity_workflow"
        case "api":
            return "pack.web.api_async"
        case "patch":
            return "pack.patch_variant"
        case "llm":
            return "pack.llm.synthetic"
        case unreachable:
            assert_never(unreachable)
