"""Workflow trace mining, invariant synthesis, and race hypotheses."""

from __future__ import annotations

from collections import defaultdict
from enum import StrEnum
from typing import Literal, Self, assert_never

from pydantic import Field, model_validator

from faultloom_protocol import (
    EvidenceRef,
    SCHEMA_VERSION,
    TransitionRecord,
    WorkflowGraph,
    WorkflowState,
)
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest

from ._base import IdentityWorkflowModel
from .errors import IdentityWorkflowError
from .sessions import IdentitySessionVault


class WorkflowKind(StrEnum):
    INVITE = "invite"
    ADMIN = "admin"
    BILLING = "billing"
    WORKSPACE = "workspace"
    RECOVERY = "recovery"
    MFA = "mfa"
    APPROVAL = "approval"
    OTHER = "other"


class WorkflowInvariantKind(StrEnum):
    TENANT_ISOLATION = "tenant_isolation"
    INVITE_LIFECYCLE = "invite_lifecycle"
    ROLE_ESCALATION = "role_escalation"
    BILLING_ADMIN_SEPARATION = "billing_admin_separation"
    RECOVERY_REQUIRES_MFA = "recovery_requires_mfa"
    SESSION_REVOCATION = "session_revocation"
    WORKFLOW_ORDER = "workflow_order"


class WorkflowTraceStep(IdentityWorkflowModel):
    transition_id: Identifier
    workflow_id: Identifier
    from_state_id: Identifier
    to_state_id: Identifier
    ui_action_id: Identifier
    backend_operation_id: Identifier
    identity_context_id: Identifier
    occurred_at: AwareDatetime
    action_intent_digest: Sha256Digest
    dispatch_receipt_digest: Sha256Digest
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class WorkflowTrace(IdentityWorkflowModel):
    graph_id: Identifier
    run_id: Identifier
    workflow_id: Identifier
    workflow_kind: WorkflowKind
    states: tuple[WorkflowState, ...] = Field(min_length=2)
    steps: tuple[WorkflowTraceStep, ...] = Field(min_length=1)
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def _is_closed_and_ordered(self) -> Self:
        state_ids = {state.workflow_state_id for state in self.states}
        if len(state_ids) != len(self.states):
            raise IdentityWorkflowError(
                code="workflow.state_reused",
                detail="workflow state IDs must be unique",
            )
        transition_ids = {step.transition_id for step in self.steps}
        if len(transition_ids) != len(self.steps):
            raise IdentityWorkflowError(
                code="workflow.transition_reused",
                detail="workflow transition IDs must be unique",
            )
        if any(state.workflow_id != self.workflow_id for state in self.states):
            raise IdentityWorkflowError(
                code="workflow.state_foreign",
                detail="workflow states must identify the traced workflow",
            )
        if any(
            step.workflow_id != self.workflow_id
            or step.from_state_id not in state_ids
            or step.to_state_id not in state_ids
            for step in self.steps
        ):
            raise IdentityWorkflowError(
                code="workflow.transition_dangling",
                detail="workflow transitions must connect traced states",
            )
        ordered = tuple(sorted(self.steps, key=lambda step: (step.occurred_at, step.transition_id)))
        if tuple(self.steps) != ordered:
            raise IdentityWorkflowError(
                code="workflow.trace_unordered",
                detail="workflow trace steps must be chronologically ordered",
            )
        if any(
            evidence.run_id != self.run_id
            for step in self.steps
            for evidence in step.evidence_refs
        ):
            raise IdentityWorkflowError(
                code="workflow.evidence_foreign",
                detail="workflow evidence must belong to the traced run",
            )
        return self


class WorkflowInvariant(IdentityWorkflowModel):
    invariant_id: Identifier
    workflow_id: Identifier
    kind: WorkflowInvariantKind


class OperationBinding(IdentityWorkflowModel):
    transition_id: Identifier
    ui_action_id: Identifier
    backend_operation_id: Identifier


class WorkflowMiningResult(IdentityWorkflowModel):
    graph: WorkflowGraph
    invariants: tuple[WorkflowInvariant, ...]
    operation_bindings: tuple[OperationBinding, ...]


class RaceHypothesis(IdentityWorkflowModel):
    hypothesis_id: Identifier
    workflow_graph_id: Identifier
    from_state_id: Identifier
    transition_ids: tuple[Identifier, ...] = Field(min_length=2)
    invariant_id: Identifier
    execution_contract: Literal["semantic_parallel_only"] = "semantic_parallel_only"
    single_packet_supported: Literal[False] = False


class WorkflowMiner:
    def __init__(self, vault: IdentitySessionVault) -> None:
        self._vault = vault

    def mine(self, trace: WorkflowTrace) -> WorkflowMiningResult:
        for step in trace.steps:
            self._vault.registration(step.identity_context_id)
        invariants = synthesize_invariants(trace.workflow_id, trace.workflow_kind)
        transitions = tuple(
            TransitionRecord(
                schema_version=SCHEMA_VERSION,
                transition_id=step.transition_id,
                workflow_id=step.workflow_id,
                from_state_id=step.from_state_id,
                to_state_id=step.to_state_id,
                operation_id=step.backend_operation_id,
                identity_context_id=step.identity_context_id,
                occurred_at=step.occurred_at,
                action_intent_digest=step.action_intent_digest,
                dispatch_receipt_digest=step.dispatch_receipt_digest,
                evidence_refs=step.evidence_refs,
            )
            for step in trace.steps
        )
        graph = WorkflowGraph(
            schema_version=SCHEMA_VERSION,
            graph_id=trace.graph_id,
            run_id=trace.run_id,
            workflow_kind=trace.workflow_kind.value,
            states=tuple(sorted(trace.states, key=lambda state: state.workflow_state_id)),
            transitions=transitions,
            invariant_ids=tuple(invariant.invariant_id for invariant in invariants),
            version=trace.version,
        )
        bindings = tuple(
            OperationBinding(
                transition_id=step.transition_id,
                ui_action_id=step.ui_action_id,
                backend_operation_id=step.backend_operation_id,
            )
            for step in trace.steps
        )
        return WorkflowMiningResult(
            graph=graph,
            invariants=invariants,
            operation_bindings=bindings,
        )


def synthesize_invariants(
    workflow_id: Identifier,
    kind: WorkflowKind,
) -> tuple[WorkflowInvariant, ...]:
    match kind:
        case WorkflowKind.INVITE:
            kinds = (
                WorkflowInvariantKind.TENANT_ISOLATION,
                WorkflowInvariantKind.INVITE_LIFECYCLE,
            )
        case WorkflowKind.ADMIN:
            kinds = (
                WorkflowInvariantKind.TENANT_ISOLATION,
                WorkflowInvariantKind.ROLE_ESCALATION,
            )
        case WorkflowKind.BILLING:
            kinds = (WorkflowInvariantKind.BILLING_ADMIN_SEPARATION,)
        case WorkflowKind.RECOVERY:
            kinds = (
                WorkflowInvariantKind.RECOVERY_REQUIRES_MFA,
                WorkflowInvariantKind.SESSION_REVOCATION,
            )
        case WorkflowKind.MFA:
            kinds = (WorkflowInvariantKind.RECOVERY_REQUIRES_MFA,)
        case WorkflowKind.APPROVAL:
            kinds = (WorkflowInvariantKind.WORKFLOW_ORDER,)
        case WorkflowKind.WORKSPACE | WorkflowKind.OTHER:
            kinds = (WorkflowInvariantKind.TENANT_ISOLATION,)
        case unreachable:
            assert_never(unreachable)
    return tuple(
        WorkflowInvariant(
            invariant_id=f"invariant.{workflow_id}.{invariant_kind.value}",
            workflow_id=workflow_id,
            kind=invariant_kind,
        )
        for invariant_kind in kinds
    )


def race_hypotheses(result: WorkflowMiningResult) -> tuple[RaceHypothesis, ...]:
    grouped: defaultdict[str, list[TransitionRecord]] = defaultdict(list)
    for transition in result.graph.transitions:
        grouped[transition.from_state_id].append(transition)
    fallback_invariant = result.graph.invariant_ids[0]
    hypotheses: list[RaceHypothesis] = []
    for state_id, transitions in sorted(grouped.items()):
        destinations = {transition.to_state_id for transition in transitions}
        if len(transitions) < 2 or len(destinations) < 2:
            continue
        transition_ids = tuple(sorted(item.transition_id for item in transitions))
        hypotheses.append(
            RaceHypothesis(
                hypothesis_id=f"race.{result.graph.graph_id}.{state_id}",
                workflow_graph_id=result.graph.graph_id,
                from_state_id=state_id,
                transition_ids=transition_ids,
                invariant_id=fallback_invariant,
            )
        )
    return tuple(hypotheses)
