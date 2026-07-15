from __future__ import annotations

from collections.abc import Callable

from faultloom_protocol import (
    CallbackLease,
    MessageEnvelope,
    SurfaceGraph,
)

from .contracts import (
    FilePipelineRecord,
    JobAccessAssessment,
    ScopeRevocation,
    SchemaBatch,
    StatefulSequencePlan,
    SurfaceConflictError,
    SurfaceDifferential,
)
from .state_models import SurfaceState


def add_schema(state: SurfaceState, batch: SchemaBatch) -> SurfaceState:
    if any(item.target_id != state.binding.target_id for item in batch.operations):
        raise SurfaceConflictError("schema batch targets another asset")
    operations = _merge_by_id(
        state.graph.operations,
        batch.operations,
        key=lambda item: item.operation_id,
    )
    evidence = _merge_by_id(
        state.graph.schema_evidence,
        (batch.evidence,),
        key=lambda item: item.schema_evidence_id,
    )
    if operations == state.graph.operations and evidence == state.graph.schema_evidence:
        return state
    return _replace_graph(
        state,
        state.graph.model_copy(
            update={
                "operations": operations,
                "schema_evidence": evidence,
                "version": state.graph.version + 1,
            }
        ),
    )


def add_message(state: SurfaceState, message: MessageEnvelope) -> SurfaceState:
    messages = _merge_by_id(state.messages, (message,), key=lambda item: item.message_id)
    if messages == state.messages:
        return state
    return state.model_copy(
        update={"messages": messages, "watermark": state.watermark + 1}
    )


def add_callback_lease(state: SurfaceState, lease: CallbackLease) -> SurfaceState:
    leases = _merge_by_id(
        state.callback_leases,
        (lease,),
        key=lambda item: item.callback_lease_id,
    )
    if leases == state.callback_leases:
        return state
    return state.model_copy(
        update={"callback_leases": leases, "watermark": state.watermark + 1}
    )


def add_job(state: SurfaceState, assessment: JobAccessAssessment) -> SurfaceState:
    records = _merge_by_id(
        state.job_assessments,
        (assessment,),
        key=lambda item: item.assessment_id,
    )
    if records == state.job_assessments:
        return state
    return state.model_copy(
        update={"job_assessments": records, "watermark": state.watermark + 1}
    )


def add_file(state: SurfaceState, record: FilePipelineRecord) -> SurfaceState:
    records = _merge_by_id(
        state.file_pipelines,
        (record,),
        key=lambda item: item.record_id,
    )
    if records == state.file_pipelines:
        return state
    return state.model_copy(
        update={"file_pipelines": records, "watermark": state.watermark + 1}
    )


def add_plan(state: SurfaceState, plan: StatefulSequencePlan) -> SurfaceState:
    if plan.run_id != state.binding.run_id:
        raise SurfaceConflictError("sequence plan belongs to another run")
    known = {item.operation_id for item in state.graph.operations}
    if any(item not in known for item in plan.baseline_operation_ids):
        raise SurfaceConflictError("sequence plan references an unknown operation")
    plans = _merge_by_id(state.sequence_plans, (plan,), key=lambda item: item.plan_id)
    if plans == state.sequence_plans:
        return state
    return state.model_copy(
        update={"sequence_plans": plans, "watermark": state.watermark + 1}
    )


def add_differential(
    state: SurfaceState,
    differential: SurfaceDifferential,
) -> SurfaceState:
    if differential.operation_id not in {
        item.operation_id for item in state.graph.operations
    }:
        raise SurfaceConflictError("differential references an unknown operation")
    records = _merge_by_id(
        state.differentials,
        (differential,),
        key=lambda item: item.differential_id,
    )
    if records == state.differentials:
        return state
    return state.model_copy(
        update={"differentials": records, "watermark": state.watermark + 1}
    )


def revoke_scope(state: SurfaceState, revocation: ScopeRevocation) -> SurfaceState:
    if revocation.scope_epoch != state.binding.scope_epoch:
        raise SurfaceConflictError("scope revocation belongs to another epoch")
    if state.revocation == revocation:
        return state
    if state.revocation is not None:
        raise SurfaceConflictError("scope epoch is already revoked")
    leases = tuple(
        CallbackLease.model_validate(
            item.model_copy(update={"revoked": True}).model_dump(mode="python")
        )
        for item in state.callback_leases
    )
    return state.model_copy(
        update={
            "callback_leases": leases,
            "revocation": revocation,
            "watermark": state.watermark + 1,
        }
    )


def _replace_graph(state: SurfaceState, graph: SurfaceGraph) -> SurfaceState:
    return state.model_copy(update={"graph": graph, "watermark": state.watermark + 1})


def _merge_by_id[RecordT](
    existing: tuple[RecordT, ...],
    incoming: tuple[RecordT, ...],
    *,
    key: Callable[[RecordT], str],
) -> tuple[RecordT, ...]:
    records = {key(item): item for item in existing}
    for item in incoming:
        record_id = key(item)
        prior = records.get(record_id)
        if prior is not None and prior != item:
            raise SurfaceConflictError(f"record ID {record_id!r} is already bound")
        records[record_id] = item
    return tuple(records[item] for item in sorted(records))
