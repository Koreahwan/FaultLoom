from __future__ import annotations

import hashlib
from typing import Literal, assert_never

from faultloom_protocol import (
    AsyncFlow,
    OperationKind,
    SCHEMA_VERSION,
    SurfaceEdge,
    SurfaceGraph,
)

from .contracts import FlowCompletion, FlowStart, SurfaceConflictError
from .state_models import SurfaceState
from .transitions import _merge_by_id, _replace_graph

type EdgeKind = Literal["sequence", "callback", "message", "job", "file", "subscription"]


def start_flow(state: SurfaceState, start: FlowStart) -> SurfaceState:
    operation_ids = {item.operation_id for item in state.graph.operations}
    if any(item not in operation_ids for item in start.flow.operation_ids):
        raise SurfaceConflictError("async flow references an unknown operation")
    if any(item.operation_id not in operation_ids for item in start.follow_ups):
        raise SurfaceConflictError("follow-up references an unknown operation")
    known_leases = {item.callback_lease_id for item in state.callback_leases}
    referenced_leases = {
        item.callback_lease_id
        for item in start.follow_ups
        if item.callback_lease_id is not None
    }
    if not referenced_leases.issubset(known_leases):
        raise SurfaceConflictError("callback follow-up references an unknown lease")
    flows = _merge_by_id(
        state.graph.async_flows,
        (start.flow,),
        key=lambda item: item.async_flow_id,
    )
    follow_ups = _merge_by_id(
        state.follow_ups,
        start.follow_ups,
        key=lambda item: item.follow_up_id,
    )
    if flows == state.graph.async_flows and follow_ups == state.follow_ups:
        return state
    edges = _merge_by_id(
        state.graph.edges,
        _flow_edges(state.graph, start.flow),
        key=lambda item: item.edge_id,
    )
    graph = state.graph.model_copy(
        update={
            "async_flows": flows,
            "edges": edges,
            "version": state.graph.version + 1,
        }
    )
    return _replace_graph(state, graph).model_copy(update={"follow_ups": follow_ups})


def complete_flow(state: SurfaceState, completion: FlowCompletion) -> SurfaceState:
    flow = next(
        (
            item
            for item in state.graph.async_flows
            if item.async_flow_id == completion.async_flow_id
        ),
        None,
    )
    if flow is None:
        raise SurfaceConflictError("async flow is unknown")
    if not flow.pending:
        if completion.effect_id in state.completed_effect_ids:
            return state
        raise SurfaceConflictError("async flow is already complete with another effect")
    if completion.terminal_operation_id not in flow.operation_ids:
        raise SurfaceConflictError("terminal operation is outside the async flow")
    completed = AsyncFlow.model_validate(
        flow.model_copy(
            update={
                "terminal_operation_id": completion.terminal_operation_id,
                "pending": False,
                "completed_at": completion.completed_at,
            }
        ).model_dump(mode="python")
    )
    flows = tuple(
        completed if item.async_flow_id == completion.async_flow_id else item
        for item in state.graph.async_flows
    )
    graph = state.graph.model_copy(
        update={"async_flows": flows, "version": state.graph.version + 1}
    )
    updated = _replace_graph(state, graph)
    return updated.model_copy(
        update={
            "completed_effect_ids": updated.completed_effect_ids
            + (completion.effect_id,)
        }
    )


def _flow_edges(graph: SurfaceGraph, flow: AsyncFlow) -> tuple[SurfaceEdge, ...]:
    operations = {item.operation_id: item for item in graph.operations}
    edges: list[SurfaceEdge] = []
    for source, target in zip(flow.operation_ids, flow.operation_ids[1:], strict=False):
        target_operation = operations[target]
        material = f"{flow.async_flow_id}\0{source}\0{target}".encode()
        edges.append(
            SurfaceEdge(
                schema_version=SCHEMA_VERSION,
                edge_id=f"surface-edge.{hashlib.sha256(material).hexdigest()}",
                source_operation_id=source,
                target_operation_id=target,
                edge_kind=_edge_kind(target_operation.operation_kind),
                correlation_refs=flow.correlation_refs,
            )
        )
    return tuple(edges)


def _edge_kind(kind: OperationKind) -> EdgeKind:
    match kind:
        case (
            OperationKind.REST
            | OperationKind.GRAPHQL_QUERY
            | OperationKind.GRAPHQL_MUTATION
        ):
            return "sequence"
        case OperationKind.GRAPHQL_SUBSCRIPTION:
            return "subscription"
        case OperationKind.WEBSOCKET:
            return "message"
        case OperationKind.WEBHOOK | OperationKind.CALLBACK:
            return "callback"
        case OperationKind.BACKGROUND_JOB:
            return "job"
        case OperationKind.FILE_UPLOAD | OperationKind.FILE_DOWNLOAD:
            return "file"
        case unreachable:
            assert_never(unreachable)
