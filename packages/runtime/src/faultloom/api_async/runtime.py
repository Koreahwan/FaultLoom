from __future__ import annotations

from typing import assert_never

from faultloom.state import StateStore
from faultloom_protocol import CallbackLease, FilePipeline, MessageEnvelope
from faultloom_protocol.base import AwareDatetime

from .contracts import (
    CallbackAdmission,
    FilePipelineRecord,
    FlowCompletion,
    FlowStart,
    FollowUpAction,
    FollowUpKind,
    InertFileCanary,
    JobAccessProbe,
    ScopeRevocation,
    SchemaBatch,
    SequencePlanRequest,
    StatefulSequencePlan,
    SurfaceBinding,
    SurfaceConflictError,
    SurfaceDifferential,
    SurfacePolicyError,
    UndocumentedObservation,
)
from .durable import append_state, bind_surface, replay_surface
from .flow_transitions import complete_flow, start_flow
from .policies import (
    assess_job_access,
    plan_stateful_sequence,
    require_callback_eligible,
    validate_file_pipeline,
)
from .schema import SchemaSource, ingest_graphql_sdl, ingest_openapi, undocumented_batch
from .state_models import SurfaceState, empty_surface_state
from .transitions import (
    add_callback_lease,
    add_differential,
    add_file,
    add_job,
    add_message,
    add_plan,
    add_schema,
    revoke_scope,
)


class ApiAsyncSurfaceEngine:
    def __init__(self, store: StateStore, binding: SurfaceBinding) -> None:
        self._store = store
        self._binding = binding

    @classmethod
    def open(
        cls,
        store: StateStore,
        binding: SurfaceBinding,
    ) -> ApiAsyncSurfaceEngine:
        bind_surface(store, binding)
        return cls(store, binding)

    @property
    def state(self) -> SurfaceState:
        replay = replay_surface(self._store, self._binding.run_id)
        if replay.binding != self._binding:
            raise SurfaceConflictError("surface runtime binding differs from durable state")
        return replay.state or empty_surface_state(self._binding)

    def ingest_openapi(self, raw: bytes, source: SchemaSource) -> SchemaBatch:
        batch = ingest_openapi(raw, source)
        self._commit(add_schema(self.state, batch), source.observed_at)
        return batch

    def ingest_graphql(self, raw: bytes, source: SchemaSource) -> SchemaBatch:
        batch = ingest_graphql_sdl(raw, source)
        self._commit(add_schema(self.state, batch), source.observed_at)
        return batch

    def observe_undocumented(self, observation: UndocumentedObservation) -> SchemaBatch:
        batch = undocumented_batch(observation)
        self._commit(add_schema(self.state, batch), observation.observed_at)
        return batch

    def begin_flow(self, start: FlowStart) -> None:
        self._commit(start_flow(self.state, start), start.flow.initiated_at)

    def finish_flow(self, completion: FlowCompletion) -> None:
        self._commit(complete_flow(self.state, completion), completion.completed_at)

    def observe_message(self, message: MessageEnvelope) -> None:
        self._commit(add_message(self.state, message), message.observed_at)

    def issue_callback_lease(self, lease: CallbackLease) -> None:
        state = self.state
        require_callback_eligible(
            CallbackAdmission(
                binding=self._binding,
                lease=lease,
                observed_at=lease.issued_at,
                scope_active=state.revocation is None,
            )
        )
        self._commit(add_callback_lease(state, lease), lease.issued_at)

    def admit_callback(
        self,
        callback_lease_id: str,
        observed_at: AwareDatetime,
    ) -> CallbackLease:
        state = self.state
        lease = next(
            (
                item
                for item in state.callback_leases
                if item.callback_lease_id == callback_lease_id
            ),
            None,
        )
        if lease is None:
            raise SurfacePolicyError("callback lease is unknown")
        return require_callback_eligible(
            CallbackAdmission(
                binding=self._binding,
                lease=lease,
                observed_at=observed_at,
                scope_active=state.revocation is None,
            )
        )

    def observe_job(self, probe: JobAccessProbe) -> None:
        assessment = assess_job_access(probe)
        self._commit(add_job(self.state, assessment), probe.observation.observed_at)

    def observe_file_pipeline(
        self,
        canary: InertFileCanary,
        pipeline: FilePipeline,
    ) -> FilePipelineRecord:
        record = validate_file_pipeline(canary, pipeline)
        if not pipeline.stages:
            raise SurfacePolicyError("file pipeline requires at least one observed stage")
        self._commit(add_file(self.state, record), pipeline.stages[-1].observed_at)
        return record

    def plan_sequence(
        self,
        request: SequencePlanRequest,
    ) -> StatefulSequencePlan:
        plan = plan_stateful_sequence(
            request,
            self._binding.run_id,
        )
        self._commit(add_plan(self.state, plan), request.created_at)
        return plan

    def observe_differential(self, differential: SurfaceDifferential) -> None:
        self._commit(
            add_differential(self.state, differential),
            differential.observed_at,
        )

    def revoke(self, revocation: ScopeRevocation) -> None:
        self._commit(revoke_scope(self.state, revocation), revocation.revoked_at)

    def eligible_follow_ups(self, observed_at: AwareDatetime) -> tuple[FollowUpAction, ...]:
        state = self.state
        if state.revocation is not None:
            return ()
        pending_ids = {
            item.async_flow_id for item in state.graph.async_flows if item.pending
        }
        eligible: list[FollowUpAction] = []
        for action in state.follow_ups:
            if action.async_flow_id not in pending_ids:
                continue
            match action.kind:
                case FollowUpKind.POLL | FollowUpKind.WEBSOCKET:
                    eligible.append(action)
                case FollowUpKind.CALLBACK:
                    lease_id = action.callback_lease_id
                    if lease_id is None:
                        raise SurfacePolicyError("callback follow-up has no lease")
                    try:
                        self.admit_callback(lease_id, observed_at)
                    except SurfacePolicyError:
                        continue
                    eligible.append(action)
                case unreachable:
                    assert_never(unreachable)
        return tuple(eligible)

    def authorize_follow_up(
        self,
        action: FollowUpAction,
        observed_at: AwareDatetime,
    ) -> FollowUpAction:
        if action not in self.eligible_follow_ups(observed_at):
            raise SurfacePolicyError("follow-up is not eligible under the current scope")
        return action

    def _commit(self, state: SurfaceState, recorded_at: AwareDatetime) -> None:
        append_state(self._store, state, recorded_at)
