"""Narrow Gateway-only execution bridge for admitted automation plans."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from faultloom._research_durable import (
    EncryptedEventSpec,
    append_encrypted,
    durable_events,
    load_encrypted,
)
from faultloom.execution import (
    DispatchUncertainError,
    ExecutionContractError,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
    LocalDispatchState,
    SemanticHttpExecutor,
)
from faultloom.state import ArtifactRef, EventRecord, StateStore, StorageError
from faultloom.tool_planner import ToolPlanItem
from faultloom_protocol import Ed25519PublicKeyRecord, sha256_digest
from faultloom_protocol.models import (
    ActionClass,
    DispatchOutcome,
    EgressPlane,
    EvidenceRef,
    ObservationRef,
)
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest

from .admission import SignedAutomationAdmission, verify_automation_admission
from .models import AuthorizedAutomationResult


AUTOMATION_DISPATCH_ACTOR_STREAM = "automation.dispatch"
AUTOMATION_DISPATCH_EVENT_TYPE = "automation.dispatch.v1"
AUTOMATION_DISPATCH_MEDIA_TYPE = "application/vnd.faultloom.automation-dispatch+json"


class AutomationDispatchError(ValueError):
    """An admitted candidate cannot be bound safely to a live command."""


class _DispatchModel(BaseModel):
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class AutomationDispatchRecord(_DispatchModel):
    """One non-retrying Gateway presentation and its authoritative outcome."""

    dispatch_id: Identifier
    run_id: Identifier
    candidate_id: Identifier
    action_id: Identifier
    lease_id: Identifier
    requested_at: AwareDatetime
    command_digest: Sha256Digest
    result_digest: Sha256Digest
    admission: SignedAutomationAdmission
    gateway_result: GatewayResult | None = None
    status: Literal["completed", "denied", "unknown_requires_reconciliation"]
    target_dispatch_performed: bool | None
    automatic_submission_performed: Literal[False] = False
    independent_verification_performed: Literal[False] = False

    @model_validator(mode="after")
    def _digest_and_identity_are_exact(self) -> Self:
        result = self.admission.payload.result
        if self.result_digest != _result_digest(result):
            raise AutomationDispatchError("dispatch result digest mismatch")
        if self.dispatch_id != _dispatch_id(self.command_digest, self.result_digest):
            raise AutomationDispatchError("dispatch ID is not command/result bound")
        selected = _selected_item(result, self.candidate_id)
        if selected.candidate.intent.action_id != self.action_id:
            raise AutomationDispatchError("dispatch action does not match its selected candidate")
        if selected.candidate.intent.requested_at != self.requested_at:
            raise AutomationDispatchError("dispatch timestamp does not match its selected candidate")
        if self.gateway_result is None:
            if self.status != "unknown_requires_reconciliation":
                raise AutomationDispatchError("missing Gateway result requires reconciliation")
        elif isinstance(self.gateway_result, GatewayDeniedResult):
            if self.status != "denied":
                raise AutomationDispatchError("Gateway denial has the wrong dispatch status")
            if self.gateway_result.action_id != self.action_id:
                raise AutomationDispatchError("Gateway denial belongs to another action")
        else:
            expected = (
                "completed"
                if self.gateway_result.receipt.outcome is DispatchOutcome.COMPLETED
                else "unknown_requires_reconciliation"
            )
            if self.status != expected:
                raise AutomationDispatchError("Gateway outcome has the wrong dispatch status")
            if (
                self.gateway_result.receipt.action_id != self.action_id
                or self.gateway_result.receipt.lease_id != self.lease_id
            ):
                raise AutomationDispatchError(
                    "Gateway receipt belongs to another action or lease"
                )
        expected_dispatch = (
            True if self.status == "completed" else False if self.status == "denied" else None
        )
        if self.target_dispatch_performed is not expected_dispatch:
            raise AutomationDispatchError("target-dispatch fact differs from Gateway status")
        return self


class AutomationDispatchEnvelope(_DispatchModel):
    dispatch_id: Identifier
    dispatch_digest: Sha256Digest
    record: AutomationDispatchRecord

    @model_validator(mode="after")
    def _record_is_bound(self) -> Self:
        if self.dispatch_digest != _record_digest(self.record):
            raise AutomationDispatchError("dispatch envelope digest mismatch")
        if self.dispatch_id != self.record.dispatch_id:
            raise AutomationDispatchError("dispatch envelope belongs to another record")
        return self


class AutomationDispatchPersistence(_DispatchModel):
    """The one encrypted aggregate event and raw, non-disclosed references."""

    envelope: AutomationDispatchEnvelope
    event: EventRecord
    observation_ref: ObservationRef
    evidence_ref: EvidenceRef

    @model_validator(mode="after")
    def _references_are_the_same_raw_aggregate(self) -> Self:
        if self.event.actor_stream != AUTOMATION_DISPATCH_ACTOR_STREAM:
            raise AutomationDispatchError("dispatch event actor is invalid")
        if self.event.event_type != AUTOMATION_DISPATCH_EVENT_TYPE:
            raise AutomationDispatchError("dispatch event type is invalid")
        if self.observation_ref.run_id != self.envelope.record.run_id:
            raise AutomationDispatchError("dispatch observation belongs to another run")
        if self.evidence_ref.run_id != self.envelope.record.run_id:
            raise AutomationDispatchError("dispatch evidence belongs to another run")
        if self.evidence_ref.redaction_digest is not None:
            raise AutomationDispatchError("dispatch evidence must remain raw and unredacted")
        if self.evidence_ref.observation_ids != (self.observation_ref.observation_id,):
            raise AutomationDispatchError("dispatch evidence is not bound to its observation")
        if self.evidence_ref.cas_digest != self.observation_ref.cas_digest:
            raise AutomationDispatchError("dispatch evidence and observation differ")
        return self


def execute_admitted_tool_plan(
    *,
    admission: SignedAutomationAdmission,
    trusted_admission_keys: dict[str, Ed25519PublicKeyRecord],
    trusted_clock: Callable[[], datetime],
    candidate_id: str,
    command: GatewayDispatchCommand,
    executor: SemanticHttpExecutor,
) -> AutomationDispatchRecord:
    """Present exactly one fully bound admitted semantic plan to the Gateway.

    This function neither performs target I/O itself nor retries a Gateway
    presentation.  An uncertain presentation is represented durably as needing
    explicit reconciliation.
    """

    _validate_inputs(admission, command, executor, trusted_clock)
    admitted = verify_automation_admission(
        admission,
        trusted_admission_keys,
        verification_time=trusted_clock(),
    )
    result = admitted.result
    item = _selected_item(result, candidate_id)
    _validate_binding(result, item, command)
    command_digest = _command_digest(command)
    result_digest = _result_digest(result)
    previous_state = executor.state_for(command.intent.action_id)
    try:
        gateway_result = executor.execute(command)
    except DispatchUncertainError:
        if previous_state is not None:
            raise
        return _record(
            admission=admission,
            result=result,
            item=item,
            command=command,
            command_digest=command_digest,
            result_digest=result_digest,
            gateway_result=None,
            status="unknown_requires_reconciliation",
        )
    except ExecutionContractError:
        if (
            previous_state is not None
            or executor.state_for(command.intent.action_id) is not LocalDispatchState.UNKNOWN
        ):
            raise
        return _record(
            admission=admission,
            result=result,
            item=item,
            command=command,
            command_digest=command_digest,
            result_digest=result_digest,
            gateway_result=None,
            status="unknown_requires_reconciliation",
        )
    return _record(
        admission=admission,
        result=result,
        item=item,
        command=command,
        command_digest=command_digest,
        result_digest=result_digest,
        gateway_result=gateway_result,
        status=_status_for(gateway_result),
    )


def persist_automation_dispatch(
    store: StateStore,
    record: AutomationDispatchRecord,
) -> AutomationDispatchPersistence:
    """Atomically create or return one encrypted, idempotent dispatch aggregate."""

    if type(store) is not StateStore:
        raise TypeError("dispatch persistence requires an exact state store")
    if type(record) is not AutomationDispatchRecord:
        raise TypeError("dispatch persistence requires an exact dispatch record")
    exact = AutomationDispatchRecord.model_validate(record.model_dump(mode="python"))
    envelope = AutomationDispatchEnvelope(
        dispatch_id=exact.dispatch_id,
        dispatch_digest=_record_digest(exact),
        record=exact,
    )
    spec = _spec(exact.run_id, exact.dispatch_id)
    with store.serialized():
        for event in durable_events(store):
            if (
                event.actor_stream != AUTOMATION_DISPATCH_ACTOR_STREAM
                or event.event_type != AUTOMATION_DISPATCH_EVENT_TYPE
            ):
                continue
            prior = _load_envelope(store, event, spec)
            if prior.dispatch_id != envelope.dispatch_id:
                continue
            if prior != envelope:
                raise StorageError("dispatch ID is bound to different bytes")
            return _persistence(event, prior)
        event = append_encrypted(store, envelope, spec)
        return _persistence(event, envelope)


def load_automation_dispatch(
    store: StateStore,
    event: EventRecord,
) -> AutomationDispatchEnvelope:
    """Load and revalidate an encrypted dispatch aggregate."""

    if type(store) is not StateStore or type(event) is not EventRecord:
        raise TypeError("dispatch load requires an exact store and event")
    return _load_envelope(store, event, _spec("placeholder.run", "placeholder.dispatch"))


def load_authenticated_automation_dispatch(
    store: StateStore,
    *,
    dispatch_id: str,
    command: GatewayDispatchCommand,
    trusted_admission_keys: dict[str, Ed25519PublicKeyRecord],
) -> AutomationDispatchPersistence:
    """Load one ledger-backed dispatch authenticated at its Gateway receipt time."""

    if type(store) is not StateStore:
        raise TypeError("dispatch provenance requires an exact state store")
    if type(dispatch_id) is not str:
        raise TypeError("dispatch provenance requires a dispatch ID")
    if type(command) is not GatewayDispatchCommand:
        raise TypeError("dispatch provenance requires an exact Gateway command")
    matches: list[tuple[EventRecord, AutomationDispatchEnvelope]] = []
    with store.serialized():
        for event in durable_events(store):
            if (
                event.actor_stream != AUTOMATION_DISPATCH_ACTOR_STREAM
                or event.event_type != AUTOMATION_DISPATCH_EVENT_TYPE
            ):
                continue
            envelope = _load_envelope(store, event, _spec("placeholder.run", "placeholder"))
            if envelope.dispatch_id == dispatch_id:
                matches.append((event, envelope))
    if len(matches) != 1:
        raise StorageError("dispatch provenance must resolve to exactly one ledger event")
    event, envelope = matches[0]
    record = envelope.record
    if record.command_digest != _command_digest(command):
        raise AutomationDispatchError("dispatch provenance command digest differs from exact command")
    receipt_time = _completed_receipt_time(record, command)
    admitted = verify_automation_admission(
        record.admission,
        trusted_admission_keys,
        verification_time=receipt_time,
    )
    if admitted != record.admission.payload or admitted.result != record.admission.payload.result:
        raise AutomationDispatchError("dispatch provenance admission payload is not exact")
    return _persistence(event, envelope)


def _completed_receipt_time(
    record: AutomationDispatchRecord,
    command: GatewayDispatchCommand,
) -> datetime:
    gateway_result = record.gateway_result
    if (
        record.status != "completed"
        or record.target_dispatch_performed is not True
        or type(gateway_result) is not GatewayDispatchResult
    ):
        raise AutomationDispatchError(
            "dispatch provenance requires a completed Gateway receipt"
        )
    receipt = gateway_result.receipt
    if (
        receipt.action_id != command.intent.action_id
        or receipt.lease_id != command.lease.lease_id
        or receipt.intent_digest != command.intent_digest
        or receipt.decision_digest != command.decision_digest
        or receipt.scope_epoch != command.lease.scope_epoch
    ):
        raise AutomationDispatchError(
            "dispatch provenance Gateway receipt is not bound to the exact command"
        )
    if not command.lease.issued_at <= receipt.dispatched_at < command.lease.expires_at:
        raise AutomationDispatchError(
            "dispatch provenance Gateway receipt is outside the command lease window"
        )
    return receipt.dispatched_at


def _validate_inputs(
    admission: SignedAutomationAdmission,
    command: GatewayDispatchCommand,
    executor: SemanticHttpExecutor,
    trusted_clock: Callable[[], datetime],
) -> None:
    if type(admission) is not SignedAutomationAdmission:
        raise TypeError("dispatch requires an exact signed automation admission")
    if type(command) is not GatewayDispatchCommand:
        raise TypeError("dispatch requires an exact Gateway command")
    if type(executor) is not SemanticHttpExecutor:
        raise TypeError("dispatch requires an exact semantic HTTP executor")
    if not callable(trusted_clock):
        raise TypeError("dispatch requires a trusted clock")


def _selected_item(result: AuthorizedAutomationResult, candidate_id: str) -> ToolPlanItem:
    items = tuple(
        plan.selected
        for plan in result.admitted_plans
        if plan.selected.candidate.candidate_id == candidate_id
    )
    if len(items) != 1:
        raise AutomationDispatchError("dispatch candidate must select exactly one admitted plan")
    return items[0]


def _validate_binding(
    result: AuthorizedAutomationResult,
    item: ToolPlanItem,
    command: GatewayDispatchCommand,
) -> None:
    if item.receipt.authority_digest != result.authority_grant_digest:
        raise AutomationDispatchError("tool-plan receipt authority digest differs from result")
    if item.candidate.intent.payload_digest is None:
        raise AutomationDispatchError("live tool plan requires a semantic payload digest")
    if item.candidate.intent != command.intent:
        raise AutomationDispatchError("admitted candidate intent differs from Gateway command")
    if item.candidate.intent.action_class not in {ActionClass.OBSERVE, ActionClass.SAFE_PROBE}:
        raise AutomationDispatchError("only observe and safe_probe plans may be dispatched")
    if command.lease.egress_plane is not EgressPlane.TARGET_GATEWAY:
        raise AutomationDispatchError("dispatch must use the target Gateway egress plane")
    grant_id, grant_version = _result_grant(result)
    if (
        command.decision.grant_id != grant_id
        or command.lease.grant_id != grant_id
        or command.decision.grant_version != grant_version
        or command.lease.grant_version != grant_version
    ):
        raise AutomationDispatchError("Gateway decision and lease must bind the result grant")


def _result_grant(result: AuthorizedAutomationResult) -> tuple[str, int]:
    return result.authority_grant_id, result.authority_grant_version


def _record(
    *,
    admission: SignedAutomationAdmission,
    result: AuthorizedAutomationResult,
    item: ToolPlanItem,
    command: GatewayDispatchCommand,
    command_digest: str,
    result_digest: str,
    gateway_result: GatewayResult | None,
    status: Literal["completed", "denied", "unknown_requires_reconciliation"],
) -> AutomationDispatchRecord:
    return AutomationDispatchRecord(
        dispatch_id=_dispatch_id(command_digest, result_digest),
        run_id=result.run_id,
        candidate_id=item.candidate.candidate_id,
        action_id=command.intent.action_id,
        lease_id=command.lease.lease_id,
        requested_at=item.candidate.intent.requested_at,
        command_digest=command_digest,
        result_digest=result_digest,
        admission=admission,
        gateway_result=gateway_result,
        status=status,
        target_dispatch_performed=(
            True if status == "completed" else False if status == "denied" else None
        ),
        automatic_submission_performed=False,
        independent_verification_performed=False,
    )


def _status_for(
    gateway_result: GatewayResult,
) -> Literal["completed", "denied", "unknown_requires_reconciliation"]:
    if isinstance(gateway_result, GatewayDeniedResult):
        return "denied"
    if gateway_result.receipt.outcome is DispatchOutcome.COMPLETED:
        return "completed"
    return "unknown_requires_reconciliation"


def _persistence(
    event: EventRecord,
    envelope: AutomationDispatchEnvelope,
) -> AutomationDispatchPersistence:
    reference = _artifact_reference(event)
    record = envelope.record
    observation = ObservationRef(
        schema_version="0.1.0",
        observation_id=f"automation-dispatch-observation.{record.dispatch_id}",
        run_id=record.run_id,
        cas_digest="sha256:" + reference.sha256,
        media_type=AUTOMATION_DISPATCH_MEDIA_TYPE,
        byte_length=reference.byte_length,
        created_at=_created_at(record),
    )
    evidence = EvidenceRef(
        schema_version="0.1.0",
        evidence_id=f"automation-dispatch-evidence.{record.dispatch_id}",
        run_id=record.run_id,
        cas_digest="sha256:" + reference.sha256,
        observation_ids=(observation.observation_id,),
        redaction_digest=None,
        created_at=_created_at(record),
    )
    return AutomationDispatchPersistence(
        envelope=envelope,
        event=event,
        observation_ref=observation,
        evidence_ref=evidence,
    )


def _created_at(record: AutomationDispatchRecord) -> datetime:
    gateway_result = record.gateway_result
    if isinstance(gateway_result, GatewayDispatchResult):
        return gateway_result.receipt.dispatched_at
    return record.requested_at


def _artifact_reference(event: EventRecord) -> ArtifactRef:
    value = event.payload.get("artifact_ref")
    if type(value) is not dict:
        raise StorageError("dispatch event artifact reference is invalid")
    return ArtifactRef.from_dict(value)  # pyright: ignore[reportUnknownArgumentType]


def _load_envelope(
    store: StateStore,
    event: EventRecord,
    spec: EncryptedEventSpec,
) -> AutomationDispatchEnvelope:
    try:
        return AutomationDispatchEnvelope.model_validate_json(load_encrypted(store, event, spec))
    except Exception as exc:
        if isinstance(exc, StorageError):
            raise
        raise StorageError("dispatch artifact is invalid") from exc


def _command_digest(command: GatewayDispatchCommand) -> str:
    return sha256_digest(command.model_dump(mode="json"))


def _result_digest(result: AuthorizedAutomationResult) -> str:
    return sha256_digest(result.model_dump(mode="json"))


def _record_digest(record: AutomationDispatchRecord) -> str:
    return sha256_digest(record.model_dump(mode="json"))


def _dispatch_id(command_digest: str, result_digest: str) -> str:
    return "automation-dispatch." + sha256_digest(
        {"command_digest": command_digest, "result_digest": result_digest}
    ).removeprefix("sha256:")


def _spec(run_id: str, dispatch_id: str) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_DISPATCH_ACTOR_STREAM,
        event_type=AUTOMATION_DISPATCH_EVENT_TYPE,
        media_type=AUTOMATION_DISPATCH_MEDIA_TYPE,
        run_id=run_id,
        record_id=dispatch_id,
    )


__all__ = [
    "AUTOMATION_DISPATCH_ACTOR_STREAM",
    "AUTOMATION_DISPATCH_EVENT_TYPE",
    "AUTOMATION_DISPATCH_MEDIA_TYPE",
    "AutomationDispatchEnvelope",
    "AutomationDispatchError",
    "AutomationDispatchPersistence",
    "AutomationDispatchRecord",
    "execute_admitted_tool_plan",
    "load_automation_dispatch",
    "load_authenticated_automation_dispatch",
    "persist_automation_dispatch",
]
