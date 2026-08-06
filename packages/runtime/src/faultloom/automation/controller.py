"""One-shot controller for admitted Gateway automation dispatches."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from faultloom._research_durable import (
    EncryptedEventSpec,
    append_encrypted,
    durable_events,
    load_encrypted,
)
from faultloom.execution import GatewayDispatchCommand, SemanticHttpExecutor
from faultloom.state import StateStore, StorageError
from faultloom_protocol import Ed25519PublicKeyRecord
from faultloom_protocol.base import Identifier, ShortStr

from .admission import SignedAutomationAdmission
from .execution_bridge import (
    AUTOMATION_DISPATCH_ACTOR_STREAM,
    AUTOMATION_DISPATCH_EVENT_TYPE,
    AutomationDispatchError,
    AutomationDispatchPersistence,
    PreparedAutomationDispatch,
    execute_admitted_tool_plan,
    load_automation_dispatch_persistence,
    persist_automation_dispatch,
    prepare_admitted_tool_plan,
    unknown_automation_dispatch_record,
)


AUTOMATION_DISPATCH_RESERVATION_ACTOR_STREAM = "automation.dispatch.reservation"
AUTOMATION_DISPATCH_RESERVATION_EVENT_TYPE = "automation.dispatch.reservation.v1"
AUTOMATION_DISPATCH_RESERVATION_MEDIA_TYPE = (
    "application/vnd.faultloom.automation-dispatch-reservation+json"
)
AUTOMATION_CAMPAIGN_CONTROL_ACTOR_STREAM = "automation.campaign.control"
AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE = "automation.campaign.control.v1"
AUTOMATION_CAMPAIGN_CONTROL_MEDIA_TYPE = (
    "application/vnd.faultloom.automation-campaign-control+json"
)


class CampaignControlError(AutomationDispatchError):
    """A campaign control record cannot safely authorize a dispatch."""


class CampaignRevokedError(CampaignControlError):
    """A sticky emergency stop blocks a new Gateway presentation."""


class CampaignControl(BaseModel):
    """A sticky emergency stop for one automation run."""

    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    run_id: Identifier
    epoch: int = Field(ge=1)
    revoked: bool
    reason: ShortStr


class AutomationDispatchReservation(BaseModel):
    """Durable controller intent written before any Gateway presentation."""

    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    prepared: PreparedAutomationDispatch


def execute_and_persist_admitted_tool_plan(
    *,
    admission: SignedAutomationAdmission,
    trusted_admission_keys: dict[str, Ed25519PublicKeyRecord],
    trusted_clock: Callable[[], datetime],
    candidate_id: str,
    command: GatewayDispatchCommand,
    executor: SemanticHttpExecutor,
    store: StateStore,
) -> AutomationDispatchPersistence:
    """Reserve, present once, and immediately persist an admitted command.

    A matching final dispatch is returned without presentation.  A matching
    reservation without a final result is sealed as unknown without retrying:
    the earlier process may have died after presentation.
    """

    if type(store) is not StateStore:
        raise TypeError("dispatch controller requires an exact state store")
    prepared = prepare_admitted_tool_plan(
        admission=admission,
        trusted_admission_keys=trusted_admission_keys,
        trusted_clock=trusted_clock,
        candidate_id=candidate_id,
        command=command,
        executor=executor,
    )
    with store.serialized():
        final, reservation = _find_durable_dispatch(store, prepared)
        if final is not None:
            return final
        if reservation is not None:
            return persist_automation_dispatch(
                store, unknown_automation_dispatch_record(reservation.prepared)
            )
        _require_active_campaign(store, run_id=prepared.run_id)
        _persist_reservation(store, AutomationDispatchReservation(prepared=prepared))
        record = execute_admitted_tool_plan(
            admission=admission,
            trusted_admission_keys=trusted_admission_keys,
            trusted_clock=trusted_clock,
            candidate_id=candidate_id,
            command=command,
            executor=executor,
        )
        return persist_automation_dispatch(store, record)


def revoke_campaign(
    *,
    store: StateStore,
    run_id: str,
    epoch: int,
    reason: str,
    revoked: bool = True,
) -> CampaignControl:
    """Persist an irreversible, operator-local campaign emergency stop."""

    if type(store) is not StateStore:
        raise TypeError("campaign control requires an exact state store")
    control = CampaignControl(
        run_id=run_id,
        epoch=epoch,
        revoked=revoked,
        reason=reason,
    )
    if not control.revoked:
        raise CampaignControlError("campaign revocation cannot be cleared")
    with store.serialized():
        previous = _campaign_control(store, run_id=control.run_id)
        if previous is not None:
            if control.epoch < previous.epoch:
                raise CampaignControlError("campaign control epoch rollback was rejected")
            if control.epoch == previous.epoch:
                if control != previous:
                    raise CampaignControlError("campaign control epoch differs from prior record")
                return previous
        append_encrypted(store, control, _campaign_control_spec(control))
    return control


def _require_active_campaign(store: StateStore, *, run_id: str) -> None:
    control = _campaign_control(store, run_id=run_id)
    if control is not None:
        raise CampaignRevokedError(f"campaign is revoked: {control.reason}")


def _campaign_control(
    store: StateStore,
    *,
    run_id: str,
) -> CampaignControl | None:
    controls: list[CampaignControl] = []
    for event in durable_events(store):
        if (
            event.actor_stream != AUTOMATION_CAMPAIGN_CONTROL_ACTOR_STREAM
            or event.event_type != AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE
        ):
            continue
        control = _load_campaign_control(store, event)
        if control.run_id != run_id:
            continue
        if controls:
            previous = controls[-1]
            if control.epoch < previous.epoch:
                raise CampaignControlError("campaign control epoch rollback was rejected")
            if control.epoch == previous.epoch and control != previous:
                raise CampaignControlError("campaign control epoch differs from prior record")
            if previous.revoked and not control.revoked:
                raise CampaignControlError("campaign revocation cannot be cleared")
        if not control.revoked:
            raise CampaignControlError("campaign revocation cannot be cleared")
        controls.append(control)
    return controls[-1] if controls else None


def _find_durable_dispatch(
    store: StateStore,
    prepared: PreparedAutomationDispatch,
) -> tuple[AutomationDispatchPersistence | None, AutomationDispatchReservation | None]:
    finals: list[AutomationDispatchPersistence] = []
    reservations: list[AutomationDispatchReservation] = []
    for event in durable_events(store):
        if (
            event.actor_stream == AUTOMATION_DISPATCH_ACTOR_STREAM
            and event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        ):
            final = load_automation_dispatch_persistence(store, event)
            if final.envelope.record.dispatch_id == prepared.dispatch_id:
                _require_exact_final(final, prepared)
                finals.append(final)
        elif (
            event.actor_stream == AUTOMATION_DISPATCH_RESERVATION_ACTOR_STREAM
            and event.event_type == AUTOMATION_DISPATCH_RESERVATION_EVENT_TYPE
        ):
            reservation = _load_reservation(store, event)
            if reservation.prepared.dispatch_id == prepared.dispatch_id:
                if reservation.prepared != prepared:
                    raise AutomationDispatchError(
                        "durable reservation differs from the prepared dispatch"
                    )
                reservations.append(reservation)
    if len(finals) > 1:
        raise StorageError("dispatch controller found multiple durable dispatches")
    if len(reservations) > 1:
        raise StorageError("dispatch controller found multiple durable reservations")
    return (finals[0] if finals else None, reservations[0] if reservations else None)


def _require_exact_final(
    final: AutomationDispatchPersistence,
    prepared: PreparedAutomationDispatch,
) -> None:
    record = final.envelope.record
    if record.admission != prepared.admission:
        raise AutomationDispatchError("durable dispatch admission differs from request")
    if (
        record.dispatch_id,
        record.run_id,
        record.candidate_id,
        record.action_id,
        record.lease_id,
        record.requested_at,
        record.command_digest,
        record.result_digest,
    ) != (
        prepared.dispatch_id,
        prepared.run_id,
        prepared.candidate_id,
        prepared.action_id,
        prepared.lease_id,
        prepared.requested_at,
        prepared.command_digest,
        prepared.result_digest,
    ):
        raise AutomationDispatchError("durable dispatch identity differs from request")


def _persist_reservation(
    store: StateStore,
    reservation: AutomationDispatchReservation,
) -> None:
    append_encrypted(store, reservation, _reservation_spec(reservation.prepared))


def _campaign_control_spec(control: CampaignControl) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_CAMPAIGN_CONTROL_ACTOR_STREAM,
        event_type=AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE,
        media_type=AUTOMATION_CAMPAIGN_CONTROL_MEDIA_TYPE,
        run_id=control.run_id,
        record_id=f"campaign-control.{control.run_id}.{control.epoch}",
    )


def _load_campaign_control(store: StateStore, event) -> CampaignControl:
    try:
        return CampaignControl.model_validate_json(
            load_encrypted(store, event, _campaign_control_spec_placeholder())
        )
    except Exception as exc:
        if isinstance(exc, StorageError):
            raise
        raise StorageError("campaign control artifact is invalid") from exc


def _campaign_control_spec_placeholder() -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_CAMPAIGN_CONTROL_ACTOR_STREAM,
        event_type=AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE,
        media_type=AUTOMATION_CAMPAIGN_CONTROL_MEDIA_TYPE,
        run_id="placeholder.run",
        record_id="placeholder.campaign-control",
    )


def _load_reservation(
    store: StateStore,
    event,
) -> AutomationDispatchReservation:
    try:
        return AutomationDispatchReservation.model_validate_json(
            load_encrypted(store, event, _reservation_spec_placeholder())
        )
    except Exception as exc:
        if isinstance(exc, StorageError):
            raise
        raise StorageError("dispatch reservation artifact is invalid") from exc


def _reservation_spec(prepared: PreparedAutomationDispatch) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_DISPATCH_RESERVATION_ACTOR_STREAM,
        event_type=AUTOMATION_DISPATCH_RESERVATION_EVENT_TYPE,
        media_type=AUTOMATION_DISPATCH_RESERVATION_MEDIA_TYPE,
        run_id=prepared.run_id,
        record_id=prepared.dispatch_id,
    )


def _reservation_spec_placeholder() -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_DISPATCH_RESERVATION_ACTOR_STREAM,
        event_type=AUTOMATION_DISPATCH_RESERVATION_EVENT_TYPE,
        media_type=AUTOMATION_DISPATCH_RESERVATION_MEDIA_TYPE,
        run_id="placeholder.run",
        record_id="placeholder.dispatch",
    )


__all__ = [
    "AUTOMATION_CAMPAIGN_CONTROL_ACTOR_STREAM",
    "AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE",
    "AUTOMATION_CAMPAIGN_CONTROL_MEDIA_TYPE",
    "AUTOMATION_DISPATCH_RESERVATION_ACTOR_STREAM",
    "AUTOMATION_DISPATCH_RESERVATION_EVENT_TYPE",
    "AUTOMATION_DISPATCH_RESERVATION_MEDIA_TYPE",
    "AutomationDispatchReservation",
    "CampaignControl",
    "CampaignControlError",
    "CampaignRevokedError",
    "execute_and_persist_admitted_tool_plan",
    "revoke_campaign",
]
