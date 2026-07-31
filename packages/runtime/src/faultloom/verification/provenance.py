"""Authenticated automation-dispatch provenance for independent verification."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING

from faultloom_protocol import Ed25519PublicKeyRecord, sha256_digest

if TYPE_CHECKING:
    from faultloom.automation.execution_bridge import AutomationDispatchPersistence
    from faultloom.execution import GatewayDispatchCommand
    from faultloom.state import StateStore


AUTOMATION_DISPATCH_PROVENANCE_MARKER = "faultloom:automation_dispatch_provenance="
_PROVENANCE_FACTORY = object()


@dataclass(frozen=True, slots=True)
class _ProvenanceProof:
    material_digest: str


@dataclass(frozen=True, slots=True, init=False)
class AutomationDispatchProvenance:
    """Opaque link to one authenticated, ledger-backed dispatch aggregate."""

    dispatch: AutomationDispatchPersistence
    command: GatewayDispatchCommand
    _proof: _ProvenanceProof

    def __init__(
        self,
        *,
        _factory: object,
        dispatch: AutomationDispatchPersistence,
        command: GatewayDispatchCommand,
    ) -> None:
        if _factory is not _PROVENANCE_FACTORY:
            raise TypeError("automation dispatch provenance must be loaded from the ledger")
        object.__setattr__(self, "dispatch", dispatch)
        object.__setattr__(self, "command", command)
        object.__setattr__(
            self,
            "_proof",
            _ProvenanceProof(material_digest=_provenance_material_digest(dispatch, command)),
        )


@dataclass(frozen=True, slots=True)
class AutomationDispatchProvenanceError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def load_automation_dispatch_provenance(
    store: StateStore,
    *,
    dispatch_id: str,
    command: GatewayDispatchCommand,
    trusted_admission_keys: dict[str, Ed25519PublicKeyRecord],
) -> AutomationDispatchProvenance:
    """Create provenance only after loading the authenticated ledger aggregate."""

    from faultloom.automation.execution_bridge import load_authenticated_automation_dispatch

    dispatch = load_authenticated_automation_dispatch(
        store,
        dispatch_id=dispatch_id,
        command=command,
        trusted_admission_keys=trusted_admission_keys,
    )
    return AutomationDispatchProvenance(
        _factory=_PROVENANCE_FACTORY,
        dispatch=dispatch,
        command=command,
    )


def automation_dispatch_provenance_digest(
    provenance: AutomationDispatchProvenance,
) -> str:
    """Digest every immutable dispatch input bound into a verification artifact."""

    return _validate_and_digest(provenance)


def automation_dispatch_provenance_marker(
    provenance: AutomationDispatchProvenance,
) -> str:
    return (
        f"{AUTOMATION_DISPATCH_PROVENANCE_MARKER}"
        f"{_validate_and_digest(provenance)}"
    )


def validate_automation_dispatch_provenance(
    provenance: AutomationDispatchProvenance,
) -> AutomationDispatchProvenance:
    _validate_and_digest(provenance)
    return provenance


def _validate_and_digest(provenance: AutomationDispatchProvenance) -> str:
    from faultloom.automation.execution_bridge import AutomationDispatchPersistence
    from faultloom.execution import GatewayDispatchCommand, GatewayDispatchResult

    if type(provenance) is not AutomationDispatchProvenance:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance must use the exact loaded type"
        )
    if type(provenance.dispatch) is not AutomationDispatchPersistence:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance requires an exact persisted aggregate"
        )
    if type(provenance.command) is not GatewayDispatchCommand:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance requires an exact Gateway command"
        )
    if type(provenance._proof) is not _ProvenanceProof or not hmac.compare_digest(
        provenance._proof.material_digest,
        _provenance_material_digest(provenance.dispatch, provenance.command),
    ):
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance proof is invalid"
        )

    persistence = provenance.dispatch
    record = persistence.envelope.record
    result = record.admission.payload.result
    selected = _selected_item(result, record.candidate_id)
    gateway_result = record.gateway_result
    if record.status != "completed" or record.target_dispatch_performed is not True:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance requires a completed Gateway dispatch"
        )
    if type(gateway_result) is not GatewayDispatchResult:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance requires a completed Gateway result"
        )
    if record.command_digest != sha256_digest(provenance.command.model_dump(mode="json")):
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch command digest differs from the exact command"
        )
    if result.run_id != record.run_id or selected.candidate.intent != provenance.command.intent:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch candidate is not bound to the exact command"
        )
    if (
        selected.receipt.authority_digest != result.authority_grant_digest
        or gateway_result.receipt.action_id != provenance.command.intent.action_id
        or gateway_result.receipt.lease_id != provenance.command.lease.lease_id
        or gateway_result.receipt.intent_digest != provenance.command.intent_digest
        or gateway_result.receipt.decision_digest != provenance.command.decision_digest
    ):
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch Gateway result is not bound to the admitted command"
        )
    evidence = persistence.evidence_ref
    if (
        evidence.evidence_id != f"automation-dispatch-evidence.{record.dispatch_id}"
        or evidence.run_id != result.run_id
        or evidence.cas_digest != persistence.observation_ref.cas_digest
        or evidence.observation_ids != (persistence.observation_ref.observation_id,)
    ):
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch evidence is not bound to the persisted dispatch"
        )
    return _provenance_material_digest(persistence, provenance.command)


def _provenance_material_digest(
    dispatch: AutomationDispatchPersistence,
    command: GatewayDispatchCommand,
) -> str:
    record = dispatch.envelope.record
    result = record.admission.payload.result
    selected = _selected_item(result, record.candidate_id)
    event = dispatch.event
    return sha256_digest(
        {
            "admission": record.admission.model_dump(mode="json"),
            "automation_result": result.model_dump(mode="json"),
            "command": command.model_dump(mode="json"),
            "command_digest": record.command_digest,
            "dispatch_envelope": dispatch.envelope.model_dump(mode="json"),
            "dispatch_evidence": dispatch.evidence_ref.model_dump(mode="json"),
            "event": {
                "actor_stream": event.actor_stream,
                "created_at": event.created_at,
                "engagement_id": event.engagement_id,
                "event_auth_tag": event.event_auth_tag,
                "event_hash": event.event_hash,
                "event_type": event.event_type,
                "payload": event.payload,
                "payload_sha256": event.payload_sha256,
                "prev_auth_tag": event.prev_auth_tag,
                "prev_hash": event.prev_hash,
                "schema_version": event.schema_version,
                "seq": event.seq,
            },
            "gateway_result": record.gateway_result.model_dump(mode="json"),
            "tool_candidate": selected.candidate.model_dump(mode="json"),
            "tool_plan_receipt": selected.receipt.model_dump(mode="json"),
        }
    )


def _selected_item(result: object, candidate_id: str):
    plans = getattr(result, "admitted_plans", ())
    items = tuple(
        plan.selected
        for plan in plans
        if plan.selected.candidate.candidate_id == candidate_id
    )
    if len(items) != 1:
        raise AutomationDispatchProvenanceError(
            reason="automation dispatch provenance requires one admitted tool candidate"
        )
    return items[0]
