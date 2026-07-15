from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from faultloom_protocol import canonical_json_bytes, sha256_digest

from ..state import ArtifactRef, StateStore, StorageError
from ..state.cas import EncryptedCAS
from ..state.canonical import canonical_json
from ..state.ledger import EventLedger, EventRecord
from ..state.store import METADATA_MEDIA_TYPE
from .models import (
    ActionReconciliation,
    CheckpointConflictError,
    CheckpointEnvelope,
    CheckpointIntegrityError,
    CheckpointReason,
    CheckpointRecord,
    ResumeTrustError,
    UnresolvedActionState,
)
from .wire import canonical_model_bytes, model_digest


CHECKPOINT_ACTOR_STREAM = "control.resume"
CHECKPOINT_EVENT_TYPE = "runtime.checkpoint.v1"
CHECKPOINT_MEDIA_TYPE = "application/vnd.faultloom.resume-checkpoint+json"
ACTION_RECONCILIATION_EVENT_TYPE = "runtime.action_reconciliation.v1"
ACTION_RECONCILIATION_MEDIA_TYPE = (
    "application/vnd.faultloom.action-reconciliation-evidence+octets"
)
_CHECKPOINT_PAYLOAD_KEYS = frozenset(
    {"artifact_ref", "metadata_ref", "metadata_schema_version"}
)


class _ReconciliationPredecessor(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    checkpoint_id: str
    checkpoint_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    checkpoint_sequence: int = Field(gt=0)
    stable_watermark: int = Field(gt=0)
    event_sequence: int = Field(gt=0)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class _ReconciliationMetadataValues(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    action_reconciliation: ActionReconciliation
    predecessor: _ReconciliationPredecessor


class _ReconciliationMetadata(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    schema_version: Literal[1]
    values: _ReconciliationMetadataValues


@dataclass(frozen=True, slots=True)
class DurableActionReconciliation:
    event_sequence: int
    event_hash: str
    evidence_artifact: ArtifactRef
    reconciliation: ActionReconciliation
    predecessor: _ReconciliationPredecessor


@dataclass(frozen=True, slots=True)
class JournalSnapshot:
    checkpoints: tuple[CheckpointRecord, ...]
    action_reconciliations: tuple[DurableActionReconciliation, ...]


class CheckpointJournal:
    _store: StateStore

    def __init__(self, store: StateStore) -> None:
        self._store = store

    def append(
        self,
        envelope: CheckpointEnvelope,
        canonical_bytes: bytes,
        checkpoint_digest: str,
    ) -> CheckpointRecord:
        event, _ = self._store.append_observation(
            actor_stream=CHECKPOINT_ACTOR_STREAM,
            event_type=CHECKPOINT_EVENT_TYPE,
            raw_output=canonical_bytes,
            metadata=_metadata_values(envelope, checkpoint_digest),
            media_type=CHECKPOINT_MEDIA_TYPE,
        )
        return CheckpointRecord(
            event_sequence=event.seq,
            event_hash=event.event_hash,
            checkpoint_digest=checkpoint_digest,
            canonical_bytes=canonical_bytes,
            envelope=envelope,
        )

    def append_action_reconciliation(
        self,
        reconciliation: ActionReconciliation,
        evidence: bytes,
        predecessor: CheckpointRecord,
    ) -> DurableActionReconciliation:
        if not hmac.compare_digest(
            reconciliation.evidence_ref.cas_digest,
            evidence_digest(evidence),
        ):
            raise CheckpointConflictError(
                "action reconciliation evidence bytes differ from the evidence reference"
            )
        event, artifact = self._store.append_observation(
            actor_stream=CHECKPOINT_ACTOR_STREAM,
            event_type=ACTION_RECONCILIATION_EVENT_TYPE,
            raw_output=evidence,
            metadata=_reconciliation_metadata_values(reconciliation, predecessor),
            media_type=ACTION_RECONCILIATION_MEDIA_TYPE,
        )
        return DurableActionReconciliation(
            event_sequence=event.seq,
            event_hash=event.event_hash,
            evidence_artifact=artifact,
            reconciliation=reconciliation,
            predecessor=_predecessor_binding(predecessor),
        )

    def snapshot(self) -> JournalSnapshot:
        ledger, cas = self._components()
        events: list[EventRecord] = []
        after_sequence = 0
        while True:
            page = ledger.events(after_seq=after_sequence, limit=10_000)
            events.extend(page)
            if len(page) < 10_000:
                break
            after_sequence = page[-1].seq

        records: list[CheckpointRecord] = []
        checkpoint_ids: set[str] = set()
        latest_by_run: dict[str, CheckpointRecord] = {}
        resolved_actions_by_run: dict[str, set[str]] = {}
        reconciliation_ids_by_run: dict[str, set[str]] = {}
        durable_reconciliations: list[DurableActionReconciliation] = []
        durable_ids_by_run: dict[str, set[str]] = {}
        durable_action_bindings_by_run: dict[str, set[tuple[int, str]]] = {}
        for event in events:
            if event.event_type == ACTION_RECONCILIATION_EVENT_TYPE:
                durable = self._decode_action_reconciliation(event, cas)
                reconciliation = durable.reconciliation
                run_id = reconciliation.evidence_ref.run_id
                durable_ids = durable_ids_by_run.setdefault(run_id, set())
                durable_action_bindings = durable_action_bindings_by_run.setdefault(
                    run_id,
                    set(),
                )
                if reconciliation.reconciliation_id in durable_ids:
                    raise CheckpointIntegrityError(
                        "action reconciliation ID appears more than once"
                    )
                prior = latest_by_run.get(run_id)
                if prior is None:
                    raise CheckpointIntegrityError(
                        "action reconciliation has no prior checkpoint"
                    )
                try:
                    validate_reconciliation_stage(prior, reconciliation)
                    validate_reconciliation_predecessor(durable, prior)
                except CheckpointConflictError as exc:
                    raise CheckpointIntegrityError(
                        "action reconciliation differs from prior durable state"
                    ) from exc
                action_binding = (
                    durable.predecessor.event_sequence,
                    reconciliation.action_id,
                )
                if action_binding in durable_action_bindings:
                    raise CheckpointIntegrityError(
                        "action has more than one reconciliation for its predecessor"
                    )
                durable_ids.add(reconciliation.reconciliation_id)
                durable_action_bindings.add(action_binding)
                durable_reconciliations.append(durable)
                continue
            if event.event_type != CHECKPOINT_EVENT_TYPE:
                continue
            record = self._decode_record(event, cas)
            checkpoint = record.envelope.context_state.checkpoint
            if checkpoint.checkpoint_id in checkpoint_ids:
                raise CheckpointIntegrityError("checkpoint ID appears more than once")
            checkpoint_ids.add(checkpoint.checkpoint_id)
            resolved_action_ids = resolved_actions_by_run.setdefault(
                checkpoint.run_id,
                set(),
            )
            reconciliation_ids = reconciliation_ids_by_run.setdefault(
                checkpoint.run_id,
                set(),
            )
            _validate_action_history_state(
                resolved_action_ids,
                reconciliation_ids,
                record.envelope,
            )
            prior = latest_by_run.get(checkpoint.run_id)
            if prior is None:
                validate_initial(record.envelope)
            else:
                validate_successor(prior, record.envelope)
            try:
                validate_durable_reconciliations(
                    tuple(durable_reconciliations),
                    record.envelope,
                    prior,
                )
            except CheckpointConflictError as exc:
                raise CheckpointIntegrityError(
                    "checkpoint reconciliation lacks exact prior durable evidence"
                ) from exc
            for reconciliation in record.envelope.action_reconciliations:
                resolved_action_ids.add(reconciliation.action_id)
                reconciliation_ids.add(reconciliation.reconciliation_id)
            latest_by_run[checkpoint.run_id] = record
            records.append(record)
        return JournalSnapshot(
            checkpoints=tuple(records),
            action_reconciliations=tuple(durable_reconciliations),
        )

    def event_hash_at(self, sequence: int) -> str:
        ledger, _ = self._components()
        return ledger.event_hash_at(sequence)

    def _components(self) -> tuple[EventLedger, EncryptedCAS]:
        ledger = self._store.ledger
        cas = self._store.cas
        if ledger is None or cas is None:
            raise StorageError("state store is closed")
        return ledger, cas

    def _decode_record(
        self,
        event: EventRecord,
        cas: EncryptedCAS,
    ) -> CheckpointRecord:
        if event.actor_stream != CHECKPOINT_ACTOR_STREAM:
            raise CheckpointIntegrityError("checkpoint event actor stream is invalid")
        if frozenset(event.payload) != _CHECKPOINT_PAYLOAD_KEYS:
            raise CheckpointIntegrityError("checkpoint event payload shape is invalid")
        if event.payload["metadata_schema_version"] != 1:
            raise CheckpointIntegrityError("checkpoint metadata schema is invalid")
        artifact = _artifact(event, "artifact_ref")
        metadata = _artifact(event, "metadata_ref")
        if artifact.media_type != CHECKPOINT_MEDIA_TYPE:
            raise CheckpointIntegrityError("checkpoint artifact media type is invalid")
        if metadata.media_type != METADATA_MEDIA_TYPE:
            raise CheckpointIntegrityError("checkpoint metadata media type is invalid")
        canonical = cas.get(artifact)
        metadata_bytes = cas.get(metadata)
        try:
            envelope = CheckpointEnvelope.model_validate_json(canonical)
        except (ValidationError, ValueError) as exc:
            raise CheckpointIntegrityError("checkpoint artifact is invalid") from exc
        if canonical_model_bytes(envelope, CheckpointEnvelope) != canonical:
            raise CheckpointIntegrityError("checkpoint artifact is not canonical")
        expected_metadata = canonical_json(
            {
                "schema_version": 1,
                "values": _metadata_values(
                    envelope,
                    model_digest(envelope, CheckpointEnvelope),
                ),
            }
        ).encode("utf-8")
        if metadata_bytes != expected_metadata:
            raise CheckpointIntegrityError(
                "checkpoint metadata differs from its embedded identity"
            )
        if envelope.context_state.engagement_id != self._store.engagement_id:
            raise ResumeTrustError("checkpoint belongs to another engagement")
        return CheckpointRecord(
            event_sequence=event.seq,
            event_hash=event.event_hash,
            checkpoint_digest=model_digest(envelope, CheckpointEnvelope),
            canonical_bytes=canonical,
            envelope=envelope,
        )

    def _decode_action_reconciliation(
        self,
        event: EventRecord,
        cas: EncryptedCAS,
    ) -> DurableActionReconciliation:
        if event.actor_stream != CHECKPOINT_ACTOR_STREAM:
            raise CheckpointIntegrityError(
                "action reconciliation event actor stream is invalid"
            )
        if frozenset(event.payload) != _CHECKPOINT_PAYLOAD_KEYS:
            raise CheckpointIntegrityError(
                "action reconciliation event payload shape is invalid"
            )
        if event.payload["metadata_schema_version"] != 1:
            raise CheckpointIntegrityError(
                "action reconciliation metadata schema is invalid"
            )
        artifact = _artifact(event, "artifact_ref", context="action reconciliation")
        metadata = _artifact(event, "metadata_ref", context="action reconciliation")
        if artifact.media_type != ACTION_RECONCILIATION_MEDIA_TYPE:
            raise CheckpointIntegrityError(
                "action reconciliation evidence media type is invalid"
            )
        if metadata.media_type != METADATA_MEDIA_TYPE:
            raise CheckpointIntegrityError(
                "action reconciliation metadata media type is invalid"
            )
        evidence = cas.get(artifact)
        metadata_bytes = cas.get(metadata)
        try:
            document = _ReconciliationMetadata.model_validate_json(metadata_bytes)
        except (ValidationError, ValueError) as exc:
            raise CheckpointIntegrityError(
                "action reconciliation metadata is invalid"
            ) from exc
        reconciliation = document.values.action_reconciliation
        predecessor = document.values.predecessor
        expected_metadata = canonical_json(
            {
                "schema_version": 1,
                "values": _reconciliation_metadata_values(
                    reconciliation,
                    predecessor,
                ),
            }
        ).encode("utf-8")
        if metadata_bytes != expected_metadata:
            raise CheckpointIntegrityError(
                "action reconciliation metadata is not canonical"
            )
        if not hmac.compare_digest(
            reconciliation.evidence_ref.cas_digest,
            evidence_digest(evidence),
        ):
            raise CheckpointIntegrityError(
                "action reconciliation evidence digest is invalid"
            )
        return DurableActionReconciliation(
            event_sequence=event.seq,
            event_hash=event.event_hash,
            evidence_artifact=artifact,
            reconciliation=reconciliation,
            predecessor=predecessor,
        )


def _metadata_values(
    envelope: CheckpointEnvelope,
    checkpoint_digest: str,
) -> dict[str, object]:
    checkpoint = envelope.context_state.checkpoint
    return {
        "checkpoint_digest": checkpoint_digest,
        "checkpoint_id": checkpoint.checkpoint_id,
        "reason": envelope.reason.value,
        "run_id": checkpoint.run_id,
        "sequence": checkpoint.sequence,
    }


def _reconciliation_metadata_values(
    reconciliation: ActionReconciliation,
    predecessor: CheckpointRecord | _ReconciliationPredecessor,
) -> dict[str, object]:
    binding = (
        predecessor
        if isinstance(predecessor, _ReconciliationPredecessor)
        else _predecessor_binding(predecessor)
    )
    return {
        "action_reconciliation": reconciliation.model_dump(mode="json"),
        "predecessor": binding.model_dump(mode="json"),
    }


def _predecessor_binding(
    predecessor: CheckpointRecord,
) -> _ReconciliationPredecessor:
    checkpoint = predecessor.envelope.context_state.checkpoint
    return _ReconciliationPredecessor(
        checkpoint_id=checkpoint.checkpoint_id,
        checkpoint_digest=predecessor.checkpoint_digest,
        checkpoint_sequence=checkpoint.sequence,
        stable_watermark=checkpoint.stable_watermark,
        event_sequence=predecessor.event_sequence,
        event_hash=predecessor.event_hash,
    )


def evidence_digest(evidence: bytes) -> str:
    return f"sha256:{hashlib.sha256(evidence).hexdigest()}"


def _artifact(
    event: EventRecord,
    key: str,
    *,
    context: str = "checkpoint",
) -> ArtifactRef:
    value = event.payload.get(key)
    if type(value) is not dict:
        raise CheckpointIntegrityError(f"{context} {key} is invalid")
    try:
        return ArtifactRef.from_dict(value)
    except (StorageError, TypeError) as exc:
        raise CheckpointIntegrityError(f"{context} {key} is invalid") from exc


def latest_checkpoint(
    records: tuple[CheckpointRecord, ...],
    run_id: str,
) -> CheckpointRecord | None:
    matching = (
        record
        for record in records
        if record.envelope.context_state.checkpoint.run_id == run_id
    )
    return max(matching, key=lambda item: item.event_sequence, default=None)


def validate_reconciliation_stage(
    prior: CheckpointRecord,
    reconciliation: ActionReconciliation,
) -> None:
    checkpoint = prior.envelope.context_state.checkpoint
    if reconciliation.evidence_ref.run_id != checkpoint.run_id:
        raise CheckpointConflictError(
            "action reconciliation evidence belongs to another run"
        )
    if not any(
        hmac.compare_digest(
            canonical_json_bytes(reconciliation.evidence_ref),
            canonical_json_bytes(reference),
        )
        for reference in checkpoint.recent_evidence_refs
    ):
        raise CheckpointConflictError(
            "action reconciliation evidence is not linked to the durable predecessor"
        )
    if reconciliation.action_id in checkpoint.pending_action_ids:
        expected_state = UnresolvedActionState.PENDING
    elif reconciliation.action_id in checkpoint.unknown_outcome_action_ids:
        expected_state = UnresolvedActionState.UNKNOWN_OUTCOME
    else:
        raise CheckpointConflictError(
            "action reconciliation requires a currently unresolved action"
        )
    if reconciliation.prior_state is not expected_state:
        raise CheckpointConflictError(
            "action reconciliation prior state differs from durable state"
        )
    if not hmac.compare_digest(
        reconciliation.authority_digest,
        checkpoint.authority_digest,
    ):
        raise CheckpointConflictError(
            "action reconciliation authority differs from durable state"
        )
    if reconciliation.scope_epoch != checkpoint.scope_epoch:
        raise CheckpointConflictError(
            "action reconciliation scope epoch differs from durable state"
        )
    if reconciliation.reconciled_at < checkpoint.created_at:
        raise CheckpointConflictError(
            "action reconciliation predates the unresolved checkpoint"
        )


def validate_reconciliation_predecessor(
    durable: DurableActionReconciliation,
    predecessor: CheckpointRecord,
) -> None:
    if not reconciliation_matches_predecessor(durable, predecessor):
        raise CheckpointConflictError(
            "action reconciliation is not bound to the immediate predecessor"
        )


def reconciliation_matches_predecessor(
    durable: DurableActionReconciliation,
    predecessor: CheckpointRecord,
) -> bool:
    expected = _predecessor_binding(predecessor)
    return durable.event_sequence > predecessor.event_sequence and hmac.compare_digest(
        canonical_model_bytes(durable.predecessor, _ReconciliationPredecessor),
        canonical_model_bytes(expected, _ReconciliationPredecessor),
    )


def validate_durable_reconciliations(
    durable_records: tuple[DurableActionReconciliation, ...],
    envelope: CheckpointEnvelope,
    predecessor: CheckpointRecord | None,
) -> None:
    if not envelope.action_reconciliations:
        return
    if predecessor is None:
        raise CheckpointConflictError(
            "action reconciliation requires an immediate predecessor"
        )
    run_id = envelope.context_state.checkpoint.run_id
    by_id = {
        durable.reconciliation.reconciliation_id: durable
        for durable in durable_records
        if durable.reconciliation.evidence_ref.run_id == run_id
    }
    for reconciliation in envelope.action_reconciliations:
        durable = by_id.get(reconciliation.reconciliation_id)
        if durable is None:
            raise CheckpointConflictError(
                "action reconciliation requires prior durable evidence"
            )
        validate_reconciliation_predecessor(durable, predecessor)
        validate_reconciliation_stage(predecessor, reconciliation)
        if not hmac.compare_digest(
            canonical_model_bytes(durable.reconciliation, ActionReconciliation),
            canonical_model_bytes(reconciliation, ActionReconciliation),
        ):
            raise CheckpointConflictError(
                "checkpoint reconciliation differs from prior durable evidence"
            )


def validate_successor(
    prior: CheckpointRecord,
    envelope: CheckpointEnvelope,
) -> None:
    previous = prior.envelope.context_state.checkpoint
    checkpoint = envelope.context_state.checkpoint
    if checkpoint.sequence <= previous.sequence:
        raise CheckpointConflictError("checkpoint sequence must advance monotonically")
    if checkpoint.stable_watermark < previous.stable_watermark:
        raise CheckpointConflictError("stable watermark cannot move backwards")
    if (
        envelope.reason is CheckpointReason.STABLE_WATERMARK
        and checkpoint.stable_watermark <= previous.stable_watermark
    ):
        raise CheckpointConflictError("stable-watermark checkpoint must advance")
    if checkpoint.goal_digest != previous.goal_digest:
        raise CheckpointConflictError("run goal digest changed between checkpoints")
    _validate_action_continuity(prior, envelope)
    _validate_manifest_continuity(prior, envelope)


def validate_initial(envelope: CheckpointEnvelope) -> None:
    if envelope.action_reconciliations:
        raise CheckpointConflictError(
            "action reconciliation requires a prior unresolved action"
        )


def validate_action_history(
    records: tuple[CheckpointRecord, ...],
    envelope: CheckpointEnvelope,
) -> None:
    run_id = envelope.context_state.checkpoint.run_id
    resolved_action_ids: set[str] = set()
    reconciliation_ids: set[str] = set()
    for record in records:
        checkpoint = record.envelope.context_state.checkpoint
        if checkpoint.run_id != run_id:
            continue
        for reconciliation in record.envelope.action_reconciliations:
            resolved_action_ids.add(reconciliation.action_id)
            reconciliation_ids.add(reconciliation.reconciliation_id)

    _validate_action_history_state(
        resolved_action_ids,
        reconciliation_ids,
        envelope,
    )


def _validate_action_history_state(
    resolved_action_ids: set[str],
    reconciliation_ids: set[str],
    envelope: CheckpointEnvelope,
) -> None:
    checkpoint = envelope.context_state.checkpoint
    current_unresolved = set(checkpoint.pending_action_ids) | set(
        checkpoint.unknown_outcome_action_ids
    )
    if resolved_action_ids & current_unresolved:
        raise CheckpointConflictError(
            "reconciled action cannot become unresolved again"
        )
    current_reconciliations = envelope.action_reconciliations
    if resolved_action_ids & {
        reconciliation.action_id for reconciliation in current_reconciliations
    }:
        raise CheckpointConflictError("action cannot be reconciled more than once")
    if reconciliation_ids & {
        reconciliation.reconciliation_id
        for reconciliation in current_reconciliations
    }:
        raise CheckpointConflictError("action reconciliation ID is already durable")


def _validate_action_continuity(
    prior: CheckpointRecord,
    envelope: CheckpointEnvelope,
) -> None:
    previous = prior.envelope.context_state.checkpoint
    checkpoint = envelope.context_state.checkpoint
    previous_pending = frozenset(previous.pending_action_ids)
    previous_unknown = frozenset(previous.unknown_outcome_action_ids)
    current_pending = frozenset(checkpoint.pending_action_ids)
    current_unknown = frozenset(checkpoint.unknown_outcome_action_ids)

    if previous_unknown & current_pending:
        raise CheckpointConflictError(
            "unknown-outcome action cannot regress to pending"
        )

    previous_unresolved = previous_pending | previous_unknown
    current_unresolved = current_pending | current_unknown
    removed = previous_unresolved - current_unresolved
    reconciliations = {
        record.action_id: record for record in envelope.action_reconciliations
    }
    reconciliation_ids = frozenset(reconciliations)
    silently_removed = removed - reconciliation_ids
    if silently_removed:
        raise CheckpointConflictError(
            "unresolved action removal requires durable reconciliation"
        )
    if reconciliation_ids - removed:
        raise CheckpointConflictError(
            "action reconciliation must resolve a prior unresolved action"
        )

    for action_id, record in reconciliations.items():
        expected_state = (
            UnresolvedActionState.PENDING
            if action_id in previous_pending
            else UnresolvedActionState.UNKNOWN_OUTCOME
        )
        if record.prior_state is not expected_state:
            raise CheckpointConflictError(
                "action reconciliation prior state differs from durable state"
            )
        if record.reconciled_at < previous.created_at:
            raise CheckpointConflictError(
                "action reconciliation predates the unresolved checkpoint"
            )


def _validate_manifest_continuity(
    prior: CheckpointRecord,
    envelope: CheckpointEnvelope,
) -> None:
    previous_envelope = prior.envelope
    intent = previous_envelope.failover_intent
    if intent is None:
        if sha256_digest(envelope.run_manifest) != sha256_digest(
            previous_envelope.run_manifest
        ):
            raise CheckpointConflictError("run manifest changed between checkpoints")
        return

    expected = previous_envelope.run_manifest.model_copy(
        update={"model": intent.to_model}
    )
    if sha256_digest(envelope.run_manifest) != sha256_digest(expected):
        raise CheckpointConflictError(
            "provider failover successor must use the exact target model"
        )
    if envelope.context_state.checkpoint.created_at < intent.requested_at:
        raise CheckpointConflictError(
            "provider failover successor predates the failover intent"
        )
