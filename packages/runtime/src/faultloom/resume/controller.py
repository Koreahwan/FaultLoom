from __future__ import annotations

import hmac

from faultloom_protocol import ModelIdentity, RunManifest, canonical_json_bytes, sha256_digest

from ..context import ContextState
from ..state import AnchorCheckpoint, StateStore
from .journal import (
    CheckpointJournal,
    evidence_digest,
    latest_checkpoint,
    validate_action_history,
    validate_durable_reconciliations,
    validate_initial,
    validate_reconciliation_stage,
    validate_successor,
)
from .models import (
    ActionReconciliation,
    CheckpointConflictError,
    CheckpointEnvelope,
    CheckpointNotFoundError,
    CheckpointReason,
    CheckpointRecord,
    FailoverIntent,
    ReconciliationRequiredError,
    ResumeError,
    ResumePacket,
    ResumeTrustError,
    ResumeTrustPolicy,
)


class CheckpointController:
    _store: StateStore
    _journal: CheckpointJournal

    def __init__(self, store: StateStore) -> None:
        self._store = store
        self._journal = CheckpointJournal(store)

    @staticmethod
    def model_digest(model: ModelIdentity) -> str:
        exact = ModelIdentity.model_validate(model.model_dump(mode="python"))
        return sha256_digest(exact)

    def record_action_reconciliation(
        self,
        reconciliation: ActionReconciliation,
        *,
        evidence: bytes,
    ) -> ActionReconciliation:
        exact = ActionReconciliation.model_validate(
            reconciliation.model_dump(mode="python")
        )
        if type(evidence) is not bytes or not evidence:
            raise ResumeError("action reconciliation evidence must be non-empty bytes")
        actual_evidence_digest = evidence_digest(evidence)
        if not hmac.compare_digest(
            exact.evidence_ref.cas_digest,
            actual_evidence_digest,
        ):
            raise CheckpointConflictError(
                "action reconciliation evidence bytes differ from the evidence reference"
            )

        with self._store.serialized():
            snapshot = self._journal.snapshot()
            for durable in snapshot.action_reconciliations:
                existing = durable.reconciliation
                if existing.evidence_ref.run_id != exact.evidence_ref.run_id:
                    continue
                if existing.reconciliation_id == exact.reconciliation_id:
                    if hmac.compare_digest(
                        canonical_json_bytes(existing),
                        canonical_json_bytes(exact),
                    ):
                        return existing
                    raise CheckpointConflictError(
                        "action reconciliation ID is already bound to different state"
                    )
                if existing.action_id == exact.action_id:
                    raise CheckpointConflictError(
                        "action already has a durable reconciliation"
                    )

            prior = latest_checkpoint(
                snapshot.checkpoints,
                exact.evidence_ref.run_id,
            )
            if prior is None:
                raise CheckpointConflictError(
                    "action reconciliation requires a prior checkpoint"
                )
            validate_reconciliation_stage(prior, exact)
            return self._journal.append_action_reconciliation(
                exact,
                evidence,
            ).reconciliation

    def write(
        self,
        *,
        reason: CheckpointReason,
        run_manifest: RunManifest,
        context_state: ContextState,
        failover_intent: FailoverIntent | None = None,
        action_reconciliations: tuple[ActionReconciliation, ...] = (),
    ) -> ResumePacket:
        if type(reason) is not CheckpointReason:
            raise ResumeError("checkpoint reason must be a typed CheckpointReason")
        manifest = RunManifest.model_validate(run_manifest.model_dump(mode="python"))
        context = ContextState.model_validate(context_state.model_dump(mode="python"))
        failover = (
            None
            if failover_intent is None
            else FailoverIntent.model_validate(failover_intent.model_dump(mode="python"))
        )
        reconciliations = tuple(
            ActionReconciliation.model_validate(record.model_dump(mode="python"))
            for record in action_reconciliations
        )
        envelope = CheckpointEnvelope(
            reason=reason,
            run_manifest=manifest,
            context_state=context,
            model_digest=self.model_digest(manifest.model),
            failover_intent=failover,
            action_reconciliations=reconciliations,
        )
        if envelope.context_state.engagement_id != self._store.engagement_id:
            raise ResumeTrustError("checkpoint belongs to another engagement")
        canonical = canonical_json_bytes(envelope)
        checkpoint_digest = sha256_digest(envelope)

        with self._store.serialized():
            snapshot = self._journal.snapshot()
            records = snapshot.checkpoints
            checkpoint = envelope.context_state.checkpoint
            for record in records:
                existing = record.envelope.context_state.checkpoint
                if existing.checkpoint_id != checkpoint.checkpoint_id:
                    continue
                if hmac.compare_digest(record.checkpoint_digest, checkpoint_digest) and (
                    record.canonical_bytes == canonical
                ):
                    return self._packet(record)
                raise CheckpointConflictError(
                    "checkpoint ID is already bound to different durable state"
                )

            prior = latest_checkpoint(records, checkpoint.run_id)
            validate_action_history(records, envelope)
            if prior is None:
                validate_initial(envelope)
            else:
                validate_successor(prior, envelope)
            validate_durable_reconciliations(
                snapshot.action_reconciliations,
                envelope,
            )
            return self._packet(
                self._journal.append(envelope, canonical, checkpoint_digest)
            )

    def inspect(self, trust: ResumeTrustPolicy) -> ResumePacket:
        policy = ResumeTrustPolicy.model_validate(trust.model_dump(mode="python"))
        if policy.engagement_id != self._store.engagement_id:
            raise ResumeTrustError("resume policy belongs to another engagement")
        with self._store.serialized():
            self._verify_anchor_floor(policy)
            record = latest_checkpoint(
                self._journal.snapshot().checkpoints,
                policy.run_id,
            )
            if record is None:
                raise CheckpointNotFoundError("no durable checkpoint exists for the run")
            self._verify_trust(record, policy)
            return self._packet(record)

    def resume(self, trust: ResumeTrustPolicy) -> ResumePacket:
        _ = self._store.recover()
        packet = self.inspect(trust)
        if packet.blocked_action_ids:
            actions = ", ".join(packet.blocked_action_ids)
            raise ReconciliationRequiredError(
                f"resume requires action reconciliation: {actions}"
            )
        return packet

    def _verify_anchor_floor(self, policy: ResumeTrustPolicy) -> None:
        current = self._store.checkpoint()
        floor = policy.anchor_floor()
        if current.seq < floor.seq:
            raise ResumeTrustError("durable anchor is older than the trusted floor")
        if current.seq == floor.seq:
            if not hmac.compare_digest(current.head, floor.head):
                raise ResumeTrustError("durable anchor diverges from the trusted floor")
            return
        if floor.seq == 0:
            return
        if not hmac.compare_digest(
            self._journal.event_hash_at(floor.seq),
            floor.head,
        ):
            raise ResumeTrustError("durable chain does not contain the trusted floor")

    @staticmethod
    def _verify_trust(record: CheckpointRecord, policy: ResumeTrustPolicy) -> None:
        envelope = record.envelope
        checkpoint = envelope.context_state.checkpoint
        checks = (
            (record.checkpoint_digest, policy.checkpoint_digest, "checkpoint"),
            (checkpoint.goal_digest, policy.goal_digest, "goal"),
            (checkpoint.plan_digest, policy.plan_digest, "plan"),
            (checkpoint.authority_digest, policy.authority_digest, "scope authority"),
            (sha256_digest(envelope.run_manifest), policy.run_manifest_digest, "manifest"),
            (envelope.model_digest, policy.model_digest, "model"),
            (envelope.run_manifest.model.prompt_digest, policy.prompt_digest, "prompt"),
            (
                envelope.run_manifest.model.tool_schema_digest,
                policy.tool_schema_digest,
                "tool schema",
            ),
        )
        for actual, expected, label in checks:
            if not hmac.compare_digest(actual, expected):
                raise ResumeTrustError(f"{label} digest differs from trusted expectations")
        if checkpoint.scope_epoch != policy.scope_epoch:
            raise ResumeTrustError("scope epoch differs from trusted expectations")
        if checkpoint.sequence < policy.minimum_checkpoint_sequence:
            raise ResumeTrustError("checkpoint sequence is older than the trusted floor")
        if checkpoint.stable_watermark < policy.minimum_stable_watermark:
            raise ResumeTrustError("stable watermark is older than the trusted floor")

    @staticmethod
    def _packet(record: CheckpointRecord) -> ResumePacket:
        checkpoint = record.envelope.context_state.checkpoint
        blocked = checkpoint.pending_action_ids + checkpoint.unknown_outcome_action_ids
        failover = record.envelope.failover_intent
        return ResumePacket(
            checkpoint_digest=record.checkpoint_digest,
            event_sequence=record.event_sequence,
            event_hash=record.event_hash,
            reason=record.envelope.reason,
            run_manifest=record.envelope.run_manifest,
            context_state=record.envelope.context_state,
            failover_intent=failover,
            action_reconciliations=record.envelope.action_reconciliations,
            blocked_action_ids=blocked,
            automatic_retry_action_ids=(),
            dispatch_ready=not blocked and failover is None,
            requires_reconciliation=bool(blocked),
            failover_required=failover is not None,
        )


def trust_policy_for(
    packet: ResumePacket,
    *,
    minimum_anchor: AnchorCheckpoint,
) -> ResumeTrustPolicy:
    checkpoint = packet.context_state.checkpoint
    if minimum_anchor.engagement_id != packet.context_state.engagement_id:
        raise ResumeTrustError("minimum anchor belongs to another engagement")
    if minimum_anchor.seq < packet.event_sequence:
        raise ResumeTrustError("minimum anchor does not cover the checkpoint event")
    if minimum_anchor.seq == packet.event_sequence and not hmac.compare_digest(
        minimum_anchor.head,
        packet.event_hash,
    ):
        raise ResumeTrustError("minimum anchor does not cover the checkpoint event")
    manifest = packet.run_manifest
    return ResumeTrustPolicy(
        engagement_id=manifest.engagement_id,
        run_id=manifest.run_id,
        checkpoint_digest=packet.checkpoint_digest,
        goal_digest=checkpoint.goal_digest,
        plan_digest=checkpoint.plan_digest,
        authority_digest=checkpoint.authority_digest,
        scope_epoch=checkpoint.scope_epoch,
        run_manifest_digest=sha256_digest(manifest),
        model_digest=CheckpointController.model_digest(manifest.model),
        prompt_digest=manifest.model.prompt_digest,
        tool_schema_digest=manifest.model.tool_schema_digest,
        minimum_checkpoint_sequence=checkpoint.sequence,
        minimum_stable_watermark=checkpoint.stable_watermark,
        minimum_anchor_seq=minimum_anchor.seq,
        minimum_anchor_head=minimum_anchor.head,
    )
