from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from faultloom.context import checkpoint_binding_tag_for
from faultloom.resume import (
    CheckpointConflictError,
    CheckpointController,
    CheckpointIntegrityError,
    CheckpointNotFoundError,
    CheckpointReason,
    ReconciliationRequiredError,
    ResumeTrustError,
    UnresolvedActionState,
    trust_policy_for,
)
from faultloom.state import ArtifactRef, ChainIntegrityError, EventRecord, StorageError
from faultloom_protocol import DispatchOutcome
from tests.protocol.factories import D1
from tests.runtime.resume_support import (
    RECONCILIATION_EVIDENCE,
    make_context,
    make_failover_intent,
    make_manifest,
    make_reconciliation,
    open_store,
    state_root,
    write_checkpoint,
)
from tests.runtime.test_context import DEFAULT_RETRIEVAL_KEY


def test_ten_crash_resets_preserve_ids_without_duplicate_effects(tmp_path: Path) -> None:
    given_context = make_context()
    with open_store(tmp_path) as active:
        packet = write_checkpoint(CheckpointController(active), given_context)
        floor = active.checkpoint()
        policy = trust_policy_for(packet, minimum_anchor=floor)

    for _ in range(10):
        with open_store(tmp_path, minimum_anchor=floor) as reopened:
            when_resumed = CheckpointController(reopened).resume(policy)
            checkpoint = when_resumed.context_state.checkpoint
            assert checkpoint.active_hypothesis_ids == ("hypothesis.1",)
            assert checkpoint.important_negative_result_ids == ("negative.1",)
            assert checkpoint.identity_graph_id == "identity-graph.1"
            assert checkpoint.workflow_graph_id == "workflow-graph.1"
            assert checkpoint.surface_graph_id == "surface-graph.1"
            assert checkpoint.chain_graph_id == "chain-graph.1"
            assert when_resumed.automatic_retry_action_ids == ()
            assert reopened.ledger is not None
            assert len(reopened.ledger.events()) == 1


def test_unknown_outcome_is_inspectable_but_resume_requires_reconciliation(
    tmp_path: Path,
) -> None:
    given_context = make_context(unknown=("action.unknown",))
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        packet = write_checkpoint(controller, given_context)
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())

        when_inspected = controller.inspect(policy)
        assert when_inspected.blocked_action_ids == ("action.unknown",)
        assert when_inspected.automatic_retry_action_ids == ()
        with pytest.raises(ReconciliationRequiredError, match="action.unknown"):
            controller.resume(policy)
        assert active.ledger is not None
        assert len(active.ledger.events()) == 1


def test_unknown_outcome_cannot_be_silently_dropped_by_a_successor(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )

        with pytest.raises(CheckpointConflictError, match="reconciliation"):
            write_checkpoint(
                controller,
                make_context(sequence=2, checkpoint_id="checkpoint.2"),
            )

        assert active.ledger is not None
        assert len(active.ledger.events()) == 1


def test_pending_action_cannot_be_silently_dropped_by_a_successor(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(pending=("action.pending",)),
        )

        with pytest.raises(CheckpointConflictError, match="reconciliation"):
            write_checkpoint(
                controller,
                make_context(sequence=2, checkpoint_id="checkpoint.2"),
            )


def test_pending_action_can_advance_to_unknown_but_stays_blocked(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(pending=("action.pending",)),
        )
        packet = write_checkpoint(
            controller,
            make_context(
                sequence=2,
                checkpoint_id="checkpoint.2",
                unknown=("action.pending",),
            ),
        )
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())

        with pytest.raises(ReconciliationRequiredError, match="action.pending"):
            controller.resume(policy)


def test_reconciliation_rejects_successor_only_fabricated_evidence(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.fabricated-evidence",
    )
    fabricated = resolved_context.checkpoint.recent_evidence_refs[0].model_copy(
        update={
            "evidence_id": "evidence.fabricated",
            "cas_digest": "sha256:" + "f" * 64,
            "observation_ids": ("observation.fabricated",),
        }
    )
    checkpoint = resolved_context.checkpoint.model_copy(
        update={"recent_evidence_refs": (fabricated,)}
    )
    resolved_context = resolved_context.model_copy(
        update={
            "checkpoint": checkpoint,
            "checkpoint_binding_tag": checkpoint_binding_tag_for(
                checkpoint,
                engagement_id=resolved_context.engagement_id,
                binding_key=DEFAULT_RETRIEVAL_KEY,
            ),
        }
    )
    reconciliation = make_reconciliation(resolved_context)

    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )

        with pytest.raises(CheckpointConflictError, match="durable evidence"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(reconciliation,),
            )

        assert active.ledger is not None
        assert tuple(event.event_type for event in active.ledger.events()) == (
            "runtime.checkpoint.v1",
        )


def test_evidence_linked_reconciliation_atomically_resolves_unknown_action(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    reconciliation = make_reconciliation(resolved_context)
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        assert (
            controller.record_action_reconciliation(
                reconciliation,
                evidence=RECONCILIATION_EVIDENCE,
            )
            == reconciliation
        )
        assert (
            controller.record_action_reconciliation(
                reconciliation,
                evidence=RECONCILIATION_EVIDENCE,
            )
            == reconciliation
        )
        assert active.ledger is not None
        assert tuple(event.event_type for event in active.ledger.events()) == (
            "runtime.checkpoint.v1",
            "runtime.action_reconciliation.v1",
        )
        packet = controller.write(
            reason=CheckpointReason.BEFORE_STATE_CHANGE,
            run_manifest=make_manifest(),
            context_state=resolved_context,
            action_reconciliations=(reconciliation,),
        )
        floor = active.checkpoint()
        policy = trust_policy_for(packet, minimum_anchor=floor)

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        restored = CheckpointController(reopened).resume(policy)

    assert restored.action_reconciliations == (reconciliation,)
    assert restored.blocked_action_ids == ()
    assert restored.requires_reconciliation is False
    assert restored.dispatch_ready is True


def test_reconciliation_stage_is_bound_to_its_immediate_predecessor(
    tmp_path: Path,
) -> None:
    old_clearing_context = make_context(
        sequence=3,
        watermark=12,
        checkpoint_id="checkpoint.stale-clear",
    )
    old_reconciliation = make_reconciliation(old_clearing_context)
    newer_evidence = b"newer durable operator reconciliation evidence\n"
    intermediate_context = make_context(
        sequence=2,
        watermark=11,
        checkpoint_id="checkpoint.after-stage",
        unknown=("action.unknown",),
        evidence_bytes=newer_evidence,
        evidence_id="evidence.after-stage",
        observation_ids=("observation.after-stage",),
    )
    new_clearing_context = make_context(
        sequence=3,
        watermark=12,
        checkpoint_id="checkpoint.fresh-clear",
        evidence_bytes=newer_evidence,
        evidence_id="evidence.after-stage",
        observation_ids=("observation.after-stage",),
    )
    new_reconciliation = make_reconciliation(new_clearing_context).model_copy(
        update={"reconciliation_id": "reconciliation.action.unknown.after-stage"}
    )

    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        controller.record_action_reconciliation(
            old_reconciliation,
            evidence=RECONCILIATION_EVIDENCE,
        )
        intermediate = write_checkpoint(controller, intermediate_context)
        before_stale_clear = active.checkpoint()

        with pytest.raises(CheckpointConflictError, match="different state or predecessor"):
            controller.record_action_reconciliation(
                old_reconciliation,
                evidence=RECONCILIATION_EVIDENCE,
            )
        with pytest.raises(CheckpointConflictError, match="immediate predecessor"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=old_clearing_context,
                action_reconciliations=(old_reconciliation,),
            )

        assert active.checkpoint() == before_stale_clear
        assert active.ledger is not None
        assert tuple(event.event_type for event in active.ledger.events()) == (
            "runtime.checkpoint.v1",
            "runtime.action_reconciliation.v1",
            "runtime.checkpoint.v1",
        )
        stale_floor = active.checkpoint()
        stale_policy = trust_policy_for(intermediate, minimum_anchor=stale_floor)

    with open_store(tmp_path, minimum_anchor=stale_floor) as reopened:
        controller = CheckpointController(reopened)
        inspected = controller.inspect(stale_policy)
        assert inspected.blocked_action_ids == ("action.unknown",)
        with pytest.raises(ReconciliationRequiredError, match="action.unknown"):
            controller.resume(stale_policy)
        controller.record_action_reconciliation(
            new_reconciliation,
            evidence=newer_evidence,
        )
        resolved = controller.write(
            reason=CheckpointReason.BEFORE_STATE_CHANGE,
            run_manifest=make_manifest(),
            context_state=new_clearing_context,
            action_reconciliations=(new_reconciliation,),
        )
        floor = reopened.checkpoint()
        policy = trust_policy_for(resolved, minimum_anchor=floor)

    with open_store(tmp_path, minimum_anchor=floor) as final:
        restored = CheckpointController(final).resume(policy)
        assert restored.dispatch_ready is True
        assert restored.action_reconciliations == (new_reconciliation,)
        assert final.ledger is not None
        assert tuple(event.event_type for event in final.ledger.events()) == (
            "runtime.checkpoint.v1",
            "runtime.action_reconciliation.v1",
            "runtime.checkpoint.v1",
            "runtime.action_reconciliation.v1",
            "runtime.checkpoint.v1",
        )


def test_durable_reconciliation_without_clearing_checkpoint_stays_blocked(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    reconciliation = make_reconciliation(resolved_context)
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        blocked = write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        controller.record_action_reconciliation(
            reconciliation,
            evidence=RECONCILIATION_EVIDENCE,
        )
        floor = active.checkpoint()
        policy = trust_policy_for(blocked, minimum_anchor=floor)

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        controller = CheckpointController(reopened)
        with pytest.raises(ReconciliationRequiredError, match="action.unknown"):
            controller.resume(policy)
        assert reopened.ledger is not None
        assert tuple(event.event_type for event in reopened.ledger.events()) == (
            "runtime.checkpoint.v1",
            "runtime.action_reconciliation.v1",
        )


def test_recorded_reconciliation_requires_exact_evidence_bytes(tmp_path: Path) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    reconciliation = make_reconciliation(resolved_context)
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )

        with pytest.raises(CheckpointConflictError, match="evidence bytes"):
            controller.record_action_reconciliation(
                reconciliation,
                evidence=b"fabricated replacement",
            )

        assert active.ledger is not None
        assert len(active.ledger.events()) == 1


def test_untyped_observation_cannot_authenticate_action_reconciliation(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    reconciliation = make_reconciliation(resolved_context)
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        active.append_observation(
            actor_stream="researcher",
            event_type="tool.observation",
            raw_output=RECONCILIATION_EVIDENCE,
            metadata={"observation_id": "observation.1"},
        )

        with pytest.raises(CheckpointConflictError, match="durable evidence"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(reconciliation,),
            )

        assert active.ledger is not None
        assert tuple(event.event_type for event in active.ledger.events()) == (
            "runtime.checkpoint.v1",
            "tool.observation",
        )


def test_clearing_checkpoint_must_match_exact_durable_reconciliation(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    recorded = make_reconciliation(resolved_context)
    conflicting = recorded.model_copy(update={"outcome": DispatchOutcome.FAILED})
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        controller.record_action_reconciliation(
            recorded,
            evidence=RECONCILIATION_EVIDENCE,
        )

        with pytest.raises(CheckpointConflictError, match="differs from prior"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(conflicting,),
            )

        assert active.ledger is not None
        assert len(active.ledger.events()) == 2


def test_reconciliation_must_match_the_prior_unresolved_state(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    reconciliation = make_reconciliation(
        resolved_context,
        prior_state=UnresolvedActionState.PENDING,
    )
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )

        with pytest.raises(CheckpointConflictError, match="prior state"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(reconciliation,),
            )


def test_reconciliation_requires_checkpoint_linked_terminal_evidence(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    valid = make_reconciliation(resolved_context)
    unlinked = valid.model_copy(
        update={
            "evidence_ref": valid.evidence_ref.model_copy(
                update={"evidence_id": "evidence.unlinked"}
            )
        }
    )
    nonterminal = valid.model_copy(
        update={"outcome": DispatchOutcome.UNKNOWN_OUTCOME}
    )
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )

        with pytest.raises(ValueError, match="checkpoint-linked"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(unlinked,),
            )
        with pytest.raises(ValueError, match="terminal outcome"):
            controller.write(
                reason=CheckpointReason.BEFORE_STATE_CHANGE,
                run_manifest=make_manifest(),
                context_state=resolved_context,
                action_reconciliations=(nonterminal,),
            )


def test_reconciled_action_id_cannot_be_reintroduced_as_unresolved(
    tmp_path: Path,
) -> None:
    resolved_context = make_context(
        sequence=2,
        checkpoint_id="checkpoint.reconciled",
    )
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(
            controller,
            make_context(unknown=("action.unknown",)),
        )
        reconciliation = make_reconciliation(resolved_context)
        controller.record_action_reconciliation(
            reconciliation,
            evidence=RECONCILIATION_EVIDENCE,
        )
        controller.write(
            reason=CheckpointReason.BEFORE_STATE_CHANGE,
            run_manifest=make_manifest(),
            context_state=resolved_context,
            action_reconciliations=(reconciliation,),
        )

        with pytest.raises(CheckpointConflictError, match="become unresolved"):
            write_checkpoint(
                controller,
                make_context(
                    sequence=3,
                    checkpoint_id="checkpoint.reintroduced",
                    pending=("action.unknown",),
                ),
            )


def test_failover_intent_survives_resume_and_target_model_continues(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        intent = make_failover_intent()
        first = controller.write(
            reason=CheckpointReason.BEFORE_PROVIDER_FAILOVER,
            run_manifest=make_manifest(),
            context_state=make_context(),
            failover_intent=intent,
        )
        policy = trust_policy_for(first, minimum_anchor=active.checkpoint())

        restored = controller.resume(policy)
        assert restored.failover_intent == intent
        assert restored.failover_required is True
        assert restored.dispatch_ready is False

        target_manifest = make_manifest().model_copy(update={"model": intent.to_model})
        drifted_target = target_manifest.model_copy(
            update={"pack_ids": ("pack.unplanned",)}
        )
        with pytest.raises(CheckpointConflictError, match="exact target model"):
            controller.write(
                reason=CheckpointReason.TURN_END,
                run_manifest=drifted_target,
                context_state=make_context(
                    sequence=2,
                    checkpoint_id="checkpoint.drifted-failover",
                ),
            )
        continuation = controller.write(
            reason=CheckpointReason.TURN_END,
            run_manifest=target_manifest,
            context_state=make_context(
                sequence=2,
                checkpoint_id="checkpoint.failover-complete",
            ),
        )

        assert continuation.run_manifest.model == intent.to_model
        assert continuation.failover_intent is None
        assert continuation.failover_required is False
        assert continuation.dispatch_ready is True


def test_unplanned_manifest_change_is_rejected_without_failover_intent(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(controller, make_context())
        changed_manifest = make_manifest().model_copy(
            update={"model": make_failover_intent().to_model}
        )

        with pytest.raises(CheckpointConflictError, match="manifest changed"):
            controller.write(
                reason=CheckpointReason.TURN_END,
                run_manifest=changed_manifest,
                context_state=make_context(
                    sequence=2,
                    checkpoint_id="checkpoint.unplanned-model-change",
                ),
            )


def test_crash_before_ledger_commit_leaves_no_resumable_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    given_context = make_context()
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        assert active.ledger is not None
        original_append = active.ledger.append

        def interrupted_append(**_values: object) -> None:
            raise StorageError("simulated crash before ledger commit")

        monkeypatch.setattr(active.ledger, "append", interrupted_append)
        with pytest.raises(StorageError, match="simulated crash"):
            write_checkpoint(controller, given_context)
        monkeypatch.setattr(active.ledger, "append", original_append)

        assert active.ledger.events() == ()
        assert active.cas is not None
        assert active.cas.blob_digests()

    with open_store(tmp_path) as reopened:
        report = reopened.recover()
        assert report.quarantined_orphans
        assert reopened.ledger is not None
        assert reopened.ledger.events() == ()
        assert reopened.cas is not None
        assert reopened.cas.blob_digests() == ()


def test_lost_success_response_is_idempotent_after_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    given_context = make_context()
    with open_store(tmp_path) as active:
        original_append = active.append_observation

        def append_then_lose_response(
            *,
            actor_stream: str,
            event_type: str,
            raw_output: bytes,
            metadata: Mapping[str, object],
            media_type: str = "application/octet-stream",
        ) -> tuple[EventRecord, ArtifactRef]:
            original_append(
                actor_stream=actor_stream,
                event_type=event_type,
                raw_output=raw_output,
                metadata=metadata,
                media_type=media_type,
            )
            raise StorageError("simulated crash after durable commit")

        monkeypatch.setattr(
            active,
            "append_observation",
            append_then_lose_response,
        )
        with pytest.raises(StorageError, match="after durable commit"):
            write_checkpoint(CheckpointController(active), given_context)

    with open_store(tmp_path) as reopened:
        when_retried = write_checkpoint(
            CheckpointController(reopened),
            given_context,
        )
        assert when_retried.context_state == given_context
        assert reopened.ledger is not None
        assert len(reopened.ledger.events()) == 1


def test_tampered_policy_and_cross_engagement_state_fail_closed(tmp_path: Path) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        packet = write_checkpoint(controller, make_context())
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())
        tampered = policy.model_copy(update={"goal_digest": D1})
        with pytest.raises(ResumeTrustError, match="goal"):
            controller.inspect(tampered)

    with open_store(tmp_path / "other", engagement_id="engagement.2") as other:
        with pytest.raises(ResumeTrustError, match="engagement"):
            CheckpointController(other).inspect(policy)


def test_checkpoint_metadata_must_match_embedded_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with open_store(tmp_path) as active:
        original_append = active.append_observation

        def append_with_mismatched_metadata(
            *,
            actor_stream: str,
            event_type: str,
            raw_output: bytes,
            metadata: Mapping[str, object],
            media_type: str = "application/octet-stream",
        ) -> tuple[EventRecord, ArtifactRef]:
            mismatched = dict(metadata)
            mismatched["run_id"] = "run.other"
            return original_append(
                actor_stream=actor_stream,
                event_type=event_type,
                raw_output=raw_output,
                metadata=mismatched,
                media_type=media_type,
            )

        monkeypatch.setattr(
            active,
            "append_observation",
            append_with_mismatched_metadata,
        )
        packet = write_checkpoint(CheckpointController(active), make_context())
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())

        with pytest.raises(CheckpointIntegrityError, match="metadata"):
            CheckpointController(active).inspect(policy)


def test_checkpoint_ciphertext_tamper_is_rejected(tmp_path: Path) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        packet = write_checkpoint(controller, make_context())
        policy = trust_policy_for(packet, minimum_anchor=active.checkpoint())
        assert active.ledger is not None
        reference = active.ledger.events()[0].payload["artifact_ref"]

    namespace = hashlib.sha256(b"engagement.1").hexdigest()
    digest = reference["sha256"]
    ciphertext = state_root(tmp_path) / "cas" / namespace / digest[:2] / f"{digest}.flcas"
    body = bytearray(ciphertext.read_bytes())
    body[-1] ^= 1
    ciphertext.write_bytes(body)

    with open_store(tmp_path) as reopened:
        with pytest.raises((ChainIntegrityError, StorageError)):
            CheckpointController(reopened).inspect(policy)
