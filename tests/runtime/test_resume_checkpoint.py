from __future__ import annotations

from pathlib import Path

import pytest

from faultloom.resume import (
    CheckpointConflictError,
    CheckpointController,
    CheckpointReason,
    trust_policy_for,
)
from tests.runtime.resume_support import (
    make_context,
    make_manifest,
    open_store,
    write_checkpoint,
)


@pytest.mark.parametrize("reason", tuple(CheckpointReason))
def test_every_boundary_persists_the_complete_context(
    tmp_path: Path,
    reason: CheckpointReason,
) -> None:
    given_context = make_context(pending=("action.pending",))
    with open_store(tmp_path) as active:
        packet = write_checkpoint(
            CheckpointController(active),
            given_context,
            reason=reason,
        )
        floor = active.checkpoint()
        policy = trust_policy_for(packet, minimum_anchor=floor)

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        when_restored = CheckpointController(reopened).inspect(policy)

    assert when_restored.context_state == given_context
    assert when_restored.run_manifest == make_manifest()
    assert when_restored.reason is reason
    assert when_restored.context_state.active_hypotheses == given_context.active_hypotheses
    assert (
        when_restored.context_state.important_negative_results
        == given_context.important_negative_results
    )
    assert when_restored.context_state.graph_slices == given_context.graph_slices
    assert (
        when_restored.context_state.checkpoint.retrieval_cursors
        == given_context.checkpoint.retrieval_cursors
    )
    assert (
        when_restored.context_state.checkpoint.remaining_budget
        == given_context.checkpoint.remaining_budget
    )


def test_checkpoint_identity_is_idempotent_and_immutable(tmp_path: Path) -> None:
    given_context = make_context()
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)

        first = write_checkpoint(controller, given_context)
        when_repeated = write_checkpoint(controller, given_context)

        assert when_repeated.event_sequence == first.event_sequence
        assert when_repeated.checkpoint_digest == first.checkpoint_digest
        assert active.ledger is not None
        assert len(active.ledger.events()) == 1

        conflicting = make_context(
            sequence=2,
            watermark=11,
            checkpoint_id=given_context.checkpoint.checkpoint_id,
        )
        with pytest.raises(CheckpointConflictError, match="checkpoint ID"):
            write_checkpoint(controller, conflicting)
        assert len(active.ledger.events()) == 1


def test_sequence_and_stable_watermark_never_move_backwards(tmp_path: Path) -> None:
    with open_store(tmp_path) as active:
        controller = CheckpointController(active)
        write_checkpoint(controller, make_context(watermark=11))

        with pytest.raises(CheckpointConflictError, match="sequence"):
            write_checkpoint(
                controller,
                make_context(sequence=1, checkpoint_id="checkpoint.other"),
            )
        with pytest.raises(CheckpointConflictError, match="watermark"):
            write_checkpoint(controller, make_context(sequence=2, watermark=10))
        with pytest.raises(CheckpointConflictError, match="advance"):
            write_checkpoint(
                controller,
                make_context(sequence=2, watermark=11),
                reason=CheckpointReason.STABLE_WATERMARK,
            )


def test_failover_boundary_requires_a_typed_intent(tmp_path: Path) -> None:
    with open_store(tmp_path) as active:
        with pytest.raises(ValueError, match="failover intent"):
            CheckpointController(active).write(
                reason=CheckpointReason.BEFORE_PROVIDER_FAILOVER,
                run_manifest=make_manifest(),
                context_state=make_context(),
            )
