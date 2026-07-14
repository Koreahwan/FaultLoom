from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from faultloom.resume import (
    CheckpointController,
    CheckpointIntegrityError,
    CheckpointNotFoundError,
    ReconciliationRequiredError,
    ResumeTrustError,
    trust_policy_for,
)
from faultloom.state import ArtifactRef, ChainIntegrityError, EventRecord, StorageError
from tests.protocol.factories import D1
from tests.runtime.resume_support import (
    make_context,
    open_store,
    state_root,
    write_checkpoint,
)


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
