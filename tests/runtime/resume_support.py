from __future__ import annotations

import hashlib
from pathlib import Path

from faultloom.context import ContextState, checkpoint_binding_tag_for
from faultloom.resume import (
    ActionReconciliation,
    CheckpointController,
    CheckpointReason,
    FailoverIntent,
    ResumePacket,
    UnresolvedActionState,
)
from faultloom.state import AnchorCheckpoint, EngagementKey, StateStore
from faultloom_protocol import DispatchOutcome, ModelIdentity, RunManifest
from tests.protocol.factories import NOW, sample_models
from tests.runtime.test_context import DEFAULT_RETRIEVAL_KEY, context_state


KEY_BYTES = bytes(range(32))
RECONCILIATION_EVIDENCE = b"durable operator reconciliation evidence\n"
RECONCILIATION_EVIDENCE_DIGEST = (
    f"sha256:{hashlib.sha256(RECONCILIATION_EVIDENCE).hexdigest()}"
)


def state_root(root: Path) -> Path:
    return root / "state"


def anchor_root(root: Path) -> Path:
    return root / "anchor"


def open_store(
    root: Path,
    *,
    engagement_id: str = "engagement.1",
    minimum_anchor: AnchorCheckpoint | None = None,
) -> StateStore:
    return StateStore(
        state_root(root),
        engagement_id,
        EngagementKey(KEY_BYTES),
        anchor_root=anchor_root(root),
        minimum_anchor=minimum_anchor,
    )


def make_context(
    *,
    sequence: int = 1,
    watermark: int = 10,
    checkpoint_id: str | None = None,
    pending: tuple[str, ...] = (),
    unknown: tuple[str, ...] = (),
) -> ContextState:
    base = context_state()
    evidence = base.checkpoint.recent_evidence_refs[0].model_copy(
        update={"cas_digest": RECONCILIATION_EVIDENCE_DIGEST}
    )
    checkpoint = base.checkpoint.model_copy(
        update={
            "checkpoint_id": checkpoint_id or f"checkpoint.{sequence}",
            "sequence": sequence,
            "stable_watermark": watermark,
            "pending_action_ids": pending,
            "unknown_outcome_action_ids": unknown,
            "recent_evidence_refs": (evidence,),
        }
    )
    hypotheses = tuple(
        hypothesis.model_copy(
            update={
                "supporting_evidence": tuple(
                    evidence if reference.evidence_id == evidence.evidence_id else reference
                    for reference in hypothesis.supporting_evidence
                ),
                "contradicting_evidence": tuple(
                    evidence if reference.evidence_id == evidence.evidence_id else reference
                    for reference in hypothesis.contradicting_evidence
                ),
            }
        )
        for hypothesis in base.active_hypotheses
    )
    negative_results = tuple(
        negative.model_copy(
            update={
                "evidence_refs": tuple(
                    evidence if reference.evidence_id == evidence.evidence_id else reference
                    for reference in negative.evidence_refs
                )
            }
        )
        for negative in base.important_negative_results
    )
    return base.model_copy(
        update={
            "checkpoint": checkpoint,
            "checkpoint_binding_tag": checkpoint_binding_tag_for(
                checkpoint,
                engagement_id=base.engagement_id,
                binding_key=DEFAULT_RETRIEVAL_KEY,
            ),
            "active_hypotheses": hypotheses,
            "important_negative_results": negative_results,
        }
    )


def make_manifest() -> RunManifest:
    value = sample_models()["RunManifest"]
    return RunManifest.model_validate(value.model_dump(mode="python"))


def make_failover_intent() -> FailoverIntent:
    current = make_manifest().model
    next_model = ModelIdentity.model_validate(
        current.model_copy(
            update={"actual_snapshot": "frontier-2030-02-01"}
        ).model_dump(mode="python")
    )
    return FailoverIntent(
        from_model_digest=CheckpointController.model_digest(current),
        to_model=next_model,
        requested_at=NOW,
        reason="operator-approved failover boundary",
    )


def make_reconciliation(
    context: ContextState,
    *,
    action_id: str = "action.unknown",
    prior_state: UnresolvedActionState = UnresolvedActionState.UNKNOWN_OUTCOME,
) -> ActionReconciliation:
    checkpoint = context.checkpoint
    return ActionReconciliation(
        reconciliation_id=f"reconciliation.{action_id}",
        action_id=action_id,
        prior_state=prior_state,
        outcome=DispatchOutcome.COMPLETED,
        evidence_ref=checkpoint.recent_evidence_refs[0],
        authority_digest=checkpoint.authority_digest,
        scope_epoch=checkpoint.scope_epoch,
        reconciled_at=NOW,
    )


def write_checkpoint(
    controller: CheckpointController,
    context: ContextState,
    *,
    reason: CheckpointReason = CheckpointReason.TURN_END,
) -> ResumePacket:
    failover = (
        make_failover_intent()
        if reason is CheckpointReason.BEFORE_PROVIDER_FAILOVER
        else None
    )
    return controller.write(
        reason=reason,
        run_manifest=make_manifest(),
        context_state=context,
        failover_intent=failover,
    )
