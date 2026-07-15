from __future__ import annotations

from dataclasses import dataclass

from faultloom_protocol import SCHEMA_VERSION, ClaimPacket, FindingCandidate

from .contracts import ClaimDraft


@dataclass(frozen=True, slots=True)
class ClaimAssemblyError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def _has_duplicates(values: tuple[str, ...]) -> bool:
    return len(values) != len(set(values))


def assemble_claim_packet(
    candidate: FindingCandidate,
    draft: ClaimDraft,
) -> ClaimPacket:
    if not candidate.final_effect_observed:
        raise ClaimAssemblyError(reason="a claim requires an observed final effect")
    if not draft.evidence_refs:
        raise ClaimAssemblyError(reason="a claim requires positive evidence")
    if not draft.negative_control_refs:
        raise ClaimAssemblyError(reason="a claim requires a negative control")
    if draft.created_at < candidate.created_at:
        raise ClaimAssemblyError(reason="a claim cannot predate its candidate")
    replay = draft.replay_plan
    if not replay.fresh_identity_context_ids or not replay.reset_state_refs:
        raise ClaimAssemblyError(reason="a replay plan requires fresh identity and reset state")
    if not replay.edge_ids or not replay.negative_control_edge_ids:
        raise ClaimAssemblyError(reason="a replay plan requires positive and negative controls")
    if _has_duplicates(replay.edge_ids) or _has_duplicates(replay.negative_control_edge_ids):
        raise ClaimAssemblyError(reason="a replay plan cannot contain duplicate control edges")
    candidate_evidence = candidate.evidence_refs
    claim_evidence = (*draft.evidence_refs, *draft.negative_control_refs)
    if any(reference.run_id != candidate.run_id for reference in claim_evidence):
        raise ClaimAssemblyError(reason="claim evidence belongs to a different run")
    if any(reference not in candidate_evidence for reference in claim_evidence):
        raise ClaimAssemblyError(reason="claim evidence is not bound to the candidate")
    if replay.cleanup_plan_ref != draft.cleanup_plan_ref:
        raise ClaimAssemblyError(reason="claim and replay cleanup plans differ")
    return ClaimPacket(
        schema_version=SCHEMA_VERSION,
        claim_id=draft.claim_id,
        candidate_id=candidate.candidate_id,
        run_id=candidate.run_id,
        claim=draft.claim,
        prerequisites=draft.prerequisites,
        evidence_refs=draft.evidence_refs,
        negative_control_refs=draft.negative_control_refs,
        replay_plan_id=replay.replay_plan_id,
        cleanup_plan_ref=draft.cleanup_plan_ref,
        created_at=draft.created_at,
    )
