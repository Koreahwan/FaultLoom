from __future__ import annotations

from dataclasses import dataclass

from faultloom_protocol import (
    SCHEMA_VERSION,
    EvidenceRef,
    VerificationVerdict,
    VerdictOutcome,
    sha256_digest,
)

from .authority import require_authorized_verifier
from .contracts import (
    ControlResult,
    ReplayExecutionRequest,
    ReplayExecutor,
    VerificationCase,
)
from .provenance import (
    AutomationDispatchProvenanceError,
    automation_dispatch_provenance_marker,
    validate_automation_dispatch_provenance,
)


VERIFIER_ACTOR_MARKER = "faultloom:verifier_actor="
VERIFIER_AUTHORITY_MARKER = "faultloom:verifier_authority="
REPLAY_PLAN_MARKER = "faultloom:replay_plan="


@dataclass(frozen=True, slots=True)
class VerificationInputError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def verifier_markers(
    actor_id: str,
    authority_digest: str,
    replay_plan_digest: str,
) -> tuple[str, str, str]:
    return (
        f"{VERIFIER_ACTOR_MARKER}{actor_id}",
        f"{VERIFIER_AUTHORITY_MARKER}{authority_digest}",
        f"{REPLAY_PLAN_MARKER}{replay_plan_digest}",
    )


def _validate_case(case: VerificationCase) -> None:
    verifier = require_authorized_verifier(case.verifier)
    if case.candidate.run_id != case.claim.run_id:
        raise VerificationInputError(reason="candidate and claim run IDs differ")
    if case.candidate.candidate_id != case.claim.candidate_id:
        raise VerificationInputError(reason="claim belongs to a different candidate")
    if case.claim.replay_plan_id != case.replay_plan.replay_plan_id:
        raise VerificationInputError(reason="claim identifies a different replay plan")
    if not case.candidate.final_effect_observed:
        raise VerificationInputError(reason="candidate has no observed final effect")
    if verifier.authority_digest == case.source_authority_digest:
        raise VerificationInputError(
            reason="verifier authority must be separate from source authority"
        )
    if not case.replay_plan.fresh_identity_context_ids:
        raise VerificationInputError(reason="replay plan has no fresh identity context")
    if not case.replay_plan.reset_state_refs:
        raise VerificationInputError(reason="replay plan has no clean reset state")
    if not case.replay_plan.edge_ids or not case.replay_plan.negative_control_edge_ids:
        raise VerificationInputError(reason="replay plan is missing a control class")
    provenance = case.automation_dispatch_provenance
    if provenance is not None:
        try:
            validate_automation_dispatch_provenance(provenance)
        except AutomationDispatchProvenanceError as exc:
            raise VerificationInputError(reason=str(exc)) from exc
        record = provenance.dispatch.envelope.record
        if record.run_id != case.candidate.run_id:
            raise VerificationInputError(
                reason="automation dispatch provenance belongs to a different candidate run"
            )
        if record.candidate_id != case.candidate.candidate_id:
            raise VerificationInputError(
                reason="automation dispatch provenance belongs to a different candidate"
            )


def _control_ids(controls: tuple[ControlResult, ...]) -> tuple[str, ...]:
    return tuple(control.edge_id for control in controls)


def _replay_evidence(
    controls: tuple[ControlResult, ...],
) -> tuple[tuple[EvidenceRef, ...], bool]:
    ordered: list[EvidenceRef] = []
    seen: dict[str, EvidenceRef] = {}
    consistent = True
    for control in controls:
        for reference in control.evidence_refs:
            previous = seen.get(reference.evidence_id)
            if previous is None:
                seen[reference.evidence_id] = reference
                ordered.append(reference)
            elif previous != reference:
                consistent = False
    return tuple(ordered), consistent


def verify_candidate(
    case: VerificationCase,
    executor: ReplayExecutor,
) -> VerificationVerdict:
    _validate_case(case)
    verifier = case.verifier
    replay_digest = sha256_digest(case.replay_plan)
    execution = executor.execute(
        ReplayExecutionRequest(
            verifier_run_id=verifier.verifier_run_id,
            verifier_actor_id=verifier.verifier_actor_id,
            verifier_authority_digest=verifier.authority_digest,
            claim_packet_digest=sha256_digest(case.claim),
            replay_plan=case.replay_plan,
        )
    )
    controls = (*execution.positive_controls, *execution.negative_controls)
    evidence, evidence_consistent = _replay_evidence(controls)
    provenance = case.automation_dispatch_provenance
    if provenance is not None:
        evidence = (*evidence, provenance.dispatch.evidence_ref)
    source_evidence_ids = {
        reference.evidence_id
        for reference in (*case.claim.evidence_refs, *case.claim.negative_control_refs)
    }
    incomplete: list[str] = []
    if execution.verifier_run_id != verifier.verifier_run_id:
        incomplete.append("verification.verifier_run_mismatch")
    if execution.reset_state_refs != case.replay_plan.reset_state_refs:
        incomplete.append("verification.clean_state_mismatch")
    if _control_ids(execution.positive_controls) != case.replay_plan.edge_ids:
        incomplete.append("verification.positive_control_set_incomplete")
    if _control_ids(execution.negative_controls) != case.replay_plan.negative_control_edge_ids:
        incomplete.append("verification.negative_control_set_incomplete")
    if any(not control.evidence_refs for control in controls):
        incomplete.append("verification.control_evidence_missing")
    if not evidence_consistent:
        incomplete.append("verification.evidence_id_collision")
    if any(reference.run_id != case.candidate.run_id for reference in evidence):
        incomplete.append("verification.evidence_run_mismatch")
    if any(reference.evidence_id in source_evidence_ids for reference in evidence):
        incomplete.append("verification.source_evidence_reused")

    rejected: list[str] = []
    if any(not control.passed for control in execution.positive_controls):
        rejected.append("verification.positive_control_failed")
    if any(not control.passed for control in execution.negative_controls):
        rejected.append("verification.negative_control_failed")
    if not execution.final_effect_observed:
        rejected.append("verification.final_effect_absent")

    if incomplete:
        outcome = VerdictOutcome.INCONCLUSIVE
        reasons = tuple(incomplete)
    elif rejected:
        outcome = VerdictOutcome.REJECTED
        reasons = tuple(rejected)
    else:
        outcome = VerdictOutcome.VERIFIED
        reasons = (
            "verification.clean_replay",
            "verification.positive_controls_passed",
            "verification.negative_controls_passed",
            "verification.final_effect_observed",
        )
    reasons = (
        *reasons,
        *verifier_markers(
            verifier.verifier_actor_id,
            verifier.authority_digest,
            replay_digest,
        ),
        *(
            (automation_dispatch_provenance_marker(provenance),)
            if provenance is not None
            else ()
        ),
    )
    verdict_digest = sha256_digest(
        {
            "claim_packet_digest": sha256_digest(case.claim),
            "verifier_run_id": verifier.verifier_run_id,
        }
    ).removeprefix("sha256:")
    return VerificationVerdict(
        schema_version=SCHEMA_VERSION,
        verdict_id=f"verdict.{verdict_digest[:32]}",
        run_id=case.candidate.run_id,
        claim_id=case.claim.claim_id,
        claim_packet_digest=sha256_digest(case.claim),
        verifier_run_id=verifier.verifier_run_id,
        outcome=outcome,
        independent_replay=True,
        reasons=reasons,
        evidence_refs=evidence,
        verified_at=case.verified_at,
    )
