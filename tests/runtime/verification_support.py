from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from faultloom.verification import (
    ClaimDraft,
    ControlResult,
    ReplayExecutionRequest,
    ReplayExecutionResult,
    ResultArtifactContext,
    ResultArtifactDraft,
    ResultExpectations,
    VerificationCase,
    VerifierAuthorizationRequest,
    assemble_claim_packet,
    authorize_verifier,
    sign_verification_result,
    verify_candidate,
)
from faultloom_protocol import (
    AuthoritySigner,
    ClaimPacket,
    EvidenceRef,
    FindingCandidate,
    ReplayPlan,
    SignedRunResultBundle,
    VerificationVerdict,
    sign_authority_grant,
)
from tests.protocol.factories import D1, D3, D4, NOW, sample_models


@dataclass(frozen=True, slots=True)
class ReplayFixtureOptions:
    positive_passed: bool = True
    include_negative_control: bool = True
    final_effect_observed: bool = True
    include_secret_text: bool = False


class RecordingReplayExecutor:
    def __init__(self, result: ReplayExecutionResult) -> None:
        self.result = result
        self.requests: list[ReplayExecutionRequest] = []

    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult:
        self.requests.append(request)
        return self.result


@dataclass(frozen=True, slots=True)
class VerificationFixture:
    candidate: FindingCandidate
    claim: ClaimPacket
    replay_plan: ReplayPlan
    authorization_request: VerifierAuthorizationRequest
    executor: RecordingReplayExecutor
    verdict: VerificationVerdict
    signed_result: SignedRunResultBundle
    result_signer: AuthoritySigner
    expectations: ResultExpectations


def build_verification_fixture(
    options: ReplayFixtureOptions = ReplayFixtureOptions(),
) -> VerificationFixture:
    values = sample_models()
    candidate = values["FindingCandidate"]
    replay_plan = values["ReplayPlan"]
    source_result = values["RunResultBundle"]
    if not isinstance(candidate, FindingCandidate):
        raise AssertionError("protocol fixture returned the wrong candidate type")
    if not isinstance(replay_plan, ReplayPlan):
        raise AssertionError("protocol fixture returned the wrong replay type")

    if options.include_secret_text:
        candidate = candidate.model_copy(
            update={"title": "Authorization: Bearer should-not-render"}
        )
    original_evidence = candidate.evidence_refs[0]
    claim = assemble_claim_packet(
        candidate,
        ClaimDraft(
            claim_id="claim.verification",
            claim=(
                "Read secret://run/raw-token from an owned canary."
                if options.include_secret_text
                else "Read the owned cross-tenant canary."
            ),
            prerequisites=("Two operator-provisioned identities",),
            evidence_refs=(original_evidence,),
            negative_control_refs=(original_evidence,),
            replay_plan=replay_plan,
            cleanup_plan_ref=None,
            created_at=NOW,
        ),
    )

    authority_signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    source_grant = values["AuthorityGrant"]
    verifier_grant = source_grant.model_copy(
        update={
            "grant_id": "grant.verifier",
            "grant_version": 4,
            "issued_to": "verifier.1",
        }
    )
    signed_verifier_authority = sign_authority_grant(
        verifier_grant,
        authority_signer,
        signed_at=NOW,
    )
    authorization_request = VerifierAuthorizationRequest(
        source_actor_id="researcher.1",
        verifier_actor_id="verifier.1",
        verifier_run_id="verify.run-1",
        signed_authority=signed_verifier_authority,
        trusted_authority_key=authority_signer.public_key_record,
        verification_time=NOW + timedelta(seconds=1),
    )
    authorized_verifier = authorize_verifier(authorization_request)

    evidence_base = values["EvidenceRef"]
    if not isinstance(evidence_base, EvidenceRef):
        raise AssertionError("protocol fixture returned the wrong evidence type")
    positive_evidence = evidence_base.model_copy(
        update={
            "evidence_id": "evidence.verify-positive",
            "cas_digest": D3,
            "redaction_digest": D4,
        }
    )
    negative_evidence = evidence_base.model_copy(
        update={
            "evidence_id": "evidence.verify-negative",
            "cas_digest": D4,
            "redaction_digest": D3,
        }
    )
    negative_controls = (
        (
            ControlResult(
                edge_id=replay_plan.negative_control_edge_ids[0],
                passed=True,
                evidence_refs=(negative_evidence,),
            ),
        )
        if options.include_negative_control
        else ()
    )
    replay_result = ReplayExecutionResult(
        verifier_run_id="verify.run-1",
        reset_state_refs=replay_plan.reset_state_refs,
        positive_controls=(
            ControlResult(
                edge_id=replay_plan.edge_ids[0],
                passed=options.positive_passed,
                evidence_refs=(positive_evidence,),
            ),
        ),
        negative_controls=negative_controls,
        final_effect_observed=options.final_effect_observed,
        cleanup_receipt_digests=(D1,),
    )
    executor = RecordingReplayExecutor(replay_result)
    verdict = verify_candidate(
        VerificationCase(
            candidate=candidate,
            claim=claim,
            replay_plan=replay_plan,
            source_authority_digest=source_result.authority_digest,
            verifier=authorized_verifier,
            verified_at=NOW + timedelta(seconds=2),
        ),
        executor,
    )

    result_signer = AuthoritySigner.from_private_bytes(bytes(range(64, 96)))
    context = ResultArtifactContext(
        bundle_id="result-bundle.verifier-1",
        bundle_version=3,
        engagement_id=source_result.engagement_id,
        run_manifest_digest=source_result.run_manifest_digest,
        source_authority_digest=source_result.authority_digest,
        final_checkpoint_digest=source_result.final_checkpoint_digest,
        generated_at=NOW + timedelta(seconds=3),
        expires_at=None,
    )
    signed_result = sign_verification_result(
        ResultArtifactDraft(
            context=context,
            candidate=candidate,
            claim=claim,
            verdict=verdict,
            cleanup_receipt_digests=replay_result.cleanup_receipt_digests,
        ),
        result_signer,
    )
    expectations = ResultExpectations(
        engagement_id=source_result.engagement_id,
        run_id=candidate.run_id,
        run_manifest_digest=source_result.run_manifest_digest,
        source_authority_digest=source_result.authority_digest,
        source_actor_id="researcher.1",
        verifier_actor_id="verifier.1",
        verifier_authority_digest=authorized_verifier.authority_digest,
        signed_verifier_authority=signed_verifier_authority,
        trusted_verifier_authority_key=authority_signer.public_key_record,
        verification_time=NOW + timedelta(seconds=4),
        minimum_bundle_version=3,
    )
    return VerificationFixture(
        candidate=candidate,
        claim=claim,
        replay_plan=replay_plan,
        authorization_request=authorization_request,
        executor=executor,
        verdict=verdict,
        signed_result=signed_result,
        result_signer=result_signer,
        expectations=expectations,
    )
