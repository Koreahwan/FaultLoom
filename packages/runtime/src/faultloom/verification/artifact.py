from __future__ import annotations

from dataclasses import dataclass

from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    EvidenceRef,
    RunResultBundle,
    SignedRunResultBundle,
    SignatureVerificationError,
    sha256_digest,
    sign_run_result_bundle,
    verify_run_result_bundle,
)

from .contracts import (
    ResultArtifactDraft,
    ResultExpectations,
    VerifierBinding,
)
from .authority import (
    VerifierAuthorizationError,
    VerifierAuthorizationRequest,
    authorize_verifier,
)
from .engine import VERIFIER_ACTOR_MARKER, VERIFIER_AUTHORITY_MARKER
from .provenance import (
    AutomationDispatchProvenance,
    AutomationDispatchProvenanceError,
    automation_dispatch_provenance_marker,
    validate_automation_dispatch_provenance,
)


@dataclass(frozen=True, slots=True)
class _ArtifactProof:
    envelope_digest: str
    payload_digest: str
    verifier: VerifierBinding
    automation_dispatch_provenance: AutomationDispatchProvenance | None


@dataclass(frozen=True, slots=True)
class ArtifactVerificationError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class VerifiedResultArtifact:
    envelope: SignedRunResultBundle
    payload: RunResultBundle
    verifier: VerifierBinding
    automation_dispatch_provenance: AutomationDispatchProvenance | None
    _proof: _ArtifactProof


def _collect_evidence(draft: ResultArtifactDraft) -> tuple[EvidenceRef, ...]:
    ordered: list[EvidenceRef] = []
    seen: dict[str, EvidenceRef] = {}
    references = (
        *draft.candidate.evidence_refs,
        *draft.claim.evidence_refs,
        *draft.claim.negative_control_refs,
        *draft.verdict.evidence_refs,
        *(
            (draft.automation_dispatch_provenance.dispatch.evidence_ref,)
            if draft.automation_dispatch_provenance is not None
            else ()
        ),
    )
    for reference in references:
        previous = seen.get(reference.evidence_id)
        if previous is not None and previous != reference:
            raise ArtifactVerificationError(reason="result evidence ID collision")
        if previous is None:
            seen[reference.evidence_id] = reference
            ordered.append(reference)
    return tuple(ordered)


def sign_verification_result(
    draft: ResultArtifactDraft,
    signer: AuthoritySigner,
) -> SignedRunResultBundle:
    context = draft.context
    if draft.claim.candidate_id != draft.candidate.candidate_id:
        raise ArtifactVerificationError(reason="claim belongs to a different candidate")
    if draft.verdict.claim_id != draft.claim.claim_id:
        raise ArtifactVerificationError(reason="verdict belongs to a different claim")
    if draft.verdict.verified_at > context.generated_at:
        raise ArtifactVerificationError(reason="result generation predates its verdict")
    provenance = draft.automation_dispatch_provenance
    provenance_markers = _provenance_markers((draft.verdict,))
    if provenance is None and provenance_markers:
        raise ArtifactVerificationError(
            reason="verification verdict contains unbound automation dispatch provenance"
        )
    if provenance is not None:
        try:
            validate_automation_dispatch_provenance(provenance)
        except AutomationDispatchProvenanceError as exc:
            raise ArtifactVerificationError(reason=str(exc)) from exc
        record = provenance.dispatch.envelope.record
        if record.run_id != draft.candidate.run_id:
            raise ArtifactVerificationError(
                reason="automation dispatch provenance belongs to a different candidate run"
            )
        if record.candidate_id != draft.candidate.candidate_id:
            raise ArtifactVerificationError(
                reason="automation dispatch provenance belongs to a different candidate"
            )
        marker = automation_dispatch_provenance_marker(provenance)
        if (
            provenance_markers != (marker,)
            or provenance.dispatch.evidence_ref not in draft.verdict.evidence_refs
        ):
            raise ArtifactVerificationError(
                reason="verification verdict does not bind automation dispatch provenance"
            )
    bundle = RunResultBundle(
        schema_version=SCHEMA_VERSION,
        bundle_id=context.bundle_id,
        bundle_version=context.bundle_version,
        engagement_id=context.engagement_id,
        run_id=draft.candidate.run_id,
        run_manifest_digest=context.run_manifest_digest,
        authority_digest=context.source_authority_digest,
        finding_candidates=(draft.candidate,),
        claim_packets=(draft.claim,),
        verification_verdicts=(draft.verdict,),
        evidence_refs=_collect_evidence(draft),
        final_checkpoint_digest=context.final_checkpoint_digest,
        generated_at=context.generated_at,
        cleanup_receipt_digests=draft.cleanup_receipt_digests,
    )
    return sign_run_result_bundle(
        bundle,
        signer,
        signed_at=context.generated_at,
        expires_at=context.expires_at,
    )


def verify_result_artifact(
    envelope: SignedRunResultBundle,
    trusted_key: Ed25519PublicKeyRecord,
    expectations: ResultExpectations,
) -> VerifiedResultArtifact:
    try:
        payload = verify_run_result_bundle(
            envelope,
            trusted_key,
            now=expectations.verification_time,
            minimum_version=expectations.minimum_bundle_version,
            expected_engagement_id=expectations.engagement_id,
            expected_run_id=expectations.run_id,
            expected_run_manifest_digest=expectations.run_manifest_digest,
            expected_authority_digest=expectations.source_authority_digest,
        )
    except (SignatureVerificationError, ValueError) as exc:
        raise ArtifactVerificationError(
            reason=f"result signature verification failed: {exc}"
        ) from exc
    if not payload.verification_verdicts:
        raise ArtifactVerificationError(reason="result contains no verification verdict")
    verifier_run_ids = {
        verdict.verifier_run_id for verdict in payload.verification_verdicts
    }
    if len(verifier_run_ids) != 1:
        raise ArtifactVerificationError(reason="result contains multiple verifier runs")
    try:
        authorized_verifier = authorize_verifier(
            VerifierAuthorizationRequest(
                source_actor_id=expectations.source_actor_id,
                verifier_actor_id=expectations.verifier_actor_id,
                verifier_run_id=next(iter(verifier_run_ids)),
                signed_authority=expectations.signed_verifier_authority,
                trusted_authority_key=expectations.trusted_verifier_authority_key,
                verification_time=expectations.verification_time,
            )
        )
    except VerifierAuthorizationError as exc:
        raise ArtifactVerificationError(reason=str(exc)) from exc
    if authorized_verifier.authority_digest != expectations.verifier_authority_digest:
        raise ArtifactVerificationError(reason="verifier authority digest differs from expected")
    required_markers = {
        f"{VERIFIER_ACTOR_MARKER}{authorized_verifier.verifier_actor_id}",
        f"{VERIFIER_AUTHORITY_MARKER}{authorized_verifier.authority_digest}",
    }
    if any(
        not required_markers.issubset(verdict.reasons)
        for verdict in payload.verification_verdicts
    ):
        raise ArtifactVerificationError(
            reason="result verifier binding does not match expectations"
        )
    provenance = expectations.automation_dispatch_provenance
    provenance_markers = _provenance_markers(payload.verification_verdicts)
    if provenance is None and provenance_markers:
        raise ArtifactVerificationError(
            reason="result automation dispatch provenance is missing from expectations"
        )
    if provenance is not None:
        try:
            validate_automation_dispatch_provenance(provenance)
        except AutomationDispatchProvenanceError as exc:
            raise ArtifactVerificationError(reason=str(exc)) from exc
        marker = automation_dispatch_provenance_marker(provenance)
        evidence = provenance.dispatch.evidence_ref
        candidate_id = provenance.dispatch.envelope.record.candidate_id
        if (
            len(payload.finding_candidates) != 1
            or payload.finding_candidates[0].candidate_id != candidate_id
            or provenance_markers != (marker,)
            or evidence not in payload.evidence_refs
            or any(
                marker not in verdict.reasons or evidence not in verdict.evidence_refs
                for verdict in payload.verification_verdicts
            )
        ):
            raise ArtifactVerificationError(
                reason="result automation dispatch provenance does not match expectations"
            )
    return VerifiedResultArtifact(
        envelope=envelope,
        payload=payload,
        verifier=VerifierBinding(
            actor_id=authorized_verifier.verifier_actor_id,
            authority_digest=authorized_verifier.authority_digest,
        ),
        automation_dispatch_provenance=provenance,
        _proof=_ArtifactProof(
            envelope_digest=sha256_digest(envelope),
            payload_digest=sha256_digest(payload),
            verifier=VerifierBinding(
                actor_id=authorized_verifier.verifier_actor_id,
                authority_digest=authorized_verifier.authority_digest,
            ),
            automation_dispatch_provenance=provenance,
        ),
    )


def require_verified_result(artifact: VerifiedResultArtifact) -> VerifiedResultArtifact:
    proof = artifact._proof
    if (
        sha256_digest(artifact.envelope) != proof.envelope_digest
        or sha256_digest(artifact.payload) != proof.payload_digest
        or artifact.payload != artifact.envelope.payload
        or artifact.verifier != proof.verifier
        or artifact.automation_dispatch_provenance != proof.automation_dispatch_provenance
    ):
        raise ArtifactVerificationError(reason="result artifact proof is invalid")
    return artifact


def _provenance_markers(verdicts: tuple[object, ...]) -> tuple[str, ...]:
    return tuple(
        reason
        for verdict in verdicts
        for reason in verdict.reasons
        if reason.startswith("faultloom:automation_dispatch_provenance=")
    )
