from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TypedDict, assert_never

from faultloom_protocol import (
    ClaimPacket,
    EvidenceRef,
    FindingCandidate,
    FindingClass,
    VerificationVerdict,
    VerdictOutcome,
    sha256_digest,
)

from .artifact import VerifiedResultArtifact, require_verified_result
from .contracts import (
    ReportArtifact,
    ReportFormat,
    ReportReceipt,
    VerificationSummary,
)
from .provenance import (
    AutomationDispatchProvenanceError,
    automation_dispatch_provenance_marker,
    validate_automation_dispatch_provenance,
)


_SECRET_URI = re.compile(r"secret://[A-Za-z0-9][A-Za-z0-9._/-]*")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_FIELD = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|password)"
    r"\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_SPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class ReportGateError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class _FindingSelection:
    candidate: FindingCandidate
    claim: ClaimPacket
    verdict: VerificationVerdict


class _EvidenceDocument(TypedDict):
    evidence_id: str
    cas_digest: str
    redaction_digest: str | None


def _scrub(value: str) -> str:
    scrubbed = _SECRET_FIELD.sub(lambda match: f"{match.group(1)}: <secret-ref>", value)
    scrubbed = _BEARER.sub("Bearer <secret-ref>", scrubbed)
    scrubbed = _SECRET_URI.sub("<secret-ref>", scrubbed)
    return _SPACE.sub(" ", _CONTROL.sub(" ", scrubbed)).strip()


def _markdown(value: str) -> str:
    escaped = _scrub(value).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _classification(finding_class: FindingClass) -> tuple[str, str]:
    match finding_class:
        case FindingClass.CVE_REPRODUCTION:
            return finding_class.value, "reproduction classification"
        case FindingClass.ONE_DAY_ADAPTATION:
            return finding_class.value, "deployment-specific adaptation classification"
        case FindingClass.PATCH_VARIANT:
            return finding_class.value, "patch variant classification"
        case FindingClass.ZERO_DAY_LIKE:
            return finding_class.value, "candidate taxonomy; not an automatic zero-day claim"
        case unreachable:
            assert_never(unreachable)


def _linked_selection(
    artifact: VerifiedResultArtifact,
    candidate_id: str,
) -> _FindingSelection:
    payload = require_verified_result(artifact).payload
    candidates = tuple(
        candidate
        for candidate in payload.finding_candidates
        if candidate.candidate_id == candidate_id
    )
    if len(candidates) != 1:
        raise ReportGateError(reason="finding candidate is absent or ambiguous")
    candidate = candidates[0]
    claims = tuple(
        claim for claim in payload.claim_packets if claim.candidate_id == candidate_id
    )
    if len(claims) != 1:
        raise ReportGateError(reason="candidate has no unambiguous claim packet")
    claim = claims[0]
    verdicts = tuple(
        verdict for verdict in payload.verification_verdicts if verdict.claim_id == claim.claim_id
    )
    if len(verdicts) != 1:
        raise ReportGateError(reason="claim has no unambiguous verification verdict")
    return _FindingSelection(candidate=candidate, claim=claim, verdict=verdicts[0])


def _select_verified(
    artifact: VerifiedResultArtifact,
    candidate_id: str,
) -> _FindingSelection:
    selected = _linked_selection(artifact, candidate_id)
    candidate = selected.candidate
    claim = selected.claim
    verdict = selected.verdict
    match verdict.outcome:
        case VerdictOutcome.VERIFIED:
            pass
        case VerdictOutcome.REJECTED | VerdictOutcome.INCONCLUSIVE:
            raise ReportGateError(reason="finding is not independently verified")
        case unreachable:
            assert_never(unreachable)
    if not verdict.independent_replay or not candidate.final_effect_observed:
        raise ReportGateError(reason="finding is not independently verified")
    if verdict.claim_packet_digest != sha256_digest(claim):
        raise ReportGateError(reason="verdict does not bind the selected claim")
    if not verdict.evidence_refs or not claim.negative_control_refs:
        raise ReportGateError(reason="verified report lacks replay or negative-control evidence")
    provenance = artifact.automation_dispatch_provenance
    if provenance is not None:
        try:
            validate_automation_dispatch_provenance(provenance)
        except AutomationDispatchProvenanceError as exc:
            raise ReportGateError(reason=str(exc)) from exc
        if (
            provenance.dispatch.envelope.record.candidate_id != candidate.candidate_id
            or tuple(
                reason
                for reason in verdict.reasons
                if reason.startswith("faultloom:automation_dispatch_provenance=")
            )
            != (automation_dispatch_provenance_marker(provenance),)
            or provenance.dispatch.evidence_ref not in verdict.evidence_refs
        ):
            raise ReportGateError(
                reason="verified report does not bind automation dispatch provenance"
            )
    return selected


def verification_summary(
    artifact: VerifiedResultArtifact,
    candidate_id: str,
) -> VerificationSummary:
    selected = _linked_selection(artifact, candidate_id)
    return VerificationSummary(
        candidate_id=selected.candidate.candidate_id,
        claim_id=selected.claim.claim_id,
        verdict_id=selected.verdict.verdict_id,
        verifier_run_id=selected.verdict.verifier_run_id,
        outcome=selected.verdict.outcome.value,
        result_artifact_digest=sha256_digest(artifact.envelope),
    )


def _evidence_document(reference: EvidenceRef) -> _EvidenceDocument:
    return {
        "evidence_id": reference.evidence_id,
        "cas_digest": reference.cas_digest,
        "redaction_digest": reference.redaction_digest,
    }


def _json_report(
    artifact: VerifiedResultArtifact,
    selected: _FindingSelection,
) -> str:
    candidate = selected.candidate
    claim = selected.claim
    verdict = selected.verdict
    classification, classification_scope = _classification(candidate.finding_class)
    document: dict[str, object] = {
        "candidate_id": candidate.candidate_id,
        "claim": _scrub(claim.claim),
        "claim_id": claim.claim_id,
        "classification": classification,
        "classification_scope": classification_scope,
        "evidence": [
            _evidence_document(reference)
            for reference in sorted(verdict.evidence_refs, key=lambda item: item.evidence_id)
        ],
        "negative_control_evidence": [
            _evidence_document(reference)
            for reference in sorted(
                claim.negative_control_refs,
                key=lambda item: item.evidence_id,
            )
        ],
        "prerequisites": [_scrub(value) for value in claim.prerequisites],
        "reasons": [_scrub(value) for value in verdict.reasons],
        "title": _scrub(candidate.title),
        "verdict": verdict.outcome.value,
        "verdict_id": verdict.verdict_id,
        "verified_at": verdict.verified_at.isoformat(),
        "verifier_actor_id": artifact.verifier.actor_id,
        "verifier_authority_digest": artifact.verifier.authority_digest,
        "verifier_run_id": verdict.verifier_run_id,
    }
    provenance = artifact.automation_dispatch_provenance
    if provenance is not None:
        document["automation_dispatch_provenance_digest"] = (
            automation_dispatch_provenance_marker(provenance).removeprefix(
                "faultloom:automation_dispatch_provenance="
            )
        )
        document["automation_dispatch_evidence_id"] = (
            provenance.dispatch.evidence_ref.evidence_id
        )
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _markdown_report(
    artifact: VerifiedResultArtifact,
    selected: _FindingSelection,
) -> str:
    candidate = selected.candidate
    claim = selected.claim
    verdict = selected.verdict
    classification, classification_scope = _classification(candidate.finding_class)
    prerequisites = "\n".join(f"- {_markdown(value)}" for value in claim.prerequisites)
    evidence = "\n".join(
        f"- `{reference.evidence_id}` — `{reference.cas_digest}`"
        for reference in sorted(verdict.evidence_refs, key=lambda item: item.evidence_id)
    )
    negative = "\n".join(
        f"- `{reference.evidence_id}` — `{reference.cas_digest}`"
        for reference in sorted(claim.negative_control_refs, key=lambda item: item.evidence_id)
    )
    reasons = "\n".join(f"- `{_markdown(value)}`" for value in verdict.reasons)
    provenance = artifact.automation_dispatch_provenance
    provenance_section = ""
    if provenance is not None:
        provenance_digest = automation_dispatch_provenance_marker(provenance).removeprefix(
            "faultloom:automation_dispatch_provenance="
        )
        provenance_section = (
            "\n## Automation dispatch provenance\n\n"
            f"- Digest: `{provenance_digest}`\n"
            f"- Evidence: `{provenance.dispatch.evidence_ref.evidence_id}`\n"
        )
    return (
        f"# {_markdown(candidate.title)}\n\n"
        f"- Candidate: `{candidate.candidate_id}`\n"
        f"- Classification: `{classification}` ({classification_scope})\n"
        f"- Verdict: `{verdict.outcome.value}`\n"
        f"- Verifier actor: `{artifact.verifier.actor_id}`\n"
        f"- Verifier authority: `{artifact.verifier.authority_digest}`\n\n"
        f"## Claim\n\n{_markdown(claim.claim)}\n\n"
        f"## Prerequisites\n\n{prerequisites}\n\n"
        f"## Independent replay evidence\n\n{evidence}\n\n"
        f"## Negative controls\n\n{negative}\n\n"
        f"## Verification reasons\n\n{reasons}\n{provenance_section}"
    )


def render_finding_report(
    artifact: VerifiedResultArtifact,
    candidate_id: str,
    report_format: ReportFormat,
) -> ReportArtifact:
    selected = _select_verified(artifact, candidate_id)
    match report_format:
        case ReportFormat.MARKDOWN:
            content = _markdown_report(artifact, selected)
        case ReportFormat.JSON:
            content = _json_report(artifact, selected)
        case unreachable:
            assert_never(unreachable)
    report_digest = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
    return ReportArtifact(
        content=content,
        receipt=ReportReceipt(
            candidate_id=selected.candidate.candidate_id,
            claim_id=selected.claim.claim_id,
            verdict_id=selected.verdict.verdict_id,
            report_format=report_format,
            report_digest=report_digest,
            result_artifact_digest=sha256_digest(artifact.envelope),
        ),
    )
