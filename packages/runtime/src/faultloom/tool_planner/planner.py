from __future__ import annotations

from dataclasses import dataclass
from typing import assert_never

from faultloom_protocol import (
    ActionClass,
    AdapterManifest,
    AuthorityGrant,
    EvidenceCapability,
    HypothesisRecord,
    HypothesisStatus,
    sha256_digest,
)
from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionRegistry,
    AdapterAdmissionSnapshot,
    AdmissionGate,
    AdmissionOutcome,
    ManifestRegistry,
    ManifestRegistryError,
)

from .models import (
    PlanningBudget,
    ToolCandidate,
    ToolEvidenceRole,
    ToolPlan,
    ToolPlanItem,
    ToolPlanReceipt,
)


class ToolPlanningError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class ToolPlanningUnavailableError(ToolPlanningError):
    pass


@dataclass(frozen=True, slots=True)
class _AdmittedCandidate:
    candidate: ToolCandidate
    manifest: AdapterManifest
    snapshot: AdapterAdmissionSnapshot


class ToolPlanner:
    def __init__(
        self,
        manifests: ManifestRegistry,
        admissions: AdapterAdmissionRegistry,
    ) -> None:
        if type(manifests) is not ManifestRegistry:
            raise ToolPlanningError("planner requires an exact T29 manifest registry")
        if type(admissions) is not AdapterAdmissionRegistry:
            raise ToolPlanningError("planner requires an exact T29 admission registry")
        self._manifests = manifests
        self._admissions = admissions

    def select(
        self,
        *,
        hypothesis: HypothesisRecord,
        grant: AuthorityGrant,
        budget: PlanningBudget,
        candidates: tuple[ToolCandidate, ...],
    ) -> ToolPlan:
        self._validate_inputs(hypothesis, grant, budget, candidates)
        admitted = tuple(
            self._admit(candidate, grant)
            for candidate in candidates
        )
        feasible = tuple(
            item for item in admitted if _fits(item.candidate, budget)
        )
        if not feasible:
            raise ToolPlanningUnavailableError(
                "no admitted tool candidate fits every remaining budget"
            )
        selected = min(feasible, key=_selection_key)
        candidate = selected.candidate
        utility = next(
            (
                receipt
                for receipt in selected.snapshot.receipts
                if receipt.gate is AdmissionGate.MODEL_UTILITY
            ),
            None,
        )
        if utility is None or utility.outcome is not AdmissionOutcome.PASSED:
            raise ToolPlanningError("adapter utility admission receipt is unavailable")
        evidence_role = _evidence_role(selected.manifest.evidence_capability)
        receipt = ToolPlanReceipt(
            candidate_id=candidate.candidate_id,
            candidate_digest=sha256_digest(candidate.model_dump(mode="json")),
            hypothesis_id=hypothesis.hypothesis_id,
            hypothesis_digest=sha256_digest(hypothesis),
            authority_digest=sha256_digest(grant),
            adapter_id=candidate.adapter_id,
            manifest_digest=sha256_digest(selected.manifest),
            admission_snapshot_digest=sha256_digest(
                selected.snapshot.model_dump(mode="json")
            ),
            utility_receipt_digest=sha256_digest(utility.model_dump(mode="json")),
            budget_digest=sha256_digest(budget.model_dump(mode="json")),
        )
        return ToolPlan(
            hypothesis_id=hypothesis.hypothesis_id,
            selected=ToolPlanItem(
                candidate=candidate,
                evidence_role=evidence_role,
                receipt=receipt,
            ),
            remaining=budget.consume(candidate.estimate),
        )

    def _validate_inputs(
        self,
        hypothesis: HypothesisRecord,
        grant: AuthorityGrant,
        budget: PlanningBudget,
        candidates: tuple[ToolCandidate, ...],
    ) -> None:
        if type(hypothesis) is not HypothesisRecord:
            raise ToolPlanningError("planner requires an exact hypothesis record")
        if type(grant) is not AuthorityGrant:
            raise ToolPlanningError("planner requires an exact authority grant")
        if type(budget) is not PlanningBudget:
            raise ToolPlanningError("planner requires an exact remaining budget")
        if type(candidates) is not tuple or not candidates:
            raise ToolPlanningError("planner requires at least one candidate")
        if any(type(item) is not ToolCandidate for item in candidates):
            raise ToolPlanningError("planner candidates must be exact typed values")
        candidate_ids = tuple(item.candidate_id for item in candidates)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ToolPlanningError("planner candidate IDs must be unique")
        match hypothesis.status:
            case HypothesisStatus.ACTIVE | HypothesisStatus.SUPPORTED:
                pass
            case HypothesisStatus.REFUTED | HypothesisStatus.SUPERSEDED:
                raise ToolPlanningError("closed hypothesis cannot request a tool plan")
            case unreachable:
                assert_never(unreachable)
        if any(
            item.hypothesis_id != hypothesis.hypothesis_id
            or item.intent.run_id != hypothesis.run_id
            for item in candidates
        ):
            raise ToolPlanningError("tool candidate belongs to another hypothesis or run")
        limits = grant.budget
        if (
            budget.rate_slots > limits.rate_per_minute
            or budget.duration_seconds > limits.max_duration_seconds
            or budget.bytes > limits.max_request_bytes + limits.max_response_bytes
            or budget.concurrency > limits.max_concurrency
            or budget.actions > limits.total_actions
        ):
            raise ToolPlanningError("remaining budget exceeds the authority ceiling")

    def _admit(
        self,
        candidate: ToolCandidate,
        grant: AuthorityGrant,
    ) -> _AdmittedCandidate:
        try:
            manifest = self._admissions.require_candidate_source(candidate.adapter_id)
            snapshot = self._admissions.doctor(candidate.adapter_id)
            self._manifests.prepare_compile(
                request_id=candidate.candidate_id,
                grant=grant,
                intent=candidate.intent,
            )
        except (AdapterAdmissionError, ManifestRegistryError) as exc:
            raise ToolPlanningError(f"adapter or action admission failed: {exc}") from exc
        pinned = next(
            (
                item
                for item in self._manifests.adapters
                if item.adapter_id == candidate.adapter_id
            ),
            None,
        )
        if pinned is None or sha256_digest(pinned) != sha256_digest(manifest):
            raise ToolPlanningError("adapter admission is not bound to the pinned registry")
        if candidate.adapter_id not in grant.adapter_ids:
            raise ToolPlanningError("adapter is outside the supplied authority grant")
        if candidate.capability not in manifest.capabilities:
            raise ToolPlanningError("adapter capability is not admitted")
        if candidate.intent.action_class not in manifest.action_classes:
            raise ToolPlanningError("adapter action class is not admitted")
        if candidate.intent.action_class in {
            ActionClass.HIGH_LOAD,
            ActionClass.DESTRUCTIVE,
        }:
            raise ToolPlanningError("unsupported v0.1 action class")
        estimate = candidate.estimate
        if (
            estimate.rate_slots > manifest.budget.rate_per_minute
            or estimate.duration_seconds > manifest.budget.timeout_seconds
            or estimate.bytes > manifest.budget.max_bytes
            or estimate.concurrency > manifest.budget.max_concurrency
        ):
            raise ToolPlanningError("candidate exceeds the pinned adapter budget")
        return _AdmittedCandidate(candidate, manifest, snapshot)


def _fits(candidate: ToolCandidate, budget: PlanningBudget) -> bool:
    estimate = candidate.estimate
    return (
        estimate.rate_slots <= budget.rate_slots
        and estimate.duration_seconds <= budget.duration_seconds
        and estimate.bytes <= budget.bytes
        and estimate.concurrency <= budget.concurrency
        and estimate.actions <= budget.actions
        and estimate.cost_microunits <= budget.cost_microunits
    )


def _selection_key(item: _AdmittedCandidate) -> tuple[int, int, int, int, int, int, str, str]:
    candidate = item.candidate
    estimate = candidate.estimate
    return (
        -candidate.expected_information_gain_bps,
        estimate.cost_microunits,
        estimate.duration_seconds,
        estimate.bytes,
        estimate.concurrency,
        estimate.rate_slots,
        candidate.adapter_id,
        candidate.candidate_id,
    )


def _evidence_role(capability: EvidenceCapability) -> ToolEvidenceRole:
    match capability:
        case EvidenceCapability.CANDIDATE_ONLY:
            return ToolEvidenceRole.CANDIDATE
        case EvidenceCapability.EVIDENCE_CAPABLE:
            return ToolEvidenceRole.CORROBORATING_REQUIRES_INDEPENDENT_REPLAY
        case unreachable:
            assert_never(unreachable)
