"""Immutable adapter admission states and receipts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self, assert_never

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import AdapterManifest, EvidenceCapability, sha256_digest
from faultloom_protocol.base import Identifier, Sha256Digest


class AdmissionGate(StrEnum):
    CONTRACT = "contract"
    FIDELITY = "fidelity"
    MODEL_UTILITY = "model_utility"


class AdmissionOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class AdapterAdmissionState(StrEnum):
    PENDING_CONTRACT = "pending_contract"
    PENDING_FIDELITY = "pending_fidelity"
    PENDING_MODEL_UTILITY = "pending_model_utility"
    ADMITTED_CANDIDATE = "admitted_candidate"
    ADMITTED_EVIDENCE = "admitted_evidence"
    REJECTED = "rejected"


class AdapterAdmissionReceipt(BaseModel):
    """One immutable, artifact-bound admission-gate result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    adapter_id: Identifier
    manifest_digest: Sha256Digest
    gate: AdmissionGate
    outcome: AdmissionOutcome
    artifact_digest: Sha256Digest
    dispatched_oos: Annotated[int, Field(ge=0)] = 0
    escaped_oos: Annotated[int, Field(ge=0)] = 0
    tool_only_false_verified: Annotated[int, Field(ge=0)] = 0
    recall_gain_bps: Annotated[int, Field(ge=-10_000, le=10_000)] = 0
    unique_verified_positives: Annotated[int, Field(ge=0)] = 0
    efficiency_gain_bps: Annotated[int, Field(ge=0, le=10_000)] = 0
    recall_loss_bps: Annotated[int, Field(ge=0, le=10_000)] = 0

    @model_validator(mode="after")
    def _gate_claim_is_supported(self) -> Self:
        safety_failures = (self.dispatched_oos, self.escaped_oos, self.tool_only_false_verified)
        match self.outcome:
            case AdmissionOutcome.PASSED:
                passed = True
                if any(safety_failures):
                    raise ValueError("passed admission receipt requires zero safety counters")
            case AdmissionOutcome.FAILED | AdmissionOutcome.INCONCLUSIVE:
                passed = False
            case unreachable:
                assert_never(unreachable)
        metrics = (
            self.recall_gain_bps,
            self.unique_verified_positives,
            self.efficiency_gain_bps,
            self.recall_loss_bps,
        )
        match self.gate:
            case AdmissionGate.CONTRACT | AdmissionGate.FIDELITY:
                if any(metrics):
                    raise ValueError("only model-utility receipts may carry utility metrics")
            case AdmissionGate.MODEL_UTILITY:
                utility_proven = (
                    self.recall_gain_bps >= 1_000
                    or self.unique_verified_positives >= 2
                    or (
                        self.efficiency_gain_bps >= 2_000
                        and self.recall_loss_bps == 0
                    )
                )
                if passed and not utility_proven:
                    raise ValueError("passed model-utility receipt lacks a utility threshold")
            case unreachable:
                assert_never(unreachable)
        return self


class AdapterAdmissionSnapshot(BaseModel):
    """An immutable view bound to one exact adapter manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest: AdapterManifest
    manifest_digest: Sha256Digest
    receipts: tuple[AdapterAdmissionReceipt, ...]
    state: AdapterAdmissionState

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> Self:
        if self.manifest_digest != sha256_digest(self.manifest):
            raise ValueError("admission snapshot manifest digest mismatch")
        if any(
            receipt.adapter_id != self.manifest.adapter_id
            or receipt.manifest_digest != self.manifest_digest
            for receipt in self.receipts
        ):
            raise ValueError("admission receipt is not bound to the snapshot manifest")
        expected = derive_admission_state(self.manifest, self.receipts)
        if self.state is not expected:
            raise ValueError("admission snapshot state does not match its receipts")
        return self


ADMISSION_GATE_ORDER = (
    AdmissionGate.CONTRACT,
    AdmissionGate.FIDELITY,
    AdmissionGate.MODEL_UTILITY,
)


def derive_admission_state(
    manifest: AdapterManifest,
    receipts: tuple[AdapterAdmissionReceipt, ...],
) -> AdapterAdmissionState:
    gates = tuple(receipt.gate for receipt in receipts)
    if gates != ADMISSION_GATE_ORDER[: len(gates)]:
        raise ValueError("admission receipts are not an ordered gate prefix")
    for index, receipt in enumerate(receipts):
        match receipt.outcome:
            case AdmissionOutcome.PASSED:
                pass
            case AdmissionOutcome.FAILED | AdmissionOutcome.INCONCLUSIVE:
                if index != len(receipts) - 1:
                    raise ValueError("rejected admission cannot contain later receipts")
                return AdapterAdmissionState.REJECTED
            case unreachable:
                assert_never(unreachable)
    if len(receipts) == 0:
        return AdapterAdmissionState.PENDING_CONTRACT
    if len(receipts) == 1:
        return AdapterAdmissionState.PENDING_FIDELITY
    if len(receipts) == 2:
        return AdapterAdmissionState.PENDING_MODEL_UTILITY
    if len(receipts) == 3:
        match manifest.evidence_capability:
            case EvidenceCapability.CANDIDATE_ONLY:
                return AdapterAdmissionState.ADMITTED_CANDIDATE
            case EvidenceCapability.EVIDENCE_CAPABLE:
                return AdapterAdmissionState.ADMITTED_EVIDENCE
            case unreachable:
                assert_never(unreachable)
    raise ValueError("adapter admission has too many receipts")
