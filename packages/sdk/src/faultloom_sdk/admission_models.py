"""Immutable adapter admission states and receipts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol.base import Identifier, Sha256Digest
from faultloom_protocol.canonical import sha256_digest
from faultloom_protocol.models import AdapterManifest, EvidenceCapability


class AdapterAdmissionModelError(ValueError):
    pass


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

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True
    )

    adapter_id: Identifier
    manifest_digest: Sha256Digest
    gate: AdmissionGate
    outcome: AdmissionOutcome
    artifact_digest: Sha256Digest
    evaluation_digest: Sha256Digest | None = None
    dispatched_oos: Annotated[int, Field(ge=0)] = 0
    escaped_oos: Annotated[int, Field(ge=0)] = 0
    tool_only_false_verified: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def _gate_claim_is_supported(self) -> Self:
        safety_failures = (self.dispatched_oos, self.escaped_oos, self.tool_only_false_verified)
        if self.outcome is AdmissionOutcome.PASSED and any(safety_failures):
            raise AdapterAdmissionModelError(
                "passed admission receipt requires zero safety counters"
            )
        if self.gate is AdmissionGate.MODEL_UTILITY and (
            self.evaluation_digest is None
            or self.artifact_digest != self.evaluation_digest
        ):
            raise AdapterAdmissionModelError(
                "model-utility receipt must bind its canonical evaluation digest"
            )
        if (
            self.gate is not AdmissionGate.MODEL_UTILITY
            and self.evaluation_digest is not None
        ):
            raise AdapterAdmissionModelError(
                "only model-utility receipts may bind an evaluation"
            )
        return self


class AdapterAdmissionSnapshot(BaseModel):
    """An immutable view bound to one exact adapter manifest."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True
    )

    manifest: AdapterManifest
    manifest_digest: Sha256Digest
    receipts: tuple[AdapterAdmissionReceipt, ...]
    state: AdapterAdmissionState

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> Self:
        if self.manifest_digest != sha256_digest(self.manifest):
            raise AdapterAdmissionModelError(
                "admission snapshot manifest digest mismatch"
            )
        if any(
            receipt.adapter_id != self.manifest.adapter_id
            or receipt.manifest_digest != self.manifest_digest
            for receipt in self.receipts
        ):
            raise AdapterAdmissionModelError(
                "admission receipt is not bound to the snapshot manifest"
            )
        expected = derive_admission_state(self.manifest, self.receipts)
        if self.state is not expected:
            raise AdapterAdmissionModelError(
                "admission snapshot state does not match its receipts"
            )
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
        raise AdapterAdmissionModelError(
            "admission receipts are not an ordered gate prefix"
        )
    for index, receipt in enumerate(receipts):
        if receipt.outcome is AdmissionOutcome.PASSED:
            continue
        if index != len(receipts) - 1:
            raise AdapterAdmissionModelError(
                "rejected admission cannot contain later receipts"
            )
        return AdapterAdmissionState.REJECTED
    if len(receipts) == 0:
        return AdapterAdmissionState.PENDING_CONTRACT
    if len(receipts) == 1:
        return AdapterAdmissionState.PENDING_FIDELITY
    if len(receipts) == 2:
        return AdapterAdmissionState.PENDING_MODEL_UTILITY
    if len(receipts) == 3:
        if manifest.evidence_capability is EvidenceCapability.CANDIDATE_ONLY:
            return AdapterAdmissionState.ADMITTED_CANDIDATE
        return AdapterAdmissionState.ADMITTED_EVIDENCE
    raise AdapterAdmissionModelError("adapter admission has too many receipts")
