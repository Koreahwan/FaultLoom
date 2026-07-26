"""Fail-closed registry for pinned adapter admission."""

from __future__ import annotations

from faultloom_protocol import sha256_digest
from faultloom_protocol.models import AdapterManifest, EvidenceCapability
from pydantic import ValidationError

from .model_utility import ModelUtilityEvaluation
from .admission_models import (
    ADMISSION_GATE_ORDER,
    AdapterAdmissionReceipt,
    AdapterAdmissionSnapshot,
    AdapterAdmissionState,
    AdmissionGate,
    derive_admission_state,
)
from .registry import ManifestRegistry


class AdapterAdmissionError(ValueError):
    """An adapter admission or use request failed closed."""


class AdapterNotFoundError(AdapterAdmissionError):
    """The requested adapter has no pinned installed manifest."""


def _canonical_evaluation(
    evaluation: ModelUtilityEvaluation,
) -> ModelUtilityEvaluation:
    try:
        return ModelUtilityEvaluation.model_validate(
            evaluation.model_dump(mode="python")
        )
    except ValidationError:
        error = AdapterAdmissionError("model utility evaluation is not canonical")
    raise error


class AdapterAdmissionRegistry:
    """Track admission without accepting commands, environment, or target sockets."""

    def __init__(self, manifest_registry: ManifestRegistry) -> None:
        if type(manifest_registry) is not ManifestRegistry:
            raise AdapterAdmissionError("admission requires an exact T11 manifest registry")
        self._manifests: dict[str, AdapterManifest] = {}
        self._receipts: dict[str, tuple[AdapterAdmissionReceipt, ...]] = {}
        for manifest in manifest_registry.adapters:
            if type(manifest) is not AdapterManifest:
                raise AdapterAdmissionError("adapter manifest must be an exact protocol model")
            current = self._manifests.get(manifest.adapter_id)
            if current is not None and sha256_digest(current) != sha256_digest(manifest):
                raise AdapterAdmissionError("adapter ID has conflicting pinned manifests")
            self._manifests[manifest.adapter_id] = manifest
            _ = self._receipts.setdefault(manifest.adapter_id, ())

    def list(self) -> tuple[AdapterAdmissionSnapshot, ...]:
        return tuple(self._snapshot(adapter_id) for adapter_id in sorted(self._manifests))

    def doctor(self, adapter_id: str) -> AdapterAdmissionSnapshot:
        _ = self._require_manifest(adapter_id)
        return self._snapshot(adapter_id)

    def prepare_test(self, adapter_id: str) -> AdapterManifest:
        """Return only a pinned manifest; process launch details are never accepted."""

        return self._require_manifest(adapter_id)

    def record(self, receipt: AdapterAdmissionReceipt) -> AdapterAdmissionSnapshot:
        if type(receipt) is not AdapterAdmissionReceipt:
            raise AdapterAdmissionError("admission receipt must be an exact SDK model")
        if receipt.gate is AdmissionGate.MODEL_UTILITY:
            raise AdapterAdmissionError(
                "model utility admission requires a canonical evaluation"
            )
        return self._record(receipt)

    def record_model_utility(
        self,
        evaluation: ModelUtilityEvaluation,
    ) -> AdapterAdmissionSnapshot:
        if type(evaluation) is not ModelUtilityEvaluation:
            raise AdapterAdmissionError(
                "model utility admission requires an exact canonical evaluation"
            )
        canonical = _canonical_evaluation(evaluation)
        plan = canonical.plan
        manifest = self._require_manifest(plan.adapter_id)
        if plan.manifest_digest != sha256_digest(manifest):
            raise AdapterAdmissionError("model utility manifest digest mismatch")
        raise AdapterAdmissionError(
            "trusted model utility attestation is unavailable"
        )

    def _record(self, receipt: AdapterAdmissionReceipt) -> AdapterAdmissionSnapshot:
        manifest = self._require_manifest(receipt.adapter_id)
        if receipt.manifest_digest != sha256_digest(manifest):
            raise AdapterAdmissionError("admission receipt manifest digest mismatch")
        receipts = self._receipts[receipt.adapter_id]
        existing = next((item for item in receipts if item.gate is receipt.gate), None)
        if existing is not None:
            if existing != receipt:
                raise AdapterAdmissionError("admission gate already has a different receipt")
            return self._snapshot(receipt.adapter_id)
        state = derive_admission_state(manifest, receipts)
        expected_index = len(receipts)
        pending_states = {
            AdapterAdmissionState.PENDING_CONTRACT,
            AdapterAdmissionState.PENDING_FIDELITY,
            AdapterAdmissionState.PENDING_MODEL_UTILITY,
        }
        if state not in pending_states:
            raise AdapterAdmissionError(f"adapter admission is terminal: {state.value}")
        expected = ADMISSION_GATE_ORDER[expected_index]
        if receipt.gate is not expected:
            raise AdapterAdmissionError(
                f"expected {expected.value} admission receipt, got {receipt.gate.value}"
            )
        self._receipts[receipt.adapter_id] = (*receipts, receipt)
        return self._snapshot(receipt.adapter_id)

    def require_candidate_source(self, adapter_id: str) -> AdapterManifest:
        snapshot = self.doctor(adapter_id)
        admitted_states = {
            AdapterAdmissionState.ADMITTED_CANDIDATE,
            AdapterAdmissionState.ADMITTED_EVIDENCE,
        }
        if snapshot.state not in admitted_states:
            raise AdapterAdmissionError("adapter has not passed every admission gate")
        return snapshot.manifest

    def require_evidence_source(
        self,
        adapter_id: str,
        *,
        independent_non_tool_evidence: bool,
    ) -> AdapterManifest:
        manifest = self.require_candidate_source(adapter_id)
        if manifest.evidence_capability is EvidenceCapability.CANDIDATE_ONLY:
            raise AdapterAdmissionError("candidate-only adapter cannot supply evidence")
        if not independent_non_tool_evidence:
            raise AdapterAdmissionError("tool-only verified findings are forbidden")
        return manifest

    def _require_manifest(self, adapter_id: str) -> AdapterManifest:
        manifest = self._manifests.get(adapter_id)
        if manifest is None:
            raise AdapterNotFoundError(f"adapter is not installed: {adapter_id}")
        return manifest

    def _snapshot(self, adapter_id: str) -> AdapterAdmissionSnapshot:
        manifest = self._manifests[adapter_id]
        receipts = self._receipts[adapter_id]
        return AdapterAdmissionSnapshot(
            manifest=manifest,
            manifest_digest=sha256_digest(manifest),
            receipts=receipts,
            state=derive_admission_state(manifest, receipts),
        )
