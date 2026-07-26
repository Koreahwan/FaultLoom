"""Fixed operator-owned admission bundle for the formal T40 FaultLoom arm."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import ClassVar, Literal

from faultloom_protocol import (
    AdapterManifest,
    Ed25519PublicKeyRecord,
    SignedModelProducerAttestation,
    SignedModelUtilityAdmission,
    SignedModelVerifierAttestation,
    canonical_json_bytes,
)
from faultloom_sdk import (
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    ManifestRegistry,
    ModelUtilityEvaluation,
    verify_model_utility_admission,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .t40_arm_runtime import T40ArmRuntimeError

_BUNDLE_PATH = Path("/etc/faultloom/t40-formal-v1/adapter-admission-bundle.json")
_MAX_BUNDLE_BYTES = 4_194_304


class T40FaultLoomAdmissionError(T40ArmRuntimeError):
    pass


class _Bundle(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    schema_version: Literal["faultloom.t40-admission-bundle.v1"]
    bundle_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    manifest: AdapterManifest
    contract_receipt: AdapterAdmissionReceipt
    fidelity_receipt: AdapterAdmissionReceipt
    evaluation: ModelUtilityEvaluation
    producer: SignedModelProducerAttestation
    verifier: SignedModelVerifierAttestation
    admission: SignedModelUtilityAdmission
    producer_trust: tuple[Ed25519PublicKeyRecord, ...]
    verifier_trust: tuple[Ed25519PublicKeyRecord, ...]
    minimum_producer_sequence: int = Field(ge=0)
    minimum_verifier_sequence: int = Field(ge=0)
    minimum_admission_sequence: int = Field(ge=0)
    session_id: str
    evaluator_challenge: str = Field(pattern=r"^[0-9a-f]{64}$")


def _read_bundle() -> tuple[_Bundle, str]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_BUNDLE_PATH, flags)
    except OSError:
        raise T40FaultLoomAdmissionError("formal admission bundle is unavailable") from None
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, _MAX_BUNDLE_BYTES + 1)
        after = os.fstat(descriptor)
        named = os.stat(_BUNDLE_PATH, follow_symlinks=False)
    except OSError:
        raise T40FaultLoomAdmissionError("formal admission bundle is unavailable") from None
    finally:
        os.close(descriptor)
    metadata = (before, after, named)
    if any(
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != 0
        or item.st_gid != 0
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_nlink != 1
        for item in metadata
    ):
        raise T40FaultLoomAdmissionError("formal admission bundle metadata is unsafe")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        for item in metadata
    }
    if len(identities) != 1 or len(raw) != before.st_size or len(raw) > _MAX_BUNDLE_BYTES:
        raise T40FaultLoomAdmissionError("formal admission bundle changed during read")
    try:
        bundle = _Bundle.model_validate_json(raw)
    except ValidationError:
        raise T40FaultLoomAdmissionError("formal admission bundle is malformed") from None
    if raw != canonical_json_bytes(bundle.model_dump(mode="json")):
        raise T40FaultLoomAdmissionError("formal admission bundle is not canonical JSON")
    return bundle, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def admitted_registry(manifests: ManifestRegistry) -> tuple[AdapterAdmissionRegistry, str]:
    """Reverify and record the fixed proof through the public SDK admission path."""

    bundle, digest = _read_bundle()
    installed = tuple(
        item for item in manifests.adapters if item.adapter_id == bundle.manifest.adapter_id
    )
    if len(installed) != 1 or installed[0] != bundle.manifest:
        raise T40FaultLoomAdmissionError("formal admission manifest is not installed exactly")
    producer_trust = {item.key_id: item for item in bundle.producer_trust}
    verifier_trust = {item.key_id: item for item in bundle.verifier_trust}
    if len(producer_trust) != len(bundle.producer_trust) or len(verifier_trust) != len(
        bundle.verifier_trust
    ):
        raise T40FaultLoomAdmissionError("formal admission trust roots are ambiguous")
    proof = verify_model_utility_admission(
        bundle.admission,
        evaluation=bundle.evaluation,
        producer=bundle.producer,
        verifier=bundle.verifier,
        manifest=bundle.manifest,
        producer_trust_registry=producer_trust,
        verifier_trust_registry=verifier_trust,
        minimum_producer_sequence=bundle.minimum_producer_sequence,
        minimum_verifier_sequence=bundle.minimum_verifier_sequence,
        minimum_admission_sequence=bundle.minimum_admission_sequence,
        expected_session_id=bundle.session_id,
        expected_evaluator_challenge=bundle.evaluator_challenge,
    )
    registry = AdapterAdmissionRegistry(manifests)
    _ = registry.record(bundle.contract_receipt)
    _ = registry.record(bundle.fidelity_receipt)
    _ = registry.record_verified_model_utility(
        proof,
        producer_trust_registry=producer_trust,
        verifier_trust_registry=verifier_trust,
        minimum_producer_sequence=bundle.minimum_producer_sequence,
        minimum_verifier_sequence=bundle.minimum_verifier_sequence,
        minimum_admission_sequence=bundle.minimum_admission_sequence,
        expected_session_id=bundle.session_id,
        expected_evaluator_challenge=bundle.evaluator_challenge,
    )
    return registry, digest


__all__ = ["T40FaultLoomAdmissionError"]
