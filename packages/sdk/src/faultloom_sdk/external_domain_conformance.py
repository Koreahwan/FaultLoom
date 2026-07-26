"""Deterministic receipt helpers for the stable external-domain ABI."""

from __future__ import annotations

from datetime import datetime

from faultloom_protocol import ProtocolModel, canonical_json
from faultloom_protocol.base import Sha256Digest, ShortStr
from faultloom_protocol.models import Ed25519PublicKeyRecord

from .external_domain import (
    EXTERNAL_DOMAIN_ABI_VERSION,
    ExternalDomainAdmissionError,
    VerifiedExternalDomainAdmission,
)


EXTERNAL_DOMAIN_CONFORMANCE_VERSION = "1.0.0"


class ExternalDomainConformanceReceipt(ProtocolModel):
    """Stable, data-only record of a signed-authority ABI conformance run."""

    conformance_version: ShortStr
    abi_version: ShortStr
    domain_id: ShortStr
    schema_namespace: ShortStr
    canonical_manifest_digest: Sha256Digest
    pack_manifest_digest: Sha256Digest
    adapter_manifest_digests: tuple[Sha256Digest, ...]
    signed_authority_grant_digest: Sha256Digest


def build_external_domain_conformance_receipt(
    verified_admission: object,
    *,
    trusted_public_key: Ed25519PublicKeyRecord,
    minimum_grant_version: int = 1,
    now: datetime | None = None,
) -> ExternalDomainConformanceReceipt:
    """Build a receipt only after revalidating a signed admission envelope.

    Candidate results from :meth:`ExternalDomainRegistry.admit` are deliberately
    rejected: they have no pinned-key signature proof.  The caller supplies
    the pinned key and verification controls so a process-local private helper
    cannot turn an unsigned candidate admission into a signed receipt. No
    dynamic import, extension execution, or network operation is performed.
    """

    if type(verified_admission) is not VerifiedExternalDomainAdmission:
        raise ExternalDomainAdmissionError(
            "conformance receipt requires a verified signed admission proof"
        )
    admission, _, signed_grant_digest, _ = verified_admission.conformance_parts(
        trusted_public_key=trusted_public_key,
        minimum_grant_version=minimum_grant_version,
        now=now,
    )
    if admission.abi_version != EXTERNAL_DOMAIN_ABI_VERSION:
        raise ExternalDomainAdmissionError("admission ABI version is not the stable v1 ABI")
    if admission.authority_grant_digest != signed_grant_digest:
        raise ExternalDomainAdmissionError("verified grant digest does not match admission")
    return ExternalDomainConformanceReceipt(
        schema_version="0.1.0",
        conformance_version=EXTERNAL_DOMAIN_CONFORMANCE_VERSION,
        abi_version=admission.abi_version,
        domain_id=admission.domain_id,
        schema_namespace=admission.schema_namespace,
        canonical_manifest_digest=admission.declaration_digest,
        pack_manifest_digest=admission.pack_manifest_digest,
        adapter_manifest_digests=admission.adapter_manifest_digests,
        signed_authority_grant_digest=signed_grant_digest,
    )


def canonical_external_domain_conformance_receipt(
    receipt: ExternalDomainConformanceReceipt,
) -> str:
    """Serialize a receipt as canonical JSON without broadening protocol types."""

    if type(receipt) is not ExternalDomainConformanceReceipt:
        raise ExternalDomainAdmissionError(
            "receipt must be an exact ExternalDomainConformanceReceipt"
        )
    return canonical_json(receipt.model_dump(mode="python"))
