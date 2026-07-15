from __future__ import annotations

from typing import assert_never

from faultloom_protocol import CapabilityPrimitive, SCHEMA_VERSION

from .admissions import (
    ApiAsyncPrimitive,
    IdentityWorkflowPrimitive,
    PatchVariantPrimitive,
    PrimitiveAdmission,
    PrimitiveRegistry,
    SyntheticLlmPrimitive,
)
from .errors import ChainIntegrityError


def normalize_primitives(
    admissions: tuple[PrimitiveAdmission, ...],
) -> PrimitiveRegistry:
    """Normalize source-specific admissions into one deterministic registry."""

    admission_ids = tuple(item.admission_id for item in admissions)
    primitive_ids = tuple(item.primitive.primitive_id for item in admissions)
    if len(admission_ids) != len(set(admission_ids)):
        raise ChainIntegrityError(
            "chain.duplicate_admission",
            "primitive admission IDs must be unique",
        )
    if len(primitive_ids) != len(set(primitive_ids)):
        raise ChainIntegrityError(
            "chain.duplicate_primitive",
            "one PrimitiveRecord cannot be registered twice",
        )
    capabilities = tuple(
        _normalize(admission)
        for admission in sorted(admissions, key=lambda item: item.capability_id)
    )
    verified = tuple(
        item.capability_id for item in capabilities if item.verified
    )
    candidates = tuple(
        item.capability_id for item in capabilities if not item.verified
    )
    return PrimitiveRegistry(
        capabilities=capabilities,
        candidate_capability_ids=candidates,
        verified_capability_ids=verified,
    )


def _normalize(admission: PrimitiveAdmission) -> CapabilityPrimitive:
    match admission:
        case IdentityWorkflowPrimitive() | ApiAsyncPrimitive():
            pass
        case PatchVariantPrimitive():
            pass
        case SyntheticLlmPrimitive():
            pass
        case unreachable:
            assert_never(unreachable)
    return CapabilityPrimitive(
        schema_version=SCHEMA_VERSION,
        capability_id=admission.capability_id,
        primitive=admission.primitive,
        capability_kind=admission.capability_kind,
        source_pack_id=admission.source_pack_id,
        verified=admission.primitive.verified,
        precondition_ids=tuple(sorted(admission.precondition_ids)),
        effect_ids=tuple(sorted(admission.effect_ids)),
    )
