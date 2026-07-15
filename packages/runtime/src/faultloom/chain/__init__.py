"""Public T35 cross-surface chain engine."""

from .admissions import (
    ApiAsyncPrimitive,
    IdentityWorkflowPrimitive,
    PatchVariantPrimitive,
    PrimitiveAdmission,
    PrimitiveRegistry,
    PrimitiveStatus,
    SyntheticLlmPrimitive,
)
from .contracts import (
    AssetClass,
    ChainAuthority,
    ChainBudget,
    ChainCheckpoint,
    ChainSearchResult,
    ChainSearchSettings,
    EdgeAuthorityBinding,
    GraphComponent,
    PlannedChain,
    ReplayObservation,
    ReplayRequest,
    ReplaySeed,
    SearchMode,
)
from .engine import CrossSurfaceChainEngine
from .errors import ChainError, ChainIntegrityError, ChainPolicyError
from .registry import normalize_primitives
from .replay import finding_eligible

__all__ = [
    "ApiAsyncPrimitive",
    "AssetClass",
    "ChainAuthority",
    "ChainBudget",
    "ChainCheckpoint",
    "ChainError",
    "ChainIntegrityError",
    "ChainPolicyError",
    "ChainSearchResult",
    "ChainSearchSettings",
    "CrossSurfaceChainEngine",
    "EdgeAuthorityBinding",
    "GraphComponent",
    "IdentityWorkflowPrimitive",
    "PatchVariantPrimitive",
    "PlannedChain",
    "PrimitiveAdmission",
    "PrimitiveRegistry",
    "PrimitiveStatus",
    "ReplayObservation",
    "ReplayRequest",
    "ReplaySeed",
    "SearchMode",
    "SyntheticLlmPrimitive",
    "finding_eligible",
    "normalize_primitives",
]
