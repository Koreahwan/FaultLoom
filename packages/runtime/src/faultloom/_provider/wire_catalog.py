from __future__ import annotations

from typing import Final

from faultloom.egress_wire import ExactEnumCatalog
from faultloom.egress_wire_snapshot import ExactWireBoundary

from .common import (
    FailureCode,
    MetadataSourceKind,
    ProviderCallOutcome,
    ProviderPlane,
    ProviderToolKind,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
)
from .intent import (
    FailoverProvenance,
    GenerationConfig,
    ProviderCallBudget,
    ProviderCallIntent,
)
from .metadata import (
    MetadataProvenance,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderToolSpec,
)
from .proxy import ProviderProxyRequest, ProviderProxyResult, ProviderUsage
from .receipt import ProviderCallReceipt

_PROVIDER_ENUM_TYPES: Final = (
    FailureCode,
    MetadataSourceKind,
    ProviderCallOutcome,
    ProviderPlane,
    ProviderToolKind,
    ProxyEffectDisposition,
    ProxyOutcome,
    RetryDisposition,
)
_PROVIDER_MODEL_TYPES: Final = (
    GenerationConfig,
    ProviderCallBudget,
    FailoverProvenance,
    ProviderCallIntent,
    MetadataProvenance,
    ProviderToolSpec,
    ProviderModelProfile,
    ProviderObservedMetadata,
    ProviderUsage,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderCallReceipt,
)

PROVIDER_WIRE: Final = ExactWireBoundary(
    enum_catalog=ExactEnumCatalog(_PROVIDER_ENUM_TYPES),
    enum_types=_PROVIDER_ENUM_TYPES,
    model_types=_PROVIDER_MODEL_TYPES,
)
