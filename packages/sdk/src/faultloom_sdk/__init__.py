"""Public out-of-process extension SDK."""

from .reference import (
    ReferenceProcessClient,
    ReferenceProcessError,
    reference_adapter_manifest,
    reference_pack_manifest,
    reference_registry,
)
from .registry import (
    AuthorityBindingError,
    ManifestConflictError,
    ManifestRegistry,
    ManifestRegistryError,
    UnknownDescriptorError,
)
from .rpc import (
    CompileActionRequest,
    CompileActionResponse,
    CompiledAction,
    DescribeRequest,
    DescribeResponse,
    NormalizeObservationRequest,
    NormalizeObservationResponse,
    NormalizedObservation,
    RpcErrorResponse,
    RpcMethod,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AuthorityBindingError",
    "CompileActionRequest",
    "CompileActionResponse",
    "CompiledAction",
    "DescribeRequest",
    "DescribeResponse",
    "ManifestConflictError",
    "ManifestRegistry",
    "ManifestRegistryError",
    "NormalizeObservationRequest",
    "NormalizeObservationResponse",
    "NormalizedObservation",
    "ReferenceProcessClient",
    "ReferenceProcessError",
    "RpcErrorResponse",
    "RpcMethod",
    "UnknownDescriptorError",
    "reference_adapter_manifest",
    "reference_pack_manifest",
    "reference_registry",
]
