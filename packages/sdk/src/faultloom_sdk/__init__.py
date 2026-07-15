"""Public out-of-process extension SDK."""

from .admission import (
    AdapterAdmissionError,
    AdapterAdmissionRegistry,
    AdapterNotFoundError,
)
from .admission_models import (
    AdapterAdmissionReceipt,
    AdapterAdmissionSnapshot,
    AdapterAdmissionState,
    AdmissionGate,
    AdmissionOutcome,
)

from .reference import (
    ReferenceProcessClient,
    ReferenceProcessError,
    reference_adapter_manifest,
    reference_pack_manifest,
    reference_registry,
)
from .registry import (
    AuthorityBindingError,
    DescriptorRoleConflictError,
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
    rpc_input_schema,
    rpc_output_schema,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AdapterAdmissionError",
    "AdapterAdmissionReceipt",
    "AdapterAdmissionRegistry",
    "AdapterAdmissionSnapshot",
    "AdapterAdmissionState",
    "AdapterNotFoundError",
    "AdmissionGate",
    "AdmissionOutcome",
    "AuthorityBindingError",
    "CompileActionRequest",
    "CompileActionResponse",
    "CompiledAction",
    "DescribeRequest",
    "DescribeResponse",
    "DescriptorRoleConflictError",
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
    "rpc_input_schema",
    "rpc_output_schema",
]
