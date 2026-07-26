"""Gateway-only semantic HTTP and multi-identity browser execution."""

from .browser import BrowserExecutionCoordinator
from .browser_driver import ChromiumBrowserDriver, ChromiumLaunchConfig
from .browser_runtime_manifest import (
    ChromiumRuntimeAsset,
    PINNED_CHROMIUM_RUNTIME_ASSETS,
)
from .browser_contracts import (
    BrowserContractError,
    BrowserIdentityContext,
    UnsupportedBrowserTransport,
)
from .contracts import (
    SEMANTIC_HTTP_ACTION_KIND,
    BrowserChildCandidate,
    BrowserChildKind,
    EndpointScheme,
    ExecutionIdentity,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
    SemanticBodyRef,
    SemanticEndpoint,
    SemanticHeader,
    SemanticHttpObservation,
    SemanticHttpRequest,
    SemanticQueryParameter,
    SemanticResponseHeader,
    SemanticValue,
    semantic_payload_digest,
)
from .http import SemanticHttpExecutor
from .http_validation import (
    DispatchReplayError,
    DispatchUncertainError,
    ExecutionContractError,
    GatewayChannelError,
    LocalDispatchState,
    ReconciliationStateError,
)
from .gateway import (
    ExecutionFlowKind,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    bind_gateway_response,
    canonical_dispatch_receipt_id,
    gateway_dispatch_frame,
    gateway_frame_digest,
)
from .gateway_client import (
    AuthenticatedGatewayClient,
    GatewayChannelConfig,
)
from .gateway_launcher import (
    GatewayLaunchBundle,
    GatewayLaunchError,
    GatewayLauncher,
)
from .gateway_provisioner import (
    GatewayProvisionedHandoff,
    GatewayProvisioningError,
    GatewayProvisioningMaterial,
    provision_gateway_handoff,
)

__all__ = [
    "SEMANTIC_HTTP_ACTION_KIND",
    "BrowserChildCandidate",
    "BrowserChildKind",
    "BrowserContractError",
    "BrowserExecutionCoordinator",
    "BrowserIdentityContext",
    "ChromiumBrowserDriver",
    "ChromiumLaunchConfig",
    "ChromiumRuntimeAsset",
    "AuthenticatedGatewayClient",
    "PINNED_CHROMIUM_RUNTIME_ASSETS",
    "DispatchReplayError",
    "DispatchUncertainError",
    "EndpointScheme",
    "ExecutionFlowKind",
    "ExecutionContractError",
    "ExecutionIdentity",
    "GatewayDeniedResult",
    "GatewayLaunchBundle",
    "GatewayLaunchError",
    "GatewayLauncher",
    "GatewayProvisionedHandoff",
    "GatewayProvisioningError",
    "GatewayProvisioningMaterial",
    "GatewayChannelConfig",
    "GatewayChannelError",
    "GatewayDispatchCommand",
    "GatewayDispatchFrame",
    "GatewayDispatchResult",
    "GatewayResponseEnvelope",
    "GatewayResult",
    "LocalDispatchState",
    "ReconciliationStateError",
    "SemanticBodyRef",
    "SemanticEndpoint",
    "SemanticHeader",
    "SemanticHttpExecutor",
    "SemanticHttpObservation",
    "SemanticHttpRequest",
    "SemanticQueryParameter",
    "SemanticResponseHeader",
    "SemanticValue",
    "UnsupportedBrowserTransport",
    "bind_gateway_response",
    "canonical_dispatch_receipt_id",
    "gateway_dispatch_frame",
    "gateway_frame_digest",
    "provision_gateway_handoff",
    "semantic_payload_digest",
]
